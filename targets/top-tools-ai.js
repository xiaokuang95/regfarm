/**
 * targets/top-tools-ai.js — 注册目标：top-tools-ai.com
 *
 * 流程：Clerk 注册 → Turnstile → 邮箱 OTP → referral claim → 创建 API key
 *
 * 新增目标就照这个文件抄一份：
 *   - 改 config（站点地址 / sitekey / solver / 邮箱源）
 *   - 改 registerOne 里的业务流程
 *
 * 放好文件即生效，cli.js 会自动扫描 targets/ 目录。
 *
 * registerOne(ctx) 的 ctx：
 *   idx         任务序号
 *   proxy       本次要用的代理（可能 null）
 *   mailbox     { open() } → EmailBox（.address / .provider_name / .close()）
 *   solve       (pageUrl) => turnstileToken
 *   pollOtp     (box, tries) => code
 *   Session     lib/http.js 的 Session 类
 *   genPassword (n) => string
 *   sleep / uniform / log
 *   cfg         本文件的 config
 *
 * 返回值必须含：email / password / created_at
 * 落盘用 credential_line（不给就按 email | password | api_key | created_at 拼）
 */

import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

import { createMailboxPool } from '../lib/mailbox.js';
import { wibNow } from '../lib/util.js';

// ============================================================ 配置（改这里）

export const config = {
  /** 站点根地址 */
  baseUrl: 'https://top-tools-ai.com',
  /** 邀请码。留空则跳过 referral claim */
  referral: '',
  /** Cloudflare Turnstile sitekey */
  sitekey: '0x4AAAAAAAWXJGBD7bONzLBd',
  /** 求解器地址（本地 sidecar 或第三方，契约见 lib/solver.js） */
  solverUrl: 'https://captcha.tokents.top',
  userAgent:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
  /** 输出目录 */
  outDir: path.join(os.homedir(), 'projects', 'tt_farm', 'out'),
  /** 邮箱源优先级（轮询；见 lib/mail_providers.js 的 provider 名） */
  mailPrefer: [
    'temp.tf', 'tempmail.plus', 'maildrop', 'guerrilla',
    'mail.tm', 'temp-mail.io', 'emailnator',
    'smailpro', 'ncaori', 'tempmail.lol', 'zoromail',
  ],
};

/** Clerk 前端 API（从 baseUrl 推导，一般不用改） */
const clerkBase = (cfg) => `${cfg.baseUrl}/api/__clerk/v1/client`;

export function createMailbox() {
  return createMailboxPool({ prefer: config.mailPrefer });
}

// ======================================================== 业务流程（改这里）

export async function registerOne(ctx) {
  const { idx, proxy, mailbox, solve, pollOtp, Session, genPassword, sleep, uniform, log, cfg } = ctx;
  const CLERK = clerkBase(cfg);

  const box = await mailbox.open();
  try {
    const email = box.address;
    const password = genPassword();
    log(`[${idx}] email=${email} provider=${box.provider_name}` + (proxy ? ` proxy=${proxy}` : ''));

    const s = new Session({ proxy, userAgent: cfg.userAgent });
    try {
      const signUpUrl = cfg.referral
        ? `${cfg.baseUrl}/sign-up?ref=${cfg.referral}`
        : `${cfg.baseUrl}/sign-up`;
      s.headers = {
        Origin: cfg.baseUrl,
        Referer: signUpUrl,
      };
      await s.get(CLERK); // 拿 __client cookie

      const token = await solve(signUpUrl);

      // --- 创建 sign_up ---
      let r = await s.post(`${CLERK}/sign_ups`, {
        data: {
          email_address: email,
          password,
          captcha_token: token,
          captcha_widget_type: 'smart',
        },
      });
      if (r.status !== 200) {
        throw new Error(`sign_up create HTTP ${r.status}: ${r.text.slice(0, 200)}`);
      }
      const suaId = r.json().response.id;
      log(`[${idx}] sign_up=${suaId.slice(0, 14)}…`);

      await sleep(uniform(1000, 2500));

      // --- 触发发信 ---
      r = await s.post(`${CLERK}/sign_ups/${suaId}/prepare_verification`, {
        data: { strategy: 'email_code' },
      });
      if (r.status !== 200) {
        throw new Error(`prepare_verification HTTP ${r.status}: ${r.text.slice(0, 200)}`);
      }

      const otp = await pollOtp(box);
      log(`[${idx}] otp=${otp}`);

      // --- 验证 ---
      // attempt_verification 常返 429 但 OTP 其实有效 → 用同一个码重试，
      // 不要重新注册（重新注册等于把 OTP 浪费掉）。4 次，退避 30s×n。
      let verified = null;
      for (let vTry = 0; vTry < 4; vTry++) {
        verified = await s.post(`${CLERK}/sign_ups/${suaId}/attempt_verification`, {
          data: { strategy: 'email_code', code: otp },
        });
        if (verified.status === 200) break;
        if (verified.status === 429 && vTry < 3) {
          const wait = 30 * (vTry + 1);
          log(`[${idx}] attempt_verification 429 — ulang kode sama dalam ${wait}s`);
          await sleep(wait * 1000);
          continue;
        }
        throw new Error(`attempt_verification HTTP ${verified.status}: ${verified.text.slice(0, 200)}`);
      }

      const sess = verified.json().client.sessions[0];
      const jwt = sess.last_active_token.jwt;
      const authHdr = verified.headers.authorization;
      let clientToken = String(Array.isArray(authHdr) ? authHdr[0] : (authHdr || "")).replace(/^Bearer\s+/i, "");
      if (!clientToken) {
        for (const [k, c] of s.cookies.map) {
          if (!k.endsWith("\t__client")) continue;
          try { clientToken = decodeURIComponent(c.value); } catch { clientToken = c.value; }
          clientToken = clientToken.replace(/^\d+:/, "");
          break;
        }
      }
      if (!clientToken) {
        log(`[${idx}] warn: clerk client token missing; cookies=${[...s.cookies.map.keys()].join(",")}`);
      }
      const auth = { Authorization: `Bearer ${jwt}`, 'User-Agent': cfg.userAgent };

      // --- referral（非致命）---
      let refOk = null;
      if (cfg.referral) {
        r = await s.post(`${cfg.baseUrl}/api/referral/claim`, {
          headers: auth,
          json: { code: cfg.referral },
        });
        refOk = r.status === 200 && r.json().ok === true;
        log(`[${idx}] referral ok=${refOk}`);
      }

      // --- API key ---
      r = await s.post(`${cfg.baseUrl}/api/api-keys`, {
        headers: auth,
        json: { name: `farm-${idx}-${crypto.randomBytes(4).toString('hex')}` },
      });
      if (r.status !== 201) {
        throw new Error(`api-keys HTTP ${r.status}: ${r.text.slice(0, 200)}`);
      }
      const keyBody = r.json();
      log(`[${idx}] api_key=${keyBody.key.slice(0, 14)}…`);

      return {
        idx,
        created_at: wibNow(),
        email,
        mail_provider: box.provider_name,
        password,
        user_id: sess.user.id,
        session_id: sess.id,
        referral_code: cfg.referral,
        referral_claimed: refOk,
        api_key: keyBody.key,
        api_key_name: keyBody.name,
        jwt,
        client_token: clientToken,
      };
    } finally {
      s.close();
    }
  } finally {
    box.close();
  }
}

export async function afterSuccess(res, { log } = {}) {
  const uid = String(res.user_id || "").replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, 64) || "tt";
  const fileName = `toptools-${uid}.json`;
  const body = {
    type: "toptools",
    provider: "toptools",
    logo: "https://top-tools-ai.com/logo.png",
    disabled: false,
    auth: {
      accessToken: res.api_key,
      refreshToken: "",
      expiresAt: 0,
      domain: "https://top-tools-ai.com/v1",
      sessionAccess: res.jwt || "",
      sessionId: res.session_id || "",
      clientToken: res.client_token || "",
      refreshToken: res.client_token || "",
    },
    account: { uid, nickname: res.email || uid, email: res.email || "" },
  };
  const host = process.env.TT_CPA_HOST || process.env.CPA_HOST || "";
  const dir = (process.env.TT_CPA_DIR || process.env.CPA_DIR || "/root/.cli-proxy-api").replace(/\/$/, "");
  if (!host) {
    log?.("cpa skip: CPA_HOST unset");
    return;
  }
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const { writeFileSync, unlinkSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const execFileAsync = promisify(execFile);
  const tmp = join(tmpdir(), fileName);
  writeFileSync(tmp, `${JSON.stringify(body, null, 2)}\n`, { mode: 0o600 });
  try {
    await execFileAsync("scp", ["-q", "-o", "StrictHostKeyChecking=accept-new", tmp, `${host}:${dir}/${fileName}`]);
    await execFileAsync("ssh", [host, `chmod 600 ${dir}/${fileName}`]);
    log?.(`cpa ${fileName} → ${host}:${dir}/${fileName}`);
  } finally {
    try { unlinkSync(tmp); } catch { /* ignore */ }
  }
}
