/**
 * targets/alysis-code.js — 注册目标：alysiscode.com
 *
 * 流程：Supabase 邮箱注册 → Turnstile(action=signup) → 邮件确认链接 →
 *       device-code 设备登录 → Turnstile(action=device_approve) → slk_ 网关 key
 *
 * 与 top-tools-ai 的差别（都是实测踩出来的，改之前先看这里）：
 *
 *   1. 确认邮件里是**链接**不是 OTP。站点用 PKCE，邮件里是 pkce_ 前缀的
 *      token_hash，只有持有 code_verifier 的那个浏览器能兑换。所以这里注册时
 *      **不带 code_challenge**，拿到的是普通 token_hash，
 *      POST /auth/v1/verify 直接换 session —— 确认环节不需要浏览器。
 *
 *   2. 两个 Turnstile 的 action 不同：注册用 signup，审批用 device_approve。
 *      Cloudflare 把 action 签进 token，服务端会校验 —— 用错 action 的 token
 *      在 device-approve 上会被判 403 Verification failed。
 *      （Supabase 自己的 captcha 校验不看 action。）
 *
 *   3. device-approve 必须带 Origin: https://alysiscode.com，否则
 *      403 {"error":"Origin is not allowed."}
 *
 *   4. 注册是按 IP 限流的：同 IP 短时间内建几个号之后，所有 signup 都会
 *      403 error_code=unknown（不是域名黑名单 —— 用不存在的域名试也一样）。
 *      所以这个 target 必须配合代理池跑，--conc 别开大。
 *
 *   5. 拿到的 api_key 是长期网关 key（slk_...），不过期，只能吊销。
 */

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { createMailboxPool } from '../lib/mailbox.js';
import { wibNow } from '../lib/util.js';

const execFileAsync = promisify(execFile);

// ============================================================ 配置（改这里）

export const config = {
  baseUrl: 'https://alysiscode.com',
  /** 邀请码：本目标没有 referral 流程，留空 */
  referral: '',
  /** Cloudflare Turnstile sitekey（站点 bundle 里的公开值） */
  sitekey: '0x4AAAAAAFCGJnIFvPtF_pgs',
  solverUrl: 'https://captcha.tokents.top',
  userAgent:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
  outDir: path.join(os.homedir(), 'projects', 'alysis_farm', 'out'),

  /**
   * 只列实现了 _iter_messages（→ wait_link）的 provider：
   * 确认信是链接，wait_code 抠不出东西，列别的只会白等超时。
   * 实测 mail.tm 对 alysis 正常送达。
   */
  mailPrefer: ['mail.tm', 'tempmail.lol', 'temp-mail.io'],
  /** 注册成功后 scp 到这台 CPA 的 auth-dir（.env: CPA_HOST / CPA_DIR） */
  get cpaHost() {
    return process.env.ALYSIS_CPA_HOST || process.env.CPA_HOST || '';
  },
  get cpaDir() {
    return process.env.ALYSIS_CPA_DIR || process.env.CPA_DIR || '/root/.cli-proxy-api';
  },
  /** Supabase 项目（anon key 是公开值，站点自己的浏览器 bundle 里也有） */
  supabaseUrl: 'https://vzigujbcjjmpntxhmyvr.supabase.co',
  anonKey:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InZ6aWd1amJjamptcG50eGhteXZyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODA5Mzc0NTIsImV4cCI6MjA5NjUxMzQ1Mn0.' +
    'vLH9q-BNO8IWIZrVlvCw8pZWXdLgmKG4Tl9toTTD3pg',
};

const AUTH = (cfg) => `${cfg.supabaseUrl}/auth/v1`;
const FN = (cfg) => `${cfg.supabaseUrl}/functions/v1`;

/** 每个 Supabase 调用都要 apikey；anon key 足够公开路由，受保护路由另加 Bearer。 */
const apiHeaders = (cfg, extra = {}) => ({
  apikey: cfg.anonKey,
  'Content-Type': 'application/json',
  ...extra,
});

/** 从确认链接里抠出 token_hash / type。链接是 #fragment 形式。 */
export function parseConfirmLink(url) {
  const hash = url.includes('#') ? url.slice(url.indexOf('#') + 1) : url.split('?')[1] || '';
  const params = new URLSearchParams(hash);
  const tokenHash = params.get('token_hash');
  if (!tokenHash) throw new Error(`confirm link tanpa token_hash: ${url.slice(0, 120)}`);
  return { tokenHash, type: params.get('type') || 'email' };
}

/** 把 Supabase 那些不透明的错误翻译成人话（403 是限流，不是域名问题）。 */
function explainSignupError(r) {
  let msg = '';
  try {
    msg = r.json().msg || '';
  } catch {
    msg = r.text.slice(0, 160);
  }
  if (r.status === 403) {
    return `signup 403（该 IP 注册限流，换代理重试）: ${msg}`;
  }
  if (r.status === 500 && /confirmation email/i.test(msg)) {
    return `账号已建但确认邮件发不出（Supabase SMTP 限流）: ${msg}`;
  }
  return `signup HTTP ${r.status}: ${msg}`;
}

export function createMailbox() {
  return createMailboxPool({ prefer: config.mailPrefer });
}

// ======================================================== 业务流程（改这里）

export async function registerOne(ctx) {
  const { idx, proxy, mailbox, solve, Session, genPassword, log, cfg } = ctx;

  const box = await mailbox.open();
  try {
    const email = box.address;
    const password = genPassword();
    log(`[${idx}] email=${email} provider=${box.provider_name}` + (proxy ? ` proxy=${proxy}` : ''));

    // 站点域：Turnstile token 绑定 hostname，Session 的 Origin 也用它
    const s = new Session({ proxy, userAgent: cfg.userAgent });
    try {
      // --- 1. 注册（Turnstile action=signup）---
      // 故意不带 code_challenge：带了就变 PKCE，邮件里会是 pkce_ 前缀的
      // token_hash，只有原浏览器能兑换，我们换不到 session。
      const signupToken = await solve(`${cfg.baseUrl}/login`, { action: 'signup' });
      const r1 = await s.post(`${AUTH(cfg)}/signup`, {
        headers: apiHeaders(cfg, { Origin: cfg.baseUrl }),
        json: {
          email,
          password,
          data: { full_name: `Alysis ${idx}`, marketing_opt_in: false },
          gotrue_meta_security: { captcha_token: signupToken },
        },
      });
      if (r1.status !== 200) throw new Error(explainSignupError(r1));
      const userId = r1.json().id || r1.json().user?.id;
      log(`[${idx}] signup ok user=${String(userId).slice(0, 8)}…`);

      // --- 2. 等确认邮件，取链接 ---
      // 发件人 noreply@alysisai.com，主题 "Confirm your email for Alysis Code"
      const link = await box.wait_link(180, /token_hash=/);
      const { tokenHash, type } = parseConfirmLink(link);
      log(`[${idx}] confirm link ok type=${type} pkce=${tokenHash.startsWith('pkce_')}`);

      // --- 3. 兑换 session（纯 HTTP，不需要浏览器）---
      const r2 = await s.post(`${AUTH(cfg)}/verify`, {
        headers: apiHeaders(cfg, { Origin: cfg.baseUrl }),
        json: { type, token_hash: tokenHash },
      });
      if (r2.status !== 200) throw new Error(`verify HTTP ${r2.status}: ${r2.text.slice(0, 160)}`);
      const session = r2.json();
      if (!session.access_token) throw new Error('verify 没返回 access_token');
      log(`[${idx}] session ok confirmed=${Boolean(session.user?.email_confirmed_at)}`);

      // --- 4. 设备登录：申请 device code ---
      // device-code / device-token 是公开端点（服务端 verify_jwt off），带 anon key 即可
      const r3 = await s.post(`${FN(cfg)}/device-code`, {
        headers: apiHeaders(cfg, { Authorization: `Bearer ${cfg.anonKey}` }),
        json: { client_name: `regfarm-${idx}` },
      });
      if (r3.status !== 200) throw new Error(`device-code HTTP ${r3.status}: ${r3.text.slice(0, 160)}`);
      const grant = r3.json();
      log(`[${idx}] device code=${grant.user_code}`);

      // --- 5. 审批（Turnstile action=device_approve + session JWT + Origin）---
      const approveToken = await solve(`${cfg.baseUrl}/activate`, { action: 'device_approve' });
      const r4 = await s.post(`${FN(cfg)}/device-approve`, {
        headers: apiHeaders(cfg, {
          Authorization: `Bearer ${session.access_token}`,
          Origin: cfg.baseUrl,
        }),
        json: { user_code: grant.user_code, captcha_token: approveToken },
      });
      if (r4.status !== 200) {
        throw new Error(`device-approve HTTP ${r4.status}: ${r4.text.slice(0, 160)}`);
      }

      // --- 6. 换长期网关 key ---
      const r5 = await s.post(`${FN(cfg)}/device-token`, {
        headers: apiHeaders(cfg, { Authorization: `Bearer ${cfg.anonKey}` }),
        json: { device_code: grant.device_code },
      });
      const tok = r5.json();
      if (tok.status !== 'approved' || !tok.key) {
        throw new Error(`device-token ${r5.status}: ${r5.text.slice(0, 160)}`);
      }
      log(`[${idx}] api_key=${tok.key.slice(0, 14)}…`);

      return {
        idx,
        created_at: wibNow(),
        email,
        mail_provider: box.provider_name,
        password,
        user_id: session.user?.id || userId,
        device_user_code: grant.user_code,
        email_confirmed: Boolean(session.user?.email_confirmed_at),
        api_key: tok.key,
        refresh_token: session.refresh_token || '',
        key_type: 'alysis_gateway',
        gateway_base_url: `${FN(cfg)}/llm/v1`,
        credential_line: `${email} | ${password} | ${tok.key} | ${wibNow()}`,
      };
    } finally {
      s.close();
    }
  } finally {
    box.close();
  }
}

export function sanitizeUid(uid) {
  const s = String(uid || '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .slice(0, 64);
  return s && s !== '.' && s !== '..' ? s : '';
}

export function buildCpaAuthFile(res) {
  const uid = sanitizeUid(res.user_id) || 'alysis';
  return {
    fileName: `alysis-${uid}.json`,
    body: {
      type: 'alysis',
      provider: 'alysis',
      logo: 'https://alysiscode.com/favicon.ico',
      disabled: false,
      auth: {
        accessToken: res.api_key,
        refreshToken: '',
        expiresAt: 0,
        domain: res.gateway_base_url || `${FN(config)}/llm/v1`,
        sessionRefresh: res.refresh_token || '',
      },
      account: {
        uid,
        nickname: res.email || uid,
        email: res.email || '',
        password: res.password || '',
      },
    },
  };
}

/** runner 在本地 ledger 写完后调用：scp 到 CPA auth-dir，file watcher 会吃进去。 */
export async function afterSuccess(res, { log } = {}) {
  const { fileName, body } = buildCpaAuthFile(res);
  const host = config.cpaHost;
  const dir = config.cpaDir.replace(/\/$/, '');
  if (!host) {
    log?.('cpa skip: CPA_HOST unset');
    return;
  }
  const remote = `${host}:${dir}/${fileName}`;
  const tmp = path.join(os.tmpdir(), fileName);
  fs.writeFileSync(tmp, `${JSON.stringify(body, null, 2)}\n`, { mode: 0o600 });
  try {
    await execFileAsync('scp', ['-q', '-o', 'StrictHostKeyChecking=accept-new', tmp, remote]);
    await execFileAsync('ssh', [host, `chmod 600 ${dir}/${fileName}`]);
    log?.(`cpa ${fileName} → ${remote}`);
  } catch (e) {
    throw new Error(`cpa 落盘失败: ${e.message}`);
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* ignore */
    }
  }
}
