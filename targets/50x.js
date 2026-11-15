/**
 * targets/50x.js — 注册目标：ai.50x.energy
 *
 * 流程：邮箱+密码注册 → 确认邮件里的 `?verify=<token>` 链接 →
 *       POST /api/auth/verify 换会话 → 建 key → sk-50x-…
 *
 * 实测要点（改之前先看这里）：
 *
 *   1. 注册是纯 JSON API，**没有验证码**：
 *        POST https://api.ai.50x.energy/api/auth/register {"email","password"}
 *        -> 201 {"status":"verification_sent"}
 *
 *   2. 确认邮件是**链接**（不是 OTP）：
 *        https://ai.50x.energy/?verify=<Django signing token>
 *      前端 SPA 拿到 `verify` 参数后调
 *        POST https://api.ai.50x.energy/api/auth/verify {"token": "..."}
 *      响应直接给会话：{"token":"<40 位 hex>"}，**不用再 login**。
 *      所以这里只要 wait_link 抠出 token，不需要浏览器。
 *
 *   3. 会话头是 `Authorization: Token <session>`（不是 Bearer）。
 *      建 key：
 *        POST /api/keys {"name":"..."}  -> {"api_key":"sk-50x-…","prefix":"sk-50x-XXXX",…}
 *      余额：GET /api/billing -> {"balance_usd":"100.000000000","tier":"paid"}
 *
 *   4. 邮箱域名是**黑名单**：mailinator / guerrillamail / 10minutemail /
 *      example.org 会被 400 拒；gmail / outlook / hotmail / qq / 自建域名都过。
 *      所以 mailPrefer 先用 temp.tf 的微软/谷歌真邮箱别名。
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
  baseUrl: 'https://ai.50x.energy',
  /** 控制面 API（注册 / 验证 / 建 key / 账单） */
  apiBaseUrl: 'https://api.ai.50x.energy/api',
  /** 推理 API（OpenAI 兼容，key 探活用） */
  inferBaseUrl: 'https://api.ai.50x.energy/v1',
  referral: '',
  /** 本目标没有验证码；solverUrl/sitekey 只是 runner 要求非空，从不调用 */
  solverUrl: 'https://captcha.tokents.top',
  sitekey: 'unused',
  userAgent:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36',
  outDir: path.join(os.homedir(), 'projects', '50x_farm', 'out'),

  /** 确认信是链接；只列实现 _iter_messages 的 provider。微软别名池最大 */
  mailPrefer: ['temp.tf-outlook', 'temp.tf-hotmail', 'temp.tf'],

  /** 同 IP 连开还没测出限制，先用 5 分钟 */
  ipCooldownMs: 5 * 60 * 1000,

  /** 注册成功后 scp 到这台 CPA 的 auth-dir（.env: CPA_HOST / CPA_DIR） */
  get cpaHost() {
    return process.env.FIFTYX_CPA_HOST || process.env.CPA_HOST || '';
  },
  get cpaDir() {
    return process.env.FIFTYX_CPA_DIR || process.env.CPA_DIR || '/root/.cli-proxy-api';
  },
};

// ======================================================== 解析（可单测）

export const VERIFY_LINK_RE = /[?&]verify=[A-Za-z0-9%:._-]+/;

/** 从确认邮件正文里抠 `?verify=` 的签名 token。 */
export function extractVerifyToken(link) {
  const m = String(link || '').match(/[?&]verify=([^&\s"'<>]+)/);
  if (!m) throw new Error('确认链接里没有 verify 参数');
  return decodeURIComponent(m[1]);
}

/** 建 key 响应里取 `sk-50x-…`；形状变了也能递归找。 */
const KEY_RE = /^sk-50x-[A-Za-z0-9_-]{32,}$/;

export function findKey(obj) {
  if (typeof obj === 'string') return KEY_RE.test(obj) ? obj : '';
  if (Array.isArray(obj)) {
    for (const v of obj) {
      const hit = findKey(v);
      if (hit) return hit;
    }
    return '';
  }
  if (obj && typeof obj === 'object') {
    for (const v of Object.values(obj)) {
      const hit = findKey(v);
      if (hit) return hit;
    }
  }
  return '';
}

export function sanitizeUid(uid) {
  return String(uid || '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .replace(/^[._-]+|[._-]+$/g, '')
    .slice(0, 64);
}

export function createMailbox() {
  return createMailboxPool({ prefer: config.mailPrefer });
}

// ======================================================== 业务流程（改这里）

export async function registerOne(ctx) {
  const { idx, proxy, mailbox, Session, genPassword, log, cfg } = ctx;

  const box = await mailbox.open();
  try {
    const email = box.address;
    const password = genPassword();
    log(`[${idx}] email=${email} provider=${box.provider_name}` + (proxy ? ` proxy=${proxy}` : ''));

    const s = new Session({ proxy, userAgent: cfg.userAgent });
    try {
      // --- 1. 注册 ---
      const r1 = await s.post(`${cfg.apiBaseUrl}/auth/register`, {
        json: { email, password },
        headers: { Origin: cfg.baseUrl, Referer: `${cfg.baseUrl}/signup` },
      });
      if (r1.status >= 400) {
        throw new Error(`register HTTP ${r1.status}: ${r1.text.slice(0, 200)}`);
      }
      log(`[${idx}] signup ok, waiting email`);

      // --- 2. 确认邮件 -> verify token ---
      const link = await box.wait_link(180, VERIFY_LINK_RE);
      const verifyToken = extractVerifyToken(link);

      // --- 3. 换会话（verify 直接返回 session token）---
      const r2 = await s.post(`${cfg.apiBaseUrl}/auth/verify`, {
        json: { token: verifyToken },
        headers: { Origin: cfg.baseUrl, Referer: `${cfg.baseUrl}/` },
      });
      if (r2.status >= 400) throw new Error(`verify HTTP ${r2.status}: ${r2.text.slice(0, 200)}`);
      const session = String(r2.json().token || '');
      if (!session) throw new Error('verify 响应里没有会话 token');
      log(`[${idx}] email verified`);

      // --- 4. 建 key ---
      const keyName = `regfarm-${idx}-${Date.now().toString(36)}`;
      const r3 = await s.post(`${cfg.apiBaseUrl}/keys`, {
        json: { name: keyName },
        headers: { Authorization: `Token ${session}`, Origin: cfg.baseUrl, Referer: `${cfg.baseUrl}/dashboard` },
      });
      if (r3.status !== 200 && r3.status !== 201) {
        throw new Error(`create key HTTP ${r3.status}: ${r3.text.slice(0, 200)}`);
      }
      const apiKey = findKey(r3.json());
      if (!apiKey) throw new Error(`建 key 响应里没有 sk-50x-: ${r3.text.slice(0, 200)}`);
      log(`[${idx}] api_key=${apiKey.slice(0, 16)}…`);

      // --- 5. 账单 + 验活 ---
      let balance = '';
      try {
        const rb = await s.get(`${cfg.apiBaseUrl}/billing`, {
          headers: { Authorization: `Token ${session}` },
        });
        if (rb.status === 200) balance = String(rb.json().balance_usd ?? '');
      } catch {
        /* 账单查不到不算失败 */
      }
      const probe = await s.get(`${cfg.inferBaseUrl}/models`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      const alive = probe.status === 200;
      log(`[${idx}] key probe ${alive ? 'ok' : `HTTP ${probe.status}`} balance=${balance || '?'}`);

      return {
        idx,
        created_at: wibNow(),
        email,
        mail_provider: box.provider_name,
        password,
        api_key: apiKey,
        key_name: keyName,
        key_alive: alive,
        balance_usd: balance,
        credential_line: `${email} | ${password} | ${apiKey} | ${wibNow()}`,
      };
    } finally {
      s.close();
    }
  } finally {
    box.close();
  }
}

export function buildCpaAuthFile(res) {
  const uid = sanitizeUid(res.email) || sanitizeUid(`k${res.api_key.slice(-12)}`) || '50x';
  return {
    fileName: `50x-${uid}.json`,
    body: {
      type: '50x',
      provider: '50x',
      logo: 'https://ai.50x.energy/favicon.png',
      disabled: false,
      auth: {
        accessToken: res.api_key,
        domain: config.inferBaseUrl,
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
  if (res.key_alive === false) {
    log?.('cpa skip: key 探活失败，不落盘');
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
