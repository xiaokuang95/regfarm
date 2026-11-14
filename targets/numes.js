/**
 * targets/numes.js — 注册目标：numes.ai
 *
 * 流程：Keycloak 注册（Turnstile action=register）→ 邮件确认链接 →
 *       设置密码 → numes.ai 会话 → BFF 建 key → sk-numes-v1-…
 *
 * 与 tokenharbor / alysis 的差别（实测踩出来的，改之前先看这里）：
 *
 *   1. 注册和登录是两套难度：登录页（kc-form-login）挂 Turnstile，
 *      密码登录没法纯 HTTP 过；**注册页的 Turnstile action 是 `register`**，
 *      求解器给 token 就能过。所以这个 target 只做"注册新号"，不做登录。
 *
 *   2. 确认邮件里是**链接**（/realms/numes/login-actions/action-token?key=…），
 *      不是 OTP → 必须用盒子的 wait_link，mailPrefer 只能列支持 _iter_messages
 *      的 provider（mail.tm / tempmail.lol / temp-mail.io）。
 *
 *   3. 点完链接不是结束，还要**设置密码**（required-action 页）。
 *      设置完 Keycloak 才 302 回 numes.ai/auth/callback，这时才有
 *      numes_session_0…5 这些会话 cookie。
 *
 *   4. 建 key 走 BFF：
 *        POST /api/bff/app/v1/accounts/<active_account_id>/keys
 *        x-numes-csrf: <SSR 里的 csrfToken>   Referer: https://numes.ai/dashboard/keys
 *        {"name":"…","kind":"inference","billing_currency":"USD","limit":null,"limit_reset":null}
 *      csrfToken 和 active_account_id 都在 GET /dashboard/keys 的 SSR 脚本里，
 *      带着 JSON 转义（`csrfToken\":\"…`），正则要留出反斜杠。
 *
 *   5. 产出的 key 是推理用的 `sk-numes-v1-…`，免费模型 $0。key 本身查不了消费
 *      （$0），但 `GET https://api.numes.ai/api/v1/key` 能确认 key 有效。
 *
 *   6. 邮箱源会抽风（mail.tm 偶尔 429/超时），runner 的多 provider 轮询兜底；
 *      连续失败就换 provider 或加代理再跑。
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
  baseUrl: 'https://numes.ai',
  authBaseUrl: 'https://auth.numes.ai',
  realm: 'numes',
  /** 推理 API（key 校验 / 聊天） */
  apiBaseUrl: 'https://api.numes.ai/api/v1',
  /** 邀请码：本目标没有 referral 流程，留空 */
  referral: '',
  /** Cloudflare Turnstile sitekey（注册页 cf-turnstile 的公开值） */
  sitekey: '0x4AAAAAAFLWEC7CNO3A8O1H',
  solverUrl: 'https://captcha.tokents.top',
  userAgent:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36',
  outDir: path.join(os.homedir(), 'projects', 'numes_farm', 'out'),

  /** 确认信是链接，只列实现 _iter_messages（→ wait_link）的 provider */
  mailPrefer: ['mail.tm', 'tempmail.lol', 'temp-mail.io'],

  /** 注册成功后 scp 到这台 CPA 的 auth-dir（.env: CPA_HOST / CPA_DIR） */
  get cpaHost() {
    return process.env.NUMES_CPA_HOST || process.env.CPA_HOST || '';
  },
  get cpaDir() {
    return process.env.NUMES_CPA_DIR || process.env.CPA_DIR || '/root/.cli-proxy-api';
  },
};

const authUrl = (cfg, p) => `${cfg.authBaseUrl}/realms/${cfg.realm}${p}`;

// ======================================================== 解析（可单测）

/**
 * 从登录页 HTML 里抠出 Keycloak 注册链接（相对路径，带 tab_id/client_data）。
 * 链接是 HTML 转义的（&amp;），调用方负责还原。
 */
export function extractRegistrationPath(html) {
  const m = String(html || '').match(/href="([^"]*\/login-actions\/registration[^"]*)"/i);
  if (!m) throw new Error('登录页里没有注册链接');
  return m[1].replaceAll('&amp;', '&');
}

/** 找 form action（含指定片段），同样还原 &amp;。 */
export function extractFormAction(html, needle) {
  for (const m of String(html || '').matchAll(/<form[^>]*action="([^"]+)"/gi)) {
    const action = m[1].replaceAll('&amp;', '&');
    if (action.includes(needle)) return action;
  }
  throw new Error(`页面里没有 action 含 ${needle} 的表单`);
}

/** 注册提交成功的标志；失败时尽量把 Keycloak 的报错抠出来。 */
export function registrationOutcome(html) {
  const text = String(html || '');
  if (/Check your email/i.test(text)) return { ok: true, message: '' };
  const err =
    text.match(/kc-feedback-text[^>]*>([^<]{4,200})/i)?.[1] ||
    text.match(/id="input-error[^"]*"[^>]*>([^<]{4,200})/i)?.[1] ||
    '';
  return { ok: false, message: err.trim() || '注册提交后没有出现 Check your email' };
}

/** SSR 脚本里 `csrfToken\":\"…\"`（带 JSON 转义）。 */
export function extractCsrf(html) {
  const text = String(html || '');
  const i = text.indexOf('csrfToken');
  if (i < 0) throw new Error('dashboard 里没有 csrfToken');
  const m = text.slice(i).match(/[A-Za-z0-9_-]{30,}/);
  if (!m) throw new Error('csrfToken 值解析失败');
  return m[0];
}

/** SSR 里 `"accounts":{"active_account_id":"<uuid>"`。 */
export function extractActiveAccountId(html) {
  const text = String(html || '');
  const i = text.indexOf('active_account_id');
  if (i < 0) throw new Error('dashboard 里没有 active_account_id');
  const m = text.slice(i).match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
  if (!m) throw new Error('active_account_id 不是 uuid');
  return m[0];
}

/** 建 key 的请求体；limit/limit_reset 为 null = 不限。 */
export function buildKeyBody(name) {
  return {
    name,
    kind: 'inference',
    billing_currency: 'USD',
    limit: null,
    limit_reset: null,
  };
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

    const s = new Session({ proxy, userAgent: cfg.userAgent });
    try {
      // --- 1. 打开登录页，拿注册链接 ---
      const r1 = await s.get(`${cfg.baseUrl}/auth/login`);
      if (r1.status !== 200) throw new Error(`login page HTTP ${r1.status}`);
      const regUrl = new URL(extractRegistrationPath(r1.text), cfg.authBaseUrl).href;

      const r2 = await s.get(regUrl);
      if (r2.status !== 200) throw new Error(`registration page HTTP ${r2.status}`);
      const registerAction = extractFormAction(r2.text, '/login-actions/registration');
      if (!/cf-turnstile/i.test(r2.text)) throw new Error('注册页没有 Turnstile，站点可能改版了');

      // --- 2. Turnstile（action=register）---
      const token = await solve(regUrl, { action: 'register' });

      // --- 3. 提交注册 ---
      const r3 = await s.post(registerAction, {
        data: {
          firstName: 'Lin',
          lastName: 'Wu',
          email,
          'cf-turnstile-response': token,
        },
        headers: { Origin: cfg.authBaseUrl, Referer: regUrl },
      });
      const outcome = registrationOutcome(r3.text);
      if (r3.status !== 200 || !outcome.ok) {
        throw new Error(`signup HTTP ${r3.status}: ${outcome.message}`);
      }
      log(`[${idx}] signup ok, waiting email`);

      // --- 4. 确认邮件里的链接 ---
      const link = await box.wait_link(180, /login-actions\/action-token/);
      const r4 = await s.get(link);
      if (r4.status !== 200 || !/Choose a password/i.test(r4.text)) {
        throw new Error(`verify link 没到设密码页: HTTP ${r4.status}`);
      }
      log(`[${idx}] email verified`);

      // --- 5. 设置密码（required-action）---
      const pwAction = extractFormAction(r4.text, '/login-actions/required-action');
      const r5 = await s.post(pwAction, {
        data: { 'password-new': password, 'password-confirm': password },
        headers: { Origin: cfg.authBaseUrl, Referer: r4.headers?.location || cfg.authBaseUrl },
      });
      if (r5.status !== 200) throw new Error(`set password HTTP ${r5.status}`);
      log(`[${idx}] password set`);

      // --- 6. 进 dashboard，取 csrf + account id ---
      const r6 = await s.get(`${cfg.baseUrl}/dashboard/keys`);
      if (r6.status !== 200) throw new Error(`dashboard HTTP ${r6.status}`);
      const csrf = extractCsrf(r6.text);
      const accountId = extractActiveAccountId(r6.text);

      // --- 7. 建推理 key ---
      const keyName = `regfarm-${idx}-${Date.now().toString(36)}`;
      const r7 = await s.post(`${cfg.baseUrl}/api/bff/app/v1/accounts/${accountId}/keys`, {
        json: buildKeyBody(keyName),
        headers: {
          'x-numes-csrf': csrf,
          Origin: cfg.baseUrl,
          Referer: `${cfg.baseUrl}/dashboard/keys`,
        },
      });
      if (r7.status !== 200 && r7.status !== 201) {
        throw new Error(`create key HTTP ${r7.status}: ${r7.text.slice(0, 160)}`);
      }
      const payload = r7.json();
      const apiKey = findKey(payload);
      if (!apiKey) throw new Error(`建 key 响应里没有 sk-numes-v1-: ${r7.text.slice(0, 160)}`);
      log(`[${idx}] api_key=${apiKey.slice(0, 18)}…`);

      // --- 8. 验活 ---
      const probe = await s.get(`${cfg.apiBaseUrl}/key`, {
        headers: { Authorization: `Bearer ${apiKey}` },
      });
      const alive = probe.status === 200;
      log(`[${idx}] key probe ${alive ? 'ok' : `HTTP ${probe.status}`}`);

      return {
        idx,
        created_at: wibNow(),
        email,
        mail_provider: box.provider_name,
        password,
        account_id: accountId,
        key_name: keyName,
        api_key: apiKey,
        key_alive: alive,
        credential_line: `${email} | ${password} | ${apiKey} | ${wibNow()}`,
      };
    } finally {
      s.close();
    }
  } finally {
    box.close();
  }
}

/** 真 key = sk-numes-v1- + 64 位 hex；响应里还有个掩码标签（eddb...b7ec），别抓错。 */
const KEY_RE = /^sk-numes-v1-[0-9a-f]{64}$/i;

/** BFF 的响应形状不稳定，递归找第一个完整 key。 */
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
  const s = String(uid || '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .slice(0, 64);
  return s && s !== '.' && s !== '..' ? s : '';
}

export function buildCpaAuthFile(res) {
  const uid = sanitizeUid(res.account_id) || 'numes';
  return {
    fileName: `numes-${uid}.json`,
    body: {
      type: 'numes',
      provider: 'numes',
      logo: 'https://numes.ai/favicon.svg',
      disabled: false,
      auth: {
        accessToken: res.api_key,
        domain: config.apiBaseUrl,
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
