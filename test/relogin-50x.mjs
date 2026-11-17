/**
 * relogin-50x.mjs — 用已注册的邮箱/密码重登 50x，拿新的 dashboard session。
 * 50x 登录要 Turnstile（sitekey 0x4AAAAAAGDX104XP4OHk0Z3，无 action），
 * 走 captcha.tokents.top。仅用于诊断/救号，不属于 farm 流程。
 *
 * 用法: node test/relogin-50x.mjs <email> <password> [--proxy=http://127.0.0.1:8044]
 */
import fs from 'node:fs';
import path from 'node:path';
import { Session } from '../lib/http.js';
import { createSolver } from '../lib/solver.js';

const cfg = {
  loginUrl: 'https://ai.50x.energy/login',
  apiBase: 'https://api.ai.50x.energy',
  sitekey: '0x4AAAAAAGDX104XP4OHk0Z3',
  solverUrl: 'https://captcha.tokents.top',
  userAgent:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36',
};

const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const [email, password] = args;
const proxyArg = process.argv.find((a) => a.startsWith('--proxy='));
const proxyFile = path.join(import.meta.dirname, '..', 'proxies.txt');
const proxy =
  proxyArg?.slice('--proxy='.length) ||
  fs.readFileSync(proxyFile, 'utf8').split('\n').map((s) => s.trim()).find(Boolean) ||
  null;

if (!email || !password) {
  console.error('usage: node test/relogin-50x.mjs <email> <password> [--proxy=...]');
  process.exit(2);
}

const log = (m) => console.log(m);
const solve = createSolver({ solverUrl: cfg.solverUrl, sitekey: cfg.sitekey, log });
const s = new Session({ proxy, userAgent: cfg.userAgent });
log(`proxy: ${proxy || 'direct'}`);

try {
  const token = await solve(cfg.loginUrl, { proxy });
  log(`token: ${token.slice(0, 24)}…`);

  const r = await s.post(`${cfg.apiBase}/api/auth/login`, {
    data: { email, password, captcha: token },
    headers: { Origin: 'https://ai.50x.energy', Referer: cfg.loginUrl },
  });
  const body = (() => { try { return r.json(); } catch { return {}; } })();
  if (r.status === 200 && body.token) {
    console.log(JSON.stringify({ ok: true, email, session: body.token }));
  } else {
    console.log(JSON.stringify({ ok: false, email, status: r.status, error: body.error || body.detail || r.text.slice(0, 120), code: body.code || '' }));
  }
} finally {
  s.close();
}
