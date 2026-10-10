/**
 * lib/solver.js — Turnstile 求解器客户端
 *
 * 契约（与本地 sidecar :8877 及 captcha.tokents.top 一致）：
 *   GET {solverUrl}/turnstile?url=<pageUrl>&sitekey=<sitekey>[&action=<action>]  -> {task_id}
 *   GET {solverUrl}/result?id=<task_id>                                        -> {status, value}
 *
 * 走 lib/http.js 的 Session 而不是裸 fetch：求解器常常只有通过代理才连得上
 * （本机直连 captcha.tokents.top 是 CONNECT_TIMEOUT），而 Session 自带
 * http:// / socks5:// 代理隧道。runner 会把当前任务的代理透传进来，
 * 这样注册链路（页面 + captcha）出口 IP 一致。
 *
 * action 是可选的：Cloudflare 把 action 签进 token，站点服务端可以校验。
 * Supabase 的 captcha 校验不看 action，但自建 edge function 会看 ——
 * alysiscode.com 的 device-approve 就是（用错 action 的 token 被判
 * 403 Verification failed）。不需要 action 的站点不传即可。
 */

import { Session } from './http.js';
import { sleep, log as defaultLog } from './util.js';

export function createSolver({
  solverUrl,
  sitekey,
  action = null,
  maxPolls = 40,
  pollMs = 2000,
  timeoutMs = 60_000,
  log = defaultLog,
}) {
  if (!solverUrl) throw new Error('createSolver: solverUrl 必填');
  if (!sitekey) throw new Error('createSolver: sitekey 必填');

  /**
   * @param {string} pageUrl token 绑定到的页面（hostname 必须匹配 sitekey 的允许域）
   * @param {object} [o]
   * @param {string} [o.action] 覆盖 config 里的 action；传 '' 表示不带
   * @param {string|null} [o.proxy] 求解器出口代理；不传则直连
   */
  return async function solve(pageUrl, o = {}) {
    const act = o.action === undefined ? action : o.action;
    const q = { url: pageUrl, sitekey };
    if (act) q.action = act;

    const s = new Session({ proxy: o.proxy ?? null, timeout: Math.ceil(timeoutMs / 1000) });
    try {
      const t = await s.get(`${solverUrl}/turnstile`, {
        params: q,
        headers: { Accept: 'application/json' },
      });
      if (t.status >= 400) throw new Error(`solver HTTP ${t.status}: ${t.text.slice(0, 120)}`);
      const { task_id: tid } = t.json();
      log(`  solver task=${String(tid).slice(0, 8)}…${act ? ` action=${act}` : ''}`);

      for (let i = 0; i < maxPolls; i++) {
        await sleep(pollMs);
        const p = await s.get(`${solverUrl}/result`, {
          params: { id: tid },
          headers: { Accept: 'application/json' },
        });
        const body = p.content.length ? (() => { try { return p.json(); } catch { return {}; } })() : {};
        if (body.status === 'success') return body.value;
        if (body.status === 'failed' || body.status === 'error') {
          throw new Error(`solver failed: ${JSON.stringify(body)}`);
        }
        if (p.status >= 400) continue; // 429 之类，继续等
      }
      throw new Error('solver timeout');
    } finally {
      s.close();
    }
  };
}
