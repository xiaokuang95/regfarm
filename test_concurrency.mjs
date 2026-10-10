#!/usr/bin/env node
/**
 * 测 alysis gateway 单 key 的并发上限。
 *
 * 打 N 个同时在飞的请求，看有多少成功、有多少被拒、拒绝的理由是什么。
 * 只跑一次不重试，所以结果就是服务端的真实判定。
 *
 * 用法: node test_concurrency.mjs <key> [levels...]
 *   默认 levels = 1,2,4,8,16
 */
const KEY = process.argv[2];
const LEVELS = process.argv.slice(3).map(Number).filter(Boolean);
const LEVEL_LIST = LEVELS.length ? LEVELS : [1, 2, 4, 8, 16];
// 项目 ref 是公开值（站点 bundle 里就有），跟 deploy_sub2api.py 保持一致
const BASE = 'https://vzigujbcjjmpntxhmyvr.supabase.co/functions/v1/llm/v1';

if (!KEY) {
  console.error('usage: node test_concurrency.mjs <slk_key> [levels...]');
  process.exit(1);
}

async function one(i) {
  const t0 = Date.now();
  try {
    const res = await fetch(`${BASE}/chat/completions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'deepseek-flash',
        messages: [{ role: 'user', content: `reply with the single word: ok${i}` }],
        max_tokens: 300,
      }),
      signal: AbortSignal.timeout(120_000),
    });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { /* non-JSON */ }
    return {
      i, status: res.status, ms: Date.now() - t0,
      ok: Boolean(body?.choices),
      err: body?.error?.message || body?.msg || (res.ok ? null : text.slice(0, 90)),
    };
  } catch (e) {
    return { i, status: 0, ms: Date.now() - t0, ok: false, err: e.message };
  }
}

console.log(`key=${KEY.slice(0, 20)}…  base=${BASE}\n`);
for (const n of LEVEL_LIST) {
  const t0 = Date.now();
  const results = await Promise.all(Array.from({ length: n }, (_, k) => one(k + 1)));
  const wall = Date.now() - t0;
  const ok = results.filter((r) => r.ok).length;
  const codes = {};
  for (const r of results) codes[r.status] = (codes[r.status] || 0) + 1;
  const avg = Math.round(results.reduce((s, r) => s + r.ms, 0) / results.length);
  console.log(
    `并发 ${String(n).padStart(2)}  成功 ${String(ok).padStart(2)}/${n}  ` +
    `HTTP ${JSON.stringify(codes)}  平均 ${avg}ms  墙钟 ${wall}ms`,
  );
  const fails = results.filter((r) => !r.ok);
  if (fails.length) {
    const reasons = [...new Set(fails.map((f) => `${f.status}: ${String(f.err).slice(0, 70)}`))];
    for (const r of reasons.slice(0, 4)) console.log(`           ✗ ${r}`);
  }
  // 每档之间停 3s，避免上一档的余温影响下一档
  if (n !== LEVEL_LIST.at(-1)) await new Promise((r) => setTimeout(r, 3000));
}
