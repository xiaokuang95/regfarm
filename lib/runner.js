/**
 * lib/runner.js — 通用编排：代理轮换 / 并发 / 重试 / 限流 / 落盘
 *
 * 目标只负责「一个账号怎么注册出来」，其余都在这里。
 * 目标契约见 targets/top-tools-ai.js。
 */

import fs from 'node:fs';
import path from 'node:path';

import { Session } from './http.js';
import { pollOtp } from './mailbox.js';
import { createSolver } from './solver.js';
import { log, sleep, uniform, monotonic, genPassword, makeSemaphore } from './util.js';

/**
 * @param {object} o
 * @param {object} o.target      target 模块（含 config + registerOne）
 * @param {number} o.count
 * @param {number} o.delayMin
 * @param {number} o.delayMax
 * @param {number} o.conc
 * @param {boolean} o.dry
 * @param {string[]} o.proxyPool
 * @param {string} o.outDir
 * @param {string|null} o.mailProvider  固定单个邮箱源
 */
export async function run({
  target,
  count,
  delayMin,
  delayMax,
  conc,
  proxyPool,
  outDir,
  mailProvider = null,
}) {
  const cfg = target.config;
  fs.mkdirSync(outDir, { recursive: true });
  fs.chmodSync(outDir, 0o700);
  const LEDGER = path.join(outDir, 'ledger.jsonl');
  const CREDS = path.join(outDir, 'credentials.txt');

  const mailbox = target.createMailbox();
  if (mailProvider) {
    mailbox.pin(mailProvider);
    log(`mail provider dipin: ${mailProvider}`);
  }

  const solve = createSolver({
    solverUrl: cfg.solverUrl,
    sitekey: cfg.sitekey,
    log,
  });

  const sem = makeSemaphore(conc);
  const results = [];
  const failures = [];
  let lastThrottle = null;

  // IP 冷却池：站点回 "Too many sign-ups from this network" 就封该出口一小时。
  // cooldownMs 可由 target 覆盖（config.ipCooldownMs）。
  const cooldownMs = Number(cfg.ipCooldownMs) > 0 ? Number(cfg.ipCooldownMs) : 60 * 60 * 1000;
  const cooling = new Map(); // proxy -> 解冻时间(ms)
  const freeProxies = () => {
    const now = Date.now();
    return proxyPool.filter((p) => (cooling.get(p) || 0) <= now);
  };
  const nextProxy = () => {
    const free = freeProxies();
    if (free.length) return free[0];
    // 全部冷却：等最早解冻的那个
    const [p, until] = [...cooling.entries()].sort((a, b) => a[1] - b[1])[0] || [];
    if (!p) return null;
    const wait = Math.max(0, until - Date.now());
    log(`所有 IP 冷却中，等 ${Math.ceil(wait / 1000)}s 恢复（最早 ${p}）`);
    return { waitProxy: p, wait };
  };

  const worker = (i) =>
    sem(async () => {
      // 每次尝试都重新挑一个没冷却的出口
      for (let attempt = 0; attempt < 3; attempt++) {
        let pick = nextProxy();
        if (pick && pick.waitProxy) {
          await sleep(Math.min(pick.wait, 60000) / 1000);
          pick = nextProxy();
          if (pick && pick.waitProxy) {
            log(`[${i}] 无可用 IP，跳过`);
            failures.push(i);
            return;
          }
        }
        const proxy = pick;
        try {
          const res = await target.registerOne({
            idx: i,
            proxy,
            mailbox,
            // 求解器默认走同一个出口 IP（可用 { proxy: ... } 单次覆盖）
            solve: (pageUrl, o = {}) => solve(pageUrl, { proxy, ...o }),
            pollOtp,
            Session,
            genPassword,
            sleep,
            uniform,
            log,
            cfg,
          });
          results.push(res);
          fs.appendFileSync(LEDGER, `${JSON.stringify(res)}\n`);
          const credLine = res.credential_line || `${res.email} | ${res.password} | ${res.api_key} | ${res.created_at}`;
          fs.appendFileSync(CREDS, `${credLine}\n`);
          if (typeof target.afterSuccess === 'function') {
            try {
              await target.afterSuccess(res, { log });
            } catch (e) {
              log(`[${i}] cpa 落盘失败（本地已记）: ${e.message}`);
            }
          }
          return;
        } catch (e) {
          const cause = e.cause
            ? ` (cause: ${e.cause.code || ''} ${e.cause.message || ''})`
            : '';
          log(`[${i}] attempt ${attempt + 1}/3 gagal: ${e.message}${cause}`);
          // 该出口被限流：冷却一小时，换下一个 IP 立刻重试（不消耗重试次数）
          if (e.ipCooldown && proxy) {
            const until = Date.now() + cooldownMs;
            cooling.set(proxy, until);
            log(`[${i}] IP 冷却 ${Math.round(cooldownMs / 60000)}min: ${proxy}（剩余可用 ${freeProxies().length}/${proxyPool.length}）`);
            attempt--;
            continue;
          }
          const msg = String(e.message);
          if (/signup 403/.test(msg)) break;
          if (attempt === 2) break;
          const wait = msg.includes('429') ? 8 * (attempt + 1) : 2 * (attempt + 1);
          await sleep((wait + uniform(0, 2)) * 1000);
        }
      }
      failures.push(i);
    });

  const throttle = async (i) => {
    if (delayMax <= 0) return;
    if (i > 0) {
      const tPrev = lastThrottle === null ? delayMax : monotonic() - lastThrottle;
      const d = Math.min(delayMax, uniform(delayMin, Math.max(delayMin, tPrev * 3)));
      await sleep(d * 1000);
    }
    lastThrottle = monotonic();
  };

  const pair = async (i) => {
    await throttle(i);
    await worker(i);
  };

  await Promise.all(Array.from({ length: count }, (_, k) => pair(k + 1)));

  for (const p of [LEDGER, CREDS]) {
    if (fs.existsSync(p)) fs.chmodSync(p, 0o600);
  }

  console.log(`\n${'='.repeat(60)}`);
  log(
    `SELESAI. sukses=${results.length}/${count} gagal=${failures.length}`,
  );
  if (results.length) {
    console.log('\n--- RINGKASAN ---');
    for (const r of results) {
      const key = r.api_key || r.credential || '';
      console.log(
        `  #${String(r.idx).padStart(2)}  ${r.email}  key=${key.slice(0, 18)}…` +
          (r.referral_claimed === undefined ? '' : `  ref=${r.referral_claimed ? 'OK' : 'NO'}`),
      );
    }
  }
  console.log(`\n  ledger: ${LEDGER}\n  creds : ${CREDS} (chmod 600)`);
  return failures.length ? 1 : 0;
}
