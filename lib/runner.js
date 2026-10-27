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

  // 冷却按「端口 + 出口 IP」落盘：换端口但还是同一出口，不能当新口。
  const cooldownMs = Number(cfg.ipCooldownMs) > 0 ? Number(cfg.ipCooldownMs) : 60 * 60 * 1000;
  const quietMs = 15 * 60 * 1000; // FAST 之后整池冷静，别 5 秒再开一轮
  const coolFile = path.join(outDir, 'ip-cooldown.json');
  const cooling = new Map(); // proxy -> until
  const coolingIps = new Map(); // exit IP -> until
  const proxyIps = new Map(); // proxy -> last exit IP
  const ipStats = new Map(); // exit IP -> {t: 尝试, o: 成功}
  const inUse = new Set();
  let quietUntil = 0;
  try {
    const saved = JSON.parse(fs.readFileSync(coolFile, 'utf8'));
    const now = Date.now();
    if (saved && (saved.proxies || saved.ips)) {
      for (const [p, until] of Object.entries(saved.proxies || {})) {
        if (Number(until) > now) cooling.set(p, Number(until));
      }
      for (const [ip, until] of Object.entries(saved.ips || {})) {
        if (Number(until) > now) coolingIps.set(ip, Number(until));
      }
      for (const [p, ip] of Object.entries(saved.proxyIps || {})) {
        if (ip) proxyIps.set(p, String(ip));
      }
      for (const [ip, st] of Object.entries(saved.ipStats || {})) {
        ipStats.set(ip, { t: Number(st.t) || 0, o: Number(st.o) || 0 });
      }
      quietUntil = Number(saved.quietUntil) || 0;
    } else {
      for (const [p, until] of Object.entries(saved || {})) {
        if (Number(until) > now) cooling.set(p, Number(until));
      }
    }
  } catch {
    /* 没有落盘就从零开始 */
  }
  const saveCooling = () => {
    const now = Date.now();
    const proxies = {};
    const ips = {};
    const pin = {};
    for (const [p, until] of cooling) if (until > now) proxies[p] = until;
    for (const [ip, until] of coolingIps) if (until > now) ips[ip] = until;
    for (const [p, ip] of proxyIps) pin[p] = ip;
    const stats = {};
    for (const [ip, st] of ipStats) stats[ip] = st;
    fs.writeFileSync(coolFile, `${JSON.stringify({ proxies, ips, proxyIps: pin, ipStats: stats, quietUntil }, null, 0)}\n`);
  };
  // 零成本入口校验：从没出过号、且试够多次的出口直接拉黑，不再烧 captcha。
  const deadIp = (ip) => {
    const st = ipStats.get(ip);
    return !!st && st.o === 0 && st.t >= 3;
  };
  const bumpStat = (ip, ok) => {
    if (!ip) return;
    const st = ipStats.get(ip) || { t: 0, o: 0 };
    st.t += 1;
    if (ok) st.o += 1;
    ipStats.set(ip, st);
  };
  const freeProxies = () => {
    const now = Date.now();
    return proxyPool.filter((p) => {
      if (inUse.has(p) || (cooling.get(p) || 0) > now) return false;
      const ip = proxyIps.get(p);
      if (ip && (coolingIps.get(ip) || 0) > now) return false;
      return true;
    });
  };
  const probeExitIp = async (proxy) => {
    if (!proxy) return '';
    if (proxyIps.has(proxy)) return proxyIps.get(proxy);
    const s = new Session({ proxy, timeout: 8 });
    try {
      const r = await s.get('https://api.ipify.org', { timeout: 8 });
      const ip = String(r.text || '').trim();
      if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
        proxyIps.set(proxy, ip);
        return ip;
      }
    } catch {
      /* 探活失败当口废 */
    } finally {
      s.close();
    }
    return '';
  };
  const claimProxy = async () => {
    const now = Date.now();
    for (const p of proxyPool) {
      if (inUse.has(p) || (cooling.get(p) || 0) > now) continue;
      const known = proxyIps.get(p);
      if (known && (coolingIps.get(known) || 0) > now) {
        cooling.set(p, coolingIps.get(known));
        continue;
      }
      if (known && deadIp(known)) {
        cooling.set(p, now + 24 * 60 * 60 * 1000);
        continue;
      }
      inUse.add(p);
      const ip = await probeExitIp(p);
      if (!ip) {
        coolProxy(p, '探活失败');
        continue;
      }
      const ipUntil = coolingIps.get(ip) || 0;
      if (ipUntil > Date.now()) {
        inUse.delete(p);
        cooling.set(p, ipUntil);
        saveCooling();
        log(`跳过 ${p}，出口 ${ip} 仍在冷却 ${Math.ceil((ipUntil - Date.now()) / 1000)}s`);
        continue;
      }
      if (deadIp(ip)) {
        inUse.delete(p);
        const st = ipStats.get(ip);
        cooling.set(p, Date.now() + 24 * 60 * 60 * 1000);
        saveCooling();
        log(`跳过 ${p}，出口 ${ip} 战绩 ${st.o}/${st.t}（0 成功），拉黑 24h`);
        continue;
      }
      return p;
    }
    if (!proxyPool.length) return null;
    const waits = [...cooling.values(), ...coolingIps.values()].filter((t) => t > Date.now());
    const until = waits.length ? Math.min(...waits) : 0;
    const p = [...cooling.entries()].sort((a, b) => a[1] - b[1])[0]?.[0] || '';
    return { waitProxy: p, wait: Math.max(0, until - Date.now()) };
  };
  const coolProxy = (proxy, why, ms = cooldownMs) => {
    if (!proxy) return;
    inUse.delete(proxy);
    const until = Date.now() + ms;
    cooling.set(proxy, until);
    const ip = proxyIps.get(proxy);
    if (ip) coolingIps.set(ip, Math.max(coolingIps.get(ip) || 0, until));
    saveCooling();
    log(`${why}，冷却 ${Math.round(ms / 60000)}min: ${proxy}${ip ? ` ip=${ip}` : ''}（剩余可用 ${freeProxies().length}/${proxyPool.length}）`);
  };

  if (quietUntil > Date.now()) {
    log(`FAST 冷静中，${Math.ceil((quietUntil - Date.now()) / 1000)}s 后再跑`);
    return 0;
  }
  if (proxyPool.length && freeProxies().length === 0) {
    const waits = [...cooling.values(), ...coolingIps.values()].filter((t) => t > Date.now());
    const until = waits.length ? Math.min(...waits) : 0;
    log(`所有 IP 仍在冷却（proxy=${cooling.size} ip=${coolingIps.size}，最早 ${until ? Math.ceil((until - Date.now()) / 1000) : 0}s），本轮不跑`);
    return 0;
  }
  count = Math.min(count, Math.max(freeProxies().length, 1));

  const worker = (i) =>
    sem(async () => {
      // 每次尝试都重新挑一个没冷却、没在用的出口
      for (let attempt = 0; attempt < 3; attempt++) {
        let pick = await claimProxy();
        if (pick && pick.waitProxy) {
          // 一口一号：本轮口用完就结束，把 1h 留给 hourly 的 sleep，别卡在 node 里
          log(`[${i}] 所有 IP 冷却中（最早 ${pick.waitProxy} ${Math.ceil(pick.wait / 1000)}s），跳过本号`);
          failures.push(i);
          return;
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
          bumpStat(proxyIps.get(proxy), true);
          fs.appendFileSync(LEDGER, `${JSON.stringify(res)}\n`);
          const credLine = res.credential_line || `${res.email} | ${res.password} | ${res.api_key} | ${res.created_at}`;
          fs.appendFileSync(CREDS, `${credLine}\n`);
          coolProxy(proxy, `[${i}] 出号`);
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
          bumpStat(proxyIps.get(proxy), false);
          if (e.ipCooldown && proxy) {
            const msg0 = e.message || '';
            const bad = /not supported/i.test(msg0);
            const fast = /bit fast/i.test(msg0);
            const nope = /couldn't create/i.test(msg0);
            if (fast) quietUntil = Math.max(quietUntil, Date.now() + quietMs);
            // 1 小时（用户定的）；硬封 only not supported 才长封。
            // 真正死掉的口交给 ipStats（0 成功且试>=3 → 拉黑 24h）。
            const ms = bad ? cooldownMs * 12 : cooldownMs;
            coolProxy(proxy, `[${i}] 站点限流`, ms);
            break;
          }
          const msg = String(e.message);
          if (proxy && /no link for|TLS|socket disconnected|timeout after/i.test(msg)) {
            coolProxy(proxy, `[${i}] 口已废`);
            break;
          }
          if (proxy) inUse.delete(proxy);
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
