#!/usr/bin/env node
/**
 * cli.js — 注册任务框架入口
 *
 * 用法：
 *   regfarm --target <name> --count 12 --proxy-file proxies.txt
 *   regfarm --list
 *
 * 新增一个注册目标 = 往 targets/ 丢一个 .js 文件，不用改本文件。
 * 目标模块契约见 docs/architecture.md，照 targets/top-tools-ai.js 抄。
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

import './lib/env.js';
import { run } from './lib/runner.js';
import { log, wibNow, readLines } from './lib/util.js';

const TARGETS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'targets');

/** 目标模块必须导出这三个东西，缺一个就是接错了。 */
const REQUIRED_EXPORTS = ['config', 'registerOne', 'createMailbox'];

/** 扫描 targets/，文件名即 target 名。 */
async function loadTargets() {
  const targets = {};
  const files = fs
    .readdirSync(TARGETS_DIR)
    .filter((f) => f.endsWith('.js'))
    .sort();
  for (const f of files) {
    const mod = await import(pathToFileURL(path.join(TARGETS_DIR, f)).href);
    for (const key of REQUIRED_EXPORTS) {
      if (!mod[key]) throw new Error(`target 模块 targets/${f} 缺少导出: ${key}`);
    }
    targets[f.slice(0, -3)] = mod;
  }
  return targets;
}

function listTargets(targets) {
  const names = Object.keys(targets);
  if (!names.length) {
    console.log(`targets/ 目录下没有可用的 target 模块。`);
    return;
  }
  console.log('可用 target：\n');
  for (const [name, t] of Object.entries(targets)) {
    const c = t.config;
    console.log(`  ${name}`);
    console.log(`    站点   : ${c.baseUrl}`);
    console.log(`    solver : ${c.solverUrl}`);
    console.log(`    输出   : ${c.outDir}`);
    console.log();
  }
}

async function main() {
  const { values: v } = parseArgs({
    options: {
      target: { type: 'string' },
      count: { type: 'string', default: '1' },
      'delay-min': { type: 'string', default: '25.0' },
      'delay-max': { type: 'string', default: '45.0' },
      conc: { type: 'string', default: '1' },
      'proxy-file': { type: 'string' },
      'mail-provider': { type: 'string' },
      'out-dir': { type: 'string' },
      list: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: false,
  });

  if (v.help) {
    console.log(`用法: regfarm [选项]

  --target <name>       注册目标（--list 看全部；只有一个时可省略）
  --list                列出可用 target
  --count <n>           任务数（默认 1）
  --conc <n>            并发（默认 1；服务端按 IP 限流，别开大）
  --delay-min <s>       任务间隔下限秒（默认 25）
  --delay-max <s>       任务间隔上限秒（默认 45）
  --proxy-file <path>   代理列表，每行一个（http:// 或 socks5://）
  --mail-provider <n>   固定单个邮箱源（默认轮询全部）
  --out-dir <path>      输出目录（默认取 target 配置）
  --list / -h`);
    return 0;
  }

  const targets = await loadTargets();

  if (v.list) {
    listTargets(targets);
    return 0;
  }

  const names = Object.keys(targets);
  let targetName = v.target;
  if (!targetName) {
    if (names.length === 1) {
      targetName = names[0];
    } else {
      throw new Error(
        `targets/ 下有 ${names.length} 个目标，必须用 --target 指定：${names.join(', ')}`,
      );
    }
  }
  const target = targets[targetName];
  if (!target) {
    throw new Error(`未知 target: ${targetName}（可用: ${names.join(', ')}）`);
  }

  const cfg = target.config;
  const outDir = v['out-dir'] || cfg.outDir;

  let proxyPool = [];
  if (v['proxy-file']) {
    if (!fs.existsSync(v['proxy-file'])) {
      throw new Error(`proxy-file 不存在: ${v['proxy-file']}`);
    }
    proxyPool = readLines(v['proxy-file']);
    log(`proxy pool: ${proxyPool.length} entry`);
  }

  console.log(`
╔══════════════════════════════════════════════════════════╗
║  REGFARM · ${targetName.padEnd(46)}║
╚══════════════════════════════════════════════════════════╝
  waktu   : ${wibNow()}
  target  : ${targetName}
  site    : ${cfg.baseUrl}
  solver  : ${cfg.solverUrl}
  count   : ${v.count} · conc=${v.conc} · delay=${v['delay-min']}-${v['delay-max']}s
  proxy   : ${proxyPool.length || 'none'}
  out     : ${outDir}
`);

  return run({
    target,
    count: Number(v.count),
    delayMin: Number(v['delay-min']),
    delayMax: Number(v['delay-max']),
    conc: Number(v.conc),
    proxyPool,
    outDir,
    mailProvider: v['mail-provider'] || null,
  });
}

process.exit(await main());
