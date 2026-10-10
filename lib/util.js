/**
 * lib/util.js — 通用工具（无业务依赖）
 */

import fs from 'node:fs';
import crypto from 'node:crypto';

const wibFmt = new Intl.DateTimeFormat('sv-SE', {
  timeZone: 'Asia/Jakarta',
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

/** Python datetime.now(WIB).strftime("%Y-%m-%d %H:%M:%S WIB") */
export const wibNow = () => `${wibFmt.format(new Date())} WIB`;

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Python random.uniform(a, b) */
export const uniform = (a, b) => a + Math.random() * (b - a);

/** Python time.monotonic() */
export const monotonic = () => performance.now() / 1000;

export function log(m) {
  console.log(`[${wibNow()}] ${m}`);
}

/** Python gen_password(16) */
export function genPassword(n = 16) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
  return Array.from({ length: n }, () => alphabet[crypto.randomInt(alphabet.length)]).join('');
}

/** Python asyncio.Semaphore 的等价实现。 */
export function makeSemaphore(n) {
  let active = 0;
  const queue = [];
  return async (fn) => {
    if (active >= n) await new Promise((r) => queue.push(r));
    active++;
    try {
      return await fn();
    } finally {
      active--;
      queue.shift()?.();
    }
  };
}

/** 读文本文件，按行 trim + 去空行。文件不存在返回 []。 */
export function readLines(file) {
  if (!file || !fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}
