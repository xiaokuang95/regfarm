/**
 * lib/mailbox.js — 临时邮箱池（多 provider 轮询）
 *
 * 轮询而非固定：每个 task 从不同 provider 起头，避免 rate-limit
 * 在同一个 base/domain 上堆积。
 */

import { EmailBox } from './mail_providers.js';
import { log as defaultLog } from './util.js';

export function createMailboxPool({ prefer, log = defaultLog }) {
  if (!Array.isArray(prefer) || prefer.length === 0) {
    throw new Error('createMailboxPool: prefer 不能为空');
  }
  const state = { i: 0, prefer: [...prefer] };

  return {
    /** 固定单个 provider（--mail-provider）。 */
    pin(name) {
      state.prefer = [name];
      state.i = 0;
    },

    /** Round-robin：返回从第 i 个开始的完整列表。 */
    rotated() {
      const list = state.prefer;
      const i = state.i % list.length;
      state.i += 1;
      return [...list.slice(i), ...list.slice(0, i)];
    },

    /** 建一个 mailbox（走轮询顺序，失败自动 fallback）。 */
    async open() {
      const box = new EmailBox(this.rotated());
      const addr = await box.create_account();
      log(`  mail provider=${box.provider_name} addr=${addr}`);
      return box;
    },
  };
}

/** 等 OTP；tries 是「逻辑次数」，实际超时 = tries * 1.5 秒。 */
export async function pollOtp(box, tries = 30) {
  const code = await box.wait_code(Math.round(tries * 1.5));
  if (!code) throw new Error('OTP tidak masuk');
  return code;
}
