/**
 * 50x target 的离线单测：链接解析 + key 提取 + CPA auth 文件。不联网。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  extractVerifyToken,
  findKey,
  sanitizeUid,
  buildCpaAuthFile,
} from '../targets/50x.js';

test('extractVerifyToken: 前端链接 / 原始 token', () => {
  const tok = 'eyJ1IjozMTU5LCJlIjoiYS1iQGNkLmNvbSJ9:1xSSJQ:Dteo1MibuEJ-6JTk8UVCkeALuSei17';
  assert.equal(extractVerifyToken(`https://ai.50x.energy/?verify=${tok}&x=1`), tok);
  assert.equal(extractVerifyToken(`https://ai.50x.energy/?a=1&verify=${tok}`), tok);
  assert.throws(() => extractVerifyToken('https://ai.50x.energy/'));
});

test('findKey: 淘宝式递归', () => {
  const k = 'sk-50x-VHG4ImYitK-cd-__xRHPmCLYPDRq5PGEBI-HswbDEVk';
  assert.equal(findKey({ api_key: k }), k);
  assert.equal(findKey({ prefix: 'sk-50x-VHG4', data: [{ api_key: k }] }), k);
  assert.equal(findKey({ prefix: 'sk-50x-VHG4' }), '', '前缀不能当完整 key');
});

test('buildCpaAuthFile: type/provider/accessToken/domain', () => {
  const { fileName, body } = buildCpaAuthFile({
    email: 'nessa+abc@outlook.com',
    password: 'pw',
    api_key: 'sk-50x-abc',
  });
  assert.match(fileName, /^50x-nessa_abc_outlook_com\.json$/);
  assert.equal(body.type, '50x');
  assert.equal(body.provider, '50x');
  assert.equal(body.auth.accessToken, 'sk-50x-abc');
  assert.equal(body.auth.domain, 'https://api.ai.50x.energy/v1');
  assert.equal(body.account.email, 'nessa+abc@outlook.com');
});

test('sanitizeUid: 空/点拒绝', () => {
  assert.equal(sanitizeUid('..'), '');
  assert.equal(sanitizeUid(''), '');
  assert.equal(sanitizeUid('a+b@c.d'), 'a_b_c_d');
});
