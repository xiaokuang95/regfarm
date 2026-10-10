/**
 * alysis-code target 的离线单测：确认链接解析 + Supabase 错误翻译 + 邮件取链接。
 * 不联网、不开浏览器。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { parseConfirmLink, sanitizeUid, buildCpaAuthFile } from '../targets/alysis-code.js';
import { extractLink } from '../lib/mail_providers.js';

test('parseConfirmLink: 普通（非 PKCE）确认链接', () => {
  const url =
    'https://alysiscode.com/auth/confirm#token_hash=2d14ac98688a07acfcedde428bb3f80b&type=email';
  assert.deepEqual(parseConfirmLink(url), {
    tokenHash: '2d14ac98688a07acfcedde428bb3f80b',
    type: 'email',
  });
});

test('parseConfirmLink: PKCE 链接（pkce_ 前缀要原样带出）', () => {
  const url = 'https://alysiscode.com/auth/confirm#token_hash=pkce_f121f463cd9a&type=email';
  const got = parseConfirmLink(url);
  assert.equal(got.tokenHash, 'pkce_f121f463cd9a');
  assert.equal(got.type, 'email');
});

test('parseConfirmLink: 缺 type 时默认 email', () => {
  assert.equal(parseConfirmLink('https://x/y#token_hash=abc').type, 'email');
});

test('parseConfirmLink: 没有 token_hash 要抛错', () => {
  assert.throws(
    () => parseConfirmLink('https://alysiscode.com/auth/confirm#type=email'),
    /token_hash/,
  );
});

test('parseConfirmLink: 链接在 ?query 里也能解析', () => {
  assert.equal(parseConfirmLink('https://x/y?token_hash=zzz&type=email').tokenHash, 'zzz');
});

test('extractLink: 从 HTML 里取链接并还原 &amp;', () => {
  const html = '<a href="https://alysiscode.com/auth/confirm#token_hash=aa&amp;type=email">go</a>';
  assert.equal(
    extractLink(html),
    'https://alysiscode.com/auth/confirm#token_hash=aa&type=email',
  );
});

test('extractLink: pattern 为字符串时按包含匹配', () => {
  const blob = 'https://alysiscode.com/email-owl.png then https://alysiscode.com/auth/confirm#token_hash=bb';
  assert.equal(extractLink(blob, '/auth/confirm'), 'https://alysiscode.com/auth/confirm#token_hash=bb');
});

test('extractLink: pattern 为正则时匹配', () => {
  const blob = 'see https://x.test/a and https://x.test/auth/confirm#token_hash=cc';
  assert.equal(extractLink(blob, /token_hash=/), 'https://x.test/auth/confirm#token_hash=cc');
});

test('extractLink: 带 /g 的正则不会因 lastIndex 泄漏而漏匹配', () => {
  const blob = 'https://x.test/auth/confirm#token_hash=dd';
  const g = /token_hash=/g;
  assert.equal(extractLink(blob, g), 'https://x.test/auth/confirm#token_hash=dd');
  assert.equal(extractLink(blob, g), 'https://x.test/auth/confirm#token_hash=dd', '第二次调用应一致');
});

test('extractLink: 没有链接返回 null', () => {
  assert.equal(extractLink('no links here'), null);
  assert.equal(extractLink(''), null);
  assert.equal(extractLink('https://x.test/a', /nope/), null);
});

test('extractLink: 剥掉结尾的句号/逗号', () => {
  assert.equal(extractLink('Go to https://x.test/a.'), 'https://x.test/a');
});

test('sanitizeUid: 去掉路径字符', () => {
  assert.equal(sanitizeUid('../etc/passwd'), '_etc_passwd');
  assert.equal(sanitizeUid('277cbc36-5611-49ff-9966-c8b6eba3eb26').length, 36);
});

test('buildCpaAuthFile: slk_ + sessionRefresh', () => {
  const { fileName, body } = buildCpaAuthFile({
    user_id: '277cbc36-5611-49ff-9966-c8b6eba3eb26',
    email: 'a@b.com',
    api_key: 'slk_abc',
    refresh_token: 'rt_1',
    gateway_base_url: 'https://x/llm/v1',
  });
  assert.equal(fileName, 'alysis-277cbc36-5611-49ff-9966-c8b6eba3eb26.json');
  assert.equal(body.type, 'alysis');
  assert.equal(body.auth.accessToken, 'slk_abc');
  assert.equal(body.auth.sessionRefresh, 'rt_1');
  assert.equal(body.account.email, 'a@b.com');
});
