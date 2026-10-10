/**
 * lib/http.js 离线单测：cookie jar 与 TLS profile 形状。
 * 不联网。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { CookieJar, CHROME_TLS, DEFAULT_UA } from '../lib/http.js';

test('CookieJar 存/取 Set-Cookie 首个 k=v 对', () => {
  const jar = new CookieJar();
  jar.store(['XSRF-TOKEN=eyJhbGciOi; expires=Wed, 01 Oct 2026 00:00:00 GMT; path=/; samesite=lax'], 'www.emailnator.com');
  assert.equal(jar.get('XSRF-TOKEN'), 'eyJhbGciOi');
});

test('CookieJar 忽略无等号的畸形 Set-Cookie', () => {
  const jar = new CookieJar();
  jar.store(['garbage-without-equals', '=novalue', 'ok=1'], 'example.com');
  assert.equal(jar.get('ok'), '1');
  assert.equal(jar.get('garbage-without-equals'), undefined);
});

test('CookieJar 按 host 隔离，域 cookie 对子域可见', () => {
  const jar = new CookieJar();
  jar.store(['a=1'], 'example.com');
  jar.store(['a=2'], 'other.com');
  assert.equal(jar.get('a', 'example.com'), '1');
  assert.equal(jar.get('a', 'other.com'), '2');
  assert.equal(jar.get('a', 'sub.example.com'), '1', '子域应能读到父域 cookie');
  assert.equal(jar.get('a', 'nope.com'), undefined);
});

test('CookieJar.header 只输出匹配 host 的 cookie', () => {
  const jar = new CookieJar();
  jar.store(['a=1', 'b=2'], 'example.com');
  jar.store(['c=3'], 'other.com');
  const h = jar.header('example.com').split('; ').sort();
  assert.deepEqual(h, ['a=1', 'b=2']);
  assert.equal(jar.header('unknown.com'), '');
});

test('CHROME_TLS 关键字段形状正确', () => {
  assert.match(CHROME_TLS.ciphers, /^ECDHE-ECDSA-AES128-GCM-SHA256:/);
  assert.match(CHROME_TLS.sigalgs, /^ecdsa_secp256r1_sha256:/);
  assert.equal(CHROME_TLS.ecdhCurve, 'X25519:P-256:P-384');
  assert.equal(CHROME_TLS.minVersion, 'TLSv1.2');
  assert.equal(CHROME_TLS.maxVersion, 'TLSv1.3');
  assert.deepEqual(CHROME_TLS.ALPNProtocols, ['http/1.1']);
});

test('DEFAULT_UA 是 Chrome 136', () => {
  assert.match(DEFAULT_UA, /Chrome\/136\./);
});
