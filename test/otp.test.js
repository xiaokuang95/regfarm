/**
 * OTP 提取回归测试。
 *
 * 期望值来自 Python 原版 mail_providers._extract_code 的实跑输出
 * （差分验证：28/28 与 JS 版一致，2026-10-01）。
 * 任何一个 case 改动都说明正则分支被改坏了。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { extractCode } from '../lib/mail_providers.js';

const CASES = [
  // [输入, 期望输出, 覆盖分支]
  ['Your confirmation code: HPN-7Z9', 'HPN-7Z9', 'hyphen labeled'],
  ['confirmation code: DIR-TOP', null, 'hyphen 命中 SKIP_HYPHEN'],
  ['code: AX3BBY', 'AX3BBY', 'legacy 6-char alnum'],
  ['123456 is your verification code', '123456', 'code-first'],
  ['Your verification code is 654321', '654321', 'code-is'],
  ['Your OTP: 998877', '998877', 'digit6 labeled'],
  [
    'Unleash the power of AI tools! Visit our directory of online resources.',
    null,
    '广告过滤（无 xAI 上下文）',
  ],
  ['Your one-time password: 112233', '112233', 'one-time password'],
  ['sign-up for our newsletter', null, '无验证码'],
  ['Subject: Your verification code\n\nUse 445566 to continue', null, '只有 subject 且无数字'],
  ['Subject: Your OTP is 778899', '778899', 'subject fallback'],
  ['confirmation code: ABC-=\r\n123', 'ABC-123', 'quoted-printable 软换行'],
  ['AI tools newsletter: xAI confirmation code: ZZZ-999', 'ZZZ-999', '广告词 + xAI 上下文 → 不判广告'],
  ['code: SIGNUP', null, 'legacy 命中 SKIP_LEGACY'],
  ['code: 123456', null, '纯数字 legacy 无 xAI 上下文 → 拒绝'],
  ['confirmation code: 123456', '123456', '纯数字 legacy + confirmation 上下文'],
  ['verification code is 111111 and confirmation code: BBB-222', '111111', '多码取先出现的'],
  ['', null, '空输入'],
  ['Hello world, no code here.', null, '无码'],
  ['Your SpacexAI code is 909090', null, '有 xAI 上下文但无匹配分支'],
  [
    '<html><body><h1>xAI</h1><p>Your confirmation code: K7M-2QX</p><p>This code expires in 10 minutes.</p></body></html>',
    'K7M-2QX',
    'HTML 正文',
  ],
  [
    'Emailnator - Disposable Gmail temp mail. Unleash the power of AI tools.',
    null,
    '广告过滤（Emailnator 自有广告）',
  ],
  ['temp mail directory of online tools', null, '广告过滤（纯广告词）'],
  ['confirmation code: HPN-7Z9 and later confirmation code: XXX-111', 'HPN-7Z9', '多码取先出现的'],
  ['one-time passcode: 246810', '246810', 'one-time passcode'],
  ['OTP#445566', '445566', 'OTP# 分隔符'],
  ['Set-up your account today', null, 'SKIP_HYPHEN 词形'],
  ['xAI validation code: QQQ-888', 'QQQ-888', 'validation code'],
];

for (const [input, expected, branch] of CASES) {
  test(`extractCode: ${branch}`, () => {
    assert.equal(extractCode(input), expected, `输入: ${JSON.stringify(input)}`);
  });
}

test('extractCode 对非字符串输入不抛异常', () => {
  assert.equal(extractCode(''), null);
  assert.equal(extractCode(null), null);
  assert.equal(extractCode(undefined), null);
});

test('extractCode 可重复调用（正则 lastIndex 不泄漏）', () => {
  const blob = 'Your confirmation code: HPN-7Z9';
  for (let i = 0; i < 5; i++) assert.equal(extractCode(blob), 'HPN-7Z9');
});
