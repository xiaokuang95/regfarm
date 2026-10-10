/**
 * tokenharbor target 的离线单测：Server Action 引用提取 + body 拼装 + flight 响应解析。
 * 不联网。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSignupBody,
  parseActionRef,
  extractSignupError,
  extractUserId,
  config,
} from '../targets/tokenharbor.js';

const BOUNDARY = '----WebKitFormBoundaryTESTBOUNDARY1';
const FINGERPRINT = '11111111-2222-3333-4444-555555555555';
const ACTION_ID = '607164493180ce5d8eb93f6872116b22c3f4433e02';
const ACTION_KEY = 'kb3df6a1d48e1a01307dd1ff043d81c6e';

/** 真页面上的 no-JS 表单片段（HTML 属性是 &quot; 编码的）。 */
const LOGIN_HTML = `
<form class="space-y-4" action="" encType="multipart/form-data" method="POST">
  <input type="hidden" name="$ACTION_1:0" value="{&quot;id&quot;:&quot;${ACTION_ID}&quot;,&quot;bound&quot;:&quot;$@1&quot;}"/>
  <input type="hidden" name="$ACTION_1:1" value="[&quot;$undefined&quot;]"/>
  <input type="hidden" name="$ACTION_KEY" value="${ACTION_KEY}"/>
  <input type="hidden" name="device_fingerprint" value=""/>
  <input type="email" name="email"/>
</form>`;

const ref = () => parseActionRef(LOGIN_HTML);

const build = (o = {}) =>
  buildSignupBody('a@b.com', 'pw!Aa1', ref(), {
    boundary: BOUNDARY,
    fingerprint: FINGERPRINT,
    ...o,
  });

/** 把 body 拆成 [{name, value}]，顺带验证 CRLF 结构完整。 */
function fields(body) {
  assert.ok(body.startsWith(`--${BOUNDARY}\r\n`), 'body 要以首个 boundary 开头');
  assert.ok(body.endsWith(`--${BOUNDARY}--\r\n`), 'body 要以闭合 boundary 结尾');
  return body
    .slice(0, -`--${BOUNDARY}--\r\n`.length)
    .split(`--${BOUNDARY}\r\n`)
    .slice(1)
    .map((chunk) => {
      const [head, ...rest] = chunk.split('\r\n\r\n');
      const name = /name="([^"]+)"/.exec(head)[1];
      return { name, value: rest.join('\r\n\r\n').replace(/\r\n$/, '') };
    });
}

test('parseActionRef: 抠出 action id / key / bound', () => {
  const got = ref();
  assert.equal(got.actionId, ACTION_ID);
  assert.equal(got.actionKey, ACTION_KEY);
  assert.deepEqual(JSON.parse(got.actionRef), { id: ACTION_ID, bound: '$@1' });
});

test('parseActionRef: 反转义 &quot;，actionRef 直接就是合法 JSON', () => {
  assert.ok(!ref().actionRef.includes('&quot;'));
  assert.equal(JSON.parse(ref().actionRef).bound, '$@1');
});

test('parseActionRef: 页面改版/抠不到就报错（不拿写死的值兜底）', () => {
  assert.throws(() => parseActionRef('<html>no form here</html>'), /找不到 Server Action 引用/);
  assert.throws(
    () => parseActionRef(LOGIN_HTML.replace(/\$ACTION_KEY/, '$ACTION_KEY_X')),
    /找不到 Server Action 引用/,
  );
});

test('parseActionRef: id 不是 JSON 时报错', () => {
  const broken = LOGIN_HTML.replace(/value="\{[^"]*\}"\/>/, 'value="not-json"/>');
  assert.throws(() => parseActionRef(broken), /不是合法 JSON/);
});

test('buildSignupBody: 字段名与顺序跟 Python 版一致', () => {
  const names = fields(build().body).map((f) => f.name);
  assert.deepEqual(names, [
    '1_$ACTION_REF_1',
    '1_$ACTION_1:0',
    '1_$ACTION_1:1',
    '1_$ACTION_KEY',
    '1_device_fingerprint',
    '1_timezone',
    '1_next',
    '1_email',
    '1_password',
    '1_invite_code',
    '0',
  ]);
});

test('buildSignupBody: 空字段也要发（少一个服务端当缺参数）', () => {
  const byName = Object.fromEntries(fields(build().body).map((f) => [f.name, f.value]));
  assert.equal(byName['1_timezone'], 'Asia/Shanghai');
  assert.equal(byName['1_next'], '');
  assert.equal(byName['1_invite_code'], '');
  assert.equal(byName['1_$ACTION_REF_1'], '');
  assert.equal(byName['0'], '["$undefined","$K1"]');
  assert.equal(byName['1_$ACTION_1:1'], '["$undefined"]');
});

test('buildSignupBody: action 引用原样进 body', () => {
  const byName = Object.fromEntries(fields(build().body).map((f) => [f.name, f.value]));
  assert.deepEqual(JSON.parse(byName['1_$ACTION_1:0']), { id: ACTION_ID, bound: '$@1' });
  assert.equal(byName['1_$ACTION_KEY'], ACTION_KEY);
});

test('buildSignupBody: email / password / 指纹落在正确字段上', () => {
  const byName = Object.fromEntries(fields(build().body).map((f) => [f.name, f.value]));
  assert.equal(byName['1_email'], 'a@b.com');
  assert.equal(byName['1_password'], 'pw!Aa1');
  assert.equal(byName['1_device_fingerprint'], FINGERPRINT);
});

test('buildSignupBody: captcha 字段在 0/$K1 之前（放后面 FormData 收不到）', () => {
  const names = fields(build({ captchaToken: 'tok123' }).body).map((f) => f.name);
  assert.ok(names.includes('1_cf-turnstile-response'));
  assert.ok(!names.includes('cf-turnstile-response'));
  assert.ok(names.indexOf('1_cf-turnstile-response') < names.indexOf('0'));
});

test('buildSignupBody: 不传 boundary 时生成 WebKit 形状的随机 boundary', () => {
  const { body, boundary } = buildSignupBody('a@b.com', 'pw', ref());
  assert.match(boundary, /^----WebKitFormBoundary[A-Z0-9]{16}$/);
  assert.ok(body.includes(`--${boundary}\r\n`), 'body 要用生成的 boundary');
  assert.notEqual(
    buildSignupBody('a@b.com', 'pw', ref()).boundary,
    boundary,
    '两次调用 boundary 应不同',
  );
});

test('extractSignupError: 只认 action 返回行，不误伤 RSC', () => {
  assert.equal(
    extractSignupError('0:{"a":"$@1"}\n1:{"error":"Email already registered","needCaptcha":true}\n'),
    'Email already registered',
  );
  assert.equal(extractSignupError('0:{"a":1}'), null);
  assert.equal(
    extractSignupError('1:I[195237,["/x.js"],"Loading"]\n3:"$Sreact.fragment"'),
    null,
  );
});

test('extractUserId: 抠 userId，没有就空串', () => {
  assert.equal(
    extractUserId('{"userId": "08efd3d5-efd1-45b1-90fa-729ecba81988"}'),
    '08efd3d5-efd1-45b1-90fa-729ecba81988',
  );
  assert.equal(extractUserId('{"signedIn":true}'), '');
});

test('config: 邮箱源必须支持 wait_link（确认信是链接）', () => {
  // 只有实现了 _iter_messages 的 provider 能用 wait_link，列错了会白等到超时
  const linkCapable = new Set(['mail.tm', 'tempmail.lol', 'temp-mail.io']);
  for (const name of config.mailPrefer) {
    assert.ok(linkCapable.has(name), `${name} 不支持 wait_link`);
  }
  assert.match(config.verifyLinkPattern.source, /tokenharbor/);
});
