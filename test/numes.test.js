/**
 * numes target 的离线单测：HTML 解析 + 建 key 请求体 + CPA auth 文件。
 * 不联网。
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  extractRegistrationPath,
  extractFormAction,
  registrationOutcome,
  extractCsrf,
  extractActiveAccountId,
  buildKeyBody,
  findKey,
  sanitizeUid,
  buildCpaAuthFile,
} from '../targets/numes.js';

const LOGIN_HTML = `
<div id="kc-social-providers"></div>
<form id="kc-form-login" action="https://auth.numes.ai/realms/numes/login-actions/authenticate?session_code=x&amp;execution=y"></form>
<a href="/realms/numes/login-actions/registration?client_id=numes-web&amp;tab_id=abc&amp;client_data=zzz">Create an account</a>
`;

const REG_HTML = `
<form id="kc-register-form" action="https://auth.numes.ai/realms/numes/login-actions/registration?session_code=s1&amp;execution=e1" method="post">
  <input name="firstName"><input name="lastName"><input name="email">
  <div class="cf-turnstile" data-sitekey="0x4AAAAAAFLWEC7CNO3A8O1H" data-action="register"></div>
</form>
`;

const PASSWORD_HTML = `
<form action="https://auth.numes.ai/realms/numes/login-actions/required-action?session_code=s2&amp;execution=e2" method="post">
  <input id="password-new" name="password-new"><input id="password-confirm" name="password-confirm">
</form>
`;

// SSR 里的真实形态：csrfToken\":\"…\"（反斜杠是 JSON 转义）
const DASH_HTML = String.raw`<script>{"csrfToken\":\"NkMyNmcfOwAgaSjFwdglb0oqMkg8MshmfAjhhCUKtPs\"}</script>
<script>{"accounts":{"active_account_id":"0a6d8b2e-c215-448d-8ca5-199ceee7d901","data":[]}}</script>`;

test('extractRegistrationPath: 还原 &amp;', () => {
  const p = extractRegistrationPath(LOGIN_HTML);
  assert.match(p, /^\/realms\/numes\/login-actions\/registration\?/);
  assert.match(p, /tab_id=abc/);
  assert.ok(!p.includes('&amp;'));
});

test('extractFormAction: 按片段挑表单，还原 &amp;', () => {
  assert.match(
    extractFormAction(REG_HTML, '/login-actions/registration'),
    /session_code=s1&execution=e1$/,
  );
  assert.match(
    extractFormAction(PASSWORD_HTML, '/login-actions/required-action'),
    /session_code=s2&execution=e2$/,
  );
  assert.throws(() => extractFormAction(LOGIN_HTML, '/nope'), /没有 action/);
});

test('registrationOutcome: 成功与失败', () => {
  assert.equal(registrationOutcome('<p>Check your email</p>').ok, true);
  const bad = registrationOutcome('<span class="kc-feedback-text">Email already exists</span>');
  assert.equal(bad.ok, false);
  assert.match(bad.message, /already exists/);
  assert.equal(registrationOutcome('<html></html>').ok, false);
});

test('extractCsrf / extractActiveAccountId: 带 JSON 转义也能取', () => {
  assert.equal(extractCsrf(DASH_HTML), 'NkMyNmcfOwAgaSjFwdglb0oqMkg8MshmfAjhhCUKtPs');
  assert.equal(extractActiveAccountId(DASH_HTML), '0a6d8b2e-c215-448d-8ca5-199ceee7d901');
  assert.throws(() => extractCsrf('<html></html>'), /csrfToken/);
  assert.throws(() => extractActiveAccountId('<html></html>'), /active_account_id/);
});

test('buildKeyBody: 无限额推理 key', () => {
  assert.deepEqual(buildKeyBody('n1'), {
    name: 'n1',
    kind: 'inference',
    billing_currency: 'USD',
    limit: null,
    limit_reset: null,
  });
});

test('findKey: 只认真 key，不抓掩码标签', () => {
  const real = 'sk-numes-v1-' + 'a1'.repeat(32);
  const masked = 'sk-numes-v1-a1a1...a1a1';
  assert.equal(findKey({ data: { label: masked, key: real } }), real);
  assert.equal(findKey({ items: [{ secret: masked }, { secret: real }] }), real);
  assert.equal(findKey({ label: masked }), '');
  assert.equal(findKey({ nope: 'thk_live_x' }), '');
});

test('buildCpaAuthFile: 结构对齐插件 parseStored', () => {
  const { fileName, body } = buildCpaAuthFile({
    account_id: '0a6d8b2e-c215-448d-8ca5-199ceee7d901',
    email: 'a@b.c',
    password: 'pw',
    api_key: 'sk-numes-v1-zzz',
  });
  assert.equal(fileName, 'numes-0a6d8b2e-c215-448d-8ca5-199ceee7d901.json');
  assert.equal(body.type, 'numes');
  assert.equal(body.auth.accessToken, 'sk-numes-v1-zzz');
  assert.equal(body.auth.domain, 'https://api.numes.ai/api/v1');
  assert.equal(body.account.email, 'a@b.c');
  assert.equal(sanitizeUid('../etc'), '_etc');
});
