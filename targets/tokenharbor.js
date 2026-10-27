/**
 * targets/tokenharbor.js — 注册目标：tokenharbor.ai
 *
 * 流程：Next.js Server Action 注册 → 建 API key → 同意免费模型条款 →
 *       邮件确认链接 → 拿 key 打一次 :free 模型冒烟
 *
 * 移植自 tokenharbor 项目（Python `tokenharbor_self.py`，实跑出 409 个 key）。
 * 与 Python 版的差异：编排（代理轮换 / 重试 / 落盘）交给 lib/runner.js，
 * 邮箱换成框架的 EmailBox（走 wait_link），Server Action 的 id / key 改成
 * 每次从 /login 页面动态抠（见第 2 条）。
 *
 * 实测要点（改之前先看这里）：
 *
 *   1. **一个出口 IP 只能注册一个号**。第二个号开始 Cloudflare 就挡人机验证，
 *      而且不是一次性的 —— 同一个 IP 会持续被挡。所以必须配代理池，
 *      `--conc` 开大没有意义（IP 数 = 上限）。
 *
 *   2. 注册是 **Next.js Server Action**：multipart/form-data + `Next-Action`
 *      header，响应是 `text/x-component`（flight 流）。成功标志是响应体里
 *      出现 `signedIn`，失败是 `"error":"..."`。字段名 `1_$ACTION_*` 里的
 *      `$` 和 `:` 都不能改 —— 改了服务端认不出来。
 *
 *      **action id / key 每次构建都会变**（Python 版把它们写死，站点重建后
 *      直接 404 "Server action not found."）。这里改成从 /login 的 SSR HTML
 *      里抠 —— 页面 no-JS 表单的 hidden input 就是当前构建的 action 引用：
 *        <input type="hidden" name="$ACTION_1:0" value='{"id":"<40hex>","bound":"$@1"}'>
 *        <input type="hidden" name="$ACTION_KEY"  value="kb<32hex>">
 *      抠不到就报错，不用写死的值兜底（写死的值只会 404）。
 *
 *      **必须抠 `/login?mode=signup`，不是 `/login`** —— 同一个路径下登录和注册
 *      是两个 action。抠错了服务端会回 `"That email and password don't match"`
 *      （拿注册的字段去跑登录 action），不是 404，很容易看漏。
 *
 *   3. 确认邮件里是**链接**（`/verify-email?...`）不是 OTP，所以 `mailPrefer`
 *      只列实现了 `_iter_messages`（→ `wait_link`）的 provider。
 *      实测 tempmail.lol 已经对 CN 关掉免费档（403），所以 mail.tm 排前面。
 *
 *   4. 邮件确认**必须成功**才算产出。不到确认信 / 模型仍 403 Verify your email
 *      就抛错，不写 ledger、不进 CPA。
 *
 *   5. Turnstile **必过**：所有出口 IP 不带 token 都回
 *      "Please complete the human check to continue."。走框架接好的在线求解器
 *      （captcha.tokents.top），跟页面共用同一个代理出口。
 */

import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

import { createMailboxPool } from '../lib/mailbox.js';
import { wibNow } from '../lib/util.js';

// ============================================================ 配置（改这里）

export const config = {
  baseUrl: 'https://tokenharbor.ai',
  /** 本目标没有 referral 流程，留空 */
  referral: '',
  /** Cloudflare Turnstile sitekey（站点 chunk 里的公开值） */
  sitekey: '0x4AAAAAADBuC8Knz1EJZx9-',
  /** 在线求解器（契约见 lib/solver.js；本机直连会超时，必须走任务代理） */
  solverUrl: 'https://captcha.tokents.top',
  /** Python 版实测用的 UA，别随便换 */
  userAgent:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36',
  outDir: path.join(os.homedir(), 'projects', 'tokenharbor_farm', 'out'),
  /** 一 IP 一号：出号或限流后冷却一小时 */
  ipCooldownMs: 60 * 60 * 1000,

  /**
   * 只要支持 wait_link 的源（确认信是链接）。
   * **别把 mail.tm 放前面**：它只有 maxxspace.com 一个域名，建了几百个号后被站点按域名限速，
   * 实测同一个新 IP 用 maxxspace 报 "doing that a bit fast"，换 ooynib.com 立刻成功。
   * temp-mail.io 每次轮换多个域名，tempmail.lol 也多家。
   */
  // 只走微软：temp-mail.io / tempmail.lol / maxxspace 的域名已被站点拉黑，
  // temp.tf 的 gmail 基础地址也已被注册光。
  mailPrefer: ['temp.tf-outlook', 'temp.tf-hotmail'],

  /** 注册表单所在路径。登录和注册在同一个路径下，靠 ?mode=signup 区分 */
  signupPath: '/login?mode=signup',
  /** 确认链接的形状，给 wait_link 用 */
  verifyLinkPattern: /tokenharbor\.ai\/verify-email/,
  /** 冒烟用的免费模型 */
  testModel: 'mimo-v2.5:free',
  get cpaHost() {
    return process.env.TH_CPA_HOST || process.env.CPA_HOST || '';
  },
  get cpaDir() {
    return process.env.TH_CPA_DIR || process.env.CPA_DIR || '/root/.cli-proxy-api';
  },
};

const execFileAsync = promisify(execFile);

/** 等确认邮件的秒数。Python 版是 90s，框架每 3s 轮询一次。 */
const VERIFY_WAIT = 120;

const BOUNDARY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

/**
 * `Next-Router-State-Tree` header：URL-encoded 的 flight 状态树，指向 /login 的
 * __PAGE__ 节点。跟 action id 不同，这个值是路由结构，站点没改路由就不用动。
 * （原样抄 Python 版 urllib.parse.quote() 的输出。）
 */
const ROUTER =
  '%5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C0%5D%7D%2Cnull%2Cnull%2C20%5D';

export function createMailbox() {
  return createMailboxPool({ prefer: config.mailPrefer });
}

// ==================================================== 纯函数（单测覆盖）

/** HTML 属性值反转义。页面里的 JSON 是 &quot; 编码的。 */
function unescapeHtml(s) {
  return s
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

/**
 * 从 /login 的 SSR HTML 里抠出当前构建的 Server Action 引用。
 *
 * 页面上的 no-JS 表单带了三个 hidden input，正好是 JS 协议要的东西：
 *   $ACTION_1:0 → {"id":"<40hex>","bound":"$@1"}   ← action id + bound 参数
 *   $ACTION_1:1 → ["$undefined"]
 *   $ACTION_KEY → kb<32hex>                         ← bound 参数的加密 key
 *
 * @param {string} html
 * @returns {{actionId: string, actionKey: string, actionRef: string}}
 *   actionRef 是原样可以直接当 `1_$ACTION_1:0` 字段发的 JSON 串
 */
export function parseActionRef(html) {
  const refMatch = /name="\$ACTION_1:0"\s+value="([^"]*)"/.exec(html);
  const keyMatch = /name="\$ACTION_KEY"\s+value="([^"]*)"/.exec(html);
  if (!refMatch || !keyMatch) {
    throw new Error(
      'login 页面里找不到 Server Action 引用（$ACTION_1:0 / $ACTION_KEY）—— ' +
        '站点改版了，需要重新看 /login 的 no-JS 表单结构',
    );
  }
  const actionRef = unescapeHtml(refMatch[1]);
  const actionKey = unescapeHtml(keyMatch[1]);
  let actionId;
  try {
    actionId = JSON.parse(actionRef).id;
  } catch {
    throw new Error(`$ACTION_1:0 不是合法 JSON: ${actionRef.slice(0, 120)}`);
  }
  if (!actionId) throw new Error(`$ACTION_1:0 里没有 id: ${actionRef.slice(0, 120)}`);
  return { actionId, actionKey, actionRef };
}

/**
 * 拼 Next.js Server Action 的 multipart body。
 *
 * 字段顺序和空值都不能动：空字段（timezone / next / invite_code）也要发，
 * 少一个服务端会当成缺参数。
 *
 * @param {string} email
 * @param {string} password
 * @param {{actionId: string, actionKey: string, actionRef: string}} ref parseActionRef() 的返回值
 * @param {object} [o]
 * @param {string} [o.fingerprint] 设备指纹，默认随机 uuid
 * @param {string} [o.captchaToken] 有就塞 cf-turnstile-response
 * @param {string} [o.boundary] 固定 boundary（测试用）
 * @returns {{body: string, boundary: string}}
 */
export function buildSignupBody(email, password, ref, o = {}) {
  const boundary =
    o.boundary ||
    `----WebKitFormBoundary${Array.from(
      { length: 16 },
      () => BOUNDARY_ALPHABET[crypto.randomInt(BOUNDARY_ALPHABET.length)],
    ).join('')}`;

  const parts = [];
  const af = (name, value = '') =>
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}`);

  af('$ACTION_REF_1');
  af('$ACTION_1:0', ref.actionRef);
  af('$ACTION_1:1', '["$undefined"]');
  af('$ACTION_KEY', ref.actionKey);
  af('device_fingerprint', o.fingerprint || crypto.randomUUID());
  af('timezone', o.timezone || 'Asia/Shanghai');
  af('next');
  af('email', email);
  af('password', password);
  af('invite_code');
  // captcha 必须在 `0`（$K1 参数表）之前：放后面 FormData 里就没有这个字段，
  // 站点会回 needCaptcha（token 其实已经拿到了）。
  if (o.captchaToken) af('cf-turnstile-response', o.captchaToken);
  af('0', '["$undefined","$K1"]');

  return { body: `${parts.join('\r\n')}\r\n--${boundary}--\r\n`, boundary };
}

/**
 * 只认两种真实的错误形状：
 *   1. flight 流  `1:{"error":"..."}`
 *   2. no-JS 回包 `[{&quot;error&quot;:&quot;...&quot;}]`（在 $ACTION_1:1 的 value 里）
 * 不能宽泛地找 "error"：成功响应的 RSC 里到处是这个词，会抽到垃圾。
 */
export function extractSignupError(text) {
  const s = String(text || '');
  const err =
    /^1:\{"error":"([^"]+)"/m.exec(s)?.[1] ??
    /\[\{&quot;error&quot;:&quot;([\s\S]*?)&quot;\}\]/.exec(s)?.[1] ??
    /\[\{"error":"([^"]*?)"\}\]/.exec(s)?.[1];
  if (err) return err.replace(/&#x27;/g, "'").replace(/&amp;/g, '&');
  // 没 error 字段但要人机：以前被当成 signup 200 成功，随后 /api/keys 401 Sign in first
  if (/needCaptcha"\s*:\s*true/.test(s) && !/signedIn/.test(s)) return 'needCaptcha';
  return null;
}

/**
 * 出口 IP 被站点限流/风控。实测四种文案，同一个邮箱域名换干净 IP 就能过：
 *   Too many sign-ups from this network. Please try again in an hour.
 *   We couldn't create your account right now. Our team has been alerted…
 *   Your IP or email provider is not supported for Token Harbor accounts.
 *   You're doing that a bit fast — take a breath and try again.
 * 命中就把该出口冷却，换下一个 IP，别在同一口上重试。
 * 注意区分："not a throwaway address" 是域名黑名单，"already on board" 是邮箱重复，换 IP 都没用。
 */
export function isIpCooldown(text) {
  const s = String(text || '');
  return (
    /too many sign-?ups? from this network|try again in an? hour/i.test(s) ||
    /couldn't create your account right now/i.test(s) ||
    /ip or email provider is not supported/i.test(s) ||
    /doing that a bit fast/i.test(s)
  );
}

/** flight 流里的 `"userId": "..."`；没有就返回 ''。 */
export function extractUserId(text) {
  return /"userId":\s*"([^"]+)"/.exec(text)?.[1] ?? '';
}

/** 真注册成功：303/redirect，或 body 里有 signedIn / userId。光 HTTP 200 不算。 */
export function signupOk(status, text, headers = {}) {
  if (status === 303 || headers['x-action-redirect'] || headers.location) return true;
  if (extractUserId(text)) return true;
  return /signedIn/.test(text);
}

// ======================================================== 业务流程（改这里）

/** 用刚建的 key 打一次免费模型；返回人类可读的一行，不抛错。 */
async function testFreeModel(s, apiKey, cfg) {
  try {
    const r = await s.post(`${cfg.baseUrl}/v1/chat/completions`, {
      headers: { Authorization: `Bearer ${apiKey}` },
      json: {
        model: cfg.testModel,
        messages: [{ role: 'user', content: 'say ok' }],
        max_tokens: 20,
      },
      timeout: 30,
    });
    if (r.status === 200) {
      const reply = r.json().choices?.[0]?.message?.content ?? '';
      return `200 OK - ${reply.slice(0, 30)}`;
    }
    return `${r.status} - ${r.text.slice(0, 60)}`;
  } catch (e) {
    return `ERR - ${String(e.message).slice(0, 50)}`;
  }
}

export async function registerOne(ctx) {
  const { idx, proxy, mailbox, solve, Session, genPassword, log, cfg } = ctx;

  const box = await mailbox.open();
  try {
    const email = box.address;
    const password = genPassword();
    log(`[${idx}] email=${email} provider=${box.provider_name}` + (proxy ? ` proxy=${proxy}` : ''));

    const s = new Session({ proxy, userAgent: cfg.userAgent });
    try {
      // --- 1. GET 注册页：拿会话 cookie，同时抠出当前构建的 action 引用 ---
      // 必须是 ?mode=signup —— /login 上的 action 是登录，抠错了服务端会回
      // "That email and password don't match"（拿注册字段跑登录 action）。
      const signupUrl = `${cfg.baseUrl}${cfg.signupPath}`;
      const page = await s.get(signupUrl, { timeout: 20 });
      const ref = parseActionRef(page.text);
      log(`[${idx}] action=${ref.actionId.slice(0, 10)}… key=${ref.actionKey.slice(0, 10)}…`);

      // --- 2. Turnstile（必过）。站点 widget 的 action 是 "signup"，token 里签了这个值。---
      const captchaToken = await solve(signupUrl, { action: 'signup' });
      if (!captchaToken) throw new Error('solver 没返回 token');
      log(`[${idx}] turnstile ok ${captchaToken.slice(0, 12)}…`);

      // 站点先打 /api/auth/signup-precheck?fp=&email= 决定要不要 captcha，指纹要跟表单里的一致
      // 但它只影响前端弹不弹 captcha，失败不该致命（代理抖动很常见）
      const fingerprint = crypto.randomUUID();
      try {
        await s.get(`${cfg.baseUrl}/api/auth/signup-precheck`, {
          params: { fp: fingerprint, email },
          timeout: 10,
        });
      } catch {
        /* 忽略：拿不到 precheck 也照常提交 */
      }

      // 注意：不要先做「不带 captcha 的探测」。实测探测请求会把邮箱占掉，
      // 紧接着真实注册就报 already on board（换一个地址也白搭）。
      // 所以直接带 captcha 打一次。
      // --- 3b. 提交注册（带 captcha）---
      const { body, boundary } = buildSignupBody(email, password, ref, { captchaToken, fingerprint });
      const r = await s.post(signupUrl, {
        data: body,
        timeout: 30,
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          Accept: 'text/html',
          Origin: cfg.baseUrl,
          Referer: signupUrl,
        },
      });
      // 失败：短 flight（0:{"a":"$@1"} + 1:{"error":...}）或 no-JS 回包里的 error。
      const err = extractSignupError(r.text);
      const redirected =
        r.status === 303 || Boolean(r.headers['x-action-redirect'] || r.headers.location);
      if (err && !redirected) {
        log(`[${idx}] signup resp ${r.status}: ${r.text.slice(0, 240).replace(/\s+/g, ' ')}`);
        // IP 被限流：让 runner 冷却这个出口，换下一个 IP。
        // 只认提取出的错误文案：整页 r.text 里有 JS 字符串，会误匹配 not supported/couldn't create
        if (isIpCooldown(err)) {
          const e = new Error(`ip cooldown: ${err}`);
          e.ipCooldown = true;
          throw e;
        }
        if (/already on board/i.test(err)) {
          throw new Error(`email taken: ${err}`);
        }
        if (/email provider is not supported|couldn't create your account/i.test(err)) {
          throw new Error(err);
        }
        throw new Error(`signup 403（该 IP 被挡或已用过）: ${err}`);
      }
      if (!signupOk(r.status, r.text, r.headers)) {
        log(`[${idx}] signup resp ${r.status}: ${r.text.slice(0, 240).replace(/\s+/g, ' ')}`);
        throw new Error(`signup 未登录 HTTP ${r.status}: ${r.text.slice(0, 120).replace(/\s+/g, ' ')}`);
      }
      let userId = extractUserId(r.text);
      log(`[${idx}] signup ok user=${userId.slice(0, 8) || '?'} status=${r.status}`);

      // Next 成功时常走 x-action-redirect 而不是 Location，Session 不会自动跟。
      const dest = r.headers['x-action-redirect'] || r.headers.location;
      if (dest) {
        const pathOnly = String(dest).split(';')[0];
        const nextUrl = pathOnly.startsWith('http') ? pathOnly : `${cfg.baseUrl}${pathOnly}`;
        await s.get(nextUrl, { timeout: 20 });
      }

      // --- 4. 删掉自动建的 key，再建一个干净的 ---
      const r2 = await s.get(`${cfg.baseUrl}/api/keys`, {
        headers: { Accept: 'application/json' },
        timeout: 20,
      });
      let autoKeys = [];
      try {
        autoKeys = r2.json().keys || [];
      } catch {
        /* 空/非 JSON 就当没有 */
      }
      for (const k of autoKeys) {
        await s.request('DELETE', `${cfg.baseUrl}/api/keys/${k.id}`, { timeout: 15 });
      }

      const label = `farm-${idx}-${crypto.randomInt(100, 1000)}`;
      const r3 = await s.post(`${cfg.baseUrl}/api/keys`, {
        headers: { Accept: 'application/json' },
        json: { label },
        timeout: 20,
      });
      if (r3.status !== 201) {
        throw new Error(`key create HTTP ${r3.status}: ${r3.text.slice(0, 120)}`);
      }
      const apiKey = r3.json().plaintext;
      if (!apiKey) throw new Error('key create 没返回 plaintext');
      log(`[${idx}] api_key=${apiKey.slice(0, 20)}…`);
      if (!userId) {
        try {
          const me = await s.get(`${cfg.baseUrl}/api/me`, {
            headers: { Accept: 'application/json' },
            timeout: 15,
          });
          const j = me.json();
          userId = String(j?.id || j?.user?.id || j?.userId || '');
        } catch {
          /* 没有 /api/me 就用 email 当 CPA 文件名 */
        }
      }

      // --- 5. 同意免费模型条款（不点的话 :free 模型会 403）---
      const rc = await s.post(`${cfg.baseUrl}/api/me/privacy`, {
        headers: { Accept: 'application/json' },
        json: { free_models_enabled: true },
        timeout: 15,
      });
      const consent = rc.status === 200 && rc.text.includes('"ok":true');

      // --- 6. 确认邮件是链接。不到就不产出（模型会 403 Verify your email）。---
      const link = await box.wait_link(VERIFY_WAIT, cfg.verifyLinkPattern);
      await s.get(link, { timeout: 25 });
      log(`[${idx}] email verified`);

      // --- 7. 冒烟：拿 key 打一次免费模型 ---
      const modelTest = await testFreeModel(s, apiKey, cfg);
      log(`[${idx}] model test: ${modelTest}`);
      if (/verify your email/i.test(modelTest)) {
        throw new Error(`邮箱未验证，模型 ${modelTest}`);
      }

      return {
        idx,
        created_at: wibNow(),
        email,
        mail_provider: box.provider_name,
        password,
        user_id: userId,
        api_key: apiKey,
        api_key_label: label,
        email_verified: true,
        consent,
        model_test: modelTest,
      };
    } finally {
      s.close();
    }
  } finally {
    box.close();
  }
}

export function sanitizeUid(uid) {
  const s = String(uid || '')
    .replace(/[^a-zA-Z0-9_-]+/g, '_')
    .slice(0, 64);
  return s && s !== '.' && s !== '..' ? s : '';
}

export function buildCpaAuthFile(res) {
  // no-JS 注册经常抠不到 user_id，不能全写成 tokenharbor-tokenharbor.json，否则 CPA 一直覆盖同一份
  const uid =
    sanitizeUid(res.user_id) ||
    sanitizeUid(String(res.email || '').replace(/@/g, '_')) ||
    sanitizeUid(String(res.api_key || '').replace(/^thk_live_/, '').slice(0, 24)) ||
    'tokenharbor';
  return {
    fileName: `tokenharbor-${uid}.json`,
    body: {
      type: 'tokenharbor',
      provider: 'tokenharbor',
      logo: 'https://tokenharbor.ai/icon.png',
      disabled: false,
      auth: {
        accessToken: res.api_key,
        refreshToken: '',
        expiresAt: 0,
        domain: 'https://tokenharbor.ai/v1',
      },
      account: {
        uid,
        nickname: res.email || uid,
        email: res.email || '',
        password: res.password || '',
      },
    },
  };
}

export async function afterSuccess(res, { log } = {}) {
  if (!res.email_verified) {
    log?.(`跳过 CPA：${res.email} 邮箱未验证，模型会 403`);
    return;
  }
  const { fileName, body } = buildCpaAuthFile(res);
  const host = config.cpaHost;
  const dir = config.cpaDir.replace(/\/$/, '');
  if (!host) {
    log?.('cpa skip: CPA_HOST unset');
    return;
  }
  const remote = `${host}:${dir}/${fileName}`;
  const tmp = path.join(os.tmpdir(), fileName);
  fs.writeFileSync(tmp, `${JSON.stringify(body, null, 2)}\n`, { mode: 0o600 });
  try {
    await execFileAsync('scp', ['-q', '-o', 'StrictHostKeyChecking=accept-new', tmp, remote]);
    await execFileAsync('ssh', [host, `chmod 600 ${dir}/${fileName}`]);
    log?.(`cpa ${fileName} → ${remote}`);
  } catch (e) {
    throw new Error(`cpa 落盘失败: ${e.message}`);
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* ignore */
    }
  }
}
