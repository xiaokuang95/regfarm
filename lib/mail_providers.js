/**
 * lib/mail_providers.js — temp mail providers
 *
 * 参照实现见 reference/mail_providers.py
 *
 * Provider 优先级与 Python 版一致：
 *   1) ncaori         (ncaori.my.id / nca.my.id catch-all)
 *   2) zoromail       (zoromail.com REST domains)
 *   3) tempmail.lol   (best free pure-API token rate)
 *   4) smailpro       (sonjj unique domains)
 *   5) tempmail.plus / emailnator / temp-mail.io / mail.tm / guerrilla / maildrop
 *
 * 与 Python 版的差异：
 *   - creq.Session() → lib/http.js 的 Session（零依赖 TLS 指纹）
 *   - time.sleep 轮询循环 → async/await sleep，wait_code 变成 Promise
 *   - 每个 provider 多一个 close()，用于释放 keepAlive socket（否则 Node 进程不退出）
 */

import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Session } from './http.js';

const JSON_HEADERS = {
  Accept: 'application/json',
  'Content-Type': 'application/json',
};

// xAI/SpaceXAI emails: "confirmation code: HPN-7Z9" (preferred) or legacy 6-char
const OTP_HYPHEN_RE = /(?:confirmation\s+)?code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})\b/gi;
const OTP_HYPHEN_BARE_RE = /\b([A-Z0-9]{3}-[A-Z0-9]{3})\b/gi;
const OTP_LEGACY_RE = /(?:confirmation\s+)?code[:\s]+([A-Z0-9]{6})\b/gi;
// pure 6-digit only when clearly labeled confirmation/OTP (avoid ad tracking ids)
const OTP_CODE_IS_RE = /(?:verification|confirmation)\s+code\s+is\s+([A-Z0-9]{6}|\d{6})/gi;
const OTP_CODEFIRST_RE = /\b(\d{6})\b\s+is\s+your\s+verification\s+code/gi;
const OTP_DIGIT6_LABELED_RE =
  /(?:confirmation\s+code|verification\s+code|otp|one[- ]time(?:\s+pass(?:word|code))?)[:\s#]*([0-9]{6})\b/gi;

const SKIP_HYPHEN = new Set([
  'per-100', 'max-100', 'min-100', 'dir-top', 'top-dir', 'moz-osx',
  'pre-built', 'pre-made', 'one-time', 'set-up', 'sign-up', 'log-in',
  'opt-out', 'opt-in', 'non-stop', 'all-in', 'end-to', 'to-end',
]);
const SKIP_LEGACY = new Set([
  'signup', 'verify', 'account', 'please', 'gmail', 'xaiapp', 'spacex',
  'edge', 'chrome', 'safari', 'webkit', 'mozilla', 'button', 'submit',
  'create', 'ignore', 'footer', 'strong', 'hidden', 'center', 'inline',
  'mobile', 'column', 'screen', 'border', 'margin', 'height', 'weight',
  'family', 'system', 'domain', 'tensor', 'mailto', 'adjust', 'bottom',
  'unleash', 'online', 'tools', 'power', 'ultimate', 'directory',
]);
// subjects/from that are emailnator ads — never treat as OTP source
const AD_MARKERS = [
  'ai tools', 'unleash the power', 'adsvpn', 'buysellads', 'directory of online',
  'temp mail', 'emailnator', 'disposable gmail',
];
const XAI_MARKERS = [
  'x.ai', 'xai', 'grok', 'spacex', 'confirmation code', 'validation code',
  'verify your email', 'email verification', 'accounts.x.ai',
];

const SUBJECT_RE = /^subject:.*$/im;
const SUBJECT_HINT_RE = /verification|\botp\b|one[- ]time|passcode/i;
const SIX_DIGITS_RE = /\b(\d{6})\b/;
const CONTEXT_RE = /confirmation|verification|otp|one[- ]time/i;
const HYPHEN_SHAPE_RE = /^[A-Z]{3}-[A-Z]{3}$/;
const ALL_DIGITS_RE = /^\d+$/;

// ------------------------------------------------------------------- helpers

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
/** Python uuid.uuid4().hex[:n] */
const randHex = (n) =>
  crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
/** Python secrets.choice 等价（CSPRNG） */
const securePick = (arr) => arr[crypto.randomInt(arr.length)];
/** Python time.time() */
const nowSec = () => Date.now() / 1000;

function decodeQpish(blob) {
  // quoted-printable soft line breaks in tempmail bodies
  return (blob || '').replace(/=\r\n/g, '').replace(/=\n/g, '');
}

function looksLikeAd(blob) {
  const low = (blob || '').toLowerCase();
  return AD_MARKERS.some((m) => low.includes(m)) && !XAI_MARKERS.some((m) => low.includes(m));
}

function hasXaiContext(blob) {
  const low = (blob || '').toLowerCase();
  return XAI_MARKERS.some((m) => low.includes(m));
}

/** 对等 Python _extract_code：从邮件正文/subject 里抠 OTP。 */
export function extractCode(blob) {
  const text = decodeQpish(blob);
  if (!text || looksLikeAd(text)) return null;
  const xaiish = hasXaiContext(text);

  // 0) code-first / "code is" Clerk-top-tools style
  for (const m of text.matchAll(OTP_CODEFIRST_RE)) return m[1];
  for (const m of text.matchAll(OTP_CODE_IS_RE)) return m[1].toUpperCase();

  // 1) labeled hyphen code (subject: confirmation code: HPN-7Z9)
  for (const m of text.matchAll(OTP_HYPHEN_RE)) {
    const code = m[1].toUpperCase();
    if (!SKIP_HYPHEN.has(code.toLowerCase())) return code;
  }

  // 2) bare hyphen — only when xAI context present (avoid ad junk like DIR-TOP)
  if (xaiish) {
    for (const m of text.matchAll(OTP_HYPHEN_BARE_RE)) {
      const code = m[1].toUpperCase();
      const low = code.toLowerCase();
      if (SKIP_HYPHEN.has(low) || low.startsWith('per-')) continue;
      // xAI codes are typically mixed alnum, not pure words
      if (HYPHEN_SHAPE_RE.test(code) && SKIP_HYPHEN.has(low)) continue;
      return code;
    }
  }

  // 3) labeled legacy 6-char alnum (HAR: AX3BBY) — reject pure-digit unless xAI-labeled
  for (const m of text.matchAll(OTP_LEGACY_RE)) {
    const code = m[1].toUpperCase();
    const low = code.toLowerCase();
    if (SKIP_LEGACY.has(low)) continue;
    if (ALL_DIGITS_RE.test(code)) {
      // only accept pure digits with strong xAI confirmation label nearby
      if (!xaiish) continue;
      const window = text.slice(Math.max(0, m.index - 40), m.index + m[0].length + 10);
      if (!CONTEXT_RE.test(window)) continue;
    }
    return code;
  }

  // 4) labeled pure 6-digit OTP — label cukup kuat, tanpa gate xaiish
  for (const m of text.matchAll(OTP_DIGIT6_LABELED_RE)) return m[1];

  // 5) fallback: 6 digit polos di subject yang menyebut verification/otp
  const subj = SUBJECT_RE.exec(text);
  if (subj && SUBJECT_HINT_RE.test(subj[0])) {
    const hit = SIX_DIGITS_RE.exec(subj[0]);
    if (hit) return hit[1];
  }

  return null;
}

/**
 * 从邮件正文里抠链接。
 *
 * @param {string} blob 邮件全文（subject + html/text 拼接）
 * @param {RegExp|string|null} pattern 链接必须满足的条件；不传就取第一个
 * @returns {string|null} 已还原 &amp; 、去掉尾部标点的链接
 */
export function extractLink(blob, pattern = null) {
  const text = decodeQpish(blob);
  if (!text) return null;
  // match() 会重置 lastIndex，全局正则的状态不会泄漏到下一次调用
  const urls = text.match(/https?:\/\/[^\s"'<>)\]}]+/g) || [];
  for (const raw of urls) {
    const url = raw.replace(/&amp;/g, '&').replace(/[.,;:]+$/, '');
    if (!pattern) return url;
    if (typeof pattern === 'string') {
      if (url.includes(pattern)) return url;
    } else {
      // 调用方的正则可能带 /g，test() 会推进 lastIndex → 每次归零
      pattern.lastIndex = 0;
      if (pattern.test(url)) return url;
    }
  }
  return null;
}

/** 每个 provider 都要能释放 keepAlive socket。 */
class BaseProvider {
  close() {
    this.s?.close();
  }

  /**
   * 通用 wait_link：子类只要实现 _iter_messages(cb, seen) 就能用。
   *
   * 用于「确认邮件里是链接而不是 OTP」的站点（alysiscode.com 就是）。
   *
   * @param {number} timeout 秒
   * @param {RegExp|string|null} pattern 见 extractLink
   */
  async wait_link(timeout = 150, pattern = null) {
    if (typeof this._iter_messages !== 'function') {
      throw new Error(`${this.constructor.name} tidak mendukung wait_link`);
    }
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const link = await this._iter_messages((blob) => extractLink(blob, pattern) || null, seen);
      if (link) return link;
      await sleep(3000);
    }
    throw new Error(`${this.constructor.name} no link for ${this.address}`);
  }
}

// --------------------------------------------------------------- emailnator

export class EmailNator extends BaseProvider {
  /**
   * Gmail-like temp addresses via emailnator.com (plus/dot/googlemail).
   *
   * Produces real *@gmail.com / *@googlemail.com aliases that often pass
   * disposable-mail filters better than random temp domains.
   */
  HOME = 'https://www.emailnator.com';
  GEN = 'https://www.emailnator.com/generate-email';
  LIST = 'https://www.emailnator.com/message-list';
  // Prefer real Gmail alias styles first; domain= is plain disposable.
  STYLES = ['plusGmail', 'dotGmail', 'googleMail'];

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
    this._bootstrapped = false;
  }

  _headers() {
    const xsrf = this.s.cookies.get('XSRF-TOKEN');
    const h = {
      Accept: 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      Origin: this.HOME,
      Referer: `${this.HOME}/`,
    };
    if (xsrf) h['X-XSRF-TOKEN'] = decodeURIComponent(xsrf);
    return h;
  }

  async _bootstrap() {
    if (this._bootstrapped) return;
    const r = await this.s.get(`${this.HOME}/`, { timeout: 30 });
    if (r.status >= 400) throw new Error(`emailnator home ${r.status}`);
    if (!this.s.cookies.get('XSRF-TOKEN')) throw new Error('emailnator missing XSRF-TOKEN');
    this._bootstrapped = true;
  }

  async create_account() {
    await this._bootstrap();
    const r = await this.s.post(this.GEN, {
      json: { email: this.STYLES },
      headers: this._headers(),
      timeout: 30,
    });
    if (r.status >= 400) {
      throw new Error(`emailnator generate ${r.status}: ${r.text.slice(0, 200)}`);
    }
    const data = r.content.length ? r.json() : {};
    const emails = data.email || [];
    if (!emails.length) throw new Error(`emailnator empty: ${JSON.stringify(data)}`);
    this.address = String(emails[0]).trim();
    // Only accept gmail/googlemail aliases — domain= style is disposable junk.
    const low = this.address.toLowerCase();
    if (!(low.endsWith('@gmail.com') || low.endsWith('@googlemail.com'))) {
      throw new Error(`emailnator non-gmail alias: ${this.address}`);
    }
    return this.address;
  }

  async wait_code(timeout = 150) {
    if (!this.address) throw new Error('emailnator no address');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const r = await this.s.post(this.LIST, {
        json: { email: this.address },
        headers: this._headers(),
        timeout: 30,
      });
      if (r.status < 400 && r.content.length) {
        const data = r.content.length ? r.json() : {};
        for (const m of data.messageData || []) {
          const mid = String(m.messageID || '');
          const subj = String(m.subject || '');
          const frm = String(m.from || '');
          if (!mid || mid.toUpperCase() === 'ADSVPN' || seen.has(mid)) continue;
          if (looksLikeAd(`${subj} ${frm}`)) {
            seen.add(mid);
            continue;
          }
          // subject alone may already carry "confirmation code: ABC-DEF"
          let code = extractCode(`${subj} ${frm}`);
          if (code) return code;
          // full body via message-list + messageID (returns HTML/string)
          const r2 = await this.s.post(this.LIST, {
            json: { email: this.address, messageID: mid },
            headers: this._headers(),
            timeout: 30,
          });
          let body = '';
          if (r2.status < 400 && r2.content.length) {
            body = r2.text;
            try {
              const j = r2.json();
              if (typeof j === 'string') {
                body = j;
              } else if (j && typeof j === 'object') {
                // successful body is often raw HTML string in response;
                // if JSON dict, join known fields
                body =
                  ['messageData', 'body', 'html', 'text', 'content', 'subject']
                    .map((k) => String(j[k] ?? ''))
                    .join(' ') || body;
              }
            } catch {
              /* 不是 JSON 就用原始 text */
            }
          }
          code = extractCode(`${subj} ${frm} ${body}`);
          if (code) return code;
          // mark seen only after we attempted body — allow retry if body 5xx early
          if (r2.status < 500) seen.add(mid);
        }
      }
      await sleep(3000);
    }
    throw new Error(`emailnator no OTP for ${this.address}`);
  }
}

// ------------------------------------------------------------------ smailpro

export class SmailPro extends BaseProvider {
  /**
   * smailpro.com via sonjj payload-signed API.
   *
   * Creates unique *@domain addresses (not gmail aliases). Good for signup when
   * emailnator gmail norms are already taken. Chat free tier still may 403.
   */
  SITE = 'https://smailpro.com';
  BASE = 'https://api.sonjj.com/v1/temp_email';

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
    this._bootstrapped = false;
  }

  async _boot() {
    if (this._bootstrapped) return;
    const r = await this.s.get(`${this.SITE}/`, { timeout: 30 });
    if (r.status >= 400) throw new Error(`smailpro home ${r.status}`);
    this._bootstrapped = true;
  }

  async _payload(params) {
    await this._boot();
    const r = await this.s.get(`${this.SITE}/app/payload`, {
      params,
      timeout: 30,
      headers: { Accept: 'text/plain, */*', Referer: `${this.SITE}/` },
    });
    if (r.status >= 400 || !r.text.trim()) {
      throw new Error(`smailpro payload ${r.status}: ${r.text.slice(0, 120)}`);
    }
    return r.text.trim();
  }

  async _api(path, params) {
    const payload = await this._payload(params);
    const r = await this.s.get(`${this.BASE}${path}`, {
      params: { payload },
      timeout: 30,
      headers: {
        Accept: 'application/json, text/plain, */*',
        Origin: this.SITE,
        Referer: `${this.SITE}/`,
      },
    });
    if (r.status >= 400) {
      throw new Error(`smailpro ${path} ${r.status}: ${r.text.slice(0, 200)}`);
    }
    let data;
    try {
      data = r.json();
    } catch (e) {
      throw new Error(`smailpro ${path} bad json: ${r.text.slice(0, 160)}`);
    }
    if (data && typeof data === 'object' && data.detail) {
      // {"detail":{"error":{"code":400,"message":"Invalid domain: ..."}}}
      const err = data.detail;
      const msg =
        err && typeof err === 'object'
          ? (err.error || {}).message || JSON.stringify(err)
          : err;
      throw new Error(`smailpro ${path}: ${msg}`);
    }
    return data && typeof data === 'object' ? data : { raw: data };
  }

  async create_account() {
    let last = null;
    for (let i = 0; i < 5; i++) {
      try {
        const data = await this._api('/create', { url: `${this.BASE}/create` });
        const email = data.email;
        if (!email) throw new Error(`smailpro no email: ${JSON.stringify(data)}`);
        this.address = String(email);
        return this.address;
      } catch (e) {
        last = e;
        await sleep(400);
      }
    }
    throw new Error(`smailpro create failed: ${last}`);
  }

  async wait_code(timeout = 150) {
    if (!this.address) throw new Error('smailpro no address');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      let data;
      try {
        data = await this._api('/inbox', {
          url: `${this.BASE}/inbox`,
          email: this.address,
        });
      } catch {
        await sleep(3000);
        continue;
      }
      let msgs = data.messages || [];
      if (!Array.isArray(msgs)) msgs = [];
      for (const m of msgs) {
        const mid = String(m.mid ?? m.id ?? m.message_id ?? '');
        if (!mid || seen.has(mid)) continue;
        const subj = String(m.subject || '');
        const frm = String(m.from || m.sender || '');
        if (looksLikeAd(`${subj} ${frm}`)) {
          seen.add(mid);
          continue;
        }
        let code = extractCode(`${subj} ${frm}`);
        if (code) return code;
        // full body
        let body = '';
        try {
          const full = await this._api('/message', {
            url: `${this.BASE}/message`,
            email: this.address,
            mid,
          });
          body = String(full.body ?? full.html ?? full.text ?? '');
        } catch {
          body = String(m.body ?? m.text ?? m.preview ?? '');
        }
        code = extractCode(`${subj} ${frm} ${body}`);
        if (code) return code;
        seen.add(mid);
      }
      await sleep(3000);
    }
    throw new Error(`smailpro no OTP for ${this.address}`);
  }
}

// --------------------------------------------------------------- temp-mail.io

export class TempMailIO extends BaseProvider {
  /** temp-mail.io free public API (api.internal.temp-mail.io). */
  BASE = 'https://api.internal.temp-mail.io/api/v3';

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
    this.token = null;
  }

  async create_account() {
    const r = await this.s.post(`${this.BASE}/email/new`, {
      json: { min_name_length: 8, max_name_length: 12 },
      headers: JSON_HEADERS,
      timeout: 30,
    });
    if (r.status >= 400) {
      throw new Error(`temp-mail.io create ${r.status}: ${r.text.slice(0, 200)}`);
    }
    const data = r.json();
    this.address = data.email;
    this.token = data.token;
    if (!this.address) throw new Error(`temp-mail.io bad: ${JSON.stringify(data)}`);
    return this.address;
  }

  async wait_code(timeout = 150) {
    if (!this.address) throw new Error('temp-mail.io no address');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const r = await this.s.get(`${this.BASE}/email/${this.address}/messages`, {
        headers: {
          Accept: 'application/json',
          'Application-Name': 'web',
          'Application-Version': '2.4.2',
        },
        timeout: 30,
      });
      if (r.status < 400 && r.content.length) {
        let msgs = r.content.length ? r.json() : [];
        if (!Array.isArray(msgs)) msgs = msgs.messages || msgs.mail_list || [];
        for (const m of msgs) {
          const mid = String(m.id ?? m._id ?? m.message_id ?? JSON.stringify(m));
          if (seen.has(mid)) continue;
          seen.add(mid);
          // body may be inline; else fetch
          let blob = ['subject', 'body', 'body_text', 'body_html', 'html', 'text', 'preview', 'from']
            .map((k) => String(m[k] ?? ''))
            .join(' ');
          if (!extractCode(blob) && m.id) {
            try {
              const r2 = await this.s.get(
                `${this.BASE}/email/${this.address}/messages/${m.id}`,
                { headers: { Accept: 'application/json' }, timeout: 30 },
              );
              if (r2.status < 400 && r2.content.length) {
                const full = r2.json();
                blob +=
                  ' ' +
                  ['subject', 'body', 'body_text', 'body_html', 'html', 'text']
                    .map((k) => String(full[k] ?? ''))
                    .join(' ');
              }
            } catch {
              /* 拿不到全文就用列表里的摘要 */
            }
          }
          const code = extractCode(blob);
          if (code) return code;
        }
      }
      await sleep(3000);
    }
    throw new Error(`temp-mail.io no OTP for ${this.address}`);
  }

  /** 遍历收件箱（列表里没有正文就再拉一封全文），把 blob 交给 cb。 */
  async _iter_messages(cb, seen = new Set()) {
    const r = await this.s.get(`${this.BASE}/email/${this.address}/messages`, {
      headers: {
        Accept: 'application/json',
        'Application-Name': 'web',
        'Application-Version': '2.4.2',
      },
      timeout: 30,
    });
    if (r.status >= 400 || !r.content.length) return null;
    let msgs = r.json();
    if (!Array.isArray(msgs)) msgs = msgs.messages || msgs.mail_list || [];
    for (const m of msgs) {
      const mid = String(m.id ?? m._id ?? m.message_id ?? JSON.stringify(m));
      if (seen.has(mid)) continue;
      seen.add(mid);
      let blob = ['subject', 'body', 'body_text', 'body_html', 'html', 'text', 'preview', 'from']
        .map((k) => String(m[k] ?? ''))
        .join(' ');
      if (!extractLink(blob) && m.id) {
        try {
          const r2 = await this.s.get(`${this.BASE}/email/${this.address}/messages/${m.id}`, {
            headers: { Accept: 'application/json' },
            timeout: 30,
          });
          if (r2.status < 400 && r2.content.length) {
            const full = r2.json();
            blob +=
              ' ' +
              ['subject', 'body', 'body_text', 'body_html', 'html', 'text']
                .map((k) => String(full[k] ?? ''))
                .join(' ');
          }
        } catch {
          /* 拿不到全文就用列表里的摘要 */
        }
      }
      const hit = cb(blob);
      if (hit) return hit;
    }
    return null;
  }
}

// --------------------------------------------------------------- tempmail.lol

export class TempMailLol extends BaseProvider {
  BASE = 'https://api.tempmail.lol/v2';

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
    this.token = null;
  }

  async create_account() {
    const r = await this.s.post(`${this.BASE}/inbox/create`, {
      headers: JSON_HEADERS,
      timeout: 30,
    });
    if (r.status >= 400) {
      throw new Error(`tempmail.lol create ${r.status}: ${r.text.slice(0, 200)}`);
    }
    const data = r.json();
    this.address = data.address || data.email;
    this.token = data.token;
    if (!this.address || !this.token) {
      throw new Error(`tempmail.lol bad response: ${JSON.stringify(data)}`);
    }
    return this.address;
  }

  async wait_code(timeout = 150) {
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const r = await this.s.get(`${this.BASE}/inbox`, {
        params: { token: this.token },
        headers: { Accept: 'application/json' },
        timeout: 30,
      });
      if (r.status < 400) {
        const data = r.content.length ? r.json() : {};
        const emails = Array.isArray(data) ? data : data.emails || data.messages || [];
        for (const m of emails) {
          const mid = String(m.id ?? m._id ?? m.date ?? JSON.stringify(m));
          if (seen.has(mid)) continue;
          seen.add(mid);
          const blob = ['subject', 'body', 'html', 'text', 'preview', 'content']
            .map((k) => String(m[k] ?? ''))
            .join(' ');
          const code = extractCode(blob);
          if (code) return code;
        }
      }
      await sleep(3000);
    }
    throw new Error(`tempmail.lol no OTP for ${this.address}`);
  }

  /** 遍历收件箱，把每封拼成 blob 交给 cb；cb 返回真值就停并透传该值。 */
  async _iter_messages(cb, seen = new Set()) {
    const r = await this.s.get(`${this.BASE}/inbox`, {
      params: { token: this.token },
      headers: { Accept: 'application/json' },
      timeout: 30,
    });
    if (r.status >= 400) return null;
    const data = r.content.length ? r.json() : {};
    const emails = Array.isArray(data) ? data : data.emails || data.messages || [];
    for (const m of emails) {
      const mid = String(m.id ?? m._id ?? m.date ?? JSON.stringify(m));
      if (seen.has(mid)) continue;
      seen.add(mid);
      const blob = ['subject', 'body', 'html', 'text', 'preview', 'content']
        .map((k) => String(m[k] ?? ''))
        .join(' ');
      const hit = cb(blob);
      if (hit) return hit;
    }
    return null;
  }
}

// -------------------------------------------------------------- guerrillamail

export class GuerrillaMail extends BaseProvider {
  BASE = 'https://api.guerrillamail.com/ajax.php';

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
    this.sid_token = null;
    this.seq = 0;
  }

  async create_account() {
    const r = await this.s.get(this.BASE, {
      params: { f: 'get_email_address', lang: 'en' },
      timeout: 30,
    });
    if (r.status >= 400) {
      throw new Error(`guerrilla create ${r.status}: ${r.text.slice(0, 200)}`);
    }
    const data = r.json();
    this.address = data.email_addr;
    this.sid_token = data.sid_token;
    if (!this.address) throw new Error(`guerrilla bad: ${JSON.stringify(data)}`);
    return this.address;
  }

  async wait_code(timeout = 150) {
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const r = await this.s.get(this.BASE, {
        params: { f: 'check_email', sid_token: this.sid_token, seq: this.seq },
        timeout: 30,
      });
      if (r.status < 400 && r.content.length) {
        const data = r.json();
        this.sid_token = data.sid_token || this.sid_token;
        for (const m of data.list || []) {
          const mid = String(m.mail_id);
          if (!mid || seen.has(mid)) continue;
          seen.add(mid);
          // fetch full
          const r2 = await this.s.get(this.BASE, {
            params: { f: 'fetch_email', sid_token: this.sid_token, email_id: mid },
            timeout: 30,
          });
          const full = r2.content.length ? r2.json() : m;
          const blob = ['mail_subject', 'mail_body', 'mail_excerpt', 'subject', 'body']
            .map((k) => String(full[k] ?? m[k] ?? ''))
            .join(' ');
          const code = extractCode(blob);
          if (code) return code;
        }
      }
      await sleep(3000);
    }
    throw new Error(`guerrilla no OTP for ${this.address}`);
  }
}

// -------------------------------------------------------------------- mail.tm

export class MailTM extends BaseProvider {
  BASE = 'https://api.mail.tm';

  constructor() {
    super();
    this.s = new Session();
    this.token = null;
    this.address = null;
    this.password = null;
  }

  async _req(method, path, kw = {}) {
    const headers = { ...JSON_HEADERS, ...(kw.headers || {}) };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const { headers: _h, timeout, ...rest } = kw;
    const r = await this.s.request(method, this.BASE + path, {
      headers,
      timeout: timeout ?? 30,
      ...rest,
    });
    if (r.status >= 400) {
      throw new Error(`mail.tm ${method} ${path} -> ${r.status} ${r.text.slice(0, 200)}`);
    }
    if (r.status === 204 || !r.content.length) return null;
    return r.json();
  }

  async create_account() {
    const data = await this._req('GET', '/domains');
    const domains = Array.isArray(data) ? data : data['hydra:member'] || [];
    const active = domains.filter((d) => d.isActive !== false).map((d) => d.domain);
    if (!active.length) throw new Error('mail.tm no domains');
    const local = `xai${randHex(10)}`;
    this.address = `${local}@${active[0]}`;
    this.password = `${randHex(32)}Aa1!`;
    await this._req('POST', '/accounts', {
      json: { address: this.address, password: this.password },
    });
    const tok = await this._req('POST', '/token', {
      json: { address: this.address, password: this.password },
    });
    this.token = tok.token;
    return this.address;
  }

  async wait_code(timeout = 150) {
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const data = (await this._req('GET', '/messages')) || {};
      const msgs = Array.isArray(data) ? data : data['hydra:member'] || [];
      for (const m of msgs) {
        const mid = m.id;
        if (!mid || seen.has(mid)) continue;
        seen.add(mid);
        const full = (await this._req('GET', `/messages/${mid}`)) || {};
        const blob = ['subject', 'intro', 'text', 'html']
          .map((k) => String(full[k] ?? ''))
          .join(' ');
        const code = extractCode(blob);
        if (code) return code;
      }
      await sleep(3000);
    }
    throw new Error(`mail.tm no OTP for ${this.address}`);
  }

  /** 遍历收件箱，把每封拼成 blob 交给 cb；cb 返回真值就停并透传该值。 */
  async _iter_messages(cb, seen = new Set()) {
    const data = (await this._req('GET', '/messages')) || {};
    const msgs = Array.isArray(data) ? data : data['hydra:member'] || [];
    for (const m of msgs) {
      const mid = m.id;
      if (!mid || seen.has(mid)) continue;
      seen.add(mid);
      const full = (await this._req('GET', `/messages/${mid}`)) || {};
      const blob = ['subject', 'intro', 'text', 'html']
        .map((k) => String(full[k] ?? ''))
        .join(' ');
      const hit = cb(blob);
      if (hit) return hit;
    }
    return null;
  }
}

// --------------------------------------------------------------- tempmail.plus

export class TempMailPlus extends BaseProvider {
  /**
   * tempmail.plus invent-style shared inbox (no create).
   *
   * Invent local@domain, poll /api/mails. Shared = OTP race risk.
   * Domains: mailto.plus, fexpost.com, fexbox.org, mailbox.in.ua, ...
   */
  BASE = 'https://tempmail.plus/api';
  DOMAINS = ['fextemp.com'];

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
    this.domain = null;
    this.local = null;
  }

  async create_account() {
    this.local = `xai${randHex(10)}`;
    this.domain = pick(this.DOMAINS);
    this.address = `${this.local}@${this.domain}`;
    // warm list endpoint
    const r = await this.s.get(`${this.BASE}/mails`, {
      params: { email: this.address, limit: 1, epin: '' },
      headers: { Accept: 'application/json' },
      timeout: 30,
    });
    if (r.status >= 400) {
      throw new Error(`tempmail.plus invent ${r.status}: ${r.text.slice(0, 200)}`);
    }
    return this.address;
  }

  async wait_code(timeout = 150) {
    if (!this.address) throw new Error('tempmail.plus no address');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const r = await this.s.get(`${this.BASE}/mails`, {
        params: { email: this.address, limit: 20, epin: '' },
        headers: { Accept: 'application/json' },
        timeout: 30,
      });
      if (r.status < 400 && r.content.length) {
        const data = r.content.length ? r.json() : {};
        let mails = data.mail_list || data.mails || data.list || [];
        if (Array.isArray(data)) mails = data;
        for (const m of mails) {
          const mid = String(m.mail_id ?? m.id ?? m._id ?? '');
          if (!mid || seen.has(mid)) continue;
          seen.add(mid);
          const blob = ['subject', 'from_mail', 'from', 'text', 'preview', 'summary']
            .map((k) => String(m[k] ?? ''))
            .join(' ');
          let code = extractCode(blob);
          if (code) return code;
          // full body
          try {
            const r2 = await this.s.get(`${this.BASE}/mails/${mid}`, {
              params: { email: this.address, epin: '' },
              headers: { Accept: 'application/json' },
              timeout: 30,
            });
            if (r2.status < 400 && r2.content.length) {
              const full = r2.json();
              const blob2 = ['subject', 'text', 'html', 'from_mail', 'from', 'body']
                .map((k) => String(full[k] ?? ''))
                .join(' ');
              code = extractCode(blob2);
              if (code) return code;
            }
          } catch {
            /* 全文拿不到就靠摘要 */
          }
        }
      }
      await sleep(3000);
    }
    throw new Error(`tempmail.plus no OTP for ${this.address}`);
  }
}

// ------------------------------------------------------------------- maildrop

export class Maildrop extends BaseProvider {
  /** maildrop.cc GraphQL invent-style shared inbox. */
  GQL = 'https://api.maildrop.cc/graphql';
  DOMAIN = 'maildrop.cc';
  INBOX_Q = 'query($mailbox:String!){inbox(mailbox:$mailbox){id headerfrom subject date}}';
  MSG_Q =
    'query($mailbox:String!,$id:String!)' +
    '{message(mailbox:$mailbox,id:$id){id headerfrom subject data html}}';

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
    this.mailbox = null;
  }

  async create_account() {
    this.mailbox = `xai${randHex(10)}`;
    this.address = `${this.mailbox}@${this.DOMAIN}`;
    // warm inbox query
    const r = await this.s.post(this.GQL, {
      json: { query: this.INBOX_Q, variables: { mailbox: this.mailbox } },
      headers: JSON_HEADERS,
      timeout: 30,
    });
    if (r.status >= 400) {
      throw new Error(`maildrop invent ${r.status}: ${r.text.slice(0, 200)}`);
    }
    return this.address;
  }

  async wait_code(timeout = 150) {
    if (!this.mailbox) throw new Error('maildrop no mailbox');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      const r = await this.s.post(this.GQL, {
        json: { query: this.INBOX_Q, variables: { mailbox: this.mailbox } },
        headers: JSON_HEADERS,
        timeout: 30,
      });
      if (r.status < 400 && r.content.length) {
        const data = r.content.length ? r.json() : {};
        const msgs = (data.data || {}).inbox || [];
        for (const m of msgs) {
          const mid = String(m.id || '');
          if (!mid || seen.has(mid)) continue;
          seen.add(mid);
          const blob = ['subject', 'headerfrom'].map((k) => String(m[k] ?? '')).join(' ');
          let code = extractCode(blob);
          if (code) return code;
          // full message
          try {
            const r2 = await this.s.post(this.GQL, {
              json: { query: this.MSG_Q, variables: { mailbox: this.mailbox, id: mid } },
              headers: JSON_HEADERS,
              timeout: 30,
            });
            if (r2.status < 400 && r2.content.length) {
              const full = (r2.json().data || {}).message || {};
              const blob2 = ['subject', 'headerfrom', 'data', 'html']
                .map((k) => String(full[k] ?? ''))
                .join(' ');
              code = extractCode(blob2);
              if (code) return code;
            }
          } catch {
            /* 全文拿不到就靠摘要 */
          }
        }
      }
      await sleep(3000);
    }
    throw new Error(`maildrop no OTP for ${this.address}`);
  }
}

// -------------------------------------------------------------------- ncaori

export class NcaoriMail extends BaseProvider {
  /**
   * GAC-proven catch-all: invent *@ncaori.my.id / *@nca.my.id, poll nca.my.id API.
   *
   * Inbox response already includes full body_text/body_html — no separate read.
   */
  BASE = 'https://www.nca.my.id';
  DOMAINS = ['ncaori.my.id', 'nca.my.id'];
  WORDS1 = [
    'swift', 'crystal', 'storm', 'frost', 'shadow', 'ember', 'azure',
    'phantom', 'silver', 'iron', 'crimson', 'golden', 'neo', 'cosmic',
    'lunar', 'solar', 'dark', 'light', 'void', 'flux',
  ];
  WORDS2 = [
    'core', 'leaf', 'forge', 'wave', 'peak', 'gate', 'pulse', 'blade',
    'shard', 'drift', 'hive', 'node', 'edge', 'beacon', 'nova', 'cloud',
    'moon', 'star', 'wind', 'spark',
  ];

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
  }

  async create_account() {
    const local = `${pick(this.WORDS1)}_${pick(this.WORDS2)}${randHex(4)}`;
    const domain = pick(this.DOMAINS);
    this.address = `${local}@${domain}`;
    // warm inbox endpoint (invent style — no explicit create)
    const r = await this.s.get(`${this.BASE}/api/emails`, {
      params: { recipient: this.address },
      headers: JSON_HEADERS,
      timeout: 30,
    });
    if (r.status >= 500) {
      throw new Error(`ncaori warm ${r.status}: ${r.text.slice(0, 120)}`);
    }
    return this.address;
  }

  async wait_code(timeout = 150) {
    if (!this.address) throw new Error('ncaori no OTP for no address');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    // adaptive poll: fast first 20s, then ease (mail usually lands 2–8s)
    let poll = Number(process.env.OTP_POLL_S ?? 0.8);
    const pollMax = Number(process.env.OTP_POLL_MAX_S ?? 2.0);
    const t0 = nowSec();
    while (nowSec() < deadline) {
      const r = await this.s.get(`${this.BASE}/api/emails`, {
        params: { recipient: this.address },
        headers: JSON_HEADERS,
        timeout: 15,
      });
      if (r.status < 400 && r.content.length) {
        let data;
        try {
          data = r.json();
        } catch {
          data = {};
        }
        const msgs = data && typeof data === 'object' ? data.emails : [];
        for (const m of msgs || []) {
          const mid = String(m.id || '');
          if (mid && seen.has(mid)) continue;
          if (mid) seen.add(mid);
          const blob = ['subject', 'sender', 'body_text', 'body_html', 'preview']
            .map((k) => String(m[k] ?? ''))
            .join(' ');
          const code = extractCode(blob);
          if (code) return code;
        }
      }
      // ramp poll interval after first 12s
      if (nowSec() - t0 > 12) poll = Math.min(pollMax, poll * 1.15);
      await sleep(poll * 1000);
    }
    throw new Error(`ncaori no OTP for ${this.address}`);
  }
}

// ------------------------------------------------------------------ zoromail

export class Zoromail extends BaseProvider {
  /**
   * GAC-proven REST tempmail: domains from API, create email, poll messages.
   *
   * https://zoromail.com/public_api.php/v1
   */
  API = 'https://zoromail.com/public_api.php/v1';

  constructor() {
    super();
    this.s = new Session();
    this.address = null;
  }

  async _api(method, path, kw = {}) {
    const { headers: extra, timeout, ...rest } = kw;
    const r = await this.s.request(method, this.API + path, {
      headers: { ...JSON_HEADERS, ...(extra || {}) },
      timeout: timeout ?? 30,
      ...rest,
    });
    if (r.status >= 400) {
      throw new Error(`zoromail ${method} ${path} -> ${r.status} ${r.text.slice(0, 160)}`);
    }
    let payload;
    try {
      payload = r.content.length ? r.json() : {};
    } catch (e) {
      throw new Error(`zoromail bad json: ${e.message}`);
    }
    if (!payload || typeof payload !== 'object' || payload.success !== true) {
      const err = payload && typeof payload === 'object' ? payload.error : payload;
      throw new Error(`zoromail api error: ${JSON.stringify(err)}`);
    }
    return payload.data;
  }

  async create_account() {
    const domains = await this._api('GET', '/domains');
    if (!Array.isArray(domains) || !domains.length) throw new Error('zoromail no domains');
    const domain = pick(domains);
    const username = `xai${randHex(10)}`;
    const data = await this._api('POST', '/emails', {
      json: { username, domain },
    });
    this.address =
      data && typeof data === 'object' ? data.email || `${username}@${domain}` : `${username}@${domain}`;
    return this.address;
  }

  async wait_code(timeout = 150) {
    if (!this.address) throw new Error('zoromail no address');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      let msgs;
      try {
        msgs = (await this._api('GET', `/emails/${this.address}/messages`)) || [];
      } catch {
        msgs = [];
      }
      if (!Array.isArray(msgs)) msgs = [];
      for (const m of msgs) {
        const mid = String(m.id || '');
        if (mid && seen.has(mid)) continue;
        if (mid) seen.add(mid);
        const blob = ['subject', 'from', 'preview', 'text']
          .map((k) => String(m[k] ?? ''))
          .join(' ');
        let code = extractCode(blob);
        if (code) return code;
        if (mid) {
          try {
            const full = (await this._api('GET', `/messages/${mid}`)) || {};
            const blob2 = ['subject', 'from', 'text', 'body_text', 'html', 'body_html']
              .map((k) => String(full[k] ?? ''))
              .join(' ');
            code = extractCode(blob2);
            if (code) return code;
          } catch {
            /* 全文拿不到就靠摘要 */
          }
        }
      }
      await sleep(3000);
    }
    throw new Error(`zoromail no OTP for ${this.address}`);
  }
}

// ------------------------------------------------------------------- temp.tf

export class TempTfGmail extends BaseProvider {
  /**
   * temp.tf — real @gmail.com addresses via Gmail dot-trick + sub-addressing.
   *
   * 100% Pure-HTTP:
   *   allocate : GET  https://temp.tf/api/account?providers=gmail&dot=1&plus=0
   *              -> {"email":"user.dot.alias@gmail.com"}
   *   poll msg : POST https://temp.tf/api/check  {"email":"<addr>","wait":false}
   *              -> {"data":[{subject,from,date,body,...}], "totalReceived":N}
   *
   * 2026-09-29 findings (live-verified):
   *   * Only 3-5 real @gmail seed accounts behind the service (checked via
   *     /api/stats: "accounts":{"gmail":5,...}). Repeated allocation rotates
   *     among the same handful of bases -> xAI strips the dots, sees ONE base
   *     address, and hits every base with per-address send rate limits.
   *   * `plus=1&dot=0` yields MORE unique bases per N allocations than
   *     `dot=1&plus=0` (5 uniques per 8 vs 3 per 12) because the plus-tag
   *     addresses are served from a wider seed rotation. Default now uses
   *     dot=0&plus=1; `dot_mode="dot"` restores dot-only.
   *   * Mailbox polling must ignore historic mail on the shared seed inbox —
   *     only accept messages that landed AFTER we allocated the address.
   */
  BASE = 'https://temp.tf/api';

  constructor(dotMode = null, provider = 'gmail') {
    super();
    this.s = new Session();
    this.address = null;
    this.provider = String(provider || 'gmail').trim().toLowerCase();
    // plus-tag spreads the allocation across more base seeds (see docstring)
    this.dot_mode = String(dotMode || 'plus').trim().toLowerCase();
    // seeded so we only accept mail that arrived AFTER this mailbox was created
    this.started_at = nowSec();
  }

  static _parse_ts(v) {
    if (!v) return null;
    // Python datetime.fromisoformat(...).timestamp() → 秒；JS Date.parse → 毫秒
    const ms = Date.parse(String(v));
    return Number.isNaN(ms) ? null : ms / 1000;
  }

  async create_account() {
    const dot = this.dot_mode === 'dot' ? '1' : '0';
    const plus = this.dot_mode === 'dot' ? '0' : '1';
    const r = await this.s.get(`${this.BASE}/account`, {
      params: this.provider === 'edu' ? {} : { providers: this.provider, dot, plus },
      headers: { Accept: 'application/json', Referer: 'https://temp.tf/' },
      timeout: 30,
    });
    if (r.status >= 400) {
      throw new Error(`temp.tf alloc ${r.status}: ${r.text.slice(0, 200)}`);
    }
    const data = r.content.length ? r.json() : {};
    const addr = String(data.email || data.address || '').trim().toLowerCase();
    if (!addr || !addr.includes('@')) {
      throw new Error(`temp.tf bad alloc: ${JSON.stringify(data)}`);
    }
    const okSuffix =
      (this.provider === 'gmail' && addr.endsWith('@gmail.com')) ||
      (this.provider === 'outlook' && addr.endsWith('@outlook.com')) ||
      (this.provider === 'hotmail' && addr.endsWith('@hotmail.com')) ||
      this.provider === 'edu';
    if (!okSuffix) throw new Error(`temp.tf unexpected addr for ${this.provider}: ${addr}`);
    this.address = addr;
    this.started_at = nowSec();
    return addr;
  }

  async wait_code(timeout = 150) {
    if (!this.address) throw new Error('temp.tf no address');
    const deadline = nowSec() + timeout;
    const seen = new Set();
    while (nowSec() < deadline) {
      let r;
      try {
        r = await this.s.post(`${this.BASE}/check`, {
          json: { email: this.address, wait: false },
          headers: {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            Referer: 'https://temp.tf/',
          },
          timeout: 30,
        });
      } catch {
        await sleep(2000);
        continue;
      }
      if (r.status < 400 && r.content.length) {
        let data;
        try {
          data = r.json();
        } catch {
          data = {};
        }
        let msgs = data.data || [];
        if (!Array.isArray(msgs)) msgs = [msgs];
        for (const m of msgs) {
          const mid = String(m.id || '');
          const ts = TempTfGmail._parse_ts(m.date);
          // shared seed inbox can carry tons of unrelated historic mail —
          // only consider messages that landed after we allocated
          if (ts !== null && ts < this.started_at - 60) continue;
          if (mid && seen.has(mid)) continue;
          if (mid) seen.add(mid);
          const blob = ['subject', 'from', 'body', 'text', 'html', 'content', 'preview']
            .map((k) => String(m[k] ?? ''))
            .join(' ');
          const code = extractCode(blob);
          if (code) return code;
        }
      }
      await sleep(2500);
    }
    throw new Error(`temp.tf no OTP for ${this.address}`);
  }

  /** wait_link 用：扫当前邮件，把能拼出链接的 blob 交给 cb。 */
  async _iter_messages(cb, seen = new Set()) {
    if (!this.address) return null;
    let r;
    try {
      r = await this.s.post(`${this.BASE}/check`, {
        json: { email: this.address, wait: false },
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          Referer: 'https://temp.tf/',
        },
        timeout: 30,
      });
    } catch {
      return null;
    }
    if (r.status >= 400 || !r.content.length) return null;
    let data;
    try {
      data = r.json();
    } catch {
      return null;
    }
    let msgs = data.data || [];
    if (!Array.isArray(msgs)) msgs = [msgs];
    for (const m of msgs) {
      const mid = String(m.id || JSON.stringify(m));
      const ts = TempTfGmail._parse_ts(m.date);
      if (ts !== null && ts < this.started_at - 60) continue;
      if (seen.has(mid)) continue;
      seen.add(mid);
      const blob = ['subject', 'from', 'body', 'text', 'html', 'content', 'preview']
        .map((k) => String(m[k] ?? ''))
        .join(' ');
      const hit = cb(blob);
      if (hit) return hit;
    }
    return null;
  }
}

// ------------------------------------------------------------------ EmailBox

export class EmailBox {
  /** Unified mailbox: create_account() + wait_code() + address. */

  // GAC-proven first (custom domains), then best free pure-API from bake-off.
  // Disposable classics last — often domain-rejected by xAI.
  static DEFAULT_PREFER = [
    // 2026-09-30: BOZ's own catch-all — immune to the xAI disposable purge,
    // unlimited aliases (no per-base send limit like temp.tf's 5 seeds).
    // TEST FIRST: it's the only provider that scales.
    // real @gmail.com, domain accepted — limited by per-base rate limit only
    'temp.tf',
    // fast-fail (domain rejected, ~1-5s each)
    'mail.tm',
    'smailpro',
    'tempmail.plus',
    'guerrilla',
    'maildrop',
    'temp-mail.io',
    // slow-fail (domain accepted, OTP never arrives ~80-120s)
    'tempmail.lol',
    'ncaori',
    // emailnator works but Gmail alias pool is small (existing email errors)
    'emailnator',
    // zoromail: API DNS unresachable as of 2026-09-30
    'zoromail',
  ];

  // Canonical names for matrix tests / CLI
  static ALL = [
    'ncaori',
    'zoromail',
    'tempmail.lol',
    'temp-mail.io',
    'emailnator',
    'smailpro',
    'guerrilla',
    'mail.tm',
    'tempmail.plus',
    'maildrop',
    'temp.tf',
  ];

  constructor(prefer = null) {
    this.prefer = prefer || [...EmailBox.DEFAULT_PREFER];
    this.provider_name = null;
    this.impl = null;
    this.address = null;
  }

  static make(name) {
    if (['ncaori', 'ncaorimail', 'nca'].includes(name)) return new NcaoriMail();
    if (['zoromail', 'zoro'].includes(name)) return new Zoromail();
    if (['smailpro', 'smail', 'sonjj'].includes(name)) return new SmailPro();
    if (['emailnator', 'gmailnator'].includes(name)) return new EmailNator();
    if (['temp-mail.io', 'tempmail.io', 'tempmailio'].includes(name)) return new TempMailIO();
    if (['tempmail.lol', 'tempmail', 'lol'].includes(name)) return new TempMailLol();
    if (['guerrilla', 'guerrillamail'].includes(name)) return new GuerrillaMail();
    if (['mail.tm', 'mailtm'].includes(name)) return new MailTM();
    if (['tempmail.plus', 'tempmailplus', 'plus'].includes(name)) return new TempMailPlus();
    if (['maildrop', 'maildrop.cc'].includes(name)) return new Maildrop();
    if (['temp.tf', 'temptf', 'temp-tf', 'temptf_gmail'].includes(name)) return new TempTfGmail(null, 'gmail');
    if (['temp.tf-outlook', 'temptf-outlook'].includes(name)) return new TempTfGmail(null, 'outlook');
    if (['temp.tf-hotmail', 'temptf-hotmail'].includes(name)) return new TempTfGmail(null, 'hotmail');
    throw new Error(`unknown mail provider: ${name}`);
  }

  async create_account() {
    const errors = [];
    for (const name of this.prefer) {
      let impl;
      try {
        impl = EmailBox.make(name);
        const addr = await impl.create_account();
        this.impl = impl;
        this.provider_name = name;
        this.address = addr;
        return addr;
      } catch (e) {
        impl?.close();
        errors.push(`${name}: ${e.message}`);
      }
    }
    throw new Error(`all email providers failed: ${errors.join(' | ')}`);
  }

  wait_code(timeout = 150) {
    if (!this.impl) throw new Error('no mailbox');
    return this.impl.wait_code(timeout);
  }

  /**
   * 等一封带链接的邮件（确认信）。只有实现了 _iter_messages 的 provider 支持；
   * target 应该把自己的 mailPrefer 限制在这些 provider 上。
   */
  wait_link(timeout = 150, pattern = null) {
    if (!this.impl) throw new Error('no mailbox');
    return this.impl.wait_link(timeout, pattern);
  }

  close() {
    this.impl?.close();
    this.impl = null;
  }
}

// 直接用 node lib/mail_providers.js 跑一次冒烟
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const box = new EmailBox();
  try {
    const addr = await box.create_account();
    console.log(addr, box.provider_name);
  } finally {
    box.close();
  }
}
