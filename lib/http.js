/**
 * lib/http.js — 零依赖 HTTP 层，替代 curl_cffi.Session
 *
 * curl_cffi 的核心价值是 TLS 指纹伪装（JA3/JA4）。Node 没有 1:1 等价物，
 * 这里用 node:https + node:tls 手工拼一个 Chrome 形状的 ClientHello：
 *   ciphers / sigalgs / ecdhCurve / minVersion / maxVersion / ALPN
 *
 * 已知上限（ponytail）：
 *   1. ALPN 固定 ['http/1.1'] — 真 Chrome 发 h2 优先。OpenSSL 扩展顺序 != BoringSSL，
 *      JA3 不会 100% 匹配。要更强指纹 → 换 cycletls 或 curl-impersonate sidecar。
 *   2. Cookie jar 按 host+name 存，不实现 RFC6265 的 path/expiry/samesite。
 *      这些 provider 每个 session 只对一个 host 说话，够用。
 */

import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { URL, URLSearchParams } from 'node:url';

// Chrome 的 TLS1.2 密码套件顺序（TLS1.3 suites 用 Node/OpenSSL 默认值，
// 恰与 Chrome 一致：AES128-GCM / AES256-GCM / CHACHA20-POLY1305）
const CHROME_CIPHERS = [
  'ECDHE-ECDSA-AES128-GCM-SHA256',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-CHACHA20-POLY1305',
  'ECDHE-RSA-CHACHA20-POLY1305',
  'ECDHE-RSA-AES128-SHA',
  'ECDHE-RSA-AES256-SHA',
  'AES128-GCM-SHA256',
  'AES256-GCM-SHA384',
  'AES128-SHA',
  'AES256-SHA',
].join(':');

// Chrome 的 signature_algorithms 顺序
const CHROME_SIGALGS = [
  'ecdsa_secp256r1_sha256',
  'rsa_pss_rsae_sha256',
  'rsa_pkcs1_sha256',
  'ecdsa_secp384r1_sha384',
  'rsa_pss_rsae_sha384',
  'rsa_pkcs1_sha384',
  'rsa_pss_rsae_sha512',
  'rsa_pkcs1_sha512',
  'rsa_pss_pss_sha256',
  'rsa_pss_pss_sha384',
  'rsa_pss_pss_sha512',
].join(':');

export const CHROME_TLS = {
  ciphers: CHROME_CIPHERS,
  sigalgs: CHROME_SIGALGS,
  ecdhCurve: 'X25519:P-256:P-384',
  minVersion: 'TLSv1.2',
  maxVersion: 'TLSv1.3',
  ALPNProtocols: ['http/1.1'],
  honorCipherOrder: true,
};

export const DEFAULT_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36';

// ---------------------------------------------------------------- cookie jar

function parseSetCookie(line) {
  const semi = line.indexOf(';');
  const pair = semi === -1 ? line : line.slice(0, semi);
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  return { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim() };
}

export class CookieJar {
  constructor() {
    /** @type {Map<string, {value: string, host: string}>} */
    this.map = new Map();
  }

  store(setCookieLines, host) {
    for (const line of setCookieLines ?? []) {
      const c = parseSetCookie(line);
      if (c) this.map.set(`${host}\t${c.name}`, { value: c.value, host });
    }
  }

  get(name, host) {
    if (host !== undefined) {
      const hit = this.map.get(`${host}\t${name}`);
      if (hit) return hit.value;
    }
    for (const [key, c] of this.map) {
      if (!key.endsWith(`\t${name}`)) continue;
      // 域 cookie 回退：请求 host 是存储 host 的子域
      if (host === undefined || host === c.host || host.endsWith(`.${c.host}`)) return c.value;
    }
    return undefined;
  }

  header(host) {
    const out = [];
    for (const [key, c] of this.map) {
      const name = key.slice(key.indexOf('\t') + 1);
      if (host === c.host || host.endsWith(`.${c.host}`)) out.push(`${name}=${c.value}`);
    }
    return out.join('; ');
  }
}

// ------------------------------------------------------------- proxy tunnel

/** 从 socket 精确读 n 字节，多读的部分 unshift 回 stream。 */
function readN(sock, n) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < n) return;
      sock.off('data', onData);
      sock.off('error', onErr);
      const rest = buf.subarray(n);
      if (rest.length) sock.unshift(rest);
      resolve(buf.subarray(0, n));
    };
    const onErr = (e) => {
      sock.off('data', onData);
      reject(e);
    };
    sock.on('data', onData);
    sock.once('error', onErr);
  });
}

function parseProxy(raw) {
  const u = new URL(raw.includes('://') ? raw : `http://${raw}`);
  return {
    scheme: u.protocol.replace(':', ''),
    host: u.hostname,
    port: Number(u.port || (u.protocol === 'socks5:' || u.protocol === 'socks5h:' ? 1080 : 8080)),
    username: u.username ? decodeURIComponent(u.username) : '',
    password: u.password ? decodeURIComponent(u.password) : '',
  };
}

function httpConnectTunnel(p, host, port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(p.port, p.host);
    sock.once('error', reject);
    sock.once('connect', () => {
      const auth = p.username
        ? `Proxy-Authorization: Basic ${Buffer.from(`${p.username}:${p.password}`).toString('base64')}\r\n`
        : '';
      sock.write(
        `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`,
      );
      let buf = Buffer.alloc(0);
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        sock.off('data', onData);
        const status = Number(buf.subarray(0, idx).toString('latin1').split(' ')[1]);
        if (status !== 200) {
          sock.destroy();
          reject(new Error(`proxy CONNECT ${status}`));
          return;
        }
        const rest = buf.subarray(idx + 4);
        if (rest.length) sock.unshift(rest);
        resolve(sock);
      };
      sock.on('data', onData);
    });
  });
}

async function socks5Connect(p, host, port) {
  const sock = await new Promise((resolve, reject) => {
    const s = net.connect(p.port, p.host);
    s.once('error', reject);
    s.once('connect', () => resolve(s));
  });

  try {
    const methods = p.username ? [0x00, 0x02] : [0x00];
    sock.write(Buffer.from([0x05, methods.length, ...methods]));

    const [, method] = await readN(sock, 2);
    if (method === 0x02) {
      const u = Buffer.from(p.username);
      const pw = Buffer.from(p.password);
      sock.write(Buffer.concat([Buffer.from([0x01, u.length]), u, Buffer.from([pw.length]), pw]));
      const [av, st] = await readN(sock, 2);
      if (av !== 0x01 || st !== 0x00) throw new Error('socks5 auth rejected');
    } else if (method !== 0x00) {
      throw new Error(`socks5 method 0x${method.toString(16)} rejected`);
    }

    const addr = Buffer.from(host, 'utf8');
    sock.write(
      Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, addr.length]),
        addr,
        Buffer.from([port >> 8, port & 0xff]),
      ]),
    );

    const [, rep, , atyp] = await readN(sock, 4);
    if (rep !== 0x00) throw new Error(`socks5 connect failed: 0x${rep.toString(16)}`);
    if (atyp === 0x03) {
      const [len] = await readN(sock, 1);
      await readN(sock, len + 2);
    } else {
      await readN(sock, (atyp === 0x01 ? 4 : 16) + 2);
    }
    return sock;
  } catch (e) {
    sock.destroy();
    throw e;
  }
}

function tlsOverSocket(sock, servername, tlsOpts) {
  return new Promise((resolve, reject) => {
    const t = tls.connect({ ...tlsOpts, socket: sock, servername });
    t.once('secureConnect', () => resolve(t));
    t.once('error', reject);
  });
}

function makeAgent(tlsOpts, proxy) {
  let agent;
  if (proxy) {
    const p = parseProxy(proxy);
    agent = new https.Agent({ keepAlive: true, maxSockets: 16 });

    // createConnection 必须赋到**实例属性**上。
    // 放进 new https.Agent({ createConnection }) 的构造 options 里不会被调用
    // （Node 26 实测：钩子静默失效，请求退化成直连目标 IP → ECONNREFUSED），
    // 而 agent.createConnection = fn 一定会被调用。
    agent.createConnection = (options, cb) => {
      const host = options.host;
      const port = Number(options.port) || 443;
      const tunnel =
        p.scheme === 'socks5' || p.scheme === 'socks5h'
          ? socks5Connect(p, host, port)
          : httpConnectTunnel(p, host, port);
      tunnel
        .then((sock) => tlsOverSocket(sock, options.servername || host, tlsOpts))
        .then((t) => cb(null, t))
        .catch(cb);
    };
  } else {
    agent = new https.Agent({ keepAlive: true, maxSockets: 16, ...tlsOpts });
  }

  // keepAlive 池里的空闲 socket 默认会 hold 住 event loop → 进程不退出。
  // 空闲时 unref，被请求真正占用时（_raw 的 'socket' 事件）再 ref 回来。
  agent.on('free', (sock) => sock.unref?.());
  return agent;
}

// ------------------------------------------------------------------ response

class Response {
  constructor(status, headers, content) {
    this.status = status;
    this.headers = headers;
    this.content = content;
  }

  get text() {
    return this.content.toString('utf8');
  }

  json() {
    return JSON.parse(this.text);
  }
}

function decompress(body, encoding) {
  const enc = (encoding || '').toLowerCase().trim();
  if (!body.length || !enc || enc === 'identity') return body;
  try {
    if (enc.includes('br')) return zlib.brotliDecompressSync(body);
    if (enc.includes('gzip')) return zlib.gunzipSync(body);
    if (enc.includes('deflate')) return zlib.inflateSync(body);
  } catch {
    return body; // 解压失败就当明文，别把整个流程炸掉
  }
  return body;
}

// ------------------------------------------------------------------- session

export class Session {
  /**
   * @param {object} [opts]
   * @param {string} [opts.proxy]   http:// / socks5:// URL
   * @param {object} [opts.tls]     覆盖 CHROME_TLS 的部分字段
   * @param {number} [opts.timeout] 默认超时（秒）
   * @param {string} [opts.userAgent]
   */
  constructor(opts = {}) {
    this.tlsOpts = { ...CHROME_TLS, ...(opts.tls || {}) };
    this.proxy = opts.proxy || null;
    this.timeout = opts.timeout ?? 30;
    this.userAgent = opts.userAgent || DEFAULT_UA;
    this.cookies = new CookieJar();
    this.headers = {};
    this.agent = makeAgent(this.tlsOpts, this.proxy);
  }

  close() {
    this.agent.destroy();
  }

  /**
   * @param {string} method
   * @param {string} url
   * @param {object} [o]
   * @param {object} [o.params]  查询参数（null/undefined 跳过）
   * @param {object} [o.headers]
   * @param {object} [o.json]    → application/json
   * @param {object|string} [o.data] → application/x-www-form-urlencoded
   * @param {number} [o.timeout] 秒
   * @param {number} [o.maxRedirects]
   * @param {string} [o.redirect] 'follow' | 'manual'
   */
  request(method, url, o = {}) {
    const maxRedirects = o.redirect === 'manual' ? 0 : (o.maxRedirects ?? 10);
    return this._send(method, url, o, maxRedirects);
  }

  async _send(method, url, o, redirectsLeft) {
    const u = new URL(url);
    for (const [k, v] of Object.entries(o.params || {})) {
      if (v !== null && v !== undefined) u.searchParams.set(k, String(v));
    }

    const headers = {
      'User-Agent': this.userAgent,
      'Accept-Encoding': 'gzip, deflate, br',
      ...this.headers,
      ...(o.headers || {}),
    };

    let body;
    if (o.json !== undefined) {
      body = Buffer.from(JSON.stringify(o.json));
      headers['Content-Type'] ??= 'application/json';
    } else if (o.data !== undefined) {
      body = Buffer.from(
        typeof o.data === 'string' ? o.data : new URLSearchParams(o.data).toString(),
      );
      headers['Content-Type'] ??= 'application/x-www-form-urlencoded';
    }

    const cookie = this.cookies.header(u.hostname);
    if (cookie) headers.Cookie = headers.Cookie ? `${headers.Cookie}; ${cookie}` : cookie;
    if (body) headers['Content-Length'] = String(body.length);

    const res = await this._raw(u, method, headers, body, o.timeout ?? this.timeout);

    this.cookies.store(res.headers['set-cookie'], u.hostname);

    const { status } = res;
    const loc = res.headers.location;
    if (loc && [301, 302, 303, 307, 308].includes(status) && redirectsLeft > 0) {
      const next = new URL(loc, u).toString();
      const keep = status === 307 || status === 308;
      return this._send(keep ? method : 'GET', next, {
        headers: o.headers,
        timeout: o.timeout,
      }, redirectsLeft - 1);
    }

    return new Response(status, res.headers, decompress(res.body, res.headers['content-encoding']));
  }

  _raw(u, method, headers, body, timeoutSec) {
    return new Promise((resolve, reject) => {
      const req = https.request(
        { hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, method, headers, agent: this.agent },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () =>
            resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }),
          );
          res.on('error', reject);
        },
      );

      const timer = setTimeout(() => {
        req.destroy(new Error(`timeout after ${timeoutSec}s: ${method} ${u.href}`));
      }, timeoutSec * 1000);

      // 从 keepAlive 池复用的 socket 在 'free' 时被 unref 过，占用期间要 ref 回来
      req.on('socket', (sock) => sock.ref?.());

      req.on('error', (e) => {
        clearTimeout(timer);
        reject(e);
      });
      req.on('close', () => clearTimeout(timer));
      if (body) req.write(body);
      req.end();
    });
  }

  get(url, o) {
    return this.request('GET', url, o);
  }

  post(url, o) {
    return this.request('POST', url, o);
  }
}
