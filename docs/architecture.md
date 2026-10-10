# 项目结构

`regfarm` 是一个**可插拔的注册任务框架**：通用编排在 `lib/`，站点专属流程在 `targets/`。
`top-tools-ai` 只是 `targets/` 下的一个模块，不是项目本体。

## 目录

```
cli.js                    入口：parseArgs + 自动扫描 targets/
lib/
  http.js                 零依赖 HTTP 层（Chrome TLS 指纹 / Cookie / 代理隧道）
  runner.js               通用编排：代理轮换 / 并发 / 重试 / 退避 / 限流 / 落盘
  util.js                 wibNow / sleep / uniform / monotonic / log / genPassword / makeSemaphore / readLines
  solver.js               Turnstile 求解器客户端（支持 action）
  mailbox.js              临时邮箱池（多 provider 轮询）+ pollOtp
  mail_providers.js       11 个临时邮箱 provider 实现（被 lib/mailbox.js 调用）
targets/
  top-tools-ai.js         注册目标：top-tools-ai.com（邮箱 OTP 型）
  alysis-code.js          注册目标：alysiscode.com（邮件确认链接 + 设备码换 key 型）
  tokenharbor.js          注册目标：tokenharbor.ai（Next.js Server Action + 邮件确认链接型）
reference/                Python 原版（参照实现，不参与运行）
test/                     离线单测
docs/                     本目录
```

## 分层

```
cli.js  →  lib/runner.js  →  targets/<name>.js
                ↓                    ↓
        lib/{solver,mailbox,     lib/http.js
             util}               lib/mail_providers.js
```

- **`targets/` 只管业务流程**：一个账号怎么注册出来
- **`lib/runner.js` 管通用编排**：代理轮换、并发、重试、退避、限流、落盘
- **`lib/http.js` / `lib/mail_providers.js` 是基础设施**：与具体站点无关

## 用法

```bash
regfarm --list                                   # 列出所有 target
regfarm --target top-tools-ai --count 12         # 跑 12 个
regfarm --target alysis-code --count 1           # 换一个 target
regfarm --target top-tools-ai --proxy-file proxies.txt --conc 2
```

> 未 `npm link` 时用 `node cli.js` 代替 `regfarm`，或 `npm start`。

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--target <name>` | 只有一个 target 时可省略 | 注册目标 |
| `--list` | — | 列出 `targets/` 下所有模块 |
| `--count` | 1 | 任务数 |
| `--conc` | 1 | 并发；服务端按 IP 限流，默认保持 1 |
| `--delay-min` / `--delay-max` | 25 / 45 | 任务间隔（秒），退避用 decorrelated jitter |
| `--proxy-file` | — | 每行一个代理，支持 `http://` 与 `socks5://` |
| `--mail-provider` | — | 固定单个邮箱源，默认轮询全部 |
| `--out-dir` | target 配置里的 `outDir` | 输出目录 |

## target 模块契约

`targets/<name>.js`，**文件名即 target 名**。必须导出三样，缺一个 `cli.js` 会直接报错：

| 导出 | 类型 | 说明 |
|------|------|------|
| `config` | object | 站点配置，见下表 |
| `registerOne(ctx)` | async function | 注册一个账号，返回结果对象 |
| `createMailbox()` | function | 返回邮箱池实例（一般 `createMailboxPool({prefer: config.mailPrefer})`） |

### `config` 字段

| 字段 | 必填 | 说明 |
|------|------|------|
| `baseUrl` | ✅ | 站点根地址 |
| `solverUrl` | ✅ | Turnstile 求解器地址（契约见 `lib/solver.js`） |
| `sitekey` | ✅ | Cloudflare Turnstile sitekey |
| `outDir` | ✅ | ledger / credentials 输出目录 |
| `referral` | — | 邀请码；留空跳过 claim |
| `userAgent` | — | 覆盖默认 UA |
| `mailPrefer` | — | 邮箱源优先级数组 |

### `registerOne(ctx)` 的 `ctx`

| 字段 | 说明 |
|------|------|
| `idx` | 任务序号 |
| `proxy` | 本次要用的代理，可能为 `null` |
| `mailbox` | `{ open() }` → `EmailBox`（`.address` / `.provider_name` / `.close()`） |
| `solve(pageUrl, opts?)` | 返回 Turnstile token；`opts.action` 覆盖 action，`opts.proxy` 覆盖出口 |
| `pollOtp(box, tries)` | 等 OTP 验证码 |
| `Session` | `lib/http.js` 的 Session 类 |
| `genPassword(n)` | 随机密码 |
| `sleep` / `uniform` / `log` | 工具函数 |
| `cfg` | 本模块的 `config` |

### 返回值

必须含 `email` / `password` / `created_at`。落盘用可选的 `credential_line`，
不给就按 `email | password | api_key | created_at` 拼。

### 邮箱：OTP 还是链接

两种确认方式都支持，看站点：

- **OTP 型**（top-tools-ai）：`ctx.pollOtp(box, tries)`，内部走 `EmailBox.wait_code()`
- **链接型**（alysis-code）：`box.wait_link(timeout, pattern)`，内部走 provider 的
  `_iter_messages()` + `extractLink()`。**只有实现了 `_iter_messages` 的 provider 支持**
  （目前 `mail.tm` / `tempmail.lol` / `temp-mail.io`），所以链接型 target 必须把自己的
  `mailPrefer` 限制在这几个上，否则会白等到超时。

### Turnstile action

Cloudflare 把 `action` 签进 token，站点服务端可以校验：

```js
await solve(`${cfg.baseUrl}/login`, { action: 'signup' });
await solve(`${cfg.baseUrl}/activate`, { action: 'device_approve' });
```

Supabase 自带的 captcha 校验**不看** action，但站点自建的 edge function 会看 ——
alysiscode.com 的 `device-approve` 就是（用错 action 的 token 会被判
`403 Verification failed`）。不需要 action 的站点不传即可。

## 新增一个注册目标

1. 抄 `targets/top-tools-ai.js`（OTP 型）或 `targets/alysis-code.js`（链接型）
2. 改 `config`（站点地址 / sitekey / solver / 邮箱源）
3. 改 `registerOne` 里的业务流程
4. 跑 `regfarm --list` 确认被扫到

**不需要改 `cli.js`** —— 目录里放好文件即生效。

## 已实现的目标

| target | 站点 | 确认方式 | 产物 |
|--------|------|----------|------|
| `top-tools-ai` | top-tools-ai.com | 邮箱 OTP（Clerk） | API key |
| `alysis-code` | alysiscode.com | 邮件确认链接 + 设备码 | `slk_` 网关 key |
| `tokenharbor` | tokenharbor.ai | 邮件确认链接 | `thk_live_` API key |

### alysis-code 要点

- **确认邮件里是链接**，不是 OTP → 用 `box.wait_link()`，`mailPrefer` 只列支持它的 provider。
- **注册不带 PKCE**：站点自己的前端带 `code_challenge`，那样邮件里会是 `pkce_` 前缀的
  token_hash，只有原浏览器能兑换。直连 Supabase REST 不带 `code_challenge`，拿到的
  token_hash 可以用 `POST /auth/v1/verify` 直接换 session。
- **两个 Turnstile action**：`signup` 和 `device_approve`。
- **`device-approve` 必须带 `Origin: https://alysiscode.com`**，否则
  `403 {"error":"Origin is not allowed."}`。
- **注册按 IP 限流**：同 IP 建几个号后所有 signup 返回 `403 error_code=unknown`
  （不是域名黑名单 —— 用不存在的域名试也一样）。必须配代理池，`--conc` 别开大。
- 产物 `slk_` key **不过期**，只能吊销（`POST /llm/v1/logout` 或站点 Devices → Revoke）。

### tokenharbor 要点

- **一个出口 IP 只能注册一个号**，第二个号起 Cloudflare 持续挡人机验证（HTTP 200 的
  interstitial 或 403）。IP 数就是上限，`--conc` 开大没意义。
- 注册走 **Next.js Server Action**：`multipart/form-data` + `Next-Action` header，
  响应 `text/x-component`。成功看响应体里有没有 `signedIn`，失败看 `"error":"..."`。
  字段名 `1_$ACTION_*` 里的 `$` / `:` 不能动。
- 确认邮件里是**链接**（`/verify-email?...`），所以 `mailPrefer` 只列实现了
  `_iter_messages` 的 provider。tempmail.lol 对 CN 免费档已关，mail.tm 排前。
- 邮件确认**不是注册成功的前提**：key 在确认之前就建好了，`wait_link` 超时只记
  `email_verified:false`，账号照留。
- Turnstile **必过**：不带 token 一律 `Please complete the human check`。走
  `captcha.tokents.top`，跟页面共用同一个代理出口。

## 代理

`--proxy-file` 每行一个 `http://` 或 `socks5://`。配合 PoolX 代理池时，把池端口写进去即可：

```
http://127.0.0.1:7910
http://127.0.0.1:7911
...
```

调度行为：

- `runner` 会把当前任务的代理透传给 `solve`，所以**注册和 captcha 走同一个出口 IP**。
  需要单次覆盖就传 `solve(url, { proxy: ... })`。
- **重试会换代理**（`proxyPool[(i + attempt) % len]`）—— 多数目标按 IP 限流，
  同一个 IP 重试三次没意义。

> `lib/http.js` 的代理隧道走 `agent.createConnection`（赋在**实例属性**上）。
> 放进 `new https.Agent({ createConnection })` 的构造 options 里 Node 不会调用 ——
> 钩子静默失效，请求退化成直连目标 IP，表现为 `ECONNREFUSED` 或超时。

## 输出落点

每个 target 自己的 `outDir` 下：

| 文件 | 内容 |
|------|------|
| `ledger.jsonl` | 每条一行完整 JSON（含 user_id / session_id / referral 状态） |
| `credentials.txt` | `email \| password \| api_key \| created_at` |

两个文件都会 `chmod 600`。
