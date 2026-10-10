# regfarm 1.0.0

零依赖注册任务框架。Node >= 22。

```bash
cp .env.example .env   # CPA / sub2api 主机与库口令，不要提交 .env
```

## 解压后

```bash
node --test
node cli.js --list
node cli.js --target top-tools-ai --count 1 --proxy-file proxies.txt
node cli.js --target alysis-code  --count 1 --proxy-file proxies.txt
node cli.js --target tokenharbor  --count 1 --proxy-file proxies.txt
```

代理文件每行一个 `http://` 或 `socks5://`（PoolX 池端口直接写进去即可）。
输出默认 `~/projects/<site>_farm/out`。

## 内置目标

| target | 站点 | 确认方式 | 产物 |
|--------|------|----------|------|
| `top-tools-ai` | top-tools-ai.com | 邮箱 OTP（Clerk） | API key |
| `alysis-code` | alysiscode.com | 邮件确认链接 + 设备码 | `slk_` 网关 key |
| `tokenharbor` | tokenharbor.ai | 邮件确认链接 | `thk_live_` API key |

`alysis-code` 要点（细节见 `targets/alysis-code.js` 头部注释）：

- 注册**按 IP 限流** —— 同 IP 建几个号之后全部 403，必须配代理池，`--conc` 别开大
- 确认邮件里是**链接**，所以 `mailPrefer` 只列支持 `wait_link` 的 provider
- 两个 Turnstile action：`signup` / `device_approve`
- 产出的 `slk_` key **不过期**，只能吊销

`tokenharbor` 要点（细节见 `targets/tokenharbor.js` 头部注释）：

- **一个出口 IP 只能注册一个号**，第二个号起 Cloudflare 持续挡人机验证；IP 数就是上限，`--conc` 开大没意义
- 注册是 **Next.js Server Action**（multipart + `Next-Action` header，响应 `text/x-component`），字段名 `1_$ACTION_*` 不能动
- 确认邮件里是**链接**，`mailPrefer` 只列支持 `wait_link` 的 provider（mail.tm 排前，tempmail.lol 对 CN 免费档已关）
- 邮件确认**不是注册成功的前提**：key 先建好，`wait_link` 超时只记 `email_verified:false`，账号照留
- Turnstile **必过**，走 `captcha.tokents.top`，跟页面共用同一个代理出口

配置在 `targets/<name>.js`（站点、solver、邀请码、邮箱源）。
用法见 `docs/architecture.md`。
