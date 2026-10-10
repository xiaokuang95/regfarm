# 移植说明（Python → Node）

Python 原版已移到 `reference/`，只作参照，不参与运行。
本文只记录**移植相关的技术决策**：TLS 指纹方案、与 Python 的行为差异、验证记录。
项目结构与用法见 [architecture.md](./architecture.md)。

## 运行环境

- **Node >= 22**（用到 `node:util parseArgs`、顶层 await、`node --test`）
- **零 npm 依赖** —— 只用 Node 内置模块

## TLS 指纹方案（重要）

Python 版用 `curl_cffi` 做 TLS 指纹伪装（`impersonate="chrome136"/"chrome131"`）。
**Node 没有 1:1 等价物**，且 `undici` 在 Node 22 中内置但不对外暴露（`import 'undici'` 会 `MODULE_NOT_FOUND`）。

因此 `lib/http.js` 用 `node:https` + `node:tls` 手工构造 Chrome 形状的 ClientHello：
`ciphers` / `sigalgs` / `ecdhCurve` / `minVersion` / `maxVersion` / `ALPN`。

### 实测结果（tls.peet.ws，2026-10-01）

```
ja3      : 771,4866-4867-4865-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-0-11-10-35-16-22-23-13-43-45-51,29-23-24,0-1-2
ja3_hash : fc433f1448764ac006fe4055db7d79e7
ja4      : t13d1512h1_8daaf6152771_b4091cf95f14
```

**已匹配 Chrome：**
- TLS1.2 密码套件顺序（`49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53`）
- 椭圆曲线顺序 `29-23-24` = X25519 / P-256 / P-384

**已知偏差：**
1. **TLS1.3 suite 顺序** —— Node/OpenSSL 无 `ciphersuites` 选项，实测为 `4866-4867-4865`，Chrome 是 `4865-4866-4867`。
2. **ALPN 固定 `http/1.1`** —— 真 Chrome 发 `h2` 优先（JA4 里的 `h1` 就是这个）。改用 HTTP/2 需要重写 `lib/http.js` 的请求层。
3. **扩展顺序** —— OpenSSL 与 BoringSSL 不同，JA3 不会 100% 匹配。

**影响评估：** 纯 JSON REST 的 provider（temp.tf / mail.tm / maildrop / guerrilla / temp-mail.io / tempmail.lol / zoromail / tempmail.plus）不依赖指纹，实测 temp.tf 创建邮箱正常。
若 Cloudflare 类站点（emailnator / smailpro）出现 403，升级路径是换 `cycletls`（Go，真 JA3/JA4）或 `curl-impersonate` 外部二进制。

## 与 Python 版的差异

| 项 | Python | Node |
|----|--------|------|
| HTTP | `curl_cffi`（TLS 指纹） | `node:https` 手搓 Chrome profile（见上） |
| 本地 HTTP | `httpx.AsyncClient` | 原生 `fetch` |
| CLI | `argparse` | `node:util parseArgs` |
| 并发 | `asyncio.Semaphore` / `gather` | `Promise` + 自实现信号量 |
| 时区 | `datetime` + `timezone(timedelta(hours=7))` | `Intl.DateTimeFormat('sv-SE', {timeZone:'Asia/Jakarta'})` |
| 定时 | `time.monotonic()` | `performance.now()/1000` |
| 退出 | 自动 | `Session.close()` 必须调用（keepAlive socket 会挂住进程）；`lib/http.js` 已在 socket 空闲时 `unref` |

**行为差异：** 无。`_extract_code` 的 28 条语料差分测试结果与 Python 完全一致。

## 验证

```bash
node --test                     # 47 条离线断言
node lib/mail_providers.js      # 联网冒烟：创建 1 个 temp mailbox
regfarm --list                  # CLI 与配置装配
```

## 已知缺口

- 11 个 provider 中只有 `temp.tf` / `tempmail.plus` / `maildrop` 在真实注册流程中验证过，
  其余 8 个仅做代码对等移植，未经联网验证。
