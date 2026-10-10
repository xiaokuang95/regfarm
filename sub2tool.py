#!/usr/bin/env python3
"""sub2api 小工具：查询 / 改并发 / 删账号。

复用 deploy_sub2api.py 的鉴权方式（运行时从服务器签 admin JWT）。

子命令：
    list                     列出活跃的 alysis-* 账号
    setconc <n> <id...>      改一批账号的 concurrency
    delete <id...>           删除账号
    sql                      从 stdin 读 SQL 直接执行
"""
import base64, hashlib, hmac, json, os, subprocess, sys, time, urllib.error, urllib.request
from env import load_env

load_env()

HOST = os.environ.get("SUB2API_HOST") or ""
PORT = int(os.environ.get("SUB2API_PORT") or "8080")
SSH_HOST = os.environ.get("SUB2API_SSH") or os.environ.get("CPA_HOST") or ""
PGHOST = os.environ.get("PGHOST") or "127.0.0.1"
PGPORT = os.environ.get("PGPORT") or "5543"
PGUSER = os.environ.get("PGUSER") or "sub2api"
PGDATABASE = os.environ.get("PGDATABASE") or "sub2api"
PGPASSWORD = os.environ.get("PGPASSWORD") or ""
PSQL = f"psql -h {PGHOST} -p {PGPORT} -U {PGUSER} -d {PGDATABASE} -tA"


def ssh(cmd, stdin=None, timeout=30):
    if not SSH_HOST:
        sys.exit("SUB2API_SSH or CPA_HOST unset (see .env.example)")
    p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", SSH_HOST, cmd],
                       input=stdin, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        sys.exit(f"ssh failed: {p.stderr.strip()[-300:]}")
    return p.stdout


def sql(stmt):
    if not PGPASSWORD:
        sys.exit("PGPASSWORD unset (see .env.example)")
    return ssh(f"PGPASSWORD={PGPASSWORD} {PSQL} -f -", stdin=stmt)


def admin_token():
    raw = sql("SELECT email||chr(9)||password_hash FROM users WHERE id=1;").strip()
    email, pw_hash = [x.strip() for x in raw.split("\t", 1)]
    tv = int.from_bytes(hashlib.sha256((email.lower() + "\n" + pw_hash).encode()).digest()[:8], "big") & 0x7FFFFFFFFFFFFFFF
    secret = ssh("grep -A2 '^jwt:' /opt/sub2api/config.yaml | grep secret | awk '{print $2}'").strip()
    stamp = int(time.time())
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    b = b64(json.dumps({"user_id": 1, "email": email, "role": "admin", "token_version": tv,
                        "sid": "deploy", "exp": stamp + 3600, "iat": stamp, "nbf": stamp},
                       separators=(",", ":")).encode())
    return f"{h}.{b}." + b64(hmac.new(secret.encode(), f"{h}.{b}".encode(), hashlib.sha256).digest())


def api(tok, method, path, payload=None, timeout=60):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(f"http://{HOST}:{PORT}/api/v1{path}", data=data, method=method,
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:300].decode("utf-8", "replace")
    except Exception as e:
        return 0, f"transport: {e}"


def main():
    tok = admin_token()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"

    if cmd == "list":
        print(sql("SELECT name||' | '||status||' | conc='||concurrency||' | proxy='||COALESCE(proxy_id::text,'-')"
                  "||' | id='||id FROM accounts WHERE name LIKE 'alysis-%' AND deleted_at IS NULL ORDER BY id;"))

    elif cmd == "setconc":
        value = int(sys.argv[2])
        for aid in sys.argv[3:]:
            # 更新走 PUT /admin/accounts/{id}；PATCH 与 /concurrency 子路径都不存在。
            st, body = api(tok, "PUT", f"/admin/accounts/{aid}", {"concurrency": value})
            ok = "ok" if st == 200 else "FAIL"
            print(f"  {ok}  id={aid} -> concurrency={value}  (http {st})")
        print("\n当前分布：")
        print(sql("SELECT '  conc='||concurrency||' × '||count(*) FROM accounts"
                  " WHERE name LIKE 'alysis-%' AND deleted_at IS NULL GROUP BY concurrency ORDER BY concurrency;"))

    elif cmd == "delete":
        for aid in sys.argv[2:]:
            st, body = api(tok, "DELETE", f"/admin/accounts/{aid}")
            print(f"  id={aid} -> http {st} {str(body)[:80]}")

    elif cmd == "sql":
        print(sql(sys.stdin.read()))

    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
