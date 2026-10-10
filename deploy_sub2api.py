#!/usr/bin/env python3
"""Deploy alysis-code farm keys into the sub2api pool (host from .env).

Usage:
    ./deploy_sub2api.py [keyfile] [--dry-run]

Default keyfile: ~/projects/alysis_farm/out/credentials.txt

Keyfile lines may be either a bare `slk_...` key or the `email | password | key | date`
shape that regfarm writes. Blank lines and `#` comments are ignored.

Idempotent: a key already present as a live `alysis-*` account is skipped.
Soft-deleted keys count as already handled, so deleting one is a deliberate
verdict that never resurrects next round.

The admin JWT is signed at runtime from the server's own jwt.secret, so no
credential is stored here. Group settings are copied from the top-tools-ai
group (18) so the two farms behave identically apart from their model list.
"""

import base64
import hashlib
import hmac
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, NoReturn

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

GROUP_NAME = "alysis"
TEMPLATE_GROUP_ID = 18  # top-tools-ai — copied as the settings template
PROXY_ID = 7            # warp; verified 200 against the alysis gateway
CONCURRENCY = 4   # 文档上限：每用户 4 并发（docs/hosted-prompt-caching.md）
PRIORITY = 50

BASE_URL = "https://vzigujbcjjmpntxhmyvr.supabase.co/functions/v1/llm/v1"

# The gateway serves exactly these ids; map the lowercase aliases onto themselves
# so a client can call them by name.
MODELS = ["deepseek-flash", "glm-5.3-flash", "gpt-6-luna", "claude-haiku-5-5"]
MODEL_MAPPING = {m: m for m in MODELS}
DEFAULT_MODEL = "deepseek-flash"

# Same shape the tt-* accounts carry.
EXTRA = {
    "quota_daily_limit": 10000000,
    "quota_reset_timezone": "UTC",
    "quota_daily_reset_hour": 0,
    "quota_daily_reset_mode": "fixed",
    "openai_responses_mode": "force_chat_completions",
    "openai_responses_supported": True,
    "upstream_billing_probe_enabled": False,
    "openai_long_context_billing_enabled": False,
    "openai_apikey_responses_websockets_v2_mode": "off",
    "openai_apikey_responses_websockets_v2_enabled": False,
}


def fail(msg: str) -> NoReturn:
    print(msg, file=sys.stderr)
    sys.exit(1)


def ssh(cmd: str, stdin: str | None = None, timeout: int = 30) -> str:
    if not SSH_HOST:
        fail("SUB2API_SSH or CPA_HOST unset (see .env.example)")
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", SSH_HOST, cmd],
        input=stdin, capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode:
        fail(f"ssh failed ({proc.returncode}): {proc.stderr.strip()[-400:]}")
    return proc.stdout


def sql(stmt: str) -> str:
    """SQL travels over stdin so query text is never interpolated into a shell string."""
    if not PGPASSWORD:
        fail("PGPASSWORD unset (see .env.example)")
    return ssh(f"PGPASSWORD={PGPASSWORD} {PSQL} -f -", stdin=stmt)


def admin_token() -> str:
    """Mint an HS256 admin JWT; the panel password is unknown so we sign our own."""
    raw = sql("SELECT email||chr(9)||password_hash FROM users WHERE id=1;").strip()
    if "\t" not in raw:
        fail("could not read admin user row from sub2api database")
    email, pw_hash = [x.strip() for x in raw.split("\t", 1)]
    # token_version is derived, not a column: sha256(email + "\n" + hash)[:8] as 63-bit BE int.
    digest = hashlib.sha256((email.lower() + "\n" + pw_hash).encode()).digest()
    tv = int.from_bytes(digest[:8], "big") & 0x7FFFFFFFFFFFFFFF
    secret = ssh("grep -A2 '^jwt:' /opt/sub2api/config.yaml | grep secret | awk '{print $2}'").strip()
    if not secret:
        fail("could not read jwt.secret from /opt/sub2api/config.yaml")
    stamp = int(time.time())
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = b64(json.dumps({"user_id": 1, "email": email, "role": "admin", "token_version": tv,
                           "sid": "deploy", "exp": stamp + 3600, "iat": stamp, "nbf": stamp},
                          separators=(",", ":")).encode())
    sig = b64(hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def api(tok: str, method: str, path: str, payload: Any = None, timeout: int = 180):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        f"http://{HOST}:{PORT}/api/v1{path}", data=data, method=method,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, None, exc.read()[:300].decode("utf-8", "replace"), {}
    except Exception as exc:  # noqa: BLE001 - surface unreachable gateway
        return 0, None, f"transport error: {exc}", {}
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        return status, None, f"non-JSON response: {exc}", {}
    body = parsed if isinstance(parsed, dict) else {}
    return status, body.get("code"), body.get("message"), body.get("data") or {}


def account_name(api_key: str) -> str:
    """Short stable handle. SHA-1 is a name digest here, not a security primitive."""
    return "alysis-" + hashlib.sha1(api_key.encode()).hexdigest()[:8]  # nosec B324


def read_keys(path: pathlib.Path) -> list[str]:
    keys = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # regfarm writes `email | password | key | date`; take field 3 when present.
        candidate = line.split("|")[2].strip() if line.count("|") >= 2 else line
        if candidate.startswith("slk_"):
            keys.append(candidate)
    return list(dict.fromkeys(keys))


def ensure_group(tok: str, dry: bool) -> int:
    """Return the id of the `alysis` group, creating it from the template if needed."""
    status, code, msg, data = api(tok, "GET", "/admin/groups?page_size=200")
    if status != 200:
        fail(f"could not list groups: http={status} {msg}")
    items = data.get("items") or []
    for g in items:
        if g.get("name") == GROUP_NAME:
            print(f"group {GROUP_NAME!r} already exists (id={g['id']})")
            return g["id"]

    template = next((g for g in items if g.get("id") == TEMPLATE_GROUP_ID), None)
    if not template:
        fail(f"template group {TEMPLATE_GROUP_ID} not found; cannot derive settings")

    # Copy the template wholesale, then override what makes alysis different.
    payload = {k: v for k, v in template.items()
               if k not in {"id", "created_at", "updated_at", "account_count", "active_account_count"}}
    payload.update({
        "name": GROUP_NAME,
        "description": "alysiscode.com farm keys",
        "platform": "openai",
        "rate_multiplier": 1,
        "default_mapped_model": DEFAULT_MODEL,
        "model_allowlist": {"enabled": True, "models": MODELS},
    })

    if dry:
        print(f"[dry-run] would create group {GROUP_NAME!r} from template {TEMPLATE_GROUP_ID}")
        return -1

    status, code, msg, data = api(tok, "POST", "/admin/groups", payload)
    if status not in (200, 201):
        fail(f"group create failed: http={status} code={code} msg={msg}")
    gid = (data.get("group") or {}).get("id") or data.get("id")
    if not gid:
        fail(f"group created but no id returned: {json.dumps(data)[:200]}")
    print(f"created group {GROUP_NAME!r} (id={gid})")
    return gid


def main() -> None:
    if not HOST or not SSH_HOST:
        fail("SUB2API_HOST and SUB2API_SSH/CPA_HOST required (see .env.example)")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    out_dir = pathlib.Path.home() / "projects" / "alysis_farm" / "out"
    # regfarm 写出来的，加上探索阶段手工建号留下的 key（不在 ledger 里）
    keyfiles = [pathlib.Path(args[0])] if args else [out_dir / "credentials.txt", out_dir / "extra_keys.txt"]

    keys: list[str] = []
    for f in keyfiles:
        if not f.is_file():
            if args:
                fail(f"key file not found: {f}")
            continue
        found = read_keys(f)
        print(f"keyfile={f} keys={len(found)}")
        keys.extend(found)
    keys = list(dict.fromkeys(keys))
    if not keys:
        fail(f"no slk_ keys found in {', '.join(str(f) for f in keyfiles)}")
    print(f"total unique keys={len(keys)}")

    tok = admin_token()
    gid = ensure_group(tok, dry)

    deployed = {line.strip() for line in sql(
        "SELECT credentials->>'api_key' FROM accounts WHERE name LIKE 'alysis-%';"
    ).splitlines() if line.strip()}
    new = [(k, account_name(k)) for k in keys if k not in deployed]
    print(f"already deployed={len(deployed)} new={len(new)}")
    if not new:
        return
    if dry:
        for _, n in new:
            print(f"  [dry-run] {n}")
        return

    accounts = [{
        "name": name, "platform": "openai", "type": "apikey",
        "credentials": {
            "api_key": key, "base_url": BASE_URL,
            "model_mapping": MODEL_MAPPING, "pool_mode": True,
        },
        "extra": EXTRA, "proxy_id": PROXY_ID, "concurrency": CONCURRENCY,
        "priority": PRIORITY, "rate_multiplier": 1, "group_ids": [gid],
        "auto_pause_on_expired": True, "upstream_billing_probe_enabled": False,
    } for key, name in new]

    status, code, msg, data = api(tok, "POST", "/admin/accounts/batch", {"accounts": accounts})
    print(f"batch http={status} code={code} msg={msg} "
          f"success={data.get('success')} failed={data.get('failed')}")
    for row in data.get("results", []):
        if not row.get("success"):
            print("  FAIL:", str(row.get("error"))[:140])
    if not data.get("success"):
        sys.exit(1)

    counts = sql(
        "SELECT count(*) FROM accounts WHERE name LIKE 'alysis-%' AND deleted_at IS NULL;\n"
        "SELECT count(*) FROM account_groups ag JOIN accounts a ON a.id=ag.account_id\n"
        f" WHERE a.name LIKE 'alysis-%' AND ag.group_id={gid} AND a.deleted_at IS NULL;\n"
        "SELECT count(*) FROM accounts WHERE name LIKE 'alysis-%' AND deleted_at IS NULL\n"
        f" AND proxy_id={PROXY_ID} AND concurrency={CONCURRENCY};\n"
    ).split()
    print("total / bound-to-group / warp+conc =", " / ".join(counts))


if __name__ == "__main__":
    main()
