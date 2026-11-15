#!/usr/bin/env python3
"""Add the 50x pool to sub2api (one account -> CPA, all farmed keys behind it)."""
import json, os, sys
import deploy_sub2api as d

GROUP_ID = 7          # opencode — the group the user's日常 key uses
ACCOUNT = "50x-farm"
CPA_KEY = os.environ.get("CPA_50X_KEY") or "sk-beXBRfTjpPMYaCWFRqHQYaPKZRJSPGaDxarhSyLumrOfmfmR"
MODEL = "deepseek-ai/DeepSeek-V4.1-Flash-1017"

payload = {
    "name": ACCOUNT,
    "platform": "openai",
    "type": "apikey",
    "credentials": {
        "api_key": CPA_KEY,
        "base_url": "http://127.0.0.1:8317",
        "pool_mode": True,
        "pool_mode_retry_count": 3,
        "model_mapping": {
            "deepseek-v4.1-flash": MODEL,
            "deepseek-50x": MODEL,
        },
    },
    "extra": d.EXTRA,
    "concurrency": 50,
    "priority": 50,
    "rate_multiplier": 1,
    "group_ids": [GROUP_ID],
    "auto_pause_on_expired": True,
    "upstream_billing_probe_enabled": False,
}

tok = d.admin_token()
st, code, msg, data = d.api(tok, "GET", "/admin/accounts?page_size=200&search=50x-farm")
existing = [a for a in (data.get("items") or []) if a.get("name") == ACCOUNT]
if existing:
    acc = existing[0]
    print(f"exists id={acc['id']} status={acc.get('status')}")
    if "--update" in sys.argv:
        st, code, msg, data = d.api(tok, "PUT", f"/admin/accounts/{acc['id']}", payload)
        print("update", st, code, msg)
    sys.exit(0)

st, code, msg, data = d.api(tok, "POST", "/admin/accounts", payload)
print("create", st, code, msg, json.dumps(data)[:300])
