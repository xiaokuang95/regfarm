"""Load gitignored .env next to this file. Existing process env wins."""
from __future__ import annotations

import os
import pathlib


def load_env(path: str | os.PathLike[str] | None = None) -> None:
    p = pathlib.Path(path) if path else pathlib.Path(__file__).with_name(".env")
    if not p.is_file():
        return
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        if key and key not in os.environ:
            os.environ[key] = val
