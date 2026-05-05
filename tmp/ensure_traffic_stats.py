#!/usr/bin/env python3
from __future__ import annotations

import re
import secrets
from pathlib import Path


CFG = Path("/etc/hysteria/config.yaml")


def main() -> int:
    text = CFG.read_text(encoding="utf-8", errors="ignore")
    block_match = re.search(r"(?ms)^trafficStats:\s*\n(?:[ \t]+.*\n)*", text)

    secret = ""
    if block_match:
        m = re.search(r"(?m)^\s+secret:\s*(\S+)\s*$", block_match.group(0))
        if m:
            secret = m.group(1).strip()
    if not secret:
        secret = secrets.token_hex(16)

    new_block = f"trafficStats:\n  listen: 127.0.0.1:9999\n  secret: {secret}\n"
    if block_match:
        text = text[: block_match.start()] + new_block + text[block_match.end() :]
    else:
        if not text.endswith("\n"):
            text += "\n"
        text += "\n" + new_block

    CFG.write_text(text, encoding="utf-8")
    print(secret)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

