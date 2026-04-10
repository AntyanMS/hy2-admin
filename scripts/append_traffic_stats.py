#!/usr/bin/env python3
"""Append trafficStats block to Hysteria2 config (run with sudo)."""
import secrets
import sys

PATH = "/etc/hysteria/config.yaml"
BLOCK = (
    "\n"
    "trafficStats:\n"
    "  listen: 127.0.0.1:25413\n"
    f"  secret: {secrets.token_hex(16)}\n"
)


def main() -> int:
    with open(PATH, "a", encoding="utf-8") as f:
        f.write(BLOCK)
    print("OK: appended trafficStats to", PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main())
