#!/usr/bin/env python3
"""
sing-box 1.13+: sniff только через route rule action (не inbound.sniff).
Добавляет в начало route.rules два правила sniff для наших inbound-тегов.
Удаляет legacy sniff* с inbounds.
"""
from __future__ import annotations

import json
from pathlib import Path

CONFIG = Path("/etc/sing-box/config.json")
INBOUND_TAGS = ["in-vless-reality", "in-hy2"]

SNIFF_RULES = [
    {"inbound": tag, "action": "sniff", "timeout": "1s"} for tag in INBOUND_TAGS
]


def main() -> int:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))

    for ib in cfg.get("inbounds") or []:
        if not isinstance(ib, dict):
            continue
        ib.pop("sniff", None)
        ib.pop("sniff_override_destination", None)
        ib.pop("sniff_timeout", None)
        ib.pop("domain_strategy", None)

    route = cfg.get("route")
    if not isinstance(route, dict):
        raise SystemExit("no route")

    rules = route.get("rules")
    if not isinstance(rules, list):
        rules = []
        route["rules"] = rules

    # Убрать старые sniff-action с теми же inbound (если скрипт запускали дважды)
    filtered = []
    for r in rules:
        if not isinstance(r, dict):
            filtered.append(r)
            continue
        if r.get("action") == "sniff" and r.get("inbound") in INBOUND_TAGS:
            continue
        filtered.append(r)

    route["rules"] = SNIFF_RULES + filtered

    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("OK: route prepend sniff actions for", INBOUND_TAGS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
