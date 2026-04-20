#!/usr/bin/env python3
"""
Явные правила для зон *.ru, *.рф, *.su на mskgw (sing-box):
  — domain_suffix идёт ПЕРВЫМ (до geoip-ru), чтобы CDN/зарубежный IP
    не уводил трафик на msgw.
  — .рф задаётся как Punycode .xn--p1ai.
"""
from __future__ import annotations

import json
from pathlib import Path

CONFIG = Path("/etc/sing-box/config.json")

RU_SUFFIXES = [".ru", ".xn--p1ai", ".su"]

# Явные хосты, которые часто уезжают на CDN / странный SNI
EXPLICIT_RU_HOSTS = ["2ip.ru", "www.2ip.ru"]

RULE_EXPLICIT = {"domain": EXPLICIT_RU_HOSTS, "outbound": "direct"}
RULE_RU_TLD = {"domain_suffix": RU_SUFFIXES, "outbound": "direct"}


def main() -> int:
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))
    route = cfg.get("route")
    if not isinstance(route, dict):
        raise SystemExit("no route section")

    rules = route.get("rules")
    if not isinstance(rules, list):
        rules = []
        route["rules"] = rules

    geoip_rule = None
    default_rule = None
    rest: list = []

    for r in rules:
        if not isinstance(r, dict):
            rest.append(r)
            continue
        rs = r.get("rule_set") or []
        if r.get("outbound") == "direct" and "geoip-ru" in rs:
            geoip_rule = r
            continue
        if r.get("outbound") == "to-msgw" and len(r) == 1:
            default_rule = r
            continue
        if r.get("domain_suffix") == RU_SUFFIXES or r.get("domain_suffix") == [
            ".ru",
            ".xn--p1ai",
            ".su",
        ]:
            continue  # пересоберём явно
        if r.get("domain") == EXPLICIT_RU_HOSTS:
            continue
        rest.append(r)

    if geoip_rule is None:
        geoip_rule = {
            "rule_set": ["geoip-ru"],
            "outbound": "direct",
        }
    if default_rule is None:
        default_rule = {"outbound": "to-msgw"}

    # Порядок: явные хосты → TLD → geoip → остальное → default
    new_rules: list = [RULE_EXPLICIT, RULE_RU_TLD, geoip_rule]
    new_rules.extend(rest)
    new_rules.append(default_rule)

    route["rules"] = new_rules
    CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("OK: order = explicit 2ip -> domain_suffix(ru/рф/su) -> geoip-ru -> ... -> to-msgw")
    print("     explicit:", EXPLICIT_RU_HOSTS)
    print("     suffixes:", RU_SUFFIXES)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
