#!/usr/bin/env python3
"""Собрать статический UI-preview всей index.html для правки на сервере без пересборки панели."""
from __future__ import annotations

import json
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
OUT = Path(__file__).resolve().parent / "index.html"

PANEL_PREFIX = "/70a99cc4aee89f9e/panel"


def mock_url_for(endpoint: str, **kwargs) -> str:
    if endpoint == "hy2.api_direct_routing_explicit_state_handler":
        return f"{PANEL_PREFIX}/api/server/direct-routing-explicit"
    if endpoint == "hy2.api_direct_routing_whitelist_state_handler":
        return f"{PANEL_PREFIX}/api/server/direct-routing-whitelist"
    path = endpoint.replace("hy2.", "").replace("_handler", "").replace("_", "-")
    if path in ("index",):
        return f"{PANEL_PREFIX}/"
    if path == "logout":
        return f"{PANEL_PREFIX}/logout"
    if path == "qr-handler" and "u" in kwargs:
        return f"{PANEL_PREFIX}/qr?u={kwargs['u']}"
    return f"{PANEL_PREFIX}/{path}"


def sample_users() -> tuple[list[dict], list[dict]]:
    def u(name: str, *, online: bool = False, disabled: bool = False) -> dict:
        return {
            "username": name,
            "is_online": online,
            "online_count": 2 if online else 0,
            "rx_h": "120 MB",
            "tx_h": "45 MB",
            "total_h": "165 MB",
            "total": 165_000_000,
            "traffic_limit_bytes": 0,
            "traffic_limit_h": "—",
            "traffic_remaining_h": "—",
            "traffic_usage_percent": 0,
            "duration_days": 0,
            "expires_at": "",
            "speed_up_mbps": 0,
            "speed_down_mbps": 0,
            "max_connections": 0,
            "current_ips": ["77.220.143.56"] if online else [],
            "history_ips": ["77.220.143.56"],
            "last_seen_ip": "77.220.143.56" if online else "",
            "last_seen_ip_at": "2026-05-21 16:00",
            "note": "",
        }

    active = [u("antyanmsa", online=True), u("demo_user_02"), u("demo_user_03")]
    disabled = [u("old_client", disabled=True)]
    return active, disabled


def sample_cascade_state() -> dict:
    servers = [
        {
            "node_id": "f9845730-0dc3-4fff-a7ae-fcaff0086032",
            "name": "SHAMAN-IL",
            "host": "msgw01.mooo.com",
            "api_port": 9443,
            "enabled": True,
            "role": "exit",
            "cascade_exit": True,
            "hy2_server": "msgw01.mooo.com",
            "hy2_port": 443,
            "hy2_sni": "msgw01.mooo.com",
            "hop_username": "mskgw_mooo_com",
            "hop_password_set": True,
            "hy2_insecure": False,
            "last_sync_ok": True,
            "last_sync_result": "ok:200",
            "last_sync_at": "2026-05-21T17:00:00+00:00",
            "last_sync_at_local": "21.05.2026 20:00",
        },
        {
            "node_id": "0632bbf9-cbc6-4c54-87d1-04b848184d53",
            "name": "msgw02-exit",
            "host": "msgw02.mooo.com",
            "api_port": 9443,
            "enabled": True,
            "role": "exit",
            "cascade_exit": True,
            "hy2_server": "msgw02.mooo.com",
            "hy2_port": 443,
            "hy2_sni": "msgw02.mooo.com",
            "hop_username": "mskgw_mooo_com",
            "hop_password_set": True,
            "hy2_insecure": True,
            "last_sync_ok": True,
            "last_sync_result": "ok:200",
            "last_sync_at": "2026-05-21T17:00:00+00:00",
            "last_sync_at_local": "21.05.2026 20:00",
        },
    ]
    return {
        "master_enabled": True,
        "servers": servers,
        "servers_count": len(servers),
        "exit_enabled_count": len(servers),
        "cascade_exit_pool_roles": ["exit"],
        "singbox_lb_mode": "urltest",
        "exit_selector_tag": "cascade-exit-auto",
    }


def sample_direct_state() -> dict:
    return {
        "config_path": "/etc/sing-box/config.json",
        "load_error": "",
        "has_default_outbound": True,
        "has_geoip_ru_direct": False,
        "has_ru_suffix_direct": True,
        "direct_rule_count": 3,
        "default_rule_count": 1,
        "default_outbound_tag": "cascade-exit-auto",
        "outbound_tags": ["direct", "block", "cascade-exit-auto", "cascade-hy2-0632bbf9cbc64c54"],
        "explicit_hosts_text": "",
        "ru_suffixes_text": ".ru\n.xn--p1ai\n.su",
        "enable_geoip_ru": False,
        "enable_default_outbound": True,
        "explicit_domains_list": ["smartape.ru"],
        "explicit_domains_detail": [
            {
                "domain": "smartape.ru",
                "cidrs": [
                    "185.9.145.9/32",
                    "185.9.145.10/32",
                    "2a06:dd00:20:0:109::1/128",
                    "2a06:dd00:20:0:10a::1/128",
                ],
                "error": "",
            }
        ],
        "whitelist_synced": False,
        "whitelist_domains_count": 0,
        "whitelist_ip_count": 0,
        "whitelist_auto_sync_enabled": False,
        "whitelist_synced_at": "",
        "whitelist_last_sync_at": "",
        "whitelist_sync_status": "idle",
        "whitelist_sync_error": "",
        "whitelist_source_url": "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
    }


def sample_sing_box_summary() -> dict:
    return {
        "config_path": "/etc/sing-box/config.json",
        "load_error": "",
        "route_rule_count": 4,
        "outbound_tags": ["direct", "cascade-exit-auto", "cascade-hy2-0632bbf9cbc64c54"],
        "inbounds": [
            {
                "type": "hysteria2",
                "tag": "in-hy2",
                "listen": "",
                "listen_port": 443,
                "users": [
                    {"kind": "hysteria2", "id": "••••", "name": "antyanmsa"},
                    {"kind": "hysteria2", "id": "••••", "name": "demo_user_02"},
                ],
            }
        ],
    }


def neutralize_forms(html: str) -> str:
    html = re.sub(
        r"<form\b",
        '<form onsubmit="return false;" action="#"',
        html,
        flags=re.IGNORECASE,
    )
    return html


def main() -> int:
    active, disabled = sample_users()
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    env.globals["url_for"] = mock_url_for

    html = env.get_template("index.html").render(
        defaults={
            "prefix": "user-",
            "count": 10,
            "start": 1,
            "width": 3,
            "mode": "manual",
            "traffic_limit_gb_manual": "",
            "duration_days_manual": "",
            "expires_at_manual": "",
            "traffic_limit_gb_prefix": "",
            "duration_days_prefix": "",
            "expires_at_prefix": "",
            "speed_up_mbps_manual": "",
            "speed_down_mbps_manual": "",
            "max_connections_manual": "",
            "speed_up_mbps_prefix": "",
            "speed_down_mbps_prefix": "",
            "max_connections_prefix": "",
            "logs_service": "both",
            "logs_level": "all",
            "logs_username": "",
            "logs_query": "",
            "logs_since_minutes": "180",
            "logs_limit": "200",
            "panel_prefix_secret": "",
            "cascade_token": "",
            "cascade_name": "",
            "direct_explicit_domains_json": "",
            "direct_ru_suffixes": ".ru\n.xn--p1ai\n.su",
            "server_exclusions": "",
        },
        results=[],
        skipped=[],
        ok_message="",
        error_message="",
        created_urls=[],
        active_users=active,
        disabled_users=disabled,
        stats={
            "enabled": False,
            "error": "",
            "online_users": 1,
            "online_connections": 2,
            "sum_rx": 0,
            "sum_tx": 0,
            "sum_total": 0,
            "sum_rx_h": "0 B",
            "sum_tx_h": "0 B",
            "sum_total_h": "0 B",
            "users": {},
            "gateway_traffic_note": "",
        },
        bandwidth={"up_mbps": 0, "down_mbps": 0, "up_display": "—", "down_display": "—"},
        exclusions=[],
        blacklist=[],
        logs_data={"searched": False, "lines": [], "lines_html": [], "total": 0},
        panel_login="admin",
        panel_timezone="Europe/Moscow",
        panel_timezone_options=(
            "UTC",
            "Europe/Kaliningrad",
            "Europe/Moscow",
            "Europe/Samara",
            "Asia/Yekaterinburg",
        ),
        panel_backend="sing-box",
        sing_box_summary=sample_sing_box_summary(),
        ui_shell_only=False,
        https_stub={"enabled": False},
        panel_url_prefix_display="/70a99cc4aee89f9e/panel",
        panel_insecure_debug_strip_prefix="",
        panel_systemd_service="hy2-admin.service",
        cascade_state=sample_cascade_state(),
        direct_state=sample_direct_state(),
    )
    html = neutralize_forms(html)
    OUT.write_text(html, encoding="utf-8")
    print(f"written {OUT} ({OUT.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
