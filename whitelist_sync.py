#!/usr/bin/env python3
"""Скачивание hxehex/russia-mobile-internet-whitelist и сопоставление с прошлым запуском + проверка IP сервера.

Не изменяет конфиг Hysteria2, userpass, /opt/hy2-admin/data/user_state.json, users_meta.json,
clients.json и прочие файлы пользователей/лимитов — только каталог data/russia-whitelist/.
При ошибке загрузки любого из трёх файлов предыдущие копии списков на диске остаются без изменений.
"""
from __future__ import annotations

import hashlib
import os
import ipaddress
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

INSTALL_DIR = Path("/opt/hy2-admin")
ENV_PATH = INSTALL_DIR / ".env"
DATA_DIR = INSTALL_DIR / "data" / "russia-whitelist"
STATE_PATH = DATA_DIR / "state.json"
UPSTREAM = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main"
FILES = ("whitelist.txt", "ipwhitelist.txt", "cidrwhitelist.txt")


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def fetch(url: str, timeout: int = 120) -> bytes:
    req = Request(url, headers={"User-Agent": "hy2-admin-whitelist-sync/1.0"})
    with urlopen(req, timeout=timeout) as r:
        return r.read()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def line_count(data: bytes) -> int:
    if not data:
        return 0
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


def resolve_server_ip(env: dict[str, str]) -> Optional[str]:
    explicit = (env.get("RU_WHITELIST_CHECK_IP") or "").strip()
    if explicit:
        try:
            ipaddress.ip_address(explicit)
            return explicit
        except ValueError:
            pass
    host = (env.get("SERVER_HOST") or "").strip()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
            for info in infos:
                return info[4][0]
        except OSError:
            return None
    return None


def load_ip_set(path: Path) -> set[str]:
    s: set[str] = set()
    if not path.exists():
        return s
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                s.add(line)
    return s


def load_cidr_list(path: Path) -> list:
    nets = []
    if not path.exists():
        return nets
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                continue
    return nets


def ip_in_any_cidr(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        if addr in n:
            return True
    return False


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    env = load_env(ENV_PATH)
    prev_state: dict[str, Any] = {}
    if STATE_PATH.exists():
        try:
            prev_state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            prev_state = {}

    prev_files = prev_state.get("files") or {}
    files_out: dict[str, Any] = {}

    # Сначала качаем всё в память: при сбое не перезаписываем ни один файл на диске.
    downloaded: dict[str, bytes] = {}
    for name in FILES:
        url = f"{UPSTREAM}/{name}"
        try:
            downloaded[name] = fetch(url)
        except (URLError, HTTPError, OSError) as e:
            print(f"[whitelist_sync] ошибка загрузки {name}: {e}", file=sys.stderr)
            return 1

    for name, data in downloaded.items():
        h = sha256_bytes(data)
        lc = line_count(data)
        prev_meta = prev_files.get(name) or {}
        prev_hash = prev_meta.get("sha256")
        changed = bool(prev_hash) and prev_hash != h
        dest = DATA_DIR / name
        tmp = DATA_DIR / f".{name}.part"
        tmp.write_bytes(data)
        os.replace(str(tmp), str(dest))
        files_out[name] = {
            "sha256": h,
            "sha256_short": h[:12],
            "lines": lc,
            "bytes": len(data),
            "changed_vs_previous": changed,
        }

    any_changed = any(files_out[n].get("changed_vs_previous") for n in files_out)

    server_ip = resolve_server_ip(env)
    in_ip: Optional[bool] = None
    in_cidr: Optional[bool] = None
    if server_ip:
        ip_set = load_ip_set(DATA_DIR / "ipwhitelist.txt")
        in_ip = server_ip in ip_set
        nets = load_cidr_list(DATA_DIR / "cidrwhitelist.txt")
        in_cidr = ip_in_any_cidr(server_ip, nets)

    state = {
        "last_run_utc": datetime.now(timezone.utc).isoformat(),
        "upstream": UPSTREAM,
        "files": files_out,
        "any_file_changed": any_changed,
        "server_ip_checked": server_ip,
        "server_ip_in_ipwhitelist": in_ip,
        "server_ip_in_cidr": in_cidr,
    }
    state_text = json.dumps(state, ensure_ascii=False, indent=2) + "\n"
    state_tmp = DATA_DIR / ".state.json.part"
    state_tmp.write_text(state_text, encoding="utf-8")
    os.replace(str(state_tmp), str(STATE_PATH))
    print(json.dumps(state, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
