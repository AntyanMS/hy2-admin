#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---interactive}"

INSTALL_DIR="/opt/hy2-admin"
SERVICE_NAME="hy2-admin.service"
APP_PORT="8787"
APP_HOST=""
APP_SCHEME="http"
USE_CERTBOT="n"
CERT_EMAIL=""
ENABLE_AUTOSTART="y"
START_NOW="y"
PANEL_USER="admin"
PANEL_PASS=""

detect_public_ip() {
  local ip=""
  ip="$(curl -4 -fsS https://ifconfig.me 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -z "${ip}" ]]; then
    ip="127.0.0.1"
  fi
  printf "%s" "${ip}"
}

is_ip() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

random_pass() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24
}

ask_yes_no() {
  local prompt="$1"
  local default="$2"
  local ans
  read -r -p "${prompt} [${default}]: " ans
  ans="${ans:-$default}"
  ans="$(echo "$ans" | tr '[:upper:]' '[:lower:]')"
  if [[ "$ans" == "y" || "$ans" == "yes" ]]; then
    echo "y"
  else
    echo "n"
  fi
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Ошибка: скрипт нужно запускать от root" >&2
    exit 1
  fi
}

collect_auto() {
  APP_HOST="$(detect_public_ip)"
  APP_SCHEME="http"
  PANEL_USER="admin"
  PANEL_PASS="$(random_pass)"
  ENABLE_AUTOSTART="y"
  START_NOW="y"
}

collect_interactive() {
  local detected_ip
  detected_ip="$(detect_public_ip)"
  APP_HOST="${detected_ip}"
  PANEL_PASS="$(random_pass)"

  read -r -p "Порт админки (default 8787): " input_port
  APP_PORT="${input_port:-8787}"

  read -r -p "IP или доменное имя панели (default ${detected_ip}): " input_host
  APP_HOST="${input_host:-$detected_ip}"

  echo "Протокол панели: 1) HTTP  2) HTTPS"
  read -r -p "Выберите 1/2 (default 1): " proto
  proto="${proto:-1}"
  if [[ "${proto}" == "2" ]]; then
    APP_SCHEME="https"
  else
    APP_SCHEME="http"
  fi

  if [[ "${APP_SCHEME}" == "https" ]]; then
    if is_ip "${APP_HOST}"; then
      echo "Вы указан IP. Будет создан self-signed сертификат."
      USE_CERTBOT="n"
    else
      USE_CERTBOT="$(ask_yes_no "Использовать certbot для ${APP_HOST}?" "y")"
      if [[ "${USE_CERTBOT}" == "y" ]]; then
        read -r -p "Email для certbot: " CERT_EMAIL
        if [[ -z "${CERT_EMAIL}" ]]; then
          echo "Email обязателен для certbot" >&2
          exit 1
        fi
      fi
    fi
  fi

  ENABLE_AUTOSTART="$(ask_yes_no "Добавить сервис в автозагрузку?" "y")"
  START_NOW="$(ask_yes_no "Запустить сервис сейчас?" "y")"

  read -r -p "Пользователь панели: default/custom (d/c, default d): " user_mode
  user_mode="${user_mode:-d}"
  if [[ "${user_mode}" == "c" || "${user_mode}" == "C" ]]; then
    read -r -p "Введите пользователя панели: " custom_user
    if [[ -n "${custom_user}" ]]; then
      PANEL_USER="${custom_user}"
    fi
  fi
}

install_packages() {
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip curl openssl
  if [[ "${APP_SCHEME}" == "https" && "${USE_CERTBOT}" == "y" ]]; then
    apt-get install -y certbot
  fi
}

prepare_files() {
  mkdir -p "${INSTALL_DIR}/templates" "${INSTALL_DIR}/data" "${INSTALL_DIR}/backups" "${INSTALL_DIR}/tls"

  cat > "${INSTALL_DIR}/requirements.txt" <<'EOF'
Flask==3.0.3
PyYAML==6.0.2
qrcode[pil]==7.4.2
gunicorn==22.0.0
EOF

  cat > "${INSTALL_DIR}/app.py" <<'PYAPP'
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.parse import quote

import qrcode
import yaml
from flask import Flask, Response, render_template, request


def load_env(path: str) -> dict:
    env = {}
    p = Path(path)
    if not p.exists():
        return env
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


ENV = load_env("/opt/hy2-admin/.env")
HY2_CONFIG = ENV.get("HY2_CONFIG_PATH", "/etc/hysteria/config.yaml")
HY2_SERVICE = ENV.get("HY2_SERVICE_NAME", "hysteria-server.service")
SERVER_HOST = ENV.get("SERVER_HOST", "")
SERVER_PORT = ENV.get("SERVER_PORT", "")
SERVER_SNI = ENV.get("SERVER_SNI", "")
INSECURE = ENV.get("CLIENT_INSECURE", "0") == "1"
BASIC_USER = ENV.get("PANEL_BASIC_USER", "admin")
BASIC_PASS = ENV.get("PANEL_BASIC_PASS", "")
BIND_HOST = ENV.get("PANEL_BIND_HOST", "127.0.0.1")
BIND_PORT = int(ENV.get("PANEL_BIND_PORT", "8787"))
PROTECTED_USERS_RAW = ENV.get("PROTECTED_USERS", "admin,Admin")

REGISTRY_PATH = Path("/opt/hy2-admin/data/clients.json")
BACKUP_DIR = Path("/opt/hy2-admin/backups")
STATE_PATH = Path("/opt/hy2-admin/data/user_state.json")
META_PATH = Path("/opt/hy2-admin/data/users_meta.json")
TRAFFIC_STATE_PATH = Path("/opt/hy2-admin/data/traffic_state.json")

app = Flask(__name__)


def get_protected_users() -> set[str]:
    names = set()
    for item in PROTECTED_USERS_RAW.split(","):
        name = item.strip()
        if name:
            names.add(name)
    return names


def unauthorized() -> Response:
    return Response("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="HY2 Admin"'})


def requires_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not BASIC_PASS:
            return Response("PANEL_BASIC_PASS is not configured", status=500)

        auth = request.authorization
        if not auth:
            return unauthorized()

        user_ok = secrets.compare_digest(auth.username or "", BASIC_USER)
        pass_ok = secrets.compare_digest(auth.password or "", BASIC_PASS)
        if not (user_ok and pass_ok):
            return unauthorized()
        return func(*args, **kwargs)

    return wrapper


def parse_usernames_manual(raw: str) -> list[str]:
    usernames = []
    seen = set()
    separators = [",", ";", "\n", "\t", " "]
    for sep in separators[1:]:
        raw = raw.replace(sep, separators[0])
    for part in raw.split(separators[0]):
        name = part.strip()
        if not name:
            continue
        if not valid_username(name):
            raise ValueError(f"Недопустимое имя пользователя: {name}")
        if name not in seen:
            usernames.append(name)
            seen.add(name)
    if not usernames:
        raise ValueError("Список пользователей пуст")
    return usernames


def parse_usernames_prefix(prefix: str, count: int, start: int, width: int) -> list[str]:
    if not prefix:
        raise ValueError("Префикс обязателен")
    if count < 1 or count > 500:
        raise ValueError("Количество должно быть от 1 до 500")
    if start < 0:
        raise ValueError("Стартовый индекс должен быть >= 0")
    if width < 0 or width > 8:
        raise ValueError("Ширина номера должна быть от 0 до 8")

    usernames = []
    for i in range(start, start + count):
        suffix = str(i).zfill(width) if width > 0 else str(i)
        name = f"{prefix}{suffix}"
        if not valid_username(name):
            raise ValueError(f"Недопустимое имя пользователя: {name}")
        usernames.append(name)
    return usernames


def valid_username(username: str) -> bool:
    # Hysteria2 config parser splits userpass keys by dot, so "." breaks config parsing.
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    return len(username) <= 64 and all(ch in allowed for ch in username)


def random_password() -> str:
    return secrets.token_hex(16)


def load_hy2_config() -> dict:
    with open(HY2_CONFIG, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    if not isinstance(cfg, dict):
        raise RuntimeError("Некорректный YAML: корень должен быть object")
    cfg.setdefault("auth", {})
    if not isinstance(cfg["auth"], dict):
        raise RuntimeError("Некорректный YAML: auth должен быть object")
    cfg["auth"]["type"] = "userpass"
    up = cfg["auth"].get("userpass")
    if up is None:
        up = {}
    if not isinstance(up, dict):
        raise RuntimeError("Некорректный YAML: auth.userpass должен быть object")
    cfg["auth"]["userpass"] = up
    return cfg


def infer_server_values(cfg: dict) -> tuple[str, int, str]:
    host = SERVER_HOST
    port = int(SERVER_PORT) if SERVER_PORT else None
    sni = SERVER_SNI

    if not host:
        acme = cfg.get("acme") or {}
        domains = acme.get("domains") if isinstance(acme, dict) else None
        if isinstance(domains, list) and domains:
            host = str(domains[0])

    if port is None:
        listen = str(cfg.get("listen", "0.0.0.0:443"))
        if ":" in listen:
            try:
                port = int(listen.rsplit(":", 1)[1])
            except ValueError:
                port = 443
        else:
            port = 443

    if not host:
        raise RuntimeError("Не удалось определить SERVER_HOST. Укажите в /opt/hy2-admin/.env")

    if not sni:
        sni = host

    return host, port, sni


def make_client_url(
    username: str,
    password: str,
    host: str,
    port: int,
    sni: str,
    speed_up_mbps: float | None = None,
    speed_down_mbps: float | None = None,
) -> str:
    user_enc = quote(username, safe="")
    pass_enc = quote(password, safe="")
    query_parts = [f"sni={quote(sni, safe='')}"]
    if INSECURE:
        query_parts.append("insecure=1")
    if isinstance(speed_up_mbps, (int, float)) and float(speed_up_mbps) > 0:
        query_parts.append(f"upmbps={float(speed_up_mbps):g}")
    if isinstance(speed_down_mbps, (int, float)) and float(speed_down_mbps) > 0:
        query_parts.append(f"downmbps={float(speed_down_mbps):g}")
    query = "&".join(query_parts)
    return f"hysteria2://{user_enc}:{pass_enc}@{host}:{port}/?{query}#{quote(username, safe='')}"


def make_qr_png(text: str) -> bytes:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def human_bytes(num: int) -> str:
    value = float(max(0, int(num)))
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(value)} {units[idx]}"
    return f"{value:.2f} {units[idx]}"


def calc_limit_view(total_bytes: int, limit_bytes: int) -> tuple[str, int]:
    if limit_bytes <= 0:
        return "", 0
    remaining = max(0, limit_bytes - max(0, total_bytes))
    percent = int((max(0, total_bytes) * 100) / limit_bytes) if limit_bytes > 0 else 0
    if percent > 100:
        percent = 100
    return human_bytes(remaining), percent


def parse_stats_listen(listen_value: str) -> str:
    listen = (listen_value or "").strip()
    if not listen:
        raise ValueError("trafficStats.listen is empty")
    if listen.startswith("http://") or listen.startswith("https://"):
        parsed = urlsplit(listen)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port
        if port is None:
            raise ValueError("trafficStats URL has no port")
        return f"http://{host}:{port}"
    if listen.startswith(":"):
        return f"http://127.0.0.1{listen}"
    if ":" not in listen:
        raise ValueError("trafficStats.listen must include port")
    host, port = listen.rsplit(":", 1)
    host = host or "127.0.0.1"
    return f"http://{host}:{port}"


def fetch_stats_json(base_url: str, endpoint: str, secret: str) -> dict:
    url = f"{base_url}{endpoint}"
    req = Request(url)
    if secret:
        req.add_header("Authorization", secret)
    with urlopen(req, timeout=3) as resp:
        data = resp.read().decode("utf-8")
    decoded = json.loads(data)
    if not isinstance(decoded, dict):
        return {}
    return decoded


def get_hy2_stats(cfg: dict) -> dict:
    stats_cfg = cfg.get("trafficStats")
    if not isinstance(stats_cfg, dict):
        return {
            "enabled": False,
            "error": "",
            "online_users": 0,
            "online_connections": 0,
            "sum_rx": 0,
            "sum_tx": 0,
            "sum_total": 0,
            "sum_rx_h": "0 B",
            "sum_tx_h": "0 B",
            "sum_total_h": "0 B",
            "users": {},
        }

    try:
        base_url = parse_stats_listen(str(stats_cfg.get("listen", "")))
        secret = str(stats_cfg.get("secret", ""))
        traffic_raw = fetch_stats_json(base_url, "/traffic", secret)
        online_raw = fetch_stats_json(base_url, "/online", secret)
    except (ValueError, URLError, TimeoutError, json.JSONDecodeError) as e:
        return {
            "enabled": True,
            "error": f"Traffic API недоступен: {e}",
            "online_users": 0,
            "online_connections": 0,
            "sum_rx": 0,
            "sum_tx": 0,
            "sum_total": 0,
            "sum_rx_h": "0 B",
            "sum_tx_h": "0 B",
            "sum_total_h": "0 B",
            "users": {},
        }

    traffic = {}
    for user, rec in traffic_raw.items():
        if not isinstance(rec, dict):
            continue
        rx = int(rec.get("rx", 0) or 0)
        tx = int(rec.get("tx", 0) or 0)
        traffic[str(user).strip().lower()] = {"rx": rx, "tx": tx}

    online = {}
    for user, cnt in online_raw.items():
        online[str(user).strip().lower()] = int(cnt or 0)

    users = build_cumulative_stats(traffic, online)
    sum_rx = sum(v["rx"] for v in users.values())
    sum_tx = sum(v["tx"] for v in users.values())
    sum_total = sum_rx + sum_tx
    online_connections = sum(v["online_count"] for v in users.values())
    online_users = sum(1 for v in users.values() if v["is_online"])

    return {
        "enabled": True,
        "error": "",
        "online_users": online_users,
        "online_connections": online_connections,
        "sum_rx": sum_rx,
        "sum_tx": sum_tx,
        "sum_total": sum_total,
        "sum_rx_h": human_bytes(sum_rx),
        "sum_tx_h": human_bytes(sum_tx),
        "sum_total_h": human_bytes(sum_total),
        "users": users,
    }


def write_registry(entries: list[dict]) -> None:
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if REGISTRY_PATH.exists():
        try:
            data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                data = []
        except Exception:
            data = []
    else:
        data = []

    data.extend(entries)
    REGISTRY_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_user_state() -> dict:
    if not STATE_PATH.exists():
        return {"disabled": {}}
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"disabled": {}}
    if not isinstance(state, dict):
        return {"disabled": {}}
    disabled = state.get("disabled")
    if not isinstance(disabled, dict):
        disabled = {}
    return {"disabled": disabled}


def save_user_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def load_user_meta() -> dict:
    if not META_PATH.exists():
        return {"users": {}}
    try:
        data = json.loads(META_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}}
    if not isinstance(data, dict):
        return {"users": {}}
    users = data.get("users")
    if not isinstance(users, dict):
        users = {}
    return {"users": users}


def save_user_meta(meta: dict) -> None:
    META_PATH.parent.mkdir(parents=True, exist_ok=True)
    META_PATH.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def load_traffic_state() -> dict:
    if not TRAFFIC_STATE_PATH.exists():
        return {"users": {}}
    try:
        data = json.loads(TRAFFIC_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}}
    if not isinstance(data, dict):
        return {"users": {}}
    users = data.get("users")
    if not isinstance(users, dict):
        users = {}
    return {"users": users}


def save_traffic_state(state: dict) -> None:
    TRAFFIC_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    TRAFFIC_STATE_PATH.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def build_cumulative_stats(traffic: dict, online: dict) -> dict:
    state = load_traffic_state()
    users_state = state["users"]
    now_iso = datetime.now(timezone.utc).isoformat()
    merged = {}

    keys = set(users_state.keys()) | set(traffic.keys()) | set(online.keys())
    for key in keys:
        rec = users_state.get(key, {})
        if not isinstance(rec, dict):
            rec = {}

        cur_rx = int((traffic.get(key) or {}).get("rx", 0))
        cur_tx = int((traffic.get(key) or {}).get("tx", 0))
        last_rx = int(rec.get("last_rx", 0) or 0)
        last_tx = int(rec.get("last_tx", 0) or 0)
        acc_rx = int(rec.get("acc_rx", 0) or 0)
        acc_tx = int(rec.get("acc_tx", 0) or 0)

        delta_rx = cur_rx - last_rx if cur_rx >= last_rx else cur_rx
        delta_tx = cur_tx - last_tx if cur_tx >= last_tx else cur_tx
        if delta_rx < 0:
            delta_rx = 0
        if delta_tx < 0:
            delta_tx = 0

        acc_rx += delta_rx
        acc_tx += delta_tx

        online_count = int(online.get(key, 0) or 0)
        was_online = bool(rec.get("online_now", False))
        is_online = online_count > 0
        sessions = int(rec.get("online_sessions", 0) or 0)
        last_seen_online_at = str(rec.get("last_seen_online_at", ""))

        if is_online and not was_online:
            sessions += 1
        if is_online:
            last_seen_online_at = now_iso

        users_state[key] = {
            "last_rx": cur_rx,
            "last_tx": cur_tx,
            "acc_rx": acc_rx,
            "acc_tx": acc_tx,
            "online_now": is_online,
            "online_sessions": sessions,
            "last_seen_online_at": last_seen_online_at,
        }

        merged[key] = {
            "rx": acc_rx,
            "tx": acc_tx,
            "total": acc_rx + acc_tx,
            "online_count": online_count,
            "is_online": is_online,
            "online_sessions": sessions,
            "last_seen_online_at": last_seen_online_at,
        }

    save_traffic_state(state)
    return merged


def parse_float_or_none(value: str) -> float | None:
    text = (value or "").strip()
    if not text:
        return None
    parsed = float(text)
    if parsed <= 0:
        return None
    return parsed


def parse_int_or_none(value: str) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    parsed = int(text)
    if parsed <= 0:
        return None
    return parsed


def parse_positive_mbps(value: str, field_name: str) -> float:
    text = (value or "").strip()
    if not text:
        raise ValueError(f"Поле '{field_name}' обязательно")
    parsed = float(text)
    if parsed <= 0:
        raise ValueError(f"Поле '{field_name}' должно быть больше 0")
    return parsed


def bandwidth_to_mbps(value) -> float | None:
    if isinstance(value, (int, float)):
        return float(value) if float(value) > 0 else None
    text = str(value or "").strip().lower()
    if not text:
        return None
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*(gbps|mbps|kbps)?$", text)
    if not m:
        return None
    num = float(m.group(1))
    unit = (m.group(2) or "mbps").lower()
    if unit == "gbps":
        return num * 1000.0
    if unit == "kbps":
        return num / 1000.0
    return num


def read_bandwidth_settings(cfg: dict | None = None) -> dict:
    cfg = cfg or load_hy2_config()
    bw = cfg.get("bandwidth")
    if not isinstance(bw, dict):
        return {"up_mbps": "", "down_mbps": "", "up_raw": "", "down_raw": ""}
    up_raw = str(bw.get("up", "")).strip()
    down_raw = str(bw.get("down", "")).strip()
    up_mbps = bandwidth_to_mbps(up_raw)
    down_mbps = bandwidth_to_mbps(down_raw)
    return {
        "up_mbps": f"{up_mbps:g}" if up_mbps is not None else "",
        "down_mbps": f"{down_mbps:g}" if down_mbps is not None else "",
        "up_raw": up_raw,
        "down_raw": down_raw,
    }


def parse_date_to_utc_end(date_text: str) -> datetime | None:
    text = (date_text or "").strip()
    if not text:
        return None
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(hour=23, minute=59, second=59, microsecond=0, tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def iso_to_dt(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def apply_limits_to_users(
    usernames: list[str],
    traffic_limit_gb: float | None,
    duration_days: int | None,
    expires_at: datetime | None,
    speed_up_mbps: float | None,
    speed_down_mbps: float | None,
    max_connections: int | None,
) -> None:
    meta = load_user_meta()
    users = meta["users"]
    now_iso = datetime.now(timezone.utc).isoformat()
    for username in usernames:
        entry = users.get(username, {})
        if not isinstance(entry, dict):
            entry = {}
        entry.setdefault("created_at", now_iso)
        if traffic_limit_gb is None:
            entry.pop("traffic_limit_bytes", None)
            entry.pop("traffic_limit_gb", None)
        else:
            bytes_limit = int(traffic_limit_gb * 1024 * 1024 * 1024)
            entry["traffic_limit_bytes"] = bytes_limit
            entry["traffic_limit_gb"] = round(traffic_limit_gb, 2)
        if duration_days is None:
            entry.pop("duration_days", None)
        else:
            entry["duration_days"] = duration_days
        if expires_at is None:
            entry.pop("expires_at", None)
        else:
            entry["expires_at"] = expires_at.isoformat()
        if speed_up_mbps is None:
            entry.pop("speed_up_mbps", None)
        else:
            entry["speed_up_mbps"] = round(float(speed_up_mbps), 2)
        if speed_down_mbps is None:
            entry.pop("speed_down_mbps", None)
        else:
            entry["speed_down_mbps"] = round(float(speed_down_mbps), 2)
        if max_connections is None:
            entry.pop("max_connections", None)
        else:
            entry["max_connections"] = int(max_connections)
        users[username] = entry
    save_user_meta(meta)


def update_single_user_limits(
    username: str,
    traffic_limit_gb: float | None,
    duration_days: int | None,
    expires_at: datetime | None,
    speed_up_mbps: float | None,
    speed_down_mbps: float | None,
    max_connections: int | None,
) -> None:
    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    state = load_user_state()
    disabled = state["disabled"]
    if username not in up and username not in disabled:
        raise ValueError("Пользователь не найден")
    apply_limits_to_users(
        [username],
        traffic_limit_gb,
        duration_days,
        expires_at,
        speed_up_mbps,
        speed_down_mbps,
        max_connections,
    )


def remove_users_from_meta(usernames: list[str]) -> None:
    if not usernames:
        return
    meta = load_user_meta()
    users = meta["users"]
    changed = False
    for username in usernames:
        if username in users:
            users.pop(username, None)
            changed = True
    if changed:
        save_user_meta(meta)


def evaluate_limit_reason(username: str, stats_key: str, meta_users: dict, stats: dict, now: datetime) -> str:
    info = meta_users.get(username, {})
    if not isinstance(info, dict):
        return ""

    expires_at = iso_to_dt(str(info.get("expires_at", "")))
    if expires_at and now >= expires_at:
        return "Срок действия истек"

    duration_days = info.get("duration_days")
    created_at = iso_to_dt(str(info.get("created_at", "")))
    if isinstance(duration_days, int) and duration_days > 0 and created_at:
        if now >= created_at + timedelta(days=duration_days):
            return "Истек срок (дни)"

    traffic_limit_bytes = info.get("traffic_limit_bytes")
    if isinstance(traffic_limit_bytes, int) and traffic_limit_bytes > 0 and stats.get("enabled"):
        usage = ((stats.get("users") or {}).get(stats_key) or {}).get("total", 0)
        if int(usage) >= traffic_limit_bytes:
            return "Достигнут лимит трафика"

    max_connections = info.get("max_connections")
    if isinstance(max_connections, int) and max_connections > 0 and stats.get("enabled"):
        online_count = int(((stats.get("users") or {}).get(stats_key) or {}).get("online_count", 0) or 0)
        if online_count > max_connections:
            return f"Превышен лимит подключений ({online_count}/{max_connections})"

    return ""


def enforce_limits_if_needed() -> None:
    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    if not up:
        return

    protected = get_protected_users()
    state = load_user_state()
    disabled = state["disabled"]
    meta = load_user_meta()
    meta_users = meta["users"]
    stats = get_hy2_stats(cfg)
    now = datetime.now(timezone.utc)

    changed_cfg = False
    changed_state = False
    for username in list(up.keys()):
        if username in protected:
            continue
        stats_key = str(username).strip().lower()
        reason = evaluate_limit_reason(username, stats_key, meta_users, stats, now)
        if not reason:
            continue
        password = up.pop(username)
        changed_cfg = True
        disabled[username] = {
            "password": password,
            "disabled_at": now.isoformat(),
            "reason": reason,
        }
        changed_state = True

    if changed_cfg:
        write_config_with_backup_and_restart(cfg)
    if changed_state:
        save_user_state(state)

def restart_hy2_or_rollback(backup_path: Path) -> None:
    restart = subprocess.run(["systemctl", "restart", HY2_SERVICE], capture_output=True, text=True)
    if restart.returncode == 0:
        return

    shutil.copy2(backup_path, HY2_CONFIG)
    subprocess.run(["systemctl", "restart", HY2_SERVICE], capture_output=True, text=True)
    raise RuntimeError(
        f"Не удалось перезапустить {HY2_SERVICE}. Изменения откатили. stderr: {restart.stderr.strip()}"
    )


def write_config_with_backup_and_restart(cfg: dict) -> None:
    hy2_config_path = Path(HY2_CONFIG)
    old_raw = hy2_config_path.read_text(encoding="utf-8")
    old_stat = hy2_config_path.stat()

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = BACKUP_DIR / f"config-{ts}.yaml"
    backup_path.write_text(old_raw, encoding="utf-8")

    fd, tmp_path = tempfile.mkstemp(prefix="hy2-config-", suffix=".yaml", dir=str(hy2_config_path.parent))
    os.close(fd)
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)
        os.chmod(tmp_path, old_stat.st_mode)
        os.chown(tmp_path, old_stat.st_uid, old_stat.st_gid)
        os.replace(tmp_path, HY2_CONFIG)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    restart_hy2_or_rollback(backup_path)


def build_users_view() -> tuple[list[dict], list[dict], dict]:
    enforce_limits_if_needed()
    cfg = load_hy2_config()
    state = load_user_state()
    meta = load_user_meta()
    meta_users = meta["users"]
    protected = get_protected_users()
    host, port, sni = infer_server_values(cfg)
    stats = get_hy2_stats(cfg)
    stats_users = stats.get("users", {})
    active = []
    for username, password in sorted(cfg["auth"]["userpass"].items()):
        stats_key = str(username).strip().lower()
        t = stats_users.get(
            stats_key,
            {
                "rx": 0,
                "tx": 0,
                "total": 0,
                "online_count": 0,
                "is_online": False,
                "online_sessions": 0,
                "last_seen_online_at": "",
            },
        )
        online_count = int(t.get("online_count", 0) or 0)
        info = meta_users.get(username, {}) if isinstance(meta_users.get(username, {}), dict) else {}
        traffic_limit_bytes = int(info.get("traffic_limit_bytes", 0) or 0)
        traffic_limit_gb = info.get("traffic_limit_gb")
        duration_days = info.get("duration_days")
        expires_at = str(info.get("expires_at", ""))
        speed_up_mbps = info.get("speed_up_mbps")
        speed_down_mbps = info.get("speed_down_mbps")
        max_connections = info.get("max_connections")
        remaining_h, usage_percent = calc_limit_view(t["total"], traffic_limit_bytes)
        active.append(
            {
                "username": username,
                "is_protected": username in protected,
                "url": make_client_url(
                    username,
                    str(password),
                    host,
                    port,
                    sni,
                    speed_up_mbps=speed_up_mbps if isinstance(speed_up_mbps, (int, float)) else None,
                    speed_down_mbps=speed_down_mbps if isinstance(speed_down_mbps, (int, float)) else None,
                ),
                "rx": t["rx"],
                "tx": t["tx"],
                "total": t["total"],
                "rx_h": human_bytes(t["rx"]),
                "tx_h": human_bytes(t["tx"]),
                "total_h": human_bytes(t["total"]),
                "online_count": online_count,
                "is_online": bool(t.get("is_online", False)),
                "online_sessions": int(t.get("online_sessions", 0) or 0),
                "last_seen_online_at": str(t.get("last_seen_online_at", "")),
                "traffic_limit_bytes": traffic_limit_bytes,
                "traffic_limit_gb": traffic_limit_gb if isinstance(traffic_limit_gb, (int, float)) else None,
                "traffic_limit_h": human_bytes(traffic_limit_bytes) if traffic_limit_bytes > 0 else "",
                "traffic_remaining_h": remaining_h,
                "traffic_usage_percent": usage_percent,
                "duration_days": duration_days if isinstance(duration_days, int) and duration_days > 0 else None,
                "expires_at": expires_at,
                "speed_up_mbps": speed_up_mbps if isinstance(speed_up_mbps, (int, float)) and speed_up_mbps > 0 else None,
                "speed_down_mbps": speed_down_mbps if isinstance(speed_down_mbps, (int, float)) and speed_down_mbps > 0 else None,
                "max_connections": max_connections if isinstance(max_connections, int) and max_connections > 0 else None,
                "is_disabled": False,
            }
        )

    disabled = []
    disabled_map = state.get("disabled", {})
    for username in sorted(disabled_map.keys()):
        rec = disabled_map.get(username, {})
        password = rec.get("password", "")
        url = ""
        if password:
            url = make_client_url(username, str(password), host, port, sni)
        stats_key = str(username).strip().lower()
        t = stats_users.get(
            stats_key,
            {
                "rx": 0,
                "tx": 0,
                "total": 0,
                "online_count": 0,
                "is_online": False,
                "online_sessions": 0,
                "last_seen_online_at": "",
            },
        )
        online_count = int(t.get("online_count", 0) or 0)
        info = meta_users.get(username, {}) if isinstance(meta_users.get(username, {}), dict) else {}
        traffic_limit_bytes = int(info.get("traffic_limit_bytes", 0) or 0)
        traffic_limit_gb = info.get("traffic_limit_gb")
        duration_days = info.get("duration_days")
        expires_at = str(info.get("expires_at", ""))
        speed_up_mbps = info.get("speed_up_mbps")
        speed_down_mbps = info.get("speed_down_mbps")
        max_connections = info.get("max_connections")
        remaining_h, usage_percent = calc_limit_view(t["total"], traffic_limit_bytes)
        disabled.append(
            {
                "username": username,
                "disabled_at": rec.get("disabled_at", ""),
                "disabled_reason": rec.get("reason", ""),
                "is_protected": username in protected,
                "url": make_client_url(
                    username,
                    str(password),
                    host,
                    port,
                    sni,
                    speed_up_mbps=speed_up_mbps if isinstance(speed_up_mbps, (int, float)) else None,
                    speed_down_mbps=speed_down_mbps if isinstance(speed_down_mbps, (int, float)) else None,
                ) if password else url,
                "rx": t["rx"],
                "tx": t["tx"],
                "total": t["total"],
                "rx_h": human_bytes(t["rx"]),
                "tx_h": human_bytes(t["tx"]),
                "total_h": human_bytes(t["total"]),
                "online_count": online_count,
                "is_online": bool(t.get("is_online", False)),
                "online_sessions": int(t.get("online_sessions", 0) or 0),
                "last_seen_online_at": str(t.get("last_seen_online_at", "")),
                "traffic_limit_bytes": traffic_limit_bytes,
                "traffic_limit_gb": traffic_limit_gb if isinstance(traffic_limit_gb, (int, float)) else None,
                "traffic_limit_h": human_bytes(traffic_limit_bytes) if traffic_limit_bytes > 0 else "",
                "traffic_remaining_h": remaining_h,
                "traffic_usage_percent": usage_percent,
                "duration_days": duration_days if isinstance(duration_days, int) and duration_days > 0 else None,
                "expires_at": expires_at,
                "speed_up_mbps": speed_up_mbps if isinstance(speed_up_mbps, (int, float)) and speed_up_mbps > 0 else None,
                "speed_down_mbps": speed_down_mbps if isinstance(speed_down_mbps, (int, float)) and speed_down_mbps > 0 else None,
                "max_connections": max_connections if isinstance(max_connections, int) and max_connections > 0 else None,
                "is_disabled": True,
            }
        )
    return active, disabled, stats


def apply_users(
    usernames: list[str],
    traffic_limit_gb: float | None,
    duration_days: int | None,
    expires_at: datetime | None,
    speed_up_mbps: float | None,
    speed_down_mbps: float | None,
    max_connections: int | None,
) -> tuple[list[dict], list[str]]:
    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    host, port, sni = infer_server_values(cfg)

    results = []
    skipped = []
    registry = []

    for username in usernames:
        exists = username in up
        if exists:
            skipped.append(username)
            continue

        password = random_password()
        up[username] = password

        url = make_client_url(
            username,
            password,
            host,
            port,
            sni,
            speed_up_mbps=speed_up_mbps,
            speed_down_mbps=speed_down_mbps,
        )

        results.append(
            {
                "username": username,
                "password": password,
                "url": url,
                "status": "updated" if exists else "created",
            }
        )

        registry.append(
            {
                "username": username,
                "action": "updated" if exists else "created",
                "password_sha256": hashlib.sha256(password.encode("utf-8")).hexdigest(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )

    write_config_with_backup_and_restart(cfg)
    write_registry(registry)
    processed_usernames = [item["username"] for item in results]
    apply_limits_to_users(
        processed_usernames,
        traffic_limit_gb,
        duration_days,
        expires_at,
        speed_up_mbps,
        speed_down_mbps,
        max_connections,
    )
    return results, skipped


def toggle_user(username: str, action: str) -> str:
    if not valid_username(username):
        raise ValueError("Недопустимое имя пользователя")
    if action not in {"disable", "enable"}:
        raise ValueError("Недопустимое действие")

    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    state = load_user_state()
    disabled = state["disabled"]
    protected = get_protected_users()

    if action == "disable":
        if username in protected:
            raise ValueError("Защищенного пользователя нельзя отключить")
        if username not in up:
            raise ValueError("Пользователь не найден среди активных")
        password = up.pop(username)
        write_config_with_backup_and_restart(cfg)
        disabled[username] = {
            "password": password,
            "disabled_at": datetime.now(timezone.utc).isoformat(),
        }
        save_user_state(state)
        return "Пользователь отключен"

    if username in up:
        raise ValueError("Пользователь уже активен")
    rec = disabled.get(username)
    if not isinstance(rec, dict) or "password" not in rec:
        raise ValueError("Нет данных для повторного включения пользователя")

    up[username] = str(rec["password"])
    write_config_with_backup_and_restart(cfg)
    disabled.pop(username, None)
    save_user_state(state)
    return "Пользователь включен"


def delete_users(scope: str, mode: str, selected: list[str]) -> str:
    if scope not in {"active", "disabled"}:
        raise ValueError("Недопустимая область удаления")
    if mode not in {"selected", "all_except_protected", "all"}:
        raise ValueError("Недопустимый режим удаления")

    protected = get_protected_users()
    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    state = load_user_state()
    disabled = state["disabled"]

    selected_clean = []
    seen = set()
    for username in selected:
        username = (username or "").strip()
        if not username:
            continue
        if username in seen:
            continue
        seen.add(username)
        if not valid_username(username):
            raise ValueError(f"Недопустимое имя пользователя: {username}")
        selected_clean.append(username)

    changed_active = False
    changed_state = False
    deleted_count = 0
    skipped_protected = 0
    deleted_usernames = []

    if scope == "active":
        if mode == "selected":
            targets = selected_clean
        elif mode == "all_except_protected":
            targets = [u for u in up.keys() if u not in protected]
        else:
            targets = list(up.keys())

        for username in targets:
            if username in protected:
                skipped_protected += 1
                continue
            if username in up:
                up.pop(username, None)
                deleted_count += 1
                changed_active = True
                deleted_usernames.append(username)
            if username in disabled:
                disabled.pop(username, None)
                changed_state = True
    else:
        if mode == "selected":
            targets = selected_clean
        elif mode == "all_except_protected":
            targets = [u for u in disabled.keys() if u not in protected]
        else:
            targets = list(disabled.keys())

        for username in targets:
            if username in protected:
                skipped_protected += 1
                continue
            if username in disabled:
                disabled.pop(username, None)
                deleted_count += 1
                changed_state = True
                deleted_usernames.append(username)

    if changed_active:
        write_config_with_backup_and_restart(cfg)
    if changed_state:
        save_user_state(state)
    remove_users_from_meta(deleted_usernames)

    if deleted_count == 0 and skipped_protected == 0:
        return "Ничего не удалено"
    if skipped_protected:
        return f"Удалено: {deleted_count}. Защищенных пропущено: {skipped_protected}"
    return f"Удалено: {deleted_count}"


def base_defaults() -> dict:
    return {
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
    }


def render_index_page(
    *,
    defaults: dict | None = None,
    results: list[dict] | None = None,
    skipped: list[str] | None = None,
    ok_message: str | None = None,
    error_message: str | None = None,
    created_urls: list[str] | None = None,
):
    active_users, disabled_users, stats = build_users_view()
    cfg = load_hy2_config()
    merged_defaults = base_defaults()
    if isinstance(defaults, dict):
        merged_defaults.update(defaults)
    return render_template(
        "index.html",
        defaults=merged_defaults,
        results=results or [],
        skipped=skipped or [],
        ok_message=ok_message or "",
        error_message=error_message or "",
        created_urls=created_urls or [],
        active_users=active_users,
        disabled_users=disabled_users,
        stats=stats,
        bandwidth=read_bandwidth_settings(cfg),
    )


@app.route("/", methods=["GET"])
@requires_auth
def index():
    return render_index_page()


@app.route("/apply", methods=["POST"])
@requires_auth
def apply_handler():
    mode = request.form.get("mode", "manual")
    traffic_limit_raw = request.form.get("traffic_limit_gb_manual", "") if mode == "manual" else request.form.get("traffic_limit_gb_prefix", "")
    duration_days_raw = request.form.get("duration_days_manual", "") if mode == "manual" else request.form.get("duration_days_prefix", "")
    expires_at_raw = request.form.get("expires_at_manual", "") if mode == "manual" else request.form.get("expires_at_prefix", "")
    speed_up_raw = request.form.get("speed_up_mbps_manual", "") if mode == "manual" else request.form.get("speed_up_mbps_prefix", "")
    speed_down_raw = request.form.get("speed_down_mbps_manual", "") if mode == "manual" else request.form.get("speed_down_mbps_prefix", "")
    max_connections_raw = request.form.get("max_connections_manual", "") if mode == "manual" else request.form.get("max_connections_prefix", "")

    try:
        if mode == "manual":
            raw = request.form.get("manual_usernames", "")
            usernames = parse_usernames_manual(raw)
        elif mode == "prefix":
            usernames = parse_usernames_prefix(
                prefix=request.form.get("prefix", "").strip(),
                count=int(request.form.get("count", "0")),
                start=int(request.form.get("start", "1")),
                width=int(request.form.get("width", "3")),
            )
        else:
            raise ValueError("Неизвестный режим")

        traffic_limit_gb = parse_float_or_none(traffic_limit_raw)
        duration_days = parse_int_or_none(duration_days_raw)
        expires_at = parse_date_to_utc_end(expires_at_raw)
        speed_up_mbps = parse_float_or_none(speed_up_raw)
        speed_down_mbps = parse_float_or_none(speed_down_raw)
        max_connections = parse_int_or_none(max_connections_raw)

        results, skipped = apply_users(
            usernames,
            traffic_limit_gb,
            duration_days,
            expires_at,
            speed_up_mbps,
            speed_down_mbps,
            max_connections,
        )
        created_urls = [item["url"] for item in results if item.get("status") == "created"]
        return render_index_page(
            defaults={
                "prefix": request.form.get("prefix", "user-").strip() or "user-",
                "count": request.form.get("count", "10"),
                "start": request.form.get("start", "1"),
                "width": request.form.get("width", "3"),
                "manual_usernames": request.form.get("manual_usernames", ""),
                "mode": mode,
                "traffic_limit_gb_manual": request.form.get("traffic_limit_gb_manual", ""),
                "duration_days_manual": request.form.get("duration_days_manual", ""),
                "expires_at_manual": request.form.get("expires_at_manual", ""),
                "traffic_limit_gb_prefix": request.form.get("traffic_limit_gb_prefix", ""),
                "duration_days_prefix": request.form.get("duration_days_prefix", ""),
                "expires_at_prefix": request.form.get("expires_at_prefix", ""),
                "speed_up_mbps_manual": request.form.get("speed_up_mbps_manual", ""),
                "speed_down_mbps_manual": request.form.get("speed_down_mbps_manual", ""),
                "max_connections_manual": request.form.get("max_connections_manual", ""),
                "speed_up_mbps_prefix": request.form.get("speed_up_mbps_prefix", ""),
                "speed_down_mbps_prefix": request.form.get("speed_down_mbps_prefix", ""),
                "max_connections_prefix": request.form.get("max_connections_prefix", ""),
            },
            results=results,
            skipped=skipped,
            ok_message=f"Успешно обработано: {len(results)}",
            created_urls=created_urls,
        )
    except Exception as e:
        return render_index_page(
            defaults={
                "prefix": request.form.get("prefix", "user-").strip() or "user-",
                "count": request.form.get("count", "10"),
                "start": request.form.get("start", "1"),
                "width": request.form.get("width", "3"),
                "manual_usernames": request.form.get("manual_usernames", ""),
                "mode": mode,
                "traffic_limit_gb_manual": request.form.get("traffic_limit_gb_manual", ""),
                "duration_days_manual": request.form.get("duration_days_manual", ""),
                "expires_at_manual": request.form.get("expires_at_manual", ""),
                "traffic_limit_gb_prefix": request.form.get("traffic_limit_gb_prefix", ""),
                "duration_days_prefix": request.form.get("duration_days_prefix", ""),
                "expires_at_prefix": request.form.get("expires_at_prefix", ""),
                "speed_up_mbps_manual": request.form.get("speed_up_mbps_manual", ""),
                "speed_down_mbps_manual": request.form.get("speed_down_mbps_manual", ""),
                "max_connections_manual": request.form.get("max_connections_manual", ""),
                "speed_up_mbps_prefix": request.form.get("speed_up_mbps_prefix", ""),
                "speed_down_mbps_prefix": request.form.get("speed_down_mbps_prefix", ""),
                "max_connections_prefix": request.form.get("max_connections_prefix", ""),
            },
            error_message=str(e),
        )


@app.route("/qr", methods=["GET"])
@requires_auth
def qr_handler():
    text = request.args.get("u", "").strip()
    if not text:
        return Response("Missing parameter: u", status=400)
    png = make_qr_png(text)
    return Response(png, mimetype="image/png")


@app.route("/users/toggle", methods=["POST"])
@requires_auth
def users_toggle_handler():
    username = request.form.get("username", "").strip()
    action = request.form.get("action", "").strip()
    try:
        msg = toggle_user(username, action)
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@app.route("/users/delete", methods=["POST"])
@requires_auth
def users_delete_handler():
    scope = request.form.get("scope", "").strip()
    mode = request.form.get("mode", "").strip()
    selected = request.form.getlist("selected_users")
    try:
        msg = delete_users(scope, mode, selected)
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@app.route("/users/limits", methods=["POST"])
@requires_auth
def users_limits_handler():
    username = request.form.get("username", "").strip()
    traffic_limit_raw = request.form.get("traffic_limit_gb", "")
    duration_days_raw = request.form.get("duration_days", "")
    expires_at_raw = request.form.get("expires_at", "")
    speed_up_raw = request.form.get("speed_up_mbps", "")
    speed_down_raw = request.form.get("speed_down_mbps", "")
    max_connections_raw = request.form.get("max_connections", "")
    try:
        traffic_limit_gb = parse_float_or_none(traffic_limit_raw)
        duration_days = parse_int_or_none(duration_days_raw)
        expires_at = parse_date_to_utc_end(expires_at_raw)
        speed_up_mbps = parse_float_or_none(speed_up_raw)
        speed_down_mbps = parse_float_or_none(speed_down_raw)
        max_connections = parse_int_or_none(max_connections_raw)
        update_single_user_limits(
            username,
            traffic_limit_gb,
            duration_days,
            expires_at,
            speed_up_mbps,
            speed_down_mbps,
            max_connections,
        )
        msg = "Лимиты пользователя обновлены"
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@app.route("/server/bandwidth", methods=["POST"])
@requires_auth
def server_bandwidth_handler():
    up_raw = request.form.get("server_up_mbps", "")
    down_raw = request.form.get("server_down_mbps", "")
    try:
        up_mbps = parse_positive_mbps(up_raw, "Up (Mbps)")
        down_mbps = parse_positive_mbps(down_raw, "Down (Mbps)")
        cfg = load_hy2_config()
        cfg["bandwidth"] = {
            "up": f"{up_mbps:g} mbps",
            "down": f"{down_mbps:g} mbps",
        }
        write_config_with_backup_and_restart(cfg)
        return render_index_page(ok_message=f"Лимит скорости обновлен: {up_mbps:g}/{down_mbps:g} Mbps")
    except Exception as e:
        return render_index_page(error_message=str(e))


@app.route("/api/live", methods=["GET"])
@requires_auth
def api_live_handler():
    active_users, disabled_users, stats = build_users_view()
    users = {}
    for u in active_users + disabled_users:
        users[u["username"]] = {
            "is_online": bool(u.get("is_online")),
            "online_count": int(u.get("online_count", 0) or 0),
            "rx_h": u.get("rx_h", "0 B"),
            "tx_h": u.get("tx_h", "0 B"),
            "total_h": u.get("total_h", "0 B"),
            "total": int(u.get("total", 0) or 0),
            "is_disabled": bool(u.get("is_disabled", False)),
            "traffic_limit_bytes": int(u.get("traffic_limit_bytes", 0) or 0),
            "traffic_limit_h": u.get("traffic_limit_h", ""),
            "traffic_remaining_h": u.get("traffic_remaining_h", ""),
            "traffic_usage_percent": int(u.get("traffic_usage_percent", 0) or 0),
        }
    payload = {
        "stats": {
            "sum_rx_h": stats.get("sum_rx_h", "0 B"),
            "sum_tx_h": stats.get("sum_tx_h", "0 B"),
            "sum_total_h": stats.get("sum_total_h", "0 B"),
            "online_users": int(stats.get("online_users", 0) or 0),
            "online_connections": int(stats.get("online_connections", 0) or 0),
        },
        "users": users,
    }
    return Response(json.dumps(payload, ensure_ascii=False), mimetype="application/json")


if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT)
PYAPP

  cat > "${INSTALL_DIR}/templates/index.html" <<'HTML'
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HY2 Admin</title>
  <style>
    :root {
      --bg: #0f1115;
      --bg-soft: #171a21;
      --text: #e6e6e6;
      --muted: #9ca3af;
      --border: #2a2f3a;
      --ok: #4ade80;
      --err: #f87171;
      --btn: #2563eb;
      --btn-hover: #1d4ed8;
      --input-bg: #0b0d12;
      --code-bg: #0b0d12;
    }
    body { font-family: Arial, sans-serif; margin: 16px; background: var(--bg); color: var(--text); }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    textarea, input {
      width: 100%;
      padding: 8px;
      box-sizing: border-box;
      background: var(--input-bg);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
    }
    label { display: block; margin-top: 10px; font-weight: 600; }
    .box { border: 1px solid var(--border); border-radius: 8px; padding: 12px; background: var(--bg-soft); }
    .actions { margin-top: 10px; }
    button {
      padding: 8px 12px;
      font-weight: 700;
      font-size: 14px;
      background: var(--btn);
      color: #fff;
      border: 0;
      border-radius: 8px;
      cursor: pointer;
    }
    button:hover { background: var(--btn-hover); }
    .ok { color: var(--ok); }
    .err { color: var(--err); }
    .row { margin-top: 8px; }
    .result { border: 1px solid var(--border); border-radius: 8px; padding: 10px; margin: 8px 0; background: var(--bg-soft); }
    code { word-break: break-all; background: var(--code-bg); padding: 2px 4px; border-radius: 4px; }
    img { border: 1px solid var(--border); border-radius: 6px; padding: 6px; background: #fff; }
    .muted { color: var(--muted); }
    .danger { background: #b91c1c; }
    .danger:hover { background: #991b1b; }
    .inline { display: inline-block; margin-right: 6px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }
    .tabs { display: flex; gap: 8px; margin-bottom: 8px; }
    .tab-btn { background: #374151; }
    .tab-btn.active { background: #2563eb; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .qr-copy { cursor: pointer; transition: transform 0.12s ease; }
    .qr-copy:hover { transform: scale(1.03); }
    .copy-status { margin: 8px 0; min-height: 18px; color: var(--ok); font-weight: 600; }
    .links-list { width: 100%; min-height: 170px; }
    details.user-card { border: 1px solid var(--border); border-radius: 8px; margin: 8px 0; background: var(--bg-soft); }
    details.user-card > summary { cursor: pointer; list-style: none; padding: 10px 12px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
    details.user-card > summary::-webkit-details-marker { display: none; }
    details.user-card > summary::after { content: "▸"; float: right; color: var(--muted); }
    details.user-card[open] > summary::after { content: "▾"; }
    .user-body { border-top: 1px solid var(--border); padding: 10px; }
    .url-text { display: block; margin-top: 8px; white-space: pre-wrap; word-break: break-all; }
    .summary-name { flex: 1; min-width: 0; }
    .summary-select { display: inline-flex; align-items: center; margin-right: 18px; }
    .summary-select input { margin: 0; width: 16px; height: 16px; }
    .summary-meta { font-size: 12px; color: var(--muted); margin-left: 8px; font-weight: 500; }
    .conn-badge {
      display: inline-block;
      margin-left: 6px;
      padding: 1px 6px;
      border-radius: 999px;
      font-size: 11px;
      color: #bfdbfe;
      background: rgba(37, 99, 235, 0.22);
      border: 1px solid rgba(59, 130, 246, 0.45);
      vertical-align: middle;
      font-weight: 700;
    }
    .edit-limits { margin-top: 8px; border-top: 1px dashed var(--border); padding-top: 8px; }
    .edit-grid { display: grid; grid-template-columns: repeat(3, minmax(120px, 1fr)); gap: 8px; }
    .edit-grid label { margin-top: 0; font-size: 12px; color: var(--muted); font-weight: 500; }
    .users-tools { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
    .users-tools input, .users-tools select { width: auto; min-width: 180px; }
    .limit-bar { height: 8px; background: #1f2937; border-radius: 999px; overflow: hidden; margin-top: 6px; }
    .limit-fill { height: 100%; background: linear-gradient(90deg, #22c55e, #84cc16); width: 0%; transition: width 0.25s ease; }
    .limit-fill.warn { background: linear-gradient(90deg, #f59e0b, #f97316); }
    .limit-fill.danger { background: linear-gradient(90deg, #ef4444, #dc2626); }
    .stats-grid { display: grid; grid-template-columns: repeat(4, minmax(160px, 1fr)); gap: 8px; margin-bottom: 10px; }
    .stat-card { border: 1px solid var(--border); border-radius: 8px; padding: 10px; background: #111827; }
    .stat-title { font-size: 12px; color: var(--muted); margin-bottom: 4px; }
    .stat-value { font-size: 18px; font-weight: 700; }
    .user-stats { margin: 6px 0 0; font-size: 13px; color: var(--muted); }
    .status-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
      margin-left: 8px;
      box-shadow: 0 0 0 1px rgba(255,255,255,0.08) inset;
      vertical-align: middle;
    }
    .status-dot.online {
      background: #22c55e;
      box-shadow: 0 0 0 1px rgba(255,255,255,0.08) inset, 0 0 10px rgba(34, 197, 94, 0.65);
      animation: breathGreen 1.6s ease-in-out infinite;
    }
    .status-dot.offline {
      background: #ef4444;
      box-shadow: 0 0 0 1px rgba(255,255,255,0.08) inset, 0 0 6px rgba(239, 68, 68, 0.45);
    }
    .status-dot.disabled {
      background: #111827;
      box-shadow: 0 0 0 1px rgba(255,255,255,0.12) inset;
    }
    @keyframes breathGreen {
      0% { transform: scale(1); opacity: 0.75; }
      50% { transform: scale(1.18); opacity: 1; }
      100% { transform: scale(1); opacity: 0.75; }
    }
    details.create-card {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--bg-soft);
      overflow: hidden;
      margin-bottom: 10px;
    }
    details.create-card > summary {
      cursor: pointer;
      list-style: none;
      padding: 10px 12px;
      font-weight: 700;
      background: #111827;
    }
    details.create-card > summary::-webkit-details-marker { display: none; }
    details.create-card > summary::after { content: "▸"; float: right; color: var(--muted); }
    details.create-card[open] > summary::after { content: "▾"; }
    .create-body { padding: 10px 12px 12px; }
    .mode-panel { display: none; }
    .mode-panel.active { display: block; }
    .limits-grid { display: grid; grid-template-columns: repeat(3, minmax(140px, 1fr)); gap: 8px; margin-top: 8px; }
    .limits-grid label { margin-top: 0; font-size: 12px; color: var(--muted); }
    .limit-note { font-size: 12px; color: var(--muted); margin-top: 6px; }
    .server-box { margin-bottom: 10px; }
    .server-grid { display: grid; grid-template-columns: repeat(2, minmax(140px, 1fr)); gap: 8px; }
    .server-grid label { margin-top: 0; font-size: 12px; color: var(--muted); }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .secondary-btn { background: #374151; }
    .secondary-btn:hover { background: #4b5563; }
    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.65);
      display: none;
      align-items: center;
      justify-content: center;
      padding: 14px;
      z-index: 1000;
    }
    .modal-backdrop.open { display: flex; }
    .modal-card {
      width: min(700px, 100%);
      max-height: 90vh;
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: var(--bg-soft);
      padding: 12px;
    }
    .modal-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
    .close-btn {
      width: 30px;
      height: 30px;
      border-radius: 8px;
      background: #1f2937;
      font-size: 18px;
      line-height: 1;
      padding: 0;
    }
    .close-btn:hover { background: #374151; }
    .site-footer {
      margin-top: 18px;
      padding-top: 12px;
      border-top: 1px solid var(--border);
      color: var(--muted);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      font-size: 13px;
    }
    .footer-icons { display: inline-flex; gap: 10px; align-items: center; }
    .icon-link {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 30px;
      height: 30px;
      border: 1px solid var(--border);
      border-radius: 8px;
      color: var(--text);
      text-decoration: none;
      background: #111827;
      transition: transform 0.12s ease, border-color 0.12s ease;
    }
    .icon-link:hover {
      transform: translateY(-1px);
      border-color: #4b5563;
    }
    .icon-link svg { width: 16px; height: 16px; fill: currentColor; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>Hysteria2 Clients Admin</h1>
    <button id="open-server-settings" type="button" class="secondary-btn">Настройки сервера</button>
  </div>
  <p id="copy-status" class="copy-status"></p>

  {% if ok_message %}<p class="ok"><strong>{{ ok_message }}</strong></p>{% endif %}
  {% if error_message %}<p class="err"><strong>Ошибка:</strong> {{ error_message }}</p>{% endif %}

  {% if stats and stats.enabled %}
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Скачано (RX)</div>
        <div id="stat-sum-rx" class="stat-value">{{ stats.sum_rx_h }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Отдано (TX)</div>
        <div id="stat-sum-tx" class="stat-value">{{ stats.sum_tx_h }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Общий трафик</div>
        <div id="stat-sum-total" class="stat-value">{{ stats.sum_total_h }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Онлайн</div>
        <div id="stat-online" class="stat-value">{{ stats.online_users }} юз. / {{ stats.online_connections }} подкл.</div>
      </div>
    </div>
    {% if stats.error %}<p class="muted">{{ stats.error }}</p>{% endif %}
  {% else %}
    <p class="muted">Статистика отключена. Включите trafficStats в конфиге Hysteria2.</p>
  {% endif %}

  <div id="server-settings-modal" class="modal-backdrop" aria-hidden="true">
    <div class="modal-card">
      <div class="modal-head">
        <h2>Настройки сервера</h2>
        <button id="close-server-settings" type="button" class="close-btn" title="Закрыть">×</button>
      </div>
      <form method="post" action="/server/bandwidth">
        <div class="server-grid">
          <div>
            <label>Скорость Up (Mbps)</label>
            <input type="number" step="0.1" min="0.1" name="server_up_mbps" value="{{ bandwidth.up_mbps or '' }}" placeholder="например 150">
          </div>
          <div>
            <label>Скорость Down (Mbps)</label>
            <input type="number" step="0.1" min="0.1" name="server_down_mbps" value="{{ bandwidth.down_mbps or '' }}" placeholder="например 150">
          </div>
        </div>
        <div class="actions"><button type="submit">Применить лимит скорости</button></div>
      </form>
      <p class="muted">Текущий глобальный лимит Hysteria2: Up {{ bandwidth.up_raw or 'не задан' }} / Down {{ bandwidth.down_raw or 'не задан' }}</p>
    </div>
  </div>

  <form method="post" action="/apply">
    <input type="hidden" id="mode-input" name="mode" value="{{ defaults.mode or 'manual' }}">
    <details id="create-users-card" class="create-card">
      <summary>Создание пользователей</summary>
      <div class="create-body">
        <div class="tabs">
          <button id="mode-manual-btn" class="tab-btn {% if (defaults.mode or 'manual') == 'manual' %}active{% endif %}" type="button">Режим Manual</button>
          <button id="mode-prefix-btn" class="tab-btn {% if (defaults.mode or 'manual') == 'prefix' %}active{% endif %}" type="button">Режим Prefix</button>
        </div>

        <div id="mode-manual-panel" class="mode-panel {% if (defaults.mode or 'manual') == 'manual' %}active{% endif %}">
          <label>Логины (через пробел, запятую или новую строку)</label>
          <textarea name="manual_usernames" rows="10" placeholder="ivan&#10;petr&#10;user-001">{{ defaults.manual_usernames or '' }}</textarea>
          <p class="muted">Допустимые символы: a-z, A-Z, 0-9, "_" и "-". Точка не поддерживается Hysteria2.</p>
          <div class="limits-grid">
            <div>
              <label>Лимит трафика (GB)</label>
              <input type="number" step="0.1" min="0" name="traffic_limit_gb_manual" value="{{ defaults.traffic_limit_gb_manual or '' }}" placeholder="например 50">
            </div>
            <div>
              <label>Лимит по времени (дней)</label>
              <input type="number" min="1" name="duration_days_manual" value="{{ defaults.duration_days_manual or '' }}" placeholder="например 30">
            </div>
            <div>
              <label>До даты</label>
              <input type="date" name="expires_at_manual" value="{{ defaults.expires_at_manual or '' }}">
            </div>
          </div>
          <div class="limits-grid">
            <div>
              <label>Лимит скорости Up (Mbps)</label>
              <input type="number" step="0.1" min="0" name="speed_up_mbps_manual" value="{{ defaults.speed_up_mbps_manual or '' }}" placeholder="например 30">
            </div>
            <div>
              <label>Лимит скорости Down (Mbps)</label>
              <input type="number" step="0.1" min="0" name="speed_down_mbps_manual" value="{{ defaults.speed_down_mbps_manual or '' }}" placeholder="например 50">
            </div>
            <div>
              <label>Лимит подключений</label>
              <input type="number" min="1" name="max_connections_manual" value="{{ defaults.max_connections_manual or '' }}" placeholder="например 2">
            </div>
          </div>
          <p class="limit-note">Пустые поля = без лимитов.</p>
        </div>

        <div id="mode-prefix-panel" class="mode-panel {% if (defaults.mode or 'manual') == 'prefix' %}active{% endif %}">
          <label>Префикс</label>
          <input name="prefix" value="{{ defaults.prefix }}" />
          <label>Количество</label>
          <input type="number" min="1" max="500" name="count" value="{{ defaults.count }}" />
          <label>Стартовый индекс</label>
          <input type="number" min="0" name="start" value="{{ defaults.start }}" />
          <label>Ширина номера (0 = без zero-pad)</label>
          <input type="number" min="0" max="8" name="width" value="{{ defaults.width }}" />
          <div class="limits-grid">
            <div>
              <label>Лимит трафика (GB)</label>
              <input type="number" step="0.1" min="0" name="traffic_limit_gb_prefix" value="{{ defaults.traffic_limit_gb_prefix or '' }}" placeholder="например 50">
            </div>
            <div>
              <label>Лимит по времени (дней)</label>
              <input type="number" min="1" name="duration_days_prefix" value="{{ defaults.duration_days_prefix or '' }}" placeholder="например 30">
            </div>
            <div>
              <label>До даты</label>
              <input type="date" name="expires_at_prefix" value="{{ defaults.expires_at_prefix or '' }}">
            </div>
          </div>
          <div class="limits-grid">
            <div>
              <label>Лимит скорости Up (Mbps)</label>
              <input type="number" step="0.1" min="0" name="speed_up_mbps_prefix" value="{{ defaults.speed_up_mbps_prefix or '' }}" placeholder="например 30">
            </div>
            <div>
              <label>Лимит скорости Down (Mbps)</label>
              <input type="number" step="0.1" min="0" name="speed_down_mbps_prefix" value="{{ defaults.speed_down_mbps_prefix or '' }}" placeholder="например 50">
            </div>
            <div>
              <label>Лимит подключений</label>
              <input type="number" min="1" name="max_connections_prefix" value="{{ defaults.max_connections_prefix or '' }}" placeholder="например 2">
            </div>
          </div>
          <p class="limit-note">Пустые поля = без лимитов.</p>
        </div>
      </div>
    </details>

    <div class="actions">
      <button type="submit">Применить и сгенерировать URL/QR</button>
    </div>
  </form>

  {% if skipped %}
    <h3>Пропущены</h3>
    <p>{{ skipped|join(', ') }}</p>
  {% endif %}

  {% if results %}
    <h2>Результаты</h2>
    <p class="muted">Нажмите на QR, чтобы скопировать URL пользователя в буфер обмена.</p>
    {% for item in results %}
      <div class="result">
        <p><strong>{{ item.username }}</strong> ({{ item.status }})</p>
        <p>
          <img
            class="qr-copy"
            src="/qr?u={{ item.url | urlencode }}"
            data-url="{{ item.url }}"
            alt="QR for {{ item.username }}"
            title="Нажмите, чтобы скопировать URL"
            width="220"
            loading="lazy"
          />
        </p>
      </div>
    {% endfor %}
    <p class="muted">QR загружаются отдельно, поэтому страница остается стабильной даже при массовом создании.</p>

    {% if created_urls %}
      <h3>Новые добавленные URL</h3>
      <textarea class="links-list" readonly>{% for u in created_urls %}{{ u }}{% if not loop.last %}
{% endif %}{% endfor %}</textarea>
    {% endif %}
  {% endif %}

  <div class="section-header">
    <h2>Пользователи</h2>
    <div class="users-tools">
      <input id="user-search" type="text" placeholder="Поиск пользователя">
      <select id="user-sort">
        <option value="online_first" selected>Сортировка: онлайн сначала</option>
        <option value="name_asc">Сортировка: имя A→Z</option>
        <option value="traffic_desc">Сортировка: трафик ↓</option>
        <option value="traffic_asc">Сортировка: трафик ↑</option>
      </select>
    </div>
    <form id="active-delete-form" method="post" action="/users/delete">
      <input type="hidden" name="scope" value="active">
      <button class="danger inline" type="submit" name="mode" value="selected">Удалить выбранных</button>
      <button class="danger inline" type="submit" name="mode" value="all_except_protected">Удалить всех кроме admin</button>
    </form>
  </div>

  <div class="tabs">
    <button id="tab-active-btn" class="tab-btn active" type="button">Активные ({{ active_users|length if active_users else 0 }})</button>
    <button id="tab-disabled-btn" class="tab-btn" type="button">Отключенные ({{ disabled_users|length if disabled_users else 0 }})</button>
  </div>

  <div id="tab-active" class="tab-panel active box">
    {% if active_users %}
      {% for u in active_users %}
        <details class="user-card" data-username="{{ u.username }}" data-total="{{ u.total }}" data-online="{{ 1 if u.is_online else 0 }}" data-disabled="0">
          <summary><span class="summary-name">{{ u.username }}{% if u.is_protected %} <span class="muted">(защищен)</span>{% endif %}{% if u.is_online %}<span class="status-dot online" data-user-dot="{{ u.username }}" title="Онлайн: {{ u.online_count }}"></span>{% else %}<span class="status-dot offline" data-user-dot="{{ u.username }}" title="Оффлайн"></span>{% endif %}{% if u.online_count and u.online_count > 1 %}<span class="conn-badge" data-user-online-count="{{ u.username }}" title="Одновременных подключений">x{{ u.online_count }}</span>{% else %}<span class="conn-badge" data-user-online-count="{{ u.username }}" style="display:none;"></span>{% endif %}<span class="summary-meta" data-user-meta="{{ u.username }}">↓ {{ u.rx_h }} | ↑ {{ u.tx_h }} | Σ {{ u.total_h }}</span></span><label class="summary-select" title="Выбрать для удаления"><input form="active-delete-form" type="checkbox" name="selected_users" value="{{ u.username }}" {% if u.is_protected %}disabled{% endif %}></label></summary>
          <div class="user-body">
            <form method="post" action="/users/toggle" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <input type="hidden" name="action" value="disable">
              <button type="submit" {% if u.is_protected %}disabled{% endif %}>Временно отключить</button>
            </form>
            <p class="user-stats">
              {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}Лимит трафика: {{ u.traffic_limit_h }}{% else %}Лимит трафика: нет{% endif %}
              | {% if u.duration_days %}Срок: {{ u.duration_days }} дн.{% else %}Срок: нет{% endif %}
              | {% if u.expires_at %}До: {{ u.expires_at[:10] }}{% else %}До даты: нет{% endif %}
              | {% if u.speed_up_mbps %}Up: {{ u.speed_up_mbps }} Mbps{% else %}Up: нет{% endif %}
              | {% if u.speed_down_mbps %}Down: {{ u.speed_down_mbps }} Mbps{% else %}Down: нет{% endif %}
              | {% if u.max_connections %}Подкл.: {{ u.max_connections }}{% else %}Подкл.: нет{% endif %}
            </p>
            {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}
              <p class="user-stats" data-user-limit-text="{{ u.username }}">Остаток: {{ u.traffic_remaining_h }}</p>
              <div class="limit-bar"><div class="limit-fill {% if u.traffic_usage_percent >= 100 %}danger{% elif u.traffic_usage_percent >= 90 %}warn{% endif %}" data-user-limit-bar="{{ u.username }}" style="width: {{ u.traffic_usage_percent }}%;"></div></div>
            {% endif %}
            <form method="post" action="/users/limits" class="edit-limits">
              <input type="hidden" name="username" value="{{ u.username }}">
              <div class="edit-grid">
                <div>
                  <label>Трафик (GB)</label>
                  <input type="number" step="0.1" min="0" name="traffic_limit_gb" value="{{ u.traffic_limit_gb if u.traffic_limit_gb is defined and u.traffic_limit_gb else '' }}">
                </div>
                <div>
                  <label>Дней</label>
                  <input type="number" min="1" name="duration_days" value="{{ u.duration_days or '' }}">
                </div>
                <div>
                  <label>До даты</label>
                  <input type="date" name="expires_at" value="{{ u.expires_at[:10] if u.expires_at else '' }}">
                </div>
              </div>
              <div class="edit-grid">
                <div>
                  <label>Скорость Up (Mbps)</label>
                  <input type="number" step="0.1" min="0" name="speed_up_mbps" value="{{ u.speed_up_mbps if u.speed_up_mbps else '' }}">
                </div>
                <div>
                  <label>Скорость Down (Mbps)</label>
                  <input type="number" step="0.1" min="0" name="speed_down_mbps" value="{{ u.speed_down_mbps if u.speed_down_mbps else '' }}">
                </div>
                <div>
                  <label>Лимит подключений</label>
                  <input type="number" min="1" name="max_connections" value="{{ u.max_connections if u.max_connections else '' }}">
                </div>
              </div>
              <div class="actions"><button type="submit">Редактировать лимиты</button></div>
            </form>
            <p>
              <img
                class="qr-copy"
                src="/qr?u={{ u.url | urlencode }}"
                data-url="{{ u.url }}"
                alt="QR for {{ u.username }}"
                title="Нажмите, чтобы скопировать URL"
                width="220"
                loading="lazy"
              />
            </p>
            <code class="url-text">{{ u.url }}</code>
          </div>
        </details>
      {% endfor %}
    {% else %}
      <p class="muted">Нет активных пользователей.</p>
    {% endif %}
  </div>

  <div id="tab-disabled" class="tab-panel box">
    {% if disabled_users %}
      {% for u in disabled_users %}
        <details class="user-card" data-username="{{ u.username }}" data-total="{{ u.total }}" data-online="0" data-disabled="1">
          <summary>{{ u.username }}{% if u.is_protected %} <span class="muted">(защищен)</span>{% endif %}<span class="status-dot disabled" data-user-dot="{{ u.username }}" title="Клиент выключен"></span><span class="conn-badge" data-user-online-count="{{ u.username }}" style="display:none;"></span><span class="summary-meta" data-user-meta="{{ u.username }}">↓ {{ u.rx_h }} | ↑ {{ u.tx_h }} | Σ {{ u.total_h }}</span></summary>
          <div class="user-body">
            <p class="muted">Отключен: {{ u.disabled_at or 'неизвестно' }}</p>
            <form method="post" action="/users/toggle" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <input type="hidden" name="action" value="enable">
              <button type="submit">Включить обратно</button>
            </form>
            <p class="user-stats">
              {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}Лимит трафика: {{ u.traffic_limit_h }}{% else %}Лимит трафика: нет{% endif %}
              | {% if u.duration_days %}Срок: {{ u.duration_days }} дн.{% else %}Срок: нет{% endif %}
              | {% if u.expires_at %}До: {{ u.expires_at[:10] }}{% else %}До даты: нет{% endif %}
              | {% if u.speed_up_mbps %}Up: {{ u.speed_up_mbps }} Mbps{% else %}Up: нет{% endif %}
              | {% if u.speed_down_mbps %}Down: {{ u.speed_down_mbps }} Mbps{% else %}Down: нет{% endif %}
              | {% if u.max_connections %}Подкл.: {{ u.max_connections }}{% else %}Подкл.: нет{% endif %}
            </p>
            {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}
              <p class="user-stats" data-user-limit-text="{{ u.username }}">Остаток: {{ u.traffic_remaining_h }}</p>
              <div class="limit-bar"><div class="limit-fill {% if u.traffic_usage_percent >= 100 %}danger{% elif u.traffic_usage_percent >= 90 %}warn{% endif %}" data-user-limit-bar="{{ u.username }}" style="width: {{ u.traffic_usage_percent }}%;"></div></div>
            {% endif %}
            {% if u.disabled_reason %}
              <p class="muted">Причина отключения: {{ u.disabled_reason }}</p>
            {% endif %}
            <form method="post" action="/users/limits" class="edit-limits">
              <input type="hidden" name="username" value="{{ u.username }}">
              <div class="edit-grid">
                <div>
                  <label>Трафик (GB)</label>
                  <input type="number" step="0.1" min="0" name="traffic_limit_gb" value="{{ u.traffic_limit_gb if u.traffic_limit_gb is defined and u.traffic_limit_gb else '' }}">
                </div>
                <div>
                  <label>Дней</label>
                  <input type="number" min="1" name="duration_days" value="{{ u.duration_days or '' }}">
                </div>
                <div>
                  <label>До даты</label>
                  <input type="date" name="expires_at" value="{{ u.expires_at[:10] if u.expires_at else '' }}">
                </div>
              </div>
              <div class="edit-grid">
                <div>
                  <label>Скорость Up (Mbps)</label>
                  <input type="number" step="0.1" min="0" name="speed_up_mbps" value="{{ u.speed_up_mbps if u.speed_up_mbps else '' }}">
                </div>
                <div>
                  <label>Скорость Down (Mbps)</label>
                  <input type="number" step="0.1" min="0" name="speed_down_mbps" value="{{ u.speed_down_mbps if u.speed_down_mbps else '' }}">
                </div>
                <div>
                  <label>Лимит подключений</label>
                  <input type="number" min="1" name="max_connections" value="{{ u.max_connections if u.max_connections else '' }}">
                </div>
              </div>
              <div class="actions"><button type="submit">Редактировать лимиты</button></div>
            </form>
            {% if u.url %}
              <p>
                <img
                  class="qr-copy"
                  src="/qr?u={{ u.url | urlencode }}"
                  data-url="{{ u.url }}"
                  alt="QR for {{ u.username }}"
                  title="Нажмите, чтобы скопировать URL"
                  width="220"
                  loading="lazy"
                />
              </p>
              <code class="url-text">{{ u.url }}</code>
            {% else %}
              <p class="muted">Для этого пользователя нет сохраненного URL.</p>
            {% endif %}
          </div>
        </details>
      {% endfor %}
    {% else %}
      <p class="muted">Нет отключенных пользователей.</p>
    {% endif %}
  </div>

  <footer class="site-footer">
    <span>© 2026 Разработка: AntyanMSA</span>
    <div class="footer-icons">
      <a class="icon-link" href="https://github.com/AntyanMS" target="_blank" rel="noopener noreferrer" title="GitHub">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 .5a12 12 0 0 0-3.79 23.39c.6.11.82-.26.82-.58v-2.03c-3.34.73-4.04-1.61-4.04-1.61-.55-1.38-1.33-1.75-1.33-1.75-1.08-.74.08-.72.08-.72 1.2.08 1.83 1.2 1.83 1.2 1.06 1.83 2.8 1.3 3.49 1 .1-.77.42-1.3.76-1.6-2.67-.3-5.48-1.34-5.48-5.95 0-1.31.46-2.37 1.2-3.2-.12-.3-.52-1.52.11-3.16 0 0 .99-.32 3.24 1.22a11.3 11.3 0 0 1 5.9 0c2.25-1.54 3.24-1.22 3.24-1.22.63 1.64.23 2.86.12 3.16.75.83 1.2 1.89 1.2 3.2 0 4.62-2.82 5.64-5.5 5.94.43.38.82 1.11.82 2.25v3.34c0 .32.21.69.83.58A12 12 0 0 0 12 .5z"></path>
        </svg>
      </a>
      <a class="icon-link" href="https://t.me/Cmint" target="_blank" rel="noopener noreferrer" title="Telegram">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M21.94 4.66a1.5 1.5 0 0 0-1.64-.2L2.55 11.8a1.5 1.5 0 0 0 .12 2.81l4.18 1.38 1.53 4.92a1.5 1.5 0 0 0 2.67.46l2.36-3.18 4.29 3.14a1.5 1.5 0 0 0 2.35-.88l2.77-14.4a1.5 1.5 0 0 0-.88-1.39zM9.9 16.7l-.64 2.1-.88-2.82 8.82-7.89-7.3 8.61z"></path>
        </svg>
      </a>
    </div>
  </footer>

  <script>
    (function () {
      const tabActiveBtn = document.getElementById("tab-active-btn");
      const tabDisabledBtn = document.getElementById("tab-disabled-btn");
      const tabActive = document.getElementById("tab-active");
      const tabDisabled = document.getElementById("tab-disabled");
      const copyStatus = document.getElementById("copy-status");
      const searchInput = document.getElementById("user-search");
      const sortSelect = document.getElementById("user-sort");
      const statSumRx = document.getElementById("stat-sum-rx");
      const statSumTx = document.getElementById("stat-sum-tx");
      const statSumTotal = document.getElementById("stat-sum-total");
      const statOnline = document.getElementById("stat-online");
      const openServerSettingsBtn = document.getElementById("open-server-settings");
      const closeServerSettingsBtn = document.getElementById("close-server-settings");
      const serverSettingsModal = document.getElementById("server-settings-modal");
      const modeInput = document.getElementById("mode-input");
      const modeManualBtn = document.getElementById("mode-manual-btn");
      const modePrefixBtn = document.getElementById("mode-prefix-btn");
      const modeManualPanel = document.getElementById("mode-manual-panel");
      const modePrefixPanel = document.getElementById("mode-prefix-panel");

      function openServerModal() {
        if (!serverSettingsModal) return;
        serverSettingsModal.classList.add("open");
        serverSettingsModal.setAttribute("aria-hidden", "false");
      }

      function closeServerModal() {
        if (!serverSettingsModal) return;
        serverSettingsModal.classList.remove("open");
        serverSettingsModal.setAttribute("aria-hidden", "true");
      }

      if (openServerSettingsBtn) {
        openServerSettingsBtn.addEventListener("click", openServerModal);
      }
      if (closeServerSettingsBtn) {
        closeServerSettingsBtn.addEventListener("click", closeServerModal);
      }
      if (serverSettingsModal) {
        serverSettingsModal.addEventListener("click", function (e) {
          if (e.target === serverSettingsModal) closeServerModal();
        });
      }
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") closeServerModal();
      });

      function setTab(name) {
        const active = name === "active";
        tabActive.classList.toggle("active", active);
        tabDisabled.classList.toggle("active", !active);
        tabActiveBtn.classList.toggle("active", active);
        tabDisabledBtn.classList.toggle("active", !active);
      }

      if (tabActiveBtn && tabDisabledBtn) {
        tabActiveBtn.addEventListener("click", function () { setTab("active"); });
        tabDisabledBtn.addEventListener("click", function () { setTab("disabled"); });
      }

      function setModeTab(name) {
        const manual = name === "manual";
        modeManualBtn.classList.toggle("active", manual);
        modePrefixBtn.classList.toggle("active", !manual);
        modeManualPanel.classList.toggle("active", manual);
        modePrefixPanel.classList.toggle("active", !manual);
        if (modeInput) modeInput.value = manual ? "manual" : "prefix";
      }

      if (modeManualBtn && modePrefixBtn && modeManualPanel && modePrefixPanel) {
        modeManualBtn.addEventListener("click", function () { setModeTab("manual"); });
        modePrefixBtn.addEventListener("click", function () { setModeTab("prefix"); });
      }

      function getCards(container) {
        if (!container) return [];
        return Array.from(container.querySelectorAll("details.user-card"));
      }

      function applyFilterAndSort(container) {
        const cards = getCards(container);
        if (!cards.length) return;
        const q = ((searchInput && searchInput.value) || "").trim().toLowerCase();
        cards.forEach(function (card) {
          const uname = (card.dataset.username || "").toLowerCase();
          card.style.display = !q || uname.includes(q) ? "" : "none";
        });
        const mode = (sortSelect && sortSelect.value) || "online_first";
        cards.sort(function (a, b) {
          const aName = (a.dataset.username || "").toLowerCase();
          const bName = (b.dataset.username || "").toLowerCase();
          const aTotal = Number(a.dataset.total || 0);
          const bTotal = Number(b.dataset.total || 0);
          const aOnline = Number(a.dataset.online || 0);
          const bOnline = Number(b.dataset.online || 0);
          if (mode === "traffic_desc") return bTotal - aTotal || aName.localeCompare(bName);
          if (mode === "traffic_asc") return aTotal - bTotal || aName.localeCompare(bName);
          if (mode === "online_first") return bOnline - aOnline || bTotal - aTotal || aName.localeCompare(bName);
          return aName.localeCompare(bName);
        });
        cards.forEach(function (card) { container.appendChild(card); });
      }

      function applyAllFilters() {
        applyFilterAndSort(tabActive);
        applyFilterAndSort(tabDisabled);
      }

      if (searchInput) searchInput.addEventListener("input", applyAllFilters);
      if (sortSelect) sortSelect.addEventListener("change", applyAllFilters);
      applyAllFilters();

      async function copyText(text) {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
          return;
        }
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }

      document.querySelectorAll(".qr-copy").forEach(function (img) {
        img.addEventListener("click", async function () {
          const url = img.getAttribute("data-url");
          if (!url) return;
          try {
            await copyText(url);
            if (copyStatus) {
              copyStatus.textContent = "URL скопирован в буфер обмена";
            }
          } catch (e) {
            if (copyStatus) {
              copyStatus.textContent = "Не удалось скопировать URL";
            }
          }
        });
      });

      const cardByUser = {};
      const dotByUser = {};
      const onlineCountBadgeByUser = {};
      const metaByUser = {};
      const limitTextByUser = {};
      const limitBarByUser = {};

      document.querySelectorAll("details.user-card").forEach(function (card) {
        const user = card.dataset.username;
        if (user) cardByUser[user] = card;
      });
      document.querySelectorAll("[data-user-dot]").forEach(function (el) {
        dotByUser[el.getAttribute("data-user-dot")] = el;
      });
      document.querySelectorAll("[data-user-online-count]").forEach(function (el) {
        onlineCountBadgeByUser[el.getAttribute("data-user-online-count")] = el;
      });
      document.querySelectorAll("[data-user-meta]").forEach(function (el) {
        metaByUser[el.getAttribute("data-user-meta")] = el;
      });
      document.querySelectorAll("[data-user-limit-text]").forEach(function (el) {
        limitTextByUser[el.getAttribute("data-user-limit-text")] = el;
      });
      document.querySelectorAll("[data-user-limit-bar]").forEach(function (el) {
        limitBarByUser[el.getAttribute("data-user-limit-bar")] = el;
      });

      function updateLimitBar(bar, percent) {
        const p = Math.max(0, Math.min(100, Number(percent || 0)));
        bar.style.width = p + "%";
        bar.classList.remove("warn", "danger");
        if (p >= 100) bar.classList.add("danger");
        else if (p >= 90) bar.classList.add("warn");
      }

      async function refreshLive() {
        try {
          const r = await fetch("/api/live", { cache: "no-store" });
          if (!r.ok) return;
          const data = await r.json();
          const st = data.stats || {};
          if (statSumRx) statSumRx.textContent = st.sum_rx_h || "0 B";
          if (statSumTx) statSumTx.textContent = st.sum_tx_h || "0 B";
          if (statSumTotal) statSumTotal.textContent = st.sum_total_h || "0 B";
          if (statOnline) statOnline.textContent = (st.online_users || 0) + " юз. / " + (st.online_connections || 0) + " подкл.";
          const users = data.users || {};
          Object.keys(users).forEach(function (u) {
            const info = users[u] || {};
            if (cardByUser[u]) {
              cardByUser[u].dataset.total = String(info.total || 0);
              cardByUser[u].dataset.online = info.is_online ? "1" : "0";
            }
            if (dotByUser[u]) {
              const dot = dotByUser[u];
              dot.classList.remove("online", "offline", "disabled");
              if (info.is_disabled) {
                dot.classList.add("disabled");
                dot.title = "Клиент выключен";
              } else if (info.is_online) {
                dot.classList.add("online");
                dot.title = "Онлайн: " + (info.online_count || 0);
              } else {
                dot.classList.add("offline");
                dot.title = "Оффлайн";
              }
            }
            if (onlineCountBadgeByUser[u]) {
              const badge = onlineCountBadgeByUser[u];
              const cnt = Number(info.online_count || 0);
              if (!info.is_disabled && cnt > 1) {
                badge.style.display = "inline-block";
                badge.textContent = "x" + cnt;
                badge.title = "Одновременных подключений: " + cnt;
              } else {
                badge.style.display = "none";
                badge.textContent = "";
              }
            }
            if (metaByUser[u]) {
              metaByUser[u].textContent = "↓ " + (info.rx_h || "0 B") + " | ↑ " + (info.tx_h || "0 B") + " | Σ " + (info.total_h || "0 B");
            }
            if (limitTextByUser[u] && info.traffic_limit_bytes > 0) {
              limitTextByUser[u].textContent = "Остаток: " + (info.traffic_remaining_h || "0 B");
            }
            if (limitBarByUser[u] && info.traffic_limit_bytes > 0) {
              updateLimitBar(limitBarByUser[u], info.traffic_usage_percent || 0);
            }
          });
          applyAllFilters();
        } catch (e) {
          // keep UI functional even if live API temporarily unavailable
        }
      }

      setInterval(refreshLive, 8000);
    })();
  </script>
</body>
</html>
HTML
}

write_env_file() {
  cat > "${INSTALL_DIR}/.env" <<EOF
HY2_CONFIG_PATH=/etc/hysteria/config.yaml
HY2_SERVICE_NAME=hysteria-server.service
SERVER_HOST=${APP_HOST}
SERVER_PORT=443
SERVER_SNI=${APP_HOST}
CLIENT_INSECURE=0
PANEL_BASIC_USER=${PANEL_USER}
PANEL_BASIC_PASS=${PANEL_PASS}
PANEL_BIND_HOST=0.0.0.0
PANEL_BIND_PORT=${APP_PORT}
PROTECTED_USERS=admin,Admin
EOF
}

setup_tls() {
  TLS_ARGS=""
  if [[ "${APP_SCHEME}" != "https" ]]; then
    return
  fi
  local cert_path key_path
  if [[ "${USE_CERTBOT}" == "y" ]]; then
    mkdir -p /var/www/masq
    certbot certonly --webroot -w /var/www/masq -d "${APP_HOST}" -m "${CERT_EMAIL}" --agree-tos --no-eff-email --non-interactive
    cert_path="/etc/letsencrypt/live/${APP_HOST}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${APP_HOST}/privkey.pem"
  else
    cert_path="${INSTALL_DIR}/tls/panel.crt"
    key_path="${INSTALL_DIR}/tls/panel.key"
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
      -keyout "${key_path}" \
      -out "${cert_path}" \
      -subj "/CN=${APP_HOST}" >/dev/null 2>&1
  fi
  TLS_ARGS=" --certfile ${cert_path} --keyfile ${key_path}"
}

write_service() {
  cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=HY2 Admin Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/gunicorn --workers 2 --worker-class gthread --threads 8 --timeout 15 --graceful-timeout 15 --keep-alive 2 --max-requests 1000 --max-requests-jitter 100 --access-logfile - -b 0.0.0.0:${APP_PORT}${TLS_ARGS} app:app
Restart=always
RestartSec=2
User=root
Group=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
}

install_python_deps() {
  python3 -m venv "${INSTALL_DIR}/.venv"
  "${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
  "${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"
}

service_manage() {
  systemctl daemon-reload
  if [[ "${ENABLE_AUTOSTART}" == "y" ]]; then
    systemctl enable "${SERVICE_NAME}"
  fi
  if [[ "${START_NOW}" == "y" ]]; then
    systemctl restart "${SERVICE_NAME}"
  fi
}

open_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -qi "Status: active"; then
      yes | ufw delete allow "${APP_PORT}/tcp" >/dev/null 2>&1 || true
      ufw limit "${APP_PORT}/tcp" >/dev/null 2>&1 || true
    fi
  fi
}

print_summary() {
  local url
  url="${APP_SCHEME}://${APP_HOST}:${APP_PORT}/"
  echo
  echo "==========================================="
  echo "Установка завершена"
  echo "Панель: ${url}"
  echo "Логин: ${PANEL_USER}"
  echo "Пароль: ${PANEL_PASS}"
  echo "Сервис: ${SERVICE_NAME}"
  echo "==========================================="
}

main() {
  require_root
  if [[ "${MODE}" == "--auto" ]]; then
    collect_auto
  elif [[ "${MODE}" == "--interactive" ]]; then
    collect_interactive
  else
    echo "Использование: $0 [--auto|--interactive]" >&2
    exit 1
  fi
  install_packages
  prepare_files
  write_env_file
  setup_tls
  write_service
  install_python_deps
  open_firewall
  service_manage
  print_summary
}

main "$@"

