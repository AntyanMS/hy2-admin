import hashlib
import io
import ipaddress
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
USER_NOTES_PATH = Path("/opt/hy2-admin/data/user_notes.json")
USER_IP_STATE_PATH = Path("/opt/hy2-admin/data/user_ip_state.json")
F2B_JAIL_PATH = Path("/etc/fail2ban/jail.d/hy2-admin.local")

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


def load_user_notes() -> dict:
    if not USER_NOTES_PATH.exists():
        return {"users": {}}
    try:
        data = json.loads(USER_NOTES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}}
    if not isinstance(data, dict):
        return {"users": {}}
    users = data.get("users")
    if not isinstance(users, dict):
        users = {}
    out = {}
    for k, v in users.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v
    return {"users": out}


def save_user_notes(data: dict) -> None:
    USER_NOTES_PATH.parent.mkdir(parents=True, exist_ok=True)
    USER_NOTES_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_note(value: str) -> str:
    text = (value or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if len(text) > 4000:
        raise ValueError("Заметка слишком длинная (максимум 4000 символов)")
    return text


def update_user_note(username: str, note: str) -> None:
    data = load_user_notes()
    users = data["users"]
    value = normalize_note(note)
    if value:
        users[username] = value
    else:
        users.pop(username, None)
    save_user_notes(data)


def load_user_ip_state() -> dict:
    if not USER_IP_STATE_PATH.exists():
        return {"users": {}, "last_scan_at": ""}
    try:
        data = json.loads(USER_IP_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"users": {}, "last_scan_at": ""}
    if not isinstance(data, dict):
        return {"users": {}, "last_scan_at": ""}
    users = data.get("users")
    if not isinstance(users, dict):
        users = {}
    last_scan_at = str(data.get("last_scan_at", ""))
    return {"users": users, "last_scan_at": last_scan_at}


def save_user_ip_state(data: dict) -> None:
    USER_IP_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    USER_IP_STATE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def extract_ip_from_remote_addr(addr: str) -> str:
    text = str(addr or "").strip()
    if not text:
        return ""
    if text.startswith("[") and "]" in text:
        host = text[1:text.find("]")]
    elif ":" in text:
        host, _ = text.rsplit(":", 1)
    else:
        host = text
    host = host.strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


def update_user_ip_observations(stats_users: dict) -> dict:
    state = load_user_ip_state()
    users_state = state["users"] if isinstance(state.get("users"), dict) else {}
    now = datetime.now(timezone.utc)
    last_scan_at = iso_to_dt(str(state.get("last_scan_at", "")))
    if last_scan_at is None:
        since_dt = now - timedelta(days=2)
    else:
        since_dt = last_scan_at - timedelta(seconds=2)
    since_str = since_dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    proc = subprocess.run(
        ["journalctl", "-u", HY2_SERVICE, "--since", since_str, "--no-pager", "-o", "cat"],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0:
        r1 = re.compile(r'"addr"\s*:\s*"([^"]+)"\s*,\s*"id"\s*:\s*"([^"]+)"')
        r2 = re.compile(r'"id"\s*:\s*"([^"]+)"\s*,\s*"addr"\s*:\s*"([^"]+)"')
        for line in proc.stdout.splitlines():
            m = r1.search(line)
            if m:
                addr_raw = m.group(1)
                user_raw = m.group(2)
            else:
                m = r2.search(line)
                if not m:
                    continue
                user_raw = m.group(1)
                addr_raw = m.group(2)
            ip = extract_ip_from_remote_addr(addr_raw)
            if not ip:
                continue
            key = str(user_raw).strip().lower()
            if not key:
                continue
            rec = users_state.get(key, {})
            if not isinstance(rec, dict):
                rec = {}
            history = rec.get("history")
            if not isinstance(history, list):
                history = []
            history = [str(x) for x in history if isinstance(x, str)]
            if ip in history:
                history.remove(ip)
            history.append(ip)
            history = history[-30:]

            events = rec.get("events")
            if not isinstance(events, list):
                events = []
            events = [x for x in events if isinstance(x, dict) and isinstance(x.get("ip"), str) and isinstance(x.get("at"), str)]
            events.append({"ip": ip, "at": now.isoformat()})
            events = events[-80:]

            users_state[key] = {
                "history": history,
                "events": events,
                "last_ip": ip,
                "last_seen_at": now.isoformat(),
            }

    state["users"] = users_state
    state["last_scan_at"] = now.isoformat()
    save_user_ip_state(state)

    out = {}
    for key, rec in users_state.items():
        if not isinstance(rec, dict):
            continue
        history = rec.get("history")
        if not isinstance(history, list):
            history = []
        history = [str(x) for x in history if isinstance(x, str)]
        events = rec.get("events")
        if not isinstance(events, list):
            events = []
        current = []
        online_count = int(((stats_users or {}).get(key) or {}).get("online_count", 0) or 0)
        if online_count > 0:
            threshold = now - timedelta(minutes=20)
            seen = set()
            for ev in reversed(events):
                if not isinstance(ev, dict):
                    continue
                ip = str(ev.get("ip", "")).strip()
                ts = iso_to_dt(str(ev.get("at", "")))
                if not ip or ts is None or ts < threshold:
                    continue
                if ip in seen:
                    continue
                seen.add(ip)
                current.append(ip)
                if len(current) >= 8:
                    break
        out[key] = {
            "current_ips": current,
            "history_ips": list(reversed(history))[:12],
            "last_seen_ip": str(rec.get("last_ip", "")),
            "last_seen_at": str(rec.get("last_seen_at", "")),
        }
    return out


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


def parse_exclusion_tokens(raw: str) -> list[str]:
    text = (raw or "").strip()
    if not text:
        return []
    norm = text.replace(",", " ").replace(";", " ").replace("\n", " ").replace("\t", " ")
    out: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for token in norm.split(" "):
        item = token.strip()
        if not item:
            continue
        try:
            if "/" in item:
                parsed = ipaddress.ip_network(item, strict=False)
                normalized = str(parsed)
            else:
                parsed = ipaddress.ip_address(item)
                normalized = str(parsed)
        except ValueError:
            invalid.append(item)
            continue
        if normalized not in seen:
            out.append(normalized)
            seen.add(normalized)
    if invalid:
        raise ValueError("Некорректные IP/CIDR: " + ", ".join(invalid[:10]))
    return out


def normalize_exclusions(items: list[str]) -> list[str]:
    baseline = ["127.0.0.0/8", "::1"]
    out: list[str] = []
    seen: set[str] = set()
    for item in baseline + list(items):
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def read_server_exclusions() -> dict:
    if not F2B_JAIL_PATH.exists():
        base = normalize_exclusions([])
        return {"items": base, "text": "\n".join(base), "raw_line": ""}
    text = F2B_JAIL_PATH.read_text(encoding="utf-8")
    m = re.search(r"(?mi)^\s*ignoreip\s*=\s*(.+?)\s*$", text)
    raw_line = m.group(1).strip() if m else ""
    parsed = parse_exclusion_tokens(raw_line) if raw_line else []
    items = normalize_exclusions(parsed)
    return {"items": items, "text": "\n".join(items), "raw_line": raw_line}


def write_server_exclusions(items: list[str]) -> None:
    final_items = normalize_exclusions(items)
    ignore_value = " ".join(final_items)
    if F2B_JAIL_PATH.exists():
        text = F2B_JAIL_PATH.read_text(encoding="utf-8")
    else:
        text = "[DEFAULT]\nignoreip = 127.0.0.0/8 ::1\n\n[hy2-admin-auth]\nenabled = true\nport = 8787\nbackend = systemd\njournalmatch = _SYSTEMD_UNIT=hy2-admin.service\nfilter = hy2-admin-auth\nmaxretry = 6\nfindtime = 10m\nbantime = 2h\n"

    lines = text.splitlines()
    default_start = None
    default_end = len(lines)
    for i, line in enumerate(lines):
        if re.match(r"^\s*\[DEFAULT\]\s*$", line):
            default_start = i
            for j in range(i + 1, len(lines)):
                if re.match(r"^\s*\[.+\]\s*$", lines[j]):
                    default_end = j
                    break
            break

    if default_start is None:
        lines = [f"[DEFAULT]", f"ignoreip = {ignore_value}", ""] + lines
    else:
        replaced = False
        for i in range(default_start + 1, default_end):
            if re.match(r"^\s*ignoreip\s*=", lines[i]):
                lines[i] = f"ignoreip = {ignore_value}"
                replaced = True
                break
        if not replaced:
            lines.insert(default_start + 1, f"ignoreip = {ignore_value}")

    F2B_JAIL_PATH.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    reload_res = subprocess.run(["fail2ban-client", "reload"], capture_output=True, text=True)
    if reload_res.returncode != 0:
        raise RuntimeError(f"Не удалось перезагрузить fail2ban: {reload_res.stderr.strip() or reload_res.stdout.strip()}")


def run_fail2ban(args: list[str]) -> str:
    res = subprocess.run(["fail2ban-client", *args], capture_output=True, text=True)
    if res.returncode != 0:
        msg = (res.stderr or res.stdout or "").strip()
        raise RuntimeError(msg or f"Команда fail2ban завершилась с кодом {res.returncode}")
    return (res.stdout or "").strip()


def get_fail2ban_jails() -> list[str]:
    out = run_fail2ban(["status"])
    m = re.search(r"Jail list:\s*(.+)", out)
    if not m:
        return []
    return [item.strip() for item in m.group(1).split(",") if item.strip()]


def parse_banned_ips_from_status(output: str) -> list[str]:
    m = re.search(r"Banned IP list:\s*(.*)", output)
    if not m:
        return []
    raw = m.group(1).strip()
    if not raw:
        return []
    ips = []
    for token in raw.split():
        try:
            ips.append(str(ipaddress.ip_address(token.strip())))
        except ValueError:
            continue
    return ips


def read_server_blacklist() -> dict:
    try:
        jails = get_fail2ban_jails()
        index: dict[str, set[str]] = {}
        for jail in jails:
            try:
                status_out = run_fail2ban(["status", jail])
            except Exception:
                continue
            for ip in parse_banned_ips_from_status(status_out):
                index.setdefault(ip, set()).add(jail)
        entries = [{"ip": ip, "jails": sorted(list(js))} for ip, js in sorted(index.items(), key=lambda x: x[0])]
        return {"entries": entries, "error": ""}
    except Exception as e:
        return {"entries": [], "error": str(e)}


def parse_single_ip(value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("IP адрес обязателен")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValueError("Укажите корректный IPv4/IPv6 адрес")


def unban_ip_in_all_jails(ip: str) -> int:
    count = 0
    for jail in get_fail2ban_jails():
        res = subprocess.run(["fail2ban-client", "set", jail, "unbanip", ip], capture_output=True, text=True)
        if res.returncode == 0:
            count += 1
    return count


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


def remove_users_from_notes(usernames: list[str]) -> None:
    if not usernames:
        return
    data = load_user_notes()
    users = data["users"]
    changed = False
    for username in usernames:
        if username in users:
            users.pop(username, None)
            changed = True
    if changed:
        save_user_notes(data)


def remove_users_from_ip_state(usernames: list[str]) -> None:
    if not usernames:
        return
    state = load_user_ip_state()
    users = state["users"] if isinstance(state.get("users"), dict) else {}
    changed = False
    for username in usernames:
        key = str(username).strip().lower()
        if key in users:
            users.pop(key, None)
            changed = True
    if changed:
        state["users"] = users
        save_user_ip_state(state)


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

    # Не отключаем пользователя при превышении лимита устройств:
    # иначе отключаются сразу все его подключения.
    # max_connections остается информативным лимитом в UI.

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
    notes = load_user_notes().get("users", {})
    protected = get_protected_users()
    host, port, sni = infer_server_values(cfg)
    stats = get_hy2_stats(cfg)
    stats_users = stats.get("users", {})
    ip_users = update_user_ip_observations(stats_users)
    active = []
    for username, password in sorted(cfg["auth"]["userpass"].items()):
        stats_key = str(username).strip().lower()
        ip_info = ip_users.get(stats_key, {}) if isinstance(ip_users.get(stats_key, {}), dict) else {}
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
                "current_ips": ip_info.get("current_ips", []),
                "history_ips": ip_info.get("history_ips", []),
                "last_seen_ip": ip_info.get("last_seen_ip", ""),
                "last_seen_ip_at": ip_info.get("last_seen_at", ""),
                "note": str(notes.get(username, "")),
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
        ip_info = ip_users.get(stats_key, {}) if isinstance(ip_users.get(stats_key, {}), dict) else {}
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
                "current_ips": ip_info.get("current_ips", []),
                "history_ips": ip_info.get("history_ips", []),
                "last_seen_ip": ip_info.get("last_seen_ip", ""),
                "last_seen_ip_at": ip_info.get("last_seen_at", ""),
                "note": str(notes.get(username, "")),
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
    remove_users_from_notes(deleted_usernames)
    remove_users_from_ip_state(deleted_usernames)

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
        exclusions=read_server_exclusions(),
        blacklist=read_server_blacklist(),
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


@app.route("/users/note", methods=["POST"])
@requires_auth
def users_note_handler():
    username = request.form.get("username", "").strip()
    note = request.form.get("note", "")
    try:
        if not valid_username(username):
            raise ValueError("Недопустимое имя пользователя")
        cfg = load_hy2_config()
        state = load_user_state()
        if username not in cfg["auth"]["userpass"] and username not in state["disabled"]:
            raise ValueError("Пользователь не найден")
        update_user_note(username, note)
        return render_index_page(ok_message=f"Заметка сохранена: {username}")
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


@app.route("/server/exclusions", methods=["POST"])
@requires_auth
def server_exclusions_handler():
    raw = request.form.get("server_exclusions", "")
    try:
        items = parse_exclusion_tokens(raw)
        if len(items) > 200:
            raise ValueError("Слишком много исключений (максимум 200)")
        write_server_exclusions(items)
        return render_index_page(ok_message=f"Исключения обновлены: {len(normalize_exclusions(items))}")
    except Exception as e:
        return render_index_page(
            defaults={"server_exclusions": raw},
            error_message=str(e),
        )


@app.route("/server/blacklist/add", methods=["POST"])
@requires_auth
def server_blacklist_add_handler():
    raw = request.form.get("blacklist_ip_add", "")
    try:
        ip = parse_single_ip(raw)
        exclusions = read_server_exclusions().get("items", [])
        if ip in exclusions:
            raise ValueError(f"{ip} уже в исключениях fail2ban (ignoreip)")
        run_fail2ban(["set", "hy2-admin-auth", "banip", ip])
        return render_index_page(ok_message=f"IP добавлен в черный список: {ip}")
    except Exception as e:
        return render_index_page(defaults={"blacklist_ip_add": raw}, error_message=str(e))


@app.route("/server/blacklist/remove", methods=["POST"])
@requires_auth
def server_blacklist_remove_handler():
    raw = request.form.get("blacklist_ip_remove", "")
    try:
        ip = parse_single_ip(raw)
        unbanned = unban_ip_in_all_jails(ip)
        if unbanned == 0:
            raise ValueError(f"IP {ip} не найден в черном списке")
        return render_index_page(ok_message=f"IP удален из черного списка: {ip}")
    except Exception as e:
        return render_index_page(defaults={"blacklist_ip_remove": raw}, error_message=str(e))


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
