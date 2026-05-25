import base64
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sys
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.parse import quote

import qrcode
import yaml
from flask import Blueprint, Flask, Response, redirect, render_template, request, session, url_for

from suffix_flags import FLAG_SVG_24x16

try:
    import pyotp
except ImportError:  # pragma: no cover
    pyotp = None  # type: ignore[misc, assignment]


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


ENV_PATH = Path("/opt/hy2-admin/.env")
ENV = load_env(str(ENV_PATH))
HY2_CONFIG = ENV.get("HY2_CONFIG_PATH", "/etc/hysteria/config.yaml")
HY2_SERVICE = ENV.get("HY2_SERVICE_NAME", "hysteria-server.service")
SERVER_HOST = ENV.get("SERVER_HOST", "")
SERVER_PORT = ENV.get("SERVER_PORT", "")
SERVER_SNI = ENV.get("SERVER_SNI", "")
INSECURE = ENV.get("CLIENT_INSECURE", "0") == "1"
BIND_HOST = ENV.get("PANEL_BIND_HOST", "127.0.0.1")
BIND_PORT = int(ENV.get("PANEL_BIND_PORT", "18080"))
PANEL_SYSTEMD_SERVICE = ENV.get("PANEL_SYSTEMD_SERVICE", "hy2-admin.service").strip() or "hy2-admin.service"
PROTECTED_USERS_RAW = ENV.get("PROTECTED_USERS", "")
HY2_UI_HIDDEN_USERS_RAW = (ENV.get("HY2_UI_HIDDEN_USERS") or "").strip()
SING_BOX_CONFIG_PATH = ENV.get("SING_BOX_CONFIG_PATH", "/etc/sing-box/config.json")
SINGBOX_GEOIP_RU_URL = (
    ENV.get("SINGBOX_GEOIP_RU_URL")
    or "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs"
).strip()
GEOIP_RU_RULE_SET_TAG = "geoip-ru"
SINGBOX_CLASH_API_URL = (ENV.get("SINGBOX_CLASH_API_URL") or "http://127.0.0.1:19090").strip()
SINGBOX_CLASH_API_SECRET = (ENV.get("SINGBOX_CLASH_API_SECRET") or "").strip()
try:
    SINGBOX_ONLINE_WINDOW_SECONDS = max(60, min(86400, int(ENV.get("SINGBOX_ONLINE_WINDOW_SECONDS", "1800"))))
except ValueError:
    SINGBOX_ONLINE_WINDOW_SECONDS = 1800
try:
    SINGBOX_USER_MAP_WINDOW_SECONDS = max(60, min(7200, int(ENV.get("SINGBOX_USER_MAP_WINDOW_SECONDS", "600"))))
except ValueError:
    SINGBOX_USER_MAP_WINDOW_SECONDS = 600

REGISTRY_PATH = Path("/opt/hy2-admin/data/clients.json")
BACKUP_DIR = Path("/opt/hy2-admin/backups")
STATE_PATH = Path("/opt/hy2-admin/data/user_state.json")
META_PATH = Path("/opt/hy2-admin/data/users_meta.json")
TRAFFIC_STATE_PATH = Path("/opt/hy2-admin/data/traffic_state.json")
USER_NOTES_PATH = Path("/opt/hy2-admin/data/user_notes.json")
USER_IP_STATE_PATH = Path("/opt/hy2-admin/data/user_ip_state.json")
DIRECT_EXPLICIT_STORE_PATH = Path("/opt/hy2-admin/data/direct_routing_explicit.json")
DIRECT_WHITELIST_STORE_PATH = Path("/opt/hy2-admin/data/direct_routing_github_whitelist.json")
GITHUB_WHITELIST_RAW_URL = (
    ENV.get("GITHUB_WHITELIST_RAW_URL")
    or "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt"
)
WHITELIST_AUTO_SYNC_INTERVAL_SEC = 86400
WHITELIST_DNS_WORKERS = max(4, min(64, int((ENV.get("WHITELIST_DNS_WORKERS") or "32").strip() or "32")))
WHITELIST_DNS_TIMEOUT_SEC = max(1.0, float((ENV.get("WHITELIST_DNS_TIMEOUT_SEC") or "4").strip() or "4"))
_whitelist_sync_lock = threading.Lock()
_whitelist_sync_thread: threading.Thread | None = None
# ccTLD для правила domain_suffix → direct (чекбоксы в панели, по странам)
DIRECT_DOMAIN_SUFFIX_GROUPS: list[dict] = [
    {
        "flag_iso": "ru",
        "country": "Россия",
        "suffixes": [
            {"label": ".ru", "suffix": ".ru"},
            {"label": ".рф", "suffix": ".xn--p1ai"},
            {"label": ".su", "suffix": ".su"},
        ],
    },
]
DIRECT_DOMAIN_SUFFIX_DEFAULT = (".ru", ".xn--p1ai", ".su")


def _flatten_direct_suffix_options() -> list[dict[str, str]]:
    flat: list[dict[str, str]] = []
    for grp in DIRECT_DOMAIN_SUFFIX_GROUPS:
        iso = str(grp.get("flag_iso", "")).strip().lower()
        country = str(grp.get("country", "")).strip()
        for item in grp.get("suffixes") or []:
            if not isinstance(item, dict):
                continue
            suf = str(item.get("suffix", "")).strip()
            if not suf:
                continue
            flat.append(
                {
                    "flag_iso": iso,
                    "label": str(item.get("label", suf)),
                    "suffix": suf,
                    "title": country,
                }
            )
    return flat


DIRECT_DOMAIN_SUFFIX_OPTIONS: list[dict[str, str]] = _flatten_direct_suffix_options()
CASCADE_REMOTE_SERVERS_PATH = Path("/opt/hy2-admin/data/cascade/remote_servers.json")
BACKUP_FORMAT = "hy2-admin-backup"
BACKUP_FORMAT_VERSION = 1
BACKUP_UPLOAD_MAX_BYTES = 4 * 1024 * 1024


def _app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", ""))
    return Path(__file__).resolve().parent


F2B_JAIL_PATH = Path("/etc/fail2ban/jail.d/hy2-admin.local")
# HTML для HTTPS-заглушки корневого сайта. Переопределение: HTTPS_ROOT_STUB_HTML_PATH в .env
HTTPS_ROOT_STUB_MAX_BYTES = 512 * 1024
# Всегда в ignoreip (fail2ban [DEFAULT]): SSH и панель.
F2B_ALWAYS_IGNORE_IPS = (
    "77.220.143.56",
    "94.159.40.2",
    "185.239.48.216",
    "185.239.49.36",
)

PANEL_TIMEZONE_OPTIONS = (
    "UTC",
    "Europe/Kaliningrad",
    "Europe/Moscow",
    "Europe/Samara",
    "Asia/Yekaterinburg",
    "Asia/Omsk",
    "Asia/Krasnoyarsk",
    "Asia/Irkutsk",
    "Asia/Yakutsk",
    "Asia/Vladivostok",
    "Asia/Magadan",
    "Asia/Kamchatka",
)

app = Flask(__name__, template_folder=str(_app_root() / "templates"))

_sess_key = (ENV.get("PANEL_SESSION_SECRET") or "").strip()
if len(_sess_key) >= 32:
    app.secret_key = _sess_key
else:
    app.secret_key = secrets.token_hex(32)
app.config["SESSION_COOKIE_NAME"] = "hy2a"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if ENV.get("PANEL_SESSION_COOKIE_SECURE", "0") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)


def _normalize_panel_prefix(raw: Optional[str]) -> str:
    """Пусто = корень (legacy). Иначе: /panel (публичный путь) или /<secret>/panel (UUID или hex 16–64)."""
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    if not s.startswith("/"):
        s = "/" + s
    s = s.rstrip("/")
    parts = [p for p in s.split("/") if p]
    if not parts:
        return ""
    # Фиксированный путь без секретного slug: https://домен/panel/
    if len(parts) == 1 and parts[0].lower() == "panel":
        return "/panel"
    if len(parts) != 2 or parts[1].lower() != "panel":
        raise ValueError('PANEL_URL_PREFIX: пусто, "/panel" или "/<секрет>/panel"')
    slug = parts[0]
    uuid_pat = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
    legacy_pat = re.compile(r"^[a-f0-9]{16,64}$", re.I)
    if uuid_pat.match(slug):
        slug_out = slug.lower()
    elif legacy_pat.match(slug):
        slug_out = slug.lower()
    else:
        raise ValueError(
            "Секрет в URL: UUID (36 символов, 8-4-4-4-12) или legacy hex 16–64 символов перед /panel"
        )
    return "/" + slug_out + "/panel"


try:
    PANEL_URL_PREFIX = _normalize_panel_prefix(ENV.get("PANEL_URL_PREFIX"))
except ValueError:
    PANEL_URL_PREFIX = ""

# Только отладка: PANEL_URL_PREFIX пуст, а nginx шлёт полный путь /…/panel/…
INSECURE_DEBUG_STRIP_PREFIX = ""
if not PANEL_URL_PREFIX:
    _strip_raw = (ENV.get("PANEL_INSECURE_DEBUG_STRIP_PREFIX") or "").strip()
    if _strip_raw:
        try:
            INSECURE_DEBUG_STRIP_PREFIX = _normalize_panel_prefix(_strip_raw)
        except ValueError:
            print(
                "hy2-admin: PANEL_INSECURE_DEBUG_STRIP_PREFIX задан неверно — отключён",
                file=sys.stderr,
            )
if INSECURE_DEBUG_STRIP_PREFIX:
    print(
        "hy2-admin: ПРЕДУПРЕЖДЕНИЕ: PANEL_INSECURE_DEBUG_STRIP_PREFIX активен — "
        "для продакшена задайте PANEL_URL_PREFIX и уберите отладочную переменную.",
        file=sys.stderr,
    )

bp = Blueprint("hy2", __name__)


def is_sing_box_readonly_panel() -> bool:
    raw = (ENV.get("PANEL_BACKEND") or "hysteria").strip().lower()
    return raw in ("sing-box", "singbox", "gateway")


def get_panel_credentials() -> tuple[str, str]:
    """Актуальные логин/пароль из .env (после смены через панель без перезапуска)."""
    env = load_env(str(ENV_PATH))
    u = (env.get("PANEL_BASIC_USER") or "admin").strip()
    p = env.get("PANEL_BASIC_PASS") or ""
    return u, p


def get_panel_timezone() -> str:
    env = load_env(str(ENV_PATH))
    tz = (env.get("PANEL_TIMEZONE") or "Europe/Moscow").strip()
    if tz not in PANEL_TIMEZONE_OPTIONS:
        return "Europe/Moscow"
    return tz


def get_live_panel_url_prefix() -> str:
    """Только PANEL_URL_PREFIX из .env (без учёта отладочного strip)."""
    try:
        return _normalize_panel_prefix(load_env(str(ENV_PATH)).get("PANEL_URL_PREFIX"))
    except ValueError:
        return ""


def get_live_effective_panel_url_prefix() -> str:
    """Реальный путь панели в URL: PANEL_URL_PREFIX, иначе при отладке — PANEL_INSECURE_DEBUG_STRIP_PREFIX."""
    env = load_env(str(ENV_PATH))
    try:
        p = _normalize_panel_prefix(env.get("PANEL_URL_PREFIX"))
    except ValueError:
        p = ""
    if p:
        return p
    try:
        return _normalize_panel_prefix(env.get("PANEL_INSECURE_DEBUG_STRIP_PREFIX")) or ""
    except ValueError:
        return ""


def normalize_user_panel_prefix_secret(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        raise ValueError("Укажите новый секрет или полный путь вида /<секрет>/panel")
    if s.startswith("http://") or s.startswith("https://"):
        raise ValueError("Нужен только секрет или путь, без http(s)://")
    s_low = s.lower().rstrip("/")
    if s_low in ("panel", "/panel"):
        return _normalize_panel_prefix("/panel")
    if s.startswith("/"):
        return _normalize_panel_prefix(s)
    return _normalize_panel_prefix("/" + s.strip("/") + "/panel")


def schedule_panel_service_restart() -> None:
    """Перезапуск unit после ответа клиенту (иначе обрыв соединения)."""

    def _run() -> None:
        time.sleep(0.8)
        try:
            subprocess.run(
                ["systemctl", "restart", PANEL_SYSTEMD_SERVICE],
                capture_output=True,
                text=True,
                timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    threading.Thread(target=_run, daemon=True).start()


def _deferred_service_restart_delay_sec() -> float:
    raw = (ENV.get("DEFERRED_SERVICE_RESTART_SEC") or "3").strip()
    try:
        delay = float(raw)
    except ValueError:
        delay = 3.0
    return max(0.5, min(delay, 60.0))


def schedule_systemd_service_restart(service: str, *, delay_sec: float | None = None) -> tuple[bool, str]:
    """Планирует systemctl restart после паузы, чтобы HTTP-ответ успел дойти до клиента."""
    svc = (service or "").strip()
    if not svc:
        return False, "пустое имя unit"

    delay = _deferred_service_restart_delay_sec() if delay_sec is None else float(delay_sec)
    delay = max(0.5, min(delay, 60.0))

    active = subprocess.run(
        ["systemctl", "is-active", svc],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if active.returncode != 0 or active.stdout.strip() != "active":
        return False, active.stdout.strip() or "inactive"

    def _run() -> None:
        time.sleep(delay)
        try:
            subprocess.run(
                ["systemctl", "restart", svc],
                capture_output=True,
                text=True,
                timeout=90,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    threading.Thread(target=_run, daemon=True).start()
    delay_label = str(int(delay)) if delay == int(delay) else f"{delay:g}"
    return True, f"через {delay_label} сек"


def _schedule_sing_box_restart() -> tuple[bool, str]:
    return schedule_systemd_service_restart("sing-box")


def _sing_box_restart_phrase(ok: bool, status: str, *, inline: bool = False) -> str:
    if ok:
        if inline:
            return f", sing-box перезапустится {status}."
        return f" sing-box перезапустится {status}."
    if inline:
        return f", sing-box: {status} (конфиг записан)."
    return f" sing-box: {status} (конфиг записан)."


def panel_nginx_site_paths_from_env(env: dict) -> list[Path]:
    raw = (env.get("PANEL_NGINX_SITE_PATH") or "").strip()
    if not raw:
        return []
    out: list[Path] = []
    for part in raw.split(","):
        p = part.strip()
        if p:
            out.append(Path(p))
    return out


def _nginx_brace_block_end(s: str, open_brace: int) -> int:
    depth = 0
    i = open_brace
    while i < len(s):
        c = s[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _nginx_remove_location_block(s: str, line_regex: re.Pattern) -> tuple[str, bool]:
    m = line_regex.search(s)
    if not m:
        return s, False
    line_start = m.start()
    brace = s.rfind("{", m.start(), m.end())
    if brace < 0:
        return s, False
    end = _nginx_brace_block_end(s, brace)
    if end < 0:
        return s, False
    return s[:line_start] + s[end:], True


def _nginx_strip_panel_locations(content: str, prefix: str) -> str:
    if not prefix:
        return content
    pat_eq = re.compile(rf"(?m)^[ \t]*location\s*=\s*{re.escape(prefix)}\s*\{{[ \t]*$")
    pat_sl = re.compile(rf"(?m)^[ \t]*location\s+{re.escape(prefix)}/\s*\{{[ \t]*$")
    s, ok1 = _nginx_remove_location_block(content, pat_eq)
    if not ok1:
        raise ValueError(f"В nginx не найдена строка location = {prefix} {{ … }}")
    s, ok2 = _nginx_remove_location_block(s, pat_sl)
    if not ok2:
        raise ValueError(f"В nginx не найдена строка location {prefix}/ {{ … }}")
    return s


def _nginx_panel_location_snippet(prefix: str, port: int) -> str:
    return (
        f"    location = {prefix} {{\n"
        f"        return 301 https://$host{prefix}/;\n"
        f"    }}\n\n"
        f"    location {prefix}/ {{\n"
        f'        proxy_set_header X-Hy2-Legacy-Basic "";\n'
        f"        proxy_pass http://127.0.0.1:{port};\n"
        f"        proxy_http_version 1.1;\n"
        f"        proxy_set_header Host $host;\n"
        f"        proxy_set_header X-Real-IP $remote_addr;\n"
        f"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        f"        proxy_set_header X-Forwarded-Proto $scheme;\n"
        f'        proxy_set_header Connection "";\n'
        f"        proxy_read_timeout 120s;\n"
        f"        proxy_buffering off;\n"
        f"    }}\n\n"
    )


def _nginx_inject_panel_locations(content: str, prefix: str, port: int) -> str:
    m = re.search(r"(?m)^[ \t]*location\s+/[ \t]*\{", content)
    if not m:
        raise ValueError("Не найден блок «location / {» (корень заглушки) — вставьте location панели вручную")
    if prefix in content:
        raise ValueError("Этот префикс уже встречается в конфиге nginx")
    return content[: m.start()] + _nginx_panel_location_snippet(prefix, port) + content[m.start() :]


def apply_panel_url_prefix_to_nginx_configs(
    paths: list[Path],
    *,
    old_prefix: str,
    new_prefix: str,
    upstream_port: int,
    removing: bool,
) -> None:
    """Пишет файлы nginx, nginx -t, reload. При ошибке откатывает содержимое файлов."""
    if not paths:
        return
    payloads: list[tuple[Path, str, str]] = []
    for p in paths:
        if not p.is_file():
            raise ValueError(f"Файл nginx не найден: {p}")
        raw = p.read_text(encoding="utf-8")
        if removing:
            if not old_prefix:
                continue
            new_text = _nginx_strip_panel_locations(raw, old_prefix)
        elif old_prefix and old_prefix in raw:
            new_text = raw.replace(old_prefix, new_prefix)
        elif not old_prefix and new_prefix:
            new_text = _nginx_inject_panel_locations(raw, new_prefix, upstream_port)
        else:
            raise ValueError(
                f"В {p} не найден текущий префикс {old_prefix!r}. "
                "Один раз добавьте блоки location вручную или очистите PANEL_NGINX_SITE_PATH в .env."
            )
        if new_text == raw:
            raise ValueError(f"Без изменений: {p}")
        payloads.append((p, raw, new_text))

    if not payloads:
        return

    backups: list[tuple[Path, Path, str]] = []
    try:
        for p, old_raw, new_text in payloads:
            bak = p.with_name(p.name + f".hy2bak.{int(time.time())}")
            shutil.copy2(p, bak)
            backups.append((p, bak, old_raw))
            p.write_text(new_text, encoding="utf-8")
        r = subprocess.run(["nginx", "-t"], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "").strip()
            raise RuntimeError(err or "nginx -t завершился с ошибкой")
        r2 = subprocess.run(
            ["systemctl", "reload", "nginx"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if r2.returncode != 0:
            err = (r2.stderr or r2.stdout or "").strip()
            raise RuntimeError(err or "systemctl reload nginx завершился с ошибкой")
    except Exception:
        for p, _bak, old_raw in backups:
            try:
                p.write_text(old_raw, encoding="utf-8")
            except OSError:
                pass
        raise


def format_whitelist_last_sync_display(iso_str: Optional[str], tz_name: str) -> str:
    if not iso_str or not str(iso_str).strip():
        return ""
    s = str(iso_str).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = ZoneInfo("Europe/Moscow")
        local = dt.astimezone(tz)
        return local.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return s[:19] if len(s) >= 19 else s


def update_env_keys(keys_out: dict[str, str]) -> None:
    path = ENV_PATH
    if not path.exists():
        raise RuntimeError(".env не найден")
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or "=" not in line:
            out.append(line)
            continue
        k = s.split("=", 1)[0].strip()
        if k in keys_out:
            out.append(f"{k}={keys_out[k]}")
            seen.add(k)
        else:
            out.append(line)
    for k, v in keys_out.items():
        if k not in seen:
            out.append(f"{k}={v}")
    path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


def update_panel_credentials_in_env(new_user: str, new_pass: str) -> None:
    update_env_keys({"PANEL_BASIC_USER": new_user, "PANEL_BASIC_PASS": new_pass})


def get_protected_users() -> set[str]:
    names = set()
    for item in PROTECTED_USERS_RAW.split(","):
        name = item.strip()
        if name:
            names.add(name)
    return names


def hy2_ui_hidden_usernames() -> set[str]:
    """Логины auth.userpass, которые не показываем в таблице «Пользователи» (служебные, hop и т.п.)."""
    return {x.strip().lower() for x in HY2_UI_HIDDEN_USERS_RAW.split(",") if x.strip()}


_login_fail_ts: dict[str, list[float]] = {}


def _client_ip() -> str:
    xff = (request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For") or "").strip()
    if xff and "," in xff:
        xff = xff.split(",")[0].strip()
    return xff or (request.remote_addr or "0.0.0.0")


def _login_rate_allow(ip: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    window = 900.0
    lst = _login_fail_ts.setdefault(ip, [])
    lst[:] = [t for t in lst if now - t < window]
    return len(lst) < 15


def _login_rate_record_fail(ip: str) -> None:
    now = datetime.now(timezone.utc).timestamp()
    _login_fail_ts.setdefault(ip, []).append(now)


def get_panel_totp_secret() -> str:
    s = (load_env(str(ENV_PATH)).get("PANEL_TOTP_SECRET") or "").strip().replace(" ", "")
    return s.upper().rstrip("=")


def panel_totp_required() -> bool:
    """2FA на странице входа только после явного включения (из панели задаётся PANEL_TOTP_LOGIN_ENABLED=1 + секрет)."""
    env = load_env(str(ENV_PATH))
    if (env.get("PANEL_TOTP_DISABLED") or "0").strip() == "1":
        return False
    if (env.get("PANEL_TOTP_LOGIN_ENABLED") or "0").strip() != "1":
        return False
    return bool(get_panel_totp_secret())


def verify_panel_totp(code: str) -> bool:
    secret = get_panel_totp_secret()
    if not secret or pyotp is None:
        return False
    digits = re.sub(r"\D", "", code or "")
    if len(digits) != 6:
        return False
    try:
        return bool(pyotp.TOTP(secret).verify(digits, valid_window=1))
    except Exception:
        return False


def panel_session_ok() -> bool:
    return bool(session.get("panel_auth"))


def _legacy_basic_proxy() -> bool:
    """Если nginx передаёт X-Hy2-Legacy-Basic: 1 — режим HTTP Basic (опционально, см. nginx-конфиг)."""
    return (request.headers.get("X-Hy2-Legacy-Basic") or "").strip() == "1"


def _parse_http_basic_credentials() -> tuple[str, str] | None:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth.lower().startswith("basic "):
        return None
    b64 = auth[6:].strip()
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64, validate=True).decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in raw:
        return None
    user, pw = raw.split(":", 1)
    return user, pw


def panel_basic_auth_ok() -> bool:
    pair = _parse_http_basic_credentials()
    if not pair:
        return False
    user_in, pass_in = pair
    u, pw = get_panel_credentials()
    if not pw:
        return False
    try:
        return secrets.compare_digest(user_in, u) and secrets.compare_digest(pass_in, pw)
    except TypeError:
        return False


def basic_auth_challenge_response() -> Response:
    return Response(
        "Unauthorized",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="HY2 Admin"'},
    )


def _legacy_basic_login_landing(target: str) -> Response:
    """После успешного Basic на /login: без 302 (Brave и др. часто не повторяют Authorization на редиректе)."""
    loc = target if (isinstance(target, str) and target.startswith("/") and ".." not in target) else url_for("hy2.index")
    ae = html.escape(loc, quote=True)
    js = json.dumps(loc, ensure_ascii=False)
    body = (
        "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\" />"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
        f"<meta http-equiv=\"refresh\" content=\"0;url={ae}\" />"
        "<title>HY2 Admin</title></head>"
        "<body style=\"margin:24px;font-family:system-ui;background:#0f1115;color:#e5e7eb;\">"
        "<p>Авторизация принята. Если панель не открылась, нажмите ссылку:</p>"
        f"<p><a href=\"{ae}\" style=\"color:#93c5fd;font-weight:600\">Открыть панель</a></p>"
        f"<script>location.replace({js});</script>"
        "</body></html>"
    )
    return Response(body, mimetype="text/html; charset=utf-8")


def _legacy_basic_logout_response() -> Response:
    """Basic без сессии: Clear-Site-Data (Chromium) + страница без авто-редиректа (иначе браузер снова шлёт Basic на /panel/)."""
    session.clear()
    loc = url_for("hy2.index")
    ae = html.escape(loc, quote=True)
    body = (
        "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\" />"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />"
        "<title>Выход — HY2 Admin</title></head>"
        "<body style=\"margin:24px;font-family:system-ui;background:#0f1115;color:#e5e7eb;\">"
        "<p><strong>Вы вышли.</strong> Автоматического перехода в панель нет — иначе браузер снова подставил бы пароль.</p>"
        "<p style=\"color:#9ca3af;font-size:0.9rem;\">Когда будете готовы войти снова, нажмите ссылку ниже. "
        "Если пароль не спрашивают, удалите сохранённые данные сайта или используйте инкогнито.</p>"
        f"<p><a href=\"{ae}\" style=\"color:#93c5fd;font-weight:600\">Войти снова</a></p>"
        "</body></html>"
    )
    r = Response(body, mimetype="text/html; charset=utf-8")
    r.headers["Clear-Site-Data"] = '"credentials"'
    return r


def safe_next_path(raw: Optional[str]) -> str:
    if not raw or not isinstance(raw, str):
        return ""
    s = raw.strip()
    if not s.startswith("/") or s.startswith("//"):
        return ""
    if "\n" in s or "\r" in s:
        return ""
    if PANEL_URL_PREFIX and not s.startswith(PANEL_URL_PREFIX):
        return ""
    return s


def _paths_equal_trailing_agnostic(a: str, b: str) -> bool:
    aa = (a or "").strip()
    bb = (b or "").strip()
    if not aa.startswith("/") or not bb.startswith("/"):
        return False
    return aa.rstrip("/") == bb.rstrip("/")


def api_json_unauthorized() -> Response:
    return Response(
        json.dumps({"error": "unauthorized"}, ensure_ascii=False),
        status=401,
        mimetype="application/json",
    )


def requires_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if _legacy_basic_proxy():
            if panel_basic_auth_ok():
                return func(*args, **kwargs)
            return basic_auth_challenge_response()
        if panel_session_ok():
            return func(*args, **kwargs)
        path = request.path or ""
        if path.endswith("/api/live") or path.rstrip("/").endswith("/api/live"):
            return api_json_unauthorized()
        if "/qr" in path:
            return Response("Unauthorized", status=401)
        nxt = safe_next_path(request.path)
        home = url_for("hy2.index")
        if nxt and not _paths_equal_trailing_agnostic(nxt, home):
            return redirect(url_for("hy2.login", next=nxt))
        return redirect(url_for("hy2.login"))
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


def load_sing_box_config_json() -> dict | None:
    p = Path(SING_BOX_CONFIG_PATH)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def sing_box_has_hysteria2_inbound() -> bool:
    """True, если sing-box принимает клиентов по Hysteria2 (типичный шлюз с in-hy2)."""
    cfg = load_sing_box_config_json()
    if not cfg:
        return False
    for ib in cfg.get("inbounds") or []:
        if isinstance(ib, dict) and str(ib.get("type", "")).strip().lower() == "hysteria2":
            return True
    return False


def summarize_sing_box_for_panel() -> dict:
    """Сводка для UI: теги inbounds, UUID (VLESS), имена HY2 без паролей."""
    out: dict = {
        "config_path": str(SING_BOX_CONFIG_PATH),
        "load_error": "",
        "inbounds": [],
        "route_rule_count": 0,
        "outbound_tags": [],
    }
    cfg = load_sing_box_config_json()
    if cfg is None:
        out["load_error"] = f"Файл не найден или невалидный JSON: {SING_BOX_CONFIG_PATH}"
        return out

    inbounds = cfg.get("inbounds")
    if isinstance(inbounds, list):
        for ib in inbounds:
            if not isinstance(ib, dict):
                continue
            tag = str(ib.get("tag") or "")
            ib_type = str(ib.get("type") or "")
            listen = ib.get("listen")
            listen_port = ib.get("listen_port")
            users_out: list[dict] = []
            users = ib.get("users")
            if isinstance(users, list):
                for u in users:
                    if not isinstance(u, dict):
                        continue
                    if u.get("uuid") is not None:
                        users_out.append(
                            {
                                "kind": "vless",
                                "id": str(u.get("uuid") or ""),
                                "name": str(u.get("name") or ""),
                            }
                        )
                    elif ib_type == "hysteria2" or "name" in u:
                        users_out.append(
                            {
                                "kind": "hysteria2",
                                "id": str(u.get("name") or ""),
                                "secret_masked": True,
                            }
                        )
            out["inbounds"].append(
                {
                    "tag": tag or "(без тега)",
                    "type": ib_type or "?",
                    "listen": listen,
                    "listen_port": listen_port,
                    "users": users_out,
                }
            )

    route = cfg.get("route")
    if isinstance(route, dict):
        rules = route.get("rules")
        if isinstance(rules, list):
            out["route_rule_count"] = len(rules)
    outbounds = cfg.get("outbounds")
    if isinstance(outbounds, list):
        for ob in outbounds:
            if isinstance(ob, dict) and ob.get("tag"):
                out["outbound_tags"].append(str(ob["tag"]))
    return out


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
    query_parts.append("alpn=h3")
    if INSECURE:
        query_parts.append("insecure=1")
    if isinstance(speed_up_mbps, (int, float)) and float(speed_up_mbps) > 0:
        query_parts.append(f"upmbps={float(speed_up_mbps):g}")
    if isinstance(speed_down_mbps, (int, float)) and float(speed_down_mbps) > 0:
        query_parts.append(f"downmbps={float(speed_down_mbps):g}")
    query = "&".join(query_parts)
    style = (ENV.get("HY2_URI_AUTH_STYLE") or "auto").strip().lower()
    if style == "auto":
        # sing-box hysteria2 inbound (и клиенты) ожидают URI «только пароль»; раньше это было
        # только при PANEL_BACKEND=sing-box, но на шлюзе часто hysteria+YAML для пользователей.
        style = (
            "password_only"
            if (is_sing_box_readonly_panel() or sing_box_has_hysteria2_inbound())
            else "userpass"
        )
    if style in {"password", "password_only", "passonly"}:
        return f"hysteria2://{pass_enc}@{host}:{port}/?{query}#{user_enc}"
    # Режим по умолчанию для нативного Hysteria userpass.
    return f"hysteria2://{user_enc}:{pass_enc}@{host}:{port}/?{query}#{user_enc}"


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


def get_singbox_recent_online_counts(window_seconds: int = SINGBOX_ONLINE_WINDOW_SECONDS) -> dict[str, int]:
    """Best-effort online users from recent sing-box logs.

    sing-box has no trafficStats API like hysteria, so when hysteria stats are
    unavailable we infer online users from recent authenticated in-hy2 entries.
    """
    since = f"{max(10, int(window_seconds))} seconds ago"
    cmd = [
        "journalctl",
        "-u",
        "sing-box",
        "--since",
        since,
        "--no-pager",
        "-o",
        "cat",
    ]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=3)
    except (subprocess.SubprocessError, OSError):
        return {}

    seen_users: set[str] = set()
    for line in out.splitlines():
        # Example: inbound/hysteria2[in-hy2]: [antyanmsa] inbound connection to ...
        m = re.search(r"inbound/hysteria2\[in-hy2\]:\s*\[([^\]]+)\]\s+inbound\s+(?:packet\s+)?connection", line)
        if not m:
            continue
        key = str(m.group(1)).strip().lower()
        if not key:
            continue
        seen_users.add(key)
    # In sing-box log fallback we only infer "online recently", not exact
    # concurrent stream count, so keep one active session marker per user.
    return {u: 1 for u in seen_users}


def get_singbox_recent_source_ip_user_map(window_seconds: int = SINGBOX_USER_MAP_WINDOW_SECONDS) -> dict[str, str]:
    """Best-effort map source IP -> username from recent sing-box in-hy2 auth logs."""
    since = f"{max(10, int(window_seconds))} seconds ago"
    cmd = [
        "journalctl",
        "-u",
        "sing-box",
        "--since",
        since,
        "--no-pager",
        "-o",
        "cat",
    ]
    try:
        out = subprocess.check_output(cmd, text=True, timeout=4)
    except (subprocess.SubprocessError, OSError):
        return {}

    ansi_re = re.compile(r"\x1b\[[0-9;]*m")
    rid_ip: dict[str, str] = {}
    rid_user: dict[str, str] = {}
    # Example:
    # [1820224369 0ms] inbound/hysteria2[in-hy2]: inbound connection from 77.220.143.56:48626
    # [1820224369 0ms] inbound/hysteria2[in-hy2]: [test123] inbound connection to ...
    re_from = re.compile(r"\[([0-9]+)\s+[0-9]+ms\].*inbound/hysteria2\[in-hy2\]:\s+inbound connection from ([^:\s]+):")
    re_user = re.compile(r"\[([0-9]+)\s+[0-9]+ms\].*inbound/hysteria2\[in-hy2\]:\s+\[([^\]]+)\]\s+inbound\s+(?:packet\s+)?connection")

    for raw in out.splitlines():
        line = ansi_re.sub("", raw)
        m1 = re_from.search(line)
        if m1:
            rid_ip[m1.group(1)] = str(m1.group(2)).strip()
        m2 = re_user.search(line)
        if m2:
            rid_user[m2.group(1)] = str(m2.group(2)).strip().lower()

    ip_users: dict[str, set[str]] = {}
    for rid, ip in rid_ip.items():
        user = rid_user.get(rid, "")
        if not ip or not user:
            continue
        ip_users.setdefault(ip, set()).add(user)

    out_map: dict[str, str] = {}
    for ip, users in ip_users.items():
        if len(users) == 1:
            out_map[ip] = next(iter(users))
    return out_map


def get_singbox_live_user_counters() -> tuple[dict[str, dict[str, int]], dict[str, int], str]:
    """Live per-user counters from sing-box Clash API /connections."""
    base = (SINGBOX_CLASH_API_URL or "").strip().rstrip("/")
    if not base:
        return {}, {}, "SINGBOX_CLASH_API_URL пуст"
    url = f"{base}/connections"
    req = Request(url)
    if SINGBOX_CLASH_API_SECRET:
        req.add_header("Authorization", f"Bearer {SINGBOX_CLASH_API_SECRET}")
    try:
        with urlopen(req, timeout=3) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
    except Exception as e:
        return {}, {}, str(e)
    if not isinstance(data, dict):
        return {}, {}, "некорректный ответ /connections"

    conns = data.get("connections")
    if not isinstance(conns, list):
        return {}, {}, "в /connections нет списка connections"

    ip_user_map = get_singbox_recent_source_ip_user_map()
    traffic: dict[str, dict[str, int]] = {}
    user_sessions: dict[str, set[str]] = {}
    for c in conns:
        if not isinstance(c, dict):
            continue
        md = c.get("metadata")
        if not isinstance(md, dict):
            md = {}
        user_raw = (
            md.get("user")
            or md.get("inbound_user")
            or md.get("inboundUser")
            or md.get("auth_user")
            or md.get("authUser")
            or ""
        )
        user = str(user_raw).strip().lower()
        if not user:
            src_ip = str(md.get("sourceIP") or md.get("source_ip") or "").strip()
            if src_ip:
                user = str(ip_user_map.get(src_ip) or "").strip().lower()
        if not user:
            continue

        # Clash API uses upload/download per connection.
        rx = int(c.get("download", 0) or c.get("downlink", 0) or 0)
        tx = int(c.get("upload", 0) or c.get("uplink", 0) or 0)
        if user not in traffic:
            traffic[user] = {"rx": 0, "tx": 0}
        traffic[user]["rx"] += max(0, rx)
        traffic[user]["tx"] += max(0, tx)
        src_ip = str(md.get("sourceIP") or md.get("source_ip") or "").strip()
        # Показываем число подключённых клиентов/устройств, а не число TCP/UDP потоков.
        # Поэтому считаем по уникальному source IP.
        session_key = src_ip or str(c.get("id") or "")
        if user not in user_sessions:
            user_sessions[user] = set()
        if session_key:
            user_sessions[user].add(session_key)

    online = {u: max(1, len(v)) for u, v in user_sessions.items()}
    return traffic, online, ""


def get_hy2_stats(cfg: dict) -> dict:
    stats_cfg = cfg.get("trafficStats")
    if not isinstance(stats_cfg, dict):
        return {
            "enabled": False,
            "error": "",
            "gateway_traffic_note": "",
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
        fallback_online = get_singbox_recent_online_counts()
        users = build_cumulative_stats({}, fallback_online) if fallback_online else {}
        online_connections = sum(v["online_count"] for v in users.values())
        online_users = sum(1 for v in users.values() if v["is_online"])
        return {
            "enabled": True,
            "error": f"Traffic API недоступен: {e}",
            "gateway_traffic_note": "",
            "online_users": online_users,
            "online_connections": online_connections,
            "sum_rx": 0,
            "sum_tx": 0,
            "sum_total": 0,
            "sum_rx_h": "0 B",
            "sum_tx_h": "0 B",
            "sum_total_h": "0 B",
            "users": users,
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

    # На шлюзе клиенты часто приходят в sing-box (in-hy2), а не напрямую в hysteria trafficStats.
    # В таком режиме /online от hysteria может быть пустым при реально активных сессиях.
    # Подмешиваем live counters sing-box (если Clash API включен на шлюзе).
    sb_traffic, sb_online, sb_err = get_singbox_live_user_counters()
    for user, rec in sb_traffic.items():
        key = str(user).strip().lower()
        if not key:
            continue
        cur = traffic.get(key) or {"rx": 0, "tx": 0}
        traffic[key] = {
            "rx": max(int(cur.get("rx", 0) or 0), int(rec.get("rx", 0) or 0)),
            "tx": max(int(cur.get("tx", 0) or 0), int(rec.get("tx", 0) or 0)),
        }
    for user, cnt in sb_online.items():
        key = str(user).strip().lower()
        if not key:
            continue
        online[key] = max(int(online.get(key, 0) or 0), int(cnt or 0))

    # Подмешиваем log-based fallback из sing-box и берём максимум.
    fallback_online = get_singbox_recent_online_counts()
    for user, cnt in fallback_online.items():
        key = str(user).strip().lower()
        if not key:
            continue
        online[key] = max(int(online.get(key, 0) or 0), int(cnt or 0))

    users = build_cumulative_stats(traffic, online)
    sum_rx = sum(v["rx"] for v in users.values())
    sum_tx = sum(v["tx"] for v in users.values())
    sum_total = sum_rx + sum_tx
    online_connections = sum(v["online_count"] for v in users.values())
    online_users = sum(1 for v in users.values() if v["is_online"])

    gateway_traffic_note = ""
    if (fallback_online or sb_online) and sum_total == 0:
        gateway_traffic_note = (
            "Шлюзовый режим: онлайн определяется по логам sing-box, "
            "но per-user трафик из Hysteria trafficStats сейчас пустой."
        )
        if sb_err:
            gateway_traffic_note += f" Clash API недоступен: {sb_err}."

    return {
        "enabled": True,
        "error": "",
        "gateway_traffic_note": gateway_traffic_note,
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


_hy2_agg_rate_prev: dict = {}


def format_speed_mbps_label(bytes_per_sec: float) -> str:
    if bytes_per_sec <= 0:
        return "0 Мбит/с"
    mbps = (bytes_per_sec * 8) / 1_000_000
    if mbps < 0.01:
        return "<0.01 Мбит/с"
    if mbps >= 1000:
        return f"{mbps / 1000:.2f} Гбит/с"
    return f"{mbps:.2f} Мбит/с"


def hy2_aggregate_throughput_labels(sum_rx: int, sum_tx: int) -> tuple[str, str]:
    """Скорость по дельте суммарного трафика Hysteria2: TX — к клиентам (скачивание), RX — от клиентов (отдача)."""
    global _hy2_agg_rate_prev
    now = time.monotonic()
    rx = max(0, int(sum_rx))
    tx = max(0, int(sum_tx))
    if not _hy2_agg_rate_prev:
        _hy2_agg_rate_prev = {"t": now, "rx": rx, "tx": tx, "rx_l": "—", "tx_l": "—"}
        return "—", "—"
    dt = now - _hy2_agg_rate_prev["t"]
    prev_rx = int(_hy2_agg_rate_prev.get("rx", 0))
    prev_tx = int(_hy2_agg_rate_prev.get("tx", 0))
    if rx < prev_rx or tx < prev_tx:
        _hy2_agg_rate_prev = {"t": now, "rx": rx, "tx": tx, "rx_l": "—", "tx_l": "—"}
        return "—", "—"
    if dt < 0.35:
        return str(_hy2_agg_rate_prev.get("rx_l", "—")), str(_hy2_agg_rate_prev.get("tx_l", "—"))
    rx_bps = (rx - prev_rx) / dt
    tx_bps = (tx - prev_tx) / dt
    rx_l = format_speed_mbps_label(rx_bps)
    tx_l = format_speed_mbps_label(tx_bps)
    _hy2_agg_rate_prev = {"t": now, "rx": rx, "tx": tx, "rx_l": rx_l, "tx_l": tx_l}
    return rx_l, tx_l


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


def _is_cascade_master_enabled() -> bool:
    raw = (ENV.get("CASCADE_MASTER_ENABLED") or "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _cascade_sync_timeout() -> int:
    raw = (ENV.get("CASCADE_SYNC_TIMEOUT_SEC") or "8").strip()
    try:
        val = int(raw)
    except ValueError:
        return 8
    return max(3, min(val, 30))


def _load_cascade_remote_servers() -> list[dict]:
    if not CASCADE_REMOTE_SERVERS_PATH.exists():
        return []
    try:
        data = json.loads(CASCADE_REMOTE_SERVERS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []
    servers = data.get("servers")
    if not isinstance(servers, list):
        return []
    out: list[dict] = []
    for item in servers:
        if not isinstance(item, dict):
            continue
        if not item.get("enabled", True):
            continue
        role_norm = str(item.get("role", "")).strip().lower() or "exit"
        if role_norm not in _cascade_exit_pool_roles_set():
            continue
        host = str(item.get("host", "")).strip()
        api_port = int(item.get("api_port", 0) or 0)
        secret = str(item.get("api_secret", "")).strip()
        if not host or api_port <= 0 or not secret:
            continue
        out.append(item)
    return out


def _build_cascade_users_snapshot() -> dict:
    cfg = load_hy2_config()
    return {
        "auth_userpass": dict(cfg.get("auth", {}).get("userpass", {})),
        "user_state": load_user_state(),
        "user_meta": load_user_meta(),
        "user_notes": load_user_notes(),
        "user_ip_state": load_user_ip_state(),
    }


def _send_cascade_payload(remote: dict, payload: dict) -> tuple[bool, str]:
    secret = str(remote.get("api_secret", "")).strip()
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    url = f"http://{remote['host']}:{int(remote['api_port'])}/sync/full-users"
    req = Request(
        url=url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Cascade-Signature": signature,
            "X-Cascade-Node": str(remote.get("node_id", "")),
        },
    )
    try:
        with urlopen(req, timeout=_cascade_sync_timeout()) as resp:
            code = int(getattr(resp, "status", 200))
            if 200 <= code < 300:
                return True, f"ok:{code}"
            return False, f"http:{code}"
    except URLError as e:
        return False, f"urlerror:{e}"
    except Exception as e:
        return False, f"error:{e}"


def _cascade_remote_is_hybrid(remote: dict) -> bool:
    raw = remote.get("hybrid")
    if raw is True or raw == 1:
        return True
    if isinstance(raw, str) and raw.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    return str(remote.get("sync_mode", "")).strip().lower() == "hybrid"


def cascade_sync_users_best_effort(reason: str) -> None:
    if not _is_cascade_master_enabled():
        return
    remotes = _load_cascade_remote_servers()
    if not remotes:
        return
    snapshot = _build_cascade_users_snapshot()
    base_payload = {
        "source": "gateway",
        "reason": reason,
        "ts": int(time.time()),
        "snapshot": snapshot,
    }
    status_rows: list[dict] = []
    for remote in remotes:
        payload = dict(base_payload)
        if _cascade_remote_is_hybrid(remote):
            payload["hybrid"] = True
            payload["sync_mode"] = "hybrid"
        ok, msg = _send_cascade_payload(remote, payload)
        status_rows.append(
            {
                "node_id": remote.get("node_id", ""),
                "name": remote.get("name", ""),
                "host": remote.get("host", ""),
                "ok": ok,
                "result": msg,
                "at": datetime.now(timezone.utc).isoformat(),
            }
        )
    try:
        p = Path("/opt/hy2-admin/data/cascade/last_sync_status.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"reason": reason, "rows": status_rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def _b64url_decode(raw: str) -> bytes:
    s = (raw or "").strip()
    if not s:
        return b""
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _load_cascade_db() -> dict:
    if not CASCADE_REMOTE_SERVERS_PATH.exists():
        return {"servers": []}
    try:
        data = json.loads(CASCADE_REMOTE_SERVERS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"servers": []}
    servers = data.get("servers")
    if not isinstance(servers, list):
        data["servers"] = []
    return data


def _save_cascade_db(data: dict) -> None:
    CASCADE_REMOTE_SERVERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    CASCADE_REMOTE_SERVERS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_cascade_registration_token(raw: str) -> dict:
    payload = json.loads(_b64url_decode(raw).decode("utf-8"))
    required = ("node_id", "name", "host", "api_port", "api_secret", "fingerprint", "issued_at", "role")
    missing = [k for k in required if k not in payload]
    if missing:
        raise ValueError(f"Токен неполный: отсутствуют {', '.join(missing)}")
    return payload


def _cascade_exit_selector_tag() -> str:
    t = (ENV.get("CASCADE_EXIT_SELECTOR_TAG") or "cascade-exit-auto").strip()
    return t or "cascade-exit-auto"


def _cascade_exit_pool_roles_set() -> set[str]:
    """Роли узлов каскада, которые участвуют в пуле exit (кнопка «все в пул» и отбор для sing-box)."""
    raw = (ENV.get("CASCADE_EXIT_POOL_ROLES") or "exit").strip()
    if not raw:
        return {"exit"}
    roles = {p.strip().lower() for p in raw.replace(";", ",").split(",") if p.strip()}
    return roles or {"exit"}


def _cascade_hy2_outbound_tag(node_id: str) -> str:
    nid = re.sub(r"[^a-zA-Z0-9]", "", str(node_id or ""))[:16].lower()
    if not nid:
        nid = "node"
    return f"cascade-hy2-{nid}"


def _cascade_last_sync_map() -> dict[str, bool]:
    out: dict[str, bool] = {}
    for p in (
        Path("/opt/hy2-admin/data/cascade/master_sync_state.json"),
        Path("/opt/hy2-admin/data/cascade/last_sync_status.json"),
    ):
        if not p.exists():
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        rows = d.get("rows")
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            node_id = str(row.get("node_id", ""))
            if not node_id:
                continue
            out[node_id] = bool(row.get("ok", False))
    return out


def _get_singbox_lb_mode_from_db(db: dict) -> str:
    m = str(db.get("singbox_lb_mode") or "urltest").strip().lower()
    if m in ("single", "singleurl", "single_url", "one", "first"):
        return "single"
    # legacy: round_robin / rr / … больше не поддерживаются → urltest
    return "urltest"


def _get_cascade_hy2_host(item: dict) -> str:
    return str(item.get("hy2_server") or item.get("host") or "").strip()


def _cascade_exit_candidates_for_singbox(
    db: dict, *, require_last_sync_ok: bool
) -> list[dict]:
    allowed: list[dict] = []
    sync_ok = _cascade_last_sync_map() if require_last_sync_ok else {}
    for item in db.get("servers") or []:
        if not isinstance(item, dict):
            continue
        if not item.get("enabled", True):
            continue
        role_norm = str(item.get("role", "")).strip().lower() or "exit"
        if role_norm not in _cascade_exit_pool_roles_set():
            continue
        if not item.get("cascade_exit", False):
            continue
        pwd = str(item.get("hop_password") or "").strip()
        host = _get_cascade_hy2_host(item)
        if not pwd or not host:
            continue
        nid = str(item.get("node_id", ""))
        if require_last_sync_ok and nid in sync_ok and not sync_ok.get(nid, False):
            continue
        allowed.append(item)
    return allowed


def _sort_candidates_for_single_exit(items: list[dict]) -> list[dict]:
    """Порядок для режима single: сначала узлы с последним успешным sync, затем по hy2 host."""
    if len(items) <= 1:
        return items
    sync = _cascade_last_sync_map()

    def tier(node_id: str) -> int:
        st = sync.get(node_id)
        if st is True:
            return 0
        if st is False:
            return 2
        return 1

    idxs = sorted(
        range(len(items)),
        key=lambda i: (
            tier(str(items[i].get("node_id", ""))),
            str(items[i].get("hy2_server") or items[i].get("host") or "").lower(),
            i,
        ),
    )
    return [items[j] for j in idxs]


def _build_one_cascade_hysteria2_outbound(item: dict, *, tag: str | None = None) -> dict:
    tag = (tag or "").strip() or _cascade_hy2_outbound_tag(item.get("node_id", ""))
    host = _get_cascade_hy2_host(item)
    try:
        port = int(item.get("hy2_port", 443) or 443)
    except (TypeError, ValueError):
        port = 443
    sni = str(item.get("hy2_sni") or "").strip()
    if not sni:
        try:
            ipaddress.ip_address(host)
            sni = ""
        except ValueError:
            sni = host
    usr = str(item.get("hop_username") or "").strip()
    pwd = str(item.get("hop_password") or "").strip()
    insecure = bool(item.get("hy2_insecure", False))

    tls_obj: dict = {"enabled": True, "insecure": insecure}
    if sni:
        tls_obj["server_name"] = sni

    # sing-box hysteria2 outbound: для auth userpass задаётся одна строка "user:pass" в password
    auth_secret = f"{usr}:{pwd}" if usr else pwd
    return {
        "type": "hysteria2",
        "tag": tag,
        "server": host,
        "server_port": port,
        "password": auth_secret,
        "tls": tls_obj,
    }


def _strip_managed_cascade_outbounds(cfg: dict, selector_tag: str) -> None:
    obs = cfg.get("outbounds")
    if not isinstance(obs, list):
        cfg["outbounds"] = []
        return
    kept: list = []
    for ob in obs:
        if not isinstance(ob, dict):
            kept.append(ob)
            continue
        t = str(ob.get("tag", "")).strip()
        if t == selector_tag or t.startswith("cascade-hy2-"):
            continue
        kept.append(ob)
    cfg["outbounds"] = kept


def _restart_sing_box_best_effort() -> tuple[bool, str]:
    return _schedule_sing_box_restart()


def apply_cascade_singbox_outbounds(*, lb_mode: str | None = None) -> str:
    """Записывает в sing-box hysteria2 per-node + групповой outbound (single | urltest).
    Возвращает текстовое сообщение для UI."""
    selector_tag = _cascade_exit_selector_tag()
    db = _load_cascade_db()
    mode = str(lb_mode or _get_singbox_lb_mode_from_db(db)).strip().lower()
    if mode in ("single", "singleurl", "single_url", "one", "first"):
        mode = "single"
    else:
        mode = "urltest"

    require_sync = (ENV.get("CASCADE_URLTEST_REQUIRE_SYNC_OK") or "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    candidates = _cascade_exit_candidates_for_singbox(db, require_last_sync_ok=require_sync)

    p = Path(SING_BOX_CONFIG_PATH)
    if not p.exists():
        raise ValueError(f"Файл sing-box не найден: {SING_BOX_CONFIG_PATH}")
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"Ошибка чтения sing-box JSON: {e}") from e
    if not isinstance(cfg, dict):
        raise ValueError("sing-box: корень JSON должен быть объектом")

    _strip_managed_cascade_outbounds(cfg, selector_tag)
    obs = cfg.setdefault("outbounds", [])
    if not isinstance(obs, list):
        cfg["outbounds"] = []
        obs = cfg["outbounds"]

    if not candidates:
        p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        ok, st = _schedule_sing_box_restart()
        extra = _sing_box_restart_phrase(ok, st, inline=True)
        return (
            "Каскадные outbounds удалены из sing-box (нет узлов с заполненным HY2 hop-паролем и адресом)."
            + extra
        )

    if mode == "single":
        candidates_single = _sort_candidates_for_single_exit(candidates)
        first = candidates_single[0]
        ob = _build_one_cascade_hysteria2_outbound(first, tag=selector_tag)
        obs.append(ob)
        p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        ok, st = _schedule_sing_box_restart()
        tail = _sing_box_restart_phrase(ok, st)
        return (
            f"Каскад: один exit → outbound «{selector_tag}» (режим single, первый доступный узел в списке).{tail}"
        )

    tags: list[str] = []
    seen: set[str] = set()
    for item in _sort_candidates_for_single_exit(candidates):
        ob = _build_one_cascade_hysteria2_outbound(item)
        t = str(ob.get("tag", "")).strip()
        if not t or t in seen:
            continue
        seen.add(t)
        tags.append(t)
        obs.append(ob)

    if not tags:
        p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return "Не удалось сформировать теги outbounds."

    probe_url = (ENV.get("CASCADE_URLTEST_PROBE_URL") or "https://www.gstatic.com/generate_204").strip()
    interval = (ENV.get("CASCADE_URLTEST_INTERVAL") or "3m").strip() or "3m"
    tol_raw = (ENV.get("CASCADE_URLTEST_TOLERANCE") or "50").strip()
    try:
        tolerance = int(tol_raw)
    except ValueError:
        tolerance = 50

    composite = {
        "type": "urltest",
        "tag": selector_tag,
        "outbounds": tags,
        "url": probe_url,
        "interval": interval,
        "tolerance": tolerance,
        "interrupt_exist_connections": False,
    }
    obs.append(composite)

    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ok, st = _schedule_sing_box_restart()
    mode_human = "urltest (мин. задержка к пробе)"
    tail = _sing_box_restart_phrase(ok, st)
    return (
        f"Каскад: записано {len(tags)} HY2 outbounds + группа «{selector_tag}» ({mode_human}).{tail}"
    )


def read_cascade_ui_state() -> dict:
    db = _load_cascade_db()
    servers_raw = db.get("servers") or []
    servers: list[dict] = []
    for item in servers_raw:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role", "")).strip().lower() or "exit"
        hy2_port_raw = item.get("hy2_port", 443)
        try:
            hy2_port = int(hy2_port_raw)
        except (TypeError, ValueError):
            hy2_port = 443
        hop_pwd = str(item.get("hop_password") or "").strip()
        servers.append(
            {
                "node_id": str(item.get("node_id", "")),
                "name": str(item.get("name", "")),
                "host": str(item.get("host", "")),
                "api_port": int(item.get("api_port", 0) or 0),
                "enabled": bool(item.get("enabled", True)),
                "role": role,
                "cascade_exit": bool(item.get("cascade_exit", False)),
                "fingerprint": str(item.get("fingerprint", "")),
                "issued_at": str(item.get("issued_at", "")),
                "hy2_server": _get_cascade_hy2_host(item),
                "hy2_port": hy2_port,
                "hy2_sni": str(item.get("hy2_sni") or "").strip(),
                "hop_username": str(item.get("hop_username") or "").strip(),
                "hop_password_set": bool(hop_pwd),
                "hy2_insecure": bool(item.get("hy2_insecure", False)),
            }
        )

    status_rows_map: dict[str, dict] = {}
    for p in (
        Path("/opt/hy2-admin/data/cascade/master_sync_state.json"),
        Path("/opt/hy2-admin/data/cascade/last_sync_status.json"),
    ):
        if not p.exists():
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        rows = d.get("rows")
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            node_id = str(row.get("node_id", ""))
            if not node_id:
                continue
            status_rows_map[node_id] = {
                "ok": bool(row.get("ok", False)),
                "result": str(row.get("result", "")),
                "at": str(row.get("at", "")),
            }

    for s in servers:
        st = status_rows_map.get(s["node_id"], {})
        s["last_sync_ok"] = bool(st.get("ok", False))
        s["last_sync_result"] = str(st.get("result", "нет данных"))
        s["last_sync_at"] = str(st.get("at", ""))
        s["last_sync_at_local"] = (
            format_whitelist_last_sync_display(s["last_sync_at"], get_panel_timezone()) if s["last_sync_at"] else ""
        )

    pool_roles = _cascade_exit_pool_roles_set()
    exit_enabled = [
        s for s in servers if s["enabled"] and s["role"] in pool_roles and s["cascade_exit"]
    ]
    return {
        "master_enabled": _is_cascade_master_enabled(),
        "servers": sorted(servers, key=lambda x: (x["name"] or x["host"] or x["node_id"]).lower()),
        "servers_count": len(servers),
        "exit_enabled_count": len(exit_enabled),
        "cascade_exit_pool_roles": sorted(pool_roles),
        "singbox_lb_mode": _get_singbox_lb_mode_from_db(db),
        "exit_selector_tag": _cascade_exit_selector_tag(),
    }


def _attach_whitelist_summary(out: dict) -> dict:
    wl = load_direct_whitelist_store()
    out["whitelist_synced"] = bool(wl.get("synced_at"))
    out["whitelist_domains_count"] = len(wl.get("domains") or [])
    out["whitelist_ip_count"] = len(_whitelist_merged_ip_cidrs(wl))
    out["whitelist_auto_sync_enabled"] = bool(wl.get("auto_sync_enabled"))
    out["whitelist_synced_at"] = str(wl.get("synced_at") or "")
    out["whitelist_last_sync_at"] = str(wl.get("last_sync_at") or "")
    out["whitelist_sync_status"] = str(wl.get("sync_status") or "idle")
    out["whitelist_sync_error"] = str(wl.get("sync_error") or "")
    out["whitelist_source_url"] = str(wl.get("source_url") or GITHUB_WHITELIST_RAW_URL)
    return out


def read_direct_routing_state() -> dict:
    p = Path(SING_BOX_CONFIG_PATH)
    out = {
        "config_path": str(p),
        "load_error": "",
        "has_default_outbound": False,
        "has_geoip_ru_direct": False,
        "has_ru_suffix_direct": False,
        "direct_rule_count": 0,
        "default_rule_count": 0,
        "default_outbound_tag": "",
        "outbound_tags": [],
        "explicit_hosts_text": "",
        "ru_suffixes_text": ".ru\n.xn--p1ai\n.su",
        "enable_geoip_ru": False,
        "enable_default_outbound": False,
        "explicit_domains_list": [],
        "explicit_domains_detail": [],
        "whitelist_synced": False,
        "whitelist_domains_count": 0,
        "whitelist_ip_count": 0,
        "whitelist_auto_sync_enabled": False,
        "whitelist_synced_at": "",
        "whitelist_last_sync_at": "",
        "whitelist_sync_status": "idle",
        "whitelist_sync_error": "",
        "whitelist_source_url": GITHUB_WHITELIST_RAW_URL,
    }
    if not p.exists():
        out["load_error"] = "Файл конфигурации sing-box не найден"
        return _attach_whitelist_summary(out)
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        out["load_error"] = f"Ошибка чтения sing-box: {e}"
        return _attach_whitelist_summary(out)

    outbounds = cfg.get("outbounds") if isinstance(cfg, dict) else None
    if isinstance(outbounds, list):
        for ob in outbounds:
            if not isinstance(ob, dict):
                continue
            tag = str(ob.get("tag", "")).strip()
            if tag and tag not in out["outbound_tags"]:
                out["outbound_tags"].append(tag)

    route = cfg.get("route") if isinstance(cfg, dict) else None
    rules = route.get("rules") if isinstance(route, dict) else []
    if not isinstance(rules, list):
        rules = []
    ru_suffixes = {".ru", ".xn--p1ai", ".su"}

    for r in rules:
        if not isinstance(r, dict):
            continue
        outbound = str(r.get("outbound", "")).strip()
        if outbound == "direct":
            out["direct_rule_count"] += 1
            rs = r.get("rule_set")
            if isinstance(rs, list) and GEOIP_RU_RULE_SET_TAG in rs:
                out["has_geoip_ru_direct"] = True
            ds = r.get("domain_suffix")
            if isinstance(ds, list):
                if ru_suffixes.issubset({str(x).strip() for x in ds}):
                    out["has_ru_suffix_direct"] = True
        elif outbound and outbound != "direct":
            out["default_rule_count"] += 1
            if len(r.keys()) == 1:
                out["has_default_outbound"] = True
                if not out["default_outbound_tag"]:
                    out["default_outbound_tag"] = outbound
    out["explicit_hosts_text"] = ""
    out["ru_suffixes_text"] = ".ru\n.xn--p1ai\n.su"
    out["enable_geoip_ru"] = out["has_geoip_ru_direct"]
    out["enable_default_outbound"] = out["has_default_outbound"]
    if not out["default_outbound_tag"] and out["outbound_tags"]:
        preferred = [t for t in out["outbound_tags"] if t not in {"direct", "block", "dns-out"}]
        out["default_outbound_tag"] = preferred[0] if preferred else out["outbound_tags"][0]
    for r in rules:
        if not isinstance(r, dict):
            continue
        if str(r.get("outbound", "")).strip() != "direct":
            continue
        dom = r.get("domain")
        if isinstance(dom, list) and dom:
            out["explicit_hosts_text"] = "\n".join(str(x).strip() for x in dom if str(x).strip())
        ds = r.get("domain_suffix")
        if isinstance(ds, list) and ds:
            out["ru_suffixes_text"] = "\n".join(str(x).strip() for x in ds if str(x).strip())
    store = load_direct_explicit_store()
    doms = list(store["domains"])
    if not doms and out.get("explicit_hosts_text"):
        doms = _split_tokens(out["explicit_hosts_text"].replace("\n", ","))
    lr_map: dict[str, list[str]] = {}
    raw_lr = store.get("last_resolved")
    if isinstance(raw_lr, dict):
        for k, v in raw_lr.items():
            kk = str(k).strip().lower().rstrip(".")
            if isinstance(v, list):
                lr_map[kk] = [str(x) for x in v]
            else:
                lr_map[kk] = []
    errs = store.get("resolve_errors") if isinstance(store.get("resolve_errors"), dict) else {}
    out["explicit_domains_list"] = doms
    out["explicit_domains_detail"] = [
        {
            "domain": d,
            "cidrs": lr_map.get(d, []),
            "error": str(errs.get(d) or errs.get(d.rstrip(".")) or ""),
        }
        for d in doms
    ]
    return _attach_whitelist_summary(out)


def normalize_direct_state_for_template(ds: dict) -> dict:
    """Гарантирует все ключи, которые читает index.html (старые сборки без них давали 500 на tojson/for)."""
    defaults: dict = {
        "config_path": str(Path(SING_BOX_CONFIG_PATH)),
        "load_error": "",
        "has_default_outbound": False,
        "has_geoip_ru_direct": False,
        "has_ru_suffix_direct": False,
        "direct_rule_count": 0,
        "default_rule_count": 0,
        "default_outbound_tag": "",
        "outbound_tags": [],
        "explicit_hosts_text": "",
        "ru_suffixes_text": ".ru\n.xn--p1ai\n.su",
        "enable_geoip_ru": False,
        "enable_default_outbound": False,
        "explicit_domains_list": [],
        "explicit_domains_detail": [],
        "whitelist_synced": False,
        "whitelist_domains_count": 0,
        "whitelist_ip_count": 0,
        "whitelist_auto_sync_enabled": False,
        "whitelist_synced_at": "",
        "whitelist_last_sync_at": "",
        "whitelist_sync_status": "idle",
        "whitelist_sync_error": "",
        "whitelist_source_url": GITHUB_WHITELIST_RAW_URL,
    }
    if not isinstance(ds, dict):
        return defaults
    merged = {**defaults, **ds}
    for key in ("outbound_tags", "explicit_domains_list", "explicit_domains_detail"):
        if not isinstance(merged.get(key), list):
            merged[key] = []
    return merged


def _known_direct_suffixes() -> set[str]:
    return {str(x.get("suffix", "")).strip() for x in DIRECT_DOMAIN_SUFFIX_OPTIONS if str(x.get("suffix", "")).strip()}


def _direct_ru_suffixes_from_form() -> list[str]:
    known = _known_direct_suffixes()
    picked = request.form.getlist("direct_ru_suffixes")
    out: list[str] = []
    seen: set[str] = set()
    for raw in picked:
        s = str(raw).strip()
        if not s.startswith("."):
            continue
        if s not in known:
            raise ValueError(f"Недопустимый суффикс: {s}")
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def direct_suffix_groups_for_template(selected_raw: str = "") -> list[dict]:
    selected = set(_split_tokens(str(selected_raw or "").replace("\n", " ")))
    if not selected:
        selected = set(DIRECT_DOMAIN_SUFFIX_DEFAULT)
    groups: list[dict] = []
    for grp in DIRECT_DOMAIN_SUFFIX_GROUPS:
        iso = str(grp.get("flag_iso", "")).strip().lower() or "un"
        items_out: list[dict] = []
        for item in grp.get("suffixes") or []:
            if not isinstance(item, dict):
                continue
            suf = str(item.get("suffix", "")).strip()
            if not suf:
                continue
            label = str(item.get("label", suf))
            hint = str(item.get("hint") or "").strip()
            title = str(grp.get("country", ""))
            if hint:
                title = f"{title} ({hint})"
            if label != suf:
                title = f"{title} · {suf}"
            items_out.append(
                {
                    "label": label,
                    "suffix": suf,
                    "title": title,
                    "flag_svg": FLAG_SVG_24x16.get(iso, FLAG_SVG_24x16.get("ru", "")),
                    "checked": suf in selected,
                }
            )
        if not items_out:
            continue
        groups.append(
            {
                "flag_iso": iso,
                "country": str(grp.get("country", "")),
                "flag_svg": FLAG_SVG_24x16.get(iso, FLAG_SVG_24x16.get("ru", "")),
                "suffixes": items_out,
            }
        )
    return groups


def _split_tokens(raw: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[\s,;]+", str(raw or "").strip()):
        v = part.strip()
        if not v:
            continue
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def load_direct_explicit_store() -> dict:
    if not DIRECT_EXPLICIT_STORE_PATH.exists():
        return {"domains": [], "last_resolved": {}, "resolve_errors": {}}
    try:
        data = json.loads(DIRECT_EXPLICIT_STORE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"domains": [], "last_resolved": {}, "resolve_errors": {}}
    if not isinstance(data, dict):
        return {"domains": [], "last_resolved": {}, "resolve_errors": {}}
    doms = data.get("domains")
    if not isinstance(doms, list):
        doms = []
    lr = data.get("last_resolved")
    if not isinstance(lr, dict):
        lr = {}
    er = data.get("resolve_errors")
    if not isinstance(er, dict):
        er = {}
    cleaned: list[str] = []
    seen: set[str] = set()
    for x in doms:
        d = str(x).strip().lower().rstrip(".")
        if d and d not in seen:
            seen.add(d)
            cleaned.append(d)
    return {"domains": cleaned, "last_resolved": {str(k): v for k, v in lr.items()}, "resolve_errors": {str(k): str(v) for k, v in er.items()}}


def save_direct_explicit_store(
    *,
    domains: list[str],
    last_resolved: dict[str, list[str]],
    resolve_errors: dict[str, str],
) -> None:
    DIRECT_EXPLICIT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "domains": domains,
        "last_resolved": last_resolved,
        "resolve_errors": resolve_errors,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    DIRECT_EXPLICIT_STORE_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def load_direct_whitelist_store() -> dict:
    empty = {
        "domains": [],
        "last_resolved": {},
        "resolve_errors": {},
        "source_url": GITHUB_WHITELIST_RAW_URL,
        "synced_at": "",
        "last_sync_at": "",
        "auto_sync_enabled": False,
        "sync_status": "idle",
        "sync_started_at": "",
        "sync_error": "",
    }
    if not DIRECT_WHITELIST_STORE_PATH.exists():
        return empty
    try:
        data = json.loads(DIRECT_WHITELIST_STORE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return empty
    if not isinstance(data, dict):
        return empty
    doms = data.get("domains")
    if not isinstance(doms, list):
        doms = []
    lr = data.get("last_resolved")
    if not isinstance(lr, dict):
        lr = {}
    er = data.get("resolve_errors")
    if not isinstance(er, dict):
        er = {}
    cleaned: list[str] = []
    seen: set[str] = set()
    for x in doms:
        d = str(x).strip().lower().rstrip(".")
        if d and d not in seen:
            seen.add(d)
            cleaned.append(d)
    out = {**empty, **data}
    out["domains"] = cleaned
    out["last_resolved"] = {str(k): v for k, v in lr.items()}
    out["resolve_errors"] = {str(k): str(v) for k, v in er.items()}
    out["source_url"] = str(out.get("source_url") or GITHUB_WHITELIST_RAW_URL)
    out["synced_at"] = str(out.get("synced_at") or "")
    out["last_sync_at"] = str(out.get("last_sync_at") or "")
    out["auto_sync_enabled"] = bool(out.get("auto_sync_enabled"))
    out["sync_status"] = str(out.get("sync_status") or "idle")
    out["sync_started_at"] = str(out.get("sync_started_at") or "")
    out["sync_error"] = str(out.get("sync_error") or "")
    return out


def save_direct_whitelist_store(data: dict) -> None:
    DIRECT_WHITELIST_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "domains": list(data.get("domains") or []),
        "last_resolved": data.get("last_resolved") if isinstance(data.get("last_resolved"), dict) else {},
        "resolve_errors": data.get("resolve_errors") if isinstance(data.get("resolve_errors"), dict) else {},
        "source_url": str(data.get("source_url") or GITHUB_WHITELIST_RAW_URL),
        "synced_at": str(data.get("synced_at") or ""),
        "last_sync_at": str(data.get("last_sync_at") or ""),
        "auto_sync_enabled": bool(data.get("auto_sync_enabled")),
        "sync_status": str(data.get("sync_status") or "idle"),
        "sync_started_at": str(data.get("sync_started_at") or ""),
        "sync_error": str(data.get("sync_error") or ""),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    DIRECT_WHITELIST_STORE_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _whitelist_merged_ip_cidrs(store: dict) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    lr = store.get("last_resolved")
    if not isinstance(lr, dict):
        return merged
    for v in lr.values():
        if not isinstance(v, list):
            continue
        for c in v:
            cs = str(c).strip()
            if cs and cs not in seen:
                seen.add(cs)
                merged.append(cs)
    return merged


def _whitelist_domains_detail(store: dict) -> list[dict]:
    doms = store.get("domains") if isinstance(store.get("domains"), list) else []
    lr = store.get("last_resolved") if isinstance(store.get("last_resolved"), dict) else {}
    errs = store.get("resolve_errors") if isinstance(store.get("resolve_errors"), dict) else {}
    out: list[dict] = []
    for d in doms:
        dd = str(d).strip().lower().rstrip(".")
        if not dd:
            continue
        cidrs_raw = lr.get(dd) or lr.get(d) or []
        cidrs = [str(x) for x in cidrs_raw] if isinstance(cidrs_raw, list) else []
        out.append(
            {
                "domain": dd,
                "cidrs": cidrs,
                "error": str(errs.get(dd) or errs.get(d) or ""),
            }
        )
    return out


def fetch_github_whitelist_domains() -> list[str]:
    req = Request(
        GITHUB_WHITELIST_RAW_URL,
        headers={"User-Agent": "hy2-admin-panel/whitelist-sync"},
    )
    try:
        with urlopen(req, timeout=90) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except URLError as e:
        raise ValueError(f"Не удалось загрузить whitelist с GitHub: {e}") from e
    domains: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        d = raw.lower().rstrip(".")
        if not d or not _valid_direct_explicit_hostname(d):
            continue
        if d not in seen:
            seen.add(d)
            domains.append(d)
    if not domains:
        raise ValueError("Файл whitelist пуст или не содержит доменов")
    return domains


def resolve_domains_to_ip_cidrs_bulk(domains: list[str]) -> tuple[dict[str, list[str]], dict[str, str], list[str]]:
    last_resolved: dict[str, list[str]] = {}
    resolve_errors: dict[str, str] = {}
    merged_cidrs: list[str] = []
    seen_c: set[str] = set()
    if not domains:
        return last_resolved, resolve_errors, merged_cidrs

    def _one(domain: str) -> tuple[str, list[str], str]:
        cidrs, err = resolve_domain_to_ip_cidrs(domain)
        return domain, cidrs, err

    workers = min(WHITELIST_DNS_WORKERS, max(1, len(domains)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one, d) for d in domains]
        for fut in as_completed(futures):
            d, cidrs, err = fut.result()
            last_resolved[d] = cidrs
            if err:
                resolve_errors[d] = err
            for c in cidrs:
                if c not in seen_c:
                    seen_c.add(c)
                    merged_cidrs.append(c)
    return last_resolved, resolve_errors, merged_cidrs


def _read_direct_routing_singbox_settings() -> dict:
    """Текущие суффиксы / geoip / default outbound из sing-box (без списков доменов)."""
    out = {
        "ru_suffixes": [".ru", ".xn--p1ai", ".su"],
        "enable_geoip_ru": False,
        "enable_default_outbound": False,
        "default_outbound_tag": "",
    }
    p = Path(SING_BOX_CONFIG_PATH)
    if not p.exists():
        return out
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    route = cfg.get("route") if isinstance(cfg, dict) else None
    rules = route.get("rules") if isinstance(route, dict) else []
    if not isinstance(rules, list):
        return out
    for r in rules:
        if not isinstance(r, dict):
            continue
        outbound = str(r.get("outbound", "")).strip()
        if outbound == "direct":
            rs = r.get("rule_set")
            if isinstance(rs, list) and GEOIP_RU_RULE_SET_TAG in rs:
                out["enable_geoip_ru"] = True
            ds = r.get("domain_suffix")
            if isinstance(ds, list) and ds:
                out["ru_suffixes"] = [str(x).strip() for x in ds if str(x).strip()]
        elif outbound and outbound != "direct" and len(r.keys()) == 1:
            out["enable_default_outbound"] = True
            if not out["default_outbound_tag"]:
                out["default_outbound_tag"] = outbound
    return out


def apply_direct_routing_from_stores(
    *,
    explicit_hosts: list[str] | None = None,
    explicit_ip_cidrs: list[str] | None = None,
) -> None:
    explicit_store = load_direct_explicit_store()
    whitelist_store = load_direct_whitelist_store()
    hosts = explicit_hosts if explicit_hosts is not None else list(explicit_store["domains"])
    if explicit_ip_cidrs is not None:
        custom_cidrs = explicit_ip_cidrs
    else:
        custom_cidrs = []
        seen_c: set[str] = set()
        lr = explicit_store.get("last_resolved")
        if isinstance(lr, dict):
            for v in lr.values():
                if not isinstance(v, list):
                    continue
                for c in v:
                    cs = str(c).strip()
                    if cs and cs not in seen_c:
                        seen_c.add(cs)
                        custom_cidrs.append(cs)
    flags = _read_direct_routing_singbox_settings()
    apply_direct_routing_rules(
        explicit_hosts=hosts,
        explicit_ip_cidrs=custom_cidrs,
        whitelist_hosts=list(whitelist_store["domains"]),
        whitelist_ip_cidrs=_whitelist_merged_ip_cidrs(whitelist_store),
        ru_suffixes=flags["ru_suffixes"],
        enable_geoip_ru=flags["enable_geoip_ru"],
        enable_default_outbound=flags["enable_default_outbound"],
        default_outbound_tag=flags["default_outbound_tag"],
    )


def _run_github_whitelist_sync(*, first_sync: bool = False) -> None:
    store = load_direct_whitelist_store()
    store["sync_status"] = "running"
    store["sync_started_at"] = datetime.now(timezone.utc).isoformat()
    store["sync_error"] = ""
    save_direct_whitelist_store(store)
    try:
        domains = fetch_github_whitelist_domains()
        last_resolved, resolve_errors, merged_cidrs = resolve_domains_to_ip_cidrs_bulk(domains)
        now = datetime.now(timezone.utc).isoformat()
        store = load_direct_whitelist_store()
        store["domains"] = domains
        store["last_resolved"] = last_resolved
        store["resolve_errors"] = resolve_errors
        store["source_url"] = GITHUB_WHITELIST_RAW_URL
        if first_sync or not store.get("synced_at"):
            store["synced_at"] = now
            store["auto_sync_enabled"] = True
        store["last_sync_at"] = now
        store["sync_status"] = "idle"
        store["sync_started_at"] = ""
        store["sync_error"] = ""
        save_direct_whitelist_store(store)
        apply_direct_routing_from_stores()
        sing_active = subprocess.run(
            ["systemctl", "is-active", "sing-box"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if sing_active.returncode == 0 and sing_active.stdout.strip() == "active":
            _schedule_sing_box_restart()
    except Exception as e:
        store = load_direct_whitelist_store()
        store["sync_status"] = "idle"
        store["sync_started_at"] = ""
        store["sync_error"] = str(e)
        save_direct_whitelist_store(store)


def _start_github_whitelist_sync_thread(*, first_sync: bool = False) -> bool:
    global _whitelist_sync_thread
    with _whitelist_sync_lock:
        store = load_direct_whitelist_store()
        if store.get("sync_status") == "running":
            if _whitelist_sync_thread and _whitelist_sync_thread.is_alive():
                return False
        store["sync_status"] = "running"
        store["sync_started_at"] = datetime.now(timezone.utc).isoformat()
        store["sync_error"] = ""
        save_direct_whitelist_store(store)

        def _worker() -> None:
            try:
                _run_github_whitelist_sync(first_sync=first_sync)
            finally:
                global _whitelist_sync_thread
                with _whitelist_sync_lock:
                    _whitelist_sync_thread = None

        _whitelist_sync_thread = threading.Thread(
            target=_worker,
            name="github-whitelist-sync",
            daemon=True,
        )
        _whitelist_sync_thread.start()
        return True


def _maybe_auto_sync_github_whitelist() -> None:
    store = load_direct_whitelist_store()
    if not store.get("synced_at"):
        return
    if not store.get("auto_sync_enabled"):
        return
    if store.get("sync_status") == "running":
        return
    last_raw = str(store.get("last_sync_at") or store.get("synced_at") or "")
    last_dt = iso_to_dt(last_raw)
    if last_dt is None:
        return
    if datetime.now(timezone.utc) - last_dt < timedelta(seconds=WHITELIST_AUTO_SYNC_INTERVAL_SEC):
        return
    _start_github_whitelist_sync_thread(first_sync=False)


def _whitelist_auto_sync_loop() -> None:
    time.sleep(30)
    while True:
        try:
            _maybe_auto_sync_github_whitelist()
        except Exception:
            pass
        time.sleep(3600)


def _start_whitelist_background_tasks() -> None:
    t = threading.Thread(target=_whitelist_auto_sync_loop, name="whitelist-auto-sync", daemon=True)
    t.start()


def _valid_direct_explicit_hostname(h: str) -> bool:
    t = str(h).strip().lower().rstrip(".")
    if not t or len(t) > 253:
        return False
    if any(x in t for x in ("/", " ", "\t", "\n", "\r", "..")):
        return False
    if t.startswith("-") or ":" in t:
        return False
    return True


def resolve_domain_to_ip_cidrs(domain: str) -> tuple[list[str], str]:
    d = str(domain).strip().lower().rstrip(".")
    if not d:
        return [], "пустой хост"
    cidrs: list[str] = []
    seen: set[str] = set()
    try:
        infos = socket.getaddrinfo(d, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return [], str(e).strip() or "ошибка DNS"
    for info in infos:
        ip = info[4][0]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        c = f"{a}/32" if a.version == 4 else f"{a}/128"
        if c not in seen:
            seen.add(c)
            cidrs.append(c)
    if not cidrs:
        return [], "нет A/AAAA"
    return cidrs, ""


def _is_direct_explicit_rule(rule: dict) -> bool:
    return isinstance(rule.get("domain"), list) and str(rule.get("outbound", "")).strip() == "direct"


def _is_direct_explicit_ip_cidr_rule(rule: dict) -> bool:
    """Панельная запись явных IP (из DNS по домёнам) -> direct."""
    return (
        str(rule.get("outbound", "")).strip() == "direct"
        and isinstance(rule.get("ip_cidr"), list)
        and len(rule.get("ip_cidr")) > 0
    )


def _is_direct_suffix_rule(rule: dict) -> bool:
    return isinstance(rule.get("domain_suffix"), list) and str(rule.get("outbound", "")).strip() == "direct"


def _is_geoip_ru_rule(rule: dict) -> bool:
    if str(rule.get("outbound", "")).strip() != "direct":
        return False
    rs = rule.get("rule_set")
    return isinstance(rs, list) and GEOIP_RU_RULE_SET_TAG in rs


def _is_geoip_ru_rule_set_def(item: dict) -> bool:
    return isinstance(item, dict) and str(item.get("tag", "")).strip() == GEOIP_RU_RULE_SET_TAG


def _default_geoip_ru_rule_set_entry() -> dict:
    return {
        "tag": GEOIP_RU_RULE_SET_TAG,
        "type": "remote",
        "format": "binary",
        "url": SINGBOX_GEOIP_RU_URL,
        "download_detour": "direct",
    }


def _sync_route_rule_set_geoip_ru(route: dict, *, enable: bool) -> None:
    """Добавляет/убирает remote rule-set geoip-ru (без него sing-box падает: rule-set not found)."""
    raw = route.get("rule_set")
    kept: list[dict] = []
    if isinstance(raw, list):
        kept = [x for x in raw if isinstance(x, dict) and not _is_geoip_ru_rule_set_def(x)]
    if enable:
        kept.append(_default_geoip_ru_rule_set_entry())
        route["rule_set"] = kept
        return
    if kept:
        route["rule_set"] = kept
    elif isinstance(raw, list):
        route["rule_set"] = []
    elif "rule_set" in route:
        del route["rule_set"]


def _is_non_direct_default_rule(rule: dict) -> bool:
    outbound = str(rule.get("outbound", "")).strip()
    return bool(outbound) and outbound != "direct" and len(rule.keys()) == 1


def _is_bare_direct_default_rule(rule: dict) -> bool:
    """Только { \"outbound\": \"direct\" } — раньше попадало в kept и перехватывало весь трафик до final."""
    return isinstance(rule, dict) and len(rule) == 1 and str(rule.get("outbound", "")).strip() == "direct"


def _is_route_preprocess_rule(rule: dict) -> bool:
    """
    Правила, которые должны идти до domain/domain_suffix, иначе SNI/Host неизвестны
    и суффиксы (.ru и т.д.) не матчятся — весь трафик уезжает в default (каскад).
    """
    if not isinstance(rule, dict):
        return False
    act = str(rule.get("action", "")).strip().lower()
    if act in ("sniff", "resolve", "hijack-dns"):
        return True
    if str(rule.get("protocol", "")).strip().lower() == "dns":
        return True
    return False


def apply_direct_routing_rules(
    *,
    explicit_hosts: list[str],
    explicit_ip_cidrs: list[str],
    whitelist_hosts: list[str] | None = None,
    whitelist_ip_cidrs: list[str] | None = None,
    ru_suffixes: list[str],
    enable_geoip_ru: bool,
    enable_default_outbound: bool,
    default_outbound_tag: str,
) -> None:
    p = Path(SING_BOX_CONFIG_PATH)
    if not p.exists():
        raise ValueError(f"Файл не найден: {SING_BOX_CONFIG_PATH}")
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise ValueError(f"Ошибка чтения JSON: {e}") from e
    if not isinstance(cfg, dict):
        raise ValueError("Корень JSON должен быть объектом")
    route = cfg.get("route")
    if not isinstance(route, dict):
        route = {}
        cfg["route"] = route
    rules = route.get("rules")
    if not isinstance(rules, list):
        rules = []

    kept: list = []
    for item in rules:
        if not isinstance(item, dict):
            kept.append(item)
            continue
        if _is_direct_explicit_rule(item):
            continue
        if _is_direct_explicit_ip_cidr_rule(item):
            continue
        if _is_direct_suffix_rule(item):
            continue
        if _is_geoip_ru_rule(item):
            continue
        if _is_non_direct_default_rule(item):
            continue
        if _is_bare_direct_default_rule(item):
            continue
        kept.append(item)

    pre_rules: list = []
    kept_rest: list = []
    for item in kept:
        if isinstance(item, dict) and _is_route_preprocess_rule(item):
            pre_rules.append(item)
        else:
            kept_rest.append(item)

    new_rules: list = []
    new_rules.extend(pre_rules)
    if explicit_ip_cidrs:
        new_rules.append({"ip_cidr": explicit_ip_cidrs, "outbound": "direct"})
    wl_cidrs = list(whitelist_ip_cidrs or [])
    if wl_cidrs:
        new_rules.append({"ip_cidr": wl_cidrs, "outbound": "direct"})
    if explicit_hosts:
        new_rules.append({"domain": explicit_hosts, "outbound": "direct"})
    wl_hosts = list(whitelist_hosts or [])
    if wl_hosts:
        new_rules.append({"domain": wl_hosts, "outbound": "direct"})
    if ru_suffixes:
        new_rules.append({"domain_suffix": ru_suffixes, "outbound": "direct"})
    if enable_geoip_ru:
        new_rules.append({"rule_set": [GEOIP_RU_RULE_SET_TAG], "outbound": "direct"})
    new_rules.extend(kept_rest)
    if enable_default_outbound and default_outbound_tag:
        new_rules.append({"outbound": default_outbound_tag})
    route["rules"] = new_rules
    _sync_route_rule_set_geoip_ru(route, enable=enable_geoip_ru)
    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
    if cfg is None:
        cfg = load_hy2_config()
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
    for item in baseline + list(F2B_ALWAYS_IGNORE_IPS) + list(items):
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
        text = (
            "[DEFAULT]\n"
            "ignoreip = 127.0.0.0/8 ::1\n"
            "\n"
            "[hy2-admin-auth]\n"
            "enabled = true\n"
            f"port = {BIND_PORT}\n"
            "protocol = tcp\n"
            "backend = systemd\n"
            "journalmatch = _SYSTEMD_UNIT=hy2-admin.service\n"
            "filter = hy2-admin-auth\n"
            "maxretry = 6\n"
            "findtime = 10m\n"
            "bantime = 2h\n"
        )

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

    F2B_JAIL_PATH.parent.mkdir(parents=True, exist_ok=True)
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


# Эталон HTTPS-заглушки: tools/https-root-stub/index.html (для «Вернуть исходное»). При правке файла пересоберите base64 в эту константу.
_DEFAULT_HTTPS_ROOT_STUB_B64 = (
    'PCFkb2N0eXBlIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgPG1ldGEgY2hhcnNldD0idXRmLTgiIC8+'
    'CiAgPG1ldGEgbmFtZT0idmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2Fs'
    'ZT0xIiAvPgogIDx0aXRsZT5tc2d3Lm1vb28uY29tPC90aXRsZT4KICA8c3R5bGU+CiAgICAqIHsgYm94LXNpemlu'
    'ZzogYm9yZGVyLWJveDsgfQogICAgaHRtbCwgYm9keSB7IGhlaWdodDogMTAwJTsgbWFyZ2luOiAwOyBvdmVyZmxv'
    'dzogaGlkZGVuOyBmb250LWZhbWlseTogc3lzdGVtLXVpLCAiU2Vnb2UgVUkiLCBzYW5zLXNlcmlmOyB9CiAgICAj'
    'YmcgewogICAgICBwb3NpdGlvbjogZml4ZWQ7CiAgICAgIGluc2V0OiAwOwogICAgICB3aWR0aDogMTAwJTsKICAg'
    'ICAgaGVpZ2h0OiAxMDAlOwogICAgICBkaXNwbGF5OiBibG9jazsKICAgICAgei1pbmRleDogMDsKICAgICAgcG9p'
    'bnRlci1ldmVudHM6IG5vbmU7CiAgICB9CiAgICAubGF5ZXIgewogICAgICBwb3NpdGlvbjogcmVsYXRpdmU7CiAg'
    'ICAgIHotaW5kZXg6IDE7CiAgICAgIG1pbi1oZWlnaHQ6IDEwMCU7CiAgICAgIGRpc3BsYXk6IGZsZXg7CiAgICAg'
    'IGFsaWduLWl0ZW1zOiBjZW50ZXI7CiAgICAgIGp1c3RpZnktY29udGVudDogY2VudGVyOwogICAgICBwYWRkaW5n'
    'OiAyOHB4IDIwcHg7CiAgICB9CiAgICAuY2FyZCB7CiAgICAgIG1heC13aWR0aDogNDIwcHg7CiAgICAgIHRleHQt'
    'YWxpZ246IGNlbnRlcjsKICAgICAgcGFkZGluZzogMzJweCAyOHB4OwogICAgICBib3JkZXItcmFkaXVzOiAxNnB4'
    'OwogICAgICBib3JkZXI6IDFweCBzb2xpZCByZ2JhKDE0OCwgMTYzLCAxODQsIDAuMik7CiAgICAgIGJhY2tncm91'
    'bmQ6IHJnYmEoMTUsIDE3LCAyMywgMC41NSk7CiAgICAgIGJhY2tkcm9wLWZpbHRlcjogYmx1cigxNHB4KTsKICAg'
    'ICAgLXdlYmtpdC1iYWNrZHJvcC1maWx0ZXI6IGJsdXIoMTRweCk7CiAgICAgIGJveC1zaGFkb3c6CiAgICAgICAg'
    'MCAyNHB4IDgwcHggcmdiYSgwLCAwLCAwLCAwLjQ1KSwKICAgICAgICBpbnNldCAwIDFweCAwIHJnYmEoMjU1LCAy'
    'NTUsIDI1NSwgMC4wNik7CiAgICB9CiAgICBoMSB7CiAgICAgIG1hcmdpbjogMCAwIDEycHg7CiAgICAgIGZvbnQt'
    'c2l6ZTogMS4zNXJlbTsKICAgICAgZm9udC13ZWlnaHQ6IDcwMDsKICAgICAgbGV0dGVyLXNwYWNpbmc6IC0wLjAy'
    'ZW07CiAgICAgIGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCgxMjBkZWcsICNlMmU4ZjAgMCUsICM5NGEzYjgg'
    'NDUlLCAjY2JkNWUxIDEwMCUpOwogICAgICAtd2Via2l0LWJhY2tncm91bmQtY2xpcDogdGV4dDsKICAgICAgYmFj'
    'a2dyb3VuZC1jbGlwOiB0ZXh0OwogICAgICBjb2xvcjogdHJhbnNwYXJlbnQ7CiAgICB9CiAgICBwIHsKICAgICAg'
    'bWFyZ2luOiAwOwogICAgICBmb250LXNpemU6IDAuOTVyZW07CiAgICAgIGxpbmUtaGVpZ2h0OiAxLjU1OwogICAg'
    'ICBjb2xvcjogcmdiYSgxNDgsIDE2MywgMTg0LCAwLjk1KTsKICAgIH0KICA8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5'
    'PgogIDxjYW52YXMgaWQ9ImJnIiBhcmlhLWhpZGRlbj0idHJ1ZSI+PC9jYW52YXM+CiAgPGRpdiBjbGFzcz0ibGF5'
    'ZXIiPgogICAgPGRpdiBjbGFzcz0iY2FyZCI+CiAgICAgIDxoMT5TZXJ2ZXIgdGVtcG9yYXJpbHkgb3ZlcmxvYWRl'
    'ZDwvaDE+CiAgICAgIDxwPgogICAgICAgIFRoZSBvcmlnaW4gaG9zdCBpcyBydW5uaW5nIHVuZGVyIGhpZ2ggbG9h'
    'ZCBvciBtYWludGVuYW5jZS4gUGxlYXNlIHRyeSBhZ2FpbiBpbiBhIGZldyBtaW51dGVzLgogICAgICA8L3A+CiAg'
    'ICA8L2Rpdj4KICA8L2Rpdj4KICA8c2NyaXB0PgooZnVuY3Rpb24gKCkgewogIHZhciBjYW52YXMgPSBkb2N1bWVu'
    'dC5nZXRFbGVtZW50QnlJZCgiYmciKTsKICBpZiAoIWNhbnZhcyB8fCAhY2FudmFzLmdldENvbnRleHQpIHJldHVy'
    'bjsKICB2YXIgY3R4ID0gY2FudmFzLmdldENvbnRleHQoIjJkIik7CiAgdmFyIGRwciA9IE1hdGgubWluKHdpbmRv'
    'dy5kZXZpY2VQaXhlbFJhdGlvIHx8IDEsIDIpOwogIHZhciB3LCBoLCB0MCA9IHBlcmZvcm1hbmNlLm5vdygpOwog'
    'IHZhciBwdHMgPSBbXTsKCiAgZnVuY3Rpb24gYnVpbGRQdHMoKSB7CiAgICB2YXIgbiA9IE1hdGgubWluKDk2LCBN'
    'YXRoLmZsb29yKCh3ICogaCkgLyAxNjAwMCkgKyAzNik7CiAgICBwdHMgPSBbXTsKICAgIGZvciAodmFyIGkgPSAw'
    'OyBpIDwgbjsgaSsrKSB7CiAgICAgIHB0cy5wdXNoKHsKICAgICAgICB4OiBNYXRoLnJhbmRvbSgpICogdywKICAg'
    'ICAgICB5OiBNYXRoLnJhbmRvbSgpICogaCwKICAgICAgICB2eDogKE1hdGgucmFuZG9tKCkgLSAwLjUpICogMC4z'
    'MiwKICAgICAgICB2eTogKE1hdGgucmFuZG9tKCkgLSAwLjUpICogMC4zMiwKICAgICAgICByOiBNYXRoLnJhbmRv'
    'bSgpICogMS4zNSArIDAuMjUKICAgICAgfSk7CiAgICB9CiAgfQoKICBmdW5jdGlvbiByZXNpemUoKSB7CiAgICB3'
    'ID0gd2luZG93LmlubmVyV2lkdGg7CiAgICBoID0gd2luZG93LmlubmVySGVpZ2h0OwogICAgY2FudmFzLndpZHRo'
    'ID0gTWF0aC5mbG9vcih3ICogZHByKTsKICAgIGNhbnZhcy5oZWlnaHQgPSBNYXRoLmZsb29yKGggKiBkcHIpOwog'
    'ICAgY3R4LnNldFRyYW5zZm9ybShkcHIsIDAsIDAsIGRwciwgMCwgMCk7CiAgICBidWlsZFB0cygpOwogIH0KICB3'
    'aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcigicmVzaXplIiwgcmVzaXplKTsKICByZXNpemUoKTsKCiAgZnVuY3Rpb24g'
    'dGljayhub3cpIHsKICAgIHZhciB0ID0gKG5vdyAtIHQwKSAqIDAuMDAxOwogICAgdmFyIGcgPSBjdHguY3JlYXRl'
    'TGluZWFyR3JhZGllbnQoMCwgMCwgdywgaCk7CiAgICBnLmFkZENvbG9yU3RvcCgwLCAiIzA3MGExMCIpOwogICAg'
    'Zy5hZGRDb2xvclN0b3AoMC40NSwgIiMwYzEwMjAiKTsKICAgIGcuYWRkQ29sb3JTdG9wKDEsICIjMDgwYzE0Iik7'
    'CiAgICBjdHguZmlsbFN0eWxlID0gZzsKICAgIGN0eC5maWxsUmVjdCgwLCAwLCB3LCBoKTsKCiAgICB2YXIgY3gg'
    'PSB3ICogKDAuNSArIDAuMDggKiBNYXRoLnNpbih0ICogMC4zNSkpOwogICAgdmFyIGN5ID0gaCAqICgwLjQ1ICsg'
    'MC4wNiAqIE1hdGguY29zKHQgKiAwLjI4KSk7CiAgICB2YXIgcmcgPSBjdHguY3JlYXRlUmFkaWFsR3JhZGllbnQo'
    'Y3gsIGN5LCAwLCBjeCwgY3ksIE1hdGgubWF4KHcsIGgpICogMC41NSk7CiAgICByZy5hZGRDb2xvclN0b3AoMCwg'
    'InJnYmEoNTksIDEzMCwgMjQ2LCAwLjA5KSIpOwogICAgcmcuYWRkQ29sb3JTdG9wKDAuNDUsICJyZ2JhKDk5LCAx'
    'MDIsIDI0MSwgMC4wNSkiKTsKICAgIHJnLmFkZENvbG9yU3RvcCgxLCAicmdiYSgwLDAsMCwwKSIpOwogICAgY3R4'
    'LmZpbGxTdHlsZSA9IHJnOwogICAgY3R4LmZpbGxSZWN0KDAsIDAsIHcsIGgpOwoKICAgIGN0eC5zdHJva2VTdHls'
    'ZSA9ICJyZ2JhKDUxLCA2NSwgODUsIDAuMzgpIjsKICAgIGN0eC5saW5lV2lkdGggPSAxOwogICAgdmFyIHN0ZXAg'
    'PSA1MjsKICAgIHZhciBneCwgZ3k7CiAgICBmb3IgKGd4ID0gKHQgKiAxMCkgJSBzdGVwOyBneCA8IHcgKyBzdGVw'
    'OyBneCArPSBzdGVwKSB7CiAgICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgY3R4Lm1vdmVUbyhneCwgMCk7CiAg'
    'ICAgIGN0eC5saW5lVG8oZ3gsIGgpOwogICAgICBjdHguc3Ryb2tlKCk7CiAgICB9CiAgICBmb3IgKGd5ID0gKHQg'
    'KiA2LjUpICUgc3RlcDsgZ3kgPCBoICsgc3RlcDsgZ3kgKz0gc3RlcCkgewogICAgICBjdHguYmVnaW5QYXRoKCk7'
    'CiAgICAgIGN0eC5tb3ZlVG8oMCwgZ3kpOwogICAgICBjdHgubGluZVRvKHcsIGd5KTsKICAgICAgY3R4LnN0cm9r'
    'ZSgpOwogICAgfQoKICAgIHZhciBpLCBwOwogICAgZm9yIChpID0gMDsgaSA8IHB0cy5sZW5ndGg7IGkrKykgewog'
    'ICAgICBwID0gcHRzW2ldOwogICAgICBwLnggKz0gcC52eDsKICAgICAgcC55ICs9IHAudnk7CiAgICAgIGlmIChw'
    'LnggPCAwIHx8IHAueCA+IHcpIHAudnggKj0gLTE7CiAgICAgIGlmIChwLnkgPCAwIHx8IHAueSA+IGgpIHAudnkg'
    'Kj0gLTE7CiAgICB9CgogICAgdmFyIG1heEQgPSAxMDg7CiAgICB2YXIgYSwgYiwgZHgsIGR5LCBkLCBhbHBoYTsK'
    'ICAgIGZvciAoYSA9IDA7IGEgPCBwdHMubGVuZ3RoOyBhKyspIHsKICAgICAgZm9yIChiID0gYSArIDE7IGIgPCBw'
    'dHMubGVuZ3RoOyBiKyspIHsKICAgICAgICBkeCA9IHB0c1thXS54IC0gcHRzW2JdLng7CiAgICAgICAgZHkgPSBw'
    'dHNbYV0ueSAtIHB0c1tiXS55OwogICAgICAgIGQgPSBNYXRoLnNxcnQoZHggKiBkeCArIGR5ICogZHkpOwogICAg'
    'ICAgIGlmIChkIDwgbWF4RCkgewogICAgICAgICAgYWxwaGEgPSAoMSAtIGQgLyBtYXhEKSAqIDAuMjsKICAgICAg'
    'ICAgIGN0eC5zdHJva2VTdHlsZSA9ICJyZ2JhKDE0OCwgMTYzLCAxODQsICIgKyBhbHBoYSArICIpIjsKICAgICAg'
    'ICAgIGN0eC5iZWdpblBhdGgoKTsKICAgICAgICAgIGN0eC5tb3ZlVG8ocHRzW2FdLngsIHB0c1thXS55KTsKICAg'
    'ICAgICAgIGN0eC5saW5lVG8ocHRzW2JdLngsIHB0c1tiXS55KTsKICAgICAgICAgIGN0eC5zdHJva2UoKTsKICAg'
    'ICAgICB9CiAgICAgIH0KICAgIH0KCiAgICBmb3IgKGkgPSAwOyBpIDwgcHRzLmxlbmd0aDsgaSsrKSB7CiAgICAg'
    'IHAgPSBwdHNbaV07CiAgICAgIGN0eC5maWxsU3R5bGUgPSAicmdiYSgyMjYsIDIzMiwgMjQwLCAwLjUpIjsKICAg'
    'ICAgY3R4LmJlZ2luUGF0aCgpOwogICAgICBjdHguYXJjKHAueCwgcC55LCBwLnIsIDAsIE1hdGguUEkgKiAyKTsK'
    'ICAgICAgY3R4LmZpbGwoKTsKICAgIH0KCiAgICByZXF1ZXN0QW5pbWF0aW9uRnJhbWUodGljayk7CiAgfQogIHJl'
    'cXVlc3RBbmltYXRpb25GcmFtZSh0aWNrKTsKfSkoKTsKICA8L3NjcmlwdD4KPC9ib2R5Pgo8L2h0bWw+Cg=='
)

def https_root_stub_html_path() -> Path:
    raw = (ENV.get("HTTPS_ROOT_STUB_HTML_PATH") or "").strip()
    if raw:
        return Path(raw)
    # Стандартный путь root-заглушки для location /.
    return Path("/var/www/hy2-site/index.html")


def bundled_default_https_root_stub_html() -> str:
    """Эталонная зашитая заглушка для «Вернуть исходное» (как tools/https-root-stub/index.html)."""
    return base64.b64decode(_DEFAULT_HTTPS_ROOT_STUB_B64).decode("utf-8")

def build_https_stub_panel_view(merged_defaults: dict) -> dict:
    path = https_root_stub_html_path()
    err = ""
    if "https_stub_html" in merged_defaults:
        text = str(merged_defaults["https_stub_html"])
    else:
        try:
            if path.is_file():
                text = path.read_text(encoding="utf-8")
            else:
                text = bundled_default_https_root_stub_html()
        except OSError as e:
            text = bundled_default_https_root_stub_html()
            err = f"Не удалось прочитать файл: {e}"
    return {"path": str(path), "text": text, "read_error": err}


def write_https_root_stub_atomic(text: str) -> None:
    path = https_root_stub_html_path()
    raw = text.encode("utf-8")
    if len(raw) > HTTPS_ROOT_STUB_MAX_BYTES:
        raise ValueError(f"Слишком большой файл (максимум {HTTPS_ROOT_STUB_MAX_BYTES // 1024} КБ)")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix="https-stub-", suffix=".html", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        raise


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
    cascade_sync_users_best_effort("update_single_user_limits")


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
    if changed_cfg or changed_state:
        cascade_sync_users_best_effort("enforce_limits_if_needed")

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
    host, port, sni = infer_server_values(cfg)
    stats = get_hy2_stats(cfg)
    stats_users = stats.get("users", {})
    ip_users = update_user_ip_observations(stats_users)
    active = []
    hidden_ui = hy2_ui_hidden_usernames()
    for username, password in sorted(cfg["auth"]["userpass"].items()):
        if str(username).strip().lower() in hidden_ui:
            continue
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
    hidden_ui = hy2_ui_hidden_usernames()
    for username in sorted(disabled_map.keys()):
        if str(username).strip().lower() in hidden_ui:
            continue
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
    cascade_sync_users_best_effort("apply_users")
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

    if action == "disable":
        if username not in up:
            raise ValueError("Пользователь не найден среди активных")
        password = up.pop(username)
        write_config_with_backup_and_restart(cfg)
        disabled[username] = {
            "password": password,
            "disabled_at": datetime.now(timezone.utc).isoformat(),
        }
        save_user_state(state)
        cascade_sync_users_best_effort("toggle_user_disable")
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
    cascade_sync_users_best_effort("toggle_user_enable")
    return "Пользователь включен"


def disable_all_active_users() -> str:
    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    if not up:
        return "Активных пользователей нет"

    state = load_user_state()
    disabled = state["disabled"]
    now = datetime.now(timezone.utc).isoformat()
    moved = 0
    for username, password in list(up.items()):
        disabled[username] = {
            "password": password,
            "disabled_at": now,
            "reason": "bulk_disable_all",
        }
        moved += 1
    up.clear()

    write_config_with_backup_and_restart(cfg)
    save_user_state(state)
    cascade_sync_users_best_effort("bulk_disable_all_users")
    return f"Отключены все активные пользователи: {moved}"


def reset_user_password_random(username: str) -> str:
    if not valid_username(username):
        raise ValueError("Недопустимое имя пользователя")

    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    state = load_user_state()
    disabled = state["disabled"]

    new_pass = random_password()
    if username in up:
        up[username] = new_pass
        write_config_with_backup_and_restart(cfg)
        cascade_sync_users_best_effort("reset_user_password_random_active")
        return f"Пароль пользователя {username} обновлен (рандомный)"

    rec = disabled.get(username)
    if isinstance(rec, dict):
        rec["password"] = new_pass
        disabled[username] = rec
        save_user_state(state)
        cascade_sync_users_best_effort("reset_user_password_random_disabled")
        return f"Пароль пользователя {username} обновлен (клиент выключен)"

    raise ValueError("Пользователь не найден")


def delete_users(scope: str, mode: str, selected: list[str]) -> str:
    if scope not in {"active", "disabled"}:
        raise ValueError("Недопустимая область удаления")
    if mode not in {"selected", "all"}:
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
    if changed_active or changed_state:
        cascade_sync_users_best_effort("delete_users")

    if deleted_count == 0 and skipped_protected == 0:
        return "Ничего не удалено"
    if skipped_protected:
        return f"Удалено: {deleted_count}. Защищенных пропущено: {skipped_protected}"
    return f"Удалено: {deleted_count}"


def parse_log_int(value: str, default: int, min_v: int, max_v: int) -> int:
    text = (value or "").strip()
    if not text:
        return default
    num = int(text)
    if num < min_v:
        return min_v
    if num > max_v:
        return max_v
    return num


def read_diagnostic_logs(
    service: str,
    username: str,
    query: str,
    level: str,
    since_minutes: int,
    limit: int,
) -> dict:
    def render_log_line_html(line: str) -> str:
        highlights: list[tuple[int, int, str]] = []

        def add_matches(pattern: str, css_class: str, group_idx: int = 0):
            for m in re.finditer(pattern, line):
                try:
                    s, e = m.start(group_idx), m.end(group_idx)
                except IndexError:
                    continue
                if s < e:
                    highlights.append((s, e, css_class))

        # Log level token (INFO/WARN/ERROR).
        add_matches(r"\b(INFO|WARN|ERROR)\b", "log-level")
        # Message type after level, for example "TCP error" / "client disconnected".
        add_matches(r"\b(?:INFO|WARN|ERROR)\b\s+(.+?)(?:\s+\{.*|\s*$)", "log-type", group_idx=1)
        # IPv4/IPv6 + optional port.
        add_matches(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b|\[[0-9a-fA-F:]+\](?::\d+)?", "log-ip")
        # User id value from JSON payload.
        add_matches(r'"id"\s*:\s*"([^"]+)"', "log-user", group_idx=1)
        # Error reason value from JSON payload.
        add_matches(r'"error"\s*:\s*"([^"]+)"', "log-error", group_idx=1)

        highlights.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        out: list[str] = []
        pos = 0
        for s, e, cls in highlights:
            if s < pos:
                continue
            out.append(html.escape(line[pos:s]))
            out.append(f'<span class="{cls}">{html.escape(line[s:e])}</span>')
            pos = e
        out.append(html.escape(line[pos:]))
        return "".join(out)

    service_map = {
        "hysteria": ["hysteria-server.service"],
        "admin": ["hy2-admin.service"],
        "both": ["hysteria-server.service", "hy2-admin.service"],
    }
    services = service_map.get(service, service_map["both"])
    level = (level or "all").strip().lower()
    level_tokens = {
        "info": [" info ", " [info] "],
        "warn": [" warn ", " warning ", " [warn] "],
        "error": [" error ", " failed ", " critical ", " panic ", " fatal ", " traceback ", " exception "],
    }
    uname = (username or "").strip().lower()
    needle = (query or "").strip().lower()
    lines: list[str] = []

    for svc in services:
        proc = subprocess.run(
            [
                "journalctl",
                "-u",
                svc,
                "--since",
                f"{since_minutes} minutes ago",
                "--no-pager",
                "-o",
                "short-iso",
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            continue
        for raw in proc.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            low = line.lower()
            if uname and uname not in low:
                continue
            if needle and needle not in low:
                continue
            if level in level_tokens and not any(tok in low for tok in level_tokens[level]):
                continue
            lines.append(line)

    # Deduplicate and show latest first
    uniq = list(dict.fromkeys(lines))
    uniq.sort(reverse=True)
    clipped = uniq[:limit]
    return {
        "searched": True,
        "service": service if service in service_map else "both",
        "level": level if level in {"all", "info", "warn", "error"} else "all",
        "username": username,
        "query": query,
        "since_minutes": since_minutes,
        "limit": limit,
        "total": len(uniq),
        "lines": clipped,
        "lines_html": [render_log_line_html(x) for x in clipped],
    }


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
        "logs_service": "both",
        "logs_level": "all",
        "logs_username": "",
        "logs_query": "",
        "logs_since_minutes": "180",
        "logs_limit": "200",
        "panel_prefix_secret": "",
        "direct_explicit_hosts": "",
        "direct_explicit_domains_json": "",
        "direct_ru_suffixes": "",
        "direct_geoip_ru": "",
        "direct_default_enabled": "",
        "direct_default_outbound_tag": "",
        "backup_include_users_limits": "1",
        "backup_include_server_settings": "1",
        "restore_include_users_limits": "1",
        "restore_include_server_settings": "1",
    }


def _is_checked(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "on", "true", "yes"}


def _sanitize_userpass(data: object) -> dict[str, str]:
    if not isinstance(data, dict):
        raise ValueError("Некорректный backup: users_limits.auth_userpass должен быть object")
    out: dict[str, str] = {}
    for k, v in data.items():
        username = str(k or "").strip()
        if not valid_username(username):
            raise ValueError(f"Некорректный username в backup: {username!r}")
        if not isinstance(v, str):
            raise ValueError(f"Некорректный пароль для {username}: должен быть строкой")
        if "\n" in v or "\r" in v:
            raise ValueError(f"Пароль для {username} содержит перевод строки")
        out[username] = v
    return out


def _sanitize_user_state(data: object) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Некорректный backup: users_limits.user_state должен быть object")
    disabled = data.get("disabled", {})
    if not isinstance(disabled, dict):
        raise ValueError("Некорректный backup: users_limits.user_state.disabled должен быть object")
    out_disabled: dict[str, dict] = {}
    for k, v in disabled.items():
        username = str(k or "").strip()
        if not valid_username(username):
            continue
        if isinstance(v, dict):
            out_disabled[username] = v
        else:
            out_disabled[username] = {"disabled_at": "", "reason": str(v)}
    return {"disabled": out_disabled}


def _sanitize_user_meta(data: object) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Некорректный backup: users_limits.user_meta должен быть object")
    users = data.get("users", {})
    if not isinstance(users, dict):
        raise ValueError("Некорректный backup: users_limits.user_meta.users должен быть object")
    out_users: dict[str, dict] = {}
    for k, v in users.items():
        username = str(k or "").strip()
        if not valid_username(username):
            continue
        out_users[username] = v if isinstance(v, dict) else {}
    return {"users": out_users}


def _sanitize_user_notes(data: object) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Некорректный backup: users_limits.user_notes должен быть object")
    users = data.get("users", {})
    if not isinstance(users, dict):
        raise ValueError("Некорректный backup: users_limits.user_notes.users должен быть object")
    out_users: dict[str, str] = {}
    for k, v in users.items():
        username = str(k or "").strip()
        if not valid_username(username):
            continue
        note_text = normalize_note(str(v or ""))
        if note_text:
            out_users[username] = note_text
    return {"users": out_users}


def render_index_page(
    *,
    defaults: dict | None = None,
    results: list[dict] | None = None,
    skipped: list[str] | None = None,
    ok_message: str | None = None,
    error_message: str | None = None,
    created_urls: list[str] | None = None,
    logs_data: dict | None = None,
):
    merged_defaults = base_defaults()
    if isinstance(defaults, dict):
        merged_defaults.update(defaults)
    ptz = get_panel_timezone()

    ui_shell_only = (ENV.get("PANEL_UI_SHELL_ONLY", "0").strip() == "1")

    if is_sing_box_readonly_panel():
        active_users = []
        disabled_users = []
        stats = {
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
        cfg: dict = {}
        sing_box_summary = summarize_sing_box_for_panel()
        panel_backend = "sing-box"
    else:
        active_users, disabled_users, stats = build_users_view()
        cfg = load_hy2_config()
        sing_box_summary = {
            "config_path": "",
            "load_error": "",
            "inbounds": [],
            "route_rule_count": 0,
            "outbound_tags": [],
        }
        panel_backend = "hysteria"

    _direct_state = normalize_direct_state_for_template(read_direct_routing_state())
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
        logs_data=logs_data or {"searched": False, "lines": [], "lines_html": [], "total": 0},
        panel_login=get_panel_credentials()[0],
        panel_timezone=ptz,
        panel_timezone_options=PANEL_TIMEZONE_OPTIONS,
        panel_backend=panel_backend,
        sing_box_summary=sing_box_summary,
        ui_shell_only=ui_shell_only,
        https_stub=build_https_stub_panel_view(merged_defaults),
        panel_url_prefix_display=get_live_effective_panel_url_prefix(),
        panel_insecure_debug_strip_prefix=INSECURE_DEBUG_STRIP_PREFIX,
        panel_systemd_service=PANEL_SYSTEMD_SERVICE,
        cascade_state=read_cascade_ui_state(),
        direct_state=_direct_state,
        direct_suffix_groups=direct_suffix_groups_for_template(
            str(merged_defaults.get("direct_ru_suffixes") or "")
            or str(_direct_state.get("ru_suffixes_text") or "")
        ),
    )


def reject_sing_box_mutations():
    """POST: в режиме sing-box блокируем изменения HY2 и связанных настроек сервера."""
    if not is_sing_box_readonly_panel():
        return None
    return render_index_page(
        error_message="Режим sing-box (только чтение): изменение пользователей Hysteria2 и связанных настроек сервера отключено.",
    )


@bp.route("/login", methods=["GET", "POST"])
def login():
    if _legacy_basic_proxy():
        if panel_basic_auth_ok():
            nxt = safe_next_path(
                (request.args.get("next") or request.form.get("next") or "").strip()
            )
            return _legacy_basic_login_landing(nxt or url_for("hy2.index"))
        return basic_auth_challenge_response()
    if panel_session_ok():
        return redirect(url_for("hy2.index"))

    if request.method == "GET":
        csrf = secrets.token_hex(16)
        session["login_csrf"] = csrf
        return render_template(
            "login.html",
            csrf=csrf,
            next_path=safe_next_path(request.args.get("next") or ""),
            default_user="",
            error="",
            totp_required=panel_totp_required(),
        )

    ip = _client_ip()
    if not _login_rate_allow(ip):
        csrf = secrets.token_hex(16)
        session["login_csrf"] = csrf
        return (
            render_template(
                "login.html",
                csrf=csrf,
                next_path=safe_next_path(request.form.get("next") or ""),
                default_user=(request.form.get("user") or "").strip(),
                error="Слишком много неудачных попыток. Подождите несколько минут.",
                totp_required=panel_totp_required(),
            ),
            429,
        )

    posted_csrf = request.form.get("csrf", "")
    expected_csrf = session.get("login_csrf")
    if not expected_csrf or not secrets.compare_digest(str(posted_csrf), str(expected_csrf)):
        csrf = secrets.token_hex(16)
        session["login_csrf"] = csrf
        return render_template(
            "login.html",
            csrf=csrf,
            next_path=safe_next_path(request.form.get("next") or ""),
            default_user=(request.form.get("user") or "").strip(),
            error="Форма устарела. Обновите страницу и попробуйте снова.",
            totp_required=panel_totp_required(),
        )

    u, pw = get_panel_credentials()
    if not pw:
        return Response("PANEL_BASIC_PASS is not configured", status=500)
    need_totp = panel_totp_required()
    if need_totp and pyotp is None:
        csrf = secrets.token_hex(16)
        session["login_csrf"] = csrf
        return render_template(
            "login.html",
            csrf=csrf,
            next_path=safe_next_path(request.form.get("next") or ""),
            default_user=(request.form.get("user") or "").strip(),
            error="На сервере не установлен пакет pyotp (pip install pyotp).",
            totp_required=True,
        )

    user_in = (request.form.get("user") or "").strip()
    pass_in = request.form.get("password") or ""
    totp_in = request.form.get("totp") or ""

    user_ok = secrets.compare_digest(user_in, u)
    pass_ok = secrets.compare_digest(pass_in, pw)
    totp_ok = verify_panel_totp(totp_in) if need_totp else True

    if not (user_ok and pass_ok and totp_ok):
        _login_rate_record_fail(ip)
        csrf = secrets.token_hex(16)
        session["login_csrf"] = csrf
        err = (
            "Неверный логин, пароль или код 2FA."
            if need_totp
            else "Неверный логин или пароль."
        )
        return render_template(
            "login.html",
            csrf=csrf,
            next_path=safe_next_path(request.form.get("next") or ""),
            default_user=user_in,
            error=err,
            totp_required=need_totp,
        )

    session.pop("login_csrf", None)
    session.clear()
    session["panel_auth"] = True
    session.permanent = True
    nxt = safe_next_path(request.form.get("next") or "")
    return redirect(nxt or url_for("hy2.index"))


@bp.route("/logout", methods=["GET", "POST"])
def logout():
    if _legacy_basic_proxy():
        # Иначе 401 по кругу на /panel/logout. Редирект на /panel/ не «выходит» — браузер снова шлёт Basic.
        if panel_basic_auth_ok():
            return _legacy_basic_logout_response()
        return basic_auth_challenge_response()
    session.clear()
    return redirect(url_for("hy2.login"))


@bp.route("/", methods=["GET"])
@requires_auth
def index():
    return render_index_page()


@bp.route("/apply", methods=["POST"])
@requires_auth
def apply_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
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


@bp.route("/qr", methods=["GET"])
@requires_auth
def qr_handler():
    text = request.args.get("u", "").strip()
    if not text:
        return Response("Missing parameter: u", status=400)
    png = make_qr_png(text)
    return Response(png, mimetype="image/png")


@bp.route("/users/toggle", methods=["POST"])
@requires_auth
def users_toggle_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
    username = request.form.get("username", "").strip()
    action = request.form.get("action", "").strip()
    try:
        msg = toggle_user(username, action)
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/users/disable-all", methods=["POST"])
@requires_auth
def users_disable_all_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
    try:
        msg = disable_all_active_users()
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/users/password/random", methods=["POST"])
@requires_auth
def users_password_random_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
    username = request.form.get("username", "").strip()
    try:
        msg = reset_user_password_random(username)
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/users/delete", methods=["POST"])
@requires_auth
def users_delete_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
    scope = request.form.get("scope", "").strip()
    mode = request.form.get("mode", "").strip()
    selected = request.form.getlist("selected_users")
    try:
        msg = delete_users(scope, mode, selected)
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/users/limits", methods=["POST"])
@requires_auth
def users_limits_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
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


@bp.route("/users/note", methods=["POST"])
@requires_auth
def users_note_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
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


def build_backup_export_filename() -> str:
    """Имя файла: домен-дд.мм.гг-чч.мм.json (часовой пояс панели)."""
    host = (SERVER_HOST or "server").strip().lower()
    host = re.sub(r"[^\w.\-]", "-", host).strip(".-") or "server"
    try:
        tz = ZoneInfo(get_panel_timezone())
    except Exception:
        tz = ZoneInfo("Europe/Moscow")
    now = datetime.now(tz)
    return f"{host}-{now.strftime('%d.%m.%y')}-{now.strftime('%H.%M')}.json"


@bp.route("/server/backup/export", methods=["POST"])
@requires_auth
def server_backup_export_handler():
    include_users_limits = _is_checked(request.form.get("backup_include_users_limits"), default=True)
    include_server_settings = _is_checked(request.form.get("backup_include_server_settings"), default=True)
    if not include_users_limits and not include_server_settings:
        return render_index_page(
            defaults={
                "backup_include_users_limits": "",
                "backup_include_server_settings": "",
            },
            error_message="Резервное копирование: выберите хотя бы одну секцию для выгрузки.",
        )

    try:
        cfg = load_hy2_config()
        payload: dict = {
            "format": BACKUP_FORMAT,
            "version": BACKUP_FORMAT_VERSION,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "server_host": SERVER_HOST or "",
            "hy2_config_path": HY2_CONFIG,
            "sections": {},
        }
        if include_users_limits:
            payload["sections"]["users_limits"] = {
                "auth_userpass": dict(cfg.get("auth", {}).get("userpass", {})),
                "user_meta": load_user_meta(),
                "user_state": load_user_state(),
                "user_notes": load_user_notes(),
            }
        if include_server_settings:
            cfg_no_auth = dict(cfg)
            cfg_no_auth.pop("auth", None)
            payload["sections"]["server_settings"] = {
                "hy2_config": cfg_no_auth,
                "server_exclusions_items": read_server_exclusions().get("items", []),
                "cascade_remote_servers": _load_cascade_db(),
                "panel_timezone": get_panel_timezone(),
            }

        body = json.dumps(payload, ensure_ascii=False, indent=2)
        filename = build_backup_export_filename()
        return Response(
            body,
            mimetype="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        return render_index_page(error_message=f"Резервное копирование: {e}")


@bp.route("/server/backup/import", methods=["POST"])
@requires_auth
def server_backup_import_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked

    include_users_limits = _is_checked(request.form.get("restore_include_users_limits"), default=True)
    include_server_settings = _is_checked(request.form.get("restore_include_server_settings"), default=True)
    if not include_users_limits and not include_server_settings:
        return render_index_page(
            defaults={
                "restore_include_users_limits": "",
                "restore_include_server_settings": "",
            },
            error_message="Восстановление: выберите хотя бы одну секцию.",
        )

    uploaded = request.files.get("backup_file")
    if uploaded is None or not uploaded.filename:
        return render_index_page(error_message="Восстановление: выберите JSON-файл резервной копии.")
    try:
        raw = uploaded.read(BACKUP_UPLOAD_MAX_BYTES + 1)
        if len(raw) > BACKUP_UPLOAD_MAX_BYTES:
            raise ValueError(f"Файл слишком большой (максимум {BACKUP_UPLOAD_MAX_BYTES // (1024 * 1024)} MB)")
        doc = json.loads(raw.decode("utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("Корень JSON должен быть object")
        if str(doc.get("format", "")).strip().lower() != BACKUP_FORMAT:
            raise ValueError("Это не backup-файл hy2-admin")
        sections = doc.get("sections")
        if not isinstance(sections, dict):
            raise ValueError("Некорректный backup: отсутствует sections")

        cfg_new = load_hy2_config()
        cfg_changed = False
        applied_labels: list[str] = []
        sync_needed = False

        if include_users_limits:
            sec = sections.get("users_limits")
            if not isinstance(sec, dict):
                raise ValueError("В backup отсутствует секция users_limits")
            auth_userpass = _sanitize_userpass(sec.get("auth_userpass", {}))
            cfg_new.setdefault("auth", {})
            cfg_new["auth"]["type"] = "userpass"
            cfg_new["auth"]["userpass"] = auth_userpass
            save_user_meta(_sanitize_user_meta(sec.get("user_meta", {})))
            save_user_state(_sanitize_user_state(sec.get("user_state", {})))
            save_user_notes(_sanitize_user_notes(sec.get("user_notes", {})))
            cfg_changed = True
            sync_needed = True
            applied_labels.append("пользователи и лимиты")

        if include_server_settings:
            sec = sections.get("server_settings")
            if not isinstance(sec, dict):
                raise ValueError("В backup отсутствует секция server_settings")
            restored_cfg = sec.get("hy2_config", {})
            if isinstance(restored_cfg, dict) and restored_cfg:
                keep_auth = cfg_new.get("auth", {"type": "userpass", "userpass": {}})
                cfg_new = dict(restored_cfg)
                cfg_new["auth"] = keep_auth
                cfg_changed = True
            exclusions_items = sec.get("server_exclusions_items", [])
            if isinstance(exclusions_items, list):
                parsed = parse_exclusion_tokens("\n".join(str(x) for x in exclusions_items))
                write_server_exclusions(parsed)
            cascade_db = sec.get("cascade_remote_servers")
            if isinstance(cascade_db, dict):
                _save_cascade_db(cascade_db)
            panel_tz = str(sec.get("panel_timezone", "")).strip()
            if panel_tz in PANEL_TIMEZONE_OPTIONS:
                update_env_keys({"PANEL_TIMEZONE": panel_tz})
            applied_labels.append("настройки сервера")

        if cfg_changed:
            write_config_with_backup_and_restart(cfg_new)
        if sync_needed:
            cascade_sync_users_best_effort("restore_backup_ui")

        msg = "Восстановление завершено: " + ", ".join(applied_labels)
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=f"Восстановление backup: {e}")


@bp.route("/server/bandwidth", methods=["POST"])
@requires_auth
def server_bandwidth_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
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


@bp.route("/server/panel-auth", methods=["POST"])
@requires_auth
def server_panel_auth_handler():
    current_pw = request.form.get("panel_current_password", "")
    new_user = request.form.get("panel_new_user", "").strip()
    new_pass = request.form.get("panel_new_password", "")
    new_pass2 = request.form.get("panel_new_password_confirm", "")
    try:
        u, pw = get_panel_credentials()
        if not secrets.compare_digest(current_pw, pw):
            raise ValueError("Неверный текущий пароль")
        if not new_user:
            new_user = u
        if not re.match(r"^[a-zA-Z0-9._-]{1,64}$", new_user):
            raise ValueError("Логин: 1–64 символа (буквы, цифры, . _ -)")
        if "\n" in new_pass or "\r" in new_pass:
            raise ValueError("Пароль не должен содержать переводы строк")
        if len(new_pass) < 8:
            raise ValueError("Новый пароль: минимум 8 символов")
        if new_pass != new_pass2:
            raise ValueError("Повтор нового пароля не совпадает")
        if secrets.compare_digest(new_pass, current_pw) and new_user == u:
            raise ValueError("Укажите новый пароль или другой логин")
        update_panel_credentials_in_env(new_user, new_pass)
        session.clear()
        return redirect(url_for("hy2.login", updated="1"))
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/server/panel-url-prefix", methods=["POST"])
@requires_auth
def server_panel_url_prefix_handler():
    action = (request.form.get("panel_prefix_action") or "update").strip().lower()
    secret_raw = request.form.get("panel_prefix_secret", "")
    try:
        live = get_live_effective_panel_url_prefix()
        if action == "remove":
            if not live:
                raise ValueError("Не удалось определить текущий путь панели (.env).")
            if live == "/panel":
                raise ValueError("Секретный slug уже снят: панель на /panel/")
            new_prefix = "/panel"
        elif action == "update":
            new_prefix = normalize_user_panel_prefix_secret(secret_raw)
            if new_prefix == live:
                raise ValueError("Этот префикс уже задан в .env")
        else:
            raise ValueError("Неизвестное действие")
        env_disk = load_env(str(ENV_PATH))
        nginx_paths = panel_nginx_site_paths_from_env(env_disk)
        if nginx_paths:
            try:
                apply_panel_url_prefix_to_nginx_configs(
                    nginx_paths,
                    old_prefix=live,
                    new_prefix=new_prefix,
                    upstream_port=BIND_PORT,
                    removing=False,
                )
            except (OSError, ValueError, RuntimeError) as e:
                raise ValueError(f"Синхронизация nginx: {e}") from e
        update_env_keys(
            {
                "PANEL_URL_PREFIX": new_prefix,
                "PANEL_INSECURE_DEBUG_STRIP_PREFIX": "",
            }
        )
        schedule_panel_service_restart()
        # Вкладка «Настройки сервера» → «Администратор» (#server-admin обрабатывается в шаблоне).
        tab = "#server-admin"
        loc = new_prefix.rstrip("/") + "/" + tab
        return redirect(loc, code=302)
    except Exception as e:
        return render_index_page(
            defaults={"panel_prefix_secret": secret_raw if action == "update" else ""},
            error_message=str(e),
        )


@bp.route("/server/cascade/register", methods=["POST"])
@requires_auth
def server_cascade_register_handler():
    token_raw = (request.form.get("cascade_token") or "").strip()
    mark_exit = (request.form.get("cascade_mark_exit") or "") in {"1", "on", "true", "yes"}
    alias = (request.form.get("cascade_name") or "").strip()
    try:
        if not token_raw:
            raise ValueError("Вставьте registration token")
        payload = _parse_cascade_registration_token(token_raw)
        if alias:
            payload["name"] = alias
        host = str(payload.get("host") or "").strip()
        hy2_server = str(payload.get("hy2_server") or host).strip() or host
        payload["hy2_server"] = hy2_server
        try:
            payload["hy2_port"] = int(payload.get("hy2_port") or 443)
        except (TypeError, ValueError):
            payload["hy2_port"] = 443
        hy2_sni = str(payload.get("hy2_sni") or hy2_server or host).strip()
        payload["hy2_sni"] = hy2_sni or hy2_server or host
        if "hop_username" not in payload:
            payload["hop_username"] = ""
        if "hop_password" not in payload:
            payload["hop_password"] = ""
        payload.setdefault("hy2_insecure", False)
        db = _load_cascade_db()
        servers = [s for s in (db.get("servers") or []) if isinstance(s, dict) and s.get("node_id") != payload["node_id"]]
        payload["enabled"] = True
        payload["cascade_exit"] = bool(mark_exit)
        servers.append(payload)
        if mark_exit:
            for s in servers:
                if s.get("node_id") != payload["node_id"]:
                    s["cascade_exit"] = False
        db["servers"] = servers
        _save_cascade_db(db)
        cascade_sync_users_best_effort("register_remote_ui")
        return render_index_page(ok_message=f"Каскад-узел добавлен: {payload.get('name') or payload.get('host')}")
    except Exception as e:
        return render_index_page(
            defaults={"cascade_token": token_raw, "cascade_name": alias},
            error_message=f"Регистрация узла: {e}",
        )


@bp.route("/server/cascade/toggle", methods=["POST"])
@requires_auth
def server_cascade_toggle_handler():
    node_id = (request.form.get("node_id") or "").strip()
    action = (request.form.get("action") or "").strip().lower()
    try:
        if not node_id:
            raise ValueError("node_id не передан")
        db = _load_cascade_db()
        servers = db.get("servers") or []
        hit = None
        for item in servers:
            if isinstance(item, dict) and str(item.get("node_id")) == node_id:
                hit = item
                break
        if not isinstance(hit, dict):
            raise ValueError("Узел не найден")
        if action == "enable":
            hit["enabled"] = True
        elif action == "disable":
            hit["enabled"] = False
        elif action == "set-exit":
            hit["cascade_exit"] = True
            hit["enabled"] = True
            for s in servers:
                if isinstance(s, dict) and s is not hit:
                    s["cascade_exit"] = False
        else:
            raise ValueError("Неизвестное действие")
        db["servers"] = servers
        _save_cascade_db(db)
        if action in {"enable", "set-exit"}:
            cascade_sync_users_best_effort("toggle_remote_ui")
        return render_index_page(ok_message="Настройки узла обновлены")
    except Exception as e:
        return render_index_page(error_message=f"Узел каскада: {e}")


@bp.route("/server/cascade/delete", methods=["POST"])
@requires_auth
def server_cascade_delete_handler():
    node_id = (request.form.get("node_id") or "").strip()
    try:
        if not node_id:
            raise ValueError("node_id не передан")
        db = _load_cascade_db()
        old = db.get("servers") or []
        new = [s for s in old if not (isinstance(s, dict) and str(s.get("node_id")) == node_id)]
        if len(new) == len(old):
            raise ValueError("Узел не найден")
        db["servers"] = new
        _save_cascade_db(db)
        return render_index_page(ok_message="Узел удалён из реестра каскада")
    except Exception as e:
        return render_index_page(error_message=f"Удаление узла: {e}")


@bp.route("/server/cascade/sync-now", methods=["POST"])
@requires_auth
def server_cascade_sync_now_handler():
    try:
        cascade_sync_users_best_effort("manual_sync_ui")
        return render_index_page(ok_message="Синхронизация каскада запущена")
    except Exception as e:
        return render_index_page(error_message=f"Синхронизация каскада: {e}")


@bp.route("/server/cascade/pool-all-exits", methods=["POST"])
@requires_auth
def server_cascade_pool_all_exits_handler():
    """Помечает cascade_exit для всех включённых узлов с ролью из CASCADE_EXIT_POOL_ROLES."""
    pool_roles = _cascade_exit_pool_roles_set()
    try:
        db = _load_cascade_db()
        servers = db.get("servers") or []
        n_on = 0
        n_off = 0
        for item in servers:
            if not isinstance(item, dict):
                continue
            role_norm = str(item.get("role", "")).strip().lower() or "exit"
            if role_norm not in pool_roles:
                continue
            if item.get("enabled", True):
                item["cascade_exit"] = True
                n_on += 1
            else:
                item["cascade_exit"] = False
                n_off += 1
        db["servers"] = servers
        _save_cascade_db(db)
        cascade_sync_users_best_effort("pool_all_exits_ui")

        roles_txt = ", ".join(sorted(pool_roles))
        head = (
            f"Пул exit: роли «{roles_txt}» — cascade_exit включён у {n_on} активных узл."
            + (f" Снят с {n_off} выключенных." if n_off else "")
        )
        try:
            sb_msg = apply_cascade_singbox_outbounds()
        except Exception as e:
            sb_msg = f" Sing-box: не обновлён ({e}). Нажмите «Применить к sing-box»."
        return render_index_page(ok_message=head + " " + sb_msg)
    except Exception as e:
        return render_index_page(error_message=f"Пул exit каскада: {e}")


@bp.route("/server/cascade/hop", methods=["POST"])
@requires_auth
def server_cascade_hop_handler():
    node_id = (request.form.get("node_id") or "").strip()
    hy2_server = (request.form.get("hy2_server") or "").strip()
    hy2_sni = (request.form.get("hy2_sni") or "").strip()
    hop_username = (request.form.get("hop_username") or "").strip()
    hop_password = (request.form.get("hop_password") or "").strip()
    hy2_insecure = (request.form.get("hy2_insecure") or "") in {"1", "on", "true", "yes"}
    hy2_port_raw = (request.form.get("hy2_port") or "").strip()
    try:
        if not node_id:
            raise ValueError("node_id не передан")
        try:
            hy2_port = int(hy2_port_raw) if hy2_port_raw else 443
        except ValueError:
            raise ValueError("Некорректный HY2 порт") from None
        if hy2_port <= 0 or hy2_port > 65535:
            raise ValueError("HY2 порт вне диапазона 1–65535")

        db = _load_cascade_db()
        servers = db.get("servers") or []
        hit = None
        for item in servers:
            if isinstance(item, dict) and str(item.get("node_id")) == node_id:
                hit = item
                break
        if not isinstance(hit, dict):
            raise ValueError("Узел не найден")

        if hy2_server:
            hit["hy2_server"] = hy2_server
        hop_host = _get_cascade_hy2_host(hit)
        if not hop_host:
            raise ValueError("Укажите адрес HY2 (хост или IP) для выхода на этот узел")

        hit["hy2_port"] = hy2_port
        hit["hy2_sni"] = hy2_sni
        hit["hop_username"] = hop_username
        if hop_password:
            hit["hop_password"] = hop_password
        elif not str(hit.get("hop_password") or "").strip():
            raise ValueError("Укажите пароль hop (тот же учётка должна существовать на exit после синхронизации)")
        hit["hy2_insecure"] = hy2_insecure

        db["servers"] = servers
        _save_cascade_db(db)
        return render_index_page(ok_message=f"Hop для узла {hit.get('name') or node_id} сохранён. При необходимости нажмите «Записать outbounds в sing-box».")
    except Exception as e:
        return render_index_page(error_message=f"Каскад hop: {e}")


@bp.route("/server/cascade/apply-singbox", methods=["POST"])
@requires_auth
def server_cascade_apply_singbox_handler():
    mode_raw = (request.form.get("singbox_lb_mode") or "").strip().lower()
    try:
        db = _load_cascade_db()
        if mode_raw in ("single", "singleurl", "single_url", "one", "first"):
            db["singbox_lb_mode"] = "single"
        elif mode_raw in (
            "urltest",
            "url_test",
            "latency",
            "lat",
            "round_robin",
            "rr",
            "balance",
            "roundrobin",
        ):
            db["singbox_lb_mode"] = "urltest"
        else:
            db["singbox_lb_mode"] = _get_singbox_lb_mode_from_db(db)
        _save_cascade_db(db)
        msg = apply_cascade_singbox_outbounds(lb_mode=str(db.get("singbox_lb_mode") or "urltest"))
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=f"Sing-box каскад: {e}")


@bp.route("/server/direct-routing", methods=["POST"])
@requires_auth
def server_direct_routing_handler():
    explicit_json_raw = (request.form.get("direct_explicit_domains_json") or "").strip()
    suffixes_raw = ""
    enable_geoip_ru = (request.form.get("direct_geoip_ru") or "") in {"1", "on", "true", "yes"}
    enable_default = (request.form.get("direct_default_enabled") or "") in {"1", "on", "true", "yes"}
    default_outbound_tag = (request.form.get("direct_default_outbound_tag") or "").strip()
    # Выбран тег, но галочку забыли: иначе в JSON не попадает финальное правило и весь «прочий»
    # трафик уходит в поведение sing-box по умолчанию (часто direct, IP шлюза).
    if default_outbound_tag and not enable_default:
        enable_default = True
    explicit_hosts: list[str] = []
    try:
        default_note = ""
        if explicit_json_raw:
            try:
                parsed = json.loads(explicit_json_raw)
            except json.JSONDecodeError as e:
                raise ValueError("Некорректный JSON списка доменов") from e
            if not isinstance(parsed, list):
                raise ValueError("Список доменов должен быть JSON-массивом")
            for item in parsed:
                hn = str(item).strip().lower().rstrip(".")
                if hn:
                    explicit_hosts.append(hn)
            seen_h: set[str] = set()
            deduped_h: list[str] = []
            for h in explicit_hosts:
                if h not in seen_h:
                    seen_h.add(h)
                    deduped_h.append(h)
            explicit_hosts = deduped_h
        else:
            explicit_hosts = _split_tokens(request.form.get("direct_explicit_hosts", ""))
        ru_suffixes = _direct_ru_suffixes_from_form()
        suffixes_raw = "\n".join(ru_suffixes)
        for h in explicit_hosts:
            if not _valid_direct_explicit_hostname(h):
                raise ValueError(f"Недопустимое имя хоста: {h}")
        state = read_direct_routing_state()
        available_tags = [str(x) for x in state.get("outbound_tags", []) if isinstance(x, str)]
        if enable_default:
            if not default_outbound_tag:
                remembered_tag = str(state.get("default_outbound_tag") or "").strip()
                if remembered_tag:
                    default_outbound_tag = remembered_tag
                    default_note = f" Использован текущий default outbound: {default_outbound_tag}."
                elif available_tags:
                    default_outbound_tag = available_tags[0]
                    default_note = f" Автоматически выбран default outbound: {default_outbound_tag}."
                else:
                    # sing-box может быть отключен/не настроен на этом узле:
                    # сохраняем остальные правила, но default outbound не включаем.
                    enable_default = False
                    default_note = " Default outbound отключен: не найдено доступных outbound-тегов."
            if available_tags and default_outbound_tag not in available_tags:
                raise ValueError(f"Тег не найден в sing-box: {default_outbound_tag}")
        last_resolved: dict[str, list[str]] = {}
        resolve_errors: dict[str, str] = {}
        merged_cidrs: list[str] = []
        seen_c: set[str] = set()
        for d in explicit_hosts:
            cidrs, err = resolve_domain_to_ip_cidrs(d)
            last_resolved[d] = cidrs
            if err:
                resolve_errors[d] = err
            for c in cidrs:
                if c not in seen_c:
                    seen_c.add(c)
                    merged_cidrs.append(c)
        save_direct_explicit_store(
            domains=explicit_hosts,
            last_resolved=last_resolved,
            resolve_errors=resolve_errors,
        )
        apply_direct_routing_rules(
            explicit_hosts=explicit_hosts,
            explicit_ip_cidrs=merged_cidrs,
            whitelist_hosts=list(load_direct_whitelist_store()["domains"]),
            whitelist_ip_cidrs=_whitelist_merged_ip_cidrs(load_direct_whitelist_store()),
            ru_suffixes=ru_suffixes,
            enable_geoip_ru=enable_geoip_ru,
            enable_default_outbound=enable_default,
            default_outbound_tag=default_outbound_tag,
        )
        if resolve_errors:
            default_note += (
                " DNS: не удалось разрешить "
                + ", ".join(sorted(resolve_errors.keys()))
                + " (правила по IP для них не добавлены)."
            )
        sing_active = subprocess.run(
            ["systemctl", "is-active", "sing-box"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        restart_note = ""
        if sing_active.returncode == 0 and sing_active.stdout.strip() == "active":
            ok_rb, st_rb = _schedule_sing_box_restart()
            restart_note = _sing_box_restart_phrase(ok_rb, st_rb, inline=True)
        msg = f"Direct routing правила сохранены{restart_note}{default_note}"
        return render_index_page(ok_message=msg)
    except Exception as e:
        err_domains_json = explicit_json_raw
        if not err_domains_json and explicit_hosts:
            err_domains_json = json.dumps(explicit_hosts, ensure_ascii=False)
        return render_index_page(
            defaults={
                "direct_explicit_domains_json": err_domains_json,
                "direct_ru_suffixes": suffixes_raw,
                "direct_geoip_ru": "1" if enable_geoip_ru else "",
                "direct_default_enabled": "1" if enable_default else "",
                "direct_default_outbound_tag": default_outbound_tag,
            },
            error_message=f"Direct routing: {e}",
        )


@bp.route("/server/direct-routing/whitelist-sync", methods=["POST"])
@requires_auth
def server_direct_routing_whitelist_sync_handler():
    try:
        store = load_direct_whitelist_store()
        first = not bool(store.get("synced_at"))
        started = _start_github_whitelist_sync_thread(first_sync=first)
        if not started:
            return render_index_page(ok_message="Синхронизация GitHub whitelist уже выполняется.")
        note = (
            "Синхронизация GitHub whitelist запущена (DNS и правила direct). "
            "Обновите страницу через минуту."
        )
        if first:
            note += " Автообновление раз в сутки включено — можно отключить кнопкой ⟳."
        return render_index_page(ok_message=note)
    except Exception as e:
        return render_index_page(error_message=f"GitHub whitelist: {e}")


@bp.route("/server/direct-routing/whitelist-auto", methods=["POST"])
@requires_auth
def server_direct_routing_whitelist_auto_handler():
    try:
        store = load_direct_whitelist_store()
        if not store.get("synced_at"):
            raise ValueError("Сначала выполните синхронизацию с GitHub")
        enable = (request.form.get("whitelist_auto_sync") or "") in {"1", "on", "true", "yes"}
        store["auto_sync_enabled"] = enable
        save_direct_whitelist_store(store)
        if enable:
            msg = "Автообновление GitHub whitelist включено (раз в сутки)."
        else:
            msg = "Автообновление GitHub whitelist отключено."
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=f"GitHub whitelist: {e}")


@bp.route("/server/panel-timezone", methods=["POST"])
@requires_auth
def server_panel_timezone_handler():
    tz = request.form.get("panel_timezone", "").strip()
    try:
        if tz not in PANEL_TIMEZONE_OPTIONS:
            raise ValueError("Недопустимый часовой пояс")
        update_env_keys({"PANEL_TIMEZONE": tz})
        return render_index_page(ok_message=f"Часовой пояс панели: {tz}")
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/server/exclusions", methods=["POST"])
@requires_auth
def server_exclusions_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
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


@bp.route("/server/blacklist/add", methods=["POST"])
@requires_auth
def server_blacklist_add_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
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


@bp.route("/server/blacklist/remove", methods=["POST"])
@requires_auth
def server_blacklist_remove_handler():
    blocked = reject_sing_box_mutations()
    if blocked is not None:
        return blocked
    raw = request.form.get("blacklist_ip_remove", "")
    try:
        ip = parse_single_ip(raw)
        unbanned = unban_ip_in_all_jails(ip)
        if unbanned == 0:
            raise ValueError(f"IP {ip} не найден в черном списке")
        return render_index_page(ok_message=f"IP удален из черного списка: {ip}")
    except Exception as e:
        return render_index_page(defaults={"blacklist_ip_remove": raw}, error_message=str(e))


@bp.route("/server/https-stub/apply", methods=["POST"])
@requires_auth
def server_https_stub_apply_handler():
    raw = request.form.get("https_stub_html", "")
    if not isinstance(raw, str):
        raw = ""
    try:
        write_https_root_stub_atomic(raw)
        nchars = len(raw)
        nbytes = len(raw.encode("utf-8"))
        return render_index_page(
            ok_message=(
                f"Заглушка сохранена: {https_root_stub_html_path()} "
                f"({nchars} символов, {nbytes} байт UTF-8). Откройте сайт с полным обновлением (Ctrl+F5)."
            )
        )
    except Exception as e:
        return render_index_page(defaults={"https_stub_html": raw}, error_message=str(e))


@bp.route("/server/https-stub/revert", methods=["POST"])
@requires_auth
def server_https_stub_revert_handler():
    try:
        write_https_root_stub_atomic(bundled_default_https_root_stub_html())
        return render_index_page(
            ok_message="Восстановлена исходная заглушка (как tools/https-root-stub/index.html, зашита в код панели)."
        )
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/logs/search", methods=["POST"])
@requires_auth
def logs_search_handler():
    service = request.form.get("logs_service", "both").strip().lower()
    level = request.form.get("logs_level", "all").strip().lower()
    username = request.form.get("logs_username", "").strip()
    query = request.form.get("logs_query", "").strip()
    since_raw = request.form.get("logs_since_minutes", "")
    limit_raw = request.form.get("logs_limit", "")
    try:
        since_minutes = parse_log_int(since_raw, default=180, min_v=5, max_v=10080)
        limit = parse_log_int(limit_raw, default=200, min_v=20, max_v=2000)
        logs_data = read_diagnostic_logs(
            service=service,
            username=username,
            query=query,
            level=level,
            since_minutes=since_minutes,
            limit=limit,
        )
        return render_index_page(
            defaults={
                "logs_service": logs_data["service"],
                "logs_level": logs_data["level"],
                "logs_username": username,
                "logs_query": query,
                "logs_since_minutes": str(since_minutes),
                "logs_limit": str(limit),
            },
            logs_data=logs_data,
        )
    except Exception as e:
        return render_index_page(
            defaults={
                "logs_service": service,
                "logs_level": level,
                "logs_username": username,
                "logs_query": query,
                "logs_since_minutes": since_raw,
                "logs_limit": limit_raw,
            },
            error_message=str(e),
        )


@bp.route("/api/live", methods=["GET"])
@requires_auth
def api_live_handler():
    if is_sing_box_readonly_panel():
        payload = {
            "panel_backend": "sing-box",
            "stats": {
                "sum_rx_h": "0 B",
                "sum_tx_h": "0 B",
                "sum_total_h": "0 B",
                "online_users": 0,
                "online_connections": 0,
                "rate_download_h": "—",
                "rate_upload_h": "—",
                "gateway_traffic_note": "",
            },
            "users": {},
        }
        return Response(json.dumps(payload, ensure_ascii=False), mimetype="application/json")

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
    rate_up_h, rate_down_h = "—", "—"
    if stats.get("enabled"):
        sum_rx = int(stats.get("sum_rx", 0) or 0)
        sum_tx = int(stats.get("sum_tx", 0) or 0)
        # RX = от клиентов к серверу (отдача абонентов), TX = к клиентам (скачивание абонентов)
        rate_up_h, rate_down_h = hy2_aggregate_throughput_labels(sum_rx, sum_tx)

    payload = {
        "panel_backend": "hysteria",
        "stats": {
            "sum_rx_h": stats.get("sum_rx_h", "0 B"),
            "sum_tx_h": stats.get("sum_tx_h", "0 B"),
            "sum_total_h": stats.get("sum_total_h", "0 B"),
            "online_users": int(stats.get("online_users", 0) or 0),
            "online_connections": int(stats.get("online_connections", 0) or 0),
            "rate_download_h": rate_down_h,
            "rate_upload_h": rate_up_h,
            "gateway_traffic_note": str(stats.get("gateway_traffic_note", "")),
        },
        "users": users,
    }
    return Response(json.dumps(payload, ensure_ascii=False), mimetype="application/json")


@bp.route("/api/server/direct-routing-explicit", methods=["GET"])
@requires_auth
def api_direct_routing_explicit_state_handler():
    state = read_direct_routing_state()
    payload = {
        "explicit_domains_list": state.get("explicit_domains_list", []),
        "explicit_domains_detail": state.get("explicit_domains_detail", []),
    }
    return Response(json.dumps(payload, ensure_ascii=False), mimetype="application/json")


@bp.route("/api/server/direct-routing-whitelist", methods=["GET"])
@requires_auth
def api_direct_routing_whitelist_state_handler():
    store = load_direct_whitelist_store()
    payload = {
        "synced": bool(store.get("synced_at")),
        "domains_count": len(store.get("domains") or []),
        "ip_count": len(_whitelist_merged_ip_cidrs(store)),
        "auto_sync_enabled": bool(store.get("auto_sync_enabled")),
        "synced_at": str(store.get("synced_at") or ""),
        "last_sync_at": str(store.get("last_sync_at") or ""),
        "sync_status": str(store.get("sync_status") or "idle"),
        "sync_error": str(store.get("sync_error") or ""),
        "source_url": str(store.get("source_url") or GITHUB_WHITELIST_RAW_URL),
        "domains_detail": _whitelist_domains_detail(store),
    }
    return Response(json.dumps(payload, ensure_ascii=False), mimetype="application/json")


if PANEL_URL_PREFIX:
    app.register_blueprint(bp, url_prefix=PANEL_URL_PREFIX)
else:
    app.register_blueprint(bp)


if INSECURE_DEBUG_STRIP_PREFIX:

    class _StripNginxPanelPrefix:
        __slots__ = ("_app", "_prefix")

        def __init__(self, application, prefix: str):
            self._app = application
            self._prefix = prefix.rstrip("/")

        def __call__(self, environ, start_response):
            path = environ.get("PATH_INFO") or ""
            p = self._prefix
            if p and (path == p or path.startswith(p + "/")):
                script = environ.get("SCRIPT_NAME") or ""
                environ["SCRIPT_NAME"] = script + p
                environ["PATH_INFO"] = path[len(p):] or "/"
            return self._app(environ, start_response)

    app.wsgi_app = _StripNginxPanelPrefix(app.wsgi_app, INSECURE_DEBUG_STRIP_PREFIX)  # type: ignore[method-assign]

_start_whitelist_background_tasks()

if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT)

