import base64
import hashlib
import html
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import sys
import subprocess
import tempfile
import threading
import time
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
BIND_PORT = int(ENV.get("PANEL_BIND_PORT", "8787"))
PANEL_SYSTEMD_SERVICE = ENV.get("PANEL_SYSTEMD_SERVICE", "hy2-admin.service").strip() or "hy2-admin.service"
PROTECTED_USERS_RAW = ENV.get("PROTECTED_USERS", "")
SING_BOX_CONFIG_PATH = ENV.get("SING_BOX_CONFIG_PATH", "/etc/sing-box/config.json")

REGISTRY_PATH = Path("/opt/hy2-admin/data/clients.json")
BACKUP_DIR = Path("/opt/hy2-admin/backups")
STATE_PATH = Path("/opt/hy2-admin/data/user_state.json")
META_PATH = Path("/opt/hy2-admin/data/users_meta.json")
TRAFFIC_STATE_PATH = Path("/opt/hy2-admin/data/traffic_state.json")
USER_NOTES_PATH = Path("/opt/hy2-admin/data/user_notes.json")
USER_IP_STATE_PATH = Path("/opt/hy2-admin/data/user_ip_state.json")
WHITELIST_STATE_PATH = Path("/opt/hy2-admin/data/russia-whitelist/state.json")
WHITELIST_SYNC_SCRIPT = Path("/opt/hy2-admin/whitelist_sync.py")


def _app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", ""))
    return Path(__file__).resolve().parent


def _whitelist_python() -> Path:
    explicit = (ENV.get("WHITELIST_PYTHON") or "").strip()
    if explicit:
        return Path(explicit)
    venv_py = Path("/opt/hy2-admin/.venv/bin/python")
    if venv_py.is_file():
        return venv_py
    return Path("/usr/bin/python3")


WHITELIST_PYTHON = _whitelist_python()
F2B_JAIL_PATH = Path("/etc/fail2ban/jail.d/hy2-admin.local")
# HTML для HTTPS-заглушки (например корень msgw.mooo.com). Переопределение: HTTPS_ROOT_STUB_HTML_PATH в .env
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


# Эталон HTTPS-заглушки: tools/msgw-https-root-stub/index.html (для «Вернуть исходное»). При правке файла пересоберите base64 в эту константу.
_DEFAULT_MSGW_HTTPS_ROOT_STUB_B64 = (
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
    # Как в tools/msgw.mooo.com.nginx.conf: location / { root /var/www/msgw-https-root; ... }
    return Path("/var/www/msgw-https-root/index.html")


def bundled_default_https_root_stub_html() -> str:
    """Эталонная заглушка msgw.mooo.com (canvas), зашита в код панели — «Вернуть исходное» (как tools/msgw-https-root-stub/index.html)."""
    return base64.b64decode(_DEFAULT_MSGW_HTTPS_ROOT_STUB_B64).decode("utf-8")

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
        return f"Пароль пользователя {username} обновлен (рандомный)"

    rec = disabled.get(username)
    if isinstance(rec, dict):
        rec["password"] = new_pass
        disabled[username] = rec
        save_user_state(state)
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
    }


def read_whitelist_sync_state() -> dict:
    if not WHITELIST_STATE_PATH.exists():
        return {}
    try:
        return json.loads(WHITELIST_STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


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
    ws = read_whitelist_sync_state()
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
        whitelist_sync=ws,
        whitelist_last_sync_display=format_whitelist_last_sync_display(ws.get("last_run_utc"), ptz),
        panel_timezone=ptz,
        panel_timezone_options=PANEL_TIMEZONE_OPTIONS,
        panel_backend=panel_backend,
        sing_box_summary=sing_box_summary,
        ui_shell_only=ui_shell_only,
        https_stub=build_https_stub_panel_view(merged_defaults),
        panel_url_prefix_display=get_live_effective_panel_url_prefix(),
        panel_insecure_debug_strip_prefix=INSECURE_DEBUG_STRIP_PREFIX,
        panel_systemd_service=PANEL_SYSTEMD_SERVICE,
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


@bp.route("/server/whitelist-sync", methods=["POST"])
@requires_auth
def server_whitelist_sync_handler():
    try:
        if not WHITELIST_SYNC_SCRIPT.is_file():
            raise RuntimeError("Скрипт whitelist_sync.py не найден")
        if not WHITELIST_PYTHON.is_file():
            raise RuntimeError("Интерпретатор Python для whitelist не найден")
        r = subprocess.run(
            [str(WHITELIST_PYTHON), str(WHITELIST_SYNC_SCRIPT)],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(WHITELIST_SYNC_SCRIPT.parent),
        )
        if r.returncode != 0:
            err = (r.stderr or r.stdout or "").strip() or f"код {r.returncode}"
            return render_index_page(error_message=f"Whitelist: {err}")
        return render_index_page(ok_message="Списки обновлены (проверка выполнена).")
    except subprocess.TimeoutExpired:
        return render_index_page(error_message="Whitelist: таймаут загрузки")
    except Exception as e:
        return render_index_page(error_message=str(e))


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
            ok_message="Восстановлена исходная заглушка (как tools/msgw-https-root-stub/index.html, зашита в код панели)."
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
        },
        "users": users,
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


if __name__ == "__main__":
    app.run(host=BIND_HOST, port=BIND_PORT)

