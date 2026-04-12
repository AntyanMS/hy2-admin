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
# Секретный префикс URL панели, например /a1b2c3d4.../panel (без хвостового /)
PANEL_URL_PREFIX=""

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
  # Не использовать `tr | head`: при `set -o pipefail` head закрывает pipe → SIGPIPE (141) и установка падает.
  openssl rand -hex 12
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
  PANEL_URL_PREFIX="/$(openssl rand -hex 16)/panel"
  ENABLE_AUTOSTART="y"
  START_NOW="y"
  WHITELIST_SYNC_SCHEDULE="${WHITELIST_SYNC_SCHEDULE:-daily}"
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

  echo ""
  echo "Секретный путь панели (не светить в открытом виде): https://<домен>/<slug>/panel/"
  read -r -p "Slug пути: 1) случайный  2) свой [1]: " slug_mode
  slug_mode="${slug_mode:-1}"
  if [[ "${slug_mode}" == "2" ]]; then
    read -r -p "Slug (только a-z A-Z 0-9 _ -): " custom_slug
    custom_slug="$(echo "${custom_slug}" | tr -d '/' | tr -d ' ')"
    if [[ -z "${custom_slug}" ]]; then
      echo "Пустой slug — генерируем случайный." >&2
      PANEL_URL_PREFIX="/$(openssl rand -hex 16)/panel"
    elif [[ "${custom_slug}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      PANEL_URL_PREFIX="/${custom_slug}/panel"
    else
      echo "Недопустимые символы — случайный slug." >&2
      PANEL_URL_PREFIX="/$(openssl rand -hex 16)/panel"
    fi
  else
    PANEL_URL_PREFIX="/$(openssl rand -hex 16)/panel"
  fi
}

install_packages() {
  apt-get update -y
  apt-get install -y python3 python3-venv python3-pip curl openssl fail2ban
  if [[ "${APP_SCHEME}" == "https" && "${USE_CERTBOT}" == "y" ]]; then
    apt-get install -y certbot
  fi
}

# fail2ban: сравнение SHA256 желаемого содержимого с файлом на диске.
# Совпадает — пропуск. Отличается — копия в path.bak.YYYYMMDD_HHMMSS, затем запись нового файла.
f2b_install_or_skip() {
  local path="$1"
  local tmp
  tmp="$(mktemp)"
  cat > "${tmp}"
  mkdir -p "$(dirname "${path}")"
  local want cur
  want="$(sha256sum "${tmp}" | awk '{print $1}')"
  if [[ -f "${path}" ]]; then
    cur="$(sha256sum "${path}" | awk '{print $1}')"
    if [[ "${cur}" == "${want}" ]]; then
      rm -f "${tmp}"
      echo "[hy2-admin install] fail2ban: без изменений (SHA256 совпадает): ${path}"
      return 0
    fi
    local bak="${path}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -a "${path}" "${bak}"
    echo "[hy2-admin install] fail2ban: резервная копия ${path} -> ${bak}"
  fi
  install -m 0644 "${tmp}" "${path}"
  rm -f "${tmp}"
  echo "[hy2-admin install] fail2ban: записан ${path}"
}

setup_fail2ban() {
  echo "[hy2-admin install] Настройка fail2ban для панели..."
  mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d

  f2b_install_or_skip /etc/fail2ban/filter.d/hy2-admin-auth.conf <<'F2BFILTER'
[Definition]
failregex = ^.*<HOST>.*"(GET|POST|HEAD).*(HTTP/1\.[01]|HTTP/2(\.0)?)" 401 .*$
ignoreregex =
F2BFILTER

  f2b_install_or_skip /etc/fail2ban/jail.d/hy2-admin.local <<F2BJAIL
[DEFAULT]
ignoreip = 127.0.0.0/8 ::1 77.220.143.56 94.159.40.2 185.239.48.216 185.239.49.36

[hy2-admin-auth]
enabled = true
port = ${APP_PORT}
protocol = tcp
backend = systemd
journalmatch = _SYSTEMD_UNIT=${SERVICE_NAME}
filter = hy2-admin-auth
maxretry = 6
findtime = 10m
bantime = 2h
F2BJAIL

  f2b_install_or_skip /etc/fail2ban/jail.d/sshd-permanent-3.local <<'F2BSSH'
[sshd]
enabled = true
maxretry = 3
findtime = 10m
bantime = -1
F2BSSH

  systemctl enable fail2ban 2>/dev/null || true
  systemctl restart fail2ban
  sleep 2
  fail2ban-client reload 2>/dev/null || true
}

prepare_files() {
  mkdir -p "${INSTALL_DIR}/templates" "${INSTALL_DIR}/data" "${INSTALL_DIR}/data/russia-whitelist" "${INSTALL_DIR}/backups" "${INSTALL_DIR}/tls"

  cat > "${INSTALL_DIR}/whitelist_sync.py" <<'WHLSYNC'
#!/usr/bin/env python3
"""Скачивание hxehex/russia-mobile-internet-whitelist и сопоставление с прошлым запуском + проверка IP сервера.

Не изменяет конфиг Hysteria2, userpass, /opt/hy2-admin/data/user_state.json, users_meta.json,
clients.json и прочие файлы пользователей/лимитов — только каталог data/russia-whitelist/.
При ошибке загрузки любого из трёх файлов предыдущие копии списков на диске остаются без изменений.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
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
WHLSYNC
  chmod 755 "${INSTALL_DIR}/whitelist_sync.py"

  cat > "${INSTALL_DIR}/requirements.txt" <<'EOF'
Flask==3.0.3
PyYAML==6.0.2
qrcode[pil]==7.4.2
gunicorn==22.0.0
EOF

  cat > "${INSTALL_DIR}/app.py" <<'PYAPP'
import hashlib
import html
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from typing import Optional
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.parse import quote

import qrcode
import yaml
from flask import Blueprint, Flask, Response, render_template, request


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
PROTECTED_USERS_RAW = ENV.get("PROTECTED_USERS", "")

REGISTRY_PATH = Path("/opt/hy2-admin/data/clients.json")
BACKUP_DIR = Path("/opt/hy2-admin/backups")
STATE_PATH = Path("/opt/hy2-admin/data/user_state.json")
META_PATH = Path("/opt/hy2-admin/data/users_meta.json")
TRAFFIC_STATE_PATH = Path("/opt/hy2-admin/data/traffic_state.json")
USER_NOTES_PATH = Path("/opt/hy2-admin/data/user_notes.json")
USER_IP_STATE_PATH = Path("/opt/hy2-admin/data/user_ip_state.json")
WHITELIST_STATE_PATH = Path("/opt/hy2-admin/data/russia-whitelist/state.json")
WHITELIST_SYNC_SCRIPT = Path("/opt/hy2-admin/whitelist_sync.py")
WHITELIST_VENV_PYTHON = Path("/opt/hy2-admin/.venv/bin/python")
F2B_JAIL_PATH = Path("/etc/fail2ban/jail.d/hy2-admin.local")
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

app = Flask(__name__)


def _normalize_panel_prefix(raw: Optional[str]) -> str:
    """Пусто = корень (совместимость со старыми установками). Иначе /slug/... без завершающего /."""
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    if not s.startswith("/"):
        s = "/" + s
    s = s.rstrip("/")
    parts = [p for p in s.split("/") if p]
    for p in parts:
        if not re.match(r"^[a-zA-Z0-9_-]+$", p):
            raise ValueError(f"Недопустимый сегмент пути панели: {p}")
    return "/" + "/".join(parts) if parts else ""


try:
    PANEL_URL_PREFIX = _normalize_panel_prefix(ENV.get("PANEL_URL_PREFIX"))
except ValueError:
    PANEL_URL_PREFIX = ""

bp = Blueprint("hy2", __name__)


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


def unauthorized() -> Response:
    return Response("Unauthorized", 401, {"WWW-Authenticate": 'Basic realm="HY2 Admin"'})


def requires_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user, pw = get_panel_credentials()
        if not pw:
            return Response("PANEL_BASIC_PASS is not configured", status=500)

        auth = request.authorization
        if not auth:
            return unauthorized()

        user_ok = secrets.compare_digest(auth.username or "", user)
        pass_ok = secrets.compare_digest(auth.password or "", pw)
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
    active_users, disabled_users, stats = build_users_view()
    cfg = load_hy2_config()
    merged_defaults = base_defaults()
    if isinstance(defaults, dict):
        merged_defaults.update(defaults)
    ws = read_whitelist_sync_state()
    ptz = get_panel_timezone()
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
    )


@bp.route("/", methods=["GET"])
@requires_auth
def index():
    return render_index_page()


@bp.route("/apply", methods=["POST"])
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
    username = request.form.get("username", "").strip()
    try:
        msg = reset_user_password_random(username)
        return render_index_page(ok_message=msg)
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/users/delete", methods=["POST"])
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


@bp.route("/users/limits", methods=["POST"])
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


@bp.route("/users/note", methods=["POST"])
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


@bp.route("/server/bandwidth", methods=["POST"])
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
        return render_index_page(
            ok_message="Логин и пароль панели сохранены в .env. Браузер запросит вход заново — используйте новые данные."
        )
    except Exception as e:
        return render_index_page(error_message=str(e))


@bp.route("/server/whitelist-sync", methods=["POST"])
@requires_auth
def server_whitelist_sync_handler():
    try:
        if not WHITELIST_SYNC_SCRIPT.is_file():
            raise RuntimeError("Скрипт whitelist_sync.py не найден")
        if not WHITELIST_VENV_PYTHON.is_file():
            raise RuntimeError("Интерпретатор .venv не найден")
        r = subprocess.run(
            [str(WHITELIST_VENV_PYTHON), str(WHITELIST_SYNC_SCRIPT)],
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
    raw = request.form.get("blacklist_ip_remove", "")
    try:
        ip = parse_single_ip(raw)
        unbanned = unban_ip_in_all_jails(ip)
        if unbanned == 0:
            raise ValueError(f"IP {ip} не найден в черном списке")
        return render_index_page(ok_message=f"IP удален из черного списка: {ip}")
    except Exception as e:
        return render_index_page(defaults={"blacklist_ip_remove": raw}, error_message=str(e))


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


if PANEL_URL_PREFIX:
    app.register_blueprint(bp, url_prefix=PANEL_URL_PREFIX)
else:
    app.register_blueprint(bp)


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
    body { font-family: Arial, sans-serif; margin: 16px; background: rgba(15, 17, 21, 0.9); color: var(--text); }
    #bg-canvas {
      position: fixed;
      inset: 0;
      width: 100%;
      height: 100%;
      z-index: 0;
      pointer-events: none;
    }
    body > * { position: relative; z-index: 1; }
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
    .wl-block { margin: 8px 0 12px; }
    .wl-line { display: flex; align-items: center; gap: 10px; margin: 8px 0; flex-wrap: wrap; }
    .wl-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
    .wl-dot.wl-ok { background: #22c55e; box-shadow: 0 0 6px rgba(34,197,94,0.45); }
    .wl-dot.wl-no { background: #6b7280; }
    .wl-name { flex: 1; min-width: 140px; font-size: 0.95rem; }
    .wl-check-form { margin: 0; }
    .wl-check-form button { padding: 4px 12px; font-size: 0.85rem; }
    .wl-tz-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin: 10px 0 8px; font-size: 0.9rem; }
    .wl-tz-row select { padding: 6px 8px; border-radius: 6px; background: var(--bg-soft); color: inherit; border: 1px solid var(--border); min-width: 200px; }
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
    .user-ip-line { margin: 6px 0 0; font-size: 12px; color: var(--muted); word-break: break-word; }
    .user-note { margin-top: 8px; }
    .user-note textarea { min-height: 72px; }
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
    .blacklist-list { margin-top: 8px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
    .blacklist-row { display: grid; grid-template-columns: 1fr auto auto; gap: 8px; align-items: center; padding: 8px; border-top: 1px solid var(--border); }
    .blacklist-row:first-child { border-top: 0; }
    .blacklist-ip { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
    .blacklist-jails { font-size: 12px; color: var(--muted); }
    .danger-btn { background: #7f1d1d; }
    .danger-btn:hover { background: #991b1b; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
    .brand-link {
      display: inline-block;
      color: #dbeafe;
      text-decoration: none;
      padding: 8px 14px;
      border-radius: 12px;
      border: 1px solid rgba(96, 165, 250, 0.45);
      background: linear-gradient(135deg, rgba(30, 41, 59, 0.85), rgba(37, 99, 235, 0.2));
      box-shadow: 0 8px 24px rgba(15, 23, 42, 0.45), inset 0 0 0 1px rgba(255, 255, 255, 0.05);
      transition: transform 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .brand-link:hover {
      transform: translateY(-1px);
      border-color: rgba(147, 197, 253, 0.85);
      box-shadow: 0 10px 26px rgba(37, 99, 235, 0.28), inset 0 0 0 1px rgba(255, 255, 255, 0.08);
    }
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
    .logs-tools { display: grid; grid-template-columns: repeat(3, minmax(140px, 1fr)); gap: 8px; margin-top: 8px; }
    .logs-tools label { margin-top: 0; font-size: 12px; color: var(--muted); }
    .logs-output {
      width: 100%;
      min-height: 240px;
      white-space: pre;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      background: #0b0f1a;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      overflow: auto;
      line-height: 1.35;
    }
    .log-line { white-space: pre-wrap; word-break: break-word; margin: 0; }
    .log-level { color: #fbbf24; font-weight: 700; }
    .log-type { color: #93c5fd; font-weight: 600; }
    .log-ip { color: #34d399; }
    .log-user { color: #f9a8d4; font-weight: 600; }
    .log-error { color: #fca5a5; }
    #logs-modal { padding: 5vh 5vw; }
    #logs-modal .modal-card {
      width: 100%;
      height: 100%;
      max-height: none;
      display: flex;
      flex-direction: column;
    }
    #logs-modal .logs-output {
      flex: 1 1 auto;
      min-height: 0;
      height: 100%;
    }
  </style>
</head>
<body>
  <canvas id="bg-canvas" aria-hidden="true"></canvas>
  <div class="topbar">
    <h1><a href="{{ url_for('hy2.index') }}" class="brand-link">Hysteria2 Clients Admin</a></h1>
    <div style="display:flex; gap:8px; align-items:center;">
      <button id="open-logs-modal" type="button" class="secondary-btn">Логи</button>
      <button id="open-server-settings" type="button" class="secondary-btn">Настройки сервера</button>
    </div>
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
      <form method="post" action="{{ url_for('hy2.server_bandwidth_handler') }}">
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
      <hr style="border-color:#374151; opacity:.5; margin:10px 0;">
      <h3 style="margin:0 0 8px; font-size:1rem;">Белый список РФ (моб. интернет)</h3>
      {% set wlf = whitelist_sync.get('files') or {} %}
      <div class="wl-block">
        <div class="wl-line">
          <span class="wl-dot {% if wlf.get('whitelist.txt') %}wl-ok{% else %}wl-no{% endif %}" title="{% if wlf.get('whitelist.txt') %}есть актуальная копия{% else %}ещё не синхронизировано{% endif %}"></span>
          <span class="wl-name">Домены · whitelist.txt</span>
          <form class="wl-check-form" method="post" action="{{ url_for('hy2.server_whitelist_sync_handler') }}"><button type="submit" class="secondary-btn">Проверка</button></form>
        </div>
        <div class="wl-line">
          <span class="wl-dot {% if wlf.get('ipwhitelist.txt') %}wl-ok{% else %}wl-no{% endif %}" title="{% if wlf.get('ipwhitelist.txt') %}есть актуальная копия{% else %}ещё не синхронизировано{% endif %}"></span>
          <span class="wl-name">IP · ipwhitelist.txt</span>
          <form class="wl-check-form" method="post" action="{{ url_for('hy2.server_whitelist_sync_handler') }}"><button type="submit" class="secondary-btn">Проверка</button></form>
        </div>
        <div class="wl-line">
          <span class="wl-dot {% if wlf.get('cidrwhitelist.txt') %}wl-ok{% else %}wl-no{% endif %}" title="{% if wlf.get('cidrwhitelist.txt') %}есть актуальная копия{% else %}ещё не синхронизировано{% endif %}"></span>
          <span class="wl-name">Подсети · cidrwhitelist.txt</span>
          <form class="wl-check-form" method="post" action="{{ url_for('hy2.server_whitelist_sync_handler') }}"><button type="submit" class="secondary-btn">Проверка</button></form>
        </div>
      </div>
      <form method="post" action="{{ url_for('hy2.server_panel_timezone_handler') }}" class="wl-tz-row">
        <label class="muted" for="panel-timezone-select">Часовой пояс</label>
        <select id="panel-timezone-select" name="panel_timezone">
          {% for z in panel_timezone_options %}
          <option value="{{ z }}" {% if z == panel_timezone %}selected{% endif %}>{{ z }}</option>
          {% endfor %}
        </select>
        <button type="submit" class="secondary-btn">Сохранить</button>
      </form>
      {% if whitelist_last_sync_display %}
        <p class="muted" style="margin:0; font-size:0.8rem;">Последняя синхронизация: {{ whitelist_last_sync_display }}{% if whitelist_sync.get('server_ip_checked') %} · IP {{ whitelist_sync.server_ip_checked }}: ipwhitelist {% if whitelist_sync.server_ip_in_ipwhitelist %}да{% else %}нет{% endif %}, cidr {% if whitelist_sync.server_ip_in_cidr %}да{% else %}нет{% endif %}{% endif %}</p>
      {% else %}
        <p class="muted" style="margin:0; font-size:0.8rem;">Нажмите «Проверка» или дождитесь таймера.</p>
      {% endif %}
      <hr style="border-color:#374151; opacity:.5; margin:10px 0;">
      <h3 style="margin:0 0 8px; font-size:1rem;">Вход в панель (Basic Auth)</h3>
      <p class="muted" style="margin:0 0 10px;">Сейчас логин: <strong>{{ panel_login }}</strong>. Меняется запись в `/opt/hy2-admin/.env`.</p>
      <form method="post" action="{{ url_for('hy2.server_panel_auth_handler') }}" autocomplete="off">
        <div class="server-grid">
          <div>
            <label>Новый логин</label>
            <input type="text" name="panel_new_user" value="{{ panel_login }}" placeholder="admin" maxlength="64">
          </div>
          <div>
            <label>Текущий пароль</label>
            <input type="password" name="panel_current_password" required placeholder="обязательно">
          </div>
        </div>
        <div class="server-grid">
          <div>
            <label>Новый пароль (мин. 8 символов)</label>
            <input type="password" name="panel_new_password" placeholder="новый пароль" required minlength="8" autocomplete="new-password">
          </div>
          <div>
            <label>Повтор нового пароля</label>
            <input type="password" name="panel_new_password_confirm" placeholder="ещё раз" required minlength="8" autocomplete="new-password">
          </div>
        </div>
        <div class="actions"><button type="submit">Сохранить логин и пароль</button></div>
      </form>
      <hr style="border-color:#374151; opacity:.5; margin:10px 0;">
      <form method="post" action="{{ url_for('hy2.server_exclusions_handler') }}">
        <label>Исключения fail2ban (IP или CIDR, по одному в строке)</label>
        <textarea name="server_exclusions" rows="6" placeholder="77.220.143.56&#10;192.168.1.0/24">{{ defaults.server_exclusions or exclusions.text or '' }}</textarea>
        <div class="actions"><button type="submit">Применить исключения</button></div>
      </form>
      <p class="muted">Используется для `ignoreip` в fail2ban. Записи `127.0.0.0/8`, `::1` и фиксированные доверенные IP добавляются автоматически при сохранении (их нельзя отключить через форму).</p>
      <hr style="border-color:#374151; opacity:.5; margin:10px 0;">
      <form method="post" action="{{ url_for('hy2.server_blacklist_add_handler') }}">
        <label>Добавить IP в черный список fail2ban</label>
        <div class="server-grid">
          <div>
            <input name="blacklist_ip_add" value="{{ defaults.blacklist_ip_add or '' }}" placeholder="например 178.176.78.251">
          </div>
          <div class="actions" style="margin:0;">
            <button type="submit" class="danger-btn">Добавить в черный список</button>
          </div>
        </div>
      </form>
      <div class="blacklist-list">
        {% if blacklist.entries %}
          {% for item in blacklist.entries %}
            <div class="blacklist-row">
              <div class="blacklist-ip">{{ item.ip }}</div>
              <div class="blacklist-jails">{{ item.jails|join(', ') }}</div>
              <form method="post" action="{{ url_for('hy2.server_blacklist_remove_handler') }}" style="margin:0;">
                <input type="hidden" name="blacklist_ip_remove" value="{{ item.ip }}">
                <button type="submit" class="danger-btn">Удалить</button>
              </form>
            </div>
          {% endfor %}
        {% else %}
          <div class="blacklist-row">
            <div class="muted">Черный список пуст</div>
            <div></div>
            <div></div>
          </div>
        {% endif %}
      </div>
      {% if blacklist.error %}
        <p class="muted">Не удалось получить черный список: {{ blacklist.error }}</p>
      {% endif %}
    </div>
  </div>

  <div id="logs-modal" class="modal-backdrop" aria-hidden="true">
    <div class="modal-card">
      <div class="modal-head">
        <h2>Логи диагностики</h2>
        <button id="close-logs-modal" type="button" class="close-btn" title="Закрыть">×</button>
      </div>
      <form method="post" action="{{ url_for('hy2.logs_search_handler') }}">
        <div class="logs-tools">
          <div>
            <label>Сервис</label>
            <select name="logs_service">
              <option value="both" {% if (defaults.logs_service or 'both') == 'both' %}selected{% endif %}>Hysteria + Admin</option>
              <option value="hysteria" {% if defaults.logs_service == 'hysteria' %}selected{% endif %}>Только Hysteria</option>
              <option value="admin" {% if defaults.logs_service == 'admin' %}selected{% endif %}>Только Admin</option>
            </select>
          </div>
          <div>
            <label>Уровень</label>
            <select name="logs_level">
              <option value="all" {% if (defaults.logs_level or 'all') == 'all' %}selected{% endif %}>Все</option>
              <option value="info" {% if defaults.logs_level == 'info' %}selected{% endif %}>Info</option>
              <option value="warn" {% if defaults.logs_level == 'warn' %}selected{% endif %}>Warn</option>
              <option value="error" {% if defaults.logs_level == 'error' %}selected{% endif %}>Error</option>
            </select>
          </div>
          <div>
            <label>Пользователь (логин)</label>
            <input type="text" name="logs_username" value="{{ defaults.logs_username or '' }}" placeholder="например paullo_111">
          </div>
        </div>
        <div class="logs-tools">
          <div>
            <label>Поиск по тексту</label>
            <input type="text" name="logs_query" value="{{ defaults.logs_query or '' }}" placeholder="timeout, TLS, disconnected...">
          </div>
          <div>
            <label>Период (минут)</label>
            <input type="number" min="5" max="10080" name="logs_since_minutes" value="{{ defaults.logs_since_minutes or '180' }}">
          </div>
          <div>
            <label>Лимит строк</label>
            <input type="number" min="20" max="2000" name="logs_limit" value="{{ defaults.logs_limit or '200' }}">
          </div>
        </div>
        <div class="actions"><button type="submit">Показать логи</button></div>
      </form>
      {% if logs_data and logs_data.searched %}
        <p class="muted">Найдено: {{ logs_data.total }} | Показано: {{ logs_data.lines|length }}</p>
        <div class="logs-output">{% if logs_data.lines_html %}{% for line in logs_data.lines_html %}<div class="log-line">{{ line|safe }}</div>{% endfor %}{% else %}Нет совпадений по фильтрам.{% endif %}</div>
      {% else %}
        <p class="muted">Выберите фильтры и нажмите «Показать логи».</p>
      {% endif %}
    </div>
  </div>

  <form method="post" action="{{ url_for('hy2.apply_handler') }}">
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
            src="{{ url_for('hy2.qr_handler', u=item.url) }}"
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
    <form id="active-delete-form" method="post" action="{{ url_for('hy2.users_delete_handler') }}">
      <input type="hidden" name="scope" value="active">
      <button class="danger inline" type="submit" name="mode" value="selected">Удалить выбранных</button>
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
          <summary><span class="summary-name">{{ u.username }}{% if u.is_online %}<span class="status-dot online" data-user-dot="{{ u.username }}" title="Онлайн: {{ u.online_count }}"></span>{% else %}<span class="status-dot offline" data-user-dot="{{ u.username }}" title="Оффлайн"></span>{% endif %}{% if u.online_count and u.online_count > 1 %}<span class="conn-badge" data-user-online-count="{{ u.username }}" title="Одновременных подключений">x{{ u.online_count }}</span>{% else %}<span class="conn-badge" data-user-online-count="{{ u.username }}" style="display:none;"></span>{% endif %}<span class="summary-meta" data-user-meta="{{ u.username }}">↓ {{ u.rx_h }} | ↑ {{ u.tx_h }} | Σ {{ u.total_h }}</span></span><label class="summary-select" title="Выбрать для удаления"><input form="active-delete-form" type="checkbox" name="selected_users" value="{{ u.username }}"></label></summary>
          <div class="user-body">
            <form method="post" action="{{ url_for('hy2.users_toggle_handler') }}" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <input type="hidden" name="action" value="disable">
              <button type="submit">Временно отключить</button>
            </form>
            <form method="post" action="{{ url_for('hy2.users_password_random_handler') }}" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <button type="submit">Сменить пароль (рандом)</button>
            </form>
            <p class="user-stats">
              {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}Лимит трафика: {{ u.traffic_limit_h }}{% else %}Лимит трафика: нет{% endif %}
              | {% if u.duration_days %}Срок: {{ u.duration_days }} дн.{% else %}Срок: нет{% endif %}
              | {% if u.expires_at %}До: {{ u.expires_at[:10] }}{% else %}До даты: нет{% endif %}
              | {% if u.speed_up_mbps %}Up: {{ u.speed_up_mbps }} Mbps{% else %}Up: нет{% endif %}
              | {% if u.speed_down_mbps %}Down: {{ u.speed_down_mbps }} Mbps{% else %}Down: нет{% endif %}
              | {% if u.max_connections %}Подкл.: {{ u.max_connections }}{% else %}Подкл.: нет{% endif %}
            </p>
            <p class="user-ip-line">
              Сейчас IP:
              {% if u.current_ips %}{{ u.current_ips|join(', ') }}{% else %}нет данных{% endif %}
            </p>
            <p class="user-ip-line">
              История IP:
              {% if u.history_ips %}{{ u.history_ips|join(', ') }}{% else %}пока пусто{% endif %}
            </p>
            {% if u.last_seen_ip %}
              <p class="user-ip-line">Последний замеченный IP: {{ u.last_seen_ip }}{% if u.last_seen_ip_at %} ({{ u.last_seen_ip_at }}){% endif %}</p>
            {% endif %}
            {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}
              <p class="user-stats" data-user-limit-text="{{ u.username }}">Остаток: {{ u.traffic_remaining_h }}</p>
              <div class="limit-bar"><div class="limit-fill {% if u.traffic_usage_percent >= 100 %}danger{% elif u.traffic_usage_percent >= 90 %}warn{% endif %}" data-user-limit-bar="{{ u.username }}" style="width: {{ u.traffic_usage_percent }}%;"></div></div>
            {% endif %}
            <form method="post" action="{{ url_for('hy2.users_limits_handler') }}" class="edit-limits">
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
            <form method="post" action="{{ url_for('hy2.users_note_handler') }}" class="user-note">
              <input type="hidden" name="username" value="{{ u.username }}">
              <label>Заметки по пользователю</label>
              <textarea name="note" rows="3" placeholder="Любая информация о пользователе...">{{ u.note or '' }}</textarea>
              <div class="actions"><button type="submit">Сохранить заметку</button></div>
            </form>
            <p>
              <img
                class="qr-copy"
                src="{{ url_for('hy2.qr_handler', u=u.url) }}"
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
          <summary>{{ u.username }}<span class="status-dot disabled" data-user-dot="{{ u.username }}" title="Клиент выключен"></span><span class="conn-badge" data-user-online-count="{{ u.username }}" style="display:none;"></span><span class="summary-meta" data-user-meta="{{ u.username }}">↓ {{ u.rx_h }} | ↑ {{ u.tx_h }} | Σ {{ u.total_h }}</span></summary>
          <div class="user-body">
            <p class="muted">Отключен: {{ u.disabled_at or 'неизвестно' }}</p>
            <form method="post" action="{{ url_for('hy2.users_toggle_handler') }}" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <input type="hidden" name="action" value="enable">
              <button type="submit">Включить обратно</button>
            </form>
            <form method="post" action="{{ url_for('hy2.users_password_random_handler') }}" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <button type="submit">Сменить пароль (рандом)</button>
            </form>
            <p class="user-stats">
              {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}Лимит трафика: {{ u.traffic_limit_h }}{% else %}Лимит трафика: нет{% endif %}
              | {% if u.duration_days %}Срок: {{ u.duration_days }} дн.{% else %}Срок: нет{% endif %}
              | {% if u.expires_at %}До: {{ u.expires_at[:10] }}{% else %}До даты: нет{% endif %}
              | {% if u.speed_up_mbps %}Up: {{ u.speed_up_mbps }} Mbps{% else %}Up: нет{% endif %}
              | {% if u.speed_down_mbps %}Down: {{ u.speed_down_mbps }} Mbps{% else %}Down: нет{% endif %}
              | {% if u.max_connections %}Подкл.: {{ u.max_connections }}{% else %}Подкл.: нет{% endif %}
            </p>
            <p class="user-ip-line">
              Сейчас IP:
              {% if u.current_ips %}{{ u.current_ips|join(', ') }}{% else %}нет данных{% endif %}
            </p>
            <p class="user-ip-line">
              История IP:
              {% if u.history_ips %}{{ u.history_ips|join(', ') }}{% else %}пока пусто{% endif %}
            </p>
            {% if u.last_seen_ip %}
              <p class="user-ip-line">Последний замеченный IP: {{ u.last_seen_ip }}{% if u.last_seen_ip_at %} ({{ u.last_seen_ip_at }}){% endif %}</p>
            {% endif %}
            {% if u.traffic_limit_bytes and u.traffic_limit_bytes > 0 %}
              <p class="user-stats" data-user-limit-text="{{ u.username }}">Остаток: {{ u.traffic_remaining_h }}</p>
              <div class="limit-bar"><div class="limit-fill {% if u.traffic_usage_percent >= 100 %}danger{% elif u.traffic_usage_percent >= 90 %}warn{% endif %}" data-user-limit-bar="{{ u.username }}" style="width: {{ u.traffic_usage_percent }}%;"></div></div>
            {% endif %}
            {% if u.disabled_reason %}
              <p class="muted">Причина отключения: {{ u.disabled_reason }}</p>
            {% endif %}
            <form method="post" action="{{ url_for('hy2.users_limits_handler') }}" class="edit-limits">
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
            <form method="post" action="{{ url_for('hy2.users_note_handler') }}" class="user-note">
              <input type="hidden" name="username" value="{{ u.username }}">
              <label>Заметки по пользователю</label>
              <textarea name="note" rows="3" placeholder="Любая информация о пользователе...">{{ u.note or '' }}</textarea>
              <div class="actions"><button type="submit">Сохранить заметку</button></div>
            </form>
            {% if u.url %}
              <p>
                <img
                  class="qr-copy"
                  src="{{ url_for('hy2.qr_handler', u=u.url) }}"
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
      const openLogsModalBtn = document.getElementById("open-logs-modal");
      const closeLogsModalBtn = document.getElementById("close-logs-modal");
      const logsModal = document.getElementById("logs-modal");
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

      function openLogsModal() {
        if (!logsModal) return;
        logsModal.classList.add("open");
        logsModal.setAttribute("aria-hidden", "false");
      }

      function closeLogsModal() {
        if (!logsModal) return;
        logsModal.classList.remove("open");
        logsModal.setAttribute("aria-hidden", "true");
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
      if (openLogsModalBtn) {
        openLogsModalBtn.addEventListener("click", openLogsModal);
      }
      if (closeLogsModalBtn) {
        closeLogsModalBtn.addEventListener("click", closeLogsModal);
      }
      if (logsModal) {
        logsModal.addEventListener("click", function (e) {
          if (e.target === logsModal) closeLogsModal();
        });
      }
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
          closeServerModal();
          closeLogsModal();
        }
      });
      {% if logs_data and logs_data.searched %}
      openLogsModal();
      {% endif %}

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
          const r = await fetch("{{ url_for('hy2.api_live_handler') }}", { cache: "no-store", credentials: "same-origin" });
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

      const bgCanvas = document.getElementById("bg-canvas");
      if (bgCanvas && bgCanvas.getContext) {
        const ctx = bgCanvas.getContext("2d");
        let w = 0;
        let h = 0;
        function resizeCanvas() {
          w = window.innerWidth || 1;
          h = window.innerHeight || 1;
          bgCanvas.width = w;
          bgCanvas.height = h;
        }
        function drawBackground(t) {
          const time = t * 0.00028;
          ctx.clearRect(0, 0, w, h);
          const g = ctx.createLinearGradient(0, 0, w, h);
          g.addColorStop(0, "#0b1020");
          g.addColorStop(0.5, "#121a30");
          g.addColorStop(1, "#0b1220");
          ctx.fillStyle = g;
          ctx.fillRect(0, 0, w, h);

          const blobs = [
            { x: w * (0.18 + 0.06 * Math.sin(time * 1.2)), y: h * (0.28 + 0.08 * Math.cos(time * 0.9)), r: Math.max(w, h) * 0.32, c: "rgba(56, 189, 248, 0.12)" },
            { x: w * (0.72 + 0.05 * Math.cos(time * 1.05)), y: h * (0.38 + 0.09 * Math.sin(time * 0.8)), r: Math.max(w, h) * 0.36, c: "rgba(99, 102, 241, 0.14)" },
            { x: w * (0.52 + 0.04 * Math.sin(time * 0.75)), y: h * (0.78 + 0.07 * Math.cos(time * 1.1)), r: Math.max(w, h) * 0.34, c: "rgba(34, 197, 94, 0.10)" }
          ];

          blobs.forEach(function (b) {
            const rg = ctx.createRadialGradient(b.x, b.y, 0, b.x, b.y, b.r);
            rg.addColorStop(0, b.c);
            rg.addColorStop(1, "rgba(0,0,0,0)");
            ctx.fillStyle = rg;
            ctx.beginPath();
            ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2);
            ctx.fill();
          });

          requestAnimationFrame(drawBackground);
        }
        resizeCanvas();
        window.addEventListener("resize", resizeCanvas);
        requestAnimationFrame(drawBackground);
      }
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
PANEL_URL_PREFIX=${PANEL_URL_PREFIX}
PROTECTED_USERS=
RU_WHITELIST_SYNC_SCHEDULE=${WHITELIST_SYNC_SCHEDULE:-daily}
PANEL_TIMEZONE=Europe/Moscow
EOF
}

write_whitelist_sync_systemd() {
  mkdir -p "${INSTALL_DIR}/data/russia-whitelist"
  local cal
  if [[ "${WHITELIST_SYNC_SCHEDULE:-daily}" == "weekly" ]]; then
    cal="OnCalendar=Sun *-*-* 04:15:00"
  else
    cal="OnCalendar=*-*-* 04:15:00"
  fi
  cat > "/etc/systemd/system/hy2-whitelist-sync.service" <<EOF
[Unit]
Description=HY2 Admin: sync Russia mobile internet whitelist (GitHub)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/whitelist_sync.py
User=root
EOF
  cat > "/etc/systemd/system/hy2-whitelist-sync.timer" <<EOF
[Unit]
Description=Timer: russia-mobile-internet-whitelist (${WHITELIST_SYNC_SCHEDULE:-daily})

[Timer]
${cal}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable hy2-whitelist-sync.timer 2>/dev/null || true
  systemctl start hy2-whitelist-sync.timer 2>/dev/null || true
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
      # Без `yes | ufw`: при pipefail SIGPIPE от yes может завершить скрипт с кодом 141.
      while ufw status 2>/dev/null | grep -qE ":${APP_PORT}/tcp| ${APP_PORT}/tcp"; do
        ufw delete allow "${APP_PORT}/tcp" >/dev/null 2>&1 || break
      done
      ufw limit "${APP_PORT}/tcp" >/dev/null 2>&1 || true
    fi
  fi
}

print_summary() {
  local url
  url="${APP_SCHEME}://${APP_HOST}:${APP_PORT}${PANEL_URL_PREFIX}/"
  echo
  echo "==========================================="
  echo "Установка завершена"
  echo "Панель: ${url}"
  echo "Префикс пути (см. PANEL_URL_PREFIX в .env): ${PANEL_URL_PREFIX:-/}"
  echo "Логин: ${PANEL_USER}"
  echo "Пароль: ${PANEL_PASS}"
  echo "Сервис: ${SERVICE_NAME}"
  echo "Whitelist РФ: таймер hy2-whitelist-sync.timer (${WHITELIST_SYNC_SCHEDULE:-daily}), файлы: ${INSTALL_DIR}/data/russia-whitelist/"
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
  WHITELIST_SYNC_SCHEDULE="${WHITELIST_SYNC_SCHEDULE:-daily}"
  install_packages
  setup_fail2ban
  prepare_files
  write_env_file
  setup_tls
  write_service
  install_python_deps
  write_whitelist_sync_systemd
  "${INSTALL_DIR}/.venv/bin/python" "${INSTALL_DIR}/whitelist_sync.py" || true
  open_firewall
  service_manage
  print_summary
}

main "$@"

