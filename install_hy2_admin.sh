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
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
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
BIND_HOST = ENV.get("PANEL_BIND_HOST", "0.0.0.0")
BIND_PORT = int(ENV.get("PANEL_BIND_PORT", "8787"))
PROTECTED_USERS_RAW = ENV.get("PROTECTED_USERS", "admin,Admin")

REGISTRY_PATH = Path("/opt/hy2-admin/data/clients.json")
BACKUP_DIR = Path("/opt/hy2-admin/backups")
STATE_PATH = Path("/opt/hy2-admin/data/user_state.json")

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


def make_client_url(username: str, password: str, host: str, port: int, sni: str) -> str:
    user_enc = quote(username, safe="")
    pass_enc = quote(password, safe="")
    query = f"sni={quote(sni, safe='')}"
    if INSECURE:
        query += "&insecure=1"
    return f"hysteria2://{user_enc}:{pass_enc}@{host}:{port}/?{query}#{quote(username, safe='')}"


def make_qr_png(text: str) -> bytes:
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


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


def build_users_view() -> tuple[list[dict], list[dict]]:
    cfg = load_hy2_config()
    state = load_user_state()
    protected = get_protected_users()
    host, port, sni = infer_server_values(cfg)
    active = []
    for username, password in sorted(cfg["auth"]["userpass"].items()):
        active.append(
            {
                "username": username,
                "is_protected": username in protected,
                "url": make_client_url(username, str(password), host, port, sni),
            }
        )
    disabled = []
    disabled_map = state.get("disabled", {})
    for username in sorted(disabled_map.keys()):
        rec = disabled_map.get(username, {})
        password = rec.get("password", "")
        url = make_client_url(username, str(password), host, port, sni) if password else ""
        disabled.append(
            {
                "username": username,
                "disabled_at": rec.get("disabled_at", ""),
                "is_protected": username in protected,
                "url": url,
            }
        )
    return active, disabled


def apply_users(usernames: list[str], update_existing: bool) -> tuple[list[dict], list[str]]:
    cfg = load_hy2_config()
    up = cfg["auth"]["userpass"]
    host, port, sni = infer_server_values(cfg)
    results, skipped, registry = [], [], []
    for username in usernames:
        exists = username in up
        if exists and not update_existing:
            skipped.append(username)
            continue
        password = random_password()
        up[username] = password
        url = make_client_url(username, password, host, port, sni)
        results.append({"username": username, "password": password, "url": url, "status": "updated" if exists else "created"})
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
        disabled[username] = {"password": password, "disabled_at": datetime.now(timezone.utc).isoformat()}
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
        if not username or username in seen:
            continue
        seen.add(username)
        if not valid_username(username):
            raise ValueError(f"Недопустимое имя пользователя: {username}")
        selected_clean.append(username)
    changed_active, changed_state, deleted_count, skipped_protected = False, False, 0, 0
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
    if changed_active:
        write_config_with_backup_and_restart(cfg)
    if changed_state:
        save_user_state(state)
    if deleted_count == 0 and skipped_protected == 0:
        return "Ничего не удалено"
    if skipped_protected:
        return f"Удалено: {deleted_count}. Защищенных пропущено: {skipped_protected}"
    return f"Удалено: {deleted_count}"


def render_index(defaults=None, **kwargs):
    active_users, disabled_users = build_users_view()
    base_defaults = {"prefix": "user-", "count": 10, "start": 1, "width": 3, "update_existing": True}
    if defaults:
        base_defaults.update(defaults)
    return render_template("index.html", defaults=base_defaults, active_users=active_users, disabled_users=disabled_users, **kwargs)


@app.route("/", methods=["GET"])
@requires_auth
def index():
    return render_index()


@app.route("/apply", methods=["POST"])
@requires_auth
def apply_handler():
    mode = request.form.get("mode", "manual")
    update_existing = request.form.get("update_existing") == "on"
    defaults = {
        "prefix": request.form.get("prefix", "user-").strip() or "user-",
        "count": request.form.get("count", "10"),
        "start": request.form.get("start", "1"),
        "width": request.form.get("width", "3"),
        "update_existing": update_existing,
        "manual_usernames": request.form.get("manual_usernames", ""),
    }
    try:
        if mode == "manual":
            usernames = parse_usernames_manual(request.form.get("manual_usernames", ""))
        elif mode == "prefix":
            usernames = parse_usernames_prefix(
                prefix=request.form.get("prefix", "").strip(),
                count=int(request.form.get("count", "0")),
                start=int(request.form.get("start", "1")),
                width=int(request.form.get("width", "3")),
            )
        else:
            raise ValueError("Неизвестный режим")
        results, skipped = apply_users(usernames, update_existing)
        created_urls = [item["url"] for item in results if item.get("status") == "created"]
        return render_index(defaults=defaults, results=results, skipped=skipped, ok_message=f"Успешно обработано: {len(results)}", created_urls=created_urls)
    except Exception as e:
        return render_index(defaults=defaults, error_message=str(e))


@app.route("/qr", methods=["GET"])
@requires_auth
def qr_handler():
    text = request.args.get("u", "").strip()
    if not text:
        return Response("Missing parameter: u", status=400)
    return Response(make_qr_png(text), mimetype="image/png")


@app.route("/users/toggle", methods=["POST"])
@requires_auth
def users_toggle_handler():
    try:
        msg = toggle_user(request.form.get("username", "").strip(), request.form.get("action", "").strip())
        return render_index(ok_message=msg)
    except Exception as e:
        return render_index(error_message=str(e))


@app.route("/users/delete", methods=["POST"])
@requires_auth
def users_delete_handler():
    try:
        msg = delete_users(request.form.get("scope", "").strip(), request.form.get("mode", "").strip(), request.form.getlist("selected_users"))
        return render_index(ok_message=msg)
    except Exception as e:
        return render_index(error_message=str(e))


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
    :root { --bg:#0f1115; --bg-soft:#171a21; --text:#e6e6e6; --muted:#9ca3af; --border:#2a2f3a; --ok:#4ade80; --err:#f87171; --btn:#2563eb; --btn-hover:#1d4ed8; --input-bg:#0b0d12; --code-bg:#0b0d12; }
    body { font-family: Arial, sans-serif; margin: 24px; background: var(--bg); color: var(--text); }
    .grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
    textarea, input { width:100%; padding:8px; box-sizing:border-box; background:var(--input-bg); color:var(--text); border:1px solid var(--border); border-radius:6px; }
    label { display:block; margin-top:10px; font-weight:600; }
    .box { border:1px solid var(--border); border-radius:8px; padding:16px; background:var(--bg-soft); }
    .actions { margin-top:16px; }
    button { padding:10px 16px; font-weight:700; background:var(--btn); color:#fff; border:0; border-radius:8px; cursor:pointer; }
    button:hover { background:var(--btn-hover); }
    .ok { color:var(--ok); } .err { color:var(--err); } .row { margin-top:14px; }
    .result { border:1px solid var(--border); border-radius:8px; padding:12px; margin:12px 0; background:var(--bg-soft); }
    code { word-break:break-all; background:var(--code-bg); padding:2px 4px; border-radius:4px; }
    img { border:1px solid var(--border); border-radius:6px; padding:6px; background:#fff; }
    .muted { color:var(--muted); } .danger { background:#b91c1c; } .danger:hover { background:#991b1b; }
    .inline { display:inline-block; margin-right:8px; }
    .section-header { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; }
    .tabs { display:flex; gap:8px; margin-bottom:12px; }
    .tab-btn { background:#374151; } .tab-btn.active { background:#2563eb; }
    .tab-panel { display:none; } .tab-panel.active { display:block; }
    .qr-copy { cursor:pointer; transition:transform .12s ease; } .qr-copy:hover { transform:scale(1.03); }
    .copy-status { margin:8px 0; min-height:18px; color:var(--ok); font-weight:600; }
    .links-list { width:100%; min-height:170px; }
    details.user-card { border:1px solid var(--border); border-radius:8px; margin:12px 0; background:var(--bg-soft); }
    details.user-card > summary { cursor:pointer; list-style:none; padding:12px; font-weight:700; }
    details.user-card > summary::-webkit-details-marker { display:none; }
    details.user-card > summary::after { content:"▸"; float:right; color:var(--muted); }
    details.user-card[open] > summary::after { content:"▾"; }
    .user-body { border-top:1px solid var(--border); padding:12px; }
    .url-text { display:block; margin-top:8px; white-space:pre-wrap; word-break:break-all; }
  </style>
</head>
<body>
  <h1>Hysteria2 Clients Admin</h1>
  <p id="copy-status" class="copy-status"></p>
  {% if ok_message %}<p class="ok"><strong>{{ ok_message }}</strong></p>{% endif %}
  {% if error_message %}<p class="err"><strong>Ошибка:</strong> {{ error_message }}</p>{% endif %}

  <form method="post" action="/apply">
    <div class="row"><label><input type="checkbox" name="update_existing" {% if defaults.update_existing %}checked{% endif %}> Обновлять пароль у существующего логина</label></div>
    <div class="grid">
      <div class="box">
        <h3>Режим Manual</h3>
        <label><input type="radio" name="mode" value="manual" checked> Использовать ручной список</label>
        <label>Логины (через пробел, запятую или новую строку)</label>
        <textarea name="manual_usernames" rows="10" placeholder="ivan&#10;petr&#10;user-001">{{ defaults.manual_usernames or '' }}</textarea>
        <p class="muted">Допустимые символы: a-z, A-Z, 0-9, "_" и "-". Точка не поддерживается Hysteria2.</p>
      </div>
      <div class="box">
        <h3>Режим Prefix</h3>
        <label><input type="radio" name="mode" value="prefix"> Генерация по префиксу</label>
        <label>Префикс</label><input name="prefix" value="{{ defaults.prefix }}" />
        <label>Количество</label><input type="number" min="1" max="500" name="count" value="{{ defaults.count }}" />
        <label>Стартовый индекс</label><input type="number" min="0" name="start" value="{{ defaults.start }}" />
        <label>Ширина номера (0 = без zero-pad)</label><input type="number" min="0" max="8" name="width" value="{{ defaults.width }}" />
      </div>
    </div>
    <div class="actions"><button type="submit">Применить и сгенерировать URL/QR</button></div>
  </form>

  {% if skipped %}<h3>Пропущены</h3><p>{{ skipped|join(', ') }}</p>{% endif %}

  {% if results %}
    <h2>Результаты</h2>
    <p class="muted">Нажмите на QR, чтобы скопировать URL пользователя в буфер обмена.</p>
    {% for item in results %}
      <div class="result">
        <p><strong>{{ item.username }}</strong> ({{ item.status }})</p>
        <p><img class="qr-copy" src="/qr?u={{ item.url | urlencode }}" data-url="{{ item.url }}" alt="QR for {{ item.username }}" title="Нажмите, чтобы скопировать URL" width="220" loading="lazy" /></p>
      </div>
    {% endfor %}
    {% if created_urls %}
      <h3>Новые добавленные URL</h3>
      <textarea class="links-list" readonly>{% for u in created_urls %}{{ u }}{% if not loop.last %}
{% endif %}{% endfor %}</textarea>
    {% endif %}
  {% endif %}

  <div class="section-header">
    <h2>Пользователи</h2>
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
        <details class="user-card">
          <summary>{{ u.username }}{% if u.is_protected %} <span class="muted">(защищен)</span>{% endif %}</summary>
          <div class="user-body">
            <label class="inline"><input form="active-delete-form" type="checkbox" name="selected_users" value="{{ u.username }}" {% if u.is_protected %}disabled{% endif %}> Выбрать для удаления</label>
            <form method="post" action="/users/toggle" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <input type="hidden" name="action" value="disable">
              <button type="submit" {% if u.is_protected %}disabled{% endif %}>Временно отключить</button>
            </form>
            <p><img class="qr-copy" src="/qr?u={{ u.url | urlencode }}" data-url="{{ u.url }}" alt="QR for {{ u.username }}" title="Нажмите, чтобы скопировать URL" width="220" loading="lazy" /></p>
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
        <details class="user-card">
          <summary>{{ u.username }}{% if u.is_protected %} <span class="muted">(защищен)</span>{% endif %}</summary>
          <div class="user-body">
            <p class="muted">Отключен: {{ u.disabled_at or 'неизвестно' }}</p>
            <form method="post" action="/users/toggle" class="inline">
              <input type="hidden" name="username" value="{{ u.username }}">
              <input type="hidden" name="action" value="enable">
              <button type="submit">Включить обратно</button>
            </form>
            {% if u.url %}
              <p><img class="qr-copy" src="/qr?u={{ u.url | urlencode }}" data-url="{{ u.url }}" alt="QR for {{ u.username }}" title="Нажмите, чтобы скопировать URL" width="220" loading="lazy" /></p>
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

  <script>
    (function () {
      const tabActiveBtn = document.getElementById("tab-active-btn");
      const tabDisabledBtn = document.getElementById("tab-disabled-btn");
      const tabActive = document.getElementById("tab-active");
      const tabDisabled = document.getElementById("tab-disabled");
      const copyStatus = document.getElementById("copy-status");
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
            if (copyStatus) copyStatus.textContent = "URL скопирован в буфер обмена";
          } catch (e) {
            if (copyStatus) copyStatus.textContent = "Не удалось скопировать URL";
          }
        });
      });
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
ExecStart=${INSTALL_DIR}/.venv/bin/gunicorn -w 2 -b 0.0.0.0:${APP_PORT}${TLS_ARGS} app:app
Restart=always
RestartSec=2
User=root
Group=root

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
      ufw allow "${APP_PORT}/tcp" >/dev/null 2>&1 || true
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
