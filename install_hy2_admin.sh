#!/usr/bin/env bash
set -euo pipefail

MODE="interactive"
APP_DOMAIN="${APP_DOMAIN:-}"
APP_EMAIL="${APP_EMAIL:-}"
PANEL_USER="${PANEL_USER:-}"
PANEL_PASS="${PANEL_PASS:-}"
PANEL_URL_PREFIX="${PANEL_URL_PREFIX:-}"
USE_RANDOM_CREDS="${USE_RANDOM_CREDS:-y}"
INTERNAL_PORT="${INTERNAL_PORT:-18080}"
INSTALL_DIR="/opt/hy2-admin"
SERVICE_NAME="hy2-admin.service"
CREATE_PANEL_CASCADE_HOP_USER="${CREATE_PANEL_CASCADE_HOP_USER:-n}"
PANEL_CASCADE_HOP_USER="${PANEL_CASCADE_HOP_USER:-cascade_hop}"
NGINX_SITE_NAME="hy2-admin-panel"
NGINX_SITE_PATH="/etc/nginx/sites-available/${NGINX_SITE_NAME}"
HTTPS_STUB_DIR="/var/www/hy2-site"
HTTPS_STUB_PATH="${HTTPS_STUB_DIR}/index.html"
BINARY_PATH="${INSTALL_DIR}/hy2-admin-panel"
# По умолчанию — GitHub «Latest» (см. https://github.com/AntyanMS/hy2-admin/releases/latest).
# Явный URL: HY2_PANEL_URL. Зафиксировать версию по тегу: HY2_PANEL_RELEASE_TAG (например v1.2.3).
PANEL_LATEST_BINARY_URL="https://github.com/AntyanMS/hy2-admin/releases/latest/download/hy2-admin-panel"
if [[ -n "${HY2_PANEL_URL:-}" ]]; then
  PANEL_BINARY_URL="${HY2_PANEL_URL}"
elif [[ -n "${HY2_PANEL_RELEASE_TAG:-}" ]]; then
  PANEL_BINARY_URL="https://github.com/AntyanMS/hy2-admin/releases/download/${HY2_PANEL_RELEASE_TAG}/hy2-admin-panel"
else
  PANEL_BINARY_URL="${PANEL_LATEST_BINARY_URL}"
fi
PANEL_SESSION_SECRET=""
SERVER_HOST=""
USE_LETS_ENCRYPT="n"
HYSTERIA_CERT_SYNC_RESULT="not_attempted"

log() { printf "[INFO] %s\n" "$*"; }
warn() { printf "[WARN] %s\n" "$*" >&2; }
die() { printf "[ERROR] %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./install_hy2_admin.sh --interactive
  ./install_hy2_admin.sh --auto [опционально те же флаги, что ниже]

Режим --auto без флагов:
  • домен не задан явно → пробуем взять из /etc/hysteria/config.yaml (блок acme → domains) или из nginx hy2-site.conf (server_name);
  • если домен так и не найден → HTTPS по самоподписанному сертификату на IPv4 сервера;
  • логин/пароль по умолчанию random-creds (admin + случайный пароль);
  • префикс URL панели случайный.

Параметры можно не указывать в командной строке: задайте переменные окружения HY2_ADMIN_*
или создайте файл /etc/hy2-admin/install.env или /root/.hy2-admin-install.env (формат KEY=value).

HY2_ADMIN_DOMAIN              → --domain (если есть и HY2_ADMIN_EMAIL → Let's Encrypt)
HY2_ADMIN_EMAIL               → --email
HY2_ADMIN_PANEL_USER          → при наличии включает ручные учётные данные
HY2_ADMIN_PANEL_PASS          → пароль панели
HY2_ADMIN_RANDOM_CREDS=y|n    → как --random-creds / без manual (по умолчанию y)
HY2_ADMIN_PANEL_URL_PREFIX    → например /secret/panel (слэши можно опустить)
HY2_ADMIN_BINARY_URL          → URL бинаря панели (иначе HY2_PANEL_URL, иначе HY2_PANEL_RELEASE_TAG, иначе Latest на GitHub)
HY2_ADMIN_CREATE_CASCADE_HOP=y→ как --create-cascade-hop
HY2_ADMIN_INSTALL_ENV=/path   → явный путь к env-файлу вместо стандартных путей выше

Flags:
  --interactive            Interactive mode (default)
  --auto                   Non-interactive mode
  --domain <domain>        Public domain for panel (optional)
  --email <email>          Email for Let's Encrypt (required when domain is set)
  --panel-user <user>      Manual panel username (with --manual-creds)
  --panel-pass <pass>      Manual panel password (with --manual-creds)
  --manual-creds           Use manual username/password
  --random-creds           Generate random username/password (default)
  --panel-url-prefix </x/panel>
                           Explicit panel URL prefix (default random)
  --binary-url <url>       Override panel binary URL
  --create-cascade-hop     Добавить служебного HY2-пользователя для hop/каскада (см. HY2_UI_HIDDEN_USERS)
  -h, --help               Show help
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Запустите скрипт от root."
  fi
}

random_hex() {
  openssl rand -hex "${1:-16}"
}

detect_ipv4() {
  local ip
  ip="$(curl -4fsS https://ifconfig.me 2>/dev/null || true)"
  if [[ -z "${ip}" ]]; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  [[ -n "${ip}" ]] || ip="127.0.0.1"
  printf "%s" "${ip}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --interactive) MODE="interactive"; shift ;;
      --auto) MODE="auto"; shift ;;
      --domain) APP_DOMAIN="${2:-}"; shift 2 ;;
      --email) APP_EMAIL="${2:-}"; shift 2 ;;
      --panel-user) PANEL_USER="${2:-}"; shift 2 ;;
      --panel-pass) PANEL_PASS="${2:-}"; shift 2 ;;
      --manual-creds) USE_RANDOM_CREDS="n"; shift ;;
      --random-creds) USE_RANDOM_CREDS="y"; shift ;;
      --panel-url-prefix) PANEL_URL_PREFIX="${2:-}"; shift 2 ;;
      --binary-url) PANEL_BINARY_URL="${2:-}"; shift 2 ;;
      --create-cascade-hop) CREATE_PANEL_CASCADE_HOP_USER="y"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "Неизвестный аргумент: $1" ;;
    esac
  done
}

collect_interactive() {
  local input
  echo "=== Установка панели HY2 Admin (HTTPS-only) ==="
  read -r -p "Домен панели (Enter = использовать IPv4 сервера): " input
  APP_DOMAIN="${input}"

  if [[ -n "${APP_DOMAIN}" ]]; then
    USE_LETS_ENCRYPT="y"
    read -r -p "Email для SSL сертификата (Let's Encrypt): " input
    APP_EMAIL="${input}"
    [[ -n "${APP_EMAIL}" ]] || die "Email обязателен, если указан домен."
  fi

  read -r -p "Сгенерировать random user/pass для панели? [Y/n]: " input
  if [[ "${input:-Y}" =~ ^[Nn]$ ]]; then
    USE_RANDOM_CREDS="n"
    read -r -p "Panel user: " input
    PANEL_USER="${input}"
    [[ -n "${PANEL_USER}" ]] || die "Panel user обязателен."
    read -r -p "Panel pass: " input
    PANEL_PASS="${input}"
    [[ -n "${PANEL_PASS}" ]] || die "Panel pass обязателен."
  else
    USE_RANDOM_CREDS="y"
  fi

  read -r -p "Кастомный URL префикс панели (Enter = random): " input
  if [[ -n "${input}" ]]; then
    input="${input#/}"
    input="${input%/}"
    PANEL_URL_PREFIX="/${input}/panel"
  fi
}

validate_auto() {
  if [[ -n "${APP_DOMAIN}" ]]; then
    USE_LETS_ENCRYPT="y"
    if [[ -z "${APP_EMAIL}" ]]; then
      if [[ -f "/etc/letsencrypt/live/${APP_DOMAIN}/fullchain.pem" ]]; then
        APP_EMAIL="${APP_EMAIL:-admin@${APP_DOMAIN}}"
        warn "Email для Let's Encrypt не задан — подставлен ${APP_EMAIL} (сертификат для домена уже есть в /etc/letsencrypt)."
      else
        die "--auto / HY2_ADMIN_DOMAIN: для выпуска Let's Encrypt нужен email (--email или HY2_ADMIN_EMAIL)."
      fi
    fi
  fi
  if [[ "${USE_RANDOM_CREDS}" != "y" ]]; then
    [[ -n "${PANEL_USER}" ]] || die "--manual-creds / HY2_ADMIN_PANEL_*: нужен --panel-user или HY2_ADMIN_PANEL_USER."
    [[ -n "${PANEL_PASS}" ]] || die "--manual-creds / HY2_ADMIN_PANEL_*: нужен --panel-pass или HY2_ADMIN_PANEL_PASS."
  fi
}

# Для --auto: подставить значения из окружения и опционального env-файла (без передачи десятка флагов в CLI).
hydrate_auto_from_env() {
  [[ "${MODE}" == "auto" ]] || return 0

  local candidate env_file
  env_file="${HY2_ADMIN_INSTALL_ENV:-}"
  if [[ -n "${env_file}" ]]; then
    [[ -f "${env_file}" ]] || die "HY2_ADMIN_INSTALL_ENV: файл не найден: ${env_file}"
    set -a
    # shellcheck disable=SC1090
    source "${env_file}"
    set +a
  else
    for candidate in /etc/hy2-admin/install.env /root/.hy2-admin-install.env; do
      [[ -f "${candidate}" ]] || continue
      set -a
      # shellcheck disable=SC1090
      source "${candidate}"
      set +a
      break
    done
  fi

  APP_DOMAIN="${APP_DOMAIN:-${HY2_ADMIN_DOMAIN:-}}"
  APP_EMAIL="${APP_EMAIL:-${HY2_ADMIN_EMAIL:-}}"
  PANEL_URL_PREFIX="${PANEL_URL_PREFIX:-${HY2_ADMIN_PANEL_URL_PREFIX:-}}"

  if [[ -n "${HY2_ADMIN_PANEL_USER:-}" ]]; then
    PANEL_USER="${PANEL_USER:-${HY2_ADMIN_PANEL_USER}}"
    USE_RANDOM_CREDS="n"
  fi
  if [[ -n "${HY2_ADMIN_PANEL_PASS:-}" ]]; then
    PANEL_PASS="${PANEL_PASS:-${HY2_ADMIN_PANEL_PASS}}"
    USE_RANDOM_CREDS="n"
  fi
  if [[ "${HY2_ADMIN_RANDOM_CREDS:-}" =~ ^[Yy1] ]]; then
    USE_RANDOM_CREDS="y"
  elif [[ "${HY2_ADMIN_RANDOM_CREDS:-}" =~ ^[Nn0] ]]; then
    USE_RANDOM_CREDS="n"
  fi

  if [[ -n "${HY2_ADMIN_BINARY_URL:-}" ]]; then
    PANEL_BINARY_URL="${HY2_ADMIN_BINARY_URL}"
  fi

  if [[ "${HY2_ADMIN_CREATE_CASCADE_HOP:-}" =~ ^[Yy1] ]]; then
    CREATE_PANEL_CASCADE_HOP_USER="y"
  fi

  if [[ -n "${HY2_ADMIN_INTERNAL_PORT:-}" ]]; then
    INTERNAL_PORT="${HY2_ADMIN_INTERNAL_PORT}"
  fi

  infer_auto_panel_domain_from_stack
}

# Если --domain не передали и нет HY2_ADMIN_DOMAIN: взять домен из HY2 (acme) или nginx hy2-site.
infer_auto_panel_domain_from_stack() {
  [[ "${MODE}" == "auto" ]] || return 0
  [[ -z "${APP_DOMAIN:-}" ]] || return 0

  local inferred inferred_email line
  inferred=""
  inferred_email=""
  if [[ -f /etc/hysteria/config.yaml ]]; then
    while IFS= read -r line || [[ -n "${line}" ]]; do
      [[ -z "${line}" ]] && continue
      if [[ -z "${inferred}" ]]; then inferred="${line}"; continue; fi
      inferred_email="${line}"
      break
    done < <(python3 <<'PY' 2>/dev/null || true
from pathlib import Path
import re
p = Path("/etc/hysteria/config.yaml")
if not p.exists():
    raise SystemExit(0)
text = p.read_text(encoding="utf-8")
dom = None
email = None
if re.search(r"(?m)^acme:\s*$", text) or re.search(r"(?m)^acme:\s+.+$", text):
    m = re.search(r"(?ms)^acme:.*?^\s*domains:\s*\n\s*-\s*(\S+)", text)
    if m:
        dom = m.group(1).strip("\"'")
    em = re.search(r"(?ms)^acme:.*?^\s*email:\s*(\S+)", text)
    if em:
        email = em.group(1).strip("\"'")
if dom and "." in dom and not dom.startswith("/"):
    print(dom)
    if email and "@" in email:
        print(email)
PY
)
  fi

  if [[ -z "${inferred}" ]]; then
    inferred="$(infer_domain_from_nginx_hy2_site_conf || true)"
  fi

  if [[ -n "${inferred}" ]]; then
    APP_DOMAIN="${inferred}"
    if [[ -z "${APP_EMAIL:-}" && -n "${inferred_email}" ]]; then
      APP_EMAIL="${inferred_email}"
    fi
    log "Домен для панели определён автоматически (HY2-acme или nginx hy2-site): ${APP_DOMAIN}"
  fi
}

infer_domain_from_nginx_hy2_site_conf() {
  local f raw sn
  for f in /etc/nginx/sites-enabled/hy2-site.conf /etc/nginx/sites-available/hy2-site.conf; do
    [[ -f "${f}" ]] || continue
    raw="$(grep -E '^[[:space:]]*server_name[[:space:]]+' "${f}" | head -1)" || continue
    sn="${raw#*server_name}"
    sn="$(printf "%s" "${sn}" | awk '{print $1}' | tr -d ';')"
    if [[ -z "${sn}" || "${sn}" == "_" ]]; then continue; fi
    printf "%s" "${sn}"
    return 0
  done
  return 1
}

prepare_values() {
  if [[ -z "${APP_DOMAIN}" ]]; then
    SERVER_HOST="$(detect_ipv4)"
  else
    SERVER_HOST="${APP_DOMAIN}"
  fi

  if [[ "${USE_RANDOM_CREDS}" == "y" ]]; then
    PANEL_USER="admin"
    PANEL_PASS="$(random_hex 10)"
  else
    [[ -n "${PANEL_USER}" ]] || PANEL_USER="admin"
  fi

  if [[ -z "${PANEL_URL_PREFIX}" ]]; then
    PANEL_URL_PREFIX="/$(random_hex 16)/panel"
  fi
  PANEL_URL_PREFIX="${PANEL_URL_PREFIX%/}"
  [[ "${PANEL_URL_PREFIX}" == /* ]] || PANEL_URL_PREFIX="/${PANEL_URL_PREFIX}"

  PANEL_SESSION_SECRET="$(random_hex 32)"
}

install_packages() {
  log "Установка пакетов..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y curl openssl nginx fail2ban ufw
  if [[ "${USE_LETS_ENCRYPT}" == "y" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-nginx
  fi
}

download_binary() {
  log "Загрузка панели: ${PANEL_BINARY_URL}"
  local tmp_binary
  mkdir -p "${INSTALL_DIR}"
  tmp_binary="${INSTALL_DIR}/.hy2-admin-panel.tmp.$$"
  rm -f "${tmp_binary}"
  curl -4fL --retry 10 --retry-all-errors --connect-timeout 15 --max-time 300 \
    "${PANEL_BINARY_URL}" -o "${tmp_binary}"
  install -m 0755 "${tmp_binary}" "${BINARY_PATH}"
  rm -f "${tmp_binary}"
}

cleanup_legacy_sources() {
  local stamp legacy_dir
  stamp="$(date +%Y%m%d-%H%M%S)"
  legacy_dir="${INSTALL_DIR}/legacy-src-${stamp}"
  mkdir -p "${legacy_dir}"

  # Удаляем/архивируем старую source-установку, чтобы бинарь не подхватывал
  # случайно устаревшие app.py/templates от предыдущих инсталлов.
  for p in app.py templates launcher.py requirements.txt requirements-build.txt tools tmp tls __pycache__ .venv; do
    if [[ -e "${INSTALL_DIR}/${p}" ]]; then
      mv "${INSTALL_DIR}/${p}" "${legacy_dir}/"
    fi
  done
}

write_env() {
  cat > "${INSTALL_DIR}/.env" <<EOF
SERVER_HOST=${SERVER_HOST}
SERVER_PORT=443
SERVER_SNI=${SERVER_HOST}
HY2_CONFIG_PATH=/etc/hysteria/config.yaml
HY2_SERVICE_NAME=hysteria-server.service
PANEL_BIND_HOST=127.0.0.1
PANEL_BIND_PORT=${INTERNAL_PORT}
PANEL_BASIC_USER=${PANEL_USER}
PANEL_BASIC_PASS=${PANEL_PASS}
PANEL_URL_PREFIX=${PANEL_URL_PREFIX}
PANEL_SESSION_SECRET=${PANEL_SESSION_SECRET}
PANEL_SESSION_COOKIE_SECURE=1
PANEL_NGINX_SITE_PATH=${NGINX_SITE_PATH}
HTTPS_ROOT_STUB_HTML_PATH=${HTTPS_STUB_PATH}
SING_BOX_CONFIG_PATH=/etc/sing-box/config.json
CASCADE_EXIT_POOL_ROLES=${CASCADE_EXIT_POOL_ROLES:-exit}
# auto: userpass для чистого HY2; password_only если PANEL_BACKEND=sing-box или в SING_BOX есть inbound hysteria2
HY2_URI_AUTH_STYLE=auto
HY2_UI_HIDDEN_USERS=${HY2_UI_HIDDEN_USERS:-}
EOF
  chmod 0600 "${INSTALL_DIR}/.env"
}

write_systemd_unit() {
  cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=HY2 Admin Web Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${BINARY_PATH}
Restart=always
RestartSec=2
User=root
Group=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
  systemctl restart "${SERVICE_NAME}"
}

make_self_signed_cert() {
  local cert_dir="/etc/ssl/hy2-admin"
  mkdir -p "${cert_dir}"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${cert_dir}/panel.key" \
    -out "${cert_dir}/panel.crt" \
    -days 3650 \
    -subj "/CN=${SERVER_HOST}" >/dev/null 2>&1
  printf "%s|%s" "${cert_dir}/panel.crt" "${cert_dir}/panel.key"
}

prepare_https_root_stub() {
  install -d -m 0755 "${HTTPS_STUB_DIR}"
  cat > "${HTTPS_STUB_PATH}" <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Service</title>
  <style>
    html, body { height: 100%; margin: 0; font-family: system-ui, sans-serif; }
    body { display: grid; place-items: center; background: #0b1020; color: #d8e1f0; }
    .card { border: 1px solid #2a3652; border-radius: 14px; padding: 22px 26px; background: #111a31; }
  </style>
</head>
<body>
  <div class="card">Service is running.</div>
</body>
</html>
EOF
  chmod 0644 "${HTTPS_STUB_PATH}"
}

write_nginx_site() {
  local cert_path="$1"
  local key_path="$2"
  cat > "${NGINX_SITE_PATH}" <<EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${SERVER_HOST};
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name ${SERVER_HOST};

  ssl_certificate ${cert_path};
  ssl_certificate_key ${key_path};
  ssl_session_timeout 1d;
  ssl_session_cache shared:SSL:10m;
  ssl_protocols TLSv1.2 TLSv1.3;

  location ${PANEL_URL_PREFIX}/ {
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    proxy_set_header X-Forwarded-Prefix ${PANEL_URL_PREFIX};
    proxy_pass http://127.0.0.1:${INTERNAL_PORT}${PANEL_URL_PREFIX}/;
  }

  location / {
    root ${HTTPS_STUB_DIR};
    index index.html;
    try_files \$uri \$uri/ /index.html;
  }
}
EOF

  ln -sfn "${NGINX_SITE_PATH}" "/etc/nginx/sites-enabled/${NGINX_SITE_NAME}"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
}

setup_tls_and_nginx() {
  local cert_path="" key_path=""
  if [[ "${USE_LETS_ENCRYPT}" == "y" ]]; then
    cat > "${NGINX_SITE_PATH}" <<EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${SERVER_HOST};
  location / {
    root ${HTTPS_STUB_DIR};
    index index.html;
    try_files \$uri \$uri/ /index.html;
  }
}
EOF
    ln -sfn "${NGINX_SITE_PATH}" "/etc/nginx/sites-enabled/${NGINX_SITE_NAME}"
    rm -f /etc/nginx/sites-enabled/default
    nginx -t
    systemctl restart nginx

    certbot --nginx -d "${SERVER_HOST}" -m "${APP_EMAIL}" --agree-tos --no-eff-email --non-interactive --redirect
    cert_path="/etc/letsencrypt/live/${SERVER_HOST}/fullchain.pem"
    key_path="/etc/letsencrypt/live/${SERVER_HOST}/privkey.pem"
  else
    local cert_pair
    cert_pair="$(make_self_signed_cert)"
    cert_path="${cert_pair%%|*}"
    key_path="${cert_pair##*|}"
  fi

  # Убираем legacy vhost из sites-enabled, чтобы исключить warning
  # "conflicting server name" при одновременном наличии hy2-site + panel.
  rm -f /etc/nginx/sites-enabled/hy2-site.conf
  write_nginx_site "${cert_path}" "${key_path}"
}

sync_hysteria_certbot_materials() {
  local cert_path key_path
  cert_path="/etc/letsencrypt/live/${SERVER_HOST}/fullchain.pem"
  key_path="/etc/letsencrypt/live/${SERVER_HOST}/privkey.pem"

  if [[ ! -f "${cert_path}" || ! -f "${key_path}" ]]; then
    HYSTERIA_CERT_SYNC_RESULT="cert_missing"
    return
  fi
  if [[ ! -f /etc/hysteria/config.yaml ]]; then
    HYSTERIA_CERT_SYNC_RESULT="hysteria_config_not_found"
    return
  fi

  local cert_owner cert_group
  cert_owner="root"
  cert_group="root"
  if id -u hysteria >/dev/null 2>&1; then
    cert_owner="hysteria"
    cert_group="hysteria"
  fi

  install -d -m 0755 /etc/hysteria
  install -o "${cert_owner}" -g "${cert_group}" -m 0644 "${cert_path}" /etc/hysteria/fullchain.pem
  install -o "${cert_owner}" -g "${cert_group}" -m 0600 "${key_path}" /etc/hysteria/privkey.pem

  python3 - <<'PY'
from pathlib import Path
import re

cfg = Path("/etc/hysteria/config.yaml")
text = cfg.read_text(encoding="utf-8")

new_tls_block = "tls:\n  cert: /etc/hysteria/fullchain.pem\n  key: /etc/hysteria/privkey.pem\n"

# 1) If tls block exists, replace only it.
if re.search(r"(?m)^tls:\s*$", text):
    text = re.sub(
        r"(?m)^tls:\s*\n(?:[ \t][^\n]*\n)*",
        new_tls_block + "\n",
        text,
        count=1,
    )
    cfg.write_text(text, encoding="utf-8")
    raise SystemExit(0)

# 2) If acme block exists, replace acme with tls (preserve all other sections).
if re.search(r"(?m)^acme:\s*$", text):
    text = re.sub(
        r"(?m)^acme:\s*\n(?:[ \t][^\n]*\n)*",
        new_tls_block + "\n",
        text,
        count=1,
    )
    cfg.write_text(text, encoding="utf-8")
    raise SystemExit(0)

# 3) Otherwise append tls block after listen line if possible, else append to end.
listen_match = re.search(r"(?m)^listen:\s*.*\n?", text)
if listen_match:
    insert_at = listen_match.end()
    text = text[:insert_at] + "\n" + new_tls_block + "\n" + text[insert_at:]
else:
    if not text.endswith("\n"):
        text += "\n"
    text += "\n" + new_tls_block
cfg.write_text(text, encoding="utf-8")
PY

  if systemctl list-unit-files | grep -q '^hysteria-server\.service'; then
    systemctl restart hysteria-server.service || true
  fi

  local hook_dir hook
  hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
  hook="${hook_dir}/hy2-sync-hysteria.sh"
  install -d -m 0755 "${hook_dir}"
  cat > "${hook}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${RENEWED_DOMAINS%% *}"
if [[ -z "${DOMAIN}" ]]; then
  exit 0
fi
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
if [[ ! -f "${CERT}" || ! -f "${KEY}" ]]; then
  exit 0
fi
if [[ ! -f /etc/hysteria/config.yaml ]]; then
  exit 0
fi
if id -u hysteria >/dev/null 2>&1; then
  install -o hysteria -g hysteria -m 0644 "${CERT}" /etc/hysteria/fullchain.pem
  install -o hysteria -g hysteria -m 0600 "${KEY}" /etc/hysteria/privkey.pem
else
  install -o root -g root -m 0644 "${CERT}" /etc/hysteria/fullchain.pem
  install -o root -g root -m 0600 "${KEY}" /etc/hysteria/privkey.pem
fi
systemctl restart hysteria-server.service || true
EOF
  chmod 0755 "${hook}"
  HYSTERIA_CERT_SYNC_RESULT="ok"
}

# Служебный HY2 userpass для каскада (шлюз → exit): те же логин/пароль в «Hop Hysteria2».
maybe_add_cascade_hop_user_to_hysteria() {
  if [[ "${CREATE_PANEL_CASCADE_HOP_USER}" != "y" ]]; then
    return 0
  fi
  if [[ ! -f /etc/hysteria/config.yaml ]]; then
    log "CREATE_PANEL_CASCADE_HOP_USER: нет /etc/hysteria/config.yaml — пропуск."
    return 0
  fi
  log "Служебный HY2 hop «${PANEL_CASCADE_HOP_USER}» (скрыт в UI при HY2_UI_HIDDEN_USERS)..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-yaml >/dev/null 2>&1 || {
    log "Установите: apt-get install -y python3-yaml"
    return 0
  }
  local hop_pass creds_file env_tmp
  hop_pass="$(random_hex 16)"
  creds_file="/root/.hy2-admin-cascade-hop.creds"
  export PANEL_CASCADE_HOP_USER
  export PANEL_CASCADE_HOP_PASS="${hop_pass}"
  if ! python3 <<'PY'
import os
from pathlib import Path
import sys

import yaml

hop_user = os.environ["PANEL_CASCADE_HOP_USER"]
hop_pass = os.environ["PANEL_CASCADE_HOP_PASS"]
cfg_path = Path("/etc/hysteria/config.yaml")
cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
auth = cfg.setdefault("auth", {})
auth["type"] = "userpass"
up = auth.get("userpass")
if not isinstance(up, dict):
    up = {}
if hop_user in up:
    print("exists")
    sys.exit(0)
up[hop_user] = hop_pass
auth["userpass"] = up
cfg_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
print("ok")
PY
  then
    log "Не удалось записать /etc/hysteria/config.yaml."
    return 0
  fi
  {
    echo "# Совпадает с hop_username / hop_password в каскаде панели."
    echo "HY2_USERNAME=${PANEL_CASCADE_HOP_USER}"
    echo "HY2_PASSWORD=${hop_pass}"
  } > "${creds_file}"
  chmod 0600 "${creds_file}" || true
  log "Учётные данные hop: ${creds_file}"

  env_tmp="$(mktemp)"
  grep -v '^HY2_UI_HIDDEN_USERS=' "${INSTALL_DIR}/.env" > "${env_tmp}" || cp "${INSTALL_DIR}/.env" "${env_tmp}"
  echo "HY2_UI_HIDDEN_USERS=${PANEL_CASCADE_HOP_USER}" >> "${env_tmp}"
  mv "${env_tmp}" "${INSTALL_DIR}/.env"
  chmod 0600 "${INSTALL_DIR}/.env"

  if systemctl list-unit-files 2>/dev/null | grep -q '^hysteria-server\.service'; then
    systemctl restart hysteria-server.service || true
  fi
  if [[ -f /usr/local/bin/hy2-sync-users-to-singbox.py ]]; then
    python3 /usr/local/bin/hy2-sync-users-to-singbox.py 2>/dev/null || true
    systemctl try-restart sing-box.service 2>/dev/null || true
  fi
}

setup_fail2ban() {
  mkdir -p /etc/fail2ban/jail.d
  cat > /etc/fail2ban/jail.d/sshd-hard.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
findtime = 10m
bantime = 4h
EOF
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban || true
}

setup_ufw() {
  ufw allow 443/tcp >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
}

print_summary() {
  local panel_url
  panel_url="https://${SERVER_HOST}${PANEL_URL_PREFIX}/"
  echo
  echo "========== Установка панели завершена =========="
  echo "URL панели: ${panel_url}"
  echo "Логин:      ${PANEL_USER}"
  echo "Пароль:     ${PANEL_PASS}"
  echo "Secret:     ${PANEL_SESSION_SECRET}"
  echo
  echo "Проверка:"
  echo "  systemctl status ${SERVICE_NAME}"
  echo "  systemctl is-active ${SERVICE_NAME}"
  echo "  systemctl is-enabled ${SERVICE_NAME}"
  echo "  systemctl status nginx"
  if [[ "${HYSTERIA_CERT_SYNC_RESULT}" == "ok" ]]; then
    echo "  Hysteria: cert sync выполнен (/etc/hysteria/fullchain.pem, /etc/hysteria/privkey.pem)"
  elif [[ "${HYSTERIA_CERT_SYNC_RESULT}" == "hysteria_config_not_found" ]]; then
    echo "  Hysteria: конфиг не найден, cert sync пропущен"
  fi
  if [[ -f /root/.hy2-admin-cascade-hop.creds ]]; then
    echo "  Каскад hop (шлюз→exit): /root/.hy2-admin-cascade-hop.creds"
  fi
  echo "==============================================="
}

main() {
  parse_args "$@"
  require_root

  if [[ "${MODE}" == "interactive" ]]; then
    collect_interactive
  else
    hydrate_auto_from_env
    validate_auto
  fi
  prepare_values

  install_packages
  cleanup_legacy_sources
  download_binary
  prepare_https_root_stub
  write_env
  maybe_add_cascade_hop_user_to_hysteria
  write_systemd_unit
  setup_tls_and_nginx
  if [[ "${USE_LETS_ENCRYPT}" == "y" ]]; then
    sync_hysteria_certbot_materials
  fi
  setup_fail2ban
  setup_ufw
  print_summary
}

main "$@"
