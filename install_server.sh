#!/usr/bin/env bash
# Онлайн-установка Hysteria2 сервера: скачивает install_hysteria2.sh с GitHub.
# По умолчанию ветка main. Для своего форка: HY2_INSTALL_REF или полный HY2_SERVER_INSTALL_SCRIPT_URL.
set -euo pipefail
HY2_INSTALL_REF="${HY2_INSTALL_REF:-main}"
HY2_SERVER_INSTALL_SCRIPT_URL="${HY2_SERVER_INSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/AntyanMS/hy2-admin/${HY2_INSTALL_REF}/install_hysteria2.sh}"
exec bash <(curl -4fsSL --connect-timeout 25 --max-time 300 "${HY2_SERVER_INSTALL_SCRIPT_URL}") "$@"
