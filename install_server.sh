#!/usr/bin/env bash
# Онлайн-установка Hysteria2 сервера: скачивает install_hysteria2.sh с GitHub.
# Для тестов задайте HY2_INSTALL_REF=dev, для стабильного канала оставьте main.
set -euo pipefail
HY2_INSTALL_REF="${HY2_INSTALL_REF:-main}"
HY2_SERVER_INSTALL_SCRIPT_URL="${HY2_SERVER_INSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/AntyanMS/hy2-admin/${HY2_INSTALL_REF}/install_hysteria2.sh}"
exec bash <(curl -4fsSL --connect-timeout 25 --max-time 300 "${HY2_SERVER_INSTALL_SCRIPT_URL}") "$@"
