#!/usr/bin/env bash
# Онлайн-установка HY2 Admin (аналогично Quick Start из 3x-ui): с GitHub скачивается install_hy2_admin.sh.
# При форке задайте HY2_INSTALL_SCRIPT_URL на свой raw URL.
set -euo pipefail
HY2_INSTALL_REF="${HY2_INSTALL_REF:-main}"
HY2_INSTALL_SCRIPT_URL="${HY2_INSTALL_SCRIPT_URL:-https://raw.githubusercontent.com/AntyanMS/hy2-admin/${HY2_INSTALL_REF}/install_hy2_admin.sh}"
exec bash <(curl -4fsSL --connect-timeout 25 --max-time 300 "${HY2_INSTALL_SCRIPT_URL}") "$@"
