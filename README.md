# HY2 Admin

Минимальный набор для установки Hysteria2 и веб-панели.

## Быстрый старт

### 1) Установить Hysteria2 (VPN)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_hysteria2.sh)" -- --interactive
```

### 2) Установить HY2 Admin (панель)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_hy2_admin.sh)" -- --interactive
```

Для авто-режима замените `--interactive` на `--auto`.

## Важно

- Запускайте от `root`.
- Панель по умолчанию ставится как готовый бинарник из `Releases`.
- Если скрипт скопирован с Windows и ругается на `pipefail`, выполните:

```bash
sed -i 's/\r$//' install_hy2_admin.sh
```

## Подробная документация

- Установка панели и переменные: [`INSTALL.md`](INSTALL.md)
- Релизы: [github.com/AntyanMS/hy2-admin/releases](https://github.com/AntyanMS/hy2-admin/releases)