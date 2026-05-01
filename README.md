# HY2 Installers

Набор из двух установщиков:

- `install_hysteria2.sh` — установка VPN-сервера (Hysteria2).
- `install_hy2_admin.sh` — установка HTTPS-панели управления.

## Быстрый старт

Установка сервера:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_hysteria2.sh)" -- --interactive
```

Установка панели:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_hy2_admin.sh)" -- --interactive
```

## Что важно

- Внешний доступ панели: только `443/tcp` (HTTPS через nginx).
- VPN: `443/udp` (HY2), плюс `443/tcp`/`80/tcp` при TLS/masquerade.
- Локальный backend панели работает на внутреннем порту (по умолчанию `127.0.0.1:18080`).
- Скрипт панели всегда генерирует `PANEL_SESSION_SECRET`.
- Скрипт сервера в конце печатает 1 готового пользователя и команды проверки systemd.

## Проверка после установки

Сервер:

```bash
systemctl status hysteria-server.service
systemctl is-active hysteria-server.service
systemctl is-enabled hysteria-server.service
```

Панель:

```bash
systemctl status hy2-admin.service
systemctl is-active hy2-admin.service
systemctl is-enabled hy2-admin.service
systemctl status nginx
```

## Каскадный режим (серверный установщик)

Если при установке сервера выбран режим каскадного узла, в конце выводятся:

- `Fingerprint`
- `Registration token`
- путь к файлу с метаданными узла

## Документация

- [INSTALL.md](INSTALL.md) — детально по установке панели.
- [docs/CASCADE.md](docs/CASCADE.md) — заметки по каскадной схеме.
