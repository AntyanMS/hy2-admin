# HY2 Admin Installer

Установщик web-панели для управления пользователями Hysteria2.

Скрипт устанавливает панель в `/opt/hy2-admin`, настраивает systemd-сервис `hy2-admin.service`, поднимает Flask+Gunicorn, и выводит ссылку/логин/пароль после установки.

---

## Что в репозитории

- `install_hy2_admin.sh` — единый установщик.

Поддерживаются только два режима запуска:

```bash
./install_hy2_admin.sh --auto
./install_hy2_admin.sh --interactive
```

---

## Возможности установщика

- Проверка запуска от `root`.
- Определение IP сервера (для авто-режима).
- Установка зависимостей (`python3`, `venv`, `pip`, `curl`, `openssl`).
- Создание структуры панели в `/opt/hy2-admin`.
- Генерация логина/пароля панели (пароль всегда случайный).
- Генерация и регистрация `hy2-admin.service`.
- Включение сервиса в автозагрузку (опционально в интерактивном режиме).
- Запуск сервиса (опционально в интерактивном режиме).
- Поддержка HTTP и HTTPS:
  - HTTPS через self-signed сертификат (для IP/без certbot),
  - HTTPS через certbot (для домена).
- Открытие порта в UFW, если UFW активен.

---

## Требования

- ОС: Debian/Ubuntu (используется `apt-get`).
- Права `root`.
- Для HTTPS через certbot:
  - домен должен указывать на сервер,
  - порт 80 должен быть доступен для HTTP-валидации.

---

## Быстрый старт

### 1) Подготовка

```bash
chmod +x install_hy2_admin.sh
```

### 2) Автоматическая установка

```bash
./install_hy2_admin.sh --auto
```

Что делает auto:

- определяет IP сервера,
- ставит панель на HTTP (`http://IP:8787/`),
- включает автозагрузку сервиса,
- запускает сервис,
- печатает финальные доступы.

### 3) Интерактивная установка

```bash
./install_hy2_admin.sh --interactive
```

Что спрашивает interactive:

- порт админки,
- IP или домен,
- HTTP/HTTPS (1/2),
- использовать certbot (если домен + HTTPS),
- добавить в автозагрузку (Y/N),
- запускать сервис сейчас (Y/N),
- пользователь панели `default/custom` (`d/c`).

В конце печатаются:

- ссылка на панель,
- логин,
- сгенерированный пароль.

---

## Параметры запуска

```bash
./install_hy2_admin.sh --auto
./install_hy2_admin.sh --interactive
```

Другие параметры не поддерживаются.

---

## Что устанавливается

### Каталоги и файлы

- `/opt/hy2-admin/app.py`
- `/opt/hy2-admin/templates/index.html`
- `/opt/hy2-admin/requirements.txt`
- `/opt/hy2-admin/.env`
- `/opt/hy2-admin/.venv/`
- `/opt/hy2-admin/data/`
- `/opt/hy2-admin/backups/`
- `/opt/hy2-admin/tls/` (если self-signed HTTPS)

### Systemd

- `/etc/systemd/system/hy2-admin.service`

---

## Управление сервисом

```bash
systemctl status hy2-admin.service
systemctl restart hy2-admin.service
systemctl stop hy2-admin.service
systemctl start hy2-admin.service
systemctl enable hy2-admin.service
systemctl disable hy2-admin.service
journalctl -u hy2-admin.service -n 200 --no-pager
```

---

## Настройки панели

Основные значения в `/opt/hy2-admin/.env`:

- `HY2_CONFIG_PATH` — путь к конфигу Hysteria2.
- `HY2_SERVICE_NAME` — имя сервиса Hysteria2.
- `SERVER_HOST`, `SERVER_PORT`, `SERVER_SNI` — параметры для генерации клиентских URL.
- `PANEL_BASIC_USER`, `PANEL_BASIC_PASS` — доступ в панель.
- `PANEL_BIND_HOST`, `PANEL_BIND_PORT` — адрес/порт панели.
- `PROTECTED_USERS` — защищенные пользователи, которых нельзя отключить/удалить массово.

После изменения `.env`:

```bash
systemctl restart hy2-admin.service
```

---

## HTTPS сценарии

### HTTPS + домен + certbot

Рекомендуется для production:

- в интерактивном режиме выберите HTTPS,
- укажите домен,
- согласитесь на certbot,
- введите email.

### HTTPS + IP (или без certbot)

Будет self-signed сертификат.

---

## Устранение проблем

### Панель не открывается

1. Проверьте сервис:
   ```bash
   systemctl status hy2-admin.service
   ```
2. Проверьте логи:
   ```bash
   journalctl -u hy2-admin.service -n 200 --no-pager
   ```
3. Проверьте порт:
   ```bash
   ss -lntp | rg 8787
   ```
4. Если UFW включен, проверьте правило:
   ```bash
   ufw status
   ```

### Проблемы с HTTPS/certbot

- Убедитесь, что домен указывает на сервер.
- Убедитесь, что порт 80 доступен.
- Посмотрите логи certbot:
  ```bash
  journalctl -u certbot -n 200 --no-pager
  ```

### Ошибки применения пользователей Hysteria2

- Проверьте путь к конфигу и имя сервиса в `.env`.
- Проверьте права на файл конфига Hysteria2.

---

## Безопасность

- После установки сохраните сгенерированный пароль панели в безопасном месте.
- Для публичного доступа используйте HTTPS.
- Ограничьте доступ к порту панели через firewall, если нужно.
- Регулярно обновляйте систему и зависимости.
