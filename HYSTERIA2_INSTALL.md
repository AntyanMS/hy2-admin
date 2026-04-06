# Установка Hysteria2 (автоматизировано в один скрипт)

Этот документ описывает скрипт `install_hysteria2.sh`, который автоматизирует вашу инструкцию шаг-в-шаг.

## Что делает скрипт

Скрипт выполняет в одном запуске:

1. Обновление Ubuntu:
   - `apt update`
   - `apt upgrade -y`
2. Установку Hysteria2:
   - `bash <(curl -fsSL https://get.hy2.sh/)`
3. Подготовку сайта-заглушки:
   - создает `/var/www/masq`
   - записывает `index.html` с анимацией `RETRYING CONNECTION`
4. Генерацию/запись `/etc/hysteria/config.yaml`:
   - `listen: 0.0.0.0:443`
   - ACME (`domain`, `email`)
   - `auth.userpass` (Admin + пароль)
   - `masquerade` на `/var/www/masq` + `80/443`
5. Настройку systemd:
   - `systemctl daemon-reload`
   - `systemctl enable hysteria-server.service` (если включено)
   - `systemctl restart hysteria-server.service` (если включено)
6. Настройку UFW:
   - SSH порт (`22` или ваш)
   - `80/tcp`
   - `443/udp`
   - `443/tcp`
   - `ufw --force enable`
7. Вывод финальной информации:
   - IP сервера
   - домен
   - логин
   - пароль
   - статус сервиса
   - клиентская ссылка `hysteria2://...`

---

## Файл скрипта

- `install_hysteria2.sh`

Запуск без клонирования репозитория (скачать и сразу выполнить):

- [Скачать и запустить INTERACTIVE](https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)
  ```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --interactive
  ```
- [Скачать и запустить AUTO](https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)
  ```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --auto --domain your.domain.com --email you@example.com
  ```

---

## Режимы запуска

## Интерактивный режим

```bash
chmod +x install_hysteria2.sh
./install_hysteria2.sh --interactive
```

Или одной командой:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --interactive
```

Скрипт спросит:

- домен,
- email для ACME,
- имя пользователя (по умолчанию `Admin`),
- пароль (если пусто — сгенерируется автоматически),
- SSH порт для UFW,
- включать автозапуск сервиса (Y/N),
- запускать сервис сразу (Y/N),
- настраивать UFW (Y/N).

## Автоматический режим

```bash
./install_hysteria2.sh --auto --domain your.domain.com --email you@example.com
```

Или одной командой:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --auto --domain your.domain.com --email you@example.com
```

Дополнительно (необязательно):

```bash
./install_hysteria2.sh --auto \
  --domain your.domain.com \
  --email you@example.com \
  --admin-user Admin \
  --admin-pass 0123456789abcdef0123456789abcdef \
  --ssh-port 22
```

Можно через env:

```bash
DOMAIN=your.domain.com EMAIL=you@example.com ./install_hysteria2.sh --auto
```

---

## Поддерживаемые флаги

- `--interactive` — интерактивный режим (по умолчанию)
- `--auto` — неинтерактивный режим
- `--domain <domain>` — домен
- `--email <email>` — email для ACME
- `--admin-user <user>` — логин пользователя Hysteria2
- `--admin-pass <pass>` — пароль пользователя Hysteria2
- `--ssh-port <port>` — SSH порт для UFW
- `--no-autostart` — не включать автозапуск службы
- `--no-start` — не запускать службу после установки
- `--skip-ufw` — пропустить настройку UFW
- `-h, --help` — справка

---

## Что важно перед запуском

- запускать только от `root`;
- домен должен указывать на IP сервера;
- порты `80` и `443` должны быть доступны извне;
- если уже есть `/etc/hysteria/config.yaml`, скрипт сделает backup:
  - `/etc/hysteria/config.yaml.bak_YYYYmmdd_HHMMSS`

---

## Проверка после установки

```bash
systemctl status hysteria-server.service
journalctl -u hysteria-server.service -n 100 --no-pager
ufw status verbose
```

Проверка порта:

```bash
ss -lntup | rg 443
```

---

## Пример итоговой клиентской ссылки

```text
hysteria2://Admin:your_password@your.domain.com:443/?sni=your.domain.com#Admin
```

---

## Примечание

Скрипт нацелен именно на автоматизацию вашей исходной инструкции и не устанавливает дополнительную админ-панель.  
Если нужна установка панели управления (web UI), используйте отдельный скрипт панели.
