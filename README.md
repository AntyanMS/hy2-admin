# Hysteria2 + HY2 Admin

Единый проект из двух установщиков:

- `install_hysteria2.sh` — установка сервера Hysteria2
- `install_hy2_admin.sh` — установка web-панели управления

✅ Протестировано на **Ubuntu 24.04**

---

## 1) Установка сервера Hysteria2

### Быстрый старт

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --auto --domain your.domain.com --email you@example.com
```

### Автоматический режим

```bash
./install_hysteria2.sh --auto --domain your.domain.com --email you@example.com
```

### Интерактивный режим

```bash
./install_hysteria2.sh --interactive
```

### Все режимы и параметры

```bash
./install_hysteria2.sh --interactive
./install_hysteria2.sh --auto --domain your.domain.com --email you@example.com
./install_hysteria2.sh --auto --domain your.domain.com --email you@example.com --admin-user Admin --admin-pass 0123456789abcdef0123456789abcdef --ssh-port 22
DOMAIN=your.domain.com EMAIL=you@example.com ./install_hysteria2.sh --auto
```

Пояснение по `--ssh-port`: это порт **SSH для UFW-правила доступа**, а не порт Hysteria2.
Указывайте его, если SSH на сервере работает не на `22` (например `2222`), чтобы не потерять доступ после настройки firewall.

Поддерживаемые флаги:

- `--interactive`
- `--auto`
- `--domain <domain>`
- `--email <email>`
- `--admin-user <user>`
- `--admin-pass <pass>`
- `--ssh-port <port>`
- `--no-autostart`
- `--no-start`
- `--skip-ufw`
- `-h`, `--help`

### Обслуживание

```bash
systemctl status hysteria-server.service
systemctl restart hysteria-server.service
journalctl -u hysteria-server.service -n 200 --no-pager
ss -lntup | rg 443
ufw status verbose
```

### Удаление

```bash
systemctl disable --now hysteria-server.service
rm -f /etc/systemd/system/hysteria-server.service
systemctl daemon-reload
rm -rf /etc/hysteria
rm -rf /var/www/masq
```

> Подробная инструкция по серверу: `HYSTERIA2_INSTALL.md`

---

## 2) Установка админки HY2 Admin

### Быстрый старт

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hy2_admin.sh)" -- --auto
```

### Автоматический режим

```bash
./install_hy2_admin.sh --auto
```

### Интерактивный режим

```bash
./install_hy2_admin.sh --interactive
```

### Все режимы и варианты запуска

```bash
./install_hy2_admin.sh --auto
./install_hy2_admin.sh --interactive
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hy2_admin.sh)" -- --auto
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hy2_admin.sh)" -- --interactive
```

Скрипт ставит панель в `/opt/hy2-admin`, создает `hy2-admin.service`, включает защитные параметры Gunicorn (gthread, timeout, recycling воркеров), включает `ufw limit` на порт панели (если UFW активен), и выводит ссылку/логин/пароль.

### Обслуживание

```bash
systemctl status hy2-admin.service
systemctl restart hy2-admin.service
journalctl -u hy2-admin.service -n 200 --no-pager
ss -lntp | rg 8787
ufw status
```

Полезные пути:

- `/opt/hy2-admin/app.py`
- `/opt/hy2-admin/templates/index.html`
- `/opt/hy2-admin/.env`
- `/etc/systemd/system/hy2-admin.service`

### Удаление

```bash
systemctl disable --now hy2-admin.service
rm -f /etc/systemd/system/hy2-admin.service
systemctl daemon-reload
rm -rf /opt/hy2-admin
yes | ufw delete limit 8787/tcp || true
yes | ufw delete allow 8787/tcp || true
```

---

## Возможности панели

- Управление пользователями Hysteria2 (создание/отключение/включение/удаление)
- Режимы `Manual` и `Prefix`
- QR и `hysteria2://` ссылки
- Статистика трафика и онлайн
- Лимиты: трафик, срок, дата, скорость `Up/Down`, лимит подключений
- Бейдж `xN` в свернутом списке для подключений с нескольких устройств
- Модальное окно настройки серверного `bandwidth`
- Безопасное применение конфига с backup + rollback

---

## Автор

**AntyanMSA**  
GitHub: [https://github.com/AntyanMS](https://github.com/AntyanMS)  
Telegram: [https://t.me/Cmint](https://t.me/Cmint)
