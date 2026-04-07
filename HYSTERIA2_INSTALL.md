# Установка Hysteria2

Отдельная инструкция для скрипта `install_hysteria2.sh`.

✅ Протестировано на **Ubuntu 24.04**

---

## Быстрый старт

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --auto --domain your.domain.com --email you@example.com
```

---

## Автоматический режим

```bash
./install_hysteria2.sh --auto --domain your.domain.com --email you@example.com
```

или без клонирования:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --auto --domain your.domain.com --email you@example.com
```

---

## Интерактивный режим

```bash
./install_hysteria2.sh --interactive
```

или без клонирования:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/refs/heads/main/install_hysteria2.sh)" -- --interactive
```

---

## Все режимы и параметры

Примеры:

```bash
./install_hysteria2.sh --interactive
./install_hysteria2.sh --auto --domain your.domain.com --email you@example.com
./install_hysteria2.sh --auto --domain your.domain.com --email you@example.com --admin-user Admin --admin-pass 0123456789abcdef0123456789abcdef --ssh-port 22
DOMAIN=your.domain.com EMAIL=you@example.com ./install_hysteria2.sh --auto
```

Пояснение по `--ssh-port`: это порт **SSH для UFW-правила**, а не порт Hysteria2.
Нужен в случаях, когда SSH-сервер слушает не `22`, чтобы после включения UFW вы не потеряли доступ к серверу.

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

Что делает скрипт:

1. Обновляет систему (`apt update && apt upgrade -y`)
2. Устанавливает Hysteria2
3. Создает masquerade-страницу `/var/www/masq`
4. Пишет `/etc/hysteria/config.yaml`
5. Настраивает/перезапускает `hysteria-server.service`
6. Настраивает UFW (если не отключено)
7. Показывает итоговые данные и клиентскую ссылку

---

## Обслуживание

```bash
systemctl status hysteria-server.service
systemctl restart hysteria-server.service
journalctl -u hysteria-server.service -n 200 --no-pager
ss -lntup | rg 443
ufw status verbose
```

---

## Удаление

```bash
systemctl disable --now hysteria-server.service
rm -f /etc/systemd/system/hysteria-server.service
systemctl daemon-reload
rm -rf /etc/hysteria
rm -rf /var/www/masq
yes | ufw delete allow 443/udp || true
yes | ufw delete allow 443/tcp || true
yes | ufw delete allow 80/tcp || true
```

---

## Автор

**AntyanMSA**  
GitHub: [https://github.com/AntyanMS](https://github.com/AntyanMS)  
Telegram: [https://t.me/Cmint](https://t.me/Cmint)
