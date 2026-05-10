# Установка шлюза sing-box (этап 3, hy2-admin)

Документ описывает **переключение хоста в режим gateway**: внешний вход — **sing-box** (Hysteria2 inbound на `443/udp`), локальный **Hysteria** уходит на **control-plane** `127.0.0.1:24443`, синхронизация пользователей из `/etc/hysteria/config.yaml` в inbound sing-box. Все имена и адреса ниже — **примеры-заглушки**: `example.com`, `123.123.123.123`, пользователь `example_hop_user`.

**Цепочка инструкций:** [обзор](../README.md) → [этап 1 — сервер](./INSTALLATION-SERVER.ru.md) → [этап 2 — панель](./INSTALLATION-PANEL.ru.md) → **шлюз sing-box (этот файл)**.

---

## 1. Когда запускать этап 3

- Уже выполнены [установка сервера](./INSTALLATION-SERVER.ru.md) и [установка панели](./INSTALLATION-PANEL.ru.md) на **том же** хосте (типичный сценарий).
- В `/etc/hysteria/config.yaml` есть рабочий `auth.userpass` и TLS-материалы, согласованные с панелью.
- Для **каскада** в панели настроены узлы-exit; скрипт читает `/opt/hy2-admin/data/cascade/remote_servers.json` (роль `exit`, флаг `cascade_exit`). Если файла нет или список пуст, sing-box всё равно поднимется, но исходящий каскад будет ограничен конфигом по умолчанию.

---

## 2. Скачивание репозитория и права на скрипты

Кратко (подробнее в [INSTALLATION-SERVER.ru.md](./INSTALLATION-SERVER.ru.md)):

```bash
git clone https://github.com/AntyanMS/hy2-admin.git
cd hy2-admin
chmod +x install_singbox_gateway.sh install_hysteria2.sh install_hy2_admin.sh
```

Запуск от **root**:

```bash
sudo ./install_singbox_gateway.sh ...
```

---

## 3. Что делает `install_singbox_gateway.sh`

1. По желанию создаёт **резервную копию** в `/opt/hy2-admin/backups/pre-singbox-<время>/`.
2. При отсутствии бинаря **скачивает sing-box** с GitHub Releases (архитектура `amd64` / `arm64`).
3. Генерирует **`/etc/sing-box/config.json`**: inbound `hysteria2` на `::443`, outbounds `direct` / `block` / каскадные `hysteria2` из панели, маршрутизация (в т.ч. rule-set `geoip-ru` с удалённого URL).
4. Останавливает Hysteria на публичном `:443`, поднимает **sing-box** на `:443`, переводит **listen** Hysteria на **`127.0.0.1:24443`**, перезапускает сервисы.
5. Устанавливает **синхронизацию** пользователей: `hy2-sync-users-to-singbox.service` + **`hy2-sync-users-to-singbox.path`** (запуск при изменении `/etc/hysteria/config.yaml`). Скрипт синка перезапускает `sing-box` **только если** список пользователей в конфиге реально изменился. Старый периодический таймер при повторном запуске установщика **отключается**.

---

## 4. Аргументы CLI

| Флаг | Назначение |
|------|------------|
| `--service-user <имя>` | Учётная запись HY2 из `auth.userpass`, пароль которой используется как **hop** на exit-узлах каскада (если не указан — **автоопределение**: предпочитается пользователь без `cascade`/`hop` в имени) |
| `--skip-backup` | Не создавать каталог backup перед переключением |
| `-h`, `--help` | Справка |

---

## 5. Переменные окружения (дополнительно)

| Переменная | Назначение |
|------------|------------|
| `SERVICE_USER` | То же, что `--service-user` |
| `SKIP_BACKUP=1` | То же, что `--skip-backup` |
| `SINGBOX_LB_MODE` | Режим выбора exit: `urltest` (по умолчанию) или `rr` (round-robin через `selector`) |
| `SINGBOX_GEOIP_RU_URL` | URL для скачивания rule-set `geoip-ru.srs` |
| `SINGBOX_BIN` | Путь к бинарю sing-box (по умолчанию `/usr/local/bin/sing-box`) |
| `SINGBOX_CONFIG_PATH` | Путь к JSON-конфигу (по умолчанию `/etc/sing-box/config.json`) |

---

## 6. Примеры запуска

### Минимальный (всё авто, в т.ч. `service-user`)

```bash
sudo ./install_singbox_gateway.sh
```

### Явный служебный пользователь для hop (имя из вашего `config.yaml`)

```bash
sudo ./install_singbox_gateway.sh --service-user example_hop_user
```

### Без создания локального backup

```bash
sudo SKIP_BACKUP=1 ./install_singbox_gateway.sh
```

или

```bash
sudo ./install_singbox_gateway.sh --skip-backup
```

### Режим балансировки `rr` вместо `urltest`

```bash
sudo SINGBOX_LB_MODE=rr ./install_singbox_gateway.sh
```

### Комбинированный пример

```bash
sudo SINGBOX_LB_MODE=urltest ./install_singbox_gateway.sh --service-user example_hop_user
```

---

## 7. Запуск без клонирования (raw-скрипт с GitHub)

Если репозиторий не клонировали, можно передать скрипт в `bash` по URL (ветка `main`; для тестов замените на `dev`):

```bash
curl -4fsSL --connect-timeout 25 --max-time 300 \
  https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_singbox_gateway.sh | sudo bash -s --
```

С явным пользователем:

```bash
curl -4fsSL --connect-timeout 25 --max-time 300 \
  https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_singbox_gateway.sh | sudo bash -s -- --service-user example_hop_user
```

*(При форке замените `AntyanMS/hy2-admin` и при необходимости ветку.)*

---

## 8. Про `example.com` и `123.123.123.123`

Публичный **домен** и **IP** клиенты по-прежнему берут из вашего URI Hysteria; этап 3 не заменяет DNS. `123.123.123.123` в документации — условный внешний IP; реальные сертификаты и SNI остаются связанными с **`example.com`** или вашим доменом, как настроено на этапах 1–2.

---

## 9. После установки

```bash
sudo systemctl status sing-box.service --no-pager
sudo systemctl status hysteria-server.service --no-pager
sudo systemctl status hy2-sync-users-to-singbox.path --no-pager
sudo ss -lunp | grep -E ':443|:24443' || true
```

Проверьте панель: пользователи, каскад, direct routing — как прежде, с учётом того, что входящий трафик пользователей идёт через sing-box.

---

## 10. Связанные документы

- [Обзор проекта](../README.md)
- [Установка сервера Hysteria2 (этап 1)](./INSTALLATION-SERVER.ru.md)
- [Установка панели (этап 2)](./INSTALLATION-PANEL.ru.md)

---

*Репозиторий: [hy2-admin](https://github.com/AntyanMS/hy2-admin).*
