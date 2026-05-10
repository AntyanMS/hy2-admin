# Установка веб-панели HY2 Admin (hy2-admin)

Документ описывает получение репозитория, права на shell-скрипты и **установку только панели** (`install_hy2_admin.sh`). Все адреса ниже — **примеры-заглушки**: `example.com`, `123.123.123.123`, `admin@example.com`.

Панель обычно ставят **после** сервера Hysteria2 на том же хосте (см. [установку сервера](./INSTALLATION-SERVER.ru.md)). Опциональный **этап 3** — шлюз sing-box: [INSTALLATION-GATEWAY.ru.md](./INSTALLATION-GATEWAY.ru.md).

**Цепочка инструкций:** [обзор](../README.md) → [сервер](./INSTALLATION-SERVER.ru.md) → **панель (этот файл)** → [шлюз sing-box](./INSTALLATION-GATEWAY.ru.md).

---

## 1. Скачивание репозитория

### Вариант A — Git

```bash
git clone https://github.com/AntyanMS/hy2-admin.git
cd hy2-admin
```

Ветка для тестов, например `dev`:

```bash
git checkout dev
git pull
```

### Вариант B — архив ZIP

Распакуйте архив с GitHub и перейдите в каталог проекта:

```bash
cd hy2-admin
```

---

## 2. Как сделать `.sh` исполняемым

```bash
chmod +x install_hy2_admin.sh install_hysteria2.sh install_singbox_gateway.sh install.sh install_server.sh
```

Проверка:

```bash
ls -l install_hy2_admin.sh
```

Запуск без `chmod`:

```bash
sudo bash install_hy2_admin.sh --help
```

Установка панели выполняется от **root**:

```bash
sudo ./install_hy2_admin.sh ...
```

---

## 3. Что делает `install_hy2_admin.sh`

- Ставит зависимости (`nginx`, `certbot` при домене, `fail2ban`, `ufw` и т.д.).
- Скачивает **бинарь** панели (по умолчанию с GitHub Releases, тег задаётся переменной `HY2_PANEL_RELEASE_TAG`, по умолчанию в скрипте — например `v0.0.3`).
- Пишет `/opt/hy2-admin/.env`, unit `hy2-admin.service`, конфиг сайта nginx.
- При указании домена и почты настраивает **Let's Encrypt** и HTTPS для панели.
- Опционально синхронизирует материалы сертификата в конфиг Hysteria (если он есть на машине).

Внутренний порт панели по умолчанию — `127.0.0.1:18080` (можно переопределить, см. ниже).

---

## 4. Справка по аргументам CLI

| Флаг | Назначение |
|------|------------|
| `--interactive` | Диалоговый режим (по умолчанию) |
| `--auto` | Неинтерактивный режим |
| `--domain <домен>` | Публичный домен панели (пример: `example.com`); включает Let's Encrypt |
| `--email <почта>` | Email для Let's Encrypt (пример: `admin@example.com`); обязателен при новом домене без уже существующего сертификата |
| `--panel-user <логин>` | Логин Basic-auth панели (только с `--manual-creds`) |
| `--panel-pass <пароль>` | Пароль панели (только с `--manual-creds`) |
| `--manual-creds` | Не генерировать случайные учётные данные |
| `--random-creds` | Сгенерировать логин/пароль (поведение по умолчанию в части сценариев) |
| `--panel-url-prefix </секрет/panel>` | Явный префикс URL панели (иначе случайный или из env) |
| `--binary-url <url>` | Другой URL бинаря панели |
| `--create-cascade-hop` | Добавить служебного пользователя HY2 для hop/каскада |
| `-h`, `--help` | Краткая справка |

### Режим `--auto` без флагов домена

Если **не** передавать `--domain`:

- скрипт пытается **вывести домен** из `/etc/hysteria/config.yaml` (ACME → `domains`) или из nginx `hy2-site.conf` / `hy2-admin-panel` (`server_name`);
- если домен не найден — HTTPS на **самоподписанном** сертификате по IPv4 хоста (условно тот же смысл, что и публичный адрес вида `123.123.123.123`);
- логин/пароль по умолчанию — **random** (`admin` + случайный пароль), префикс URL — **случайный**.

### Переменные окружения `HY2_ADMIN_*` (альтернатива длинной команде)

Можно задать в оболочке или в файле `/etc/hy2-admin/install.env` / `/root/.hy2-admin-install.env` (формат `KEY=value`):

| Переменная | Соответствие |
|------------|----------------|
| `HY2_ADMIN_DOMAIN` | `--domain` |
| `HY2_ADMIN_EMAIL` | `--email` |
| `HY2_ADMIN_PANEL_USER` | логин панели (включает ручные учётные данные) |
| `HY2_ADMIN_PANEL_PASS` | пароль панели |
| `HY2_ADMIN_RANDOM_CREDS` | `y` / `n` — как `--random-creds` / ручной режим |
| `HY2_ADMIN_PANEL_URL_PREFIX` | префикс URL |
| `HY2_ADMIN_BINARY_URL` | URL бинаря (аналог `--binary-url`) |
| `HY2_ADMIN_CREATE_CASCADE_HOP` | `y` — как `--create-cascade-hop` |
| `HY2_ADMIN_INSTALL_ENV` | явный путь к env-файлу |
| `HY2_ADMIN_INTERNAL_PORT` | порт биндинга панели (по умолчанию `18080`) |

Дополнительно для выбора релиза бинаря:

- `HY2_PANEL_RELEASE_TAG` — тег на GitHub Releases (например `v0.0.3`);
- `HY2_PANEL_URL` — полный URL бинаря (если задан, имеет приоритет в логике скрипта над шаблоном по тегу).

---

## 5. Интерактивная установка

```bash
sudo ./install_hy2_admin.sh --interactive
```

Скрипт спросит домен (или Enter для работы по IP), email при домене, режим учётных данных и опционально префикс URL.

---

## 6. Примеры `--auto`: от базового к наполненному

Все команды — **иллюстрация**; замените домен, почту и секреты на свои.

### Минимальный авто-запуск (домен и почта из стека или только IP)

Полезно, когда Hysteria и nginx уже настроены с `example.com`:

```bash
sudo ./install_hy2_admin.sh --auto
```

Если домен не удастся определить, панель поднимется с **самоподписанным** HTTPS на IPv4 (в документации для наглядности это может быть `123.123.123.123`).

### Авто с явным доменом и почтой (Let's Encrypt)

```bash
sudo ./install_hy2_admin.sh --auto \
  --domain example.com \
  --email admin@example.com
```

### Авто с ручными логином и паролем панели

```bash
sudo ./install_hy2_admin.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --manual-creds \
  --panel-user paneluser \
  --panel-pass 'YourStrongPanelPassword'
```

### Авто с фиксированным префиксом URL (без случайного slug)

Префикс должен заканчиваться на `/panel` в терминах скрипта; можно передать короткий секрет — скрипт нормализует:

```bash
sudo ./install_hy2_admin.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --panel-url-prefix /mysecret/panel
```

### Авто + служебный hop-пользователь для каскада

```bash
sudo ./install_hy2_admin.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --create-cascade-hop
```

### Авто с переопределением URL бинаря панели

```bash
sudo ./install_hy2_admin.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --binary-url https://github.com/example-org/example-repo/releases/download/v0.0.0/hy2-admin-panel
```

### «Максимально упакованный» пример (домен, почта, ручные учётные данные, префикс, hop, свой тег релиза)

```bash
sudo HY2_PANEL_RELEASE_TAG=v0.0.3 ./install_hy2_admin.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --manual-creds \
  --panel-user paneluser \
  --panel-pass 'YourStrongPanelPassword' \
  --panel-url-prefix /mysecret/panel \
  --create-cascade-hop
```

### Тот же сценарий через файл `install.env`

```bash
sudo mkdir -p /etc/hy2-admin
sudo tee /etc/hy2-admin/install.env >/dev/null <<'EOF'
HY2_ADMIN_DOMAIN=example.com
HY2_ADMIN_EMAIL=admin@example.com
HY2_ADMIN_PANEL_USER=paneluser
HY2_ADMIN_PANEL_PASS=YourStrongPanelPassword
HY2_ADMIN_RANDOM_CREDS=n
HY2_ADMIN_PANEL_URL_PREFIX=/mysecret/panel
HY2_ADMIN_CREATE_CASCADE_HOP=y
EOF

sudo ./install_hy2_admin.sh --auto
```

---

## 7. Онлайн-установка без клонирования (`install.sh`)

Скрипт `install.sh` подтягивает с GitHub **`install_hy2_admin.sh`** и передаёт ему аргументы.

Ветка по умолчанию — `main`; для `dev`:

```bash
HY2_INSTALL_REF=dev curl -4fsSL --connect-timeout 25 --max-time 300 \
  https://raw.githubusercontent.com/AntyanMS/hy2-admin/dev/install.sh | sudo env HY2_INSTALL_REF=dev bash -s -- --auto \
  --domain example.com \
  --email admin@example.com
```

*(При форке замените организацию/репозиторий или задайте `HY2_INSTALL_SCRIPT_URL` внутри `install.sh`.)*

---

## 8. Про IP `123.123.123.123`

Если **не** задан домен и автоопределение не нашло имя в конфигах, панель может быть выдана с **самоподписанным** сертификатом на CN, соответствующем IPv4 сервера. В примерах документации `123.123.123.123` — условный внешний IP VPS; в браузере появится предупреждение о сертификате, пока не настроите нормальный домен и Let's Encrypt.

---

## 9. После установки

```bash
sudo systemctl status hy2-admin.service --no-pager
sudo systemctl is-active nginx
```

URL панели скрипт выводит в конце (вида `https://example.com/<префикс>/`).

Отключение конфликтующего дубля nginx: если ранее включали отдельный `hy2-site.conf` с тем же `server_name`, современный инсталлятор панели может отключать такой линк, чтобы не было предупреждений nginx о дублирующемся `server_name`.

**Следующий шаг (опционально):** шлюз sing-box — [этап 3](./INSTALLATION-GATEWAY.ru.md).

---

## 10. Связанные документы

- [Обзор проекта](../README.md)
- [Установка сервера Hysteria2 (этап 1)](./INSTALLATION-SERVER.ru.md)
- [Установка шлюза sing-box (этап 3)](./INSTALLATION-GATEWAY.ru.md) — `install_singbox_gateway.sh`

---

*Репозиторий: [hy2-admin](https://github.com/AntyanMS/hy2-admin).*
