# Установка сервера Hysteria2 (hy2-admin)

Документ описывает получение репозитория, подготовку shell-скриптов и **установку только сервера** (`install_hysteria2.sh`). Все адреса ниже — **примеры-заглушки**: `example.com`, `123.123.123.123`, `admin@example.com`.

**Цепочка инструкций:** [обзор проекта](../README.md) → этап 1 — этот файл → [панель](./INSTALLATION-PANEL.ru.md) → [шлюз sing-box](./INSTALLATION-GATEWAY.ru.md).

---

## 1. Скачивание репозитория

### Вариант A — Git (рекомендуется для разработки и повторяемых установок)

```bash
git clone https://github.com/AntyanMS/hy2-admin.git
cd hy2-admin
```

Переключение на ветку (например, `dev`):

```bash
git checkout dev
git pull
```

### Вариант B — архив без Git

Скачайте ZIP с GitHub (кнопка **Code → Download ZIP**), распакуйте и перейдите в каталог проекта:

```bash
cd hy2-admin
```

---

## 2. Как сделать `.sh` исполняемым

После клонирования скрипты могут быть без бита выполнения. Выдайте права так:

```bash
chmod +x install_hysteria2.sh install_hy2_admin.sh install_singbox_gateway.sh install_server.sh install.sh
```

Остальные этапы: [панель](./INSTALLATION-PANEL.ru.md), [шлюз sing-box](./INSTALLATION-GATEWAY.ru.md).

Проверка:

```bash
ls -l install_hysteria2.sh
# ожидается что-то вроде: -rwxr-xr-x
```

Запуск возможен и без `chmod`, явным интерпретатором:

```bash
sudo bash install_hysteria2.sh --help
```

Для установки сервера обычно нужен **root**:

```bash
sudo ./install_hysteria2.sh ...
```

---

## 3. Установка сервера: `install_hysteria2.sh`

Скрипт ставит **Hysteria2** на чистый Debian/Ubuntu-подобный хост: пакеты, бинарь, конфиг, nginx (при необходимости), UFW, fail2ban, сервис `hysteria-server.service`.

### 3.1. Справка по аргументам

| Флаг | Назначение |
|------|------------|
| `--interactive` | Диалоговый режим (по умолчанию) |
| `--auto` | Без вопросов; нужны обязательные параметры (см. ниже) |
| `--domain <домен>` | Домен для TLS / ACME (пример: `example.com`) |
| `--email <почта>` | Email для Let's Encrypt (пример: `admin@example.com`) |
| `--hy2-user <имя>` | Первый пользователь HY2 (по умолчанию `user1`) |
| `--hy2-pass <пароль>` | Пароль; если не задать в `--auto`, будет случайный |
| `--ssh-port <порт>` | Порт SSH для правил UFW (по умолчанию `22`) |
| `--cascade-node` | Пометить узел как каскадный (exit) и вывести fingerprint |
| `--tls-mode <режим>` | `auto` \| `acme` \| `certbot` (по умолчанию `auto`) |
| `--tls-cert <путь>` | Явный путь к fullchain (для сценариев с certbot) |
| `--tls-key <путь>` | Явный путь к privkey |
| `--skip-ufw` | Не трогать UFW |
| `-h`, `--help` | Краткая справка |

В режиме `--auto` **обязательны** `--domain` и `--email` для типичных режимов `auto` / `acme`. Для `--tls-mode certbot` при отсутствии уже выданных PEM-сертификатов также нужен `--email` (скрипт может выпустить сертификат через nginx + webroot).

---

### 3.2. Интерактивная установка

Самый простой вход — ответить на вопросы скрипта:

```bash
sudo ./install_hysteria2.sh --interactive
```

Укажите, например, домен `example.com`, email `admin@example.com`, пользователя и пароль по подсказкам.

---

### 3.3. Примеры `--auto`: от базового к «наполненному»

Все примеры — **иллюстрация**; подставьте свой домен и почту.

#### Минимальный авто-запуск (домен + почта, пароль HY2 сгенерируется)

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com
```

Режим TLS по умолчанию — `auto` (как в скрипте).

#### Авто с явным первым пользователем и паролем

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --hy2-user client1 \
  --hy2-pass 'YourStrongPassphraseHere'
```

#### Авто + нестандартный SSH-порт для UFW (например, 2222)

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --ssh-port 2222
```

#### Узел каскада (exit)

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --cascade-node
```

#### Явный TLS: `certbot` (удобно, если порт 80 занят под nginx и нужен webroot)

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --tls-mode certbot
```

#### Явный TLS: `acme` (встроенный ACME Hysteria — по смыслу сценария скрипта)

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --tls-mode acme
```

#### Максимально «упакованный» пример (домен, почта, пользователь, пароль, SSH-порт, каскад, certbot)

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --hy2-user client1 \
  --hy2-pass 'YourStrongPassphraseHere' \
  --ssh-port 2222 \
  --tls-mode certbot \
  --cascade-node
```

#### Без изменения UFW

```bash
sudo ./install_hysteria2.sh --auto \
  --domain example.com \
  --email admin@example.com \
  --skip-ufw
```

---

## 4. Онлайн-установка без клонирования (обёртка)

В репозитории есть `install_server.sh`: он подтягивает **ту же** `install_hysteria2.sh` с GitHub и передаёт ей аргументы.

Стабильная ветка по умолчанию — `main`; для тестов можно указать `dev`:

```bash
curl -4fsSL --connect-timeout 25 --max-time 300 \
  https://raw.githubusercontent.com/AntyanMS/hy2-admin/main/install_server.sh | sudo bash -s -- --auto \
  --domain example.com \
  --email admin@example.com
```

С веткой `dev`:

```bash
HY2_INSTALL_REF=dev curl -4fsSL --connect-timeout 25 --max-time 300 \
  https://raw.githubusercontent.com/AntyanMS/hy2-admin/dev/install_server.sh | sudo env HY2_INSTALL_REF=dev bash -s -- --auto \
  --domain example.com \
  --email admin@example.com
```

*(Проверьте актуальность URL ветки и репозитория в вашем форке.)*

---

## 5. Про IP `123.123.123.123`

Скрипт установки сервера сам определяет публичный IPv4 (например, для сводки или проверок). Вам **не обязательно** передавать `123.123.123.123` в аргументах: это лишь **условный пример** внешнего адреса VPS в документации. Реальная привязка TLS и клиентских URI обычно идёт через **домен** (`example.com`).

---

## 6. После установки (краткий чеклист)

```bash
sudo systemctl status hysteria-server.service --no-pager
sudo ss -lunp | grep ':443' || true
```

Дальше по пайплайну:

1. **Этап 2 — панель:** [INSTALLATION-PANEL.ru.md](./INSTALLATION-PANEL.ru.md) (`install_hy2_admin.sh`).
2. **Этап 3 — шлюз sing-box:** [INSTALLATION-GATEWAY.ru.md](./INSTALLATION-GATEWAY.ru.md) (`install_singbox_gateway.sh`).

---

*Репозиторий: [hy2-admin](https://github.com/AntyanMS/hy2-admin). При форке замените URL клонирования и raw-ссылки на свои.*

- [Обзор проекта](../README.md)
