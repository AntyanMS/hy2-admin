# Установка панели (HTTPS-only)

## 1) Запуск

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/AntyanMS/hy2-admin/HEAD/install_hy2_admin.sh)" -- --interactive
```

## 2) Логика мастера

1. Запрашивает домен панели.
2. Если домен пустой — автоматически берёт IPv4 сервера.
3. Если домен задан — запрашивает email для Let's Encrypt.
4. Спрашивает режим учётных данных:
   - random `user/pass`
   - ручной `user/pass`
5. `secret` для панели генерируется случайно всегда.

## 3) Что настраивается

- `hy2-admin.service` (панель).
- `nginx` на `443/tcp` (HTTPS).
- Redirect `80 -> 443`.
- Внутренний апстрим панели: `127.0.0.1:18080` (наружу не публикуется).
- `.env` в `/opt/hy2-admin/.env` с `PANEL_SESSION_SECRET`, `PANEL_URL_PREFIX`, `PANEL_BASIC_USER`, `PANEL_BASIC_PASS`.

## 4) Проверка

```bash
systemctl is-active hy2-admin.service
systemctl is-enabled hy2-admin.service
systemctl is-active nginx
curl -k -I https://127.0.0.1/
```

## 5) URL панели

Формат:

`https://<domain-or-ip>/<random_or_custom>/panel/`
