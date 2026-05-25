# hy2-admin-panel v0.0.5

## Панель

- Direct routing: блок **Custom** (сворачиваемая таблица), синхронизация **GitHub whitelist** из [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) (`whitelist.txt`), DNS → IP → правила `direct`, автообновление раз в сутки.
- Toast-уведомления, улучшения UI (каскад, трафик, резервное копирование, отложенный restart sing-box, исправление geoip-ru rule-set).
- UI-preview: `panel/demo/build_full_ui_preview.py` (артефакт `index.html` не в git).

## Установка

Скачать бинарь: [hy2-admin-panel](https://github.com/AntyanMS/hy2-admin/releases/download/v0.0.5/hy2-admin-panel) или Latest после публикации.

```bash
sudo HY2_PANEL_RELEASE_TAG=v0.0.5 ./install_hy2_admin.sh ...
```

## Внешние данные

Whitelist доменов загружается с GitHub (см. [README](../README.md#синхронизация-whitelist-для-direct-routing-github)). Спасибо [**hxehex**](https://github.com/hxehex) за репозиторий [russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist).
