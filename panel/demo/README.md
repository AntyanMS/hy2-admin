# Временный UI-preview на шлюзе

Статическая **полная** страница панели для правки вёрстки без пересборки `hy2-admin-panel`.

## Сборка (локально или на сервере)

```bash
cd panel
pip install jinja2   # один раз
python demo/build_full_ui_preview.py
```

Результат: `panel/demo/index.html` (не в git — генерируется локально, формы отключены).

## Деплой на шлюз

```powershell
scp panel/demo/index.html mskgw:/tmp/index.html
ssh mskgw "sudo cp /tmp/index.html /opt/hy2-admin/ui-preview/index.html"
```

## Файлы

| Файл | Назначение |
|------|------------|
| `build_full_ui_preview.py` | Сборка preview из шаблона |
| `nginx-ui-preview.snippet` | Пример location для nginx |

После правок в `panel/templates/index.html` — пересборка бинаря (`tools/build-panel-linux.sh`).
