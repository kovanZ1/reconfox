# Changelog

Все значимые изменения проекта документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект следует [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

### Безопасность
- **OPSEC: обогащение гео/ASN через ip-api.com теперь ВЫКЛ по умолчанию.** Раньше
  каждый скан безусловно отправлял IP цели третьей стороне (`ip-api.com`)
  открытым текстом. Включается флагом `--enrich`; флаг `--proxy` маршрутизирует
  этот трафик через прокси. DNS-резолв (нужен для nmap) по-прежнему локальный.
- **Экранирование Markdown-отчёта.** Данные скана (баннеры сервисов, заголовки,
  URL, redirect, ошибки) — подконтрольны цели; теперь они HTML-экранируются и
  обезвреживаются `|` / backtick / переводы строк, чтобы нельзя было внедрить
  HTML/Markdown в отчёт (как уже делал HTML-рендерер).

### Добавлено
- **Таймауты сканеров.** `run_capture` получил параметр `timeout`: по истечении
  дочерний процесс убивается, а не висит вечно. Дефолты: nmap — по режиму
  (quick 600s / full · stealth 3600s), ffuf — 900s, searchsploit — 60s на
  запрос. Переопределяется флагом `--timeout`.
- Юнит-тесты на `core/_proc.run_capture` (успех / ненулевой код / таймаут с kill
  дочернего / отмена с kill).
- **Unix-citizen I/O.** Флаг `--ndjson` стримит находки в stdout по одной
  JSON-строке на запись (target → port/web/http/vuln → summary, со
  `schema_version`), человекочитаемый вывод уходит в stderr — pipe-friendly.
  `-O -` печатает отчёт выбранного формата в stdout. Цель можно подать через
  stdin: `reconfox scan -`.
- **HTTP-fingerprinting** (стадия `http`). reconfox теперь действительно ходит
  HTTP(S) к цели: `core/http_prober.py` (httpx) снимает status, финальный URL
  после редиректов, `<title>`, заголовок `Server` и набор технологий по
  сигнатурам заголовков/cookie. Пробит сам target и обнаруженные nmap'ом
  http-порты. Результат — в модель `HttpProbe`/`ScanResult.http_probes`, в отчёты
  (Markdown «## HTTP», NDJSON `type:http`, JSON) и в TUI (бар фазы `http`).
  Реализован как новая `Scanner`-стадия — без правок оркестратора.
- **Rate-limit и тюнинг скана.** Прокинуты во флаги: `--threads` и `--rate`
  (ffuf `-t`/`-rate`), `--nmap-min-rate`/`--nmap-max-rate` и `--scan-delay`
  (nmap). Раньше скорость было не настроить, а «stealth» был просто `-T2`;
  теперь скрытность/нагрузку можно задать реально. Дефолты режимов не изменены.
- **nuclei** (стадия `nuclei`, флаг `--nuclei`). Активное сканирование
  уязвимостей по шаблонам: `core/nuclei_scanner.py` гоняет nuclei (`-jsonl`) по
  живым URL из HTTP-проб (fallback — сам target) и маппит находки в
  `Vulnerability` с `source="nuclei"` (severity, CVE, описание, ссылки).
  Интрузивно, потому **opt-in**. Стадии теперь дополняют (`extend`) список
  уязвимостей, а не перезаписывают — searchsploit и nuclei сосуществуют.

### Изменено
- **Архитектура: Scanner Protocol + registry.** Orchestrator стал generic-движком,
  который гоняет самоописывающиеся стадии (`Scanner`: `name`/`phase`/`depends_on`/
  `critical`/`applicable`/`run`) по графу зависимостей, изолируя падения. nmap/ffuf/
  resolver/exploit переехали в адаптеры (`core/stages.py`), стандартный конвейер —
  `default_pipeline()`. Новый сканер теперь добавляется регистрацией, без правок
  оркестратора.

## [0.2.1] — 2026-06-13

### Исправлено
- **opts-дропдауны рендерились пустыми** — `Select` с двойной рамкой схлопывал
  значение в 0 строк. Заменены на cycle-кнопки `mode: quick ▾` / `fmt: md ▾` /
  `msf: off`, которые циклически переключаются по клику — значение всегда видно.
- **LIVE LOG показывал сырую разметку** (`[#00ff5f]...`) — `Log` не парсит
  Rich-markup. Заменён на `RichLog(markup=True)` — цветной вывод.

### Изменено
- TUI приведён к точному соответствию дизайн-референсу:
  - Логотип **larry3d** «reconfox» (3D-outline, чистый ASCII — рендерится
    одинаково в любом терминале; `assets/banner.txt`, грузится в рантайме)
  - opts: `mode: quick ▼` / `format: markdown ▼` / `[ ] msf` (полные слова)
  - Кнопки: `▶ RUN` (зелёная) · `■ ABORT` (залитая янтарём) · `CLEAR` (тусклая)
    · `× QUIT` (красная), скруглённые рамки
  - **PHASES PANEL**: колонка процентов + толстые цветные бары
    (зелёный=done, янтарный=running с анимацией через `set_interval`)
  - **LIVE LOG** и **FINDINGS TABLE** — боксы со скруглённой зелёной рамкой и
    заголовком, встроенным в рамку (`border_title`)
  - FINDINGS — текстовая таблица с разделителями ` | ` (как на референсе),
    через `format_findings_table()` вместо `DataTable`
  - Тёмно-зелёная палитра `#2ee66a`, status bar закреплён внизу (`dock: bottom`)
- TUI-тесты: цикл mode/format, тоггл msf, прогон скана, формат таблицы (9 шт.)

## [0.2.0] — 2026-06-10

### Добавлено
- `install.sh` — однокомандная установка с симлинком в `/usr/local/bin`
- `--output-file/-O` — точный путь к файлу отчёта, формат по расширению
- JSON-формат отчёта (`-f json`, `-f all`)
- `--verbose/-v` — детальный лог каждого шага в CLI
- Поэтапные info-события: IP/ASN/geo от резолвера, каждый открытый порт от nmap,
  каждая веб-находка от ffuf, каждая уязвимость от exploit-finder
- Полный редизайн TUI в "хакерском" стиле:
  - ASCII лого + matrix-green/amber палитра
  - Progress-bars для каждой фазы
  - Live-лог с цветными префиксами `[+]/[*]/[-]/→`
  - Поля для URL, output-файла, выбора формата/режима
  - Биндинги: Ctrl+R запуск, Ctrl+L очистка лога, Ctrl+C выход

### Изменено
- `-f both` переименован в `-f all` (теперь это md + html + json)
- Сообщения CLI на русском с пентест-стилем (`[+] saved html: ...`)

## [0.1.0] — 2026-06-10

Первый рабочий релиз. Все базовые модули.

### Добавлено
- Resolver: URL → IP, ASN, ISP, geolocation через ip-api.com
- Async nmap wrapper с тремя режимами: quick / full / stealth
- Async ffuf wrapper для поиска веб-директорий
- Orchestrator: параллельный запуск nmap+ffuf через asyncio.gather
- Exploit Finder через searchsploit
- Metasploit RPC интеграция (read-only поиск модулей)
- HTML отчёт с тёмной темой (Jinja2)
- Markdown отчёт (GitHub-flavored)
- CLI на Click + Rich с live-прогрессом
- TUI на Textual с одним экраном
- 136 unit-тестов, 100% pass
- ruff линтер в CI
- GitHub Actions CI (Python 3.11/3.12)
- Полная документация в README на русском

### Безопасность
- defusedxml для парсинга XML вывода nmap
- autoescape в Jinja2 для всех пользовательских данных в HTML отчёте
- Metasploit RPC: только поиск модулей, никакого выполнения
- Все секреты только через env (см. .env.example)
