# Changelog

Все значимые изменения проекта документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
проект следует [Semantic Versioning](https://semver.org/lang/ru/).

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
