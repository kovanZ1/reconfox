<div align="center">

# 🦊 reconfox

**Разведка веб-цели одной командой — для авторизованного пентеста.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-326%20passing-brightgreen.svg)](#тесты)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-46a2f1.svg)](https://github.com/astral-sh/ruff)

</div>

---

reconfox берёт на себя рутину первого этапа пентеста. Ты даёшь ему URL — он
находит поддомены, резолвит цель, снимает TLS-сертификат, сканирует порты через
nmap, фингерпринтит HTTP, ищет директории через ffuf, гоняет nuclei-шаблоны,
подбирает известные эксплоиты по версиям сервисов и складывает всё в один
аккуратный отчёт. Можно гонять из терминала как `nmap`, а можно — в живом
TUI с прогресс-барами.

```
                         URL / список / CIDR / stdin
                                    │
        ┌───────────────┬──────────┴──────────┐
        ▼               ▼                      │
  ┌───────────┐  ┌───────────┐                 │  первая волна
  │subdomains │  │ Resolver  │  IP·ASN·geo      │  (без зависимостей)
  │ crt.sh+DNS│  │+scope-guard│                 │
  └───────────┘  └─────┬─────┘                 │
                       │  (resolve — critical)  │
        ┌──────────────┼───────────────┐
        ▼              ▼               ▼
    ┌──────┐       ┌──────┐        ┌──────┐
    │ tls  │       │ nmap │        │ ffuf │   TLS-cert / порты+сервисы / веб-пути
    └──────┘       └──┬───┘        └──────┘
                      ▼
                 ┌────────┐
                 │  http  │   status·title·server·tech
                 └───┬────┘
             ┌───────┴────────┐   запускаются параллельно
             ▼                ▼
       ┌──────────┐     ┌─────────────┐
       │  nuclei  │     │  exploits   │   шаблоны / searchsploit·Metasploit
       └────┬─────┘     └──────┬──────┘
            └────────┬─────────┘
                 ┌───▼────┐
                 │ Отчёт  │   HTML · Markdown · JSON · NDJSON · SARIF
                 └────────┘
```

Оркестратор — обобщённый движок: он гоняет самоописывающиеся стадии
(`Scanner`-протокол) по графу зависимостей, параллеля независимые и изолируя
падения. Новый сканер добавляется регистрацией, без правок оркестратора.

> ⚠️ **Только для легального использования.**
> reconfox создан для своих систем, авторизованного пентеста с письменным
> разрешением владельца, обучения на стендах (DVWA, HackTheBox, TryHackMe,
> Metasploitable) и CTF. Несанкционированное сканирование чужих систем может
> нарушать закон (ст. 272–274 УК РФ). Ответственность за применение — на тебе.

---

## Установка

Самый быстрый путь — скрипт. Он поднимает изолированный venv в
`~/.local/share/reconfox`, ставит пакет и кладёт симлинк в `/usr/local/bin`,
после чего `reconfox` работает из любой папки:

```bash
git clone https://github.com/kovanZ1/reconfox.git
cd reconfox
./install.sh
```

Полезные флаги: `--prefix /opt/reconfox` (свой путь), `--no-link` (без
симлинка), `--uninstall` (снести всё).

**Для разработки** — обычный editable-install:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,msf]"
```

reconfox — обёртка над системными утилитами, так что их нужно поставить
отдельно (Kali/Debian):

```bash
sudo apt install nmap ffuf exploitdb seclists
sudo apt install metasploit-framework   # только если будешь использовать --metasploit
```

---

## Как пользоваться

### TUI (по умолчанию)

Запусти без аргументов:

```bash
reconfox
```

Откроется тёмный «хакерский» интерфейс на Textual: ASCII-лого, поля для URL и
файла отчёта, переключатели режима/формата, прогресс-бары по каждой фазе
(resolve → nmap → ffuf → exploits), живой лог и таблица открытых портов в
реальном времени. Горячие клавиши: `Ctrl+R` — запуск, `Ctrl+L` — очистить
лог, `Ctrl+C` — выход.

### CLI (headless)

Для скриптов и CI — флаг `--no-tui`:

```bash
# быстрый скан, Markdown-отчёт в ./reports
reconfox scan https://example.com --no-tui

# конкретный файл — формат берётся из расширения (.md/.html/.json/.sarif)
reconfox scan https://example.com -O ./scan.html --no-tui

# полный скан с поддоменами и nuclei, все форматы сразу, подробный лог
reconfox scan https://example.com -m full --scan-subdomains --nuclei -f all -v --no-tui

# несколько целей + NDJSON в pipe (человеческий вывод уходит в stderr)
reconfox scan a.com b.com 10.0.0.0/24 --ndjson --no-tui | jq .

# CI-гейт: выйти с кодом 3, если есть уязвимость high и выше
reconfox scan https://example.com --nuclei --fail-on high --no-tui
```

Основные опции `reconfox scan <URL...>`:

| Опция | Что делает |
|---|---|
| `-m, --mode [quick\|full\|stealth]` | профиль nmap (по умолчанию `quick`) |
| `-o, --output PATH` | папка для отчётов (по умолчанию `./reports`) |
| `-O, --output-file PATH` | точный путь к файлу (`-O -` — в stdout); формат по расширению |
| `-f, --format [md\|html\|json\|sarif\|all]` | формат(ы) отчёта |
| `-iL, --target-file PATH` | файл со списком целей (по строке на цель) |
| `--subdomains` / `--scan-subdomains` | искать поддомены / и прогнать по каждому весь конвейер |
| `--nuclei` | активное сканирование уязвимостей через nuclei (opt-in) |
| `--metasploit` | искать модули через msfrpcd вместо searchsploit |
| `--enrich` / `--proxy URL` | гео/ASN через ip-api (по умолчанию ВЫКЛ, OPSEC) / прокси |
| `--scope CIDR` / `--out-of-scope CIDR` | allow/deny диапазоны (можно несколько) |
| `--allow-private` | разрешить приватные IP (127.0.0.1/RFC1918) и редиректы на них |
| `--ndjson` | стримить находки в stdout как NDJSON (человеческий вывод → stderr) |
| `--fail-on [info\|low\|medium\|high\|critical]` | код выхода 3, если есть находка ≥ этой важности |
| `--threads` / `--rate` | потоки/лимит запросов ffuf |
| `--nmap-min-rate` / `--nmap-max-rate` / `--scan-delay` | тюнинг скорости nmap |
| `--timeout SEC` | таймаут на один сканер (по умолчанию зависит от режима) |
| `--wordlist PATH` | свой wordlist для ffuf (есть fallback на seclists) |
| `--nmap-binary` / `--ffuf-binary` / `--nuclei-binary` | пути к бинарникам |
| `-v, --verbose` / `--no-tui` | подробный лог / headless-режим |

### Другие команды

```bash
reconfox doctor          # проверить, что установлено (nmap/ffuf/searchsploit/nuclei) + wordlist
reconfox schema          # JSON Schema результата скана — контракт для JSON/NDJSON
reconfox diff old.json new.json   # что появилось/исчезло между сканами (для мониторинга)
```

`doctor` — первый шаг на новой машине: одной командой показывает, какие
инструменты доступны (с версией) и есть ли wordlist; код выхода 1, если нет
обязательного (nmap/ffuf) — удобно как preflight в CI.

### Область (scope) и безопасность

reconfox создан для **авторизованного** пентеста, поэтому по умолчанию не бьёт
по приватным адресам: цель, которая резолвится в `127.0.0.1`, RFC1918 или
link-local (в т.ч. cloud-metadata `169.254.169.254`), **отклоняется** — это
защита от опечатки и DNS-rebind. Для стендов (DVWA, Metasploitable во
внутренней сети) добавь `--allow-private`. Диапазоны движка можно жёстко
ограничить: `--scope 10.0.0.0/24` (бить только внутри) и `--out-of-scope
1.2.3.0/24` (никогда не бить внутри). HTTP-пробер не пойдёт за редиректом на
внутренний хост без `--allow-private` (защита от SSRF на metadata-эндпоинт).

### Режимы сканирования

| Режим | nmap | Когда |
|---|---|---|
| **quick** | `-T4 -F -sV` | топ-100 портов + версии — быстрая картина |
| **full** | `-T4 -p- -sV -sC` | все 65535 портов + NSE — детальный аудит |
| **stealth** | `-T2 -sS -f -sV` | SYN + фрагментация — потише |

---

## Metasploit (опционально)

С флагом `--metasploit` reconfox ищет подходящие модули в Metasploit вместо
searchsploit. Для этого нужен запущенный RPC-демон:

```bash
msfrpcd -P your_password -S -a 127.0.0.1
```

Параметры подключения — через переменные окружения (см. `.env.example`):
`MSF_RPC_HOST`, `MSF_RPC_PORT`, `MSF_RPC_USER`, `MSF_RPC_PASS`, `MSF_RPC_SSL`.

**Важно:** reconfox только **ищет** модули по версии сервиса. Никакие эксплоиты
не запускаются автоматически.

---

## Как устроено

Каждый сканер — отдельный модуль-обёртка над CLI-утилитой; общаются они через
pydantic-модели, а оркестратор гоняет их параллельно через `asyncio.gather`.

```
src/reconfox/
├── models.py            # Target, PortInfo, WebFinding, Vulnerability, ScanResult, ...
├── cli.py               # CLI на Click (scan/diff/doctor/schema)
├── tui.py               # TUI на Textual
├── core/
│   ├── _proc.py         # запуск подпроцессов + kill при отмене/таймауте
│   ├── _http.py         # httpx-чтение с лимитом размера тела (анти-OOM)
│   ├── netguard.py      # детект приватных/внутренних IP (SSRF + scope)
│   ├── scope.py         # ScopePolicy: allow/deny CIDR + private-guard
│   ├── doctor.py        # проверки окружения для `reconfox doctor`
│   ├── scanner.py       # Scanner-протокол + ScanContext
│   ├── stages.py        # адаптеры-стадии + default_pipeline
│   ├── orchestrator.py  # обобщённый движок по графу зависимостей
│   ├── resolver.py      # async DNS + (opt-in) ip-api.com
│   ├── subdomain_finder.py  # crt.sh + DNS-brute
│   ├── tls_prober.py    # TLS-версия/cipher/cert/SAN
│   ├── nmap_scanner.py  # async nmap + парсер XML (defusedxml)
│   ├── ffuf_scanner.py  # async ffuf + парсер JSON
│   ├── http_prober.py   # HTTP-fingerprint (httpx) + SSRF-guard редиректов
│   ├── nuclei_scanner.py    # активные шаблоны уязвимостей
│   ├── exploit_finder.py    # searchsploit
│   ├── metasploit_finder.py # msfrpcd (read-only)
│   └── diffing.py       # сравнение двух сканов
└── reporting/           # markdown / html (Jinja2) / json / ndjson / sarif / diff
```

Что держим в голове по ходу разработки:

- **async-first** — долгие операции не блокируют друг друга;
- **graceful degradation** — упавший сканер не валит весь скан, ошибка просто
  попадает в отчёт;
- **отмена без зомби** — `_proc.run_capture` убивает дочерний процесс, если
  скан прервали или сработал таймаут (иначе `nmap -p-` остался бы висеть);
- **безопасность** — `defusedxml` на вывод nmap, экранирование данных в
  Markdown/HTML-отчётах, SSRF-guard редиректов, лимит размера HTTP-тела,
  scope-guard приватных IP, секреты только через env.

---

## Тесты

```bash
pip install -e ".[dev]"
pytest          # 326 тестов
ruff check src tests
```

Принцип простой: сначала тест, потом код. Каждый сканер тестируется через
подмену подпроцесса (monkeypatch), без реальных запусков nmap/ffuf.

---

## Дорожная карта

Готово: Scanner-протокол + оркестратор по графу зависимостей; стадии
subdomains (crt.sh+DNS), resolve+scope-guard, TLS, nmap, ffuf, HTTP-fingerprint,
nuclei, exploit finder (searchsploit/Metasploit RPC); мульти-цель (список/файл/
stdin/CIDR) и авто-скан поддоменов; отчёты HTML/MD/JSON/NDJSON/SARIF; команды
`diff`/`doctor`/`schema`; config.toml + env; `--fail-on`/коды выхода для CI;
таймауты, rate-limit, SSRF-guard, лимит тела, экранирование отчётов.

В планах: пассивные источники (Shodan/Censys/SecurityTrails), SAN→поддомены,
webhook-нотификации по `diff`, robots/sitemap-crawl, IPv6/полные DNS-записи,
resume-checkpointing, Docker-образ, pipx/PyPI.

---

## Похожие инструменты

[reconftw](https://github.com/six2dez/reconftw) и
[AutoRecon](https://github.com/Tib3rius/AutoRecon) — мощнее и шире по охвату.
reconfox берёт другим: он компактный и прозрачный — по одному модулю на
инструмент, стадии на едином `Scanner`-протоколе, никакой магии. Удобно
читать, удобно расширять.

---

## Вклад

PR и issue приветствуются. Пара правил: любой PR — с тестами, `ruff check`
должен проходить, без молчаливых breaking changes в API.

---

## Лицензия

[MIT](LICENSE) © 2026 Fedor Zuev ([kovanZ1](https://github.com/kovanZ1))

<div align="center">
<sub>Сделано для авторизованного пентеста. Используй с головой.</sub>
</div>
