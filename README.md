<div align="center">

# 🦊 reconfox

**Разведка веб-цели одной командой — для авторизованного пентеста.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-157%20passing-brightgreen.svg)](#тесты)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-46a2f1.svg)](https://github.com/astral-sh/ruff)

</div>

---

reconfox берёт на себя рутину первого этапа пентеста. Ты даёшь ему URL — он
сам резолвит цель, сканирует порты через nmap, ищет директории через ffuf,
подбирает известные эксплоиты по версиям сервисов и складывает всё в один
аккуратный отчёт. Можно гонять из терминала как `nmap`, а можно — в живом
TUI с прогресс-барами.

```
        URL
         │
   ┌─────▼─────┐
   │  Resolver │   IP · ASN · ISP · страна/город (ip-api.com)
   └─────┬─────┘
         │
   ┌─────┴─────┐         запускаются параллельно
   ▼           ▼
┌──────┐   ┌──────┐
│ nmap │   │ ffuf │     порты+сервисы   /   веб-директории
└──┬───┘   └──┬───┘
   │          │
   ▼          │
┌────────────────┐      searchsploit или Metasploit RPC
│ Exploit Finder │
└──────┬─────────┘
       │
   ┌───▼────┐
   │ Отчёт  │           HTML · Markdown · JSON
   └────────┘
```

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

# конкретный файл — формат берётся из расширения
reconfox scan https://example.com -O ./scan.html --no-tui

# полный скан, подробный лог, все три формата сразу
reconfox scan https://example.com -m full -f all -v --no-tui

# скрытный режим + поиск модулей через Metasploit
reconfox scan https://target.local -m stealth --metasploit --no-tui
```

Все опции `reconfox scan <URL>`:

| Опция | Что делает |
|---|---|
| `-m, --mode [quick\|full\|stealth]` | профиль скана (по умолчанию `quick`) |
| `-o, --output PATH` | папка для отчёта (по умолчанию `./reports`) |
| `-O, --output-file PATH` | точный путь к файлу; формат — по расширению `.md`/`.html`/`.json` |
| `-f, --format [md\|html\|json\|all]` | формат(ы) отчёта |
| `--wordlist PATH` | свой wordlist для ffuf |
| `--nmap-binary` / `--ffuf-binary` | пути к бинарникам, если они не в PATH |
| `--metasploit` | искать модули через msfrpcd вместо searchsploit |
| `-v, --verbose` | показывать каждый шаг |
| `--no-tui` | без интерфейса, только вывод в терминал |

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
├── models.py            # Target, PortInfo, WebFinding, Vulnerability, ScanResult
├── cli.py               # CLI на Click
├── tui.py               # TUI на Textual
├── core/
│   ├── _proc.py         # запуск подпроцессов + kill при отмене скана
│   ├── resolver.py      # async DNS + ip-api.com
│   ├── nmap_scanner.py  # async nmap + парсер XML (defusedxml)
│   ├── ffuf_scanner.py  # async ffuf + парсер JSON
│   ├── exploit_finder.py# searchsploit
│   ├── metasploit_finder.py # msfrpcd (read-only)
│   └── orchestrator.py  # параллельный запуск сканеров
└── reporting/           # markdown / html (Jinja2) / json
```

Что держим в голове по ходу разработки:

- **async-first** — долгие операции не блокируют друг друга;
- **graceful degradation** — упавший сканер не валит весь скан, ошибка просто
  попадает в отчёт;
- **отмена без зомби** — `_proc.run_capture` убивает дочерний процесс, если
  скан прервали (иначе `nmap -p-` остался бы висеть в фоне);
- **безопасность** — `defusedxml` на вывод nmap, autoescape в HTML-шаблоне,
  секреты только через env.

---

## Тесты

```bash
pip install -e ".[dev]"
pytest          # 157 тестов
ruff check src tests
```

Принцип простой: сначала тест, потом код. Каждый сканер тестируется через
подмену подпроцесса (monkeypatch), без реальных запусков nmap/ffuf.

---

## Дорожная карта

Готово: bootstrap, модели на pydantic v2, resolver, async-обёртки nmap и ffuf,
оркестратор, отчёты HTML/MD/JSON, CLI, TUI, exploit finder, Metasploit RPC,
документация.

В планах: IPv6, WHOIS, кеш между запусками, несколько целей за раз,
plugin-система для своих сканеров, Docker-образ.

---

## Похожие инструменты

[reconftw](https://github.com/six2dez/reconftw) и
[AutoRecon](https://github.com/Tib3rius/AutoRecon) — мощнее и шире по охвату.
reconfox берёт другим: он маленький и прозрачный — один файл, один сканер,
никакой магии. Удобно читать, удобно расширять.

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
