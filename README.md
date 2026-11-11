# Open AG Patcher

Патчер для Antigravity IDE, Antigravity 2.0, CLI и расширения Google Antigravity для VS Code. В этом форке пункт IDE исправляет случай, когда вход прошёл, а агент остался недоступен из-за локальной проверки авторизации в `agy.exe`.

## Скачать

**[Open AG Patcher для Windows x64](https://github.com/Arbuzyakaby/AvenCores-open-antigravity-patcher/releases/latest/download/Open_AG_Patcher_Windows.exe)**

Список изменений и SHA-256 файла есть в [релизе](https://github.com/Arbuzyakaby/AvenCores-open-antigravity-patcher/releases/latest). На Linux и macOS запусти патчер из исходников.

## Если IDE вошла в аккаунт, а агент не работает

Этот сценарий проверен на **Antigravity IDE 2.6.0 с бэкендом `agy.exe` 1.5.5 для Windows x64**. В журнале IDE вход отмечен как `signedIn`, а бэкенд возвращает `ineligible` и `hasValidAuth=false`.

1. Закрой Antigravity IDE и запусти патчер.
2. Выбери **PATCH → `1` Antigravity IDE patch**.
3. Дождись `PATCH COMPLETE`. В разделе **ANTIGRAVITY IDE** меню показывает статус `main.js` и бэкенда отдельно.
4. Открой IDE и отправь короткий запрос агенту.

Пункт `1` ищет бэкенд по пути `%USERPROFILE%\.gemini\bin\agy.exe`. Если файл ещё не скачан, запусти IDE, дождись его появления, закрой IDE и повтори патч. Если `main.js` уже обработан старой версией патчера, пункт `1` сразу перейдёт к бэкенду.

Если найдена другая установка IDE, выбери **TOOLS → `11` → `1`** и укажи папку нужной IDE или её `main.js`. Копии IDE, запущенные из одного профиля Windows, могут использовать один бэкенд.

## Пункты меню

| Продукт | Патч | Откат | Какие файлы меняются |
|---|---:|---:|---|
| Antigravity IDE | `1` | `5` | `main.js` и распознанный `agy.exe` бэкенда на Windows x64 |
| Antigravity 2.0 | `2` | `6` | `language_server` или `language_server.exe` |
| Antigravity CLI | `3` | `7` | `agy` или `agy.exe`. Правка экрана Eligibility Check и, при совпадении сигнатуры Windows x64, проверка авторизации |
| Расширение Google Antigravity для VS Code | `4` | `8` | `extension.js` и бинарь, который расширение скачивает в `~/.gemini/bin` при первом запуске |

Патчер ищет приложения автоматически. Чтобы указать другой файл, открой **TOOLS → `11` Select custom path** и выбери нужный продукт. Для отдельной копии CLI используй **`11` → `3`**.

## Резервные копии и откат

Патчер сохраняет файлы рядом с оригиналами. Для `main.js` используется `main.js.bak`, для бинарей — суффикс `.agybak`, для `extension.js` — `.vscodebak`.

Перед откатом закрой приложение и выбери его пункт в **RESTORE**. Пункт `5` восстанавливает `main.js` и пропатченный бэкенд из резервных копий. Если отдельный CLI использует тот же `agy.exe`, восстановление затронет и его.

При допатчивании бинаря существующий `.agybak` сохраняется. Если оригинальной копии нет, патчер сообщает об этом и сохраняет текущее состояние перед новой правкой.

## Что меняется в IDE

- В `main.js` чтение `isGoogleInternal` после `resetIsTierGCPTos()` заменяется на `true`.
- В бэкенде Windows x64 проверка `PersonalAuthValidator.Validate` получает шестибайтовую правку `80 78 08 00 74 3b` → `c6 40 08 01 90 90`. Она выставляет флаг авторизации в `1` перед присоединением данных авторизации.
- Патчер проверяет архитектуру файла и ищет окружающую последовательность инструкций. Для записи нужно ровно одно совпадение. При отсутствии сигнатуры или нескольких совпадениях патчер выводит ошибку.
- Правка применяется заменой через временный файл. После обновления IDE или бэкенда проверь статус обоих файлов в меню.

## Совместимость

| Компонент | Что проверено |
|---|---|
| IDE 2.6.0 и `agy.exe` 1.5.5 на Windows x64 | Патч на копиях, побайтовое совпадение с рабочим бинарём, повторное применение и откат |
| CLI 1.5.6 на Windows x64 | Штатная правка экрана и новая правка авторизации применяются вместе. Откат проверен по SHA-256 |
| Официальные сборки CLI 1.5.6 | Все 8 архивов Windows, macOS и Linux прошли тесты сигнатур и цикла «патч → откат» |

Проверка версии в меню ориентируется на IDE **2.5.5** и Antigravity 2.0 **2.15.0**. Совместимость конкретного файла зависит от сигнатуры. Правка бэкенда IDE добавлена для Windows x64. На Linux и macOS пункт `1` обрабатывает `main.js`.

## Если патч не сработал

| Сообщение | Что проверить |
|---|---|
| `main.js` — `pattern not found` | Проверь, что выбран `main.js` из установленной Antigravity IDE. При необходимости укажи путь через `11` → `1`. |
| `IDE backend not found` | Запусти IDE один раз, дождись скачивания бэкенда и закрой IDE перед повторным патчем. |
| `signature not found` или `signature is ambiguous` | Сверь версию и архитектуру бинаря. Для отчёта пригодятся версия патчера, версия Antigravity и текст ошибки. |
| `File is locked` или `Permission denied` | Закрой приложение и его фоновые процессы. Для системной папки запусти патчер с правами записи. |
| `HTTP 403 SUBSCRIPTION_REQUIRED` или `#3501` | Проверь лицензию и доступ аккаунта на стороне Google. Патч меняет локальные файлы. |

На Windows вход в IDE можно проверить в `%APPDATA%\Antigravity IDE\logs\<сеанс>\auth.log`. Журналы бэкенда лежат в `%USERPROFILE%\.gemini\antigravity\log\cli-*.log`.

Сообщить об ошибке можно в [Issues форка](https://github.com/Arbuzyakaby/AvenCores-open-antigravity-patcher/issues). Другие сообщения Google API разобраны в [README исходного репозитория](https://github.com/trustybird/AvenCores-open-antigravity-patcher/blob/b59258fbc2f4c397e3b752c5a9033b5185bd9641/README.md).

## Запуск из исходников

Запусти команды из корня репозитория.

```sh
python -m pip install -r source/requirements.txt
python source/main.py
```

На macOS или Linux используй `python3`, если интерпретатор установлен под этим именем. Команды сборки Windows, Linux и macOS лежат в [source/build.txt](source/build.txt). Запускай их из каталога `source`.

## Тесты

Проверки патча бэкенда, повторного запуска и отката работают на временных файлах.

```sh
python -m unittest discover -s test-agy -p test_ide_backend.py -v
```

Полный набор также скачивает официальные сборки CLI и проверяет сигнатуры. `AGY_RELEASE_TAG` задаёт версию CLI, а `AGY_TEST_CACHE` позволяет сохранить архивы между запусками.

```sh
python -m unittest discover -s test-agy -v
```

## Лицензия

Проект распространяется под [GPL-3.0](LICENSE). Форк основан на [trustybird/AvenCores-open-antigravity-patcher](https://github.com/trustybird/AvenCores-open-antigravity-patcher). В исходном проекте использованы наработки [QNIX-Dev/eligibility-antigravity-patcher](https://github.com/QNIX-Dev/eligibility-antigravity-patcher) под лицензией MIT.
