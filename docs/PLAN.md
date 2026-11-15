# Переход на Xray-core 26.11.9

Аудит: 2026-11-09. A выполнен в 0.5.76-5, B — в 0.5.77-0, C — в 0.5.78-0,
D — в 0.5.79-0, E — в 0.5.80-0 (2026-11-11); F ещё не начат.
Статусы этапов ведутся в Roadmap §4.5. Подробности аудита — Architecture §153.

## Что изменилось

В [сравнении v26.10.31…v26.11.9](https://github.com/XTLS/Xray-core/compare/v26.10.31...v26.11.9)
24 коммита и 60 файлов. Для Feldjäger существенны:

| Область | Необходимая работа |
|---|---|
| Log Settings / Xray Logs | Читать `logLevel` и старое `loglevel`; сейчас новый ключ не распознаётся, а Save может добавить второй ключ с другим значением. |
| Freedom `finalRules` | `blockDelay` устарел, заменён на `delay`; добавлен `logLevel`. Новое ядро отвергает эти параметры у `allow`, включая старый `blockDelay`. |
| TUN | Новые `autoSystemWfpBlockLeak`: all/allexceptlan, tcp/udp/icmp, порты и диапазоны, CIDR-префиксы; текущая проверка их блокирует даже для Linux-сервера. |
| Mux | TCP concurrency 0…128 теперь означает 128; лимит переиспользования соединения — 1024. Исправить расчёты, подписи и прежнее предупреждение «выше 128 действует как 128». |
| TLS / REALITY | Добавлен `hellochrome_155`; Feldjäger сейчас отвергает его в outbound. `chrome` следует новому default ядра. |
| GeoData | Ядро подменяет XTLS/Xray-rules-dat URL с `.dat` на `.dat.gz`. Менять источник ручного обновления Feldjäger (Loyalsoldier) не требуется. |
| XDRIVE | [Публичная beta](https://github.com/XTLS/Xray-core/pull/7352): пора заменить отложенный пункт явной поддержкой. Существующего preserve-unknown недостаточно для структурного редактора. |

Остальные изменения — исправления runtime, зависимости и сборка самого Xray;
их не нужно воспроизводить в Feldjäger. Подтверждение: 44 конфигурации проверены
через `run -test` на обеих локальных версиях (88 запусков), без обращения к Google.
Успешный `-test` на старом ядре не доказывает поддержку неизвестного поля: оно может игнорироваться.

## Этапы реализации

1. **A — Log Settings и защита секретов — выполнен (0.5.76-5, Architecture §154).** Общий reader для вариантов `logLevel`/`loglevel`
   в редакторе и Xray Logs; сохранять существующее написание, для новой секции — `logLevel`.
   Если ключей несколько — показать конфликт и предложить явное исправление, не менять смысл молча.
   Закрыть redaction массива `xdriveSettings.secrets` во всех diff-путях, в том числе
   при изменении одного элемента, добавлении/удалении массива или родительского объекта.
   Проверить Debug/ошибки: OAuth-значения не должны попадать в tracing или Status Bar.
2. **B — Freedom — выполнен (0.5.77-0, Architecture §155).** Typed `delay` и `logLevel` (none/debug/info/warning/error; default info),
   только для `block`; `blockDelay` читать и сохранять до явной миграции.
   При наличии обоих ключей учитывать, что ядро отдаёт приоритет `blockDelay`.
   Миграция и удаление неуместных полей — через Preview и явное действие пользователя.
   Добавить version warnings для нового формата на старом ядре; обновить справку EN/RU.
3. **C — Остальная совместимость — выполнен (0.5.78-0, Architecture §156).** Расширить TUN grammar по `wfp_leak.go` и parity fixtures;
   не переносить Windows WFP-логику в Linux/systemd или GUI. Обновить version-aware
   effective mux concurrency и границу 1024, не переписывая заданные числа автоматически.
   Добавить fingerprint и предупреждение для старого ядра. Для GeoData — пояснение
   подмены URL в справке/просмотре; исходный URL конфигурации сохранять.
4. **D — Общая модель XDRIVE и проверки — выполнен (0.5.79-0, Architecture §157).** Новый direction-aware модуль `config/stream/xdrive`:
   `service`, `remoteFolder`, `secrets`, восемь uint32-параметров размера/таймингов/concurrency,
   `xmux`, `template`, `s3`; неизвестные поля/формы сохранять без изменения.
   Поддержать local/google-drive/template/s3, legacy `Google Drive` читать с предупреждением.
   Проверки по `XDriveConfig.Build`/`validateXDrive`: VLESS, непустая рабочая пара
   encryption/decryption из `xray vlessenc`, без flow/testpre; один inbound-порт;
   клиентский mux без отрицательных concurrency/xudpConcurrency и UDP443=skip
   (учесть исключение VLESS reverse). Для h3 — ALPN ровно `["h3"]`, без brutal;
   Google Drive допускает из UDP-масок только noise. Version warning — beta 26.11.9,
   с требованием одинаковых версий клиента/сервера из release notes.
   Формат ключей проверяется локально; соответствие пары и доступ к storage подтверждаются
   только реальным соединением. Template маскируется целиком в Preview/внешних ошибках.
5. **E — Формы XDRIVE — выполнен (0.5.80-0, Architecture §158).** Встроить в Stream существующих Inbound/Outbound Shell через
   ApplicationService, без новой sidebar-страницы. Общие поля и advanced-блок;
   для Google Drive — три маскированных OAuth-поля в правильном порядке и folder ID,
   для S3 — его typed-поля, для template — generic JSON через application layer.
   Не применять к inbound XDRIVE обычное требование серверного TLS-сертификата:
   этот транспорт сам обращается к storage, в том числе с клиентским TLS.
   Пресет VLESS + Google Drive beta: объяснить mux, encryption, h2/h3, квоты и
   отсутствие прямого соединения; не создавать Google Cloud project/OAuth автоматически.
   Дефолты оставлять ядру, рекомендованный `eagerWindowMs=10000` — явный выбор пресета.
   Share URI/QR для XDRIVE отключить с объяснением: официального формата пока нет.
   Пресет применяется к пустым storage settings без настроенного security; существующие
   данные редактируются по полям. Credentials/template маскированы, reveal изолирован по сессии.
6. **F — Приёмка и baseline.** Lossless/dirty-on-open, compatibility, redaction,
   backup/conflict/rollback и parity на обеих версиях. Явно задавать `XRAY_BIN`
   из `testbin`, чтобы тесты не использовали старый `xray-bin` незаметно.
   Затем workspace tests/build/clippy; учесть прежние предупреждения отдельно.
   `BASELINE_XRAY_CORE` уже обновлён до 26.11.9 по запросу пользователя для About (0.5.80-1);
   приёмка F ещё требуется. Реальный Google Drive
   smoke-test — отдельная ручная приёмка с тестовым аккаунтом; `-test` его не заменяет.

Каждый этап — отдельное законченное изменение с повышением корневой версии и
записью в Architecture. SSH crate менять только при реальной необходимости.
Общий путь записи остаётся прежним: backup → atomic write → Xray `-test` → rollback
при ошибке, restart/reload отдельным действием.

## Особенности руководства

Локальный [PDF](XDRIVE.with.Google.Drive.setup.guide.v26.11.9.pdf) прочитан, 13 страниц;
Markdown-копия не требуется. Внутри указано 26.11.8, а release notes требуют минимум
26.11.9 и одинаковые версии обоих концов — для beta ориентируемся на release notes.
Google OAuth остаётся внешней настройкой; секреты хранятся в remote Xray config,
не в локальном `config.json` Feldjäger. В документации показывать, что аккаунт/папка
используются транспортом и его собственная очистка временных файлов — поведение Xray.
