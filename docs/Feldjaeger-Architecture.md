# 1	Manifest Feldjaeger

## 1.1	Архитектура Feldjaeger
| gui/                                     | Desktop UI                    | ← без raw SSH, без systemd       |
| :--------------------------------------- | :---------------------------- | :------------------------------- |
| <!-- obsidian --><p>&nbsp;app/&nbsp;</p> | ApplicationService            | ←  фасад для GUI                 |
| xray/                                    | remote                        | ← Xray-логика / файлы на сервере |
| ssh/                                     | SshBackend trait              | ← транспорт, без Xray-семантики  |
| init/                                    | InitSystemManager&nbsp;&nbsp; | ← управление сервисами           |
| domain/                                  | Общие типы                    |                                  |
| error/                                   | AppError / AppResult          |                                  |
Поток данных: GUI → ApplicationService → RemoteAdmin / XrayManager → SshBackend + InitSystemManager.

## 1.2	 Структура Feldjaeger
```
Feldjaeger/
├── Cargo.toml
├── rules.md
├── README.md
├── LICENSE
└── src/
    ├── main.rs <- точка входа desktop-приложения
    ├── lib.rs <- корень библиотеки, экспорт модулей
    ├── error.rs
    ├── domain/
    │   ├── mod.rs
    │   ├── connection.rs <- ConnectionProfile, AuthMethod
    │   └── path.rs <- RemotePath
    ├── ssh/
    │   ├── mod.rs
    │   ├── backend.rs <- trait SshBackend
    │   ├── session.rs <- SshSession
    │   └── russh.rs <- RusshBackend (заготовка MVP)
    ├── init/
    │   ├── mod.rs
    │   ├── manager.rs <- trait InitSystemManager, ServiceState
    │   └── systemd.rs <- SystemdManager (единственный MVP-бэкенд)
    ├── remote/
    │   ├── mod.rs
    │   ├── admin.rs <- RemoteAdmin
    │   └── backup.rs <- ConfigBackup
    ├──  <-/
    │   ├── mod.rs
    │   ├── config.rs <- XrayConfig
    │   ├── validator.rs <- trait ConfigValidator, DefaultConfigValidator
    │   └── manager.rs <- XrayManager
    ├──  <-/
    │   ├── mod.rs
    │   └── service.rs <- ApplicationService
    └── gui/
        ├── mod.rs
        └── application.rs <- GuiApplication
```

## 1.3	Назначение модулей
| Модуль               | Назначение                                                                              |
| -------------------- | --------------------------------------------------------------------------------------- |
| `main.rs`            | Минимальная точка входа; создаёт `GuiApplication`.                                      |
| `lib.rs`             | Корень crate, документирует слои и реэкспортирует модули.                               |
| `error`              | `AppError` и `AppResult<T>` — единый тип ошибок без panic для ожидаемых сбоев.          |
| `domain`             | Общие value-типы, не привязанные к конкретному слою.                                    |
| `domain::connection` | `ConnectionProfile`, `AuthMethod` — параметры SSH-подключения.                          |
| `domain::path`       | `RemotePath` — валидируемый абсолютный путь на удалённом сервере.                       |
| `ssh`                | Транспортный слой; не знает о Xray.                                                     |
| `ssh::backend`       | Trait `SshBackend` — connect, read/write файлов, exec с явными аргументами (без shell). |
| `ssh::session`       | `SshSession` — handle активной SSH-сессии.                                              |
| `ssh::russh`         | `RusshBackend` — заготовка MVP-реализации через Russh (без зависимости пока).           |
| `init`               | Абстракция init-систем; весь контроль сервисов идёт через неё.                          |
| `init::manager`      | Trait `InitSystemManager`, enum `ServiceState`.                                         |
| `init::systemd`      | `SystemdManager` — единственная реализация в MVP.                                       |
| `remote`             | Высокоуровневые удалённые операции (чтение/запись конфигов, бэкап).                     |
| `remote::admin`      | `RemoteAdmin` — фасад над SSH; GUI не вызывает SSH напрямую.                            |
| `remote::backup`     | `ConfigBackup` — метаданные бэкапа перед перезаписью конфига.                           |
| `xray`               | Xray-специфичная логика; использует `init` и `remote`, не russh API.                    |
| `xray::config`       | `XrayConfig` — in-memory представление; неизвестные секции сохраняются.                 |
| `xray::validator`    | `ConfigValidator` — валидация перед restart.                                            |
| `xray::manager`      | `XrayManager` — оркестрация: backup → validate → write → restart.                       |
| `app`                | Сборка всех подсистем в единый фасад.                                                   |
| `app::service`       | `ApplicationService` — единственная точка доступа для GUI.                              |
| `gui`                | Desktop UI; без systemd-логики и raw SSH.                                               |
| `gui::application`   | `GuiApplication` — владеет `ApplicationService`, место для UI-фреймворка.               |

## 1.4	Соответствие rules.md
> Соответствие rules.md
> SSH абстрагирован за SshBackend; Xray и GUI не зависят от russh API.
> Управление сервисами только через InitSystemManager; MVP — SystemdManager.
> GUI не выполняет raw SSH и не содержит systemd-логику.
> Заготовки для backup (ConfigBackup), validation (ConfigValidator) и сохранения неизвестных секций (XrayConfig).
> Все публичные struct/enum имеют rustdoc.
> Cargo.toml: edition 2024, GPL-3.0-or-later, без неиспользуемых зависимостей.


# 2	Реализация модуля SSH

## 2.1	Структура модуля SSH
```
Feldjaeger/
├── Cargo.toml <- workspace: feldjaeger + feldjaeger-ssh
├── feldjaeger-ssh/ <- независимая SSH-библиотека
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── error.rs
│       ├── connection.rs
│       ├── path.rs
│       ├── command.rs
│       ├── exec.rs
│       ├── session.rs
│       └── backend.rs
└── src/ <- основной crate (без src/ssh/, без domain/)
```

## 2.2	Модели данных
| Тип                            | Назначение                                           |
| ------------------------------ | ---------------------------------------------------- |
| `ConnectionProfile`            | Хост, порт, username — без секретов                  |
| `AuthCredentials`              | Пароль или путь к ключу; `Debug` редактирует секреты |
| `AuthMethod`                   | Тип аутентификации                                   |
| `ConnectRequest`               | Профиль + credentials для подключения                |
| `RemotePath`                   | Абсолютный путь с базовой валидацией                 |
| `RemoteCommand`                | Программа + явные аргументы (без shell)              |
| `ExecResult`                   | stdout, stderr, exit code                            |
| `SessionInfo` / `SessionState` | Метаданные сессии                                    |
| `SshError` / `SshResult<T>`    | Ошибки SSH-слоя                                      |

## 2.3	Интерфейсы
```rust
pub trait SshBackend: Send + Sync {
    type Session: SshSession;
    fn connect(&self, request: &ConnectRequest)
        -> impl Future<Output = SshResult<Self::Session>> + Send;
}

pub trait SshSession: Send {
    fn profile(&self) -> &ConnectionProfile;
    fn read_file(&self, path: &RemotePath) -> impl Future<...> + Send;
    fn write_file(&self, path: &RemotePath, contents: &[u8]) -> impl Future<...> + Send;
    fn exec(&self, command: &RemoteCommand) -> impl Future<...> + Send;
    fn disconnect(self) -> impl Future<...> + Send;
}
```

Трейты async-ready (под будущие `tokio` + `russh`), без внешних зависимостей.

## 2.4	Соответствие rules.md
> SSH не знает о Xray — отдельный crate без ссылок на остальной проект
> Абстракция за SshBackend / SshSession, не за russh API
> Секреты не попадают в логи через Debug у AuthCredentials
> Команды через RemoteCommand, без shell-интерполяции
> Валидация RemotePath перед операциями
> Заглушка RusshBackend удалена — реализация будет позже

## 2.5	Изменения
Изменения в основном crate
- Удалены `src/ssh/` и `src/domain/` (типы перенесены в `feldjaeger-ssh`)
- `feldjaeger` зависит от `feldjaeger-ssh` и реэкспортирует crate
- `remote/` использует `feldjaeger_ssh::RemotePath` и `SshSession`

Сборка workspace проходит успешно. Следующий шаг — реализация Russh-бэкенда в отдельном модуле `feldjaeger-ssh`.


# 3	Парсер конфигурации Xray

## 3.1	Добавлено
 `XrayConfigParser` (`src/xray/parser.rs`)
 
| Метод                   | Назначение           |
| ----------------------- | -------------------- |
| `parse_str(&str)`       | Парсинг UTF-8 JSON   |
| `parse_bytes(&[u8])`    | Парсинг байтов       |
| `to_json(&XrayConfig)`  | Сериализация в JSON  |
| `to_bytes(&XrayConfig)` | Сериализация в байты |
 `XrayConfig` (`src/xray/config.rs`)
- 14 известных top-level секций Xray (`log`, `inbounds`, `outbounds`, `burstObservatory`, …)
- `extra: BTreeMap<String, Value>` — неизвестные top-level ключи
- Секции хранятся как `serde_json::Value` — вложенные неизвестные поля сохраняются без потерь

## 3.2	Тестовые JSON (`tests/fixtures/xray/`)
| Файл                         | Сценарий                                   |
| ---------------------------- | ------------------------------------------ |
| `minimal.json`               | Базовый конфиг                             |
| `with_unknown_sections.json` | Неизвестные top-level секции               |
| `full_sample.json`           | Полный конфиг + вложенные неизвестные поля |
| `invalid.json`               | Битый JSON                                 |

## 3.3	Зависимости
```rust
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

## 3.4	Соответствие rules.md
> Unknown sections preserved — top-level → `extra`, nested → через `Value`
> Reading broader than writing — парсер принимает все секции; редактирование будет позже
> Result, no panic — ошибки через `AppResult` / `AppError`
> rustdoc — на всех публичных типах

## 3.5	Тесты (7/7)
- Парсинг минимального конфига
- Сохранение неизвестных top-level секций
- Сохранение вложенных полей (`unknownClientField` в `inbounds`)
- Round-trip без потери данных
- Отклонение невалидного JSON и корня-массива

Пример использования:

```rust
let parser = XrayConfigParser::new();
let config = parser.parse_str(&json)?;
let restored = parser.to_json(&config)?;
```


# 4	Модуль резервного копирования

## 4.1	Компоненты
`BackupManager` (`src/remote/backup_manager.rs`)

| Метод                                      | Назначение                                       |
| ------------------------------------------ | ------------------------------------------------ |
| `create_backup(session, original_path)`    | Читает оригинал, записывает копию по новому пути |
| `restore_backup(session, backup)`          | Восстанавливает оригинал из бэкапа               |
| `resolve_backup_path(original, timestamp)` | Вычисляет путь бэкапа без I/O                    |
  `BackupManagerOptions`
- `backup_dir: Option<RemotePath>` — опциональная директория для бэкапов
- По умолчанию бэкап создаётся рядом с оригиналом:
    `/etc/xray/config.json` → `/etc/xray/config.json.feldjaeger.bak.{unix_ts}`
- С `backup_dir` используется только basename:
    `/var/backups/feldjaeger/config.json.feldjaeger.bak.{unix_ts}`
`ConfigBackup` (расширен)

Добавлены поля `created_at_unix` и `size_bytes` для проверки при restore.

## 4.2	Алгоритм бэкапа
```rust
read_file(original) → write_file(backup_path, bytes)
```

Без `cp`, `ssh` CLI и shell-интерполяции — только прямое чтение/запись через `SshSession`.

## 4.3	Соответствие rules.md
> Always backup before overwriting — `create_backup` вызывается до записи
> Reversible changes — `restore_backup` откатывает конфиг
> Validate remote paths — через `RemotePath` и проверку basename
> Log SSH operations — `log::info!` / `log::warn!` (без содержимого файлов и секретов)
> Result, no panic — все ошибки через `AppResult`

## 4.4	Зависимости
```rust
log = "0.4"                              # runtime
tokio = { version = "1", features = ["rt", "macros"] }  # dev, для async-тестов
```

## 4.5	Тесты (6 новых, 13/13 всего)
- Разрешение пути (рядом с оригиналом / в `backup_dir`)
- Создание бэкапа через mock `SshSession`
- Restore после модификации
- Ошибка при отсутствии оригинала
- Ошибка при несовпадении размера бэкапа
Пример использования:

```rust
let manager = BackupManager::new();
let backup = manager.create_backup(&session, &config_path).await?;
// ... modify and write config ...
manager.restore_backup(&session, &backup).await?; // rollback
```


# 5	Взаимодействие с системой инициализации

## 5.1	Архитектура
```
GUI / XrayManager
       ↓
InitSystemManager (trait)
       ↓
SystemdManager → SSH session → systemctl <subcommand> <unit>
```

## 5.2	InitSystemManager (async)
| Метод                            | Действие              |
| -------------------------------- | --------------------- |
| `service_state(session, name)`   | `systemctl is-active` |
| `start_service(session, name)`   | `systemctl start`     |
| `stop_service(session, name)`    | `systemctl stop`      |
| `restart_service(session, name)` | `systemctl restart`   |
Все операции выполняются на удалённом хосте через `SshSession::exec` с явными аргументами — без shell.

## 5.3	`SystemdManager`
- Вызывает `systemctl` как отдельную программу с аргументами через `RemoteCommand`
- Парсит `is-active`: `active`/`activating` → `Running`, `inactive`/`deactivating` → `Stopped`
- При ненулевом exit code lifecycle-операций возвращает ошибку со stderr
- Логирует операции через `log` (хост, user, service — без секретов)

## 5.4	ServiceName — валидация
Имена сервисов проверяются до передачи в `systemctl`:
- только `[a-zA-Z0-9._@-]`
- без пробелов, `/`, `\`, shell-метасимволов

## 5.5	Соответствие rules.md
> Весь контроль сервисов через InitSystemManager
> MVP — только SystemdManager
> Без shell-интерполяции — прямая передача аргументов
> Result, без panic
> rustdoc на всех публичных типах

## 5.6	Тесты (8 новых, 21/21)
- `active` / `inactive` state
- Вызов `systemctl start` с корректными аргументами
- Ошибка при сбое `restart`
- Отклонение небезопасного имени сервиса
- Валидация имён в `service_name`
Пример:

```rust
let init = SystemdManager::new();
let state = init.service_state(&session, "xray").await?;
init.restart_service(&session, "xray").await?;
```


# 6	Russh-клиент

## 6.1	Структура
feldjaeger-ssh/src/russh/  
├── mod.rs  
├── client.rs <- RusshClient + RusshClientOptions (SshBackend)  
├── session.rs <- RusshSession (SshSession)  
├── handler.rs <- ClientHandler + проверка host key  
├── host_key.rs <- HostKeyPolicy  
├── exec.rs <- сборка и выполнение remote command  
└── sftp.rs <- read/write через SFTP  

## 6.2	API
| Тип                             | Назначение                                          |
| ------------------------------- | --------------------------------------------------- |
| `RusshClient`                   | Реализует `SshBackend::connect()`                   |
| `RusshSession`                  | Реализует `SshSession` (read/write/exec/disconnect) |
| `RusshClientOptions`            | Политика host key                                   |
| `HostKeyPolicy::KnownHostsFile` | Проверка по `~/.ssh/known_hosts` (по умолчанию)     |
| `HostKeyPolicy::AcceptAny`      | Только для dev/test                                 |

## 6.3	Операции
| Операция                   | Механизм                                                |
| -------------------------- | ------------------------------------------------------- |
| Подключение                | `russh::client::connect` + password / private key       |
| `read_file` / `write_file` | SFTP subsystem (`russh-sftp`)                           |
| `exec`                     | SSH exec channel, program + args без shell-метасимволов |
| `disconnect`               | `systemctl disconnect`                                  |

## 6.4	Соответствие rules.md
> SSH абстрагирован за SshBackend / SshSession — russh не экспортируется в Xray/GUI
> Пароли и ключи не пишутся в логи (Debug у credentials + логи без секретов)
> Каждая SSH-операция логируется через log
> Без shell-интерполяции: валидация аргументов exec
> Result, без panic
> Зависимости Apache-2.0 — совместимы с GPL-3.0
> russh с feature ring (без aws-lc-rs/NASM на Windows)

## 6.5	Зависимости (feldjaeger-ssh/Cargo.toml)
```rust
russh = { version = "0.63.3", default-features = false, features = ["ring", "flate2", "rsa"] }
tracing = "0.1.44"
russh-sftp = "3.0.1"
serde = { version = "1.0.229", features = ["derive"] }
tokio = { version = "1.53.2", features = ["io-util", "net", "rt", "sync", "time"] }
```

## 6.6	Пример
```rust
use feldjaeger_ssh::{
    ConnectRequest, ConnectionProfile, AuthCredentials,
    HostKeyPolicy, RusshClient, RusshClientOptions, SshBackend,
};

let client = RusshClient::with_options(RusshClientOptions {
    host_key_policy: HostKeyPolicy::AcceptAny, // dev only
    ..Default::default()
});

let request = ConnectRequest::new(
    ConnectionProfile::new("server.example", 22, "admin"),
    AuthCredentials::Password("secret".into()),
);

let session = client.connect(&request).await?;
let data = session.read_file(&path).await?;
```

## 6.7	Тесты
3 unit-теста в feldjaeger-ssh + 21 тест в workspace — все проходят.


# 7	Skeleton GUI

## 7.1	Итоговая структура GUI
```
src/gui/
    mod.rs              # публичный API: FeldjaegerApp, run()
    app.rs              # eframe::App, layout, владение ApplicationService
    navigation.rs       # enum Page, централизованный роутинг
    sidebar.rs          # постоянная левая панель навигации
    pages/
        mod.rs
        dashboard.rs
        connection.rs
        inbounds.rs     # General | Protocol | Stream | Security | Sniffing | Users (§34; users.rs — вкладка)
        users.rs
        outbounds.rs
        dns.rs
        fakedns.rs
        routing.rs
        policy.rs
        observatory.rs
        burst_observatory.rs
        log_settings.rs
        logs.rs
        service.rs
        xray_management.rs
        geodata.rs
        warp.rs
        settings.rs
```

`src/main.rs` вызывает `feldjaeger::gui::run()`.
> Актуально (sidebar): Users не пункт меню — см. §32–§34. Полный список страниц — `Page::ALL` в `navigation.rs`.

## 7.2	Архитектура навигации
Навигация сосредоточена в `Page` (`navigation.rs`):
- `Page::ALL` — порядок пунктов в sidebar
- `Page::label()` — подписи для меню
- `Page::show(ui)` — единственный match, делегирующий в модуль страницы
`FeldjaegerApp::update()` только компонует layout:

```rust
fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
    egui::SidePanel::left("sidebar")
        .resizable(true)
        .default_width(180.0)
        .show(ctx, |ui| sidebar::show(ui, &mut self.page));

    egui::CentralPanel::default().show(ctx, |ui| {
        self.page.show(ui);
    });
}
```

Каждая страница — отдельный модуль с `pub fn show(ui: &mut Ui)`. Общий текст-заглушка вынесен в `pages::placeholder()`, без дублирования.

## 7.3	Взаимодействие с `ApplicationService` в будущем
Сейчас `FeldjaegerApp` владеет `ApplicationService`, но не вызывает его методы — страницы показывают только placeholder.
На следующих этапах:
1. Действия пользователя (кнопки, формы) → методы `ApplicationService`, не SSH/Xray/systemd напрямую.
2. Отображение состояния — страницы получат `&ApplicationService` или узкий контекст (`GuiContext`) с данными для UI.
3. Асинхронные операции (SSH, restart) — результаты через канал/poll в `update()`, с индикатором прогресса по `ui.md`.
4. Граница слоёв — в `gui/` нет импортов `remote`, `xray`, `init`, `feldjaeger_ssh` (проверено).

## 7.4	Принятые архитектурные решения
| Решение                                      | Обоснование                                       |
| -------------------------------------------- | ------------------------------------------------- |
| egui + eframe 0.31                           | Требование ТЗ; GPL-совместимо                     |
| `FeldjaegerApp` владеет `ApplicationService` | Готовая точка интеграции с бизнес-слоем           |
| `Page` enum + `Page::show()`                 | Централизованная навигация без match в `update()` |
| Страница = модуль + `show()`                 | Независимое развитие экранов                      |
| Sidebar всегда слева, resizable              | `ui.md`: always visible, один уровень             |
| Placeholder без фейковой логики              | Соответствие этапу «только архитектура»           |
| Минималистичный стиль, без иконок/анимаций   | Требование этапа                                  |
| `run()` возвращает `eframe::Result`          | Без `unwrap()` на путях запуска                   |
| rustdoc на публичных типах                   | `rules.md`                                        |

## 7.5	Добавленные зависимости Cargo
| Зависимость | Версия | Назначение                                                                       |
| ----------- | ------ | -------------------------------------------------------------------------------- |
| eframe      | 0.31   | Окно, event loop, `NativeOptions`, trait `App`, backend (winit + glow/wgpu)      |
| egui        | 0.31   | Виджеты, `Ui`, `SidePanel`/`CentralPanel` — явный импорт в модулях pages/sidebar |
Остальные зависимости (winit, glow, accesskit и т.д.) подтягиваются транзитивно через eframe.


# 8	Добавление Status Bar
Status Bar добавлен. Сборка и clippy проходят.

## 8.1	Что сделано
Модель состояния (`src/app/status.rs`) — владеет `ApplicationService`, GUI только читает снимок:
- `CurrentOperation` — Ready / Connecting / UploadingConfig / RestartingXray / CreatingBackup
- `SshStatus` — Disconnected, Connecting, Connected, Authentication failed, …
- `XrayStatus` — произвольное сообщение + severity (`Xray: Running`, `Xray: Inactive`, …)
- `OperationProgress` — None / Determinate(f32) / Indeterminate
- `StatusSnapshot` — то, что отдаёт `service.status_snapshot()`
API сервиса для будущих операций:
- `set_current_operation` / `clear_current_operation`
- `set_operation_progress`
- `set_ssh_status` / `set_xray_status`
GUI (`src/gui/status_bar.rs`):
- фиксированная высота 28px, всегда видна `TopBottomPanel::bottom`
- слева: Current Operation (+ progress bar % или spinner)
- справа: Xray Status | SSH Status
- цвета по `ui.md`: green / yellow / red / gray
- Status Bar не обращается к SSH — только к `ApplicationService`
Стартовое состояние: `Ready` | `Xray: Unknown` | `SSH: Disconnected`.


# 9	Хранение настроек
Конфигурация подключена. Тесты и clippy проходят.

## 9.1	Структура
```
src/storage/
    mod.rs
    app_config.rs      # AppConfig, UiConfig, ThemeMode, WindowSize/Position
    config_manager.rs  # load / save / defaults / malformed backup
```

## 9.2	Расположение `config.json`
Через `directories::ProjectDirs`:

| OS      | Путь                                                   |
| ------- | ------------------------------------------------------ |
| Windows | `%APPDATA%\Feldjaeger\config\config.json`              |
| Linux   | `~/.config/feldjaeger/config.json`                     |
| macOS   | `~/Library/Application Support/Feldjaeger/config.json` |
На Windows у `ProjectDirs` стандартный подкаталог `config\` — это поведение crate, не ручной путь.

## 9.3	Поведение
- Нет файла → создаётся default и сохраняется
- Нет полей → заполняются через `#[serde(default)]`
- Битый JSON → `config.json.bak` (+ `.bak.N` при конфликте), новый default, `log::warn!`
- GUI не трогает файл — только `ApplicationService` → `ConfigManager`
- Автосохранение: sidebar width, last page, window size/position при изменении
- `theme`: `System` | `Light` | `Dark` (сейчас всегда System в UI)

## 9.4	Зависимости
| Crate       | Зачем                             |
| ----------- | --------------------------------- |
| directories | Кроссплатформенный config-каталог |
| env_logger  | Логирование проблем с конфигом    |
Секреты в `config.json` не хранятся.


# 10	Окно подключения по SSH

## 10.1	Созданные и изменённые модули
| Модуль                              | Изменение                                                       |
| ----------------------------------- | --------------------------------------------------------------- |
| `src/storage/connection_profile.rs` | новый — `StoredConnectionProfile`, `ConnectionDraft`, валидация |
| `src/app/connection_secrets.rs`     | новый — пароль/passphrase только в памяти, Debug redacted       |
| `src/storage/app_config.rs`         | поле `connection`                                               |
| `src/app/service.rs`                | draft/secrets/save/reset + Status Bar message                   |
| `src/app/status.rs`                 | `CurrentOperation::Message`                                     |
| `src/gui/pages/connection.rs`       | форма профиля                                                   |
| `src/gui/navigation.rs`             | `Page::show(ui, service)`                                       |
| `feldjaeger-ssh`                    | `serde` для `AuthMethod`                                        |

## 10.2	Поток данных
```
Connection page (GUI)
    ↓  читает/пишет draft + secrets
ApplicationService
    ↓  validate → save_config()
ConfigManager → config.json
```

GUI не трогает файлы и SSH. `StoredConnectionProfile::to_ssh_profile()` готов для будущего SSH-слоя.

## 10.3	Сохраняемые поля
`profile_name`, `host`, `port`, `username`, `auth_method`, `private_key_path`

## 10.4	Секреты не сериализуются
`password` и `passphrase` живут только в `ConnectionSecrets` (память процесса). В JSON их нет; `Debug` показывает `[REDACTED]`; в Status Bar и ошибках валидации не попадают.

## 10.5	Тесты
- валидный профиль (Password / Private key)
- пустые name / host / username
- port `0` и `65536`
- нет private key path при Private key
- save/reload несекретных полей через `ApplicationService`
- отсутствие password/passphrase в JSON
- Debug redacts secrets
- reset восстанавливает сохранённый профиль

## 10.6	Новые зависимости
| Зависимость | Где              | Зачем                                                           |
| ----------- | ---------------- | --------------------------------------------------------------- |
| serde       | `feldjaeger-ssh` | сериализация `AuthMethod` в `config.json` без дублирования enum |

Других новых зависимостей в корневом crate нет.


# 11	Подключение по SSH
Реализована реальная проверка SSH-подключения. 51 тест и clippy проходят.

## 11.1	Модули
| Модуль                          | Изменение                                                                         |
| ------------------------------- | --------------------------------------------------------------------------------- |
| `src/app/connection_test.rs`    | новый — state machine, validate, `run_connection_test`, error mapping, mock-тесты |
| `src/app/service.rs`            | async start/poll, Status Bar, `RusshClient`                                       |
| `src/app/status.rs`             | расширен `SshStatus`                                                              |
| `src/gui/pages/connection.rs`   | активна кнопка Test connection                                                    |
| `src/gui/app.rs`                | repaint во время Connecting                                                       |
| `feldjaeger-ssh/.../client.rs`  | `connect_timeout` (10s), классификация ошибок                                     |
| `storage/connection_profile.rs` | поле ошибки `password`                                                            |

## 11.2	Async-поток
```rust
ConnectionPage → ApplicationService::start_connection_test()
  → snapshot профиля + секретов → ConnectRequest
  → thread + tokio current-thread runtime
  → RusshClient::connect() (таймаут 10s, known_hosts)
  → session.disconnect()
  → mpsc → poll_connection_test() в tick_status()
```

GUI не вызывает RusshClient / SshBackend напрямую. UI thread не использует block_on.

## 11.3	Состояние операции
```
Idle → Connecting → Succeeded | Failed { summary, detail }
```

Пока `Connecting`: кнопка `Connecting...` отключена, повторный запуск невозможен.

## 11.4	Mapping ошибок → Status Bar
| Резюме                           | Источник                     |
| -------------------------------- | ---------------------------- |
| Connection refused               | refused / ECONNREFUSED       |
| Authentication failed            | auth fail / decrypt key      |
| Too many authentication failures | too many authentication      |
| Connection timed out             | timeout                      |
| Host key verification failed     | host key unknown/mismatch    |
| Host not found                   | DNS / lookup                 |
| Connection closed                | reset / closed / broken pipe |
| Unknown SSH error                | остальное                    |

## 11.5	Подтверждения
- UI thread не блокируется (фон + `try_recv`)
- `HostKeyPolicy::AcceptAny` не используется (только `KnownHostsFile`)
- после успеха вызывается `disconnect()`, Status Bar: `SSH: Disconnected`

## 11.6	Unit-тесты
- отказ при невалидном профиле / пустом password
- нельзя стартовать повторно в `Connecting`
- success/failure → Status Bar
- mock: `disconnect()` после успеха, не вызывается при fail
- классификация ошибок, redaction секретов
- production client ≠ `AcceptAny`

## 11.7	Новые зависимости
| Crate                       | Зачем                                             |
| --------------------------- | ------------------------------------------------- |
| tokio (root, `rt`+`time`)   | фоновый runtime для SSH-теста без блокировки egui |
| tokio time (feldjaeger-ssh) | `connect_timeout` в `RusshClientOptions`          |

## 11.8	Изменение размера шрифта ошибок
Размер шрифта сообщения об ошибке подключения увеличен до 14 pt (вместо `.small()`).

## 11.9	Изменение размера шрифта контекстуальных ошибок
Контекстные ошибки полей на странице Connection теперь тоже 14 pt, как в `ui.md`.


# 12	Обнаружение установки xray
Реализовано read-only обнаружение Xray. Все 69 unit-тестов проходят. Новых Cargo-зависимостей нет.

## 12.1	Модули
| Модуль                      | Назначение                                                                              |
| --------------------------- | --------------------------------------------------------------------------------------- |
| `src/xray/installation.rs`  | `XrayInstallation`, `ConfigSource`, `InitSystemKind`, `DiscoveryState`, warnings/errors |
| `src/xray/discovery.rs`     | `XrayDiscoveryService` — read-only probe через `SshSession`                             |
| `src/init/systemd_probe.rs` | `systemctl show` / ExecStart / unit probe (с учётом drop-ins)                           |
| `src/app/discovery.rs`      | async connect → discover → disconnect для UI                                            |
| Изменены                    | `ApplicationService`, `CurrentOperation`, Connection page, `xray`/`init`/`app` exports  |

## 12.2	Алгоритм discovery
1. OS (`/etc/os-release`) → arch (`uname -m`) → init (runtime markers)
2. Binary: `which xray` → fallback paths → `xray version`
3. Если systemd: probe unit → `ExecStart` → `InitSystemManager::service_state`
4. Config из ExecStart (`-c`/`-config`/`-confdir`) или fallback paths
5. Чтение + `XrayConfigParser` (ошибки → warnings, не abort)

## 12.3	Порядок поиска binary
1. `which xray`
2. `/usr/local/bin/xray`
3. `/usr/bin/xray`
4. `/opt/xray/xray`

## 12.4	Порядок поиска config
1. ExecStart (`-c` / `-config` / `-confdir`)
2. `/usr/local/etc/xray/config.json`
3. `/etc/xray/config.json`
4. `/usr/local/etc/xray/` и `/etc/xray/` — только если есть `.json`

## 12.5	systemd / unsupported init
- systemd: `systemctl show` (не только файл unit), `xray.service` → `xray@*` → `xray@.service`, state через `InitSystemManager`
- OpenRC / runit: детект по маркерам, warning «unsupported for service control», binary/config продолжают искаться

## 12.6	Read-only
Разрешены: `read_file`, `ls`, `test`, `which`, `uname`, `systemctl show|list-units|is-active`, `xray version`.  
Запрещены: write, install, restart/enable/disable. Тест `discovery_does_not_write` это проверяет.

## 12.7	Тесты (mock SSH)
PATH / fallback / not found · version ok / unavailable · systemd found / absent · ExecStart `-c` / `-confdir` · fallback configs · unreadable / invalid JSON · OpenRC unsupported · SSH lost · no writes · ApplicationService gating

## 12.8	Зависимости
Новых нет — только существующие `feldjaeger-ssh`, `serde_json`, `tokio`, `log`.

## 12.9	UI
После успешного Test connection (`SSH: Connected`) доступна Discover Xray. Во время операции: слева `Discovering Xray installation...`, справа `SSH: Connected`. Итог — read-only summary на странице Connection.
Ручной прогон на Debian/Ubuntu и Alpine VM нужно сделать у себя (в репозиторий секреты не добавлялись).


# 13	Модель конфигурации XRAY
Реализована внутренняя lossless-модель конфигурации Xray в `src/xray/config/`. Все 88 тестов проходят.

## 13.1	Модель конфигурации
`XrayConfigSections` хранит известные верхнеуровневые секции (`log`…`metrics`, `inbounds`, `outbounds`) и неизвестные в `extra_sections`. Содержимое секций — `serde_json::Value` (без глубокой типизации). `inbounds`/`outbounds` — упорядоченные списки с сохранением порядка.

## 13.2	Почему такая архитектура
- Эволюция старого `XrayConfig`, без дублирующих моделей (`XrayConfig` = alias).
- `SourcedSection<T>` готовит будущую запись по файлам.
- `ConfigParseOutcome` поддерживает частичный разбор без panic.
- Summary отдельно от полного JSON — для будущего GUI.

## 13.3	Источник секций
Каждая секция/элемент обёрнут в `SourcedSection { source_file, value }`. Для single file — один путь; для directory — путь конкретного `.json` (файлы сортируются по имени, как у Xray confdir).

## 13.4	Неизвестные секции
Не теряются: попадают в `extra_sections` (в т.ч. `transport`, `fakedns`).

## 13.5	Неизвестные protocol
Не ошибка: строка сохраняется в JSON и в `InboundSummary`/`OutboundSummary`.  
Распознавание Tier‑2 / shell: `InboundClientProtocol::from_wire` — vless | trojan | hysteria | tunnel; legacy `dokodemo-door` и прочие exotic — read-only в GUI (Edit disabled).

## 13.6	Созданные структуры
| Структура                            | Назначение                            |
| ------------------------------------ | ------------------------------------- |
| `XrayConfigSections`                 | Внутренняя модель секций              |
| `XrayConfig`                         | Alias на `XrayConfigSections`         |
| `SourcedSection<T>`                  | Значение + `source_file`              |
| `InboundSummary` / `OutboundSummary` | Read-only summary                     |
| `ConfigError` / `ConfigErrorKind`    | Типизированные ошибки                 |
| `ConfigParseOutcome`                 | Результат (секции + ошибки + partial) |
| `XrayConfigParser`                   | Парсер single file / directory        |

## 13.7	Тесты (20)
single config · config directory · unknown top-level · unknown inbound/outbound protocol · empty config · missing optional sections · 2 inbounds · 3 outbounds · order preservation · source_file · corrupted DNS · corrupted routing · invalid JSON · duplicate inbound/outbound tags · (+ non-object root, full sample, transport/fakedns in extra)

## 13.8	Новые зависимости
Нет. Использованы уже существующие serde / serde_json.


# 14	Чтение Inbounds конфигурации
Страница Inbounds показывает реальные данные из модели конфигурации в режиме только чтения. Все 102 теста проходят.
> Актуально: после выбора inbound — вкладки General | Protocol | Stream | Security | Sniffing | Users (§34 Complete Inbounds; исторические слои §32–§33). Таблица и read-only summary ниже остаются базой списка. Add Inbound — отдельный режим редактора.

## 14.1	Изменения GUI
- Страница Inbounds вместо placeholder: таблица Tag / Protocol / Listen / Port / Clients / Source file
- Сортировка по клику на Tag, Protocol, Port
- Состояния с понятными сообщениями (нет SSH, нет Xray, discovery не завершён, конфиг не загружен, нет inbounds, загружено, с warnings)
- Контекстное меню: Copy tag/port/protocol; Edit / Duplicate — shell-editable (VLESS/Trojan/Hysteria/Tunnel, §34); Delete — любой protocol (unsupported confirm + routing `inboundTag` hard-block); legacy `dokodemo-door` — Edit/Duplicate disabled, Delete allowed if unreferenced
- Пустые поля → `—`; неизвестный protocol отображается как есть
- Source file — только имя файла (`config.json` / `03-inbounds.json`)

## 14.2	Поток данных
Discovery (SSH read)
  → XrayConfigParser → XrayConfigSections → InboundSummary
  → DiscoveryOutcome / LoadedConfigSnapshot
  → ApplicationService
  → InboundsPageModel
  → GUI table

## 14.3	Структуры
`LoadedConfigSnapshot`, `InboundsPageState`, `InboundsPageModel`, `InboundsSort` / `InboundsSortColumn`, `InboundRowDisplay`, плюс существующий `InboundSummary`

## 14.4	Подтверждения
- GUI не трогает JSON — только `ApplicationService` / `InboundSummary` (и editor session через сервис, §34)
- Таблица Inbounds остаётся read-only; мутации — через вкладки редактора / Users

## 14.5	Тесты `app::inbounds`
пустой список · один / несколько inbound · unknown protocol · missing listen/tag/port · sort Tag/Port · source file basename · No SSH · Configuration not loaded · (+ discovery not completed, no Xray, warnings)

## 14.6	Новые зависимости
Нет — использованы egui clipboard API и уже существующие crate-зависимости.


# 15	Механизм чтения пользователей
> Актуально: см. §32 / §34 — Users вкладка под выбранным inbound. Ниже — исторический MVP read-only.

Страница Users показывает VLESS-клиентов в режиме только чтения. 115 тестов проходят.

## 15.1	Поток
XrayConfigSections
  → extract_vless_clients()
  → VlessClientSummary / SupportedUserInbound
  → LoadedConfigSnapshot (при Discovery)
  → ApplicationService.users_page_model()
  → Users GUI
GUI не читает `settings["clients"]` напрямую.

## 15.2	UI
- Селектор: `Inbound: [ tag · VLESS · :443 ▼ ]` — только `protocol = vless`
- Таблица: Email · ID · Flow · Inbound tag · Source file  
    (без Enabled — в официальном VLESS client его нет)
- Контекстное меню: Copy email/ID/flow; Edit/Delete отключены; Copy VLESS link не показывается

## 15.3	Клиенты
Поддержаны оба массива: `settings.clients` (типичные конфиги) и `settings.users` (текущая док. Xray). Исходный JSON не меняется. `source_file` — `String` (как у `InboundSummary`), не `RemotePath`: так проще для `<memory>` и basename-отображения.

## 15.4	Состояния
No SSH · Xray not discovered · Configuration not loaded · No supported inbounds · Selected inbound has no clients · Clients loaded · Configuration contains warnings

## 15.5	Новые зависимости
Нет.


# 16	Отображение настроек пользователей
> Актуально: см. §32 / §34 (Inbounds → 6 вкладок, без sidebar Users).

Страница Users доведена до read-only MVP. 117 тестов проходят.

## 16.1	Изменённые GUI-модули
- `src/gui/pages/users.rs` — селектор inbound, таблица, сортировка, контекстное меню
- `src/gui/navigation.rs` — уже передаёт `ApplicationService` в Users

## 16.2	Поток данных
XrayConfigSections
  → extract_vless_clients() → UserSummary (= VlessClientSummary)
  → LoadedConfigSnapshot (Discovery)
  → ApplicationService.users_page_model()
  → Users page
  GUI не читает JSON и не трогает `XrayConfigSections`.

## 16.3	Состояния
| Состояние                        | Сообщение                           |
| -------------------------------- | ----------------------------------- |
| No SSH connection                | Connect on Connection page…         |
| Xray installation not discovered | Run Discover Xray…                  |
| Configuration not loaded         | Discover again when readable…       |
| No supported inbound selected    | VLESS only…                         |
| Selected inbound has no users    | Selected inbound has no users.      |
| Users loaded                     | Таблица                             |
| Configuration contains warnings  | Warning + таблица при наличии строк |

## 16.4	Ограничения
Только чтение; только VLESS; нет create/edit/delete/VLESS link/записи/рестарта. Edit / Delete / Generate VLESS link — disabled.

## 16.5	Тесты `app::users`
нет пользователей · один · несколько · переключение inbound · missing fields + unknown flow · sort Email/UUID · source file · configuration not loaded · no SSH · Xray not discovered · no supported inbound


# 17	Изменение пользователей (MVP)
> Актуально: см. §32 — typed write (`inbound_clients`), fingerprint, `level`, inbound-scoped UI. Ниже — первый MVP (Value-patch update).

## 17.1	Архитектура изменения конфигурации
- `EditableXrayConfig` — merged `XrayConfigSections` + `file_roots` (исходный JSON каждого файла)
- Операции в `xray/config/modify.rs`: `add_user` / `update_user` / `delete_user`
- Запись через `RemoteAdmin::write_config_safe`: backup → atomic upload
- GUI вызывает только `ApplicationService::{start_add_user,start_update_user,start_delete_user}`

## 17.2	Поток данных
```
Users Page → ApplicationService (AddUser/UpdateUser/DeleteUser)
  → modify layer (EditableXrayConfig)
  → serialize affected source file
  → validate JSON
  → BackupManager
  → SFTP atomic write (temp → replace)
  → refresh summaries in LoadedConfigSnapshot
```

## 17.3	Backup
Перед любой записью: `*.feldjaeger.bak.<unix_ts>`. Если backup не создан — запись отменяется, рабочий файл не трогается.

## 17.4	Unknown fields
Update меняет только `email`/`flow` в существующем client object. Остальные ключи (например `futureField`) сохраняются. Пустой `flow` удаляется из JSON.

## 17.5	Поддерживаемые операции
| Action     | Поля                                 |
| ---------- | ------------------------------------ |
| AddUser    | email, UUID (auto v4), optional flow |
| UpdateUser | email, flow (UUID read-only)         |
| DeleteUser | confirmation `Delete user <email>?`  |
Только inbound с `protocol = vless`. Иначе: `Unsupported inbound type`.

## 17.6	Ограничения MVP
Нет (на момент MVP Users): Reality/streamSettings/routing/DNS editing, auto-restart Xray, dry-run preview.  
Актуально: Complete Inbounds §34 (Shell Save, Stream/Reality, Preview, `-test`, Share URI). Outbound mutate — WARP / modify outbound APIs.  
После успеха Users: User updated. Configuration updated. Xray restart required.

## 17.7	Тесты `src/xray/config/modify_tests.rs`
Add (UUID, optional flow),
Update (email/flow, UUID fixed, unknown fields), Delete (selected only / missing),
Safety (backup before write, backup abort, invalid JSON rejected, confdir only one file).

## 17.8	Новые зависимости
- `uuid` `1.23.4` с feature `v4`
Ключевые файлы: `editable.rs`, `modify.rs`, `serialize.rs`, `user_ops.rs`, обновлённые `RemoteAdmin`, SFTP atomic write, Users GUI.


# 18	Чтение Outbounds
Реализована read-only страница Outbounds по той же схеме, что Inbounds/Users. Все 144 теста проходят.

## 18.1	Модифицированные модули GUI
- `src/gui/pages/outbounds.rs` — таблица Tag / Protocol / Send Through / Summary / Source file, сортировка, контекстное меню
- `src/gui/navigation.rs` — страница получает `ApplicationService`

## 18.2	Поток данных
```
Remote config → XrayConfigSections → OutboundSummary
  → LoadedConfigSnapshot.outbounds
  → ApplicationService.outbounds_page_model()
  → Outbounds page
```

GUI не парсит JSON, не трогает SSH и не пишет конфигурацию.

## 18.3	Структура OutboundSummary
Поля: `index`, `tag`, `protocol`, `send_through`, `description`, `source_file`.  
`OutboundKind` классифицирует протокол (включая `Unknown`); вид не дублируется в структуре — через `summary.kind()`.

## 18.4	Генерация сводки
| Протокол             | Summary                 |
| -------------------- | ----------------------- |
| freedom              | Direct connection       |
| blackhole            | Response: none / http   |
| wireguard            | Peers: N                |
| socks                | Proxy server configured |
| прочие / неизвестные | Summary unavailable     |

## 18.5	Состояния GUI
`NoSshConnection` · `XrayNotDiscovered` · `ConfigurationNotLoaded` · `NoOutbounds` · `ConfigurationLoaded` · `ConfigurationContainsWarnings`
Строка состояния на странице: `Loading outbounds...` → `Loaded N outbound(s)` → `Ready`.

## 18.6	Тесты
- `src/app/outbounds.rs` — пустой/один/несколько, unknown protocol, missing tag/sendThrough, source file, sort by tag/protocol, configuration not loaded
- `src/xray/config/tests.rs` — описания протоколов, `sendThrough`, missing tag

## 18.7	Новые зависимости
Нет.


# 19	Чтение настроек DNS

## 19.1	Реализовано
Реализована read-only DNS-страница.
1. GUI: `src/gui/pages/dns.rs`, навигация обновлена.
2. Добавлены `DnsSummary`, `DnsServerSummary`, `DnsHostSummary`.
3. Поток: Xray model → discovery → snapshot → ApplicationService → GUI.
4. Поддержаны общие поля, серверы, DoH/localhost/FakeDNS, IPv4/IPv6/aliases и source file.
5. Реализованы все состояния, warnings, контекстные меню и status lifecycle.
6. Добавлено 15 DNS-тестов; все 169 workspace-тестов проходят.
7. Новых зависимостей нет.

## 19.2	Проверки:
- `cargo fmt --check` — успешно
- `cargo check --workspace` — успешно
- IDE diagnostics — чисто
- строгий Clippy блокируется существующими repository-wide предупреждениями, включая `collapsible_if`, `manual_async_fn` и ранее крупные enum-варианты.


> Этот раздел (§19) описывает исторический read-only слой. §50 добавил поверх него полноценный
> редактор (`dns` edit, Roadmap §2.1:46) — `DnsSummary`/`dns_summary()` из этого раздела остались
> без изменений (используются в других местах через `LoadedConfigSnapshot`), но сама страница
> `gui/pages/dns.rs` теперь читает и пишет через отдельную, более полную типизированную модель
> `DnsSettings` — см. §50.

# 20	Чтение маршрутизации

## 20.1	План

### 20.1.1	Read-only Routing page

#### 20.1.1.1	Current gap
- Секция `routing` уже парсится lossless в `[src/xray/config/sections.rs](src/xray/config/sections.rs)` как `Option<SourcedSection<Value>>` с `source_file`.
- GUI сейчас — placeholder: `[src/gui/pages/routing.rs](src/gui/pages/routing.rs)`, навигация вызывает `pages::routing::show(ui)` без `ApplicationService`.
- Нет `RoutingSummary`, нет прокидывания через discovery/`LoadedConfigSnapshot`.

#### 20.1.1.2	Data flow
```mermaid
flowchart TD
  remoteConfig[Remote Xray config]
  sections[XrayConfigSections.routing]
  summary[RoutingSummary / RoutingRuleSummary]
  discovery[DiscoveryResult + LoadedConfigSnapshot]
  service[ApplicationService.routing_page_model]
  page[gui/pages/routing.rs]
  remoteConfig --> sections --> summary --> discovery --> service --> page
```

GUI never touches JSON, `XrayConfigSections`, SSH, serialization, backup, or restart.

### 20.1.2	Internal summary model
Extend `[src/xray/config/summary.rs](src/xray/config/summary.rs)` (and re-exports in `[config/mod.rs](src/xray/config/mod.rs)`, `[xray/mod.rs](src/xray/mod.rs)`, `[sections.rs](src/xray/config/sections.rs)`, `[editable.rs](src/xray/config/editable.rs)`):

```rust
RoutingSummary {
  domain_strategy: Option<String>,
  domain_matcher: Option<String>,
  rule_count: usize,
  rules: Vec<RoutingRuleSummary>,
  source_file: String,
}

RoutingRuleSummary {
  index: usize,                 // 0-based internally; UI shows # = index + 1
  target: Option<String>,       // outboundTag preferred over balancerTag
  criteria: Vec<String>,        // labels like Domain, IP, Protocol, Inbound...
  summary: String,              // single condition text or "N совпадающих условия"
  source_file: String,
  // detail fields for selection panel (supported subset only)
  rule_tag, type_, domain, ip, port, source_port, local_port,
  network, source_ip, local_ip, user, vless_route, inbound_tag,
  protocol, attrs_summary, process, outbound_tag, balancer_tag
}
```

`routing_summary(sections) -> Option<RoutingSummary>`:
- absent section → `None` (not an error);
- extract only supported fields; unknown keys ignored for display, remain in lossless model;
- `port`/`sourcePort`/`localPort`/`vlessRoute` accept number or string;
- `source` treated as alias of `sourceIP`;
- if both tags present, target/detail prefer `outboundTag` (Xray docs);
- balancers out of this page scope unless already trivial; do not invent UI for them unless needed for rule target display.

#### 20.1.2.1	Summary / criteria generation
Supported match labels (examples from task): Domain, IP, Port, Network, Protocol, Inbound, User, Source IP, Attribute (+ Source Port / Local Port / Local IP / Process / VLESS Route when present).
- 0 conditions → summary `—` (or empty criteria + dash);
- 1 condition → e.g. `domain: google.com`, `ip: geoip:private`, `protocol: bittorrent`, `inbound: socks-in`;
- multiple → Russian plural text: `N совпадающих условия` / correct pluralization for 1/2-4/5+ if already used elsewhere; otherwise keep task wording and cover in tests.

### 20.1.3	Discovery and snapshot plumbing
Thread `Option<RoutingSummary>` through:
- `[src/xray/discovery.rs](src/xray/discovery.rs)`: `DiscoveredConfig`, `DiscoveryResult::Found`, both single-file and directory parse paths;
- `[src/app/inbounds.rs](src/app/inbounds.rs)`: `LoadedConfigSnapshot::Loaded { routing, ... }` + `routing()` accessor;
- `[src/app/discovery.rs](src/app/discovery.rs)`: `map_discovery_result`;
- user-mutation refresh in `[src/app/service.rs](src/app/service.rs)` that rebuilds `LoadedConfigSnapshot` (keep routing from editable via `editable.routing_summary()`);
- all existing `Loaded { ... }` test helpers (`dns`, `outbounds`, `users`, `service` tests).

### 20.1.4	3. Application page model
Add `[src/app/routing.rs](src/app/routing.rs)`, mirror DNS + Outbounds:

|   |   |
|---|---|
|Piece|Behavior|
|`RoutingPageState`|`NoSshConnection`, `XrayNotDiscovered`, `ConfigurationNotLoaded`, `RoutingSectionMissing`, `NoRoutingRules`, `ConfigurationLoaded`, `ConfigurationContainsWarnings`|
|Messages|Missing section: `Routing section is not configured.` (not an error). Empty rules: `No routing rules.`|
|Sort|`Index`, `Target` (default index asc)|
|Display helpers|`routing_general_display`, `routing_rule_row_display`, reuse `MISSING_FIELD` / `display_source_file`|
|Selection|local egui temp data by `rule.index` (same approach as Users); not required in `ApplicationService`|
Wire in `[src/app/service.rs](src/app/service.rs)` / `[src/app/mod.rs](src/app/mod.rs)`:
- `routing_page_model()`, `routing_sort()`, `set_routing_sort_column()`;
- `tick_routing_page_status()`: `Loading routing...` while discovering; once after load `Loaded N routing rule(s).` then Ready (same announce-once pattern as outbounds/dns)
- reset announce flag on rediscovery.

### 20.1.5	GUI page
Replace placeholder in `[src/gui/pages/routing.rs](src/gui/pages/routing.rs)`; pass service from `[src/gui/navigation.rs](src/gui/navigation.rs)`.
Layout (egui, like DNS):
1. Heading `Routing` + state/warnings.
2. General information: Domain strategy, Domain matcher, Rule count (`—` when absent).
3. Routing rules table: `#`, `Target`, `Criteria`, `Summary`, `Source file`; sortable Index/Target only (not Type/Inbound); row click selects (mark selected row); no empty table without explanation.
4. Rule details below table when selected — new UI pattern (existing pages lack detail panels): groups General / Matching Conditions / Target; only supported fields; missing → `—`.
5. Context menu: `Copy outbound tag`, `Copy summary`; disabled `Edit`, `Delete`, `Duplicate`, `Move up`, `Move down` with hover `Not implemented yet`.
6. Strict read-only: no save/upload/backup/restart/edit APIs.
Status colors: red unavailable, yellow warnings, gray missing/empty — same as DNS. Sidebar/`pages/mod.rs` already list Routing; no Cargo dependency changes.

### 20.1.6	Tests
No egui GUI tests exist today; keep tests colocated with view-model/summary like DNS/Outbounds. Primary coverage in `src/app/routing.rs` (+ focused summary extraction tests in `summary.rs` or nearby; optional service tick/sort test in `service.rs`):
- missing routing section;
- empty rules;
- one rule / several rules;
- geoip / geosite / protocol / inboundTag;
- outboundTag / balancerTag targets;
- unknown match condition preserved in model, not shown as supported criteria;
- missing optional fields → `—`;
- source file basename (`config.json` vs `04-routing.json`);
- configuration not loaded (+ SSH / not discovered / warnings / no rules states);
- summary generation for single vs multi criteria;
- sort by Index/Target.
No new Cargo dependencies expected; reuse `serde_json` already present.

### 20.1.7	Out of scope
- Editing, reordering, balancers editor, filtering (not on existing Outbounds/DNS pages), config write-back.
- Showing unknown JSON keys in the detail panel.

## 20.2	Реализация
Реализована read-only страница Routing. Краткий отчёт:

### 20.2.1	GUI-модули
- [`src/gui/pages/routing.rs`](vscode-file://vscode-app/c:/prg/Cursor/resources/app/out/vs/code/electron-sandbox/workbench/src/gui/pages/routing.rs) — general info, таблица правил, detail panel, context menu, состояния
- [`src/gui/navigation.rs`](vscode-file://vscode-app/c:/prg/Cursor/resources/app/out/vs/code/electron-sandbox/workbench/src/gui/navigation.rs) — `show(ui, service)`

### 20.2.2	`RoutingSummary`
`domain_strategy`, `domain_matcher`, `rule_count`, `rules`, `source_file`

### 20.2.3	`RoutingRuleSummary`
Таблица: `index`, `target`, `criteria`, `summary`, `source_file`  
Detail: `rule_tag`, `rule_type`, domain/ip/port/…, `outbound_tag`, `balancer_tag`, …

### 20.2.4	Генерация summary
- 0 условий → `—`
- 1 → `domain: …` / `ip: …` / `protocol: …` / …
- несколько → `N совпадающих условия`  
    `outboundTag` приоритетнее `balancerTag`; неизвестные match-ключи игнорируются в UI.

### 20.2.5	Поток данных
Remote config → XrayConfigSections.routing → routing_summary()
→ DiscoveryResult / LoadedConfigSnapshot → ApplicationService.routing_page_model()
→ Routing page

### 20.2.6	Состояния GUI
`NoSshConnection`, `XrayNotDiscovered`, `ConfigurationNotLoaded`, `RoutingSectionMissing`, `NoRoutingRules`, `ConfigurationLoaded`, `ConfigurationContainsWarnings`  
Status bar: `Loading routing...` → `Loaded N routing rule(s).` → `Ready`

### 20.2.7	Тесты
14 тестов в `app/routing.rs` + 2 status-теста в `service.rs` (missing/empty/geoip/geosite/protocol/inbound/balancer/outbound/unknown/source file/states/sort).  
175 lib-тестов — ok.

### 20.2.8	Зависимости
Новых нет.
Страница только для чтения: без JSON/SSH, без save/backup/restart.


# 21	Чтение политик

## 21.1	План

### 21.1.1	Архитектура
```mermaid
flowchart TD
  remoteConfig[Remote Xray config]
  policySection[XrayConfigSections.policy]
  policySummary[PolicySummary]
  discovery[DiscoveryResult + LoadedConfigSnapshot]
  applicationService[ApplicationService.policy_page_model]
  policyPage[gui/pages/policy.rs]
  remoteConfig --> policySection --> policySummary --> discovery --> applicationService --> policyPage
```

`PolicySummary` сейчас в проекте отсутствует, хотя секция `policy` уже lossless хранится как `SourcedSection<Value>` в `[src/xray/config/sections.rs](src/xray/config/sections.rs)`. Реализация добавит только read-only проекцию; исходный JSON со всеми неизвестными полями останется источником истины.

### 21.1.2	Сводки внутренней модели
Расширить `[src/xray/config/summary.rs](src/xray/config/summary.rs)`, экспорты в `[src/xray/config/mod.rs](src/xray/config/mod.rs)` и `[src/xray/mod.rs](src/xray/mod.rs)`, accessors в `[src/xray/config/sections.rs](src/xray/config/sections.rs)` и `[src/xray/config/editable.rs](src/xray/config/editable.rs)`:
- `PolicySummary`
    - `user_policy_count: Option<usize>` — `None`, если `levels` отсутствует; `Some(0)` для пустого объекта;    
    - `user_levels: Vec<UserPolicySummary>`;    
    - `system_policy: Option<SystemPolicySummary>`;    
    - `source_file: String`.    
- `UserPolicySummary`
    - `level: String`;    
    - `handshake`, `conn_idle`, `uplink_only`, `downlink_only`, `buffer_size`: `Option<i64>`;    
    - `stats_user_uplink`, `stats_user_downlink`, `stats_user_online`: `Option<bool>`;    
    - `source_file: String`.    
- `SystemPolicySummary`
    - `stats_inbound_uplink`, `stats_inbound_downlink`, `stats_outbound_uplink`, `stats_outbound_downlink`: `Option<bool>`.    
`policy_summary()` будет shallow/tolerant: читать только `levels`, `system` и официальные поля Xray; неизвестные ключи и неподдерживаемые типы не вызывают panic/ошибку и остаются в lossless `Value`. Уровни сохраняют исходный ключ; сортировка сравнивает числовые ключи численно и использует строковый fallback.

### 21.1.3	Discovery и application snapshot
Прокинуть `Option<PolicySummary>` через:
- `[src/xray/discovery.rs](src/xray/discovery.rs)`: `DiscoveryResult::Found`, `DiscoveredConfig`, single-file/confdir extraction и все empty/error constructors;
- `[src/app/inbounds.rs](src/app/inbounds.rs)`: поле `policy` в `LoadedConfigSnapshot::Loaded` и accessor `policy()`;
- `[src/app/discovery.rs](src/app/discovery.rs)`: mapping discovery result;
- `[src/app/service.rs](src/app/service.rs)`: пересчёт policy после user mutation, чтобы сводка не исчезала при обновлении snapshot;
- существующие test helpers, создающие `LoadedConfigSnapshot::Loaded`.

### 21.1.4	Policy page model и ApplicationService
Добавить `[src/app/policy.rs](src/app/policy.rs)`, подключить в `[src/app/mod.rs](src/app/mod.rs)`:
- `PolicyPageState`: `NoSshConnection`, `XrayNotDiscovered`, `ConfigurationNotLoaded`, `PolicySectionMissing`, `NoUserPolicies`, `ConfigurationLoaded`, `ConfigurationContainsWarnings`;
- `PolicySort` / `PolicySortColumn::Level`, переключение asc/desc;
- `PolicyPageModel` с `summary`, отсортированными rows, warnings и sort;
- display helpers:
    - отсутствующее значение → `—`;    
    - system booleans → `Enabled` / `Disabled` / `—`;    
    - table `Stats` → явная компактная строка по Uplink/Downlink/Online, а при полном отсутствии → `—`;    
    - source file → basename.    
Расширить `[src/app/service.rs](src/app/service.rs)`:
- `policy_summary()`, `policy_page_model()`, `policy_sort()`, `set_policy_sort_column()`;
- `policy_status_announced` и `tick_policy_page_status()`:
    - discovery: `Loading policy...`;    
    - после загрузки: `Loaded N policy level(s).`;    
    - затем существующий transient status возвращает `Ready`;    
- сбрасывать announce-флаг при новом discovery.

### 21.1.5	GUI и навигация
Добавить `[src/gui/pages/policy.rs](src/gui/pages/policy.rs)`, экспортировать в `[src/gui/pages/mod.rs](src/gui/pages/mod.rs)`, добавить `Page::Policy` после Routing в `[src/gui/navigation.rs](src/gui/navigation.rs)`.
Страница:
1. Heading `Policy`, сообщения состояний и warnings по паттерну Routing.
2. General information: `User policy count`, `System policy configured` (`Configured` либо `—`).
3. User policies table: `Level`, `Handshake`, `Connection Idle`, `Uplink Only`, `Downlink Only`, `Stats`; сортируемый Level, selection через egui temp data.
4. При отсутствии levels — пояснение `No user policies.` вместо пустой таблицы; system-only конфигурация всё равно показывает общую и системную панели.
5. Details выбранного уровня:
    - General: level, source file;    
    - Timeouts: handshake/connIdle/uplinkOnly/downlinkOnly (seconds);    
    - Buffer: bufferSize (KB);        
    - Statistics: user uplink/downlink/online (`Enabled`/`Disabled`/`—`).      
6. System policy panel с четырьмя требуемыми флагами; если `system` отсутствует — явное `System policy is not configured.`
7. Context menu: `Copy level`, `Copy timeout values`; disabled `Edit`, `Delete`, `Duplicate` с `Not implemented yet`.
GUI получает только app/xray summary types через `ApplicationService`; никаких JSON, SSH, serialization, upload/backup/restart API.

### 21.1.6	Тесты и проверка
Добавить colocated unit tests в `[src/app/policy.rs](src/app/policy.rs)` и extraction/status tests рядом с существующими:
- policy section missing и пустая секция;
- один и несколько user levels;
- только system / только levels;
- все timeout, buffer и user stats поля;
- четыре system stats поля;
- отсутствующие optional values → `—`;
- неизвестные поля не попадают в сводку и сохраняются в исходной секции;
- правильный source file для `config.json` и confdir owner;
- configuration not loaded, SSH/discovery/warnings/no-user-policies states;
- numeric asc/desc sorting по level;
- loading/loaded/Ready status sequence.
Запустить форматирование, `cargo check` и полный `cargo test --lib`. Новых зависимостей не требуется.

## 21.2	Реализация
Реализована read-only страница Policy. Краткий отчёт:

### 21.2.1	GUI-модули
- [`src/gui/pages/policy.rs`](vscode-file://vscode-app/c:/prg/Cursor/resources/app/out/vs/code/electron-sandbox/workbench/src/gui/pages/policy.rs) — general info, system panel, таблица levels, details, context menu
- [`src/gui/pages/mod.rs`](vscode-file://vscode-app/c:/prg/Cursor/resources/app/out/vs/code/electron-sandbox/workbench/src/gui/pages/mod.rs), [`src/gui/navigation.rs`](vscode-file://vscode-app/c:/prg/Cursor/resources/app/out/vs/code/electron-sandbox/workbench/src/gui/navigation.rs) — пункт Policy после Routing

### 21.2.2	`PolicySummary`
`user_policy_count`, `user_levels`, `system_policy`, `source_file` (+ `has_system_policy()`)

### 21.2.3	`UserPolicySummary`
`level`, `handshake`, `conn_idle`, `uplink_only`, `downlink_only`, `buffer_size`, `stats_user_uplink/downlink/online`, `source_file`

### 21.2.4	`SystemPolicySummary`
`stats_inbound_uplink/downlink`, `stats_outbound_uplink/downlink`

### 21.2.5	Поток данных
Remote config → XrayConfigSections.policy → policy_summary()
→ DiscoveryResult / LoadedConfigSnapshot → ApplicationService.policy_page_model()
→ Policy page

### 21.2.6	Поддерживаемые поля
Level timeouts (s), `bufferSize` (KB), user stats flags, four system stats flags. Неизвестные ключи сохраняются в lossless `Value`, в UI не показываются.

### 21.2.7	Состояния GUI
`NoSshConnection`, `XrayNotDiscovered`, `ConfigurationNotLoaded`, `PolicySectionMissing`, `NoUserPolicies`, `ConfigurationLoaded`, `ConfigurationContainsWarnings`  
Status bar: `Loading policy...` → `Loaded N policy level(s).` → `Ready`

### 21.2.8	Тесты
Покрытие в `app/policy.rs`, status в `service.rs`, extraction в `xray/config/tests.rs`.  
192 lib-теста — ok.

### 21.2.9	Зависимости
Новых нет.


# 22	Чтение FakeDNS

## 22.1	План

### 22.1.1	Расширить lossless-модель и сводку Xray
- В [src/xray/config/sections.rs](E:/prj/rust/Feldjaeger/src/xray/config/sections.rs) сделать `fakedns` известным sourced-разделом с accessor/setter, сохранив исходный `serde_json::Value` без преобразования; обновить `KNOWN_SECTION_NAMES`, `is_empty()` и parser dispatch в [src/xray/config/parser.rs](E:/prj/rust/Feldjaeger/src/xray/config/parser.rs). Это заменит текущее хранение `fakedns` в `extra_sections`, не меняя lossless write-back.
- В [src/xray/config/summary.rs](E:/prj/rust/Feldjaeger/src/xray/config/summary.rs) добавить:
    - `FakeDnsAddressFamily::{Ipv4, Ipv6, Unknown}`;    
    - `FakeDnsPoolSummary { ip_pool, pool_size, address_family }`;    
    - `FakeDnsSummary { pools, source_file, warnings }`.     
- Нормализовать официальный одиночный объект и массив объектов в `pools`; некорректные элементы не должны паниковать. Формировать локальные предупреждения для отсутствующих/неверно типизированных `ipPool` и `poolSize`, некорректного CIDR, неподдерживаемого адреса, пустого/неподдерживаемого контейнера и неизвестных ключей. Неизвестные значения остаются только в исходном lossless `Value`.
- Добавить `fakedns_summary()` в `XrayConfigSections` и `EditableXrayConfig`, а также re-export через [src/xray/config/mod.rs](E:/prj/rust/Feldjaeger/src/xray/config/mod.rs) и [src/xray/mod.rs](E:/prj/rust/Feldjaeger/src/xray/mod.rs).

### 22.1.2	Прокинуть сводку через discovery и snapshot
- В [src/xray/discovery.rs](E:/prj/rust/Feldjaeger/src/xray/discovery.rs) добавить `FakeDnsSummary` в `DiscoveryResult::Found`/`DiscoveredConfig` и обе ветки чтения конфигурации.
- В [src/app/inbounds.rs](E:/prj/rust/Feldjaeger/src/app/inbounds.rs) расширить `LoadedConfigSnapshot::Loaded` полем `fakedns: Option<FakeDnsSummary>` и accessor `fakedns()`.
- В [src/app/discovery.rs](E:/prj/rust/Feldjaeger/src/app/discovery.rs) перенести summary в snapshot; в [src/app/service.rs](E:/prj/rust/Feldjaeger/src/app/service.rs) сохранить его и при refresh после user mutation через `EditableXrayConfig::fakedns_summary()`.

### 22.1.3	Добавить app-level модель и безопасные производные значения
- Создать [src/app/fakedns.rs](E:/prj/rust/Feldjaeger/src/app/fakedns.rs) по шаблону DNS/Policy: `FakeDnsPageState`, `FakeDnsPageModel`, display-модель одного пула и чистые функции построения состояния/представления.
- Состояния: no SSH, Xray not discovered, config not loaded, section missing, loaded, loaded with warnings. Отсутствующий раздел возвращает ровно `FakeDNS section is not configured.` и не считается ошибкой.
- Вычислять для представления без зависимости CIDR:
    - family — из IP-части через `std::net::IpAddr`;    
    - prefix — только если число допустимо для IPv4/IPv6;    
    - total capacity — через checked-арифметику, иначе `—`;    
    - configured pool size — исходное `poolSize` либо `—`. Несоответствие capacity и `poolSize` не валидировать как ошибку.
- Подключить модуль/re-export в [src/app/mod.rs](E:/prj/rust/Feldjaeger/src/app/mod.rs); добавить в `ApplicationService` summary/page-model API, `fakedns_status_announced` и lifecycle: `Loading FakeDNS...` → `FakeDNS configuration loaded.` либо `FakeDNS is not configured.` → `Ready`, со сбросом флага при новом discovery.

### 22.1.4	Реализовать GUI и навигацию
- Создать [src/gui/pages/fakedns.rs](E:/prj/rust/Feldjaeger/src/gui/pages/fakedns.rs), используя только `ApplicationService` и app-level display model.
- Показывать каждый нормализованный пул отдельным блоком (`Pool 1`, `Pool 2` для массива) с `IP pool`, `Pool size`, `Address family`, `Source file`, затем `CIDR prefix`, `Total address capacity`, `Configured pool size`; отсутствующие/небезопасные значения — `—`.
- Всегда показывать информационное примечание `FakeDNS requires corresponding DNS and routing configuration.` при наличии раздела, не делая выводов об активности.
- Показать локальные некритические warnings без блокировки поддерживаемых значений; для пустого массива/неподдерживаемой структуры дать пояснение вместо пустого UI.
- На блоке/значениях добавить context menu `Copy IP pool`, `Copy pool size`, `Copy source file`; `Edit` и `Delete` disabled с hover-текстом `Not implemented yet`.
- Зарегистрировать модуль в [src/gui/pages/mod.rs](E:/prj/rust/Feldjaeger/src/gui/pages/mod.rs), а `Page::FakeDns` — после DNS в enum, `ALL`, `label()` и `show()` в [src/gui/navigation.rs](E:/prj/rust/Feldjaeger/src/gui/navigation.rs).

### 22.1.5	Покрыть тестами и проверить
- В [src/xray/config/tests.rs](E:/prj/rust/Feldjaeger/src/xray/config/tests.rs) заменить старое ожидание `fakedns` в extras тестами summary для missing, default/custom IPv4, IPv6, object+array, missing fields, invalid CIDR/address, unknown-field preservation и config-directory source ownership.
- В [src/app/fakedns.rs](E:/prj/rust/Feldjaeger/src/app/fakedns.rs) протестировать все page states, family/prefix/capacity formatting, warnings и `—`; в [src/app/service.rs](E:/prj/rust/Feldjaeger/src/app/service.rs) — loading/loaded/missing/Ready status lifecycle.
- Обновить все test constructors/patterns `LoadedConfigSnapshot::Loaded` и `DiscoveryResult::Found` новым полем.
- Выполнить `cargo fmt --check`, `cargo check`, `cargo test --lib` и проверить lints изменённых файлов.

## 22.2	Реализация
FakeDNS read-only page is implemented. All 209 lib tests pass.

### 22.2.1	Modified GUI modules
- `src/gui/pages/fakedns.rs` — new page
- `src/gui/pages/mod.rs`] — module registration
- `src/gui/navigation.rs` — `Page::FakeDns` after DNS

### 22.2.2	`FakeDnsSummary` structure
FakeDnsSummary

```
pools: Vec<FakeDnsPoolSummary>
source_file: String
warnings: Vec<String>
```

FakeDnsPoolSummary

```
ip_pool: Option<String>
pool_size: Option<u64>
address_family: FakeDnsAddressFamily { Ipv4 | Ipv6 | Unknown }
```

### 22.2.3	Supported FakeDNS fields
- `ipPool`
- `poolSize`
- Object and array forms of `fakedns`
- Unknown nested keys preserved in lossless JSON (warnings only)

### 22.2.4	Derived view values
- Address family from `ipPool`
- CIDR prefix
- Total address capacity (checked math, no new deps)
- Configured pool size  
    Missing/unsafe values show `—`. Capacity vs `poolSize` mismatch is not an error.

### 22.2.5	Data flow
Remote config
→ XrayConfigSections (known `fakedns` sourced Value)
→ FakeDnsSummary
→ LoadedConfigSnapshot / ApplicationService
→ FakeDNS page
Status bar: `Loading FakeDNS...` → `FakeDNS configuration loaded.` / `FakeDNS is not configured.` → `Ready`.


> Этот раздел (§22) описывает исторический read-only слой. §51 добавил поверх него полноценный
> редактор (`fakedns` edit, Roadmap §2.1:47) — `FakeDnsSummary`/`fakedns_summary()` из этого
> раздела остались без изменений (используются в других местах через `LoadedConfigSnapshot`), но
> сама страница `gui/pages/fakedns.rs` теперь читает и пишет через отдельную типизированную модель
> `FakeDnsSettings` — см. §51.

# 23	Чтение Observatory

## 23.1	План

### 23.1.1	Добавить ObservatorySummary поверх lossless-модели
- В [src/xray/config/summary.rs](E:/prj/rust/Feldjaeger/src/xray/config/summary.rs) создать отсутствующую сейчас `ObservatorySummary { probe_url, probe_interval, subject_selectors, source_file, warnings }` и tolerant extraction из существующего sourced `observatory`.
- Поддержать официальный subset `probeUrl`, `probeInterval`, `subjectSelector`; неверные типы не должны паниковать. Сохранять порядок строковых selectors, пропуская некорректные элементы с предупреждением.
- Формировать локальные warnings для отсутствующих `probeUrl`/`probeInterval`, отсутствующего или пустого `subjectSelector`, а также ключей вне поддерживаемого subset. Исходный `Value` не изменять, поэтому `enableConcurrency` и будущие поля сохраняются losslessly.
- Добавить `observatory_summary()` в [src/xray/config/sections.rs](E:/prj/rust/Feldjaeger/src/xray/config/sections.rs) и [src/xray/config/editable.rs](E:/prj/rust/Feldjaeger/src/xray/config/editable.rs), затем re-export через [src/xray/config/mod.rs](E:/prj/rust/Feldjaeger/src/xray/config/mod.rs) и [src/xray/mod.rs](E:/prj/rust/Feldjaeger/src/xray/mod.rs). Parser менять не нужно: `observatory` уже является известным sourced-разделом с ownership; `burstObservatory` остаётся отдельным неподдерживаемым разделом.

### 23.1.2	Прокинуть сводку до ApplicationService
- В [src/xray/discovery.rs](E:/prj/rust/Feldjaeger/src/xray/discovery.rs) добавить `observatory_summary` в `DiscoveredConfig` и `DiscoveryResult::Found` для single-file, config-directory, empty/error веток.
- В [src/app/inbounds.rs](E:/prj/rust/Feldjaeger/src/app/inbounds.rs) расширить `LoadedConfigSnapshot::Loaded` полем `observatory: Option<ObservatorySummary>` и accessor `observatory()`.
- В [src/app/discovery.rs](E:/prj/rust/Feldjaeger/src/app/discovery.rs) перенести summary в snapshot; в [src/app/service.rs](E:/prj/rust/Feldjaeger/src/app/service.rs) сохранить его при refresh после user mutation через `EditableXrayConfig::observatory_summary()`.

### 23.1.3	Создать app-level состояния и display model
- Добавить [src/app/observatory.rs](E:/prj/rust/Feldjaeger/src/app/observatory.rs) по шаблону DNS/FakeDNS: `ObservatoryPageState`, `ObservatoryPageModel`, `ObservatoryGeneralDisplay` и чистые builders/formatters.
- Реализовать состояния: no SSH, Xray not discovered, configuration not loaded, section missing, no subject selectors, loaded, loaded with warnings. Для отсутствующего раздела использовать `Observatory section is not configured.` и не считать его ошибкой.
- Для пустого/отсутствующего списка первичным состоянием сделать `NoSubjectSelectors`, при этом локальные warnings всё равно показывать; это не даст состоянию исчезнуть из-за обязательного warning о пустом списке.
- Форматировать отсутствующие `probeUrl`/`probeInterval` как `—`, selector count как `0`, source file через существующий basename helper. Объединять global config warnings и summary warnings только при существующем Observatory-разделе.
- Зарегистрировать модуль/re-exports в [src/app/mod.rs](E:/prj/rust/Feldjaeger/src/app/mod.rs). В `ApplicationService` добавить summary/page-model API, `observatory_status_announced`, reset при discovery и lifecycle `Loading Observatory...` → `Observatory configuration loaded.` → `Ready`.

### 23.1.4	Реализовать GUI
- Создать [src/gui/pages/observatory.rs](E:/prj/rust/Feldjaeger/src/gui/pages/observatory.rs), используя только `ApplicationService`/app display model.
- Показать:
    - блок `General`: Probe URL, Probe Interval, Subject Selector count, Source file;
    - блок `Subjects`: таблицу `# | Selector` в source order либо пояснение `No subject selectors configured.`;
    - постоянное информационное сообщение о недоступности runtime latency/availability и Tier 3 Xray API.
- Показать warnings жёлтым, не блокируя доступные значения. На Probe URL добавить `Copy Probe URL`; на selector row — `Copy Selector`; в обоих меню disabled `Edit`, `Delete`, `Duplicate` с `Not implemented yet`.
- Зарегистрировать страницу в [src/gui/pages/mod.rs](E:/prj/rust/Feldjaeger/src/gui/pages/mod.rs) и добавить `Page::Observatory` после Policy и перед Logs во все exhaustive места [src/gui/navigation.rs](E:/prj/rust/Feldjaeger/src/gui/navigation.rs).

### 23.1.5	Тесты и проверка
- В [src/xray/config/tests.rs](E:/prj/rust/Feldjaeger/src/xray/config/tests.rs) покрыть missing/empty section, one/multiple selectors, missing probe URL/interval, empty selectors, malformed selector entries, unknown-field preservation и config-directory source owner. Не опираться на `full_sample.json`: там есть только `burstObservatory`, поэтому использовать inline JSON.
- В [src/app/observatory.rs](E:/prj/rust/Feldjaeger/src/app/observatory.rs) покрыть все page states, `—`, selector count/order, warning visibility и source basename; в [src/app/service.rs](E:/prj/rust/Feldjaeger/src/app/service.rs) — loading/loaded/Ready status lifecycle.
- Обновить `LoadedConfigSnapshot::Loaded` в helper/test literals: discovery map, `poll_user_mutation`, и тестовые helpers в `inbounds`/`outbounds`/`dns`/`fakedns`/`routing`/`policy`/`users`/`service`.
- Запустить `cargo fmt --check`, `cargo check`, `cargo test --lib` и lints изменённых файлов; ожидается отсутствие новых Cargo dependencies.

## 23.2	Реализация
Read-only Observatory page is implemented per the plan. All todos are complete.

### 23.2.1	What landed
- `ObservatorySummary` — tolerant extraction of `probeUrl` / `probeInterval` / `subjectSelector`, local warnings, lossless preservation of unknown fields (e.g. `enableConcurrency`)
- Pipeline — summary through discovery → `LoadedConfigSnapshot` → mutation refresh
- App model — `src/app/observatory.rs` with states (including `NoSubjectSelectors` as primary when the list is empty, warnings still shown)
- GUI — `src/gui/pages/observatory.rs` with General grid, Subjects `# | Selector` table, Tier-3 API note, yellow warnings, Copy menus + disabled Edit/Delete/Duplicate
- Navigation — `Page::Observatory` after Policy, before Logs
- Status lifecycle — `Loading Observatory...` → `Observatory configuration loaded.` → `Ready`

### 23.2.2	Verification
- `cargo fmt --check` — clean
- `cargo check` — clean (no new deps)
- `cargo test --lib` — 225 passed

## 23.3	Реализация
Read-only Observatory page is implemented per the plan. All todos are complete.

### 23.3.1	What landed
- `ObservatorySummary` — tolerant extraction of `probeUrl` / `probeInterval` / `subjectSelector`, local warnings, lossless preservation of unknown fields (e.g. `enableConcurrency`)
- Pipeline — summary through discovery → `LoadedConfigSnapshot` → mutation refresh
- App model — `src/app/observatory.rs` with states (including `NoSubjectSelectors` as primary when the list is empty, warnings still shown)
- GUI — `src/gui/pages/observatory.rs` with General grid, Subjects `# | Selector` table, Tier-3 API note, yellow warnings, Copy menus + disabled Edit/Delete/Duplicate
- Navigation — `Page::Observatory` after Policy, before Logs
- Status lifecycle — `Loading Observatory...` → `Observatory configuration loaded.` → `Ready`

### 23.3.2	Verification
- `cargo fmt --check` — clean
- `cargo check` — clean (no new deps)
- `cargo test --lib` — 225 passed


# 24	Чтение BurstObservatory
Реализована read-only страница BurstObservatory.
1. GUI: новая страница `burst_observatory.rs`, навигация после Observatory.
2. `BurstObservatorySummary`: selectors, singular `ping_config`, source, warnings.
3. `BurstPingConfigSummary`: destination, connectivity, interval, timeout, sampling, HTTP method, summary.
4. Поддержаны официальные поля Xray; `pingConfig` — один объект по спецификации, поэтому таблица содержит 0/1 строку.
5. Данные проходят через config model → discovery → snapshot → `ApplicationService` → GUI.
6. Реализованы все состояния, выбор ping-конфигурации и подробности.
7. Некорректные и неизвестные поля дают предупреждения и сохраняются losslessly.
8. Добавлены тесты модели, состояний, форматирования, source ownership и status lifecycle.
9. Новых зависимостей нет.

Проверки:
- `cargo fmt --check` — успешно
- `cargo check` — успешно
- `cargo test --lib` — 237 тестов успешно
- IDE lints — ошибок нет
- Clippy изменённого кода — успешно
Файл плана не изменялся.


# 25	Логирование

## 25.1	План

### 25.1.1	Создать подсистему логирования и безопасный запуск
- Добавить зависимости `tracing`, `tracing-subscriber` и `tracing-appender` в [Cargo.toml](Cargo.toml), `tracing` в [feldjaeger-ssh/Cargo.toml](feldjaeger-ssh/Cargo.toml); удалить заменённые `log`/`env_logger`.
- Добавить [src/logging.rs](src/logging.rs) с:
    - вычислением пути `Feldjaeger/logs/feldjaeger.log` через platform data directory (`%LOCALAPPDATA%`, XDG data directory, `~/Library/Application Support`);
    - созданием каталога и append-only writer без ротации;
    - локальным timestamp, level, module target и message без ANSI;    
    - фильтром уровня `INFO` по умолчанию с переопределением через `RUST_LOG`;        
    - guard для гарантированного сброса неблокирующего writer;
    - каскадом отказоустойчивости: основной файл → stderr + файл у executable → stderr.
- Экспортировать модуль из [src/lib.rs](src/lib.rs), а в [src/main.rs](src/main.rs) инициализировать subscriber до GUI/ApplicationService и записать startup-событие с версией приложения и фактическим назначением журнала.

### 25.1.2	Перевести существующие события на структурированный `tracing`
- Мигрировать текущие макросы во всех существующих точках (`app`, `storage`, `remote`, `init`, `xray`, `feldjaeger-ssh`) на поля `host`, `port`, `operation`, `path`, `error_kind`, `count` вместо интерполяции строк.
- В [src/app/service.rs](src/app/service.rs) использовать границу ApplicationService для событий действий GUI: запуск/результат connection test, discovery, сохранение профиля и user mutations; GUI-страницы не получают собственной реализации логгера.
- В [feldjaeger-ssh/src/russh/client.rs](feldjaeger-ssh/src/russh/client.rs), [feldjaeger-ssh/src/russh/session.rs](feldjaeger-ssh/src/russh/session.rs) и handler логировать connect/disconnect на `INFO`, операции exec/SFTP на `DEBUG`, исправимые ситуации на `WARN`; содержимое команд, файлов, ключей и credentials не выводить.
- В [src/app/discovery.rs](src/app/discovery.rs) и [src/xray/discovery.rs](src/xray/discovery.rs) добавить start/result/error/warning события и убрать вывод stdout/stderr удалённых команд; писать только безопасные метаданные и классифицированные причины.
- В [src/storage/config_manager.rs](src/storage/config_manager.rs), конфигурационном parser/modify flow, remote backup и systemd слоях логировать успешные этапы, частичное восстановление (`WARN`) и неустранимые ошибки (`ERROR`) без JSON payload, UUID, токенов и пользовательских значений конфигурации.

### 25.1.3	Разделить пользовательские сообщения, Status Bar и диагностику
- Сохранить текущий Status Bar как независимое краткое состояние в [src/app/service.rs](src/app/service.rs) и [src/gui/status_bar.rs](src/gui/status_bar.rs); события журнала не будут менять его жизненный цикл.
- Для connection/discovery/config mutation ошибок писать технический безопасный контекст в журнал, а в моделях, которые читает [src/gui/pages/connection.rs](src/gui/pages/connection.rs), возвращать короткое понятное сообщение с указанием `See application log for details.`.
- Не реализовывать и не подключать существующую placeholder-страницу [src/gui/pages/logs.rs](src/gui/pages/logs.rs).

### 25.1.4	Закрепить защиту секретов
- Сохранить redacted `Debug` для `ConnectionSecrets` и `AuthCredentials`, централизовать очистку диагностических строк от маркеров password/passphrase/token/private-key и ограничить длину внешних error strings до передачи в журнал/UI.
- Ввести правило безопасных полей: разрешены endpoint, username, auth method, operation, validated path, byte/count/status; запрещены credentials, private-key contents, command/file payloads, Xray JSON, VLESS UUID и произвольные remote stdout/stderr.
- Проверить и исправить существующие события, которые сейчас печатают stdout/stderr discovery/systemd, поскольку эти данные не имеют гарантии отсутствия пользовательских секретов.

### 25.1.5	Добавить тесты и документацию
- В тестах [src/logging.rs](src/logging.rs) проверить platform path helper, инициализацию на явном temp path, создание `feldjaeger.log`, append/flush и наличие timestamp/level/module/message для `ERROR/WARN/INFO/DEBUG`.
- Добавить тесты redaction: password, passphrase, auth token, private-key marker/content и VLESS UUID не попадают в сформированный журнал; redacted credential types также не раскрывают значения.
- Проверить startup event через тестируемую функцию и fallback выбора destination без запуска окна; обновить ApplicationService tests для пользовательских ошибок и независимости Status Bar.
- Обновить [docs/rules.md](docs/rules.md) и при необходимости README: архитектура, выбор библиотек, пути Windows/Linux/macOS, формат, уровни и модули интеграции, fallback, безопасность и перечень тестов.
- Проверка: `cargo fmt`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, IDE diagnostics.

```mermaid
flowchart TD
  main[main.rs] --> initLog[logging::init]
  initLog --> primary[Platform data_local logs]
  initLog --> fallbackExe[stderr plus exe-dir log]
  initLog --> fallbackStderr[stderr only]
  main --> gui[gui::run]
  gui --> appSvc[ApplicationService]
  appSvc --> ssh[feldjaeger-ssh]
  appSvc --> discovery[Xray discovery]
  appSvc --> config[storage and config layer]
  appSvc --> statusBar[Status Bar snapshot]
  ssh --> tracingEvents[tracing events]
  discovery --> tracingEvents
  config --> tracingEvents
  appSvc --> tracingEvents
  tracingEvents --> logFile[feldjaeger.log]
```

## 25.2	Реализация
Реализация логирования завершена. Краткий отчёт:

### 25.2.1	Архитектура логирования
```
main.rs
→ logging::init()
→ GUI → ApplicationService → SSH / Discovery / Config / Remote / Init
↓
tracing events
↓
feldjaeger.log (+ fallback)
```

- Инициализация в `main` до GUI.
- GUI не реализует собственный логгер; события идут из ApplicationService и нижних слоёв.
- Status Bar остаётся отдельным UI-состоянием.

### 25.2.2	Библиотеки
| Crate                | Зачем                          |
| -------------------- | ------------------------------ |
| `tracing`            | структурированные события      |
| `tracing-subscriber` | фильтр (`RUST_LOG`), форматтер |
| `tracing-appender`   | неблокирующая запись в файл    |
| `chrono`             | локальный timestamp            |
Заменены `log` / `env_logger`.

### 25.2.3	Расположение логов
- Windows: `%LOCALAPPDATA%\Feldjaeger\logs\feldjaeger.log`
- Linux: `~/.local/share/feldjaeger/logs/feldjaeger.log`
- macOS: `~/Library/Application Support/Feldjaeger/logs/feldjaeger.log`
Fallback: stderr + файл рядом с exe → только stderr.

### 25.2.4	Формат
2026-01-01 12:00:00 INFO ssh Connected to server
Timestamp · Level · Module · Message

### 25.2.5	Интегрированные модули
`app` (ApplicationService, connection test, discovery, user ops), `feldjaeger-ssh`, `xray/discovery`, `storage`, `remote`, `init/systemd`.

### 25.2.6	Безопасность
- Центральный `logging::redact::sanitize_detail`
- Убраны raw stdout/stderr из discovery/systemd логов
- UI-ошибки: `Unable to connect... See application log for details.`
- Не логируются пароли, ключи, passphrase, токены, VLESS UUID, JSON config

### 25.2.7	Тесты
Пути, формат, уровни, создание файла, redaction, AuthCredentials Debug, fallback destination. Документация: `docs/rules.md`, `README.md`.
Проверки: `cargo fmt`, `cargo test --workspace` (265 тестов), `cargo clippy --workspace --all-targets -- -D warnings` — успешно.


# 26	Управление сервисом

## 26.1	План

### 26.1.1	Контекст
Значительная часть фундамента уже существует и будет использована повторно, а не скопирована:
- [src/init/manager.rs](src/init/manager.rs) — Трейт `InitSystemManager` с `service_state`, `start_service`, `stop_service`, `restart_service`; `ServiceState { Running, Stopped, Unknown }`.
- [src/init/systemd.rs](src/init/systemd.rs) — `SystemdManager` выполняет `systemctl` через `SshSession::exec` с проверенными аргументами (без оболочки), а также тестовый стенд `MockSession`.
- [src/init/service_name.rs](src/init/service_name.rs) — Проверка `ServiceName` (уже отклоняет внедрение).
- [src/xray/discovery.rs](src/xray/discovery.rs) / [src/xray/installation.rs](src/xray/installation.rs) — обнаружение выдает `XrayInstallation { init_system: InitSystemKind, service_name: Option<String>, service_state, ... }`. Имя юнита берется из `systemd_probe.rs` (обрабатывает `xray.service`, `xray@*.service`), никогда не задается жестко в коде.
- [src/app/service.rs](src/app/service.rs) — установленный асинхронный шаблон: `start_*()` запускает поток + среду выполнения Tokio текущего потока, результат возвращается через канал `mpsc`, опрашивается в `tick_status()`.
- [src/gui/pages/service.rs](src/gui/pages/service.rs) — в настоящее время это страница-заглушка, уже находящаяся в навигации.
- API строки состояния: `set_current_operation`, `show_status_message` ([src/app/status.rs](src/app/status.rs)); логирование с маскировкой ([src/logging/redact.rs](src/logging/redact.rs)).

### 26.1.2	Поток данных
```mermaid
flowchart TD
    ServicePage[GUI Service page] --> AppService[ApplicationService start_service_operation / poll]
    AppService --> Worker[Worker thread plus tokio runtime]
    Worker --> Workflow[app/service_control.rs run_service_operation]
    Workflow --> InitMgr[SystemdManager via InitSystemManager trait]
    InitMgr --> SshLayer[feldjaeger-ssh SshSession exec]
    SshLayer --> Systemctl[systemctl action unit]
```

### 26.1.3	Изменения

### 26.1.4	Расширение начального слоя (`src/init/`)
- `ServiceState`: добавить варианты `Failed` и `Inactive` (метки `failed`, `inactive`). Обновить `parse_service_state` в `systemd.rs`: `active/activating/reloading -> Running`, `deactivating -> Stopped`, `inactive -> Inactive`, `failed -> Failed`, в противном случае использовать код завершения / `Unknown`. Обновить единственное место, где `ServiceState` сопоставляется с `XrayStatus`/discovery display.
- Трейт `InitSystemManager`: добавить `reload_service`, `enable_service`, `disable_service` (те же сигнатуры, что и у существующих методов жизненного цикла).
- `SystemdManager`: реализовать их через существующий `run_lifecycle_action` с действиями `reload`, `enable`, `disable`.
- Ввести типизированный тип ошибки, чтобы сбои можно было различать (в настоящее время все сводится к строковым сообщениям `AppError`). Добавить перечисление `ServiceOperationErrorKind` в слой инициализации (или `src/app`): `SshConnectionFailed`, `PermissionDenied`, `ServiceNotFound`, `CommandFailed`, `UnsupportedInitSystem`, `StateUnknown`. В `systemd.rs` классифицировать сбои `systemctl` по коду завершения + stderr (например, stderr, содержащий `Access denied` / `Permission denied` / `Interactive authentication required` -> PermissionDenied; `not found` / `could not be found` / exit 5 on status -> ServiceNotFound), сохраняя очищенную строку с подробной информацией вместе с типом ошибки.

### 26.1.5	Новый рабочий процесс на уровне приложений.: `src/app/service_control.rs`
Зеркала [src/app/discovery.rs](src/app/discovery.rs):
- `ServiceOperation` enum: `Start, Stop, Restart, Reload, Enable, Disable` with labels for status bar ("Starting Xray...", "Stopping Xray...", "Restarting Xray...", "Reloading Xray...", "Enabling Xray service...", "Disabling Xray service...").
- `run_service_operation(backend, profile, secrets, init, service_name, operation) -> ServiceOperationOutcome`:
    1. Подключение осуществляется через SSH-бэкэнд (с использованием сохраненного профиля и секретов в оперативной памяти, как при обнаружении).
    2. Выполните операцию через `InitSystemManager`.
    3. После этого всегда повторно запрашивайте `service_state` (успех не означает запуск).
    4. Отключиться; вернуть результат `{ result: Result<(), (kind, safe_detail)>, refreshed_state: Option<ServiceState> }`.
- Перед запуском `ApplicationService` применяются следующие ограничения: обнаружение должно пройти успешно, `init_system == Systemd` (в противном случае — отказ, графический интерфейс покажет «Не пытаться управлять службой»), `service_name` должен присутствовать (в противном случае — `ServiceNotFound`), и имя должно быть повторно проверено с помощью `ServiceName::new`. Имя службы всегда берется из `XrayInstallation.service_name`; никогда не из пользовательского ввода, никогда не задается жестко.

### 26.1.6	Связывание `ApplicationService` ([src/app/service.rs](src/app/service.rs))
- Новые поля: `service_control: ServiceControlState` (Idle / Busy(operation) / last error), `service_control_rx: Option<Receiver<ServiceOperationOutcome>>`, а также текущее известное `ServiceState`.
- `service_page_model()` — модель только для чтения для графического интерфейса пользователя: имя службы, метка инициализации системы, текущее состояние, разрешено ли управление, выполняется ли операция.
- `start_service_operation(op: ServiceOperation) -> Result<(), String>` — проверяет условия, устанавливает сообщение об операции в строке состояния, запускает рабочий процесс (та же схема потока и среды выполнения, что и `start_discovery`).
- Функция `poll_service_operation()` вызывается из `tick_status()`: при успешном выполнении отображается сообщение «Xray service updated.» (временно, затем возвращается в состояние «Ready»), обновляется сохраненное `ServiceState`, синхронизируется `XrayStatus` для строки состояния; при сбое отображается отдельное, безопасное сообщение для каждого типа ошибки и регистрируется через `tracing` (`target: "init"` / `"app"`, очищенные данные; INFO при запуске/успехе, например, "Starting Xray service xray.service" / Xray service restarted successfully", ERROR, например, "Failed to restart Xray service"). В логах отсутствуют учетные данные/ключи/секреты (закрытие уже обработано функцией `sanitize_detail`).
- Добавьте необходимые варианты `CurrentOperation` (или повторно используйте `Message`) в файле [src/app/status.rs](src/app/status.rs) для шести текстов, отображающих текущую операцию.

### 26.1.7	Страница графического интерфейса пользователя (GUI) ([src/gui/pages/service.rs](src/gui/pages/service.rs))
Замените заполнитель, следуя шаблонам страницы "Connection/Users":
- Если обнаружение не удалось: поясняющее пустое состояние («Сначала выполните обнаружение на странице подключения»).
- Если система инициализации не systemd: отобразить систему инициализации и текст "Do not attempt service management."; кнопки действий не отображаются.
- Если сервисный блок не найден: отобразить это состояние; никаких действий не требуется.
- В противном случае — сетка:
    - `Service: xray.service` (со страницы Discovery)
    - `Init: systemd`
    - `State: running / stopped / failed / inactive / unknown` (цветовая кодировка согласно docs/ui.md: зеленый/серый/красный)
- Кнопки: Start, Stop, Restart, Reload, Enable, Disable; отключены во время выполнения операции.
- Подтверждение через модальное окно `egui::Window` (тот же шаблон, что и в диалоговом окне удаления пользователя в [src/gui/pages/users.rs](src/gui/pages/users.rs)) для остановки ("Stop Xray?"), перезапуска ("Restart Xray?"), отключения ("Disable Xray startup?"). Запуск и перезагрузка выполняются без подтверждения.
- Страница только вызывает методы `ApplicationService` и отображает модель — без SSH, без systemctl, без анализа выходных данных в графическом интерфейсе.

### 26.1.8	Тесты
Следуя существующим шаблонам (test-local `MockSession`/`MockBackend`, `#[tokio::test]`):
- `src/init/systemd.rs`: перезагрузка/включение/отключение корректных аргументов `systemctl`; разбор состояния для `failed` -> `Failed`, `inactive` -> `Inactive`; stderr с сообщением об ошибке "отказано в доступе" классифицирован как `PermissionDenied`; "не найдено" классифицировано как `ServiceNotFound`; существующие тесты запуска/остановки/перезапуска/небезопасного имени сохранены.
- `src/app/service_control.rs`: полный рабочий процесс с имитацией бэкенда — при успешном выполнении состояние обновляется; при сбое SSH-подключения -> `SshConnectionFailed`; состояние обновляется даже после успешного выполнения действия, но служба не запущена; отклонена неподдерживаемая система инициализации; отклонено отсутствующее имя службы.
- Тесты на странице Discovery уже охватывают обнаружение systemd; add/verify тесты для пути предупреждения unsupported-init, если он отсутствует.

### 26.1.9	Выход за рамки темы / примечания
- Новых зависимостей не ожидается — всё использует существующие `feldjaeger-ssh`, `tokio`, `egui`, `tracing`.
- Create/Edit unit: при отсутствии права записи в `/etc/systemd/system` GUI запрашивает пароль sudo; пароль передаётся только через `sudo -S` на stdin (`exec_with_stdin`), никогда не попадает в argv и логи.
- Реализована только система systemd; трейт `InitSystemManager` оставляет возможность для использования других систем инициализации. Unit Create/Edit — systemd-only (`src/init/unit.rs`), не на трейте.

## 26.2	Реализация
Реализовано удалённое управление сервисом Xray через SSH для systemd. Все 271 теста и clippy проходят.

### 26.2.1	Архитектура ServiceManager
Управление идёт через существующий слой `InitSystemManager` / `SystemdManager`, плюс app-workflow:

```
GUI (Service page)
→ ApplicationService::start_service_operation
→ worker thread + Tokio
→ run_service_operation (app/service_control.rs)
→ SystemdManager (InitSystemManager)
→ SshSession::exec(RemoteCommand)
→ systemctl <action> <unit>
```

Новые типы: `ServiceControlError`, `ServiceOperationErrorKind`, `ServiceOperation`, `ServiceControlState`, `ServicePageModel`.

### 26.2.2	Поддерживаемые системы инициализации
Только systemd. Для OpenRC / runit / unknown GUI показывает:
`Do not attempt service management.`
и кнопки не активны.

### 26.2.3	Поток данных GUI → systemctl
1. Discovery сохраняет `service_name` и `init_system` в `XrayInstallation`.
2. Service page читает `service_page_model()`.
3. Кнопка вызывает `start_service_operation(op)` — имя юнита берётся только из discovery.
4. Worker: connect → systemctl action → `is-active` → disconnect.
5. `poll_service_operation` обновляет state / Status Bar / логи.

### 26.2.4	Поддерживаемые операции
|Операция|Confirm|
|---|---|
|Start|нет|
|Stop|Stop Xray?|
|Restart|Restart Xray?|
|Reload|нет|
|Enable|нет|
|Disable|Disable Xray startup?|
После каждой операции состояние перечитывается (`running` / `stopped` / `failed` / `inactive` / `unknown`).

### 26.2.5	Ограничения безопасности
- GUI не строит и не выполняет SSH/systemctl-команды.
- Имя сервиса не из пользовательского ввода; валидация через `ServiceName`.
- Команды — `RemoteCommand` с отдельными аргументами (без shell).
- Логи: без паролей, ключей, секретов (`sanitize_detail`).

### 26.2.6	Обработка ошибок
Отдельные виды: `SSH connection failed`, `Permission denied`, `Service not found`, `systemctl command failed`, `Unsupported init system`, `Service state unknown`.

### 26.2.7	Добавленные тесты
- systemd: start/stop/reload/enable/disable, parse `failed`/`inactive`, permission denied, not found, unsafe name
- workflow: success + refresh, SSH fail, permission, not found
- page model: unsupported init, systemd allowed, discovery required
- confirmation prompts

### 26.2.8	Новые зависимости
Нет. Используются уже существующие `feldjaeger-ssh`, `tokio`, `egui`, `tracing`.

### 26.2.9	Ключевые файлы
- [`src/init/error.rs`](src/init/error.rs) — typed errors (`ServiceControlError`, `UnitFileError`)
- [`src/init/manager.rs`](src/init/manager.rs) / [`systemd.rs`](src/init/systemd.rs) — lifecycle
- [`src/init/unit.rs`](src/init/unit.rs) — Create/Edit unit (render, preflight, install, sudo -S)
- [`src/app/service_control.rs`](src/app/service_control.rs) — lifecycle + unit Apply workflow
- [`src/app/service.rs`](src/app/service.rs) — wiring + polling
- [`src/gui/pages/service.rs`](src/gui/pages/service.rs) — UI

## 26.3	Create / Edit unit (реализовано)

Guided authoring of `/etc/systemd/system/{ServiceName}.service` (Lean Approach B).

### 26.3.1	Формат unit
Совпадает с официальным `install-release.sh` (не DynamicUser):
- `User=nobody` (или `root` — caps закомментированы)
- `CapabilityBoundingSet` / `AmbientCapabilities` / `NoNewPrivileges`
- `ExecStart=… run -config …` или `-confdir …`
- `Restart=on-failure`, `LimitNPROC=10000`, `WantedBy=multi-user.target`
- Один полный файл (без `.service.d` в v1)

### 26.3.2	Create vs Edit
Авторитетный gate — наличие файла в `/etc/systemd/system/{name}` (probe). Create / override, если файла нет (в т.ч. маскирует vendor unit из `/lib`). Edit — если файл есть. Имена с `@` — Create/Edit запрещены. Lifecycle по-прежнему требует discovered `service_name`.

### 26.3.3	Apply
Prefight mode bits (o+r / o+x) → backup → atomic write (или `sudo -S -- install`) → `daemon-reload` → restore при сбое. Опционально Enable+Start. Если сервис был Running — GUI предлагает Restart (default No).

### 26.3.4	Слои
GUI → ApplicationService → `install_or_replace_unit` / probes → SSH. Не на `InitSystemManager`.


# 27	Управление установкой

## 27.1	План

### 27.1.1	Область применения
Операции жизненного цикла бинарника Xray: Install, Update, Remove, плюс Check versions.
Каналы установки (session-only, не в `AppConfig`):
- Stable — официальный `install-release.sh install` (без `--beta`); probe через GitHub `releases/latest`.
- Beta — официальный `install --beta` (`PRE_RELEASE_LATEST` в скрипте); probe зеркалит алгоритм скрипта (не флаг GitHub `prerelease`).

В v1 нет `--version` pin и нет `--force` (downgrade / принудительный reinstall — вне scope).
«Available versions» получаются удалённым `curl` к GitHub API по SSH (локальной HTTP-зависимости нет).

### 27.1.2	Повторное использование исходных данных
- [feldjaeger-ssh/src/command.rs](feldjaeger-ssh/src/command.rs) — `RemoteCommand` (программа + явные аргументы, без строк оболочки).
- [src/remote/backup_manager.rs](src/remote/backup_manager.rs) — `BackupManager::create_backup` (SFTP-копия); сбой → `BackupFailed`.
- [src/xray/discovery.rs](src/xray/discovery.rs) — `XrayInstallation` как источник путей, текущей версии и init system.
- [src/app/service_control.rs](src/app/service_control.rs) — схема worker/channel/outcome.
- [src/init/](src/init/) — `SystemdManager` для проверки состояния после install/update.
- [src/logging/redact.rs](src/logging/redact.rs) — `sanitize_detail`, `user_message_see_log`.

### 27.1.3	Поток данных
```mermaid
flowchart TD
    MgmtPage[GUI Xray Management] --> AppService[ApplicationService]
    AppService --> LifecycleWorker[run_xray_lifecycle plus channel]
    AppService --> VersionWorker[run_version_check]
    LifecycleWorker --> Installer[XrayInstaller install update remove]
    VersionWorker --> Probe[available_versions dual probe]
    Installer --> SshLayer[feldjaeger-ssh RemoteCommand]
    Probe --> SshLayer
    SshLayer --> RemoteHost[curl bash install-release.sh uname systemctl]
    LifecycleWorker -->|on success| Rediscover[start_discovery]
```

### 27.1.4	Официальный механизм без shell composition
Вместо `bash -c "$(curl -L URL)" @ install` установщик выполняет discrete `RemoteCommand`:
1. `curl -L -f -o /tmp/feldjaeger-xray-install-<uuid>.sh …/install-release.sh` → иначе `DownloadFailed`.
2. SFTP read: непустой файл + shebang `#!` → иначе `VerificationFailed`.
3. `bash <script> install` | `bash <script> install --beta` | `bash <script> remove`.
4. Удаление temp-скрипта (best effort).

Имя temp-файла — UUID v4 (не wall-clock), чтобы исключить предсказуемые `/tmp` races.
URL, путь и argv — внутренние константы, не user input.

## 27.2	Изменения

### 27.2.1	`src/xray/installer.rs` — `XrayInstaller`
- `InstallerErrorKind`: `SshConnectionFailed`, `DownloadFailed`, `VerificationFailed`, `PermissionDenied`, `ServiceCreationFailed`, `ServiceStartFailed`, `BackupFailed`, `AlreadyInstalled`, `UnsupportedSystem`, `CommandFailed`.
- `InstallChannel { Stable, Beta }`.
- `AvailableVersions { stable, beta, stable_error, beta_error }` — partial success по каналам.
- Guards: только systemd; install отказывается при уже установленном (`AlreadyInstalled`).
- `install(session, init, already_installed, channel)` / `update(session, installation, channel)` — argv из канала; после скрипта `SystemdManager::service_state` → Running.
- `remove(session, installation)` — канал игнорируется; config не удаляется.
- `available_versions(session)` — всегда оба канала, последовательно на одной SSH-сессии:
  1. Stable: `GET …/releases/latest` → `tag_name` (без ведущего `v`).
  2. `uname -m` → map в script `MACHINE` (полная таблица install-release.sh + side-checks: Features/vfp для armv6/7, `lscpu` Little Endian для mips64). Неизвестная arch → `beta: None` + `beta_error`.
  3. Beta: `GET …/releases` (первая страница) → первый `tag_name`, для которого в JSON есть URL  
     `https://github.com/XTLS/Xray-core/releases/download/v{tag}/Xray-linux-{MACHINE}.zip`  
     (как `PRE_RELEASE_LATEST` в скрипте; это не фильтр `prerelease==true`).
- `version_gt(candidate, current)` — pure Rust, numeric segments ≈ `sort -V` для Xray-тегов; без crate `semver` и без remote `sort -V`.
- Unit path: `systemctl show -p FragmentPath` из discovery, не hardcode.

### 27.2.2	Резервные копии
`BackupManager` (SFTP):
- Update: binary, unit (FragmentPath), каждый `config_files`.
- Remove: unit + config files.
- Любой сбой backup → `BackupFailed`, скрипт не запускается.

### 27.2.3	`src/app/xray_management.rs`
- `XrayLifecycleOperation { Install, Update, Remove }`.
- Confirms с каналом и `{to}`:
  - Install Stable: `Install Xray (stable) version {to}?`
  - Install Beta: `Install Xray (beta) version {to}? Warning: pre-release may be unstable.`
  - Update Stable/Beta — аналогично с `{from}` → `{to}`.
  - Remove: config preserved (без канала).
- `run_xray_lifecycle(..., channel)` / `run_version_check` → `VersionCheckOutcome { result: Result<AvailableVersions, InstallerError> }` (SSH fail до probe → Err; иначе Ok с per-channel errors).
- `XrayManagementPageModel`: dual tags, `channel`, `channel_hint`, gating:
  - Install/Update требуют успешный tag выбранного канала.
  - Update дополнительно: `version_gt(target, current)`; иначе hint «Already on latest/newer for this channel.»
  - Beta без кандидата: «No install candidate from GitHub releases list.»
  - Stable без check / с ошибкой: hint про Check versions / retry.
  - Downgrade / `--force` — не в v1 (скрипт без force при не-newer делает no-op `exit 0`).

### 27.2.4	`ApplicationService` ([src/app/service.rs](src/app/service.rs))
- Session fields: `install_channel: InstallChannel`, `available_versions: AvailableVersions`, lifecycle + version-check receivers/busy.
- `set_install_channel` / `install_channel()` — preference только на сессию (сброс при disconnect).
- `start_xray_lifecycle(op)` передаёт текущий channel в worker.
- `poll_version_check`: merge partial success — при ошибке канала сохраняется last-known tag; успешный beta без кандидата очищает stale beta.
- После успешного lifecycle → `start_discovery()`.

### 27.2.5	GUI ([src/gui/pages/xray_management.rs](src/gui/pages/xray_management.rs))
- Радио Stable | Beta; для Beta — предупреждение про официальный `install --beta` (newest listed release with matching host download; may be pre-release).
- Сетка: status, installed version, Available (stable) и Available (beta), paths, init.
- Кнопка Check versions; per-channel error lines при необходимости.
- Install / Update / Remove + confirm dialogs; enablement из page model.
- GUI не делает SSH, download, path management, parse output.

### 27.2.6	Тесты
- installer: sequence curl→verify→bash; `--beta` argv; dual `available_versions` + partial fail; `parse_beta_tag` + MACHINE zip; `version_gt`; MACHINE map; backups; remove preserves config.
- app: page-model gating (installed / not installed / empty beta / not-newer / discovery required); confirm templates.

### 27.2.7	Примечания / ограничения
- Нет новых crate-зависимостей: remote `curl`/`bash`/`uname`; JSON через существующий `serde_json`.
- Root: официальный скрипт требует root; иначе `PermissionDenied` (без sudo).
- Lifecycle бинарника отделён от config editing (docs/rules.md).
- Скриптовый Update без `--force` ставит только если target новее current (`version_gt`); Feldjaeger зеркалит это в enablement кнопки.

### 27.2.8	Manual acceptance oracle (Beta)
На тестовом VPS тем же discrete flow, что Feldjaeger:
1. `curl -L -f -o /tmp/fj-xray-install.sh https://github.com/XTLS/Xray-install/raw/main/install-release.sh`
2. Проверка shebang / что это официальный installer
3. `bash /tmp/fj-xray-install.sh install --beta`

Установленный tag должен совпасть с beta-probe Feldjaeger («Check versions» → Available (beta)) на том же хосте.

## 27.3	Реализация
Реализовано: Stable/Beta channels, dual probe, `version_gt` gating, GUI radio, session-only channel, тесты (см. §27.2 / §27.11).

## 27.4	Архитектура XrayInstaller
GUI (Xray Management)
→ ApplicationService (`install_channel`, `available_versions`)
→ app/xray_management.rs (workers)
→ xray/installer.rs (`XrayInstaller`)
→ feldjaeger-ssh (`RemoteCommand`)
→ curl / bash install-release.sh / uname / systemctl

`XrayInstaller` скачивает официальный `install-release.sh` discrete-командами (без `bash -c "$(curl …)"`), проверяет shebang, запускает `bash <script> install|install --beta|remove`, проверяет сервис через `SystemdManager`. Check versions — dual GitHub probe + MACHINE map.

## 27.5	Workflow установки
1. Guards: systemd; Xray ещё не установлен; выбранный канал имеет успешный tag (после Check versions).
2. Confirm с каналом + `{to}`.
3. Download + verify official script.
4. `bash <script> install` или `install --beta`.
5. `systemctl is-active` → Running.
6. Cleanup temp script; rediscovery.

## 27.6	Workflow обновления
1. Guards: установлен; tag канала есть; `version_gt(target, current)`.
2. Backup: binary, unit, configs.
3. Тот же официальный `install` / `install --beta` (in-place).
4. Verify service; rediscovery.
   Config / routing / DNS / inbounds не трогаются.
   Если скрипт всё же сделает no-op (`exit 0`, «No new version») — soft success + Status Bar (edge case; UI обычно не даёт нажать Update).

## 27.7	Workflow удаления
1. Backup unit + configs.
2. `bash <script> remove` (официально сохраняет json и logs).
3. Config-пути никогда не удаляются приложением.
4. Rediscovery. Канал на Remove не влияет.

## 27.8	Workflow Check versions
1. Connect SSH.
2. Stable curl `/releases/latest` → parse `tag_name`.
3. `uname -m` (+ side-checks) → `MACHINE`.
4. Beta curl `/releases` → first tag with matching `Xray-linux-{MACHINE}.zip` URL in JSON.
5. Disconnect; merge в session `available_versions` (partial success).

## 27.9	Стратегия backup
`BackupManager` (SFTP, суффикс `.feldjaeger.bak`). Сбой → `BackupFailed`, операция до скрипта отменяется.

## 27.10	Ограничения безопасности
- GUI не выполняет shell, не качает файлы, не парсит вывод
- URL/аргументы — внутренние константы
- `RemoteCommand` без shell-интерполяции
- Имя юнита из discovery + `ServiceName` validation
- Логи без credentials / keys / tokens (`sanitize_detail`)

## 27.11	Поддерживаемые платформы
- OS: Linux
- Init: systemd only
- Способ: официальный Xray-install script (Stable + `--beta`)
- Arch: полная MACHINE-таблица скрипта (x86_64, aarch64, arm*, mips*, ppc*, riscv64, s390x, …)
- Нет: package managers, Docker, Windows, custom builds, config generation, `--version` / `--force`

## 27.12	Добавленные тесты
- Already installed / unsupported init
- Download / verification / service start / permission failures
- Install/Update с `InstallChannel::Beta` → argv содержит `--beta`
- Dual `available_versions` + partial beta fail
- `parse_beta_tag` (first matching zip) / empty list
- `version_gt` numeric segments
- MACHINE map (common arches + unsupported)
- Update backups + abort on backup fail
- Remove preserves config
- Page model: gating install/update/remove, empty beta, not-newer, discovery required
- Confirm templates per channel

## 27.13	Новые зависимости
Нет. Используются существующие `serde_json`, `feldjaeger-ssh`, `tokio`, `egui`, `tracing`, `uuid` (temp script name). Available tags — remote `curl` к GitHub API.

## 27.14	Ключевые файлы
- [`src/xray/installer.rs`](src/xray/installer.rs) — channels, dual probe, MACHINE, `version_gt`, script argv
- [`src/app/xray_management.rs`](src/app/xray_management.rs) — page model, gating, confirms, workers
- [`src/app/service.rs`](src/app/service.rs) — session channel + dual tags + poll/merge
- [`src/gui/pages/xray_management.rs`](src/gui/pages/xray_management.rs) — radio Stable/Beta, UI


# 28	Обновление GeoData

## 28.1	Архитектура GeoDataManager
`src/xray/geodata.rs` → `GeoDataManager`  
Поток: GUI → `ApplicationService` → `GeoDataManager` → SSH (`RemoteCommand` / SFTP) → remote.  
GUI не трогает shell, download, remote files.

## 28.2	Базы
Только `geoip.dat`, `geosite.dat`.

## 28.3	Discovery
Resolve asset dir: systemd `XRAY_LOCATION_ASSET` / `xray.location.asset` → каталог с уже лежащими `.dat` → parent бинаря → `/usr/local/share/xray`.  
Probe каждого файла: `test -f`, size, mtime. Missing = `Not installed` + WARN, не fatal.  
Модель: `GeoDataSummary` / `GeoDataDatabaseSummary`.

## 28.4	Update workflow
Refresh / Update через `start_geodata_refresh` / `start_geodata_update`.  
Download (hardcoded URL) → verify size>0 → backup `.feldjaeger.prev` (fail = abort) → `write_file_atomic` → re-discover.  
Xray не restart. UI: «Restart Xray recommended…».

## 28.5	Backup
Перед replace: `name.feldjaeger.prev`. Одна предыдущая версия. Backup fail → весь update отменяется. Partial fail → rollback из `.prev`.

## 28.6	Security
URL только официальный источник Xray-core CI (Loyalsoldier `v2ray-rules-dat`).  
Нет user URL. Нет shell из GUI. Лог без credentials/keys.

## 28.7	GUI states
Страница GeoData в sidebar.  
Таблица: Database / Status / Version / Modified / Size.  
Кнопки: Refresh information, Update GeoData.  
Состояния: SSH failed, Download failed, Verification failed, Permission denied, Backup failed, Database missing, Unsupported installation.  
Status Bar: `Updating GeoData...` → `GeoData updated successfully.` → `Ready`.

## 28.8	Тесты
~18 в `xray::geodata` (neither/only-geoip/only-geosite/both, update, backup fail, verify fail, permission, SSH, refresh).
- page model / service guards (`geodata_requires_*`, `geodata_blocked_while_busy`).

## 28.9	Новые зависимости
Нет. `uuid` / `chrono` уже в проекте.
Файлы: `src/xray/geodata.rs`, `src/app/geodata.rs`, `src/gui/pages/geodata.rs` + wiring в `service` / `navigation` / `status` / `mod`.


# 29	Доступ с access log

## 29.1	Архитектура `XrayLogService`
`GUI → ApplicationService → XrayLogService → SSH (tail / journalctl)`  
Код: `src/xray/logs/`, оркестрация: `src/app/xray_logs.rs`. Логика не в ServiceManager / Discovery / GUI.

## 29.2	Источники
- Access Log (`log.access`)
- Error Log (`log.error`)
- System Journal (unit из Discovery)

## 29.3	Обнаружение
Из загруженного `log` (официальная семантика Xray): путь / `none` / пусто→stdout / `stderr` / неизвестное.  
`loglevel: none` гасит оба потока. Journal — только systemd + `service_name` Discovery. Пути `/var/log/xray/*` не зашиты.

## 29.4	Чтение файлов
`tail -n N -- path` через `RemoteCommand` (argv, quoting). Сначала `test -e/-f/-r`. Целый файл не тянем.

## 29.5	Journal
`journalctl -u <Discovery unit> -n N --no-pager -o short-iso --show-cursor`. Не эквивалент access/error.

## 29.6	Follow
Один SSH-сеанс, poll ~750 ms: файл по byte offset (`stat` + `tail -c +N`), journal по cursor. Смена источника / SSH disconnect / уход со страницы / stop — сессия гаснет. Generation отсекает stale.

## 29.7	GUI-состояния
No SSH / Xray not discovered / Source unavailable|disabled / Loading / Loaded / Empty log / Following / Follow interrupted / Error. Privacy notice на странице.

## 29.8	Параллелизм
Worker-thread + Tokio current-thread, `mpsc` события, busy-флаги, generation reject. GUI не блокируется; follow держит repaint.

## 29.9	Безопасность / privacy
Только read. Пути и unit только из config/Discovery. Нет shell от пользователя, chmod/chown/truncate/delete. Тела Xray-логов не пишутся в app logs.

## 29.10	Тесты
28 unit-тестов (моки SSH): destination, disabled/stdout, missing/perm, journal unit, limits, empty, unknown line, stale reject, search, no IP в app error detail.

## 29.11	Документация
`docs/rules.md`, `docs/ui.md` — разделение Application vs Xray logs, источники, limits, privacy, deferred.

## 29.12	Зависимости
Новых crate нет. Follow через poll существующего `exec`, не streaming API.

Страница sidebar: Xray Logs. Refresh / Follow / локальный search / Copy.


# 30	Настройки журнала Xray (Log Settings)

## 30.1	Архитектура
`GUI (Log Settings) → ApplicationService → LogSettings / update_log_settings → Backup → Validation → Remote write`  
Код: `src/xray/config/log_settings.rs`, `modify.rs` (`UpdateLogSettingsRequest`), оркестрация `src/app/log_settings_ops.rs`, страница `src/gui/pages/log_settings.rs`.  
GUI не разбирает raw JSON, не пишет файлы и не вызывает SSH напрямую. Используется общий pipeline изменения конфигурации (как Users), без отдельного write-path только для логов.

## 30.2	Поддерживаемые поля Xray
Только объект верхнего уровня `log` по официальной спецификации LogObject:
- `access`, `error` — stdout (пусто/отсутствует), файл (абсолютный путь), `none`
- `loglevel` — `debug` | `info` | `warning` | `error` | `none` (по умолчанию `warning`; управляет только error log)
- `dnsLog` — bool
- `maskAddress` — пусто / `quarter` / `half` / `full` / custom `/v4+/v6`
Неизвестные ключи внутри `log` сохраняются. Редактор не считает, что `loglevel: none` отключает access (в отличие от viewer D021).

## 30.3	Внутренняя модель
`LogSettings { access: LogOutput, error: LogOutput, log_level: LogLevel, dns_log, mask_address: MaskAddress, … }`  
Варианты `Unknown(String)` для неподдерживаемых существующих значений. При отсутствии объекта `log` показываются defaults; объект создаётся только при Save.

## 30.4	Сохранение неизвестных полей
`apply_log_settings_to_value` обновляет только известные ключи на существующем JSON-объекте. Confdir: переписывается только файл-владелец секции `log`.

## 30.5	Проверка
Пути File: не пустые, без NUL/newline, абсолютные Linux (`/…`). Custom mask: `/N+/M`, N∈0..=32 и кратно 8, M∈0..=128. Unknown mask сохраняется, пока пользователь явно не сменит режим. Без remote chmod/mkdir/touch.

## 30.6	Save / backup
Validate draft → mutate model → change summary → conflict check (семантическое сравнение JSON) → `write_config_safe` (backup + atomic write) → refresh snapshot. Автоперезапуск Xray не выполняется; UI показывает требование restart/reload.

## 30.7	Взаимодействие с D021 (Xray Logs)
После успешного Save: `seed_xray_log_sources()`, сброс probe/entries/generation, stop follow. Устаревшие пути не остаются в кэше источников.

## 30.8	Безопасность и privacy
Предупреждения: access/DNS могут раскрывать адреса и домены; отключение mask — полные IP. Допустимые настройки не блокируются. App logs: start/updated/validation failed без тел Xray-логов и секретов.

## 30.9	Тесты
Unit: missing log, defaults, access/error modes, levels, dnsLog, masks, custom/invalid mask, unknown preservation, paths, change summary, confdir ownership, backup fail, remote conflict, log-source refresh. Моки SSH, без реального Xray.

## 30.10	Документация
Этот раздел; `docs/rules.md` (разделение тел логов vs редактирование `log`); `docs/ui.md` (страница Log Settings).

## 30.11	Зависимости
Новых crate нет.

## 30.12	Вне области
Ротация, journald/syslog, права на файлы, mkdir, truncate/delete, scheduled cleanup, auto-restart, auto-diagnostics, настройки логов приложения Feldjäger.


# 31	Cloudflare WARP (Xray WireGuard outbound)

## 31.1	Что значит Cloudflare WARP в Feldjäger
В этом этапе Cloudflare WARP — соединение Cloudflare WARP, используемое через встроенный в Xray исходящий WireGuard outbound.  
Это не:
- управление организацией Cloudflare Zero Trust;
- установка настольного Cloudflare One Client;
- общесистемный туннель WARP на Linux;
- произвольное управление пирами WireGuard.

В GUI имя: Cloudflare WARP. Базовый объект конфигурации Xray: WireGuard outbound.

Creating a WARP outbound does not route traffic through it automatically.

## 31.2	Архитектура
```
GUI (Cloudflare WARP)
  → ApplicationService (src/app/warp.rs, warp_ops.rs)
    → WarpManager
      ├── WarpHelperManager      (wgcf-cli install/verify/remove)
      ├── WarpRegistrationService (register + backup/restore)
      ├── WarpConfigurationService (generate --xray, ownership.json)
      └── WarpConnectivityService (outbound-scoped probe; сейчас unavailable)
    → config-modify pipeline (add/replace/remove outbound)
    → SSH layer
    → remote Linux host
```

Код домена: `src/xray/warp/`. GUI не собирает shell-команды, не вызывает SSH и не вставляет ключи в JSON.

## 31.3	Вспомогательный модуль (wgcf-cli)
- Утверждённый helper: wgcf-cli (pinned release, сейчас `v0.3.6`).
- Установка только в managed path: `/usr/local/lib/feldjaeger/tools/wgcf-cli`.
- Перед запуском: имя, ELF magic, архитектура, checksum (`.dgst`), `version`.
- Не берём произвольный `wgcf`/`wgcf-cli` из `PATH`.
- Удаление helper — отдельное действие; не трогает system WireGuard / Cloudflare One / чужие установки.

## 31.4	Хранение учётных данных и ownership
- Регистрация: `/usr/local/lib/feldjaeger/warp/wgcf.json` (dir `700`, file `600`).
- Сгенерированный outbound: `wgcf.xray.json` (парсится во внутреннюю модель, не вставляется как opaque JSON).
- Ownership marker (не секрет): `ownership.json` — `outbound_tag`, `managed`, optional `helper_version`.
- Метаданные владения не внедряются в удалённый `config.json` Xray.
- Секреты: `SecretString` (`src/xray/secret.rs`, общий с inbound clients), redaction в Debug/логах; private key никогда не показывается в GUI.

## 31.5	Владение outbound
Классификация: Managed / External / Possible WARP / Invalid / Unknown.  
Теги вроде `warp` / `cloudflare` — подсказки, не доказательство.  
Внешний WireGuard не становится managed только из‑за endpoint Cloudflare.  
Adoption — только после явного подтверждения; credentials не перегенерируются.

## 31.6	Изменение конфигурации
`add_outbound` / `replace_outbound` / `remove_outbound` в `src/xray/config/modify.rs` через общий backup → conflict check → atomic write.  
Маршрутизация, DNS, inbounds не меняются автоматически.  
После add: сообщение «WARP outbound was added successfully. No routing rules were changed.»  
Restart Xray — только с подтверждением через ServiceManager.

## 31.7	Проверка подключения
Безопасный outbound-specific тест без мутации production routing в текущей архитектуре недоступен:  
`Outbound-specific connectivity test is unavailable.`  
Дополнительно — read-only DNS resolve `engage.cloudflareclient.com` (не доказательство WARP path).  
IPv6 unavailable ≠ полный failure при рабочем IPv4 (когда/если probe станет available).

## 31.8	Regenerate / Remove / Rollback
- Regenerate: backup registration → new identity → replace только managed outbound settings → validate/commit; при сбое — restore registration; tag/routing/DNS не трогаем.
- Remove integration: блокируется при routing references; иначе remove managed outbound, ownership `managed=false`, registration files сохраняются.
- Remove helper — отдельно.
- Сбой backup отменяет операцию; partial write не оставляем.

## 31.9	Безопасность
Запрещено: user shell, произвольные download URL/paths из GUI, ключи в argv где возможно, отключение firewall, system routing, Cloudflare One client, авто-маршрут SSH через WARP.  
Приоритет: сохранить SSH администратора.

## 31.10	Неподдерживаемое / отложено
WARP+ license keys, Zero Trust org tokens/MDM, MASQUE, system WARP client, auto routing/firewall, произвольный WireGuard editor, multi-account, scheduled regen, bandwidth analytics.

## 31.11	Тесты
Моки SSH/helper/config writes; без реальной регистрации WARP и без Internet.  
Покрыты: helper install/verify/fail, register, parse IPv4/IPv6/reserved, tag uniqueness/conflict, detect Possible/External, adopt, remove blocked/allowed, regenerate rollback, connectivity unavailable, secret redaction, page model.

## 31.12	Зависимости
Новых crate нет. Используется существующий SSH + config-modify + ServiceManager.


# 32	Inbound-scoped Users (Tier‑2)

Расширение MVP §15–§17: клиенты редактируются в контексте выбранного inbound, а не через глобальную страницу sidebar. Typed-модель клиентов, единый parse/write, fingerprint conflict detection.

> Статус: Lake 1 (VLESS) + Lake 2 (Trojan) + Wave A Hysteria shipped; Tunnel shell (без Users) — Roadmap §2.2:70 (2026-08-02). Актуальное shell/Stream/Security/Share/matrix — §34.

## 32.1	Цель и границы
- В scope (shipped): VLESS, Trojan, Hysteria CRUD; GUI Inbounds → Users с dispatch (`UsersProtocolUi`: Vless / Trojan / Hysteria).
- Shell без Users (shipped): Tunnel — General + Protocol + Sniffing; wire только `protocol: "tunnel"`; legacy `dokodemo-door` read-only.
- Вне scope / backlog: subscription/limits/expiry; schema engine. Retired (Roadmap §4.1, 2026-10-06): редакторы VMess/HTTP/SOCKS/`mixed`/Shadowsocks/WireGuard inbound (G11 — только predicate); для Socks/HTTP — предупреждение «open proxy» (§96).

Capability gate (клиенты): `InboundClientProtocol::mutate_enabled()` — Vless | Trojan | Hysteria.  
Отдельно: `shell_edit_enabled()` — VLESS | Trojan | Hysteria | Tunnel (Tunnel: Stream/Security/Users tab disabled; matrix tcp×none; Shell Save не перезаписывает `streamSettings`/`security` на диске).

## 32.2	Архитектура
```
GUI (Inbounds → select → … | Users)
  → selected_users_protocol() → UsersProtocolUi dispatch
  → ApplicationService (ClientDialogDraft + fingerprint at edit/delete intent)
    → start_add/update/delete_* (VLESS | Trojan | Hysteria)
      → add_user / update_user / delete_user
      или add_inbound_client / update_inbound_client (VLESS | Trojan | Hysteria enum APIs)
      → require_tier2_mutate_inbound (protocol + AmbiguousClientsArray)
      → fingerprint verify (update/delete)
      → parse_inbound_client → typed + extras
      → write_inbound_client → Value
      → with_clients_mut → sync clients/users array into file_roots
      → check_inbound_compatibility (G3 Vision×transport на VLESS add/update; rollback при fail)
      → write_config_validated (backup → atomic write → optional xray run -test) → reload
      → refresh_editor_fingerprint() / `vision_active` если открыт Shell-редактор (§34)
```

Код: `src/xray/config/inbound_clients/`, `editable.rs`, `modify.rs` (`add_hysteria_client`, `update_hysteria_client`, `generate_client_auth`), `users.rs` (`HysteriaClientSummary`), `src/xray/secret.rs`, `src/app/user_ops.rs`, `src/app/users.rs` (`UsersProtocolUi`, `hysteria_row_display`), GUI `inbounds.rs` + `users.rs`, `docs/ui.md`.

## 32.3	Модель клиентов (Approach B)
| Тип | Назначение |
| --- | ---------- |
| `InboundClient` | enum Vless / Trojan / Hysteria (Tunnel — без клиентов / без variant) |
| `InboundClientProtocol` | wire: vless / trojan / hysteria / tunnel; `mutate_enabled` — первые три; `shell_edit_enabled` — все четыре |
| `VlessClient` | `id`, `email`, `flow`, `level`, `extras` |
| `TrojanClient` | `password: SecretString`, `email`, `level`, `extras` (без `flow`) |
| `HysteriaClient` | `auth: SecretString`, `email`, `level`, `extras` |
| `ClientRef` | `location: InboundLocation`, `client_index`, `protocol`, `expected_fingerprint` |
| `SecretFieldDraft` | `Preserve` \| `Replace(SecretString)` (Trojan password / Hysteria auth edit) |

Неизвестные ключи клиента живут в `extras` и мержатся при write-back.

## 32.4	Ключ массива `clients` / `users`
- Есть только `clients` или только `users` → используем существующий ключ.
- Есть оба → `AmbiguousClientsArray` (mutate запрещён).
- Нет ни одного при add → VLESS/Trojan → `clients`; Hysteria → `users`.

## 32.5	Fingerprint
- `json_value_fingerprint` → `client_fingerprint` / `inbound_fingerprint`.
- Clients: снимается при Edit/Delete; mismatch → `FingerprintMismatch`, запись не выполняется.
- В логах — только hex.

## 32.6	Операции modify
| Action | Поля |
| ------ | ---- |
| Add / Update / Delete VLESS | email, id/flow/level + fingerprint на update/delete |
| Add / Update / Delete Trojan | email, password (`Preserve`/`Replace`), level + fingerprint |
| Add / Update / Delete Hysteria | email (required + unique), auth (`Preserve`/`Replace`; Add pre-filled via `generate_client_auth()`), level + fingerprint |

## 32.7	GUI
- Sidebar: Users удалён. Legacy `last_page = "Users"` → `Page::Inbounds`.
- Users tab: protocol dispatch по выбранному inbound (`UsersProtocolUi`); таблицы VLESS / Trojan / Hysteria с protocol-specific колонками; dirty shell drafts блокируют Users (§34).
- Диалоги: `ClientDialogDraft` — VLESS + Trojan + Hysteria variants (`AddHysteria` auth generate-by-default + Regenerate).
- Context menu: Copy share URI (`vless://` / `trojan://` / `hy2://`) — §34.7.

## 32.8	Состояния Users tab
| Состояние | Когда |
| --------- | ----- |
| NoInboundSelected | inbound не выбран |
| NoSupportedInboundSelected | не VLESS/Trojan/Hysteria для mutate |
| SelectedInboundHasNoUsers | пустой массив клиентов |
| UsersLoaded / warnings | как раньше |

## 32.9	SecretString
`src/xray/secret.rs`. WARP + typed inbound clients. `Debug` → `[REDACTED]`.

## 32.10	Тесты
VLESS + Trojan + Hysteria mutate matrix (`add/update/delete`, empty auth, duplicate email, `Preserve`/`Replace` auth); AmbiguousClientsArray; fingerprint; preserve `users` key; Hysteria extract summary; Vision + xhttp на Users mutate → G3 (`modify_tests`). View model: `selected_users_protocol`, `hysteria_row_display` (`app/users.rs`).

## 32.11	Зависимости
`sha2`, `uuid`, `serde_json`, config-modify / backup / IB-L6 `-test`.

## 32.12	Документация
Этот раздел; §34; `docs/ui.md`; `docs/qa-inbound-users-lake1.md`.


# 33	Inbound shell edit (General + Sniffing, D027 Lake 1) — исторический слой

Первый shell-lake: tag / listen / port и sniffing без Transport/Security.  
> Актуально: единый Shell Save + вкладки Protocol/Stream/Security/Add — §34 (`InboundEditorSession`). Ниже — исходный D027 Lake 1 (два независимых Save, `InboundShellDrafts`); код legacy-path сохранён, GUI ведёт через §34.

## 33.1	Цель и границы (D027)
- Было в scope: General + Sniffing; VLESS/Trojan/Hysteria shell; preserve-unknown; whole-inbound fingerprint; два Save; duplicate tags hard-block; scalar port.
- Было вне scope (часть закрыта в §34 / Wave A / TLS advanced / multi-cert): Reality/Stream, `-test`, visual diff, Trojan client mutate, TLS (paths → полный TLSObject → multi-entry `certificates[]`), Hysteria shell + Users CRUD, remote cert path SFTP check.  
  По-прежнему вне scope: смена protocol; ACME; full `hy2` query (см. Roadmap §2.2–2.5, §3). Non-scalar port (range/array/mixed list) закрыт (Roadmap §3:118) — preserve-only, см. §34.4. Routing `inboundTag` на rename закрыт (Roadmap §3:119) — warn+list, v1, не блокирует; см. §34.4.

Gates: `require_shell_editable_inbound` ≠ `require_tier2_mutate_inbound`. AmbiguousClientsArray не блокирует shell path.

## 33.2	Архитектура (legacy)
```
GUI → ApplicationService (InboundShellDrafts + InboundRef)
  → update_inbound_general / update_inbound_sniffing
  → with_inbound_mut → finish_modification → backup → remote write
```

Код: `src/xray/config/inbound_edit/`, `inbound_ops.rs` (legacy workers).

## 33.3–33.9	Модель и правила (кратко)
См. реализацию: `InboundRef`, `InboundGeneral`, `SniffingSettings`, sniffing NoWrite/create, scalar port, duplicate tag hard-block, `with_inbound_mut` sync полного inbound Value. Routing refs на rename — warn/TODO. Тесты shell matrix в `modify_tests`.

## 33.10	Документация
Исторический слой; актуальный продукт — §34; Wave A Users CRUD shipped (2026-08-01); backlog: Waves B–D (Roadmap). Non-scalar port shipped 2026-08-14 (Roadmap §3:118); routing `inboundTag` rename warn+list shipped 2026-08-14 (Roadmap §3:119).


# 34	Complete Inbounds (IB-L1…L6 + Share URI + Wave 0/A/C1/C2/C3 matrix)

Продуктовый слой поверх §32–§33: один Edit/Add window, Stream + Security, post-write `-test`, redacted JSON preview, share links. Design/eng: gstack Complete Inbounds (2026-07-26/27). Wave 0 (2026-07-28): CompatibilityMatrix + GUI filter API + Users G3. Wave A (2026-07-29…2026-08-01): TLS + Hysteria shell + gates G9/G10/G12 + minimal `hy2://` / TLS share + Hysteria Users CRUD (design `anubarak-master-design-20260728-205339.md`). Tunnel shell (Roadmap §2.2:70, 2026-08-02): dokodemo-door successor без Users/Share. Wave C1 WebSocket (Roadmap §2.3:80, 2026-08-06): `StreamMethod::Ws` + `wsSettings` editor; Reality greyed; TLS-only share. Wave C1 mKCP (Roadmap §2.3:81, 2026-08-07): `StreamMethod::Mkcp` + full `kcpSettings` editor; Reality greyed; TLS-only share; FinalMask tip (без editor). Wave C2 fallbacks (Roadmap §2.3:83, 2026-08-07): shared `settings.fallbacks` editor для VLESS/Trojan (TCP+TLS/Reality); auto-strip на Shell Save. Wave C3 XHTTP (Roadmap §2.3:82, 2026-08-07): full `xhttpSettings` allowlist (padding/SSE/sc*/placement/XMUX/`downloadSettings`) + Share `extra=`. TLS advanced (Roadmap §2.3:84, 2026-08-07): полный `TLSObject` + CertificateObject editor; ALPN tag multi-select; при fallbacks — обязательный non-empty Security ALPN (без auto-patch). Multi-entry `certificates[]` + remote SFTP path check (Roadmap §2.3:85 / §2.5:104, 2026-08-07): typed `Vec<CertificateDraft>`; G12 per-entry file-or-PEM; post-G12 `SshSession::path_is_file` before write. REALITY advanced + FinalMask editor (Roadmap §2.3:86, 2026-08-08): `RealitySettingsDraft` gains `show`/`xver` GUI widgets + `minClientVer`/`maxClientVer`/`maxTimeDiff`/`limitFallbackUpload`/`limitFallbackDownload`; new `streamSettings.finalmask.tcp[]`/`.udp[]` layer editor for VLESS/Trojan (not Hysteria); G4 path bug fixed (was reading `realitySettings.finalmask.tcp` instead of the top-level sibling key, so it never fired). Sockopt editor (Roadmap §2.3:87, 2026-08-09): new `inbound_stream/sockopt.rs` submodule — typed `SockoptDraft` for `streamSettings.sockopt` (method-independent; VLESS/Trojan/Hysteria), replacing the previous opaque clone-through; GUI editor on the Stream tab for inbound-applicable fields (`tproxy`, `tcpFastOpen`, `acceptProxyProtocol`, `V6Only`, keep-alive/timeout/window fields, `trustedXForwardedFor`, raw-JSON `customSockopt`); outbound-only fields (`mark`, `domainStrategy`, `dialerProxy`, `tcpcongestion`, `interface`, `tcpMptcp`, `addressPortStrategy`, `happyEyeballs`) modeled typed for future outbound reuse but not yet exposed in GUI, since no Outbound Shell exists yet (§2.4/Tier 4 backlog). Tunnel transparent-proxy follow-up (Roadmap §2.3:88, 2026-08-09): Tunnel Protocol tab gains a narrow `sockopt.tproxy` field (combo + free text, shared widget with the Stream-tab Sockopt editor) next to `followRedirect`; Shell Save gained `apply_tunnel_sockopt` — writes only `streamSettings.sockopt` (empty ⇒ key removed), still leaving every other `streamSettings`/`security` key byte-for-byte untouched.

## 34.1	Цель и границы
- В scope (shipped, Wave 0 + A core + Tunnel + C1 WS + C1 mKCP + C2 fallbacks + C3 XHTTP + TLS advanced + multi-cert + REALITY advanced/FinalMask + Sockopt + Tunnel tproxy follow-up):
  - VLESS + Trojan + Hysteria Add/Edit shell; вкладки General | Protocol | Stream | Security | Sniffing | Users
  - Tunnel Add/Edit shell: вкладки General | Protocol | Sniffing (Stream / Security / Users disabled); wire `protocol: "tunnel"`; legacy `dokodemo-door` — строка в таблице, shell edit disabled
  - unified Shell Save; IB-L5 Preview; IB-L6 `xray run -test`
  - remote `x25519` / `vlessenc` / `mldsa65`
  - CompatibilityMatrix + dual filter/Save API; Vision Stream filter + G3 на VLESS client mutate
  - TLS (`InboundSecurityMode::Tls`, полный `TlsSettingsDraft`: TLSObject + `certificates: Vec<CertificateDraft>`; unknown TLS keys → `extras`; per-cert unknown → `CertificateDraft.extras`; editor всегда ≥1 entry)
  - G12 (local): каждый `certificates[]` — file-пара или PEM-пара; `usage=verify` → key/keyFile optional; пустой массив → fail
  - Remote TLS paths (после G12, до write): `verify_remote_tls_cert_paths` → `SshSession::path_is_file` (SFTP metadata) для non-empty `certificateFile`/`keyFile` на Shell Save / Add
  - Security modes: VLESS `none|tls|reality`; Trojan `tls|reality` (Add default Reality); Hysteria `tls` only; Tunnel — security `none` only (matrix), без Security tab; WebSocket / mKCP ⇒ Reality недоступен (matrix `websocket×reality` / `mkcp×reality` = false)
  - Symmetric strip `tlsSettings` ↔ `realitySettings` на смене mode; unknown `security` → read-only open + Save `ValidationFailed`
  - Hysteria transport (`StreamMethod::Hysteria`, `hysteriaSettings`, typed `finalmask.quicParams`); Tunnel — transport tcp locked (matrix), Shell Save по-прежнему не мутирует `streamSettings`/`security` в целом, кроме узкого `sockopt.tproxy` (Roadmap §2.3:88) и `finalmask.tcp`/`.udp` (Roadmap §2.6 4.2, §88; `apply_tunnel_stream`) — всё остальное (network/tlsSettings/прочие sockopt-поля) preserve on disk
  - WebSocket transport (`StreamMethod::Ws`, `wsSettings`: `path` / `host` / `acceptProxyProtocol` / Early Data `ed`; extras preserve incl. client-only `headers`); wire write всегда `websocket` (read `ws`|`websocket`); не для Hysteria
  - mKCP transport (`StreamMethod::Mkcp`, `kcpSettings` — поля `KCPConfig` ядра, §65: `mtu` / `tti` / `uplinkCapacity` / `downlinkCapacity` + опциональные `cwndMultiplier` / `maxSendingWindow`; defaults ядра на выборе метода; hard-validate как `KCPConfig.Build()`; ядром игнорируемые `congestion`/`readBufferSize`/`writeBufferSize` и legacy `header`/`seed` — extras preserve + предупреждения); wire write всегда `mkcp` (read `kcp`|`mkcp`); не для Hysteria
  - XHTTP transport (`StreamMethod::Xhttp`, `xhttpSettings` Wave C3): `host`/`path`/`mode` + `headers` + ranges (`xPaddingBytes`, `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `scStreamUpServerSecs`, …) + bools (`noSSEHeader`/`noGRPCHeader`) + placement/obfs + nested `xmux` + one-level `downloadSettings` (nested xhttp без рекурсивного download); documented defaults на выборе метода; Save пишет typed surface; hard-validate mode/placement/xmux conflict/ranges; extras preserve; не для Hysteria
  - Shared fallbacks (Wave C2 + TLS advanced): `settings.fallbacks[]` для VLESS / Trojan на вкладке Protocol; полный `FallbackObject` (`name` / `alpn` / `path` / typed `dest` / `xver`); только TCP|raw + tls|reality; Hysteria/Tunnel — без секции; на Save: auto-strip при несовместимом Stream/Security; иначе `require_alpn_for_fallbacks` — non-empty `tlsSettings.alpn` / `realitySettings.alpn` (GUI tag multi-select; без auto-patch); extras preserve; empty list → omit key
  - При выборе WS / mKCP / XHTTP в GUI: auto-coerce security — Trojan → `tls` (WS/mKCP); VLESS Reality→WS/mKCP → `none` (TLS сохраняется) — `coerce_security_mode_for_transport`; выбор mKCP / XHTTP сбрасывает draft на documented defaults
  - Protocol Hysteria `settings.version = 2`; Add defaults TLS + hysteria network
  - Tunnel Protocol tab: `allowedNetwork`, `rewriteAddress`, `rewritePort`, `followRedirect`, `sockopt.tproxy` (combo + free text; Roadmap §2.3:88), `userLevel`, `portMap` editor (target forms `host:port` / `:port` / `host:`); Add defaults `tcp` / `localhost` / empty map
  - Gates: G7 retired; Save order G9→G10→G6→G5→G1→G2→G8→G12→G4→G3; G11 predicate+tests (Shadowsocks tcp-only; SS editor retired, Roadmap §4.1)
  - Share: Reality + TLS для VLESS/Trojan; WS / mKCP — только TLS (`type=ws` path/host; `type=kcp`; `security=none` / Reality → отказ); XHTTP — `type=xhttp` path + optional host/mode + URL-encoded `extra=` (JSON всех advanced кроме host/path/mode); minimal `hy2://auth@host:port` (+ optional `sni`/`insecure`); Tunnel — без Share URI
  - Hysteria Users CRUD + protocol dispatch в Users tab (2026-08-01); Hysteria shell edit GUI разблокирован (G7 retired)
  - Delete inbound для любого protocol (unsupported incl.); Edit/Duplicate — только `shell_edit_enabled` (incl. Tunnel); hard-block если tag в `routing.rules[].inboundTag`; Delete-диалог показывает список ссылающихся routing-правил заранее и блокирует кнопку, пока они не убраны (Roadmap §3:117)
  - Inbound tag rename (через General-таб composed Shell Save, отдельного Rename-действия нет) — warn+list на routing `inboundTag` refs, не блокирует: проактивное предупреждение в форме, пока draft-тег отличается от текущего и ссылки ещё есть; после Save, если тег реально сменился, статус-бар повторяет оставшиеся ссылки (Roadmap §3:119, `inbound_tag_reference_preview` / `inbound_stale_tag_references`)
  - Outbound Delete UI (любой protocol) + hard-block по `outboundTag` / `balancers[].selector` (prefix); Edit/Duplicate outbound — backlog
  - Delete / Duplicate inbound shell protocols (VLESS/Trojan/Hysteria/Tunnel) — Duplicate по-прежнему shell-only
  - REALITY advanced (`show`, `xver`, `minClientVer`, `maxClientVer`, `maxTimeDiff`, `limitFallbackUpload`/`limitFallbackDownload` с `afterBytes`/`bytesPerSec`/`burstBytesPerSec`) — GUI на Security tab; FinalMask editor (`stream/finalmask.rs`, до §63 — `inbound_stream/finalmask.rs`): typed `FinalMaskLayerDraft` (`type` + raw JSON `settings`) для `streamSettings.finalmask.tcp[]`/`.udp[]`; presets `TCP_FINALMASK_TYPES` (`header-custom`/`fragment`/`sudoku`/`xmc`) и `UDP_FINALMASK_TYPES` (`header-custom`/`mkcp-legacy`/`noise`/`salamander`/`sudoku`/`xdns`/`xicmp`/`realm`/`udphop`) + free-text fallback; Add/Remove/Move up-down; VLESS/Trojan, не Hysteria (Hysteria уже владеет `finalmask.quicParams`); G4 предупреждение inline при Reality + non-empty `finalmask.tcp`. Типизированные формы `settings` для `fragment`/`salamander`/`sudoku`/`realm`/`udphop`/`noise`/`xdns`/`xicmp` (`stream/finalmask_layers.rs`, Roadmap §2.3:89) `mkcp-legacy` (`stream/finalmask_mkcp.rs`, §73) и `header-custom` (`stream/finalmask_header_custom.rs`: TCP §74, UDP §75), `xmc` (`stream/finalmask_xmc.rs`, §76); любой непредставимый слой — raw-JSON редактор; help по каждому типу и полю, пресеты `fragment.packets`/`noise.type`/`sudoku.ascii` — §77. Правило «без потерь или raw», shape-preserving значения, персистентные draft'ы форм и некритичные предупреждения — §62 (Roadmap §2.6, этап 0)
  - Sockopt editor (Roadmap §2.3:87) — typed `streamSettings.sockopt` для VLESS/Trojan/Hysteria (method-independent); GUI-редактируемые поля: `tproxy`/`tcpFastOpen`/`acceptProxyProtocol`/`V6Only`/`tcpMaxSeg`/`tcpKeepAliveIdle`/`tcpKeepAliveInterval`/`tcpUserTimeout`/`tcpWindowClamp`/`trustedXForwardedFor`/`customSockopt` (raw JSON); read-only summary на Stream tab в view-режиме; outbound-only поля (`mark`/`domainStrategy`/`dialerProxy`/`tcpcongestion`/`interface`/`tcpMptcp`/`addressPortStrategy`/`happyEyeballs`) типизированы в `SockoptDraft`, но без GUI-виджетов и без нового CompatibilityGate — нет ни одного пересечения с G1–G12
- Вне scope / backlog:
  - Outbound sockopt GUI — `SockoptDraft`/`parse_sockopt`/`sockopt_to_value` уже общие для inbound/outbound streamSettings; Freedom Outbound Shell теперь существует (§35) но не редактирует `streamSettings` вовсе (только `settings.fragment`/`noises` — вне scope §2.4:94); GUI-редактор для outbound sockopt по-прежнему backlog
  - Wave B (VMess + G11 live для Shadowsocks inbound editor) — retired 2026-10-06 (Roadmap §4.1)
  - Wave C1 remainder: httpupgrade; multi-level nested `downloadSettings` recursion
  - Wave D remainder: outbound Delete остаётся чистый hard-block без проактивного предупреждения (routing `outboundTag`/`balancer.selector`); inbound Delete уже показывает список ссылающихся routing-правил заранее и блокирует кнопку, пока они не убраны (Roadmap §3:117, `inbound_tag_reference_preview` в Delete-диалоге)
  - Также: смена `protocol`; ACME; миграция `dokodemo-door` → `tunnel`; structured `echSockopt` editor (сейчас raw JSON per-field, но теперь также доступен через whole-object Raw JSON tab — §3:125) (Roadmap §2–3). Users-tab JSON Preview закрыт (Roadmap §3:120) — см. §34.8. Full Share URI query parity закрыт (Roadmap §3:121) — см. §34.9. Share URI QR code UI закрыт (Roadmap §3:122) — см. §34.9. Pop-up help / field documentation overlays закрыт для Inbound Shell editor (Roadmap §3:124) — см. §34.10; остальные страницы приложения не покрыты. Raw JSON editor (whole inbound/outbound) закрыт (Roadmap §3:125) — см. §34.11 / §35.4.

## 34.2	Архитектура
```
GUI (inbounds.rs + users.rs)
  → ApplicationService
      InboundEditorSession (dirty, vision_active, ephemeral PublicKey / vlessenc / mldsa65)
      ShareMaterialStore (retained PublicKey/encryption после Save)
      selectable_stream_methods (protocol×Vision) + allowed_security_modes (matrix ∩ security)
      coerce_security_mode_for_transport (на смене Stream, напр. Reality→WS/mKCP)
      inbound_editor_warnings / inbound_warnings_at               # §62.5, non-blocking
    → update_inbound_shell / add_inbound / user mutate
      → compose_inbound_shell (Shell Save; общий с warnings, §62.5):
          apply_inbound_general + apply_inbound_protocol (incl. settings.fallbacks)
          → apply_inbound_stream + apply_inbound_security
          → reconcile_inbound_fallbacks (strip | require ALPN)
          → apply_inbound_sniffing
      → check_inbound_compatibility / first_failing_gate(&Value)   # G12 local file-or-PEM
      → finish_modification snapshots
    → run_update_inbound_shell / run_add_inbound (SSH)
      → connect
      → verify_remote_tls_cert_paths (SFTP path_is_file; non-empty cert/key paths)
      → write_config_validated:
            backup → atomic write
            → xray run -c|-confdir … -test (IB-L6)
            → on fail: restore backup → XrayValidationFailed
    → poll_inbound_mutation (Shell Save / Add / Raw JSON):
        статус-бар + with_warning_suffix(inbound_warnings_at(index))   # §62.5
```

Ключевые модули:
| Область | Путь |
| ------- | ---- |
| Shell / Add | `modify.rs` (`update_inbound_shell`, `add_inbound`; `pub compose_inbound_shell` — все `apply_*` без gates; `pub build_add_inbound_value` — §62.5), `inbound_ops.rs` (remote TLS path probe) |
| Protocol | `inbound_protocol/` (VLESS `decryption` + fallbacks; Trojan fallbacks; Hysteria `version`; Tunnel `allowedNetwork` / rewrite / `portMap` / `followRedirect` / `userLevel`) |
| Fallbacks | `inbound_fallbacks/` (`FallbackObject`, typed `FallbackDest` Port\|TcpAddr\|UnixSocket; `parse`/`apply`/`validate`; `fallbacks_transport_compatible`; `reconcile_inbound_fallbacks`; `require_alpn_for_fallbacks`) |
| Stream | `inbound_stream/` (tcp/raw\|xhttp\|grpc\|websocket\|mkcp\|hysteria; `XhttpStreamSettings`/`XhttpCoreSettings`/`XmuxDraft`/`XhttpDownloadDraft` + `validate_xhttp_settings` / `xhttp_extra_json`; `WsStreamSettings` + `join/split_ws_path_and_ed`; `KcpStreamSettings` + `validate_kcp_settings`; `hysteriaSettings`; `other_method` preserve). Реэкспортирует всё из общего direction-aware модуля `stream/` (§63): `quic_params`: `QuicParamsDraft` + `parse_quic_params`/`quic_params_to_value`; `finalmask`: `FinalMaskLayerDraft` + `TCP_FINALMASK_TYPES`/`UDP_FINALMASK_TYPES` + `parse_finalmask_layers`/`finalmask_layers_to_value`/`validate_finalmask_layers` (VLESS/Trojan `finalmask.tcp`/`.udp`; not Hysteria); `finalmask_layers` submodule: typed `settings` per layer type (`FragmentMaskSettings`/`SalamanderSettings`/`SudokuSettings`/`RealmSettings`/`UdpHopSettings`/`NoiseMaskSettings`/`XdnsSettings`/`XicmpSettings` + `parse_*`/`*_to_value`; правило «без потерь или raw», §62.3); `values` submodule: shape-preserving `RangeValue`/`PortListValue`/`PacketValue` (§62.2); `sockopt` submodule: `SockoptDraft`/`TcpFastOpenDraft`/`HappyEyeballsDraft` + `parse_sockopt`/`sockopt_to_value`/`validate_sockopt` (method-independent; VLESS/Trojan/Hysteria; `write_sockopt` dirty-flag gates typed-write vs raw clone-through, same pattern as `write_finalmask_tcp`/`.udp`; direction table `INBOUND_ONLY_SOCKOPT_FIELDS`/`OUTBOUND_ONLY_SOCKOPT_FIELDS` + `sockopt_field_applies`, §63) |
| Stream editors (GUI) | `gui/pages/stream_finalmask.rs` (`show_finalmask_edit`, `show_quic_params_edit`, формы слоёв, `FinalMaskForm`), `gui/pages/stream_sockopt.rs` (`show_sockopt_edit` / `show_sockopt_readonly` с `StreamDirection`, `tproxy_combo_field`) — §63 |
| Security | `inbound_security/` (none\|tls\|reality; `TlsSettingsDraft` + `CertificateDraft` vec; Reality `alpn` + advanced `show`/`xver`/`minClientVer`/`maxClientVer`/`maxTimeDiff`/`RealityLimitFallbackDraft` (`limitFallbackUpload`/`limitFallbackDownload`); presets в `alpn.rs`; unknown → `security_unknown`) |
| Gates / matrix / warnings | `compatibility/` (`warnings.rs` — некритичные `CompatibilityWarning` + `inbound_warnings` / `with_warning_suffix`, §62.5; `mod.rs` Save order Wave A + G12 per-entry; `matrix.rs` wire table + `allowed_*` / `selectable_stream_methods` / `coerce_security_mode_for_transport`; tunnel ⇒ tcp + none; ws×reality / mkcp×reality запрещены; fallbacks используют `normalized_method` + `effective_security` без отдельного Gx) |
| SSH / SFTP | `feldjaeger-ssh` (`SshSession::path_is_file` via SFTP metadata) |
| Remote CLI | `remote_cli/` (`x25519`, `vlessenc`, `mldsa65`, `config_test`) |
| Diff IB-L5 | `json_diff.rs` + shared render `gui::pages::json_diff_preview()` — used by Inbound Shell Preview (`inbounds.rs`) and Users tab Add/Edit dialogs (`users.rs`, Roadmap §3:120: `preview_add_user_diff` / `preview_update_user_diff`) |
| Write+test | `app/config_write.rs` |
| Share URI | `share_uri.rs` (`ShareTransport::Ws` / `Kcp`, `ShareSecurity::Tls` + `alpn`, `ShareProtocol::Hysteria` / hy2 + `port_hop`/`obfs_salamander_password`/`pin_sha256`), `app/share_material.rs`; local `pbk` fallback — `x25519_local::public_key_from_private_key` (no SSH round-trip) derives Reality `pbk` from `realitySettings.privateKey` when neither the session nor `ShareMaterialStore` has a stored public key; `xray/cert_pin.rs` — local SHA-256 DER hash for hy2 `pinSHA256` (Roadmap §3:121), fetched via `ApplicationService::start_fetch_cert_pin` (SFTP `certificateFile` read) |
| Tag refs / Delete | `tag_refs.rs` (`inbound_tag_references` / `outbound_tag_references`); `delete_inbound` (any protocol); `delete_outbound` + Outbounds GUI Delete |

## 34.3	`InboundEditorSession`
Единая session вместо dual General/Sniffing Save:
- Edit: fingerprint `InboundRef`; dirty shell блокирует Users.
- Add: `is_add`; protocol picker VLESS | Trojan | Hysteria | Tunnel; Trojan Add default Reality (+ remote `x25519` для share); Hysteria Add → TLS + `network/method=hysteria` + `version=2`; Tunnel Add → `protocol: "tunnel"`, defaults tcp/`localhost`, stream tcp/none, без Security draft / без `clients`.
- Guided presets (Roadmap §3:123): ряд «Presets:» над протокол-пикером в Add-форме (`inbounds.rs::apply_inbound_preset`) — «VLESS + Reality» / «Trojan + Reality» / «Hysteria2 (TLS)». Не отдельный wizard-диалог (осознанный выбор дизайна после уточнения с пользователем) — просто вызывает `begin_add_inbound`, для VLESS переключает `session.security.mode` на `Reality` (у `begin_add_inbound` дефолт для VLESS — `none`; Trojan/Hysteria и так корректны), и для VLESS/Trojan сразу запускает `start_generate_x25519()` тем же путём, что и ручная кнопка Generate на Security-табе. Результат — обычная Add-сессия, ничего не блокирует; протокол-пикер и Security-таб доступны как раньше для полностью ручного пути.
- Ephemeral: PublicKey, mldsa65 verify, client encryption — никогда не пишутся в inbound JSON (`publicKey` outbound-only).
- После Generate / перед clear session — retain в `ShareMaterialStore` (ключ `tag:…` / `idx:N`).
- Remote sidecar (не Xray config): рядом с конфигом — `{config}.feldjaeger-share.json` (single file) или `{dir}/feldjaeger-share.json` (directory). Load при Discover; write после Generate / Shell Save / Add Save. Поля: `publicKey`, `encryption`, `mldsa65Verify` per inbound key.
- `vision_active` из loaded clients при open; refresh после успешного Users mutate (не из unsaved Users form).

## 34.4	Вкладки
| Tab | Поведение |
| --- | --------- |
| General | tag / listen / scalar port; non-scalar `port` (range string / array / mixed list) shown read-only with its raw shape and preserved byte-for-byte on Save — never coerced to scalar (Roadmap §3:118, `raw_port_display`); duplicate tag hard-block; tag rename shows a proactive warning (`inbound_tag_reference_preview`) when the draft tag still has routing `inboundTag` refs, and the post-Save status message repeats the stale refs if the tag actually changed (`inbound_stale_tag_references`) — v1 warn+list, never blocks (Roadmap §3:119) |
| Protocol | VLESS decryption + Generate `vlessenc` + shared fallbacks editor; Trojan shared fallbacks (clients → Users); Hysteria `version=2` (fixed); Tunnel — network combo, rewrite address/port, `followRedirect`, `sockopt.tproxy` (combo + free text, shared widget with Stream-tab Sockopt; Roadmap §2.3:88), `userLevel`, portMap table (add/edit/delete + target validation) |
| Stream | вверху (view и edit) — жёлтые некритичные предупреждения с JSON-путём (`show_compatibility_warnings`: edit — по черновику `inbound_editor_warnings`, view — по сохранённому `inbound_warnings_at`; §62.5); FinalMask `tcp[]`/`udp[]` — типизированные формы слоёв с draft'ом, переживающим кадры egui, и raw-JSON fallback (§62.3–§62.4); tcp/raw \| xhttp \| grpc \| websocket \| mkcp \| hysteria; combo через `selectable_stream_methods` (protocol×Vision; security coerce отдельно); Hy protocol locks hysteria; XHTTP: full allowlist + headers From/To ranges + XMUX + one-level download; WS: path/host/acceptProxyProtocol/`ed`; mKCP: `kcpSettings` по `KCPConfig` ядра (cwndMultiplier/maxSendingWindow, пусто = дефолт ядра) + hard-validate как `Build()` + кнопка «Remove ignored fields» (§65); quicParams — все 17 полей `QuicParamsConfig` + валидация как `Build()`, client-only поля на inbound — только если заданы (§78); у XHTTP при TLS alpn ровно ["h3"] — тот же редактор для XHTTP/3 (congestion reno/bbr/force-brutal, §80); Sockopt (VLESS/Trojan/Hysteria, method-independent): `tproxy`/`tcpFastOpen`/`acceptProxyProtocol`/`V6Only`/keep-alive+timeout+window fields/`trustedXForwardedFor`/`customSockopt` (raw JSON); outbound-only sockopt поля preserve-only; `other_method` preserve; coerce display без dirty-on-open; Tunnel — tab disabled (tcp/none fixed; on-disk `streamSettings` preserved on Shell Save except the narrow `sockopt.tproxy` field exposed on the Protocol tab) |
| Security | VLESS none\|tls\|reality; Trojan tls\|reality; Hysteria tls; WS / mKCP ⇒ none\|tls (Reality greyed); TLS (полный TLSObject + multi-entry certificates cards; ALPN/curves tags; ECH collapse); Reality keygen + ALPN tags; unknown security read-only + Apply mode; Tunnel — tab disabled |
| Sniffing | как §33 (NoWrite / create / preserve unknown) |
| Users | §32; protocol dispatch VLESS/Trojan/Hysteria; blocked while shell dirty; Vision на xhttp → G3 ValidationFailed; Tunnel — tab disabled (`mutate_enabled` false) |

## 34.5	TLS advanced + multi-entry certificates (Roadmap §2.3:84–85, §2.5:104)

Полный inbound editor для [`tlsSettings`](https://xtls.github.io/ru/config/transports/tls.html) (VLESS / Trojan / Hysteria): TLSObject + массив CertificateObject + remote existence probe для file-путей.

### Модель (`TlsSettingsDraft` / `CertificateDraft`)
- TLSObject (typed): `serverName`, `verifyPeerCertByName`, `rejectUnknownSni`, `allowInsecure`, `alpn[]`, `minVersion` / `maxVersion`, `cipherSuites`, `disableSystemRoot`, `enableSessionResumption`, `fingerprint`, `pinnedPeerCertSha256`, `curvePreferences[]`, `masterKeyLog`, `echServerKeys`, `echConfigList`, `echSockopt` (`Option<Value>` — raw JSON object).
- `certificates: Vec<CertificateDraft>` (всегда ≥1 в default / parse-empty / write ensure):
  - `certificateFile` / `keyFile`, inline `certificate` / `key` (PEM lines), `ocspStapling`, `oneTimeLoading`, `usage` (`encipherment`\|`verify`\|`issue`), `buildChain` (только при `usage=issue`), `extras` (unknown per-cert keys).
- Unknown keys на уровне `tlsSettings` → `TlsSettingsDraft.extras` (исключая `certificates` и typed keys).
- UI-флаг `enable_ech` (parse: true если любой ECH-поле непусто) — секция ECH скрыта, пока `false`.
- Reality: typed `realitySettings.alpn` в `RealitySettingsDraft` (тот же tag-виджет; нужен для fallbacks gate). **Отменено в 0.5.32-2 (§82):** у REALITY нет `alpn`, ключ хранится как unknown с предупреждением.

### GUI
- Certificates: карточки как у fallbacks (`ui.group`); Add / Remove; Remove disabled при `len == 1`; без reorder (MVP).
- Readonly Security: summary `certificate[i]` — `usage` + paths или `PEM`.
- ALPN / `curvePreferences`: multi-select из пресетов → теги с remove; unknown on-disk значения сохраняются как теги.
- Пресеты: `ALPN_PRESETS` (IANA ALPN Protocol IDs без reserved/`h2c` + Xray `FromMitM`), `CURVE_PRESETS`, `TLS_VERSION_PRESETS`, `FINGERPRINT_PRESETS`, `CERT_USAGE_PRESETS` (`inbound_security/alpn.rs`).
- Длинные значения (PEM, cipherSuites, masterKeyLog, ECH strings / sockopt JSON) — multiline + ScrollArea.
- При непустых fallbacks: жёлтый notify на Security; Save disabled, пока active ALPN пуст.

### G12 (local) + remote probe
- G12 (`compatibility/`): security=`tls` ⇒ массив non-empty; каждый entry — полный file-mode или PEM-mode; `usage=verify` → key/keyFile optional. Не трогает remote FS.
- Remote (`inbound_ops::verify_remote_tls_cert_paths`): после connect на Shell Save / Add, до `write_modified_file`; только non-empty `certificateFile`/`keyFile`; `SshSession::path_is_file` (SFTP `stat` / regular file); miss → `ValidationFailed` (paths only, без PEM/body в логах). Preview остаётся local-only.

### Apply / Share
- Write: сериализует весь `certificates[]` из typed vec; non-default / non-empty TLSObject keys; bools только при `true`; ECH-поля только если `enable_ech`.
- Share TLS URI: `sni` из typed `tls.server_name` (не из `extras`).

## 34.6	Shared fallbacks (Wave C2)

Официальная функция Xray [`fallbacks`](https://xtls.github.io/ru/config/features/fallback.html): TCP-переадресация после TLS/Reality (anti-probe + path split). В Feldjäger — shared editor на Protocol tab для VLESS и Trojan.

### Модель
- Draft: `InboundProtocolDraft::Vless { decryption, fallbacks }` / `Trojan { fallbacks }` (`Vec<FallbackObject>`).
- Поля `FallbackObject`: `name` (SNI), `alpn`, `path` (пусто или `/…`), typed `dest`, `xver` ∈ {0,1,2}, `extras` preserve.
- `FallbackDest`: Port (число → localhost), TcpAddr (`host:port`), UnixSocket (абсолютный путь / `@` / `@@` abstract).
- Write: empty optional strings omit; `xver=0` omit; empty list → remove `settings.fallbacks`; clients/users не трогаем.

### Совместимость и Save
- Допустимо только при `protocol ∈ {vless,trojan}` ∧ transport `tcp|raw` ∧ security `tls|reality` (`fallbacks_transport_compatible` / `fallbacks_compatible_on_inbound`).
- Порядок Shell Save / Add: protocol → stream → security → `reconcile_inbound_fallbacks` → sniffing → gates.
  - Несовместимый Stream/Security → auto-strip `settings.fallbacks` (без отдельного CompatibilityGate).
  - Совместимый + непустой список → `require_alpn_for_fallbacks`: non-empty `tlsSettings.alpn` или `realitySettings.alpn` (иначе `ValidationFailed`; с 0.5.32-2 — только `tlsSettings.alpn` как `StringList`, REALITY без требования, §82); auto-patch удалён — пользователь задаёт ALPN на Security tab (tags).
- GUI: hint «будут сняты при Save», если draft непустой, а текущий Stream/Security несовместим; редактор не блокируется; отдельно — notify/Save-block при пустом Security ALPN.
- Hysteria / Tunnel: секция fallbacks не показывается.

### Код
`src/xray/config/inbound_fallbacks/`; wiring в `inbound_protocol/`, `modify.rs` (`update_inbound_shell` / `build_add_inbound_value`); GUI `src/gui/pages/inbounds.rs` (Protocol View/Edit + Security ALPN).

## 34.7	Compatibility gates (Wave A)
Save / Add / VLESS client mutate — hard-block через `first_failing_gate`.

Порядок Wave A: G9→G10→G6→G5→G1→G2→G8→G12→G3→G13 (G4 выведен в Roadmap §2.6 5.1, §90)  
(G7 удалён из Save; G11 не в Save до Wave B — SS+exotic configs не ломаем.)

| ID | Правило | Статус |
| -- | ------- | ------ |
| G1 | Reality ⇒ raw\|tcp\|xhttp\|grpc | Save + filter |
| G2 | Reality dest host:port | Save |
| G3 | Vision flow ⇒ raw\|tcp | Save + Users mutate + Stream filter |
| G4 | *(retired, §90)* Reality + non-empty `streamSettings.finalmask.tcp` (top-level, sibling of `realitySettings`; path fixed §2.3:86 — was incorrectly reading `realitySettings.finalmask.tcp`, which never fires on real configs) | message id retained; не в `first_failing_gate`; заменён предупреждением `RealityProbeSeesFinalMask` |
| G5 | VLESS decryption non-empty | Save |
| G6 | Trojan ⇒ security ≠ none | Save + filter |
| G7 | *(retired)* Hysteria shell/users gate | message id retained; не в `first_failing_gate`; GUI IB-L7 block removed |
| G8 | Reality privateKey / serverNames / shortIds | Save |
| G9 | Hysteria protocol ⇒ transport hysteria | Save |
| G10 | Hysteria protocol/transport ⇒ security tls | Save |
| G11 | Shadowsocks ⇒ tcp/raw only | predicate + tests; SS inbound editor retired (Roadmap §4.1, 2026-10-06) — не подключается |
| G12 | TLS ⇒ каждый `certificates[]` entry: file-пути или PEM (`usage=verify` → key optional); массив non-empty | Save (local); remote SFTP existence — отдельный post-G12 probe |

Dual API: wire-string matrix в `compatibility/matrix.rs` (`ws` → `websocket`, `kcp` → `mkcp`); typed helpers:
- `selectable_stream_methods(protocol, vision)` — GUI Stream picker (без фильтра по текущему security; Wave C1: Reality→WS/mKCP возможен с auto-coerce);
- `allowed_stream_methods(protocol, security, vision)` — matrix ∩ editable (security-aware; Reality скрывает WS/mKCP);
- `allowed_security_modes(protocol, method_wire)` — Security combo (WS/mKCP ⇒ без Reality);
- `coerce_security_mode_for_transport` — при смене Stream (Trojan→tls; VLESS→none, если не tls).

Wave A/C1: Tls в candidates; Hy stream только для protocol hysteria; Tunnel ⇒ только Tcp + None; WS / mKCP для VLESS/Trojan (не Hysteria). Exotic `other_method` не coerce — preserve + Save hard-block. Unknown `security` не coerce в `none`. Fallbacks (C2) не добавляют отдельный Gx — strip + require ALPN через `reconcile_inbound_fallbacks` после stream/security.

Gates и предупреждения — два разных механизма (Roadmap §2.6, этап 0.3; подробно §62.5): gate (`CompatibilityGateId`) **блокирует** Save / Add / client mutate, предупреждение (`CompatibilityWarningId`, `compatibility/warnings.rs`) Save **никогда** не блокирует — оно отмечает конфигурацию, которую ядро принимает, но которая делает не то, что кажется (как правило, ключ, молча игнорируемый текущим Xray-core). Предупреждения не входят в `first_failing_gate` и не имеют порядка Save; их порядок — порядок в конфиге. Текущий набор: `QuicParamsUdpHopIgnored` (outbound), `QuicParamsUdpHopClientOnly` (inbound, любое ядро; §79), `QuicParamsUnusedTransport` (`quicParams` не на Hysteria/XHTTP-h3; §80), `UdpHopSockoptIgnored` (версионные — с учётом версии ядра из Discovery), `RequiresNewerCore` (маска новее установленного ядра; §67), а также mKCP (§65) и Freedom (§66). G4 по-прежнему gate — его перевод в два предупреждения запланирован в этапе 5.1 Roadmap §2.6 (Reality и `finalmask.tcp` штатно композируются в ядре: `tcp/hub.go`, `tcp/dialer.go`); после этого строка G4 в таблице выше и тесты `g4_*` / `finalmask_tcp_blocked_by_g4_with_reality_security` должны быть обновлены.

## 34.8	IB-L5 / IB-L6
- Preview changes: structural path diff `original_serialized` vs `serialized`; secrets (`password`, `privateKey`, `id`, `auth`, …) → `[REDACTED]`. Preview идёт тем же Shell/Add pipeline (incl. fallbacks reconcile), поэтому strip / ALPN ValidationFailed видны до Save.
- `-test`: после успешного write; confdir install → `-confdir`; fail → restore backup; Status Bar / `XrayValidationFailed`. Skip если binary path неизвестен. G12 = local material check (file or PEM); remote file existence для non-empty paths — `verify_remote_tls_cert_paths` перед write (Shell Save / Add).
- Users tab Preview (Roadmap §3:120, IB-L5 follow-up): `add_inbound_client` / `update_inbound_client` (уже общие VLESS/Trojan/Hysteria диспетчеры, `modify.rs`) возвращают `ModifyUserOutcome = ModifyConfigOutcome`, поэтому `ApplicationService::preview_add_user_diff` / `preview_update_user_diff` клонируют `editable`, дёргают ту же dry-run мутацию (без сети, без изменения `loaded_config`) и прогоняют байты через `redacted_json_diff_bytes`. Рендер diff вынесен из `inbounds.rs` в общую `gui::pages::json_diff_preview()` (переиспользуется Inbound Shell Preview и Users tab). Кнопка «Preview changes» — во всех 6 Add/Edit диалогах `users.rs` (VLESS/Trojan/Hysteria); Delete-диалоги без diff (только confirm-текст, как у inbound Delete). Diff не обновляется реактивно при последующем изменении полей — повторный клик пересчитывает.

## 34.9	Share URI
- Users context menu Copy share URI:
  - `vless://…` / `trojan://…` — Reality и TLS (`ShareSecurity::Tls`: optional `sni` из typed `serverName`, `allowInsecure`, `alpn` из `TlsSettingsDraft.alpn`, Roadmap §3:121)
  - WebSocket (`ShareTransport::Ws`): `type=ws` + `path` (+ optional `host`); path может включать `?ed=N`; только с TLS — `security=none` / Reality → отказ (`build_share_uri` + `ApplicationService::build_client_share_uri`)
  - mKCP (`ShareTransport::Kcp`): `type=kcp` (без seed/header query); только с TLS — `security=none` / Reality → отказ
  - XHTTP (`ShareTransport::Xhttp`): `type=xhttp` path + optional host/mode + `extra=` (URL-encoded JSON advanced allowlist)
  - `hy2://auth@host:port` — full query parity (Roadmap §3:121): optional `sni` / `insecure`; hop — host:port заменяется на Hysteria2 "port hopping" синтаксис (`443,5000-6000`) через `port_hop_syntax()`/`first_hop_port()` (`inbound_edit/general.rs`), если `port` не скаляр (переиспользует §3:118); obfs — read-only детект `finalmask.udp[]` слоя `type: "salamander"` (`hysteria_salamander_obfs_password()`, `inbound_stream/finalmask.rs`) → `obfs=salamander&obfs-password=`; FinalMask UDP editor для Hysteria по-прежнему не реализован (Wave A ограничила это VLESS/Trojan) — только чтение уже существующего на диске (с 0.5.33-0 заменено: редактор `finalmask.udp` для Hysteria и `hy2_share_obfs()` по типизированным слоям, §83); pin — `pinSHA256`: SHA-256 DER-хеш реального сертификата, вычисляется async через `ApplicationService::start_fetch_cert_pin` (SFTP-чтение `certificateFile`, зеркалит паттерн Generate x25519/mldsa65; `src/xray/cert_pin.rs::cert_pin_sha256` — PEM или raw DER, hex lowercase, тот же формат что апстрим hysteria `sha256.Sum256(rawCert)`), кнопка "Fetch cert pin" на Security tab (Hysteria + TLS + certificateFile only); результат кэшируется в `ShareMaterialStore` (`merge_cert_pin`, новое поле `InboundShareMaterial.cert_pin_sha256` / sidecar `certPinSha256`) — не блокирует Copy share URI, pin просто отсутствует пока не выбран Fetch
- Host = Connection host; port = inbound port (или `port_hop` для hy2); Reality: `pbk`/`sid`/`sni`/`fp=chrome`/`spx=/`.
- `pbk`: session Generate → `ShareMaterialStore` → local fallback (`x25519_local::public_key_from_private_key`, derives `pbk` from `realitySettings.privateKey`, no SSH round-trip; result cached back into `ShareMaterialStore`). Client `encryption` — только из Generate / `ShareMaterialStore` (нет local fallback).
- QR code (Roadmap §3:122): «Show QR code» рядом с «Copy share URI» во всех 3 Users context menus (VLESS/Trojan/Hysteria) — открывает независимое от Add/Edit/Delete окно (своя temp-data запись, `qr_dialog_id`) с QR + read-only полем URI + Copy. Рендер — `gui::pages::qr_code(ui, data)`: `qrcode::QrCode::new` (crate `qrcode = "0.14.1"`, `default-features = false` — без `image`/`svg`/`pic`) → модули рисуются painter'ом напрямую как залитые прямоугольники (без текстур), с обязательной 4-модульной quiet-zone по краям (требование стандарта QR); при encode-ошибке (теоретически возможно для очень длинных `extra=`/hy2 URI) возвращает `Err` вместо паники, диалог показывает текст ошибки вместо QR.
- Fallbacks не входят в share URI (server-side only). grpc `authority` и plain-TLS `fp` сознательно не входят: `authority` не смоделирован в `GrpcStreamSettings` (новый редактор — вне scope §3:121); `fp` для TLS не имеет серверного источника и функционально не нужен вне Reality.

## 34.10	Field help overlays (Roadmap §3:124)
Круглая кнопка «h» слева от подписи поля → `egui::Window` с текстом + явной кнопкой Close (плюс штатный крестик окна). Общие виджеты в `gui::pages::mod.rs`, не завязаны на конкретную страницу:
- `help_button(ui, title, help_text)` — сама кнопка; клик кладёт `(title, help_text)` в `egui::Id`-temp-data (`field_help_dialog`).
- `field_label(ui, text, help_text)` — `help_button` + `ui.label(text)` в одном `ui.horizontal`; drop-in замена голого `ui.label(...)` в Grid-формах (одна ячейка Grid = один `horizontal`, как и в остальном коде).
- `show_help_dialog(ui)` — рендерит текущее (последнее нажатое) окно помощи; вызывается один раз в конце `inbounds.rs::show()`, поэтому работает из любой вкладки/диалога. Единое состояние на страницу — второй клик по другой кнопке заменяет предыдущее окно, а не открывает второе.

Объём (сознательно ограничен после уточнения с пользователем): только Inbound Shell editor — General / Protocol (VLESS decryption+vlessenc, fallbacks, Hysteria version, Tunnel incl. portMap/sockopt.tproxy) / Stream (method + tcp + XHTTP + gRPC + WS + mKCP + Hysteria quicParams + FinalMask + Sockopt) / Security (mode + TLS + certificates[] + Reality + limitFallback) / Sniffing — суммарно ~90 полей/групп в `inbounds.rs`. Read-only-представления (view-режим, таблицы) кнопок не получили — только формы редактирования. Остальные страницы приложения (Outbounds/DNS/Routing/Policy/FakeDNS/Observatory/…) — задел на будущее, не покрыты.

Источник текста: https://xtls.github.io/config/ — прямые WebFetch-запросы к живым страницам (`inbound.html`, `sniffing`-раздел, `inbounds/vless.html`, `inbounds/tunnel.html`, `features/fallback.html`, `transports/{hysteria,tls,reality,sockopt,websocket,mkcp}.html`), процитировано и сжато до 1–3 предложений на поле. Исключение — `transports/xhttp.html`: страница отдаёт клиентский JS-рендер, статический fetch не содержит таблиц полей (только заголовок). Текст для XHTTP написан по собственным знаниям + doc-комментариям уже реализованной типизированной модели (`inbound_stream/xhttp.rs`) — не дословная цитата сайта. Для самых сложных XHTTP-групп (Padding/SSE/gRPC, packet/stream-тюнинг, Placement/obfuscation, XMUX, downloadSettings) справка дана на уровне collapsing-заголовка секции (`xhttp_spoiler_header` получил параметр `help_text`), а не на уровне каждого из ~20 отдельных под-полей; Basic (host/path/mode) и Headers покрыты индивидуально.

## 34.11	Raw JSON escape hatch (Roadmap §3:125)
Формулировка бэклога не задавала объём — уточнено с пользователем: редактор целого inbound/outbound объекта как raw JSON, а не только "extras"-полей и не всего config-файла.

- `editable.rs::replace_inbound_value(inbound_index, new_value)` — новый метод, гейт `locate_inbound` (не `require_shell_editable_inbound`) → работает для любого протокола, включая Shadowsocks/VMess/HTTP/Socks/WireGuard/TUN/legacy `dokodemo-door`, у которых иначе нет вообще никакого редактора (только Delete). Валидирует `is_object`, синхронизирует и `sections`, и `file_roots`, по образцу уже существующего `with_tier2_inbound_mut`. Для outbound переиспользован уже существующий `replace_outbound_value` (сам валидирует object + уникальность tag) — нового метода в editable.rs не потребовалось.
- `modify.rs::replace_inbound_raw_json`/`replace_outbound_raw_json` — оркестрация: locate → (опционально) fingerprint-сверка через `inbound_object_fingerprint`/`outbound_object_fingerprint` → для inbound `validate_no_duplicate_inbound_tag` (уже существовавшая private-функция, переиспользована) → `replace_*_value` → `finish_modification`/`finish_outbound_modification`. Тот же pipeline, что у `delete_inbound`/`rename_outbound_tag`.
- Async workers — `inbound_ops.rs::run_replace_inbound_raw_json` (мутация → connect → `verify_remote_tls_cert_paths` — как в `run_add_inbound`, raw JSON может содержать любой `tlsSettings.certificates` путь → write → disconnect) и `outbound_ops.rs::run_replace_outbound_raw_json` (без TLS-шага — outbound-протоколы не обслуживают TLS-сертификаты со стороны сервера, тот же паттерн, что `run_rename_outbound_tag`).
- `ApplicationService`: `inbound_raw_json_view`/`outbound_raw_json_view` (pretty-printed JSON + fingerprint для текущего объекта) и `start_replace_inbound_raw_json`/`start_replace_outbound_raw_json` (парсинг текста → `serde_json::Value`, ранняя ошибка на невалидный JSON/не-объект до какой-либо сетевой активности → spawn thread, тот же async-паттерн, что у остальных мутаций). Новые `CurrentOperation::ReplacingInboundRawJson`/`ReplacingOutboundRawJson`.
- GUI, Inbounds (`inbounds.rs`): новая вкладка «Raw JSON» в detail pane (`InboundDetailTab::RawJson`) — единственная вкладка помимо General/Sniffing, доступная без гейта `shell_ok` (Stream/Security/Users по-прежнему гейтятся). Локальное состояние `RawJsonEditState` намеренно не встроено в типизированный `InboundEditorSession` — это самостоятельное действие, не Shell Save.
- GUI, Outbounds (`outbounds.rs`): у страницы нет вкладок/detail pane (только Add/Edit-сессия для Freedom/Blackhole/DNS) — вместо вкладки пункт «Raw JSON» в контекстном меню строки (доступен всегда, не только когда `row.kind()` — Freedom/Blackhole/DNS), открывающий отдельное modal-окно `show_raw_json_outbound_dialog` (тот же `PendingOutboundRename`-паттерн: state в `egui::Id`-temp-data, `closed`-флаг, Save/Cancel).
- Save в обоих случаях оптимистично закрывает форму при `Ok(())` от `start_replace_*` (тот же UX, что у Rename Outbound) — реальный успех/провал приходит асинхронно через статус-бар (`poll_inbound_mutation`/`poll_outbound_mutation`, новые match-ветки на `InboundMutationSuccess::RawJson`/`OutboundMutationSuccess::RawJson`).
- Тесты: `modify_tests` (`replace_inbound_raw_json_replaces_whole_object`, `replace_inbound_raw_json_works_for_unsupported_protocol`, `replace_inbound_raw_json_fingerprint_mismatch`, `replace_inbound_raw_json_rejects_non_object`, `replace_inbound_raw_json_rejects_duplicate_tag`, `replace_outbound_raw_json_replaces_whole_object`, `replace_outbound_raw_json_fingerprint_mismatch`).

## 34.12	Тесты и QA
- Unit: `modify_tests` (Vision+xhttp G3, Reality round-trip, Trojan Add Reality, Hysteria user add/update/delete, Tunnel add/shell save/`from_wire`/`dokodemo-door` None, `wave_c2_*` fallbacks require ALPN + WS strip, `finalmask_tcp_ok_with_tls_security` / `finalmask_tcp_blocked_by_g4_with_reality_security`); `inbound_fallbacks` (dest variants, extras round-trip, strip, TLS/Reality require ALPN, path validate, transport matrix); `inbound_protocol` (Tunnel parse/apply round-trip, `portMap` target forms); `inbound_security` (полный TLS parse/apply/round-trip/strip, multi-entry certificates, Reality alpn, Reality advanced fields round-trip (`parse_reality_reads_advanced_fields` / `apply_reality_roundtrip_advanced_fields`), unknown hard-fail); `compatibility` + `matrix` (G9/G10/G12 multi-entry + PEM + verify-without-key Save, G11, G4 top-level `finalmask.tcp` path (+ nested-shape no-false-positive + empty/absent pass), `tunnel` tcp×none, `allowed_*` / `selectable_*` / WS/mKCP coerce, `websocket×reality` / `mkcp×reality`); `share_uri` (hy2 + TLS + WS/mKCP TLS / reject none + XHTTP extra=); `inbound_stream` (ws alias→websocket, kcp alias→mkcp, full `kcpSettings` defaults/write, xhttp defaults/write/validate/download/extra, range validate, path↔ed, drop old `*Settings`, `finalmask` submodule: parse/apply/validate `tcp[]`/`udp[]` layers + malformed-shape fallback + quicParams-sibling preservation, `sockopt` submodule: known-fields+extras parse, `tcpFastOpen` bool/backlog/unset/unrecognized-shape, `customSockopt`/`happyEyeballs` valid/invalid-shape, full round-trip, default→`{}`; `inbound_stream` parse/apply: write-flag set on valid object / stays false + raw preserve on malformed shape / unknown future field survives edit-unrelated-field cycle) / protocol; `app/users` (`selected_users_protocol`, `hysteria_row_display`); `modify_tests` (`sockopt_shell_save_edits_field_and_preserves_unknown_field`, `tunnel_shell_save_edits_tproxy_and_preserves_other_stream_fields` — full `update_inbound_shell` round-trip via `apply_tunnel_sockopt`; existing `tunnel_shell_save_preserves_stream_and_unknown_settings` re-verified unaffected for the untouched/`write_sockopt=false` case); `inbound_stream` (`apply_tunnel_sockopt_noop_when_not_edited` / `apply_tunnel_sockopt_writes_only_sockopt_key` / `apply_tunnel_sockopt_creates_stream_settings_when_absent`); `x25519_local` (`derives_fixture_public_key`, `rejects_empty_and_bad_length`); `app/service` (`vless_share_uri_derives_pbk_from_private_key_without_ephemeral`, `preview_add_user_diff_redacts_and_does_not_mutate`, `preview_update_user_diff_shows_email_change_without_mutating`); `xray/cert_pin` (PEM/DER hashing, first-cert-of-chain, empty-input reject, Roadmap §3:121); `inbound_edit/general` (`port_hop_syntax_*`, `first_hop_port_*`); `inbound_stream/finalmask` (`salamander_obfs_password_*`); `share_uri` (`builds_hy2_with_port_hop` / `_with_salamander_obfs` / `_with_pin_sha256` / `_ignores_blank_optional_fields`, `builds_vless_tls_ws` alpn assertion); `app/share_material` (`merge_cert_pin_stores_and_ignores_blank`, `roundtrip_json` extended for `certPinSha256`); `app/inbound_ops` (`stale_tag_references_*`). FinalMask этап 0 (shape-preserving значения, «без потерь или raw», GUI-draft'ы на реальных кадрах egui, некритичные предупреждения) — §62.7.
- Ручной QA: eng-review test plan `~/.gstack/projects/Feldjaeger/*eng-review-test-plan*`; `docs/ui.md`; Hysteria shell + Users CRUD — enabled (Wave A complete для §2.2:69); Tunnel shell — Roadmap §2.2:70; WebSocket Stream — Roadmap §2.3:80; mKCP Stream — Roadmap §2.3:81; XHTTP advanced — Roadmap §2.3:82; Shared fallbacks — Roadmap §2.3:83; TLS advanced — Roadmap §2.3:84; Multi-entry certificates + remote path check — Roadmap §2.3:85 / §2.5:104; REALITY advanced + FinalMask editor — Roadmap §2.3:86; Sockopt editor — Roadmap §2.3:87; Tunnel tproxy follow-up — Roadmap §2.3:88.

## 34.13	Документация
- Этот раздел; §32–§33 (слои); `docs/ui.md`; `docs/Feldjaeger Roadmap.md` — Wave 0 + Wave A (incl. Hysteria Users) + Tunnel shell + Wave C1 WebSocket + mKCP + Wave C2 fallbacks + Wave C3 XHTTP + TLS advanced + multi-entry certificates / remote SFTP probe + REALITY advanced fields + FinalMask `tcp[]`/`udp[]` editor (§2.3:86) + Sockopt editor (§2.3:87) + Tunnel tproxy follow-up (§2.3:88) shipped; C1 remainder (httpupgrade) + Waves B–D backlog; outbound `sockopt` GUI (typed, but no widget yet — §34.1 backlog) остаётся вне scope §35 (Freedom не трогает `streamSettings`). FinalMask — полная реализация (Roadmap §2.6): этап 0 (0.1–0.3) — §62; остальные этапы — backlog Roadmap §2.6.

# 35	Outbounds Shell: Freedom + Blackhole (Roadmap §2.4:94, §2.4:95)

## 35.1	Цель и границы

Первый Outbound Shell в Feldjäger — до этого outbounds были read-only таблицей + Delete UI (§2.4:97) + внутренний mutate API, используемый только Cloudflare WARP (§31) для собственного managed WireGuard outbound. §2.4:94 добавил Add / Edit General + Protocol для Freedom (`protocol: "freedom"`); §2.4:95 расширил тот же механизм на Blackhole (`protocol: "blackhole"`) — второй, структурно куда более простой shell-editable outbound-протокол.

- В scope (shipped):
  - Add / Edit Freedom outbound (поля Protocol пересмотрены по документации в §66: `domainStrategy` → `streamSettings.sockopt.domainStrategy`, + `proxyProtocol`, `finalRules[]`): `tag` (rename запрещён на Edit — см. §35.4), `sendThrough`, Protocol: `domainStrategy` (reuse `DOMAIN_STRATEGIES` пресетов из `streamSettings.sockopt.domainStrategy` — тот же список значений, другое расположение в JSON), `redirect`, `userLevel`, `fragment` (`packets`/`length`/`interval`, toggle-able блок), `noises[]` (`type`/`packet`/`delay`, add/edit/delete таблица; пресеты `rand`/`str`/`hex`/`base64`) — §2.4:94
  - Add / Edit Blackhole outbound: `tag`/`sendThrough` (то же General, что и Freedom), Protocol: `response.type` (`none`|`http`, combo+free-text; пусто = ключ `response` отсутствует целиком = Xray default `none`) — §2.4:95
  - Общий General слой (`OutboundGeneral`/`OutboundRef`/`outbound_edit`) и общий Add/Edit/Save GUI-каркас (`OutboundEditorSession`) переиспользуются между протоколами без дублирования — только `OutboundSettingsDraft` ветвится по протоколу (`Freedom { .. }` / `Blackhole { .. }`)
  - Fingerprint-checked Shell Save (мирроринг inbound `InboundRef`/`with_inbound_mut`, но через clone-mutate-`replace_outbound_value` вместо отдельного `with_outbound_mut` — см. §35.3), общий для обоих протоколов
  - Delete (уже было, §2.4:97) — без изменений
- Вне scope / backlog на момент реализации:
  - DNS outbound Shell (§2.4:96, реализован — см. §36)
  - Outbound Duplicate UI (§2.4:98, реализован — см. §37)
  - Outbound tag rename + routing/`balancerselector` ref-check (§2.4:99, реализован — см. §37) — Shell Save по-прежнему жёстко запрещает смену tag (переиспользует `replace_outbound`'s "replacement outbound tag must match the target tag" guard); rename живёт как отдельное действие
  - `streamSettings.sockopt` / `mux` / `proxySettings` editors для Freedom/Blackhole — не в scope этих пунктов (roadmap явно называет только fragment/noises для Freedom и ничего сверх response для Blackhole); поля сохраняются как есть при Shell Save (см. §35.3 preserve-invariant)
  - IB-L5-style JSON Preview для outbound Shell

## 35.2	Модель

Два модуля под `src/xray/config/`, следуя ровно тому же threading-паттерну, что и `inbound_edit`/`inbound_protocol` (General отдельно от Protocol), расширенные под §2.4:95 без структурных изменений — Blackhole лёг в тот же `enum`/dispatch, что и Freedom:

| Область | Путь |
| ------- | ---- |
| General | `outbound_edit/mod.rs` — `OutboundGeneral { tag, send_through }`, `OutboundRef { outbound_index, expected_fingerprint }` (мирроринг `InboundRef`, без typed protocol-поля — протокол не влияет на General); `parse_outbound_general` / `apply_outbound_general`. Общий для Freedom и Blackhole без изменений с §2.4:94 |
| Protocol | (Freedom с §66 — `OutboundSettingsDraft::Freedom(FreedomSettingsDraft)` в `outbound_protocol/freedom.rs`) `outbound_protocol/mod.rs` — `OutboundSettingsDraft::Freedom { domain_strategy, redirect, user_level, fragment: Option<FragmentDraft>, noises: Vec<NoiseDraft> }` и `OutboundSettingsDraft::Blackhole { response_type: String, response_extras: Map<String, Value> }`; `FragmentDraft`/`NoiseDraft` — typed + `extras: Map<String, Value>` каждый (per-entry unknown-key preserve, тот же паттерн что `FallbackObject`); Blackhole хранит extras флэт (`response_extras`) вместо отдельного draft-struct — `response` содержит только `type` по документации, отдельная struct была бы избыточной; `is_shell_editable_protocol(protocol: &str) -> bool` — единый источник истины для списка shell-editable протоколов (`freedom`, `blackhole`), используется и в `validate_outbound_object`, и в `ApplicationService::build_outbound_ref`; `ensure_settings_object` — private twin инбаундового хелпера (settings живёт в отдельном JSON location у outbound, поэтому не шарится) |
| Mutate API | `modify.rs`: `AddOutboundShellRequest` / `add_outbound_shell` (строит skeleton `{"protocol": <из draft>, "settings":{}}` — protocol строка выводится из `OutboundSettingsDraft`-варианта через `outbound_settings_protocol_name`, применяет General+Protocol, делегирует в существующий `add_outbound`); `UpdateOutboundShellRequest` / `update_outbound_shell` (fingerprint-check по индексу через `outbound_object_fingerprint`, clone текущего outbound `Value`, apply General+Protocol in place на клоне — preserve любых нетронутых ключей типа `mux`/`streamSettings`/`proxySettings`/неизвестных `settings`-полей — затем делегирует в существующий `replace_outbound` по исходному tag, что и даёт rename-guard бесплатно). Обе функции протокол-агностичны — Blackhole не потребовал изменений сигнатур |
| Validation gate | `validate_outbound_object` (`modify.rs`) ослаблен: принимает `protocol` `"wireguard"` или `is_shell_editable_protocol(...)` (`"freedom"`/`"blackhole"`) |

`apply_outbound_settings`/`apply_outbound_general` не пересобирают весь `settings`/outbound объект с нуля — трогают только известные top-level ключи (как `apply_tunnel_protocol`), поэтому preserve-unknown работает структурно. Вложенные `fragment`/`noises[]`/`response` пересобираются из typed-полей на каждый Save — отсюда per-entry `extras` у `FragmentDraft`/`NoiseDraft`/Blackhole `response_extras`, чтобы не терять будущие поля Xray. Для Blackhole: если `response_type` пусто и `response_extras` пусто — ключ `response` целиком удаляется (Xray default `none`); если extras непусты, но `type` не задан — `response` всё равно пишется (без `type`), чтобы не терять неизвестные поля.

Ссылки: <https://xtls.github.io/en/config/outbounds/freedom.html>, <https://xtls.github.io/en/config/outbounds/blackhole.html>. `noises[].type`: `rand` | `str` | `hex` | `base64`; `response.type`: `none` | `http` (документированные значения; свободный текст тоже принимается для обоих).

## 35.3	Concurrency safety (fingerprint) — без нового `with_outbound_mut`

В отличие от inbound Shell Save (`EditableXrayConfig::with_inbound_mut`), для outbound не заведён отдельный closure-based in-place mutate primitive. Вместо этого `update_outbound_shell` (общий для Freedom и Blackhole):
1. `locate_outbound` + `outbound_object_fingerprint` → hard fail `FingerprintMismatch` при несовпадении (тот же `ConfigModifyErrorKind`, что и `delete_outbound`, который уже поддерживал опциональный fingerprint-check по индексу).
2. Клонирует полный outbound `Value`, мутирует клон через `apply_outbound_general`/`apply_outbound_settings`.
3. Делегирует запись в уже существующий `replace_outbound` (tag-based lookup + `validate_outbound_object` + `replace_outbound_value`) — `replace_outbound_value` уже корректно исключает сам себя из tag-conflict проверки (`index == location.outbound_index`), так что редактирование без смены tag не ловит ложный `OutboundTagConflict`.

Итог: тот же уровень defence-in-depth, что у inbound Shell Save, без дублирования `with_inbound_mut`-подобной инфраструктуры под outbound.

## 35.4	GUI (`src/gui/pages/outbounds.rs`)

- "Add Outbound" — теперь `ui.menu_button` с двумя пунктами, Freedom и Blackhole (было: единственная кнопка под Freedom в §2.4:94), каждый вызывает свой `ApplicationService::begin_add_outbound_freedom()`/`begin_add_outbound_blackhole()` (оба тонкие обёртки над общим приватным `begin_add_outbound(settings)`).
- Контекстное меню строки: Edit активен, когда `row.kind()` — `OutboundKind::Freedom` или `OutboundKind::Blackhole` (иначе disabled hint "Shell editing is available for Freedom and Blackhole outbounds only"); Delete — без изменений (§2.4:97); Duplicate — по-прежнему disabled (§2.4:98, backlog).
- Единая панель редактора (без вкладок — ни Freedom, ни Blackhole не используют Stream/Security/Sniffing/Users), заголовок и подпись Protocol-секции подставляют имя протокола динамически (`outbound_protocol_label`, выведено из активного варианта `OutboundSettingsDraft`): General grid (`tag` — editable только на Add, на Edit — read-only label с hover-подсказкой про §2.4:99; `sendThrough`) → Protocol-секция диспетчеризуется по варианту:
  - Freedom (с §66: `sockopt.domainStrategy`, `proxyProtocol`, `finalRules[]`, предупреждения + «Migrate to sockopt»): `domainStrategy` combo+free-text, `redirect`, `userLevel` DragValue, `fragment` toggle + 3-поле grid, `noises` add/edit/delete таблица (combo `type` из `FREEDOM_NOISE_TYPES` + `packet`/`delay` text fields)
  - Blackhole: `response.type` combo (`BLACKHOLE_RESPONSE_TYPES` = `none`/`http`) + free-text
  → Save/Cancel.
- `ApplicationService`: `outbound_editor_session()`/`_mut()`, `begin_add_outbound_freedom()`, `begin_add_outbound_blackhole()`, `begin_edit_outbound_shell(index)` (протокол-агностичен — гейтится через `is_shell_editable_protocol`), `cancel_outbound_editor_session()`, `start_add_outbound_shell()`, `start_save_outbound_shell()`; `is_outbound_mutation_busy()` расширен на `CurrentOperation::AddingOutbound`/`UpdatingOutboundShell`; `poll_outbound_mutation()` получил match-ветки на `OutboundMutationSuccess::Add`/`Update` (очищают `outbound_editor_session`, вызывают `replace_loaded_editable`) — ни один из этих методов не потребовал изменений под §2.4:95, кроме нового `begin_add_outbound_blackhole()`.
- Worker-слой: `src/app/outbound_ops.rs` — `OutboundEditorSession` (мирроринг `InboundEditorSession`, но без Stream/Security/Sniffing/keygen-полей), `run_add_outbound_shell`/`run_update_outbound_shell` (тот же connect → write → disconnect паттерн, что `run_delete_outbound`, но без TLS remote-path probe шага — ни у Freedom, ни у Blackhole нет сертификатов); протокол-агностичны, без изменений под §2.4:95.
- Raw JSON escape hatch (Roadmap §3:125, детали — §34.11): контекстное меню строки получило пункт «Raw JSON» — доступен для любого протокола (не только Freedom/Blackhole/DNS), открывает modal-окно с полным JSON outbound-объекта; Save заменяет объект целиком через `replace_outbound_raw_json`.

## 35.5	Тесты
- `outbound_edit` (parse/apply roundtrip, empty-fields omit, sibling preserve) — общий для обоих протоколов.
- `outbound_protocol`: Freedom — `freedom_parse_apply_roundtrip_preserves_unknown` (top-level + `fragment` + `noises[]` unknown-field preserve), `apply_omits_default_fields`, `apply_rejects_noise_with_empty_type`, `non_freedom_protocol_is_not_parsed`; Blackhole — `blackhole_parse_apply_roundtrip_preserves_unknown` (top-level + `response` unknown-field preserve), `blackhole_apply_omits_default_response`, `blackhole_apply_keeps_extras_only_response` (extras без `type` всё равно пишутся).
- `modify_tests`: Freedom — `add_freedom_outbound_shell_writes_settings`; `update_freedom_outbound_shell_edits_settings_and_preserves_unrelated_fields` (`mux` + unknown `settings` field survive Shell Save); `update_freedom_outbound_shell_fingerprint_mismatch_rejected`; `update_freedom_outbound_shell_rejects_tag_rename`. Blackhole — `add_blackhole_outbound_shell_writes_settings`; `update_blackhole_outbound_shell_edits_settings_and_preserves_unrelated_fields` (fingerprint/tag-rename тесты не дублированы — эта логика протокол-агностична и уже покрыта Freedom-тестами).
- Ручной QA: `docs/ui.md`; Roadmap §2.4:94, §2.4:95.


# 36	Outbounds Shell: DNS (Roadmap §2.4:96)

## 36.1	Цель и границы

Третий и последний Outbound Shell из «рекомендованного» набора §2.4 (после Freedom/Blackhole, §35) — `protocol: "dns"`. В отличие от Freedom/Blackhole это не proxy-протокол, а rule-based DNS query rewriting/forwarding outbound: принимает DNS-трафик, направленный на него из routing (TUN / transparent proxy / tunnel inbound сценарии), и опционально переписывает транспорт/адрес/порт цели и/или фильтрует запросы по упорядоченным правилам. Поддерживает только классический UDP/TCP DNS — без DoH/DoT/DoQ.

Источник истины (см. `docs/rules.md`) — официальная документация Xray, проверена через Context7 (`/websites/xtls_github_io_ru`) и WebFetch <https://xtls.github.io/ru/config/outbounds/dns.html> на момент реализации: актуальная схема — `rewriteNetwork`/`rewriteAddress`/`rewritePort`/`userLevel`/`rules[]` (не более старая гипотетическая `network`/`address`/`port`/`nonIPQuery`/`blockTypes` схема, которой в текущей Xray-core документации нет).

- В scope (shipped):
  - Add / Edit DNS outbound: General — то же `tag`/`sendThrough`, что у Freedom/Blackhole (rename запрещён на Edit, как и у остальных, см. §35.3/§35.4); Protocol — `rewriteNetwork` (`tcp`|`udp`, combo+free-text), `rewriteAddress`, `rewritePort` (1-65535, валидируется), `userLevel`, `rules[]` — упорядоченный список (порядок значим — первое совпадение побеждает): `action` (`direct`|`hijack`|`drop`|`return`, combo+free-text, обязателен), `qType` (свободный текст: целое число, диапазон или comma-list вида `"11,13,15-17"`), `rCode` (0-65535, актуален для `action=return`), `domain` (список доменных матчеров routing-синтаксиса, одна строка на GUI-запись)
  - Add/Remove/Move up/down для `rules[]` (порядок значим — тот же UX-паттерн, что и у FinalMask layer-list editor, §34)
  - DNS добавлен в `is_shell_editable_protocol` → Edit разблокирован в контекстном меню строки outbound; General/Save/fingerprint/tag-rename-guard/routing-tag-ref delete-block переиспользованы без изменений (протокол-агностичны, см. §35.2-§35.3)
  - Read-only Summary колонка для `OutboundKind::Dns` (была `"Summary unavailable"`) — теперь `"Rewrite: {address}[:{port}]"`, либо `"N rule(s)"`, либо `"Default (A/AAAA → internal DNS)"`
- Вне scope / backlog на момент реализации:
  - Outbound Duplicate UI (§2.4:98, реализован — см. §37) — на момент §36 по-прежнему disabled для всех протоколов
  - Outbound tag rename + routing/`balancer.selector` ref-check (§2.4:99, реализован — см. §37) — на момент §36 DNS наследовал тот же жёсткий запрет смены tag, что Freedom/Blackhole

## 36.2	Модель

Расширение тех же модулей, без новых файлов:

| Область | Изменение |
| ------- | --------- |
| Protocol draft | `outbound_protocol/mod.rs` — `OutboundSettingsDraft::Dns { rewrite_network, rewrite_address, rewrite_port: String, user_level: u64, rules: Vec<DnsRuleDraft> }`; `DnsRuleDraft { action, q_type: String, r_code: u32, domain: Vec<String>, extras: Map<String, Value> }` (per-entry unknown-key preserve, тот же паттерн что `NoiseDraft`); `dns_default()`; константы `DNS_RULE_ACTIONS` (`direct`/`hijack`/`drop`/`return`), `DNS_REWRITE_NETWORKS` (`tcp`/`udp`) |
| Parse/apply | `parse_dns_settings`/`parse_dns_rule` — верхнеуровневые ключи читаются без отдельного extras-поля (как у Freedom: `apply_dns_settings` мутирует существующий `settings`-объект на месте, трогая только известные ключи, поэтому непойманные поля переживают Save структурно, без явного round-trip хранилища); `rules[]` пересобирается с нуля на каждый Save (как `noises[]`) — отсюда `extras` именно на уровне `DnsRuleDraft` |
| Числовые поля со смешанным wire-типом | `rewritePort`/`qType` документированы Xray как «число ИЛИ строка» (диапазоны/comma-list у `qType`). Чтение — `numeric_or_string_field` (JSON Number → `to_string()`, JSON String → как есть) в единое текстовое draft-поле. Запись: `rewritePort` — `apply_optional_port` парсит как `1..=65535`, пишет `Value::Number`, иначе `ValidationFailed`; `qType` — `apply_qtype` пишет `Value::Number`, если текст — «чистое» целое без разделителей, иначе `Value::String` (диапазоны/списки/будущий синтаксис не теряются) |
| Validation | `validate_dns_rules` — Save блокируется, если у любого правила пуст `action` (обязателен по документации Xray) либо `rCode > 65535` (то же место, что `validate_freedom_noises`) |
| Wire protocol name | `outbound_settings_protocol_name` (`modify.rs`) — новая ветка `Dns { .. } => "dns"` |
| Validation gate | `is_shell_editable_protocol` (`outbound_protocol/mod.rs`) — добавлено `"dns"`; `validate_outbound_object`-сообщение об ошибке обновлено (перечисляет `wireguard`/`freedom`/`blackhole`/`dns`) |
| Read summary | `outbound_description` (`summary.rs`) — `OutboundKind::Dns` вынесен из catch-all в собственную ветку |

Ссылка: <https://xtls.github.io/en/config/outbounds/dns.html> (см. также ru-версию, использованную как основной источник в момент реализации). `rules[].action`: `direct` | `hijack` | `drop` | `return` (документированные значения; свободный текст тоже принимается — совместимость с будущими Xray-версиями).

## 36.3	GUI (`src/gui/pages/outbounds.rs`)

- "Add Outbound" — третий пункт меню, DNS, вызывает `ApplicationService::begin_add_outbound_dns()` (тонкая обёртка над общим `begin_add_outbound`, как у Freedom/Blackhole).
- Контекстное меню строки: Edit активен для `OutboundKind::Freedom` | `Blackhole` | `Dns` (disabled-hint обновлён).
- `outbound_protocol_label` / settings-edit dispatch — новая ветка `Dns { .. } => "DNS"` / `show_dns_settings_edit`.
- `show_dns_settings_edit`: grid `rewriteNetwork` (combo+free-text) / `rewriteAddress` / `rewritePort` / `userLevel` (DragValue) → `show_dns_rules_edit` — на каждое правило: `ui.group` с заголовком `rule[i]` + Up/Down/Remove, grid `action` (combo+free-text) / `qType` (free-text с hover-подсказкой про формат) / `rCode` (DragValue 0..=65535), затем multiline `domain` (`egui::TextEdit::multiline`, одна строка = один матчер, тот же UX, что `trustedXForwardedFor` в Sockopt editor, §2.3:87) → "Add rule" в конце списка.
- `ApplicationService::begin_add_outbound_dns()` — единственный новый публичный метод; `begin_edit_outbound_shell`/`build_outbound_ref`/`start_add_outbound_shell`/`start_save_outbound_shell`/worker-слой (`src/app/outbound_ops.rs`) не потребовали изменений — все протокол-агностичны с §35.

## 36.4	Тесты
- `outbound_protocol`: `dns_parse_apply_roundtrip_preserves_unknown` (top-level `settings` + per-rule unknown-field preserve), `dns_apply_omits_default_fields`, `dns_apply_rejects_rule_with_empty_action`, `dns_qtype_numeric_vs_string_round_trip` (число vs диапазон/список пишутся как Number/String соответственно), `dns_apply_rejects_invalid_rewrite_port`, `dns_protocol_is_parsed`.
- `modify_tests`: `add_dns_outbound_shell_writes_settings`; `update_dns_outbound_shell_edits_settings_and_preserves_unrelated_fields` (`mux` + unknown `settings` field survive Shell Save); `update_dns_outbound_shell_fingerprint_mismatch_rejected`; `update_dns_outbound_shell_rejects_tag_rename` (fingerprint/tag-rename логика протокол-агностична — уже покрыта Freedom-тестами в §35.5, DNS-тесты подтверждают, что новый протокол корректно через неё проходит).
- Ручная сборка: `cargo build --workspace`, `cargo test --workspace` (654/663 pass; 9 pre-existing fixture-path failures на этой машине не связаны с изменением — воспроизводятся и на чистом `main`), `cargo clippy --workspace --all-targets` (0 новых warning в затронутых файлах).
- Ручной QA: `docs/ui.md`; Roadmap §2.4:96.


# 37	Outbound Duplicate + Rename (Roadmap §2.4:98, §2.4:99)

## 37.1	Цель и границы

Последние два пункта §2.4 Outbounds после трёх Shell-протоколов (§35, §36) и Delete (§2.4:97, до §35). Оба действия — прямые аналоги уже существующих inbound-фич (`duplicate_inbound`, backlog inbound tag rename), но с продуктовыми развилками, специфичными для outbound: Duplicate гейтится так же строго, как inbound-версия (только shell-editable протоколы), а Rename — наоборот, шире Delete и Duplicate: доступен для любого протокола и никогда не блокируется routing/`balancer.selector`-ссылками, только предупреждает.

- В scope (shipped):
  - Duplicate (§2.4:98) — deep-copy outbound-объекта с уникальным `{tag}-copy[-N]` тегом в тот же source file; доступен только для `OutboundKind::Freedom`/`Blackhole`/`Dns` (тех же протоколов, что `is_shell_editable_protocol`) — по аналогии с `duplicate_inbound`, который тоже гейтится через `require_shell_editable_inbound`, хотя сам по себе дублирование не требует протокол-специфичной логики. Срабатывает сразу по клику в контекстном меню, без confirm-диалога — тот же UX, что у Inbound Duplicate (§34)
  - Rename (§2.4:99) — отдельное действие в контекстном меню строки outbound, доступное для любого протокола (не только shell-editable — переименование тега не завязано на понимание protocol-specific `settings`). Диалог показывает текущий тег, поле для нового тега и preview затронутых routing rules/`balancer.selector` записей, вычисленный локально (без похода на сервер) ещё до отправки формы. Rename никогда не блокируется этими ссылками — только предупреждает и после успешного переименования, и заранее в preview (v1-scope, то же решение, что уже описано как план для inbound tag rename в Roadmap — «warn + list, hard-block позже»)
  - Shell Save (`update_outbound_shell`, §35/§36) не получил возможность менять tag — guard `replace_outbound`'а («replacement outbound tag must match the target tag») сохранён намеренно; переименование теперь всегда идёт через отдельное Rename-действие, а не через Edit-форму
- Вне scope:
  - Автоматическое переписывание найденных routing rule `outboundTag` / `balancer.selector` записей на новый tag — Rename оставляет их as-is, пользователь правит routing вручную (см. текст предупреждения)
  - Hard-block переименования при наличии ссылок — сознательно не реализован в v1 (см. выше)

## 37.2	Модель (`src/xray/config/modify.rs`)

| Функция / тип | Назначение |
| -------------- | ---------- |
| `DuplicateOutboundRequest { outbound_index }` | Запрос на дублирование по merged-индексу |
| `duplicate_outbound(config, request)` | `locate_outbound` → протокол-гейт через `is_shell_editable_protocol` (`ValidationFailed`, если протокол не Freedom/Blackhole/DNS) → deep-clone `Value` → `unique_outbound_copy_tag` → `validate_outbound_object` → `config.add_outbound_value(clone, Some(&source_file))` в тот же файл — структурно один в один `duplicate_inbound` (§34), с той разницей, что уникальность тега проверяется через уже существующий `config.outbound_tag_taken()` (case-insensitive), а не ручным сканированием, как у `unique_inbound_copy_tag` |
| `unique_outbound_copy_tag(config, base)` | `{base}-copy` → `{base}-copy-2` → … → UUID-fallback, тот же алгоритм, что `unique_inbound_copy_tag`, но на `outbound_tag_taken` |
| `RenameOutboundTagRequest { outbound_index, expected_fingerprint: Option<String>, new_tag }` | Форма запроса — намеренно повторяет `DeleteOutboundRequest` (прямое действие по индексу), а не `OutboundRef` (Shell Save-сессия), потому что Rename не привязан к `is_shell_editable_protocol`-гейту, который использует `build_outbound_ref` |
| `RenameOutboundOutcome { outcome, old_tag, new_tag, stale_references }` | Помимо стандартного `ModifyConfigOutcome` — старый/новый тег и список ссылок, которые останутся указывать на старый тег после переименования |
| `rename_outbound_tag(config, request)` | `locate_outbound` → опциональный fingerprint-check (как `delete_outbound`) → читает текущий `tag` (`ValidationFailed`, если пуст — переименовывать нечего) → `normalize_outbound_tag(new_tag)` (существующий приватный helper, уже использовался `replace_outbound`/`remove_outbound`) → до мутации считает `stale_references = tag_refs::outbound_tag_references(sections, &old_tag)` → клонирует outbound `Value`, подставляет новый tag → вызывает `config.replace_outbound_value(index, updated)` напрямую, в обход wrapper-функции `replace_outbound()` — именно её guard («tag должен совпадать») блокирует rename у Shell Save; `replace_outbound_value` уже содержит self-excluding tag-conflict проверку (`OutboundTagConflict`, если другой outbound уже носит новый тег), так что отдельной проверки уникальности здесь не потребовалось |

`tag_refs::outbound_tag_references` (уже существовал для Delete hard-block, §2.4:97) переиспользован без изменений — как для serverside `stale_references` в успешном outcome, так и для клиентской preview-функции (см. §37.3).

## 37.3	App-слой (`src/app/outbound_ops.rs`, `src/app/service.rs`, `src/app/status.rs`)

- `OutboundMutationKind` — новые варианты `Duplicate`, `Rename`; `OutboundMutationSuccess` — `Duplicate { editable, new_index }` (индекс новой копии считается как `editable.sections().outbounds().len() - 1`, тот же приём, что `run_duplicate_inbound`) и `Rename { editable, old_tag, new_tag, stale_references }`.
- `run_duplicate_outbound` / `run_rename_outbound_tag` — тот же connect → write → disconnect паттерн, что `run_delete_outbound`: чистая model-функция вызывается до похода на SSH, поэтому отклонённый протокол-гейт (Duplicate) или fingerprint-mismatch (Rename) не тратят сетевой round-trip.
- `CurrentOperation::DuplicatingOutbound` / `RenamingOutboundTag` — добавлены во все три exhaustive-match места, где уже перечислялись outbound-операции (`label()`, `progress()` busy-список, и отдельный match в `service.rs` рядом с `tick_status`).
- `ApplicationService::start_duplicate_outbound(index)` — почти дословная копия `start_delete_outbound` (те же guard'ы: SSH connected, `is_any_remote_busy`, `locate_outbound`), без протокол-проверки на этом уровне — она уже стоит внутри чистой `duplicate_outbound()` и всплывает как обычная async-ошибка, если пользователь всё же дотянется до недоступной по UI кнопки.
- `ApplicationService::start_rename_outbound_tag(index, new_tag)` — та же структура, но намеренно не использует `build_outbound_ref()` (тот метод жёстко гейтит `is_shell_editable_protocol`, что здесь неверно — Rename должен работать для любого протокола); fingerprint берётся напрямую через `editable.outbound_object_fingerprint(index)`, как у Delete.
- `ApplicationService::outbound_tag_reference_preview(index) -> Vec<String>` — синхронный read-only метод без похода на SSH: читает текущий tag из уже загруженного `loaded_config` и вызывает `tag_refs::outbound_tag_references` напрямую. Используется GUI, чтобы показать список затронутых routing rules/balancer'ов в момент открытия диалога Rename, а не только после завершения операции — бесплатная UX-улучшение, так как конфиг и так уже в памяти.
- `poll_outbound_mutation()` — новые match-ветки `Duplicate` (просто `replace_loaded_editable` + статус-сообщение) и `Rename` (тоже `replace_loaded_editable`, но текст сообщения ветвится: если `stale_references` пуст — просто подтверждение переименования, иначе список незакрытых ссылок дописывается в то же сообщение статус-бара).

## 37.4	GUI (`src/gui/pages/outbounds.rs`)

- Контекстное меню строки: плейсхолдер `"Duplicate"` (`add_enabled(false, ...)`, "Not implemented yet" — стоял с §2.4:97) заменён на рабочую кнопку с тем же протокол-гейтом, что у Edit (`OutboundKind::Freedom`/`Blackhole`/`Dns`); клик сразу вызывает `start_duplicate_outbound`, без confirm-диалога.
- Новый пункт "Rename", доступный для любого протокола при простое соединения; открывает `PendingOutboundRename` (тот же паттерн ephemeral-состояния через `ui.ctx().data_mut()`/`egui::Id`, что `PendingOutboundDelete`, §2.4:97) с уже вычисленным `references: Vec<String>` через `outbound_tag_reference_preview`.
- `show_rename_outbound_dialog` — `egui::Window`, однострочный `TextEdit` для нового тега, амбер-предупреждение со списком `references` (если непуст, тот же `Color32::from_rgb(210, 170, 40)`, что и warning-состояния страницы), кнопки Rename/Cancel; ошибка от `start_rename_outbound_tag` показывается инлайн в диалоге (как у Delete), а не только в статус-баре.
- Doc-комментарии `OutboundGeneral.tag` (`outbound_edit/mod.rs`) и `update_outbound_shell` (`modify.rs`) обновлены: раньше оба ссылались на «§2.4:99 ещё не реализован», теперь явно указывают, что запрет смены tag на Shell Save — намеренное архитектурное решение, а не временный пробел; переименование живёт в отдельном `rename_outbound_tag`.

## 37.5	Тесты

- `modify_tests.rs`: `duplicate_outbound_appends_unique_tag_copy` (второй Duplicate даёт `-copy-2`, остальные поля сохраняются), `duplicate_outbound_rejects_non_shell_protocol` (VLESS outbound → `ValidationFailed`, ничего не добавлено); `rename_outbound_tag_updates_tag_and_warns_on_refs` (outbound, referenced и routing rule, и balancer prefix-selector'ом — обе ссылки попадают в `stale_references`, тег при этом обновляется), `rename_outbound_tag_rejects_conflicting_tag` (`OutboundTagConflict`, оригинальный тег не тронут), `rename_outbound_tag_fingerprint_mismatch` (мирроринг `delete_inbound_fingerprint_mismatch`).
- Ручная сборка: `cargo build` / `cargo build --workspace`, `cargo clippy --lib --all-targets` (0 новых warning в затронутых файлах — все существующие warning'и в других, не тронутых этой задачей местах), `cargo test --lib outbound` (66/66, включая 5 новых); полный `cargo test --lib` воспроизводит те же 9 pre-existing fixture-path failures, что и в §36.4 (`tests/fixtures/xray/` отсутствует на этой машине, не связано с изменением).
- Не проверено вручную (нет доступа к живому SSH-подключённому Xray-серверу в этой среде): визуальный проход Duplicate/Rename в реальном GUI.
- Ручной QA (частично): `docs/ui.md` обновлён (описание Duplicate/Rename в разделе Outbounds page); Roadmap §2.4:98/§2.4:99 отмечены выполненными.


# 38	XTLS Vision — gate G13 + flow ComboBox cleanup (Roadmap §2.5:105)

## 38.1	Цель и границы

Roadmap-пункт §2.5:105 звучал как «XTLS Vision deep-edit helpers (flow / seed fields beyond current VLESS flow gate)» — но при разборе выяснилось, что обе названные в нём фичи уже полностью реализованы под более ранними пунктами:
- Flow-редактор клиента (`VlessFlowChoice` ComboBox в Add/Edit-диалогах Users tab, `src/gui/pages/users.rs`) — доставлен под «VLESS + Trojan Users CRUD» (§2.2, ✅ 2026-07-29).
- REALITY `mldsa65Seed` — редактируемое маскированное текстовое поле + кнопка "Generate mldsa65" (`src/gui/pages/inbounds.rs`, `src/app/inbound_ops.rs`, `src/xray/remote_cli/mldsa65.rs`) — доставлено под «Security REALITY editor + remote x25519 / mldsa65» (§2.3, ✅ 2026-07-28). Единственное, что не поспевало за кодом — комментарий `RealitySettingsDraft.mldsa65_seed` (`inbound_security/mod.rs:62`), всё ещё гласивший «preserved if present, editable later»; исправлен в рамках этого пункта.

Пункт закрыт как дубликат более ранней работы, но при перепроверке через официальную документацию Xray (Context7 `/websites/xtls_github_io_ru`, дата сверки 2026-08-13) нашлись два реальных, узких пробела, которые и составили фактическую работу этого пункта:

- G13 — Vision splices на уровне TLS record layer; без внешнего security-слоя (`tls`/`reality`) сплайсить нечего. До этого пункта `first_failing_gate` проверял для Vision-flow только транспорт (G3: raw/tcp), но не security — конфиг с `flow: "xtls-rprx-vision"` + `streamSettings.security: "none"` (или отсутствующим `streamSettings` вовсе) проходил все гейты без единого замечания.
- Устаревший flow-выбор — текущая официальная inbound-документация VLESS (`config/inbounds/vless.html`) описывает для `flow` только `xtls-rprx-vision` (пустая строка = default). `xtls-rprx-vision-udp443` в текущей схеме не упоминается вовсе — исторически он был отдельным вариантом до слияния его поведения в обычный `xtls-rprx-vision` (см. `about/news.html`, запись 2022.10.3, про переработку XTLS-механизма и UDP443-сплайсинг). ComboBox в Feldjäger предлагал его как полноценный выбор для новых записей наравне с обычным Vision — не деприкейченным legacy-значением.

- В scope (shipped):
  - Новый гейт G13: `xtls-rprx-vision requires security tls or reality (not none)`, срабатывает только когда Vision активен (`inbound_has_vision_flow`) и транспорт уже прошёл G3 (raw/tcp), но `effective_security(inbound) == "none"`
  - `VlessFlowChoice` ComboBox (`users.rs`) сокращён до `None` | `xtls-rprx-vision` — `xtls-rprx-vision-udp443` удалён как выбираемый вариант
  - Legacy-конфиги с `flow: "xtls-rprx-vision-udp443"` (или любым другим нераспознанным значением) на диске по-прежнему открываются в Edit без потери данных — просто теперь через уже существующий generic-путь «unsupported flow» (тот же, что для любого будущего/неизвестного значения), а не через выделенную ветку матчинга
  - Обновлён устаревший doc-комментарий `RealitySettingsDraft.mldsa65_seed`
- Вне scope: автоматическая миграция существующих inbound-конфигов с `flow: vision` + `security: none` на диске — G13 лишь блокирует новые Save/Add через тот же путь, что и остальные G-гейты (Shell Save/Add/Users mutate); уже сохранённые невалидные конфиги не переписываются автоматически при простом чтении/отображении.

## 38.2	G13 (`src/xray/config/compatibility/mod.rs`)

`CompatibilityGateId::G13` добавлен в конец списка (doc-комментарий типа `Stable gate identifiers (design G1–G12)` обновлён на G1–G12 + G13; Wave A order в обоих doc-комментариях файла (`mod.rs:3-4`, `first_failing_gate` doc на 82-83) расширен до `…→G3→G13`). Реализация — не отдельная проверка в конце функции, а расширение уже существующего Vision-блока:

```rust
if inbound_has_vision_flow(inbound) {
    if !matches!(method.as_str(), "raw" | "tcp") {
        return Some(CompatibilityGateId::G3);
    }
    // Vision splices at the TLS record layer — it has nothing to splice without an
    // external transport security layer (Xray docs: VLESS `security: none` warning).
    if security == "none" {
        return Some(CompatibilityGateId::G13);
    }
}
```

Порядок внутри блока намеренно сохраняет G3 первым: несовместимый транспорт — более фундаментальная ошибка, чем отсутствие security-слоя, и должна репортиться раньше (см. тест `g3_takes_priority_over_g13_when_both_would_fail`, §38.4). Блок стоит в функции после уже пройденных G1/G2/G8 (reality-ветка) и G12 (tls-ветка) — то есть к моменту проверки G13 либо `security == "reality"` с уже подтверждёнными обязательными полями, либо `security == "tls"` с уже подтверждёнными сертификатами, либо ровно `security == "none"`, что и ловит G13 без риска ложных срабатываний на неполном (но не «none») security-объекте.

`inbound_has_vision_flow` (не изменён) уже был достаточно широким (`eq_ignore_ascii_case("xtls-rprx-vision") || contains("vision")`), поэтому продолжает ловить и легаси `xtls-rprx-vision-udp443` тоже — гейт защищает такие конфиги наравне с современным именем.

## 38.3	Flow ComboBox cleanup (`src/gui/pages/users.rs`)

`VlessFlowChoice` — вариант `XtlsRprxVisionUdp443` и все три его match-ветки (`label`, `to_request`, `ALL`) удалены; doc-комментарий на самом enum объясняет причину и ссылается на §2.5:105. В `open_edit_dialog` убран отдельный `Some("xtls-rprx-vision-udp443") => (...)` match-arm — строка теперь просто проваливается в уже существующий catch-all `Some(other) => (VlessFlowChoice::None, Some(other.to_owned()))`, тот же путь, что для любого прежде неизвестного flow-значения (баннер "Config had unsupported flow `{value}`. Choose an allowed value or None.", уже реализованный ранее — см. §38.1). Изменение чисто структурное: убрана одна ветка матчинга, вся инфраструктура preserve/warn уже существовала и не потребовала правок.

## 38.4	Тесты

- `compatibility::tests`: `g13_rejects_vision_with_security_none`, `g13_passes_vision_with_tls`, `g13_passes_vision_with_reality`, `g3_takes_priority_over_g13_when_both_would_fail` (несовместимый transport ловится как G3 раньше G13, даже если security тоже `none`).
- Побочные регрессии от нового гейта в уже существующих тестах: `modify_tests::add_user_preserves_optional_flow_when_set` и `update_user_changes_email_and_flow_keeps_uuid_and_unknown_fields` — оба использовали фикстуры с `flow: "xtls-rprx-vision"` без `streamSettings` вовсе (⇒ `effective_security` = `"none"`), что раньше проходило все гейты. Фикстуры обновлены — добавлен `streamSettings.security: "tls"` + валидный `tlsSettings.certificates[]`, чтобы тесты по-прежнему проверяли то, для чего написаны (write-through поля `flow`), не путаясь с G13.
- Ручная сборка: `cargo build` / `cargo build --workspace`, `cargo clippy --lib --all-targets` (0 новых warning — единственные два кандидата на `users.rs`/`compatibility/mod.rs` при точечной проверке оказались уже существовавшими предупреждениями в не тронутом этим изменением коде, просто сдвинувшимися по номеру строки), `cargo test --lib` — 654 passed, те же 9 pre-existing fixture-path failures, что и в §36.4/§37.5 (`tests/fixtures/xray/` отсутствует на этой машине).
- Не проверено вручную: визуальный проход Add/Edit User с новым укороченным flow ComboBox и G13-блоком в реальном GUI (нет доступа к живому SSH-подключённому Xray-серверу в этой среде).
- Ручной QA: `docs/ui.md` обновлён (G13 в списке гейтов Shell Save; заметка про сокращённый flow ComboBox и unsupported-value поведение в Users tab); Roadmap §2.5:105 отмечен выполненным со ссылкой на §2.2/§2.3, где основная функциональность была доставлена изначально.


# 39	Stats ↔ Metrics ↔ Policy wiring consistency checks (Roadmap §2.5:106)

## 39.1	Цель и границы

Ни `stats`, ни `api`, ни `metrics` не имеют структурных редакторов в Feldjäger — все три секции только lossless-сохраняются как `SourcedSection<Value>` (`src/xray/config/sections.rs`), это вне scope этого пункта. Roadmap-формулировка «wiring consistency checks» — про то, что три (плюс `api` как связующее звено) секции документированно зависимы друг от друга, и рассинхрон между ними даёт валидный JSON, который либо ничего не делает, либо не стартует так, как ожидает пользователь — а Feldjäger об этом молчал. Источник истины — официальная документация Xray, сверена через Context7 (`/websites/xtls_github_io_ru`, дата сверки 2026-08-13): `config/stats.html`, `config/policy.html`, `config/api.html`, `config/metrics.html`.

Задокументированные зависимости, положенные в основу проверок:
- `stats` ↔ `policy`: `stats: {}` лишь включает модуль сбора статистики; что именно собирается, определяют флаги `policy.system.stats*`/`policy.levels[N].statsUser*` — без хотя бы одного `true`-флага включённый `stats` ничего не пишет, и наоборот, `true`-флаги без `stats` ничего не делают («specific parameters must then be enabled in the Policies section to begin data gathering»).
- `stats` ↔ `api`: `api.services` может включать `StatsService` — без `stats`-секции этот сервис будет отдавать пустую статистику.
- `api`/`metrics` reachability: оба — это, по сути, виртуальный outbound с `tag` (у `metrics` дефолт `"Metrics"`, если `tag` пуст; у `api` документированного дефолта нет), либо (современный путь) прямой `listen: "host:port"`. Без `listen` официальная документация `api.html` прямо требует «manual configuration of inbound and routing sections is required to handle API traffic» — то есть должен существовать routing rule с `outboundTag`, равным этому `tag`. Без этого секция присутствует в конфиге, но полностью недостижима.

- В scope (shipped):
  - Pure-функция `stats_wiring_warnings(sections: &XrayConfigSections) -> Vec<String>` (`src/xray/config/wiring.rs`, новый модуль) — пять проверок:
    1. `policy` хочет stats, `stats` отсутствует
    2. `stats` включён, ни один `policy`-флаг ничего не собирает
    3. `api.services` содержит `StatsService`, `stats` отсутствует
    4. `api` недостижим (нет `listen`, нет routing rule на `outboundTag == api.tag`, либо нет `tag` вовсе)
    5. `metrics` недостижим (та же логика, `tag` по умолчанию `"Metrics"`)
  - Surfaced на Policy page (единственная из четырёх секций с готовым GUI) как отдельный amber-блок «Wiring consistency (stats ↔ policy ↔ api ↔ metrics)», показывается до основного state-machine page (`show_wiring_warnings` вызывается сразу после построения `model`, перед `match model.state`) — принципиально важно, потому что, например, «`stats` включён без `policy`» актуален и когда секции `policy` вообще нет (`PolicySectionMissing` иначе делал бы `return` раньше, чем warning успел бы отрисоваться)
- Вне scope:
  - Редакторы `stats`/`api`/`metrics` — по-прежнему только lossless preserve
  - Автоматическое исправление wiring (добавление `stats: {}`, дописывание routing rule и т.п.) — только предупреждение, ничего не блокирует и не переписывает конфиг
  - Проверка остальных `api.services` (`HandlerService`/`RoutingService`/`LoggerService`/`ReflectionService`) на предмет собственных зависимостей — не задокументировано настолько же чётко, оставлено вне scope

## 39.2	Модель (`src/xray/config/wiring.rs`)

Новый модуль, структурно рядом с `tag_refs.rs` (тоже «сканирует несколько секций и возвращает `Vec<String>`», тоже не мутирует конфиг):

| Функция | Логика |
| ------- | ------ |
| `stats_wiring_warnings(sections)` | Собирает все пять предупреждений (см. §39.1) в один `Vec<String>`, порядок фиксирован: stats↔policy (оба направления) → api/StatsService → api reachability → metrics reachability |
| `policy_wants_stats(sections)` | Переиспользует уже существующий `sections.policy_summary()` (не парсит JSON заново) — `true`, если `system_policy` или любой `user_levels[i]` имеет хотя бы один `stats*` флаг `Some(true)` |
| `api_services_include(value, service)` | Case-insensitive поиск строки в `api.services[]` |
| `unreachable_endpoint_warning(kind, value, sections, default_tag)` | Общая для `api` и `metrics`: `listen` непустой ⇒ `None` (всё ок); иначе `tag` (из JSON, или `default_tag`, если задан); `tag` отсутствует у обоих ⇒ отдельное сообщение «нет ни listen, ни tag»; `tag` есть, но ни один routing rule не форвардит на него ⇒ «unreachable» с конкретным именем tag в тексте |
| `routing_forwards_to_outbound_tag(sections, tag)` | Сканирует `routing.rules[].outboundTag` (case-insensitive exact match — не prefix, как у `balancer.selector` в `tag_refs.rs`: `outboundTag` там — точное значение, не префикс) |

`default_tag: Option<&str>` — единственный параметр, различающий вызовы для `api` (`None`, т.к. в документации `api.tag` не имеет дефолта) и `metrics` (`Some("Metrics")`, задокументированный дефолт).

## 39.3	Поток данных

```
EditableXrayConfig.sections() (уже загружен в ApplicationService.loaded_config)
  → stats_wiring_warnings(sections)                              [xray/config/wiring.rs]
  → PolicyPageModel.wiring_warnings: Vec<String>                  [app/policy.rs]
  → gui/pages/policy.rs::show_wiring_warnings()
```

Ключевое архитектурное решение: не повторять §21-паттерн (threading нового поля через `DiscoveryResult` → `LoadedConfigSnapshot` → `ApplicationService`) — вместо этого `build_policy_page_model` (`app/policy.rs`) читает `config.editable()` (уже существующий accessor `LoadedConfigSnapshot::editable() -> Option<&EditableXrayConfig>`, который и так хранится в снапшоте для будущего write-back) и вызывает `stats_wiring_warnings(editable.sections())` прямо на месте, без похода на discovery/SSH. Это радикально дешевле §21 по объёму правок — ни `discovery.rs`, ни `app/discovery.rs`, ни `app/inbounds.rs` не тронуты; единственное новое поле — `PolicyPageModel.wiring_warnings: Vec<String>`, независимое от уже существующего `PolicyPageModel.warnings` (то — parse/load warnings из discovery, общие для всех страниц; это — вычисляется заново при каждом построении модели).

## 39.4	GUI (`src/gui/pages/policy.rs`)

`show_wiring_warnings(ui, &model.wiring_warnings)` — ранний no-op при пустом списке; иначе строка-заголовок + amber `RichText` (`Color32::from_rgb(210, 170, 40)`, тот же оттенок, что и везде для non-fatal warnings) на каждое предупреждение. Вызывается в `show()` сразу после `let model = service.policy_page_model();`, до `match model.state { ... }` — так что блок появляется даже в ветках, которые иначе делают ранний `return` (`PolicySectionMissing`, `XrayNotDiscovered` и т.д.; на практике в тех состояниях `wiring_warnings` и так пуст, потому что `editable()` недоступен без загруженного конфига, но код не полагается на это молча — блок рисуется независимо от состояния).

## 39.5	Тесты

- `xray::config::wiring::tests` (15 тестов) — по одному на каждую заявленную комбинацию: `no_sections_no_warnings`, `policy_wants_stats_but_stats_missing`, `system_policy_stats_flag_alone_triggers_warning`, `stats_enabled_but_policy_never_collects`, `stats_enabled_no_policy_section_at_all`, `stats_and_policy_aligned_no_warning`, `api_stats_service_without_stats_object`, `api_with_listen_is_always_reachable`, `api_without_listen_or_tag_is_unreachable`, `api_without_listen_but_routed_is_reachable`, `api_without_listen_and_not_routed_is_unreachable`, `metrics_without_listen_or_tag_uses_default_tag_and_is_unreachable`, `metrics_with_listen_is_reachable`, `metrics_routed_via_default_tag_is_reachable`, `unknown_fields_do_not_affect_detection` (неизвестные ключи в `policy`/`api` не создают ложных срабатываний).
- `app::policy::tests`: `wiring_warnings_empty_without_editable_config` (снапшот без `editable` — пусто, не паника), `wiring_warnings_surface_stats_policy_mismatch`, `wiring_warnings_empty_when_aligned` — через полноценный `build_policy_page_model` с реальным `EditableXrayConfig`, не только через прямой вызов `stats_wiring_warnings`.
- Ручная сборка: `cargo build` / `cargo build --workspace`, `cargo clippy --lib --all-targets` (одно новое предупреждение, `collapsible_if` в первой версии `wiring.rs` — исправлено let-chain'ом `if let Some(metrics) = … && let Some(warning) = …`; после этого 0 новых warning в затронутых файлах), `cargo test --lib` — 672 passed (было 654 в §38.4, +18 новых тестов), те же 9 pre-existing fixture-path failures.
- Не проверено вручную: визуальный проход блока Wiring consistency на живой Policy page (нет доступа к SSH-подключённому Xray-серверу в этой среде).
- Ручной QA: `docs/ui.md` дополнен новым разделом «Policy page» (страница ранее не была задокументирована в этом файле вообще — добавлено краткое описание существующего read-only UI плюс новый Wiring consistency блок); Roadmap §2.5:106 отмечен выполненным.


# 40	Config Files page — confdir add/remove (Roadmap §2.5:107)

## 40.1	Цель и границы

Roadmap-пункт §2.5:107 — «Hot-reload / confdir file add-remove UX (multi-file config management beyond current load)». До этого пункта read/write-модель для multi-file (`confdir`) конфигов уже была полной на уровне in-memory-модели (`SourcedSection<T>` с `source_file` у каждой секции, `EditableXrayConfig.file_roots: BTreeMap<String, Value>`), но:
- Создать новый файл внутри уже существующего confdir было нечем — write-пайплайн (`BackupManager::create_backup` → `RemoteAdmin::write_config_safe`) безусловно читает целевой файл перед записью (снимок для отката), поэтому структурно не может писать файл, которого ещё нет на диске.
- Удалить файл из confdir было нечем вовсе — ни модельного примитива, ни SSH-операции, ни GUI.

Пользователь изначально предложил также реализовать в этом пункте разбиение единого `config.json` на несколько файлов по разделам. Это было проработано и сознательно отклонено: разбиение JSON бессмысленно, пока systemd-юнит не укажет Xray на `-confdir <dir>` вместо `-c config.json` — а редактирование `ExecStart`/systemd-юнита это отдельная, гораздо более рискованная функциональность (правка service-файлов, `daemon-reload`), которую приложение сегодня нигде не трогает. Итоговый scope согласован с пользователем:

- В scope (shipped):
  - Add — добавление нового, пустого (`{}`) файла в уже существующий confdir
  - Remove — удаление файла из confdir, только если он пуст (не содержит ни одной секции) — безопасный дефолт, подтверждённый пользователем явно (альтернатива — разрешить удаление непустых файлов с каскадным удалением их секций — была предложена и отклонена как принципиально более рискованная и требующая отдельного per-section impact-summary UI)
  - «Hot-reload» из заголовка пункта не порождает новую функциональность — маппится на уже существующий `ServiceOperation::Reload` (`systemctl reload`, §26); после Add/Remove показывается то же сообщение статус-бара, что и после любой другой мутации конфига («Configuration updated. Xray restart/reload required.») — без автоматического запуска reload/restart
- Вне scope:
  - Разбиение/миграция единого `config.json` в confdir (см. выше)
  - Удаление непустых файлов
  - Перемещение секций между уже существующими файлами
  - Редактирование systemd unit / `ExecStart`

## 40.2	Модель

Три новых слоя, каждый — минимальное расширение существующей инфраструктуры, без новых транспортных примитивов (`feldjaeger-ssh`'s `SshSession` уже имел `write_file`/`remove_file`/`path_is_file` — ни одного нужного метода не пришлось добавлять в `feldjaeger-ssh`):

| Слой | Файл | Добавлено |
| ---- | ---- | --------- |
| Read-only «что в этом файле» | `src/xray/config/sections.rs` | `XrayConfigSections::sections_in_file(path) -> Vec<String>` — сканирует все известные scalar-секции + `inbounds`/`outbounds` (счётом, `"N inbound(s)"`) + `extra_sections` (`` "unknown section `x`" ``) на совпадение `source_file() == path`; `is_file_empty(path)` — `sections_in_file(path).is_empty()`. Переиспользуется и remove-гейтом, и GUI-колонкой Contents |
| `file_roots` mutation | `src/xray/config/editable.rs` | `EditableXrayConfig::insert_empty_file_root(path)` (ошибка при дубликате), `remove_file_root(path)` (ошибка при отсутствии; не проверяет пустоту — это забота `modify.rs`, та же граница ответственности, что у `remove_outbound_at` vs. `remove_outbound`) |
| Orchestration | `src/xray/config/modify.rs` | `AddConfdirFileRequest { filename }` / `add_confdir_file()` — валидирует имя (непусто, без `/`\`\`, обязательно `.json` — тот же фильтр, что использует Discovery для собственного поиска confdir-файлов), директория берётся из любого существующего `file_roots`-пути (`rsplit_once('/')`), сериализация через уже существующий `config.serialize_source_file()` (тот же канонический форматтер, что у всех остальных мутаций); `RemoveConfdirFileRequest { path }` / `remove_confdir_file()` — хард-блок через `sections_in_file()`, сообщение перечисляет, что именно ещё в файле (`"cannot remove \`path\`: still contains policy, 2 inbound(s). Move or remove those sections first."`) |

`ModifyConfigOutcome` (уже существующий тип, `{ source_file, serialized, original_serialized }`) переиспользован для Add без изменений — `original_serialized` просто пустой `Vec::new()`, поскольку «оригинала» не существует; downstream-потребители (worker-слой) его для этого пути не читают.

## 40.3	Remote-транспорт: create/remove без backup-read-first

`RemoteAdmin` (`src/remote/admin.rs`) получил два новых метода рядом с уже существующим `write_config_safe`:
- `create_config_file` — `session.path_is_file(path)` guard (ошибка, если файл уже существует — защита от гонки), затем `session.write_file(path, contents)`. Backup не делается — терять нечего.
- `remove_config_file` — переиспользует существующий `BackupManager::create_backup(session, path)` (даёт точку восстановления) перед `session.remove_file(path)`, возвращает `ConfigBackup` — соответствует правилу `rules.md` «Always backup before overwriting» (удаление трактуется как форма модификации).

`src/app/config_write.rs` получил `create_confdir_file_validated` / `remove_confdir_file_validated` — по структуре почти дословные копии уже существующего `write_config_validated` (тот же опциональный `xray run -test` шаг, тот же timeout), но с create/remove-специфичным recovery: неудачный create → best-effort `session.remove_file` (новый `remove_after_failed_test`, зеркало уже существующего `restore_after_failed_test`); неудачный remove → `backup_manager().restore_backup(...)` (переиспользован без изменений). Дублирование между тремя `*_validated`-функциями оставлено как есть, без выделения общего хелпера — тот же уровень дублирования, что уже существует между `run_add_outbound_shell`/`run_update_outbound_shell`/`run_delete_outbound` в `outbound_ops.rs` (§35/§37); это установленный в проекте стиль, а не то, что стоило рефакторить именно в этом пункте.

## 40.4	App-слой и GUI

Новая пара модулей, по образцу `app/policy.rs` + `app/outbound_ops.rs`:
- `src/app/confdir_files.rs` — `ConfdirFilesPageState` (`NoSshConnection`/`XrayNotDiscovered`/`ConfigurationNotLoaded`/`NotAConfdir` — когда `installation.config_source` не `ConfigDirectory` (см. `ConfigSource`, §12)/`ConfigurationLoaded`/`ConfigurationContainsWarnings`), `ConfdirFileRow { path, display_name, is_empty, contents_summary }`, `build_confdir_files_page_model()`. Ключевое архитектурное решение — то же, что в §39.3: не заводить новое поле в `DiscoveryResult`/`LoadedConfigSnapshot`, а читать уже сохранённый `LoadedConfigSnapshot::editable()` прямо на месте построения модели (`editable.file_roots().keys()` + `editable.sections().sections_in_file(path)` на каждую строку) — конфиг уже в памяти, поход к discovery не нужен.
- `src/app/confdir_ops.rs` — `ConfdirFileMutationKind::Add | Remove`, `ConfdirFileMutationSuccess::Add { editable } | Remove { editable, removed_path }`, `run_add_confdir_file` / `run_remove_confdir_file` — тот же connect → write → disconnect паттерн, что везде в `*_ops.rs` этой сессии, вызывающий новые `config_write.rs`-функции вместо `write_config_validated`.
- `ApplicationService` (`src/app/service.rs`): новое поле `confdir_file_mutation_rx`, `confdir_files_page_model()`, `start_add_confdir_file(filename)`, `start_remove_confdir_file(path)`, `poll_confdir_file_mutation()` (подключено в общий `tick_status()` рядом с `poll_outbound_mutation()` — общий тик уже вызывается каждый кадр из `gui/app.rs`, отдельного «page tick» не потребовалось), `is_confdir_file_mutation_busy()` — добавлен и в `is_any_remote_busy()`. `CurrentOperation::AddingConfdirFile` / `RemovingConfdirFile` — те же три места правки (`label()`, busy-match в `progress()`, exhaustive match в `set_operation_progress`), что при каждом прошлом добавлении операции в этой сессии.
- `src/gui/pages/confdir_files.rs` (новая страница) + `Page::ConfigFiles` в `navigation.rs`, вставлена сразу после `Page::Connection` — про *где* хранится конфиг, логичный шаг сразу после Discovery, а не про конкретный раздел Xray-конфига (в отличие от Inbounds/Outbounds/DNS/…). `NotAConfdir` рисует только пояснение и ничего больше. Иначе — таблица (File/Empty/Contents), кнопка Add file (диалог с полем имени, подсказка про `.json`-расширение и лексикографический порядок мёржа Xray), контекстное меню Remove (enabled только когда `is_empty`, иначе disabled-hover с contents_summary) с confirm-диалогом того же вида, что Outbound Delete (§2.4:97).

## 40.5	Тесты

- `xray::config::sections::tests` (5): `sections_in_file`/`is_file_empty` — пустой файл, известная scalar-секция, inbounds/outbounds счётом, unknown top-level ключ, чужой путь.
- `xray::config::modify_tests` (6): `add_confdir_file_creates_empty_file_alongside_existing`, `add_confdir_file_rejects_duplicate_name`, `add_confdir_file_rejects_invalid_filenames` (пусто / вложенный путь / без `.json` / обратный слэш), `remove_confdir_file_succeeds_when_empty`, `remove_confdir_file_blocked_when_non_empty` (сообщение перечисляет `policy`), `remove_confdir_file_errors_when_missing`.
- `app::confdir_files::tests` (5): `single_file_config_is_not_a_confdir`, `confdir_lists_files_with_contents_summary`, `empty_confdir_file_reports_missing_field`, состояния `NoSshConnection`/`XrayNotDiscovered`/`ConfigurationNotLoaded`.
- Ручная сборка: `cargo build` / `cargo build --workspace`, `cargo clippy --lib --all-targets` — обнаружился и исправлен один реальный новый warning (`items after a test module` в `sections.rs`: тестовый модуль был вставлен перед уже существовавшим trailing `pub type XrayConfig = XrayConfigSections;` алиасом — алиас перемещён перед тестами); после исправления 0 новых warning в затронутых файлах. `cargo test --lib` — 688 passed (было 672 в §39.5, +16 новых тестов), те же 9 pre-existing fixture-path failures.
- Не проверено вручную: визуальный проход Add/Remove на живой confdir-инсталляции (нет доступа к SSH-подключённому Xray-серверу в этой среде).
- Ручной QA: `docs/ui.md` дополнен новым разделом «Config Files page»; Roadmap §2.5:107 отмечен выполненным с явной пометкой, что разбиение `config.json` было рассмотрено и отклонено.

# 41	Configuration Diff за пределами Inbound Preview (Roadmap §3:126)

## 41.1	Цель и границы

IB-L5 (§34.8) дал «Preview changes» только для Inbound Shell Save/Add и (§3:120) Users Add/Edit — везде через один и тот же движок, `json_diff.rs::redacted_json_diff` + общий рендер `gui::pages::json_diff_preview()`. Roadmap-пункт §3:126 расширяет это на остальные editable-секции. Формулировка не задавала точный список секций — уточнено с пользователем (спорный момент): ядро было предложено безусловно (Outbound Shell Add/Edit + оба Raw JSON escape hatch, §3:125), к нему добавлен список спорных кандидатов на выбор — пользователь выбрал все:

- Outbound Shell Add/Edit (Freedom/Blackhole/DNS, §35/§36) — тот же паттерн, что Inbound Shell Preview.
- Raw JSON escape hatch, inbound и outbound (§34.11) — до этого пункта единственным способом проверить правку raw-JSON перед Save было визуально сравнить текст в редакторе с памятью; теперь дью-ран считает структурный diff.
- Log Settings (§30) — уже имел собственный typed field-level «Change summary» (`log_settings_change_summary`, читаемый список «что изменится» по типизированным полям). Общий JSON-diff виджет добавлен poверх, не взамен — оба показываются одновременно в режиме редактирования; typed summary остаётся источником читаемых формулировок, JSON-diff даёт структурный path-level вид, идентичный остальным страницам.
- Rename outbound tag (§37) — однополевой диалог; JSON-diff добавляет немного (одна строка `tag`), но даёт единообразие с остальными действиями и явный «Preview» перед подтверждением.
- Duplicate inbound/outbound (§2.2:70 / §2.4:98) — было мгновенным одноклик-действием без какого-либо диалога подтверждения. Чтобы дать место для Preview, добавлен новый confirm-диалог (`PendingInboundDuplicate` / `PendingOutboundDuplicate`, по образцу уже существующих Delete-диалогов) — это единственный кандидат, потребовавший нового UI-потока, а не только новой кнопки в уже существующем диалоге.
- Unit file edit (systemd unit, §26) — единственный кандидат, который не является Xray JSON config; Edit unit уже показывал текстовый «ExecStart preview», но не before/after всего файла, хотя Edit полностью заменяет unit-файл (с явным предупреждением «unmodeled keys will be dropped»). Реализован отдельный path (§41.4) — новое remote-чтение текущего unit-файла + построчный diff.

Осознанно вне scope (не предлагалось пользователю как кандидат — не «editable section» Xray-конфига в смысле этого пункта): Delete (inbound/outbound/user) — уже имеет собственный, более уместный для необратимого действия UX (confirm-текст + предупреждение, без diff, тот же паттерн, что и раньше); WARP outbound install/register (§31) — многошаговая remote-провизия с генерацией материала на самом сервере, не чистый локальный dry-run; confdir Add/Remove (§40) — файловая операция (весь файл целиком), а не изменение содержимого существующей секции.

## 41.2	Общий паттерн: dry-run + `ModifyConfigOutcome`

Все JSON-мутации в `modify.rs` (`add_outbound_shell`, `update_outbound_shell`, `replace_inbound_raw_json`, `replace_outbound_raw_json`, `rename_outbound_tag`, `duplicate_inbound`, `duplicate_outbound`, `update_log_settings`, …) уже возвращали единый `ModifyConfigOutcome { source_file, serialized, original_serialized }` (или оборачивающий его тип, напр. `RenameOutboundOutcome { outcome, .. }`) — тот самый факт, который сделал IB-L5 и §3:120 такими дешёвыми в реализации, теперь распространён на все new preview-методы: клонировать `editable`, вызвать ту же мутирующую функцию на клоне (без сети, без изменения `self.loaded_config`), прогнать `original_serialized`/`serialized` через `redacted_json_diff_bytes`. Ни один из новых `preview_*_diff` методов не требует SSH-соединения (`&self`, не `&mut self`, кроме сессионных вариантов — см. ниже) — тот же контракт, что `preview_add_user_diff`/`preview_update_user_diff`.

Новые методы `ApplicationService` (`src/app/service.rs`):
| Метод | Мутация под капотом | Хранение результата |
| ----- | -------------------- | -------------------- |
| `preview_outbound_shell_diff(&mut self)` | `add_outbound_shell` / `update_outbound_shell` | `OutboundEditorSession.diff_preview` (сессионное поле, как у `InboundEditorSession.diff_preview`, §34.3) |
| `preview_replace_inbound_raw_json_diff(&self, …) -> Result<Vec<JsonDiffEntry>, String>` | `replace_inbound_raw_json` | GUI-local `RawJsonEditState.diff_preview` (`inbounds.rs`) |
| `preview_replace_outbound_raw_json_diff(&self, …)` | `replace_outbound_raw_json` | GUI-local `RawJsonOutboundEditState.diff_preview` (`outbounds.rs`) |
| `preview_rename_outbound_tag_diff(&self, …)` | `rename_outbound_tag` (через `.outcome`, т.к. возвращает `RenameOutboundOutcome`) | GUI-local `PendingOutboundRename.diff_preview` |
| `preview_duplicate_inbound_diff(&self, …)` | `duplicate_inbound` | GUI-local `PendingInboundDuplicate.diff_preview` (новый confirm-диалог) |
| `preview_duplicate_outbound_diff(&self, …)` | `duplicate_outbound` | GUI-local `PendingOutboundDuplicate.diff_preview` (новый confirm-диалог) |
| `preview_log_settings_diff(&mut self)` | `update_log_settings` | `ApplicationService.log_settings_diff_preview` (не сессионное — Log Settings не использует editor-session паттерн; очищается в `begin_edit_log_settings`/`cancel_edit_log_settings`/после успешного save) |

Везде — та же «stale until re-clicked» семантика, что и у IB-L5: diff не пересчитывается реактивно при дальнейшем редактировании полей, повторный клик «Preview changes» пересчитывает. Рендер — без исключений тот же `gui::pages::json_diff_preview()`, ни одного нового GUI-виджета для JSON-кейсов не потребовалось.

## 41.3	GUI-точки

- Outbounds (`outbounds.rs`): кнопка «Preview changes» рядом с Save/Add в `show_outbound_editor_pane`; в Raw JSON диалоге, в Rename-диалоге, и в новом Duplicate-диалоге.
- Inbounds (`inbounds.rs`): кнопка «Preview changes» в Raw JSON вкладке (`show_inbound_raw_json_tab`); новый Duplicate-диалог (`show_duplicate_inbound_dialog`), заменивший прежний мгновенный клик в контекстном меню.
- Log Settings (`log_settings.rs`): кнопка «Preview changes» в `show_actions`; рендер — сразу под уже существующим «Change summary» блоком в `show()`.
- Duplicate confirm-диалоги — единственная новая UI-структура в этом пункте; оба (`PendingInboundDuplicate` / `PendingOutboundDuplicate`) построены по образцу уже существующих `PendingInboundDelete` / `PendingOutboundDelete` (тот же `egui::Id`-temp-data паттерн, тот же `closed`-флаг вместо мутации `open` напрямую).

## 41.4	Unit file diff — отдельный путь (не Xray JSON)

Systemd unit — не Xray-конфиг (preserve-unknown/JSON-diff инфраструктура на него не рассчитана), а Edit unit к тому же не был read-first: `UnitSpec` для Edit восстанавливался из полей Discovery (`systemctl show --property=ExecStart …`), а не из литерального текста файла на диске — то есть до этого пункта в Feldjäger не было пути, читающего сырое тело unit-файла вообще (только его наличие, `probe_unit_file_exists`, и права на директорию, `probe_can_write_unit_dir`).

- `init/unit.rs::read_unit_file` — новое read-only remote-чтение: `probe_unit_file_exists` → если файла нет, `Ok(None)` (Create-флоу — сравнивать не с чем); если есть — `session.read_file(&path)` (тот же SFTP-примитив, что уже используют TLS-cert-probe/`cert_pin.rs`) → `String::from_utf8_lossy`. Никогда не вызывается с write-пути (`install_or_replace_unit` его не использует).
- `json_diff.rs::redacted_json_diff_lines(before: &str, after: &str)` — переиспользует тот же позиционный diff-движок, что `redacted_json_diff`, но на входе — `Value::Array` из строк текста вместо произвольного JSON-дерева. Для unit-файла (маленький, фиксированной формы шаблон — `[Unit]`/`[Service]`/`[Install]`, различия — только значения конкретных строк типа `User=`, `ExecStart=`, при Nobody↔Root — те же самые строки, что комментируются/раскомментируются) позиционное сравнение по индексу строки корректно отражает реальные изменения без необходимости в настоящем LCS-алгоритме.
- `ApplicationService`: `start_fetch_unit_file(&mut self, unit_name: &str)` — новый background-worker, зеркалящий уже существующий `start_unit_host_probe` (тот же connect → `read_unit_file` → disconnect паттерн, свой канал `unit_file_diff_rx`, опрос подключён в уже существующий `poll_unit_operations`). `unit_file_diff_result(&self) -> Option<&Result<Option<String>, String>>` — `None` = «ещё не приходил ответ» (первичный или повторный fetch в процессе), `Some(Ok(None))` = «файла раньше не было», `Some(Ok(Some(text)))` = «есть с чем сравнить», `Some(Err(_))` = ошибка чтения (не блокирует Apply — только диагностика недоступна).
- GUI (`gui/pages/service.rs`): `open_unit_form` при `!create` (Edit unit) запускает `start_fetch_unit_file` заранее — к моменту, когда пользователь долистает форму до diff-блока, ответ обычно уже пришёл. `show_unit_body_diff` — новая функция, рендерит один из четырёх случаев (fetch идёт / ошибка чтения / файла не было / есть diff) под уже существующим «ExecStart preview»; при наличии старого текста считает `render_unit(&spec)` от текущего состояния формы реактивно каждый кадр (в отличие от JSON-preview-кейсов выше — здесь нет отдельной кнопки «Preview», т.к. вычисление дешёвое — те же несколько строк, что и уже существующий ExecStart preview, который также пересчитывается каждый кадр) и пропускает обе строки через `redacted_json_diff_lines` → `json_diff_preview()`.
- Не покрыто unit-тестами (сознательно, по объёму): `read_unit_file` и `start_fetch_unit_file` требуют полного mock `SshSession` (11 методов трейта) — в `init/unit.rs` такого мока нет (в отличие от `init/systemd.rs`, где он уже существует для service-control тестов); заводить его специально ради одной тонкой read-only функции, целиком состоящей из уже протестированных примитивов (`probe_unit_file_exists`, `read_file`), сочтено непропорциональным. `redacted_json_diff_lines` — покрыта unit-тестами (`json_diff.rs`, positional line diff). Ручной QA: живой Edit unit на SSH-подключённом хосте не проверялся (нет доступа к такому серверу в этой среде) — see general caveat, §40.5.

## 41.5	Тесты

- `xray::config::json_diff::tests`: `line_diff_detects_changed_and_added_lines`, `line_diff_identical_yields_empty`.
- `app::service::tests`: `preview_outbound_shell_diff_add_does_not_mutate_loaded_config`, `preview_rename_outbound_tag_diff_shows_tag_change_without_mutating`, `preview_duplicate_outbound_diff_adds_a_copy_without_mutating`, `preview_replace_outbound_raw_json_diff_shows_change_without_mutating`, `preview_duplicate_inbound_diff_adds_a_copy_without_mutating`, `preview_replace_inbound_raw_json_diff_shows_change_without_mutating` — единый инвариант во всех: `preview_*` возвращает непустой ожидаемый diff и `service.loaded_config` остаётся байт-в-байт нетронутым (dry-run, не Save).
- `cargo build` / `cargo build --workspace`, `cargo clippy --lib --all-targets` — 0 новых warning в затронутых файлах (полный список pre-existing warning в проекте не тронут). `cargo test --lib` — 743 passed (было 737 до этого пункта, +6 новых тестов JSON diff/preview-методов), те же 9 pre-existing fixture-path failures (не связаны с этим пунктом — падают на файловых fixtures в `xray::config::tests` / `xray::remote_cli::{mldsa65,vlessenc,x25519}`, ни один из затронутых этим пунктом файлов).
- Не проверено вручную: визуальный проход всех новых «Preview changes» кнопок и Unit-diff на живом SSH-подключении (нет доступа к такому серверу в этой среде) — тот же caveat, что и в §40.5.

# 42	Backups / Rollback UI (Roadmap §3:127)

## 42.1	Цель и границы

Каждая запись конфигурации в Feldjäger уже создаёт timestamped backup рядом с оригиналом перед перезаписью (`BackupManager::create_backup`, `{filename}.feldjaeger.bak.{unix_ts}`, `rules.md`: «Always backup configuration before overwriting») — но до этого пункта backups нигде не перечислялись и не восстанавливались вручную: единственный существующий путь — автоматический restore при провале `xray run -test` сразу после записи (внутренний, не под управлением пользователя). §3:127 добавляет ручной UI поверх уже существующей инфраструктуры.

Формулировка бэклога не задавала объём — уточнено с пользователем (спорный момент): backups создаются одним и тем же механизмом (`RemoteAdmin::write_config_safe` / `remove_config_file`, оба — `BackupManager::new()` без `backup_dir`, т.е. всегда рядом с оригиналом) как для Xray-конфигурации, так и для systemd unit-файла (`install_or_replace_unit`, §26). Выбран рекомендованный вариант — только Xray config (single-file или каждый confdir-член отдельно); unit-файл вне scope:
- Unit-файл уже получил before/after diff при Edit (§41.4, Roadmap §3:126) — предварительный просмотр там уже есть.
- Restore unit-файла осмысленен только вместе с `daemon-reload` (без него systemd продолжит использовать старый unit до перезапуска демона) — это отдельный, более рискованный поток (уже есть отдельная кнопка Apply → daemon-reload → опциональный Restart, §26/§service.rs), смешивать его с общим Rollback UI признано лишним усложнением.

В scope (shipped):
- Новая страница Backups — список файлов текущей загруженной конфигурации (единственный файл для single-file layout; каждый член для confdir — те же строки, что уже показывает Config Files page, §40, но эта страница не гейтится `NotAConfdir`, работает для обоих layout).
- «List backups» на файл → таблица найденных backup (Created / Size / Restore).
- «Restore» на конкретный backup → confirm-диалог с redacted JSON diff (backup vs текущий загруженный) и подтверждением.

Вне scope: unit-файл (см. выше); удаление старых backup вручную (Feldjäger никогда не удаляет backups автоматически — `rules.md`: «Feldjäger must never remove user configuration by default» распространён и на backups по духу этого правила); настройка `BackupManagerOptions.backup_dir` через GUI (сейчас всегда `None` = рядом с оригиналом — ни один код-путь в приложении не задаёт `backup_dir`, значит все backups заведомо в тех же директориях, что и сама конфигурация).

## 42.2	Listing: `BackupManager::list_backups`

`src/remote/backup_manager.rs` — новый read-only метод рядом с уже существующими `create_backup`/`restore_backup`. Один remote round-trip вместо N+1 (по одному `stat` на файл): `find <dir> -maxdepth 1 -type f -name "<file_name>.feldjaeger.bak.*" -printf "%s\t%f\n"` — та же директория, что вычисляет уже существующий `resolve_backup_path` (либо `backup_dir`, либо `remote_parent_dir(original)`), тот же GNU-findutils допущение, что уже есть в `init/unit.rs` (`stat -c %a`, MVP таргетит Linux/systemd с обычным coreutils/findutils стеком). Парсинг устойчив к постороннему выводу: строки без `\t`, нечисловым размером, не начинающиеся с ожидаемого `{file_name}.feldjaeger.bak.` префикса или с нечисловым timestamp-суффиксом — молча пропускаются (не паникуют, `rules.md`: «Never panic for expected runtime errors»). Возвращает `Vec<ConfigBackup>` (уже существующий тип — `original_path`/`backup_path`/`created_at_unix`/`size_bytes`, ни одного нового публичного типа не потребовалось), отсортированный по убыванию `created_at_unix`.

## 42.3	Restore: тот же pipeline, что у любой другой мутации

`src/app/backup_ops.rs::run_restore_backup` не вызывает `BackupManager::restore_backup` напрямую (тот делает голый atomic write без `xray run -test`) — вместо этого читает содержимое выбранного backup (`session.read_file`) и прогоняет его через уже существующий `write_config_validated` (тот же backup → atomic write → опциональный `xray run -test` → restore-on-failure путь, что использует каждая другая мутация конфигурации в приложении). Следствие: сам rollback обратим — перед восстановлением автоматически берётся ещё один backup текущего (пред-откатного) состояния, и проваленный post-restore `-test` откатывает именно к нему, а не к выбранному историческому backup.

Conflict check (`restore_with_conflict_check`, зеркалит уже существующий `log_settings_ops::write_with_conflict_check`): перед записью читает live remote файл и сравнивает (JSON-эквивалентность, не байт-в-байт) с `expected_current_bytes` — тем, что Feldjäger сейчас показывает как загруженную версию (`ApplicationService::current_source_file_bytes`, локальный `EditableXrayConfig::serialize_source_file`, без remote-чтения). Расхождение → `ConfigurationChangedRemotely`, restore отклонён — защита от того, что кто-то другой поменял файл на сервере между Discover и Restore.

После успешного restore — полная перезагрузка (`ApplicationService::start_discovery()`), а не point-патч in-memory `EditableXrayConfig`. Это осознанное отличие от Add/Remove/Shell-Save (§2.5:107 и везде), которые применяют свою мутацию локально на клоне и после успешной записи считают локальный результат источником истины (`replace_loaded_editable`) без re-read: там локальная мутация и то, что реально записано на диск, — байт-в-байт одно и то же по построению. Восстановленный backup — произвольная историческая структура (сколько угодно старая, с другим набором inbounds/outbounds/routing/…), и для confdir-層 корректный ре-мерж секций из всех файлов заново без полного re-parse потребовал бы отдельного примитива «заменить вклад одного файла в объединённую модель», которого в кодовой базе нет и создавать который под один этот путь сочтено непропорциональным (то же рассуждение, что уже отклонило разбиение `config.json` в §40.1). Full reload — тот же путь, что уже использует `start_unit_apply` после успешного unit Apply (`let _ = self.start_discovery();`).

## 42.4	Diff preview: fetch по клику на конкретный backup, не на «List backups»

Листинг backup (Created/Size) не требует чтения содержимого — только `find`. Diff требует байты самого backup-файла, и это ЕДИНСТВЕННОЕ место в проекте, где «Preview»-подобная функциональность не может быть чистым локальным dry-run (в отличие от всех diff-кейсов §41): содержимое исторического backup нигде не хранится в памяти, только на удалённом хосте. Поэтому fetch (`start_fetch_backup_content`) запускается не при открытии страницы (что означало бы читать содержимое каждого перечисленного backup — N файлов, N remote-чтений, большинство из которых пользователь никогда не откроет), а в момент клика «Restore» на конкретной строке (`open_restore_dialog`) — тот же принцип «fetch ровно того, что сейчас нужно», что уже применялся к unit-file diff (§41.4), но триггер там был «открыл форму Edit», а здесь — «открыл диалог именно этого backup».

Два read-only background-fetch (`backup_list_rx` — листинг, `backup_content_rx` — содержимое конкретного backup) намеренно не заводят `CurrentOperation` и не входят в `is_any_remote_busy()` — зеркалят уже существующий прецедент §41.4 (`unit_probe_rx`/`unit_file_diff_rx`): read-only, best-effort, могут идти параллельно с чем угодно ещё. Restore, наоборот, — настоящая мутация: свой `CurrentOperation::RestoringBackup`, участвует в `is_any_remote_busy()`, как любая другая запись конфигурации.

## 42.5	Код

| Область | Путь |
| ------- | ---- |
| Listing (remote) | `remote/backup_manager.rs::list_backups` |
| Orchestration (async workers) | `app/backup_ops.rs` — `run_list_backups` / `run_fetch_backup_content` / `run_restore_backup` (+ `restore_with_conflict_check`) |
| Page model | `app/backups.rs` — `BackupsPageState`/`BackupFileRow`/`BackupsPageModel`, `format_backup_timestamp` |
| Service | `app/service.rs` — `backups_page_model`, `start_list_backups`/`poll_backup_list`/`backup_list_result`/`is_listing_backups`, `start_fetch_backup_content`/`poll_backup_content`/`backup_content_result`/`is_fetching_backup_content`, `current_source_file_bytes`, `start_restore_backup`/`poll_backup_restore`/`is_restoring_backup`; новый `CurrentOperation::RestoringBackup` (те же три места правки, что при каждом прошлом добавлении операции — variant, `label()`, `progress()`/`set_operation_progress` exhaustive match) |
| GUI | `gui/pages/backups.rs` (новая страница) + `Page::Backups` в `navigation.rs`, вставлена сразу после `Page::ConfigFiles` — та же логика места, что у Config Files (§40.4): про то, где живёт и что можно откатить в конфигурации, а не про конкретный Xray-раздел |

## 42.6	Тесты

- `remote::backup_manager::tests`: `list_backups_parses_and_sorts_newest_first` (устойчивость к постороннему файлу того же naming-паттерна для другого оригинала + нечисловому timestamp), `list_backups_empty_when_none_found`; новый `MockSession::with_exec_stdout` (canned `exec` response — до этого пункта `exec` в этом моке был не реализован).
- `app::backups::tests`: `single_file_config_lists_one_row`, `confdir_lists_every_member_file`, `not_connected_and_not_discovered_states`, `configuration_not_loaded_state` (тот же набор состояний, что `app::confdir_files::tests`, но без `NotAConfdir` — эта страница не гейтится layout'ом).
- `app::service::tests`: `current_source_file_bytes_serializes_the_loaded_file`, `current_source_file_bytes_none_when_config_not_loaded`, `backup_list_result_ignores_a_different_files_cached_result` (изоляция кэша между файлами).
- Не покрыто unit-тестами (сознательно, по объёму — тот же прецедент, что §41.4 для `read_unit_file`/`start_fetch_unit_file`): `backup_ops.rs`'s `run_list_backups`/`run_fetch_backup_content`/`run_restore_backup` требуют полного mock `SshBackend` (`connect()` → `Session`), а не только `SshSession` — ни один из `*_ops.rs`-модулей в проекте (`confdir_ops.rs`, `log_settings_ops.rs`, `outbound_ops.rs`) не имеет собственных unit-тестов на этом уровне; вся SSH-оркестрация (connect → операция → disconnect) везде оставлена на ручной QA, только «чистая» локальная логика мутаций (`xray::config::modify`) и page-модели тестируются напрямую. `restore_with_conflict_check`'s JSON-эквивалентность переиспользует уже протестированный (`log_settings_ops`) паттерн, отдельно не задублирована.
- `cargo build` / `cargo build --workspace`, `cargo clippy --lib --all-targets` — 0 новых warning в затронутых файлах после одной правки (`sort_by` → `sort_by_key` в `list_backups`, по подсказке clippy); `run_restore_backup`'s «8/7 arguments» — тот же уже принятый в проекте уровень (`warp.rs`/`xray_logs.rs` содержат функции с 9–10 аргументами), решено не выделять отдельный request-struct ради этого одного места. `cargo test --lib` — 752 passed (было 743 после §41, +9 новых тестов), те же 9 pre-existing fixture-path failures (не связаны с этим пунктом).
- Не проверено вручную: живой List/Restore на SSH-подключённом хосте, включая сценарий `ConfigurationChangedRemotely` (кто-то поменял файл между Discover и Restore) и confdir с несколькими файлами backup одновременно — нет доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4.

# 43	API Console — Xray gRPC/API live operations panel (Roadmap §3:128)

## 43.1	Цель и границы

Формулировка бэклога («runtime calls beyond static `api` config edit») не задавала объём — уточнено с пользователем (спорный момент) выбором из трёх вариантов: (a) только чтение + safe-действия (`lsi`/`lso`/`bi`/`restartlogger`), (b) вариант (a) + эфемерные control-действия (`sib`/`bo` — по замыслу самого Xray временные/аварийные, поэтому не расходятся с философией «конфиг = истина» так же сильно), (c) полная консоль `HandlerService`/`RoutingService`, включая live add/remove inbound/outbound/inbound-users/routing-rules без записи в файл конфигурации. Выбран вариант (c).

Предусловие, не новая фича: секция `api` (`api.listen`/`api.tag`/`api.services`) хранится как непрозрачный JSON (`XrayConfigSections::api`, как и все ещё не типизированные Tier‑2 секции) — структурированного редактора у неё нет (отдельный незакрытый пункт §2.1:54). Эта страница не дублирует его: она трактует настроенный `api.listen` как предусловие и, если он отсутствует, показывает объяснение с примером JSON и указанием использовать существующий Raw JSON escape hatch (§3:125, `EditableXrayConfig::replace_inbound_value`/`replace_outbound_value`) или confdir-файл, а не строит собственный редактор секции.

Ключевое архитектурное отличие от абсолютно любой другой мутации в проекте: live-вызовы `xray api` меняют только состояние уже запущенного процесса Xray через его gRPC API — ничего не пишется в файл конфигурации, ничего не бэкапится, `xray run -test` не запускается. Live add/remove не переживает следующий restart/reload. Это осознанный компромисс, на который пользователь согласился, выбирая вариант (c) — и единственное место в приложении, где заголовок страницы и диалог подтверждения обязаны прямо повторять это предупреждение, а не полагаться на общий «Configuration updated. Restart required.» паттерн остальных страниц.

## 43.2	Транспорт: SSH-exec `xray api`, не gRPC-клиент

`xray api <subcommand>` в апстриме (`main/commands/all/api/` в XTLS/Xray-core) — тонкая CLI-обёртка над gRPC (`dialAPIServer()` в `shared.go`, insecure localhost по умолчанию). Рассматривались два пути:
- Полноценный gRPC-клиент (tonic/prost, `.proto`-схемы Xray-core) с SSH port-forward до `api.listen` на удалённом хосте.
- SSH-exec самого `xray api` на удалённом хосте — команда обращается к `api.listen` по loopback там же, где выполняется.

Выбран второй — он не добавляет новых зависимостей (`rules.md`: «Only GPL-3.0 compatible dependencies», tonic/prost под вопросом), не требует SSH port-forwarding (которого сейчас нет ни в `feldjaeger-ssh`, ни где-либо ещё в проекте) и не создаёт нового класса инфраструктуры — вместо этого один раз используется уже существующий паттерн `SshSession::exec`/`exec_with_stdin` + `RemoteCommand`, ровно тот же, что и `xray x25519`/`xray mldsa65`/`xray vlessenc`/`xray run -test` (`src/xray/remote_cli/`). Соответствует `rules.md`: «SSH is the primary management channel», «The application should not require additional daemons on the server unless absolutely necessary» — `xray api` не демон, а однократный вызов уже установленного бинаря.

## 43.3	Generic executor (`src/xray/remote_cli/api.rs`)

Все ~17 подкоманд имеют одинаковую форму: `xray api <subcommand> -s <api.listen> [флаги] [позиционные аргументы]`, а четыре из них (`adi`/`ado`/`adu`/`adrules`) принимают JSON-тело через литеральный позиционный аргумент `stdin:`, который апстримный `loadArg()` распознаёт как «читать из stdin» — что укладывается в уже существующий `SshSession::exec_with_stdin` (тот же механизм, что уже используется для `sudo -S` в `init/unit.rs`). Поэтому вместо 17 похожих обёрток — один `run_xray_api(session, binary_path, server_addr, subcommand, extra_args, stdin_body) -> RemoteCliResult<String>`, возвращающий сырой (не типизированный) trimmed stdout.

В отличие от `x25519.rs`/`mldsa65.rs`/`vlessenc.rs` вывод сознательно не парсится в структуру: формат неоднороден между подкомандами, а `-json` для части из них (`bi`) до сих пор помечен TODO в апстриме. Вывод показывается в GUI как read-only монотекст — тот же подход, что уже применяется к телам Xray runtime-логов (`docs/rules.md`: «Xray runtime logs (read-only bodies)»). Ошибки классифицируются через уже существующий `RemoteCliError`/`RemoteCliErrorKind` (без нового типа ошибки); `stdin`-тело и stdout/stderr никогда не логируются целиком — только длина и код подкоманды (`rules.md`: «Passwords, private keys, passphrases, tokens, VLESS UUIDs, and raw remote command output must never be written to logs», вывод `inbounduser` может содержать client-идентификаторы).

Покрытые подкоманды (`stats*` сознательно вне scope — закреплены за отдельным будущим пунктом §3:129):

| Категория | Подкоманды | Требует `api.services` |
| --- | --- | --- |
| Inbounds (live) | `lsi`, `adi`, `rmi` | `HandlerService` |
| Outbounds (live) | `lso`, `ado`, `rmo` | `HandlerService` |
| Inbound users (live) | `inbounduser`, `inboundusercount`, `adu`, `rmu` | `HandlerService` |
| Routing rules (live) | `lsrules`, `adrules`, `rmrules` | `RoutingService` |
| Balancer | `bi`, `bo` | `RoutingService` |
| Source IP block | `sib` | `RoutingService` |
| Logger | `restartlogger` | `LoggerService` |

## 43.4	Оркестрация (`src/app/api_ops.rs`, `src/app/service.rs`)

`api_ops.rs` — 17 чистых pure-функций `*_request() -> ApiCallRequest` (subcommand + args + опциональное stdin-тело + человекочитаемый label), плюс один `run_api_call` (connect → `run_xray_api` → disconnect), зеркалящий стандартный `*_ops.rs`-паттерн (`outbound_ops.rs`/`backup_ops.rs`). GUI никогда не строит argv сам (`rules.md`: «GUI must not execute raw SSH commands directly» — конструирование аргументов отнесено к той же категории).

В `ApplicationService` — два независимых канала, а не 17 (по одному на каждую операцию, как могло бы быть при копировании паттерна Backups):
- Read-канал (`api_read_rx`/`api_read_key`/`api_read_result`) — для `lsi`/`lso`/`lsrules`/`bi`/`inbounduser`/`inboundusercount`. Read-only, без `CurrentOperation`, не входит в `is_any_remote_busy()` — тот же контракт, что у `backup_list_rx`/`unit_probe_rx` (§42.4). Кэш ключуется не по display-label (у двух разных вызовов `inbound users` для разных тегов один и тот же label), а по `subcommand + args` (`api_call_key`) — иначе результат для одного тега мог бы молча показаться под другим.
- Mutation-канал (`api_mutation_rx`/`api_mutation_result`) — для всех остальных 11 (Add/Remove ×4, `bo`, `sib`, `restartlogger`). Настоящая операция: один новый `CurrentOperation::ManagingLiveApi { text }` (тот же `{ text: String }`-паттерн, что у `ManagingXrayService`/`ManagingWarp`/…, §26 — вместо 11 отдельных вариантов), участвует в `is_any_remote_busy()`. После завершения мутации кэш read-канала сбрасывается (`api_read_result = None`) — live-изменение могло сделать закэшированный список устаревшим.

`api.listen`/binary path резолвятся заново на каждый вызов из уже загруженной конфигурации/discovery (`resolve_api_server_addr`/`resolve_binary_path_for_live_api`) — не кэшируются в состоянии страницы, чтобы не разойтись с тем, что реально загружено после очередного Discover.

## 43.5	Страница API Console (`src/gui/pages/api_console.rs`)

В сайдбаре — сразу после Service (§26): обе про операционное управление уже запущенным Xray, а не про его файл конфигурации. Наверху — постоянный предупреждающий баннер («changes are NOT written to the configuration file») и статус (`api.listen`, `api.services`, info-warning при отсутствии `HandlerService`/`RoutingService`/`LoggerService` — предупреждает, не блокирует, тот же принцип warn-don't-block, что у wiring-проверок Policy-страницы, §39/Roadmap §2.5:106; Xray сам отклонит вызов, если сервис действительно не включён).

Секции (`CollapsingHeader`, все закрыты по умолчанию): Logger, Inbounds, Outbounds, Inbound users, Routing rules, Balancer, Source IP block. Черновики полей формы (JSON-тела, теги, IP-списки) живут в GUI-локальном `ApiConsoleForm` через `egui::Id` + `ctx().data_mut()` temp storage — тот же паттерн, что у `RawJsonEditState` (§3:125) и `PendingBackupRestore` (§42.5), не в `ApplicationService` (черновик до отправки — забота презентационного слоя).

Remove-действия (inbound/outbound/user/rule) — единый confirm-диалог (`PendingLiveRemoval`, зеркалит `PendingBackupRestore`) с явным повтором предупреждения о невозвратности через Feldjäger (`rules.md`: «Confirmation dialogs must only be used for destructive actions»). Add/Override/Source IP block/Restart Logger — без confirm, сразу по клику: тот же уровень, что у Add Inbound/Outbound Shell (не про удаление существующего объекта), а `bo`/`sib` по замыслу самого Xray — временные/обратимые (`-r`/`-reset`).

## 43.6	Код

| Область | Путь |
| ------- | ---- |
| Generic CLI executor | `xray/remote_cli/api.rs::run_xray_api` |
| Request builders + orchestration | `app/api_ops.rs` — 17 `*_request()` + `run_api_call` |
| Page model / `api.listen` resolution | `app/api_console.rs` — `ApiConsolePageState`/`ApiConsolePageModel`, `resolve_api_listen`/`resolve_api_services` |
| Service | `app/service.rs` — `api_console_page_model`; read: `start_api_read`/`poll_api_read`/`is_running_api_read`/`api_read_result`; mutation: `start_api_mutation`/`poll_api_mutation`/`is_running_api_mutation`/`api_mutation_result`; новый `CurrentOperation::ManagingLiveApi` (те же три места правки, что при каждом прошлом добавлении операции — variant, `label()`, `progress()`/`set_operation_progress` exhaustive match) |
| GUI | `gui/pages/api_console.rs` (новая страница) + `Page::ApiConsole` в `navigation.rs`, сразу после `Page::Service` |

## 43.7	Тесты

- `xray::remote_cli::api::tests` — только чистая логика (`truncate`); сам `run_xray_api` не покрыт mock-тестом, тот же прецедент, что у `run_config_test`/`run_x25519` (ни один `remote_cli`-wrapper в проекте не мокает SSH-транспорт напрямую).
- `app::api_ops::tests` — 7 тестов на чистые `*_request()`-билдеры (порядок аргументов, `stdin:`-сентинел, `-append`/`-r`/`-reset` перед позиционными).
- `app::api_console::tests` — 6 тестов: `resolve_api_listen`/`resolve_api_services` (включая пустую/бланковую `listen`), `missing_services_warning`, состояние страницы (`NoSshConnection`/`XrayNotDiscovered`/`Ready`/`ApiNotConfigured`).
- Не покрыто unit-тестами (тот же прецедент, что §41.4/§42.6): `api_ops.rs::run_api_call` требует полного mock `SshBackend`, которого ни один `*_ops.rs`-модуль в проекте не мокает — оркестрация оставлена на ручную QA.
- `cargo build` / `cargo build --all-targets`, `cargo clippy --lib --all-targets` — 0 новых warning в затронутых файлах (один найденный — `assert_eq!(..., true)` → `assert!` в `api_console.rs`, исправлено). `cargo test --lib` — 767 passed (было 752 после §42, +15 новых тестов), те же 9 pre-existing fixture-path failures (не связаны с этим пунктом).
- Не проверено вручную: живой вызов на SSH-подключённом хосте с настоящим `api.listen` — нет доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4/§42.6.

# 44	API Settings — редактор секции `api` (Roadmap §2.1:54)

## 44.1	Цель и границы

Пункт закрывает последний пробел, оставленный §43 (API Console, §3:128): та страница трактовала `api.listen`/`api.services` как предусловие и указывала на Raw JSON escape hatch (§3:125) как единственный способ их задать — структурированного редактора у секции `api` не было (`XrayConfigSections::api` хранит её как непрозрачный `SourcedSection<Value>`, как и все ещё не типизированные Tier‑2 секции). §2.1:54 добавляет именно этот редактор: `api.tag` / `api.listen` / `api.services`, и ничего больше.

Разграничение с §43 явное и однонаправленное: эта страница не знает о live-вызовах `xray api`, не проверяет достижимость `api.listen`, не запускает `xray api lsi`/`restartlogger`/etc. — она только читает/пишет три поля JSON-объекта в конфиг-файл, тем же pipeline (backup → conflict-check → atomic write → `xray run -test`), что и любая другая мутация конфигурации. API Console (§43), в свою очередь, как читал `api.listen` напрямую из `XrayConfigSections::api` (`resolve_api_listen`), так и продолжает — ему всё равно, откуда взялось значение: из этой страницы или из Raw JSON. Никакой связи в коде между двумя страницами нет и не требуется.

Enable = Save, не отдельное действие: по аналогии с Log Settings (§30) — открытие страницы не создаёт объект `api` в конфигурации; он появляется только при Save, если ещё отсутствовал. Слово «enable» в формулировке бэклога (`api enable / services / listen`) реализовано именно так, а не отдельной кнопкой «Enable API» — второе добавило бы состояние, не соответствующее ничему в самом Xray (там нет отдельного «enable»-флага, есть только наличие/отсутствие объекта `api`).

## 44.2	Типизированная модель (`src/xray/config/api_settings.rs`)

Зеркалит `log_settings.rs` почти один в один (структура модуля, `*_from_section`/`apply_*_to_value`/`*_to_new_value`/`*_change_summary`/`validate_*`), но существенно проще: `tag`/`listen` — обычные `Option<String>` (пусто = ключ отсутствует), без специальной семантики, какая есть у `LogOutput` (stdout/file/disabled). `services` — `Vec<String>`, сохраняет порядок и любые значения, включая нераспознанные (`KNOWN_API_SERVICES` — только 5 задокументированных: `HandlerService`/`LoggerService`/`StatsService`/`RoutingService`/`ReflectionService` — используется исключительно как список для UI-чекбоксов, не как allowlist для валидации).

Валидация (`validate_api_settings`) намеренно нестрогая — `rules.md`: «prefer compatibility over convenience». Точная грамматика `api.listen` у Xray не задокументирована настолько жёстко, чтобы её стоило переизобретать (bare `host:port` vs IPv6 `[::1]:port` vs возможные будущие формы) — отклоняются только управляющие символы (`\n`/`\r`/`\0`), которые сломали бы либо сам JSON, либо (позже) аргумент `-s` при вызове `xray api` из API Console (§43) — единственная причина, по которой `listen` вообще что-то валидирует, а не принимает как есть.

Ошибка «malformed api object» переиспользует существующий `ConfigModifyErrorKind::ValidationFailed` вместо нового варианта `MalformedApiObject` — в отличие от `log_settings.rs`, у которого есть отдельный `MalformedLogObject` (используется viewer-специфичными правилами, которых у `api` нет); заводить параллельный вариант ради одного сообщения признано лишним.

## 44.3	`EditableXrayConfig::with_api_mut` (`editable.rs`)

Дословно зеркалит `with_log_mut`: создаёт `api: {}` при отсутствии (выбор целевого файла для confdir — `resolve_api_target_file`, тот же алгоритм, что `resolve_log_target_file`, с эвристикой «имя файла содержит `api`» вместо «содержит `log`»), применяет мутацию, синхронизирует объединённую секцию обратно в `file_roots`. Потребовал одного нового метода в `sections.rs` — `api_mut()` (симметрично уже существовавшим `api()`/`set_api()`; `log_mut()` уже был, `api_mut()` нет — единственный пробел, который пришлось закрыть).

## 44.4	Мутация (`modify.rs::update_api_settings`) и оркестрация (`app/api_settings.rs`, `app/api_settings_ops.rs`)

`update_api_settings` дословно зеркалит `update_log_settings` (validate → snapshot всех корней → `with_api_mut` → serialize → `validate_api_structure_after_edit` — аналог `validate_log_structure_after_edit`, проверяет, что записанный `api` — JSON-объект). `app/api_settings_ops.rs::run_update_api_settings` дословно зеркалит `log_settings_ops.rs::run_update_log_settings`, включая conflict-check перед записью (`write_with_conflict_check` — сравнение JSON-эквивалентности live-файла и того, что страница считала загруженным).

`ApplicationService` получил ровно тот же набор полей/методов, что уже есть для Log Settings (draft/error/saved_flash/rx/diff_preview, `begin_edit_api_settings`/`cancel_edit_api_settings`/`api_settings_draft_mut`/`preview_api_settings_diff`/`start_save_api_settings`/`poll_api_settings_mutation`), плюс новый `CurrentOperation::SavingApiSettings` (тот же вариант-паттерн, что и везде — три места правки: variant, `label()`, `progress()`/`set_operation_progress` exhaustive match). Единственный содержательный рефакторинг: общая функция классификации `ConfigModifyError` в пользовательское сообщение (раньше `user_facing_log_settings_error`, использовалась только Log Settings) переименована в `user_facing_config_modify_error` и используется обеими страницами — она не содержала ничего log-специфичного (общий `match` по `ConfigModifyErrorKind` с catch-all), так что дублировать её под новым именем было бы чистой копипастой.

## 44.5	Страница API Settings (`src/gui/pages/api_settings.rs`)

В сайдбаре — между BurstObservatory и Log Settings: группа редакторов корневых секций (Dns → FakeDns → Routing → Policy → Observatory → BurstObservatory → API Settings → Log Settings), а не рядом с API Console (§43, живёт после Service — это про операционное управление, а не про структуру конфига).

View/Edit/Save/Cancel/Preview changes — тот же layout, что Log Settings: `tag`/`listen` — однострочные поля (пусто = ключ отсутствует), `services` — двойной виджет над одним и тем же `Vec<String>`: ряд чекбоксов для 5 известных сервисов + textarea «один в строке» под ним (тот же паттерн, что уже применяется к `sockopt.trustedXForwardedFor` в Stream-редакторе) для порядка/неизвестных значений — оба варианта редактируют один список, не расходятся. View-режим показывает предупреждение, если `listen` пуст: «API доступен только через routing к `tag`, эта страница routing не прописывает» — явная граница, чтобы не создать ложное ощущение, что одного Save достаточно для рабочего API endpoint.

## 44.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/api_settings.rs` |
| `with_api_mut` / `api_mut()` / `set_api()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_api_settings` + `UpdateApiSettingsRequest` |
| Оркестрация | `app/api_settings_ops.rs::run_update_api_settings` |
| Page model | `app/api_settings.rs` — `ApiSettingsPageState`/`ApiSettingsPageModel`, `build_api_settings_page_model` |
| Service | `app/service.rs` — `api_settings_page_model`, `begin_edit_api_settings`/`cancel_edit_api_settings`/`api_settings_draft_mut`/`api_settings_draft`/`preview_api_settings_diff`/`api_settings_diff_preview`/`start_save_api_settings`/`poll_api_settings_mutation`/`is_api_settings_mutation_busy`; новый `CurrentOperation::SavingApiSettings`; общий `user_facing_config_modify_error` (переименован из `user_facing_log_settings_error`) |
| GUI | `gui/pages/api_settings.rs` (новая страница) + `Page::ApiSettings` в `navigation.rs`, между `BurstObservatory` и `LogSettings` |

## 44.7	Тесты

- `xray::config::api_settings::tests` — 10 тестов: defaults при отсутствии секции, парсинг `tag`/`listen`/`services`, пустой/бланковый `tag`/`listen` → `None`, сохранение неизвестных сервисов, non-array `services` → warning + пусто, сохранение неизвестных JSON-ключей при `apply`, очистка `tag` удаляет ключ, change summary только по изменённым полям, отклонение управляющих символов, полный набор известных сервисов проходит валидацию.
- `app::api_settings::tests` — 2 теста: `NoSshConnection`, `XrayNotDiscovered` (то же покрытие уровня page-state, что и у остальных страниц — полный набор состояний уже покрыт на уровне `xray::config::api_settings` тестами модели).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте, §41.4/§42.6/§43.7): `api_settings_ops.rs::run_update_api_settings` требует mock `SshBackend`, которого ни один `*_ops.rs`-модуль не мокает.
- `cargo build` / `cargo build --all-targets`, `cargo clippy --lib --all-targets` — 0 новых warning в затронутых файлах. `cargo test --lib` — 779 passed (было 767 после §43, +12 новых тестов), те же 9 pre-existing fixture-path failures (не связаны с этим пунктом).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `api` объекта с нуля, конфликт при параллельном изменении файла) — нет доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4/§42.6/§43.7.

# 45	Statistics — live `xray api statsquery`/`statssys` read + charts (Roadmap §3:129)

## 45.1	Цель и границы

Roadmap-формулировка — «Stats live read / charts (runtime; config enable — Tier 2)». «config enable» явно вынесено в отдельный, всё ещё незакрытый пункт §2.1:52 (структурный редактор секции `stats`) — этот пункт только про runtime-чтение уже собираемой статистики. §3:128 (API Console) сознательно исключил все `stats*`-подкоманды из своего generic-консольного покрытия и оставил их этому пункту (`xray/remote_cli/api.rs`, комментарий «`stats*` сознательно вне scope — закреплены за отдельным будущим пунктом §3:129»).

Предусловие то же, что у API Console: настроенный `api.listen` (§2.1:54 — редактор есть, но не обязателен; можно и через Raw JSON escape hatch, §3:125) — переиспользуется без изменений (`api_console::derive_api_console_page_state`/`resolve_api_listen`/`resolve_api_services`), с одной Stats-специфичной заменой: страница проверяет `StatsService` в `api.services`, а не `HandlerService`/`RoutingService`/`LoggerService`.

Три спорных момента, уточнённых с пользователем до реализации:
1. Графики — свой sparkline, нарисованный `egui::Painter` напрямую (`gui::pages::sparkline`), а не новая зависимость (`egui_plot` рассматривался и отклонён) — тот же выбор, что уже сделан для QR-кода (§3:122, `qr_code`): проект последовательно избегает тяжёлых GUI-зависимостей там, где хватает пары десятков строк рисования примитивов.
2. Обновление данных — только вручную, кнопкой Refresh, без фонового таймера/поллинга. Каждый клик — один SSH-exec round-trip на удалённый хост; постоянный фоновый опрос сервера, на который пользователь в данный момент не смотрит, отклонён как не соответствующий философии «SSH — основной канал управления» и не нужный для дашборда, который открывают по требованию.
3. Выбор счётчиков — категоризированный (по известным тегам Inbound/Outbound), не regex-поле для `-pattern`. Из этого следует ключевое архитектурное решение §45.3.

Осознанно вне scope: `-reset` (обнуление счётчиков после чтения) нигде не экспонируется в GUI — сервер поддерживает флаг, но пассивный дашборд не должен вмешиваться в состояние счётчиков, которые может параллельно опрашивать другой инструмент того же Xray-инстанса. `GetStatsOnline`/`GetStatsOnlineIpList`/`GetAllOnlineUsers`/`GetUsersStats` (учёт «online»-пользователей и их IP, отдельные RPC в том же `StatsService`) — не покрыты: это самостоятельная фича (кто сейчас подключён, а не сколько трафика прошло), не заявленная формулировкой бэклога и не поднятая пользователем при уточнении спорных моментов; per-user трафик (`user>>>{email}>>>...`) читается и виден (см. §45.3 — `other_counters`), но не получает собственного picker'а/графика в этой итерации.

## 45.2	Транспорт и типизированный парсинг (`src/xray/remote_cli/stats.rs`)

`statsquery`/`statssys` идут через тот же generic-исполнитель, что и вся остальная консоль (`run_xray_api`, §43.3) — новых SSH-примитивов не потребовалось. В отличие от `lsi`/`lso`/`bi` (сознательно не парсятся, §43.3 — формат нестабилен/недокументирован), у `statsquery`/`statssys` есть стабильная, задокументированная JSON-схема (`app/stats/command/command.proto` в XTLS/Xray-core) — поэтому здесь, как и у `x25519`/`mldsa65`/`vlessenc`, добавлен typed-парсер, а не read-only монотекст.

Схема подтверждена прямой сверкой с апстримным Go-источником (`app/stats/command/command.go`, `main/commands/all/api/stats_query.go`/`stats_sys.go`, `common/reflect/marshal.go` — 2026-08), а не только официальной документацией — три нюанса, которые задокументированы недостаточно чётко, чтобы полагаться на них без проверки исходников:
- JSON — не за флагом `-json` (тот распознаётся, но никогда не читается): `showJSONResponse` в `shared.go` всегда рендерит JSON через кастомный reflection-based marshaller (`common/reflect.MarshalToJson`, не стандартный `protojson`) — `statsquery` всегда отдаёт `{"stat": [{"name": ..., "value": N}, ...]}`.
- `-pattern` матчится через `strings.Contains`, а не regex, несмотря на имя флага (`command.go::QueryStats`) — не важно для Feldjäger, который всегда запрашивает пустой pattern (= всё) и группирует клиентски (§45.3), но задокументировано в doc-комментарии на случай будущего использования `-pattern` где-то ещё.
- И у `Stat.value` (`omitempty` в Go-теге), и у всех числовых полей `SysStatsResponse` (`NumGoroutine`/`Alloc`/…) нулевое значение опускается из JSON целиком — парсер трактует отсутствующий ключ как `0`, не как ошибку (`#[serde(default)]` на каждом поле).

`StatCounter { name, value: i64 }` / `SysStats { num_goroutine, num_gc, alloc, total_alloc, sys, mallocs, frees, live_objects, pause_total_ns, uptime_seconds }` — плоские структуры, без домена (инбаунд/аутбаунд не различается на этом уровне — см. §45.3).

## 45.3	Группировка счётчиков и отображение (`src/app/stats_console.rs`)

Ключевое архитектурное решение, вытекающее из выбора «категоризированный picker, не regex» (§45.1): вместо построения `-pattern` под каждый выбранный тег (N тегов → N remote round-trip'ов на один Refresh) Feldjäger всегда делает один `statsquery` без `-pattern` (сервер отдаёт вообще все известные ему счётчики) и группирует результат клиентски по задокументированной конвенции имён Xray (`inbound>>>{tag}>>>traffic>>>{uplink|downlink}` / `outbound>>>...`, подтверждено в `command.go::QueryStats` через константы `prefixUser`/`suffixUplink`/`suffixDownlink` — та же конвенция применена и к `inbound`/`outbound` префиксам). Один запрос дешевле N, и множество «чартируемых» тегов автоматически остаётся в синхроне с тем, что реально загружено в `LoadedConfigSnapshot` — не с тем, что пользователь однажды отметил чекбоксом.

`traffic_counter_name(category, tag, direction)` строит точное имя счётчика; `build_stats_page_model` итерирует все известные inbound/outbound теги (`config.inbounds()`/`config.outbounds()`, уже загруженные — не отдельный SSH-запрос) × обе стороны (uplink/downlink) и для каждой пары строит `TrafficSeriesDisplay` из накопленной истории — включая теги, для которых `statsquery` ещё не вернул данных (`policy`-флаг сбора не включён, или Refresh ещё не нажимали): такая строка не прячется, а показывает «No data yet» — тот же принцип, что у API Console («GUI must not hide configuration options that are unsupported», распространён здесь на «текущее runtime-состояние»). Счётчики, не подошедшие ни под один известный тег (per-user `user>>>{email}>>>...`, теги удалённых/переименованных inbound/outbound), попадают в `other_counters` — плоский read-only список, не скрыт, но и не чартится (пользователь выбрал категоризацию по known-тегам, не свободный regex-просмотр).

`stats_wiring_warnings` (§39, `xray/config/wiring.rs`) переиспользован без изменений — те же пять проверок stats↔policy↔api↔metrics, которые уже показываются на Policy page, дублируются и здесь, потому что на этой странице они особенно к месту: объясняют, почему у тега может быть «No data yet» несмотря на успешный `statsquery` (`policy` не собирает эту статистику, либо `stats` вовсе не включён).

Throughput между сэмплами: `rate_since_previous_sample` берёт последние два сэмпла серии, требует зазор ≥ 0.5с (защита от деления на всплеск при двух кликах подряд) и неотрицательную дельту (отрицательная — счётчик сбросил кто-то другой, например другой инструмент с `-reset`, либо перезапуск Xray; в этом случае throughput не показывается вовсе, а не рисуется как бессмысленное отрицательное число). История — `record_stats_sample`, чистая функция мутации `HashMap<String, VecDeque<(Instant, i64)>>>`, кап 120 сэмплов на счётчик (`STATS_HISTORY_CAP`) — при чисто ручном Refresh это с большим запасом покрывает любую реалистичную сессию.

Форматирование переиспользует существующее, не изобретает новое: `app::geodata::format_size` — для байтовых полей (текущее значение счётчика, throughput, `Alloc`/`Sys`/…); только `format_duration_seconds`/`format_duration_nanos` (uptime, GC pause) — новые, локальные для этого модуля, аналогов не было.

## 45.4	Оркестрация (`src/app/service.rs`) — два независимых read-канала

В отличие от API Console, где все read-only вызовы (`lsi`/`lso`/`bi`/…) делят один слот (`api_read_rx`/`api_read_key`/`api_read_result`, потому что на экране в любой момент виден результат ровно одного из них — переключение секции просто меняет, какой запрос спрашивают), у страницы Stats две независимо нажимаемые кнопки Refresh (Traffic и System), обе результаты которых должны быть видны одновременно. Переиспользование одно-слотового `api_read_*` привело бы к тому, что второй Refresh стирал бы кэш первого. Поэтому заведена отдельная пара каналов на каждый: `stats_query_rx`/`stats_query_result` и `stats_sys_rx`/`stats_sys_result` — структурно те же самые «no `CurrentOperation`, не входит в `is_any_remote_busy`» read-only контракты, что у `api_read_rx`/`backup_list_rx` (§42.4/§43.4), просто раздвоенные.

`poll_stats_query` — единственное место, где парсинг происходит сразу при получении результата (не откладывается до построения page model, в отличие от того, как `api_read_result` в API Console хранит сырой текст до отображения): так `record_stats_sample` успевает дописать новую точку в `stats_history` при каждом успешном ответе, независимо от того, открыта ли в этот момент страница Stats — история копится с первого удачного Refresh, а не только пока пользователь смотрит на график.

`stats_page_model()` собирает `StatsQuerySnapshot`/`StatsSysSnapshot` (лёгкие borrow-структуры, не клонирующие историю) из текущего состояния сервиса и передаёт в `build_stats_page_model` (§45.3) — тот же паттерн разделения «оркестрация в `service.rs`, чистая модель в `app/*.rs`», что и везде в проекте.

## 45.5	GUI (`src/gui/pages/stats.rs`, `gui::pages::sparkline`)

В сайдбаре — сразу после API Console: обе про операционное чтение уже запущенного Xray. Разделы: Traffic (Refresh + сгруппированные `CollapsingHeader`'ы Inbound/Outbound, каждая строка — тег, направление, текущее значение, throughput, sparkline), Other counters (свёрнут по умолчанию, читаемый список `name = value`), System (отдельный Refresh + `egui::Grid` с полями `statssys`).

`gui::pages::sparkline(ui, points, width, height)` — общий виджет, добавленный рядом с `qr_code` (§3:122) тем же способом: `ui.allocate_exact_size` + `Painter::add(Shape::line(...))`, без текстур/деления на кадры. Вырожденные случаи (0 или 1 точка) рисуют плоскую линию-заглушку вместо паники на `min == max` диапазоне.

## 45.6	Код

| Область | Путь |
| ------- | ---- |
| Парсинг `statsquery`/`statssys` | `xray/remote_cli/stats.rs` — `parse_stats_query_stdout`/`parse_stats_sys_stdout`, `StatCounter`/`SysStats` |
| Request-билдеры | `app/api_ops.rs` — `stats_query_all_request`/`stats_sys_request` |
| Группировка / модель страницы | `app/stats_console.rs` — `StatsPageModel`, `TrafficSeriesDisplay`, `SysStatsDisplay`, `build_stats_page_model`, `traffic_counter_name`, `record_stats_sample`, `missing_stats_service_warning` |
| Service | `app/service.rs` — `stats_page_model`; два read-канала: `start_stats_query`/`poll_stats_query`, `start_stats_sys_query`/`poll_stats_sys_query`; оба подключены в общий `tick_status()` |
| GUI | `gui/pages/stats.rs` (новая страница) + `gui::pages::sparkline` (новый общий виджет) + `Page::Stats` в `navigation.rs`, сразу после `Page::ApiConsole` |

## 45.7	Тесты

- `xray::remote_cli::stats::tests` — 9 тестов: парсинг `stat[]`, отсутствующий `value` → 0, пустой/бланковый ответ, отсутствующий ключ `stat`, некорректный JSON (обе функции), капитализированные ключи `statssys`, отсутствующие (нулевые) поля `statssys` → 0.
- `app::stats_console::tests` — 12 тестов: конвенция имени счётчика, кап истории (`record_stats_sample`), throughput (нужно 2 точки / игнорирует слишком короткий зазор / игнорирует отрицательную дельту), case-insensitive проверка `StatsService`, форматирование длительности (секунды и наносекунды), форматирование `statssys`, полная сборка модели (группировка известных тегов + `other_counters` + предупреждение о `StatsService`), сборка модели при ошибке запроса.
- `app::api_ops::tests` — 2 теста на `stats_query_all_request`/`stats_sys_request` (не передают `-pattern`/`-reset`).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs`/read-канала в проекте, §41.4/§42.6/§43.7/§44.7): сами `start_stats_query`/`start_stats_sys_query` требуют mock `SshBackend`, которого ни один такой канал в проекте не мокает — фоновый поток и SSH-транспорт оставлены на ручную QA.
- `cargo build` / `cargo build --lib`, `cargo clippy --lib --all-targets` — 0 новых warning в новых/затронутых файлах (полный прогон clippy по всему workspace показывает 67 pre-existing warning в файлах, не тронутых этим пунктом, — не связаны). `cargo test --lib` — 801 passed (было 781 до этого пункта: `cargo test --lib stats` замерил 29 совпавших + 781 filtered out, т.е. 810 всего тестов до добавления; после — 810 всего, +29 новых), те же 9 pre-existing fixture-path failures (`tests/fixtures/…` отсутствуют в этой рабочей копии — не связаны с этим пунктом, воспроизводятся и до него).
- Не проверено вручную: живой Refresh на SSH-подключённом хосте с настоящим `api.listen`/`StatsService` (реальные значения счётчиков, реальный рост при трафике) — нет доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7.

# 46	Metrics — `metrics` HTTP endpoint (`/debug/vars`) scrape + dashboard (Roadmap §3:130)

## 46.1	Цель и границы

Roadmap-формулировка — «Metrics scrape / dashboard integration (runtime; config enable — Tier 2)».
«config enable» вынесено в отдельный, всё ещё незакрытый пункт §2.1:53 (структурный редактор
секции `metrics`) — этот пункт только про runtime-чтение уже работающего эндпоинта. Название
пункта («scrape») наводит на мысль о Prometheus, но это не так: сверка с исходником Xray-core
(`app/metrics/metrics.go`, `infra/conf/metrics.go`, `app/metrics/config.proto`, 2026-08)
подтвердила, что секция `metrics` (`tag` + `listen`, `tag` дефолтится в `"Metrics"`, если пуст —
уже учтено в `stats_wiring_warnings`, §39) поднимает обычный `net/http` сервер с двумя ручками:
`/debug/pprof/*` (Go profiling — вне scope, инструмент отладки, а не администрирования) и
`/debug/vars` — не Prometheus text exposition format, а стандартный Go `expvar`: единственный JSON
объект, куда `encoding/json` пишет каждую зарегистрированную expvar-переменную (`cmdline`,
`memstats`, …) плюс два специфичных для Xray ключа — `stats` (те же счётчики трафика, что отдаёт
`xray api statsquery`, §3:129, только вложенные `{type: {tag: {direction: n}}}` вместо плоского
списка) и `observatory` (live health-check каждого outbound под наблюдением — данных, которых нет
больше нигде в Feldjäger: read-only страница Observatory, §23, показывает только статическую
конфигурацию `subjectSelector`/`probeUrl`, никогда не live-результаты пробы).

Два спорных момента, уточнённых с пользователем до реализации:

1. Транспорт. `metrics.listen` — обычно loopback-адрес на удалённом хосте (та же
   эксплуатационная модель, что у `api.listen`), недостижимый напрямую с десктоп-клиента
   Feldjäger. Рассмотрены два варианта: (a) SSH-exec `curl`/`wget` на удалённом хосте — тот же
   принцип, что уже применён для `api.listen` (`xray::run_xray_api`, §43.3): команда выполняется
   *на* удалённом хосте и сама достаёт до loopback-адреса; (b) SSH local port-forward
   (direct-tcpip channel, которого сейчас нет в `SshSession`) + локальный HTTP-клиент. Выбран
   вариант (a) — без изменений в SSH-слое и без новой HTTP-клиентской зависимости; ценой
   зависимости от `curl`/`wget`, присутствующих на удалённом хосте (с явным fallback и понятной
   ошибкой, если нет ни одного).
2. Объём страницы. Три варианта: read-only Observatory + raw expvars (минимальный,
   рекомендованный); полный mirror Statistics page (тот же Traffic-дашборд, другой транспорт).
   Выбран второй — пользователь явно попросил и Traffic-чарты через этот эндпоинт. Секция
   Observatory сохранена дополнительно к выбору (не альтернатива ему) — она приходит из того
   же единственного `/debug/vars`-запроса, без дополнительного SSH round-trip, и это единственные
   во всём Feldjäger live-данные Observatory; отказ от неё был бы чистой потерей ценности без
   экономии стоимости.

Осознанно вне scope: `/debug/pprof/*` (профилирование — `go tool pprof`, зрелый внешний
инструмент, дублировать который запрещает `rules.md`: «does not duplicate functionality of another
mature application»); полный `runtime.MemStats` (~50 полей) — вместо этого Runtime-секция
показывает подмножество из восьми самых информативных полей (`Alloc`/`TotalAlloc`/`Sys`/`Mallocs`/
`Frees`/`HeapObjects`/`NumGC`/`PauseTotalNs`), той же формы, что уже была выбрана для `statssys`
(§45.3), но явно промаркирована как *другой* источник — `memstats` (стандартный Go expvar) не
байт-в-байт совпадает со `statssys` (кастомный Xray RPC: другой набор полей, нет `NumGoroutine`/
`Uptime` в `memstats`, а `HeapObjects`/полный `MemStats` нет в `statssys`).

## 46.2	Транспорт и парсинг (`src/xray/remote_cli/metrics.rs`)

`run_metrics_scrape(session, listen_addr, path)` — SSH-exec `curl -sS -m 10 <url>`; при exit code
127 (POSIX-конвенция «command not found», общая для dash/bash/ash — тот же дискриминатор, что уже
использует `installer`/`discovery` для `command -v`) — fallback на `wget -q -T 10 -O - <url>`; при
127 у обоих — явная ошибка «Neither curl nor wget is available…». Любой другой ненулевой код (DNS/
connection refused/timeout) не триггерит fallback — вторая попытка другим инструментом при уже
работающем `curl`, но недостижимом `metrics.listen`, была бы бессмысленной. Аргументы передаются
через `RemoteCommand`/argv (не через собранную вручную shell-строку) — тот же паттерн, что и
везде в проекте; single-quote-escaping и валидация токенов уже покрыты общим `russh::exec`.

`parse_debug_vars_stdout(body)` возвращает `DebugVars { stats, observatory, memstats, cmdline }`:
- `stats` — реконструированный `Vec<StatCounter>` в формате `type>>>tag>>>traffic>>>direction`
  (`parse_stats_value`, сверено построчно с `MetricsHandler.stats()` в `app/metrics/metrics.go`:
  вложенный `map[string]map[string]map[string]int64` без protobuf-`omitempty` — то есть, в отличие
  от `statsquery`, здесь 0-значения присутствуют в JSON явно, не опускаются). Реконструкция —
  ключевое архитектурное решение: превратив вложенный объект обратно в ту же плоскую конвенцию
  имён, что и `xray api statsquery`, страница может переиспользовать группировку/чарты Statistics
  page (`app::stats_console::build_traffic_series`/`record_stats_sample`/`traffic_counter_name`,
  повышены с `fn` до `pub(super)` для этого) один-в-один, вместо повторной реализации.
- `observatory` — `Vec<ObservatoryOutboundStatus>` из `observatory.OutboundStatus` (proto-поля
  сверены с `app/observatory/config.proto`/`config.pb.go`: `alive`/`delay`/`last_error_reason`/
  `outbound_tag`/`last_seen_time`/`last_try_time`/`health_ping{all,fail,deviation,average,max,
  min}`; `delay`/`last_*_time` — сверены с `observer.go`: `delay` в миллисекундах,
  `last_seen_time`/`last_try_time` — Unix-секунды через `time.Now().Unix()`). Верхний уровень —
  JSON-объект `{outboundTag: OutboundStatus}` (не массив — `metrics.go`:
  `resp[x.OutboundTag] = x`); тег берётся из значения (`outbound_tag` в самом объекте), с fallback
  на ключ карты, если поле пусто; результат сортируется по тегу для стабильного порядка отображения.
- `memstats` — восемь полей `RawMemStats` с `#[serde(rename = "Alloc")]` и т.п. (Go expvar не
  переписывает регистр под camelCase — те же капитализированные ключи, что и `statssys`,
  §45.2) — опциональный (`None`, если `memstats` не опубликован).
- `cmdline` — `Vec<String>` как есть.

Пустое тело — `DebugVars::default()`, не ошибка (тот же принцип, что у `parse_stats_query_stdout`).

## 46.3	Модель страницы (`src/app/metrics_console.rs`)

Не переиспользует `ApiConsolePageState`/`derive_api_console_page_state` (в отличие от
Statistics page, §45) — у Metrics page другой precondition, и разница функционально значима: общая
wiring-проверка `stats_wiring_warnings` (§39) считает `metrics` «reachable», если есть `tag` +
routing-правило на него (реальный Xray-клиент действительно может дозвониться через такой
outbound) — но scrape этой страницы делает плоский HTTP GET силами `curl`/`wget`, у него нет
способа стать Xray-клиентом произвольного routing-tag. Поэтому `MetricsPageState`/
`derive_metrics_page_state`/`resolve_metrics_listen` — собственная копия того же пятизначного
state machine (`NoSshConnection`/`XrayNotDiscovered`/`ConfigurationNotLoaded`/
`MetricsNotConfigured`/`Ready`), но `Ready` требует именно непустой `metrics.listen`, а не общую
«reachability». `MetricsNotConfigured.message()` объясняет и это отличие явно (тег-only секция не
скрейпится этой страницей), не только «добавьте `metrics.listen` через Raw JSON».

`build_metrics_page_model` группирует Traffic ровно как `build_stats_page_model` (§45.3) — тот же
цикл по known inbound/outbound тегам × direction, тот же `build_traffic_series` — но против
отдельной истории (`metrics_history` на `ApplicationService`, не `stats_history`): у страниц разный
транспорт и разный ритм нажатий Refresh, смешивать сэмплы в одну историю значило бы, что клик на
одной странице искажает throughput-график другой. `wiring_warnings` — тот же `stats_wiring_warnings`
(§39), что и на Statistics/Policy — здесь тоже объясняет «No data yet» несмотря на успешный scrape.

`ObservatoryRowDisplay`/`observatory_row_display` — форматирование: `delay_ms > 0` → `"{n} ms"`,
иначе `"—"` (0 неотличим от «нет данных», поскольку proto `omitempty`, §46.2, уже трактует это как
норму); `last_seen_time`/`last_try_time` → `YYYY-MM-DD HH:MM:SS` через новый локальный
`format_unix_seconds` (секундная точность нужна — эти поля обновляются часто, в отличие от
`format_unix_date`, §28, который специально усекает до дня для файлов GeoData); `health_ping` →
одна строка-сводка (`"avg N ms · min N ms · max N ms · F/A failed"`). `MemStatsDisplay`/
`memstats_display` переиспользует `super::geodata::format_size` (байты) и
`stats_console::format_duration_nanos` (GC pause — та же функция, что и `statssys.pause_total`,
повышена до `pub(super)`, §46.2) — не изобретает новое форматирование там, где уже есть подходящее
(`rules.md`/сложившийся паттерн проекта).

## 46.4	Оркестрация (`src/app/metrics_ops.rs`, `src/app/service.rs`)

`run_metrics_scrape_op` — connect → `xray::run_metrics_scrape` → disconnect, без промежуточного
слоя «request builder» (в отличие от `api_ops.rs`, где 17 подкоманд оправдывают общий
`ApiCallRequest`) — здесь ровно один вызов, лишняя абстракция не нужна. На `ApplicationService`:
`metrics_scrape_rx`/`metrics_scrape_result`/`metrics_history` — та же no-`CurrentOperation`,
не входящая в `is_any_remote_busy` схема, что у `stats_query_rx` (§45.4), на отдельном канале;
`start_metrics_scrape`/`poll_metrics_scrape` зеркалят `start_stats_query`/`poll_stats_query`
один в один, только резолвят `metrics.listen` (`resolve_metrics_listen`) вместо `api.listen` и
дёргают `run_metrics_scrape_op` вместо `run_api_call`. `poll_metrics_scrape()` подключён в общий
`tick_status()` рядом с `poll_stats_query()`/`poll_stats_sys_query()`.

## 46.5	GUI (`src/gui/pages/metrics.rs`)

В сайдбаре — сразу после Statistics: обе про операционное чтение уже запущенного Xray, эта —
другой транспорт того же класса данных плюс уникальный Observatory-блок. Секции: Traffic
(визуально идентична Statistics page — переиспользован тот же `TrafficCategory`/
`TrafficSeriesDisplay`/`super::sparkline`), Observatory (не свёрнута по умолчанию — новые
данные, стоит показывать сразу; строка на outbound: цветной индикатор alive/dead — зелёный/красный,
`ui.md` «Colors» конвенция, — delay, last seen/try, health-ping сводка), Other counters
(свёрнута по умолчанию, как на Statistics page), Runtime (`egui::Grid`, подписи явно из
`memstats`, не `statssys`, плюс `cmdline` монотекстом). Заголовок страницы явно предупреждает, что
`/debug/vars` — не Prometheus, чтобы у пользователя не сложилось ложных ожиданий о совместимости с
Grafana/Prometheus scrape-конфигами.

## 46.6	Код

| Область | Путь |
| ------- | ---- |
| Транспорт + парсинг `/debug/vars` | `xray/remote_cli/metrics.rs` — `run_metrics_scrape`, `parse_debug_vars_stdout`, `DebugVars`/`ObservatoryOutboundStatus`/`HealthPingMeasurement`/`MetricsMemStats` |
| Оркестрация вызова | `app/metrics_ops.rs` — `run_metrics_scrape_op`, `MetricsScrapeOutcome` |
| Модель страницы | `app/metrics_console.rs` — `MetricsPageState`/`MetricsPageModel`, `build_metrics_page_model`, `resolve_metrics_listen`, `ObservatoryRowDisplay`, `MemStatsDisplay` |
| Service | `app/service.rs` — `metrics_page_model`, `start_metrics_scrape`/`poll_metrics_scrape`, поле `metrics_history` |
| Переиспользование из Statistics | `app/stats_console.rs` — `build_traffic_series`/`format_duration_nanos` повышены до `pub(super)` |
| GUI | `gui/pages/metrics.rs` (новая страница) + `Page::Metrics` в `navigation.rs`, сразу после `Page::Stats` |

## 46.7	Тесты

- `xray::remote_cli::metrics::tests` — 15 тестов: транспорт (curl success; fallback на wget при
  exit 127; ни curl, ни wget → понятная ошибка; connection refused у curl не триггерит
  fallback; пустой listen-адрес отклоняется до exec — mock `SshSession` на `std::sync::Mutex`, не
  `RefCell`, поскольку `SshSession`-методы вызываются через `&S` за точкой `.await`, что требует
  `S: Sync`) и парсинг (пустое тело; невалидный JSON; реконструкция имён счётчиков из вложенного
  `stats`; отсутствующий ключ `stats`/`observatory`; `null` observatory; сортировка по тегу;
  fallback тега на ключ карты; `health_ping`; `memstats` с капитализированными ключами и
  игнорированием будущих полей; `cmdline`).
- `app::metrics_console::tests` — 5 тестов: резолв `listen`; `tag`-only секция (даже с валидным
  routing) не даёт `Ready` — ключевое отличие от общей wiring-проверки (§46.3); пустой/blank
  `listen`; полная сборка модели (группировка известных тегов + `other_counters` + Observatory +
  `memstats` + `cmdline`); сборка модели при ошибке scrape.
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs`/read-канала в проекте,
  §41.4/§42.6/§43.7/§44.7/§45.7): `start_metrics_scrape` требует mock `SshBackend`, которого ни
  один такой канал в проекте не мокает — фоновый поток и SSH-транспорт оставлены на ручную QA.
- `cargo build` / `cargo build --lib`, `cargo clippy --lib --all-targets` — 0 новых warning в
  новых/затронутых файлах (полный прогон clippy по workspace показывает те же 67 pre-existing
  warning в файлах, не тронутых этим пунктом). `cargo test --lib` — 821 passed (было 801 до этого
  пункта, §45.7; +20 новых — 15 в `xray::remote_cli::metrics` + 5 в `app::metrics_console`), те же
  9 pre-existing fixture-path failures (`tests/fixtures/…` отсутствуют в этой рабочей копии — не
  связаны с этим пунктом, воспроизводятся и до него).
- Не проверено вручную: живой Refresh на SSH-подключённом хосте с настоящим `metrics.listen` (в
  т.ч. подтверждение, что `curl`/`wget` действительно доступны на типичном сервере, реальные
  Observatory-данные при настроенном `observatory`) — нет доступа к такому серверу в этой среде,
  тот же caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7/§45.8.

# 47	Target Lookup — SNI/Dest/host search by ASN (Roadmap §3:131)

## 47.1	Цель и границы

Roadmap-формулировка — «SNI / Dest / host target search by ASN» — не задавала дизайн. Три спорных
момента, уточнённых с пользователем до реализации:

1. Направление поиска. Рассмотрены прямой lookup (домен/IP → ASN) и обратный поиск (по ASN →
   список подходящих доменов). Выбран прямой — обратный по сути дублировал бы уже существующие
   зрелые внешние инструменты (bgp.he.net, Shodan, Censys), что прямо запрещено `rules.md`:
   «does not duplicate functionality of another mature application», и не имеет чистого лёгкого
   (бесплатного, без регистрации) источника данных для полнотекстового обратного индекса
   домен↔ASN.
2. Источник данных. Рассмотрены (a) публичный whois-сервис Team Cymru IP-to-ASN mapping
   (<https://team-cymru.com/community-services/ip-asn-mapping/>, `whois.cymru.com:43`) и
   (b) офлайн-база вроде MaxMind GeoLite2-ASN. Выбран вариант (a): бесплатно, без API-ключа, без
   лицензирования и отдельного pipeline загрузки/обновления базы (по образцу GeoData, §28) — и,
   что решило выбор, реализуется чистым `std::net` (DNS-резолв хоста + один raw TCP-запрос на
   порт 43) без единой новой зависимости — тот же принцип, что уже применён к `qr_code`/
   `sparkline` (Roadmap §3:122/§3:129 — «проект последовательно избегает тяжёлых зависимостей там,
   где хватает пары десятков строк»).
3. Размещение в UI. Рассмотрены inline-кнопка рядом с полями (REALITY `dest`, TLS
   `serverName`, routing `domain`) и отдельная самостоятельная страница. Выбрана отдельная
   страница Target Lookup — не привязана к конкретному полю/редактору, можно проверить любой
   домен до того, как он вообще куда-то вписан.

Ключевая архитектурная особенность, подтверждённая с пользователем явно: это единственная
функция во всём Feldjäger, которая обращается не к управляемому SSH-хосту, а во внешнюю
публичную сеть с рабочей станции оператора — осознанный выход за рамки `rules.md`: «SSH is the
primary management channel». Компенсируется тем, что: (a) функция полностью самодостаточна и не
трогает SSH-сессию, `ApplicationService`'s connection state, `CurrentOperation`, или загруженную
конфигурацию ни на одном этапе; (b) страница явно и лаконично сообщает об этом пользователю
(баннер над результатом), в духе privacy-notice на странице Xray Logs (`rules.md`); (c) запрашиваются
только домен/IP, которые пользователь и так собирается сделать публичным полем (SNI/dest) — не
что-то более чувствительное.

Осознанно вне scope: реверс-поиск по ASN (см. п.1); привязка к конкретным полям формы
(REALITY `dest` и т.п. остаются простыми текстовыми полями — эта страница отдельный инструмент,
не автодополнение); кэширование/офлайн-режим — каждый Look up это свежий сетевой запрос.

## 47.2	Транспорт и парсинг (`src/netinfo.rs`, новый top-level модуль)

Новый top-level модуль (не под `xray`/`ssh`/`remote` — не Xray-специфичен и не работает с
управляемым хостом), структурно на одном уровне с `error`/`logging` в `lib.rs`.

`lookup_target_asn(host)` — три шага, всё синхронно (`std::net`, никакого `tokio`):
1. `resolve_host_to_ip(host)` — если `host` уже IP-литерал, парсится напрямую
   (`IpAddr::from_str`); иначе — резолв через `(host, 0u16).to_socket_addrs()` (штатный OS-резолвер,
   без DNS-крейта); при наличии обеих семей адресов предпочитается IPv4 (для предсказуемости
   вывода — whois Team Cymru отвечает на IPv6-запросы так же, IPv6-only хосты по-прежнему
   работают).
2. `query_whois_cymru(ip)` — резолв `whois.cymru.com:43` тем же `to_socket_addrs`, TCP-подключение
   с таймаутом 10с (`TcpStream::connect_timeout`), запрос `" -v <ip>\r\n"` (verbose-флаг —
   часть текста запроса, как того требует сырой whois-протокол — нет отдельного канала для флагов),
   чтение до закрытия соединения сервером (`read_to_end` с `read_timeout`/`write_timeout` 10с,
   капом 64 КБ — реальные ответы на 1-2 порядка меньше).
3. `parse_whois_cymru_response(body)` — парсит первую строку с ровно 7 pipe-delimited полями
   (`AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name`), где первое поле — целое число
   (ASN) или литерал `NA` (регистр не важен) — un-routed/частный адрес, тогда `AsnRecord.asn =
   None`, не ошибка. Строки, не подходящие под эту форму (в т.ч. гипотетическая header-строка
   bulk-режима `begin`/`verbose`/`end`, которую этот путь никогда не использует, но парсер
   естественным образом её бы пропустил тоже — первое поле `"AS"` не парсится как число и не
   равно `NA`) — пропускаются без ошибки; ошибка `ParseFailed` только если во всём ответе не
   нашлось ни одной подходящей строки. Формат подтверждён сверкой с официальной документацией
   Team Cymru и живым тестовым запросом к `whois.cymru.com` (`8.8.8.8` → `AS15169 | US | arin |
   GOOGLE - Google LLC, US`, полное совпадение с ожидаемым форматом).

`NetInfoError`/`NetInfoErrorKind` (`InvalidHost`/`ResolutionFailed`/`ConnectionFailed`/
`ParseFailed`) — та же форма (`kind()`/`message()`/`Display`), что и `RemoteCliError` в
`xray::remote_cli`, но независимый тип: этот модуль намеренно не зависит от `xray`.

## 47.3	Модель страницы (`src/app/target_lookup.rs`)

Без state machine и без precondition-enum (в отличие от каждой другой страницы в проекте) — эта
страница не привязана к SSH/discovery/loaded-config состоянию вообще, поэтому
`TargetLookupPageModel` — плоская структура (`is_running`/`last_queried_host`/`result`/`error`),
собираемая `build_target_lookup_page_model` из простого снапшота канала
(`TargetLookupSnapshot { is_running, host, last_result }`).

`target_lookup_result_display` форматирует `AsnRecord` для отображения:
`asn: Option<u32>` → `"AS{n}"` либо `"—"`; остальные строковые поля (`bgp_prefix`/`country_code`/
`registry`/`allocated`/`as_name`) → `"—"`, если пустые или буквально `"NA"` (whois-сервер иногда
возвращает `NA` и в этих полях для неполных записей, не только в `asn`) — общий маленький
`display_field()` хелпер вместо повтора одной и той же проверки пять раз.

## 47.4	Оркестрация (`src/app/service.rs`)

`target_lookup_rx: Option<Receiver<Result<AsnLookupResult, String>>>` + `target_lookup_host:
Option<String>` (хост текущего/последнего запроса — отдельное поле, не часть канала, чтобы
`Disconnected`-ветка `poll_target_lookup` могла построить осмысленную ошибку без знания, какой
хост запрашивался) + `target_lookup_result`. `start_target_lookup(host)` — не через
`thread::spawn` + `tokio::runtime::Builder` (в отличие от вообще любого другого `start_*` в этом
файле) — здесь не нужен async-рантайм: `netinfo::lookup_target_asn` целиком синхронный
(`std::net`), поэтому фоновый поток просто вызывает её напрямую и шлёт результат в канал. Нет
`CurrentOperation`, не входит в `is_any_remote_busy` — единственная страница, где это не просто
«не блокирует другие read-only операции» (как у `stats_query_rx` и т.п.), а буквально не имеет
смысловой связи с SSH-состоянием вообще: можно запускать lookup, даже не будучи подключённым.
`poll_target_lookup()` подключён в `tick_status()`.

## 47.5	GUI (`src/gui/pages/target_lookup.rs`)

В сайдбаре — в самом конце, перед Settings (не рядом с ApiConsole/Stats/Metrics, у которых
общая тема «live-операции над запущенным Xray»; эта страница вообще не про Xray-процесс).
Единственная страница без precondition-гейта — `show()` сразу рисует форму, не проверяя
`SshStatus`/`DiscoveryState`. Draft-текст поля ввода — `egui`-temp-storage (`ctx().data_mut()`,
паттерн `PendingConfdirFileAdd` из `confdir_files.rs`), не поле `ApplicationService` — соответствует
уже сложившейся конвенции: черновой текст формы принадлежит GUI, `ApplicationService` получает
готовое значение только на submit (`start_target_lookup(host: String)`, тот же принцип, что
`start_api_read(request)`). Постоянный баннер amber-цветом сообщает про выход в публичную сеть
(§47.1); отдельная строка объясняет назначение (REALITY `dest`/TLS `serverName`/routing
`domain`). Результат — `egui::Grid` c семью полями; при `asn == "—"` — дополнительная muted-строка
«likely unrouted or private address space».

## 47.6	Код

| Область | Путь |
| ------- | ---- |
| Транспорт + парсинг | `src/netinfo.rs` (новый top-level модуль) — `lookup_target_asn`, `resolve_host_to_ip`, `query_whois_cymru`, `parse_whois_cymru_response`, `AsnLookupResult`/`AsnRecord`, `NetInfoError`/`NetInfoErrorKind` |
| Модель страницы | `app/target_lookup.rs` — `TargetLookupPageModel`, `TargetLookupSnapshot`, `build_target_lookup_page_model`, `target_lookup_result_display` |
| Service | `app/service.rs` — `target_lookup_page_model`/`start_target_lookup`/`poll_target_lookup`, поля `target_lookup_rx`/`target_lookup_host`/`target_lookup_result` |
| GUI | `gui/pages/target_lookup.rs` (новая страница) + `Page::TargetLookup` в `navigation.rs`, конец сайдбара перед Settings |

## 47.7	Тесты

- `netinfo::tests` — 8 тестов: парсинг verbose-ответа (полная строка из 7 полей); пропуск
  bulk-header строки перед данными; `NA` → `asn: None`, не ошибка; ответ без подходящей строки →
  `ParseFailed`; строка с неверным количеством полей молча пропускается; резолв IP-литерала без
  DNS; пустой host → `InvalidHost` до любого сетевого вызова; `NetInfoError::message()`
  объединяет label + detail.
- `app::target_lookup::tests` — 5 тестов: форматирование успешного результата (`AS{n}`, поля);
  `NA`-поля → `"—"`; модель в состоянии покоя (нет last_result); модель при ошибке; модель при
  успехе (включая `is_running: true` одновременно с уже показанным предыдущим результатом — тот
  же UX, что у Statistics/Metrics: старый результат не гаснет во время нового запроса).
- Не покрыто unit-тестами: сам `start_target_lookup`/фоновый поток (по тому же прецеденту, что
  у любого `start_*` в проекте — реальный сетевой ввод-вывод не мокается) — но, в отличие от
  каждого предыдущего пункта в этом документе, здесь было возможно выполнить ручную сквозную
  проверку без доступа к SSH-хосту (сеть не имитируется — это публичный сервис): временный
  игнорируемый тест дёрнул `netinfo::lookup_target_asn("8.8.8.8")` против реального
  `whois.cymru.com` и получил `AS15169 | US | arin | GOOGLE - Google LLC, US` — полное совпадение
  с ожидаемым форматом; тест не оставлен в дереве (тот же принцип, что у остального проекта —
  сетевые/внешние проверки не входят в обычный `cargo test`), но подтверждает, что реализация
  верна end-to-end, не только по офлайн-фикстурам.
- `cargo build` / `cargo build --lib`, `cargo clippy --lib --all-targets` — 0 новых warning в
  новых/затронутых файлах (те же 67 pre-existing warning в нетронутых файлах). `cargo test --lib`
  — 834 passed (было 821 до этого пункта, §46.7; +13 новых — 8 в `netinfo` + 5 в
  `app::target_lookup`), те же 9 pre-existing fixture-path failures, не связанные с этим пунктом.

# 48	AS-range REALITY candidate scan (Roadmap §3:131 follow-up)

## 48.1	Цель и границы

Пользователь спросил: какие способы подбора валидного REALITY `dest`-хоста (TLS1.3, ALPN ∈
{h2,h3,http/1.1}, curve ∈ {X25519, X25519MLKEM768}) перебором IP можно предложить — со ссылкой на
существующий инструмент RealiTLScanner, у которого IP/домен-пары (домен извлекается из SAN
сертификата при сыром скане IP-диапазона) часто не проходят обратный `nslookup`.

Перед реализацией пользователь прямо попросил оценить полезность результатов. Оценка (сверка с
официальным README проекта XTLS/REALITY, github.com/XTLS/REALITY) показала: TLS1.3+ALPN+curve —
не выдуманный критерий, это буквально задокументированный минимум («支持 TLSv1.3 与 H2»,
«домен не для редиректов»); но README называет и другие критерии, которые голая проверка
TLS-хендшейка не покрывает — «IP相近» (сетевая близость к самому REALITY-серверу) и «домен не
редирект». Redirect-проверка и OCSP Stapling сознательно оставлены вне scope этой итерации (нужен
полноценный HTTP-запрос поверх хендшейка, не только его завершение) — задел на будущее.

Три спорных момента, уточнённых с пользователем до реализации:

1. Где выполняется скан. Первая версия плана — SSH-exec на управляемом хосте (тот же паттерн,
   что у Metrics/API Console, §43/§46) ради корректной точки замера «IP相近». Пользователь указал
   на риск, который перевешивает выгоду: массовый скан-трафик именно с боевого VPS — ровно то
   поведение, за которое хостинг-провайдеры блокируют/изымают сервер (у пользователя уже был такой
   случай). Пересмотрено на локальное выполнение прямо в процессе Feldjäger: (a) DNS forward/
   reverse-консистентность (главная причина бага RealiTLScanner) не зависит от точки замера —
   PTR-записи не geo-routed; (b) единственный по-настоящему location-зависимый сигнал README
   (сетевая близость) в этой итерации не измеряется вообще (см. п.3 в §48.1 выше — вне scope), так
   что нет и compromise; (c) локальный запуск снимает риск с продакшен-сервера полностью — под
   удар попадает рабочая станция оператора, а не боевая инфраструктура.
2. Криптобэкенд. `ring` (уже в проекте через `russh`) не умеет согласовывать/распознавать
   `X25519MLKEM768` — только `aws-lc-rs` умеет. Первая оценка стоимости была ошибочной («требует
   cmake») — пользователь поправил: `aws-lc-rs` называется Rust-крейтом, но сама криптография —
   AWS-LC, C/ассемблерная библиотека (форк BoringSSL), подключаемая через FFI; для обычной
   (non-FIPS) сборки cmake/Go/bindgen НЕ нужны (готовые bindings уже в крейте) — нужен только C/C++
   компилятор, который у проекта уже есть в требованиях (Visual Studio Build Tools, `rules.md`).
   Эмпирическая проверка (`cargo build` с `rustls`+`aws-lc-rs` на этой же Windows-машине)
   подтвердила: собирается без NASM, без каких-либо дополнительных инструментов. Итоговая
   зависимость оказалась заметно легче первоначальной оценки — но всё равно самая тяжёлая в
   проекте на сегодня, добавлена осознанно, не случайно.
3. Пауза между IP. 10 секунд, предложено пользователем как достаточное — не с целью защитить
   конкретно VPS (это уже снято решением п.1 выше), а из вежливости к сканируемой сети, независимо
   от того, откуда физически идёт трафик (крупные операторы вроде Google гоняют автоматическое
   обнаружение аномальной активности по входящим IP независимо от источника). Реализовано
   отменяемыми интервалами по ~250мс, а не одним блокирующим `sleep(10s)`, чтобы Stop реагировал
   быстро, а не после полной паузы.

Кап на один запуск: 256 адресов (весь /24, либо первые 256 более широкого префикса) — при 10с
паузе полный /24 (254 хоста) занимает ~42 минуты; /16 занял бы больше недели, непрактично.
Расширение до покрытия полного широкого префикса через офсет — вне scope, задел на будущее.

## 48.2	Транспорт и парсинг (`src/netinfo/{cidr,dns,tls_probe,scan}.rs`)

`netinfo.rs` стал корнем модуля с четырьмя новыми подмодулями (Rust 2018+ «mod.rs-free» стиль,
уже используемый в проекте для `xray::config`/`xray::remote_cli`).

`cidr.rs` — `enumerate_cidr_hosts(cidr, cap) -> CidrHosts { hosts, total }`: чистая битовая
арифметика IPv4 (нормализует адрес к сетевому через маску, исключает network/broadcast для
префиксов короче /31, /31 и /32 — по RFC 3021/точечный хост без различия), возвращает и капнутый
список, и истинный total, чтобы UI мог показать «в префиксе N адресов, показаны первые 256».

`dns.rs` — reverse DNS (PTR) не покрыт `std` вообще (только forward). Вместо новой зависимости
(`dns-lookup` и т.п.) написан вручную минимальный RFC 1035 UDP-клиент — тот же принцип «простой
протокол — пишем сами», что и у whois-клиента (§47.2), согласован с пользователем явно вместо
крейта. Запрашивает фиксированный публичный резолвер (1.1.1.1, fallback 8.8.8.8) — не
OS-резолвер, сознательно: странице нужен один канонический публично-видимый ответ, а не то, что
может подменить корпоративный split-horizon DNS. `parse_name()` — единая функция для QNAME и
RDATA-имени PTR-ответа, с полной обработкой compression-pointer'ов (почти всегда встречаются в
реальных ответах) и guard'ом на количество прыжков (`MAX_NAME_POINTER_JUMPS = 20`) против
зацикленного/умышленно испорченного пакета.

`tls_probe.rs` — `rustls` с провайдером `aws-lc-rs`, TLS 1.3 only
(`with_protocol_versions(&[&rustls::version::TLS13])`), `kx_groups` явно ограничены
`[X25519MLKEM768, X25519]` (в этом порядке предпочтения — как современный Chrome, PQ первым; сервер
выбирает то, что умеет сам), ALPN предложены `h2`/`http/1.1` (`h3` — QUIC/UDP-only, недостижим при
обычном TCP-хендшейке, вне scope по согласованию с пользователем). Сертификат не валидируется
(`NoVerifier` — `rustls::client::danger::ServerCertVerifier`, принимает любой сертификат
безусловно) — клиент только наблюдает хендшейк, никогда не обменивается application data,
явно задокументировано в doc-комментарии как «не переиспользовать там, где нужна доверенная
сессия». `x509-parser` для SAN `dNSName` — единственный сознательно НЕ самописный парсер во всём
модуле `netinfo`: в отличие от плоского pipe-delimited whois-протокола, ASN.1/DER — ровно тот
случай, где риск тонкой ошибки в самодельном разборе перевешивает цену готовой, проверенной
библиотеки (осознанное отступление от обычного для этого проекта предпочтения «пишем сами»).
`build_probe_tls_client_config()` строится один раз на весь скан, не на каждый IP — построение
не бесплатно, а от IP к IP ничего в конфиге не меняется.

`scan.rs` — `probe_scan_candidate(ip, tls_config) -> Option<ScanCandidateRow>`: PTR-lookup →
`domain_forward_resolves_to(domain, ip)` (проверяет все A/AAAA-записи домена, не только первую
— у CDN/балансируемых сайтов их может быть несколько) → TLS-проба с SNI = найденный домен →
фильтр (`is_valid_reality_candidate`: TLS1.3 ∧ ALPN∈{h2,http/1.1} ∧ curve∈{X25519,X25519MLKEM768}).
Любой сбой на любом шаге — `None`, не отдельная ошибка: по требованию пользователя невалидные
результаты не показываются вообще, а не показываются с пометкой «ошибка» — на /24 подавляющее
большинство адресов не пройдёт хотя бы один шаг, это ожидаемая норма, не аномалия.

## 48.3	Оркестрация цикла (`src/app/target_scan_ops.rs`)

`run_target_scan(hosts, tls_config, cancel, tx, pause)` — единственный в проекте канал, несущий
поток событий на одну операцию (`ScanEvent::Row`/`Progress`/`Done`), а не одно-разовый
результат, как у любого другого `start_*` в `service.rs`. Пауза принимается параметром (не жёстко
зашитой константой) специально ради тестируемости — `sleep_cancellable()` протестирован с
короткими длительностями, реальные 10с (`PROBE_PAUSE`) передаются только из `service.rs`.
`sleep_cancellable()` спит интервалами по 250мс, проверяя флаг отмены между каждым — Stop
реагирует в пределах четверти секунды, а не только после полной паузы. Отправка в канал
(`tx.send(...).is_err()`) сама по себе — сигнал остановки: получатель пропал (страница/приложение
закрывается) — воркер завершается, не пытаясь продолжать в пустоту.

## 48.4	Модель страницы (`src/app/target_lookup.rs`)

`TargetScanPageModel` намеренно различает два префикса: `available_prefix` (что покажет/на что
нацелит кнопку Scan сейчас — вычисляется из *текущего* результата ASN-lookup) и
`scanned_prefix` (на что реально нацелен уже идущий/последний запуск — зафиксирован в момент клика
Scan). Это осознанное решение: если пользователь запустил новый ASN-lookup для другого хоста, пока
предыдущий скан ещё показан или идёт, секция скана не должна тихо «съехать» на новый префикс —
показанные строки должны безусловно относиться к тому префиксу, который реально сканировался.
`candidate_prefix()` (общая для availability-проверки страницы и для `service.rs::start_target_scan`,
`pub(crate)`) трактует пустой или `NA` BGP Prefix как «нет доступного префикса» — тот же паттерн,
что уже применён к `asn: Option<u32>` в §47.

## 48.5	Оркестрация (`src/app/service.rs`)

`target_scan_rx`/`target_scan_cancel`/`target_scan_rows`/`target_scan_checked`/
`target_scan_capped_total`/`target_scan_prefix_total`/`target_scan_prefix` — без
`CurrentOperation`, не в `is_any_remote_busy`, тот же принцип, что у `target_lookup_*` (§47.4):
скан не трогает SSH-сессию вообще. `start_target_scan()` резолвит префикс из текущего
`target_lookup_result`, вызывает `enumerate_cidr_hosts` (с капом `TARGET_SCAN_CAP = 256`,
публичная ассоциированная константа), строит TLS-конфиг один раз, заводит `Arc<AtomicBool>`
как флаг отмены (клонируется в поток), запускает `thread::spawn` — без `tokio::runtime::Builder`,
в отличие от каждого другого `start_*`, потому что вся цепочка `netinfo` синхронная (`std::net` +
блокирующий `rustls`), асинхронный рантайм не нужен. `poll_target_scan()` — единственный `poll_*`
в проекте, вычерпывающий все доступные на этот тик события в цикле (`loop { match
rx.try_recv() ... }`), а не одно, как у single-shot каналов везде остальные — этот канал
действительно поток из многих сообщений за один запуск, а не одноразовый результат.

## 48.6	GUI (`src/gui/pages/target_lookup.rs`)

Секция скана — под результатом ASN-lookup, на той же странице (не отдельная страница) — та же
логика размещения, что у Observatory-секции Metrics (§46.5): дешёвый доп. блок на уже
существующей странице лучше новой записи в сайдбаре, когда данные и так уже на экране. Кнопка
Scan показывает `available_prefix` (что произойдёт при клике сейчас); прогресс/таблица ниже —
`scanned_prefix` (что реально сканируется/сканировалось) — так что если два значения разошлись
(см. §48.4), пользователь это видит явно, а не путается. Строки стримятся в таблицу по мере
нахождения (не только по завершении) — тот же UX, что у стриминга Xray-логов, консистентно с
общим для проекта принципом «не заставлять ждать, пока покажется хоть что-то полезное».

## 48.7	Код

| Область | Путь |
| ------- | ---- |
| CIDR-перебор | `netinfo/cidr.rs` — `enumerate_cidr_hosts`, `CidrHosts` |
| Reverse DNS (PTR) | `netinfo/dns.rs` — `reverse_dns_lookup`, ручной RFC 1035 UDP-клиент |
| TLS-проба | `netinfo/tls_probe.rs` — `probe_tls`, `build_probe_tls_client_config`, `is_valid_reality_candidate`, `NoVerifier`, `TlsProbeResult` |
| Пайплайн кандидата | `netinfo/scan.rs` — `probe_scan_candidate`, `ScanCandidateRow` |
| Цикл скана | `app/target_scan_ops.rs` — `run_target_scan`, `ScanEvent`, `PROBE_PAUSE` |
| Модель страницы | `app/target_lookup.rs` — `TargetScanPageModel`, `TargetScanSnapshot`, `build_target_scan_page_model`, `candidate_prefix` |
| Service | `app/service.rs` — `target_scan_page_model`/`start_target_scan`/`stop_target_scan`/`poll_target_scan`, `TARGET_SCAN_CAP` |
| GUI | `gui/pages/target_lookup.rs` — новая секция под ASN-результатом (`show_scan_section`) |
| Зависимости | root `Cargo.toml` — `rustls` (features `aws-lc-rs`, `std`, `logging`, без `ring`/`tls12`), `x509-parser` |

## 48.8	Тесты

- `netinfo::cidr::tests` — 9 тестов: /24 (254 хоста, границы), /31 (2, без network/broadcast), /32
  (1 хост), кап не влияет на `total`, нормализация non-network-aligned адреса, /16 (`total =
  65534`), три варианта отклонения некорректного входа.
- `netinfo::dns::tests` — 8 тестов: построение запроса (реверс октетов, `in-addr.arpa`), разбор
  ответа без сжатия и со сжатием имени (pointer в вопрос), несовпадение ID, ненулевой RCODE,
  отсутствие PTR-записи в ответе, обнаружение зацикленного pointer'а, усечённый буфер.
- `netinfo::tls_probe::tests` — 6 тестов: все три критерия разом (оба допустимых ALPN, оба
  допустимых curve), отдельное отклонение по каждому из трёх критериев, явные строковые метки для
  `X25519`/`X25519MLKEM768`.
- `netinfo::scan::tests` — 1 тест (структурная проверка `domain_forward_resolves_to` на заведомо
  несуществующем домене — позитивный случай покрыт только живой проверкой, не CI, ниже).
- `app::target_lookup::tests` — 5 новых тестов для scan-модели: недоступность без BGP Prefix,
  доступность с префиксом, независимость `scanned_prefix` от последующего нового ASN-lookup,
  форматирование строк (join cert-domain, тире при пустом списке), прогресс/строки корректно
  попадают в модель.
- `app::target_scan_ops::tests` — 2 теста на `sleep_cancellable`: полная длительность без отмены,
  ранний выход при уже установленном флаге.
- Живая сквозная проверка всего пайплайна (временный игнорируемый тест, не оставлен в дереве —
  тот же принцип «одноразовая ручная проверка», что и в §47.7): `lookup_target_asn("dl.google.com")`
  → `216.58.198.0/24` → `enumerate_cidr_hosts(..., 8)` → `probe_scan_candidate` на каждый из первых
  8 IP — все 8 прошли: PTR (`*.1e100.net`, реальные Google-хосты), forward-resolve
  консистентность, TLS1.3, ALPN=h2, curve=X25519MLKEM768 (подтверждает, что
  `rustls`+`aws-lc-rs` действительно различает PQ-группу на живом современном сервере, не только
  синтетически), корректно извлечённые списки SAN-доменов сертификата (сотни записей на некоторых
  IP — Google использует широкие мультидоменные сертификаты).
- `cargo build` / `cargo build --lib`, `cargo clippy --lib --all-targets` — 0 новых warning в
  новых/затронутых файлах (те же 67 pre-existing warning в нетронутых файлах, не связаны).
  `cargo test --lib` — 865 passed (было 834 до этого пункта, §47.7; +31 новый — 24 в `netinfo`
  (9+8+6+1) + 5 в `app::target_lookup` + 2 в `app::target_scan_ops`), те же 9 pre-existing
  fixture-path failures, не связанные с этим пунктом.
- Не проверено вручную: полный запуск на 256 адресах через реальный GUI (заблокировано
  занятым/запущенным `feldjaeger.exe` в этой рабочей копии — не связано с корректностью кода,
  `cargo build --lib` собирается чисто); поведение кнопки Stop и live-стриминга строк в самом
  окне приложения — логика идентична уже протестированной (`sleep_cancellable`,
  `poll_target_scan`), но визуально не подтверждена.

# 49	Inbound import from Share URI / client link (Roadmap §3:133)

## 49.1	Цель и границы

Roadmap-формулировка не задавала объём. Два спорных момента, уточнённых с пользователем до
реализации:

1. Что создаёт импорт. Ссылка (`vless://`/`trojan://`/`hy2://`) кодирует и параметры
   inbound'а (порт, transport, security), и конкретного пользователя (UUID/пароль/auth, flow) —
   а это две разные операции в уже существующем Feldjäger: Add Inbound (`inbound_ops.rs`) и Add
   User в Users-табе (`users.rs`). Выбраны оба режима через выбор в диалоге импорта, а не один
   из них — пользователь решает для каждой конкретной ссылки, нужен ли новый inbound целиком или
   просто новый клиент в уже настроенном.
2. REALITY-ссылки. Публичный ключ (`pbk`) физически нельзя переиспользовать на сервере —
   приватный ключ никогда не передаётся по share-ссылке (подтверждено чтением кода генерации,
   `share_uri.rs`: `build_share_uri` берёт `pbk` только из ephemeral-результата `Generate x25519`,
   никогда не из серверного JSON). Выбрано импортировать и сразу генерировать новый keypair
   (тот же remote `xray x25519`, что уже использует preset-флоу, §3:123) — с явным предупреждением
   в превью, что исходная ссылка станет нерабочей и потребуется поделиться новой.

Что не импортируется (осознанно, с явным предупреждением вместо тихого пропуска —
`rules.md`: «must not hide configuration options»):
- TLS-сертификаты — никогда не в ссылке (только `sni`/`alpn`/`allowInsecure`); поля
  `certificateFile`/`keyFile` остаются пустыми, как у любого нового TLS-inbound'а.
- VLESS post-quantum `encryption` (когда не `"none"`) — серверный `decryption`-секрет, как и
  REALITY-приватный-ключ, никогда не передаётся клиенту; та же категория проблемы, то же решение
  (не импортировать, предупредить, оставить «Generate» на Protocol-табе как штатный путь).
- hy2 `pinSHA256` — чисто клиентское значение (пиннинг поверх реального сертификата), у Xray-core
  вообще нет соответствующего серверного поля — предупреждение без записи куда-либо.
- XHTTP `extra=` (URL-encoded JSON расширенных полей) — потребовал бы отдельного десериализатора
  «JSON → typed `XhttpStreamSettings`» (обратного тому, что уже есть у `xhttp_extra_json` только в
  одну сторону) — вне scope этой итерации; импортируются только базовые `path`/`host`/`mode`.
- hy2 port-hopping диапазон (`443,5000-6000`) при создании нового inbound'а — General-таб
  пишет только скалярный порт (`InboundGeneral.port: Option<u64>`, Roadmap §3:118 сознательно
  оставил non-scalar порт read-only на этом табе) — импортируется только первый порт диапазона,
  с предупреждением; полный диапазон можно дописать через Raw JSON escape hatch (§3:125).

Что импортируется полностью, без потерь: hy2 `obfs=salamander`/`obfs-password` — единственный
по-настоящему симметричный секрет среди Hysteria-параметров ссылки (обе стороны и так должны были
заранее согласовать этот пароль, в отличие от REALITY/TLS, где секрет асимметричен или вообще не
передаётся) — пишется в `streamSettings.finalmask.udp[]` слоем `salamander`. Технически это стало
возможно без нового кода записи: типизированная модель (`InboundStreamDraft.finalmask_udp` +
`write_finalmask_udp`) уже поддерживает произвольный протокол — «Wave A решила ограничить
редактирование FinalMask UDP для Hysteria» (§3:121) касалось только GUI-виджета, не самой модели
данных, так что импорт просто пишет в уже существующее поле напрямую, минуя отсутствующий виджет.

## 49.2	Парсинг (`src/xray/share_uri.rs`)

Расширение уже существовавшего модуля генерации share-ссылок (§3:115/§3:121/§3:122), не новый
модуль — `parse_share_uri`/`pct_decode`/`ParsedShareUri` дописаны туда же и переиспользуют
`ShareSecurity`/`ShareTransport` (те же типы, что и `build_share_uri`) вместо отдельных
«импортных» типов — так что вся логика интерпретации query-параметров (какой ключ соответствует
какому полю) существует только один раз, а не дублируется в двух направлениях.

Сам URI-парсинг написан вручную (без крейта `url`, который есть в `Cargo.lock` только транзитивно)
— тот же принцип «простой протокол — пишем сами», что и у whois-клиента (§47.2) и DNS PTR-клиента
(§48.2). Причина, по которой это остаётся простым: формат share-ссылок здесь — не произвольный
RFC 3986 URI (браузерные крайние случаи типа `userinfo:password@`, relative references,
`data:`-схемы и т.п. не нужны), а строго то, что сам же `build_share_uri` производит плюс
небольшая толерантность к другим инструментам (алиас `hysteria2://`, IPv6-литерал в скобках,
малформированные `%`-escape пропускаются как есть, а не отклоняются — `pct_decode`'s doc
комментарий явно объясняет, почему: вставленная пользователем ссылка — доверенный ввод, не
wire-данные атакующего). hy2 port-hop (`443,5000-6000`) в host:port-сегменте — единственная часть,
не покрываемая стандартным URI authority-парсингом в принципе (запятая в «порте») — обработана
отдельной веткой в `split_host_port`/основном парсере: при наличии запятой весь сегмент сохраняется
как `port_hop`, а первое число до `,`/`-` — как обычный `port`.

## 49.3	Модель превью (`src/app/inbound_import.rs`)

`build_import_preview(parsed: ParsedShareUri) -> ImportPreview` — чистая синхронная функция (без
SSH, без мутации), собирающая: типизированный `InboundClientProtocol` (из `ShareProtocol`),
человеко-читаемые сводки security/transport, и список предупреждений обо всём, что не
импортировано (см. §49.1) — вычисляется по ходу построения сводок (`describe_security`/
`describe_transport` принимают `&mut Vec<String>` и пушат туда же), а не отдельным проходом —
предупреждение и сводка для одного и того же поля физически не могут разойтись, потому что пишутся
в одном месте кода. `ImportPreview.parsed: ParsedShareUri` хранит исходные типизированные данные
целиком (не только сводки) — GUI-слой применяет их к драфтам напрямую, без повторного парсинга.

`ApplicationService::preview_inbound_import(&self, uri_text) -> Result<ImportPreview, String>` —
тонкая синхронная обёртка (`&self`, не `&mut self` — ничего не меняет в состоянии сервиса),
мирроринг того, как GUI уже вызывает `service.start_target_lookup(input)` вместо парсинга ввода
напрямую (`rules.md`: «GUI must not parse JSON»; вставленный текст ссылки — не JSON, но тот же
принцип «интерпретация пользовательского ввода идёт через ApplicationService, не в GUI-слое»
применён и здесь).

## 49.4	Применение превью (`src/gui/pages/inbounds.rs`, `src/gui/pages/users.rs`)

Создание нового inbound'а — `apply_import_to_new_inbound` зеркалит `apply_inbound_preset`
(§3:123) практически один-в-один: `begin_add_inbound(protocol)`, затем прямая работа с
`service.inbound_editor_session_mut()` (General.port, Security.mode + reality/tls поля,
Stream.method + xhttp/grpc/ws поля, для Hysteria — `finalmask_udp`), затем для REALITY —
`start_generate_x25519()`. Все поля остаются свободно редактируемыми после применения — импорт
только предзаполняет черновик, ничего не блокирует и не сохраняет само по себе; реальное сохранение
происходит через уже существующую Add Inbound кнопку формы, с тем же Preview changes/`-test`
путём, что и всегда.

Поскольку это Add-режим (`inbound_index: usize::MAX`), нового inbound'а физически ещё не
существует в момент применения превью — привязать к нему первого пользователя сразу невозможно
без ожидания асинхронного результата Save и последующего определения индекса новой записи.
Вместо усложнения (chaining «дождаться успеха Save → определить новый индекс → открыть Add User»)
выбрано простое решение: Status Bar показывает предзаполненные учётные данные («Save it, then add
the user via the Users tab — UUID: …») — пользователь сам довершает второй шаг тем же способом,
что и всегда делал бы вручную, только с данными уже под рукой, скопированными из вставленной
ссылки. Асимметрия с «add to existing» ниже (которая полностью автоматизирована) — осознанный
компромисс сложности/пользы, не недосмотр.

Добавление пользователя в существующий inbound — список кандидатов строится фильтрацией
`service.inbounds_page_model().rows` (`Vec<InboundSummary>`, уже несёт `protocol: Option<String>`
+ `index: usize`) по `import_protocol_wire(preview.protocol)` — тот же wire-string, что и в JSON
(`"vless"`/`"trojan"`/`"hysteria"`). После выбора: `service.set_selected_users_inbound(index)` +
`set_detail_tab(ui, InboundDetailTab::Users)` (обе уже существующие точки входа — первая используется
для программного выбора inbound'а под Users-таб, вторая для переключения самого таба) + новая
`pub(crate)`-функция в `users.rs` (`open_add_dialog_prefilled`/`open_add_trojan_dialog_prefilled`/
`open_add_hysteria_dialog_prefilled`) — зеркалит уже существующий приватный `open_add_dialog`
и т.п., но принимает распарсенные значения вместо генерации нового UUID / пустого черновика.
`ClientDialogDraft` остаётся module-private в `users.rs`, как и было — новые функции лишь
контролируемая точка входа для записи в него извне, инкапсуляция не нарушена. Этот путь полностью
автоматизирован: и inbound уже существует, и Add User — обычная, уже отработанная мутация, так
что диалог импорта закрывается сразу же, оставляя пользователя перед уже открытым, предзаполненным
диалогом Add User — остаётся только нажать «Add».

## 49.5	Код

| Область | Путь |
| ------- | ---- |
| Парсинг URI | `xray/share_uri.rs` — `parse_share_uri`, `pct_decode`, `ParsedShareUri` (расширение существующего модуля генерации) |
| Модель превью | `app/inbound_import.rs` — `ImportPreview`, `build_import_preview` |
| Service | `app/service.rs` — `preview_inbound_import` |
| GUI: предзаполненные Add User | `gui/pages/users.rs` — `open_add_dialog_prefilled`/`open_add_trojan_dialog_prefilled`/`open_add_hysteria_dialog_prefilled` (`pub(crate)`) |
| GUI: диалог импорта + применение | `gui/pages/inbounds.rs` — кнопка «Import from Share URI», `show_import_dialog`, `apply_import_to_new_inbound`, `import_protocol_wire` |

## 49.6	Тесты

- `xray::share_uri::tests` (новые, 14 из общих 32 в модуле) — `pct_decode`↔`pct_encode`
  round-trip, толерантность к малформированному `%`-escape, разбор VLESS+Reality/TLS+WS/
  Trojan+gRPC round-trip через уже существующие `build_share_uri`-фикстуры этого же файла, hy2 с
  одновременными obfs+pin+hop, алиас `hysteria2://`, IPv6-хост в скобках, четыре варианта
  отклонения некорректного входа (неизвестная схема, нет `://`, нет `@`, пустой credential),
  дефолты при отсутствии `security=`/`type=`, отсутствие hop у скалярного порта.
- `app::inbound_import::tests` — 7 тестов: предупреждение о новом REALITY-ключе (с точным текстом
  старого `pbk` в сообщении), обязательное предупреждение о сертификате для любого TLS-импорта,
  полное отсутствие предупреждений при `security=none`+`type=tcp` (базовый случай), предупреждение
  о non-none VLESS `encryption`, предупреждение о `extra=` при сохранении базовых xhttp-полей в
  сводке, совместное предупреждение о hy2 hop+pin, отсутствие предупреждения для обычного
  obfs-пароля (при этом сам пароль присутствует в `preview.parsed`).
- Не покрыто unit-тестами: сам `apply_import_to_new_inbound`/UI-диалог (требует живого
  `egui::Context` и `ApplicationService` с загруженным конфигом — тот же прецедент, что и у
  `apply_inbound_preset`, который тоже не покрыт unit-тестами в этом проекте) — оставлено на
  ручную/визуальную проверку.
- `cargo build` / `cargo build --lib`, `cargo clippy --lib --all-targets` — 0 новых warning в
  новых/затронутых файлах после исправления одного (collapsible-if в `pct_decode`, ушёл при
  переходе на let-chain) — те же 67 pre-existing warning в нетронутых файлах. `cargo test --lib`
  — 886 passed (было 865 до этого пункта, §48.8; +21 новый — 14 в `xray::share_uri` + 7 в
  `app::inbound_import`), те же 9 pre-existing fixture-path failures, не связанные с этим пунктом.
- Не проверено вручную: сам диалог импорта в живом GUI (заблокировано занятым `feldjaeger.exe` в
  этой рабочей копии, тот же caveat, что в §48.8) — визуальная компоновка, реальный клик по
  «Create new inbound»/«Add user to existing inbound» и последующее состояние формы не
  подтверждены глазами, только логически через типы и построение драфтов.

# 50	DNS Settings — редактор секции `dns` (Roadmap §2.1:46)

## 50.1	Цель и границы

Roadmap-пункт `dns edit (servers, hosts, queryStrategy, …)` не задавал объём явно — уточнено с
пользователем до реализации (см. диалог): взято полное покрытие обоих официальных объектов
(<https://xtls.github.io/en/config/dns.html>), а не только тех полей, что уже показывал read-only
`DnsSummary` (§19: 5 из 12 верхнеуровневых, 5 из 14 серверных). Мотивация — заголовок самого Tier 2
(«100% возможностей Xray-core») и то, что оба уже реализованных root-section редактора (Log
Settings §30, API Settings §44) полностью покрывают свои официальные объекты, а не подмножество.

Один и тот же экран для чтения и записи. В отличие от API (§43 API Console живёт отдельно от
§44 API Settings — операционные gRPC-вызовы принципиально не то же самое, что редактирование
файла), у DNS нет отдельного «живого» режима, от которого имело бы смысл отделять редактор — поэтому
`gui/pages/dns.rs` остаётся одной страницей, дополненной View/Edit/Save/Cancel/Preview changes
поверх уже существовавшей read-only разметки (контекстные пункты «Edit»/«Delete»/«Duplicate» на
строках servers/hosts стояли отключёнными с пометкой «Not implemented yet» ещё с §19 — этот пункт
их включает).

## 50.2	Типизированная модель (`src/xray/config/dns_settings.rs`)

`DnsSettings` зеркалит структуру `LogSettings`/`ApiSettings` (`*_from_section`/
`apply_*_to_value`/`*_to_new_value`/`*_change_summary`/`validate_*`), но заметно шире —
единственный root-section редактор в проекте, где одно из полей (`servers`) само является массивом
вложенных объектов с 14 полями каждый:

- `QueryStrategy` (`UseIp`/`UseIPv4`/`UseIPv6`/`UseSystem`/`Unknown(String)`) — тот же
  паттерн «сохранить нераспознанное значение как есть», что `LogLevel`/`LogOutput`/`MaskAddress` в
  `log_settings.rs`; используется и на верхнем уровне (`DnsSettings::query_strategy`, всегда
  материализуется в JSON, даже когда равен документированному дефолту `UseIP` — тот же выбор, что
  `LogLevel` в Log Settings), и как per-server override (`Option<QueryStrategy>`, `None` = ключ
  отсутствует = «наследовать от верхнего уровня»).
- `DnsServerEntry` — все 14 полей `DnsServerObject`. Ключевая деталь, которую легко перепутать:
  верхнеуровневый EDNS client-subnet — `clientIp` (строчная `p`), серверный override — `clientIP`
  (заглавная `IP`) — реальная асимметрия названий полей в самом Xray-core, а не опечатка; оба уже
  так читались в `summary.rs::dns_servers()` (§19) и здесь воспроизведены буквально теми же
  строковыми литералами что в парсере, что в `apply_dns_settings_to_value`.
- Автоматический шорткат-коллапс. `servers[]` в официальном формате допускает элемент как
  голую строку-адрес, так и полный объект. Редактор не заставляет пользователя выбирать форму
  явно — `DnsServerEntry::is_shorthand_eligible()`/`to_value()` сами решают: если из всех 13
  необязательных полей ни одно не задано (только `address`), в JSON пишется `Value::String`, иначе
  — полный объект, в который каждое поле попадает только когда оно `Some`/непусто/не равно дефолту
  (`skipFallback`/`finalQuery` — ключ вообще отсутствует, если `false`, а не `"skipFallback": false`).
  Семантически эквивалентно тому, что мог написать человек руками, просто в канонической форме —
  не нарушение `rules.md`: «Feldjaeger must never intentionally deviate from the official
  configuration format» (обе формы валидны и равнозначны по официальной спецификации).
- `hosts` — `Vec<DnsHostEntry>` (`domain` + `targets: Vec<String>`), а не `HashMap`, потому что
  порядок отображения в UI должен быть стабильным между кадрами. На запись — ровно то же
  единственная-строка-vs-массив правило, что и у `servers`: один target → `Value::String`, больше
  одного → `Value::Array`. Итерация при чтении остаётся алфавитной (как и раньше в §19) —
  `serde_json` в этом проекте собран без фичи `preserve_order` (`Cargo.toml`: `serde_json =
  "1.0.151"`), так что `Value::Object` — это `BTreeMap`, и специального кода для сохранения порядка
  не потребовалось нигде в этом пункте.
- Незлые предупреждения вместо тихой потери данных. Серверная запись без `address` или запись
  `hosts` с несловарным/нестроковым значением не отбрасываются молча — попадают в `warnings` с
  указанием позиции/домена, и продолжают round-trip'иться, пока пользователь не поправит их в
  редакторе или Save. Единственный случай, когда запись действительно теряется при следующем
  Save — элемент `servers[]`, чей JSON-тип вообще не строка и не объект (число/булево/`null`) —
  структурно невозможно восстановить в типизированную модель; тот же класс ограничения, что уже
  существовал у `services`-массива в API Settings (§44.2) и у enum-массивов клиентов в Users (§32).
- Валидация (`validate_dns_settings`) — намеренно нестрогая («prefer compatibility over
  convenience»), но с двумя содержательными проверками сверх стандартного набора «нет управляющих
  символов»: `clientIp`/`clientIP`, когда заданы, обязаны парситься как `std::net::IpAddr` (в
  отличие от `api.listen`/путей логов в §30/§44, где грамматика намеренно не проверяется — EDNS
  client-subnet однозначно обязан быть голым IP, двусмысленности в формате нет), и
  `serveExpiredTTL` (оба уровня) не может быть отрицательным. Плюс структурные проверки самого
  редактора: непустой `address` у каждого сервера, непустой `domain` и хотя бы один `target` у
  каждой hosts-записи, уникальность `domain` (ключи JSON-объекта обязаны быть уникальны).

## 50.3	`EditableXrayConfig::with_dns_mut` (`editable.rs`) и `dns_mut()` (`sections.rs`)

Дословно зеркалит `with_api_mut`/`with_log_mut`: секция `dns: {}` создаётся только на Save, если
отсутствовала (`resolve_dns_target_file` — тот же алгоритм выбора файла для confdir-раскладки, что
`resolve_log_target_file`/`resolve_api_target_file`, с эвристикой «имя файла содержит `dns`»).
Потребовался один новый метод в `sections.rs` — `dns_mut()` (симметрично уже существовавшим
`dns()`/`set_dns()`; `log_mut()`/`api_mut()` уже были, `dns_mut()` — единственный пробел).

## 50.4	Мутация (`modify.rs::update_dns_settings`) и оркестрация (`app/dns_settings_ops.rs`)

`update_dns_settings` дословно зеркалит `update_api_settings`/`update_log_settings` (validate →
snapshot всех корней → `with_dns_mut` → serialize → `validate_dns_structure_after_edit` → собрать
`ModifyConfigOutcome`). Ошибка «malformed dns object» получила отдельный
`ConfigModifyErrorKind::MalformedDnsObject` (по образцу `MalformedLogObject`, а не переиспользования
общего `ValidationFailed`, как сделано у API §44.2 — симметрия с Log показалась более уместной,
раз уж это третий root-section редактор и типизированный kind уже есть один раз). `app/
dns_settings_ops.rs::run_update_dns_settings` дословно зеркалит `run_update_api_settings`, включая
conflict-check перед записью.

## 50.5	Страница DNS (`src/app/dns.rs`, `src/gui/pages/dns.rs`)

`DnsPageState` перестроен по образцу `ApiSettingsPageState`: вместо тупиковых
`DnsSectionMissing`/`ConfigurationLoaded`/`ConfigurationContainsWarnings` — `ViewMode`/`EditMode`/
`ValidationError`/`Saving`/`Saved`/`SaveFailed`/`MalformedDnsObject`; отсутствие секции больше не
особый терминальный статус (как и у Log/API — просто `DnsSettings::defaults()` с
`section_present: false`, объект создаётся только по Save). Старые форматтеры
`DnsGeneralDisplay`/`DnsServerRowDisplay`/`DnsHostRowDisplay` удалены — страница форматирует
напрямую по `DnsSettings`/`DnsServerEntry`/`DnsHostEntry`, отдельный display-слой для них был бы
чистым дублированием (у API/Log такого промежуточного слоя тоже нет).

View-режим — таблица из всех 12 верхнеуровневых полей (подписаны и JSON-ключом для сверки с
официальной документацией), плюс компактная сводка по каждому server/host с раскрывающимися
подробностями по клику — 14 колонок на серверную таблицу физически не помещаются, тот же компромисс,
что уже принят для широких структур в Inbound-редакторах. Edit-режим — тот же
View/Edit/Save/Cancel/Preview changes chrome, что у API Settings (§44.5), плюс редактируемые списки
`servers`/`hosts` с Add/Remove на каждую запись (без drag-reorder — порядок редактирования и есть
порядок сохранения); необязательные числовые/enum/bool-поля редактируются через чекбокс
«задать значение» + виджет, три состояния «Inherit/On/Off» для `Option<bool>` override'ов сервера.

Пресеты серверов (2026-08-17, дополнение к §50). Рядом с «Add server» — отдельная кнопка-меню
«Presets ▾» (`egui::menu_button`, вложенные подменю по провайдеру: Cloudflare/Google/Quad9/
OpenDNS/AdGuard/CleanBrowsing/DNS.WATCH/Comodo/Yandex/Verisign + спецзначения `localhost`/
`fakedns`), список — `DNS_SERVER_PRESET_GROUPS` в `gui/pages/dns.rs`, чистые данные (`&'static
[(label, address)]`), без изменений в типизированной модели. Клик по пресету добавляет новый
`DnsServerEntry::blank()` с уже заполненным `address` в конец `draft.servers` — ни один пресет
не трогает уже введённые вручную значения ни в текстовых полях, ни в списке (явное требование
пользователя «не мешать вводу значений вручную»), поэтому кнопка физически отделена от поля
`address` и не имеет общего состояния с ним.

## 50.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/dns_settings.rs` |
| `with_dns_mut` / `dns_mut()` / `set_dns()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_dns_settings` + `UpdateDnsSettingsRequest`, `ConfigModifyErrorKind::MalformedDnsObject` |
| Оркестрация | `app/dns_settings_ops.rs::run_update_dns_settings` |
| Page model | `app/dns.rs` — `DnsPageState`/`DnsPageModel`, `build_dns_page_model` (перестроены под View/Edit) |
| Service | `app/service.rs` — `dns_page_model`, `begin_edit_dns_settings`/`cancel_edit_dns_settings`/`dns_settings_draft_mut`/`dns_settings_draft`/`preview_dns_settings_diff`/`dns_settings_diff_preview`/`start_save_dns_settings`/`poll_dns_settings_mutation`/`is_dns_settings_mutation_busy`; новый `CurrentOperation::SavingDnsSettings` |
| GUI | `gui/pages/dns.rs` (перестроена под View/Edit, страница и навигационная запись — те же, что в §19) |

## 50.7	Тесты

- `xray::config::dns_settings::tests` — 20 тестов: defaults при отсутствии секции, round-trip всех
  10 скалярных верхнеуровневых полей, строка-шорткат vs полный объект в парсинге сервера (включая
  предупреждение при отсутствующем `address` и пропуск нераспознанной JSON-формы с
  предупреждением), одиночная строка vs массив в `hosts` (включая пропуск нераспознанной формы),
  сохранение неизвестного `queryStrategy` с предупреждением, сохранение посторонних JSON-ключей при
  `apply`, шорткат-коллапс round-trip для голого адреса, сервер только с `port` сериализуется как
  объект (не коллапсирует), change summary только по изменённым полям, отклонение пустого
  `address`/управляющих символов/некорректного `clientIp`/отрицательного `serveExpiredTTL`/
  дублирующегося `domain`/пустых `targets`, валидация принимает и дефолты, и полностью заполненные
  настройки.
- `app::dns::tests` — 2 теста: `NoSshConnection`, `XrayNotDiscovered` (тот же минимальный набор
  page-state тестов, что у API Settings §44.7 — полное покрытие состояний уже есть на уровне модели
  `dns_settings`); 5 старых тестов (форматирование через удалённые display-хелперы,
  `DnsSectionMissing`) удалены вместе с самими хелперами.
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4/§42.6/
  §43.7/§44.7): `dns_settings_ops.rs::run_update_dns_settings` требует mock `SshBackend`.
- `cargo build` / `cargo build --all-targets`, `cargo clippy --lib --all-targets` — 0 новых warning
  в затронутых файлах (67 pre-existing warning в нетронутых файлах, как и в §49.6). `cargo test
  --lib` — 901 passed (было 886 после §49; 20 новых `dns_settings`, −5 удалённых display-тестов
  §19), те же 9 pre-existing fixture-path failures (`tests/fixtures/xray/` отсутствует на диске в
  этой рабочей копии — не связаны с этим пунктом).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `dns` объекта с нуля,
  конфликт при параллельном изменении файла, реальный рендер списков servers/hosts в GUI) — нет
  доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7.

# 51	FakeDNS Settings — редактор значения `fakedns` (Roadmap §2.1:47)

## 51.1	Цель и границы

Roadmap-пункт `fakedns edit` тоже не задавал объём явно, но здесь спор оказался вырожденным: у
`FakeDnsObject` всего два официальных поля (`ipPool`, `poolSize` —
<https://xtls.github.io/en/config/fakedns.html>), так что «полное покрытие» — единственный разумный
вариант, вопрос пользователю не задавался (в отличие от DNS §50, где выбор между 5+5 и 12+14 полями
был содержательным).

Единственная реальная архитектурная особенность этого пункта — сам верхнеуровневый `fakedns`
не всегда объект: официальный формат разрешает как один `FakeDnsObject`, так и массив пулов
(несколько одновременных диапазонов — например IPv4 + IPv6 сразу). Это первый root-section
редактор в проекте, где сама структура значения меняется в зависимости от количества элементов, а
не только содержимое внутри фиксированной оболочки-объекта, как у `log`/`api`/`dns` (§30/§44/§50).

Как и у DNS (§50), это одна страница на view+edit — у FakeDNS так же нет отдельного live-режима,
ради которого имело бы смысл делать вторую страницу.

## 51.2	Типизированная модель (`src/xray/config/fakedns_settings.rs`)

`FakeDnsSettings { pools: Vec<FakeDnsPoolEntry>, .. }` — список, а не одиночный объект с флагом
«это массив», потому что список уже сам по себе однозначно описывает обе формы: один элемент → при
сохранении пишется как голый объект, ноль или два и более → как массив. Выбор формы делает
`apply_fakedns_settings_to_value` (`*target = match pools { [only] => ..., many => ... }`) — тот же
принцип автоколлапса «в простейшую эквивалентную форму», что уже применяет `dns_settings.rs` к
`servers[]` (§50.2).

`FakeDnsPoolEntry` — `ip_pool: String` (обязательное, пустое допускается *в памяти* — для
незавершённой записи, загруженной с диска, чтобы её можно было увидеть и поправить, а не молча
потерять — тот же принцип, что и у пустого `address` в `DnsServerEntry`, §50.2), `pool_size:
Option<u64>` (`None` = ключ отсутствует = принять встроенный дефолт Xray, задокументированный как
65535), и `extra: Map<String, Value>` — единственное место, где неизвестные JSON-ключи *внутри*
редактируемого объекта хранятся отдельным полем, а не игнорируются на чтении (как делает `log`/
`api`/`dns`, у которых `apply_*_to_value` просто не трогает посторонние ключи родительского
объекта): здесь родительского объекта в привычном смысле нет — весь пул целиком заменяется при
сохранении, поэтому «оставить как есть» невозможно, только «прочитать и записать обратно
буквально».

Валидация (`validate_fakedns_settings`) — единственная содержательная проверка: `ipPool`
обязан быть настоящим CIDR-блоком (адрес + префикс, префикс в границах семейства адреса) —
переиспользует ту же логику, что уже была у read-only `classify_ip_pool` (§22), только теперь как
отказ записи, а не просто предупреждение. `poolSize` намеренно не сверяется с ёмкостью `ipPool`
(документированное ограничение Xray) — рантайм-проверка, которую и так проведёт `xray run -test`
после каждого сохранения; переизобретать её здесь означало бы дублировать логику Xray-core без
явной необходимости (`rules.md`: «prefer compatibility over convenience»).

## 51.3	`EditableXrayConfig::with_fakedns_mut` (`editable.rs`) и `fakedns_mut()` (`sections.rs`)

Структурно отличается от `with_dns_mut`/`with_log_mut`/`with_api_mut`: те принимают, что секция —
всегда JSON-объект (`Value::Object`/`Value::Null`-создаёт-объект в начале, дальше мутация внутри
объекта). Здесь ровно наоборот — `op` (в реальности всегда `apply_fakedns_settings_to_value`)
заменяет `*target` целиком, так что `with_fakedns_mut` инициализирует отсутствующую секцию как
`Value::Null` (любое исходное значение всё равно немедленно перезаписывается) и не требует, чтобы
результат был объектом. Потребовался один новый метод в `sections.rs` — `fakedns_mut()`
(симметрично уже существовавшим `fakedns()`/`set_fakedns()`).

## 51.4	Мутация (`modify.rs::update_fakedns_settings`) и оркестрация (`app/fakedns_settings_ops.rs`)

`update_fakedns_settings` мирроринг `update_dns_settings` (validate → snapshot всех корней →
`with_fakedns_mut` → serialize → `validate_fakedns_structure_after_edit` → собрать
`ModifyConfigOutcome`), с единственным отличием в структурной проверке: она принимает и объект,
и массив (`!fakedns.is_object() && !fakedns.is_array()` — только тогда ошибка), поскольку обе
формы равно легитимны и `apply_fakedns_settings_to_value` сама решает, какую использовать. Ошибка
получила отдельный `ConfigModifyErrorKind::MalformedFakeDnsObject` (по образцу `MalformedDnsObject`/
`MalformedLogObject`) с формулировкой «expected an object or an array of objects», а не «expected a
JSON object», как у `log`/`api`/`dns` — единственное текстовое отличие, отражающее реальную разницу
в допустимой форме. `app/fakedns_settings_ops.rs::run_update_fakedns_settings` дословно зеркалит
`run_update_dns_settings`, включая conflict-check перед записью.

## 51.5	Страница FakeDNS (`src/app/fakedns.rs`, `src/gui/pages/fakedns.rs`)

`FakeDnsPageState` перестроен по образцу `DnsPageState`/`ApiSettingsPageState`: вместо тупиковых
`FakeDnsSectionMissing`/`ConfigurationLoaded`/`ConfigurationContainsWarnings` —
`ViewMode`/`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/`MalformedFakeDnsObject`.
Старые форматтеры `FakeDnsPoolDisplay`/`fakedns_pool_display`/`display_address_family` (включая
CIDR-калькулятор ёмкости пула для отображения) удалены вместе с `FakeDnsAddressFamily`-зависимым
UI — редактор показывает `ipPool`/`poolSize` напрямую, без промежуточного display-слоя, тот же
выбор, что и у DNS (§50.5); адресное семейство (IPv4/IPv6/Unknown) было полезно исключительно для
read-only витрины и не несёт отдельного смысла в редакторе, где сам `ipPool` уже виден целиком.

View-режим — простая таблица `ipPool`/`poolSize` по пулам (два столбца — ровно два поля объекта,
табличная форма здесь уместнее, чем `CollapsingHeader`-на-пул из DNS §50.5, который был нужен там
из-за 14 полей на сервер). Edit-режим — тот же View/Edit/Save/Cancel/Preview changes chrome, что у
DNS/API Settings, плюс редактируемый список пулов с Add/Remove на каждый (без drag-reorder, тот же
принцип, что у списков `servers`/`hosts` в DNS-редакторе); пулы с непустым `extra` показывают
короткую пометку «N полей сохранено, но не редактируется здесь» — честно про границу редактора, не
скрывая, что данные есть, но структурного доступа к ним нет (`rules.md`: «must not hide
configuration options»).

Пресеты пулов (2026-08-17, дополнение к §51). Рядом с «Add pool» — та же кнопка-меню
«Presets ▾», что и у DNS-серверов (§50.5), список — `FAKEDNS_POOL_PRESETS` в
`gui/pages/fakedns.rs`. Помимо официального дефолта Xray (`198.18.0.0/15`, RFC 2544, тоже входит в
список — первым пунктом), предложены альтернативы из IANA-зарезервированных
«никогда не маршрутизируется в реальном интернете» блоков: половины дефолтного диапазона
(`198.18.0.0/16` / `198.19.0.0/16`), три RFC 5737 TEST-NET (`192.0.2.0/24` / `198.51.100.0/24` /
`203.0.113.0/24` — маленькие, 256 адресов, поэтому пресет также подставляет `poolSize: Some(200)`,
а не оставляет дефолтные 65535, которые превысили бы ёмкость блока) и два IPv6-варианта
(`fc00::/18` — тот же диапазон, что уже используется как пример в собственных тестах проекта;
`2001:db8::/32` — документационный RFC 3849). Приватные RFC 1918-диапазоны (`10.0.0.0/8` и т.п.)
осознанно не предлагаются — в отличие от IANA test/benchmark-блоков они с высокой вероятностью уже
заняты домашней/VPN-сетью пользователя, так что предлагать их как выбор было бы не удобством, а
источником реального конфликта маршрутизации. Как и у DNS, клик по пресету только добавляет новую
запись в `draft.pools`, не трогая уже введённые вручную значения.

## 51.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/fakedns_settings.rs` |
| `with_fakedns_mut` / `fakedns_mut()` / `set_fakedns()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_fakedns_settings` + `UpdateFakeDnsSettingsRequest`, `ConfigModifyErrorKind::MalformedFakeDnsObject` |
| Оркестрация | `app/fakedns_settings_ops.rs::run_update_fakedns_settings` |
| Page model | `app/fakedns.rs` — `FakeDnsPageState`/`FakeDnsPageModel`, `build_fakedns_page_model` (перестроены под View/Edit) |
| Service | `app/service.rs` — `fakedns_page_model`, `begin_edit_fakedns_settings`/`cancel_edit_fakedns_settings`/`fakedns_settings_draft_mut`/`fakedns_settings_draft`/`preview_fakedns_settings_diff`/`fakedns_settings_diff_preview`/`start_save_fakedns_settings`/`poll_fakedns_settings_mutation`/`is_fakedns_settings_mutation_busy`; новый `CurrentOperation::SavingFakeDnsSettings` |
| GUI | `gui/pages/fakedns.rs` (перестроена под View/Edit, страница и навигационная запись — те же, что в §22) |

## 51.7	Тесты

- `xray::config::fakedns_settings::tests` — 21 тест: defaults при отсутствии секции, парсинг
  одиночного объекта и массива (включая пустой массив как некритичное предупреждение и
  нераспознанную форму элемента массива с пропуском+предупреждением), отсутствующий `ipPool`
  сохраняется с предупреждением (не отбрасывается), отсутствующий `poolSize` — `None` без
  предупреждения (поле официально опционально), сохранение неизвестных полей пула в `extra` и их
  round-trip при `apply`, коллапс одного пула в объектную форму и разворот нескольких в массив,
  пустой список пулов сериализуется как `[]`, пропуск ключа `poolSize` при `None`, change summary
  пуст при отсутствии изменений и содержит счётчик пулов при их количестве, валидация принимает
  дефолты и полностью заполненные настройки, отклоняет пустой/не-CIDR/с недопустимым префиксом/с
  управляющими символами `ipPool`.
- `app::fakedns::tests` — 2 теста: `NoSshConnection`, `XrayNotDiscovered` (тот же минимальный набор,
  что у DNS §50.7/API Settings §44.7); 7 старых тестов (форматирование через удалённые
  display-хелперы, CIDR-калькулятор ёмкости, `FakeDnsSectionMissing`) удалены вместе с самими
  хелперами.
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4/§42.6/
  §43.7/§44.7/§50.7): `fakedns_settings_ops.rs::run_update_fakedns_settings` требует mock
  `SshBackend`.
- `cargo build` / `cargo build --all-targets`, `cargo clippy --lib --all-targets` — 0 новых warning
  в затронутых файлах (67 pre-existing warning в нетронутых файлах, как и в §50.7). `cargo test
  --lib` — 915 passed (было 901 после §50; 21 новый `fakedns_settings`, −7 удалённых
  display-тестов §22), те же 9 pre-existing fixture-path failures, не связанные с этим пунктом.
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `fakedns` значения с нуля в
  обеих формах, конфликт при параллельном изменении файла, реальный рендер списка пулов в GUI) —
  нет доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7/
  §50.7.

# 52	Routing Settings — редактор секции `routing` (Roadmap §2.1:48)

## 52.1	Цель и границы

Roadmap-пункт `routing edit (rules, balancers, domainStrategy, …)` не задавал объём явно —
взято, как и у DNS/FakeDNS/API (§44/§50/§51), полное покрытие официальных объектов
(<https://xtls.github.io/ru/config/routing.html>): `RoutingObject` целиком (`domainStrategy`/
`rules`/`balancers`), все задокументированные поля `RuleObject` (включая `webhook` →
`WebhookObject`), и весь `BalancerObject` (`tag`/`selector`/`fallbackTag`/`strategy` →
`StrategyObject`/`StrategySettingsObject`/`CostObject` для `leastLoad`).

Один спорный момент, уточнённый с пользователем до реализации: поле `routing.domainMatcher`.
Read-only `RoutingSummary` (§20) уже читает и показывает это поле («Domain matcher»), но перед тем
как делать его редактируемым, была сверка с исходниками Xray-core
(`infra/conf/router.go` — `RouterConfig` объявляет только `RuleList`/`DomainStrategy`/`Balancers`,
без `DomainMatcher`) и с текущей англ. документацией `config/routing.html` — поле отсутствует в
обоих источниках. Возможные причины (устарело/удалено в актуальном Xray-core, либо документировано
только неофициально) не определены точно. Предложены три варианта — свободное текстовое поле без
enum, выпадающий список с угаданными `hybrid`/`linear`, оставить только в read-only просмотре без
поля в форме редактирования — пользователь выбрал третий: поле убрано из формы редактирования
целиком (`RoutingSettings` в `routing_settings.rs` его не моделирует вовсе). Так как
`apply_routing_settings_to_value` мутирует уже существующий JSON-объект `routing` на месте (вставляя/
удаляя только известные ключи — `domainStrategy`/`rules`/`balancers`), уже присутствующий на диске
`domainMatcher` переживает Save нетронутым «бесплатно», без отдельного `extra`-слота на
верхнем уровне — тот же механизм, что уже документирован для `dns`/`api` (§44.2/§50.2): «apply
preserves unrelated top-level keys» проверено отдельным тестом
(`apply_preserves_unrelated_top_level_keys_including_domain_matcher`).

Как и у DNS/FakeDNS/API (§44/§50/§51), это одна страница на browsing+edit — но с более сложной
композицией, чем у них: у Routing уже была богатая read-only страница с таблицей/сортировкой/
detail-панелью (§20), которую редактирование не заменяет, а дополняет. Решение — то же, что уже
работает для Inbounds (сводная таблица + отдельная typed `InboundEditorSession`, §34): browsing
остаётся на `RoutingSummary`/`RoutingRuleSummary` без изменений, редактирование — отдельный typed
draft на `RoutingSettings`, оба режима на одной странице через `RoutingPageModel.editing`.

## 52.2	Типизированная модель (`src/xray/config/routing_settings.rs`)

Ещё на тон сложнее, чем `DnsSettings` (§50.2) — не просто массив объектов с плоскими полями
(`servers[]`), а массив объектов, один из которых (`balancers[].strategy.settings.costs[]`) сам
трёхуровнево вложен:

- `DomainStrategy`/`NetworkKind`/`BalancerStrategyType` — три enum'а того же вида, что
  `QueryStrategy` у DNS (§50.2): именованные варианты + `Unknown(String)` для сохранения
  нераспознанного значения, `default_effective()` для документированного дефолта Xray
  (`AsIs`/нет-эквивалентно-`None`/`random` соответственно). `domainStrategy` и `strategy.type`
  всегда материализуются в JSON, даже когда равны дефолту (тот же выбор, что `queryStrategy` у
  DNS); `network` пишется только когда задан (`None` = поле отсутствует = «любая сеть» на стороне
  Xray, а не наследование от чего-либо — умышленно не путается с `Option`-override'ами DNS-серверов,
  где `None` означает «inherit», у routing rules наследовать не от чего).
- `RoutingRuleEntry` — 17 полей `RuleObject`, включая псевдоним `sourceIP`/`source`: читается
  «предпочесть `sourceIP`, если пусто — попробовать `source`» (тот же приоритет, что уже был у
  read-only `RoutingRuleSummary::from_rule_value`, §20.1.2), но пишется только `sourceIP` —
  каноническое имя, `source` никогда не создаётся заново (тот же принцип, что `clientIp`/`clientIP`
  у DNS §50.2: асимметрия имён не «исправляется», а полю просто не нужно два актуальных написания
  одновременно). `port`/`sourcePort`/`localPort`/`vlessRoute` хранятся как обычные `Option<String>`
  (не `Option<u16>`, как порт у DNS-серверов, §50.2) — официальный формат допускает диапазоны и
  списки (`"53,443,1000-2000"`), которые не влезают в скаляр; при записи всегда выбирается
  JSON-строковая форма (даже для голого числа) — Xray-core одинаково понимает и число, и строку с тем
  же значением, так что не нужно распознавать/сохранять исходный JSON-тип ради этого поля.
- `attrs`/webhook `headers` — `Vec<(String, String)>`, а не `HashMap`/`serde_json::Map`, чтобы
  порядок отображения в UI был стабилен между кадрами — тот же мотив, что у `hosts` в DNS (§50.2).
- `WebhookEntry` — `url`/`deduplication`/`headers`, тот же идиом «пустое допустимо в памяти,
  отклоняется только на Save» для обязательного `url`, что у `address` в `DnsServerEntry`/`ipPool` в
  `FakeDnsPoolEntry` (§50.2/§51.2).
- `BalancerEntry` → `StrategyEntry` → `StrategySettingsEntry` → `CostEntry` — четыре уровня
  вложенности ради одного документированного случая (`leastLoad`-тюнинг: `expected`/`maxRTT`/
  `tolerance`/`baselines`/`costs[]`), каждый уровень — независимый `Option<...>`, так что балансировщик
  может иметь `strategy` без `settings`, или `settings` без единого `cost` — редактор не навязывает
  заполнение вложенных объектов только потому, что открыт внешний.
- Сохранение неизвестных полей per-entry. И `RoutingRuleEntry`, и `BalancerEntry` несут
  `extra: Map<String, Value>` (тот же паттерн, что `FakeDnsPoolEntry::extra`, §51.2, а не «оставить
  как есть», доступное `dns`/`api`/`log`, — здесь тоже нет родительского объекта, весь массив
  `rules[]`/`balancers[]` пересобирается на Save целиком). Условно-легаси поле `type` из `RuleObject`
  (в старых версиях документации — фиксированный литерал `"field"`; в текущем `infra/conf/router.go`
  оно не встречается ни в `RouterRule`, ни в `RawFieldRule` — судя по всему, не разбирается парсером
  вовсе) сюда же: не моделируется отдельным полем, а сохраняется через `extra`, если уже
  присутствует на диске — не изобретается заново.
- Валидация (`validate_routing_settings`) — нестрогая («prefer compatibility over
  convenience»), как и у DNS/FakeDNS (§50.2/§51.2): контроль управляющих символов на все строковые
  поля, без попытки переизобрести грамматику диапазонов портов/длительностей (`xray run -test`
  и так проверит после каждого Save). Содержательные структурные проверки — ровно те, что
  задокументированы: у каждого правила обязан быть `outboundTag` или `balancerTag` (иначе
  правило никогда никуда не маршрутизирует), у каждого балансировщика — непустой и уникальный
  `tag`, у `webhook` — непустой `url`, у каждого `cost` — непустой `match`.

## 52.3	`EditableXrayConfig::with_routing_mut` (`editable.rs`) и `routing_mut()` (`sections.rs`)

Дословно зеркалит `with_dns_mut` (§50.3) — `routing`, как и `dns`, всегда JSON-объект (в отличие от
`fakedns`, §51.3, где сама форма значения меняется), секция создаётся только на Save, если
отсутствовала (`resolve_routing_target_file` — тот же алгоритм с эвристикой «имя файла содержит
`routing`»). Потребовался один новый метод в `sections.rs` — `routing_mut()` (симметрично уже
существовавшим `routing()`/`set_routing()`, которые уже были нужны read-only странице §20).

## 52.4	Мутация (`modify.rs::update_routing_settings`) и оркестрация (`app/routing_settings_ops.rs`)

`update_routing_settings` дословно зеркалит `update_dns_settings` (§50.4): validate → snapshot всех
корней → `with_routing_mut` → serialize → `validate_routing_structure_after_edit` → собрать
`ModifyConfigOutcome`. Новый `ConfigModifyErrorKind::MalformedRoutingObject` — по образцу
`MalformedDnsObject`. `app/routing_settings_ops.rs::run_update_routing_settings` дословно зеркалит
`run_update_dns_settings`, включая conflict-check перед записью.

## 52.5	Страница Routing (`src/app/routing.rs`, `src/gui/pages/routing.rs`)

В отличие от DNS/FakeDNS/API (§44/§50/§51), `RoutingPageState` не перестроен с нуля — существующие
browsing-состояния (`RoutingSectionMissing`/`NoRoutingRules`/`ConfigurationLoaded`/
`ConfigurationContainsWarnings`, §20) сохранены как есть (таблица/сортировка/detail-панель по клику
на строку по-прежнему работают ровно как раньше), поверх них добавлены edit-состояния
(`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/`MalformedRoutingObject`) с тем же
приоритетом переопределения, что у DNS (`build_dns_page_model`, §50.5): Saving > Saved > (ошибка +
режим редактирования → ValidationError) > (ошибка + не редактируется → SaveFailed) > Malformed >
EditMode > browsing-состояние. `build_routing_page_model` получил 4 новых параметра
(`draft`/`saving`/`error_message`/`saved_flash`, та же сигнатура, что у DNS/FakeDNS) в дополнение к
уже существовавшим `sort`; `RoutingPageModel` — новые поля `routing_settings`/`editing`/
`change_summary`/`error_message`, унаследовав `Eq` пришлось снять (единственный root-section
редактор, где часть числовых полей — `f64`: `strategy.settings.tolerance`, `costs[].value`, у
которых нет `Eq`).

Edit-режим — тот же View/Edit/Save/Cancel/Preview changes chrome, что у DNS/FakeDNS/API. Реализация
пользовательских требований к форме («опциональные поля — чекбоксы, поля с вариантами — выпадающие
списки, крупные блоки — под спойлеры, значения по умолчанию»):

- Чекбоксы для опциональных полей. Каждое `Option<T>`-поле (числа, `Option<enum>`,
  `Option<StrategySettingsEntry>`, `webhook: Option<WebhookEntry>`, `strategy:
  Option<StrategyEntry>`) редактируется парой «чекбокс включает/выключает поле + виджет значения,
  задизейбленный, пока чекбокс снят» (`optional_i64_row`/`optional_u64_row`/`optional_f64_row` —
  локальные копии того же идиома, что `optional_u16_row`/`optional_u32_row`/`optional_i64_row` в
  `gui/pages/dns.rs`, §50.5; каждый модуль страницы держит собственные копии этих маленьких
  виджетов, а не выносит в общий `gui/pages/mod.rs` — устоявшийся в проекте выбор, не общий стиль
  для одного пункта).
- Выпадающие списки для полей с вариантами. `domainStrategy` (`AsIs`/`IPIfNonMatch`/
  `IPOnDemand`), `network` (`(any)`/`tcp`/`udp`/`tcp,udp`), `strategy.type`
  (`random`/`roundRobin`/`leastPing`/`leastLoad`) — `egui::ComboBox`, тот же паттерн, что
  `query_strategy_combo`/`optional_bool_combo` у DNS (§50.5). `protocol` — не выпадающий список
  (поле — массив, не скаляр): чекбоксы по 4 документированным значениям (`http`/`tls`/`quic`/
  `bittorrent`) плюс отдельное свободнотекстовое поле «custom protocol values» для любых
  неизвестных/будущих значений — оба виджета редактируют один и тот же `Vec<String>`, тот же
  двухкомпонентный идиом, что `services` у API Settings (§44.5, `KNOWN_API_SERVICES`).
- Крупные блоки — под спойлеры. Каждое правило и каждый балансировщик — отдельный
  `egui::CollapsingHeader` (заголовок — цель правила `→ outboundTag`/`(no target set)` или тег
  балансировщика), с кнопками Move up/Move down/Remove в отдельной строке над спойлером (порядок
  правил значим — первое совпавшее побеждает, поэтому в отличие от списков `servers`/`hosts`/пулов
  у DNS/FakeDNS, где переупорядочивание не нужно, здесь Move up/Move down — не косметика, а
  замена прежних disabled-заглушек read-only страницы §20.1.5 на рабочую функциональность).
  Внутри правила — вложенный подраздел «Target» (обычные поля) и отдельный спойлер «Webhook
  settings», открывающийся только когда чекбокс `webhook` включён. Внутри балансировщика —
  вложенный спойлер «Strategy settings», внутри него — ещё один вложенный спойлер «leastLoad
  settings» для `StrategySettingsEntry`, открывающийся только когда включён чекбокс `settings`.
- Значения по умолчанию. `domainStrategy` всегда пишется в JSON явно (дефолт `AsIs`, та же
  логика, что `queryStrategy` у DNS, §50.2); только что добавленный балансировщик (`Add balancer`)
  без включённой `strategy` эквивалентен документированному дефолту Xray (`random`, без
  вложенных `settings`); `Add rule`/`Add balancer`/`Add cost` создают записи через
  `RoutingRuleEntry::blank()`/`BalancerEntry::blank()`/`CostEntry::blank()` — пустые, но валидные
  отправные точки, тот же идиом, что `DnsServerEntry::blank()`/`FakeDnsPoolEntry::blank()`.
- `domainMatcher` остаётся только в View-режиме (§52.1) — под общей информацией страницы, как и
  раньше (§20.1.5); в Edit-форме поле явно не показано, с одной строкой пояснения-подсказки почему.

Browsing (таблица правил, сортировка по Index/Target, detail-панель по клику, контекстное меню)
не изменился по существу — пункты «Edit»/«Delete»/«Duplicate»/«Move up»/«Move down» из контекстного
меню строки (были disabled-заглушками с §20.1.5) удалены вовсе, а не включены: реальное
редактирование живёт в отдельном Edit-режиме страницы (кнопка «Edit» вверху, тот же UX, что у DNS/
FakeDNS/API), а не построчно из контекстного меню таблицы — построчный Edit потребовал бы
дублирования всей формы редактирования правила в контекстном меню без явной пользы. Cross-section
wiring-проверки `routing`↔`balancers`↔`outbounds`↔`observatory` (§2.5:108, `routing_wiring_warnings`)
не тронуты и продолжают показываться независимо от View/Edit режима — они читают уже загруженные
секции конфигурации, а не draft.

## 52.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/routing_settings.rs` |
| `with_routing_mut` / `routing_mut()` / `set_routing()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_routing_settings` + `UpdateRoutingSettingsRequest`, `ConfigModifyErrorKind::MalformedRoutingObject` |
| Оркестрация | `app/routing_settings_ops.rs::run_update_routing_settings` |
| Page model | `app/routing.rs` — `RoutingPageState`/`RoutingPageModel` (browsing-состояния сохранены §20, добавлены edit-состояния), `build_routing_page_model` (+4 параметра) |
| Service | `app/service.rs` — секция «Routing Settings»: `routing_page_model` (расширен), `begin_edit_routing_settings`/`cancel_edit_routing_settings`/`routing_settings_draft_mut`/`routing_settings_draft`/`preview_routing_settings_diff`/`routing_settings_diff_preview`/`start_save_routing_settings`/`poll_routing_settings_mutation`/`is_routing_settings_mutation_busy`; новый `CurrentOperation::SavingRoutingSettings` |
| GUI | `gui/pages/routing.rs` (browsing-функции сохранены §20.2.1, добавлены `show_edit_form`/`show_rule_edit_form`/`show_balancer_edit_form`/`show_strategy_edit`/`show_webhook_edit` + мелкие виджеты) |

## 52.7	Тесты

- `xray::config::routing_settings::tests` — 31 тест: defaults при отсутствии секции, malformed
  routing warns, round-trip `domainStrategy` (включая сохранение нераспознанного значения с
  предупреждением), round-trip правила с `domain`+`outboundTag`, приоритет `sourceIP` над `source`
  при чтении и запись только `sourceIP`, `port` принимает и число, и строку на чтении, `network`
  парсится/предупреждает о нераспознанном значении, round-trip `tcp,udp`, round-trip `attrs`,
  round-trip `webhook` (включая предупреждение при отсутствующем `url`, значение при этом не
  теряется), сохранение неизвестных полей правила включая условно-легаси `type` в `extra` и их
  round-trip при `apply`, `apply` не трогает посторонние верхнеуровневые ключи включая
  `domainMatcher` (ключевой тест для решения §52.1), round-trip балансировщика (`selector`/
  `fallbackTag`), round-trip стратегии `leastLoad` с полным `settings`/`costs[]`, сохранение
  нераспознанного `strategy.type` с предупреждением, отсутствующий тег балансировщика сохраняется с
  предупреждением, change summary по `domainStrategy`/счётчикам правил и балансировщиков (пуст при
  отсутствии изменений), валидация принимает дефолты и правило с одним `balancerTag`, отклоняет
  правило без цели/пустой тег балансировщика/дублирующиеся теги балансировщиков/пустой `url`
  webhook/пустой `match` у cost/управляющие символы в `domain`, пустой `rules` удаляет ключ при
  `apply`, `to_new_value` не содержит посторонних ключей.
- `app::routing::tests` — те же 14 тестов read-only страницы (§20.2.7), обновлены под новую
  8-параметровую сигнатуру `build_routing_page_model` (добавлены `None, false, None, false` —
  поведение без активного draft не изменилось, что и проверяют существующие ассёршены без
  модификации).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4/§42.6/
  §43.7/§44.7/§50.7/§51.7): `routing_settings_ops.rs::run_update_routing_settings` требует mock
  `SshBackend`.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто. `cargo clippy --lib` — 0 новых
  warning в затронутых файлах кроме одного pre-existing-паттерна `this function has too many
  arguments (8/7)` на `build_routing_page_model` (тот же лишний параметр `sort`, которого нет у
  DNS/FakeDNS, — уже принятый в проекте уровень допуска этого lint: `backup_ops.rs`/`user_ops.rs`
  (8), `warp.rs` (10), `xray_logs.rs` (9–10) без подавления). `cargo test --lib` — 946 passed / 9
  failed (те же 9 pre-existing fixture-path failures — `tests/fixtures/xray/` отсутствует на диске в
  этой рабочей копии, не связаны с этим пунктом, см. §50.7/§51.7); 31 новый тест в
  `routing_settings`.
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `routing` объекта с нуля,
  конфликт при параллельном изменении файла, реальный рендер формы редактирования — вложенные
  спойлеры правил/балансировщиков/стратегии/webhook, чекбоксы протоколов, drag-value для `costs`) —
  нет доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7/
  §50.7/§51.7.

# 53	Policy Settings — редактор секции `policy` (Roadmap §2.1:49)

## 53.1	Цель и границы

Roadmap-пункт `policy edit (levels, system)` не задавал объём явно — как и у DNS/FakeDNS/API/
Routing (§44/§50/§51/§52), взято полное покрытие официальных объектов
(<https://xtls.github.io/ru/config/policy.html>): весь `PolicyObject` (`levels`/`system`), все 8
полей `LevelPolicyObject` и все 4 поля `SystemPolicyObject`.

Из четырёх уже реализованных root-section редакторов это структурно самый простой: нет ни
альтернативных JSON-форм (как у `fakedns`, §51), ни enum-полей с фиксированным набором значений
(как `queryStrategy`/`domainStrategy`/`network`/`strategy.type` у DNS/Routing, §50/§52), ни
многоуровневой вложенности (как `balancers[].strategy.settings.costs[]` у Routing, §52) — только
числа с документированными дефолтами и булевы флаги. Спорных моментов, требующих уточнения у
пользователя, в этот раз не возникло: и офиц. документация, и уже существующий read-only
`PolicySummary`/`policy_user_levels`/`policy_system` (§21) сходятся на одном и том же наборе полей
без расхождений (в отличие от `routing.domainMatcher`, §52.1, где потребовалась сверка с
исходниками Xray-core).

Как и у DNS/FakeDNS/API/Routing, это одна страница на browsing+edit — Policy, как и Routing (§52),
уже имела богатую read-only страницу с таблицей уровней/сортировкой/detail-панелью (§21), которая
редактированием не заменяется, а дополняется тем же способом: browsing остаётся на
`PolicySummary`/`UserPolicySummary`, редактирование — отдельный typed draft на `PolicySettings`.

## 53.2	Типизированная модель (`src/xray/config/policy_settings.rs`)

- `PolicyLevelEntry` — все 8 полей `LevelPolicyObject`. `levels{}` в официальном формате —
  JSON-объект, ключ — уровень в виде строки-числа; как и `hosts{}` у DNS (§50.2), хранится в памяти
  как `Vec<PolicyLevelEntry>`, а не `HashMap`/`serde_json::Map`, чтобы порядок в UI был стабилен
  между кадрами. При загрузке список сортируется численно через уже существующий
  `cmp_policy_level` (§21, тот же компаратор, что использует read-only таблица уровней, различающий
  `"2" < "10"` в отличие от лексикографической сортировки `BTreeMap`-ключей) — дальнейший порядок
  редактирования (`Add level` добавляет в конец, ручной ввод/удаление не переупорядочивает) не
  переприменяет сортировку заново, тот же принцип, что у списков `servers`/`hosts`/`rules`: порядок
  в UI стабилен между кадрами, но не обязан оставаться отсортированным после ручных правок — сама
  Xray-семантика `levels{}` не зависит от порядка (это карта, а не список вроде `routing.rules[]`,
  §52.2), поэтому переупорядочивание непринципиально.
- Числовые поля с документированным Xray-дефолтом (`handshake`=4с, `connIdle`=300с,
  `uplinkOnly`=2с, `downlinkOnly`=5с, `bufferSize` — платформозависимо: 0 на ARM, 4 на ARM64, 512
  на прочих) — `Option<u64>`, `None` опускает ключ и оставляет платформенный/документированный
  дефолт эффективным на стороне Xray, тот же идиом, что `timeout_ms` у `DnsServerEntry` (§50.2).
- Булевы флаги статистики (`statsUserUplink`/`statsUserDownlink`/`statsUserOnline` на уровень,
  все 4 `SystemPolicyObject`-флага) — простой `bool`, всегда материализуется в JSON явно (дефолт
  `false`), тот же выбор, что `DnsSettings::disable_cache`/`serve_stale` и подобные у DNS (§50.2):
  наследовать не от чего (в отличие от per-server `Option<bool>`-override'ов DNS, где `None`
  означает «inherit от верхнего уровня» — у уровней политики такой иерархии нет, каждый уровень
  независим).
- `SystemPolicyEntry` — `system` целиком `Option<...>`, а не набор `Option`-полей внутри всегда
  присутствующего объекта: официальный `system` либо задан целиком, либо отсутствует — секция не
  имеет смысла "наполовину", поэтому в UI это один чекбокс «system policy», добавляющий/убирающий
  весь блок разом (как `webhook`/`strategy` у Routing, §52.2, а не как отдельные Option-поля
  `DnsSettings::client_ip`/`tag`).
- Валидация (`validate_policy_settings`) — нестрогая («prefer compatibility over convenience»),
  как и у остальных трёх редакторов; единственная содержательная структурная проверка — ровно та,
  что диктует сама форма данных: `levels{}` — карта, поэтому ключ каждого уровня обязан быть
  непустым, парситься как неотрицательное целое (`u64`, соответствует документированному «number in
  string form») и быть уникальным среди черновика (иначе на Save запись бы молча схлопнулась в
  JSON-объекте).

## 53.3	`EditableXrayConfig::with_policy_mut` (`editable.rs`) и `policy_mut()` (`sections.rs`)

Дословно зеркалит `with_dns_mut`/`with_routing_mut` (§50.3/§52.3) — `policy`, как `dns`/`routing`,
всегда JSON-объект, секция создаётся только на Save, если отсутствовала
(`resolve_policy_target_file` — тот же алгоритм с эвристикой «имя файла содержит `policy`», уже
подтверждённый на практике: в тестовых фикстурах read-only страницы файл конфигурации для policy
называется `03-policy.json`, §21). Потребовался один новый метод в `sections.rs` — `policy_mut()`
(симметрично уже существовавшим `policy()`/`set_policy()`, которые уже были нужны read-only
странице §21).

## 53.4	Мутация (`modify.rs::update_policy_settings`) и оркестрация (`app/policy_settings_ops.rs`)

`update_policy_settings` дословно зеркалит `update_dns_settings`/`update_routing_settings`
(§50.4/§52.4): validate → snapshot всех корней → `with_policy_mut` → serialize →
`validate_policy_structure_after_edit` → собрать `ModifyConfigOutcome`. Новый
`ConfigModifyErrorKind::MalformedPolicyObject` — по образцу `MalformedDnsObject`/
`MalformedRoutingObject`. `app/policy_settings_ops.rs::run_update_policy_settings` дословно
зеркалит `run_update_dns_settings`, включая conflict-check перед записью.

## 53.5	Страница Policy (`src/app/policy.rs`, `src/gui/pages/policy.rs`)

Как и у Routing (§52.5), `PolicyPageState` не перестроен с нуля — существующие browsing-состояния
(`PolicySectionMissing`/`NoUserPolicies`/`ConfigurationLoaded`/`ConfigurationContainsWarnings`,
§21) сохранены как есть (таблица уровней/сортировка/detail-панель по клику по-прежнему работают
ровно как раньше), поверх них добавлены edit-состояния (`EditMode`/`ValidationError`/`Saving`/
`Saved`/`SaveFailed`/`MalformedPolicyObject`) с тем же приоритетом переопределения, что у DNS/
Routing: Saving > Saved > (ошибка + режим редактирования → ValidationError) > (ошибка + не
редактируется → SaveFailed) > Malformed > EditMode > browsing-состояние.
`build_policy_page_model` получил 4 новых параметра (`draft`/`saving`/`error_message`/
`saved_flash`) в дополнение к уже существовавшему `sort`; `PolicyPageModel` — новые поля
`policy_settings`/`editing`/`change_summary`/`error_message`. В отличие от `RoutingPageModel`
(§52.5), `Eq` сохранён на всей модели без исключений — в `PolicySettings` нет `f64`-полей (только
`String`/`bool`/`Option<u64>`), в отличие от `strategy.settings.tolerance`/`costs[].value` у
Routing.

Edit-режим — тот же View/Edit/Save/Cancel/Preview changes chrome, что у DNS/FakeDNS/API/Routing.
Реализация пользовательских требований к форме:

- Чекбоксы для опциональных полей. Каждое числовое `Option<u64>`-поле — пара «чекбокс
  включает/выключает поле + `DragValue`, задизейбленный, пока чекбокс снят»
  (`optional_u64_row` — локальная копия того же идиома, что `optional_u16_row`/`optional_u32_row`
  у DNS §50.5 и `optional_u64_row` у Routing §52.5; каждая страница держит собственную копию, не
  общую, тот же устоявшийся в проекте выбор). Булевы поля (`statsUserUplink` и т.п.) — обычные
  `ui.checkbox`, без обёртки в Option — они не бывают «не заданы» в редакторе, всегда `true`/
  `false`. `system` целиком — один чекбокс «system policy», раскрывающий вложенный спойлер только
  когда включён (см. ниже).
- Выпадающие списки не потребовались. В отличие от DNS/Routing (§50.5/§52.5), у `PolicyObject`
  нет ни одного поля с фиксированным набором строковых значений — только числа и булевы флаги,
  так что требование «поля с вариантами значений — выпадающие списки» здесь не применяется ни к
  одному полю; это отражено явно, а не тихо пропущено.
- Крупные блоки — под спойлеры. Каждый уровень политики и системная политика — отдельный
  `egui::CollapsingHeader` (заголовок уровня — `Level {N}`), с кнопкой Remove в отдельной строке
  над спойлером. В отличие от `routing.rules[]` (§52.5), Move up/Move down не добавлены — `levels{}`
  это JSON-карта, а не список: порядок объявления уровней в конфиге не влияет на поведение Xray
  (каждый inbound/клиент ссылается на уровень по номеру, а не по позиции), так что переупорядочивание
  было бы чисто косметическим и не соответствовало бы официальной семантике поля.
- Значения по умолчанию. Каждое числовое поле подписано в UI документированным дефолтом Xray
  (например «handshake (s, default 4)», «bufferSize (KB, platform default)») — тот же принцип, что
  подсказки `(default 53)`/`(default 4000)` у полей DNS-сервера (§50.5), только без отдельного
  hint-текста на самом виджете (подпись чекбокса уже содержит дефолт). `Add level`/
  `Add system policy` создают записи через `PolicyLevelEntry::blank()`/`SystemPolicyEntry::blank()`
  — пустые, но валидные (все булевы флаги `false`, все числа не заданы = дефолт Xray) отправные
  точки, тот же идиом, что у остальных трёх редакторов.

Browsing (таблица уровней, сортировка по Level, detail-панель по клику, контекстное меню) не
изменился по существу — пункты «Edit»/«Delete»/«Duplicate» из контекстного меню строки (были
disabled-заглушками с §21.1) удалены вовсе, а не включены — тот же выбор, что у Routing (§52.5):
реальное редактирование живёт в отдельном Edit-режиме страницы, не построчно из контекстного меню.
Cross-section wiring-проверки `stats`↔`policy`↔`api`↔`metrics` (§2.5:106, `stats_wiring_warnings`)
не тронуты и продолжают показываться независимо от View/Edit режима.

## 53.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/policy_settings.rs` |
| `with_policy_mut` / `policy_mut()` / `set_policy()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_policy_settings` + `UpdatePolicySettingsRequest`, `ConfigModifyErrorKind::MalformedPolicyObject` |
| Оркестрация | `app/policy_settings_ops.rs::run_update_policy_settings` |
| Page model | `app/policy.rs` — `PolicyPageState`/`PolicyPageModel` (browsing-состояния сохранены §21, добавлены edit-состояния), `build_policy_page_model` (+4 параметра) |
| Service | `app/service.rs` — секция «Policy Settings»: `policy_page_model` (расширен), `begin_edit_policy_settings`/`cancel_edit_policy_settings`/`policy_settings_draft_mut`/`policy_settings_draft`/`preview_policy_settings_diff`/`policy_settings_diff_preview`/`start_save_policy_settings`/`poll_policy_settings_mutation`/`is_policy_settings_mutation_busy`; новый `CurrentOperation::SavingPolicySettings` |
| GUI | `gui/pages/policy.rs` (browsing-функции сохранены §21.2, добавлены `show_edit_form`/`show_level_edit_form`/`show_system_policy_edit` + `optional_u64_row`) |

## 53.7	Тесты

- `xray::config::policy_settings::tests` — 25 тестов: defaults при отсутствии секции, malformed
  policy object warns, round-trip уровня со всеми 8 полями, численная сортировка уровней при
  загрузке (`"10"`/`"2"`), отсутствующие числовые поля опускают ключ на записи (без потери
  дефолта), нераспознанная форма записи уровня пропускается с предупреждением, round-trip
  `system` со всеми 4 флагами, malformed `system` (не объект) предупреждает и не теряет секцию
  целиком, отсутствующий `system` — `None` без предупреждения, `apply` не трогает посторонние
  верхнеуровневые JSON-ключи, пустой `levels`/отсутствующий `system` удаляют соответствующий ключ
  при `apply`, change summary по количеству уровней и присутствию `system` (пуст при отсутствии
  изменений), валидация принимает дефолты и несколько валидных уровней, отклоняет пустой/
  нечисловой/отрицательный/дублирующийся ключ уровня.
- `app::policy::tests` — те же 19 тестов read-only страницы (§21.2), обновлены под новую
  8-параметровую сигнатуру `build_policy_page_model` (добавлены `None, false, None, false` —
  поведение без активного draft не изменилось).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4/§42.6/
  §43.7/§44.7/§50.7/§51.7/§52.7): `policy_settings_ops.rs::run_update_policy_settings` требует mock
  `SshBackend`.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто. `cargo clippy --lib` — 0 новых
  warning в затронутых файлах кроме одного уже принятого в проекте паттерна `this function has too
  many arguments (8/7)` на `build_policy_page_model` (тот же лишний параметр `sort`, что у Routing
  §52.7). `cargo test --lib` — 965 passed / 9 failed (те же 9 pre-existing fixture-path failures,
  не связанные с этим пунктом, см. §50.7/§51.7/§52.7); 25 новых тестов в `policy_settings` (было
  946 passed после §52).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `policy` объекта с нуля,
  конфликт при параллельном изменении файла, реальный рендер формы редактирования — спойлеры
  уровней/системной политики, чекбоксы статистики) — нет доступа к такому серверу в этой среде, тот
  же caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7/§50.7/§51.7/§52.7.

# 54	Observatory Settings — редактор секции `observatory` (Roadmap §2.1:50)

## 54.1	Цель и границы

Roadmap-пункт `observatory edit` не задавал объём явно — как и у DNS/FakeDNS/API/Routing/Policy
(§44/§50/§51/§52/§53), взято полное покрытие официального объекта
(<https://xtls.github.io/ru/config/observatory.html>): все 4 документированных поля
`ObservatoryObject` (`subjectSelector`/`probeUrl`/`probeInterval`/`enableConcurrency`) — на одно
больше, чем читал до сих пор read-only `ObservatorySummary` (§14): `enableConcurrency` никогда не
проецировался в read-only модель. Это не расхождение/баг существующего кода — `ObservatorySummary`
осознанно проецирует лишь подсказки для отображения (тот же принцип, что и у остальных summary-типов
в проекте), а полнота — обязанность именно редактора; тот же паттерн уже применялся у `dns`/
`routing`/`policy` (§50.2/§52.2/§53.2), где типизированная edit-модель тоже иногда шире
соответствующего read-only summary.

Один нюанс, не потребовавший вопроса пользователю (проверено и задокументировано, а не
угадано). Исходники Xray-core (`infra/conf/observatory.go`) помечают JSON-поле для URL проверки
тегом `probeURL` (заглавные буквы URL): `ProbeURL string json:"probeURL"`. Официальная
документация и все примеры конфигураций используют другое написание — `probeUrl`. Расхождение
безвредно на стороне самого Xray-core: `encoding/json` в Go по умолчанию делает регистронезависимый
fallback-матчинг ключей, так что оба варианта одинаково разбираются рантаймом. Но `EditableXrayConfig`
Feldjäger читает JSON через `serde_json`, который матчит ключи регистрозависимо — и уже
существующий `ObservatorySummary::from_sourced` (§14) читает именно `probeUrl`. Поэтому
`observatory_settings.rs` тоже пишет `probeUrl`, а не буквальный тег Go-структуры `probeURL` —
иначе после первого же Save собственная read-only страница Feldjäger стала бы показывать
предупреждение «`probeUrl` is missing.» о значении, которое сама только что сохранила под другим
именем ключа. В отличие от `routing.domainMatcher` (§52.1), где пришлось спрашивать пользователя
(поле не существовало ни в источнике, ни в доках), здесь оба источника согласны, что поле
есть — разошёлся только регистр двух последних букв, и один из вариантов уже был выбран этим
же кодом раньше, так что решение однозначно и не требовало обсуждения.

Как и у Routing/Policy (§52/§53), это одна страница на browsing+edit — существующая read-only
страница (§14: общая информация + таблица Subjects) дополняется, а не заменяется.

## 54.2	Типизированная модель (`src/xray/config/observatory_settings.rs`)

Самый простой из пяти реализованных root-section редакторов — плоская структура без вложенных
объектов и без enum-полей:

- `subject_selectors: Vec<String>` — `subjectSelector`, список префиксов тегов исходящих
  соединений, в порядке источник/редактирование (та же причина стабильного порядка в UI, что у
  `hosts`/`rules`/`levels` в других редакторах).
- `probe_url`/`probe_interval`: `Option<String>` — оба опциональны, без валидации грамматики
  URL/Xray duration-строки («prefer compatibility over convenience», тот же выбор, что у
  `probeInterval`-подобных строковых длительностей везде в проекте — `maxRTT`/`baselines` у Routing,
  §52.2). `probe_url` пишется как `probeUrl` — см. §54.1.
- `enable_concurrency: bool` — единственное булево поле объекта, всегда материализуется в JSON
  явно (дефолт `false`, задокументированный вариант поведения "проверять по очереди"), тот же
  выбор, что у большинства булевых флагов в DNS/Policy-редакторах.
- Выпадающие списки не потребовались — как и у Policy (§53.2), в `ObservatoryObject` нет ни
  одного поля с фиксированным набором строковых значений.
- Спойлеры не потребовались — все 4 поля умещаются в один плоский блок; нет ни массива объектов
  (как `routing.rules[]`/`policy.levels{}`), ни вложенных подобъектов (как `balancers[].strategy`) —
  единственный список (`subjectSelector`) — это список строк, а не список объектов, поэтому
  редактируется одним многострочным текстовым полем «один селектор на строку», без per-entry
  структуры и без необходимости в `CollapsingHeader`.
- Валидация (`validate_observatory_settings`) — та же лёгкость, что у остальных четырёх
  редакторов: только контроль управляющих символов на `subjectSelector`/`probeUrl`/`probeInterval`.
  Пустой `subjectSelector` разрешён к сохранению (в отличие от, например, обязательного `tag` у
  Routing-балансировщика) — read-only страница уже трактует пустой список как информационное, не
  блокирующее состояние (`NoSubjectSelectors`, §14), и это сохраняется и для редактора: секция может
  быть настроена по частям.

## 54.3	`EditableXrayConfig::with_observatory_mut` (`editable.rs`) и `observatory_mut()` (`sections.rs`)

Дословно зеркалит `with_dns_mut`/`with_routing_mut`/`with_policy_mut` (§50.3/§52.3/§53.3) —
`observatory` всегда JSON-объект, секция создаётся только на Save, если отсутствовала
(`resolve_observatory_target_file` — тот же алгоритм с эвристикой «имя файла содержит
`observatory`»). Потребовался один новый метод в `sections.rs` — `observatory_mut()` (симметрично
уже существовавшим `observatory()`/`set_observatory()`, которые уже были нужны read-only странице
§14).

## 54.4	Мутация (`modify.rs::update_observatory_settings`) и оркестрация (`app/observatory_settings_ops.rs`)

`update_observatory_settings` дословно зеркалит `update_dns_settings`/`update_routing_settings`/
`update_policy_settings` (§50.4/§52.4/§53.4): validate → snapshot всех корней →
`with_observatory_mut` → serialize → `validate_observatory_structure_after_edit` → собрать
`ModifyConfigOutcome`. Новый `ConfigModifyErrorKind::MalformedObservatoryObject` — по образцу
`MalformedRoutingObject`/`MalformedPolicyObject`. `app/observatory_settings_ops.rs::
run_update_observatory_settings` дословно зеркалит `run_update_dns_settings`, включая
conflict-check перед записью.

## 54.5	Страница Observatory (`src/app/observatory.rs`, `src/gui/pages/observatory.rs`)

Как и у Routing/Policy (§52.5/§53.5), `ObservatoryPageState` не перестроен с нуля — существующие
browsing-состояния (`ObservatorySectionMissing`/`NoSubjectSelectors`/`ConfigurationLoaded`/
`ConfigurationContainsWarnings`, §14) сохранены как есть, поверх них добавлены edit-состояния
(`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/`MalformedObservatoryObject`) с тем же
приоритетом переопределения: Saving > Saved > (ошибка + режим редактирования → ValidationError) >
(ошибка + не редактируется → SaveFailed) > Malformed > EditMode > browsing-состояние.
`build_observatory_page_model` получил 4 новых параметра (`draft`/`saving`/`error_message`/
`saved_flash`) — в отличие от Routing/Policy, без дополнительного `sort` (у Observatory нет
сортируемой таблицы уровня страницы — только простая таблица Subjects без сортировки, см. §14);
`ObservatoryPageModel` — новые поля `observatory_settings`/`editing`/`change_summary`/
`error_message`, `Eq` сохранён на всей модели (в `ObservatorySettings` нет `f64`-полей).

Edit-режим — тот же View/Edit/Save/Cancel/Preview changes chrome, что у DNS/FakeDNS/API/Routing/
Policy. Реализация пользовательских требований к форме:

- Чекбоксы для опциональных полей. `probeUrl`/`probeInterval` — пара «текстовое поле, пустое
  значение = поле не задано» (`optional_text_row`, тот же идиом, что везде: пустая строка
  трактуется как `None`, отдельного чекбокса не нужно, поскольку сам факт пустоты уже однозначен —
  в отличие от чисел, где `0` и «не задано» различимы и поэтому нужен отдельный чекбокс). `enableConcurrency`
  — простой чекбокс с однострочным пояснением документированного поведения true/false прямо под
  ним (default: off).
- Выпадающие списки не применялись — см. §54.2, в объекте нет полей-вариантов; отражено явно, а
  не тихо пропущено, тем же способом, что и у Policy (§53.5).
- Спойлеры не применялись — см. §54.2; единственный список (`subjectSelector`) — многострочное
  текстовое поле «один на строку», без вложенной структуры, которую имело бы смысл сворачивать.
- Значения по умолчанию. `enableConcurrency` явно пишется в JSON (дефолт `false`); подсказки в
  `hint_text` полей (`probeUrl`/`probeInterval`) показывают документированный пример значения, а не
  дефолт — у обоих полей нет задокументированного Xray-дефолта (в отличие от `handshake`/`connIdle`
  у Policy, §53.5), только пример из офиц. документации (`https://www.google.com/generate_204`,
  `10s`).

Browsing (общая информация, таблица Subjects, контекстное меню) не изменился по существу — пункты
«Edit»/«Delete»/«Duplicate» из контекстного меню строк Subjects/Probe URL (были disabled-заглушками)
удалены вовсе, а не включены — тот же выбор, что у Routing/Policy (§52.5/§53.5): реальное
редактирование живёт в отдельном Edit-режиме страницы.

## 54.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/observatory_settings.rs` |
| `with_observatory_mut` / `observatory_mut()` / `set_observatory()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_observatory_settings` + `UpdateObservatorySettingsRequest`, `ConfigModifyErrorKind::MalformedObservatoryObject` |
| Оркестрация | `app/observatory_settings_ops.rs::run_update_observatory_settings` |
| Page model | `app/observatory.rs` — `ObservatoryPageState`/`ObservatoryPageModel` (browsing-состояния сохранены §14, добавлены edit-состояния), `build_observatory_page_model` (+4 параметра, без `sort`) |
| Service | `app/service.rs` — секция «Observatory Settings»: `observatory_page_model` (расширен), `begin_edit_observatory_settings`/`cancel_edit_observatory_settings`/`observatory_settings_draft_mut`/`observatory_settings_draft`/`preview_observatory_settings_diff`/`observatory_settings_diff_preview`/`start_save_observatory_settings`/`poll_observatory_settings_mutation`/`is_observatory_settings_mutation_busy`; новый `CurrentOperation::SavingObservatorySettings` |
| GUI | `gui/pages/observatory.rs` (browsing-функции сохранены, добавлены `show_edit_form`/`optional_text_row`) |

## 54.7	Тесты

- `xray::config::observatory_settings::tests` — 15 тестов: defaults при отсутствии секции,
  malformed observatory object warns, round-trip всех 4 полей (включая `enableConcurrency`),
  отсутствующие опциональные поля — `None` без предупреждения, нераспознанная запись
  `subjectSelector` (не-строка) пропускается с предупреждением, нераспознанная форма самого
  `subjectSelector` (не массив) предупреждает, `apply` не трогает посторонние верхнеуровневые
  JSON-ключи, пустой `subjectSelector` удаляет ключ при `apply`, change summary по изменённым
  полям (пуст при отсутствии изменений), валидация принимает дефолты и полностью заполненные
  настройки (включая пустой список селекторов), отклоняет управляющие символы в селекторе/
  `probeUrl`, `to_new_value` не создаёт опциональные ключи без значений.
- `app::observatory::tests` — те же 9 тестов read-only страницы (§14), обновлены под новую
  7-параметровую сигнатуру `build_observatory_page_model` (добавлены `None, false, None, false` —
  поведение без активного draft не изменилось, включая тонкость «пустой список селекторов остаётся
  первичным состоянием даже при наличии предупреждения», §14).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4/§42.6/
  §43.7/§44.7/§50.7/§51.7/§52.7/§53.7): `observatory_settings_ops.rs::
  run_update_observatory_settings` требует mock `SshBackend`.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто. `cargo clippy --lib` — 0 новых
  warning вообще в затронутых файлах, включая привычный `too_many_arguments` — впервые среди пяти
  root-section редакторов (Log/API/DNS/FakeDNS/Routing/Policy) сигнатура `build_observatory_page_model`
  укладывается в 7 параметров без превышения лимита клиппи, поскольку у страницы нет параметра
  `sort`. `cargo test --lib` — 980 passed / 9 failed (те же 9 pre-existing fixture-path failures,
  не связанные с этим пунктом, см. §50.7/§51.7/§52.7/§53.7); 15 новых тестов в
  `observatory_settings` (было 965 passed после §53).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `observatory` объекта с
  нуля, конфликт при параллельном изменении файла, реальный рендер формы редактирования) — нет
  доступа к такому серверу в этой среде, тот же caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7/
  §50.7/§51.7/§52.7/§53.7.

# 55	Burst Observatory Settings — редактор секции `burstObservatory` (Roadmap §2.1:51)

## 55.1	Цель и границы

Roadmap-пункт `burstObservatory edit` не задавал объём явно — как и у всех пяти предыдущих
root-section редакторов, взято полное покрытие официального объекта. Документация
`BurstObservatoryObject`/`PingConfigObject` находится на той же странице, что и обычный
`observatory` (<https://xtls.github.io/ru/config/observatory.html>, отдельный раздел на той же
странице — проверено перед реализацией, а не предположено из совпадения URL с предыдущим пунктом
§54), поэтому обе секции по-прежнему остаются раздельными редакторами (разные root-объекты
`observatory`/`burstObservatory`, разные страницы GUI), просто описаны в одном источнике истины.

В отличие от `observatory` (§54.1, где read-only `ObservatorySummary` не проецировал
`enableConcurrency`), здесь расхождения между read-only summary и editor нет — уже существующие
`BurstObservatorySummary`/`BurstPingConfigSummary` (§16) и так проецируют весь набор из 8 полей
(`subjectSelector` + все 6 полей `pingConfig`), так что типизированная edit-модель просто зеркалит
те же имена полей 1:1, без нового покрытия сверх уже читаемого.

Как и у Routing/Policy/Observatory (§52/§53/§54), это одна страница на browsing+edit — существующая
read-only страница (§16: общая информация + таблица Subjects + таблица/детали Ping configurations)
дополняется, а не заменяется.

## 55.2	Типизированная модель (`src/xray/config/burst_observatory_settings.rs`)

Один уровень вложенности глубже, чем у `observatory` (§54.2) — единственный вложенный подобъект
(`pingConfig`), но без массивов объектов (в отличие от `routing.rules[]`/`policy.levels{}`):

- `subject_selectors: Vec<String>` — `subjectSelector`, тот же список префиксов тегов и та же
  лёгкая валидация (только управляющие символы, пустой список разрешён к сохранению), что и у
  `observatory.subjectSelector` (§54.2).
- `ping_config: Option<BurstPingConfigEntry>` — `pingConfig` целиком опционален в редакторе,
  несмотря на пометку «Обязательно» в официальной документации на уровне `BurstObservatoryObject`:
  поскольку каждое из 6 полей самого `pingConfig` имеет задокументированный дефолт Xray, пустой
  `pingConfig: {}` структурно эквивалентен «использовать все дефолты», а read-only страница уже
  трактует отсутствие ping-конфигурации как информационное состояние
  (`NoPingConfigurations`, не ошибку) — тот же принцип «prefer compatibility over convenience» и та
  же, уже принятая у `observatory` (§54.1), логика «не форсировать присутствие того, что и так
  эквивалентно всем дефолтам».
- `BurstPingConfigEntry` — все 6 полей `PingConfigObject`, каждое `Option<...>` с
  задокументированным дефолтом Xray (`destination` = `https://connectivitycheck.gstatic.com/
  generate_204`, `connectivity` = пустая строка = нет проверки, `interval` = `1m` при минимуме
  `10s`, `sampling` = `10`, `timeout` = `5s`, `httpMethod` = `HEAD`) — ключ опускается при `None`,
  дефолт применяет сам Xray; те же дефолты показаны в `hint_text` полей UI (§55.5).
- `http_method: Option<String>` — единственное поле с «вариантами значений» среди обеих секций
  Observatory/BurstObservatory. Официальная документация приводит только `HEAD`/`GET` как примеры,
  но текст явно говорит «или другие HTTP-методы» — поле открытое, не закрытый enum, поэтому
  смоделировано как обычный `Option<String>`, а не типизированный enum с вариантом `Unknown` (как
  `DomainStrategy`/`NetworkKind` у Routing, §52.2) — там, где Xray-core действительно ограничивает
  набор значений, здесь такого ограничения нет.
- Валидация (`validate_burst_observatory_settings`) — та же лёгкость, что у `observatory`
  (§54.2): только контроль управляющих символов на `subjectSelector` и все строковые поля
  `pingConfig`, без переизобретения грамматики URL/duration/HTTP-метода.

## 55.3	`EditableXrayConfig::with_burst_observatory_mut` (`editable.rs`) и `burst_observatory_mut()` (`sections.rs`)

Дословно зеркалит `with_observatory_mut`/`with_dns_mut` (§50.3/§54.3) — `burstObservatory` всегда
JSON-объект, секция создаётся только на Save, если отсутствовала
(`resolve_burst_observatory_target_file` — тот же алгоритм с эвристикой «имя файла содержит
`burst`», совпадает с тестовой фикстурой `08-burst-observatory.json` из §16). Потребовался один
новый метод в `sections.rs` — `burst_observatory_mut()` (симметрично уже существовавшим
`burst_observatory()`/`set_burst_observatory()`, которые уже были нужны read-only странице §16).

## 55.4	Мутация (`modify.rs::update_burst_observatory_settings`) и оркестрация (`app/burst_observatory_settings_ops.rs`)

`update_burst_observatory_settings` дословно зеркалит `update_observatory_settings`/
`update_dns_settings` (§50.4/§54.4): validate → snapshot всех корней → `with_burst_observatory_mut`
→ serialize → `validate_burst_observatory_structure_after_edit` → собрать `ModifyConfigOutcome`.
Новый `ConfigModifyErrorKind::MalformedBurstObservatoryObject` — по образцу
`MalformedObservatoryObject`. `app/burst_observatory_settings_ops.rs::
run_update_burst_observatory_settings` дословно зеркалит `run_update_dns_settings`, включая
conflict-check перед записью.

## 55.5	Страница Burst Observatory (`src/app/burst_observatory.rs`, `src/gui/pages/burst_observatory.rs`)

Как и у Routing/Policy/Observatory (§52.5/§53.5/§54.5), `BurstObservatoryPageState` не перестроен с
нуля — существующие browsing-состояния (`BurstObservatorySectionMissing`/`NoSubjectSelectors`/
`NoPingConfigurations`/`ConfigurationLoaded`/`ConfigurationContainsWarnings`, §16) сохранены как
есть, поверх них добавлены edit-состояния (`EditMode`/`ValidationError`/`Saving`/`Saved`/
`SaveFailed`/`MalformedBurstObservatoryObject`) с тем же приоритетом переопределения: Saving >
Saved > (ошибка + режим редактирования → ValidationError) > (ошибка + не редактируется →
SaveFailed) > Malformed > EditMode > browsing-состояние. `build_burst_observatory_page_model`
получил 4 новых параметра (`draft`/`saving`/`error_message`/`saved_flash`), без `sort` (у страницы
нет сортируемой таблицы уровня страницы — таблица Ping configurations в read-only режиме
показывает не более одной официальной конфигурации, §16); `BurstObservatoryPageModel` — новые поля
`burst_observatory_settings`/`editing`/`change_summary`/`error_message`, `Eq` сохранён на всей
модели (в `BurstObservatorySettings` нет `f64`-полей).

Edit-режим — тот же View/Edit/Save/Cancel/Preview changes chrome, что у остальных пяти редакторов.
Реализация пользовательских требований к форме:

- Чекбоксы для опциональных полей. `pingConfig` целиком — один чекбокс, добавляющий/убирающий
  весь блок (тот же идиом, что `webhook`/`strategy` у Routing, §52.5). Внутри блока: `destination`/
  `connectivity`/`interval`/`timeout` — текстовые поля с пустым значением = `None` (тот же идиом
  `optional_text_row`, что у `observatory` §54.5); `sampling` — числовое поле с явным чекбоксом
  `optional_u64_row` (число, а не строка — пустая строка неоднозначна для числа, поэтому нужен
  отдельный чекбокс, в отличие от строковых полей).
- Выпадающий список для `httpMethod`. Единственное поле с вариантами значений в обеих секциях
  Observatory/BurstObservatory: `egui::ComboBox` с пресетами `HEAD`/`GET` + пункт «(default: HEAD)»,
  и сразу рядом — свободное текстовое поле, редактирующее то же значение напрямую (поле открытое,
  выбор пресета лишь предзаполняет текст, а не ограничивает ввод) — тот же составной паттерн
  «пресет-комбобокс + прямое редактирование текста», что уже используется в проекте для TLS
  `fingerprint` (`optional_string_combo`, `gui/pages/inbounds.rs`), реализован здесь как локальная
  функция `http_method_combo` (собственная копия идиома для этой страницы, а не переиспользование
  чужого приватного хелпера — тот же устоявшийся в проекте выбор, что и у мелких виджетов
  Routing/Policy/Observatory, §52.5/§53.5/§54.5).
- Крупный блок — под спойлером. `pingConfig` (все 6 полей) — единственный вложенный подобъект
  в обеих секциях Observatory/BurstObservatory, поэтому единственный кандидат на
  `egui::CollapsingHeader` — раскрывается только когда чекбокс `pingConfig` включён. `subjectSelector`
  спойлера не требует — плоский список строк, тот же выбор, что и у `observatory.subjectSelector`
  (§54.5): редактируется одним многострочным текстовым полем «один на строку».
- Значения по умолчанию. Все 6 полей `pingConfig` показывают документированный дефолт Xray
  прямо в `hint_text` (например «https://connectivitycheck.gstatic.com/generate_204 (default)»,
  «1m (default, min 10s)», «sampling (default 10)») — более полно, чем у обычного `observatory`
  (§54.5), где `probeUrl`/`probeInterval` официально не имеют задокументированного дефолта, только
  пример значения.

Browsing (общая информация, таблицы Subjects/Ping configurations, detail-панель, контекстное меню)
не изменился по существу — пункты «Edit»/«Delete»/«Duplicate» из контекстных меню (были
disabled-заглушками) удалены вовсе вместе с общей функцией `disabled_actions`, а не включены — тот
же выбор, что у Routing/Policy/Observatory (§52.5/§53.5/§54.5): реальное редактирование живёт в
отдельном Edit-режиме страницы.

## 55.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/burst_observatory_settings.rs` |
| `with_burst_observatory_mut` / `burst_observatory_mut()` / `set_burst_observatory()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_burst_observatory_settings` + `UpdateBurstObservatorySettingsRequest`, `ConfigModifyErrorKind::MalformedBurstObservatoryObject` |
| Оркестрация | `app/burst_observatory_settings_ops.rs::run_update_burst_observatory_settings` |
| Page model | `app/burst_observatory.rs` — `BurstObservatoryPageState`/`BurstObservatoryPageModel` (browsing-состояния сохранены §16, добавлены edit-состояния), `build_burst_observatory_page_model` (+4 параметра, без `sort`) |
| Service | `app/service.rs` — секция «Burst Observatory Settings»: `burst_observatory_page_model` (расширен), `begin_edit_burst_observatory_settings`/`cancel_edit_burst_observatory_settings`/`burst_observatory_settings_draft_mut`/`burst_observatory_settings_draft`/`preview_burst_observatory_settings_diff`/`burst_observatory_settings_diff_preview`/`start_save_burst_observatory_settings`/`poll_burst_observatory_settings_mutation`/`is_burst_observatory_settings_mutation_busy`; новый `CurrentOperation::SavingBurstObservatorySettings` |
| GUI | `gui/pages/burst_observatory.rs` (browsing-функции сохранены, добавлены `show_edit_form`/`optional_text_row`/`optional_u64_row`/`http_method_combo`) |

## 55.7	Тесты

- `xray::config::burst_observatory_settings::tests` — 17 тестов: defaults при отсутствии секции,
  malformed burstObservatory object warns, round-trip `subjectSelector`, round-trip всех 6 полей
  `pingConfig`, отсутствующие поля `pingConfig` опускают ключи (без потери дефолта), отсутствующий
  `pingConfig` целиком — `None` без предупреждения, malformed `pingConfig` (не объект) предупреждает
  и не теряет секцию целиком, нераспознанная запись `subjectSelector` пропускается с
  предупреждением, `apply` не трогает посторонние верхнеуровневые JSON-ключи, пустой
  `subjectSelector`/отсутствующий `pingConfig` удаляют соответствующие ключи при `apply`, change
  summary по изменённым полям (пуст при отсутствии изменений), валидация принимает дефолты и
  полностью заполненные настройки (включая пустой список селекторов и отсутствующий `pingConfig`),
  отклоняет управляющие символы в селекторе/полях `pingConfig`, `to_new_value` не создаёт
  опциональные ключи без значений.
- `app::burst_observatory::tests` — те же 3 теста read-only страницы (§16), плюс обновлён 1 вызов
  `build_burst_observatory_page_model` под новую 7-параметровую сигнатуру (добавлены
  `None, false, None, false`; остальные тесты этого модуля используют
  `derive_burst_observatory_page_state` напрямую и сигнатуру не меняли).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4/§42.6/
  §43.7/§44.7/§50.7/§51.7/§52.7/§53.7/§54.7): `burst_observatory_settings_ops.rs::
  run_update_burst_observatory_settings` требует mock `SshBackend`.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто. `cargo clippy --lib` — 0 новых
  warning вообще в затронутых файлах (второй раз подряд после Observatory, §54.7 — сигнатура
  `build_burst_observatory_page_model` тоже укладывается в 7 параметров без `sort`). `cargo test
  --lib` — 997 passed / 9 failed (те же 9 pre-existing fixture-path failures, не связанные с этим
  пунктом, см. §50.7/§51.7/§52.7/§53.7/§54.7); 17 новых тестов в `burst_observatory_settings` (было
  980 passed после §54).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `burstObservatory` объекта
  с нуля, конфликт при параллельном изменении файла, реальный рендер формы редактирования —
  спойлер `pingConfig`, комбобокс `httpMethod`) — нет доступа к такому серверу в этой среде, тот же
  caveat, что в §40.5/§41.4/§42.6/§43.7/§44.7/§50.7/§51.7/§52.7/§53.7/§54.7.

# 56	Stats Settings — редактор секции `stats` (Roadmap §2.1:52) и исправление wiring §52–§55

## 56.1	Цель и границы

Roadmap-пункт — `stats enable / edit`. Официальная документация `StatsObject`
(<https://xtls.github.io/ru/config/stats.html>) прямым текстом говорит: «В настоящее время для
статистики не требуется никаких параметров» — объект пуст, ни одного поля. Поэтому в отличие от
всех пяти предыдущих root-section редакторов (DNS/Routing/Policy/Observatory/BurstObservatory,
§50/§52/§53/§54/§55), здесь нет ни «необязательных полей — чекбоксов», ни «полей с вариантами —
выпадающих списков», ни «крупных блоков — под спойлеры» в буквальном смысле задачи — единственное
значимое состояние всей секции: присутствует ли ключ `stats` в конфигурации. Пустой
`"stats": {}` включает модуль сбора статистики (сам сбор данных управляется отдельно через
`policy`/`api`/`metrics` — уже проверяется read-only wiring-предупреждениями, Roadmap §2.5:106,
не тронуто этим пунктом), отсутствие ключа — выключает. Это единственный из шести реализованных в
рамках Tier 2 §2.1 редакторов, где «полное покрытие документированных полей» и «ничего не покрывать
кроме presence-флага» — один и тот же объём работы, а не выбор.

## 56.2	Типизированная модель (`src/xray/config/stats_settings.rs`)

```rust
StatsSettings {
    enabled: bool,             // единственная содержательная настройка
    extra: Map<String, Value>, // неизвестные поля, если найдены на диске — сохраняются verbatim
    section_present, source_file, warnings
}
```

`extra` существует не потому, что документация предполагает какие-то поля (она прямо говорит, что
их нет), а потому что правило проекта «never invent semantics for what's already there» не делает
исключения даже для документированно-пустых объектов: если в конфиге на диске уже есть
`"stats": {"someFutureField": true}` (от новой версии Xray-core, которую этот код ещё не знает, или
от ручной правки), эти ключи не должны молча теряться при следующем Save — тот же принцип, что
`FakeDnsPoolEntry::extra` (§51.2). `validate_stats_settings` всегда возвращает `Ok(())` — сохранена
для симметрии с остальными пятью редакторами и как естественное место для будущих проверок, если
Xray-core когда-нибудь всё же задокументирует поля для этой секции.

## 56.3	`EditableXrayConfig::with_stats_mut` (`editable.rs`) и `stats_mut()` (`sections.rs`) — единственный «удаляющий» редактор

Структурно отличается от всех пяти предыдущих `with_*_mut`: те принимают `op: FnOnce(&mut Value)`
и всегда обеспечивают существование объекта перед вызовом `op` (создают `{}`, если секция
отсутствовала) — после них секция продолжает существовать, даже если все её поля сброшены в
дефолт. Здесь ровно наоборот: `with_stats_mut` принимает `op: FnOnce(&mut Option<Value>)`, и
`None` — не «пустой объект», а удаление ключа `stats` из файла целиком. Это единственный способ
выразить «отключить статистику» для секции, у которой нет собственного поля-выключателя (в отличие
от, например, `policy.system`/`routing.balancers[].strategy`, где `Option<...>`-поле контролирует
присутствие вложенного, а не корневого, ключа). Потребовался один новый метод в `sections.rs` —
`stats_mut()` (симметрично уже существовавшим `stats()`/`set_stats()`).

## 56.4	Мутация (`modify.rs::update_stats_settings`) и оркестрация (`app/stats_settings_ops.rs`)

`update_stats_settings` тот же validate → snapshot → mutate → serialize → structural re-check
каркас, что у остальных пяти, но мутация — `*value = stats_settings_to_value(&request.settings)`
(`None` при `enabled: false`, `Some(Value::Object(extra))` иначе) через `with_stats_mut`.
`validate_stats_structure_after_edit` — единственная структурная проверка в модуле, где отсутствие
ключа после сохранения не ошибка, а ожидаемый валидный исход (`enabled: false`); проверяется
только форма, когда ключ присутствует. `app/stats_settings_ops.rs::run_update_stats_settings`
дословно зеркалит `run_update_dns_settings`, включая conflict-check перед записью.

## 56.5	Страница Stats Settings (`src/app/stats_settings.rs`, `src/gui/pages/stats_settings.rs`)

В отличие от Routing/Policy/Observatory/BurstObservatory (богатая browsing-страница + отдельный
edit-режим поверх неё, §52–§55), здесь показывать в режиме просмотра, по сути, нечего — единственный
факт «включено/выключено». Поэтому страница построена по образцу API Settings (§44) —
ближайшего по форме предшественника среди уже реализованных редакторов: единый `ViewMode` без
browsing-подсостояний (`StatsSettingsPageState`: `NoSshConnection`/`XrayNotDiscovered`/
`ConfigurationNotLoaded`/`ViewMode`/`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/
`MalformedStatsObject` — без `SectionMissing`/`NoXxx`, которые были бы бессмысленны здесь: «секция
отсутствует» — это просто `ViewMode` с `enabled: false`, а не отдельное состояние). Новая страница
Stats Settings в сайдбаре, между BurstObservatory и API Settings — не путать с уже
существующей страницей Statistics (Roadmap §3:129, `app/stats_console.rs`, `gui/pages/stats.rs`,
`Page::Stats`) — та же осознанная граница, что между API Settings и API Console (§44.1): эта
страница правит только файл конфигурации (`stats.enabled`), не трогает и не заменяет живое чтение
счётчиков через `xray api statsquery`.

Edit-режим — тот же View/Edit/Save/Cancel/Preview changes chrome. Форма — один `ui.checkbox`
(«stats (enable statistics collection)») с пояснением, что фактический сбор данных настраивается
отдельно через `policy`/`api`/`metrics`, плюс информационная строка о количестве сохранённых, но
нередактируемых `extra`-полей, если таковые найдены на диске (тот же принцип честности, что у
FakeDNS-пулов с непустым `extra`, §51.5: «N полей сохранено, но не редактируется здесь»).

## 56.6	Исправление: `poll_*_settings_mutation` не были подключены к `tick_status()` (§52–§55)

При добавлении Stats Settings обнаружился баг, внесённый во всех четырёх предыдущих редакторах
этой группы — Routing (§52), Policy (§53), Observatory (§54), BurstObservatory (§55). У каждого из
них корректно реализован `poll_*_settings_mutation()` (читает `try_recv()` с канала воркера), но
ни один вызов не был добавлен в `ApplicationService::tick_status()` — единственное место, которое
`gui/app.rs` дёргает каждый кадр (`self.service.tick_status()`, `src/gui/app.rs:56`). Аналогично, ни
один из четырёх `*_settings_rx` не был включён в список `is_any_remote_busy()`.

Практическое следствие, если бы это не было замечено: после нажатия Save на страницах Routing/
Policy/Observatory/BurstObservatory фоновый поток (`run_update_*_settings`) действительно писал бы
файл на удалённый хост, но результат из канала никогда не вычитывался бы — статус-бар завис бы на
«Saving...» бессрочно, `is_*_settings_mutation_busy()` оставался бы `true` навсегда, а
`is_any_remote_busy()` не блокировал бы параллельный запуск другой мутации (не видя эти четыре
канала в своём списке) — то есть можно было бы, например, начать сохранение Policy, пока ещё «висит»
незавершённое (на самом деле уже завершённое, но невычитанное) сохранение Routing.

Почему не поймано тестами: каждый `*_settings_ops.rs::run_update_*_settings` документирован как
не покрытый unit-тестами (требует mock `SshBackend`, тот же прецедент, что и у всех
остальных `*_ops.rs` в проекте, §41.4 и далее) — соответственно ни один существующий тест не
прогонял полный цикл `start_save_* → poll_*` через `tick_status()`, только отдельные кусочки
(`build_*_page_model`, валидацию, `with_*_mut`) в изоляции.

Исправление — добавлены недостающие 4 строки в `tick_status()` и 4 строки в
`is_any_remote_busy()` (`src/app/service.rs`), одновременно с добавлением пятой (Stats) записи для
каждого списка — итоговое состояние обоих списков покрывает все восемь редакторов (Log/API/DNS/
FakeDNS/Routing/Policy/Observatory/BurstObservatory/Stats — девять пунктов, Log считается отдельно
от пары API/Stats, но использует общий `is_log_settings_mutation_busy()`), проверено вручную по
исходнику построчно (см. §56.7). Собственно поведение Routing/Policy/Observatory/BurstObservatory
при обычном использовании (View-режим, чтение, локальная валидация черновика) багом не затронуто —
проблема проявлялась только в конце полного цикла Save на реальном SSH-подключении, что и объясняет,
почему это не всплыло раньше в рамках уже пройденных ручных/автоматических проверок этой сессии.

## 56.7	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/stats_settings.rs` |
| `with_stats_mut` / `stats_mut()` / `set_stats()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_stats_settings` + `UpdateStatsSettingsRequest`, `ConfigModifyErrorKind::MalformedStatsObject` |
| Оркестрация | `app/stats_settings_ops.rs::run_update_stats_settings` |
| Page model | `app/stats_settings.rs` — новые `StatsSettingsPageState`/`StatsSettingsPageModel`/`build_stats_settings_page_model` (по образцу `api_settings.rs`, §44) |
| Service | `app/service.rs` — секция «Stats Settings»: `stats_settings_page_model`/`begin_edit_stats_settings`/`cancel_edit_stats_settings`/`stats_settings_draft_mut`/`stats_settings_draft`/`preview_stats_settings_diff`/`stats_settings_diff_preview`/`start_save_stats_settings`/`poll_stats_settings_mutation`/`is_stats_settings_mutation_busy`; новый `CurrentOperation::SavingStatsSettings`; плюс исправление §56.6 — 4 недостающих вызова в `tick_status()`, 4 недостающих условия в `is_any_remote_busy()` |
| GUI | `gui/pages/stats_settings.rs` (новая страница), `gui/navigation.rs` (`Page::StatsSettings`, между `BurstObservatory` и `ApiSettings`) |

## 56.8	Тесты

- `xray::config::stats_settings::tests` — 11 тестов: отсутствие секции = выключено по умолчанию,
  присутствующий пустой объект = включено без предупреждений, malformed (не объект) секция
  предупреждает, но остаётся включённой (сам факт присутствия ключа — уже "enabled", независимо от
  того, валидна ли его внутренняя форма), неизвестные поля сохраняются в `extra`, `to_value` при
  `enabled: false` — `None`, при `enabled: true` — round-trip `extra`, change summary сообщает о
  переключении enabled/disabled (пуст при отсутствии изменений), валидация всегда успешна
  (включая с произвольным содержимым `extra`).
- `app::stats_settings::tests` — 2 теста: `NoSshConnection`, `XrayNotDiscovered` (тот же
  минимальный набор, что у API Settings, §44.7/§50.7 — полное покрытие состояний уже есть на
  уровне модели `stats_settings`).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4 и
  далее, включая §50.7–§55.7): `stats_settings_ops.rs::run_update_stats_settings` требует mock
  `SshBackend`. Именно этот класс непокрытия и стал причиной пропуска бага §56.6 в первый раз —
  учтено в характеристике границ тестирования на будущее.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто. `cargo clippy --lib` — 0 новых
  warning в затронутых файлах. `cargo test --lib` — 1008 passed / 9 failed (те же 9 pre-existing
  fixture-path failures, не связанные с этим пунктом, см. §50.7–§55.7); 11 новых тестов в
  `stats_settings` (было 997 passed после §55).
- Не проверено вручную: живой Save на SSH-подключённом хосте — ни для Stats (создание/удаление
  ключа `stats` с нуля, конфликт при параллельном изменении файла), ни (что здесь особенно
  актуально в свете §56.6) полный цикл Save→poll на реальном SSH-хосте для всех шести редакторов
  сразу, только построчная проверка кода `tick_status()`/`is_any_remote_busy()` — нет доступа к
  такому серверу в этой среде, тот же caveat, что в §40.5 и далее по всей группе §50–§55.

# 57	Metrics Settings — редактор секции `metrics` (Roadmap §2.1:53)

## 57.1	Цель и границы

Roadmap-пункт — `metrics enable / edit`. Официальная документация `MetricsObject`
(<https://xtls.github.io/ru/config/metrics.html>) описывает ровно два поля: `tag` и `listen` —
буквально те же два поля (то же имя, тот же смысл), что уже реализованы для `api.tag`/`api.listen`
(§2.1:54, `api_settings.rs`), минус `services[]`, которого у `MetricsObject` нет вовсе. Это
структурно самый близкий аналог среди всех восьми root-section редакторов, поэтому типизированная
модель и страница — почти дословная копия API Settings с урезанным набором полей, а не новый
паттерн.

Одна содержательная деталь, отличающая эту секцию от `api`: документация прямым текстом
предупреждает — «Если при установке этого поля `tag` пустой, он автоматически устанавливается в
`Metrics`. Если оба поля не заданы, ядро не запустится.» У `api` эквивалентного предупреждения нет
(секция `api` без `tag`/`listen` просто бесполезна, но не ломает запуск ядра). Решение — не
превращать это в hard-валидацию (`validate_metrics_settings` не блокирует сохранение с обоими
пустыми полями): тот же принцип «prefer compatibility over convenience», что и у всех остальных
семи редакторов — `xray run -test`, который уже прогоняется после каждого сохранения, поймает
реальный сбой запуска. Вместо этого GUI показывает предупреждение красным текстом (в отличие
от жёлтого «no `listen`» у API Settings/у самого Metrics Settings при заданном `tag`) — единственный
редактор из восьми, где предупреждение о конкретной комбинации полей окрашено как ошибка, а не
просто информационная заметка, ровно потому что источник истины явно называет последствие
(«ядро не запустится»), а не просто «эндпоинт недостижим».

Ни выпадающие списки, ни спойлеры не потребовались: оба поля — обычные опциональные строки без
enum-семантики и без вложенной структуры, тот же случай, что уже был у `api`/`log`.

## 57.2	Типизированная модель (`src/xray/config/metrics_settings.rs`)

`MetricsSettings { tag: Option<String>, listen: Option<String>, section_present, source_file,
warnings }` — дословно `ApiSettings` без поля `services`. Парсинг/сериализация/валидация
идентичны по духу `api_settings.rs` (§44.2): `Option<String>` с trim-пустая-строка-значит-`None`,
контроль управляющих символов в валидации, `listen`-грамматика (`host:port`, IPv6 `[::1]:port`)
намеренно не переизобретается.

## 57.3	`EditableXrayConfig::with_metrics_mut` (`editable.rs`) и `metrics_mut()` (`sections.rs`)

Дословно зеркалит `with_api_mut`/`with_dns_mut` — не `with_stats_mut` (§56.3): `metrics`,
в отличие от `stats`, не может быть «выключен» удалением всей секции целиком одним переключателем
— как и `api`, единственный способ отключить эндпоинт в этой модели — очистить оба поля (что даёт
структурно валидный, но по документации «не запускающий ядро» пустой объект, см. §57.1). Секция
создаётся только на Save, если отсутствовала (`resolve_metrics_target_file` — та же эвристика «имя
файла содержит `metrics`»). Потребовался один новый метод в `sections.rs` — `metrics_mut()`
(симметрично уже существовавшим `metrics()`/`set_metrics()`, которые уже были нужны Metrics-live
странице, §3:130).

## 57.4	Мутация (`modify.rs::update_metrics_settings`) и оркестрация (`app/metrics_settings_ops.rs`)

`update_metrics_settings`/`validate_metrics_structure_after_edit`/
`ConfigModifyErrorKind::MalformedMetricsObject` дословно зеркалят `update_api_settings`/
`validate_api_structure_after_edit`/`MalformedApiObject` — секция всегда обязана существовать
как JSON-объект после Save (в отличие от `validate_stats_structure_after_edit`, §56.4, где
отсутствие ключа — валидный исход). `app/metrics_settings_ops.rs::run_update_metrics_settings`
дословно зеркалит `run_update_dns_settings`, включая conflict-check перед записью.

## 57.5	Страница Metrics Settings (`src/app/metrics_settings.rs`, `src/gui/pages/metrics_settings.rs`)

Как и Stats Settings (§56.5), построена по образцу API Settings (§44) — единый `ViewMode`
без browsing-подсостояний (`MetricsSettingsPageState`: `NoSshConnection`/`XrayNotDiscovered`/
`ConfigurationNotLoaded`/`ViewMode`/`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/
`MalformedMetricsObject`). Новая страница Metrics Settings в сайдбаре, между Stats Settings и
API Settings — не путать с уже существующей страницей Metrics (Roadmap §3:130,
`app/metrics_console.rs`, `gui/pages/metrics.rs`, `Page::Metrics`, живой HTTP-скрейп
`/debug/vars`) — та же осознанная граница, что у API Settings/API Console и Stats Settings/
Statistics (§56.5): эта страница правит только `metrics.tag`/`metrics.listen` в файле
конфигурации, не трогает и не заменяет живой скрейп.

Edit-режим — тот же View/Edit/Save/Cancel/Preview changes chrome, поля `tag`/`listen` — те же
текстовые поля с пустая-строка-значит-`None`, что у API Settings (§44.5), с одной добавленной
проверкой на стороне GUI (не типизированной модели): если оба поля пусты — красная заметка про
незапуск ядра (см. §57.1), показывается и в View-, и в Edit-режиме.

## 57.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/metrics_settings.rs` |
| `with_metrics_mut` / `metrics_mut()` / `set_metrics()` | `xray/config/editable.rs`, `xray/config/sections.rs` |
| Мутация | `xray/config/modify.rs::update_metrics_settings` + `UpdateMetricsSettingsRequest`, `ConfigModifyErrorKind::MalformedMetricsObject` |
| Оркестрация | `app/metrics_settings_ops.rs::run_update_metrics_settings` |
| Page model | `app/metrics_settings.rs` — новые `MetricsSettingsPageState`/`MetricsSettingsPageModel`/`build_metrics_settings_page_model` (по образцу `api_settings.rs`/`stats_settings.rs`, §44/§56) |
| Service | `app/service.rs` — секция «Metrics Settings»: `metrics_settings_page_model`/`begin_edit_metrics_settings`/`cancel_edit_metrics_settings`/`metrics_settings_draft_mut`/`metrics_settings_draft`/`preview_metrics_settings_diff`/`metrics_settings_diff_preview`/`start_save_metrics_settings`/`poll_metrics_settings_mutation`/`is_metrics_settings_mutation_busy`; новый `CurrentOperation::SavingMetricsSettings` — на этот раз сразу корректно подключён и к `tick_status()`, и к `is_any_remote_busy()` (см. урок §56.6) |
| GUI | `gui/pages/metrics_settings.rs` (новая страница), `gui/navigation.rs` (`Page::MetricsSettings`, между `StatsSettings` и `ApiSettings`) |

## 57.7	Тесты

- `xray::config::metrics_settings::tests` — 13 тестов: defaults при отсутствии секции, malformed
  metrics object warns, round-trip `tag`/`listen`, пустые/пробельные значения трактуются как
  отсутствие, `apply` не трогает посторонние верхнеуровневые JSON-ключи, очистка `tag` удаляет
  ключ (при сохранении `listen`), change summary по изменённым полям (пуст при отсутствии
  изменений), валидация принимает дефолты и полностью заполненные настройки, отклоняет пустую
  (пробельную) строку вместо `None` и управляющие символы.
- `app::metrics_settings::tests` — 2 теста: `NoSshConnection`, `XrayNotDiscovered` (тот же
  минимальный набор, что у API Settings/Stats Settings, §44.7/§56.7).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте — §41.4 и
  далее, включая §50.7–§56.7): `metrics_settings_ops.rs::run_update_metrics_settings` требует
  mock `SshBackend`.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто. `cargo clippy --lib` — 0 новых
  warning в затронутых файлах. `cargo test --lib` — 1021 passed / 9 failed (те же 9 pre-existing
  fixture-path failures, не связанные с этим пунктом, см. §50.7–§56.7); 13 новых тестов в
  `metrics_settings` (было 1008 passed после §56). Wiring в `tick_status()`/`is_any_remote_busy()`
  (§56.6) проверен построчно при добавлении — оба списка содержат ровно один пункт `metrics`.
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `metrics` объекта с нуля,
  конфликт при параллельном изменении файла, реальный рендер формы) — нет доступа к такому
  серверу в этой среде, тот же caveat, что в §40.5 и далее по всей группе §50–§56.

Этим пунктом закрыт весь набор корневых секций Tier 2 §2.1, для которых был задан явный Roadmap-
пункт редактирования (`log`/`dns`/`fakedns`/`api`/`routing`/`policy`/`observatory`/
`burstObservatory`/`stats`/`metrics` — все десять реализованы, §30/§44/§50–§57). Оставшиеся
незакрытыми пункты Tier 2 §2.1 — `env`/`version`/`geodata`/`reverse` — на момент написания не
запрошены пользователем.

# 58	Env Settings — редактор секции `env` (Roadmap §2.1:55)

## 58.1	Цель и границы

Roadmap-пункт — `env edit`. Официальная документация (<https://xtls.github.io/ru/config/env.html>)
описывает `env` как объект `{ "имя_переменной": "значение", ... }`, задающий переменные окружения
для процесса Xray-core — 14 задокументированных имён, но без фиксированной схемы: в
отличие от каждого из семи предыдущих root-section редакторов (`api`/`log`/`dns`/`fakedns`/
`routing`/`policy`/`observatory`/`burstObservatory`/`stats`/`metrics`), где типизированная модель
отражает конечный набор именованных полей объекта, `env` — произвольная карта строк, и любое имя
(документированное или нет) валидно как ключ. Модель поэтому — не набор именованных `Option<T>`
полей, а `Vec<EnvVarEntry { name, value }>` со свободным добавлением/удалением строк, ближе по духу
к `dns.hosts{}` (§50), чем к любому из «плоских объектов с фиксированными полями».

Содержательный вопрос, заданный пользователю явно: три из 14 задокументированных имён —
`XRAY_LOCATION_CONFIG`, `XRAY_LOCATION_CONFDIR`, `XRAY_JSON_STRICT` — документация трижды прямым
текстом описывает как не имеющие эффекта при задании через JSON `env`-объект: Xray-core читает
их из настоящего окружения ОС/systemd на этапе, предшествующем парсингу самой конфигурации, так
что значение внутри `env{}` попросту никогда не будет прочитано для этой цели. Вопрос — включать ли
эти три имени в список пресетов `KNOWN_ENV_VARS` наравне с остальными 11 (с риском, что пользователь
решит, будто выставление их здесь работает) — был задан пользователю через `AskUserQuestion`.
Пользователь выбрал «Исключить из пресетов»: `KNOWN_ENV_VARS` содержит ровно 11 имён, эти три —
не в списке чекбоксов/выпадающего выбора. Ручной ввод произвольного имени в текстовое поле рядом с
пресетами по-прежнему возможен (`rules.md`: «prefer compatibility over convenience» — редактор не
блокирует ввод), но UI-подсказка на странице явно предупреждает, что эти три переменные будут
молча проигнорированы Xray-core, если ввести их вручную.

Отдельно подтверждено (не требовало отдельного вопроса пользователю): это ортогонально собственному
механизму Feldjäger для указания расположения конфигурации на управляемом хосте (`init/unit.rs`,
`ExecStart=... run -config <path>` / `run -confdir <path>` в systemd unit-файле) — тот механизм
задаёт путь через аргументы командной строки процесса, а не через переменные окружения, и никак не
читает и не пишет `env`-объект конфигурации.

Чекбоксы для 11 пресетных имён + текстовое поле для значения на каждую строку; спойлеры не
потребовались — список пар может быть длинным, но каждая пара плоская (два текстовых поля), без
вложенной структуры, требующей сворачивания.

## 58.2	Типизированная модель (`src/xray/config/env_settings.rs`)

`EnvVarEntry { name: String, value: String }`, `EnvSettings { variables: Vec<EnvVarEntry>,
section_present, source_file, warnings }`. `env_settings_from_section` пропускает нестроковые
значения объекта с предупреждением (а не ошибкой парсинга — тот же принцип лояльного чтения, что и
везде в проекте), сохраняя обход по алфавиту ключей — известное следствие отсутствия
`serde_json`-фичи `preserve_order` (уже задокументировано для `dns.hosts{}`, §50.2, и здесь просто
подтверждено ещё раз для нового случая). `apply_env_settings_to_value` не мержит поля по одному
(как все предыдущие редакторы), а полностью пересобирает объект: `object.clear()`, затем вставка
всех пар из `settings.variables` заново — простейшая корректная семантика для списка произвольных
пар без под-структуры, которую было бы что выборочно сохранять. `validate_env_settings` отклоняет
пустое имя, повторяющиеся имена (`HashSet`) и управляющие символы в имени/значении — стандартный
минимум, грамматика имени переменной окружения (обычно `[A-Z_][A-Z0-9_]*`, но не описанная как
жёсткое требование в документации) не переизобретается. 13 unit-тестов.

## 58.3	Новая секция в лossless-модели: `sections.rs` + `parser.rs`

Единственный из восьми (девяти, считая этот) redактор, которому потребовалась новая плумбинг-цепочка
на уровне парсера — `env` до этого пункта вообще не был распознаваемой корневой секцией и падал бы
в общую корзину `extra_sections`, как любой нераспознанный top-level ключ. Изменения:

- `KNOWN_SECTION_NAMES`: добавлено `"env"` первым элементом.
- `XrayConfigSections`: новое поле `env: Option<SourcedSection<Value>>` + `env()`/`env_mut()`/
  `set_env()` — по образцу уже существовавших accessor-троек для `metrics`/`api`/`stats`.
- `is_empty()`: учитывает `self.env.is_none()`.
- `sections_in_file()`: `env` добавлен в список `scalar_sections` первым элементом.
- `parser.rs::merge_object`: новая ветка `"env" => self.assign_object_section(source_file, "env",
  section_value, sections, errors, |s, v| s.set_env(Some(v)))` — первая по порядку в `match
  key.as_str()`. `merge_object` — общая точка входа и для одиночного файла, и для confdir
  (`parse_directory` вызывает её же), так что одно добавление покрывает оба режима загрузки без
  дублирования.

## 58.4	`EditableXrayConfig::with_env_mut` (`editable.rs`) и мутация (`modify.rs`)

`with_env_mut` зеркалит `with_api_mut`/`with_metrics_mut`/`with_dns_mut` (§44.3/§57.3) —
«always-object», секция создаётся при первом Save, если отсутствовала, и не может быть удалена
целиком одним переключателем (в отличие от `with_stats_mut`, §56.3). `resolve_env_target_file` —
та же стандартная эвристика выбора файла для новой секции (один файл confdir — тривиально; иначе
файл, чьё имя содержит `env`; иначе первый файл). `update_env_settings`/
`validate_env_structure_after_edit`/`ConfigModifyErrorKind::MalformedEnvObject` дословно зеркалят
`update_metrics_settings`/`validate_metrics_structure_after_edit`/`MalformedMetricsObject`
(§57.4) — секция обязана существовать как JSON-объект после Save.

## 58.5	Оркестрация (`app/env_settings_ops.rs`) и страница (`app/env_settings.rs`, `gui/pages/env_settings.rs`)

`run_update_env_settings` дословно зеркалит `run_update_dns_settings`/`run_update_metrics_settings`
— validate → mutate → connect → conflict-check read → write → disconnect.

`EnvSettingsPageState` — тот же единый `ViewMode`/`EditMode`-набор без browsing-подсостояний, что у
Stats/Metrics/API Settings (§44.5/§56.5/§57.5): `NoSshConnection`/`XrayNotDiscovered`/
`ConfigurationNotLoaded`/`ViewMode`/`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/
`MalformedEnvObject`. В отличие от тех трёх страниц (пара текстовых полей / фиксированная сетка),
GUI-форма — таблица переменного размера (по образцу DNS/FakeDNS, §50/раздел FakeDNS): в View-режиме
`egui::Grid` со строками `(name, value)`, в Edit-режиме на каждую строку — `ComboBox` с 11 пресетами
`KNOWN_ENV_VARS` (клик по варианту заполняет соседнее текстовое поле имени) + свободный ввод имени
рядом (не блокирует произвольные/недокументированные имена) + текстовое поле значения + кнопка
Remove, и отдельная кнопка Add variable, добавляющая пустую строку. Notice на странице явно
перечисляет три исключённых из пресетов имени и объясняет, почему (см. §58.1). Новая страница Env
Settings в сайдбаре — между Metrics Settings и API Settings (та же позиция в списке, что и в
Roadmap-нумерации §2.1:53→§2.1:55→§2.1:54, сохраняющая порядок появления пунктов в документации,
а не порядок их реализации).

## 58.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/env_settings.rs` (`EnvSettings`, `EnvVarEntry`, `KNOWN_ENV_VARS`) |
| Новая секция в lossless-модели | `xray/config/sections.rs` (`env`/`env()`/`env_mut()`/`set_env()`, `KNOWN_SECTION_NAMES`), `xray/config/parser.rs` (`merge_object`, ветка `"env"`) |
| `with_env_mut` / `env_settings()` | `xray/config/editable.rs` |
| Мутация | `xray/config/modify.rs::update_env_settings` + `UpdateEnvSettingsRequest`, `ConfigModifyErrorKind::MalformedEnvObject` (`modify_error.rs`) |
| Оркестрация | `app/env_settings_ops.rs::run_update_env_settings` |
| Page model | `app/env_settings.rs` — новые `EnvSettingsPageState`/`EnvSettingsPageModel`/`build_env_settings_page_model` (по образцу `metrics_settings.rs`, §57) |
| Service | `app/service.rs` — секция «Env Settings»: `env_settings_page_model`/`begin_edit_env_settings`/`cancel_edit_env_settings`/`env_settings_draft_mut`/`env_settings_draft`/`preview_env_settings_diff`/`env_settings_diff_preview`/`start_save_env_settings`/`poll_env_settings_mutation`/`is_env_settings_mutation_busy`; новый `CurrentOperation::SavingEnvSettings` — подключён сразу и к `tick_status()`, и к `is_any_remote_busy()` (урок §56.6, проверено построчно) |
| GUI | `gui/pages/env_settings.rs` (новая страница — таблица переменного размера, а не фиксированный View/Edit блок), `gui/navigation.rs` (`Page::EnvSettings`, между `MetricsSettings` и `ApiSettings`) |

## 58.7	Тесты

- `xray::config::env_settings::tests` — 13 тестов: defaults при отсутствии секции, malformed env
  object warns, парсинг строковых пар, нестроковое значение пропускается с предупреждением,
  `apply` пересобирает объект целиком (не точечный merge), пустой список переменных даёт пустой
  объект, а не удаление ключа, change summary по числу изменений (пуст при отсутствии изменений),
  валидация принимает дефолты/валидные переменные, отклоняет пустое имя, дублирующееся имя и
  управляющие символы в имени/значении, а отдельный тест подтверждает, что `KNOWN_ENV_VARS` не
  содержит трёх заведомо неработающих имён.
- `app::env_settings::tests` — 2 теста: `NoSshConnection`, `XrayNotDiscovered` (тот же минимальный
  набор, что у API/Stats/Metrics Settings, §44.7/§56.7/§57.7).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте): `env_settings_
  ops.rs::run_update_env_settings` требует mock `SshBackend`.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто, 0 warning. `cargo clippy --lib` — 0
  новых warning в затронутых файлах (все 69 warning в полном выводе — предсуществующие, в
  несвязанных файлах). `cargo test --lib` — 1036 passed / 9 failed (те же 9 pre-existing
  fixture-path failures, не связанные с этим пунктом, см. §50.7–§57.7); 15 новых тестов (было 1021
  passed после §57).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `env` объекта с нуля,
  конфликт при параллельном изменении файла, реальный рендер формы с ComboBox-пресетами) — нет
  доступа к такому серверу в этой среде, тот же caveat, что во всей группе §40–§57.

Этим пунктом закрыт ещё один из четырёх оставшихся незакрытыми пунктов Tier 2 §2.1
(`env`/`version`/`geodata`/`reverse`, см. §57.7) — теперь реализованы одиннадцать из четырнадцати:
`log`/`dns`/`fakedns`/`api`/`routing`/`policy`/`observatory`/`burstObservatory`/`stats`/`metrics`/
`env`. Незакрытыми остаются `version`/`geodata`/`reverse`.

# 59	Version Settings — редактор секции `version` (Roadmap §2.1:56)

## 59.1	Цель и границы

Roadmap-пункт — `version constraints edit (min / max)`. В отличие от каждой из ранее задокументированных
секций (`env`/`log`/`api`/`dns`/…), у объекта `version` нет отдельной страницы документации
(`version.html`) — он описан прямо на странице обзора файла конфигурации
(<https://xtls.github.io/ru/config/>), в разделе про базовые модули конфигурации. В задаче
пользователь не указал URL явно (в отличие от каждой из десяти предыдущих задач этой серии) —
источник найден и подтверждён самостоятельно через запрос страницы `xtls.github.io/ru/config/`.
Дословный текст документации:

> «`version` — Опционально, контролирует версию, на которой может работать данный `config`.»
> «Поля `min` и `max` являются опциональными. Если они не установлены или оставлены пустыми, это
> означает отсутствие ограничений.»
> «Указанные версии не обязательно должны реально существовать, достаточно, чтобы они
> соответствовали синтаксису номера версии `Xray` `x.y.z`.»
> «При обмене `config`-файлами это предотвращает случайный запуск на нежелательных версиях
> клиента.»

Структурно это два опциональных строковых поля — почти дословная копия `MetricsSettings`
(§57.2: `tag`/`listen`), только с другими именами и другой семантикой пустоты. Значимое отличие
от `metrics`: там задокументировано явное «оба поля не заданы → ядро не запустится» (§57.1) — у
`version` эквивалентного предупреждения нет: отсутствие/пустота обоих полей просто означает «нет
ограничений», совершенно безобидное и полностью равнозначное отсутствию самого объекта состояние.
Поэтому красная UI-заметка, которая есть на Metrics Settings, здесь не нужна и не добавлена —
осознанное решение по аналогии, не потребовавшее вопроса пользователю.

Указанный в документации синтаксис `x.y.z` не превращён в grammar-валидацию: тот же принцип
«prefer compatibility over convenience» (`rules.md`), что уже применён к `metrics.listen`/
`api.listen` — сама документация говорит, что версия не обязана существовать реально, достаточно
синтаксического соответствия, а изобретать и поддерживать парсер semver-подобного формата ради
чисто косметической проверки означало бы усложнение без практической пользы (`xray run -test`,
уже прогоняемый после каждого сохранения, — не catch'ит и не обязан catch'ить это конкретное
поле, поскольку сама проверка версии — рантайм-фича самого Xray-core, а не structural JSON
validity). Отклоняются только управляющие символы и пустая/пробельная строка вместо `None` — тот
же минимум, что у всех строковых полей в проекте.

Отдельно зафиксировано (без вопроса пользователю — чисто информационная деталь): проверка версий
как фича появилась в Xray-core версии 25.8.3 — более старые запущенные бинарники молча
игнорируют весь объект `version` целиком. Редактор не имеет и не пытается получить информацию о
точной версии удалённого бинарника Xray-core в момент правки, так что не может предупредить
пользователя, если целевой сервер ещё не поддерживает эту фичу — эта проверка осталась бы для
будущего Roadmap-пункта, если понадобится.

## 59.2	Типизированная модель (`src/xray/config/version_settings.rs`)

`VersionSettings { min: Option<String>, max: Option<String>, section_present, source_file,
warnings }` — дословный клон формы `MetricsSettings` (§57.2) с переименованными полями и
переписанными doc-комментариями/сообщениями об ошибках под `version`-семантику. 13 unit-тестов.

## 59.3	Новая секция в lossless-модели: `sections.rs` + `parser.rs`

Как и `env` (§58.3), `version` до этого пункта не был распознаваемой корневой секцией — тот же
набор изменений: запись `"version"` в `KNOWN_SECTION_NAMES` (сразу после `"env"`), новое поле
`version: Option<SourcedSection<Value>>` в `XrayConfigSections` + `version()`/`version_mut()`/
`set_version()`, учёт в `is_empty()`/`sections_in_file()`, и новая ветка `"version" =>
self.assign_object_section(...)` в `parser.rs::merge_object` (общей для одиночного файла и
confdir).

## 59.4	`EditableXrayConfig::with_version_mut` (`editable.rs`) и мутация (`modify.rs`)

`with_version_mut`/`resolve_version_target_file` дословно зеркалят `with_metrics_mut`/
`resolve_metrics_target_file` (§57.3) — «always-object»: секция создаётся при первом Save, если
отсутствовала, и не может быть удалена целиком одним переключателем (в отличие от
`with_stats_mut`, §56.3) — в отличие от `metrics`, где присутствие-но-пустота потенциально ломает
запуск ядра (§57.1), у `version` присутствие-но-пустота полностью безвредно, но всё равно
сохранён единый паттерн «always-object», а не специальный `Option<Value>`-вариант: не было
причины отклоняться от паттерна большинства (7 из 9 редакторов) ради семантически нейтрального
случая. `update_version_settings`/`validate_version_structure_after_edit`/
`ConfigModifyErrorKind::MalformedVersionObject` дословно зеркалят `update_env_settings`/
`validate_env_structure_after_edit`/`MalformedEnvObject` (§58.4).

## 59.5	Оркестрация (`app/version_settings_ops.rs`) и страница (`app/version_settings.rs`, `gui/pages/version_settings.rs`)

`run_update_version_settings` дословно зеркалит `run_update_env_settings`/
`run_update_metrics_settings` — validate → mutate → connect → conflict-check read → write →
disconnect.

`VersionSettingsPageState` — тот же единый `ViewMode`/`EditMode`-набор без browsing-подсостояний,
что у Env/Metrics/Stats/API Settings: `NoSshConnection`/`XrayNotDiscovered`/
`ConfigurationNotLoaded`/`ViewMode`/`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/
`MalformedVersionObject`. GUI-форма — та же плоская сетка из двух текстовых полей, что у Metrics
Settings (§57.5), а не таблица переменного размера, как у Env Settings (§58.5) — `version` имеет
ровно два именованных поля, а не произвольный список пар, так что здесь ближе к Metrics, чем к
Env. Новая страница Version Settings в сайдбаре — между Env Settings и API Settings.

## 59.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/version_settings.rs` |
| Новая секция в lossless-модели | `xray/config/sections.rs` (`version`/`version()`/`version_mut()`/`set_version()`, `KNOWN_SECTION_NAMES`), `xray/config/parser.rs` (`merge_object`, ветка `"version"`) |
| `with_version_mut` / `version_settings()` | `xray/config/editable.rs` |
| Мутация | `xray/config/modify.rs::update_version_settings` + `UpdateVersionSettingsRequest`, `ConfigModifyErrorKind::MalformedVersionObject` (`modify_error.rs`) |
| Оркестрация | `app/version_settings_ops.rs::run_update_version_settings` |
| Page model | `app/version_settings.rs` — новые `VersionSettingsPageState`/`VersionSettingsPageModel`/`build_version_settings_page_model` (по образцу `metrics_settings.rs`, §57) |
| Service | `app/service.rs` — секция «Version Settings»: `version_settings_page_model`/`begin_edit_version_settings`/`cancel_edit_version_settings`/`version_settings_draft_mut`/`version_settings_draft`/`preview_version_settings_diff`/`version_settings_diff_preview`/`start_save_version_settings`/`poll_version_settings_mutation`/`is_version_settings_mutation_busy`; новый `CurrentOperation::SavingVersionSettings` — подключён сразу и к `tick_status()`, и к `is_any_remote_busy()` (урок §56.6, проверено построчно) |
| GUI | `gui/pages/version_settings.rs` (новая страница — плоская сетка из двух полей, как у Metrics Settings), `gui/navigation.rs` (`Page::VersionSettings`, между `EnvSettings` и `ApiSettings`) |

## 59.7	Тесты

- `xray::config::version_settings::tests` — 13 тестов: defaults при отсутствии секции, malformed
  version object warns, парсинг `min`/`max`, пустые/пробельные значения трактуются как отсутствие,
  `apply` не трогает посторонние верхнеуровневые JSON-ключи, очистка `min` удаляет ключ (при
  сохранении `max`), change summary по изменённым полям (пуст при отсутствии изменений),
  валидация принимает дефолты и полностью заполненные настройки, отклоняет пустую (пробельную)
  строку вместо `None` и управляющие символы.
- `app::version_settings::tests` — 2 теста: `NoSshConnection`, `XrayNotDiscovered` (тот же
  минимальный набор, что у API/Stats/Metrics/Env Settings, §44.7/§56.7/§57.7/§58.7).
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте):
  `version_settings_ops.rs::run_update_version_settings` требует mock `SshBackend`.
- `cargo check --lib`, `cargo build` (полный бинарник) — чисто, 0 warning. `cargo clippy --lib` —
  0 новых warning в затронутых файлах (все 69 warning в полном выводе — предсуществующие, ровно
  то же число, что и до этой задачи, в несвязанных файлах). `cargo test --lib` — 1049 passed / 9
  failed (те же 9 pre-existing fixture-path failures, не связанные с этим пунктом, см.
  §50.7–§58.7); 13 новых тестов (было 1036 passed после §58).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `version` объекта с нуля,
  конфликт при параллельном изменении файла, реальный рендер формы) — нет доступа к такому
  серверу в этой среде, тот же caveat, что во всей группе §40–§58.

Этим пунктом закрыт ещё один из оставшихся пунктов Tier 2 §2.1 (`env`/`version`/`geodata`/
`reverse`, см. §58.7) — теперь реализованы двенадцать из четырнадцати: `log`/`dns`/`fakedns`/
`api`/`routing`/`policy`/`observatory`/`burstObservatory`/`stats`/`metrics`/`env`/`version`.
Незакрытыми остаются `geodata`/`reverse`.

# 60	GeoData Settings — редактор секции `geodata` (Roadmap §2.1:57)

## 60.1	Цель и границы

Roadmap-пункт — `geodata section edit (loader / hot-reload fields; files update уже в Tier 1)`.
Источник истины подтверждён запросом страницы
<https://xtls.github.io/ru/config/geodata.html>. Дословный смысл документации:

> «`cron` — Стандартное cron-выражение из 5 полей, выполняется в локальном часовом поясе.»
> «`outbound` — `tag` исходящего прокси, используемого при загрузке файлов geodata. Если не
> указано, загрузка идёт через модуль маршрутизации.»
> «`assets` — Список файлов geodata, которые нужно скачать и заменить.» Каждый элемент —
> `AssetObject { url, file }`, оба поля обязательны: «`url` — URL для загрузки ресурса. Должен
> быть HTTPS URL.», «`file` — имя файла для записи (например `geoip.dat` или `geosite.dat`)».

Это исчерпывающий список полей `GeodataObject` — в отличие от `routing`/`policy` (§48/§49), здесь
нет вложенных объектов с десятками полей, спойлеры `egui::CollapsingHeader` не потребовались:
`cron`/`outbound` — два плоских опциональных поля (та же форма, что `version.min`/`.max`, §59.2),
`assets[]` — список из ровно двух обязательных строк на элемент (компактнее, чем `env.variables`
или `dns.servers[]`), поэтому каждая запись рендерится инлайн-строкой «Asset N / Remove», без
спойлера — тот же выбор, что уже сделан для `dns.hosts[]` (`show_host_edit_form`, §46.5:
`domain` + `targets` — тоже два поля на запись). Выпадающие списки не потребовались — ни у одного
поля `GeodataObject`/`AssetObject` нет фиксированного набора допустимых значений (`outbound` —
свободная ссылка на существующий `tag`, `cron` — свободное cron-выражение).

Не путать с уже существующей страницей GeoData (`app/geodata.rs`, `gui/pages/geodata.rs`,
Roadmap Tier 1, §2.1 таблица «GeoData files update») — та страница выполняет живые SSH-операции
прямо сейчас (скачать/заменить `geoip.dat`/`geosite.dat` на удалённом хосте) и никогда не трогает
файл конфигурации. Этот модуль редактирует именно *конфигурацию*: объект `geodata`, который
указывает уже запущенному Xray-core процессу самостоятельно периодически перезагружать/
перескачивать эти же файлы по собственному расписанию (`cron`), опционально через конкретный
`outbound`. Та же осознанная граница, что уже проведена между API Settings/API Console, Stats
Settings/Statistics, Metrics Settings/Metrics (§54.1/§56.1/§57.1).

Per `rules.md` («prefer compatibility over convenience», тот же принцип, что уже применён к
`metrics.listen`/`api.listen`/`version.min`/`.max`, §59.1) документированное требование «`url`
должен быть HTTPS» не превращено в grammar-валидацию — отклоняются только пустые обязательные
поля `url`/`file`, управляющие символы, и дубликаты `file` среди `assets[]` (два ассета,
нацеленных на один и тот же файл на диске — реальный конфликт, тот же класс проверки, что
дублирующиеся имена в `env`, §58.1).

## 60.2	Типизированная модель (`src/xray/config/geodata_settings.rs`)

`GeodataSettings { cron: Option<String>, outbound: Option<String>, assets: Vec<GeodataAssetEntry>,
section_present, source_file, warnings }`. `GeodataAssetEntry { url: String, file: String, extra:
Map<String, Value> }` — неизвестные JSON-ключи внутри объекта ассета сохраняются в `extra` и
round-trip'ятся при сохранении, тот же принцип «никогда не изобретать семантику для того, что уже
есть», что у `FakeDnsPoolEntry::extra` (§47.2). 18 unit-тестов (13 в `xray::config::geodata_settings`
+ 2 в `app::geodata_settings` + 3 в `app::service` для gate-проверок).

## 60.3	Новая секция в lossless-модели: `sections.rs` + `parser.rs`

`geodata` уже присутствовал в `KNOWN_SECTION_NAMES` (добавлен вместе с остальными корневыми
секциями на раннем этапе проекта, до начала серии §46–§59) — здесь потребовалось только новое
поле `geodata: Option<SourcedSection<Value>>` в `XrayConfigSections` + `geodata()`/
`geodata_mut()`/`set_geodata()`, учёт в `is_empty()`/`sections_in_file()`, и ветка `"geodata" =>
self.assign_object_section(...)` в `parser.rs::merge_object`.

## 60.4	`EditableXrayConfig::with_geodata_mut` (`editable.rs`) и мутация (`modify.rs`)

`with_geodata_mut`/`resolve_geodata_target_file` зеркалят `with_api_mut`/`resolve_api_target_file`
— «always-object»: секция создаётся только при первом Save, если отсутствовала, и не может быть
целиком удалена одним переключателем (в отличие от `with_stats_mut`, §56.3) — присутствие-но-
пустота объекта `geodata` полностью безвредно (в точности как у `version`, §59.4), поэтому
сохранён единый «always-object»-паттерн, а не специальный `Option<Value>`-вариант.
`update_geodata_settings`/`validate_geodata_structure_after_edit`/
`ConfigModifyErrorKind::MalformedGeodataObject` зеркалят `update_version_settings`/
`validate_version_structure_after_edit`/`MalformedVersionObject` (§59.4).

## 60.5	Оркестрация (`app/geodata_settings_ops.rs`) и страница (`app/geodata_settings.rs`, `gui/pages/geodata_settings.rs`)

`run_update_geodata_settings` зеркалит `run_update_version_settings` — validate → mutate →
connect → conflict-check read → write → disconnect.

`GeodataSettingsPageState` — тот же единый `ViewMode`/`EditMode`-набор без browsing-подсостояний,
что у Version/Env/Metrics/Stats/API Settings: `NoSshConnection`/`XrayNotDiscovered`/
`ConfigurationNotLoaded`/`ViewMode`/`EditMode`/`ValidationError`/`Saving`/`Saved`/`SaveFailed`/
`MalformedGeodataObject`. GUI-форма — плоская сетка из `cron`/`outbound` (та же форма, что у
Version Settings, §59.5), плюс инлайн-список `assets[]` без спойлеров (та же форма, что
`env.variables`/`dns.hosts[]`, §58.5/§46.5 — Remove-кнопка на строку, Add asset снизу). Новая
страница GeoData Settings в сайдбаре — между Version Settings и API Settings (та же позиция
в группе редакторов корневых секций, что у каждого из §54–§59).

При реализации GUI-страницы обнаружено и исправлено: типизированная модель, слой оркестрации
(`app/geodata_settings_ops.rs`) и весь backend-пайплайн (`editable.rs`/`sections.rs`/`modify.rs`/
`modify_error.rs`/`parser.rs`) уже существовали в рабочей копии до начала этой задачи, но GUI-
страница отсутствовала, а `CurrentOperation::SavingGeodataSettings` (уже использовавшийся в
`app/service.rs::start_save_geodata_settings`/`poll_geodata_settings_mutation`) не был объявлен в
`app/status.rs` — `cargo check` не проходил (`E0599`). Кроме того, `poll_geodata_settings_mutation`
не был подключён к `tick_status()`, а `geodata_settings_rx` не учитывался в `is_any_remote_busy()`
— тот же класс бага, что уже находили и чинили четыре раза подряд в §56.5 (Routing/Policy/
Observatory/BurstObservatory). Исправлено централизованно вместе с добавлением недостающей GUI-
страницы.

## 60.6	Код

| Область | Путь |
| ------- | ---- |
| Типизированная модель | `xray/config/geodata_settings.rs` |
| Секция в lossless-модели | `xray/config/sections.rs` (`geodata`/`geodata()`/`geodata_mut()`/`set_geodata()`), `xray/config/parser.rs` (`merge_object`, ветка `"geodata"`) |
| `with_geodata_mut` / `geodata_settings()` | `xray/config/editable.rs` |
| Мутация | `xray/config/modify.rs::update_geodata_settings` + `UpdateGeodataSettingsRequest`, `ConfigModifyErrorKind::MalformedGeodataObject` (`modify_error.rs`) |
| Оркестрация | `app/geodata_settings_ops.rs::run_update_geodata_settings` |
| Page model | `app/geodata_settings.rs` — `GeodataSettingsPageState`/`GeodataSettingsPageModel`/`build_geodata_settings_page_model` |
| Service | `app/service.rs` — секция «GeoData Settings»: `geodata_settings_page_model`/`begin_edit_geodata_settings`/`cancel_edit_geodata_settings`/`geodata_settings_draft_mut`/`geodata_settings_draft`/`preview_geodata_settings_diff`/`geodata_settings_diff_preview`/`start_save_geodata_settings`/`poll_geodata_settings_mutation`/`is_geodata_settings_mutation_busy`; `CurrentOperation::SavingGeodataSettings` добавлен в `status.rs` и подключён к `tick_status()`/`is_any_remote_busy()`/`set_operation_progress` |
| GUI | `gui/pages/geodata_settings.rs` (новая страница), `gui/navigation.rs` (`Page::GeodataSettings`, между `VersionSettings` и `ApiSettings`) |

## 60.7	Тесты

- `xray::config::geodata_settings::tests` — 13 тестов (уже существовали до этой задачи): defaults
  при отсутствии секции, malformed geodata object warns, парсинг `cron`/`outbound`/`assets`,
  сохранение неизвестных полей ассета, пропуск non-object элемента `assets` с предупреждением,
  пустые/пробельные `cron`/`outbound` трактуются как отсутствие, `apply` не трогает посторонние
  JSON-ключи и round-trip'ит `extra`, очистка `assets` удаляет ключ, change summary по изменённым
  полям и ассетам (пуст при отсутствии изменений), валидация принимает дефолты и полностью
  заполненные настройки, отклоняет пустые `url`/`file`, дубликат `file`, управляющие символы.
- `app::geodata_settings::tests` — 2 теста (уже существовали): `NoSshConnection`,
  `XrayNotDiscovered`.
- `app::service::tests` — 3 теста (уже существовали): `geodata_requires_connected_ssh`,
  `geodata_requires_discovery`, `geodata_blocked_while_busy`.
- Не покрыто unit-тестами (тот же прецедент, что у каждого `*_ops.rs` в проекте):
  `geodata_settings_ops.rs::run_update_geodata_settings` требует mock `SshBackend`.
- `cargo check --lib` — было `error[E0599]` (см. §60.5), после исправления чисто. `cargo build`
  (полный бинарник) — чисто, 0 warning. `cargo clippy --lib` — 0 новых warning в затронутых файлах
  (69 warning в полном выводе — все предсуществующие, в несвязанных файлах, то же число, что и до
  этой задачи). `cargo test --lib` — 1066 passed / 9 failed (те же 9 pre-existing fixture-path
  failures на этой машине, не связанные с этим пунктом, см. §50.7–§59.7).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание `geodata` объекта с нуля,
  конфликт при параллельном изменении файла, реальный рендер формы) — нет доступа к такому
  серверу в этой среде, тот же caveat, что во всей группе §40–§59.

Этим пунктом закрыт предпоследний из оставшихся пунктов Tier 2 §2.1 (`env`/`version`/`geodata`/
`reverse`, см. §59.7) — теперь реализованы тринадцать из четырнадцати: `log`/`dns`/`fakedns`/
`api`/`routing`/`policy`/`observatory`/`burstObservatory`/`stats`/`metrics`/`env`/`version`/
`geodata`. Незакрытым остаётся только `reverse`.

# 61	`reverse` edit — VLESS-native reverse proxy (Roadmap §2.1:58)

## 61.1	Цель и границы — спорный момент, уточнённый с пользователем

Roadmap-пункт был сформулирован как `reverse edit (bridges / portals — Reverse / NAT Traversal)`,
что дословно указывает на старую корневую секцию `reverse: {bridges[], portals[]}`. При
проверке источника истины (<https://xtls.github.io/en/config/reverse.html>) обнаружено прямое
указание апстрима: «The legacy reverse proxy has been deprecated. Please use the VLESS reverse
proxy» — старая схема (`BridgeObject`/`PortalObject`, оба поля `{tag, domain}` обязательны, без
опциональных полей и enum'ов) официально в статусе deprecated, документация к ней и живой пример
конфигурации всё ещё существуют, но новых внедрений апстрим не рекомендует. Пользователь дал
ссылку не на эту страницу, а на <https://xtls.github.io/en/document/level-2/vless_reverse.html> —
новый, не deprecated механизм: `reverse` не корневая секция, а поле, вложенное прямо в
VLESS-сущности — `inbounds[].settings.clients[].reverse` на публичной (portal) стороне и
`outbounds[].settings.reverse` на внутренней (bridge) стороне; никаких `bridges[]`/`portals[]`,
никакого фиктивного domain-matching между сторонами.

Это разошлось с буквальной формулировкой роадмапа достаточно, чтобы стать спорным моментом —
уточнено с пользователем явно (`AskUserQuestion`, два вопроса). Ответ пользователя: (1) реализовать
только VLESS-native механизм, legacy `reverse.bridges/portals` не трогать (секция `reverse`
остаётся в `KNOWN_SECTION_NAMES` как непрозрачный preserve-as-is root, как и до этой сессии — без
собственного структурированного редактора); (2) для bridge-стороны (`outbounds[].settings.reverse`
на VLESS-исходящем) — реализовать полноценный VLESS Outbound Shell, а не только узкое поле
`reverse`, и заодно добавить в Outbounds поля, нужные для «цепочки соединений» (chain proxying).
Это заранее закрывает часть незакрытого пункта бэклога `outbound.proxySettings editor (chain
proxying: tag / transportLayer)` (Roadmap §4.2) — раньше числившегося отдельно от reverse, здесь
реализовано как побочный эффект того же прохода, поскольку `proxySettings` — общее поле любого
outbound-объекта (сосед `settings`/`streamSettings`, не специфичен для VLESS).

До этой сессии в проекте не было вообще никакого VLESS Outbound Shell — только Freedom/
Blackhole/DNS (Roadmap §2.4:94/95/96); полноценный `Outbounds Shell: VLESS (+ stream/security
matrix)` остаётся отдельным, более широким пунктом бэклога Tier 4 (§4.2). Редактор этой сессии
осознанно уже: он покрывает ровно ту плоскую форму `settings` (`address`/`port`/`id`/
`encryption`/`flow`/`reverse`), которую использует официальный документ по VLESS reverse во всех
своих JSON-примерах — без `vnext[]`/`users[]`-обёртки классической многосерверной/
многопользовательской VLESS outbound-схемы, и без вкладки Stream/Security (`streamSettings`
остаётся нетронутым соседом, как и у Freedom/Blackhole/DNS). Существующий на диске VLESS-исходящий
в старой `vnext[]`-форме не парсится этим редактором (`parse_outbound_settings` возвращает `None`,
тот же сигнал «не поддерживается», что и у любого нераспознанного протокола/формы) — доступен
только через уже существующий Raw JSON escape hatch (§3:125). Duplicate — иначе: это чистое
клонирование JSON без структурного парсинга, поэтому работает для VLESS-исходящего в любой
форме, включая `vnext[]` — добавлен тест, подтверждающий это отдельно от Edit-гейта
(`duplicate_outbound_allows_vless_legacy_vnext_form`).

## 61.2	Общий тип `reverse` (`src/xray/config/reverse_proxy.rs`)

`reverse` имеет одинаковую форму в обоих местах размещения — `{tag, sniffing?}` — поэтому вынесен
в один общий модуль, а не продублирован под inbound-клиентом и outbound-настройками отдельно.
`ReverseTagDraft { tag: String, sniffing: Option<ReverseSniffingDraft>, extras }` — `tag`
обязателен и единственное документированное апстримом требование (`validate_reverse` отклоняет
пустой `tag` и управляющие символы, ничего больше — тот же минимализм, что и у `metrics.listen`/
`api.listen`, `rules.md`: «prefer compatibility over convenience»). `ReverseSniffingDraft { enabled,
dest_override: Vec<String>, unknown_dest_override: Vec<String>, metadata_only, route_only, extras }`
— та же форма полей, что у уже существующего top-level `SniffingSettings` (`inbound_edit::sniffing`,
Roadmap §30-эры), но с собственным parse/apply, работающим над произвольным `&Map<String, Value>`
вместо целого inbound-объекта (`reverse.sniffing` — не top-level `inbound.sniffing`, повторно
использовать существующие функции `parse_sniffing_settings`/`apply_inbound_sniffing` было бы
возможно только через обёртку с фиктивным контейнером — решено не усложнять и написать
самостоятельный, короткий parse/apply, переиспользуя только константу `KNOWN_DEST_OVERRIDE`).
6 unit-тестов: минимальный `{tag}`, отсутствие/`null` → `None`, sniffing с сохранением неизвестных
`destOverride`-токенов, round-trip через `Value`, `validate_reverse` принимает/отклоняет.

## 61.3	Portal-сторона: `VlessClient.reverse` (inbound client)

`VlessClient` (`inbound_clients/vless.rs`) получил новое поле `reverse: Option<ReverseTagDraft>` +
`"reverse"` добавлен в `KNOWN_KEYS` (иначе поле уходило бы в `extras` и терялось бы как
редактируемое, тем же классом проблемы, что уже решён для остальных типизированных клиентских
полей). `parse_vless`/`write_vless` (`inbound_clients/parse.rs`/`write.rs`) читают/пишут ключ через
`parse_reverse`/`reverse_to_value`. `AddUserRequest`/`UpdateUserRequest` (`modify.rs`) получили поле
`reverse: Option<ReverseTagDraft>`; `add_vless_client`/`update_vless_client` валидируют его через
`validate_reverse` перед записью (тот же порядок, что у остальных проверок клиента — email/uuid-
конфликты уже проверялись, `reverse` добавлен как ещё один шаг до мутации). `update_vless_client`
явно перезаписывает `vless.reverse` из запроса (как `email`/`flow`/`level`) — `id` и `extras`
по-прежнему сохраняются из parse, тот же принцип, что уже был для остальных полей до этой сессии.

Read-only слой (`VlessClientSummary`, `xray/config/users.rs`) получил `reverse_tag: Option<String>`
— тот же принцип «summary — подмножество для отображения, editor — полное покрытие», что уже
применён у `ObservatorySummary` (§54.1); полный `ReverseSniffingDraft` в summary не прокидывается
(sniffing — не то, что нужно видеть в списке из одной строки на пользователя).

## 61.4	GUI: Users tab Add/Edit VLESS (`gui/pages/mod.rs`, `gui/pages/users.rs`)

Виджет `ReverseDraftFields` + `reverse_fields_edit()` вынесены в `gui/pages/mod.rs` как общий
`pub(crate)`-виджет (тот же уровень переиспользования, что `json_diff_preview`/`qr_code`/
`help_button`), поскольку одна и та же форма (чекбокс присутствия + `tag` + спойлер «Sniffing
(advanced)» с чекбоксами `enabled`/`destOverride`) нужна и на Users tab (portal), и на новом VLESS
Outbound Shell (bridge) — переиспользование в буквальном смысле, не копипаста. `metadataOnly`/
`routeOnly` сознательно не выведены в виджет (минимальный охват, тот же выбор, что уже сделан для
других редко нужных sniffing-флагов) — сохраняются как есть, если были на диске, через
`ReverseSniffingDraft::extras`\-round-trip не теряется, просто не редактируется структурно.

Диалоги `AddVless`/`EditVless` (`ClientDialogDraft`, `gui/pages/users.rs`) получили поле
`reverse: ReverseDraftFields`; Edit-диалог префилл — только `enabled`/`tag` из
`VlessClientSummary::reverse_tag` (sniffing префилл не делается, тот же уровень неполноты
префилла, что уже был у `level` — Edit-диалог и раньше не подтягивал текущий `level` клиента,
всегда стартовал с `0`, требуя от пользователя вручную восстановить значение при необходимости;
поведение `reverse` сделано по аналогии, не хуже и не лучше существующего прецедента). Импорт по
Share URI (`open_add_dialog_prefilled`, §3:133) не восстанавливает `reverse` — bridge-регистрация
никогда не кодируется в `vless://`-ссылке, поэтому это не потеря данных, а честный дефолт.
Users-таблица получила новую колонку Reverse tag (`UserRowDisplay::reverse_tag`,
`app/users.rs`), заполняемую из summary — тот же принцип видимости, что и у остальных колонок:
«GUI must not hide configuration options that are unsupported by structured editors» (`rules.md`),
здесь применён зеркально — не скрывать уже поддерживаемое структурированным редактором поле.

## 61.5	Bridge-сторона: новый VLESS Outbound Shell (`xray/config/outbound_protocol/vless.rs`)

Первый VLESS-редактор среди outbound-протоколов. `VlessOutboundSettings { address, port, id,
encryption, flow, reverse: Option<ReverseTagDraft> }` — все пять «плоских» полей `settings`,
задокументированных на странице VLESS reverse (сверено буквально по всем 13 JSON-примерам на
странице — форма одинакова что для forward-outbound (без `reverse`), что для bridge-outbound
(с `reverse`), только реверс-поле отличает одно от другого). `port` хранится как свободный текст и
валидируется как 1-65535 при `apply`, тот же паттерн, что `DnsRuleDraft::rewrite_port`/
`apply_optional_port` (`outbound_protocol/mod.rs`, уже существовал для DNS outbound). `address`/`id`
— обязательны (пустое значение = `ValidationFailed`, единственные два по-настоящему обязательных
поля VLESS outbound; `encryption`/`flow` — опциональны, пустое = ключ отсутствует, `reverse` —
опционален через тот же чекбокс-паттерн presence, что и везде в проекте).

`is_legacy_vnext_form(outbound) -> bool` проверяет `settings.vnext` на массив — используется внутри
`parse_vless_outbound_settings`, которая возвращает `None` при обнаружении legacy-формы вместо
попытки её разобрать (это НЕ ошибка парсинга, а осознанный «не поддерживается этим редактором»
сигнал, идентичный тому, что уже возвращают `None` любые нераспознанные протоколы в
`parse_outbound_settings` — вызывающая сторона (`begin_edit_outbound_shell`, `app/service.rs`) уже
единообразно превращает `None` в «Protocol not supported for shell edit.», без нового кода). Метод
не экспортирован из `outbound_protocol` наружу — используется только внутри `vless.rs`, что и
отражено в решении не делать его `pub` на уровне модуля (единственное использование — внутренний
гейт парсинга).

`apply_vless_outbound_settings` мутирует только пять известных ключей внутри `settings`, оставляя
все прочие ключи `settings` (и соседей объекта outbound — `streamSettings`/`mux`/`proxySettings`)
нетронутыми — тот же паттерн in-place-мутации, что уже применяется в `apply_freedom_settings`/
`apply_dns_settings` (не полная пересборка объекта). 8 unit-тестов: парсинг плоской формы с
`reverse`, legacy `vnext[]` не парсится, round-trip с сохранением неизвестных `settings`-полей и
соседей объекта (`streamSettings`/`mux`), запись `reverse` со sniffing, отклонение пустых
`address`/`id`, отклонение невалидного `port`, отклонение `reverse` с пустым `tag`.

`OutboundSettingsDraft` (`outbound_protocol/mod.rs`) получил вариант `Vless(VlessOutboundSettings)`
+ `vless_default()`; `parse_outbound_settings`/`apply_outbound_settings` — новые ветки диспетчера;
`is_shell_editable_protocol` — `"vless"` добавлен в список (использован и для Edit-гейта, и,
как выяснилось при первом прогоне тестов, для Duplicate-гейта — общая функция, отдельного
переключателя для двух разных действий в проекте не было и раньше). `outbound_settings_protocol_name`
(`modify.rs`) — новая ветка `Vless(_) => "vless"` для Add.

## 61.6	`proxySettings` — chain proxying (`xray/config/outbound_edit/mod.rs`)

`ProxySettingsDraft { tag: String, transport_layer: bool }` — новое поле `OutboundGeneral::
proxy_settings: Option<ProxySettingsDraft>`. `proxySettings` — общее поле любого outbound-
объекта (сосед `settings`/`streamSettings`/`tag`/`sendThrough`), не специфичное для VLESS, поэтому
добавлено в `OutboundGeneral`, а не в `VlessOutboundSettings` — General-таб теперь показывает его
для Freedom/Blackhole/DNS/VLESS одинаково (побочно закрывает часть Roadmap §4.2's
`outbound.proxySettings editor`, см. §61.1 — по явному запросу пользователя). Presence определяется
непустым `tag` (тот же принцип, что у `pingConfig`/`system`-блоков в других редакторах: чекбокс в
GUI переключает наличие черновика, но итоговая запись/удаление ключа в JSON решается по факту
непустого `tag`, не по флагу чекбокса напрямую) — пустой `tag` при включённом чекбоксе тихо не
пишет `proxySettings` вообще, без отдельной ошибки валидации (тот же «prefer compatibility over
convenience» минимализм, что у `metrics.listen`). `transportLayer` пишется только когда `true`
(default `false`, ключ опускается). 4 новых unit-теста в `outbound_edit::tests`: parse с обоими
полями, пустой `tag` → `None`, apply пишет/удаляет объект, apply опускает `proxySettings` с пустым
`tag`.

## 61.7	GUI: Outbounds page (`gui/pages/outbounds.rs`)

Новый пункт «VLESS» в меню «Add Outbound» → `service.begin_add_outbound_vless()`
(`app/service.rs`, зеркалит `begin_add_outbound_freedom`/`_blackhole`/`_dns` — тот же
`begin_add_outbound(OutboundSettingsDraft)` внутренний хелпер, без нового кода в
`start_add_outbound_shell`/`start_save_outbound_shell`, которые уже были протокол-агностичными).
`edit_ok`/`duplicate_ok`-гейты (контекстное меню строки) расширены `OutboundKind::Vless`; hover-
подсказки на задизейбленных кнопках обновлены соответственно. General-таб (`show_outbound_general_
edit`) получил чекбокс+два поля для `proxySettings` — общий для всех протоколов, как и сам тип.
Protocol-таб — новая ветка диспетчера `Some(OutboundSettingsDraft::Vless(_)) =>
show_vless_settings_edit(ui, service)`, новая функция `show_vless_settings_edit`: сетка
`address`/`port`/`id` (+ кнопка «Generate» рядом с `id`, переиспользующая `generate_client_uuid()`
— тот же UUID-генератор, что уже используют Users Add-диалоги VLESS/Trojan/Hysteria)/`flow`/
`encryption`, затем общий `reverse_fields_edit()` (§61.4) под теми же чекбоксом+tag+спойлером, что
и на Users tab. Outbounds-таблица: `outbound_description` (`xray/config/summary.rs`) получила ветку
`OutboundKind::Vless` — «Reverse bridge → {tag}» при заданном `reverse.tag`, иначе `address:port`
или просто `address`, иначе «Summary unavailable» (та же деградация, что и у остальных протоколов
без специфичной сводки).

## 61.8	Код

| Область | Путь |
| ------- | ---- |
| Общий тип `reverse` | `xray/config/reverse_proxy.rs` (новый модуль) |
| Portal: VLESS client | `xray/config/inbound_clients/vless.rs` (`VlessClient::reverse`), `parse.rs`/`write.rs`, `xray/config/users.rs` (`VlessClientSummary::reverse_tag`) |
| Portal: мутация | `xray/config/modify.rs` — `AddUserRequest`/`UpdateUserRequest::reverse`, `add_vless_client`/`update_vless_client` |
| Portal: GUI | `gui/pages/mod.rs` (`ReverseDraftFields`/`reverse_fields_edit`, общий виджет), `gui/pages/users.rs` (Add/Edit диалоги + таблица) |
| Bridge: VLESS outbound | `xray/config/outbound_protocol/vless.rs` (новый модуль: `VlessOutboundSettings`, `is_legacy_vnext_form`, parse/apply + 8 тестов) |
| Bridge: диспетчер | `xray/config/outbound_protocol/mod.rs` (`OutboundSettingsDraft::Vless`, `vless_default`, `is_shell_editable_protocol`), `xray/config/modify.rs` (`outbound_settings_protocol_name`) |
| Chain proxying | `xray/config/outbound_edit/mod.rs` (`ProxySettingsDraft`, `OutboundGeneral::proxy_settings`, parse/apply + 4 теста) |
| Bridge: GUI | `gui/pages/outbounds.rs` (Add-меню, General-таб `proxySettings`, `show_vless_settings_edit`, `edit_ok`/`duplicate_ok` гейты), `app/service.rs` (`begin_add_outbound_vless`) |
| Summary | `xray/config/summary.rs` (`outbound_description` ветка `OutboundKind::Vless`) |

## 61.9	Тесты

- `xray::config::reverse_proxy::tests` — 6 новых тестов (см. §61.2).
- `xray::config::outbound_protocol::vless::tests` — 8 новых тестов (см. §61.5).
- `xray::config::outbound_edit::tests` — 4 новых теста (`proxySettings`, см. §61.6), плюс
  существующий `apply_omits_empty_fields_and_preserves_siblings` обновлён под новое поле
  `OutboundGeneral::proxy_settings`.
- `xray::config::modify_tests` — существующий `duplicate_outbound_rejects_non_shell_protocol`
  переведён с фикстуры `protocol: "vless"` на `"wireguard"` (vless теперь в whitelist
  `is_shell_editable_protocol` — тест больше не проверял бы то, что заявлено в имени); добавлен
  новый `duplicate_outbound_allows_vless_legacy_vnext_form`, явно фиксирующий, что Duplicate (в
  отличие от Edit) работает и для legacy `vnext[]`-формы VLESS-исходящего, поскольку это чистое
  клонирование JSON (§61.1).
- Порядка ~20 других call site'ов (`AddUserRequest`/`UpdateUserRequest`/`OutboundGeneral`-литералы
  в `app/service.rs`, `gui/pages/users.rs`, `xray/config/modify_tests.rs`) обновлены под новые поля
  структур без изменения проверяемого поведения.
- `cargo check --lib` / `cargo build` — чисто, 0 warning. `cargo clippy --lib` — 69 warning в полном
  выводе, то же число, что и до этой сессии (0 новых; один новый лишний clippy-hint —
  «add a `Default` impl for `ReverseTagDraft`» — устранён деривом `Default` вместо ручного `new()`,
  который теперь просто вызывает `Self::default()`). `cargo test --lib` — 1085 passed / 9 failed
  (было 1066/9 до этой сессии — 19 новых тестов, все прошли; те же 9 pre-existing fixture-path
  failures на этой машине, не связанные с этим пунктом, см. §50.7–§60.7).
- Не проверено вручную: живой Save на SSH-подключённом хосте (создание VLESS-исходящего с `reverse`
  с нуля, реальный запуск `xray run -test` над результатом, живой bridge↔portal обмен трафиком) —
  нет доступа к такому серверу в этой среде, тот же caveat, что во всей группе §40–§60.

Этим пунктом закрыт последний из четырнадцати корневых секций Tier 2 §2.1: `log`/`dns`/`fakedns`/
`api`/`routing`/`policy`/`observatory`/`burstObservatory`/`stats`/`metrics`/`env`/`version`/
`geodata`/`reverse` — все реализованы (`reverse` — в объёме, уточнённом с пользователем: VLESS-
native механизм, не legacy `bridges`/`portals`, см. §61.1).

# 62	FinalMask — этап 0: подготовка (Roadmap §2.6, пункты 0.1–0.3)

## 62.1	Цель и границы

Roadmap §2.6 «FinalMask — полная реализация» вырос из аудита 2026-09-28: сверка редактора FinalMask
(§34.1, Roadmap §2.3:86 / §2.3:89) с документацией <https://xtls.github.io/en/config/transports/finalmask.html>
и — как с источником истины при расхождениях — с `XTLS/Xray-core@main`
(`infra/conf/transport_finalmask.go`, `infra/conf/transport_internet.go`,
`transport/internet/{tcp,splithttp}/*`). Документация отстаёт от ядра (нет `xmc`, нет UDP-маски
`udphop`, `udpHop` всё ещё описан в `quicParams`).

Найденные проблемы, которые закрывает этап 0 (остальные — этапы 1–7 Roadmap §2.6):
- **потеря данных в типизированных формах масок** (§2.3:89): поля читались string-only аксессором,
  поэтому числовые `length`/`delay`/`maxSplit`/`rand`/`reset`/`interval`/`packetSize`/`remotePorts`
  и байтовые массивы `packet` молча выбрасывались при следующей записи;
- **самопроизвольная перезапись** `settings`: immediate-mode GUI каждый кадр заново выводил форму из
  `settings` и писал обратно нормализованный JSON — inbound помечался изменённым от простого
  просмотра, а набираемый текст «схлопывался»;
- **нет механизма некритичных предупреждений**: compatibility gates умеют только блокировать Save,
  а для дрейфа схемы ядра (ключ молча игнорируется) нужна жёлтая строка, а не блок.

Решения пользователя, зафиксированные в аудите и влияющие на архитектуру этого и следующих этапов:
G4 → два некритичных предупреждения (этап 5.1); полные формы для `header-custom`/`xmc`/`mkcp-legacy`
(этап 2); общий direction-aware stream-модуль (0.4); Outbound FinalMask — только после
Outbound-редактора `streamSettings` (Tier 4 §4.2 → этап 7). Порядок: этап 0 → 1 → … → 6, затем §4.2,
затем этап 7.

Статус этапа 0: 0.1–0.3 реализованы (версии 0.5.16-6 → 0.5.17-0), 0.4 — §63 (0.5.17-1),
0.5 — §64 (0.5.17-2), 0.6 — §65 (0.5.18-0); 0.7 (таблица «тип маски / поле → минимальная версия
Xray-core») — backlog.

> Пути в §62 — на момент 0.1–0.3. С 0.4 (§63) `values.rs`, `finalmask_layers.rs`, `finalmask.rs`,
> `sockopt.rs` лежат в `src/xray/config/stream/`; `FinalMaskForm` и формы слоёв — в
> `gui/pages/stream_finalmask.rs`; `SourcedTextBuffer` и `finalmask_multiline_list_row` (теперь
> `persistent_multiline_list_row`) — в `gui/pages/mod.rs`. Поведение не менялось.

## 62.2	Shape-preserving значения (0.1, `inbound_stream/values.rs`)

Часть полей FinalMask в Xray-core принимает несколько JSON-форм (`infra/conf/common.go`,
`transport_finalmask.go`). Новый модуль заменяет для них `string_field` в `finalmask_layers.rs`:

| Тип | Поле ядра | Формы | Где используется |
| --- | --------- | ----- | ---------------- |
| `RangeValue` | `Int32Range` | число (`int32`) \| строка `ParseRangeString` (`"5"`, `"10-20"`, `"-5-5"`, `"-10--5"`) | `fragment.length`/`delay`/`maxSplit`/`lengths[]`/`delays[]`, `noise.reset`, `noise[].rand`/`randRange`/`delay`, `salamander.packetSize`, `udphop.interval` |
| `PortListValue` | `PortList` | число \| строка `"443"`, `"20000-30000,40000"`, `"env:NAME"` | `udphop.remotePorts` |
| `PacketValue` | `packet` + sibling `type` | строка (`str`/`hex`/`base64`, либо base64 под `array`) \| массив байт (`array`) | `noise[].packet` (далее — items `header-custom`, этап 2) |

Принцип: значение хранит редактируемый `text` **и** JSON-форму, в которой было прочитано (приватные
поля `quoted` / `form`), поэтому нетронутое значение пишется обратно байт-в-байт:
- `RangeValue`/`PortListValue`: прочитанное как строка остаётся строкой (`"100"`); прочитанное как
  число или новое — пишется числом, если `text` — целое, иначе строкой (`"10-20"`). Пустой `text` =
  ключ отсутствует (`to_value` → `None`).
- `PacketValue`: байтовый массив редактируется как `"1, 2, 255"` (парсер принимает также пробелы и
  `[…]`) и пишется обратно массивом, пока текст разбирается как байты; строка остаётся строкой даже
  при `type: "array"`; новое значение становится массивом только при `type` `array`/пусто (дефолт
  Xray) и разбираемом тексте.
- Списки (`lengths[]`/`delays[]`): `range_values_to_lines` / `range_values_from_lines` —
  строка *n* наследует форму `previous[n]` **по позиции**; сдвиг формы после вставки строки меняет
  лишь эквивалентные `5` ↔ `"5"`, но не смысл.
- Непредставимая форма (float, bool, объект, массив не из байт) → `parse` возвращает `None`.

Валидация зеркалит ядро: `RangeValue::bounds`/`validate` — `ParseRangeString` +
`Int32Range.UnmarshalJSON` (ведущий `-` сдвигает разделитель на второй дефис, перестановка границ
как `ensureOrder`; значения вне `i32` **отклоняются** — ядро молча усекает их в строках, Feldjäger
сознательно строже); `PortListValue::validate` — `PortList.UnmarshalJSON` (порты `0..=65535`,
сегменты `PORT`/`FROM-TO`, `env:` пропускается — разрешается в рантайме); `PacketValue::validate(type)`
— `PraseByteSlice` (включая base64-строку под `array`: Go декодирует JSON-строку в `[]byte` как base64).
Методы валидации **пока не подключены к Save** — это этап 1.4 (per-type валидация как `Build()`).

## 62.3	Правило «без потерь или raw» (`inbound_stream/finalmask_layers.rs`)

`finalmask.rs` моделирует *цепочку* слоёв (`FinalMaskLayerDraft { type, settings }`, `settings` —
непрозрачный JSON). `finalmask_layers.rs` (Roadmap §2.3:89) поднимает до типизированных структур
слои с небольшой стабильной схемой: `FragmentMaskSettings`, `SalamanderSettings`, `SudokuSettings`,
`RealmSettings`, `UdpHopSettings` (переиспользует `SockoptDraft`), `NoiseMaskSettings`/`NoiseMaskItem`,
`XdnsSettings`, `XicmpSettings` — каждая с парой `parse_*` / `*_to_value` и `extras: Map` для
неизвестных ключей. `header-custom`/`mkcp-legacy`/`xmc` сознательно остаются на raw-JSON
(`docs/rules.md`: «rare/advanced → generic JSON»; полные формы — этап 2). В presets добавлены
`xmc` (`TCP_FINALMASK_TYPES`) и `udphop` (`UDP_FINALMASK_TYPES`).

Правило этапа 0.1 для **всех** `parse_*`: каждый известный ключ либо представлен без потерь, либо
`parse_*` возвращает `None`, и GUI показывает для слоя уже существующий raw-JSON редактор. Известный
ключ с непредставимой формой (число вместо строки, float в `lengths`, объект вместо bool и т.п.)
больше никогда не отбрасывается молча. Вспомогательные читатели (`string_field`,
`string_array_field`, `bool_field`, `object_field`) возвращают `Option<…>`: `None` = «форма не та».

```
settings (JSON) ──parse_*──► Some(draft) ──► типизированная форма ──*_to_value──► settings
                     │
                     └─────► None ─────────► show_finalmask_raw_json_edit (без потерь)
```

Нормализация при записи остаётся допустимой (канонические camelCase вместо legacy-алиасов `sudoku`,
выброшенный `"dgram": false`, обрезанные пробелы), но `parse → to_value` — неподвижная точка после
одной нормализации (тест `parse_to_value_is_idempotent_after_one_normalization`). Чтобы нормализация
не срабатывала от простого просмотра — §62.4.

## 62.4	GUI FinalMask-форм без самопроизвольной перезаписи (0.2, `gui/pages/inbounds.rs`)

Корень проблемы: egui — immediate-mode, форма каждый кадр строилась заново из `settings`. Два сбоя:
1. простое отображение формы переписывало `settings` выходом `*_to_value` и помечало inbound
   изменённым (dirty-on-open);
2. набираемый текст нормализовался на следующем кадре: `"1,"` в байтовом `packet` схлопывался в
   `"1"`, Enter в конце списка «один на строку» пропадал, ещё не валидный JSON в raw-редакторе
   откатывался.

Решение — draft/текстовый буфер в temp-памяти egui (`ctx.data_mut().insert_temp`, образец —
`api_console.rs`) **вместе со снимком `settings`** (`source`), из которого он получен. Буфер
используется, пока `settings == source`, и заново выводится при любом внешнем изменении (вкладка
Raw JSON, Move up/down, Cancel, другой inbound). Ключ состояния — `make_persistent_id((…, id_suffix, idx))`.

| Элемент | Роль |
| ------- | ---- |
| `FinalMaskForm<D>` + `FinalMaskFormState<D> { source, draft }` | Общая обвязка всех 8 типизированных форм: `begin(ui, settings, id_suffix, idx, parse)` берёт сохранённый draft или парсит `settings` (`None` → вызывающий показывает raw JSON); `finish(ui, settings, to_value)` пишет **только** если draft изменён за кадр (`draft != before`) **и** итоговый JSON отличается от `settings`, затем сохраняет состояние. Тела форм не менялись — между `begin`/`finish` они редактируют `form.draft`. |
| `SourcedTextBuffer<S> { source, text }` + `load_text_buffer` / `store_text_buffer` | Текстовый буфер, привязанный к значению, из которого отрисован. |
| `show_finalmask_raw_json_edit` | Raw-JSON редактор `settings` (fallback для DSL-типов и непредставимых слоёв): невалидный текст остаётся в буфере с пометкой «Not applied: …» вместо тихого отката; не-объект — «Not applied: settings must be a JSON object». |
| `finalmask_multiline_list_row` | Список «один на строку» (`Vec<String>`) с персистентным буфером — пустые строки в процессе набора сохраняются. |
| `finalmask_range_list_row` | То же для `Vec<RangeValue>` (`fragment.lengths`/`delays`) поверх `range_values_*_lines` — форма значения сохраняется по позиции строки. |

Поля форм переведены на `.text` shape-preserving значений; у `noise.packet` — подсказка формата
(`array: 1, 2, 255 · str/hex/base64: text`). Диспетчер `show_finalmask_settings_edit` выбирает форму
по `type` слоя, всё прочее — raw JSON.

## 62.5	Инфраструктура некритичных предупреждений (0.3)

### Модель (`xray/config/compatibility/warnings.rs`)

Gate (`CompatibilityGateId`) блокирует Save; предупреждение — никогда. Предупреждение отмечает
конфигурацию, которую ядро принимает, но которая делает не то, что кажется. Xray-core декодирует
JSON без `DisallowUnknownFields` (в т.ч. при `xray.json.strict`), поэтому удалённый из схемы ключ не
даёт ни ошибки, ни строки в логе ядра — только Feldjäger может о нём сообщить.

- `CompatibilityWarningId` — стабильные id (как у gates) + `message()` без секретов.
- `CompatibilityWarning { id, location }` — `location` — JSON-путь внутри inbound
  (`streamSettings.finalmask.udp[1].settings.sockopt`): `rules.md` запрещает абстракциям скрывать
  связь с местом в исходной конфигурации; `text()` → `"<location>: <message>"`.
- `inbound_warnings(&Value) -> Vec<CompatibilityWarning>` — чистая функция над JSON одного inbound;
  порядок = порядок в конфиге.
- `with_warning_suffix(message, &warnings)` — дописывает `" Warnings: a; b"` к статусу, если
  предупреждения есть.

В модуль попадают **только** факты, проверенные по `XTLS/Xray-core@main`:

| Id | Условие | Основание | Исправление |
| -- | ------- | --------- | ----------- |
| `QuicParamsUdpHopIgnored` | `streamSettings.finalmask.quicParams.udpHop` присутствует | port hopping перенесён в UDP-маску `udphop` (XTLS/Xray-core#6327); в `QuicParamsConfig` поля нет | с 0.5.31 — только outbound; на inbound `QuicParamsUdpHopClientOnly` + «Remove udpHop» (§79) |
| `UdpHopSockoptIgnored` | `sockopt` в `settings` слоя `finalmask.udp[]` типа `udphop` | удалён из маски (XTLS/Xray-core#6754); в `UDPHop` поля нет | кнопка удаления — этап 1.1 |

Следующие кандидаты в этот же механизм по Roadmap §2.6: legacy `xdns.domain` (1.3), mKCP
`congestion`/`readBufferSize`/`writeBufferSize` (0.6 — реализовано, §65, вместе с `header`/`seed`), версия ядра ниже минимальной для маски (0.7 — реализовано, §67),
матрица «маска × транспорт» (4.3), G4 → два предупреждения (5.1), FinalMask без передачи в
share-ссылке (6.1).

### Единый код сборки: `compose_inbound_shell` (`xray/config/modify.rs`)

Композиция Shell Save вынесена из `update_inbound_shell` в `pub fn compose_inbound_shell(inbound,
protocol, general, protocol_draft, stream, security, sniffing)` — все `apply_*` (general → protocol →
stream/security или `apply_tunnel_stream` для Tunnel (до §88 — `apply_tunnel_sockopt`) → `reconcile_inbound_fallbacks` → sniffing)
**без** gates (уникальность tag, compatibility, проверка clients). `update_inbound_shell` вызывает её
внутри `with_inbound_mut`, затем `check_inbound_compatibility`. `build_add_inbound_value` стал `pub`
для Add-сессий. Итог: предупреждения считаются ровно по тому JSON, который запишет Save / Add —
отдельного «предсказателя» результата нет, и он не может разойтись с Save.

### `ApplicationService` (`app/service.rs`)

- `inbound_editor_warnings(&mut self)` — по **черновику** открытой сессии: `compose_session_inbound`
  (Edit — клон on-disk inbound + `compose_inbound_shell`; Add — `build_add_inbound_value(
  add_request_from_session(..))`) → `inbound_warnings`. Пусто без сессии и пока черновик не
  собирается (ошибку покажет сам Save). Кэш `InboundWarningsCache { session, base, warnings }` —
  ключ «снимок сессии + on-disk inbound», т.к. сборка клонирует inbound и прогоняет все `apply_*`;
  поэтому вызов каждый кадр дешёвый. Без сессии (в т.ч. после Cancel) первый же вызов сбрасывает
  кэш в `None`.
- `inbound_warnings_at(index)` — по **сохранённому** inbound из `loaded_config` (view-режим,
  статус после записи); пусто для неизвестного индекса.
- Статус-бар: `poll_inbound_mutation` для Shell Save, Add и Raw JSON дописывает
  `with_warning_suffix(…, inbound_warnings_at(index))`. Для Raw JSON в
  `InboundMutationSuccess::RawJson` добавлено поле `inbound_index` (`app/inbound_ops.rs`).
- Рефакторинг попутно: `session_client_protocol` и `add_request_from_session` — общий код сборки
  `AddInboundRequest` из сессии (убран дубликат в `preview_inbound_shell_diff`).

### GUI и поток данных

```
Stream tab (inbounds.rs)
  editing ? service.inbound_editor_warnings()      # черновик: появление/исчезновение без Save
          : service.inbound_warnings_at(row.index) # сохранённый inbound
  → show_compatibility_warnings(ui, &warnings)      # жёлтые строки "Warning: <path>: <message>"
  → show_stream_edit / show_stream_readonly

Save / Add / Raw JSON → … → write_config_validated
  → poll_inbound_mutation → show_status_message(with_warning_suffix(msg, inbound_warnings_at(i)))
```

Предупреждения показываются вверху Stream-таба в обоих режимах; Save ими не блокируется, и GUI не
вычисляет их сам (`rules.md`: GUI не разбирает JSON и не обращается к модели конфигурации напрямую —
только через `ApplicationService`).

## 62.6	Код

| Область | Путь |
| ------- | ---- |
| Shape-preserving значения | `xray/config/inbound_stream/values.rs` (новый: `RangeValue`, `PortListValue`, `PacketValue`, `parse_range_values`, `range_values_to_lines`/`range_values_from_lines`) |
| Типизированные слои | `xray/config/inbound_stream/finalmask_layers.rs` (правило «без потерь или raw», переход на `values.rs`), `inbound_stream/finalmask.rs` (presets `xmc`/`udphop`), `inbound_stream/mod.rs` (реэкспорты) |
| Предупреждения | `xray/config/compatibility/warnings.rs` (новый), `compatibility/mod.rs` (реэкспорт) |
| Сборка без gates | `xray/config/modify.rs` (`compose_inbound_shell`, `pub build_add_inbound_value`) |
| App-слой | `app/service.rs` (`inbound_editor_warnings`, `inbound_warnings_at`, `InboundWarningsCache`, `compose_session_inbound`, `add_request_from_session`, суффикс статуса), `app/inbound_ops.rs` (`RawJson.inbound_index`) |
| GUI | `gui/pages/inbounds.rs` (`FinalMaskForm`, `SourcedTextBuffer`, `show_finalmask_raw_json_edit`, `finalmask_multiline_list_row`, `finalmask_range_list_row`, `show_compatibility_warnings`) |

## 62.7	Тесты

- `inbound_stream::values::tests` — 14 (0.1): сохранение формы число/строка, absent/`null`,
  отказ на непредставимых формах, новое целое → число, число, отредактированное в диапазон → строка,
  `bounds` по `ParseRangeString`, списки по позиции, `PortList` round-trip + валидация, байтовый
  `packet` round-trip, строка под `type: "array"`, форма нового `packet` по `type`, валидация как
  `PraseByteSlice`.
- `inbound_stream::finalmask_layers::tests` — `numeric_and_byte_array_values_round_trip_unchanged`,
  `unrepresentable_known_keys_fall_back_to_raw_json` (0.1), `parse_to_value_is_idempotent_after_one_normalization`
  (0.2, 8 типов слоёв) + существующие round-trip тесты каждого типа.
- `gui::pages::inbounds::finalmask_form_tests` — 5 GUI-тестов на реальных кадрах egui
  (`Context::run_ui`, 0.2): отображение 7 типов слоёв не меняет `settings`; реальная правка пишется,
  эквивалентный ввод (`"1,"`) не пишется, но сохраняется в буфере; внешнее изменение сбрасывает
  draft; raw-JSON редактор сохраняет ещё не валидный текст; список сохраняет набираемый перевод строки.
- `compatibility::warnings::tests` — 5 (0.3): чистый inbound, `udphop.sockopt` с путём слоя,
  legacy `quicParams.udpHop`, порядок = порядок в конфиге, суффикс только при наличии предупреждений.
- `app::service::tests` — 3 (0.3): `inbound_warnings_at_reports_the_saved_inbound`,
  `editor_warnings_follow_the_unsaved_draft` (появление/исчезновение без Save, кэш, сброс при Cancel),
  `editor_warnings_are_empty_while_the_draft_does_not_compose`.
- `modify_tests` подтверждают, что вынос `compose_inbound_shell` не изменил поведение Shell Save.
- Итог этапа: 1133 passed / 9 pre-existing fixture failures (каталог `tests/fixtures` в `.gitignore`,
  см. этап 1.5 Roadmap §2.6); `clippy` без новых предупреждений (68, было 70 до 0.2).
- Не проверено вручную: Save на живом SSH-хосте с `xray run -test` над конфигом с FinalMask — тот же
  caveat, что в §40–§61.

# 63	FinalMask — этап 0.4: общий direction-aware stream-модуль (Roadmap §2.6)

## 63.1	Цель и границы

`streamSettings` на inbound и outbound имеет одинаковую форму на проводе, но часть полей имеет
смысл только на одной стороне соединения: `sockopt.acceptProxyProtocol` настраивает слушающий сокет,
`sockopt.dialerProxy` — исходящий; в этапе 7 то же коснётся client-only полей FinalMask
(`xicmp.dgram`, `xdns.resolvers`, `fragment` `tlshello`, `udphop`). До 0.4 модели и редакторы
FinalMask / `quicParams` / `sockopt` жили внутри inbound-кода (`inbound_stream/`, `inbounds.rs`
на 6675 строк), и переиспользовать их для Outbound `streamSettings` (Tier 4 §4.2 → этап 7) было
нельзя без копирования.

Этот пункт — **рефакторинг без изменения поведения** inbound-редактора: вынести эти блоки в общий
модуль с явным направлением. В scope:
- модель: `src/xray/config/stream/` + `StreamDirection { Inbound, Outbound }`;
- GUI: `gui/pages/stream_finalmask.rs`, `gui/pages/stream_sockopt.rs`;
- общие GUI-хелперы (`lines_to_vec` ×4 копии, `resizable_multiline`, `optional_string_combo`) →
  `gui/pages/mod.rs`.

Вне scope: транспортные `*Settings` (`tcpSettings`/`xhttpSettings`/`wsSettings`/`kcpSettings`/
`hysteriaSettings`) остаются в `inbound_stream` и переедут вместе с Outbound-редактором
`streamSettings` (§4.2); виджеты outbound-only полей `sockopt` (Tier 4 §4.2 A3) и client-only
подсказки FinalMask (этап 7) не добавлялись — для `StreamDirection::Outbound` пока нет вызывающей
страницы.

## 63.2	Модель (`src/xray/config/stream/`)

```
xray/config/
├── stream/                    ← direction-aware, общий для inbound/outbound
│   ├── mod.rs                 StreamDirection + реэкспорты
│   ├── finalmask.rs           цепочки tcp[]/udp[] (перенесён без изменений)
│   ├── finalmask_layers.rs    типизированные settings слоёв (перенесён без изменений)
│   ├── values.rs              RangeValue / PortListValue / PacketValue (перенесён без изменений)
│   ├── quic_params.rs         QuicParamsDraft + parse_quic_params + quic_params_to_value (новый)
│   └── sockopt.rs             SockoptDraft + таблица применимости по направлению
└── inbound_stream/            транспортные *Settings + apply_inbound_stream / apply_tunnel_stream
    └── mod.rs                 pub use crate::xray::config::stream::{…}  — API inbound не изменился
```

- **`StreamDirection`** (`Inbound` — `inbounds[].streamSettings`, слушающая сторона; `Outbound` —
  `outbounds[].streamSettings`, исходящая; `as_str()`). Экспортируется через `crate::xray`.
- **Модели остаются direction-neutral и lossless.** Направление *не* участвует в parse/write: поле,
  не применимое к стороне, всё равно читается и пишется обратно без изменений (`rules.md`: unknown /
  unsupported fields must be preserved). `StreamDirection` решает только, что предлагает редактор.
- **`sockopt`**: `INBOUND_ONLY_SOCKOPT_FIELDS` (`acceptProxyProtocol`, `trustedXForwardedFor`,
  `V6Only`), `OUTBOUND_ONLY_SOCKOPT_FIELDS` (`mark`, `domainStrategy`, `dialerProxy`,
  `tcpcongestion`, `interface`, `tcpMptcp`, `addressPortStrategy`, `happyEyeballs`) и
  `sockopt_field_applies(key, direction)`. Классификация взята из уже существовавших doc-комментариев
  полей `SockoptDraft`; ключ не из списков (shared-поля, `customSockopt`, неизвестные будущие ключи)
  считается общим — ошибка в сторону «показать», а не «спрятать».
- **`quicParams`**: `QuicParamsDraft` и `parse_quic_params` перенесены из `inbound_stream/mod.rs`;
  инлайн-запись из `apply_inbound_stream` вынесена в `quic_params_to_value` (та же семантика:
  непустые типизированные поля — trimmed-строками, затем extras без перезаписи типизированных) —
  чтобы Outbound и XHTTP-h3 (этап 3.3) писали `quicParams` тем же кодом.
- Файлы перенесены обычным `mv` (индекс git не трогался); в `sockopt.rs` поправлены intra-doc ссылки
  на `inbound_stream::TcpStreamSettings`/`WsStreamSettings` и `inbound_security::TlsSettingsDraft`,
  которые раньше были относительными (`super::…`).

## 63.3	GUI: общие stream-редакторы

Контракт общих редакторов: они **меняют только переданный draft и возвращают «изменено»**; флаги
сессии (`write_finalmask_tcp`/`_udp`, `write_quic_params`, `write_sockopt`, `dirty`) выставляет
вызывающая страница. Так редактор не знает про `InboundEditorSession` и подходит будущей
Outbound-сессии без изменений.

| Модуль | API | Примечание |
| ------ | --- | ---------- |
| `gui/pages/stream_finalmask.rs` | `show_finalmask_edit(ui, direction, tcp, udp, notice) -> FinalMaskEdit { tcp, udp }` | Заголовок секции + help, опциональная жёлтая строка `notice` (сейчас — предупреждение G4 от Inbounds; G4 → предупреждения в этапе 5.1), цепочки `tcp[]`/`udp[]`. Внутри — прежние `show_finalmask_layers_edit` / `show_finalmask_settings_edit` / 8 типизированных форм / `FinalMaskForm` / raw-JSON редактор (§62.3–§62.4), без изменений логики. |
| | `show_quic_params_edit(ui, &mut QuicParamsDraft) -> bool` | Вместо трёх копий «clone → edit → записать поле + флаг + dirty» — прямое редактирование draft. |
| `gui/pages/stream_sockopt.rs` | `show_sockopt_edit(ui, direction, &mut SockoptDraft) -> bool`, `show_sockopt_readonly(ui, direction, &SockoptDraft)` | Строки inbound-only полей (`acceptProxyProtocol`, `V6Only`, `trustedXForwardedFor`) рендерятся по `sockopt_field_applies`; для `Inbound` набор строк тот же, что до 0.4. |
| | `sockopt_scope_note(direction) -> String` | Серая поясняющая строка; список полей берётся из констант модели, а не хардкодится в тексте. |
| | `tproxy_combo_field`, `HELP_SOCKOPT_TPROXY` (`pub(crate)`) | Общие с узким полем `sockopt.tproxy` на Protocol-табе Tunnel (Roadmap §2.3:88). |
| `gui/pages/mod.rs` | `lines_to_vec`, `resizable_multiline`, `optional_string_combo` | Были в `inbounds.rs`; `lines_to_vec` — ещё и копии в `api_settings.rs`/`dns.rs`/`routing.rs` (удалены). |
| | `SourcedTextBuffer` + `load_text_buffer` / `store_text_buffer`, `persistent_multiline_list_row` | Механизм §62.4 стал общим: список «один на строку» (бывш. `finalmask_multiline_list_row`) уже использовался TUN-формой (`gateway`/`dns`) — вне FinalMask имя вводило в заблуждение. |

Направление протягивается вниз по цепочке: `show_finalmask_edit(direction)` →
`show_finalmask_layers_edit` → `show_finalmask_settings_edit` → `show_udphop_settings_edit` →
вложенный `show_sockopt_edit(direction)` для legacy `udphop.sockopt` (сам ключ удалён ядром — см.
§62.5 `UdpHopSockoptIgnored`, убирается из формы в этапе 1.1). Сейчас это единственная ветка
FinalMask, зависящая от направления; client-only подсказки добавит этап 7.

Inbounds (`inbounds.rs`) вызывает редакторы с `StreamDirection::Inbound`: Hysteria-арм Stream-таба —
`show_quic_params_edit`; секция FinalMask (VLESS/Trojan, не Hysteria) — `show_finalmask_edit` с
`notice` = строка G4 при Reality + непустом `finalmask.tcp`; Sockopt (VLESS/Trojan/Hysteria) —
`sockopt_scope_note` + `show_sockopt_edit`; view-режим — `show_sockopt_readonly`. Порядок и тексты
виджетов не менялись; id egui-состояния (`finalmask_form`/`finalmask_raw`/`list_text`, grid-id)
сохранены, кроме grid `stream_hy_quic_edit_grid` → `stream_quic_params_edit_grid` (без состояния).

## 63.4	Код

| Область | Путь |
| ------- | ---- |
| Direction + реэкспорты | `xray/config/stream/mod.rs` (новый) |
| quicParams | `xray/config/stream/quic_params.rs` (новый) |
| sockopt + применимость | `xray/config/stream/sockopt.rs` (перенесён; `INBOUND_ONLY_SOCKOPT_FIELDS`, `OUTBOUND_ONLY_SOCKOPT_FIELDS`, `sockopt_field_applies`) |
| FinalMask / values | `xray/config/stream/{finalmask,finalmask_layers,values}.rs` (перенесены без изменений) |
| Inbound-реэкспорт | `xray/config/inbound_stream/mod.rs` (`pub use crate::xray::config::stream::{…}`; `apply_inbound_stream` пишет `quicParams` через `quic_params_to_value`) |
| Экспорт | `xray/config/mod.rs` (`mod stream`, `StreamDirection`, sockopt-таблица), `xray/mod.rs` (+ `QuicParamsDraft`) |
| GUI-редакторы | `gui/pages/stream_finalmask.rs`, `gui/pages/stream_sockopt.rs` (новые, `mod` в `gui/pages/mod.rs`) |
| Общие виджеты | `gui/pages/mod.rs`; `api_settings.rs`/`dns.rs`/`routing.rs` — копии `lines_to_vec` удалены |
| Inbounds | `gui/pages/inbounds.rs` — 6675 → 5456 строк; вызовы общих редакторов с `StreamDirection::Inbound` |

## 63.5	Тесты

- `xray::config::stream::quic_params::tests` — 2 новых: round-trip типизированных полей + extras;
  числовой `brutalDown` читается как текст, пустые поля опускаются при записи.
- `xray::config::stream::sockopt::tests` — 2 новых: списки направлений не пересекаются и содержат
  только моделируемые ключи (`KNOWN_SOCKOPT_KEYS`) — страховка от опечатки в имени ключа, которая
  молча сделала бы поле «общим»; применимость по направлению (inbound-only, outbound-only, shared и
  неизвестный будущий ключ).
- `gui::pages::tests` — `lines_to_vec_trims_and_skips_blank_lines` (новый) и
  `list_row_keeps_a_trailing_newline_being_typed` (перенесён из `finalmask_form_tests` вместе с
  виджетом).
- `gui::pages::stream_finalmask::finalmask_form_tests` — 4 GUI-теста §62.7 перенесены вместе с
  редакторами (вызов с `StreamDirection::Inbound`), проходят без изменений логики.
- Все существующие тесты `inbound_stream` / `modify_tests` / `finalmask_layers` / `values` проходят
  без изменений — подтверждение, что публичный API inbound и поведение записи не изменились.
- Итог: 1138 passed / 9 pre-existing fixture failures (было 1133 / 9); `cargo clippy --lib` — 68
  предупреждений, как до пункта, в новых файлах — 0.
- Не проверено вручную: живой запуск GUI (визуальная идентичность Stream-таба) и Save на SSH-хосте —
  тот же caveat, что в §40–§62; поведенческая эквивалентность подтверждена только тестами и тем, что
  код перенесён блоками без правок логики.

# 64	FinalMask — этап 0.5: не-объектный `finalmask` без владения (Roadmap §2.6)

## 64.1	Цель и границы

До 0.5 `apply_inbound_stream` при записи FinalMask / `quicParams` поверх значения
`streamSettings.finalmask`, которое не является объектом (строка, массив, число, bool), заворачивал
его в `{"_preserved": <старое значение>, "tcp": […]}`. Это:
- **изобретало ключ** `_preserved`, которого нет в схеме Xray-core — прямое нарушение `rules.md`
  («Never intentionally deviate from the official Xray configuration format», «Do not invent custom
  configuration semantics»); ядро игнорирует неизвестные ключи, так что обёртка выглядела бы как
  «сохранено», но фактически значение было потеряно для ядра;
- срабатывало **молча**: пользователь добавлял слой и не видел, что его исходное значение уехало
  внутрь служебного ключа;
- было частично мёртвым кодом: ветка `None => match finalmask {…}` не достигалась, потому что
  `finalmask` из `streamSettings` к тому моменту не удалялся.

Решение Roadmap: «сохранять как есть без владения» — тот же принцип, что у
`parse_finalmask_layers` → `None` (§62.3) и у raw clone-through для `sockopt`: то, что Feldjäger не
может представить, он не переписывает.

Вне scope: предупреждение `inbound_warnings` о не-объектном `finalmask` (что именно ядро делает с
таким значением, по исходникам `XTLS/Xray-core@main` не сверялось — а в `warnings.rs` попадают только
проверенные факты, §62.5); чужие *элементы* внутри объекта (`finalmask.tcp` не массив и т.п.) —
уже покрыты `parse_finalmask_layers` → `None` + отсутствие write-флага.

## 64.2	Модель (`xray/config/inbound_stream/mod.rs`)

| Элемент | Назначение |
| ------- | ---------- |
| `InboundStreamDraft::finalmask_foreign: bool` | Выставляется `parse_inbound_stream`: `finalmask` на диске есть, но это не объект и не `null` (`is_foreign_finalmask`). Для Add-сессий и `Default` — `false`. |
| `InboundStreamDraft::writes_finalmask()` | `write_quic_params \|\| write_finalmask_tcp \|\| write_finalmask_udp` — «применение черновика пишет в `finalmask`». Заменяет повторявшееся условие. |
| Проверка в `apply_inbound_stream` | Сразу после получения `streamSettings`, **до любой мутации**: если `writes_finalmask()` и значение на диске чужое → `ValidationFailed` «streamSettings.finalmask is a string, not a JSON object; Feldjäger leaves it as is — fix or remove it on the Raw JSON tab before editing FinalMask or quicParams». Отклонённый черновик оставляет inbound ровно таким, каким он был. |
| `json_kind(&Value)` | Тип JSON для текста ошибки («a string», «an array», …). Само значение в сообщение не попадает — в нём может быть секрет (пароль маски), а сообщение уходит в статус-бар. |
| Запись | `finalmask` из `streamSettings` больше не клонируется и не вставляется заново: без правок значение просто остаётся на месте (объект, `null` или чужое). При правке берётся существующий объект либо новый (`null`/отсутствие). Обёртка `_preserved` и мёртвая ветка удалены. |

Семантика `null`: `"finalmask": null` считается «отсутствует» (Go декодирует `null` в указатель как
`nil`), поэтому не чужое — без правок остаётся `null`, при правке заменяется объектом.

Поток:
```
parse_inbound_stream
  finalmask: object  → draft (tcp/udp/quicParams по правилам §62.3), finalmask_foreign = false
  finalmask: null    → пустой draft, finalmask_foreign = false
  finalmask: другое  → пустой draft, write-флаги false, finalmask_foreign = true
apply_inbound_stream
  writes_finalmask() && чужое  → Err(ValidationFailed), inbound не тронут
  !writes_finalmask()          → finalmask не трогается вовсе
  writes_finalmask()           → существующий объект | новый объект ← quicParams/tcp/udp
```

Путь ошибки общий для всех потребителей `apply_inbound_stream`: Shell Save / Add
(`compose_inbound_shell`, §62.5), Preview diff и `inbound_editor_warnings` (черновик не собирается →
предупреждений нет, ошибку покажет Save).

## 64.3	GUI (`gui/pages/stream_finalmask.rs`, `gui/pages/inbounds.rs`)

- `show_foreign_finalmask_notice(ui)` — заголовок «FinalMask» с help и жёлтое пояснение: значение не
  объект, редактировать здесь нельзя, при сохранении оно остаётся как есть, исправить или удалить —
  на вкладке Raw JSON (§34.11).
- `inbounds.rs` показывает его **вместо** редакторов, когда `session.stream.finalmask_foreign`:
  секция FinalMask (VLESS/Trojan) → `FinalMaskEdit::default()` (ничего не изменено), Hysteria-арм
  Stream-таба → вместо `show_quic_params_edit`. Так пользователь не может получить черновик, который
  Save отклонит; проверка в модели остаётся страховкой для остальных путей (тесты, будущий Outbound,
  импорт).
- Сессия редактирования строится из inbound при нажатии Edit (`parse_inbound_stream`), поэтому
  после исправления значения через Raw JSON и повторного открытия Edit `finalmask_foreign` будет
  `false`, и редакторы вернутся.

## 64.4	Код

| Область | Путь |
| ------- | ---- |
| Модель | `xray/config/inbound_stream/mod.rs` — `finalmask_foreign`, `writes_finalmask`, `is_foreign_finalmask`, `json_kind`, ранняя проверка и упрощённая запись в `apply_inbound_stream` |
| GUI | `gui/pages/stream_finalmask.rs` — `show_foreign_finalmask_notice`; `gui/pages/inbounds.rs` — ветвление в Stream-табе |

## 64.5	Тесты

- `xray::config::inbound_stream::tests` — 5 новых:
  `parse_flags_only_non_object_non_null_finalmask_as_foreign` (строка / массив / число / bool — чужие
  и без write-флагов; `null` / объект / отсутствие — нет);
  `apply_keeps_foreign_finalmask_byte_for_byte_without_wrapping` (несвязанная правка Stream — смена
  метода на WS — оставляет значение без изменений);
  `apply_rejects_finalmask_edit_over_foreign_value_and_leaves_inbound_unchanged` (для `quicParams`,
  `tcp` и `udp`: `ValidationFailed`, inbound побайтно равен исходному, в сообщении тип JSON, но не
  значение и не `_preserved`);
  `apply_replaces_null_finalmask_with_an_object_when_edited`; `apply_without_edits_keeps_null_finalmask`.
- `xray::config::modify_tests::shell_save_keeps_foreign_finalmask_and_rejects_editing_it` — сквозной
  `update_inbound_shell`: переименование tag сохраняется, `finalmask` остаётся строкой; правка слоя
  поверх него → `ValidationFailed`, значение на диске не изменено.
- Итог: 1144 passed / 9 pre-existing fixture failures (было 1138 / 9); `cargo clippy` — 68
  предупреждений, без новых.
- Не проверено вручную: GUI-пояснение на живом конфиге и Save на SSH-хосте (caveat §40–§63); ветвление
  в Stream-табе тестами egui не покрыто — покрыта модельная проверка, которая срабатывает при любом
  пути в обход GUI.

# 65	FinalMask — этап 0.6: mKCP синхронизирован с ядром (Roadmap §2.6)

## 65.1	Цель и границы

Редактор mKCP (Wave C1, §34.1) был построен по документации: семь полей `kcpSettings`
(`mtu`/`tti`/`uplinkCapacity`/`downlinkCapacity`/`congestion`/`readBufferSize`/`writeBufferSize`),
диапазоны из документации (mtu 576–1460, tti 10–100) и запись всех семи полей на каждый Save.
Аудит 2026-09-28 показал, что документация отстала от ядра. Этот пункт синхронизирует модель,
валидацию и форму с **исходниками** `XTLS/Xray-core@main` — источником истины при расхождениях.

Проверенные факты (сверено 2026-09-29):

| Источник | Факт |
| -------- | ---- |
| `infra/conf/transport_method.go`, `KCPConfig` | Поля: `mtu`, `tti`, `uplinkCapacity`, `downlinkCapacity`, `cwndMultiplier`, `maxSendingWindow` (все `*uint32`); `header` (`json.RawMessage`) и `seed` (`*string`) **объявлены, но нигде не используются** — ни в `Build()`, ни в файле. `congestion`/`readBufferSize`/`writeBufferSize` в структуре нет → JSON-декодер ядра их молча пропускает. |
| `KCPConfig.Build()` | Сначала дефолты, затем проверки: `Mtu < 21` → «MTU must be at least 21»; `Tti < 10 \|\| Tti > 1000` → «TTI must be between 10 and 1000»; `CwndMultiplier < 1` → ошибка; `GetSendingBufferSize() == 0` (т.е. `MaxSendingWindow / Mtu == 0`) → «MaxSendingWindow must be at least <mtu>». |
| `transport/internet/kcp/config.go`, `init` | Дефолты: `Mtu 1350`, `Tti 50`, `UplinkCapacity 5`, `DownlinkCapacity 20`, `CwndMultiplier 1`, `MaxSendingWindow 2*1024*1024`. `GetSendingInFlightSize` делит на `1000 / Tti` — отсюда верхняя граница `tti`. |

Следствия для Feldjäger:
- прежняя валидация была **строже ядра** (mtu 576–1460, tti ≤ 100) и отклоняла конфиги, которые ядро
  принимает, — нарушение «Prefer compatibility over convenience» / «never deviate from the official
  format» (`rules.md`); рекомендация документации сохранена только в help-тексте;
- Save дописывал `congestion`/`readBufferSize`/`writeBufferSize` в каждый mKCP-inbound — ключи, которые
  ядро не читает; после 0.6 они стали бы предупреждениями, созданными самим Feldjäger;
- `header`/`seed` не применяются ядром, хотя парсятся без ошибки — пользователь мог считать, что
  трафик обфусцирован.

В scope: модель, валидация, предупреждения, форма; явное удаление игнорируемых ключей. Вне scope:
миграция `header`/`seed` в FinalMask `mkcp-legacy` (этап 5.2) и форма `mkcp-legacy` (этап 2.1);
правило «без потерь» для нечисловых `mtu`/`tti`/`uplinkCapacity`/`downlinkCapacity` (прежнее поведение —
подстановка дефолта — сохранено; такое значение ядро всё равно отклонит при декодировании в `uint32`).

## 65.2	Модель (`xray/config/inbound_stream/mod.rs`)

| Элемент | Было | Стало |
| ------- | ---- | ----- |
| `KcpStreamSettings` | + `congestion: bool`, `read_buffer_size`, `write_buffer_size` | эти поля удалены (ключи — в `extras`); + `cwnd_multiplier: Option<u64>`, `max_sending_window: Option<u64>` (`None` = ключ отсутствует → дефолт ядра) |
| Запись | все 7 полей всегда | `mtu`/`tti`/`uplinkCapacity`/`downlinkCapacity` всегда (как раньше), `cwndMultiplier`/`maxSendingWindow` — только если заданы, затем `extras` (в т.ч. игнорируемые ядром ключи — ровно как были на диске) |
| Разбор новых полей | — | типизируются только при целом без знака; иная форма (`"big"`) остаётся в `extras` и пишется обратно, а не теряется |
| Константы | `KCP_MTU_MIN 576`, `KCP_MTU_MAX 1460`, `KCP_TTI_MAX 100`, `KCP_DEFAULT_READ_BUFFER`/`_WRITE_BUFFER` | `KCP_MTU_MIN 21`, `KCP_TTI_MAX 1000`, `KCP_CWND_MULTIPLIER_MIN 1`, `KCP_DEFAULT_CWND_MULTIPLIER 1`, `KCP_DEFAULT_MAX_SENDING_WINDOW 2 MiB`; `KCP_MTU_MAX` и дефолты буферов удалены |
| Списки ключей | — | `KCP_IGNORED_FIELDS` (`congestion`, `readBufferSize`, `writeBufferSize`), `KCP_LEGACY_OBFUSCATION_FIELDS` (`header`, `seed`) — единственный источник для модели, предупреждений и GUI |
| Явное удаление | — | `KcpStreamSettings::has_ignored_fields()` / `remove_ignored_fields()` — убирает только `KCP_IGNORED_FIELDS`; `header`/`seed` сохраняются для миграции 5.2 |

`validate_kcp_settings` зеркалит `Build()` в том же порядке: сначала все значения помещаются в
`uint32` (в ядре это типы полей), затем `mtu ≥ 21`, `tti` 10–1000, `cwndMultiplier ≥ 1`, и
`maxSendingWindow / mtu ≠ 0` — **с дефолтами ядра для отсутствующих ключей**, как делает ядро: при
`mtu` больше 2 MiB и отсутствующем окне Save отклоняется с сообщением «maxSendingWindow (2097152,
the default) must be at least mtu». Проверка вызывается там же, где раньше (`apply_inbound_stream`,
ветка `StreamMethod::Mkcp`), поэтому действует для Shell Save, Add, Preview и предупреждений черновика.

## 65.3	Предупреждения (`xray/config/compatibility/warnings.rs`)

Механизм §62.5, два новых id — оба «ключ молча игнорируется ядром», проверено по исходникам (§65.1):

| Id | Ключи | Сообщение (суть) |
| -- | ----- | ---------------- |
| `KcpFieldIgnored` | `kcpSettings.congestion` / `readBufferSize` / `writeBufferSize` | не параметр mKCP; `KCPConfig` содержит только mtu, tti, uplink/downlinkCapacity, cwndMultiplier, maxSendingWindow |
| `KcpLegacyObfuscationIgnored` | `kcpSettings.header` / `seed` | обфускация header/seed не применяется; эквивалент — слой `mkcp-legacy` в `finalmask.udp` |

`KcpLegacyObfuscationIgnored` — сверх буквального текста пункта 0.6 (там только три ключа), но это
тот же проверенный факт, а его последствие серьёзнее: пользователь уверен, что трафик обфусцирован.
Путь — `streamSettings.kcpSettings.<key>`, по одному предупреждению на ключ. `inbound_warnings`
разделён на `finalmask_warnings` и блок `kcpSettings`; порядок — `finalmask`, затем `kcpSettings`
(внутри — порядок ключей объекта). Предупреждения выдаются независимо от `network`: ядро строит
`kcpSettings`, если объект присутствует. Как и все предупреждения, Save они не блокируют.

## 65.4	GUI (`gui/pages/inbounds.rs`)

- Форма mKCP: убраны `congestion` (ComboBox), `readBufferSize`, `writeBufferSize`; добавлены
  `cwndMultiplier` и `maxSendingWindow (bytes)` — пустое поле = ключ отсутствует (hint «default 1» /
  «default 2097152»), help-тексты по коду ядра (`maxSendingWindow / mtu` — размер буфера в пакетах).
- Серая подсказка над формой перечисляет лимиты ядра (`mtu ≥ 21`, `tti 10–1000 ms`,
  `cwndMultiplier ≥ 1`, `maxSendingWindow ≥ mtu`), help `mtu` — «документация рекомендует 576–1460,
  ядро принимает от 21», help `tti` — 10–1000.
- «Явное удаление» из формулировки пункта — кнопка **«Remove ignored fields (congestion,
  readBufferSize, writeBufferSize)»** под формой, видна только когда такие ключи есть в черновике;
  нажатие меняет черновик (`dirty`), запись — обычным Save с backup и `xray run -test`. Какие именно
  ключи и где, показывают жёлтые предупреждения вверху Stream-таба (§62.5).
- View-режим: вместо congestion/буферов — `cwndMultiplier` / `maxSendingWindow` («default (…)» при
  отсутствии).

## 65.5	Код

| Область | Путь |
| ------- | ---- |
| Модель, валидация, константы | `xray/config/inbound_stream/mod.rs` |
| Экспорт констант | `xray/config/mod.rs`, `xray/mod.rs` |
| Предупреждения | `xray/config/compatibility/warnings.rs` (`KcpFieldIgnored`, `KcpLegacyObfuscationIgnored`, `finalmask_warnings`) |
| GUI | `gui/pages/inbounds.rs` (форма и view-режим mKCP, help-тексты) |

## 65.6	Тесты

- `xray::config::inbound_stream::tests`:
  - новые: `validate_kcp_mirrors_core_build_bounds` — значения «вне диапазона документации», которые
    принимает ядро (mtu 21/500/2000, tti 999/1000), **проходят**; `cwndMultiplier 0` — отказ;
    окно меньше mtu — отказ, равное — проходит; отсутствующее окно при mtu > 2 MiB — отказ с
    упоминанием дефолта; поле > `u32::MAX` — отказ;
    `mkcp_new_core_fields_round_trip_and_bad_shapes_stay_in_extras`;
    `mkcp_remove_ignored_fields_keeps_legacy_obfuscation_for_migration` (удаляются только три ключа,
    `seed` и неизвестный ключ остаются, повторный вызов ничего не удаляет);
  - переписаны: `mkcp_alias_parses_and_writes_full_defaults` (игнорируемые ключи идут через extras и
    сохраняются как были), `apply_mkcp_writes_documented_defaults_and_drops_old_settings` (для нового
    mKCP не пишутся ни игнорируемые ключи, ни опциональные поля ядра),
    `validate_kcp_rejects_out_of_range_mtu_tti` и `apply_mkcp_rejects_invalid_ranges` (раньше
    проверяли отказ на mtu 500 / 2000, которые ядро принимает).
- `xray::config::compatibility::warnings::tests::flags_mkcp_keys_the_core_ignores_and_nothing_else` —
  все пять ключей с id и путями, поля ядра и неизвестный ключ без предупреждений, чистый блок — пусто.
- Итог: 1148 passed / 9 pre-existing fixture failures (было 1144 / 9); `cargo clippy` — 66
  предупреждений (было 68: ушли два `collapsible_if` вместе с удалёнными полями формы), новых нет.
- Не проверено вручную: GUI-форма на живом конфиге и Save на SSH-хосте с `xray run -test`
  (caveat §40–§64). Замечено, но не менялось: help `uplinkCapacity`/`downlinkCapacity` говорит
  «0 means unlimited», а в `GetSendingInFlightSize`/`GetReceivingInFlightSize` ядра 0 даёт минимальный
  размер окна (8 пакетов) — кандидат на регулярный аудит дрейфа (Roadmap §2.6 «После FinalMask»).

# 66	Freedom по документации (Roadmap §2.4:105–107)

## 66.1	Цель и границы

Принцип (решение пользователя, аудит 2026-10-01): Freedom Shell предлагает ровно поля официальной
документации (<https://xtls.github.io/en/config/outbounds/freedom.html>) — чего в ней нет, из
редактора убирается, чего нет в Feldjäger, добавляется. Три пункта:

1. `settings.domainStrategy` → `streamSettings.sockopt.domainStrategy` (§2.4:105);
2. `settings.proxyProtocol` (§2.4:106);
3. `settings.finalRules[]` (§2.4:107).

Проверенные факты (`XTLS/Xray-core@main`, 2026-10-01):

| Источник | Факт |
| -------- | ---- |
| `infra/conf/freedom.go`, `FreedomConfig` | Есть `targetStrategy` и `domainStrategy` (оба `string`), `proxyProtocol uint32`, `finalRules []*FreedomFinalRuleConfig`. `Build()`: `targetStrategy`, если не пуст, иначе `domainStrategy` → `config.DomainStrategy` (неизвестное значение — фатальная ошибка); `proxyProtocol` берётся только при `1..=2`. |
| `FreedomFinalRuleConfig.Build()` | `action` — `allow`/`block` без учёта регистра, иначе «unknown action»; `network` — `NetworkList`, `port` — `PortList`, `ip` — `StringList` → `geodata.ParseIPRules`, `blockDelay` — `Int32Range` → `Range{Min,Max}` (`uint64`). |
| `proxy/freedom/freedom.go` | Хендлер берёт стратегию **только** из `streamSettings.SocketSettings.DomainStrategy` (#6058); `config.DomainStrategy` не читается нигде. `blockDelay` по умолчанию 30–90 с. |

Следствие: `settings.domainStrategy` ядро валидирует, но не применяет — пользователь видит в редакторе
поле, которое ничего не делает. Отсюда предупреждение «ignored by Xray-core» (тот же класс фактов, что
§62.5/§65.3) и явная миграция. `targetStrategy` (не документирован, тот же механизм) обрабатывается
вместе с `domainStrategy`.

Вне scope: прочие поля `sockopt` для outbound (Roadmap §4.2), `noises[].applyTo` / `fragment.maxSplit`
(сохраняются через `extras`), Duplicate и Raw JSON (не менялись).

## 66.2	Модель (`xray/config/outbound_protocol/freedom.rs`)

Freedom вынесен из `outbound_protocol/mod.rs` в подмодуль (по образцу `vless.rs`); вариант стал
кортежным: `OutboundSettingsDraft::Freedom(FreedomSettingsDraft)`. Добавлен
`OutboundSettingsDraft::protocol_name()` — заменил приватный `outbound_settings_protocol_name` в
`modify.rs` и используется сервисом для предупреждений черновика Add.

| Поле `FreedomSettingsDraft` | JSON | Правило записи |
| --------------------------- | ---- | -------------- |
| `sockopt_domain_strategy` | `streamSettings.sockopt.domainStrategy` | пусто = ключ отсутствует; читается через `parse_sockopt` |
| `legacy_domain_strategy` (read-only) | `settings.targetStrategy` / `settings.domainStrategy` | никогда не пишется; ключи на диске сохраняются как unknown |
| `remove_legacy_domain_strategy` | — | `true` только после миграции: Save удаляет оба legacy-ключа |
| `redirect`, `user_level`, `fragment`, `noises` | `settings.*` | как раньше (§35) |
| `proxy_protocol` | `settings.proxyProtocol` | `0` = ключ отсутствует |
| `final_rules` / `final_rules_foreign` | `settings.finalRules[]` | пусто = ключ отсутствует; `foreign` → ключ не трогается |

**Запись `sockopt.domainStrategy` — точечная**, а не полный round-trip через `SockoptDraft`
(`sockopt_to_value(parse_sockopt(x))` нормализует: `V6Only: false`, `acceptProxyProtocol: false`,
нечисловой `mark` пропадают). `apply_sockopt_domain_strategy` вставляет/удаляет только один ключ;
контейнеры `streamSettings`/`sockopt` создаются при записи значения и удаляются, только если именно это
удаление их опустошило (пустой `sockopt: {}`, бывший на диске, остаётся). Не-объектный
`streamSettings`/`sockopt` при попытке записать значение — `ValidationFailed` со ссылкой на Raw JSON.

**«Без потерь или raw» для нетипизируемых форм.** Значение, которое виджет не может показать
(`proxyProtocol: "2"`, `userLevel: "1"`, `sockopt.domainStrategy: 5`), не удаляется нетронутым
дефолтом черновика (`apply_untouched_zero_u64`; та же проверка для `sockopt`). Для `finalRules`
действует правило §62.1: если массив или любое правило содержит известный ключ непредставимой формы
(`action` не строка, `ip: [1]`, `blockDelay: 1.5`, элемент не объект, сам `finalRules` не массив) —
`final_rules_foreign = true`, GUI показывает пояснение вместо редактора, Save оставляет ключ как был.

**`FreedomFinalRuleDraft`**: `action`, `network` (текст `"tcp,udp"`), `port: PortListValue`,
`ip: Vec<String>`, `block_delay: RangeValue` (типы §62.1 — число остаётся числом, строка строкой),
`extras`. Форма списков запоминается приватным `ListForm`: `NetworkList`/`StringList` в ядре принимают
и массив, и строку через запятую, нетронутое значение пишется в исходной форме; новые значения — по
документации (`network` — строка, `ip` — массив).

**Валидация при Save** (`validate_final_rule`, зеркалит `Build()`): `action` обязателен и ∈ `allow`/`block`
(регистр не важен); `port` — `PortListValue::validate`; каждая строка `ip` — IP, CIDR с корректной длиной
префикса либо матчер `geoip:`/`ext:`/`ext-ip:` (с необязательным `!`); `blockDelay` —
`RangeValue::bounds` и не отрицателен (ядро кастует в `uint64`). Ошибка указывает индекс:
«Freedom finalRules[1]: …». `proxyProtocol` вне 0–2 не валидируется — ядро его молча игнорирует, а
блокировать Save нетронутого конфига нельзя; GUI подписывает такое значение «not supported».

**Миграция** — `FreedomSettingsDraft::migrate_legacy_domain_strategy() -> LegacyDomainStrategyMigration`:
`Moved { value }` (sockopt был пуст — значение переносится), `SockoptWins { legacy, sockopt }` (sockopt
главнее — legacy просто удаляется), `NothingToMigrate` (нет legacy или уже мигрировано). Меняет только
черновик; запись — обычным Save (backup → `xray run -test` → атомарная запись).

## 66.3	Предупреждения (`compatibility/warnings.rs`)

Добавлен outbound-аналог `inbound_warnings` — `outbound_warnings(&Value)`; путь — внутри outbound
(`settings.domainStrategy`). Новый id `FreedomSettingsDomainStrategyIgnored` — по одному на каждый
присутствующий legacy-ключ, только для `protocol: freedom`, независимо от формы значения.

## 66.4	`ApplicationService`

- `outbound_editor_warnings()` — по черновику: on-disk outbound (или `{protocol, settings}` для Add) +
  `apply_outbound_general` + `apply_outbound_settings`, затем `outbound_warnings`; без кэша (outbound
  мал, в отличие от inbound §62.5). Пусто без сессии и при несобираемом черновике.
- `outbound_warnings_at(index)` — по сохранённому outbound.
- `migrate_outbound_legacy_domain_strategy()` — миграция черновика + `preview_outbound_shell_diff()`,
  возвращает строку статуса (разная для `Moved` / `SockoptWins`).
- После Add / Shell Save статус получает суффикс `with_warning_suffix(outbound_warnings_at(…))`.

## 66.5	GUI (`gui/pages/outbounds.rs`)

Protocol-секция Freedom (`show_freedom_settings_edit`):
- вверху — жёлтые предупреждения (`show_outbound_compatibility_warnings`) и кнопка **«Migrate to
  sockopt»** (видна, пока есть legacy-значение и миграция не выполнена); после нажатия статус и diff
  preview показывают, что изменится;
- `sockopt.domainStrategy` — ComboBox `DOMAIN_STRATEGIES` + «(unset — AsIs)» + свободный текст
  (вместо прежнего `domainStrategy`);
- `proxyProtocol` — ComboBox «0 — disabled» / «v1» / «v2»;
- `finalRules` — упорядоченный список по образцу DNS `rules[]` (Up/Down/Remove/«Add final rule»):
  `action` и `network` — ComboBox, `port`, `blockDelay` (hint с дефолтом 30-90), `ip` — по строке на
  CIDR; при `final_rules_foreign` — пояснение «edit it with Raw JSON».

## 66.6	Код

| Область | Путь |
| ------- | ---- |
| Модель, валидация, миграция | `xray/config/outbound_protocol/freedom.rs` (новый) |
| Диспетчер, `protocol_name` | `xray/config/outbound_protocol/mod.rs`, `xray/config/modify.rs` |
| Предупреждения | `xray/config/compatibility/warnings.rs` |
| Экспорт | `xray/config/compatibility/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs`, `app/mod.rs` |
| Сервис | `app/service.rs` |
| GUI | `gui/pages/outbounds.rs` |

## 66.7	Тесты

- `outbound_protocol::freedom::tests` (12): round-trip `sockopt.domainStrategy` с чужими ключами
  `sockopt`/`streamSettings`; удаление только опустошённых контейнеров, сохранение пустого `sockopt` и
  нестрокового значения; отказ при не-объектном `streamSettings`; legacy читается, не пишется и не
  теряется; приоритет `targetStrategy`; миграция и конфликт; `proxyProtocol` (запись, `0`, строковая
  форма сохраняется); `finalRules` — round-trip форм и `extras`, новые правила, непредставимые формы
  не трогаются, валидация как в ядре, синтаксис `ip`.
- `outbound_protocol::tests::freedom_parse_apply_roundtrip_preserves_unknown` — дополнен `sockopt`,
  `proxyProtocol`, `finalRules`; `apply_rejects_noise_with_empty_type` — на новую структуру.
- `compatibility::warnings::tests::flags_legacy_freedom_strategy_only_on_freedom`.
- `modify_tests`: переписаны `add_freedom_outbound_shell_writes_settings` и
  `update_freedom_outbound_shell_edits_settings_and_preserves_unrelated_fields` (запись в
  `streamSettings.sockopt`, чужие ключи `sockopt` сохраняются), фикстура
  `duplicate_outbound_appends_unique_tag_copy`; новый
  `freedom_legacy_domain_strategy_is_preserved_then_migrated` (без миграции — outbound байт-в-байт +
  предупреждение; миграция; конфликт).
- `service::tests::freedom_legacy_domain_strategy_warning_and_migration` — предупреждения по
  сохранённому outbound и черновику, миграция меняет только черновик и diff preview.
- Итог: 1163 passed / 9 pre-existing fixture failures (было 1148 / 9); `cargo clippy` — 66
  предупреждений (без изменений, в новом коде 0).
- Не проверено вручную: GUI на живом конфиге и Save на SSH-хосте с `xray run -test`.


# 67	FinalMask — этап 0.7: версионная осведомлённость предупреждений (Roadmap §2.6)

## 67.1	Задача

Пункт 0.7 — не про TLS `minVersion`/`maxVersion` (это версии протокола TLS в `tlsSettings`), а про
**версию самого Xray-core**, которую Discovery читает из `xray version` (`XrayInstallation.version`).
Схема FinalMask меняется от релиза к релизу, поэтому один и тот же JSON на разных ядрах означает
разное: до v26.9.9 port hopping — это `quicParams.udpHop`, а UDP-маски `udphop` нет вовсе; на
v26.9.9–v26.9.29 у `udphop` ещё читается `sockopt`. Предупреждения §62.5 были написаны для
текущего ядра и на старом ядре вводили в заблуждение. Решение: таблица «фича → первый релиз» и
сравнение с установленной версией. Результат — только предупреждение, Save не блокируется
(пользователь может как раз собираться обновить ядро).

## 67.2	Таблица версий (`compatibility/core_version.rs`)

| `CoreFeature` | Что в конфиге | Первый релиз | PR |
| ------------- | ------------- | ------------ | -- |
| `XmcTcpMask` | слой `finalmask.tcp[]` типа `xmc` | v26.7.11 | XTLS/Xray-core#6210 |
| `XmcProfilesSchema` | `xmc` `profiles[]` вместо `usernames` (§76) | v26.7.28 | XTLS/Xray-core#6487 |
| `UdpHopUdpMask` | слой `finalmask.udp[]` типа `udphop`; с этого релиза `quicParams.udpHop` игнорируется | v26.9.9 | XTLS/Xray-core#6327 |
| `UdpHopSockoptRemoved` | `udphop` без `sockopt`; с этого релиза `settings.sockopt` слоя игнорируется | v26.9.30 | XTLS/Xray-core#6754 |

Релиз — первый тег `XTLS/Xray-core`, содержащий merge-коммит PR (проверено 2026-10-01 через
`gh api repos/XTLS/Xray-core/compare/<tag>...<commit>`: `behind`/`identical` = тег содержит
коммит), а не дата мержа. Все три релиза — pre-release.

`XrayCoreVersion { major, minor, patch }` — `Ord` (сравнение числовое: v26.9.9 < v26.9.30),
`Display` = `v26.9.30`, `parse` — нестрогий разбор строки Discovery (`"26.9.30"`, `"v26.9.30"`,
`"Xray 25.7.1 (…)"`; недостающие части = 0). `CoreFeature::available_in(Option<XrayCoreVersion>)`
— `None` (версия неизвестна) считается текущим ядром.

## 67.3	Семантика предупреждений

`inbound_warnings(&Value, Option<XrayCoreVersion>)` — новый параметр `core`:

| Конфиг | Ядро < v26.7.11 | < v26.9.9 | v26.9.9–v26.9.29 | ≥ v26.9.30 / неизвестно |
| ------ | --------------- | --------- | ---------------- | ----------------------- |
| `tcp[i].type = xmc` | `RequiresNewerCore` | — | — | — |
| `udp[i].type = udphop` | `RequiresNewerCore` | `RequiresNewerCore` | — | — |
| `udphop.settings.sockopt` | (поглощено строкой выше) | (поглощено) | — | `UdpHopSockoptIgnored` |
| `quicParams.udpHop` | — | — | `QuicParamsUdpHopIgnored` | `QuicParamsUdpHopIgnored` |

> С 0.5.31 (§79) строка `quicParams.udpHop` действует только для outbound; inbound получает
> `QuicParamsUdpHopClientOnly` на любом ядре.

- `CompatibilityWarningId::RequiresNewerCore { feature, installed }` — location указывает на
  `…[i].type`; текст: «`` `udphop` UDP mask `` requires Xray-core v26.9.9 or newer
  (XTLS/Xray-core#6327); installed v26.9.8».
- Без известной версии `RequiresNewerCore` не выдаётся, а «ignored»-предупреждения ведут себя как
  до 0.7 — поведение для пользователей без Discovery не изменилось.
- `CompatibilityWarningId::message()` теперь возвращает `Cow<'static, str>` (у нового варианта
  текст динамический).
- `outbound_warnings` не изменён: версионно-зависимых outbound-фактов пока нет.

## 67.4	Сервис

- `ApplicationService::xray_core_version()` — `XrayCoreVersion::parse` от `installation.version`
  при `DiscoveryState::Succeeded`, иначе `None`.
- `inbound_warnings_at` и `inbound_editor_warnings` передают её в `inbound_warnings`;
  `InboundWarningsCache` хранит `core` и сбрасывается при его смене (повторный Discovery после
  обновления ядра).
- GUI не менялся: новые предупреждения идут через существующие `show_compatibility_warnings`
  (Stream-таб) и `with_warning_suffix` (статус-бар после Save).

## 67.5	Попутно

Исправлен текст `FreedomSettingsDomainStrategyIgnored`: продолжение строки `\` + перевод строки
было потеряно, и в сообщении стояли ~18 пробелов подряд.

## 67.6	Код

| Область | Путь |
| ------- | ---- |
| Таблица и версия | `xray/config/compatibility/core_version.rs` (новый) |
| Предупреждения | `xray/config/compatibility/warnings.rs` |
| Экспорт | `xray/config/compatibility/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Сервис | `app/service.rs` |

## 67.7	Тесты

- `compatibility::core_version::tests` (3): разбор строк Discovery, числовой порядок, таблица
  отсортирована, границы включительные.
- `compatibility::warnings::tests` (+4): текущее/неизвестное ядро — прежний набор; v26.9.9 —
  `sockopt` не помечается; v26.9.8 — `udphop` требует v26.9.9, `quicParams.udpHop` валиден;
  v26.6.27 — `xmc` требует v26.7.11 (точный текст).
- `service::tests::inbound_warnings_follow_the_discovered_core_version` — версия берётся из
  Discovery.
- Итог: 1171 passed / 9 pre-existing fixture failures (нет каталога `tests/fixtures/`);
  в новом коде clippy-предупреждений нет.
- Не проверено вручную: GUI на живом сервере со старым ядром.

# 68	FinalMask — этап 1.1: `udphop` по схеме ядра (Roadmap §2.6)

## 68.1	Главный факт: `udphop` — только клиентская маска

Сверка с `XTLS/Xray-core@main` (`b26a91de`, 2026-09-30) и тегом v26.9.9: в
`transport/internet/finalmask/udphop/config.go` серверная обёртка с первого релиза маски —
`WrapPacketConnServer → errors.New("udphop: client only")`. `FinalMask.ListenPacket` прерывается на
этой ошибке, поэтому inbound с UDP-транспортом (mKCP, Hysteria, XHTTP-h3) и слоем `udphop` **не
стартует** — и вместе с ним весь Xray. На TCP-транспортах цепочка `udp` не используется вовсе, слой
просто мёртвый. `xray run -test` этого **не ловит**: режим `-test` строит конфиг (`Build()`), но не
запускает сервер (`main/run.go`), а ошибка возникает при прослушивании. Пункт 0.3/0.7 считал
`udphop` в inbound нормой и предупреждал только про `sockopt` — это неверно для inbound.

Решение (по правилу «Always validate Xray config before restart»): запись `udphop` в inbound
отклоняется валидацией, уже записанное на диске — предупреждение. Модель и форма слоя
направление-нейтральны и пригодятся outbound-у (этап 7).

## 68.2	Модель (`stream/finalmask.rs`, `stream/finalmask_layers.rs`)

- `CLIENT_ONLY_UDP_FINALMASK_TYPES = ["udphop"]`; `FinalMaskChain { Tcp, Udp }` (`key()`,
  `types()`); `finalmask_layer_type_applies(type, chain, direction)` — сравнение без учёта
  регистра, как `LoadWithID` ядра (`strings.ToLower`); неизвестные типы «применимы» (решает ядро).
- `validate_finalmask_layers(layers, chain, direction)` — новая сигнатура: непустой `type` (теперь с
  местом `finalmask.udp[i]` в тексте), применимость по направлению, типизированная валидация
  `udphop` (основа для этапа 1.4). Слой, который типизированная форма не представляет, оставлен
  ядру. Вызов в `apply_inbound_stream` — `StreamDirection::Inbound`; проверка идёт до мутации.
- `UdpHopSettings` — по `UDPHop` ядра: `mode`/`interval`/`remotePorts`/`remoteIPs`. Типизированный
  `sockopt: Option<SockoptDraft>` удалён: ключ попадает в `extras` и пишется байт-в-байт;
  `has_legacy_sockopt()`/`remove_legacy_sockopt()` — явное удаление. Старые ядра (v26.9.9–29) его
  ещё читают, поэтому автоудаления нет.
- `UdpHopModes { interval_local, interval_remote, per_conn_remote }` + `parse_udphop_mode` — ровно
  как `UDPHop.Build()`: `strings.Split(mode, ",")` **без trim** (`"a, b"` в ядре — ошибка), токены
  без учёта регистра, пустой `mode` = ошибка (обязателен ≥ 1). `to_mode_text()` — каноничная
  запись `intervalLocal,intervalRemote,perConnRemote`.
- `validate_udphop_settings`: `mode`; `interval` — отсутствует/`0`/`"0"` = дефолт 30 с, иначе
  нижняя граница (после упорядочивания, как `ensureOrder`) ≥ 5 (`UDPHOP_MIN_INTERVAL_SECS`);
  `remotePorts` — `PortListValue::validate`; `remoteIPs` — `netip.ParsePrefix` или
  `netip.ParseAddr` (зона `%eth0` только у IPv6-адреса без префикса, биты без ведущих нулей).

Семантика режимов (`udphop/conn.go`): `perConnRemote` — случайная цель из `remoteIPs`/`remotePorts`
при открытии соединения; `intervalRemote` — смена цели по таймеру; `intervalLocal` — новый локальный
сокет по таймеру. Таймер — случайное значение из `interval` на каждый шаг. С пустыми
`remoteIPs`/`remotePorts` «remote»-режимы адрес не меняют.

## 68.3	Предупреждения (`compatibility/warnings.rs`)

- Новое `CompatibilityWarningId::UdpHopClientOnly` на `streamSettings.finalmask.udp[i].type`.
- `finalmask_warnings` получил `StreamDirection`: для inbound слой `udphop` даёт
  `UdpHopClientOnly` (его `sockopt` не помечается — слой всё равно удалять), для outbound —
  прежнее версионное `UdpHopSockoptIgnored`. Outbound-ветка пока вызывается только тестами
  (подключение — этап 7). Таблица §67.3: строка `udphop.settings.sockopt` теперь относится к
  outbound, для inbound на ядре ≥ v26.9.9 — `UdpHopClientOnly`; `RequiresNewerCore` для ядра
  < v26.9.9 не изменился.
- Следствие для редактора: `parse_inbound_stream` выставляет `write_finalmask_udp` для любой
  цепочки на диске, поэтому при `udphop` на диске черновик не собирается (Save отклоняется) и
  `inbound_editor_warnings` пуст — вместо него в редакторе слоя показывается пояснение.

## 68.4	GUI (`gui/pages/stream_finalmask.rs`)

- Пресеты типов фильтруются по `finalmask_layer_type_applies`: inbound больше не предлагает
  `udphop`. Существующий неприменимый слой помечается оранжевым пояснением («client-only … Saving
  this chain is refused until the layer is removed»).
- Форма `udphop`: `mode` — три чекбокса (`lenient_udphop_modes` читает и неканоничный текст, клик
  переписывает его каноничным); `interval`/`remotePorts` с подсказками; `remoteIPs` списком;
  help-тексты на каждое поле; подсказка про «remote»-режимы без целей; текст ошибки
  `validate_udphop_settings` («Save will be refused: …»); для `sockopt` — пояснение и кнопка
  «Remove sockopt». Вложенный `show_sockopt_edit` из формы убран, параметр `direction` у
  `show_finalmask_settings_edit` больше не нужен.

## 68.5	Сверка ядра для следующих пунктов

Попутно обнаружено: после аудита 2026-09-28 в v26.9.30 вошли XTLS/Xray-core#6718 (XDNS
refactor: `domains[]` — объекты `{name, lenLimit, labelLimit, types, edns0}`, `resolvers[]` —
`{type: tcp|udp, settings: {addr}}`, новый `extraPoll` 0–3; ключа `domain` в схеме нет вовсе —
фатальной removed-feature ошибки тоже нет, он просто игнорируется) и #6862 (`noise.type` = `exp`).
Пункт 1.3 Roadmap в прежней формулировке устарел.

## 68.6	Код

| Область | Путь |
| ------- | ---- |
| Модель слоя | `xray/config/stream/finalmask_layers.rs` |
| Цепочка, применимость, валидация | `xray/config/stream/finalmask.rs` |
| Применение к inbound | `xray/config/inbound_stream/mod.rs` |
| Предупреждения | `xray/config/compatibility/warnings.rs` |
| Экспорт | `xray/config/stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| GUI | `gui/pages/stream_finalmask.rs` |
| Тесты сервиса | `app/service.rs` |

## 68.7	Тесты

- `stream::finalmask_layers` (+3, 1 переписан): `sockopt` сохраняется байт-в-байт и удаляется
  явно; разбор `mode` как в ядре (пробел, пустой, хвостовая запятая, регистр); валидация —
  `interval` 0/`"0"`/`"10-5"`/4/`"3-10"`/`"-5"`, порты, IP/CIDR/зоны/ведущие нули.
- `stream::finalmask` (+2, 2 переписаны): client-only по направлению; типизированная валидация
  `udphop` на клиентской стороне; место `finalmask.udp[i]` в тексте ошибки.
- `inbound_stream` (+1): Save с `udphop` отклонён без мутации, без слоя — проходит.
- `compatibility::warnings` (переписаны 4): inbound — `UdpHopClientOnly`, outbound — версионный
  `sockopt`.
- `service::tests` (переписаны 4): `UdpHopClientOnly`; кэш предупреждений черновика проверяется на
  mKCP-фикстуре с `congestion` (неблокирующее предупреждение).
- `gui::pages::stream_finalmask` (+1, 1 дополнен): чекбоксы по неканоничному тексту; показ формы
  `udphop` с невалидным `mode` и `sockopt` не переписывает `settings`.
- Итог: 1176 passed / 9 pre-existing fixture failures; clippy 66 (без изменений).
- Не проверено вручную: GUI на живом сервере.

# 69	FinalMask — этап 1.2: `realm` по схеме ядра (Roadmap §2.6)

## 69.1	Что такое `realm` и на какой стороне работает

Сверка с `XTLS/Xray-core@main` (`b26a91de`): `infra/conf/transport_finalmask.go` (`Realm`,
`Realm.Build()`) и `transport/internet/finalmask/realm/*`. Маска пробивает NAT для UDP через
realm-сервер в стиле Hysteria: обе стороны регистрируются на сервере `url` под одним realm id
(`token` — bearer-учётка), узнают свой публичный адрес через `stunServers` и, если включено,
открывают порт на домашнем шлюзе (`portMapping`: UPnP / NAT-PMP, `github.com/libp2p/go-nat`).
В отличие от `udphop` (§68), `realm` работает на **обеих** сторонах (`WrapPacketConnServer` →
`NewConnServer`), поэтому ограничений по направлению нет.

## 69.2	Модель (`stream/finalmask_realm.rs`)

Секция `realm` вынесена из `finalmask_layers.rs` в отдельный модуль (разбор URL занимает
больше, чем остальные слои); `finalmask_layers` реэкспортирует её, общие хелперы
(`string_field`, `extras_of`, `apply_*`, …) стали `pub(super)`, добавлен `bool_option_field`.

- `RealmSettings`: `url` (текст, lossless), `stun_servers`, `tls_config: Option<Value>`,
  `ip_mode`, `port_mapping: Option<RealmPortMapping>`, `extras`.
- `RealmPortMapping { enabled: Option<bool>, timeout: Option<i64>, lifetime: Option<i64>,
  extras }` — сообщение `realm.PortMapping` (Go декодирует в `int64`, поэтому float/строка →
  слой на raw JSON); явный `"enabled": false` сохраняется. Дефолты ядра:
  `REALM_DEFAULT_PORT_MAP_TIMEOUT_SECS = 10`, `REALM_DEFAULT_PORT_MAP_LIFETIME_SECS = 600`.
- `REALM_IP_MODES = ["dual", "v4", "v6"]`; `realm_ip_mode_is_known` (без учёта регистра —
  `Build()` делает `strings.ToLower`). Иное значение ядро молча трактует как `dual`, поэтому это
  подсказка в форме, а не ошибка.
- `tlsConfig` — клиентский `TLSConfig` для HTTPS к realm-серверу (`http.go: NewClient`; без него
  — `http.DefaultClient`). Остаётся JSON-объектом: клиентского TLS-редактора ещё нет (Outbound
  `streamSettings`, §4.2), а его `Build()` выполняется при загрузке конфига, т.е. ошибки ловит
  `xray run -test`.

### URL как поля

`RealmUrl { scheme: RealmScheme, token, host, port, id, suffix }`, `parse_realm_url` — как Go
`url.Parse` + чтение в `Realm.Build()`:

| Часть | Правило |
| ----- | ------- |
| схема | `realm` → HTTPS (порт 443), `realm+http` → HTTP (80); без учёта регистра |
| `?query` / `#fragment` | отрезаются первыми, ядром не читаются; хранятся в `suffix` |
| userinfo | до последнего `@` в authority; символы как `validUserinfo`, иначе ошибка; `token` = `PathUnescape(u.User.String())`, т.е. `:` — часть токена |
| host | IPv6 в `[]`; `host:` без цифр = порт по умолчанию; порт — только цифры |
| id | путь без одного ведущего `/`, `PathUnescape`; `/` внутри допустим |

`parse_realm_url` сообщает только структурные ошибки (схема, экранирование, синтаксис порта), а
пустые host/token/id — `RealmUrl::validate`, чтобы форма показывала поля недописанного URL.
`to_url_text` кодирует token (всё, кроме unreserved) и id (unreserved и `/`), поэтому ядро
читает ровно те же поля (тест обратимости на токене `p@ss:w/rd?#%+ ü`).

### Валидация (`validate_realm_settings`)

Как `Build()`: `url` обязателен и разбирается; host, token, id непусты; `stunServers` ≥ 1, каждый
проходит `net.SplitHostPort`. Сверх `Build()` — то, что рантайм отбрасывает молча или с ошибкой
только в логе:

- порт STUN-сервера не число → `resolveSTUNServers` пропускает сервер (`strconv.Atoi` → `continue`);
- порт realm-сервера вне 1–65535 (`url.Parse` принимает любые цифры);
- отрицательные `portMapping.timeout`/`lifetime` → `PortMapConfig.withDefaults` возвращает ошибку,
  маппинг не создаётся.

`validate_finalmask_layers` теперь вызывает диспетчер `validate_typed_layer(chain, type,
settings)` (`udphop`, `realm`; этап 1.4 добавит остальные типы); формат ошибки прежний —
`finalmask.udp[i] (realm): …`.

## 69.3	GUI (`gui/pages/stream_finalmask.rs`)

- `url` — текстовое поле; под ним `realm_url_fields_edit`: схема (radio), token, host, port
  (подсказка — порт схемы по умолчанию), id. Правка поля пересобирает `url`; host/port
  отбрасывают символы, после которых URL не разобрать (пробелы, `/?#@[]`, нецифры в порту). URL,
  который не разбирается, показывается ошибкой — правится текстом.
- `stunServers` — список; `ipMode` — `optional_string_combo` (`(default)` = dual) + пометка
  неизвестного значения; `portMapping` — чекбокс (снятие удаляет ключ, если кроме `enabled`
  ничего не задано) + `timeout`/`lifetime` (`optional_i64_field`); `tlsConfig` — чекбокс +
  `optional_json_object_edit` (буфер текста как у raw-JSON редактора, «Not applied: …» для
  невалидного JSON).
- Help на каждое поле, inline «Save will be refused: …» из `validate_realm_settings`.

## 69.4	Код

| Область | Путь |
| ------- | ---- |
| Модель, URL, валидация | `xray/config/stream/finalmask_realm.rs` (новый) |
| Хелперы, реэкспорт | `xray/config/stream/finalmask_layers.rs` |
| Диспетчер валидации | `xray/config/stream/finalmask.rs` |
| Экспорт | `xray/config/stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| GUI | `gui/pages/stream_finalmask.rs` |

## 69.5	Тесты

- `stream::finalmask_realm` (7): round-trip с типизированным `portMapping` и raw `tlsConfig`;
  непредставимый `portMapping` → raw JSON; разбор URL как `Build()` (регистр схемы, `:`/`@` в
  токене, IPv6, пустой порт, 9 ошибочных форм); `RealmUrl::validate`; обратимость
  `to_url_text`; валидация настроек (STUN без порта, IPv6 без скобок, нечисловой порт,
  отрицательные таймауты, неизвестный `ipMode` — не ошибка); пресеты `ipMode`.
- `stream::finalmask` (+1): `realm` на обеих сторонах, место ошибки, raw-настройки — ядру.
- `gui::pages::stream_finalmask` (+1, +2 случая): правка поля URL переписывает `url` с
  сохранением смысла токена; показ формы с неканоничным и неразбираемым URL не меняет `settings`.
- Итог: 1185 passed / 9 pre-existing fixture failures; clippy 66 (без изменений).
- Не проверено вручную: GUI и реальный realm-сервер.

# 70	FinalMask — этап 1.4: валидация каждого типа слоя по `Build()` ядра (Roadmap §2.6)

## 70.1	Задача и точка входа

До 1.4 Feldjäger проверял у слоя только непустой `type` (плюс `udphop`/`realm` с 1.1/1.2), а
ошибки `Build()` ядра всплывали лишь в post-write `xray run -test` — после записи и бэкапа, без
указания слоя. Теперь каждая проверка `Build()` зеркалится до записи:

- `validate_finalmask_layer(chain, type, settings) -> Result<(), String>` (`stream/finalmask.rs`)
  — один диспетчер на все типы; `validate_finalmask_layers` (Save) добавляет к ошибке место
  `finalmask.<chain>[i] (<type>)`.
- GUI (`stream_finalmask.rs`) показывает результат того же диспетчера под каждым слоем — в том
  числе под raw-JSON редактором `header-custom`/`xmc`/`mkcp-legacy`. Inline-проверки внутри форм
  `udphop`/`realm` убраны.

Сверено с `XTLS/Xray-core@main` (`b26a91de`, v26.9.30), `infra/conf/transport_finalmask.go`.

## 70.2	Правила диспетчера

| Ситуация | Результат |
| -------- | --------- |
| пустой `type` | `Ok` (сообщает `validate_finalmask_layers`) |
| тип только другого массива (`fragment` в `udp`) | ошибка: загрузчик массива ядра его не знает |
| тип, неизвестный обоим массивам | `Ok` — ядро может быть новее Feldjäger, `xray run -test` скажет |
| типизированный слой, `settings` разбираются | проверка черновика |
| типизированный слой, `settings` не разбираются (raw) | `Ok` — оставлено ядру |
| `header-custom`, `xmc`, `mkcp-legacy` | проверка JSON (`finalmask_raw.rs`; `mkcp-legacy` с этапа 2.1 — `finalmask_mkcp.rs`, §73; у `header-custom` с этапов 2.2/2.3 есть формы, но проверка остаётся по JSON, §74–75; для UDP — ещё размеры заголовка при старте, §75) |
| `sudoku` | `Sudoku.Build()` ничего не проверяет; с этапа 2.5 — runtime-проверки `ascii` и custom tables (§77) |
| `xdns` | `Ok` — схема сменилась (#6718), этап 1.3 |

## 70.3	Типизированные слои (`finalmask_layers.rs`)

- **fragment** (`FragmentMask.Build()`): все диапазоны разбираются; `packets` — `tlshello` (без
  учёта регистра), пусто или `ParseRangeString`, причём ядро берёт **первое число как написано**
  (без `ensureOrder`): `"0-3"` — ошибка, `"3-0"` — нет. Последний элемент `lengths` (или `length`,
  если `lengths` пуст; отсутствие = 0) не может начинаться с 0 — то есть **`length` обязателен**.
  Для этого `values::parse_range_string` стал `pub(super)`.
- **salamander**: если верхняя граница `packetSize` > 0 (режим Gecko) — диапазон в 1–2048. С этапа
  2.5 — ещё `password` ≥ 4 байт (runtime, `NewSalamanderObfuscator`; §77).
- **noise**: на каждый item — все диапазоны; `packet` и `rand` с верхней границей > 0
  взаимоисключающие; `type: "exp"` — выражение (ниже); иначе `randRange` в 0–255, `type` из
  `array`/`str`/`hex`/`base64` (`PACKET_KINDS`), для `str`/`hex`/`base64` нужен `packet` (пустой
  `RawMessage` ядро не декодирует), затем `PacketValue::validate`.
- **xicmp**: каждый `ips[]` — `netip.ParseAddr` (общий хелпер `is_ip_addr`, его же использует
  `is_ip_or_prefix` из 1.1).

### `noise` `type: "exp"` (XTLS/Xray-core#6862, v26.9.30)

`validate_noise_exp` — ручной эквивалент сканирования ядра регулярным выражением
`<\s*([a-z]+)(?:\s+([^>]*?))?\s*>` (крейта `regex` в зависимостях нет): между сегментами —
только пробельные символы RE2 (`\s` = пробел, `\t`, `\n`, `\f`, `\r`), ключ — строчные латинские
буквы, аргумент — после хотя бы одного пробела. Сегменты как `buildNoiseSegment`:

| Сегмент | Аргумент |
| ------- | -------- |
| `<b …>` | hex (пробелы внутри и префикс `0x`/`0X` допустимы), непустой, чётной длины |
| `<r N>`, `<rc N>`, `<rd N>` | размер `N` или `MIN-MAX`, 0–65535, не перевёрнутый |
| `<t>`, `<c>`, `<n>` | без аргумента |

Пустое выражение — ошибка. Версия: `CoreFeature::NoiseExpPacket` (v26.9.30, #6862) →
`RequiresNewerCore` на `streamSettings.finalmask.udp[i].settings.noise[j].type`
(`compatibility/warnings.rs`).

## 70.4	Raw-слои (`stream/finalmask_raw.rs`, новый)

Проверки по JSON с правилами Go-декодера: отсутствие или `null` — нулевое значение, неверный
JSON-тип — ошибка декодирования, поле `json.RawMessage` (`packet`, `bytes`) считается заданным,
если ключ есть, даже со значением `null`.

- **header-custom TCP** (`clients`/`servers`/`errors` — списки последовательностей items) и
  **UDP** (`mode` — пусто, `prefix` или `standalone`, с учётом регистра; `client`/`server`). Item:
  `validateCustomItemSpec` — имена `capture`/`reuse` `^[A-Za-z_][A-Za-z0-9_]*$`; ровно один вид из
  `packet`, `rand > 0`, `reuse`, `transform`; `capture` без вида — ошибка; у TCP-item — `delay`;
  `randRange` в 0–255; `packet` по `type` (`validate_raw_packet` поверх `PacketValue`);
  `transform` рекурсивно — `op` и непустые `args`, у аргумента ровно одно из `bytes`, `u64`
  (неотрицательное целое), `reuse`, `metadata`, `transform`.
- **xmc**: `profiles` ≥ 1, затем `password` непуст (порядок ядра), у профиля username
  `^[A-Za-z0-9_]{3,16}$`, UUID (крейт `uuid` — те же формы, что `google/uuid`: с дефисами,
  32 hex, `urn:uuid:`, в фигурных скобках), оба `textures*` непусты.
- **mkcp-legacy**: `header` пусто или (без учёта регистра) `dns`/`dtls`/`srtp`/`utp`/`wechat`/
  `wireguard` (`MKCP_LEGACY_HEADERS`); `value` — строка.

## 70.5	Попутно

Фикстуры `apply_without_finalmask_edits_preserves_existing_object_untouched` и
`finalmask_tcp_ok_with_tls_security` содержали `fragment` с пустыми `settings` — ядро такой слой
отвергает («last lengths entry min can't be 0»). Дополнены `length`.

## 70.6	Код

| Область | Путь |
| ------- | ---- |
| Диспетчер, `FinalMaskChain::other` | `xray/config/stream/finalmask.rs` |
| Типизированные проверки, `exp` | `xray/config/stream/finalmask_layers.rs` |
| Raw-проверки | `xray/config/stream/finalmask_raw.rs` (новый) |
| Диапазон без упорядочивания | `xray/config/stream/values.rs` |
| Версия `exp` | `xray/config/compatibility/core_version.rs`, `warnings.rs` |
| GUI | `gui/pages/stream_finalmask.rs` |
| Экспорт | `xray/config/stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |

## 70.7	Тесты

- `stream::finalmask_layers` (+4): `fragment` (первое число `packets` как написано, обязательный
  `length`, приоритет `lengths`), `salamander`, `noise` (24 случая, включая 13 на `exp`), `xicmp`.
- `stream::finalmask_raw` (5): допустимые формы `header-custom` TCP; 18 нарушений item/transform
  с местом `clients[0][0]`; UDP `mode` с учётом регистра; `xmc`; `mkcp-legacy`.
- `stream::finalmask` (+1): диспетчер для всех типов, «чужой» массив, неизвестный тип, raw-
  настройки, место ошибки.
- `compatibility::warnings` (+1): `exp` требует v26.9.30.
- Итог: 1196 passed / 9 pre-existing fixture failures; clippy 66 (без изменений).
- Не проверено: паритет с реальным `xray run -test` (fixtures — пункт 1.5), GUI вручную.

# 71	FinalMask — этап 1.3: `xdns` по схеме v26.9.30 (Roadmap §2.6)

## 71.1	Почему не по исходной формулировке

Пункт 1.3 был написан по аудиту 2026-09-28, но в v26.9.30 вошёл XTLS/Xray-core#6718 (§68.5),
полностью сменивший схему `xdns`. По решению пользователя пункт реализован под текущую схему ядра;
старая — только распознаётся, предупреждается и мигрирует по кнопке.

| | v26.9.9 – v26.9.29 | v26.9.30+ |
| - | ------------------ | --------- |
| `domains` | строки `"t.example.com[:txt\|a\|aaaa]"` (сервер) | объекты `{name, lenLimit, labelLimit, types, edns0}` (обе стороны) |
| `resolvers` | строки `"t.example.com[:метод]+udp://АДРЕС"` (клиент) | `{type: udp\|tcp, settings: {addr}}` (клиент) |
| `extraPoll` | — | 0–3 |
| `domain` | фатальная removed-feature ошибка | молча игнорируется |

## 71.2	Модель (`stream/finalmask_xdns.rs`, новый)

`XdnsSettings { domains, resolvers, extra_poll, extras }`, `XdnsDomain { name, len_limit,
label_limit, types: Vec<i64>, edns0, extras }`, `XdnsResolver { kind, addr, has_settings,
settings_extras, extras }` — extras на каждом уровне, legacy `domain` остаётся в `extras`
байт-в-байт. Строковые `domains`/`resolvers` (и иные непредставимые формы) → `parse_xdns_settings`
возвращает `None`, слой остаётся на raw JSON. Секция `xdns` удалена из `finalmask_layers.rs`
(реэкспорт сохранён).

## 71.3	Валидация

`validate_xdns_domain` — `XDNS.Build()` + `NewDomain()` (`transport/internet/finalmask/xdns/domain.go`):

- без `..`; Feldjäger дополнительно требует непустой `name` (ядро туннелировало бы под корнем DNS);
  IDNA-преобразование оставлено ядру;
- `lenLimit` 0–255, `labelLimit` 0–63 (0 = 255 / 63); значения — в пределах `int32` (Go);
- `types` ≥ 1, каждый после приведения `int32 → uint16` — A (1), CNAME (5), TXT (16), AAAA (28)
  (`65552` = TXT, как в ядре); `edns0` — 0 или 512–4096 (тоже после `uint16`);
- `dnsmessage.NewName(name + ".")` — не длиннее 255 байт; `lenLimit ≥ длина + 1`;
- ёмкость: `room = lenLimit − длина − 1`, метки `room / (labelLimit + 1)` по `labelLimit` символов
  плюс остаток − 1, затем base32 без паддинга `DecodedLen`; меньше 17 байт — ошибка
  (`xdns_payload_capacity`; для `t.example.com` при 255/63 — 147 байт).

`validate_xdns_settings(draft, direction)`: все домены и резолверы (`type` `udp`/`tcp` без учёта
регистра, `settings` обязателен, `addr` = `host:port`, IPv6 в скобках, порт 1–65535 —
`net.ParseDestination` при дозвоне), `extraPoll` 0–3, и проверки конструкторов, которых
`xray run -test` не видит: `domains` ≥ 1 (`NewServer`/`NewClient`), `resolvers` ≥ 1 только для
`StreamDirection::Outbound` (`NewClient`; сервер резолверы игнорирует).

Поэтому `validate_finalmask_layer(chain, direction, type, settings)` получил направление (Save и
GUI его уже знали). Старая схема Save не блокирует: она верна для ядра v26.9.9–29, а для нового
ядра есть предупреждение.

## 71.4	Миграция старой схемы

`xdns_has_legacy_fields` — есть `domain` или строки в `domains`/`resolvers`.
`migrate_legacy_xdns_settings` (кнопка «Migrate to the v26.9.30 schema», явное действие):

- `"name[:метод]"` (`parseDomainSpec`: метод после последнего `:`) → `{name, types: [тип]}`;
  `txt`/пусто → 16, `a` → 1, `aaaa` → 28 — без метода берётся TXT (умолчание старого клиента);
- `"name[:метод]+udp://addr"` → `{type: "udp", settings: {addr}}`, а имя попадает в `domains`
  (новому клиенту оно нужно там) — слияние по имени без учёта регистра, типы объединяются;
- строковый `domain` → запись в `domains`, ключ удаляется;
- записи уже в новой форме и неизвестные ключи сохраняются; повторная миграция — без изменений;
- нестроковый `domain`, неизвестный метод, резолвер без `+udp://`, пустое имя — ошибка, настройки
  не меняются (GUI показывает «Can't migrate automatically: …»).

## 71.5	Версии и предупреждения

`CoreFeature::XdnsObjectSchema` (v26.9.30, #6718). В `finalmask_warnings` для слоя `xdns`:

| Конфиг | Ядро < v26.9.30 | ≥ v26.9.30 / неизвестно |
| ------ | --------------- | ----------------------- |
| старая схема | — | `XdnsLegacySchema` на `…udp[i].settings` |
| объекты в `domains`/`resolvers` | `RequiresNewerCore` на `…udp[i].settings` | — |

## 71.6	GUI (`stream_finalmask.rs`)

- `show_finalmask_settings_edit` снова получает `StreamDirection` (для `xdns`).
- Новая схема: домены группами (name, чекбоксы A/CNAME/TXT/AAAA — `xdns_types_edit`, коды вне
  набора сохраняются и показываются как «unsupported», lenLimit/labelLimit/edns0 с подсказками
  умолчаний), «Add domain» (TXT по умолчанию); резолверы (ComboBox udp/tcp + addr, на inbound —
  «Client side only»), «Add resolver»; `extraPoll`; help на каждый блок. Ошибки — общей строкой
  под слоем (§70).
- Старая схема (`show_legacy_xdns_edit`): пояснение, кнопка миграции (или причина, почему нельзя) и
  raw-редактор.

## 71.7	Код

| Область | Путь |
| ------- | ---- |
| Модель, валидация, миграция | `xray/config/stream/finalmask_xdns.rs` (новый) |
| Реэкспорт, удаление старой модели | `xray/config/stream/finalmask_layers.rs` |
| Диспетчер с направлением | `xray/config/stream/finalmask.rs` |
| Версия, предупреждение | `xray/config/compatibility/core_version.rs`, `warnings.rs` |
| GUI | `gui/pages/stream_finalmask.rs` |
| Экспорт | `xray/config/stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |

## 71.8	Тесты

- `stream::finalmask_xdns` (6): round-trip новой схемы с extras на всех уровнях; старая схема не
  разбирается типизированно, `domain` сохраняется и распознаётся; `NewDomain` (13 случаев, включая
  приведение `uint16`, ёмкость, `int32`); формула ёмкости; валидация по направлению и резолверов;
  миграция (слияние, объединение типов, идемпотентность, 4 ошибки).
- `stream::finalmask` (+1, 1 дополнен): резолверы обязательны только клиенту; старая схема не
  блокирует Save.
- `compatibility::warnings` (+1): схема по версии ядра в обе стороны.
- `gui::pages::stream_finalmask` (+1 случай): показ новой формы не меняет `settings`.
- `stream::finalmask_layers`: тест старой строковой модели удалён, 2 теста переведены на новую.
- Итог: 1203 passed / 9 pre-existing fixture failures; clippy 66 (без изменений).
- Не проверено: реальный DNS-туннель, GUI вручную, IDNA-имена.

# 72	FinalMask — этап 1.5: fixtures и паритет с `xray run -test` (Roadmap §2.6)

## 72.1	Где лежат fixtures

Не в `tests/fixtures/`: строка `tests` в `.gitignore` исключает каталог целиком, а git не
заходит в исключённый каталог, поэтому `!tests/fixtures/finalmask/` не сработал бы. Из-за этого
9 старых тестов (`tests/fixtures/xray/…`) падают на чистом клоне. Fixtures FinalMask лежат рядом с
кодом — `src/xray/config/stream/fixtures/finalmask/{valid,invalid}/*.json` — и встраиваются через
`include_str!`: отсутствующий файл = ошибка компиляции. `.gitignore` не менялся.

## 72.2	Формат и таблица случаев

- Файл — объект `streamSettings.finalmask` как на диске (чистый Xray JSON без служебных ключей),
  его можно вставить в конфиг руками.
- Ожидания — в `CASES` (`stream/finalmask_fixtures.rs`, `#[cfg(test)]`): путь, `StreamDirection`,
  `Valid` / `build(needle)` / `runtime(needle)`, необязательный `CoreFeature` (минимальная версия
  ядра). Один файл может участвовать в нескольких случаях (`valid/xdns_server` — валиден на
  inbound, на outbound — ошибка `resolvers`).
- Прогон повторяет Save: каждая цепочка → `parse_finalmask_layers` → `validate_finalmask_layers`.
- `CoreCheck::Build` — ошибку видит `Build()` ядра (`xray run -test` падает); `CoreCheck::Runtime` —
  только при listen/dial (`udphop: client only`, `NewClient` без `resolvers`, нечисловой порт STUN),
  `-test` проходит. Ради второго вида Feldjäger и проверяет до записи.

## 72.3	Паритет-тест

`parity_with_xray_run_test`: без `XRAY_BIN` — no-op с сообщением в stderr. С ним — версия из
`xray version` (`XrayCoreVersion::parse`), случаи с `CoreFeature` новее ядра пропускаются; каждый
случай оборачивается в минимальный конфиг (inbound VLESS на `127.0.0.1:10443` / outbound Freedom;
`network` `kcp` для чисто UDP-цепочки, иначе `raw`), пишется во временный каталог и проверяется
`xray run -test -c <file>` (аргументы напрямую, без shell). `Build`-случаи ядро должно отвергнуть,
`Valid` и `Runtime` — принять; если ядро начнёт отвергать `Runtime`-случай на этапе build, его надо
перевести в `Build`. Все расхождения собираются в одно сообщение.

## 72.4	Код

| Область | Путь |
| ------- | ---- |
| Таблица случаев, прогон, паритет | `xray/config/stream/finalmask_fixtures.rs` (новый, `#[cfg(test)]`) |
| Fixtures (34 файла) | `xray/config/stream/fixtures/finalmask/{valid,invalid}/` (новый) |
| Подключение модуля | `xray/config/stream/mod.rs` |

## 72.5	Тесты

- `stream::finalmask_fixtures` (4): 37 случаев по 34 файлам — все 4 TCP- и 9 UDP-типов валидны,
  пустой `type`, чужая цепочка и нарушения `Build()` по каждому типу с проверками (у `sudoku` их в
  ядре нет); каждый документированный тип имеет валидный fixture; каждый файл каталога упомянут в
  `CASES`; паритет.
- Мутационная проверка: заменённое ожидание `invalid/header_custom_udp_mode_case` на `Valid` роняет
  тест с текстом ошибки валидатора.
- Итог: 1207 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений), новых
  предупреждений в тестовом модуле нет.
- Не проверено: паритет с реальным ядром — локального `xray` нет; первый прогон
  `XRAY_BIN=/path/to/xray cargo test finalmask_fixtures` может потребовать поправить `CoreCheck`
  отдельных случаев (например, `xmc`-текстуры, если ядро декодирует их строже).

# 73	FinalMask — этап 2.1: типизированная форма `mkcp-legacy` (Roadmap §2.6)

## 73.1	Сверка с ядром

`XTLS/Xray-core@main`, `infra/conf/transport_finalmask.go` `MkcpLegacy {Header, Value string}` и
`transport/internet/finalmask/mkcp/{original,aes128gcm,header}`. `Build()` выбирает одну из трёх масок:

| `header` | `value` | Маска ядра |
| -------- | ------- | ---------- |
| пусто | пусто | `original.Config` — исходная обфускация mKCP |
| пусто | задан | `aes128gcm.Config{Password: value}` |
| `dns` | домен (пусто = `www.baidu.com`) | `header.Config{ID: 0, Domain}` — поддельный DNS-запрос |
| `dtls`/`srtp`/`utp`/`wechat`/`wireguard` | **игнорируется** | `header.Config{ID: 1…5}` |

`header` сравнивается без учёта регистра (`strings.ToLower`), без `trim`; старые имена
`kcpSettings.header` (`none`, `wechat-video`) здесь недопустимы — важно для миграции 5.2. Маска
работает на обеих сторонах (`NewConnServer` = `NewConnClient`). Принимающая сторона просто отрезает
`header.Size()` байт, а для `dns` размер зависит от длины домена — домены клиента и сервера обязаны
совпадать.

Домен `dns` кодируется не в `Build()`, а при создании listener/dialer (`NewHeaderDNS` →
`packDomainName(domain + ".", buf[256])`): метка ≥ 64 байт — ошибка `bad rdata`, переполнение
буфера — `buffer size too small`, а имя ровно в 256 байт даёт `buf[:257]` — **панику** Go.
`xray run -test` ничего из этого не ловит, поэтому проверка — как у прочих runtime-only отказов
(`udphop`, `realm`).

## 73.2	Модель

Новый модуль `stream/finalmask_mkcp.rs` (туда же перенесены `MKCP_LEGACY_HEADERS` и
`validate_mkcp_legacy` из `finalmask_raw.rs`):

- `MkcpLegacySettings {header, value, extras}` — обе строки **дословно** (без `trim`, в отличие от
  `string_field`: пароль и домен ядро использует побайтно); `parse_mkcp_legacy_settings` → `None`
  для не-строковых `header`/`value` (правило «без потерь или raw»); `mkcp_legacy_settings_to_value`
  опускает пустые строки (нулевое значение Go).
- `MkcpLegacySettings::mode() -> Option<MkcpLegacyMode>` (`Original` / `Aes128Gcm` /
  `Dns {domain}` / `Header(name)`; `None` — заголовок, который ядро отвергнет) — одна реализация
  ветвления `Build()` для валидации и подсказок GUI.
- `validate_mkcp_legacy_settings` (черновик) и `validate_mkcp_legacy` (JSON: сначала типы как
  декодер Go, затем черновик). Диспетчер `validate_finalmask_layer` по-прежнему зовёт JSON-вариант:
  типизированная форма не может представить не-строковое значение, а ошибку декодирования надо
  показать до Save.
- `encoded_dns_name_len` — порт `packDomainName` (экранирование `\x`, пустые метки не ошибка) +
  отказ на 256 байтах вместо паники.

## 73.3	GUI

`show_mkcp_legacy_settings_edit` (`gui/pages/stream_finalmask.rs`) на общей обвязке
`FinalMaskForm`: ComboBox `header` («(none)» + шесть заголовков; значение с диска не из списка —
`DNS`, невалидное `none` — показывается как есть, пока не выбран другой пункт; свободного ввода нет:
ядро ничего другого не примет), `value` с `hint_text` по режиму (пароль / `www.baidu.com` /
«(not used)»), строка-пояснение `mkcp_legacy_mode_note` (что построит ядро; для `dns` — требование
одинакового домена; заданный, но игнорируемый `value` — оранжевым, значение сохраняется). Ошибки —
общая строка «Save will be refused: …» под слоем. Help на оба поля.

## 73.4	Код

| Область | Путь |
| ------- | ---- |
| Модель, валидация, порт `packDomainName` | `xray/config/stream/finalmask_mkcp.rs` (новый) |
| Удалено (перенесено) | `xray/config/stream/finalmask_raw.rs` |
| Диспетчер, реэкспорт | `xray/config/stream/{finalmask,mod}.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Форма | `gui/pages/stream_finalmask.rs` |
| Fixtures | `valid/mkcp_legacy_{dns,aes}.json`, `invalid/mkcp_legacy_dns_label.json` |

## 73.5	Тесты

- `stream::finalmask_mkcp` (4): `mode()` как `Build()` (регистр, без trim, `none`/`wechat-video`
  отвергаются); round-trip дословно + extras, пустые/`null` → отсутствуют, не-строки → raw;
  типы Go и регистр в `validate_mkcp_legacy` (перенесённый тест); границы `packDomainName`
  (63/64 байта метки, `\.`, пустые метки, 255 байт проходит, 256 — отказ вместо паники).
- GUI (`finalmask_form_tests`): +4 случая «показ не переписывает settings» (`DNS`, пробелы в
  `value`, пустой/`null`, невалидный и не-строковый `header`); выбор заголовка не трогает
  `value`/extras; пояснение следует режиму.
- Fixtures: +3 случая (`dns` в верхнем регистре, AES-пароль на outbound, `runtime` — метка 64 байта).
- Итог: 1212 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (`XRAY_BIN`) — локального `xray` нет; GUI вручную не
  запускался.

# 74	FinalMask — этап 2.2: типизированная форма `header-custom` TCP (Roadmap §2.6)

## 74.1	Сверка с ядром

`XTLS/Xray-core@main`, `infra/conf/transport_finalmask.go` `HeaderCustomTCP {Clients, Servers,
Errors [][]TCPItem}`, `TCPItem {Delay Int32Range, Rand int32, RandRange *Int32Range, Capture,
Type, Reuse string, Transform *CustomTransform, Packet json.RawMessage}` и рантайм
`transport/internet/finalmask/header/custom/tcp.go`:

| Сторона | `clients[i]` | `servers[i]` | `errors[i]` |
| ------- | ------------ | ------------ | ----------- |
| клиент (outbound) | пишет | читает и проверяет | **не использует** |
| сервер (inbound) | читает и проверяет | пишет после `clients[i]` | пишет при несовпадении `clients[i]`, затем отказ |

- Порядок: клиент `clients[0]` → `servers[0]` → `clients[1]` → …; лишние `servers` идут после
  последней клиентской последовательности.
- Item — ровно один вид (`validateCustomItemSpec`): `packet` (ключ задан, даже `null` —
  `len(RawMessage) > 0`), `rand > 0`, `reuse`, `transform`; либо ни одного (пустой item; `capture`
  без вида — ошибка). При чтении `packet`/`reuse`/`transform` сравниваются побайтно, `rand` —
  пропуск N байт любого содержимого; `randRange` (по умолчанию 0–255) влияет только на запись.
- `delay` действует только при записи: накопленные items сбрасываются в сокет, затем пауза
  (`writeSequenceWithContext`); при чтении игнорируется.
- `rand` — Go `int32`: строка `"4"` — ошибка декодирования (в отличие от `Int32Range`).
- Операции `transform` — `evaluator.go`: `concat`, `slice`, `xor16`/`xor32`, `be16`/`be32`,
  `le16`/`le32`/`le64`, `pad`, `truncate`, `add`, `sub`, `and`, `or`, `shl`, `shr`; аргумент —
  ровно одно из `bytes`(+`type`)/`u64`/`reuse`/`metadata`/`transform`.

## 74.2	Модель

Новый модуль `stream/finalmask_header_custom.rs`:

- `HeaderCustomItem {delay, rand, rand_range, kind, packet, capture, reuse, transform, extras}` —
  `delay`/`randRange` через `RangeValue`, `packet` через `PacketValue`, строки дословно
  (`verbatim_string` из `finalmask_mkcp.rs` стал `pub(super)`), `rand` — текст, пишется числом,
  если разбирается, иначе как набран (Save покажет ошибку ядра), `transform` — сырой JSON-объект.
- `HeaderCustomSequences {sequences, present}` — `present` сохраняет пустую группу с диска
  (`"errors": []` не исчезает при правке); `HeaderCustomTcpSettings {clients, servers, errors,
  extras}` + `group`/`group_mut` по `HeaderCustomTcpGroup` (`ALL`, `key()`).
- `HeaderCustomItem::kind() -> Option<HeaderCustomItemKind>` (`Empty`/`Packet`/`Rand`/`Reuse`/
  `Transform`; `None` — несколько видов) — счёт как `validateCustomItemSpec`, для подсказок GUI.
- Правило «без потерь или raw»: `packet: null` и `transform: null` → raw (для ядра `packet: null`
  — заданный вид, удаление ключа изменило бы валидацию), как и любой ключ неверного JSON-типа.
- Валидация не дублируется: диспетчер по-прежнему вызывает `validate_header_custom_tcp` по JSON
  (`finalmask_raw.rs`).

Попутное исправление `PacketValue::to_value` (`values.rs`): строковый `packet` пишется
**дословно**, без `trim` — раньше любая правка слоя срезала завершающий `\r\n\r\n` у `str`-пакета
(HTTP-подобный заголовок), т.е. меняла маску; касалось и `noise`. Пустым («ключ отсутствует»)
по-прежнему считается только пустой после `trim` текст. Новые `escape_packet_text` /
`unescape_packet_text` — представление `str`-пакета в одну строку (`\\`, `\r`, `\n`, `\t`,
`\xHH` для управляющих ASCII); неизвестное экранирование — ошибка, текст не применяется.

## 74.3	GUI

`show_header_custom_tcp_settings_edit` (`gui/pages/stream_finalmask.rs`) на `FinalMaskForm`.
Диспетчер `show_finalmask_settings_edit` получил `chain: FinalMaskChain`: у `header-custom` в
`tcp[]` и `udp[]` разные схемы, UDP остаётся на raw JSON до этапа 2.3.

- Три группы с help и строкой роли по `StreamDirection` (`header_custom_group_writes`: inbound
  читает `clients`, пишет `servers`/`errors`; на outbound заданный `errors` — оранжевое «ignored»,
  значение сохраняется).
- Последовательности и items — группы с Up / Down / Remove (`ListEdit` + `list_edit_buttons` +
  `apply_list_edit`; Up/Down недоступны на краях), «Add … sequence» (с одним пустым item),
  «Add item».
- Поля item: `delay`, `packet` (ComboBox `type`: «(array)»/`array`/`str`/`hex`/`base64`, значение
  с диска не из списка показывается как есть; смена типа перечитывает текст в новой кодировке),
  `rand` + `randRange`, `reuse`, `capture`, `transform` (`optional_json_object_edit`). `str`-пакет
  редактируется с экранированием через буфер `load_text_buffer` — недописанное `\x` не
  применяется и не схлопывается.
- Под item — `header_custom_item_note`: что эта сторона делает с item («Sends 8 random bytes,
  values 0-255», «Accepts any 8 bytes · delay is not used when receiving», «· saved as `n`»).
  Ошибки — общая строка «Save will be refused: clients[i][j]: …» под слоем; индексы в заголовках
  совпадают.

## 74.4	Код

| Область | Путь |
| ------- | ---- |
| Модель | `xray/config/stream/finalmask_header_custom.rs` (новый) |
| `packet` дословно, экранирование | `xray/config/stream/values.rs` |
| Реэкспорт, doc-комментарии | `xray/config/stream/{mod,finalmask,finalmask_layers,finalmask_raw,finalmask_mkcp}.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Форма, диспетчер по цепочке | `gui/pages/stream_finalmask.rs` |
| Fixture | `valid/header_custom_tcp_http.json` (CRLF в `str`, `capture`/`reuse`, `errors` hex) |

## 74.5	Тесты

- `stream::finalmask_header_custom` (5): round-trip документированных форм без изменений (CRLF,
  пустые последовательность и группа, extras на обоих уровнях); непредставимое → raw (`rand`
  строкой/вне `int32`/дробный, `packet: null`, `transform: null`/строка, не-массивы); запись
  правок в формах ядра + сохранение `"errors": []`; `kind()` как `validateCustomItemSpec`; обе
  valid-fixtures принимаются формой без изменений.
- `stream::values` (+2): `str`-пакет пишется дословно; экранирование обратимо, ошибки `\`, `\q`,
  `\x8`, `\xff`.
- GUI (`finalmask_form_tests`, +4): показ формы и raw-fallback не переписывают `settings`
  (типизированная форма действительно выбрана для TCP и не выбрана для UDP); правка одного item и
  перестановка сохраняют CRLF соседнего; подсказки по стороне; `apply_list_edit` на границах.
- Fixtures: +2 случая (`header_custom_tcp_http` на inbound и outbound).
- Итог: 1223 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (`XRAY_BIN`) — локального `xray` нет; GUI вручную не
  запускался.

# 75	FinalMask — этап 2.3: типизированная форма `header-custom` UDP (Roadmap §2.6)

## 75.1	Сверка с ядром

`XTLS/Xray-core@main`, `infra/conf/transport_finalmask.go` `HeaderCustomUDP {Mode string, Client,
Server []UDPItem}`, `UDPItem` = `TCPItem` без `delay`; рантайм
`transport/internet/finalmask/header/custom/{udp,evaluator}.go`.

| `mode` | Протобуф | Что происходит |
| ------ | -------- | -------------- |
| пусто / `prefix` | `UDPConfig` | `client`/`server` — заголовок перед **каждым** пакетом соответствующей стороны; получатель сверяет и срезает его, несовпадение — пакет отбрасывается (лог `header mismatch`) |
| `standalone` | `UDPStandaloneConfig` | `client` — отдельный пакет-рукопожатие, который клиент шлёт один раз на адрес и ждёт ответа `server`; затем данные идут без изменений. Сервер отвечает только на пакет **ровно** размера `client`, который совпал; остальные пакеты — данные |

`mode` сравнивается **с учётом регистра** (`Prefix` — `unknown udp mode`).

**Размер заголовка измеряется при создании listener/dialer** (`measureUDPItems` /
`measureUDPItemsWithFallback` + `collectSavedUDPSizes`), а не в `Build()` — `xray run -test`
отказ не видит, Xray не стартует (inbound) или не может дозвониться (outbound):

- `reuse` неизвестной переменной — `unknown variable`; переменные известны по порядку items, в
  `server` дополнительно доступны все `capture` из `client` (`collectSavedUDPSizes` пропускает
  items, которые не измеряются);
- `transform`: фиксированную ширину имеют только `concat` (сумма аргументов), `slice`/`pad`/
  `truncate` (длина — аргумент `u64`, проверяется число аргументов), `be16`/`le16` = 2,
  `be32`/`le32` = 4, `le64` = 8; прочие операции — `expr size is not bytes`; аргумент `u64` в
  `concat` — `u64 arg has no byte width`; `metadata` — `metadata not implemented`.
- Что измеряется, зависит от режима и стороны: `prefix` — обе стороны измеряют `client` и
  `server` (с переменными `client`); `standalone` — сервер измеряет только `client`, клиент —
  только `server`. То, что сторона **отправляет** в `standalone`, вычисляется на каждый пакет —
  там `metadata` работает (`evaluateExprArg`).

## 75.2	Модель

`stream/finalmask_header_custom.rs` расширен на обе цепочки:

- Разбор item обобщён: `parse_item(value, known)` — `delay` читается только для TCP, в UDP-item он
  неизвестный ключ и сохраняется в `extras`; запись — общий `item_to_value` (у UDP-item `delay`
  всегда пуст).
- `HeaderCustomUdpSettings {mode, client, server, extras}` (`mode` дословно), `HeaderCustomItems
  {items, present}` (пустая группа с диска сохраняется), `HeaderCustomUdpGroup` (`ALL`, `key()`),
  `is_standalone()` (точное сравнение, как ядро), `HEADER_CUSTOM_UDP_DEFAULT_MODE`;
  `parse_header_custom_udp_settings` / `header_custom_udp_settings_to_value`. Не-строковый `mode`,
  `packet: null` и прочие непредставимые формы → raw JSON.
- `values.rs`: `decoded_packet_len(value, type)` — длина после `PraseByteSlice` (`array`: длина
  списка или base64 строки; `str`: UTF-8; `hex`/`base64`: декодированная; `null` = 0).
- `finalmask_raw.rs`: порт `measureItem`/`measureExpr`/`measureExprArg` по JSON (порядок видов как
  в ядре: `rand`, `packet`, `reuse`, `transform`) и `validate_header_custom_udp_sizes(settings,
  direction)`; диспетчер `validate_finalmask_layer` вызывает её после `validate_header_custom_udp`.
  Сообщение называет item (`client[0]: unknown variable "nonce" — no earlier item captures it`) и
  поясняет, что ошибка появится при создании listener/dialer.

## 75.3	GUI

`show_header_custom_udp_settings_edit` (`gui/pages/stream_finalmask.rs`) на `FinalMaskForm`;
диспетчер выбирает TCP/UDP-форму по `FinalMaskChain`.

- ComboBox `mode` («(prefix)» + `prefix`/`standalone`; значение с диска не из списка — `Prefix` —
  показывается как есть) и строка-пояснение по режиму; help на `mode` включает правила размера
  заголовка.
- Группы `client`/`server` с help и строкой роли по режиму и `StreamDirection`
  (`header_custom_udp_group_note`: «Put in front of every packet this inbound sends», «The client
  handshake: a packet of exactly this size that matches is answered with server…»).
- Items — общий с TCP редактор: `header_custom_sequence_edit` → `header_custom_items_edit(path,
  items, writes, with_delay)`, `header_custom_item_edit(…, with_delay)`; для UDP поле `delay` не
  показывается. Up/Down/Remove, подсказка под item, экранирование `str`-пакета — как в §74.
- Тест raw-JSON редактора переведён с `header-custom` UDP на `xmc` (у UDP теперь форма).

## 75.4	Код

| Область | Путь |
| ------- | ---- |
| Модель UDP, общий разбор item | `xray/config/stream/finalmask_header_custom.rs` |
| Длина `packet` после декодирования | `xray/config/stream/values.rs` |
| Порт измерения размеров | `xray/config/stream/finalmask_raw.rs` |
| Диспетчер, реэкспорт | `xray/config/stream/{finalmask,mod}.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Форма | `gui/pages/stream_finalmask.rs` |
| Fixtures | `valid/header_custom_udp_prefix.json` (DTLS-подобный заголовок, `capture` в `client` → `reuse` в `server`), `invalid/header_custom_udp_unknown_reuse.json` (`runtime`) |

## 75.5	Тесты

- `stream::finalmask_header_custom` (+2, и обе UDP valid-fixtures в round-trip): round-trip
  `standalone` с CRLF и пустой группой, `delay` UDP-item — в extras, `Prefix` дословно,
  `null` → отсутствует, непредставимое → raw; запись правок (`mode`, новый item, пустая группа).
- `stream::values` (+1): `decoded_packet_len` по всем типам.
- `stream::finalmask_raw` (+1): размеры как `measureUDPItems` — `capture` в `client` → `reuse` в
  `server`, фиксированные операции, `reuse` до `capture`, `xor16`, `u64`/`metadata` в `concat`,
  число аргументов `slice`, длина `pad` не `u64`; `standalone` по сторонам (`metadata` в ответе
  сервера — допустимо на inbound, отказ на outbound; неизвестная переменная в `client` — наоборот).
- `stream::finalmask` (+1 случай в диспетчере), fixtures (+3 случая).
- GUI (+3): показ UDP-формы и raw-fallback не переписывают `settings` (форма действительно
  выбрана; для UDP не выбирается TCP-форма); смена `mode` сохраняет items дословно; пояснения по
  режиму и стороне.
- Итог: 1230 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (`XRAY_BIN`) — локального `xray` нет; GUI вручную не
  запускался.

# 76	FinalMask — этап 2.4: типизированная форма `xmc` (Roadmap §2.6)

## 76.1	Сверка с ядром

`XTLS/Xray-core@main`: `infra/conf/transport_finalmask.go` `XMC {Hostname, Profiles []XMCProfile,
Password}`, `XMCProfile {Username, UUID, TexturesValue, TexturesSignature}` (все — Go `string`);
рантайм `transport/internet/finalmask/xmc/{client,server,profile,protocol,derivation}.go`.

| Поле | Кто использует | Что происходит |
| ---- | -------------- | -------------- |
| `password` | обе стороны | `DeriveRSAKey` — детерминированный 1024-битный RSA-ключ (имитация online-mode шифрования); клиент дописывает пароль к 4-байтному verify token и шифрует PKCS#1 v1.5, сервер сравнивает (`ConstantTimeCompare`) |
| `profiles[]` | обе стороны | клиент **на каждое соединение** выбирает профиль случайно и шлёт username + UUID; сервер принимает только профиль из своего списка (`findProfile`, иначе «not white-listed») и отвечает **своими** textures, клиент сверяет весь профиль (`login profile mismatch`) — списки должны совпадать |
| `hostname` | только клиент | адрес сервера в Minecraft-handshake (пусто = IP, по которому идёт дозвон); сервер читает и игнорирует |

`Build()`: `profiles` ≥ 1, `password` непуст, у профиля username `^[A-Za-z0-9_]{3,16}$`, UUID
(`google/uuid.Parse`: с дефисами, 32 hex, `{…}`, `urn:uuid:`), оба textures непусты. Ограничений
по направлению нет (`WrapConnClient`/`WrapConnServer`).

**Runtime-only** (`xray run -test` не видит, Xray стартует, но **каждое соединение** падает на
логине):

- `password` > 113 байт — `128 − 11` (PKCS#1 v1.5 на 1024-битном ключе) `− 4` (verify token):
  `rsa.EncryptPKCS1v15` у клиента возвращает ошибку; отказ на обеих сторонах (пара конфигов
  должна совпадать, сервер с таким паролем недостижим);
- `texturesValue`/`texturesSignature` > 4096 байт — клиент читает строку ответа сервера с лимитом
  `String.readFrom` (`length > 4096`); обе стороны;
- `hostname` > 4096 байт — тот же лимит у сервера; только outbound (на inbound поле не
  используется).

**Смена схемы.** До v26.7.28 (XTLS/Xray-core#6487; первый тег с новой схемой, v26.7.11 ещё со
старой — проверено по исходникам тегов) был `usernames: []string` (пусто = `["Dream"]`),
`Build()` требовал только `password`. Новое ядро `usernames` игнорирует и без `profiles`
отказывает; старое игнорирует `profiles`. Решение — как у `xdns` (§71): старую схему Save **не
блокирует** (верна для старого ядра), версионное предупреждение + явное действие в редакторе.
Полной автоматической миграции нет и быть не может: подписанные textures выдаёт только Mojang.

## 76.2	Модель

Новый модуль `stream/finalmask_xmc.rs` (`validate_xmc` перенесён из `finalmask_raw.rs`):

- `XmcSettings {password, hostname, profiles: Vec<XmcProfile>, extras}`,
  `XmcProfile {username, uuid, textures_value, textures_signature, extras}` — строки **дословно**
  (пароль используется побайтно, username с пробелом ядро отвергает — не «исправляем»);
  пустая строка / пустой список = ключ отсутствует. Legacy `usernames` — в `extras` байт-в-байт
  (`legacy_usernames()`, `remove_legacy_usernames()`). Не-строковые поля, `profiles` не массив
  объектов (`[null]`) → `None` → raw JSON.
- `xmc_has_legacy_usernames(settings)` — `usernames` задан и `profiles` нет/пуст (при обоих
  ключах новое ядро читает `profiles` — валидируется новая схема).
- `migrate_legacy_xmc_usernames(draft)` — по профилю-заготовке на каждое имя (`Dream` для пустого
  списка, как старое ядро), `usernames` удаляется; UUID и textures заполняет пользователь.
  Отказ без изменений, если `profiles` уже задан или `usernames` — не список строк.
- `validate_xmc_settings(draft, direction)` — сначала проверки `Build()`, затем runtime-лимиты
  (`XMC_MAX_PASSWORD_BYTES` = 113, `XMC_MAX_STRING_BYTES` = 4096; `hostname` — только
  `Outbound`); `validate_xmc(settings, direction)` — Go-декодирование по JSON (типы строк,
  `profiles[i]` — объект), старая схема → только `password`, иначе typed-проверка. Диспетчер
  `validate_finalmask_layer` передаёт направление.
- `xmc_username_is_valid` — `xmcUsernamePattern`, общий для валидации и подсказки в форме.

## 76.3	Предупреждения и версии

- `CoreFeature::XmcProfilesSchema` → v26.7.28, #6487 (таблица §67.2).
- `finalmask_warnings` для слоя `xmc`: ядро старше v26.7.11 — только `RequiresNewerCore
  {XmcTcpMask}` на `…tcp[i].type` (схема не важна); иначе `XmcLegacyUsernames` на
  `…tcp[i].settings.usernames` при старой схеме и ядре ≥ v26.7.28/неизвестном, и
  `RequiresNewerCore {XmcProfilesSchema}` на `…tcp[i].settings.profiles` при непустых `profiles`
  и ядре v26.7.11–v26.7.27.

## 76.4	GUI

`show_xmc_settings_edit` (`gui/pages/stream_finalmask.rs`) на `FinalMaskForm`, получает
`StreamDirection`. Диспетчер: `xmc` в `tcp[]` — форма, в `udp[]` — raw JSON (ошибка «tcp mask»
под слоем).

- `password` + счётчик «N/113 bytes» (оранжевый сверх лимита); `hostname` с подсказкой по
  стороне, на inbound заданный `hostname` — оранжевое «ignored on the inbound side».
- `profiles`: строка роли по стороне (`xmc_profiles_note`), группы `profiles[i]` с Up/Down/Remove
  (общие `list_edit_buttons`/`apply_list_edit`), поля username (inline-подсказка формата), uuid,
  `texturesValue`/`texturesSignature` — многострочные; «Add profile».
- Legacy `usernames`: без `profiles` — пояснение и кнопка «Start profiles from usernames» (или
  причина, почему нельзя); с `profiles` — пояснение и «Remove usernames».
- Help на все поля; в help `profiles` — как получить профиль (UUID по имени через
  `api.mojang.com`, подписанный профиль `sessionserver.mojang.com/…?unsigned=false`). Сам
  Feldjäger к Mojang не обращается.
- Тест raw-JSON редактора переведён с `xmc` на неизвестный тип `future-mask`.
- Попутно: в help/пояснениях `mkcp-legacy` (§73) строки были склеены с серией пробелов вместо
  переноса строки-литерала — исправлено.

## 76.5	Код

| Область | Путь |
| ------- | ---- |
| Модель, валидация, миграция | `xray/config/stream/finalmask_xmc.rs` |
| Диспетчер, реэкспорт | `xray/config/stream/{finalmask,finalmask_raw,mod}.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Версии, предупреждения | `xray/config/compatibility/{core_version,warnings}.rs` |
| Форма | `gui/pages/stream_finalmask.rs` |
| Fixtures | `invalid/xmc_long_password.json` (`runtime`, обе стороны), `invalid/xmc_long_hostname.json` (`runtime` на outbound, valid на inbound); существующие xmc-случаи помечены `XmcProfilesSchema` (на v26.7.11 `profiles` игнорируется — паритет иначе разошёлся бы) |

## 76.6	Тесты

- `stream::finalmask_xmc` (+4, из них 1 перенесён из `finalmask_raw`): round-trip дословно с
  extras, нулевые значения → отсутствуют, непредставимое → raw; проверки `Build()` (включая
  username из 17 символов, `profiles[0]` не объект) и их приоритет над runtime; runtime-лимиты по
  сторонам (байты, не символы); старая схема — не блокируется, миграция, `Dream`, отказы без
  изменений.
- `compatibility::warnings` (+1): `usernames`/`profiles` по версии ядра в обе стороны, ядро без
  `xmc`.
- GUI (+2): показ формы и raw-fallback не переписывают `settings` на обеих сторонах (в т.ч. с
  legacy `usernames`), `xmc` в `udp[]` — raw; реальная правка пишется; пояснения по сторонам.
- Fixtures (+4 случая).
- Итог: 1236 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (`XRAY_BIN`) — локального `xray` нет; GUI вручную не
  запускался.

# 77	FinalMask — этап 2.5: доработка форм и help на каждый тип маски (Roadmap §2.6)

## 77.1	Сверка с ядром

`XTLS/Xray-core@main`: `infra/conf/transport_finalmask.go` (`FragmentMask`, `NoiseMask`,
`Salamander`, `Sudoku`, `Xicmp`), `infra/conf/common.go` (`Int32Range`), рантайм
`transport/internet/finalmask/{fragment,noise,salamander,sudoku,xicmp}/*.go`.

| Маска | Что важно для формы |
| ----- | ------------------- |
| `fragment` | `packets`: пусто — **каждая** запись; `tlshello` — только **первая** запись и только если это целая TLS handshake-запись (`p[0] == 22`): тело режется на несколько TLS-записей; `FROM-TO` — записи с номерами FROM..TO (с 1), режутся на отдельные TCP-записи; порядок не нормализуется, `"3-1"` не совпадает ни с одной записью. `lengths[i]`/`delays[i]` — по номеру куска, последний повторяется; `length`/`delay` читаются только при пустых списках. `tlshello` **склеивает** записи в одну TCP-запись, когда список задержек (`delays` или `[delay]`) — ровно один элемент с верхней границей 0, в т.ч. при отсутствии `delay` (`mergeTlsHelloSegments`). `maxSplit` — кусок с этим номером забирает остаток. Обе стороны (`WrapConnServer`) |
| `noise` | Мусорные датаграммы перед первым пакетом на **каждый адрес назначения**, повторно — через `reset` секунд (0/пусто — однократно); `delay` — пауза после датаграммы. Item без `packet` и `rand` шлёт **пустую** датаграмму. `exp` — выражение, `rand`/`randRange` не используются. Обе стороны, ответной маски не нужно |
| `salamander` | **Runtime-only:** `password` < 4 байт (`smPSKMinLen`) — `NewSalamanderObfuscator` отказывает при создании listener/dialer; `xray run -test` не видит. Gecko (`packetSize`) режет и добивает до размера только QUIC long-header (handshake) пакеты на 2–8 фрагментов; short-header идут как есть |
| `sudoku` | `Build()` не проверяет ничего. **Runtime-only:** `ascii` ∉ {`""`, `entropy`, `prefer_entropy`, `ascii`, `prefer_ascii`} (trim, без учёта регистра) и custom table не из 8 символов «2 x, 2 p, 4 v» (пробелы и регистр игнорируются) — `getTables` падает: на `tcp[]` на **каждом соединении**, на `udp[]` при создании listener/dialer. В ASCII-раскладке таблицы не читаются; `customTables` скрывает `customTable`; padding: каждое соединение выбирает шанс между `paddingMin` и `paddingMax` (> 100 → 100, max < min → min) |
| `xicmp` | `dgram` — только клиент (unprivileged ICMP); сервер всегда raw. `ips`: у клиента — адреса сервера (случайный), пусто — адрес outbound (домен без `ips` — ошибка дозвона); у сервера — фильтр источников (пусто — все) |

## 77.2	Модель

`stream/finalmask_layers.rs`:

- `FRAGMENT_PACKETS_TLSHELLO`, `FragmentPackets {All, TlsHello, Range{from,to}}`,
  `fragment_packets_mode(packets)` / `FragmentMaskSettings::packets_mode()`,
  `FragmentMaskSettings::merges_tls_records()` (зеркало `mergeTlsHelloSegments`).
- `NoiseItemPayload {Exp, Rand, Packet, Empty}`, `NoiseMaskItem::payload()` — как `buildPacket`;
  `None` при `packet` + `rand` (ошибка `Build()`).
- `SALAMANDER_MIN_PASSWORD_BYTES` = 4; `validate_salamander_settings` — после проверки
  `packetSize` (ошибка `Build()` раньше runtime) проверяет длину пароля в байтах.
- `SUDOKU_ASCII_MODES`, `SUDOKU_MAX_PADDING`; `SudokuSettings::{prefers_ascii, custom_patterns,
  effective_padding}`; `validate_sudoku_custom_table` (порядок проверок как `normalizeCustomTable`),
  `validate_sudoku_settings`. Диспетчер `validate_finalmask_layer`: `sudoku` в обоих массивах.

## 77.3	GUI

`gui/pages/stream_finalmask.rs`:

- Help по **типу** слоя — кнопка рядом с выбором `type` (`finalmask_type_help(chain, type)`; у
  `header-custom` свой текст для `tcp`/`udp`; тип чужого массива — без help).
- `fragment` (получил `StreamDirection`): ComboBox `packets` — «(every write)» / `tlshello` /
  «range» (выбор range начинает с `1-3`, текст правится рядом; значение с диска вроде `TLSHello`
  показывается как есть); help на все поля и списки; строка-пояснение `fragment_notes` (что
  режется на этой стороне, склейка записей `tlshello`, `FROM > TO` — оранжевым, `length`/`delay`
  при заданных списках — «not used»).
- `noise`: help на `reset`; items с Up/Down/Remove; общий с `header-custom` редактор пакета —
  `packet_kind_combo(kinds, kind, packet)` + `packet_text_edit(kind, packet)` (бывшие
  `header_custom_packet_*`), для `noise` типы `array`/`str`/`hex`/`base64`/`exp`; смена типа
  перечитывает текст; `str` — с экранированием, `exp` — подсказка выражения; строка-пояснение
  `noise_item_note` («Sends 8-16 random bytes, values 0-255 · then waits 10 ms», пустая
  датаграмма, «rand / randRange are not used with exp»).
- `salamander`: счётчик «N bytes · at least 4» (оранжевый при нехватке), подсказка
  `packetSize`, строка режима (Salamander / Gecko с диапазоном).
- `sudoku`: ComboBox `ascii` («(entropy)», `entropy`, `ascii`; `prefer_*` с диска — как есть),
  inline-ошибка `customTable` (только в entropy-раскладке), `sudoku_notes` (таблицы в ASCII,
  `customTable` под `customTables`, фактический padding).
- `xicmp` (получил `StreamDirection`): help на `dgram`/`ips`, `dgram` на inbound — оранжевое
  «ignored», пояснение смысла `ips` по стороне.

## 77.4	Код

| Область | Путь |
| ------- | ---- |
| Модель, валидация | `xray/config/stream/finalmask_layers.rs` |
| Диспетчер, реэкспорт | `xray/config/stream/{finalmask,mod}.rs`, `xray/config/mod.rs`, `xray/mod.rs` (+ `NOISE_EXP_KIND`) |
| Формы, help | `gui/pages/stream_finalmask.rs` |
| Fixtures | `valid/sudoku_custom_tables.json` (обе стороны), `invalid/sudoku_custom_table.json`, `invalid/sudoku_ascii_mode.json`, `invalid/salamander_short_password.json` (обе стороны) — все `runtime`; пароли в `valid/both_chains.json`, `invalid/salamander_packet_size.json` удлинены |

## 77.5	Тесты

- `stream::finalmask_layers` (+3, 1 расширен): `fragment_packets_mode` и склейка записей; `payload`
  noise-item; `sudoku` — режимы `ascii`, таблицы (пробелы/регистр, legacy-ключ, `customTables`
  скрывает `customTable`, ASCII не читает таблицы), `effective_padding`; `salamander` — длина
  пароля в байтах (`"äö"` = 4).
- `stream::finalmask` (+3 случая в диспетчере), fixtures (+6 случаев).
- GUI (+4, 1 расширен): help у каждого документированного типа в своём массиве; `fragment_notes`,
  `noise_item_note`, `sudoku_notes`; показ форм не переписывает `settings` (`TLSHello`, `3-1`,
  `EXP`, `randRange` при `exp`, `Prefer_ASCII`, `paddingMin: 200`, `dgram` на inbound,
  короткий пароль salamander).
- Итог: 1243 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (`XRAY_BIN`) — локального `xray` нет; GUI вручную не
  запускался.

# 78	FinalMask — этап 3.1: `quicParams` полностью (Roadmap §2.6)

## 78.1	Сверка с ядром

`XTLS/Xray-core@main` (b26a91d, 2026-09-30): `infra/conf/transport_finalmask.go`
(`QuicParamsConfig`, 17 полей), `infra/conf/transport_internet.go` (`StreamConfig.Build()`, блок
`quicParams`), `infra/conf/transport_method.go` (`Bandwidth.Bps()`), рантайм
`transport/internet/{hysteria,splithttp}/{hub,dialer}.go`.

| Поле | JSON-тип в ядре | `Build()` | Сторона |
| ---- | --------------- | --------- | ------- |
| `congestion` | string | lower-case; `""`/`reno`/`bbr`/`brutal`/`force-brutal`, иначе ошибка; `force-brutal` требует `brutalUp` > 0 | обе |
| `bbrProfile` | string | lower-case; `""` (→ `standard`)/`conservative`/`standard`/`aggressive` | обе |
| `brutalUp`, `brutalDown` | `Bandwidth` = **string** | `Bps()`; > 0 и < 65536 B/s — ошибка | обе (`brutalDown` сервер объявляет клиенту в заголовке `CCRX`) |
| `brutalDisableLossCompensation`, `debug` | bool | — (`debug` ставит `HYSTERIA_*_DEBUG` на весь процесс) | обе |
| 4 receive-окна | uint64 | > 0 и < 16384 — ошибка | обе |
| `maxIdleTimeout` | int64 | ≠ 0 и вне 4–120 — ошибка | обе |
| `keepAlivePeriod` | int64 | ≠ 0 и вне 2–60 — ошибка | **только dialer** |
| `maxIncomingStreams` | int64 | ≠ 0 и < 8 — ошибка | обе (Hysteria-dialer не читает, XHTTP/3-dialer читает) |
| `disablePathMTUDiscovery`, `disableGSO` | bool | — | обе |
| `disableChromeParrot` | bool | — | **только dialer** |
| `disableStatelessReset` | bool | — | **только hub** |

`Bandwidth.Bps()`: trim + lower-case; число — префикс из цифр и `.` (`ParseFloat`), единица —
остаток после trim: `""`/`b`/`bps`, `k`/`kb`/`kbps`, `m`/…, `g`/…, `t`/… — степени 1024, **биты**
в секунду; результат `uint64(val*mul) / 8` байт в секунду. Отсюда: `"100 mbps"` = 13 107 200 B/s,
минимум 65536 B/s = `"512 kbps"`; `1e6`, `-5`, `mbps`, `10 mib` — ошибки. Число вместо строки
(`"brutalUp": 50000000`) ядро не принимает вовсе — ошибка `json.Unmarshal` в `Bandwidth string`.

## 78.2	Модель

`stream/quic_params.rs`:

- `QuicParamsDraft` — все 17 полей: строки (`congestion`, `bbrProfile`, `brutalUp`/`brutalDown`),
  `Option<bool>` (6 флагов), `Option<u64>` (4 окна), `Option<i64>` (`maxIdleTimeout`,
  `keepAlivePeriod`, `maxIncomingStreams`) + `extras`. Явные `0`/`false` на диске остаются явными.
- **Без потерь:** известный ключ типизируется, только если его JSON-тип принимает ядро
  (`KNOWN_FIELDS` + `FieldKind::accepts`); `null`, число вместо строки, float/отрицательное окно,
  строка вместо числа — остаются в `extras` и пишутся обратно как есть. До 0.5.30 числовой
  `brutalUp` молча превращался в строку — это меняло форму и скрывало ошибку ядра.
- `QuicParamsDraft::mistyped_keys()` — такие ключи (не `null`, не перекрытые типизированным
  значением); `remove_mistyped()` — убрать их.
- `quic_bandwidth_bytes_per_sec` — порт `Bps()`; `validate_quic_params` — проверки `Build()` в
  том же порядке (сначала mistyped, затем `bbrProfile`, rates, `congestion`, окна, таймауты,
  `maxIncomingStreams`) по значениям, которые будут записаны (строки — после trim).
- Константы `QUIC_CONGESTION_MODES`, `QUIC_BBR_PROFILES`, `QUIC_MIN_BRUTAL_BYTES_PER_SEC`,
  `QUIC_MIN_RECEIVE_WINDOW`, `QUIC_MAX_IDLE_TIMEOUT_RANGE`, `QUIC_KEEP_ALIVE_PERIOD_RANGE`,
  `QUIC_MIN_INCOMING_STREAMS`; применимость по стороне — `INBOUND_ONLY_QUIC_PARAMS_FIELDS`,
  `OUTBOUND_ONLY_QUIC_PARAMS_FIELDS`, `quic_params_field_applies` (как у `sockopt`, §63).
- `apply_inbound_stream`: при `write_quic_params` — `validate_quic_params` до записи, ошибка с
  префиксом `streamSettings.finalmask.`. `write_quic_params` ставится при чтении любого
  объекта `quicParams`, поэтому Save inbound'а с невалидным для ядра `quicParams` на диске
  блокируется — так же, как его отверг бы `xray run -test`.

## 78.3	GUI

`gui/pages/stream_finalmask.rs` — `show_quic_params_edit(ui, direction, draft)`:

- `congestion`, `bbrProfile` — `optional_string_combo` (пресеты + свободный текст, значение с
  диска вроде `BBR` показывается как есть).
- `brutalUp`/`brutalDown` — текст + пересчёт «= N B/s (≈ X MiB/s)» (оранжевым ниже минимума)
  или ошибка разбора.
- Флаги — `optional_flag_combo` («(default: false)» / `false` / `true`).
- Числа — `optional_number_field`: текстовый буфер, переживающий кадры egui (§62.4), ключ — от
  корневого id редактора; непарсящийся текст не трогает модель и подсвечивается.
- Поле, не действующее на этой стороне (`keepAlivePeriod`/`disableChromeParrot` на inbound),
  получает строку только пока задано, с пометкой «client-only — ignored on an inbound».
- Под сеткой: mistyped-ключи + кнопка «Remove invalid values», иначе «Save will be rejected: …».
- Help на каждое поле и на секцию.

## 78.4	Код

| Область | Путь |
| ------- | ---- |
| Модель, валидация | `xray/config/stream/quic_params.rs` |
| Реэкспорт | `xray/config/stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs`, `xray/config/inbound_stream/mod.rs` |
| Валидация при Save | `xray/config/inbound_stream/mod.rs` (`apply_inbound_stream`) |
| Форма, help | `gui/pages/stream_finalmask.rs`; вызов — `gui/pages/inbounds.rs` (Stream tab, Hysteria) |

## 78.5	Тесты

- `stream::quic_params` (7, было 2): round-trip всех 17 полей; mistyped/`null` остаются в
  `extras` без изменений; типизированное значение перекрывает extra, `remove_mistyped`; trim и
  пропуск пустых строк; `Bps()` (единицы, регистр, `.5m`, `5.`, ошибки); валидация — 8 валидных и
  16 невалидных случаев; применимость по стороне.
- `inbound_stream` (+1): полный `quicParams` переживает Save; `force-brutal` без `brutalUp` и
  числовой `brutalUp` отклоняются.
- GUI (+2): показ формы (невалидные, mistyped, чужая сторона; обе стороны) не меняет draft;
  недопечатанное число (`-`) переживает кадр, модель не меняется.
- Итог: 1251 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (`XRAY_BIN`) — локального `xray` нет; fixtures для
  `quicParams` не заведены (корпус §72 — только слои `tcp[]`/`udp[]`); GUI вручную не запускался.

# 79	FinalMask — этап 3.2: legacy `quicParams.udpHop` (Roadmap §2.6)

## 79.1	Сверка с ядром

`XTLS/Xray-core` #6327 (18a1b50, v26.9.9) и `@main`: до него — `QuicParamsConfig.UdpHop
{ports PortList, interval Int32Range}` (`infra/conf`), `Build()` проверял `interval` ≥ 5 (кроме 0);
читал его **только** `hysteria/dialer.go`: при пустом `ports` hopping выключен; иначе dial на
случайный порт из `ports`, затем каждые `interval` с (по умолчанию 30, `hysteria/udphop`) —
**новый локальный сокет** к случайному порту списка. Listener (`hub.go`) `udpHop` не читал никогда.
После #6327 — маска `udphop` (`finalmask/udphop`): `intervalLocal` — новый сокет на каждом hop,
`intervalRemote` — новый адрес/порт из `remoteIPs`/`remotePorts` на каждом hop и при первом
dial; `interval` 0/пусто → 30, From < 5 — ошибка. Маска с `HandleDial()` (`udphop`, `xicmp`)
допустима только в `udp[0]` (`FinalMask.DialUDP`: «incorrect index»); Hysteria-dialer идёт через
`FinalMask.DialUDP`.

Отсюда эквивалент: `{"type": "udphop", "settings": {"mode": "intervalLocal,intervalRemote",
"remotePorts": ports, "interval": interval}}` в `udp[0]`, `remoteIPs` пусто (адрес сервера из
dial, как раньше). **Отступление от формулировки Roadmap:** на inbound «миграция в `udphop`»
создала бы client-only слой, с которым UDP-listener не стартует (`UdpHopClientOnly`, §68), а
сам `udpHop` там мёртв на любом ядре — поэтому на inbound миграция = удаление ключа.

## 79.2	Модель

`stream/quic_params.rs`:

- `QUIC_PARAMS_LEGACY_UDP_HOP_KEY`, `LEGACY_UDP_HOP_MODE`, `DIAL_HANDLING_UDP_FINALMASK_TYPES`
  (`udphop`, `xicmp`); `QuicParamsDraft::{has_legacy_udp_hop, remove_legacy_udp_hop}` (`udpHop`
  не входит в `KNOWN_FIELDS` — лежит в `extras`, Save не блокирует).
- `udphop_layer_from_legacy_udp_hop(&Value)` → `Ok(None)` для `null`/без `ports` (старый dialer
  не прыгал), иначе слой + `dropped_keys` (ключи кроме `ports`/`interval`, ядро их не читало);
  `ports`/`interval` переносятся в своей JSON-форме (`PortListValue`/`RangeValue`); не-объект,
  `ports` массивом, `interval` float — ошибка.
- `migrate_legacy_udp_hop(quic, udp_layers, direction) -> Result<LegacyUdpHopMigration, String>`
  (явное действие пользователя; при ошибке ничего не меняется): Inbound — удаление
  (`RemovedServerSide`, форма значения не важна); Outbound — без `ports` удаление
  (`RemovedInactive`), иначе слой в `udp[0]` (`Migrated { dropped_keys }`); если в цепочке уже
  есть `udphop`/`xicmp` — ошибка «only one dial-handling mask».

## 79.3	Предупреждения

`compatibility/warnings.rs`: новое `QuicParamsUdpHopClientOnly` — inbound, **любая** версия ядра
(раньше inbound получал версионное `QuicParamsUdpHopIgnored` и на ядре < v26.9.9 молчал).
`QuicParamsUdpHopIgnored` остаётся для outbound (ядро ≥ v26.9.9 / неизвестно), текст указывает
на «Migrate udpHop».

| Конфиг | Ядро < v26.9.9 | ≥ v26.9.9 / неизвестно |
| ------ | -------------- | ---------------------- |
| `quicParams.udpHop`, inbound | `QuicParamsUdpHopClientOnly` | `QuicParamsUdpHopClientOnly` |
| `quicParams.udpHop`, outbound | — | `QuicParamsUdpHopIgnored` |

## 79.4	GUI

`gui/pages/stream_finalmask.rs` — `show_legacy_udp_hop` под сеткой `show_quic_params_edit`:
значение `udpHop` как есть (monospace); inbound — пояснение (client-side, никогда не действовал)
и кнопка «Remove udpHop» (`migrate_legacy_udp_hop(…, Inbound)`, ставит dirty; на диск — при
Save); outbound — только пояснение: кнопке нужна цепочка `finalmask.udp`, она появится с
Outbound FinalMask-редактором (этап 7.1), модель готова.

## 79.5	Код

| Область | Путь |
| ------- | ---- |
| Конвертация, миграция | `xray/config/stream/quic_params.rs` |
| Реэкспорт | `xray/config/stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Предупреждения | `xray/config/compatibility/warnings.rs` |
| GUI | `gui/pages/stream_finalmask.rs` |

## 79.6	Тесты

- `stream::quic_params` (+3): конвертация в форме JSON (строка/число, `interval` отсутствует,
  `dropped_keys`); без `ports`/`null` — `None`, плохие формы — ошибки; миграция по стороне
  (inbound — удаление, цепочка не тронута; outbound — `udp[0]` перед другими масками;
  `udphop`/`XICMP` где угодно в цепочке — отказ без изменений; outbound без `ports` —
  `RemovedInactive`; битая форма — отказ на outbound, удаление на inbound).
- `compatibility::warnings` (переписаны 4): inbound — `QuicParamsUdpHopClientOnly` на любом ядре,
  outbound — версионное `QuicParamsUdpHopIgnored`.
- GUI (1 расширен): показ формы с `udpHop` (валидным и битым) не меняет draft.
- Итог: 1254 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром — локального `xray` нет; кнопка «Remove udpHop» не
  нажималась в тестах (клик egui не симулируется), GUI вручную не запускался.
- Найдено попутно (не исправлено): валидация Feldjäger не проверяет правило «dial-handling маска
  только в `udp[0]`» для пользовательских цепочек (`udphop`/`xicmp` не первыми — отказ ядра при
  dial, `xray run -test` не видит) — кандидат в этап 4.3.

# 80	FinalMask — этап 3.3: `quicParams` для XHTTP/3 (Roadmap §2.6)

## 80.1	Сверка с ядром

`XTLS/Xray-core@main` (b26a91d): `transport/internet/splithttp/hub.go` (`ListenXH`, `QListener.Accept`),
`splithttp/dialer.go` (`decideHTTPVersion`, QUIC dial), `infra/conf/common.go` (`StringList`),
`infra/conf/transport_security.go` (`ALPN *StringList`).

- XHTTP идёт поверх QUIC, когда TLS-конфиг даёт ALPN **ровно** `["h3"]`: listener —
  `isH3 = len(NextProtos) == 1 && NextProtos[0] == "h3"` (только `tls`, Reality сюда не попадает),
  dialer — `decideHTTPVersion` → `"3"` по тому же правилу. `alpn` — `StringList`: массив строк
  или строка, разрезанная по `,` без trim (`"h3"` = `["h3"]`, `"h3,h2"` — не h3, `" h3"` — не h3).
  Иначе XHTTP работает по TCP (h1.1/h2) и `quicParams` не читает.
- `congestion` на XHTTP/3 (listener и dialer): `reno`; `""`/`bbr` → BBR (`bbrProfile`);
  `force-brutal` → Brutal на `brutalUp`; **всё прочее — `panic`**. `Build()` допускает `brutal`
  (он законен для Hysteria), поэтому `brutal` на XHTTP/3 проходит `xray run -test` и роняет
  каждое соединение. Значение `congestion` ядро приводит к нижнему регистру.
- `brutalDown` XHTTP/3 не читает (у Hysteria он едет в заголовке `CCRX` handshake'а).
  Остальные поля — как у Hysteria (окна, `maxIdleTimeout`, `maxIncomingStreams`,
  `disablePathMTUDiscovery`, `disableGSO`, `disableStatelessReset`; клиентские — dialer).

Пункт Roadmap говорил «congestion только `bbr`/`force-brutal`»; по коду ядра допустим и `reno` —
он оставлен.

## 80.2	Модель

`stream/quic_params.rs`:

- `QuicTransport { Hysteria, XhttpH3 }`: `label`, `congestion_modes` (`QUIC_CONGESTION_MODES` /
  `XHTTP3_CONGESTION_MODES` = reno, bbr, force-brutal), `default_congestion` (brutal / bbr),
  `reads_field` (XHTTP/3 не читает `brutalDown`).
- `alpn_selects_http3(&[String])` — правило «ровно `h3`» (для черновика security в GUI);
  `quic_transport_of(&streamSettings)` — то же по JSON: `network`/`method` (`xhttp`/`splithttp`/
  `hysteria`), `security: tls`, `tlsSettings.alpn` как `StringList`.
- `validate_quic_params_for_transport(draft, transport)` = `validate_quic_params` + `congestion`
  из списка транспорта; `validate_stream_quic_params(&streamSettings)` — то же по собранному JSON,
  ошибка с префиксом `streamSettings.finalmask.`.
- `modify.rs`: `check_inbound_quic_params` — после `compose_inbound_shell` в
  `update_inbound_shell` и после сборки в `add_inbound` (метод stream и ALPN живут в разных
  черновиках, поэтому проверка — по собранному inbound). Мутации клиентов её не вызывают.

## 80.3	Предупреждения

`compatibility/warnings.rs`: `QuicParamsUnusedTransport` — `finalmask.quicParams` (не `null`) на
транспорте без QUIC (`quic_transport_of` = `None`: tcp/ws/grpc/mKCP, XHTTP не-h3, XHTTP с
Reality), location `streamSettings.finalmask.quicParams`. Тестовые fixtures предупреждений о
`udpHop`/`udphop` получили `network: hysteria`, чтобы проверять только своё.

## 80.4	GUI

- `show_quic_params_edit(ui, direction, transport, draft)`: метка транспорта у заголовка,
  строка-пояснение (Hysteria — пустой `congestion` = brutal; XHTTP/3 — пустой = bbr, brutal не
  поддерживается, `brutalDown` не используется); пресеты `congestion` по транспорту (`brutal` с
  диска показывается как есть и даёт «Save will be rejected»); `brutalDown` на XHTTP/3 — строка
  только если задан, с пометкой «not used on XHTTP/3»; проверка — `validate_quic_params_for_transport`.
- `inbounds.rs`, Stream tab, XHTTP: при security `tls` и `alpn_selects_http3(tls.alpn)` —
  редактор `quicParams` (`QuicTransport::XhttpH3`; для чужого `finalmask` — уведомление §64),
  иначе серая подсказка, когда `quicParams` применяется. Hysteria — `QuicTransport::Hysteria`.

## 80.5	Код

| Область | Путь |
| ------- | ---- |
| Транспорт, проверки | `xray/config/stream/quic_params.rs` |
| Реэкспорт | `xray/config/stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Проверка при Save / Add | `xray/config/modify.rs` (`check_inbound_quic_params`) |
| Предупреждение | `xray/config/compatibility/warnings.rs` |
| GUI | `gui/pages/stream_finalmask.rs`, `gui/pages/inbounds.rs` |

## 80.6	Тесты

- `stream::quic_params` (+3): определение транспорта (method/`method`, регистр security,
  `alpn` массивом и строкой, `h3,h2`/`" h3"`/`H3`/пусто/Reality/none/tcp — не QUIC);
  XHTTP/3 — `brutal`/`Brutal` отклоняются, `""`/reno/BBR/force-brutal — нет, Hysteria принимает
  `brutal`, общие правила идут первыми; проверка `streamSettings` только для QUIC-транспорта.
- `compatibility::warnings` (+1, 4 fixtures с `network: hysteria`): `QuicParamsUnusedTransport`
  для `{}`/tcp/XHTTP-h2/XHTTP-Reality, нет для Hysteria/XHTTP-h3/`splithttp` со строкой `"h3"`/`null`.
- `modify_tests` (+1): Shell Save XHTTP/3 с `brutal` отклонён, inbound не изменён; `force-brutal`
  без `brutalUp` отклонён; `reno` сохраняется; тот же `brutal` на XHTTP с `["h2"]` сохраняется.
- GUI (1 расширен): показ формы для обоих транспортов не меняет draft (в т.ч. `brutal` +
  `brutalDown`).
- Итог: 1259 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (локального `xray` нет), GUI вручную не запускался.
- **Найдено попутно (исправлено в 0.5.32-1, §81):** черновик TLS (`inbound_security`,
  `string_array`) читает `alpn` только массивом, а ключ `alpn` — известный, в `extras` не попадает;
  строковая форма `StringList` (`"alpn": "h3"`) при Shell Save с черновиком security
  **теряется** — XHTTP молча переходит с HTTP/3 на TCP. Save/предупреждения этого этапа строковую
  форму распознают, GUI-редактор `quicParams` для неё не показывается.

# 81	TLS `alpn` / `curvePreferences` как `StringList`; цвет выбранных тегов (bugfix 0.5.32-1)

## 81.1	Проблема

- **Потеря данных.** В ядре `tlsSettings.alpn` и `tlsSettings.curvePreferences` — `*StringList`
  (`infra/conf/transport_security.go`): JSON-массив строк **или** строка, разрезанная по `,`
  (`infra/conf/common.go`). Черновик TLS (`inbound_security`, `string_array`) читал только массив;
  оба ключа — известные (`TLS_KNOWN_KEYS`), в `extras` не попадали, а `apply_security_tls` строит
  `tlsSettings` заново. Итог: `"alpn": "h3"` при Shell Save с security исчезал — XHTTP молча
  переходил с HTTP/3 на TCP (h2/h1.1), строковые `curvePreferences` сбрасывались к умолчанию ядра.
  Найдено при этапе 3.3 (§80).
- **GUI.** Выбранные значения мультивыбора (`string_tag_multi_select`: TLS `alpn`,
  `curvePreferences`, Reality `alpn`) рисовались фиксированным `Color32::from_rgb(220, 220, 230)`.
  Тема — `ThemeMode::System`; в светлой теме ОС почти белый текст на светлом фоне выглядел
  неактивным.

## 81.2	Исправление

- `string_list(Option<&Value>)` — чтение `StringList`: строка режется по `,`, элементы trim, пустые
  отбрасываются (как у массива в `string_array`); используется для TLS `alpn` и
  `curvePreferences`.
- `insert_string_list(object, key, values, previous)` — запись: если список черновика равен тому,
  что читается из значения на диске (`string_list(previous)`), значение с диска пишется
  **дословно** (строка остаётся строкой, исходное написание и даже неподдерживаемый тип —
  без изменений); иначе — массив, как раньше (`insert_string_array`; пустой список — ключ
  удаляется). `apply_security_tls` берёт `previous` из текущего `tlsSettings` до перезаписи.
- `string_tag_multi_select`: тег — `RichText::strong()` (цвет `strong_text_color` текущей темы).
  Серый `custom: …` в выпадающем списке — намеренная подсказка, не тронут.

## 81.3	Тесты и замечания

- `inbound_security` (+1): строковые и массивные формы `alpn`/`curvePreferences` (`"h3"`,
  `"X25519,CurveP256"`, `"h2, http/1.1"`, `[" h3 ", ""]`, `""`, число) читаются и при Save без
  правки остаются байт-в-байт; правка списка пишет массив; очистка удаляет ключ.
- Итог: 1260 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: GUI вручную в светлой/тёмной теме не запускался.
- Найдено попутно (исправлено в 0.5.32-2, §82): у `REALITYConfig` ядра (`infra/conf/transport_security.go`)
  **нет** поля `alpn`, а Feldjäger моделирует `realitySettings.alpn` и требует его непустым при
  fallbacks (`session_fallbacks_missing_alpn`, `active_alpn`) — ядро этот ключ не читает; нужна
  отдельная сверка логики fallbacks + Reality с документацией и ядром.

# 82	Fallbacks + REALITY: без требования ALPN, `realitySettings.alpn` не моделируется (bugfix 0.5.32-2)

## 82.1	Сверка

Источники: `XTLS/Xray-core@main` (b26a91d) — `infra/conf/transport_security.go` (`REALITYConfig`),
`transport/internet/reality/config.go` (`GetREALITYConfig`), `proxy/vless/inbound/inbound.go`
(выбор fallback), `infra/conf/{vless,trojan}.go`; библиотека `XTLS/REALITY` на закреплённом в
`go.mod` коммите 8cdf7bf (`handshake_server_tls13.go`, `negotiateALPN`); документация
[Fallback](https://xtls.github.io/en/config/features/fallback.html) и
[REALITY](https://xtls.github.io/en/config/transports/reality.html).

| Утверждение | Основание |
| ----------- | --------- |
| У REALITY нет настройки `alpn` | В `REALITYConfig` нет поля `alpn`; в документации REALITY — тоже (поля: `show`, `target`, `xver`, `serverNames`, `privateKey`, `minClientVer`, `maxClientVer`, `maxTimeDiff`, `shortIds`, `mldsa65Seed`, `limitFallback*`); Go `json.Unmarshal` молча игнорирует ключ |
| REALITY-соединение не согласует ALPN | `GetREALITYConfig`: `NextProtos: nil, // should be nil`; `negotiateALPN(nil, …)` → `""` |
| На REALITY срабатывают только fallbacks с пустым `alpn` | `inbound.go`: `alpn = realityConn.ConnectionState().NegotiatedProtocol` (всегда `""`), затем `apfb[""]`; запись с `alpn: "h2"` не выбирается никогда |
| Ядро не требует ALPN для fallbacks | `VLESS/Trojan Build()` проверяют только `path`/`dest`/`decryption` |
| Требование `tlsSettings.alpn` — из документации, **только для TLS** | Fallback docs: «When this item has child elements, [Inbound TLS] must set `"alpn":["http/1.1"]`»; для h2 — `["h2","http/1.1"]` |

До 0.5.32-2 Feldjäger моделировал `realitySettings.alpn` (tag-виджет в форме REALITY), писал его в
конфиг и блокировал Save REALITY-inbound'а с fallbacks, пока этот список пуст (`active_alpn`,
`require_alpn_for_fallbacks`, `session_fallbacks_missing_alpn`) — заставлял записать ключ, который
ядро не читает.

## 82.2	Исправление

- `inbound_security`: поле `RealitySettingsDraft::alpn` удалено, `alpn` убран из известных ключей
  REALITY — значение с диска уходит в `extras` и сохраняется дословно (любая форма).
  `REALITY_IGNORED_ALPN_KEY`, `RealitySettingsDraft::{has_ignored_alpn, remove_ignored_alpn}`;
  `InboundSecurityDraft::active_alpn` заменён на `fallbacks_missing_alpn()` (только TLS с пустым
  `tls.alpn`); `string_list` стал `pub(crate)`.
- `inbound_fallbacks::require_alpn_for_fallbacks`: REALITY — `Ok`; TLS — непустой
  `tlsSettings.alpn`, прочитанный как `StringList` (строковый `"http/1.1"` раньше считался
  отсутствующим — тот же класс ошибки, что в §81); текст ошибки называет значения из документации.
- Предупреждения (`compatibility/warnings.rs`, только при `security: reality`):
  `RealityAlpnIgnored` на `streamSettings.realitySettings.alpn`;
  `RealityFallbackAlpnNeverMatches` на `settings.fallbacks[i].alpn` с непустым значением.
- GUI (`inbounds.rs`): в форме REALITY нет ALPN-виджета; если ключ на диске — оранжевая строка
  «not a REALITY setting — ignored by Xray-core» + кнопка «Remove alpn» (help
  `HELP_REALITY_IGNORED_ALPN`); в просмотре — та же пометка. Save блокируется и баннер на вкладке
  Security показывается только для TLS без ALPN (раньше баннер висел при любом TLS/REALITY с
  fallbacks, даже с заданным ALPN). В редакторе fallbacks на REALITY у непустого `alpn` —
  «never matches with REALITY (no ALPN negotiated)»; баннер секции и help `alpn` (TLS и fallback)
  уточнены.

Заменяет: §(Wave C2) «Reality: typed `realitySettings.alpn` … нужен для fallbacks gate» и
«`require_alpn_for_fallbacks`: non-empty `tlsSettings.alpn` или `realitySettings.alpn`».

## 82.3	Тесты

- `inbound_security` (1 переписан, +1): REALITY не пишет `alpn`; `alpn` с диска (массив и строка)
  сохраняется дословно, удаляется по запросу; `fallbacks_missing_alpn` — только TLS.
- `inbound_fallbacks` (1 переписан, +1): REALITY с fallbacks без `alpn` проходит, inbound не
  меняется; TLS со строковым `"http/1.1"` проходит, `" , "` — ошибка.
- `compatibility::warnings` (+1): оба предупреждения на REALITY (fallback с `" "` не флагается),
  ничего на TLS.
- Итог: 1263 passed / 9 pre-existing fixture failures; clippy lib 66 (без изменений).
- Не проверено: паритет с реальным ядром (локального `xray` нет), GUI вручную не запускался.

# 83	FinalMask — этап 4.1: `finalmask.udp` для Hysteria, hy2 `obfs` из типизированной модели (Roadmap §2.6)

## 83.1	Сверка с ядром

`XTLS/Xray-core@main`: `transport/internet/hysteria/hub.go` (`Listen`), `finalmask/salamander/
{config,conn}.go`, `finalmask/noise/{config,conn}.go`.

- Hysteria-листенер берёт `streamSettings.FinalMask.ListenPacket(…)`, если FinalMask задан, иначе
  `ListenSystemPacket` — т.е. к нему применяется **только** `finalmask.udp`; `finalmask.tcp`
  ядро для Hysteria не использует никогда.
- `salamander` без `packetSize` — `salamanderConn` (XOR с BLAKE2b-ключом + соль), совместим с
  `obfs=salamander` клиентов Hysteria2. С `packetSize` (верхняя граница > 0) — `GeckoConfig` →
  `geckoConn`: QUIC long-header пакеты режутся на фреймы со своим заголовком и паддингом;
  обычный salamander-клиент такие пакеты не соберёт.
- `noise`: `ReadFrom` — сквозной, действует только `WriteTo` → клиенту ответный слой не нужен.

## 83.2	Модель

`stream/finalmask.rs`: `hysteria_salamander_obfs_password(&inbound Value)` (read-only детект по
raw JSON, «редактора для Hysteria нет», §3:121) заменена на
`hy2_share_obfs(&[FinalMaskLayerDraft]) -> Result<Option<String>, String>` по типизированным
слоям редактора:

- слои `noise` пропускаются; оставшихся нет → `Ok(None)` (ссылка без `obfs`);
- ровно один `salamander` с непустым `password` и без Gecko → `Ok(Some(password))`;
- Gecko, другой тип слоя, больше одного «зеркального» слоя, нечитаемые/пустые настройки →
  `Err(причина)`: hy2-ссылка описывает всю клиентскую сторону цепочки, и вместо ссылки,
  клиент которой не подключится, Share выключается, а причина показывается предупреждением
  (решение пользователя 2026-10-04, 0.5.33-1; §83.3–83.4).

Запись `finalmask.udp` для Hysteria уже поддерживалась `apply_inbound_stream` (метод-независимо);
doc-комментарии `InboundStreamDraft.finalmask_tcp/udp` обновлены.

## 83.3	Share

`ApplicationService::build_client_share_uri`: для Hysteria `obfs` = `hy2_share_obfs(
stream_draft.finalmask_udp)`, где `stream_draft` — черновик открытой сессии редактора (если
редактируется этот inbound) или разбор с диска, т.е. ссылка отражает типизированный редактор.
`finalmask.udp` на диске (не `null`), который типизированная модель не прочла
(`write_finalmask_udp == false`, напр. слой без `type`), даёт `Err` — не «ссылку без obfs».
Для VLESS/Trojan `obfs` не вычисляется.

Общий приватный хелпер `hysteria_share_obfs(on_disk: Option<&Value>, stream)` (проверка
нечитаемой цепочки + `hy2_share_obfs`) используется тремя путями, поэтому причина везде одна:

- `build_client_share_uri` — `Err(причина)`;
- `hy2_share_blocked_reason(inbound_index) -> Option<String>` — для страницы Users: только
  `protocol: hysteria`, черновик открытой сессии этого inbound важнее диска (как в Share);
- `editor_hy2_share_blocked_reason() -> Option<String>` — для Stream-таба: черновик текущей
  сессии (метод Hysteria), в т.ч. Add-сессии (`on_disk = None`).

## 83.4	GUI

- `show_finalmask_edit(…, udp_only: bool)`: при `udp_only` цепочка `tcp` скрыта, пока пуста;
  непустая с диска показывается с жёлтой пометкой «Xray-core never applies finalmask.tcp layers
  to it… remove them if they are leftovers» (GUI не прячет конфигурацию, `rules.md`).
- `inbounds.rs`, Stream tab: условие показа FinalMask `method != Hysteria && vless|trojan` →
  `vless|trojan|hysteria`; `udp_only = method == Hysteria`. Для чужого `finalmask` уведомление
  уже показано Hysteria-веткой (вместо `quicParams`) — секция не дублируется. Клиентские маски
  (`udphop`) по-прежнему не предлагаются для inbound (`finalmask_layer_type_applies`).
- `HELP_FINALMASK_SECTION`: у Hysteria применяется только `udp[]`; когда salamander попадает в
  hy2-ссылку как `obfs`.
- Импорт hy2 (`obfs=salamander` → слой `salamander` в `finalmask_udp`) не менялся.

Причина недоступного Share видна, а не только во всплывающей подсказке (0.5.33-1):

- Stream tab (Hysteria), под цепочками FinalMask: «Share links (hy2://) are disabled: …» по
  `editor_hy2_share_blocked_reason()`. Запрос идёт после правок кадра: заимствование сессии
  заканчивается перед ним и берётся заново для Sockopt.
- Users, раздел Hysteria, над таблицей: «Share links are disabled for this inbound: …» по
  `hy2_share_blocked_reason(selected_inbound_index)` — цепочка решает за весь inbound.
- Контекстное меню клиента (VLESS/Trojan/Hysteria): три одинаковых блока Share заменены
  `show_share_menu_items` — при `Err` кнопки неактивны (подсказка осталась) и под ними строка
  «Share unavailable: …» (ширина ограничена 320 px); `SHARE_WARNING_COLOR` — тот же янтарный.

## 83.5	Код

| Область | Путь |
| ------- | ---- |
| `hy2_share_obfs` | `xray/config/stream/finalmask.rs` |
| Реэкспорт | `xray/config/stream/mod.rs`, `xray/config/inbound_stream/mod.rs`, `xray/config/mod.rs`, `xray/mod.rs` |
| Share, причины | `app/service.rs` (`build_client_share_uri`, `hysteria_share_obfs`, `hy2_share_blocked_reason`, `editor_hy2_share_blocked_reason`) |
| GUI | `gui/pages/stream_finalmask.rs`, `gui/pages/inbounds.rs`, `gui/pages/users.rs` |

## 83.6	Тесты

- `stream::finalmask` (4 удалены вместе со старой функцией, +3): plain salamander (регистр типа);
  пусто / только `noise` / `noise` + salamander; Gecko отклонён, `packetSize: 0` — plain,
  `sudoku`, два слоя, без пароля — отклонены.
- `app::service` (+1): hy2 Share из конфига — `noise`+salamander → `obfs=salamander&obfs-password=`,
  `[]` → без `obfs`, Gecko → `Err`, слой без `type` → `Err` «can't be read»; та же причина из
  `hy2_share_blocked_reason` / `editor_hy2_share_blocked_reason`, черновик сессии важнее диска,
  нет сессии / нет inbound → `None`.
- Итог: 1263 passed / 9 pre-existing fixture failures (`tests/fixtures` отсутствует); clippy lib
  66 (без изменений).
- Проверено на ядре (0.5.33-2, §84): правила `hy2_share_obfs` подтверждены живым Hysteria-
  соединением Xray 26.9.30. GUI вручную не запускался.
- **Попутно (bugfix):** в 5 пользовательских строках (`compatibility/warnings.rs`
  `QuicParamsUdpHopClientOnly`/`QuicParamsUnusedTransport`, `stream_sockopt.rs`
  `sockopt_scope_note` ×2, `inbound_stream/mod.rs` ошибка чужого `finalmask`) продолжение строки
  `\`+перевод строки было потеряно — в тексте стояли длинные серии пробелов; восстановлено.

# 84	Тесты против локального Xray: интероп Hysteria `finalmask.udp` (0.5.33-2)

## 84.1	Локальный бинарник

`xray/local_xray.rs` (`#[cfg(test)]`; до 0.5.33-3 — `config/stream/local_xray.rs`, §85): `local_xray_bin()` — `XRAY_BIN`, иначе
`xray-bin/xray(.exe)` в корне крейта, если файл есть; иначе `None`, и тесты против ядра —
no-op (чистый клон и CI зелёные). `xray-bin/` добавлен в `.gitignore` — каждый кладёт свою сборку.
Паритет-тест `finalmask_fixtures::parity_with_xray_run_test` (§2.6 этап 1.5) переведён на этот
хелпер: раньше он требовал `XRAY_BIN`, теперь подхватывает и `xray-bin`. С Xray 26.9.30
(b26a91d) — все кейсы совпадают, ни одного пропуска по версии.

## 84.2	Интероп `hy2_share_obfs` (`stream/finalmask_interop.rs`)

`hy2_share_obfs_matches_the_core`: правила §83.2 — утверждения о ядре, поэтому проверяются живым
соединением, а не `xray run -test` (тот принимает любую из этих цепочек). На каждый прогон:
Hysteria-сервер с цепочкой `finalmask.udp` → Freedom → TCP echo-сервер теста; Hysteria-клиент
с цепочкой, которую подразумевает hy2-ссылка (один plain `salamander` из `obfs`, как строит
импорт hy2, или ничего) + `tunnel`-inbound перед ним. Тест шлёт байты в `tunnel` и ждёт эха.

| Цепочка сервера | `hy2_share_obfs` | Клиент | Ожидание |
| --------------- | ---------------- | ------ | -------- |
| — | `Ok(None)` | — | эхо |
| salamander | `Ok(Some)` | salamander | эхо |
| noise → salamander, salamander → noise | `Ok(Some)` | salamander | эхо (`noise` клиенту не нужен) |
| salamander + `packetSize` (Gecko) | `Err` | ссылка до 4.1: plain salamander | нет эха |
| sudoku → salamander | `Err` | ссылка до 4.1: plain salamander | нет эха |
| контроль: Gecko | — | тот же Gecko | эхо (сам Gecko рабочий) |
| контроль: salamander | — | — | нет эха (маска действует) |

- Ожидание для `Ok`/`Err` берётся из самой `hy2_share_obfs`, т.е. тест проверяет функцию, а не
  копию её правил. Для `Err` клиент строится так, как ссылку собирал read-only детектор до 4.1
  (первый salamander, любой режим) — отказ должен быть оправдан.
- Контроли не дают сломанному окружению выглядеть как «правильно отказано».
- «Нет эха» не путается с отвергнутым конфигом: если процесс `xray` завершился, тест падает с
  его выводом (`assert_running`).
- TLS — только из бинарника (`rules.md`: криптоматериал генерирует официальный Xray):
  `xray tls cert -domain=hy.test` (certificate/key inline), пин клиента `pinnedPeerCertSha256` —
  `xray tls hash`; попутно `cert_pin_sha256` (hy2 `pinSHA256`) сверяется с `xray tls hash`.
- Найдено при прототипировании: Freedom в 26.9.30 по умолчанию блокирует приватные цели
  («blocked target … blackholing»), поэтому у серверного Freedom `finalRules` allow `127.0.0.1`.
  `allowInsecure` ядро отвергает как removed feature (→ `pinnedPeerCertSha256`).
- Прогоны параллельны (`thread::scope`, свои порты): ~4,7 с вместо ~30 с (отказ = таймаут эха 4 с).
- Мутационная проверка: если `hy2_share_obfs` перестаёт отказывать Gecko, тест падает —
  «Gecko salamander: link: expected an echo, got none» с обеими цепочками.

## 84.3	Код и итог

| Область | Путь |
| ------- | ---- |
| Поиск бинарника | `xray/local_xray.rs` (с 0.5.33-3) |
| Интероп Hysteria | `xray/config/stream/finalmask_interop.rs` |
| Паритет `-test` | `xray/config/stream/finalmask_fixtures.rs` |
| Объявления модулей | `xray/config/stream/mod.rs` |
| Игнор бинарника | `.gitignore` |

- Итог: 1264 passed / 9 pre-existing fixture failures (`tests/fixtures` отсутствует); clippy lib
  66 (без изменений). С `xray-bin` полный `cargo test` дольше на ~5 с.

# 85	Фикстуры тестов в отслеживаемых каталогах: 9 падающих тестов исправлены (0.5.33-3)

## 85.1	Причина

9 тестов (`config::tests` ×5, `remote_cli::{x25519,mldsa65,vlessenc}` ×4) читали файлы из
`tests/fixtures/xray/` во время выполнения. Каталог `tests` целиком исключён в `.gitignore`:
конфиги-фикстуры удалены из git коммитом `f072b6a` (вместе с этой строкой `.gitignore`), а
CLI-фикстуры (`tests/fixtures/xray/cli/*.stdout.txt`) в git не попадали никогда. На любом клоне
тесты падали с «failed to read fixture» / `unwrap` на `None`.

## 85.2	Решение

То же, что для корпуса FinalMask (Roadmap §2.6 этап 1.5): фикстуры рядом с кодом и
`include_str!` — отсутствующий файл = ошибка компиляции, а не падающий тест; `.gitignore` не
менялся.

- `src/xray/config/fixtures/{minimal,with_unknown_sections,invalid,full_sample}.json` —
  восстановлены побайтно из `f072b6a^` (фиктивные данные: нулевые UUID, example.com). В
  `config/tests.rs`: макрос `read_fixture!` (= `include_str!`) для текстов; `fixture()` (путь
  для `parse_path`) указывает на новый каталог. Ожидания тестов совпали со старыми файлами без
  правок.
- `src/xray/remote_cli/fixtures/*.stdout.txt` — сгенерированы официальным бинарником
  (Xray 26.9.30, `rules.md`: криптоматериал — только от Xray): `xray x25519 -i <ключ из теста>`
  и `xray mldsa65 -i <seed из теста>` детерминированы и дают ровно проверяемые значения;
  `xray vlessenc` случаен — тест проверяет только структуру (вынесена в `assert_vlessenc_shape`).
  Это тестовые ключи, на серверах не используются (отмечено в doc-комментариях).

## 85.3	Проверка формата CLI на живом ядре

`local_xray` перенесён из `config/stream/` в `xray/local_xray.rs` (`pub(crate)`, `#[cfg(test)]`),
чтобы им пользовались и CLI-парсеры; добавлен `local_xray_stdout(args)` (`None` без бинарника,
panic при ошибке команды). Новые тесты `parses_local_xray_output` в `x25519`/`mldsa65`/
`vlessenc`: вывод локального `xray` с теми же входами разбирается и равен разбору фикстуры
(vlessenc — та же проверка структуры). Ловят смену формата вывода ядра (например,
`Password (PublicKey)` вместо `PublicKey`) и устаревшую фикстуру.

## 85.4	Код и итог

| Область | Путь |
| ------- | ---- |
| Конфиги-фикстуры | `xray/config/fixtures/*.json`, `xray/config/tests.rs` |
| CLI-фикстуры | `xray/remote_cli/fixtures/*.stdout.txt`, `xray/remote_cli/{x25519,mldsa65,vlessenc}.rs`, `xray/remote_cli/mod.rs` (doc) |
| Локальный Xray | `xray/local_xray.rs`, `xray/mod.rs`; ссылки в `config/stream/finalmask_{fixtures,interop}.rs` |

- Итог: **1276 passed / 0 failed** (+3 живых теста CLI); без `xray-bin` тоже 1276 passed — тесты
  против ядра пропускаются. clippy lib 66 (без изменений).

# 86	Status Bar: уведомления до нажатия `×` (0.5.34-0)

## 86.1	Проблема и решение

Раньше `show_status_message` ставил `CurrentOperation::Message` на 3 с (`STATUS_MESSAGE_DURATION`),
после чего `tick_status` возвращал `Ready`, и текст пропадал раньше, чем пользователь успевал его
прочитать. Сделать сам `Message` бессрочным было нельзя: `FeldjaegerApp::logic` перерисовывает окно
каждые 100 мс, пока `operation != Ready`, а несколько save-потоков показывают прогресс
(«Saving DNS settings...») как раз через `Message`. Поэтому жизненный цикл `CurrentOperation`
не менялся, а текст сообщения дублируется в отдельное поле.

- `ApplicationService::status_notification: Option<String>` задаётся в `show_status_message`
  вместе с `Message`; в GUI попадает через `StatusSnapshot::notification`.
- `dismiss_status_message()` очищает уведомление, а если текущая операция — `Message`, ещё и
  возвращает `Ready`. Busy-операции не затрагиваются.
- Уведомление сбрасывается при `set_current_operation` / `clear_current_operation` (паттерн
  «show "Loading…" → сразу clear» в `begin_edit_*` не оставляет зависшего «Loading…») и в
  `tick_status`, когда `operation.is_busy()`: новая фоновая операция вытесняет старый результат,
  и он не всплывает снова после её завершения.

## 86.2	Отрисовка

`status_bar::show` теперь возвращает `bool` («нажат `×`»); `FeldjaegerApp::ui` передаёт его в
`dismiss_status_message()` (GUI → только `ApplicationService`). Порядок в зоне Current Operation:
`Ready` + уведомление → текст уведомления (зелёный) + `×`; `Message` → текст + `×`; busy →
метка + progress/spinner (как раньше); `Ready` без уведомления → «Ready». Кнопка —
`small_button("×")`, тот же глиф, что уже используется на странице Inbounds.

## 86.3	Код и итог

| Область | Путь |
| ------- | ---- |
| Модель | `app/status.rs` (`StatusSnapshot::notification`) |
| Сервис | `app/service.rs` (`status_notification`, `show_status_message`, `dismiss_status_message`, `tick_status`) |
| GUI | `gui/status_bar.rs`, `gui/app.rs` |

- Новый тест `status_notification_sticks_until_dismissed`. Итог: **1277 passed / 0 failed**,
  clippy без новых предупреждений.

# 87	Багфикс: busy-статус и ошибка worker-а при сохранении настроек (0.5.34-1)

## 87.1	Симптомы

Во всех 13 `start_save_*_settings` (DNS, FakeDNS, Routing, Policy, Observatory,
BurstObservatory, Stats, Metrics, Env, Version, GeoData, API, Log) было:

```rust
self.operation = CurrentOperation::SavingDnsSettings;
self.show_status_message("Saving DNS settings...");
```

Второй вызов сразу заменял busy-операцию на `CurrentOperation::Message` с тем же текстом
(метки `Saving*Settings` в `CurrentOperation::label` совпадают побайтно). Последствия:

- не было спиннера (`OperationProgress::Indeterminate` у `Saving*` не применялся);
- через 3 с `Message` → `Ready`, и `FeldjaegerApp::logic` переставал перерисовывать окно с
  частотой 10 Гц — результат долгого сохранения появлялся только после движения мыши;
- в `poll_*_settings_mutation` ветка `TryRecvError::Disconnected` проверяла
  `matches!(self.operation, Saving*Settings)`, а это условие никогда не выполнялось:
  падение worker-а молча сбрасывало `rx` без ошибки в форме и Status Bar.

## 87.2	Исправление

- Удалён лишний `show_status_message("Saving … settings...")`, операция остаётся busy.
- В ветке `Disconnected` проверка операции снята: раз ветка достигнута, `*_settings_rx` был
  `Some`, то есть сохранение шло. Проверка была бы хрупкой и после первой правки — любое
  `show_status_message` из GUI во время сохранения снова заменило бы операцию.

## 87.3	Код и итог

| Область | Путь |
| ------- | ---- |
| Сервис | `app/service.rs` (13 × `start_save_*` / `poll_*_settings_mutation`) |

- Новый тест `settings_save_worker_crash_is_reported_even_after_other_message`. Итог:
  **1278 passed / 0 failed**, clippy lib 66 (без изменений).

# 88	FinalMask — этап 4.2: показ по наличию `streamSettings`, FinalMask для Tunnel (0.5.35-0)

## 88.1	Сверка с ядром

`XTLS/Xray-core@main`: `app/proxyman/inbound/always.go` создаёт по `Network()` прокси
`tcpWorker` и/или `udpWorker`, оба получают `streamSettings` (`mss`):

- `tcpWorker.Start` → `internet.ListenTCP` → для raw-транспорта `tcp/hub.go`:
  `FinalMask.Listen(ctx, addr)` — цепочка `tcp[]`;
- `udpWorker.Start` → `udp.ListenUDP` (`transport/internet/udp/hub.go`):
  `FinalMask.ListenPacket(ctx, addr)` — цепочка `udp[]`.

Tunnel (`proxy/dokodemo`, `Network()` = `settings.allowedNetwork`) проходит оба пути, поэтому для
него применимы **обе** цепочки: `tcp[]` — при `allowedNetwork` с `tcp`, `udp[]` — с `udp`.
TUN воркеров не создаёт (`streamSettings` нет) — FinalMask не показывается.
Предупреждение «слой не будет задействован» по транспорту/сети — этап 4.3.

## 88.2	Модель

`xray/config/inbound_stream/mod.rs`:

- Запись FinalMask вынесена из `apply_inbound_stream` в приватные хелперы
  `reject_foreign_finalmask_write(stream, writes)` (не-объектный `finalmask` не трогается, §0.5),
  `validate_finalmask_draft(draft, with_quic_params)` и
  `write_finalmask_draft(stream, draft, with_quic_params)`; поведение `apply_inbound_stream` не
  изменилось (`with_quic_params = true`).
- `apply_tunnel_sockopt` → `apply_tunnel_stream`: Tunnel Shell Save пишет `sockopt` (как раньше)
  и `finalmask.tcp`/`.udp`. Всё валидируется **до** первой мутации — отклонённый черновик
  оставляет inbound как был (в т.ч. не создаёт `streamSettings`). `quicParams` у Tunnel не
  валидируется и не переписывается (QUIC-транспорта нет, редактор его не показывает) — чужой
  невалидный `quicParams` не ломает Save. Прочие ключи `streamSettings` и `finalmask` — как на
  диске. Нетронутый `sockopt` (`write_sockopt == false`) больше не пересоздаётся.
- Add Tunnel уже шёл через `apply_inbound_stream` (метод `Tcp`) — FinalMask из Add-формы
  записывается без изменений в коде.

## 88.3	GUI

`gui/pages/inbounds.rs`:

- Вкладка Stream: `stream_enabled = shell_ok && has_stream_settings`
  (`InboundClientProtocol::has_stream_settings`) — Tunnel получил вкладку; Security для Tunnel
  по-прежнему выключена.
- `show_stream_edit` разделён: `show_stream_transport_edit(ui, session, protocol) -> bool`
  (метод и поля транспорта; `false` для экзотического метода — остальное не показывается, как
  раньше) и общая часть — FinalMask, hy2-предупреждение, Sockopt. Для Tunnel транспортная часть
  заменена серой строкой «raw TCP / no security (locked)… sockopt.tproxy is on the Protocol tab».
- Условие показа FinalMask: `matches!(protocol, "vless"|"trojan"|"hysteria")` →
  `InboundClientProtocol::from_wire(protocol).is_some_and(has_stream_settings)`;
  `udp_only` — только Hysteria (не Tunnel). Sockopt-секция осталась для VLESS/Trojan/Hysteria:
  у Tunnel узкий редактор `tproxy` на вкладке Protocol (§2.3:88).
- Add-форма: секция Stream показывается для всего, кроме TUN.
- `HELP_FINALMASK_SECTION` (`stream_finalmask.rs`): Tunnel — `tcp[]` для TCP-листенера,
  `udp[]` для UDP (`settings.allowedNetwork`).

## 88.4	Код и итог

| Область | Путь |
| ------- | ---- |
| Модель | `xray/config/inbound_stream/mod.rs`, реэкспорт `xray/config/mod.rs`, `xray/mod.rs` |
| Shell Save | `xray/config/modify.rs` (`compose_inbound_shell`) |
| GUI | `gui/pages/inbounds.rs`, `gui/pages/stream_finalmask.rs` |

- Тесты (+3): `apply_tunnel_stream_writes_finalmask_chains_and_leaves_quic_params_alone`,
  `apply_tunnel_stream_rejects_bad_finalmask_and_leaves_inbound_unchanged` (невалидный слой без
  `streamSettings`; чужой `finalmask`), `tunnel_shell_save_writes_finalmask_udp_and_preserves_other_stream_fields`
  (`modify_tests`); три `apply_tunnel_sockopt_*` переименованы в `apply_tunnel_stream_*`. Итог:
  **1281 passed / 0 failed**.

# 89	FinalMask — этап 4.3: матрица применимости цепочек к листенерам (0.5.36-0)

## 89.1	Сверка с ядром

`XTLS/Xray-core@main`, `transport/internet/finalmask/finalmask.go`: `FinalMask.Listen` (TCP-листенер)
применяет только `tcp[]`, `FinalMask.ListenPacket` (UDP-сокет) — только `udp[]`. Кто что вызывает:

| Листенер | Вызов | Цепочка |
| -------- | ----- | ------- |
| RAW (`tcp/hub.go`), WebSocket, gRPC, HTTPUpgrade, XHTTP без h3 | `FinalMask.Listen` | `tcp[]` |
| mKCP (`kcp/listener.go` → `udp.ListenUDP`) | `FinalMask.ListenPacket` | `udp[]` |
| Hysteria (`hysteria/hub.go`), XHTTP/3 (`splithttp/hub.go`, `isH3`) | `FinalMask.ListenPacket` | `udp[]` |
| UDP-воркер прокси (`udpWorker` → `udp.ListenUDP`), независимо от транспорта | `FinalMask.ListenPacket` | `udp[]` |

Какие воркеры создаются (`app/proxyman/inbound/always.go`) — по `Network()` прокси: IP-`listen`
→ stream-воркер на порт при TCP (через транспорт) и UDP-воркер при UDP; Unix-`listen`
(абсолютный путь или `@…`, `InboundDetourConfig.Build`) → только domain-socket воркер (через
транспорт) и только при UNIX. `Network()`: VLESS/Trojan — TCP+UNIX, Hysteria — TCP, Tunnel —
`allowedNetwork` (+UNIX при TCP). `DokodemoConfig.Build()`: legacy `network` перекрывает
`allowedNetwork`, отсутствие/`null` → TCP. `NetworkList`: массив строк или строка, разрезанная
по `,` **без trim**, имена без учёта регистра, неизвестные игнорируются — `"tcp, udp"` = только
TCP. Имя протокола ядро сравнивает без учёта регистра (`JSONConfigLoader.LoadWithID`).
`masque` (H3 + H2) и `xdrive` — транспорты вне таблицы.

## 89.2	Модель

`xray/config/compatibility/matrix.rs`:

- `FinalMaskChainUse { tcp, udp }` + `uses(chain)`;
- `inbound_finalmask_chain_use(&inbound) -> Option<FinalMaskChainUse>` — по таблице выше;
  `None` (молчать, а не гадать) для протокола вне VLESS/Trojan/Hysteria/Tunnel/`dokodemo-door`,
  транспорта вне таблицы (если stream-воркер вообще создаётся) и значения `allowedNetwork`,
  которое ядро не загрузит. Транспорт — через существующие `normalized_method` /
  `matrix_transport` / `quic_transport_of`, как в gates и редакторе.

`xray/config/compatibility/warnings.rs`: новый `CompatibilityWarningId::FinalMaskChainUnused` —
непустая `finalmask.tcp`/`.udp`, которую не применяет ни один листенер inbound; по одному на
цепочку, location `streamSettings.finalmask.tcp|udp`, перед предупреждениями по слоям.
Save не блокирует (слои остаются на диске). GUI — существующая инфраструктура §0.3: жёлтые строки
вверху Stream-таба (черновик в edit, диск в view) и суффикс статуса после Save.

Расхождение, найденное при сверке (не исправлено, вне этапа): при одновременных `network` и
`method` ядро берёт `method` (`StreamConfig.Build`: `if c.Method != nil { c.Network = c.Method }`),
а Feldjäger везде — `network` (`parse_inbound_stream`, `normalized_method`, `quic_transport_of`).

## 89.3	Код и итог

| Область | Путь |
| ------- | ---- |
| Матрица | `xray/config/compatibility/matrix.rs` |
| Предупреждение | `xray/config/compatibility/warnings.rs` |
| Фикстура теста сервиса | `app/service.rs` (`UDPHOP_SOCKOPT_INBOUND`: `tcp` → `mkcp`, чтобы `udp[]` использовалась) |

- Тесты (+4): `finalmask_chain_use_follows_the_transport`,
  `finalmask_chain_use_of_a_tunnel_follows_its_networks`, `finalmask_chain_use_on_a_unix_socket`
  (`matrix`), `flags_finalmask_chain_no_listener_uses` (`warnings`). Итог: **1285 passed / 0 failed**.

# 90	FinalMask — этап 5.1: gate G4 → предупреждение `RealityProbeSeesFinalMask` (0.5.37-0)

## 90.1	Проблема

G4 («Reality + непустой `finalmask.tcp`») стоял в `first_failing_gate`, а тот вызывается из
`check_inbound_compatibility` не только на Shell Save, но и на Add, Duplicate и после **каждой**
мутации клиентов (`check_inbound_after_client_mutate`). Рабочий inbound с такой конфигурацией на
диске нельзя было ни сохранить, ни дополнить пользователем — хотя ядро её штатно запускает.

## 90.2	Сверка с ядром

`XTLS/Xray-core@main`, `transport/internet/tcp/hub.go`: `FinalMask.Listen` оборачивает сокет
(строка 50), REALITY (`reality.Server`, строка 109) работает поверх. ClientHello активного
сканера сначала проходит серверную сторону маски:

- `header-custom` (`header/custom/tcp.go`): при несовпадении `clients[i]` пишет `errors[i]` и отказывает;
- `sudoku` (`newPackedDirectionalConn`): декодирует входящий поток, fallback нет;
- `xmc` (`wrapConnServer`): ждёт Minecraft-рукопожатие;
- `fragment`: `Read` не переопределён — входящее сквозное, режутся только записи.

Сканер видит поведение маски, а не настоящий TLS-сайт `target`, куда REALITY проксировал бы
чужой ClientHello: маскировка ослаблена, но конфиг корректен.

## 90.3	Изменения

- `compatibility/mod.rs`: проверка G4 убрана из `first_failing_gate`, предикат
  `reality_finalmask_tcp_nonempty` удалён; вариант `CompatibilityGateId::G4` оставлен
  «retired» (как G7 — стабильность id/сообщений); doc-комментарии порядка обновлены.
- `stream/finalmask.rs`: `PROBE_VISIBLE_TCP_FINALMASK_TYPES` (`header-custom`/`sudoku`/`xmc`) и
  `finalmask_tcp_layer_faces_probes(type)` (trim + без учёта регистра, как
  `finalmask_layer_type_applies`); реэкспорт до `crate::xray`.
- `compatibility/warnings.rs`: `CompatibilityWarningId::RealityProbeSeesFinalMask` — при
  `effective_security == "reality"` по одному на такой слой, location
  `streamSettings.finalmask.tcp[i].type`.
- GUI (`inbounds.rs`): notice в секции FinalMask «…Save will be blocked (G4)» заменён на
  пояснение (Reality + слой из списка по типизированному черновику, «Save is allowed»);
  предупреждение также вверху Stream-таба и в статусе Save (инфраструктура §0.3).
- Бывшая часть (б) пункта («клиенту нужна идентичная цепочка») перенесена в Roadmap 6.1.

## 90.4	Код и итог

| Область | Путь |
| ------- | ---- |
| Gates | `xray/config/compatibility/mod.rs` |
| Предупреждение | `xray/config/compatibility/warnings.rs` |
| Типы масок | `xray/config/stream/finalmask.rs`, реэкспорт `stream/mod.rs`, `config/mod.rs`, `xray/mod.rs` |
| GUI | `gui/pages/inbounds.rs`, `gui/pages/stream_finalmask.rs` (doc) |

- Тесты: `g4_*` → `reality_*_passes_gates*` (первый теперь с `sudoku`);
  `finalmask_tcp_blocked_by_g4_with_reality_security` → `finalmask_tcp_with_reality_security_is_added_and_warned`
  (Add проходит, предупреждение только на `sudoku`, не на `fragment`); новые
  `client_add_on_reality_inbound_with_finalmask_tcp_is_not_blocked`,
  `flags_probe_facing_tcp_layers_only_with_reality`. Итог: **1287 passed / 0 failed**.

# 91	FinalMask — этап 5.2: миграция mKCP `header`/`seed` → `mkcp-legacy` (0.5.38-0)

## 91.1	Хронология ядра (сверено по релизам XTLS/Xray-core)

Аудит этапа 5 (2026-10-04) называл v26.1.31 релизом `mkcp-legacy` — неверно. Сканирование
`infra/conf/*.go` по тегам и `compare` дали:

| Ядро | `kcpSettings.header`/`seed` | Эквивалент в FinalMask |
| ---- | --------------------------- | ---------------------- |
| ≤ v26.1.23 | работают | — |
| v26.1.31 … v26.5.9 | фатальная ошибка загрузки (`PrintRemovedFeatureError("mkcp header & seed")`, #5560) | `header-*`, `mkcp-original`, `mkcp-aes128gcm` |
| v26.6.1 … v26.9.8 | фатальная ошибка загрузки | `mkcp-legacy` (#6201) |
| ≥ v26.9.9 | молча игнорируются (#6327) | `mkcp-legacy` |

`congestion`/`readBufferSize`/`writeBufferSize` читались до v26.9.8 и перестали в v26.9.9 (#6327).

Старое ядро (родитель #5560, `kcp/config.go`, `kcp/io.go`): шифрование **всегда** —
`seed` → AES-128-GCM, иначе `SimpleAuthenticator` (`original`); заголовок пишется перед
запечатанными байтами (`[header][sealed]`). `header` грузится loader'ом по ключу `type`
(без учёта регистра; `none`/`srtp`/`utp`/`wechat-video`/`dtls`/`wireguard`/`dns`, у `dns` —
`domain`, пусто → `www.baidu.com`); `seed` — `*string`: `""` всё равно включает AES-GCM.

## 91.2	Модель

- `compatibility/core_version.rs`: `CoreFeature::KcpHeaderSeedRemoved` (v26.1.31, #5560),
  `MkcpLegacyMask` (v26.6.1, #6201), `KcpConfigSlimmed` (v26.9.9, #6327).
- `compatibility/warnings.rs`: по версии ядра — до v26.1.31 ничего; v26.1.31…v26.9.8 новый
  `KcpLegacyObfuscationRejected` («конфиг не загрузится»; `"seed": null` не в счёт — в ядре
  nil-указатель, `"header": null` — в счёт, `RawMessage` не nil); с v26.9.9 / неизвестно —
  `KcpLegacyObfuscationIgnored` (текст: «один или два слоя», кнопка). `KcpFieldIgnored` теперь
  тоже только с v26.9.9 (был тот же баг). Слой `mkcp-legacy` на ядре < v26.6.1 →
  `RequiresNewerCore`.
- `stream/finalmask_mkcp.rs`: `mkcp_legacy_layers_from_kcp(header, seed)` — чистое
  преобразование в **два** слоя: шифр (`{"value": seed}` | `{}` = original) первым
  (внутренний), заголовок последним (внешний: `FinalMask.ListenPacket` разворачивает список).
  `wechat-video` → `wechat`, `none` → без слоя, `dns.domain` → `value` (пустой опускается —
  то же значение по умолчанию). Отказ: `seed` не строка или `""`, `header` не объект / без
  строкового `type` / неизвестный тип, `domain` не строка, домен не кодируется
  (`validate_mkcp_legacy`). Прочие ключи внутри `header` старое ядро игнорировало — не переносятся.
- `inbound_stream/mod.rs`: `KcpStreamSettings::has_legacy_obfuscation`;
  `InboundStreamDraft::migrate_kcp_legacy_obfuscation() -> Result<usize, String>` — только mKCP,
  отказ при чужом `finalmask` и **непустом `udp[]`**; убирает ключи из `kcp.extras`, ставит слои,
  `write_finalmask_udp = true`; при ошибке черновик не меняется.

## 91.3	Сервис и GUI

- `ApplicationService::editor_kcp_legacy_migration_blocked_reason()` — ядро известно и
  < v26.6.1; `finalmask.udp` на диске, который типизированная модель не прочла (запись бы его
  заменила). `migrate_editor_kcp_legacy_obfuscation()` — миграция черновика, `dirty`, затем
  `preview_inbound_shell_diff()` (редактированный JSON-diff; его ошибка не откатывает миграцию,
  а попадает в статус).
- `inbounds.rs`: `show_kcp_legacy_migration` после транспортной части Stream-таба (mKCP с
  `header`/`seed`): значения (`seed` не показывается), пояснение по версиям, причина
  недоступности, кнопка «Migrate header/seed to FinalMask». Diff — в существующем блоке
  предпросмотра сессии. На диск ничего не пишется до Save.

## 91.4	Код и итог

| Область | Путь |
| ------- | ---- |
| Версии ядра | `xray/config/compatibility/core_version.rs` |
| Предупреждения | `xray/config/compatibility/warnings.rs` |
| Преобразование | `xray/config/stream/finalmask_mkcp.rs`, реэкспорт `stream/mod.rs` |
| Миграция черновика | `xray/config/inbound_stream/mod.rs` |
| Сервис | `app/service.rs` |
| GUI | `gui/pages/inbounds.rs` |

- Тесты (+6): `legacy_kcp_header_and_seed_become_cipher_then_header`,
  `legacy_kcp_values_without_a_faithful_equivalent_are_refused` (`finalmask_mkcp`),
  `mkcp_legacy_keys_follow_the_core_version` (`warnings`),
  `mkcp_legacy_migration_writes_layers_and_drops_the_keys`,
  `mkcp_legacy_migration_refusals_leave_the_draft_unchanged` (`inbound_stream`),
  `kcp_legacy_migration_follows_the_core_and_fills_the_diff_preview` (`service`).
  Итог: **1293 passed / 0 failed**.

# 92	FinalMask — этап 6.1: клиентская цепочка в share-ссылке (`fm`) (0.5.39-0)

## 92.1	Стандарт share-ссылок

Стандарт VLESS/VMess-ссылок (XTLS/Xray-core discussion #716, §4.3.20, добавлено RPRX
2026-01-31) **уже имеет** параметр `fm`: «соответствует `finalmask` в конфиге; из-за
многоуровневой вложенности, как XHTTP `extra`, передаётся весь JSON-сегмент; обязательно
`encodeURIComponent`». Формулировка пункта 6.1 («при отсутствии параметра — предупреждение»)
устарела: предупреждение заменено на передачу цепочки в ссылке.

Эталонный клиент v2rayN (`ServiceLib/Handler/Fmt/BaseFmt.cs`): `fm` читается общим
`ResolveUriQuery` — для `vless://` и `trojan://` (у Trojan те же параметры), `ToUriQuery` пишет
его в обе; JSON кладётся в `streamSettings.finalmask` исходящего **как есть** и заменяет
finalmask, который клиент построил бы сам (`V2rayOutboundService`). У `hy2://` v2rayN `fm`
тоже читает (общий `ResolveUriQuery`), но не пишет, а в официальной схеме hy2 его нет — hy2
остаётся на `obfs` (§83).

## 92.2	Что получает клиент (сверено с `transport/internet/finalmask/*`)

Ссылка должна нести **клиентскую** цепочку, а не серверную. Порядок слоёв у сторон один
(первый — внутренний), большинство масок симметричны:

| Слой | В `fm` | Почему |
| ---- | ------ | ------ |
| `fragment`, `noise` | нет | действуют только на запись своей стороны, чтение сквозное (`fragment/conn.go`, `noise/conn.go`); выпадение не сдвигает остальные слои |
| `udphop` | нет | client-only, на inbound не сохраняется (§79) |
| `xicmp` | без `ips` | на сервере `ips` — допустимые адреса пиров (`server.go`), на клиенте — куда слать (`client.go`; пусто = адрес дозвона); `dgram` копируется |
| `realm` | без `ipMode`, `portMapping` | локальная сеть своей стороны (семейство адресов, UPnP/NAT-PMP на шлюзе); `url`/`stunServers`/`tlsConfig` — общий realm-сервер |
| `xdns` | как есть + заметка, если нет `resolvers` | клиенту нужен свой резолвер (`NewClient`), сервер их игнорирует |
| `header-custom`, `sudoku`, `xmc`, `mkcp-legacy`, `salamander` | как есть | симметричны; ключи, которые сервер игнорирует (`xmc.hostname`), сохраняются |
| неизвестный тип | как есть + заметка | Feldjäger не знает, нужен ли он клиенту |

`quicParams` не передаётся — настройки собственного QUIC-стека стороны. Цепочка — только та,
через которую клиент дозванивается: `udp[]` у mKCP / Hysteria / XHTTP/3 (TLS + `alpn` ровно
`["h3"]`), иначе `tcp[]` (отдельного UDP-воркера у VLESS/Trojan нет, §89).

## 92.3	Модель, сервис, GUI

- `stream/finalmask_client.rs`: `ClientFinalMask {value, layer_types, notes}` (+
  `compact_json`/`pretty_json`), `client_finalmask(&[(FinalMaskChain, &[FinalMaskLayerDraft])])`
  → `None`, если зеркалить нечего.
- `share_uri.rs`: `ShareUriRequest.finalmask` → `fm` (полное percent-кодирование, строже
  `encodeURIComponent`); пустое/`{}` не пишется; Hysteria игнорирует; в `Debug` — `[REDACTED]`
  (пароли масок).
- `service.rs`: `client_finalmask_of(on_disk, stream, security)` — выбор цепочки по транспорту
  черновика, ошибка при `finalmask` не-объекте или нечитаемой цепочке на диске (Share
  выключается с причиной, вместо ссылки без масок); `build_client_share_uri` добавляет `fm`
  для VLESS/Trojan; `client_share_finalmask(index) -> Result<Option<ClientShareFinalMask>>`
  (`json`, `layer_types`, `notes`, `in_share_uri`) для GUI, черновик редактора приоритетнее
  диска.
- `users.rs`: в контекстном меню клиента под Share — «Copy client finalmask JSON» + пояснение
  (VLESS/Trojan: «ссылка несёт `fm`; клиенты без поддержки `fm` подключатся без масок»; hy2:
  «hy2-ссылка несёт только plain salamander») + заметки слоёв. Предупреждение «Share links are
  disabled» у Hysteria указывает на эту кнопку.

## 92.4	Код и итог

| Область | Путь |
| ------- | ---- |
| Клиентская цепочка | `xray/config/stream/finalmask_client.rs`, реэкспорт `stream/mod.rs` |
| Share URI | `xray/share_uri.rs` |
| Сервис | `app/service.rs` (`ClientShareFinalMask`) |
| GUI | `gui/pages/users.rs` |
| Интероп | `xray/config/stream/finalmask_interop.rs` (`run_echo` вынесен из hy2-теста) |

- Тесты (+8): 4 модельных (`finalmask_client`), `builds_fm_as_encoded_json_for_vless_and_trojan`,
  `hy2_ignores_fm` (`share_uri`), `share_uri_fm_carries_the_client_finalmask` (`service`),
  интероп `vless_share_fm_matches_the_core` — Xray 26.9.30: VLESS-сервер с цепочкой ↔ клиент с
  `fm` (RAW: `fragment`+`sudoku`, `header-custom`; mKCP: `mkcp-legacy`+`noise`; неиспользуемая
  цепочка на сервере), контроль — клиент без `fm` не подключается. Итог: **1301 passed /
  0 failed**, clippy lib 66 (без изменений).
- Найдено вне пункта: XTLS/Xray-core#7090 (2026-10-05, после v26.9.30) меняет схему `xdns` —
  `domains[].name` → `names[]`, `resolvers[].type`+`settings.addr` → `addrs[]`, умолчание
  `types`. В `fm` `xdns` копируется дословно и от схемы не зависит; типизированный редактор
  (§1.3) — отдельный пункт Roadmap.

# 93	FinalMask — этап 6.2: импорт `fm` в серверные цепочки (0.5.40-0)

## 93.1	Правила (обратные §92.2)

`fm` из вставленной ссылки — клиентский `finalmask`; новому inbound нужна серверная цепочка.
Та же таблица, прочитанная в обратную сторону (`server_finalmask_from_client`):

| Клиентский слой | На сервер | Предупреждение |
| --------------- | --------- | -------------- |
| `fragment`, `noise` | нет | «формирует только то, что шлёт клиент, серверу пара не нужна» |
| `udphop` | нет | «client-only, сервер не может с ним слушать» |
| `xicmp` | без `ips`, `dgram` | на сервере `ips` — допустимые пиры (иной смысл), `dgram` игнорируется |
| `xdns` | без `resolvers` | сервер их игнорирует |
| `realm` | без `ipMode`, `portMapping` | описывают сеть клиента |
| `xmc` | без `hostname` | сервер его игнорирует |
| `header-custom`, `sudoku`, `mkcp-legacy`, `salamander` | как есть | — |
| неизвестный тип | как есть | «проверьте, нужен ли серверу» |
| `quicParams`, прочие ключи `fm` | нет | по ключу |

Предупреждение выдаётся только при реальном удалении ключа. Нечитаемый `fm` (не JSON, не
объект, цепочка не список слоёв) — ничего из этой цепочки не импортируется, с предупреждением.
Симметричная цепочка проходит круг «сервер → `fm` → сервер» без изменений (тест).

Hysteria: inbound слушает только `udp[]` — `fm.tcp` не импортируется (предупреждение); при
`fm` и `obfs` одновременно побеждает `fm` (как у v2rayN, где `fm` заменяет собственный
finalmask клиента); `obfs` не `salamander` (нестандартный `gecko` v2rayN) — предупреждение
вместо прежнего молчаливого пропуска. Без `fm` — прежний импорт salamander (§83).

## 93.2	Код

- `stream/finalmask_client.rs`: `ServerFinalMaskImport {tcp, udp, warnings}`,
  `server_finalmask_from_client(fm)`.
- `share_uri.rs`: `ParsedShareUri.finalmask` (`fm`, у всех схем) и `.obfs` (тип hy2 obfs как
  есть).
- `app/inbound_import.rs`: `ImportPreview.finalmask_tcp` / `finalmask_udp` /
  `finalmask_summary`; `import_finalmask` (в т.ч. перенесённое из GUI построение salamander-слоя
  из `obfs`).
- `gui/pages/inbounds.rs`: строка «FinalMask» в предпросмотре импорта; «Create new inbound»
  присваивает готовые цепочки черновику (раньше GUI сам собирал JSON salamander-слоя). «Add
  user to existing inbound» цепочки не трогает — сказано в подсказке.

Тесты (+6): `import_keeps_symmetric_layers_and_reports_the_rest`,
`import_of_unreadable_fm_imports_nothing`, `share_then_import_round_trips_symmetric_chains`
(`finalmask_client`), `parses_fm_and_hy2_obfs_type` (`share_uri`),
`vless_fm_becomes_server_chains`, `hysteria_fm_replaces_obfs_and_drops_tcp` (`inbound_import`;
расширен `hysteria_obfs_password_produces_no_warning_itself`). Итог: **1307 passed / 0 failed**,
clippy lib 66 (без изменений).

# 94	Outbound `streamSettings`: транспорт и клиентский security (Roadmap §4.2) (0.5.41-0)

## 94.1	Почему сейчас

Пункт 7.1 (Outbound FinalMask, §95) прямо зависел от этого пункта: у Outbound Shell не было ни
вкладки Stream, ни Security, поэтому FinalMask и `quicParams` было некуда встроить. По решению
пользователя сначала реализован §4.2 «Outbound `streamSettings` editor», затем 7.1 на нём.

## 94.2	Клиентская схема (сверено с `XTLS/Xray-core@main`, 7da5dae)

Один `StreamConfig` обслуживает обе стороны (`infra/conf/transport_internet.go`,
`transport_method.go`, `transport_security.go`); клиент читает другие поля, чем сервер:

| Транспорт | Клиентские поля | Проверки `Build()` |
| --------- | --------------- | ------------------ |
| RAW | только legacy `header` (HTTP-обфускация) — хранится как есть; `acceptProxyProtocol` серверный | — |
| XHTTP | общая модель `XhttpStreamSettings` (`host`/`path`/`mode`, headers, padding/placement, `xmux`, `downloadSettings`) | как у inbound |
| gRPC | `authority`, `serviceName`, `multiMode`, `user_agent`, `idle_timeout`, `health_check_timeout`, `permit_without_stream`, `initial_windows_size` | `int32` |
| WebSocket | `host`, `path` (`?ed=`), `headers`, `heartbeatPeriod` | `uint32`; `Host` в `headers` — deprecated (переносится в `host`) |
| HTTPUpgrade | `host`, `path` (`?ed=`), `headers` | `Host` в `headers` — ошибка |
| mKCP | общая модель `KcpStreamSettings` | как у inbound (0.6) |
| Hysteria | `version`, `auth`, `udpIdleTimeout` (`masquerade` серверный) | `version` = 2, `udpIdleTimeout` 0 или 2–600 |

Security клиента:

- **TLS** (`TlsClientDraft`): `serverName`, `alpn` (`StringList`, форма на диске сохраняется),
  `fingerprint` (полный список uTLS из `transport/internet/tls/tls.go`, регистр не важен;
  пусто = `chrome`), `pinnedPeerCertSha256` (через запятую, hex с `:`, по 32 байта),
  `verifyPeerCertByName`, `echConfigList`, `minVersion`/`maxVersion`, `cipherSuites`,
  `curvePreferences`, `disableSystemRoot`, `enableSessionResumption`, `masterKeyLog`.
  `certificates` (CA `usage: verify`), `echSockopt` и серверные ключи — в `extras`, не
  редактируются. `allowInsecure: true` с v26.1.31 (2c92339) — removed feature, конфиг не
  загружается: предупреждение + кнопка «Remove allowInsecure», сам редактор его не ставит.
- **REALITY** (`RealityClientDraft`) — клиентская ветка `REALITYConfig.Build()` (нет
  `target`/`dest`): `fingerprint` известный и не `unsafe`/`hellogolang`; `publicKey` (алиас
  `password`, при наличии побеждает — ключ на диске сохраняется) — base64url без паддинга,
  32 байта; `shortId` ≤ 16 hex, чётная длина (пустой допустим); `spiderX` начинается с `/`;
  `mldsa65Verify` — 1952 байта; непустые серверные `serverNames`/`shortIds` — ошибка.
- Матрица: REALITY только RAW/XHTTP/gRPC, Hysteria только TLS (`transport_security_allowed`);
  при смене транспорта security приводится `coerce_security_mode_for_transport`.

Приоритеты ключей, как в ядре: `method` важнее `network` (у inbound исторически наоборот),
`rawSettings` важнее `tcpSettings`, `xhttpSettings` важнее `splithttpSettings`. Написание на диске
(`raw`/`ws`/`splithttp`, `method`, алиас `*Settings`) сохраняется, пока транспорт не сменён.
`masque`/`xdrive`/неизвестный транспорт и неизвестный `security` — только для чтения, не
переписываются.

## 94.3	Запись

- `streamSettings` пишется **только после правки** Stream/Security (`OutboundStreamDraft::write`):
  Save, затронувший лишь Protocol, оставляет `streamSettings` байт в байт, а новый outbound без
  правок — без `streamSettings` (умолчание ядра RAW/none).
- При смене транспорта удаляются `*Settings` прочих транспортов: ядро собирает **все**
  присутствующие объекты, и чужой невалидный объект ломает загрузку. Без смены — не трогаются.
- `sockopt`, `finalmask` (до §95), `address`/`port` и неизвестные ключи `streamSettings` не
  трогаются никогда.
- Всё проверяется до первой мутации; ошибка — ничего не изменено.

## 94.4	Найдено паритет-тестом: plaintext VLESS/Trojan

Паритет-тест с локальным `xray run -test` (Xray 26.9.30) выявил правило ядра, о котором Roadmap
не знал: с v26.7.11 (XTLS/Xray-core#6303, `validateOutboundTransportSecurity` в
`infra/conf/xray.go`) VLESS/Trojan outbound без TLS/REALITY (VLESS: и без `encryption` ≠
`none`) к **публичному** адресу не загружается. «Приватный» — фиксированные списки
`common/geodata/consts.go`: 18 IP-диапазонов и домены `lan`, `localdomain`, `example`, `invalid`,
`localhost`, `test`, `local`, `home.arpa`, `internal` с поддоменами плюс любое имя без точек.
Адрес и `encryption` читаются как в `Build()`: плоская форма, иначе `vnext[0]`/`servers[0]`.
Реализовано точно (`compatibility/plaintext_outbound.rs`) как версионно-зависимое предупреждение
`PlaintextOutboundForbidden` (`CoreFeature::PlaintextOutboundForbidden`, v26.7.11): Save не
блокируется (на старом ядре это валидный конфиг), пост-проверка `xray run -test` остаётся.

## 94.5	GUI и сервис

- `gui/pages/outbound_stream.rs` (новый): секции «Stream (streamSettings)» и «Security» в Outbound
  Shell для протоколов с транспортом (`outbound_protocol_has_transport`; из Shell-протоколов
  сейчас только VLESS). Транспорты по протоколу (`outbound_transports_for_protocol`: Hysteria —
  только свой, прочие — все, кроме Hysteria). Все предупреждения outbound показаны здесь же.
  Подсказка Vision: `xtls-rprx-vision` работает только поверх RAW с TLS/REALITY или с VLESS
  Encryption (`proxy/vless/outbound`).
- Из `inbounds.rs` вынесены общие `show_xhttp_settings_edit` и `show_kcp_settings_edit` (с
  префиксом id); `string_tag_multi_select` стал `pub(super)`. Поведение inbound не менялось.
- `OutboundEditorSession.stream`, `AddOutboundShellRequest.stream` / `UpdateOutboundShellRequest.stream`;
  `add_outbound_shell` / `update_outbound_shell` вызывают `apply_outbound_stream`; предпросмотр
  diff и предупреждения считаются по тому же JSON.

## 94.6	Код и итог

| Область | Путь |
| ------- | ---- |
| Модель транспорта | `xray/config/outbound_stream/mod.rs` |
| Клиентский security | `xray/config/outbound_stream/security.rs` |
| Паритет с ядром | `xray/config/outbound_stream/parity.rs` |
| Plaintext-правило | `xray/config/compatibility/plaintext_outbound.rs`, `core_version.rs` |
| Предупреждения | `xray/config/compatibility/warnings.rs` |
| Общие хелперы | `inbound_stream/mod.rs` (`kcp_settings_to_object`, `parse_kcp`), `inbound_security/mod.rs` (`insert_string_list`) |
| Запись | `xray/config/modify.rs` |
| Сервис | `app/outbound_ops.rs`, `app/service.rs` |
| GUI | `gui/pages/outbound_stream.rs`, `gui/pages/outbounds.rs`, `gui/pages/inbounds.rs` |

Тесты (+20): 10 транспортных и 5 security (`outbound_stream`), 2 plaintext, 1 предупреждений,
`update_vless_outbound_shell_writes_stream_only_when_changed` (`modify_tests`), паритет
`parity_with_xray_run_test` — 20 случаев валидации + 8 случаев plaintext-правила, все совпали
с Xray 26.9.30 (без локального Xray проверяется только сторона Feldjäger). Итог: **1327 passed /
0 failed**, clippy lib 66 (без изменений).

# 95	FinalMask — этап 7.1: Outbound FinalMask и `quicParams` (0.5.42-0)

## 95.1	Анализ полноты пункта

Пункт был не готов к реализации: условие «после §4.2 Outbound `streamSettings`» не выполнено (у
Outbound Shell не было вкладок Stream/Security, Hysteria outbound Shell нет). По решению
пользователя сначала сделан §4.2 (§94). Остальное:

- Подсказки client-only полей (`xicmp` без `ips` = адрес дозвона, `dgram`; `xdns.resolvers`;
  заметки `fragment` по стороне; `udphop` client-only) уже были direction-aware с этапов 0.4,
  1.x, 2.5 — здесь они впервые работают с `StreamDirection::Outbound`.
- `quicParams` для Hysteria outbound реализован в модели и GUI, но открыть Hysteria outbound в
  Shell пока нельзя (пункт §4.2 «Outbounds Shell: Hysteria»); для VLESS доступен XHTTP/3.
- Пункт 1.6 (`xdns`, XTLS/Xray-core#7090) по-прежнему открыт; форма `xdns` — как в этапе 1.3.
- Freedom `fragment`/`noises` не затронуты.

## 95.2	Модель

`OutboundStreamDraft` получил `finalmask_tcp`/`finalmask_udp`/`quic_params` и флаги
`write_finalmask_tcp`/`write_finalmask_udp`/`write_quic_params` — каждая часть пишется только
после правки, прочие ключи `finalmask` сохраняются. `finalmask` не-объект (`finalmask_foreign`) и
цепочка, которую типизированная модель не читает (`finalmask_unreadable`), не перезаписываются
никогда — редактор такой цепочки заменён заметкой.

- Слои проверяются `validate_finalmask_layers(…, StreamDirection::Outbound)` — client-only
  `udphop` здесь разрешён.
- `quic_transport()`: Hysteria или XHTTP + TLS + `alpn` ровно `["h3"]`; `quicParams` проверяется
  `validate_quic_params_for_transport` (на XHTTP/3 `brutal` запрещён), без QUIC-транспорта —
  общей `validate_quic_params`. После сборки — `validate_stream_quic_params` на итоговом
  `streamSettings` (ловит и сохранённый `quicParams`, ставший неверным после смены ALPN).
- `dial_chain()`: `udp` у mKCP/Hysteria/XHTTP/3, иначе `tcp`.
- `migrate_legacy_udp_hop()`: удалённый `quicParams.udpHop` → слой `udphop` в `udp[0]` (общий
  `migrate_legacy_udp_hop` этапа 3.2, сторона Outbound); сервис
  `migrate_outbound_legacy_udp_hop` отказывает при ядре < v26.9.9 (там старый ключ ещё работает)
  и обновляет diff.

## 95.3	Предупреждения

`outbound_warnings(outbound, core)` получил версию ядра (Discovery) и FinalMask-часть:

- `OutboundFinalMaskChainUnused` — цепочка, через которую outbound не дозванивается. Сверено с
  `transport/internet/dialer.go` и `memory_settings.go`: TCP-дозвон идёт через диалер
  транспорта (RAW/WS/gRPC/HTTPUpgrade/XHTTP-TCP — `tcp[]`; mKCP/Hysteria/XHTTP/3 — `udp[]`),
  UDP-дозвон — через UDP-диалер (`udp[]`). Утверждение делается только для VLESS/VMess/Trojan/
  Hysteria (UDP — внутри транспорта); Freedom, Shadowsocks, WireGuard могут звонить по UDP
  напрямую — молчим.
- общие проверки слоёв и версий `finalmask_warnings(…, Outbound, core)` (`udphop.sockopt`,
  `xdns`/`xmc` legacy, «требует более нового ядра», `quicParams.udpHop`);
- `QuicParamsUnusedTransport` — `quicParams` вне QUIC-транспорта.

## 95.4	GUI

В `gui/pages/outbound_stream.rs` после Security — общие `show_quic_params_edit` (только при
QUIC-транспорте; у XHTTP без h3 — подсказка) и `show_finalmask_edit` с `StreamDirection::Outbound`
(у Hysteria цепочка `tcp` скрыта, пока пуста). Кнопка «Migrate udpHop to a udphop layer» под
`quicParams`; комментарий `show_legacy_udp_hop` обновлён.

## 95.5	Итог

Тесты (+5): `finalmask_chain_written_only_when_edited_with_client_layers`,
`foreign_or_unreadable_finalmask_is_never_overwritten`, `quic_params_follow_the_quic_transport`,
`legacy_udp_hop_becomes_a_udphop_layer` (`outbound_stream`),
`flags_outbound_finalmask_by_dial_chain` (`warnings`); паритет §94 включает `mkcp + udphop`,
Hysteria с `quicParams` и XHTTP/3 + `brutal` (runtime-отказ, `-test` пропускает). Итог: **1332
passed / 0 failed**, clippy lib 66 (без изменений).

Найдено вне пункта (в Roadmap): inbound TLS-редактор по-прежнему позволяет поставить
`allowInsecure` (ядро v26.1.31+ отвергает его и на сервере).


# 96	Retired-протоколы inbound и предупреждение «open proxy» (Roadmap §4.1) (0.5.43-0)

## 96.1	Решение по Tier 4.1

По оценке пользователя и официальной документации Xray (`config/transport.md`, примечание [2];
`inbounds/socks.md`; `outbounds/wireguard.md`) редакторы Shadowsocks / VMess / HTTP / Socks /
`mixed` / WireGuard inbound переведены в **retired**: апстрим прямо называет эти протоколы
непригодными для обхода блокировок (классифицируемый трафик, нет TLS-вида, фиксированная
UDP-сигнатура WireGuard, открытый текст Socks/HTTP). Поддержка таких inbound остаётся на уровне
«чтение + Raw JSON (§3:125) + Delete + Backups». Masque inbound отложен до финализации протокола в
Xray-core (нет в таблице `transport.md`). Predicate G11 остаётся в коде неподключённым — волна SS,
ради которой он делался, отменена; комментарии в `compatibility/mod.rs` обновлены.

Вместо редакторов добавлено одно предупреждение там, где эти протоколы опасны для самого сервера:
Socks/HTTP без аутентификации на внешнем адресе — открытый прокси, за который хостеры блокируют VPS.

## 96.2	Модель (`compatibility/open_proxy.rs`)

`open_proxy_location(inbound) -> Option<String>` — JSON-путь отсутствующей аутентификации.
Сверено с `XTLS/Xray-core@main`:

- `SocksServerConfig.Build()` (`socks`, алиас `mixed`): `switch` по `auth` без приведения регистра —
  всё, кроме точного `"password"` (отсутствует, `"noauth"`, `"Password"`), даёт `NO_AUTH`, сколько бы
  `accounts` ни было → путь `settings.auth`;
- `HTTPServerConfig.Build()`: ненулевой `accounts` заменяет `users` (пустой `[]` — тоже), пустой
  итог = без аутентификации → `settings.accounts` / `settings.users`; не-массив ядро не
  декодирует — утверждения нет.

«Внешний» `listen`: отсутствует / `null` / пустой (по умолчанию ядро слушает `0.0.0.0`), unspecified
(`0.0.0.0`, `::`) или публичный IP (в т.ч. `[v6]` и `ip:port`). Loopback и частные диапазоны — LAN /
локальное использование, которое документация и описывает; для них переиспользован
`plaintext_outbound::is_private_ip` (список `GetPrivateIPMatcher()` из `common/geodata/consts.go`,
§94) — поэтому unspecified проверяется раньше: `0.0.0.0/8` и `::/127` входят в этот список. Unix-сокет
(`/…`, абстрактный `@…`) — не сетевой слушатель; прочие не-IP строки — утверждения нет.

`warnings.rs`: `CompatibilityWarningId::OpenProxyInbound`, новый `WarningSeverity::{Caution,
Danger}` и `CompatibilityWarningId::severity()` (Danger пока только у open proxy). Проверка в
`inbound_warnings` выполняется **до** раннего выхода по отсутствию `streamSettings` — у Socks/HTTP
его обычно нет. `with_warning_suffix` (статус-бар — простой текст, знак не нарисовать) оборачивает
danger-предупреждение в `!!! … !!!`. `WarningSeverity` реэкспортирован из `xray`.

## 96.3	GUI

`gui/pages/mod.rs`: `danger_sign(ui, side)` — знак 1.33 «Прочие опасности» векторно через
`egui::Painter` (как `qr_code`/`sparkline`, без растрового ассета и новой зависимости): красный
треугольник, белое поле — тот же треугольник, сжатый к центроиду так, что рамка одинаковой ширины
со всех сторон, чёрный восклицательный знак (штрих + точка); `danger_warning(ui, text)` — знак +
жирный красный текст.

`inbounds.rs`: danger-предупреждения показываются **над вкладками** detail pane — на любой вкладке и
для протоколов без Stream-таба (Socks/HTTP не shell-редактируемы); Stream-таб их отфильтровывает,
чтобы не дублировать. В таблице Inbounds у тега строки с danger-предупреждением — маленький знак с
текстом предупреждения во всплывающей подсказке. `show_compatibility_warnings` (inbound) и
`show_outbound_compatibility_warnings` различают уровень.

## 96.4	Итог

Тесты (+8): `open_proxy` — 6 (Socks/`mixed` по умолчанию, регистр `auth`, `accounts` заменяет
`users`, локальные/частные/сокетные `listen`, wildcard/публичные `listen`, прочие протоколы);
`warnings` — 2 (danger без `streamSettings`, `!!!` в суффиксе статуса). Итог: **1340 passed / 0
failed**, clippy lib 66 (без изменений). Визуально знак в запущенном приложении не проверялся.

# 97	Outbound `proxySettings` удалён в ядре: миграция в `sockopt.dialerProxy` (Roadmap §4.2) (0.5.43-1)

## 97.1	Проблема

XTLS/Xray-core#6058 (3e2f040, 2026-09-08, первый релиз — v26.9.8) начинает
`OutboundDetourConfig.Build()` (`infra/conf/xray.go`) с проверки `if c.ProxySettings != nil` →
`errors.PrintRemovedFeatureError` («outbound "proxySettings"» → «"streamSettings.sockopt.dialerProxy"»).
Это касается **любого** outbound, а не только Freedom,
как ошибочно было записано раньше (Roadmap §4.2, справка о переносе Freedom `domainStrategy`).
Поле объявлено как `*json.RawMessage`: `null` декодируется в nil и проходит, любое другое значение
(даже `{}` или строка) — «removed feature», и Xray не стартует.

General-вкладка Outbound Shell (`outbounds.rs`) при этом предлагала чекбокс «proxySettings (chain
through another outbound)» для всех протоколов с предупреждением только у Freedom — галка на
VLESS-outbound и Save давали конфиг, который ядро ≥ v26.9.8 не загружает. Вдобавок
`apply_outbound_general` удалял `proxySettings` при `proxy_settings: None`, а `parse` возвращал
`None` для объекта с пустым `tag` — обычный Save молча стирал такой ключ (нарушение
`rules.md`: удаление только по явному действию пользователя).

Старая семантика ядра (до #6058): `transportLayer: true` — ядро само подставляло `tag` в
`sockopt.dialerProxy`; `false` — proxy-layer chaining (`senderSettings.ProxySettings`). Апстрим
называет `dialerProxy` заменой для обоих случаев; для первого миграция точная.

## 97.2	Модель (`outbound_edit/mod.rs`)

`ProxySettingsDraft` удалён — `proxySettings` больше никогда не пишется. Вместо него:

- `LegacyProxySettings { tag, transport_layer, dialer_proxy }` — что лежит на диске (только для
  показа и выбора исхода миграции); `OutboundGeneral::legacy_proxy_settings` — `Some` для любого
  не-`null` значения, в точности как в ядре;
- `OutboundGeneral::migrate_proxy_settings: bool` + метод `migrate_proxy_settings() ->
  ProxySettingsMigration` (`Moved { tag }` / `DialerProxyWins { legacy, dialer_proxy }` / `Removed`
  — тега нет / `NothingToMigrate`) — по образцу Freedom `migrate_legacy_domain_strategy` (§2.4):
  меняется только черновик, запись — на Save;
- `apply_outbound_general` трогает `proxySettings` только при запланированной миграции: удаляет
  ключ и, если `streamSettings.sockopt.dialerProxy` пуст **в записываемом значении** (а не в
  снимке черновика), пишет туда тег, создавая контейнеры. Существующий `dialerProxy` побеждает.
  Не-объектный `streamSettings`/`sockopt` — ошибка валидации. Без миграции `proxySettings`
  сохраняется байт в байт.

`OutboundGeneral` получил `Default`; конструкторы в `service.rs` / `modify_tests.rs` обновлены.

## 97.3	Предупреждение и версия ядра

`CoreFeature::OutboundProxySettingsRemoved` (v26.9.8, #6058) — в таблице `CORE_FEATURES` между
`XmcProfilesSchema` и `UdpHopUdpMask`. `CompatibilityWarningId::OutboundProxySettingsRemoved`
(уровень Caution, как у прочих «rejected by Xray-core»: сервер не в опасности, конфиг просто не
загружается), путь `proxySettings`; `outbound_warnings` выдаёт его первым, для любого протокола,
только когда ядро неизвестно или ≥ v26.9.8 (на более старых ключ работает). Предупреждение видно
и в таблице Outbounds для не-shell протоколов (VMess, Trojan, …) — там исправление через Raw JSON.

## 97.4	GUI и сервис

`ApplicationService::migrate_outbound_proxy_settings()` — зеркало
`migrate_outbound_legacy_domain_strategy`: миграция черновика, сброс и пересчёт diff-preview,
строка статуса по исходу. Кнопка доступна на любом ядре — `dialerProxy` понимают и старые.

`outbounds.rs::show_outbound_general_edit`: чекбокс и поля `proxySettings` удалены. При наличии
ключа на диске — строка «proxySettings (on disk): tag …[, transportLayer]», предупреждение и кнопка
«Migrate to sockopt.dialerProxy»; после нажатия — «Migration pending». Чтобы предупреждение не
дублировалось, Freedom-секция и Stream-секция (`outbound_stream.rs`) берут
`outbound_editor_warnings_below_general` — все предупреждения, кроме этого.

## 97.5	Итог

Тесты: `outbound_edit` — 10 (было 6; 4 теста записи `proxySettings` заменены 8 тестами
чтения/миграции: любая не-`null` форма, Save без миграции байт в байт, перенос с сохранением
соседних ключей `sockopt`/`streamSettings`, создание контейнеров, `dialerProxy` побеждает,
удаление без тега, повторная миграция, не-объектный `sockopt`); `warnings` +1 (все протоколы,
`{}`/`null`, граница v26.9.8). Итог: **1345 passed / 0 failed**, clippy lib 66 (без изменений).
Паритет с официальным Xray 26.9.30 (`xray run -test`): `proxySettings: {"tag": …}` и `{}` —
«removed feature», `null` — OK, мигрированные Freedom и VLESS+TLS с `sockopt.dialerProxy` — OK.
GUI в запущенном приложении не проверялся.

# 98	Gate G14: Freedom без `sockopt.addressPortStrategy` (Roadmap §4.2) (0.5.44-0)

## 98.1	Gate и предупреждение — напоминание

Gate (`CompatibilityGateId`, G1–G13 до этого раздела — все inbound) — проверка совместимости,
которая **блокирует** Save/Add: `modify.rs` возвращает `ValidationFailed` с текстом gate, конфиг не
меняется. Предупреждение (`CompatibilityWarningId`) ничего не блокирует и сообщает о том, что уже
лежит на диске. Правило выбора: если редактор Feldjäger может *сам записать* значение, которое ядро
отвергнет, — gate; если такое значение уже есть в конфиге — предупреждение (+ кнопка исправления).

## 98.2	Правило ядра

XTLS/Xray-core#6058 (v26.9.8) добавил в `OutboundDetourConfig.Build()` для `*freedom.Config`:
`AddressPortStrategy != AddressPortStrategy_None` → `freedom outbound does not support
"sockopt.addressPortStrategy"`, Xray не стартует. `SocketConfig.Build()` (`transport_sockopt.go`)
переводит строку через `strings.ToLower` **без trim**: `""` и `none` в любом регистре → `None`,
шесть стратегий `srv*`/`txt*` — стратегии, прочее (в т.ч. `" none"`) — «unsupported address and port
strategy». Проверено `xray run -test`: v26.9.30 отвергает Freedom с `SrvPortOnly` и `" none"`,
принимает `none` / `NONE` / `""` / `null` и VLESS с `SrvPortOnly`; v26.7.28 принимает Freedom с
`SrvPortOnly`. Поэтому G14 — первый gate, **зависящий от версии ядра**.

## 98.3	Реализация

- `core_version.rs`: `CoreFeature::FreedomAddressPortStrategyForbidden` (v26.9.8, #6058).
- `compatibility/mod.rs`: `CompatibilityGateId::G14`; `first_failing_outbound_gate(outbound, core)`
  и `check_outbound_compatibility(outbound, core)` — outbound-аналоги `first_failing_gate` /
  `check_inbound_compatibility`; предикат `freedom_address_port_strategy_set` (Freedom — по
  `protocol` без учёта регистра, как в остальном модуле; строка, не `""` и не `none` без учёта
  регистра; не-строка — ошибка декодирования вне gate) общий с предупреждением.
- `modify.rs`: `AddOutboundShellRequest` / `UpdateOutboundShellRequest` получили `core_version:
  Option<XrayCoreVersion>` (сервис передаёт `xray_core_version()` из Discovery; `None` = текущее
  ядро, как у предупреждений). `check_outbound_compatibility` вызывается в `add_outbound_shell` /
  `update_outbound_shell` после General → Protocol → Stream, на **собранном** outbound — значение,
  оставшееся с диска, тоже блокирует Save (иначе Save записал бы конфиг, который ядро не загрузит).
  Diff-preview идёт через те же функции, поэтому тоже показывает ошибку G14.
- `warnings.rs`: `FreedomAddressPortStrategyRejected`, путь
  `streamSettings.sockopt.addressPortStrategy`, после предупреждений Freedom `settings` (порядок
  конфига), с той же границей версии.
- `outbound_protocol/freedom.rs`: `FreedomSettingsDraft::{address_port_strategy,
  remove_address_port_strategy}` + метод `remove_address_port_strategy()` (по образцу
  `migrate_legacy_domain_strategy`); `apply_freedom_settings` удаляет ключ только по флагу, пустые
  `sockopt` / `streamSettings` — только если опустошены этим удалением.
- Сервис: `remove_outbound_freedom_address_port_strategy()` — черновик + diff-preview. GUI: кнопка
  «Remove addressPortStrategy» в Freedom-секции, пока по черновику есть предупреждение (то есть
  только на ядре, которое отвергает ключ).

Будущий Outbound `sockopt` editor (Roadmap §4.2) получит защиту без доработок: значение из его поля
пройдёт через тот же `check_outbound_compatibility`.

Попутно: текст предупреждения `OpenProxyInbound` (§96) содержал длинные пробелы посреди фраз —
продолжения Rust-строк (`\` + перевод строки) были потеряны при правке через heredoc; восстановлены.

## 98.4	Итог

Тесты (+5): `compatibility` — 2 (значения стратегии и протоколы; граница v26.9.8 и текст ошибки),
`warnings` — 1 (порядок, старое ядро, `None`), `freedom` — 1 (сохранение без удаления, удаление с
сохранением соседних ключей, очистка контейнеров, `none`/пусто), `modify_tests` — 1 (сквозной Save:
блок без версии и на v26.9.30, проход на v26.7.28, проход после удаления). Итог: **1350 passed / 0
failed**, clippy lib 66 (без изменений). GUI в запущенном приложении не проверялся.

# 99	Outbound `sockopt` editor (Roadmap §4.2) (0.5.45-0)

## 99.1	Задача и сверка с ядром

С v26.9.8 (#6058) `sockopt.dialerProxy` — единственный способ цепочки outbound'ов (`proxySettings`
удалён, §97), а редактор Outbound Shell давал только узкое поле `sockopt.domainStrategy` у Freedom.
Сверено с `XTLS/Xray-core@main`:

- `infra/conf/transport_sockopt.go` — `SocketConfig` декодируется Go `encoding/json`: ключи
  сопоставляются **без учёта регистра**, `mark` / `tcpKeepAliveIdle` / `tcpKeepAliveInterval` /
  `tcpMaxSeg` / `tcpUserTimeout` / `tcpWindowClamp` — `int32`, `happyEyeballs.interleave` /
  `maxConcurrentTry` — `uint32` (переполнение — ошибка декодирования, Xray не стартует). Ключ
  перегрузки — `json:"tcpCongestion"` (в документации исторически `tcpcongestion`). `Build()`
  отвергает неизвестные `domainStrategy` / `addressPortStrategy` (сравнение через `ToLower`, пусто —
  умолчание); неизвестный `tproxy` превращается в `off` без ошибки.
- `transport/internet/dialer.go` (`DialSystem`): `domainStrategy` резолвит домен до dial (UseIP* при
  неудаче откатывается к AsIs, ForceIP* — ошибка); `happyEyeballs` работает только для TCP, когда
  стратегия резолвит домен, адресов ≥ 2, `tryDelayMs` > 0, `maxConcurrentTry` > 0 и **нет**
  `dialerProxy`; несуществующий тег `dialerProxy` — ошибка каждого соединения во время работы
  («there is no outbound handler for dialerProxy»), не при загрузке.
- `app/proxyman/outbound/handler.go`: при `dialerProxy` `sendThrough` не применяется.
- Проверки циклов `dialerProxy` в ядре нет: ссылка на себя или петля через другие outbound'ы
  загружается (`xray run -test`: «Configuration OK»), но соединения бесконечно передаются по кругу.

## 99.2	Общая модель (`stream/sockopt.rs`)

- `SockoptDraft::tcpcongestion` → `tcp_congestion` + `tcp_congestion_key: Option<String>`: читается
  любое написание (регистронезависимо, как в Go; при нескольких — каноническое), существующее
  сохраняется, новое пишется как `TCP_CONGESTION_KEY` = `tcpCongestion`; прочие написания при
  дубликатах — в `extras`. `OUTBOUND_ONLY_SOCKOPT_FIELDS` и `KNOWN_SOCKOPT_KEYS` — с каноническим
  именем.
- `validate_sockopt` больше не no-op: диапазоны `int32` / `uint32` и перечисления
  `domainStrategy` / `addressPortStrategy` — ровно то, что отвергает ядро (для inbound тоже: его
  `sockopt` декодируется той же структурой).

## 99.3	Outbound-черновик: слияние вместо перезаписи (`outbound_stream/mod.rs`)

`OutboundStreamDraft` получил `sockopt`, `disk_sockopt` (снимок с диска) и `sockopt_foreign`
(`sockopt` или `streamSettings` — не объект и не `null`: не пишется, редактор недоступен).
`sockopt_changed()` — черновик отличается от снимка. `apply_outbound_stream` пишет `sockopt` только
тогда, и **трёхсторонним слиянием** (`apply_outbound_sockopt`): из `sockopt_to_value(disk)` и
`sockopt_to_value(draft)` берутся ключи с разными значениями, и только они ставятся/удаляются в
текущем объекте. Следствия:

- Protocol-only Save и Save без правок `sockopt` — байт в байт;
- ключи в форме, которую модель не читает (например, `"mark": "255"`), и неизвестные ключи не
  трогаются, если пользователь не менял именно их;
- другой писатель того же объекта в том же Save — миграция `proxySettings` → `dialerProxy` в
  General (§97, выполняется раньше Stream) — не затирается; набранный в редакторе `dialerProxy`
  побеждает мигрированный тег;
- изменённый ключ перегрузки удаляет все написания (`retain` без учёта регистра), иначе Go взял бы
  любое из двух;
- контейнеры создаются для нового ключа и удаляются, только если слияние оставило их пустыми.

`validate_outbound_sockopt(outbound, draft)` — `validate_sockopt` плюс запрет `dialerProxy`, равного
собственному тегу outbound (проверяется только при изменении значения: петля на диске не блокирует
правку других ключей). Это ошибка валидации Feldjäger, не gate: ядро такой конфиг загружает.

`outbound_protocol_uses_sockopt(protocol)` — все протоколы, кроме Blackhole и Loopback (они не
открывают сокет; DNS — да, для upstream-запросов).

`dialer_proxy_problem(own_tag, value, others) -> Option<DialerProxyProblem>` —
`SelfReference` / `UnknownTag` / `Cycle(path)`: проход по `dialerProxy` остальных outbound'ов с
диска; петля только среди других — не наша проблема (`None`), обрыв цепочки дальше первого шага —
тоже.

## 99.4	Freedom и gate G14

Узкое поле `FreedomSettingsDraft::sockopt_domain_strategy` и `apply_sockopt_domain_strategy`
удалены (§2.4 Roadmap: «заменяется этим редактором»): `apply_freedom_settings` больше не трогает
`streamSettings`. Миграция legacy `settings.domainStrategy` —
`migrate_legacy_domain_strategy(&mut SockoptDraft)`: заполняет черновик socket options (сохранение —
через слияние), `settings`-ключи удаляет по-прежнему Freedom-черновик. Поля
`FreedomSettingsDraft::{address_port_strategy, remove_address_port_strategy}` (§98) заменены методом
`OutboundStreamDraft::remove_address_port_strategy()` — очистка поля в черновике; кнопка «Remove
addressPortStrategy» вызывает его. G14 по-прежнему проверяется на **собранном** outbound в
`add/update_outbound_shell`, поэтому `addressPortStrategy`, выбранный в редакторе у Freedom,
блокирует Save на ядре ≥ v26.9.8 без доработок gate.

## 99.5	Сервис и GUI

- `ApplicationService::outbound_dialer_proxy_candidates()` (теги остальных outbound'ов в порядке
  конфига) и `outbound_dialer_proxy_problem()` (по черновику сессии и `dialer_proxy_problem`);
  `migrate_outbound_legacy_domain_strategy` / `remove_outbound_freedom_address_port_strategy`
  работают с `session.stream`.
- `stream_sockopt.rs::show_sockopt_edit(…, dialer_proxy_tags)`: для `StreamDirection::Outbound` в
  начале сетки — `dialerProxy` (теги + свободный текст), `domainStrategy`, `interface`, `mark`,
  `tcpCongestion`, `tcpMptcp`, `addressPortStrategy`; после `customSockopt` — блок `happyEyeballs`
  (чекбокс объекта + четыре поля; пустое поле — умолчание ядра). Inbound передаёт `&[]` и строк не
  видит (`sockopt_field_applies`).
- `outbound_stream.rs::show_outbound_sockopt_edit` — сворачиваемая секция «Socket options
  (streamSettings.sockopt)» в Outbound Shell для `outbound_protocol_uses_sockopt`, открыта, если
  что-то задано; под полями — подсказка `DialerProxyProblem` (красная для ссылки на себя, янтарная
  для неизвестного тега и петли). Узкое поле в Freedom-секции убрано.

## 99.6	Итог

Тесты (+9 новых, −4 удалённых, итого +5): `sockopt` — написания `tcpCongestion` (+ тест
валидации переписан под `SocketConfig.Build()`); `outbound_stream` (+7) — слияние только изменённых ключей (написание, нечитаемые и
неизвестные ключи), создание/удаление контейнеров, валидация и ссылка на себя, чужой `sockopt`,
удаление `addressPortStrategy`, `dialer_proxy_problem`, протоколы; `modify_tests` — сквозной Save:
миграция `proxySettings` + правка `sockopt` в одном Save, приоритет набранного `dialerProxy`, G14
через редактор. Четыре теста Freedom про `sockopt` удалены вместе с полями (их проверки — в
`outbound_stream`), два теста миграции переписаны на черновик `SockoptDraft`. Паритет с локальным
`xray run -test` (Xray 26.9.30): +8 случаев `sockopt` (поля outbound и `tcpcongestion` — OK;
`domainStrategy`, `addressPortStrategy`, `int32`, `uint32` — отказ ядра; `dialerProxy` на себя —
ядро принимает, Feldjäger отвергает). Итог: **1355 passed / 0 failed**, clippy lib 66 (без
изменений). GUI в запущенном приложении не проверялся.

# 100	`sendThrough`: проверка формы по `OutboundDetourConfig.Build()` (Roadmap §4.2) (0.5.46-0)

## 100.1	Правило ядра

`OutboundDetourConfig.Build()` (`infra/conf/xray.go`, `XTLS/Xray-core@main`): `sendThrough` —
`*string`; `ParseSendThough` разбирает часть до первого `/` через `net.ParseAddress` (снимает
`[…]` у IPv6, обрезает пробелы по краям). Без `/` любой домен, кроме **точно** `origin` / `srcip`
(с учётом регистра), — «unable to send through», Xray не стартует; `""` — тоже домен, тоже отказ;
`null` — ключа нет. С `/` проверка домена пропускается, текст после первого `/` уходит в `ViaCidr`, и
`SetOutboundGateway` → `ParseRandomIP` (`app/proxyman/outbound/handler.go`) на каждом соединении
делает `net.ParseCIDR(addr.IP().String() + "/" + prefix)`: домен (`origin/24`, `example.com/24`)
или кривой префикс (`1.2.3.4/abc`, `/33`) загружается, но соединения через outbound падают.
`ParseRandomIP` печатает адрес текстом, поэтому IPv4-mapped IPv6 превращается в IPv4 и префикс
больше 32 у него ломается. При `sockopt.dialerProxy` `sendThrough` не применяется вовсе.

Проверено `xray run -test` (Xray 26.9.30): отказ — `""`, `Origin`, `env:X`, `fe80::1%eth0`, домен;
OK — `origin`, `srcip`, `[2001:db8::1]`, `2001:db8::/64`, `" 1.2.3.4"`, а также `origin/24`,
`example.com/24`, `1.2.3.4/abc`, `10.0.0.0/8/9` (сломаны во время работы).

## 100.2	Реализация

- `outbound_edit/mod.rs::validate_send_through(value)` — пусто (ключ не пишется), IP (IPv6 в
  скобках или без, без зоны), `IP/prefix` (ровно один `/`, префикс — только цифры, 0–32 / 0–128 по
  семейству после `to_canonical`), `origin`, `srcip`. Текст ошибки различает отказ ядра при
  загрузке («unable to send through») и поломку во время работы («every connection … fails»).
- `apply_outbound_general` вызывает её для записываемого значения до любой мутации — Save, Add,
  diff-preview и предупреждения редактора идут через неё. Значение с диска проверяется тоже: поле
  всегда переписывается из черновика (обрезка пробелов), а неверное значение ядро всё равно не
  загрузит или сломается на первом соединении.
- GUI (`outbounds.rs::show_outbound_general_edit`): подсказка к полю описывает четыре формы;
  под полем — та же ошибка вживую (красным) или, при заданном `Socket options → dialerProxy`,
  серая пометка, что `sendThrough` не применяется.

## 100.3	Итог

Тесты (+3): `outbound_edit` — формы (валидные, отказ `Build()`, поломка во время работы) и отказ
`apply_outbound_general` без записи; паритет `send_through_parity_with_xray_run_test` (15 случаев,
`Expect::{Valid, Build, Runtime}` — совпали с Xray 26.9.30). Итог: **1358 passed / 0 failed**,
clippy lib 66 (без изменений). GUI в запущенном приложении не проверялся.

# 101	Outbounds Shell: Loopback (Roadmap §4.2) (0.5.47-0)

## 101.1	Сверка с ядром

`XTLS/Xray-core@main`:

- `infra/conf/loopback.go` — `LoopbackConfig` ровно из двух ключей: `inboundTag` (строка) и
  `sniffing` — тот же `SniffingConfig`, что у inbound (`enabled`, `destOverride`,
  `domainsExcluded`, `ipsExcluded`, `metadataOnly`, `routeOnly`). `SniffingConfig.Build()`
  (`infra/conf/xray.go`) приводит токены `destOverride` к нижнему регистру и принимает `http`,
  `tls` (а также `https`, `ssl`), `quic`, `fakedns` (а также `fakedns+others`); остальное —
  «unknown protocol», Xray не стартует.
- `proxy/loopback/loopback.go` — каждое соединение уходит обратно в dispatcher с `inbound.Tag =
  inboundTag` (копия исходного inbound) и `SkipDNSResolve`; sniffing выполняется заново, только
  если `sniffing.enabled`.
- `app/router/condition.go` — `InboundTagMatcher`: точное сравнение (регистр и пробелы важны),
  пустой тег не совпадает ни с одним правилом; `inboundTag` правила — `StringList` (массив или
  строка, разрезаемая по `,` без обрезки).

`xray run -test` (Xray 26.9.30): `{"inboundTag": "repeat"}`, `{}`, sniffing с `HTTPS` /
`fakedns+others` / `domainsExcluded` — OK; `destOverride: ["smtp"]` и `inboundTag: 5` — отказ.

## 101.2	Модель (`outbound_protocol/loopback.rs`)

- `LoopbackSettingsDraft { inbound_tag, inbound_tag_foreign, sniffing, disk_sniffing,
  sniffing_foreign }`; `OutboundSettingsDraft::Loopback`, `loopback_default()`,
  `protocol_name() = "loopback"`; `is_shell_editable_protocol` включает `loopback` (Edit, Duplicate,
  общий путь записи).
- `inboundTag` хранится и пишется **как набран** (без обрезки — маршрутизация сравнивает точно);
  пусто — ключ удаляется. Не-строка на диске (`inbound_tag_foreign`) не трогается, пока пользователь
  не введёт тег.
- `sniffing` переиспользует inbound-черновик `SniffingSettings` (получил `Eq`) и
  `apply_inbound_sniffing`: функция работает с любым объектом, где лежит ключ `sniffing`, поэтому
  ей передаётся сам `settings`. Пишется только при отличии от снимка `disk_sniffing` — Save без
  правок sniffing байт в байт (иначе `apply_inbound_sniffing` дописал бы явные `false`/`[]`).
  Не-объект на диске (`sniffing_foreign`) не перезаписывается; правка в этом случае — ошибка.
- При записи sniffing сохранённые неизвестные токены `destOverride` проверяются по
  `SniffingConfig.Build()` (`dest_override_known_to_core`: регистронезависимо, с алиасами); токен,
  который ядро отвергнет, блокирует правку sniffing, но не Save, который sniffing не меняет.
- `loopback_routing(routing, own_tag, inbound_tag) -> LoopbackRouting` — `NoTag` / `NoRule` /
  `Rules(indexes)` / `LoopsBack { rule }` (правило с этим `inboundTag` и `outboundTag`, равным
  тегу самого Loopback). Ядро такие конфиги загружает, поэтому это подсказка, а не ошибка.

## 101.3	Сервис и GUI

- `ApplicationService::begin_add_outbound_loopback()`, `outbound_loopback_routing()` (по черновику
  сессии и `routing` с диска), `routing_inbound_tag_candidates()` (теги из `inboundTag` правил, в
  порядке появления, обе формы `StringList`).
- `outbounds.rs`: пункт «Loopback» в «Add Outbound», Edit/Duplicate разрешены для
  `OutboundKind::Loopback`; `show_loopback_settings_edit` — `inboundTag` (теги из routing + текст),
  под ним подсказка `LoopbackRouting` (серым — номера правил, янтарным — нет тега/правила, красным
  — петля), затем `sniffing` общим виджетом и список сохраняемых ключей (`domainsExcluded`, …).
  Секции Stream и Socket options для Loopback не показываются (`outbound_protocol_uses_sockopt`).
- `inbounds.rs`: поля sniffing вынесены из `show_sniffing_edit_session` в
  `pub(crate) show_sniffing_fields(ui, &mut SniffingSettings) -> bool`; inbound-сессия ставит
  `dirty` по её результату — поведение inbound-вкладки не изменилось.
- `summary.rs`: строка таблицы — «Re-route as inbound {tag}[, sniffing]» / «Re-route (no
  inboundTag)» вместо «Summary unavailable».

Попутно: устаревшие после §99 комментарии `outbound_protocol/mod.rs` («Freedom owns
`sockopt.domainStrategy`») и тексты ошибок Duplicate / общего пути записи outbound обновлены.

## 101.4	Итог

Тесты (+8): `loopback` — 6 (Save без правок байт в байт и без обрезки тега; запись тега и
sniffing с сохранением чужих ключей, минимальный sniffing, удаление тега; чужие формы; токены
`destOverride` как в `Build()`; подсказка routing — точное сравнение, обе формы, петля; паритет с
`xray run -test`, 5 случаев), `modify_tests` — 1 (Add → Edit → Duplicate), `tests` — 1 (сводка).
Итог: **1366 passed / 0 failed**, clippy lib 66 (без изменений). GUI в запущенном приложении не
проверялся.

# 102	Outbounds Shell: VLESS — `level`/`email` и конвертация legacy `vnext[]` (Roadmap §4.2) (0.5.48-0)

## 102.1	Сверка с ядром

`XTLS/Xray-core@main`, `infra/conf/vless.go`:

- `VLessOutboundConfig` — плоские ключи `address`, `port`, `level`, `email`, `id`, `flow`, `seed`,
  `encryption`, `reverse`, `testpre`, `testseed` плюс `vnext`. При `c.Address != nil` `Build()`
  сам строит одноэлементный `vnext` и применяет плоские `level`/`email` к `protocol.User`, а
  `id`/`flow`/`encryption`/`testpre`/`testseed`/`reverse` — к `vless.Account`; `vnext` с диска при
  этом **игнорируется**. Иначе `users[0]` разбирается в `protocol.User` и `vless.Account`.
- `vnext` проверяется так: `"address" is not set` и `"users" should have one and only one member`;
  несколько серверов тоже не проходят (`"vnext" should have one and only one member`). Плоская
  форма и `vnext` 1×1 для ядра эквивалентны.
- `seed` объявлен, но не применяется: в `Build()` строка `//account.Seed = c.Seed`
  закомментирована. Редактировать его бессмысленно.

Решение по объёму (согласовано с пользователем): старые ядра, понимающие только `vnext`, не
поддерживаются. Поэтому `vnext` не редактируется на месте, а при Save конвертируется в плоскую форму.

## 102.2	Модель (`outbound_protocol/vless.rs`)

- `VlessOutboundSettings` получил `level: String` (свободный текст, на apply — `u32`, пусто — ключ
  удаляется), `email: String` (пусто — ключ удаляется) и `legacy_vnext: bool`.
- `legacy_vnext_entry(outbound) -> Result<(vnext[0], users[0]), reason>` принимает `vnext` только
  если: ни одного непустого (не-`null`) плоского ключа рядом (`FLAT_KEYS`; `"address": null` ядро
  читает как nil, поэтому не мешает); ровно один сервер и ровно один пользователь; ключи сервера ⊆
  `VNEXT_SERVER_KEYS` (`address`/`port`/`users`), пользователя ⊆ `VNEXT_USER_KEYS`
  (`id`/`flow`/`encryption`/`level`/`email`); `id`/`flow`/`encryption`/`email` — строки. Так
  конвертация гарантированно ничего не теряет. Например, `users[0].testpre` блокирует её, хотя в
  плоской форме такой ключ есть: неочевидно, что ядро читает его из `users[0]` с той же семантикой.
- `parse_vless_outbound_settings` для конвертируемого `vnext` заполняет черновик из
  `vnext[0]`/`users[0]` с `legacy_vnext = true`; для неконвертируемого возвращает `None` (как раньше).
  Публичный `legacy_vnext_blocker(outbound) -> Option<String>` отдаёт причину.
- `apply_vless_outbound_settings` пишет `level` числом и `email`, а при `legacy_vnext` удаляет
  `settings.vnext`. Прочие ключи `settings` (`seed`, `testpre`, `testseed`, неизвестные) и соседи
  outbound не трогаются.

## 102.3	Предупреждение `VlessVnextNotSingle`

`outbound_warnings` → `vless_vnext_not_single`: VLESS без непустого `settings.address`, у которого
`vnext` — массив не из одного элемента (location `settings.vnext`), или у `vnext[0].users` не один
элемент (location `settings.vnext[0].users`). Без версионного гейта: Feldjäger ориентируется на
текущие ядра.

## 102.4	Сервис и GUI

- `ApplicationService::begin_edit_outbound_shell`: если `parse_outbound_settings` вернул `None`, а
  `legacy_vnext_blocker` дал причину, ошибка выглядит так: «Legacy VLESS vnext[] cannot be converted:
  {reason}. Use Raw JSON.» вместо общего «Protocol not supported».
- `outbounds.rs::show_vless_settings_edit`: поля `level` и `email`; при `legacy_vnext` над формой
  курсивом пометка «Save rewrites it into the flat settings form… "Preview changes" shows the
  rewrite». Отдельной кнопки конвертации нет: явное действие — Save, точный diff показывает
  «Preview changes». Обновлены hover у Edit и `docs/ui.md`.

## 102.5	Итог

Тесты (+7): `vless` — 6 (вместо `legacy_vnext_form_is_not_parsed`: разбор конвертируемого `vnext`;
конвертация с сохранением чужих ключей и повторным разбором как плоской формы; 7 блокеров;
`"address": null`; запись/удаление `level`/`email`; невалидный `level`; сохранение
`seed`/`testpre`/`testseed`), `warnings` — 1 (`VlessVnextNotSingle`: 0/2 сервера, 2 пользователя,
плоский `address` побеждает, VMess не затронут). Итог: **1373 passed / 0 failed**, clippy lib 66
(без изменений). GUI в запущенном приложении не проверялся.

# 103	Багфикс: списки «один на строку» теряли набираемый Enter (Roadmap §4.4) (0.5.48-1)

## 103.1	Причина

egui работает в immediate-mode. Поле-список каждый кадр заново собиралось из модели
(`values.join("\n")`), а ввод разбирался через `lines_to_vec`, который отбрасывает пустые строки.
Нажатый в конце Enter давал пустую строку, она выпадала из модели, и на следующем кадре текст
восстанавливался без неё. Курсор оставался на прежней строке, и новую запись можно было начать
только через вставку. В FinalMask это было исправлено ещё на этапе 0.2 (§2.6,
`SourcedTextBuffer`), но остальные страницы по-прежнему пользовались старой идиомой.

## 103.2	Общий виджет (`gui/pages/mod.rs`)

- `persistent_list_text_edit(ui, id, values, add) -> bool` — низкоуровневое ядро. Оно загружает
  буфер `SourcedTextBuffer<Vec<String>>` по `ui.make_persistent_id(id)`, если буфер отрисован из
  того же `values`, иначе берёт `values.join("\n")`. Затем отдаёт текст замыканию `add`, которое
  рисует виджет (`TextEdit` с любыми настройками, `resizable_multiline`, ячейку `Grid`; сам хелпер
  разметки не добавляет). Буфер сохраняется вместе с актуальным `values`. `true` возвращается только
  когда разобранный список отличается от модели, поэтому Enter или пробел в конце строки не помечают
  черновик изменённым.
- `persistent_multiline_list_row` (стандартное поле «label + 2 строки») теперь тонкая обёртка над
  ним. Id буфера (`push_id(id)` → `"list_text"`) не изменился.
- Если модель меняется извне (чекбокс сервиса, Migrate, перемещение правила), буфер сбрасывается:
  сохранённый `source` больше не совпадает с `values`.

## 103.3	Переведённые места

| Страница | Поля |
|---|---|
| Routing | 10 списков правила и балансировщика (локальный `multiline_list_row` удалён), custom protocol values |
| DNS | `domains`, `expectedIPs`, `unexpectedIPs`, `hosts[].targets` (локальный `multiline_list_row` удалён) |
| API Settings | `services` |
| Observatory / BurstObservatory | `subjectSelectors` |
| Outbounds | Freedom `finalRules[].ip`, DNS-outbound `rules[].domain` |
| Inbounds | TLS `certificate`/`key` (PEM, в `resizable_multiline`), REALITY `serverNames`/`shortIds` |
| sockopt | `trustedXForwardedFor` |

Поле custom protocol values в Routing хранит в буфере только нестандартные значения, а не весь
`protocol`. Иначе клик по чекбоксу известного протокола сбрасывал бы набираемый текст. Если в поле
набрать известный протокол (`http`), он, как и раньше, переходит в чекбокс и исчезает из текста.

Буферы правил Outbounds привязаны к индексу (`("freedom_final_rule_ip", idx)`). После Move/Remove
`source` перестаёт совпадать, и буфер сбрасывается, поэтому текст одного правила не попадает в другое.

Копии `lines_to_vec` уже были сведены в одну на этапе 0.4. Прямых вызовов `lines_to_vec` вне
`mod.rs` больше нет.

## 103.4	Итог

Тесты (+1): `list_buffer_is_dropped_when_the_model_changes_elsewhere` — после внешней замены списка
буфер перерисовывается из модели и не сообщает об изменении. Существующий
`list_row_keeps_a_trailing_newline_being_typed` проходит без правок. Итог: **1374 passed / 0
failed**, clippy lib 66 (без изменений). GUI в запущенном приложении не проверялся.

Вне объёма (открытый пункт Roadmap §4.4): однострочные `optional_text_row` (4 копии: Routing,
DNS, Observatory, BurstObservatory) тоже пересобираются из модели и обрезают пробелы (`trim`).
Поэтому набрать пробел в конце поля нельзя, а значит, нельзя и ввести значение с пробелом внутри.

# 104	Pop-up help: окно рядом с курсором с учётом границ (Roadmap §4.4) (0.5.49-0)

## 104.1	Было

`show_help_dialog` (`gui/pages/mod.rs`) создавал `egui::Window` без позиции. egui ставил новое
окно автоматически (`automatic_area_position`) — в левый верхний угол области приложения, далеко
от нажатой кнопки «h». Id окна выводился из заголовка, поэтому повторное открытие той же справки
возвращало окно на прежнее место.

## 104.2	Стало

- `help_button` при клике сохраняет в temp-память не пару `(title, text)`, а `HelpDialog
  { title, text, anchor, placed }`, где `anchor` — позиция указателя в момент клика
  (`interact_pointer_pos`, запасной вариант — правый нижний угол кнопки).
- `help_dialog_left_top(anchor, size, bounds, gap)` — чистая функция, считает каждую ось отдельно:
  1. по умолчанию окно открывается на `gap` = 12 px ниже и правее курсора;
  2. если с этой стороны оно выходит за `bounds`, а с противоположной помещается, — открывается
     левее или выше курсора;
  3. если не помещается ни с одной стороны, прижимается к краю; окно больше области прижимается
     так, чтобы оставались видны левый и верхний край (заголовок и кнопка закрытия).
- `show_help_dialog` задаёт окну стабильный id `("field_help_window", title)` и пока
  `placed == false` вызывает `Window::current_pos`. На первом кадре новое окно проходит невидимый
  sizing pass, и размера ещё нет, поэтому оно ставится в точку «ниже и правее». Как только
  `egui::AreaState::load(id).size` известен, позиция считается по реальному размеру, а флаг
  `placed` поднимается. Дальше позиция не навязывается, поэтому окно можно перетаскивать.
- Границы: `bounds = ctx.content_rect()`, то есть клиентская область окна приложения. egui-окно
  рисуется внутри нативного окна и за него выйти не может. Если окно приложения само частично за
  краем монитора, справка может оказаться в невидимой части. Это редкий случай, его не
  обрабатываем. После установки позиции встроенный `constrain` (по умолчанию `true`) каждый кадр
  удерживает окно в той же области, в том числе после перетаскивания и при уменьшении окна
  приложения.

## 104.3	Итог

Тесты (+3) на `help_dialog_left_top`: по умолчанию ниже и правее курсора; отражение у правого
края, у нижнего края и в углу; прижатие к краю, когда не помещается ни с одной стороны, и окно
шире области. Итог: **1377 passed / 0 failed**, clippy lib 66 (без изменений). GUI в запущенном
приложении не проверялся.

# 105	Язык справки: настройка в Settings и русская справка Inbounds (Roadmap §4.4) (0.5.50-0)

## 105.1	Настройка

- `storage/app_config.rs`: `HelpLanguage { English (по умолчанию), Russian }`, сериализуется как
  `"English"` / `"Russian"`, `ALL` и `native_name()` («English», «Русский»). Поле
  `UiConfig.help_language` с `#[serde(default)]`, поэтому старый `config.json` без поля читается
  как English.
- `ApplicationService::set_help_language` устроен как остальные UI-сеттеры: сохраняет конфиг, только
  если значение изменилось.
- `gui/pages/settings.rs`: страница Settings (раньше заглушка) — раздел Help, ComboBox «Help
  language» и пояснение. Сама страница остаётся на английском.

## 105.2	Механизм

- `gui/pages/mod.rs`: `HelpText { en, ru: Option }` с `const fn en(en)` / `const fn new(en, ru)`
  и `get(language)`; если русского текста нет, `get` возвращает английский.
  `help_button` / `field_label` принимают `HelpText` вместо `&'static str`. Все 228 констант
  `HELP_*` (inbounds 90, sockopt 23, finalmask 77, outbound_stream 38) переведены на этот тип.
- Язык не передаётся параметром через все страницы. `gui/app.rs` раз в кадр вызывает
  `pages::set_help_language(ctx, ui_config().help_language)`, значение лежит в temp-памяти
  egui, а `help_button` / `show_help_dialog` читают его оттуда (`help_language`, по умолчанию
  English). Источник истины — `UiConfig` в `ApplicationService`, в egui только копия на кадр.
- В `HelpDialog` хранится `HelpText`, а не готовая строка, и язык выбирается при отрисовке. Если
  сменить язык при открытом окне справки, текст переключится сразу.
- `HelpChrome` локализует обвязку окна: заголовок «Help — x» / «Справка — x», подсказку кнопки и
  «Close» / «Закрыть». Имена полей Xray (`title`) не переводятся.

## 105.3	Переводы

Русские тексты стоят рядом с английскими в тех же константах (`HelpText::new(en, ru)`), поэтому
при правке одного языка второй виден сразу. Переведено всё, что открывается со страницы Inbounds:
`inbounds.rs` (90), `stream_sockopt.rs` (23) и `stream_finalmask.rs` (77). Два последних
редактора общие, так что их справка по-русски показывается и в Outbounds. Английский текст при
переводе не менялся: подстановку делал скрипт, а не ручная правка. Имена полей, значения и
команды (`inboundTag`, "none", `xray x25519`, tlshello, …) оставлены как есть.

Не переведено: `outbound_stream.rs` (38 текстов, Outbound Shell stream/security) — отдельный
открытый пункт Roadmap §4.4.

## 105.4	Итог

Тесты (+4): `help_language_is_saved_and_defaults_to_english` (сервис: по умолчанию English,
сохранение и повторное чтение `config.json`), `help_text_picks_the_language_and_falls_back_to_english`,
`help_language_defaults_to_english_until_published` и `inbounds_page_help_is_fully_translated`
(через `include_str!` проверяет, что в трёх файлах страницы Inbounds нет `HelpText::en(`).
Итог: **1381 passed / 0 failed**, clippy lib 66 (без изменений). GUI в запущенном приложении не
проверялся.

# 106	Аудит дрейфа: Xray-core v26.9.30 (Roadmap §4.5) (документация, без изменения версии)

## 106.1	Объём

- Релиз: https://github.com/XTLS/Xray-core/compare/v26.9.9...v26.9.30 — 36 коммитов (35 PR и
  коммит релиза), 263 файла, из них 17 в `infra/conf`.
- После релиза: https://github.com/XTLS/Xray-core/compare/v26.9.30...main — 10 коммитов
  (2026-10-05).

Метод: diff `infra/conf/*.go` (json-теги и проверки `Build()`), затем diff самого PR в
`proxy/*`, `transport/*`, `features/*`, `main/commands/*`; для каждого изменения — поиск по коду
Feldjäger. Данные получены через `gh api` 2026-10-07. Документация xtls.github.io не
использовалась: она отстаёт от исходников.

## 106.2	Требует работы

| # | PR | Изменение в ядре | Что затрагивает в Feldjäger |
|---|----|------------------|------------------------------|
| A | #6773, #6853 | TUN inbound: `autoSystemDnsToGateway: bool` и `autoSystemWfpBlockLeak: []string` (`dns` / `misconfigtun`, без учёта регистра; любое другое значение — ошибка `Build()` на всех ОС). Проверки по ОС, где работает Xray: Linux — `autoSystemDnsToGateway` требует непустой `gateway`; Windows — WfpBlockLeak требует `autoSystemRoutingTable`, а `"dns"` требует `dns`. `autoSystemDnsToGateway` в #6773 назывался `autoSystemDNS` — имя не вошло ни в один релиз | Модель и форма TUN (`inbound_protocol/mod.rs`, `gui/pages/inbounds.rs`) не знают новых ключей: они сохраняются как есть, но не редактируются и не проверяются |
| B | #6771 | WireGuard outbound: удалён `domainStrategy` (ключ больше не читается — молча игнорируется); удалён режим `"local"` у `remoteDNS`: каждый элемент теперь разбирается `netip.MustParseAddr`, поэтому не-IP значение (`"local"`, домен) роняет Xray с panic при запуске, а `xray run -test` этого может не поймать | WARP outbound (`xray/warp/parse.rs`) переносит сгенерированный `wgcf-cli` JSON как есть, вместе с `domainStrategy` и `remoteDNS` |
| C | #6815 | FakeDNS: значение по умолчанию `FakeIPv6Pool` — `2001:2::/48` вместо `fc00::/18` (`features/dns/fakedns.go`) | Пресеты пулов в `gui/pages/fakedns.rs` предлагают `fc00::/18` как IPv6-вариант; подписи пресетов не говорят о новом умолчании ядра |
| D | #6847 | `xray api adu` поддерживает Hysteria inbound (`extractInboundUsers`) | Проверить, ограничивает ли Feldjäger live-добавление пользователей протоколами (`app/api_ops.rs`, `app/user_ops.rs`) |
| E | #5645, #6748, #6807, #6810, #6844 | Новые транспорты `network: "xdrive"` (`xdriveSettings`: `remoteFolder`, `service` = `local` / `Google Drive` / `template`, `secrets`, тайминги) и `network: "masque"` (`masqueSettings`: `host`, `path`, `user`, `pass`, `headers`); протокол `masque` для inbound и outbound; транспорт masque допустим только с протоколом masque, masque outbound отвергает `mux.enabled` | Чтение уже безопасно: неизвестная `network` попадает в `other_method` (inbound) / `other_transport` (outbound), `*Settings` сохраняются в extras. Редакторы не делаем — отложено до документации (как Masque в §4.1/§4.2) |

## 106.3	Уже учтено

| PR | Изменение | Где в Feldjäger |
|----|-----------|-----------------|
| #6754 | Транспорты переведены на dialer/listener FinalMask; `udphop` без `sockopt` | `CoreFeature::UdpHopSockoptRemoved` (§67.2), FinalMask этап 1.1 |
| #6718 | xdns: `domains[]` — объекты `{name, lenLimit, labelLimit, types, edns0}`, `resolvers[]` — `{type, addr}` | FinalMask этап 1.3 |
| #6862 | noise `type: "exp"` (сегменты `<b>`, `<r>`, `<rc>`, `<rd>`, `<t>`, `<c>`, `<n>`) | Редактор noise, справка `HELP_NOISE_PACKET` |
| #6808 | udpHop / xicmp: исправлен panic; восстановлено умолчание `interval` (30) | Справка `HELP_UDPHOP_INTERVAL` («Empty or 0 = 30») |
| #7090 (main) | xdns: `names[]`, `addrs[]`, умолчание `types` | Открытый пункт FinalMask этап 1.6 |

## 106.4	Не касается

| PR | Причина |
|----|---------|
| #6743 | Windows `readv`: исправление блокировки — runtime |
| #6747 | TUN: адреса назначения UDP со статистикой трафика — runtime |
| #6756, #6793, #6809 | Обновления зависимостей Go |
| #6778, #6801, #6804, #6852 | WireGuard: panic, память, адрес endpoint, гонки запуска — runtime (generic WireGuard retired; WARP получает исправления с ядром) |
| #6788 | Hysteria outbound: усечение UDP DATAGRAM с ChromeParrot — runtime |
| #6796 | Меньше записей в журнал ошибок — runtime |
| #6811, #6814 | TUN: повторное использование адаптера Wintun, закрытие UDP — runtime |
| #6818, #6821, #6867 | Geodata: префильтр regexp, память матчеров — runtime |
| #6831, #6866 | Shadowsocks 2022: рефакторинг без sing — Shadowsocks retired (§4.1) |
| #6834 | XTLS Vision: подавление внешнего CloseNotify — runtime |
| #6835 | HTTPUpgrade: отправка заголовков Sec-WebSocket-* — редактор retired 2026-10-07 (§4.3), чтение не меняется |
| #6854 | Перенос `PacketConnWrapper` в `common/net` — внутренний рефакторинг |
| b26a91d | Коммит релиза v26.9.30 |
| `http.go`, `socks.go`, `lint.go`, `loader.go`, `transport_method.go` | Из ошибок убран `.AtError()` — текст и условия не меняются |

После релиза (main): #6863 (тесты), #6871 (mux, гонка), #6874 (TUN на Windows без IPv6), #6877
(gRPC client, повторное подключение), #6882 (QUIC sniffer), #7089 (xdns, deadlock и утечки
сокетов) — runtime; #6855, #6856, #6881 — WireGuard inbound / kernelTun (WireGuard retired).

Итого 36 + 10 коммитов: по одному месту в таблицах 106.2–106.4 (#7090 — в 106.3).

## 106.5	Следствия

Пункты A–E заведены в Roadmap §4.5 как дочерние пункты аудита. A–D — код, каждый со своей версией
и разделом Architecture; E — только записи в Roadmap. Изменений кода в этом разделе нет.

# 107	TUN inbound: `autoSystemDnsToGateway` и `autoSystemWfpBlockLeak` (Roadmap §4.5, аудит v26.9.30 A) (0.5.51-0)

## 107.1	Ядро

`infra/conf/tun.go` (v26.9.30; XTLS/Xray-core#6773 добавил `autoSystemDNS`, #6853 до релиза
переименовал его в `autoSystemDnsToGateway` и добавил `autoSystemWfpBlockLeak`):

- `autoSystemDnsToGateway: bool` — Linux: системный DNS направляется на `gateway`. В `Build()` на
  Linux без непустого `gateway` — ошибка `autoSystemDnsToGateway needs gateway to be set`.
- `autoSystemWfpBlockLeak: []string` — Windows Filtering Platform: `dns` / `misconfigtun`, регистр
  не важен. Любое другое значение — ошибка на **любой** ОС. На Windows также нужен
  `autoSystemRoutingTable`, а для `"dns"` — `dns`.

Проверено `xray run -test` (Xray 26.9.30, сборка для Windows): валидный конфиг — OK; `["routes"]` —
`unknown autoSystemWfpBlockLeak value`; без `autoSystemRoutingTable` — ошибка (Windows-ветка);
`autoSystemDnsToGateway` без `gateway` — OK, потому что это Linux-ветка. Linux-проверка
подтверждена только по исходнику.

## 107.2	Реализация

- `inbound_protocol/mod.rs`: в `InboundProtocolDraft::Tun` добавлены `auto_system_dns_to_gateway`
  и `auto_system_wfp_block_leak`, а также `TUN_WFP_BLOCK_LEAK_VALUES`. `true` пишется ключом; при
  `false` ключ удаляется, но явный `false` на диске сохраняется — неизменённый конфиг остаётся байт
  в байт. Список пишется как `gateway`. `validate_tun_settings` зеркалит проверки, которые на
  Linux-сервере роняют загрузку: неизвестное значение и `autoSystemDnsToGateway` без `gateway`.
  Shell Save блокируется. Windows-условия на Linux-сервере не действуют, поэтому их нет в проверках —
  они описаны в справке.
- Аргументы `apply_tun_protocol` собраны в `TunSettings` (10 полей). Заодно снято предупреждение
  clippy `too_many_arguments`: clippy lib 66 → 65.
- `compatibility`: `CoreFeature::TunAutoSystemDnsAndLeakBlock` (v26.9.30, #6853) →
  `RequiresNewerCore` для `true` / непустого списка на старом ядре (старое ядро ключи молча
  отбрасывает). Добавлено предупреждение `TunWfpBlockLeakWindowsOnly`: Feldjäger управляет
  Linux-серверами, а там поле ничего не делает. `tun_warnings` вызывается до проверки
  `streamSettings` (у TUN их нет).
- GUI (`gui/pages/inbounds.rs`): в просмотре и форме TUN появились `autoSystemDnsToGateway`
  (чекбокс) и `autoSystemWfpBlockLeak` (чекбоксы `dns` / `misconfigtun`, пометка «Windows only»).
  Неизвестные значения с диска показываются красным с кнопкой «Remove unknown values». Для
  `autoSystemDnsToGateway` без gateway выводится красная строка. Справка `HELP_TUN_*` на двух
  языках (`HelpText::new`).

## 107.3	Итог

Тесты (+4): `tun_v26_9_30_keys_round_trip_unchanged`,
`tun_dns_to_gateway_false_keeps_an_explicit_false_and_drops_true`,
`tun_validation_mirrors_tun_config_build`, `tun_v26_9_30_keys_warn_on_old_cores_and_wfp_is_windows_only`.
Итог: **1385 passed / 0 failed**, clippy lib 65. GUI в запущенном приложении не проверялся.

# 108	WireGuard / WARP outbound: `domainStrategy` и `remoteDNS` после v26.9.30 (Roadmap §4.5, аудит v26.9.30 B) (0.5.51-1)

## 108.1	Ядро

XTLS/Xray-core#6771 (v26.9.30): из `WireGuardConfig` (`infra/conf/wireguard.go`) удалён
`domainStrategy` — ключ больше не читается, любое значение молча игнорируется. В
`proxy/wireguard/client.go` каждый элемент `remoteDNS` теперь проходит через
`netip.MustParseAddr`, режима `"local"` больше нет. Проверено `xray run -test` (Xray 26.9.30):
`remoteDNS: ["local"]` и `["dns.google"]` — **panic** (`ParseAddr(...): unable to parse IP`),
`["1.1.1.1"]` — OK; `domainStrategy: "ForceIPv4"` и `"nonsense"` — OK (игнорируются).

## 108.2	Реализация

- `CoreFeature::WireGuardRemoteDnsIpOnly` (v26.9.30, #6771).
- `compatibility/warnings.rs`: `is_netip_addr` повторяет `netip.ParseAddr`: IPv4, IPv6, IPv6 с
  `%zone`; без trim, ведущие нули не принимаются. `wireguard_outbound_warnings` (из
  `outbound_warnings`, только при ядре ≥ v26.9.30 или неизвестной версии) выдаёт
  `WireGuardDomainStrategyIgnored` (Caution) для не-`null` `settings.domainStrategy` и
  `WireGuardRemoteDnsNotIp` (**Danger** — ядро не запустится) для каждого строкового
  `settings.remoteDNS[i]`, не являющегося IP. Нестроковый элемент не отмечается: это ошибка
  разбора JSON при загрузке, а не panic. Предупреждения видны в таблице Outbounds (в том числе для
  WARP-outbound, который не редактируется в Shell) и в сводке после Add / Save.
- WARP (`xray/warp/parse.rs`): `parse_generated_xray_value` отвергает сгенерированный `wgcf-cli`
  outbound с не-IP значением в `remoteDNS` (`GeneratedConfigurationInvalid`), поэтому такой outbound
  не записывается и ядро не падает. `outbound_value_with_tag` больше не пишет `domainStrategy`:
  ключ больше не читается ядром. Feldjäger ориентируется на текущие ядра (как в §102).

## 108.3	Итог

Тесты (+4): `netip_addr_matches_go_parse_addr`, `wireguard_outbound_v26_9_30_warnings` (по версиям
ядра и severity), `remote_dns_must_be_ip_addresses`, `outbound_value_with_tag_drops_ignored_domain_strategy`.
Итог: **1389 passed / 0 failed**, clippy lib 65 (без изменений). GUI в запущенном приложении не
проверялся.

# 109	FakeDNS: IPv6-пул по умолчанию `2001:2::/48` (Roadmap §4.5, аудит v26.9.30 C) (0.5.51-2)

XTLS/Xray-core#6815 (v26.9.30) сменил `dns.FakeIPv6Pool` (`features/dns/fakedns.go`) с
`fc00::/18` на `2001:2::/48` — IPv6-диапазон для бенчмарков (RFC 5180), аналог IPv4-умолчания
`198.18.0.0/15` (RFC 2544). Ядро добавляет эти пулы само (`FakeDNSPostProcessingStage`,
`infra/conf/fakedns.go`) только когда в `dns.servers` есть `fakedns`, а секции `fakedns` нет:
оба пула по 32768 адресов, или один на 65535 при `queryStrategy` `UseIPv4` / `UseIPv6`.

Изменения в `gui/pages/fakedns.rs`:
- `2001:2::/48` — первый IPv6-пресет с подписью «default since Xray-core v26.9.30»;
- `fc00::/18` остался, с подписью «default before v26.9.30; unique local range, may overlap a
  private IPv6 network». Это тот же довод, по которому в пресетах нет RFC 1918;
- комментарий к пресетам описывает оба умолчания ядра и условие, при котором ядро их добавляет.

Модель и запись не менялись. Тестовые данные с `fc00::/18` (`fakedns_settings.rs`, `tests.rs`)
используют его как произвольный валидный CIDR, их не трогали.

Тест (+1): `presets_are_valid_pools_and_follow_the_core_defaults` — каждый пресет проходит
`validate_fakedns_settings`, первые пресеты IPv4 и IPv6 совпадают с умолчаниями ядра. Итог:
**1390 passed / 0 failed**, clippy lib 65 (без изменений). GUI в запущенном приложении не
проверялся.

# 110	Аудит v26.9.30: пункты D и E без изменений кода (Roadmap §4.5)

**D — `xray api adu` для Hysteria (XTLS/Xray-core#6847).** Ядро добавило `*hysteria.ServerConfig`
в `extractInboundUsers` (`main/commands/all/api/inbound_user_add.go`). У Feldjäger ограничения
по протоколу нет: `add_inbound_users_request` (`app/api_ops.rs`) передаёт в `adu stdin:` JSON
всего inbound, который пользователь вводит в API Console («Inbound users (live)»). Поэтому с
ядром v26.9.30 добавление пользователей Hysteria работает без изменений. Старое ядро печатает
«unsupported inbound type», и консоль показывает этот вывод.

**E — XDRIVE и MASQUE.** Транспорты `xdrive` (#5645, #6748) и `masque` (#6807, #6810, #6844), а
также протокол `masque` вошли в v26.9.30, но в документации xtls.github.io их по-прежнему нет.
Чтение уже безопасно: неизвестная `network` уходит в `other_method` (inbound) / `other_transport`
(outbound), `masqueSettings` / `xdriveSettings` остаются в extras и пишутся как есть. Записи в
Roadmap: в пункты Masque inbound (§4.1) и Masque outbound (§4.2) добавлен итог аудита, в §4.3
заведён пункт «Stream XDRIVE transport» со статусом «отложено до документации». Версия не
менялась (изменения только в документации).

# 111	Багфикс: VLESS outbound без `encryption` не загружался ядром (Roadmap §4.5) (0.5.51-3)

Найдено при написании справки Outbound Shell (§4.4). `VLessOutboundConfig.Build()`
(`infra/conf/vless.go`) требует `encryption` у каждого пользователя outbound: при отсутствии ключа
или пустой строке — `VLESS users: please add/set "encryption":"none" for every user`. Проверено
`xray run -test` (Xray 26.9.30): без ключа и с `""` — ошибка, с `"none"` — OK. Черновик Feldjäger
создавался с пустым `encryption`, а `apply_vless_outbound_settings` в этом случае ключ не писал.
Поэтому VLESS outbound, добавленный через Add без ручного ввода, ломал загрузку конфига, и Save
падал только на проверке `xray run -test`.

Исправление (`outbound_protocol/vless.rs`): `VlessOutboundSettings::default_draft()` получает
`encryption: "none"`; `apply_vless_outbound_settings` отвергает пустое (после trim) значение с
сообщением, объясняющим, что писать (`"none"` или клиентская строка `xray vlessenc`), и ничего не
записывает. Уже сломанный outbound на диске без `encryption` открывается в Shell как раньше, но
Save требует заполнить поле. Три теста, которые разбирали VLESS outbound без `encryption`
(конфиг, который ядро не загрузит), получили `"encryption": "none"` во входном JSON.

Тест (+1): `default_draft_has_encryption_none_and_empty_encryption_is_refused`. Итог: **1391 passed /
0 failed**.
