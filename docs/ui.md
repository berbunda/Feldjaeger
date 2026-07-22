Block A: UI Principles
# UI Philosophy
UI framework:
    egui + eframe
    Reason:
    Rust-native, mature enough, cross-platform, simple immediate-mode architecture, good fit for AI-assisted generation.
    Rejected:
    Qt bindings - too heavy and foreign for Rust MVP.
    GTK/Relm4 - better for Linux than Windows.
    Iced/Slint - interesting, but egui is simpler for fast MVP.
    TUI - not primary product; possible future frontend.

# Main Window
Layout:
    Title Bar
    ↓
    Sidebar (resizable)
    ↓
    Content Area
    ↓
    Status Bar

# Sidebar
- Sidebars should be contained next chpates
- Dashboard
- Connection
- Inbounds
- Users
- Outbounds
- DNS
- Routing
- Logs
- Service
- WARP
- Settings
Sidebar is always visible.
Sidebar width must be user-resizable.
Sidebar width must persist between application sessions.

# Content Area
Each page is implemented independently.
Pages must not know about each other.
Pages communicate only through ApplicationService.

# Navigation
No nested sidebars.
No hidden menus.
No more than one level of navigation.

# Dialogs
Confirmation dialogs must only be used for destructive actions.
Delete user
Delete inbound
Overwrite config
Restart Xray

# Tables
Tables support:
- sorting
- filtering
- copy
- context menu
Large configuration tables should display concise summaries.
Detailed configuration is shown only after selecting an item.
  
# Colors
Status:
- Green = Healthy
- Yellow = Warning
- Red = Error
- Gray = Unknown
  
# Icons
Use standard icons.
Avoid decorative icons.
Icons must reinforce meaning, not replace text.

# Preferences
UI preferences must be persisted in the application config file.
The config file may store non-secret UI state only.
Secrets must never be stored in the UI config.

# Notifications
- Success
- Info
- Warning
- Error
Do not interrupt the user unless required.

# Text messages
Use 14pt text size for error text messages and pop-up text messages

# Long operations
SSH
Upload
Download
Restart
Update
Always show progress.

# Empty pages
Instead of blank page show:
No users
No inbounds
No log entries.
No profile

# Xray Logs
Page title: Xray Logs
Shows remote Xray runtime logs only (not Feldjäger application logs).
Layout:
- source selector (Access Log / Error Log / System Journal) with availability status
- source information (type, path or service, status)
- toolbar: line limit, Refresh, Follow / Stop Follow, local search
- monospaced read-only text view (select / copy; no edit)
- privacy notice: Xray logs may contain sensitive connection information.
Deferred: log config editing, log level changes, clear/truncate, export, analysis.

# Keyboard
- Ctrl+C = Copy
- Delete = Delete selected
- F5 = Refresh
- Ctrl+S = Save

# Future
Dark theme
Localization
Accessibility

Block B: Screen Specifications

# General Layout
┌────────────────────────────────────────────┐
│                Title Bar                   │
├───────────────┬────────────────────────────┤
│               │                            │
│   Sidebar     │       Content Area         │
│               │                            │
│               │                            │
│               │                            │
├───────────────┴────────────────────────────┤
│               Status Bar                   │
└────────────────────────────────────────────┘

# Dashboard
┌─────────────────────────────────────┐
│ Server online                       │
│                                     │
│ Xray version     25.7               │
│ SSH status       Connected          │
│ Users            18                 │
│                                     │
│ [Restart] [Reload] [Logs]           │
└─────────────────────────────────────┘

# Users
┌──────────────────────────────────────────────┐
│ Search                                       │
├──────────────────────────────────────────────┤
│ UUID │ Email │ Enabled │ Expire │ Traffic    │
├──────────────────────────────────────────────┤
│ ...                                          │
└──────────────────────────────────────────────┘

[Add]
[Edit]
[Delete]
[Copy VLESS]
