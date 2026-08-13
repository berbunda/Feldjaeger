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
- Outbounds
- DNS
- Routing
- Logs
- Service
- Cloudflare WARP
- Settings
Sidebar is always visible.
Sidebar width must be user-resizable.
Sidebar width must persist between application sessions.
Users are not a sidebar entry: open Inbounds, select an inbound, then use the Users tab.

# Content Area
Each page is implemented independently.
Pages must not know about each other.
Pages communicate only through ApplicationService.
When content does not fit the window (non-fullscreen / resized), the content area shows horizontal and vertical scrollbars.

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
- monospaced text view
- privacy notice: Xray logs may contain sensitive connection information.
Deferred on this page: truncation, deletion, rotation, export, analysis.
Log destination / level / DNS / mask editing lives on the separate Log Settings page.

# Log Settings
Page title: Log Settings
Edits the remote Xray top-level `log` object only (not Feldjäger application logs).
Modes: View / Edit with Edit, Save, Cancel.
Sections: Access log, Error log, Additional log entries, Privacy.
Supported fields: `access`, `error`, `loglevel`, `dnsLog`, `maskAddress`.
Unknown nested fields and unsupported values are preserved.
Save uses the shared configuration modification pipeline (summary → backup → write → validate).
After save: show restart/reload notice; invalidate Xray Logs source cache.
Deferred: log rotation, journald/syslog, chmod/mkdir, truncate/delete, auto-restart,
Feldjäger application log settings.

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

# Inbounds
┌──────────────────────────────────────────────┐
│ Tag │ Protocol │ Listen │ Port │ Clients …  │
├──────────────────────────────────────────────┤
│ › vless-in · …                               │
└──────────────────────────────────────────────┘

[ General | Protocol | Stream (disabled) | Security | Sniffing | Users ]

General tab (VLESS / Trojan / Hysteria):
- View / Edit for tag, listen, port (protocol)
- Single "Shell Save" button (saves General + Protocol + Stream + Security + Sniffing together)
- Duplicate tags are hard-blocked on Save
- Port editable only when absent or scalar number/decimal-string

Protocol tab:
- VLESS: decryption field (display)
- Trojan: informational note (no editable fields in IB-L1)
- Hysteria: `settings.version` = 2 (fixed)
- Tunnel: `allowedNetwork` combo, `rewriteAddress`, `rewritePort`, `followRedirect`, `sockopt.tproxy` (combo + free text; shared widget with the Stream-tab Sockopt editor), `userLevel`, `portMap` table (add/edit/delete; target forms `host:port` / `:port` / `host:`); Shell Save writes only `streamSettings.sockopt` for Tunnel — every other `streamSettings`/`security` key stays untouched

Stream tab (Wave A + C1 + C3):
- Editable for tcp/raw | xhttp | grpc | websocket | mkcp | hysteria; exotic methods preserved read-only
- Hysteria protocol locks Stream to hysteria; congestion via `finalmask.quicParams` (congestion / brutalUp / brutalDown)
- Stream/Security method combos are **matrix-filtered** (protocol × security × Vision); illegal editable methods coerce combo display without dirty-on-open
- network vs method key: write preserves the key found on disk
- xhttp: full `xhttpSettings` editor (Wave C3) — path/host/mode + headers rows + padding/SSE/gRPC + sc* ranges (From/To) + placement/obfs + XMUX + one-level `downloadSettings`; documented defaults on method select; Save always writes typed surface; unknown → extras
- xhttp `mode`: combo `auto` | `packet-up` | `stream-one` | `stream-up` (unknown on-disk values preserved)
- Share XHTTP: `path` / optional `host` / `mode` + URL-encoded `extra=` JSON (all advanced fields except host/path/mode)
- FinalMask (VLESS/Trojan; not Hysteria, which owns `finalmask.quicParams`): editor for `streamSettings.finalmask.tcp[]` / `.udp[]` masking-layer chains — per-layer `type` combo (presets + free text for unlisted types) and a `settings` JSON object text area; Add/Remove + Move up/down (layer order is meaningful — first entry is innermost); Reality + non-empty `finalmask.tcp` shows an inline warning and is hard-blocked on Save (G4)
- Sockopt (VLESS/Trojan/Hysteria; method-independent — applies regardless of transport): editor for `streamSettings.sockopt` — tproxy (combo + free text), tcpFastOpen (unset/false/true/custom backlog), acceptProxyProtocol, V6Only, tcpMaxSeg, tcpKeepAliveIdle/Interval, tcpUserTimeout, tcpWindowClamp, trustedXForwardedFor (one per line), customSockopt (raw JSON array); outbound-only fields (mark, domainStrategy, dialerProxy, tcpcongestion, interface, tcpMptcp, addressPortStrategy, happyEyeballs) preserved but not yet editable here
- Tunnel does not use the Stream tab (disabled); it exposes only `sockopt.tproxy` via a narrow field on its own Protocol tab (see above) — the rest of `streamSettings` is preserved untouched on Shell Save

Security tab (VLESS + Trojan + Hysteria):
- VLESS: `none` | `tls` | `reality` (matrix-filtered)
- Trojan: `tls` | `reality` (Add still defaults Reality)
- Hysteria: `tls` required (G10)
- TLS: full `tlsSettings` editor (ALPN / serverName / versions / cipherSuites / fingerprint / curves / ECH / …) + full `certificates[0]` (paths, inline PEM, usage, OCSP, oneTimeLoading, buildChain when usage=issue); `[1+]` preserved; G12 requires non-empty paths
- ALPN: multi-select tags from IANA presets (+ Xray `FromMitM`); unknown on-disk values kept as tags
- Fallbacks present → notify that Security ALPN is required; Save hard-blocked until non-empty (no auto-patch)
- ECH fields collapsed until "Enable ECH" is true; `echSockopt` is raw JSON
- Mode switch strips inactive `tlsSettings` ↔ `realitySettings`
- Unknown `security` wire: open read-only + banner; Save blocked until known mode chosen
- When Reality: "Generate x25519" + "Generate mldsa65" via remote SSH (30s timeout); Reality also has ALPN tags
- Server private key / optional mldsa65Seed; ephemeral public key and verify shown after keygen
- Reality advanced: `show` checkbox, `xver` (0/1/2), `minClientVer` / `maxClientVer` (x.y.z), `maxTimeDiff` (ms), and a collapsible rate-limiting section for `limitFallbackUpload` / `limitFallbackDownload` (`afterBytes` / `bytesPerSec` / `burstBytesPerSec` each)
- Share TLS URI uses typed `serverName`

Sniffing tab:
- enabled, destOverride (http/tls/quic/fakedns), metadataOnly, routeOnly
- Unknown destOverride tokens and sniffing extras preserved
- Saved together with General/Protocol/Security via Shell Save

Share:
- VLESS/Trojan: Reality + **TLS** share URIs
- XHTTP: `type=xhttp` path + optional host/mode + URL-encoded `extra=` (advanced allowlist)
- Hysteria: minimal `hy2://auth@host:port` (+ optional `sni` / `insecure`)

Shell Save / Add safety:
- "Preview changes" shows a redacted structural JSON diff (IB-L5) before write
- After remote write: `xray run -test` (IB-L6); on failure restore backup and surface Status Bar error
- Compatibility gates hard-block illegal combos (incl. Vision + non-tcp on Users mutate, G3; Vision + `security: none`, G13)

Users tab (selected VLESS or Trojan inbound):
┌──────────────────────────────────────────────┐
│ Email │ UUID │ Flow │ Inbound tag │ Source   │  ← VLESS
├──────────────────────────────────────────────┤
│ Email │ Password (masked) │ Tag │ Source     │  ← Trojan
└──────────────────────────────────────────────┘

[Add] [Edit] [Delete]
- Trojan clients: password shown masked; edit dialog allows blank = preserve
- Dirty shell drafts block the Users tab with an inline status reason
- Vision flow on clients narrows Stream method filter (tcp/raw only) after Users mutate succeeds
- Flow combo offers **None** | **xtls-rprx-vision** only; a legacy `xtls-rprx-vision-udp443` (or any other unrecognized value) found on disk opens Edit as None with an inline "Config had unsupported flow `{value}`. Choose an allowed value or None." hint — the original string is preserved until the user explicitly re-picks a value
- Context menu: **Copy share URI** (`vless://` / `trojan://`)
  - Host = Connection page host; port = inbound port
  - Reality requires prior **Generate x25519** (PublicKey kept in session / retained store; never written to inbound JSON)
  - VLESS with non-`none` decryption requires prior **Generate vlessenc** (client encryption half)
  - Disabled button hover explains what is missing
  - QR code deferred

Add Inbound:
- "Add Inbound" button opens Add mode with protocol picker (VLESS | Trojan)
- Empty clients list is allowed on save
- Same Preview changes + post-write `-test` path as Shell Save

Outbounds page (Roadmap §2.4:94, §2.4:95, §2.4:96):
- Table: Tag, Protocol, Send Through, Summary, Source file; context menu Copy tag/protocol
- "Add Outbound" is a menu button with three entries, **Freedom**, **Blackhole**, and **DNS**, each opening the Add editor for that protocol
- Context menu **Edit** — enabled for Freedom, Blackhole, and DNS outbounds only ("Shell editing is available for Freedom, Blackhole, and DNS outbounds only" hover otherwise); **Delete** — any protocol (unchanged, §2.4:97); **Duplicate** — Freedom/Blackhole/DNS only, deep-copies with a unique `{tag}-copy[-N]` tag, fires immediately, no confirm dialog (§2.4:98); **Rename** — any protocol, opens a dialog with the current tag, a routing/balancer reference preview (computed locally before submit), and a text field for the new tag; renaming never blocks on stale references — it applies the rename and reports affected rules/selectors in the status message afterward (§2.4:99)
- Editor (single pane, no tabs — none of the three protocols has Stream/Security/Sniffing/Users); title and Protocol-section label show the active protocol name:
  - General (shared by all three protocols): `tag` (editable on Add only; read-only label on Edit — use the context-menu **Rename** action instead, §2.4:99), `sendThrough`
  - Protocol (Freedom): `domainStrategy` (combo of the same presets as `streamSettings.sockopt.domainStrategy` + free text), `redirect` (`host:port`), `userLevel`
    - `fragment` checkbox toggles a `packets` / `length` / `interval` block (all free-text range strings, e.g. `tlshello`, `100-200`, `10-20`)
    - `noises[]` add/edit/delete table — `type` combo (`rand` | `str` | `hex` | `base64` + free text) / `packet` / `delay`
  - Protocol (Blackhole): `response.type` combo (`none` | `http` + free text); empty = `response` key omitted (Xray default `none`)
  - Protocol (DNS): `rewriteNetwork` combo (`tcp` | `udp` + free text) / `rewriteAddress` / `rewritePort` (1-65535) / `userLevel`; empty rewrite fields = unchanged (Xray leaves the query as-is)
    - `rules[]` ordered list (first match wins) — each entry: `action` combo (`direct` | `hijack` | `drop` | `return` + free text, required) / `qType` (free text — integer, or range/comma-list e.g. `11,13,15-17`) / `rCode` (0-65535, relevant for `return`) / `domain` multi-line box (one domain matcher per line; empty = matches all queries)
    - Add rule / Remove / Move up / Move down per entry — order is meaningful, same convention as the FinalMask layer-list editor
  - Save (Add Outbound / Save) writes via a fingerprint-checked Shell Save on Edit; Cancel discards the session
- Delete dialog unchanged: confirm + "Deletion cannot be undone from the UI (restore from backup if needed)."

Policy page (read-only; §21):
- General information: user policy count, system policy configured; System policy panel (four stats flags); User policies table (Level/Handshake/Connection Idle/Uplink Only/Downlink Only/Stats) with details panel on row select; context menu Copy level / Copy timeout values; Edit/Delete/Duplicate disabled ("Not implemented yet")
- **Wiring consistency (stats ↔ policy ↔ api ↔ metrics)** — a standalone amber warning block, shown above everything else on the page whenever non-empty, independent of the page's own state machine (so it still shows even when the `policy` section itself is missing, e.g. a lone `stats: {}` with nothing configured to collect) (Roadmap §2.5:106):
  - `policy` has a system or user-level stats flag `true` but the top-level `stats` object is missing (nothing will be collected)
  - `stats` is present but no `policy` flag anywhere turns on a statistic (module running, nothing to record)
  - `api.services` includes `StatsService` but `stats` is missing (API will report empty statistics)
  - `api` / `metrics` have no `listen` address and no routing rule forwards an inbound to their outbound tag (`metrics` defaults to tag `Metrics` when unset; `api` has no documented default) — endpoint unreachable
  - Purely informational — computed fresh from the loaded config every time the page model is built; never blocks Save (`stats`/`api`/`metrics` have no editors yet, only this consistency check)

Config Files page (Roadmap §2.5:107):
- Only meaningful for a confdir install (`-confdir <dir>`, multiple `.json` files); a single-file `config.json` install shows an explanatory message and nothing else ("file add/remove only applies to confdir installations")
- Table: File (basename) / Empty (Yes/No) / Contents (human-readable list of sections sourced from that file, e.g. `policy, 2 inbound(s)`, or `—` when empty); context menu Copy path
- **Add file** button opens a dialog with a filename field (hint: must end in `.json`; Xray merges confdir files in lexicographic order, e.g. `10-custom.json`); the new file is written empty (`{}`) — it changes nothing on its own
- Context menu **Remove** — enabled only when the file is already empty (hard-blocked otherwise, hover shows what it still contains); confirm dialog, same "cannot be undone from the UI (restore from backup if needed)" wording as other Delete dialogs
- After either action: "Configuration updated. Xray restart/reload required." — no automatic restart or reload is triggered (use the existing Reload action on the Service page)
