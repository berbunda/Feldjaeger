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

# API Settings (Roadmap §2.1:54)

Page title: API Settings. Placed between BurstObservatory and Log Settings in the sidebar — the
group of top-level root-section editors (Dns, FakeDns, Routing, Policy, Observatory,
BurstObservatory, API Settings, Log Settings), not next to API Console (which is about operating
an already-running Xray, not the config file).
Edits the Xray top-level `api` object only (`tag` / `listen` / `services`) — not related to and
not gating the separate API Console page (Roadmap §3:128), which already reads `api.listen`
directly from the loaded config regardless of how it got there (this page or the Raw JSON escape
hatch).
Modes: View / Edit with Edit, Save, Cancel, Preview changes (redacted structural JSON diff, same
widget as Log Settings / Inbound Shell Preview).
Fields: `tag` and `listen` (single-line, blank = key omitted), `services` (checkboxes for the 5
documented values — HandlerService / LoggerService / StatsService / RoutingService /
ReflectionService — plus a "one per line" text box for unrecognized/future values; both edit the
same list).
The `api` object is not created by opening the page — only by Save, same "enable by saving"
convention as Log Settings.
View mode shows a note when `listen` is empty: the API is then only reachable by routing an
inbound to `tag`, which this page does not wire automatically.
Save uses the shared configuration modification pipeline (summary → backup → write → validate).
After save: show restart/reload notice.

# Log Settings
Page title: Log Settings
Edits the remote Xray top-level `log` object only (not Feldjäger application logs).
Modes: View / Edit with Edit, Save, Cancel.
Sections: Access log, Error log, Additional log entries, Privacy.
Supported fields: `access`, `error`, `loglevel`, `dnsLog`, `maskAddress`.
Unknown nested fields and unsupported values are preserved.
Edit mode shows a typed field-level Change summary plus an optional "Preview changes" button
(redacted structural JSON diff, same widget as Inbound Shell Preview, Roadmap §3:126).
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

Import from Share URI (Roadmap §3:133):
- "Import from Share URI" button next to "Add Inbound" opens a paste-a-link dialog (`vless://` /
  `trojan://` / `hy2://`, `hysteria2://` accepted as an alias on import)
- "Parse" shows a read-only preview (protocol / port / security / transport / credential / flow)
  plus every warning about what a share link can't fully reproduce — REALITY's private key and
  TLS certificate files are never in a client link (confirmed in the generation code), so those
  always need separate setup after import; VLESS post-quantum `encryption` and hy2 `pinSHA256`
  are parsed only to warn they exist, never applied anywhere
- Two ways to apply the preview, picked per import:
  - **Create new inbound** — opens Add Inbound pre-filled from the link (port, transport,
    security mode + fields), same "every field stays freely editable, nothing is final until you
    Save" contract as the existing presets (Roadmap §3:123); for REALITY this also fires
    "Generate x25519" immediately, since the link's own public key can never be reused — a Status
    Bar note repeats the credential to add afterward via the Users tab
  - **Add user to existing inbound** — pick an already-configured inbound of the matching
    protocol from a list; opens that inbound's Add User dialog (VLESS/Trojan/Hysteria) pre-filled
    with the parsed UUID/password/auth, flow, and email — the same dialog Add User already uses,
    just not starting from a blank/freshly-generated draft
- hy2 `obfs=salamander`/`obfs-password` *is* fully reusable (a plain shared secret, not an
  asymmetric key) and is imported into the new inbound's FinalMask UDP layer
- hy2 port-hopping ranges (`443,5000-6000`) import only the first port when creating a new inbound
  — the General tab's port field is scalar-only (Roadmap §3:118); configure the full range via the
  Raw JSON editor afterward if needed

Outbounds page (Roadmap §2.4:94, §2.4:95, §2.4:96):
- Table: Tag, Protocol, Send Through, Summary, Source file; context menu Copy tag/protocol
- "Add Outbound" is a menu button with three entries, **Freedom**, **Blackhole**, and **DNS**, each opening the Add editor for that protocol
- Context menu **Edit** — enabled for Freedom, Blackhole, and DNS outbounds only ("Shell editing is available for Freedom, Blackhole, and DNS outbounds only" hover otherwise); **Delete** — any protocol (unchanged, §2.4:97); **Duplicate** — Freedom/Blackhole/DNS only, deep-copies with a unique `{tag}-copy[-N]` tag; opens a confirm dialog with "Duplicate" / "Preview changes" (redacted JSON diff, Roadmap §3:126) / "Cancel" — no longer fires immediately (§2.4:98); **Rename** — any protocol, opens a dialog with the current tag, a routing/balancer reference preview (computed locally before submit), a text field for the new tag, and a "Preview changes" button (Roadmap §3:126); renaming never blocks on stale references — it applies the rename and reports affected rules/selectors in the status message afterward (§2.4:99); **Raw JSON** — any protocol, escape-hatch editor for the whole outbound object, with its own "Preview changes" button (§3:125, §3:126)
- Editor (single pane, no tabs — none of the three protocols has Stream/Security/Sniffing/Users); title and Protocol-section label show the active protocol name:
  - General (shared by all three protocols): `tag` (editable on Add only; read-only label on Edit — use the context-menu **Rename** action instead, §2.4:99), `sendThrough`
  - Protocol (Freedom): `domainStrategy` (combo of the same presets as `streamSettings.sockopt.domainStrategy` + free text), `redirect` (`host:port`), `userLevel`
    - `fragment` checkbox toggles a `packets` / `length` / `interval` block (all free-text range strings, e.g. `tlshello`, `100-200`, `10-20`)
    - `noises[]` add/edit/delete table — `type` combo (`rand` | `str` | `hex` | `base64` + free text) / `packet` / `delay`
  - Protocol (Blackhole): `response.type` combo (`none` | `http` + free text); empty = `response` key omitted (Xray default `none`)
  - Protocol (DNS): `rewriteNetwork` combo (`tcp` | `udp` + free text) / `rewriteAddress` / `rewritePort` (1-65535) / `userLevel`; empty rewrite fields = unchanged (Xray leaves the query as-is)
    - `rules[]` ordered list (first match wins) — each entry: `action` combo (`direct` | `hijack` | `drop` | `return` + free text, required) / `qType` (free text — integer, or range/comma-list e.g. `11,13,15-17`) / `rCode` (0-65535, relevant for `return`) / `domain` multi-line box (one domain matcher per line; empty = matches all queries)
    - Add rule / Remove / Move up / Move down per entry — order is meaningful, same convention as the FinalMask layer-list editor
  - Save (Add Outbound / Save) writes via a fingerprint-checked Shell Save on Edit; "Preview changes" shows a redacted structural JSON diff before write (Roadmap §3:126, same widget as Inbound Shell Preview); Cancel discards the session
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

Backups page (Roadmap §3:127):
- Lists every current Xray config source file (one row for a single-file install; every confdir member for a confdir install) — not the systemd unit file, which has its own before/after diff on the Service page's Edit unit dialog (Roadmap §3:126) instead
- Per file: "List backups" fetches and shows a table of previously created backups (Created / Size / Restore) — not fetched automatically for every file on page load
- "Restore" opens a confirm dialog: fetches the backup's content, shows a redacted structural JSON diff (same widget as everywhere else, Roadmap §3:126) against the currently loaded copy, then "Restore" / "Cancel"
- Restore goes through the same backup → write → `xray run -test` → restore-on-failure pipeline as every other configuration change — restoring is itself reversible; on success the configuration is fully reloaded (Discover runs again)
- Refused (not silently overwritten) if the remote file changed since the last Discover

# API Console (Roadmap §3:128)

Page title: API Console. Placed right after Service in the sidebar — both are about operating an
already-running Xray, not its configuration file.
Live `xray api` gRPC calls (HandlerService / RoutingService / LoggerService) against the running
Xray process, via `api.listen`. **Nothing here is written to the configuration file** — a
permanent warning banner says so at the top of the page, repeated in the Remove confirm dialog.
Requires `api.listen` configured in the loaded config (no structured editor for the `api` section
yet, §2.1:54 — the page explains how to add it through the Raw JSON escape hatch when absent)
instead of an SSH connection alone.
Header: resolved `api.listen` address, `api.services`, an amber info-warning (not blocking) when
`HandlerService`/`RoutingService`/`LoggerService` is missing from `api.services`.
Sections (collapsed by default): Logger (Restart Logger), Inbounds (live: List / Add JSON / Remove
by tag), Outbounds (live: same shape), Inbound users (live: List / Count / Add JSON / Remove by
email), Routing rules (live: List / Add JSON with Append / Remove by rule tag), Balancer (Info /
Override selection), Source IP block (emergency route-to-outbound for one or more source IPs).
Read-only calls (List/Info/Count) show raw monospaced output, the same treatment as Xray Logs
bodies — not parsed into a table.
Remove actions (inbound/outbound/user/rule) go through a shared confirm dialog restating that the
change is live-only. Add / Override / Source IP block / Restart Logger run immediately, no
confirm — same level as Add Inbound/Outbound Shell.

# Statistics (Roadmap §3:129)

Page title: Statistics. Placed right after API Console in the sidebar — both read the running
Xray process live, via `api.listen`; this one reads `statsquery`/`statssys` specifically instead
of the general HandlerService/RoutingService console. Same precondition as API Console
(`api.listen` configured; the page explains the Raw JSON escape hatch when it's absent) and the
same warn-don't-block treatment for a missing service (`StatsService` here, instead of
Handler/Routing/Logger) — plus any `stats` ↔ `policy` ↔ `api` wiring warnings already computed for
the Policy page (Roadmap §2.5:106), shown here too since they directly explain why a counter might
read "No data yet".

Refresh is manual only — a button per section, never a background timer — every click is one
SSH-exec round trip on the remote host.

**Traffic** section: "Refresh" fetches every counter in one `statsquery` call (no `-pattern`
filter, no `-reset` — a passive dashboard must not zero counters another tool might also be
polling) and groups them client-side by the documented `inbound>>>{tag}>>>traffic>>>{uplink|
downlink}` / `outbound>>>...` naming convention. One row per known inbound/outbound tag × direction
(Inbound tags first, then Outbound), each with the current value, a small sparkline of every
sample fetched so far this session, and — once at least two samples exist with a gap of half a
second or more — an average throughput since the previous sample. A tag with no matching counter
yet (stats collection not enabled for it) still gets a row, showing "No data yet" instead of being
hidden.

**Other counters**: anything from the last response that isn't a known inbound/outbound tag —
per-user (`user>>>{email}>>>...`) counters, or tags no longer in the loaded configuration — listed
verbatim, collapsed by default, not charted.

**System** section: a separate "Refresh" fetches `statssys` (process uptime, goroutine count, GC
cycles/pause time, heap allocation figures) into a small table.

# Metrics (Roadmap §3:130)

Page title: Metrics. Placed right after Statistics in the sidebar. Reads the `metrics` HTTP
endpoint (`/debug/vars` — Go's standard `expvar` JSON dump, **not** a Prometheus scrape target,
despite the roadmap wording; confirmed against the upstream Go source) instead of the gRPC API —
a different Xray config section (`metrics.listen`, not `api.listen`) and a different transport
(SSH-execing `curl`, falling back to `wget` only when curl itself is absent from the remote host,
rather than `xray api <subcommand>`). Same precondition pattern as API Console/Statistics
(`metrics.listen` configured; the page explains the Raw JSON escape hatch when it's absent) plus
the same `stats` ↔ `policy` ↔ `api` ↔ `metrics` wiring warnings shown on the Policy/Statistics
pages (Roadmap §2.5:106). Unlike the `api`/`metrics` general reachability check (which treats a
`tag` routed through an inbound as "reachable"), this page requires a literal `listen` address —
Feldjäger's scrape only ever does a plain HTTP fetch, never acts as an Xray client dialed through
routing.

Refresh is manual only — one button, never a background timer — every click is one SSH-exec round
trip on the remote host.

**Traffic** section: same shape as the Statistics page's Traffic section (grouped by known
inbound/outbound tag × direction, sparkline, throughput, "No data yet" rows) — reconstructed from
the endpoint's nested `stats.{inbound,outbound,user}` object into the same counter-naming
convention, and charted against its own separate sample history (not shared with the Statistics
page, so refreshing one never perturbs the other's charts).

**Observatory** section: live outbound health-check results (alive/dead, delay, last seen/tried,
aggregate ping measurements) — data not available anywhere else in Feldjäger; the read-only
Observatory page (Roadmap §23) only shows static `subjectSelector`/`probeUrl` configuration, never
live probe results. Comes from the same single fetch as Traffic, at no extra SSH round trip.

**Other counters**: same treatment as the Statistics page — counters that don't match a known
inbound/outbound tag, listed verbatim, collapsed by default, not charted.

**Runtime** section: a small subset of Go's default `memstats`/`cmdline` expvars (heap/GC figures,
process argv) — visually similar to the Statistics page's System section but explicitly labelled
as a different, smaller field set from a different source (`statssys` is a custom Xray RPC;
`memstats` is Go's standard library default), so the two are never mistaken for the same data.

# Target Lookup (Roadmap §3:131)

Page title: Target Lookup. Placed at the end of the sidebar, right before Settings — a standalone
utility, not a live-Xray-operations page like its neighbors above. **The only page in Feldjäger
with no SSH precondition** and the only one that reaches the public internet from the operator's
workstation instead of the managed host — a permanent notice on the page says so.

Purpose: an authoring aid for picking or checking a REALITY `dest`, a TLS `serverName`, or a
routing `domain` value — type a domain or IP and see which organization/ASN actually owns it
(Team Cymru whois, `whois.cymru.com:43`), to help judge whether a candidate target is a plausible
camouflage host before wiring it into a config. Forward lookup only (domain/IP → ASN) — not a
reverse "find domains hosted on ASN X" search, which would duplicate mature external tools
(bgp.he.net, Shodan, Censys) and has no comparable lightweight, free, no-signup data source.

Layout: a single text field ("Domain or IP") + "Look up" button; below, once a lookup has run,
"Results for: {host}" followed by a table (Resolved IP / ASN / AS Name / BGP Prefix / Country /
Registry / Allocated) or an error message. An unrouted/private address (Team Cymru reports `NA`)
shows a plain explanatory note instead of blank fields — never a parse error.

## AS-range REALITY candidate scan (Roadmap §3:131 follow-up)

Below the ASN lookup result: "Scan network for REALITY candidates" — probes every host in the
BGP prefix from the result above (capped at 256 addresses) for a valid REALITY `dest`: reverse DNS
+ forward-resolve consistency (the direct fix for RealiTLScanner's classic failure mode — a
certificate SAN domain that doesn't actually resolve back to the IP it was found on), then a
TLS 1.3 handshake checking negotiated ALPN (`h2`/`http/1.1` — `h3` is QUIC/UDP-only and
unobservable over a TCP handshake, out of scope) and key-exchange group (`X25519` or the
post-quantum hybrid `X25519MLKEM768`). Invalid results are never shown — only fully valid rows.

Runs entirely on the local machine, never through the managed SSH host — deliberately, so bulk
scan traffic never originates from the production VPS (an explicit design decision: the point of
running locally instead of via SSH-exec on the server is to keep this traffic off the box actually
running paying Xray service). Enabled only when the current ASN result has a usable BGP prefix.
Mandatory 10-second pause between probes as a courtesy to the network being scanned, independent of
where the scan runs from — implemented as cancellable ~250ms increments so Stop responds quickly
rather than waiting out a full pause.

Progress shown live ("Checked N / capped total"; a note when the prefix is wider than the 256
cap) with a Stop button while running; valid rows stream into a table (IP / Domain / cert-domain /
ALPN / curve) as they're found, not only at the end. The scanned prefix and its results stay shown
even if the user runs a new ASN lookup for a different host mid-scan or afterward — only starting a
new scan replaces them.
