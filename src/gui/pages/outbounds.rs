//! Outbounds page — table of discovered outbound summaries + Delete.
//!
//! Data flows exclusively through [`ApplicationService`] → [`OutboundSummary`].
//! This page never reads JSON or opens SSH directly.

use egui::{Color32, RichText, Sense, Ui};

use super::{HelpText, optional_string_combo};

use crate::app::{
    ApplicationService, BLACKHOLE_RESPONSE_TYPES, DNS_REWRITE_NETWORKS, DNS_RULE_ACTIONS,
    DnsRuleDraft, FREEDOM_DEFAULT_BLOCK_DELAY, FREEDOM_FINAL_RULE_ACTIONS,
    FREEDOM_FINAL_RULE_NETWORKS, FREEDOM_NOISE_TYPES, FREEDOM_PROXY_PROTOCOL_VERSIONS,
    FragmentDraft, FreedomFinalRuleDraft, MISSING_FIELD, MUX_CONCURRENCY_EFFECTIVE_MAX,
    HYSTERIA_OUTBOUND_VERSION, MUX_XUDP_CONCURRENCY_DOCUMENTED_MAX, MUX_XUDP_PROXY_UDP443_VALUES,
    NoiseDraft, OutboundKind,
    OutboundMux, OutboundSettingsDraft, OutboundsPageState, OutboundsSortColumn,
    outbound_row_display, validate_outbound_mux,
};
use crate::xray::{
    CompatibilityWarning, CompatibilityWarningId, OutboundSummary, outbound_protocol_has_transport,
    LoopbackRouting, SHELL_EDITABLE_PROTOCOLS, outbound_protocol_uses_sockopt, validate_send_through,
};

// ─── Field help text (Roadmap §4.4) ──────────────────────────────────────────
//
// Outbound Shell fields, condensed from the official Xray-core docs
// (https://xtls.github.io/config/outbounds/) and checked against `infra/conf/*.go`. Each constant
// backs one `super::field_label(...)` / `super::help_button(...)` call; the Stream / Security /
// Socket options / FinalMask sections carry their own help (`outbound_stream.rs`,
// `stream_sockopt.rs`, `stream_finalmask.rs`).

// General.
const HELP_GENERAL_TAG: HelpText = HelpText::new(
    "Identifier of this outbound. Routing rules (outboundTag), balancers and other outbounds' \
     dialerProxy refer to it, so it must be unique. Fixed after Add — use Rename in the table.",
    "Идентификатор этого outbound. На него ссылаются правила маршрутизации (outboundTag), \
     балансировщики и dialerProxy других outbound, поэтому он должен быть уникальным. После \
     добавления не меняется здесь — используйте Rename в таблице.",
);
const HELP_GENERAL_SEND_THROUGH: HelpText = HelpText::new(
    "Local address outgoing connections are sent from: an IP; IP/prefix — a random address of \
     that range per connection; origin — the local address the client reached the inbound on; \
     srcip — the client's own address. Empty = system default. Not used while Socket options → \
     dialerProxy is set.",
    "Локальный адрес, с которого уходят исходящие подключения: IP; IP/префикс — случайный адрес \
     из диапазона на каждое подключение; origin — локальный адрес, на который клиент пришёл в \
     inbound; srcip — собственный адрес клиента. Пусто — выбор системы. Не используется, пока \
     задан Socket options → dialerProxy.",
);

// Freedom.
const HELP_FREEDOM_REDIRECT: HelpText = HelpText::new(
    "Sends every connection to this host:port instead of its own destination. :port keeps the \
     original address and changes only the port; port 0 keeps the original port. Empty = \
     disabled.",
    "Отправляет каждое подключение на этот host:port вместо исходного адреса назначения. :port \
     сохраняет исходный адрес и меняет только порт; порт 0 сохраняет исходный порт. Пусто — \
     выключено.",
);
const HELP_USER_LEVEL: HelpText = HelpText::new(
    "User level: connections use the local policy (policy.levels) of this level — timeouts, \
     buffer size, statistics. Default 0.",
    "Уровень пользователя: подключения используют локальную политику (policy.levels) этого \
     уровня — таймауты, размер буфера, статистику. По умолчанию 0.",
);
const HELP_FREEDOM_PROXY_PROTOCOL: HelpText = HelpText::new(
    "Sends a PROXY protocol header (v1 or v2) to the target, so a backend behind redirect sees \
     the client's real address. The target must expect it, or the connection breaks. 0 \
     (default) = off.",
    "Отправляет получателю заголовок PROXY protocol (v1 или v2), чтобы сервис за redirect видел \
     реальный адрес клиента. Получатель должен его ожидать, иначе соединение сломается. 0 (по \
     умолчанию) — выключено.",
);
const HELP_FREEDOM_FRAGMENT: HelpText = HelpText::new(
    "Splits what Freedom sends into small pieces, so DPI that needs a whole message (the TLS \
     ClientHello with its SNI) sees only fragments. Applies to TCP only.",
    "Разбивает то, что отправляет Freedom, на мелкие части, чтобы DPI, которому нужно сообщение \
     целиком (TLS ClientHello с его SNI), видел только фрагменты. Действует только для TCP.",
);
const HELP_FREEDOM_FRAGMENT_PACKETS: HelpText = HelpText::new(
    "Which writes to split: tlshello — the TLS ClientHello; FROM-TO (e.g. 1-3) — those writes of \
     the TCP stream, counting from 1.",
    "Какие записи разбивать: tlshello — TLS ClientHello; FROM-TO (например, 1-3) — эти записи \
     TCP-потока, считая с 1.",
);
const HELP_FREEDOM_FRAGMENT_LENGTH: HelpText = HelpText::new(
    "Piece size in bytes: a number or a range such as 100-200 (a random value per piece).",
    "Размер части в байтах: число или диапазон вроде 100-200 (случайное значение для каждой \
     части).",
);
const HELP_FREEDOM_FRAGMENT_INTERVAL: HelpText = HelpText::new(
    "Pause between pieces in milliseconds, a number or a range such as 10-20. With tlshello, 0 \
     sends the fragmented ClientHello in one TCP packet.",
    "Пауза между частями в миллисекундах, число или диапазон вроде 10-20. С tlshello значение 0 \
     отправляет фрагментированный ClientHello одним TCP-пакетом.",
);
const HELP_FREEDOM_NOISES: HelpText = HelpText::new(
    "UDP junk packets sent before the real data to confuse DPI. type: rand — random bytes, \
     packet is the length (N or MIN-MAX); str — the text in packet; hex / base64 — packet \
     decoded. delay — milliseconds to wait after the noise (N or MIN-MAX).",
    "Мусорные UDP-пакеты перед настоящими данными, чтобы запутать DPI. type: rand — случайные \
     байты, packet задаёт длину (N или MIN-MAX); str — текст из packet; hex / base64 — \
     декодированный packet. delay — пауза в миллисекундах после шума (N или MIN-MAX).",
);
const HELP_FREEDOM_FINAL_RULES: HelpText = HelpText::new(
    "Final allow / block filter on the real destination, checked in order before and after \
     dialing; the first matching rule decides. Domain targets are resolved with \
     sockopt.domainStrategy first. Not applied when sockopt.dialerProxy is set.",
    "Итоговый фильтр allow / block по реальному адресу назначения; правила проверяются по порядку \
     до и после подключения, решает первое совпавшее. Доменные адреса сначала разрешаются через \
     sockopt.domainStrategy. Не применяется, когда задан sockopt.dialerProxy.",
);
const HELP_FINAL_RULE_ACTION: HelpText = HelpText::new(
    "allow — let the connection through; block — hold it open for blockDelay seconds, then \
     close it.",
    "allow — пропустить подключение; block — удерживать его blockDelay секунд, затем закрыть.",
);
const HELP_FINAL_RULE_NETWORK: HelpText = HelpText::new(
    "tcp, udp or tcp,udp; (any) = every network.",
    "tcp, udp или tcp,udp; (any) — любая сеть.",
);
const HELP_FINAL_RULE_PORT: HelpText = HelpText::new(
    "Destination port in routing syntax, e.g. 25 or 1000-2000,443; empty = any port.",
    "Порт назначения в синтаксисе маршрутизации, например 25 или 1000-2000,443; пусто — любой \
     порт.",
);
const HELP_FINAL_RULE_BLOCK_DELAY: HelpText = HelpText::new(
    "Seconds a blocked connection is held open before it is closed, a number or a range such as \
     30-90; empty = 30-90.",
    "Сколько секунд заблокированное подключение удерживается перед закрытием, число или диапазон \
     вроде 30-90; пусто — 30-90.",
);
const HELP_FINAL_RULE_IP: HelpText = HelpText::new(
    "Destination addresses in routing syntax, one per line: a CIDR (10.0.0.0/8) or geoip:… \
     (geoip:private); empty = any address.",
    "Адреса назначения в синтаксисе маршрутизации, по одному на строку: CIDR (10.0.0.0/8) или \
     geoip:… (geoip:private); пусто — любой адрес.",
);

// Blackhole.
const HELP_BLACKHOLE_RESPONSE_TYPE: HelpText = HelpText::new(
    "What Blackhole sends before closing; whatever the client sends is discarded. none \
     (default) — close at once; http — a simple HTTP 403 response; custom — the bytes of \
     customResponseData.",
    "Что Blackhole отправляет перед закрытием; всё, что присылает клиент, отбрасывается. none \
     (по умолчанию) — закрыть сразу; http — простой ответ HTTP 403; custom — байты из \
     customResponseData.",
);
const HELP_BLACKHOLE_CUSTOM_DATA: HelpText = HelpText::new(
    "The response bytes for type custom, base64 (standard alphabet). Data that is not valid \
     base64 fails the config load.",
    "Байты ответа для type custom в base64 (стандартный алфавит). Если это не корректный base64, \
     конфиг не загрузится.",
);

// DNS.
const HELP_DNS_REWRITE_NETWORK: HelpText = HelpText::new(
    "Forward the DNS query over tcp or udp; empty = keep the network it arrived on.",
    "Пересылать DNS-запрос по tcp или udp; пусто — оставить сеть, по которой он пришёл.",
);
const HELP_DNS_REWRITE_ADDRESS: HelpText = HelpText::new(
    "DNS server the query is sent to; empty = keep the address the client asked.",
    "DNS-сервер, на который отправляется запрос; пусто — оставить адрес, который запросил клиент.",
);
const HELP_DNS_REWRITE_PORT: HelpText = HelpText::new(
    "Port of that DNS server, 1-65535; empty = keep the original port.",
    "Порт этого DNS-сервера, 1-65535; пусто — оставить исходный порт.",
);
const HELP_DNS_RULES: HelpText = HelpText::new(
    "Checked in order — the first matching rule decides. Without a match, A / AAAA queries go to \
     the built-in DNS module and other types get an empty response with RCODE 0.",
    "Проверяются по порядку — решает первое совпавшее правило. Если совпадения нет, запросы A / \
     AAAA уходят во встроенный DNS-модуль, а остальные типы получают пустой ответ с RCODE 0.",
);
const HELP_DNS_RULE_ACTION: HelpText = HelpText::new(
    "direct — send the query to the target DNS server; hijack — hand it to the built-in DNS \
     module; drop — drop it without an answer; return — answer with rCode.",
    "direct — отправить запрос на целевой DNS-сервер; hijack — передать его встроенному \
     DNS-модулю; drop — отбросить без ответа; return — ответить с кодом rCode.",
);
const HELP_DNS_RULE_QTYPE: HelpText = HelpText::new(
    "Query types to match: a number (1 = A, 28 = AAAA, 65 = HTTPS) or a range / comma list such \
     as 11,13,15-17; empty = any type.",
    "Типы запросов для сопоставления: число (1 = A, 28 = AAAA, 65 = HTTPS) или диапазон / список \
     через запятую вроде 11,13,15-17; пусто — любой тип.",
);
const HELP_DNS_RULE_RCODE: HelpText = HelpText::new(
    "DNS response code for action return, 0–65535 (0 = NOERROR, 3 = NXDOMAIN). Ignored by the \
     other actions.",
    "Код ответа DNS для action return, 0–65535 (0 = NOERROR, 3 = NXDOMAIN). Другие действия его \
     игнорируют.",
);
const HELP_DNS_RULE_DOMAIN: HelpText = HelpText::new(
    "Query names in routing syntax, one per line (domain:, full:, regexp:, keyword:, geosite:…); \
     empty = every query.",
    "Имена запросов в синтаксисе маршрутизации, по одному на строку (domain:, full:, regexp:, \
     keyword:, geosite:…); пусто — все запросы.",
);

// Loopback.
const HELP_LOOPBACK_INBOUND_TAG: HelpText = HelpText::new(
    "The inbound tag the traffic re-enters routing with: rules whose inboundTag lists it decide \
     where it goes next. Matched exactly (case and spaces count); it does not have to be the tag \
     of a real inbound.",
    "Тег inbound, с которым трафик снова попадает в маршрутизацию: куда он пойдёт дальше, решают \
     правила, в inboundTag которых он указан. Сравнивается точно (регистр и пробелы важны); \
     настоящего inbound с таким тегом может и не быть.",
);
const HELP_LOOPBACK_SNIFFING: HelpText = HelpText::new(
    "settings.sniffing — sniff the re-injected traffic again (e.g. TLS SNI after a decrypting \
     outbound); runs only when enabled.",
    "settings.sniffing — повторно анализировать возвращённый трафик (например, TLS SNI после \
     расшифровывающего outbound); работает, только если включено.",
);

// VLESS.
const HELP_VLESS_ADDRESS: HelpText = HelpText::new(
    "Server this outbound dials: an IP or a domain (required).",
    "Сервер, к которому подключается этот outbound: IP или домен (обязательно).",
);
const HELP_VLESS_PORT: HelpText = HelpText::new(
    "Server port, 1-65535 (required).",
    "Порт сервера, 1-65535 (обязательно).",
);
const HELP_VLESS_ID: HelpText = HelpText::new(
    "User ID: the UUID of one of the server's clients[] (required). Generate makes a new random \
     UUID — add the same one to the server.",
    "ID пользователя: UUID одного из clients[] сервера (обязательно). Generate создаёт новый \
     случайный UUID — добавьте его же на сервер.",
);
const HELP_VLESS_FLOW: HelpText = HelpText::new(
    "Flow control, e.g. xtls-rprx-vision; must match the server's client entry. Empty = key \
     absent (no flow).",
    "Управление потоком, например xtls-rprx-vision; должно совпадать с записью клиента на \
     сервере. Пусто — ключа нет (без flow).",
);
const HELP_VLESS_ENCRYPTION: HelpText = HelpText::new(
    "Required. none — no VLESS Encryption (the server's decryption is none); otherwise the client \
     half of the server's decryption, printed by xray vlessenc. Xray-core refuses an empty value.",
    "Обязательно. none — без VLESS Encryption (decryption сервера — none); иначе клиентская \
     половина decryption сервера, которую выводит xray vlessenc. Пустое значение Xray-core \
     отвергает.",
);
const HELP_VLESS_LEVEL: HelpText = HelpText::new(
    "User level: index into policy.levels (timeouts, buffer size); empty = key absent (level 0).",
    "Уровень пользователя: индекс в policy.levels (таймауты, размер буфера); пусто — ключа нет \
     (уровень 0).",
);
const HELP_VLESS_EMAIL: HelpText = HelpText::new(
    "User label in logs and statistics; empty = key absent.",
    "Метка пользователя в журналах и статистике; пусто — ключа нет.",
);

// Mux (Roadmap §4.2). Behaviour from Xray-core v26.9.30 (`MuxConfig`,
// `app/proxyman/outbound/handler.go`) and live runs of xray.exe 26.9.30.
const HELP_MUX: HelpText = HelpText::new(
    "Mux carries many client connections inside one connection to the server, saving handshakes \
     (TCP), and XUDP tunnels UDP the same way. The server needs nothing extra: any Xray inbound \
     that forwards traffic serves Mux. Only proxy outbounds can use it — Freedom and Loopback \
     break with Mux on. With a VLESS xtls-rprx-vision flow, TCP through Mux fails (the server \
     drops such connections): set concurrency to -1 and use xudpConcurrency for UDP.",
    "Mux передаёт много клиентских соединений внутри одного соединения с сервером и экономит \
     рукопожатия (TCP), а XUDP так же туннелирует UDP. Серверу ничего настраивать не нужно: Mux \
     обслуживает любой inbound Xray, который пересылает трафик. Использовать его может только \
     прокси-outbound — Freedom и Loopback с включённым Mux перестают работать. С flow VLESS \
     xtls-rprx-vision TCP через Mux не проходит (сервер обрывает такие соединения): поставьте \
     concurrency -1, а для UDP используйте xudpConcurrency.",
);
const HELP_MUX_ENABLED: HelpText = HelpText::new(
    "Turns Mux on. Off, the other values are kept but unused; xudpProxyUDP443 is still checked \
     when Xray loads the config.",
    "Включает Mux. Когда выключен, остальные значения сохраняются, но не действуют; \
     xudpProxyUDP443 всё равно проверяется при загрузке конфигурации.",
);
const HELP_MUX_CONCURRENCY: HelpText = HelpText::new(
    "How many TCP connections share one Mux connection. Empty or 0 = 8; from 1 to 128 — more acts \
     as 128 (a connection is reused at most 128 times); -1 = TCP is not carried by Mux (only UDP \
     via XUDP, when xudpConcurrency is set). Must be a whole number from -32768 to 32767, or \
     Xray does not load the config.",
    "Сколько TCP-соединений делят одно Mux-соединение. Пусто или 0 — 8; от 1 до 128 — большее \
     значение работает как 128 (соединение переиспользуется не больше 128 раз); -1 — TCP не идёт \
     через Mux (только UDP через XUDP, если задан xudpConcurrency). Целое число от -32768 до \
     32767, иначе Xray не загрузит конфигурацию.",
);
const HELP_MUX_XUDP_CONCURRENCY: HelpText = HelpText::new(
    "UDP over Mux. Empty or 0 = UDP rides the same Mux connections as TCP; 1 to 1024 = a separate \
     XUDP tunnel with that many UDP sessions per connection; -1 = UDP is not carried by Mux and \
     uses the protocol's own UDP (UDP over TCP for VLESS).",
    "UDP через Mux. Пусто или 0 — UDP идёт по тем же Mux-соединениям, что и TCP; от 1 до 1024 — \
     отдельный туннель XUDP с таким числом UDP-сессий на соединение; -1 — UDP не идёт через Mux, \
     а использует собственный UDP протокола (для VLESS — UDP поверх TCP).",
);
const HELP_MUX_XUDP_PROXY_UDP443: HelpText = HelpText::new(
    "UDP to port 443 (QUIC) while Mux is on. reject (default, empty) — refused, browsers fall back \
     to TCP HTTP/2; allow — carried by Mux; skip — not carried by Mux, the protocol's own UDP is \
     used. Exactly these lowercase words: Xray refuses anything else, even with Mux off.",
    "UDP на порт 443 (QUIC) при включённом Mux. reject (по умолчанию, пусто) — отклоняется, \
     браузеры переходят на TCP HTTP/2; allow — идёт через Mux; skip — не идёт через Mux, \
     используется собственный UDP протокола. Только эти слова в нижнем регистре: иное Xray \
     отвергает, даже при выключенном Mux.",
);

// Trojan (Roadmap §4.2), checked with `xray run -test` 26.9.30 (`infra/conf/trojan.go`).
const HELP_TROJAN: HelpText = HelpText::new(
    "Client of a Trojan server: password authentication inside TLS. Xray-core still supports it \
     but logs on every start that Trojan is deprecated in favour of VLESS. To a public address it \
     needs Security tls or reality (Xray refuses plain Trojan except to private addresses). The \
     removed flow setting cannot be used — for XTLS Vision use VLESS.",
    "Клиент сервера Trojan: аутентификация паролем внутри TLS. Xray-core его поддерживает, но при \
     каждом запуске пишет в журнал, что Trojan устарел и вместо него рекомендуется VLESS. К \
     публичному адресу нужен Security tls или reality (простой Trojan Xray разрешает только к \
     приватным адресам). Удалённую настройку flow использовать нельзя — для XTLS Vision \
     используйте VLESS.",
);
const HELP_TROJAN_ADDRESS: HelpText = HelpText::new(
    "Server address: IPv4, IPv6 or domain name. Required.",
    "Адрес сервера: IPv4, IPv6 или доменное имя. Обязательно.",
);
const HELP_TROJAN_PORT: HelpText = HelpText::new(
    "Server port, 1–65535, usually the port the server's Trojan inbound listens on. Required; \
     written as a number (Xray refuses a quoted port here).",
    "Порт сервера, 1–65535, обычно порт, который слушает Trojan inbound сервера. Обязательно; \
     записывается числом (порт в кавычках Xray здесь отвергает).",
);
const HELP_TROJAN_PASSWORD: HelpText = HelpText::new(
    "The password of one of the server's clients[]. Required. Kept exactly as typed — spaces \
     count, the server compares it byte for byte.",
    "Пароль одного из clients[] сервера. Обязательно. Сохраняется точно как набран — пробелы \
     учитываются, сервер сравнивает его побайтно.",
);
const HELP_TROJAN_LEVEL: HelpText = HelpText::new(
    "User level: index into policy.levels (timeouts, buffer size), 0–255; empty = key absent \
     (level 0). Xray refuses a larger number.",
    "Уровень пользователя: индекс в policy.levels (таймауты, размер буфера), 0–255; пусто — \
     ключа нет (уровень 0). Большее число Xray отвергает.",
);
const HELP_TROJAN_EMAIL: HelpText = HelpText::new(
    "User label in logs and statistics on this side; empty = key absent.",
    "Метка пользователя в журналах и статистике на этой стороне; пусто — ключа нет.",
);

// Hysteria (Roadmap §4.2), checked with `xray run -test` 26.9.30 (`infra/conf/hysteria.go`) and a
// live client / server pair.
const HELP_HYSTERIA_ADDRESS: HelpText = HelpText::new(
    "Server address: IPv4, IPv6 or domain name. Required.",
    "Адрес сервера: IPv4, IPv6 или доменное имя. Обязательно.",
);
const HELP_HYSTERIA_PORT: HelpText = HelpText::new(
    "Server UDP port, one number 1–65535 (Xray refuses a range here). For port hopping add the \
     udphop mask under Stream / Security → FinalMask.",
    "UDP-порт сервера, одно число 1–65535 (диапазон Xray здесь отвергает). Для смены портов \
     (port hopping) добавьте маску udphop в Stream / Security → FinalMask.",
);
const HELP_HYSTERIA_VERSION: HelpText = HelpText::new(
    "Protocol version. Xray-core supports only Hysteria 2 and refuses the config otherwise, so \
     Save always writes 2. The password, the hysteria transport and TLS (required — QUIC does not \
     work without it) are set under Stream / Security.",
    "Версия протокола. Xray-core поддерживает только Hysteria 2 и иначе отвергает конфигурацию, \
     поэтому Save всегда пишет 2. Пароль, транспорт hysteria и TLS (обязателен — QUIC без него \
     не работает) задаются в Stream / Security.",
);

// SOCKS (Roadmap §4.2), checked with `xray run -test` 26.9.30 (`infra/conf/socks.go`).
const HELP_SOCKS: HelpText = HelpText::new(
    "Sends traffic on to a SOCKS5 proxy. Kept for one server-side use: chaining to a proxy on \
     this server or a private network, e.g. Tor at 127.0.0.1:9050 (route .onion domains here). \
     SOCKS has no encryption — the user name, password and traffic travel in the clear — so do \
     not point it at a public address.",
    "Передаёт трафик дальше на SOCKS5-прокси. Оставлен для одного серверного сценария: цепочка на \
     прокси на этом сервере или в частной сети, например Tor на 127.0.0.1:9050 (сюда направляют \
     домены .onion). SOCKS ничего не шифрует — имя, пароль и трафик идут открыто, — поэтому не \
     указывайте публичный адрес.",
);
const HELP_SOCKS_ADDRESS: HelpText = HelpText::new(
    "Address of the SOCKS server: IP or domain name. Required.",
    "Адрес SOCKS-сервера: IP или доменное имя. Обязательно.",
);
const HELP_SOCKS_PORT: HelpText = HelpText::new(
    "Port of the SOCKS server, 1–65535 (Tor: 9050). Required; written as a number.",
    "Порт SOCKS-сервера, 1–65535 (Tor: 9050). Обязательно; записывается числом.",
);
const HELP_SOCKS_USER: HelpText = HelpText::new(
    "User name, only if the server requires authentication; empty = no authentication. Kept \
     exactly as typed.",
    "Имя пользователя — только если сервер требует аутентификацию; пусто — без аутентификации. \
     Сохраняется точно как набрано.",
);
const HELP_SOCKS_PASS: HelpText = HelpText::new(
    "Password for the user. Without a user Xray-core ignores it. Kept exactly as typed.",
    "Пароль пользователя. Без имени пользователя Xray-core его игнорирует. Сохраняется точно как \
     набран.",
);
const HELP_SOCKS_LEVEL: HelpText = HelpText::new(
    "User level: index into policy.levels; used only with a user; empty = key absent (level 0).",
    "Уровень пользователя: индекс в policy.levels; действует только вместе с именем \
     пользователя; пусто — ключа нет (уровень 0).",
);
const HELP_SOCKS_EMAIL: HelpText = HelpText::new(
    "User label in logs and statistics; used only with a user; empty = key absent.",
    "Метка пользователя в журналах и статистике; действует только вместе с именем пользователя; \
     пусто — ключа нет.",
);

/// Renders the Outbounds page.
pub fn show(ui: &mut Ui, service: &mut ApplicationService) {
    service.tick_outbounds_page_status();
    show_delete_outbound_dialog(ui, service);
    show_duplicate_outbound_dialog(ui, service);
    show_rename_outbound_dialog(ui, service);
    show_raw_json_outbound_dialog(ui, service);
    // The "h" buttons of the Outbound Shell and its Stream / Security / Socket options / FinalMask
    // sections open their pop-up here.
    super::show_help_dialog(ui);

    ui.heading("Outbounds");
    ui.add_space(8.0);

    let model = service.outbounds_page_model();

    match model.state {
        OutboundsPageState::NoSshConnection
        | OutboundsPageState::XrayNotDiscovered
        | OutboundsPageState::ConfigurationNotLoaded => {
            show_state_message(ui, model.state);
            return;
        }
        OutboundsPageState::NoOutbounds => {
            // Configuration is loaded — the outbound list is just empty (e.g. a freshly
            // created config). Show the hint but fall through so the "Add Outbound" menu
            // below stays reachable.
            show_state_message(ui, model.state);
            ui.add_space(8.0);
        }
        OutboundsPageState::ConfigurationContainsWarnings => {
            show_state_message(ui, model.state);
            for warning in &model.warnings {
                ui.label(
                    RichText::new(warning.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            ui.add_space(8.0);
            if model.rows.is_empty() {
                // Still fall through to the Add menu — an empty list plus warnings must
                // not lock the user out of creating the first outbound.
                ui.label(RichText::new("No outbounds").size(14.0));
            }
        }
        OutboundsPageState::ConfigurationLoaded => {}
    }

    // Table header with Add button (Freedom, Blackhole; Roadmap §2.4:94, §2.4:95).
    ui.horizontal(|ui| {
        ui.strong("Outbounds");
        ui.add_space(12.0);
        let busy = service.is_outbound_mutation_busy();
        let adding = service.outbound_editor_session().is_some_and(|s| s.is_add);
        ui.add_enabled_ui(!adding && !busy, |ui| {
            ui.menu_button("Add Outbound", |ui| {
                if ui.button("Freedom").clicked() {
                    if let Err(e) = service.begin_add_outbound_freedom() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui.button("Blackhole").clicked() {
                    if let Err(e) = service.begin_add_outbound_blackhole() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui.button("DNS").clicked() {
                    if let Err(e) = service.begin_add_outbound_dns() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui
                    .button("Loopback")
                    .on_hover_text(
                        "Sends traffic back into routing as if it came from an inbound with the \
                         chosen tag — https://xtls.github.io/en/config/outbounds/loopback.html",
                    )
                    .clicked()
                {
                    if let Err(e) = service.begin_add_outbound_loopback() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui
                    .button("VLESS")
                    .on_hover_text(
                        "Bridge side of VLESS-native reverse proxy, or a plain forward outbound \
                         — https://xtls.github.io/en/document/level-2/vless_reverse.html",
                    )
                    .clicked()
                {
                    if let Err(e) = service.begin_add_outbound_vless() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui
                    .button("Trojan")
                    .on_hover_text(
                        "Client of a Trojan server — https://xtls.github.io/en/config/outbounds/trojan.html",
                    )
                    .clicked()
                {
                    if let Err(e) = service.begin_add_outbound_trojan() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui
                    .button("Hysteria")
                    .on_hover_text(
                        "Client of a Hysteria 2 server (QUIC) — https://xtls.github.io/en/config/outbounds/hysteria.html",
                    )
                    .clicked()
                {
                    if let Err(e) = service.begin_add_outbound_hysteria() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
                if ui
                    .button("SOCKS")
                    .on_hover_text(
                        "Chain to a SOCKS proxy, e.g. Tor on this server — \
                         https://xtls.github.io/en/config/outbounds/socks.html",
                    )
                    .clicked()
                {
                    if let Err(e) = service.begin_add_outbound_socks() {
                        service.show_status_message(e);
                    }
                    ui.close();
                }
            });
        });
    });
    ui.add_space(4.0);

    show_table(ui, service, &model.rows);
    ui.add_space(12.0);

    if service.outbound_editor_session().is_some() {
        show_outbound_editor_pane(ui, service);
    }
}

fn show_state_message(ui: &mut Ui, state: OutboundsPageState) {
    let color = match state {
        OutboundsPageState::ConfigurationContainsWarnings => Color32::from_rgb(210, 170, 40),
        OutboundsPageState::NoOutbounds => Color32::from_rgb(140, 140, 140),
        _ => Color32::from_rgb(200, 60, 60),
    };
    ui.label(RichText::new(state.message()).size(14.0).color(color));
}

fn show_table(ui: &mut Ui, service: &mut ApplicationService, rows: &[OutboundSummary]) {
    let sort = service.outbounds_sort();

    egui::Grid::new("outbounds_table")
        .num_columns(5)
        .striped(true)
        .spacing([16.0, 6.0])
        .min_col_width(72.0)
        .show(ui, |ui| {
            sortable_header(ui, service, "Tag", OutboundsSortColumn::Tag, sort.column);
            sortable_header(
                ui,
                service,
                "Protocol",
                OutboundsSortColumn::Protocol,
                sort.column,
            );
            ui.strong("Send Through");
            ui.strong("Summary");
            ui.strong("Source file");
            ui.end_row();

            for row in rows {
                let display = outbound_row_display(row);
                cell_with_menu(ui, service, row, &display.tag);
                cell_with_menu(ui, service, row, &display.protocol);
                cell_with_menu(ui, service, row, &display.send_through);
                cell_with_menu(ui, service, row, &display.summary);
                cell_with_menu(ui, service, row, display.source_file);
                ui.end_row();
            }
        });
}

fn sortable_header(
    ui: &mut Ui,
    service: &mut ApplicationService,
    label: &str,
    column: OutboundsSortColumn,
    active: OutboundsSortColumn,
) {
    let sort = service.outbounds_sort();
    let marker = if active == column {
        if sort.ascending {
            " ▲"
        } else {
            " ▼"
        }
    } else {
        ""
    };
    let text = format!("{label}{marker}");
    if ui
        .add(egui::Label::new(RichText::new(text).strong()).sense(Sense::click()))
        .clicked()
    {
        service.set_outbounds_sort_column(column);
    }
}

fn cell_with_menu(ui: &mut Ui, service: &mut ApplicationService, row: &OutboundSummary, text: &str) {
    let response = ui.add(egui::Label::new(text).sense(Sense::click()));
    show_outbound_context_menu(&response, service, row);
}

fn show_outbound_context_menu(
    response: &egui::Response,
    service: &mut ApplicationService,
    row: &OutboundSummary,
) {
    response.context_menu(|ui| {
        if ui.button("Copy tag").clicked() {
            let text = row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }
        if ui.button("Copy protocol").clicked() {
            let text = row
                .protocol
                .clone()
                .unwrap_or_else(|| MISSING_FIELD.to_owned());
            ui.ctx().copy_text(text);
            ui.close();
        }

        ui.separator();

        let busy = service.is_outbound_mutation_busy();
        let edit_ok = is_shell_kind(row.kind());
        if ui
            .add_enabled(edit_ok && !busy, egui::Button::new("Edit"))
            .on_disabled_hover_text(format!(
                "Shell editing is available for {SHELL_EDITABLE_PROTOCOLS} outbounds only — a legacy VLESS \
                 vnext[] / Trojan servers[] outbound opens only when it has one server (with one \
                 user) (Save converts it to the flat form); any other must be edited via Raw JSON",
            ))
            .clicked()
        {
            if let Err(e) = service.begin_edit_outbound_shell(row.index) {
                service.show_status_message(e);
            }
            ui.close();
        }

        if ui
            .add_enabled(!busy, egui::Button::new("Delete"))
            .on_disabled_hover_text("Delete requires an idle connection")
            .clicked()
        {
            set_pending_outbound_delete(
                ui,
                PendingOutboundDelete {
                    index: row.index,
                    tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    protocol: row
                        .protocol
                        .clone()
                        .unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    error: None,
                },
            );
            ui.close();
        }

        let duplicate_ok = is_shell_kind(row.kind());
        if ui
            .add_enabled(duplicate_ok && !busy, egui::Button::new("Duplicate"))
            .on_disabled_hover_text(format!("Duplicate is available for {SHELL_EDITABLE_PROTOCOLS} outbounds only"))
            .clicked()
        {
            set_pending_outbound_duplicate(
                ui,
                PendingOutboundDuplicate {
                    index: row.index,
                    tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                    error: None,
                    diff_preview: None,
                },
            );
            ui.close();
        }

        if ui
            .add_enabled(!busy, egui::Button::new("Rename"))
            .on_disabled_hover_text("Rename requires an idle connection")
            .clicked()
        {
            let current_tag = row.tag.clone().unwrap_or_default();
            set_pending_outbound_rename(
                ui,
                PendingOutboundRename {
                    index: row.index,
                    current_tag: current_tag.clone(),
                    draft: current_tag,
                    references: service.outbound_tag_reference_preview(row.index),
                    error: None,
                    diff_preview: None,
                },
            );
            ui.close();
        }

        // Raw JSON escape hatch (Roadmap §3:125) — any protocol, incl. ones with no Edit above.
        if ui
            .add_enabled(!busy, egui::Button::new("Raw JSON"))
            .on_disabled_hover_text("Raw JSON requires an idle connection")
            .clicked()
        {
            if let Some((text, expected_fingerprint)) = service.outbound_raw_json_view(row.index) {
                set_raw_json_outbound_state(
                    ui,
                    RawJsonOutboundEditState {
                        index: row.index,
                        tag: row.tag.clone().unwrap_or_else(|| MISSING_FIELD.to_owned()),
                        text,
                        expected_fingerprint,
                        error: None,
                        diff_preview: None,
                    },
                );
            }
            ui.close();
        }
    });
}

#[derive(Clone)]
struct PendingOutboundDelete {
    index: usize,
    tag: String,
    protocol: String,
    error: Option<String>,
}

fn pending_outbound_delete_id() -> egui::Id {
    egui::Id::new("outbounds_pending_delete")
}

fn pending_outbound_delete(ui: &Ui) -> Option<PendingOutboundDelete> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingOutboundDelete>(pending_outbound_delete_id()))
}

fn set_pending_outbound_delete(ui: &Ui, pending: PendingOutboundDelete) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_outbound_delete_id(), pending));
}

fn clear_pending_outbound_delete(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingOutboundDelete>(pending_outbound_delete_id()));
}

fn show_delete_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(pending) = pending_outbound_delete(ui) else {
        return;
    };
    let mut open = true;
    egui::Window::new("Delete outbound")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Delete outbound «{}» ({})? This removes it from the remote configuration.",
                    pending.tag, pending.protocol
                ))
                .size(14.0),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Deletion cannot be undone from the UI (restore from backup if needed).",
                )
                .size(13.0)
                .color(Color32::from_rgb(160, 120, 40)),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_outbound_mutation_busy();
                if ui
                    .add_enabled(!busy, egui::Button::new("Delete"))
                    .clicked()
                {
                    match service.start_delete_outbound(pending.index) {
                        Ok(()) => clear_pending_outbound_delete(ui),
                        Err(message) => {
                            set_pending_outbound_delete(
                                ui,
                                PendingOutboundDelete {
                                    error: Some(message),
                                    ..pending.clone()
                                },
                            );
                        }
                    }
                }
                if ui.button("Cancel").clicked() {
                    clear_pending_outbound_delete(ui);
                }
            });
        });

    if !open {
        clear_pending_outbound_delete(ui);
    }
}

#[derive(Clone)]
struct PendingOutboundDuplicate {
    index: usize,
    tag: String,
    error: Option<String>,
    /// Last redacted structural diff preview (Roadmap §3:126); stale until re-clicked.
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
}

fn pending_outbound_duplicate_id() -> egui::Id {
    egui::Id::new("outbounds_pending_duplicate")
}

fn pending_outbound_duplicate(ui: &Ui) -> Option<PendingOutboundDuplicate> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingOutboundDuplicate>(pending_outbound_duplicate_id()))
}

fn set_pending_outbound_duplicate(ui: &Ui, pending: PendingOutboundDuplicate) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_outbound_duplicate_id(), pending));
}

fn clear_pending_outbound_duplicate(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingOutboundDuplicate>(pending_outbound_duplicate_id()));
}

fn show_duplicate_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_outbound_duplicate(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Duplicate outbound")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(format!(
                    "Duplicate outbound «{}»? A copy with a unique tag is added to the same source file.",
                    pending.tag
                ))
                .size(14.0),
            );
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            if let Some(entries) = pending.diff_preview.clone() {
                ui.add_space(8.0);
                super::json_diff_preview(ui, &entries);
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_outbound_mutation_busy();
                if ui
                    .add_enabled(!busy, egui::Button::new("Duplicate"))
                    .clicked()
                {
                    match service.start_duplicate_outbound(pending.index) {
                        Ok(()) => closed = true,
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("Preview changes"))
                    .clicked()
                {
                    match service.preview_duplicate_outbound_diff(pending.index) {
                        Ok(entries) => {
                            pending.diff_preview = Some(entries);
                            pending.error = None;
                        }
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_pending_outbound_duplicate(ui);
    } else {
        set_pending_outbound_duplicate(ui, pending);
    }
}

#[derive(Clone)]
struct PendingOutboundRename {
    index: usize,
    current_tag: String,
    draft: String,
    references: Vec<String>,
    error: Option<String>,
    /// Last redacted structural diff preview (Roadmap §3:126); stale until re-clicked.
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
}

fn pending_outbound_rename_id() -> egui::Id {
    egui::Id::new("outbounds_pending_rename")
}

fn pending_outbound_rename(ui: &Ui) -> Option<PendingOutboundRename> {
    ui.ctx()
        .data(|d| d.get_temp::<PendingOutboundRename>(pending_outbound_rename_id()))
}

fn set_pending_outbound_rename(ui: &Ui, pending: PendingOutboundRename) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(pending_outbound_rename_id(), pending));
}

fn clear_pending_outbound_rename(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<PendingOutboundRename>(pending_outbound_rename_id()));
}

fn show_rename_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut pending) = pending_outbound_rename(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new("Rename outbound")
        .collapsible(false)
        .resizable(false)
        .default_width(400.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(RichText::new(format!("Current tag: «{}»", pending.current_tag)).size(14.0));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("New tag:");
                ui.text_edit_singleline(&mut pending.draft);
            });
            if !pending.references.is_empty() {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "Still referenced in routing (will not be updated automatically): {}",
                        pending.references.join("; ")
                    ))
                    .size(13.0)
                    .color(Color32::from_rgb(210, 170, 40)),
                );
            }
            if let Some(error) = &pending.error {
                ui.add_space(8.0);
                ui.label(
                    RichText::new(error.clone())
                        .size(14.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
            }
            if let Some(entries) = pending.diff_preview.clone() {
                ui.add_space(8.0);
                super::json_diff_preview(ui, &entries);
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let busy = service.is_outbound_mutation_busy();
                let can_submit = !busy && !pending.draft.trim().is_empty();
                if ui
                    .add_enabled(can_submit, egui::Button::new("Rename"))
                    .clicked()
                {
                    match service
                        .start_rename_outbound_tag(pending.index, pending.draft.trim().to_owned())
                    {
                        Ok(()) => closed = true,
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui
                    .add_enabled(can_submit, egui::Button::new("Preview changes"))
                    .clicked()
                {
                    match service
                        .preview_rename_outbound_tag_diff(pending.index, pending.draft.trim())
                    {
                        Ok(entries) => {
                            pending.diff_preview = Some(entries);
                            pending.error = None;
                        }
                        Err(message) => pending.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_pending_outbound_rename(ui);
    } else {
        set_pending_outbound_rename(ui, pending);
    }
}

// ─── Raw JSON escape hatch (Roadmap §3:125) ──────────────────────────────────

/// Standalone dialog state — deliberately kept out of `OutboundEditorSession` (which only
/// covers Freedom/Blackhole/DNS); Raw JSON is available for **any** outbound protocol.
#[derive(Clone)]
struct RawJsonOutboundEditState {
    index: usize,
    tag: String,
    text: String,
    expected_fingerprint: String,
    error: Option<String>,
    /// Last redacted structural diff preview (Roadmap §3:126); stale until re-clicked.
    diff_preview: Option<Vec<crate::xray::JsonDiffEntry>>,
}

fn raw_json_outbound_id() -> egui::Id {
    egui::Id::new("outbounds_raw_json_edit")
}

fn raw_json_outbound_state(ui: &Ui) -> Option<RawJsonOutboundEditState> {
    ui.ctx()
        .data(|d| d.get_temp::<RawJsonOutboundEditState>(raw_json_outbound_id()))
}

fn set_raw_json_outbound_state(ui: &Ui, state: RawJsonOutboundEditState) {
    ui.ctx()
        .data_mut(|d| d.insert_temp(raw_json_outbound_id(), state));
}

fn clear_raw_json_outbound_state(ui: &Ui) {
    ui.ctx()
        .data_mut(|d| d.remove::<RawJsonOutboundEditState>(raw_json_outbound_id()));
}

fn show_raw_json_outbound_dialog(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut state) = raw_json_outbound_state(ui) else {
        return;
    };
    let mut open = true;
    let mut closed = false;
    egui::Window::new(format!("Raw JSON — {}", state.tag))
        .collapsible(false)
        .resizable(true)
        .default_width(560.0)
        .default_height(480.0)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(
                RichText::new(
                    "Escape hatch: edits the entire outbound object as raw JSON — for fields \
                     the structured editor doesn't cover, or for protocols with no structured \
                     editor at all. Save replaces the whole object; invalid JSON or a stale \
                     fingerprint (config changed underneath) is rejected before anything is \
                     written.",
                )
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
            );
            ui.add_space(6.0);
            if let Some(error) = &state.error {
                ui.label(
                    RichText::new(error.clone())
                        .size(13.0)
                        .color(Color32::from_rgb(200, 60, 60)),
                );
                ui.add_space(4.0);
            }
            if let Some(entries) = state.diff_preview.clone() {
                super::json_diff_preview(ui, &entries);
                ui.add_space(4.0);
            }
            egui::ScrollArea::vertical()
                .max_height(360.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut state.text)
                            .desired_rows(20)
                            .desired_width(f32::INFINITY)
                            .code_editor(),
                    );
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let busy = service.is_outbound_mutation_busy();
                if ui.add_enabled(!busy, egui::Button::new("Save")).clicked() {
                    match service.start_replace_outbound_raw_json(
                        state.index,
                        &state.text,
                        state.expected_fingerprint.clone(),
                    ) {
                        Ok(()) => closed = true,
                        Err(message) => state.error = Some(message),
                    }
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("Preview changes"))
                    .clicked()
                {
                    match service.preview_replace_outbound_raw_json_diff(
                        state.index,
                        &state.text,
                        state.expected_fingerprint.clone(),
                    ) {
                        Ok(entries) => {
                            state.diff_preview = Some(entries);
                            state.error = None;
                        }
                        Err(message) => state.error = Some(message),
                    }
                }
                if ui.button("Cancel").clicked() {
                    closed = true;
                }
            });
        });

    if closed || !open {
        clear_raw_json_outbound_state(ui);
    } else {
        set_raw_json_outbound_state(ui, state);
    }
}

// ─── Outbound Shell editor (Freedom, Blackhole, DNS; Roadmap §2.4:94, §2.4:95, §2.4:96) ────

fn outbound_protocol_label(settings: &OutboundSettingsDraft) -> &'static str {
    match settings {
        OutboundSettingsDraft::Freedom(_) => "Freedom",
        OutboundSettingsDraft::Blackhole { .. } => "Blackhole",
        OutboundSettingsDraft::Dns { .. } => "DNS",
        OutboundSettingsDraft::Vless(_) => "VLESS",
        OutboundSettingsDraft::Loopback(_) => "Loopback",
        OutboundSettingsDraft::Trojan(_) => "Trojan",
        OutboundSettingsDraft::Hysteria(_) => "Hysteria",
        OutboundSettingsDraft::Socks(_) => "SOCKS",
    }
}

fn show_outbound_editor_pane(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session() else {
        return;
    };
    let is_add = session.is_add;
    let protocol_label = outbound_protocol_label(&session.settings);

    ui.separator();
    ui.add_space(4.0);
    ui.strong(format!(
        "{} Outbound ({protocol_label})",
        if is_add { "Add" } else { "Edit" }
    ));
    ui.add_space(4.0);

    show_outbound_general_edit(ui, service, is_add);
    ui.add_space(6.0);
    ui.strong(format!("Protocol ({protocol_label})"));
    match service.outbound_editor_session().map(|s| &s.settings) {
        Some(OutboundSettingsDraft::Freedom(_)) => show_freedom_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Blackhole { .. }) => show_blackhole_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Dns { .. }) => show_dns_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Vless(_)) => show_vless_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Loopback(_)) => show_loopback_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Trojan(_)) => show_trojan_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Hysteria(_)) => show_hysteria_settings_edit(ui, service),
        Some(OutboundSettingsDraft::Socks(_)) => show_socks_settings_edit(ui, service),
        None => {}
    }
    // Stream / Security for protocols that dial through a transport (Roadmap §4.2).
    let protocol = service
        .outbound_editor_session()
        .map(|s| s.settings.protocol_name())
        .unwrap_or_default();
    if outbound_protocol_has_transport(protocol) {
        ui.add_space(8.0);
        ui.separator();
        super::outbound_stream::show_outbound_stream_edit(ui, service, protocol);
    }
    // Socket options for every protocol that dials (Roadmap §4.2).
    if outbound_protocol_uses_sockopt(protocol) {
        ui.add_space(8.0);
        ui.separator();
        super::outbound_stream::show_outbound_sockopt_edit(ui, service);
    }
    show_outbound_mux_edit(ui, service, protocol);
    ui.add_space(8.0);

    let busy = service.is_outbound_mutation_busy();
    ui.horizontal(|ui| {
        let save_label = if is_add { "Add Outbound" } else { "Save" };
        if ui
            .add_enabled(!busy, egui::Button::new(save_label))
            .clicked()
        {
            let result = if is_add {
                service.start_add_outbound_shell()
            } else {
                service.start_save_outbound_shell()
            };
            if let Err(e) = result {
                service.show_status_message(e);
            }
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Preview changes"))
            .clicked()
        {
            if let Err(e) = service.preview_outbound_shell_diff() {
                service.show_status_message(e);
            }
        }
        if ui.button("Cancel").clicked() {
            service.cancel_outbound_editor_session();
        }
    });
    show_outbound_diff_preview(ui, service);
}

fn show_outbound_diff_preview(ui: &mut Ui, service: &ApplicationService) {
    let Some(entries) = service
        .outbound_editor_session()
        .and_then(|s| s.diff_preview.clone())
    else {
        return;
    };
    super::json_diff_preview(ui, &entries);
}

fn show_outbound_general_edit(ui: &mut Ui, service: &mut ApplicationService, is_add: bool) {
    // Computing warnings borrows the service immutably, so before the mutable session borrow.
    let proxy_settings_warnings: Vec<_> = service
        .outbound_editor_warnings()
        .into_iter()
        .filter(|warning| warning.id == CompatibilityWarningId::OutboundProxySettingsRemoved)
        .collect();
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let general = &mut session.general;
    let mut tag = general.tag.clone().unwrap_or_default();
    let mut send_through = general.send_through.clone().unwrap_or_default();

    egui::Grid::new("outbound_general_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "tag", HELP_GENERAL_TAG);
            if is_add {
                ui.text_edit_singleline(&mut tag);
            } else {
                ui.label(if tag.is_empty() { MISSING_FIELD } else { &tag });
            }
            ui.end_row();

            super::field_label(ui, "sendThrough", HELP_GENERAL_SEND_THROUGH);
            ui.text_edit_singleline(&mut send_through);
            ui.end_row();
        });
    // Checked live with the same rule as Save (Roadmap §4.2), plus the core's precedence:
    // `SetOutboundGateway` skips sendThrough while sockopt.dialerProxy is set.
    if let Err(message) = validate_send_through(&send_through) {
        ui.label(RichText::new(message).size(12.0).color(Color32::from_rgb(220, 80, 80)));
    } else if !send_through.trim().is_empty() && !session.stream.sockopt.dialer_proxy.trim().is_empty() {
        ui.label(
            RichText::new("sendThrough is not used while Socket options → dialerProxy is set.")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    }

    general.tag = Some(tag);
    general.send_through = Some(send_through);

    // `proxySettings` is never written: it is a removed feature (XTLS/Xray-core#6058). An
    // existing one is shown read-only with an explicit migration (Roadmap §4.2).
    let Some(legacy) = general.legacy_proxy_settings.clone() else {
        return;
    };
    let pending = general.migrate_proxy_settings;
    ui.add_space(6.0);
    let tag = if legacy.tag.is_empty() { MISSING_FIELD } else { legacy.tag.as_str() };
    ui.label(format!(
        "proxySettings (on disk): tag {tag}{}",
        if legacy.transport_layer { ", transportLayer" } else { "" }
    ));
    show_outbound_compatibility_warnings(ui, &proxy_settings_warnings);
    if pending {
        ui.label(
            RichText::new("Migration pending — proxySettings is removed on Save (see the preview).")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
        return;
    }
    if ui
        .button("Migrate to sockopt.dialerProxy")
        .on_hover_text(
            "Removes proxySettings and moves its tag into streamSettings.sockopt.dialerProxy (an \
             existing dialerProxy wins) and shows the diff; nothing is written until Save",
        )
        .clicked()
    {
        match service.migrate_outbound_proxy_settings() {
            Ok(message) | Err(message) => service.show_status_message(message),
        }
    }
}

/// Mux section (Roadmap §4.2): the full editor on proxy outbounds; elsewhere — and for a `mux`
/// the core cannot load — only a "Remove mux" for one found on disk.
fn show_outbound_mux_edit(ui: &mut Ui, service: &mut ApplicationService, protocol: &str) {
    // Computing warnings borrows the service immutably, so before the mutable session borrow.
    let mux_warnings: Vec<_> = service
        .outbound_editor_warnings()
        .into_iter()
        .filter(|warning| {
            matches!(
                warning.id,
                CompatibilityWarningId::MuxRejected
                    | CompatibilityWarningId::MuxOnNonProxyOutbound
                    | CompatibilityWarningId::MuxVisionCarriesTcp
            )
        })
        .collect();
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let mux = session.general.mux.get_or_insert_with(OutboundMux::default);
    let proxy = outbound_protocol_has_transport(protocol);
    if !proxy && *mux == OutboundMux::default() {
        return;
    }

    ui.add_space(8.0);
    ui.separator();
    ui.horizontal(|ui| {
        super::help_button(ui, "mux", HELP_MUX);
        ui.strong("Mux");
    });
    show_outbound_compatibility_warnings(ui, &mux_warnings);

    if !proxy || mux.foreign.is_some() {
        let note = match &mux.foreign {
            Some(reason) => format!("mux on disk cannot be edited here: {reason}."),
            None => format!("{protocol} outbounds cannot use Mux."),
        };
        ui.label(RichText::new(note).size(12.0).color(Color32::from_rgb(140, 140, 140)));
        if ui
            .button("Remove mux")
            .on_hover_text("Removes the whole mux object on Save; \"Preview changes\" shows it")
            .clicked()
        {
            *mux = OutboundMux::default();
        }
        return;
    }

    super::help_checkbox(ui, "enabled", HELP_MUX_ENABLED, &mut mux.enabled);
    egui::Grid::new("outbound_mux_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "concurrency", HELP_MUX_CONCURRENCY);
            ui.add(egui::TextEdit::singleline(&mut mux.concurrency).desired_width(80.0).hint_text("8"));
            ui.end_row();

            super::field_label(ui, "xudpConcurrency", HELP_MUX_XUDP_CONCURRENCY);
            ui.add(egui::TextEdit::singleline(&mut mux.xudp_concurrency).desired_width(80.0).hint_text("0"));
            ui.end_row();

            super::field_label(ui, "xudpProxyUDP443", HELP_MUX_XUDP_PROXY_UDP443);
            optional_string_combo(ui, "outbound_mux_udp443", &mut mux.xudp_proxy_udp443, MUX_XUDP_PROXY_UDP443_VALUES);
            ui.end_row();
        });

    // Checked live with the same rule as Save; the rest are values the core accepts but caps.
    if let Err(message) = validate_outbound_mux(mux) {
        ui.label(RichText::new(message).size(12.0).color(Color32::from_rgb(220, 80, 80)));
    }
    let number = |text: &str| text.trim().parse::<i64>().ok();
    if number(&mux.concurrency).is_some_and(|value| value > MUX_CONCURRENCY_EFFECTIVE_MAX) {
        ui.label(
            RichText::new(format!("concurrency above {MUX_CONCURRENCY_EFFECTIVE_MAX} acts as {MUX_CONCURRENCY_EFFECTIVE_MAX}."))
                .size(12.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
    if number(&mux.xudp_concurrency).is_some_and(|value| value > MUX_XUDP_CONCURRENCY_DOCUMENTED_MAX) {
        ui.label(
            RichText::new(format!(
                "xudpConcurrency above the documented maximum {MUX_XUDP_CONCURRENCY_DOCUMENTED_MAX}."
            ))
            .size(12.0)
            .color(Color32::from_rgb(210, 170, 40)),
        );
    }
    if !mux.extras.is_empty() {
        let keys: Vec<&str> = mux.extras.keys().map(String::as_str).collect();
        ui.label(
            RichText::new(format!("Kept as is: {}", keys.join(", ")))
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    }
}

fn show_freedom_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    // Warnings first: computing them borrows the service immutably.
    let warnings = outbound_editor_warnings_below_general(service);
    let can_migrate = matches!(
        service.outbound_editor_session().map(|s| &s.settings),
        Some(OutboundSettingsDraft::Freedom(draft))
            if draft.legacy_domain_strategy.is_some() && !draft.remove_legacy_domain_strategy
    );
    show_outbound_compatibility_warnings(ui, &warnings);
    if can_migrate {
        if ui
            .button("Migrate to sockopt")
            .on_hover_text(
                "Moves settings.domainStrategy into streamSettings.sockopt.domainStrategy (an \
                 existing sockopt value wins) and shows the diff; nothing is written until Save",
            )
            .clicked()
        {
            match service.migrate_outbound_legacy_domain_strategy() {
                Ok(message) | Err(message) => service.show_status_message(message),
            }
        }
        ui.add_space(6.0);
    }
    // The warning is computed on the draft and only for cores that refuse the key (gate G14), so
    // the button disappears once the removal is scheduled.
    let address_port_strategy_rejected = warnings
        .iter()
        .any(|warning| warning.id == CompatibilityWarningId::FreedomAddressPortStrategyRejected);
    if address_port_strategy_rejected {
        if ui
            .button("Remove addressPortStrategy")
            .on_hover_text(
                "Removes streamSettings.sockopt.addressPortStrategy (Freedom cannot use it; Save is \
                 blocked while it is there) and shows the diff; nothing is written until Save",
            )
            .clicked()
        {
            match service.remove_outbound_freedom_address_port_strategy() {
                Ok(message) | Err(message) => service.show_status_message(message),
            }
        }
        ui.add_space(6.0);
    }

    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Freedom(draft) = &mut session.settings else {
        return;
    };

    let mut redirect_text = draft.redirect.clone();
    let mut level = draft.user_level as i64;
    let mut proxy_protocol = draft.proxy_protocol;

    egui::Grid::new("freedom_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "redirect", HELP_FREEDOM_REDIRECT);
            ui.text_edit_singleline(&mut redirect_text);
            ui.end_row();

            super::field_label(ui, "userLevel", HELP_USER_LEVEL);
            ui.add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64));
            ui.end_row();

            super::field_label(ui, "proxyProtocol", HELP_FREEDOM_PROXY_PROTOCOL);
            egui::ComboBox::from_id_salt("freedom_proxy_protocol")
                .selected_text(proxy_protocol_label(proxy_protocol))
                .show_ui(ui, |ui| {
                    for &version in FREEDOM_PROXY_PROTOCOL_VERSIONS {
                        ui.selectable_value(&mut proxy_protocol, version, proxy_protocol_label(version));
                    }
                });
            ui.end_row();
        });

    draft.redirect = redirect_text;
    draft.user_level = level.max(0) as u64;
    draft.proxy_protocol = proxy_protocol;

    ui.add_space(6.0);
    let mut fragment_enabled = draft.fragment.is_some();
    let fragment_toggled = ui
        .horizontal(|ui| {
            super::help_button(ui, "fragment", HELP_FREEDOM_FRAGMENT);
            ui.checkbox(&mut fragment_enabled, "fragment").changed()
        })
        .inner;
    if fragment_toggled {
        draft.fragment = if fragment_enabled {
            Some(FragmentDraft::default())
        } else {
            None
        };
    }
    if let Some(fragment) = &mut draft.fragment {
        egui::Grid::new("freedom_fragment_edit_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                super::field_label(ui, "packets", HELP_FREEDOM_FRAGMENT_PACKETS);
                ui.text_edit_singleline(&mut fragment.packets);
                ui.end_row();
                super::field_label(ui, "length", HELP_FREEDOM_FRAGMENT_LENGTH);
                ui.text_edit_singleline(&mut fragment.length);
                ui.end_row();
                super::field_label(ui, "interval", HELP_FREEDOM_FRAGMENT_INTERVAL);
                ui.text_edit_singleline(&mut fragment.interval);
                ui.end_row();
            });
    }

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        super::help_button(ui, "noises", HELP_FREEDOM_NOISES);
        ui.strong("noises");
    });
    show_freedom_noises_edit(ui, &mut draft.noises);

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        super::help_button(ui, "finalRules", HELP_FREEDOM_FINAL_RULES);
        ui.strong("finalRules");
    });
    if draft.final_rules_foreign {
        ui.label(
            RichText::new(
                "finalRules has a shape this editor cannot represent without changing it — it is \
                 kept as is; edit it with Raw JSON.",
            )
            .size(12.0)
            .color(Color32::from_rgb(210, 170, 40)),
        );
    } else {
        show_freedom_final_rules_edit(ui, &mut draft.final_rules);
    }
}

fn proxy_protocol_label(version: u64) -> String {
    match version {
        0 => "0 — disabled".to_owned(),
        1 | 2 => format!("v{version}"),
        other => format!("{other} (not supported by Xray-core)"),
    }
}

/// The editor's warnings without the ones the General section shows next to its fix
/// (`proxySettings`).
pub(super) fn outbound_editor_warnings_below_general(service: &ApplicationService) -> Vec<CompatibilityWarning> {
    let mut warnings = service.outbound_editor_warnings();
    warnings.retain(|warning| warning.id != CompatibilityWarningId::OutboundProxySettingsRemoved);
    warnings
}

/// Yellow `"<location>: <message>"` lines for non-blocking outbound warnings, danger ones in red
/// behind road sign 1.33 (mirrors the inbound Stream tab).
pub(super) fn show_outbound_compatibility_warnings(ui: &mut Ui, warnings: &[CompatibilityWarning]) {
    for warning in warnings {
        if warning.id.severity() == crate::xray::WarningSeverity::Danger {
            super::danger_warning(ui, &warning.text());
            continue;
        }
        ui.label(
            RichText::new(warning.text())
                .size(12.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
    if !warnings.is_empty() {
        ui.add_space(4.0);
    }
}

/// Ordered `settings.finalRules[]` editor (Add/Remove/Move up/down; mirrors the DNS `rules[]`
/// editor).
fn show_freedom_final_rules_edit(ui: &mut Ui, rules: &mut Vec<FreedomFinalRuleDraft>) {
    let mut remove_idx: Option<usize> = None;
    let mut move_up_idx: Option<usize> = None;
    let mut move_down_idx: Option<usize> = None;
    let count = rules.len();

    for (idx, rule) in rules.iter_mut().enumerate() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(format!("finalRules[{idx}]"));
                if ui.small_button("Up").on_hover_text("Move up").clicked() && idx > 0 {
                    move_up_idx = Some(idx);
                }
                if ui.small_button("Down").on_hover_text("Move down").clicked() && idx + 1 < count {
                    move_down_idx = Some(idx);
                }
                if ui.button("Remove").clicked() {
                    remove_idx = Some(idx);
                }
            });

            egui::Grid::new(("freedom_final_rule_edit_grid", idx))
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    super::field_label(ui, "action", HELP_FINAL_RULE_ACTION);
                    egui::ComboBox::from_id_salt(("freedom_final_rule_action", idx))
                        .selected_text(if rule.action.is_empty() {
                            "(unset)"
                        } else {
                            rule.action.as_str()
                        })
                        .show_ui(ui, |ui| {
                            for &preset in FREEDOM_FINAL_RULE_ACTIONS {
                                ui.selectable_value(&mut rule.action, preset.to_owned(), preset);
                            }
                        });
                    ui.end_row();

                    super::field_label(ui, "network", HELP_FINAL_RULE_NETWORK);
                    egui::ComboBox::from_id_salt(("freedom_final_rule_network", idx))
                        .selected_text(if rule.network.is_empty() {
                            "(any)"
                        } else {
                            rule.network.as_str()
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut rule.network, String::new(), "(any)");
                            for &preset in FREEDOM_FINAL_RULE_NETWORKS {
                                ui.selectable_value(&mut rule.network, preset.to_owned(), preset);
                            }
                        });
                    ui.end_row();

                    super::field_label(ui, "port", HELP_FINAL_RULE_PORT);
                    ui.text_edit_singleline(&mut rule.port.text);
                    ui.end_row();

                    super::field_label(ui, "blockDelay", HELP_FINAL_RULE_BLOCK_DELAY);
                    ui.add(
                        egui::TextEdit::singleline(&mut rule.block_delay.text)
                            .hint_text(FREEDOM_DEFAULT_BLOCK_DELAY),
                    );
                    ui.end_row();
                });

            super::field_label(ui, "ip (one per line)", HELP_FINAL_RULE_IP);
            super::persistent_list_text_edit(ui, ("freedom_final_rule_ip", idx), &mut rule.ip, |ui, text| {
                ui.add(egui::TextEdit::multiline(text).desired_rows(2))
            });
        });
    }

    if let Some(idx) = remove_idx {
        rules.remove(idx);
    } else if let Some(idx) = move_up_idx {
        rules.swap(idx, idx - 1);
    } else if let Some(idx) = move_down_idx {
        rules.swap(idx, idx + 1);
    }

    ui.add_space(4.0);
    if ui.button("Add final rule").clicked() {
        rules.push(FreedomFinalRuleDraft::new("block"));
    }
}

fn show_freedom_noises_edit(ui: &mut Ui, noises: &mut Vec<NoiseDraft>) {
    let mut remove_idx: Option<usize> = None;
    egui::Grid::new("freedom_noises_edit_grid")
        .num_columns(4)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new("type").strong());
            ui.label(RichText::new("packet").strong());
            ui.label(RichText::new("delay").strong());
            ui.label("");
            ui.end_row();

            for (idx, noise) in noises.iter_mut().enumerate() {
                egui::ComboBox::from_id_salt(("freedom_noise_type", idx))
                    .selected_text(if noise.kind.is_empty() {
                        "(unset)"
                    } else {
                        noise.kind.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in FREEDOM_NOISE_TYPES {
                            ui.selectable_value(&mut noise.kind, preset.to_owned(), preset);
                        }
                    });
                ui.text_edit_singleline(&mut noise.packet);
                ui.text_edit_singleline(&mut noise.delay);
                if ui.small_button("Del").clicked() {
                    remove_idx = Some(idx);
                }
                ui.end_row();
            }
        });
    if let Some(idx) = remove_idx {
        noises.remove(idx);
    }

    if ui.button("Add noise").clicked() {
        noises.push(NoiseDraft {
            kind: "rand".to_owned(),
            packet: String::new(),
            delay: String::new(),
            extras: Default::default(),
        });
    }
}

fn show_blackhole_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Blackhole {
        response_type,
        custom_response_data,
        ..
    } = &mut session.settings
    else {
        return;
    };

    let mut kind = response_type.clone();
    let mut custom_data = custom_response_data.clone();
    egui::Grid::new("blackhole_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "response.type", HELP_BLACKHOLE_RESPONSE_TYPE);
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("blackhole_response_type")
                    .selected_text(if kind.is_empty() {
                        "(unset — none)"
                    } else {
                        kind.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in BLACKHOLE_RESPONSE_TYPES {
                            ui.selectable_value(&mut kind, preset.to_owned(), preset);
                        }
                    });
                ui.text_edit_singleline(&mut kind);
            });
            ui.end_row();

            if kind.trim().eq_ignore_ascii_case("custom") {
                super::field_label(ui, "response.customResponseData", HELP_BLACKHOLE_CUSTOM_DATA);
                ui.text_edit_singleline(&mut custom_data);
                ui.end_row();
            }
        });
    *response_type = kind;
    *custom_response_data = custom_data;
}

fn show_dns_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Dns {
        rewrite_network,
        rewrite_address,
        rewrite_port,
        user_level,
        rules,
    } = &mut session.settings
    else {
        return;
    };

    let mut network = rewrite_network.clone();
    let mut address = rewrite_address.clone();
    let mut port = rewrite_port.clone();
    let mut level = *user_level as i64;

    egui::Grid::new("dns_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "rewriteNetwork", HELP_DNS_REWRITE_NETWORK);
            ui.horizontal(|ui| {
                egui::ComboBox::from_id_salt("dns_rewrite_network")
                    .selected_text(if network.is_empty() {
                        "(unset — unchanged)"
                    } else {
                        network.as_str()
                    })
                    .show_ui(ui, |ui| {
                        for &preset in DNS_REWRITE_NETWORKS {
                            ui.selectable_value(&mut network, preset.to_owned(), preset);
                        }
                    });
                ui.text_edit_singleline(&mut network);
            });
            ui.end_row();

            super::field_label(ui, "rewriteAddress", HELP_DNS_REWRITE_ADDRESS);
            ui.text_edit_singleline(&mut address);
            ui.end_row();

            super::field_label(ui, "rewritePort", HELP_DNS_REWRITE_PORT);
            ui.text_edit_singleline(&mut port);
            ui.end_row();

            super::field_label(ui, "userLevel", HELP_USER_LEVEL);
            ui.add(egui::DragValue::new(&mut level).range(0..=u32::MAX as i64));
            ui.end_row();
        });

    *rewrite_network = network;
    *rewrite_address = address;
    *rewrite_port = port;
    *user_level = level.max(0) as u64;

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        super::help_button(ui, "rules", HELP_DNS_RULES);
        ui.strong("rules");
    });
    show_dns_rules_edit(ui, rules);
}

/// Loopback Protocol section (Roadmap §4.2): `inboundTag` (routing's `inboundTag` names + free
/// text) with a hint on where routing sends the traffic, and `sniffing` (shared editor).
fn show_loopback_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    // Computed before the mutable session borrow (a frame behind the typing, which is fine).
    let candidates = service.routing_inbound_tag_candidates();
    let routing = service.outbound_loopback_routing();
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Loopback(draft) = &mut session.settings else {
        return;
    };
    let grey = Color32::from_rgb(140, 140, 140);
    let amber = Color32::from_rgb(210, 170, 40);

    let presets: Vec<&str> = candidates.iter().map(String::as_str).collect();
    egui::Grid::new("loopback_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "inboundTag", HELP_LOOPBACK_INBOUND_TAG);
            ui.horizontal(|ui| {
                optional_string_combo(ui, "loopback_inbound_tag", &mut draft.inbound_tag, &presets);
            });
            ui.end_row();
        });
    if draft.inbound_tag_foreign && draft.inbound_tag.is_empty() {
        ui.label(
            RichText::new("inboundTag on disk is not a string (Xray-core refuses it); it is kept until a tag is typed here.")
                .size(12.0)
                .color(amber),
        );
    }
    let hint = match routing {
        Some(LoopbackRouting::NoTag) => Some((
            "No inboundTag: routing rules with an inboundTag condition never match this traffic; \
             the other rules decide."
                .to_owned(),
            amber,
        )),
        Some(LoopbackRouting::NoRule) => Some((
            "No routing rule lists this inboundTag — the other rules decide, and may send the \
             traffic back into this outbound."
                .to_owned(),
            amber,
        )),
        Some(LoopbackRouting::Rules(rules)) => Some((
            format!(
                "Routing rules for this tag: {}.",
                rules.iter().map(|index| format!("#{}", index + 1)).collect::<Vec<_>>().join(", ")
            ),
            grey,
        )),
        Some(LoopbackRouting::LoopsBack { rule }) => Some((
            format!(
                "Routing rule #{} sends this inboundTag back into this outbound — the traffic \
                 would loop.",
                rule + 1
            ),
            Color32::from_rgb(220, 80, 80),
        )),
        None => None,
    };
    if let Some((text, color)) = hint {
        ui.label(RichText::new(text).size(12.0).color(color));
    }

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        super::help_button(ui, "sniffing", HELP_LOOPBACK_SNIFFING);
        ui.strong("sniffing");
    });
    if draft.sniffing_foreign {
        ui.label(
            RichText::new("settings.sniffing is not a JSON object; it is preserved — fix it on the Raw JSON tab to edit.")
                .size(12.0)
                .color(grey),
        );
        return;
    }
    super::inbounds::show_sniffing_fields(ui, &mut draft.sniffing);
    if !draft.sniffing.extras.is_empty() {
        ui.label(
            RichText::new(format!(
                "Preserved sniffing keys: {}",
                draft.sniffing.extras.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
            .size(12.0)
            .color(grey),
        );
    }
}

/// Ordered `settings.rules[]` editor (Add/Remove/Move up/down; order is meaningful — mirrors the
/// FinalMask layer-list editor convention).
fn show_dns_rules_edit(ui: &mut Ui, rules: &mut Vec<DnsRuleDraft>) {
    let mut remove_idx: Option<usize> = None;
    let mut move_up_idx: Option<usize> = None;
    let mut move_down_idx: Option<usize> = None;
    let count = rules.len();

    for (idx, rule) in rules.iter_mut().enumerate() {
        ui.add_space(4.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(format!("rule[{idx}]"));
                if ui.small_button("Up").on_hover_text("Move up").clicked() && idx > 0 {
                    move_up_idx = Some(idx);
                }
                if ui.small_button("Down").on_hover_text("Move down").clicked() && idx + 1 < count {
                    move_down_idx = Some(idx);
                }
                if ui.button("Remove").clicked() {
                    remove_idx = Some(idx);
                }
            });

            egui::Grid::new(("dns_rule_edit_grid", idx))
                .num_columns(2)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    super::field_label(ui, "action", HELP_DNS_RULE_ACTION);
                    ui.horizontal(|ui| {
                        egui::ComboBox::from_id_salt(("dns_rule_action", idx))
                            .selected_text(if rule.action.is_empty() {
                                "(unset)"
                            } else {
                                rule.action.as_str()
                            })
                            .show_ui(ui, |ui| {
                                for &preset in DNS_RULE_ACTIONS {
                                    ui.selectable_value(&mut rule.action, preset.to_owned(), preset);
                                }
                            });
                        ui.text_edit_singleline(&mut rule.action);
                    });
                    ui.end_row();

                    super::field_label(ui, "qType", HELP_DNS_RULE_QTYPE);
                    ui.text_edit_singleline(&mut rule.q_type);
                    ui.end_row();

                    super::field_label(ui, "rCode", HELP_DNS_RULE_RCODE);
                    let mut r_code = rule.r_code;
                    ui.add(egui::DragValue::new(&mut r_code).range(0..=65535));
                    rule.r_code = r_code;
                    ui.end_row();
                });

            super::field_label(ui, "domain (one per line)", HELP_DNS_RULE_DOMAIN);
            super::persistent_list_text_edit(ui, ("dns_rule_domain", idx), &mut rule.domain, |ui, text| {
                ui.add(egui::TextEdit::multiline(text).desired_rows(2))
            });
        });
    }

    if let Some(idx) = remove_idx {
        rules.remove(idx);
    } else if let Some(idx) = move_up_idx {
        rules.swap(idx, idx - 1);
    } else if let Some(idx) = move_down_idx {
        rules.swap(idx, idx + 1);
    }

    ui.add_space(4.0);
    if ui.button("Add rule").clicked() {
        rules.push(DnsRuleDraft {
            action: "direct".to_owned(),
            q_type: String::new(),
            r_code: 0,
            domain: Vec::new(),
            extras: Default::default(),
        });
    }
}

/// VLESS outbound Protocol tab — bridge side of VLESS-native reverse proxy, or a plain forward
/// outbound (Roadmap §2.1:58). Writes the flat `settings` form (`address`/`port`/`id`/
/// `encryption`/`flow`/`level`/`email`/`reverse`); a draft read from a single-server legacy
/// `vnext[]` gets a notice that Save converts it (Roadmap §4.2).
/// Whether the Outbound Shell opens this kind (Edit / Duplicate); mirrors
/// `is_shell_editable_protocol`.
fn is_shell_kind(kind: OutboundKind) -> bool {
    matches!(
        kind,
        OutboundKind::Freedom
            | OutboundKind::Blackhole
            | OutboundKind::Dns
            | OutboundKind::Vless
            | OutboundKind::Loopback
            | OutboundKind::Trojan
            | OutboundKind::Hysteria
            | OutboundKind::Socks
    )
}

/// SOCKS Protocol section (Roadmap §4.2): flat `settings`; `pass` / `level` / `email` only count
/// with a `user`.
fn show_socks_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Socks(settings) = &mut session.settings else {
        return;
    };
    ui.horizontal(|ui| {
        super::help_button(ui, "SOCKS", HELP_SOCKS);
        ui.label(
            RichText::new("No encryption: for a proxy on this server or a private network (e.g. Tor at 127.0.0.1:9050).")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    });
    if settings.legacy_servers {
        ui.label(
            RichText::new(
                "This outbound uses the servers[] form. Save rewrites it into the flat settings \
                 form — same server and user for Xray-core. \"Preview changes\" shows the rewrite.",
            )
            .italics(),
        );
    }
    ui.add_space(4.0);
    egui::Grid::new("socks_outbound_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "address", HELP_SOCKS_ADDRESS);
            ui.add(egui::TextEdit::singleline(&mut settings.address).hint_text("127.0.0.1"));
            ui.end_row();

            super::field_label(ui, "port", HELP_SOCKS_PORT);
            ui.add(egui::TextEdit::singleline(&mut settings.port).desired_width(80.0).hint_text("9050"));
            ui.end_row();

            super::field_label(ui, "user", HELP_SOCKS_USER);
            ui.text_edit_singleline(&mut settings.user);
            ui.end_row();

            super::field_label(ui, "pass", HELP_SOCKS_PASS);
            ui.add(egui::TextEdit::singleline(&mut settings.pass).password(true));
            ui.end_row();

            super::field_label(ui, "level", HELP_SOCKS_LEVEL);
            ui.add(egui::TextEdit::singleline(&mut settings.level).desired_width(80.0).hint_text("0"));
            ui.end_row();

            super::field_label(ui, "email", HELP_SOCKS_EMAIL);
            ui.text_edit_singleline(&mut settings.email);
            ui.end_row();
        });
    if settings.has_ignored_user_fields() {
        ui.label(
            RichText::new("pass, level and email are ignored by Xray-core without a user.")
                .size(12.0)
                .color(Color32::from_rgb(210, 170, 40)),
        );
    }
}

/// Hysteria Protocol section (Roadmap §4.2): server address and port; `version` is always 2,
/// the password lives under Stream / Security (`auth`).
fn show_hysteria_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Hysteria(settings) = &mut session.settings else {
        return;
    };
    if let Some(version) = settings.version_on_disk_label() {
        ui.label(
            RichText::new(format!(
                "settings.version is {version} — Xray-core accepts only 2 and refuses to load the \
                 config; Save writes 2."
            ))
            .color(Color32::from_rgb(210, 170, 40)),
        );
    }
    egui::Grid::new("hysteria_outbound_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "address", HELP_HYSTERIA_ADDRESS);
            ui.text_edit_singleline(&mut settings.address);
            ui.end_row();

            super::field_label(ui, "port", HELP_HYSTERIA_PORT);
            ui.add(egui::TextEdit::singleline(&mut settings.port).desired_width(80.0).hint_text("443"));
            ui.end_row();

            super::field_label(ui, "version", HELP_HYSTERIA_VERSION);
            ui.label(HYSTERIA_OUTBOUND_VERSION.to_string());
            ui.end_row();
        });
    ui.label(
        RichText::new("The password (auth) is under Stream / Security → hysteria.")
            .size(12.0)
            .color(Color32::from_rgb(140, 140, 140)),
    );
}

/// Trojan Protocol section (Roadmap §4.2): flat `settings`; `flow` from disk can only be removed.
fn show_trojan_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let OutboundSettingsDraft::Trojan(settings) = &mut session.settings else {
        return;
    };
    ui.horizontal(|ui| {
        super::help_button(ui, "Trojan", HELP_TROJAN);
        ui.label(
            RichText::new("Xray-core marks Trojan as deprecated in favour of VLESS (still supported).")
                .size(12.0)
                .color(Color32::from_rgb(140, 140, 140)),
        );
    });
    if settings.legacy_servers {
        ui.label(
            RichText::new(
                "This outbound uses the servers[] form. Save rewrites it into the flat settings \
                 form — same server for Xray-core. \"Preview changes\" shows the rewrite.",
            )
            .italics(),
        );
    }
    if !settings.flow.is_empty() {
        ui.label(
            RichText::new(format!(
                "flow \"{}\" is a removed feature for Trojan — Xray-core refuses to load the config \
                 and Save is blocked until it is removed.",
                settings.flow
            ))
            .color(Color32::from_rgb(210, 170, 40)),
        );
        if ui.button("Remove flow").clicked() {
            settings.flow.clear();
        }
    }
    ui.add_space(4.0);

    egui::Grid::new("trojan_outbound_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "address", HELP_TROJAN_ADDRESS);
            ui.text_edit_singleline(&mut settings.address);
            ui.end_row();

            super::field_label(ui, "port", HELP_TROJAN_PORT);
            ui.add(egui::TextEdit::singleline(&mut settings.port).desired_width(80.0).hint_text("443"));
            ui.end_row();

            super::field_label(ui, "password", HELP_TROJAN_PASSWORD);
            ui.add(egui::TextEdit::singleline(&mut settings.password).password(true));
            ui.end_row();

            super::field_label(ui, "level", HELP_TROJAN_LEVEL);
            ui.add(egui::TextEdit::singleline(&mut settings.level).desired_width(80.0).hint_text("0"));
            ui.end_row();

            super::field_label(ui, "email", HELP_TROJAN_EMAIL);
            ui.text_edit_singleline(&mut settings.email);
            ui.end_row();
        });
}

fn show_vless_settings_edit(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(session) = service.outbound_editor_session_mut() else {
        return;
    };
    let crate::app::OutboundSettingsDraft::Vless(settings) = &mut session.settings else {
        return;
    };
    let mut reverse = super::ReverseDraftFields::from_reverse(settings.reverse.as_ref());

    if settings.legacy_vnext {
        ui.label(
            egui::RichText::new(
                "This outbound uses the legacy vnext[] form. Save rewrites it into the flat \
                 settings form — same server and user for Xray-core. \"Preview changes\" shows \
                 the rewrite.",
            )
            .italics(),
        );
        ui.add_space(6.0);
    }

    egui::Grid::new("vless_outbound_settings_edit_grid")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            super::field_label(ui, "address", HELP_VLESS_ADDRESS);
            ui.text_edit_singleline(&mut settings.address);
            ui.end_row();

            super::field_label(ui, "port", HELP_VLESS_PORT);
            ui.text_edit_singleline(&mut settings.port);
            ui.end_row();

            super::field_label(ui, "id", HELP_VLESS_ID);
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut settings.id).desired_width(300.0));
                if ui.button("Generate").clicked() {
                    settings.id = crate::app::generate_client_uuid();
                }
            });
            ui.end_row();

            super::field_label(ui, "flow", HELP_VLESS_FLOW);
            ui.text_edit_singleline(&mut settings.flow);
            ui.end_row();

            super::field_label(ui, "encryption", HELP_VLESS_ENCRYPTION);
            ui.add(egui::TextEdit::singleline(&mut settings.encryption).hint_text("none"));
            ui.end_row();

            super::field_label(ui, "level", HELP_VLESS_LEVEL);
            ui.text_edit_singleline(&mut settings.level);
            ui.end_row();

            super::field_label(ui, "email", HELP_VLESS_EMAIL);
            ui.text_edit_singleline(&mut settings.email);
            ui.end_row();
        });

    ui.add_space(6.0);
    super::reverse_fields_edit(ui, "vless_outbound_reverse_sniffing", &mut reverse);
    settings.reverse = reverse.to_reverse();
}
