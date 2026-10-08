//! Non-blocking compatibility warnings for one inbound (Roadmap §2.6 stage 0.3) or outbound
//! (Roadmap §2.4:105).
//!
//! Gates ([`super::CompatibilityGateId`]) *block* Save. Warnings never do: they flag a config that
//! Xray-core accepts but that does not do what it looks like it does — typically a key the current
//! core silently ignores — or, at [`WarningSeverity::Danger`], a config that works but endangers
//! the server ([`CompatibilityWarningId::OpenProxyInbound`]). Each warning carries the JSON location it refers to, so the GUI can show
//! where in the original Xray configuration the problem lives (`docs/rules.md`: abstractions must
//! not hide the relationship to the original configuration location).
//!
//! Only facts verified against `XTLS/Xray-core@main` belong here; Xray-core decodes JSON with
//! unknown fields ignored (no `DisallowUnknownFields`, also not under `xray.json.strict`), so a
//! removed key produces neither an error nor a log line on the core side. A few warnings flag a
//! config that passes `xray run -test` but fails once Xray starts listening
//! ([`CompatibilityWarningId::UdpHopClientOnly`]); writing such a value is refused by the editor's
//! validation, the warning covers what is already on disk.
//!
//! Inbound warnings are version-aware (Roadmap §2.6 stage 0.7, [`super::core_version`]): with the
//! installed core known, "ignored by Xray-core" fires only from the release that dropped the key,
//! and a mask newer than the core gets [`CompatibilityWarningId::RequiresNewerCore`].

use std::borrow::Cow;

use serde_json::Value;

use super::core_version::{CoreFeature, XrayCoreVersion};
use super::open_proxy::open_proxy_location;
use super::plaintext_outbound::forbidden_plaintext_address;
use super::{effective_security, inbound_finalmask_chain_use, outbound_finalmask_chain_use};
use crate::xray::config::inbound_security::REALITY_IGNORED_ALPN_KEY;

use crate::xray::config::stream::{
    quic_transport_of,
    FinalMaskChain, NOISE_EXP_KIND, StreamDirection, finalmask_layer_type_applies,
    finalmask_tcp_layer_faces_probes,
    xdns_has_legacy_fields, xmc_has_legacy_usernames,
};

use crate::xray::config::inbound_stream::{KCP_IGNORED_FIELDS, KCP_LEGACY_OBFUSCATION_FIELDS};
use crate::xray::config::outbound_protocol::FREEDOM_LEGACY_STRATEGY_KEYS;

/// Stable warning identifiers (never block Save; see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompatibilityWarningId {
    /// The config uses `feature`, but the installed core predates it (Roadmap §2.6 stage 0.7).
    RequiresNewerCore {
        feature: CoreFeature,
        installed: XrayCoreVersion,
    },
    /// `streamSettings.finalmask.quicParams.udpHop` — port hopping moved to the `udphop` UDP mask
    /// (XTLS/Xray-core#6327); `QuicParamsConfig` no longer has the field.
    QuicParamsUdpHopIgnored,
    /// `streamSettings.finalmask.quicParams.udpHop` in an inbound: only the Hysteria dialer ever
    /// read it (before #6327 too), so on a listener it never had an effect, on any core. The
    /// editor removes it (Roadmap §2.6 stage 3.2) — a `udphop` layer would be client-only as well.
    QuicParamsUdpHopClientOnly,
    /// `streamSettings.finalmask.quicParams` on a transport that does not run over QUIC — only
    /// Hysteria and XHTTP with TLS ALPN exactly `["h3"]` read it (Roadmap §2.6 stage 3.3).
    QuicParamsUnusedTransport,
    /// A non-empty `finalmask.tcp[]` / `finalmask.udp[]` that none of the inbound's listeners
    /// applies — e.g. `udp[]` on RAW, `tcp[]` on mKCP / Hysteria / XHTTP/3 (Roadmap §2.6 stage
    /// 4.3, [`super::inbound_finalmask_chain_use`]). The layers stay on disk, unused.
    FinalMaskChainUnused,
    /// `security: reality` with a `finalmask.tcp[]` layer that transforms or checks the incoming
    /// stream (`header-custom` / `sudoku` / `xmc`). Xray-core composes them — the mask wraps the
    /// socket, REALITY runs on top (`tcp/hub.go`) — but an active prober now meets the mask
    /// instead of REALITY forwarding it to `target` (Roadmap §2.6 stage 5.1; formerly gate G4).
    RealityProbeSeesFinalMask,
    /// `streamSettings.realitySettings.alpn` with `security: reality` — not a field of the core's
    /// `REALITYConfig` nor of the REALITY docs; the REALITY server negotiates no ALPN.
    RealityAlpnIgnored,
    /// A non-empty `settings.fallbacks[i].alpn` with `security: reality` — a REALITY connection
    /// negotiates no ALPN (`NextProtos: nil`), so only fallbacks with an empty `alpn` are chosen.
    RealityFallbackAlpnNeverMatches,
    /// `sockopt` inside a `finalmask.udp[]` layer of type `udphop` — removed from the mask
    /// (XTLS/Xray-core#6754); `UDPHop` no longer has the field. Outbound-side (the mask is
    /// client-only, see [`Self::UdpHopClientOnly`]).
    UdpHopSockoptIgnored,
    /// A client-only `finalmask.udp[]` layer (`udphop`) in an inbound: its server wrapper returns
    /// `"udphop: client only"`, so a UDP listener with it fails when Xray starts (`xray run
    /// -test` passes — it never listens); on a TCP-only transport the layer is simply unused.
    UdpHopClientOnly,
    /// `kcpSettings.congestion` / `readBufferSize` / `writeBufferSize` — not fields of the core's
    /// `KCPConfig` (`infra/conf/transport_method.go`) any more (Roadmap §2.6 stage 0.6); read up to
    /// v26.9.8 ([`CoreFeature::KcpConfigSlimmed`]).
    KcpFieldIgnored,
    /// `kcpSettings.header` / `seed` — still declared in `KCPConfig` but never read by its
    /// `Build()` (v26.9.9+); mKCP obfuscation is one or two `mkcp-legacy` layers in
    /// `finalmask.udp` now (Roadmap §2.6 stage 5.2 migrates them).
    KcpLegacyObfuscationIgnored,
    /// `kcpSettings.header` / `seed` on a core from v26.1.31 to v26.9.8: `KCPConfig.Build()` fails
    /// with a "removed feature" error, so Xray does not start at all
    /// ([`CoreFeature::KcpHeaderSeedRemoved`] up to [`CoreFeature::KcpConfigSlimmed`]).
    KcpLegacyObfuscationRejected,
    /// `xdns` settings in the pre-v26.9.30 string schema (`domains` / `resolvers` strings, or
    /// `domain`) on a core with the object schema (XTLS/Xray-core#6718): strings fail to decode,
    /// `domain` is ignored. The editor offers a migration.
    XdnsLegacySchema,
    /// `xmc` settings in the pre-v26.7.28 schema (`usernames` without `profiles`) on a core with
    /// signed profiles (XTLS/Xray-core#6487): `usernames` is ignored and the layer is refused
    /// without `profiles`. The editor can start profiles from the usernames.
    XmcLegacyUsernames,
    /// Freedom `settings.domainStrategy` / `settings.targetStrategy` — `FreedomConfig.Build()`
    /// still validates it, but the Freedom handler resolves only with
    /// `streamSettings.sockopt.domainStrategy` (XTLS/Xray-core#6058); the key is not documented.
    FreedomSettingsDomainStrategyIgnored,
    /// `tlsSettings.allowInsecure: true` — a removed feature since Xray-core v26.1.31 (2c92339):
    /// `TLSConfig.Build()` fails, so the config does not load. `pinnedPeerCertSha256` /
    /// `verifyPeerCertByName` replace it (Roadmap §4.2).
    TlsAllowInsecureRemoved,
    /// A `Host` entry in `wsSettings.headers` — deprecated by `WebSocketConfig.Build()`: it is
    /// moved into `host` when that is empty and dropped otherwise (Roadmap §4.2).
    WsHostHeaderDeprecated,
    /// A non-empty `finalmask.tcp[]` / `finalmask.udp[]` the outbound's dialer never applies —
    /// e.g. `udp[]` on RAW, `tcp[]` on mKCP / Hysteria / XHTTP/3 (Roadmap §2.6 stage 7.1,
    /// [`super::outbound_finalmask_chain_use`]).
    OutboundFinalMaskChainUnused,
    /// A VLESS / Trojan outbound without TLS / REALITY (VLESS: and without `encryption`) to a
    /// public server address — refused at load since Xray-core v26.7.11
    /// ([`CoreFeature::PlaintextOutboundForbidden`], `validateOutboundTransportSecurity`).
    PlaintextOutboundForbidden,
    /// Outbound `proxySettings` (any non-`null` value, any protocol) — refused at load since
    /// Xray-core v26.9.8 ([`CoreFeature::OutboundProxySettingsRemoved`]); the editor migrates it
    /// into `streamSettings.sockopt.dialerProxy`.
    OutboundProxySettingsRemoved,
    /// Freedom with `streamSettings.sockopt.addressPortStrategy` other than `none` on disk —
    /// refused at load since Xray-core v26.9.8; Shell Save is blocked by gate
    /// [`super::CompatibilityGateId::G14`] until the editor removes it.
    FreedomAddressPortStrategyRejected,
    /// A VLESS outbound in the legacy `vnext[]` form with other than one server holding one user —
    /// `VLessOutboundConfig.Build()` refuses it, so the config does not load. Not version-gated:
    /// Feldjäger targets current cores (Roadmap §4.2).
    VlessVnextNotSingle,
    /// A Socks / `mixed` / HTTP inbound without authentication on an outside-facing `listen` —
    /// an open proxy ([`super::open_proxy`]); [`WarningSeverity::Danger`].
    OpenProxyInbound,
    /// TUN `settings.autoSystemWfpBlockLeak` — Windows Filtering Platform rules, applied only
    /// when Xray runs on Windows; Feldjäger manages Linux servers (`docs/rules.md`).
    TunWfpBlockLeakWindowsOnly,
    /// WireGuard outbound `settings.domainStrategy` — no longer read since Xray-core v26.9.30
    /// ([`CoreFeature::WireGuardRemoteDnsIpOnly`]).
    WireGuardDomainStrategyIgnored,
    /// WireGuard outbound `settings.remoteDNS[i]` that is not an IP address (the removed `"local"`
    /// mode, a domain) — Xray-core v26.9.30+ panics at start, `xray run -test` included;
    /// [`WarningSeverity::Danger`].
    WireGuardRemoteDnsNotIp,
}

/// How a warning is shown: [`Self::Danger`] gets the red road-sign style in the GUI and
/// `!!!` markers in plain-text status lines ([`with_warning_suffix`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningSeverity {
    /// The config does not do what it looks like it does (the default).
    Caution,
    /// The config endangers the server itself, e.g. an open proxy.
    Danger,
}

impl CompatibilityWarningId {
    /// Display severity (see [`WarningSeverity`]).
    pub fn severity(self) -> WarningSeverity {
        match self {
            Self::OpenProxyInbound | Self::WireGuardRemoteDnsNotIp => WarningSeverity::Danger,
            _ => WarningSeverity::Caution,
        }
    }

    /// Short user-facing explanation (no secrets).
    pub fn message(self) -> Cow<'static, str> {
        let text = match self {
            Self::RequiresNewerCore { feature, installed } => {
                return Cow::Owned(format!(
                    "{} requires Xray-core {} or newer (XTLS/Xray-core#{}); installed {}",
                    feature.label(),
                    feature.min_version(),
                    feature.pull_request(),
                    installed,
                ));
            }
            Self::QuicParamsUdpHopIgnored => {
                "ignored by Xray-core: port hopping moved to a `udphop` layer in `finalmask.udp` \
                 (XTLS/Xray-core#6327); use \"Migrate udpHop\" in the editor"
            }
            Self::QuicParamsUdpHopClientOnly => {
                "no effect on an inbound: port hopping is client-side — only the Hysteria dialer \
                 ever read `udpHop`, and Xray-core v26.9.9+ ignores it everywhere \
                 (XTLS/Xray-core#6327); use \"Remove udpHop\" in the editor. Hopping belongs in \
                 the client's `udphop` layer"
            }
            Self::QuicParamsUnusedTransport => {
                "no effect: quicParams is read only by QUIC transports — Hysteria, and XHTTP with \
                 `security: tls` and `tlsSettings.alpn` exactly [\"h3\"]"
            }
            Self::FinalMaskChainUnused => {
                "no effect: none of this inbound's listeners uses this chain, so its layers are \
                 never applied — tcp[] wraps TCP listeners (RAW, WebSocket, gRPC, HTTPUpgrade, \
                 XHTTP over TCP), udp[] wraps UDP sockets (mKCP, Hysteria, XHTTP/3, a Tunnel \
                 whose allowedNetwork includes udp)"
            }
            Self::RealityProbeSeesFinalMask => {
                "weakens REALITY's camouflage: this layer sits below REALITY, so a scanner probing \
                 the port meets the mask's handshake instead of being forwarded to the REALITY \
                 target and seeing its real TLS site. Works, but the port no longer looks like the \
                 target (fragment layers are fine)"
            }
            Self::RealityAlpnIgnored => {
                "ignored by Xray-core: REALITY has no `alpn` setting and negotiates no ALPN; use \
                 \"Remove alpn\" on the Security tab"
            }
            Self::RealityFallbackAlpnNeverMatches => {
                "never matches with REALITY: no ALPN is negotiated, so only fallbacks with an \
                 empty `alpn` are used"
            }
            Self::UdpHopSockoptIgnored => {
                "ignored by Xray-core: `sockopt` was removed from the `udphop` mask \
                 (XTLS/Xray-core#6754)"
            }
            Self::UdpHopClientOnly => {
                "`udphop` is a client-only mask: Xray-core cannot listen with it (\"udphop: client \
                 only\"), so a UDP inbound fails to start once Xray runs (`xray run -test` does not \
                 catch it). Remove the layer — port hopping belongs in the client's outbound"
            }
            Self::KcpFieldIgnored => {
                "ignored by Xray-core: not an mKCP setting any more (`KCPConfig` has only mtu, \
                 tti, uplinkCapacity, downlinkCapacity, cwndMultiplier, maxSendingWindow)"
            }
            Self::KcpLegacyObfuscationIgnored => {
                "ignored by Xray-core: mKCP header/seed obfuscation is not applied any more; the \
                 equivalent is one or two `mkcp-legacy` layers in `finalmask.udp` — use \
                 \"Migrate header/seed to FinalMask\" in the editor"
            }
            Self::KcpLegacyObfuscationRejected => {
                "rejected by the installed Xray-core: from v26.1.31 to v26.9.8 mKCP header/seed is a \
                 removed feature and the config does not load (XTLS/Xray-core#5560); move it to \
                 `finalmask.udp` (\"Migrate header/seed to FinalMask\", needs v26.6.1+)"
            }
            Self::XdnsLegacySchema => {
                "pre-v26.9.30 xdns schema: Xray-core v26.9.30+ rejects string domains / resolvers \
                 and ignores `domain` (XTLS/Xray-core#6718); use \"Migrate to the v26.9.30 schema\" \
                 in the editor"
            }
            Self::XmcLegacyUsernames => {
                "pre-v26.7.28 xmc schema: Xray-core v26.7.28+ ignores `usernames` and refuses the \
                 layer without `profiles` (signed Minecraft profiles, XTLS/Xray-core#6487); use \
                 \"Start profiles from usernames\" in the editor"
            }
            Self::FreedomSettingsDomainStrategyIgnored => {
                "ignored by Xray-core: Freedom resolves domains with \
                 `streamSettings.sockopt.domainStrategy` (XTLS/Xray-core#6058); use \
                 \"Migrate to sockopt\" in the editor"
            }
            Self::TlsAllowInsecureRemoved => {
                "rejected by Xray-core v26.1.31+: `allowInsecure` is a removed feature and the \
                 config does not load; pin the server certificate with `pinnedPeerCertSha256` or \
                 accept its names with `verifyPeerCertByName` — use \"Remove allowInsecure\" in \
                 the editor"
            }
            Self::PlaintextOutboundForbidden => {
                "rejected by Xray-core v26.7.11+: a VLESS / Trojan outbound to a public address \
                 needs security tls or reality (VLESS: or encryption); only private IPs and \
                 local names (localhost, *.lan, *.local, dotless names, …) may go unencrypted \
                 (XTLS/Xray-core#6303)"
            }
            Self::OutboundProxySettingsRemoved => {
                "rejected by Xray-core v26.9.8+: outbound `proxySettings` is a removed feature for \
                 every protocol and the config does not load (XTLS/Xray-core#6058); chain through \
                 another outbound with `streamSettings.sockopt.dialerProxy` — use \"Migrate to \
                 sockopt.dialerProxy\" in the editor"
            }
            Self::VlessVnextNotSingle => {
                "rejected by Xray-core: a VLESS outbound takes exactly one vnext[] server with \
                 exactly one user, and the config does not load; split it into one outbound per \
                 server/user and pick between them with a routing balancer"
            }
            Self::OutboundFinalMaskChainUnused => {
                "no effect: this outbound's transport never dials through this chain, so its \
                 layers are never applied — tcp[] wraps TCP dials (RAW, WebSocket, gRPC, \
                 HTTPUpgrade, XHTTP over TCP), udp[] wraps UDP dials (mKCP, Hysteria, XHTTP/3)"
            }
            Self::OpenProxyInbound => {
                "open proxy: no authentication and `listen` is reachable from outside (default \
                 0.0.0.0, or a public address) — anyone can relay traffic through this server, \
                 and hosting providers suspend servers for that. Bind `listen` to 127.0.0.1 / a \
                 private address, or require a password (Socks: `auth: \"password\"` + \
                 `accounts`; HTTP: `accounts`)"
            }
            Self::FreedomAddressPortStrategyRejected => {
                "rejected by Xray-core v26.9.8+: Freedom does not support \
                 `sockopt.addressPortStrategy` and the config does not load \
                 (XTLS/Xray-core#6058); use \"Remove addressPortStrategy\" in the editor"
            }
            Self::WsHostHeaderDeprecated => {
                "deprecated by Xray-core: a `Host` header is moved into `host` (and dropped when \
                 `host` is set); use the host field"
            }
            Self::TunWfpBlockLeakWindowsOnly => {
                "no effect on a Linux server: Windows Filtering Platform leak blocking applies \
                 only when Xray runs on Windows (XTLS/Xray-core#6853); the values are still \
                 checked at load — only \"dns\" and \"misconfigtun\" are accepted"
            }
            Self::WireGuardDomainStrategyIgnored => {
                "ignored by Xray-core v26.9.30+: WireGuard outbound no longer reads \
                 `domainStrategy` (XTLS/Xray-core#6771); resolve names with \
                 `streamSettings.sockopt.domainStrategy` or routing instead"
            }
            Self::WireGuardRemoteDnsNotIp => {
                "Xray-core v26.9.30+ crashes at start: every `remoteDNS` entry must be an IP \
                 address — the \"local\" mode and domain names were removed \
                 (XTLS/Xray-core#6771); `xray run -test` panics too. Replace it with an IP, e.g. \
                 1.1.1.1"
            }
        };
        Cow::Borrowed(text)
    }
}

/// One non-blocking warning: what ([`CompatibilityWarningId`]) and where (JSON path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityWarning {
    /// Warning kind.
    pub id: CompatibilityWarningId,
    /// JSON path inside the inbound / outbound, e.g.
    /// `streamSettings.finalmask.udp[1].settings.sockopt`.
    pub location: String,
}

impl CompatibilityWarning {
    /// `"<location>: <message>"` — the form shown in the GUI and in the status bar.
    pub fn text(&self) -> String {
        format!("{}: {}", self.location, self.id.message())
    }
}

/// All non-blocking warnings for one inbound JSON object, in a stable order (an open proxy first,
/// then config order: `streamSettings.finalmask`, then `streamSettings.kcpSettings`, REALITY, then
/// `streamSettings.tlsSettings`). `core` is the installed
/// Xray-core version from Discovery; `None` = unknown, treated as the current core.
pub fn inbound_warnings(inbound: &Value, core: Option<XrayCoreVersion>) -> Vec<CompatibilityWarning> {
    let mut warnings = Vec::new();
    // Before the stream checks: a Socks / HTTP inbound usually has no `streamSettings`.
    if let Some(location) = open_proxy_location(inbound) {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::OpenProxyInbound,
            location,
        });
    }
    // Before the stream checks: TUN has no `streamSettings`.
    tun_warnings(inbound, core, &mut warnings);
    let Some(stream) = inbound.get("streamSettings") else {
        return warnings;
    };
    if let Some(finalmask) = stream.get("finalmask") {
        // Unknown listener set (protocol / transport outside the table) → no claim either way.
        if let Some(used) = inbound_finalmask_chain_use(inbound) {
            for chain in [FinalMaskChain::Tcp, FinalMaskChain::Udp] {
                let has_layers = finalmask
                    .get(chain.key())
                    .and_then(Value::as_array)
                    .is_some_and(|layers| !layers.is_empty());
                if has_layers && !used.uses(chain) {
                    warnings.push(CompatibilityWarning {
                        id: CompatibilityWarningId::FinalMaskChainUnused,
                        location: format!("streamSettings.finalmask.{}", chain.key()),
                    });
                }
            }
        }
        finalmask_warnings(finalmask, StreamDirection::Inbound, core, &mut warnings);
        let has_quic_params = finalmask.get("quicParams").is_some_and(|value| !value.is_null());
        if has_quic_params && quic_transport_of(stream).is_none() {
            warnings.push(CompatibilityWarning {
                id: CompatibilityWarningId::QuicParamsUnusedTransport,
                location: "streamSettings.finalmask.quicParams".to_owned(),
            });
        }
    }
    if let Some(kcp) = stream.get("kcpSettings").and_then(Value::as_object) {
        // The core builds `kcpSettings` whenever it is present, whatever `network` says, so the
        // keys matter in either case. What they do depends on the release (Roadmap §2.6 stage
        // 5.2): up to v26.1.23 header/seed work, v26.1.31 – v26.9.8 they fail the load, from
        // v26.9.9 they and the buffer/congestion keys are ignored.
        let slimmed = CoreFeature::KcpConfigSlimmed.available_in(core);
        let header_seed_removed = CoreFeature::KcpHeaderSeedRemoved.available_in(core);
        for (key, value) in kcp {
            let id = if KCP_IGNORED_FIELDS.contains(&key.as_str()) {
                if !slimmed {
                    continue;
                }
                CompatibilityWarningId::KcpFieldIgnored
            } else if KCP_LEGACY_OBFUSCATION_FIELDS.contains(&key.as_str()) {
                if slimmed {
                    CompatibilityWarningId::KcpLegacyObfuscationIgnored
                } else if header_seed_removed && !(key == "seed" && value.is_null()) {
                    // The check is `HeaderConfig != nil || Seed != nil`: a raw `"header": null`
                    // is non-nil, a `"seed": null` pointer is nil.
                    CompatibilityWarningId::KcpLegacyObfuscationRejected
                } else {
                    continue;
                }
            } else {
                continue;
            };
            warnings.push(CompatibilityWarning {
                id,
                location: format!("streamSettings.kcpSettings.{key}"),
            });
        }
    }
    if effective_security(inbound) == "reality" {
        let tcp_layers = stream
            .get("finalmask")
            .and_then(|finalmask| finalmask.get("tcp"))
            .and_then(Value::as_array);
        for (index, layer) in tcp_layers.into_iter().flatten().enumerate() {
            let faces_probes = layer
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(finalmask_tcp_layer_faces_probes);
            if faces_probes {
                warnings.push(CompatibilityWarning {
                    id: CompatibilityWarningId::RealityProbeSeesFinalMask,
                    location: format!("streamSettings.finalmask.tcp[{index}].type"),
                });
            }
        }
        if stream
            .get("realitySettings")
            .is_some_and(|reality| reality.get(REALITY_IGNORED_ALPN_KEY).is_some())
        {
            warnings.push(CompatibilityWarning {
                id: CompatibilityWarningId::RealityAlpnIgnored,
                location: format!("streamSettings.realitySettings.{REALITY_IGNORED_ALPN_KEY}"),
            });
        }
        let fallbacks = inbound
            .get("settings")
            .and_then(|settings| settings.get("fallbacks"))
            .and_then(Value::as_array);
        for (index, fallback) in fallbacks.into_iter().flatten().enumerate() {
            let alpn = fallback.get("alpn").and_then(Value::as_str).map(str::trim);
            if alpn.is_some_and(|alpn| !alpn.is_empty()) {
                warnings.push(CompatibilityWarning {
                    id: CompatibilityWarningId::RealityFallbackAlpnNeverMatches,
                    location: format!("settings.fallbacks[{index}].alpn"),
                });
            }
        }
    }
    tls_allow_insecure_warning(stream, &mut warnings);
    warnings
}

/// `tlsSettings.allowInsecure: true` with `security: tls` — `TLSConfig.Build()` rejects it on
/// either side since v26.1.31 (checked with `xray run -test` 26.9.30 on a VLESS inbound).
fn tls_allow_insecure_warning(stream: &Value, warnings: &mut Vec<CompatibilityWarning>) {
    let tls = stream
        .get("security")
        .and_then(Value::as_str)
        .is_some_and(|security| security.trim().eq_ignore_ascii_case("tls"));
    let allow_insecure = stream
        .get("tlsSettings")
        .and_then(|tls| tls.get("allowInsecure"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if tls && allow_insecure {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::TlsAllowInsecureRemoved,
            location: "streamSettings.tlsSettings.allowInsecure".to_owned(),
        });
    }
}

/// All non-blocking warnings for one outbound JSON object, in config order. `core` is the
/// installed Xray-core version from Discovery; `None` = unknown, treated as the current core.
pub fn outbound_warnings(outbound: &Value, core: Option<XrayCoreVersion>) -> Vec<CompatibilityWarning> {
    let mut warnings = Vec::new();
    // `null` decodes to a nil pointer in the core; every other value fails the load.
    if CoreFeature::OutboundProxySettingsRemoved.available_in(core)
        && outbound.get("proxySettings").is_some_and(|value| !value.is_null())
    {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::OutboundProxySettingsRemoved,
            location: "proxySettings".to_owned(),
        });
    }
    if CoreFeature::PlaintextOutboundForbidden.available_in(core)
        && let Some(location) = forbidden_plaintext_address(outbound)
    {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::PlaintextOutboundForbidden,
            location,
        });
    }
    if let Some(location) = vless_vnext_not_single(outbound) {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::VlessVnextNotSingle,
            location,
        });
    }
    wireguard_outbound_warnings(outbound, core, &mut warnings);
    let is_freedom = outbound
        .get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|protocol| protocol.trim().eq_ignore_ascii_case("freedom"));
    if let (true, Some(settings)) = (is_freedom, outbound.get("settings").and_then(Value::as_object)) {
        for key in settings.keys() {
            if FREEDOM_LEGACY_STRATEGY_KEYS.contains(&key.as_str()) {
                warnings.push(CompatibilityWarning {
                    id: CompatibilityWarningId::FreedomSettingsDomainStrategyIgnored,
                    location: format!("settings.{key}"),
                });
            }
        }
    }
    // Same predicate and version boundary as gate G14, which blocks writing it.
    if CoreFeature::FreedomAddressPortStrategyForbidden.available_in(core)
        && super::freedom_address_port_strategy_set(outbound)
    {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::FreedomAddressPortStrategyRejected,
            location: "streamSettings.sockopt.addressPortStrategy".to_owned(),
        });
    }
    if let Some(stream) = outbound.get("streamSettings") {
        if let Some(finalmask) = stream.get("finalmask") {
            outbound_finalmask_warnings(outbound, stream, finalmask, core, &mut warnings);
        }
        outbound_stream_warnings(stream, &mut warnings);
    }
    warnings
}

/// Location of the `vnext[]` / `users[]` array a VLESS outbound has other than one entry in, when
/// the core reads it — a non-null flat `settings.address` makes the core ignore `vnext`.
fn vless_vnext_not_single(outbound: &Value) -> Option<String> {
    let is_vless = outbound
        .get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|protocol| protocol.trim().eq_ignore_ascii_case("vless"));
    let settings = outbound.get("settings").filter(|_| is_vless)?;
    if settings.get("address").is_some_and(|address| !address.is_null()) {
        return None;
    }
    let servers = settings.get("vnext")?.as_array()?;
    if servers.len() != 1 {
        return Some("settings.vnext".to_owned());
    }
    let users = servers[0].get("users").and_then(Value::as_array);
    (users.map_or(0, Vec::len) != 1).then(|| "settings.vnext[0].users".to_owned())
}

/// `streamSettings.finalmask` of an outbound (Roadmap §2.6 stage 7.1): chains the dialer never
/// applies, the shared layer / version checks for the client side, and `quicParams` off QUIC.
fn outbound_finalmask_warnings(
    outbound: &Value,
    stream: &Value,
    finalmask: &Value,
    core: Option<XrayCoreVersion>,
    warnings: &mut Vec<CompatibilityWarning>,
) {
    if let Some(used) = outbound_finalmask_chain_use(outbound) {
        for chain in [FinalMaskChain::Tcp, FinalMaskChain::Udp] {
            let has_layers = finalmask
                .get(chain.key())
                .and_then(Value::as_array)
                .is_some_and(|layers| !layers.is_empty());
            if has_layers && !used.uses(chain) {
                warnings.push(CompatibilityWarning {
                    id: CompatibilityWarningId::OutboundFinalMaskChainUnused,
                    location: format!("streamSettings.finalmask.{}", chain.key()),
                });
            }
        }
    }
    finalmask_warnings(finalmask, StreamDirection::Outbound, core, warnings);
    let has_quic_params = finalmask.get("quicParams").is_some_and(|value| !value.is_null());
    if has_quic_params && quic_transport_of(stream).is_none() {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::QuicParamsUnusedTransport,
            location: "streamSettings.finalmask.quicParams".to_owned(),
        });
    }
}

/// Client-side `streamSettings` warnings (Roadmap §4.2), in config order.
fn outbound_stream_warnings(stream: &Value, warnings: &mut Vec<CompatibilityWarning>) {
    // The core builds `wsSettings` whenever it is present, whatever the transport.
    if let Some(headers) = stream
        .get("wsSettings")
        .and_then(|ws| ws.get("headers"))
        .and_then(Value::as_object)
    {
        for key in headers.keys().filter(|key| key.eq_ignore_ascii_case("host")) {
            warnings.push(CompatibilityWarning {
                id: CompatibilityWarningId::WsHostHeaderDeprecated,
                location: format!("streamSettings.wsSettings.headers.{key}"),
            });
        }
    }
    tls_allow_insecure_warning(stream, warnings);
}

/// FinalMask warnings for one side of a connection: [`inbound_warnings`] and, for the client
/// side, [`outbound_warnings`] (Roadmap §2.6 stage 7.1).
fn finalmask_warnings(
    finalmask: &Value,
    direction: StreamDirection,
    core: Option<XrayCoreVersion>,
    warnings: &mut Vec<CompatibilityWarning>,
) {
    // Layer types are matched case- and whitespace-insensitively, like the rest of this module.
    let layer_is = |layer: &Value, kind: &str| {
        layer
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(kind))
    };

    if let Some(tcp) = finalmask.get("tcp").and_then(Value::as_array) {
        for (index, layer) in tcp.iter().enumerate() {
            if !layer_is(layer, "xmc") {
                continue;
            }
            if !CoreFeature::XmcTcpMask.available_in(core) {
                // The core does not know the layer at all; its schema is moot.
                push_if_core_too_old(
                    CoreFeature::XmcTcpMask,
                    core,
                    format!("streamSettings.finalmask.tcp[{index}].type"),
                    warnings,
                );
                continue;
            }
            let Some(settings) = layer.get("settings").filter(|settings| settings.is_object()) else {
                continue;
            };
            // v26.7.11 – v26.7.27 read `usernames` and ignore `profiles`; later releases the reverse.
            if xmc_has_legacy_usernames(settings) && CoreFeature::XmcProfilesSchema.available_in(core) {
                warnings.push(CompatibilityWarning {
                    id: CompatibilityWarningId::XmcLegacyUsernames,
                    location: format!("streamSettings.finalmask.tcp[{index}].settings.usernames"),
                });
            }
            if settings.get("profiles").and_then(Value::as_array).is_some_and(|profiles| !profiles.is_empty()) {
                push_if_core_too_old(
                    CoreFeature::XmcProfilesSchema,
                    core,
                    format!("streamSettings.finalmask.tcp[{index}].settings.profiles"),
                    warnings,
                );
            }
        }
    }

    if let Some(udp) = finalmask.get("udp").and_then(Value::as_array) {
        for (index, layer) in udp.iter().enumerate() {
            if layer_is(layer, "mkcp-legacy") {
                push_if_core_too_old(
                    CoreFeature::MkcpLegacyMask,
                    core,
                    format!("streamSettings.finalmask.udp[{index}].type"),
                    warnings,
                );
                continue;
            }
            if layer_is(layer, "xdns") {
                let settings = layer.get("settings").filter(|settings| settings.is_object());
                let location = format!("streamSettings.finalmask.udp[{index}].settings");
                if settings.is_some_and(xdns_has_legacy_fields)
                    && CoreFeature::XdnsObjectSchema.available_in(core)
                {
                    warnings.push(CompatibilityWarning {
                        id: CompatibilityWarningId::XdnsLegacySchema,
                        location: location.clone(),
                    });
                }
                let has_objects = |key: &str| {
                    settings
                        .and_then(|settings| settings.get(key))
                        .and_then(Value::as_array)
                        .is_some_and(|items| items.iter().any(Value::is_object))
                };
                if has_objects("domains") || has_objects("resolvers") {
                    push_if_core_too_old(CoreFeature::XdnsObjectSchema, core, location, warnings);
                }
                continue;
            }
            if layer_is(layer, "noise") {
                let items = layer
                    .get("settings")
                    .and_then(|settings| settings.get("noise"))
                    .and_then(Value::as_array);
                for (item_index, item) in items.into_iter().flatten().enumerate() {
                    let is_exp = item
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind.eq_ignore_ascii_case(NOISE_EXP_KIND));
                    if is_exp {
                        push_if_core_too_old(
                            CoreFeature::NoiseExpPacket,
                            core,
                            format!("streamSettings.finalmask.udp[{index}].settings.noise[{item_index}].type"),
                            warnings,
                        );
                    }
                }
                continue;
            }
            if !layer_is(layer, "udphop") {
                continue;
            }
            if !CoreFeature::UdpHopUdpMask.available_in(core) {
                // The core does not know the layer at all; `sockopt` inside it is moot.
                push_if_core_too_old(
                    CoreFeature::UdpHopUdpMask,
                    core,
                    format!("streamSettings.finalmask.udp[{index}].type"),
                    warnings,
                );
                continue;
            }
            if !finalmask_layer_type_applies("udphop", FinalMaskChain::Udp, direction) {
                // The whole layer has to go; its `sockopt` is moot.
                warnings.push(CompatibilityWarning {
                    id: CompatibilityWarningId::UdpHopClientOnly,
                    location: format!("streamSettings.finalmask.udp[{index}].type"),
                });
                continue;
            }
            let has_sockopt = layer
                .get("settings")
                .is_some_and(|settings| settings.get("sockopt").is_some());
            // v26.9.9 – v26.9.29 still read `udphop.sockopt`.
            if has_sockopt && CoreFeature::UdpHopSockoptRemoved.available_in(core) {
                warnings.push(CompatibilityWarning {
                    id: CompatibilityWarningId::UdpHopSockoptIgnored,
                    location: format!("streamSettings.finalmask.udp[{index}].settings.sockopt"),
                });
            }
        }
    }

    // Before the `udphop` mask, `quicParams.udpHop` was the port-hopping setting — of the dialer
    // only: on an inbound it is dead on every core, on an outbound from v26.9.9 on.
    let has_legacy_udp_hop = finalmask
        .get("quicParams")
        .is_some_and(|quic_params| quic_params.get("udpHop").is_some());
    let id = match direction {
        StreamDirection::Inbound => Some(CompatibilityWarningId::QuicParamsUdpHopClientOnly),
        StreamDirection::Outbound => CoreFeature::UdpHopUdpMask
            .available_in(core)
            .then_some(CompatibilityWarningId::QuicParamsUdpHopIgnored),
    };
    if has_legacy_udp_hop && let Some(id) = id {
        warnings.push(CompatibilityWarning {
            id,
            location: "streamSettings.finalmask.quicParams.udpHop".to_owned(),
        });
    }
}

/// TUN `settings` keys added in v26.9.30 (`infra/conf/tun.go`, XTLS/Xray-core#6773 / #6853): an
/// older core does not know them and silently drops them; `autoSystemWfpBlockLeak` also does
/// nothing outside Windows.
fn tun_warnings(inbound: &Value, core: Option<XrayCoreVersion>, warnings: &mut Vec<CompatibilityWarning>) {
    let is_tun = inbound
        .get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|protocol| protocol.trim().eq_ignore_ascii_case("tun"));
    let Some(settings) = inbound.get("settings").filter(|_| is_tun) else {
        return;
    };
    // Only values that change behaviour: `false` / `[]` / `null` equal the old core's defaults.
    if settings.get("autoSystemDnsToGateway").and_then(Value::as_bool) == Some(true) {
        let location = "settings.autoSystemDnsToGateway".to_owned();
        push_if_core_too_old(CoreFeature::TunAutoSystemDnsAndLeakBlock, core, location, warnings);
    }
    let blocks_leaks = settings
        .get("autoSystemWfpBlockLeak")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty());
    if blocks_leaks {
        let location = "settings.autoSystemWfpBlockLeak".to_owned();
        push_if_core_too_old(CoreFeature::TunAutoSystemDnsAndLeakBlock, core, location.clone(), warnings);
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::TunWfpBlockLeakWindowsOnly,
            location,
        });
    }
}

/// Whether `text` is what Go's `netip.ParseAddr` accepts: an IPv4 / IPv6 address, an IPv6 one
/// optionally with a `%zone`. WireGuard `remoteDNS` entries go through `netip.MustParseAddr`
/// since Xray-core v26.9.30 (XTLS/Xray-core#6771), so anything else panics at start.
pub fn is_netip_addr(text: &str) -> bool {
    if text.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    text.split_once('%').is_some_and(|(address, zone)| {
        !zone.is_empty() && address.parse::<std::net::Ipv6Addr>().is_ok()
    })
}

/// WireGuard outbound keys changed by XTLS/Xray-core#6771 (v26.9.30). The generic WireGuard
/// Shell is retired; the WARP outbound (Tier 3) is the WireGuard outbound Feldjäger writes.
fn wireguard_outbound_warnings(
    outbound: &Value,
    core: Option<XrayCoreVersion>,
    warnings: &mut Vec<CompatibilityWarning>,
) {
    let is_wireguard = outbound
        .get("protocol")
        .and_then(Value::as_str)
        .is_some_and(|protocol| protocol.trim().eq_ignore_ascii_case("wireguard"));
    if !is_wireguard || !CoreFeature::WireGuardRemoteDnsIpOnly.available_in(core) {
        return;
    }
    let Some(settings) = outbound.get("settings") else {
        return;
    };
    if settings.get("domainStrategy").is_some_and(|value| !value.is_null()) {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::WireGuardDomainStrategyIgnored,
            location: "settings.domainStrategy".to_owned(),
        });
    }
    let entries = settings.get("remoteDNS").and_then(Value::as_array);
    for (index, entry) in entries.into_iter().flatten().enumerate() {
        // A non-string entry fails `json.Unmarshal` into `[]string` — a load error, not a panic.
        if entry.as_str().is_some_and(|text| !is_netip_addr(text)) {
            warnings.push(CompatibilityWarning {
                id: CompatibilityWarningId::WireGuardRemoteDnsNotIp,
                location: format!("settings.remoteDNS[{index}]"),
            });
        }
    }
}

/// [`CompatibilityWarningId::RequiresNewerCore`] when the installed core is known and older
/// than `feature`; nothing for an unknown version.
fn push_if_core_too_old(
    feature: CoreFeature,
    core: Option<XrayCoreVersion>,
    location: String,
    warnings: &mut Vec<CompatibilityWarning>,
) {
    if let Some(installed) = core
        && !feature.available_in(core)
    {
        warnings.push(CompatibilityWarning {
            id: CompatibilityWarningId::RequiresNewerCore { feature, installed },
            location,
        });
    }
}

/// Appends `" Warnings: a; b"` to a status message when there are warnings; unchanged otherwise.
/// A [`WarningSeverity::Danger`] warning is wrapped in `!!! … !!!` (the status bar is plain text).
pub fn with_warning_suffix(message: impl Into<String>, warnings: &[CompatibilityWarning]) -> String {
    let mut message = message.into();
    if !warnings.is_empty() {
        let joined = warnings
            .iter()
            .map(|warning| match warning.id.severity() {
                // Plain text has no road sign; three exclamation marks stand in for it.
                WarningSeverity::Danger => format!("!!! {} !!!", warning.text()),
                WarningSeverity::Caution => warning.text(),
            })
            .collect::<Vec<_>>()
            .join("; ");
        message.push_str(" Warnings: ");
        message.push_str(&joined);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn netip_addr_matches_go_parse_addr() {
        for ok in ["1.1.1.1", "2606:4700:4700::1111", "fe80::1%eth0", "::ffff:1.2.3.4"] {
            assert!(is_netip_addr(ok), "{ok}");
        }
        for bad in ["local", "dns.google", " 1.1.1.1", "01.1.1.1", "1.1.1.1/32", "fe80::1%", ""] {
            assert!(!is_netip_addr(bad), "{bad:?}");
        }
    }

    #[test]
    fn wireguard_outbound_v26_9_30_warnings() {
        let outbound = json!({"protocol": "wireguard", "settings": {
            "domainStrategy": "ForceIPv4",
            "remoteDNS": ["1.1.1.1", "local", "dns.google"]
        }});
        let found = |core| outbound_warnings(&outbound, core).into_iter().map(|w| (w.id, w.location)).collect::<Vec<_>>();
        let expected = vec![
            (CompatibilityWarningId::WireGuardDomainStrategyIgnored, "settings.domainStrategy".to_owned()),
            (CompatibilityWarningId::WireGuardRemoteDnsNotIp, "settings.remoteDNS[1]".to_owned()),
            (CompatibilityWarningId::WireGuardRemoteDnsNotIp, "settings.remoteDNS[2]".to_owned()),
        ];
        assert_eq!(found(None), expected);
        assert_eq!(found(Some(XrayCoreVersion::new(26, 9, 30))), expected);
        // v26.9.9 still reads domainStrategy and supports "local".
        assert!(found(Some(XrayCoreVersion::new(26, 9, 9))).is_empty());
        assert_eq!(CompatibilityWarningId::WireGuardRemoteDnsNotIp.severity(), WarningSeverity::Danger);
        let clean = json!({"protocol": "wireguard", "settings": {"remoteDNS": ["1.1.1.1"], "domainStrategy": null}});
        assert!(outbound_warnings(&clean, None).is_empty());
    }

    #[test]
    fn tun_v26_9_30_keys_warn_on_old_cores_and_wfp_is_windows_only() {
        let tun = json!({"protocol": "tun", "settings": {
            "gateway": ["10.0.0.1"],
            "autoSystemDnsToGateway": true,
            "autoSystemWfpBlockLeak": ["dns"]
        }});
        let ids = |core| inbound_warnings(&tun, core).into_iter().map(|w| (w.id, w.location)).collect::<Vec<_>>();
        let windows_only = (
            CompatibilityWarningId::TunWfpBlockLeakWindowsOnly,
            "settings.autoSystemWfpBlockLeak".to_owned(),
        );
        // Current / unknown core: only the Windows-only note.
        assert_eq!(ids(None), vec![windows_only.clone()]);
        assert_eq!(ids(Some(XrayCoreVersion::new(26, 9, 30))), vec![windows_only.clone()]);
        // v26.9.9 does not know either key.
        let installed = XrayCoreVersion::new(26, 9, 9);
        let too_old = CompatibilityWarningId::RequiresNewerCore {
            feature: CoreFeature::TunAutoSystemDnsAndLeakBlock,
            installed,
        };
        assert_eq!(
            ids(Some(installed)),
            vec![
                (too_old, "settings.autoSystemDnsToGateway".to_owned()),
                (too_old, "settings.autoSystemWfpBlockLeak".to_owned()),
                windows_only,
            ]
        );
        // Defaults (false / []) and other protocols: nothing.
        let defaults = json!({"protocol": "tun", "settings": {"autoSystemDnsToGateway": false, "autoSystemWfpBlockLeak": []}});
        assert!(inbound_warnings(&defaults, Some(installed)).is_empty());
        let not_tun = json!({"protocol": "tunnel", "settings": {"autoSystemWfpBlockLeak": ["dns"]}});
        assert!(inbound_warnings(&not_tun, None).is_empty());
    }

    #[test]
    fn open_proxy_inbound_is_a_danger_warning_without_stream_settings() {
        let inbound = json!({"protocol": "socks", "port": 1080, "settings": {"udp": true}});
        let warnings = inbound_warnings(&inbound, None);
        assert_eq!(
            warnings,
            vec![CompatibilityWarning {
                id: CompatibilityWarningId::OpenProxyInbound,
                location: "settings.auth".to_owned(),
            }]
        );
        assert_eq!(warnings[0].id.severity(), WarningSeverity::Danger);
        let local = json!({"protocol": "socks", "listen": "127.0.0.1", "port": 1080});
        assert!(inbound_warnings(&local, None).is_empty());
    }

    #[test]
    fn status_suffix_marks_danger_warnings_with_exclamation_marks() {
        let danger = CompatibilityWarning {
            id: CompatibilityWarningId::OpenProxyInbound,
            location: "settings.auth".to_owned(),
        };
        let caution = CompatibilityWarning {
            id: CompatibilityWarningId::RealityAlpnIgnored,
            location: "streamSettings.realitySettings.alpn".to_owned(),
        };
        assert_eq!(caution.id.severity(), WarningSeverity::Caution);
        let message = with_warning_suffix("Saved.", &[danger.clone(), caution.clone()]);
        assert_eq!(
            message,
            format!("Saved. Warnings: !!! {} !!!; {}", danger.text(), caution.text())
        );
    }

    #[test]
    fn clean_inbound_has_no_warnings() {
        assert!(inbound_warnings(&json!({"protocol": "vless"}), None).is_empty());
        let inbound = json!({"streamSettings": {"network": "hysteria", "finalmask": {
            "udp": [{"type": "salamander", "settings": {"password": "p"}}],
            "quicParams": {"congestion": "bbr"}
        }}});
        assert!(inbound_warnings(&inbound, None).is_empty());
    }

    /// Roadmap §2.6 stage 3.3: only Hysteria and XHTTP/3 (TLS, ALPN exactly ["h3"]) read
    /// quicParams; anywhere else it is flagged once, at the object.
    /// REALITY has no ALPN: `realitySettings.alpn` is ignored and fallbacks matching a non-empty
    /// alpn never fire; neither is flagged on TLS.
    #[test]
    fn flags_reality_alpn_and_fallback_alpn_only_on_reality() {
        let inbound = |security: &str| {
            json!({
                "protocol": "vless",
                "settings": {"fallbacks": [{"dest": 80}, {"dest": 81, "alpn": "h2"}, {"dest": 82, "alpn": " "}]},
                "streamSettings": {"network": "raw", "security": security,
                                   "realitySettings": {"alpn": ["h2"]}, "tlsSettings": {"alpn": ["h2", "http/1.1"]}}
            })
        };
        let found: Vec<_> = inbound_warnings(&inbound("reality"), None)
            .into_iter()
            .map(|w| (w.id, w.location))
            .collect();
        assert_eq!(
            found,
            vec![
                (CompatibilityWarningId::RealityAlpnIgnored, "streamSettings.realitySettings.alpn".to_owned()),
                (CompatibilityWarningId::RealityFallbackAlpnNeverMatches, "settings.fallbacks[1].alpn".to_owned()),
            ]
        );
        assert!(inbound_warnings(&inbound("tls"), None).is_empty());
    }

    #[test]
    fn flags_quic_params_on_a_transport_without_quic() {
        let with = |mut stream: Value| {
            stream["finalmask"] = json!({"quicParams": {"congestion": "bbr"}});
            inbound_warnings(&json!({"streamSettings": stream}), None)
                .into_iter()
                .map(|w| (w.id, w.location))
                .collect::<Vec<_>>()
        };
        let unused = vec![(
            CompatibilityWarningId::QuicParamsUnusedTransport,
            "streamSettings.finalmask.quicParams".to_owned(),
        )];
        for stream in [
            json!({}),
            json!({"network": "tcp"}),
            json!({"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3", "h2"]}}),
            json!({"network": "xhttp", "security": "reality"}),
        ] {
            assert_eq!(with(stream.clone()), unused, "{stream}");
        }
        for stream in [
            json!({"network": "hysteria"}),
            json!({"network": "xhttp", "security": "tls", "tlsSettings": {"alpn": ["h3"]}}),
            json!({"method": "splithttp", "security": "tls", "tlsSettings": {"alpn": "h3"}}),
        ] {
            assert!(with(stream.clone()).is_empty(), "{stream}");
        }
        let null = json!({"streamSettings": {"finalmask": {"quicParams": null}}});
        assert!(inbound_warnings(&null, None).is_empty());
    }

    /// Roadmap §2.6 stage 5.1 (formerly gate G4): with REALITY, each tcp layer a prober meets
    /// first is flagged at its type; `fragment` only cuts writes and is not; TLS is never flagged.
    #[test]
    fn flags_probe_facing_tcp_layers_only_with_reality() {
        let inbound = |security: &str| {
            json!({"protocol": "vless", "streamSettings": {"network": "raw", "security": security,
                "finalmask": {"tcp": [
                    {"type": "fragment", "settings": {}},
                    {"type": " Sudoku ", "settings": {"password": "abc"}},
                    {"type": "header-custom", "settings": {}},
                    {"type": "XMC", "settings": {}}
                ]}}})
        };
        let found: Vec<_> = inbound_warnings(&inbound("reality"), None)
            .into_iter()
            .filter(|w| w.id == CompatibilityWarningId::RealityProbeSeesFinalMask)
            .map(|w| w.location)
            .collect();
        assert_eq!(
            found,
            [
                "streamSettings.finalmask.tcp[1].type",
                "streamSettings.finalmask.tcp[2].type",
                "streamSettings.finalmask.tcp[3].type",
            ]
        );
        assert!(
            !inbound_warnings(&inbound("tls"), None)
                .iter()
                .any(|w| w.id == CompatibilityWarningId::RealityProbeSeesFinalMask)
        );
    }

    /// Roadmap §2.6 stage 4.3: a non-empty chain that no listener applies is flagged once, at the
    /// chain; an empty chain or an unknown protocol never is.
    #[test]
    fn flags_finalmask_chain_no_listener_uses() {
        let unused = |inbound: Value| {
            inbound_warnings(&inbound, None)
                .into_iter()
                .filter(|w| w.id == CompatibilityWarningId::FinalMaskChainUnused)
                .map(|w| w.location)
                .collect::<Vec<_>>()
        };
        let layer = json!([{"type": "salamander", "settings": {"password": "secret-pw"}}]);
        let both = json!({"tcp": [{"type": "fragment", "settings": {}}], "udp": layer});

        let vless = json!({"protocol": "vless", "streamSettings": {"network": "raw", "finalmask": both}});
        assert_eq!(unused(vless), ["streamSettings.finalmask.udp"]);
        let kcp = json!({"protocol": "trojan", "streamSettings": {"network": "mkcp", "finalmask": both}});
        assert_eq!(unused(kcp), ["streamSettings.finalmask.tcp"]);
        let hysteria = json!({"protocol": "hysteria", "streamSettings": {"network": "hysteria", "finalmask": both}});
        assert_eq!(unused(hysteria), ["streamSettings.finalmask.tcp"]);
        let tunnel = json!({"protocol": "tunnel", "settings": {"allowedNetwork": "tcp,udp"},
                            "streamSettings": {"network": "tcp", "finalmask": both}});
        assert!(unused(tunnel).is_empty());
        let udp_tunnel = json!({"protocol": "tunnel", "settings": {"allowedNetwork": "udp"},
                                "streamSettings": {"network": "tcp", "finalmask": both}});
        assert_eq!(unused(udp_tunnel), ["streamSettings.finalmask.tcp"]);

        // Empty chains and protocols outside the table: nothing to say.
        let empty = json!({"protocol": "vless", "streamSettings": {"network": "raw",
                           "finalmask": {"tcp": [], "udp": []}}});
        assert!(unused(empty).is_empty());
        let vmess = json!({"protocol": "vmess", "streamSettings": {"network": "raw", "finalmask": both}});
        assert!(unused(vmess).is_empty());
    }

    /// FinalMask warnings of an *outbound* `finalmask` (the layer part of [`outbound_warnings`]).
    fn outbound_finalmask_warnings(finalmask: &Value, core: Option<XrayCoreVersion>) -> Vec<CompatibilityWarning> {
        let mut warnings = Vec::new();
        finalmask_warnings(finalmask, StreamDirection::Outbound, core, &mut warnings);
        warnings
    }

    /// Roadmap §2.6 stage 1.1: on an inbound the whole `udphop` layer is the problem (client-only);
    /// the removed `sockopt` is reported on the client side only.
    #[test]
    fn flags_udphop_by_direction_with_layer_location() {
        let finalmask = json!({"udp": [
            {"type": "salamander", "settings": {"sockopt": {"mark": 1}}},
            {"type": " UDPHop ", "settings": {"mode": "intervalRemote", "sockopt": {"mark": 1}}}
        ]});
        assert_eq!(
            inbound_warnings(&json!({"streamSettings": {"finalmask": finalmask}}), None),
            vec![CompatibilityWarning {
                id: CompatibilityWarningId::UdpHopClientOnly,
                location: "streamSettings.finalmask.udp[1].type".to_owned(),
            }]
        );
        assert_eq!(
            outbound_finalmask_warnings(&finalmask, None),
            vec![CompatibilityWarning {
                id: CompatibilityWarningId::UdpHopSockoptIgnored,
                location: "streamSettings.finalmask.udp[1].settings.sockopt".to_owned(),
            }]
        );
        // Without `sockopt` the client side is clean.
        let clean = json!({"udp": [{"type": "udphop", "settings": {"mode": "intervalRemote"}}]});
        assert!(outbound_finalmask_warnings(&clean, None).is_empty());
    }

    #[test]
    fn flags_mkcp_keys_the_core_ignores_and_nothing_else() {
        let inbound = json!({"streamSettings": {"network": "mkcp", "kcpSettings": {
            "mtu": 1350, "tti": 50, "uplinkCapacity": 5, "downlinkCapacity": 20,
            "cwndMultiplier": 1, "maxSendingWindow": 2097152,
            "congestion": false, "readBufferSize": 2, "writeBufferSize": 2,
            "header": {"type": "none"}, "seed": "s", "futureKey": 1
        }}});
        let found: Vec<(CompatibilityWarningId, String)> = inbound_warnings(&inbound, None)
            .into_iter()
            .map(|warning| (warning.id, warning.location))
            .collect();
        use CompatibilityWarningId::{KcpFieldIgnored, KcpLegacyObfuscationIgnored};
        let at = |key: &str| format!("streamSettings.kcpSettings.{key}");
        assert_eq!(
            found,
            vec![
                (KcpFieldIgnored, at("congestion")),
                (KcpLegacyObfuscationIgnored, at("header")),
                (KcpFieldIgnored, at("readBufferSize")),
                (KcpLegacyObfuscationIgnored, at("seed")),
                (KcpFieldIgnored, at("writeBufferSize")),
            ]
        );
        // A clean mKCP block (only core fields) has no warnings.
        let clean = json!({"streamSettings": {"kcpSettings": {"mtu": 1350, "cwndMultiplier": 2}}});
        assert!(inbound_warnings(&clean, None).is_empty());
    }

    /// Roadmap §2.6 stage 5.2: header/seed work up to v26.1.23, fail the load from v26.1.31 to
    /// v26.9.8 and are ignored from v26.9.9 — like congestion / buffer sizes, read until v26.9.8.
    /// `mkcp-legacy` itself needs v26.6.1.
    #[test]
    fn mkcp_legacy_keys_follow_the_core_version() {
        use CompatibilityWarningId::{KcpFieldIgnored, KcpLegacyObfuscationIgnored, KcpLegacyObfuscationRejected};
        let inbound = json!({"streamSettings": {"network": "mkcp",
            "kcpSettings": {"header": {"type": "utp"}, "seed": null, "congestion": true},
            "finalmask": {"udp": [{"type": "mkcp-legacy", "settings": {}}]}}});
        let at = |key: &str| format!("streamSettings.kcpSettings.{key}");
        let found = |version: &str| {
            inbound_warnings(&inbound, XrayCoreVersion::parse(version))
                .into_iter()
                .map(|w| (w.id, w.location))
                .collect::<Vec<_>>()
        };
        let too_old = |installed: &str| {
            (
                CompatibilityWarningId::RequiresNewerCore {
                    feature: CoreFeature::MkcpLegacyMask,
                    installed: XrayCoreVersion::parse(installed).unwrap(),
                },
                "streamSettings.finalmask.udp[0].type".to_owned(),
            )
        };
        // Old core: the keys work; only the new layer is unknown to it.
        assert_eq!(found("26.1.23"), vec![too_old("26.1.23")]);
        // `"seed": null` is a nil pointer, not part of the core's removed-feature check.
        assert_eq!(found("26.5.9"), vec![too_old("26.5.9"), (KcpLegacyObfuscationRejected, at("header"))]);
        assert_eq!(found("26.9.8"), vec![(KcpLegacyObfuscationRejected, at("header"))]);
        let current = vec![
            (KcpFieldIgnored, at("congestion")),
            (KcpLegacyObfuscationIgnored, at("header")),
            (KcpLegacyObfuscationIgnored, at("seed")),
        ];
        assert_eq!(found("26.9.9"), current);
        assert_eq!(found(""), current, "unknown core = current");
    }

    #[test]
    fn flags_legacy_quic_params_udp_hop() {
        let inbound = json!({"streamSettings": {"network": "hysteria", "finalmask": {
            "quicParams": {"udpHop": {"ports": "20000-50000", "interval": 30}}
        }}});
        let warnings = inbound_warnings(&inbound, None);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].id, CompatibilityWarningId::QuicParamsUdpHopClientOnly);
        assert!(warnings[0].text().starts_with("streamSettings.finalmask.quicParams.udpHop: no effect on an inbound"));
        // Roadmap §2.6 stage 3.2: on an inbound it is dead on every core — before the `udphop`
        // mask (v26.9.9) too, since only the Hysteria dialer ever read it.
        let old_core = inbound_warnings(&inbound, Some(XrayCoreVersion::new(26, 9, 8)));
        assert_eq!(old_core, warnings);
        // On an outbound it was the port-hopping setting until v26.9.9.
        let finalmask = &inbound["streamSettings"]["finalmask"];
        let outbound_ids = |core| -> Vec<_> {
            outbound_finalmask_warnings(finalmask, core).into_iter().map(|w| w.id).collect()
        };
        assert!(outbound_ids(Some(XrayCoreVersion::new(26, 9, 8))).is_empty());
        assert_eq!(outbound_ids(None), vec![CompatibilityWarningId::QuicParamsUdpHopIgnored]);
    }

    #[test]
    fn warnings_follow_config_order() {
        let inbound = json!({"streamSettings": {"network": "hysteria", "finalmask": {
            "udp": [
                {"type": "udphop", "settings": {"sockopt": {}}},
                {"type": "udphop", "settings": {"sockopt": {}}}
            ],
            "quicParams": {"udpHop": {}}
        }}});
        let locations: Vec<_> = inbound_warnings(&inbound, None).into_iter().map(|w| w.location).collect();
        assert_eq!(
            locations,
            vec![
                "streamSettings.finalmask.udp[0].type",
                "streamSettings.finalmask.udp[1].type",
                "streamSettings.finalmask.quicParams.udpHop",
            ]
        );
    }

    #[test]
    fn flags_legacy_freedom_strategy_only_on_freedom() {
        let outbound = json!({"protocol": "Freedom", "settings": {
            "domainStrategy": "UseIP", "targetStrategy": "UseIPv4", "redirect": ":443"
        }});
        let locations: Vec<_> = outbound_warnings(&outbound, None)
            .into_iter()
            .inspect(|w| assert_eq!(w.id, CompatibilityWarningId::FreedomSettingsDomainStrategyIgnored))
            .map(|w| w.location)
            .collect();
        assert_eq!(locations, vec!["settings.domainStrategy", "settings.targetStrategy"]);

        let migrated = json!({"protocol": "freedom", "settings": {},
                              "streamSettings": {"sockopt": {"domainStrategy": "UseIP"}}});
        assert!(outbound_warnings(&migrated, None).is_empty());
        let other = json!({"protocol": "vless", "settings": {"domainStrategy": "UseIP"}});
        assert!(outbound_warnings(&other, None).is_empty());
    }

    /// Roadmap §4.2: client `streamSettings` the core refuses or rewrites.
    #[test]
    fn flags_allow_insecure_and_ws_host_header_on_outbounds() {
        let outbound = json!({"protocol": "vless", "streamSettings": {
            "network": "ws", "wsSettings": {"headers": {"HOST": "a", "User-Agent": "b"}},
            "security": "tls", "tlsSettings": {"allowInsecure": true}
        }});
        let found: Vec<_> = outbound_warnings(&outbound, None).into_iter().map(|w| (w.id, w.location)).collect();
        assert_eq!(
            found,
            vec![
                (CompatibilityWarningId::WsHostHeaderDeprecated, "streamSettings.wsSettings.headers.HOST".to_owned()),
                (CompatibilityWarningId::TlsAllowInsecureRemoved, "streamSettings.tlsSettings.allowInsecure".to_owned()),
            ]
        );
        // TLS settings are built only for `security: tls`; `false` is harmless.
        let reality = json!({"streamSettings": {"security": "reality", "tlsSettings": {"allowInsecure": true}}});
        assert!(outbound_warnings(&reality, None).is_empty());
        let off = json!({"streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": false}}});
        assert!(outbound_warnings(&off, None).is_empty());
    }

    /// Roadmap §2.3: the server side rejects `allowInsecure: true` as well.
    #[test]
    fn flags_allow_insecure_on_inbounds() {
        let inbound = json!({"protocol": "trojan", "streamSettings": {
            "network": "raw", "security": "tls", "tlsSettings": {"allowInsecure": true}
        }});
        let found: Vec<_> = inbound_warnings(&inbound, None).into_iter().map(|w| (w.id, w.location)).collect();
        assert_eq!(
            found,
            vec![(CompatibilityWarningId::TlsAllowInsecureRemoved, "streamSettings.tlsSettings.allowInsecure".to_owned())]
        );
        let reality = json!({"protocol": "vless", "streamSettings": {"security": "reality", "tlsSettings": {"allowInsecure": true}}});
        assert!(inbound_warnings(&reality, None).is_empty());
        let off = json!({"protocol": "vless", "streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": false}}});
        assert!(inbound_warnings(&off, None).is_empty());
    }

    /// Roadmap §4.2: `VLessOutboundConfig.Build()` takes one `vnext[]` server with one user.
    #[test]
    fn flags_vless_vnext_other_than_one_server_and_user() {
        let found = |settings: Value| -> Vec<_> {
            let outbound = json!({"protocol": "vless", "settings": settings, "streamSettings": {"security": "tls"}});
            outbound_warnings(&outbound, None).into_iter().map(|w| (w.id, w.location)).collect()
        };
        let user = json!({"id": "u"});
        let server = json!({"address": "a", "port": 1, "users": [user]});
        let id = CompatibilityWarningId::VlessVnextNotSingle;
        assert_eq!(found(json!({"vnext": []})), vec![(id, "settings.vnext".to_owned())]);
        assert_eq!(found(json!({"vnext": [server, server]})), vec![(id, "settings.vnext".to_owned())]);
        assert_eq!(
            found(json!({"vnext": [{"address": "a", "users": [user, user]}]})),
            vec![(id, "settings.vnext[0].users".to_owned())]
        );
        assert!(found(json!({"vnext": [server]})).is_empty());
        // A flat `address` wins; the core never reads `vnext` then.
        assert!(found(json!({"address": "a", "vnext": []})).is_empty());
        let vmess = json!({"protocol": "vmess", "settings": {"vnext": []}});
        assert!(outbound_warnings(&vmess, None).is_empty());
    }

    /// Roadmap §4.2: `proxySettings` fails the load on any outbound from v26.9.8 (#6058).
    #[test]
    fn flags_removed_proxy_settings_on_every_protocol_from_v26_9_8() {
        let found = |outbound: &Value, core| -> Vec<_> {
            outbound_warnings(outbound, core).into_iter().map(|w| (w.id, w.location)).collect()
        };
        let expected = vec![(CompatibilityWarningId::OutboundProxySettingsRemoved, "proxySettings".to_owned())];
        for protocol in ["freedom", "vless", "vmess", "blackhole"] {
            let outbound = json!({"protocol": protocol, "proxySettings": {"tag": "chain"}});
            assert_eq!(found(&outbound, None), expected, "{protocol}");
        }
        // Any non-null shape is refused, `null` is a nil pointer.
        assert_eq!(found(&json!({"protocol": "freedom", "proxySettings": {}}), None), expected);
        assert!(found(&json!({"protocol": "freedom", "proxySettings": null}), None).is_empty());

        // Older cores still build it.
        let outbound = json!({"protocol": "freedom", "proxySettings": {"tag": "chain"}});
        assert!(found(&outbound, Some(XrayCoreVersion::new(26, 7, 28))).is_empty());
        assert_eq!(found(&outbound, Some(XrayCoreVersion::new(26, 9, 8))), expected);
    }

    /// Roadmap §4.2: the on-disk side of gate G14, after the Freedom `settings` keys (config order).
    #[test]
    fn flags_freedom_address_port_strategy_from_v26_9_8() {
        let outbound = json!({"protocol": "freedom", "settings": {"domainStrategy": "UseIP"},
            "streamSettings": {"sockopt": {"addressPortStrategy": "SrvPortOnly"}}});
        let found: Vec<_> = outbound_warnings(&outbound, None).into_iter().map(|w| (w.id, w.location)).collect();
        assert_eq!(
            found,
            vec![
                (CompatibilityWarningId::FreedomSettingsDomainStrategyIgnored, "settings.domainStrategy".to_owned()),
                (
                    CompatibilityWarningId::FreedomAddressPortStrategyRejected,
                    "streamSettings.sockopt.addressPortStrategy".to_owned()
                ),
            ]
        );
        let old_core = Some(XrayCoreVersion::new(26, 7, 28));
        assert!(
            outbound_warnings(&outbound, old_core)
                .iter()
                .all(|w| w.id != CompatibilityWarningId::FreedomAddressPortStrategyRejected)
        );
        let none = json!({"protocol": "freedom", "streamSettings": {"sockopt": {"addressPortStrategy": "None"}}});
        assert!(outbound_warnings(&none, None).is_empty());
    }

    /// Roadmap §2.6 stage 7.1: the dialer's chain, the client-side layer checks, quicParams off QUIC.
    #[test]
    fn flags_outbound_finalmask_by_dial_chain() {
        let ids = |outbound: Value| -> Vec<_> {
            outbound_warnings(&outbound, None).into_iter().map(|w| (w.id, w.location)).collect()
        };
        let both = json!({"tcp": [{"type": "fragment", "settings": {}}],
                          "udp": [{"type": "udphop", "settings": {"mode": "intervalRemote", "sockopt": {}}}],
                          "quicParams": {"congestion": "bbr"}});
        let raw = json!({"protocol": "vless", "streamSettings": {"network": "raw", "finalmask": both}});
        assert_eq!(
            ids(raw),
            vec![
                (CompatibilityWarningId::OutboundFinalMaskChainUnused, "streamSettings.finalmask.udp".to_owned()),
                (CompatibilityWarningId::UdpHopSockoptIgnored, "streamSettings.finalmask.udp[0].settings.sockopt".to_owned()),
                (CompatibilityWarningId::QuicParamsUnusedTransport, "streamSettings.finalmask.quicParams".to_owned()),
            ]
        );
        // udphop is a client mask: no "client only" warning on an outbound.
        let hysteria = json!({"protocol": "hysteria", "streamSettings": {"network": "hysteria",
            "finalmask": {"udp": [{"type": "udphop", "settings": {"mode": "intervalRemote"}}],
                          "quicParams": {"congestion": "bbr"}}}});
        assert!(ids(hysteria).is_empty());
        // Freedom may dial UDP directly: no claim about its chains.
        let freedom = json!({"protocol": "freedom", "streamSettings": {"finalmask": {
            "tcp": [{"type": "fragment", "settings": {}}], "udp": [{"type": "noise", "settings": {}}]}}});
        assert!(ids(freedom).is_empty());
    }

    fn finalmask_inbound() -> Value {
        json!({"streamSettings": {"network": "hysteria", "finalmask": {
            "tcp": [{"type": "fragment"}, {"type": " XMC "}],
            "udp": [{"type": "udphop", "settings": {"sockopt": {"mark": 1}}}],
            "quicParams": {"udpHop": {"ports": "20000-50000"}}
        }}})
    }

    fn ids_at(core: XrayCoreVersion) -> Vec<(CompatibilityWarningId, String)> {
        inbound_warnings(&finalmask_inbound(), Some(core))
            .into_iter()
            .map(|warning| (warning.id, warning.location))
            .collect()
    }

    #[test]
    fn current_core_keeps_latest_core_warnings() {
        use CompatibilityWarningId::{QuicParamsUdpHopClientOnly, UdpHopClientOnly};
        let latest = vec![
            (UdpHopClientOnly, "streamSettings.finalmask.udp[0].type".to_owned()),
            (QuicParamsUdpHopClientOnly, "streamSettings.finalmask.quicParams.udpHop".to_owned()),
        ];
        assert_eq!(ids_at(XrayCoreVersion::new(26, 9, 30)), latest);
        // Unknown version = current core.
        let unknown: Vec<_> = inbound_warnings(&finalmask_inbound(), None)
            .into_iter()
            .map(|warning| (warning.id, warning.location))
            .collect();
        assert_eq!(unknown, latest);
    }

    #[test]
    fn udphop_sockopt_is_still_read_before_6754() {
        let finalmask = &finalmask_inbound()["streamSettings"]["finalmask"];
        let ids = |core| -> Vec<_> {
            outbound_finalmask_warnings(finalmask, Some(core)).into_iter().map(|w| w.id).collect()
        };
        use CompatibilityWarningId::{QuicParamsUdpHopIgnored, UdpHopSockoptIgnored};
        assert_eq!(ids(XrayCoreVersion::new(26, 9, 9)), vec![QuicParamsUdpHopIgnored]);
        assert_eq!(
            ids(XrayCoreVersion::new(26, 9, 30)),
            vec![UdpHopSockoptIgnored, QuicParamsUdpHopIgnored]
        );
        // The inbound side is client-only from the first `udphop` release on.
        assert_eq!(
            ids_at(XrayCoreVersion::new(26, 9, 9))[0],
            (CompatibilityWarningId::UdpHopClientOnly, "streamSettings.finalmask.udp[0].type".to_owned())
        );
    }

    #[test]
    fn udphop_mask_requires_26_9_9_and_quic_udp_hop_is_valid_before() {
        let installed = XrayCoreVersion::new(26, 9, 8);
        assert_eq!(
            ids_at(installed),
            vec![
                (
                    CompatibilityWarningId::RequiresNewerCore {
                        feature: CoreFeature::UdpHopUdpMask,
                        installed
                    },
                    "streamSettings.finalmask.udp[0].type".to_owned()
                ),
                // Valid before v26.9.9 — but only for a dialer; an inbound never read it.
                (
                    CompatibilityWarningId::QuicParamsUdpHopClientOnly,
                    "streamSettings.finalmask.quicParams.udpHop".to_owned()
                ),
            ]
        );
        let finalmask = &finalmask_inbound()["streamSettings"]["finalmask"];
        let outbound: Vec<_> = outbound_finalmask_warnings(finalmask, Some(installed))
            .into_iter()
            .map(|w| w.id)
            .collect();
        assert_eq!(
            outbound,
            vec![CompatibilityWarningId::RequiresNewerCore { feature: CoreFeature::UdpHopUdpMask, installed }]
        );
    }

    #[test]
    fn xmc_requires_26_7_11() {
        let installed = XrayCoreVersion::new(26, 6, 27);
        let found = inbound_warnings(&finalmask_inbound(), Some(installed));
        // xmc, udphop (too new), then quicParams.udpHop (client-only on an inbound).
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].location, "streamSettings.finalmask.tcp[1].type");
        assert_eq!(
            found[0].text(),
            "streamSettings.finalmask.tcp[1].type: `xmc` TCP mask requires Xray-core v26.7.11 or \
             newer (XTLS/Xray-core#6210); installed v26.6.27"
        );
        assert_eq!(found[1].location, "streamSettings.finalmask.udp[0].type");
        // From v26.7.11 on, `xmc` is fine.
        assert!(ids_at(XrayCoreVersion::new(26, 7, 11)).iter().all(|(id, _)| !matches!(
            id,
            CompatibilityWarningId::RequiresNewerCore { feature: CoreFeature::XmcTcpMask, .. }
        )));
    }

    /// Roadmap §2.6 stage 2.4: `usernames` → `profiles` (#6487, v26.7.28), both directions.
    #[test]
    fn xmc_schema_follows_the_core_version() {
        let with = |settings: Value| json!({"streamSettings": {"finalmask": {"tcp": [{"type": "xmc", "settings": settings}]}}});
        let legacy = with(json!({"password": "p", "usernames": ["Notch"]}));
        let profiles = with(json!({"password": "p", "profiles": [{"username": "Notch"}]}));
        let ids = |inbound: &Value, core| -> Vec<_> {
            inbound_warnings(inbound, core).into_iter().map(|w| (w.id, w.location)).collect()
        };
        let new_core = Some(XrayCoreVersion::new(26, 7, 28));
        let old_core = XrayCoreVersion::new(26, 7, 11);
        let usernames_at = "streamSettings.finalmask.tcp[0].settings.usernames".to_owned();
        assert_eq!(ids(&legacy, new_core), vec![(CompatibilityWarningId::XmcLegacyUsernames, usernames_at.clone())]);
        assert_eq!(ids(&legacy, None), vec![(CompatibilityWarningId::XmcLegacyUsernames, usernames_at)]);
        assert!(ids(&legacy, Some(old_core)).is_empty());
        assert!(ids(&profiles, new_core).is_empty());
        assert_eq!(
            ids(&profiles, Some(old_core)),
            vec![(
                CompatibilityWarningId::RequiresNewerCore { feature: CoreFeature::XmcProfilesSchema, installed: old_core },
                "streamSettings.finalmask.tcp[0].settings.profiles".to_owned()
            )]
        );
        // Before `xmc` itself only the layer is flagged.
        let ancient = XrayCoreVersion::new(26, 6, 27);
        assert_eq!(
            ids(&profiles, Some(ancient)),
            vec![(
                CompatibilityWarningId::RequiresNewerCore { feature: CoreFeature::XmcTcpMask, installed: ancient },
                "streamSettings.finalmask.tcp[0].type".to_owned()
            )]
        );
    }

    /// Roadmap §2.6 stage 1.3: the xdns schema switch of #6718 (v26.9.30), both directions.
    #[test]
    fn xdns_schema_follows_the_core_version() {
        let with = |settings: Value| json!({"streamSettings": {"finalmask": {"udp": [{"type": "xdns", "settings": settings}]}}});
        let legacy = with(json!({"domains": ["t.example.com:txt"]}));
        let objects = with(json!({"domains": [{"name": "t.example.com", "types": [16]}]}));
        let ids = |inbound: &Value, core| -> Vec<_> {
            inbound_warnings(inbound, core).into_iter().map(|w| (w.id, w.location)).collect()
        };
        let at = "streamSettings.finalmask.udp[0].settings".to_owned();
        let new_core = Some(XrayCoreVersion::new(26, 9, 30));
        let old_core = XrayCoreVersion::new(26, 9, 20);
        assert_eq!(ids(&legacy, new_core), vec![(CompatibilityWarningId::XdnsLegacySchema, at.clone())]);
        assert_eq!(ids(&legacy, None), vec![(CompatibilityWarningId::XdnsLegacySchema, at.clone())]);
        assert!(ids(&legacy, Some(old_core)).is_empty());
        assert!(ids(&objects, new_core).is_empty());
        assert_eq!(
            ids(&objects, Some(old_core)),
            vec![(
                CompatibilityWarningId::RequiresNewerCore { feature: CoreFeature::XdnsObjectSchema, installed: old_core },
                at
            )]
        );
    }

    /// Roadmap §2.6 stage 1.4: `noise` `type: "exp"` (#6862) needs v26.9.30.
    #[test]
    fn noise_exp_requires_26_9_30() {
        let inbound = json!({"streamSettings": {"finalmask": {"udp": [{"type": "noise", "settings": {"noise": [
            {"rand": 4}, {"type": "EXP", "packet": "<r 8>"}
        ]}}]}}});
        let found = inbound_warnings(&inbound, Some(XrayCoreVersion::new(26, 9, 9)));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].location, "streamSettings.finalmask.udp[0].settings.noise[1].type");
        assert!(matches!(
            found[0].id,
            CompatibilityWarningId::RequiresNewerCore { feature: CoreFeature::NoiseExpPacket, .. }
        ));
        assert!(inbound_warnings(&inbound, Some(XrayCoreVersion::new(26, 9, 30))).is_empty());
        assert!(inbound_warnings(&inbound, None).is_empty());
    }

    #[test]
    fn warning_suffix_is_appended_only_when_present() {
        assert_eq!(with_warning_suffix("Saved.", &[]), "Saved.");
        let warning = CompatibilityWarning {
            id: CompatibilityWarningId::QuicParamsUdpHopIgnored,
            location: "x".to_owned(),
        };
        assert_eq!(
            with_warning_suffix("Saved.", &[warning.clone(), warning]),
            format!("Saved. Warnings: x: {m}; x: {m}", m = CompatibilityWarningId::QuicParamsUdpHopIgnored.message())
        );
    }
}
