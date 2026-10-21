//! Version-aware notes and checks for the Lua `script` of `routing` and `dns`
//! (XTLS/Xray-core#6823, v26.10.10; #7132 / #7136, v26.10.17; Roadmap §4.5, audits v26.10.10 C and
//! v26.10.21 A).
//!
//! With `routing.script` set, `Router.PickRoute` asks only `HandleRoute` in the script (balancers
//! stay reachable through `xray.router.PickOutbound`). With `dns.script` set, `DNS.LookupIP` hands
//! every lookup that `hosts` and the cache do not answer to `HandleDNSQuery`; the servers are
//! queried only through the script (`xray.dns`, `server.ID` = `servers[].id`). A core before
//! v26.10.10 ignores both keys and `servers[].id`.
//!
//! From v26.10.17 `Build()` refuses a script next to the keys it replaces: `routing.domainStrategy`
//! (any value, even `"AsIs"`) and non-empty `rules`; `dns.disableFallback` /
//! `disableFallbackIfMatch` / `enableParallelQuery` set to `true` and server `domains` /
//! `skipFallback` / `finalQuery`. v26.10.10 accepts them and only ignores `rules` / the servers.
//! On that core a conflict is a note; on v26.10.17+ (or an unknown core, which counts as current)
//! [`routing_script_save_error`] / [`dns_script_save_error`] stop the Save, since `xray run -test`
//! would refuse it.
//!
//! A relative path is resolved by `platform.ResolveLuaFile`: `XRAY_LOCATION_CONFDIR`,
//! `XRAY_LOCATION_CONFIG`, the working directory, the xray binary's directory. v26.10.10 checks only
//! that the file exists, in `Build()`; v26.10.17 finds and compiles it when the router / DNS is
//! created — `xray run -test` included — and refuses a file that does not end in `.lua` after
//! symlinks are resolved. Inline scripts (`base64:` / `base64+gzip:`) were added and disabled in
//! the same release ("currently unavailable"). Checked with `xray.exe` 26.10.10 and 26.10.21.

use super::core_version::{CoreFeature, XrayCoreVersion};
use crate::xray::config::dns_settings::DnsSettings;
use crate::xray::config::routing_settings::{DomainStrategy, RoutingSettings};

/// Prefixes of the inline-script form (`common/base64`): disabled in v26.10.17+.
const INLINE_SCRIPT_PREFIXES: &[&str] = &["base64:", "base64+gzip:"];

fn is_inline(path: &str) -> bool {
    INLINE_SCRIPT_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

/// Path notes: inline form, extension, relative path.
fn path_notes(key: &str, path: &str, core: Option<XrayCoreVersion>) -> Vec<String> {
    let strict = CoreFeature::LuaScriptExclusive.available_in(core);
    if is_inline(path) {
        return vec![if strict {
            format!(
                "{key}: inline scripts (base64:) are disabled in Xray-core {} and newer — Xray \
                 refuses to start (\"currently unavailable\"). Upload the script as a .lua file.",
                CoreFeature::LuaScriptExclusive.min_version()
            )
        } else {
            format!("{key}: this core reads \"{path}\" as a file name, not as an inline script.")
        }];
    }
    let mut notes = Vec::new();
    if strict && !path.ends_with(".lua") {
        notes.push(format!(
            "{key} \"{path}\" does not end in .lua: Xray-core {} and newer refuse it (unless it is a \
             symlink to a .lua file).",
            CoreFeature::LuaScriptExclusive.min_version()
        ));
    }
    if !path.starts_with('/') {
        notes.push(format!(
            "{key} \"{path}\" is not an absolute path: Xray looks for it under XRAY_LOCATION_CONFDIR, \
             XRAY_LOCATION_CONFIG, its working directory (/ for the systemd unit) and the xray binary's \
             directory — an absolute path is safer."
        ));
    }
    notes
}

fn too_old_note(what: &str, core: Option<XrayCoreVersion>) -> Option<String> {
    let installed = core.filter(|_| !CoreFeature::LuaScript.available_in(core))?;
    Some(format!(
        "{what} needs Xray-core {} or newer (XTLS/Xray-core#6823); the installed {installed} ignores it.",
        CoreFeature::LuaScript.min_version()
    ))
}

/// The keys `routing.script` cannot be combined with from v26.10.17 (`RouterConfig.Build()`).
/// `domainStrategy` counts only when it is not `"AsIs"`: Feldjäger does not write `"AsIs"` next to
/// a script (see `apply_routing_settings_to_value`).
pub fn routing_script_conflicts(settings: &RoutingSettings) -> Vec<String> {
    if settings.script.is_none() {
        return Vec::new();
    }
    let mut conflicts = Vec::new();
    if settings.domain_strategy != DomainStrategy::AsIs {
        conflicts.push(format!("domainStrategy \"{}\"", settings.domain_strategy.as_str()));
    }
    if !settings.rules.is_empty() {
        conflicts.push(format!("rules ({})", settings.rules.len()));
    }
    conflicts
}

/// The keys `dns.script` cannot be combined with from v26.10.17 (`DNSConfig.Build()`).
pub fn dns_script_conflicts(settings: &DnsSettings) -> Vec<String> {
    if settings.script.is_none() {
        return Vec::new();
    }
    let mut conflicts: Vec<String> = [
        (settings.disable_fallback, "disableFallback"),
        (settings.disable_fallback_if_match, "disableFallbackIfMatch"),
        (settings.enable_parallel_query, "enableParallelQuery"),
    ]
    .into_iter()
    .filter(|(set, _)| *set)
    .map(|(_, key)| key.to_owned())
    .collect();
    for (index, server) in settings.servers.iter().enumerate() {
        let keys: Vec<&str> = [
            (!server.domains.is_empty(), "domains"),
            (server.skip_fallback, "skipFallback"),
            (server.final_query, "finalQuery"),
        ]
        .into_iter()
        .filter(|(set, _)| *set)
        .map(|(_, key)| key)
        .collect();
        if !keys.is_empty() {
            conflicts.push(format!("servers[{index}] {}", keys.join(" / ")));
        }
    }
    conflicts
}

fn conflict_message(key: &str, conflicts: &[String], core: Option<XrayCoreVersion>) -> String {
    let release = CoreFeature::LuaScriptExclusive.min_version();
    let core_text = match core {
        Some(installed) => format!("Xray-core {installed}"),
        None => format!("Xray-core {release}+"),
    };
    format!(
        "{core_text} refuses {key} together with {}: remove them or the script \
         (XTLS/Xray-core#{}).",
        conflicts.join(", "),
        CoreFeature::LuaScriptExclusive.pull_request()
    )
}

/// Why the Routing Save must stop: a script next to keys the installed core refuses.
/// `None` on a core before v26.10.17 — there the conflict is only a note.
pub fn routing_script_save_error(settings: &RoutingSettings, core: Option<XrayCoreVersion>) -> Option<String> {
    let conflicts = routing_script_conflicts(settings);
    (!conflicts.is_empty() && CoreFeature::LuaScriptExclusive.available_in(core))
        .then(|| conflict_message("routing.script", &conflicts, core))
}

/// Why the DNS Save must stop: a script next to keys the installed core refuses.
/// `None` on a core before v26.10.17 — there the conflict is only a note.
pub fn dns_script_save_error(settings: &DnsSettings, core: Option<XrayCoreVersion>) -> Option<String> {
    let conflicts = dns_script_conflicts(settings);
    (!conflicts.is_empty() && CoreFeature::LuaScriptExclusive.available_in(core))
        .then(|| conflict_message("dns.script", &conflicts, core))
}

/// Note for a conflict on a core that still accepts it (v26.10.10 – v26.10.16).
fn upgrade_note(key: &str, conflicts: &[String]) -> String {
    format!(
        "Xray-core {} and newer refuse {key} together with {}: remove them before upgrading.",
        CoreFeature::LuaScriptExclusive.min_version(),
        conflicts.join(", ")
    )
}

/// Notes for the Routing page: what `routing.script` does, conflicts by core version, the path.
pub fn routing_script_notes(settings: &RoutingSettings, core: Option<XrayCoreVersion>) -> Vec<String> {
    let Some(path) = settings.script.as_deref() else {
        return Vec::new();
    };
    let mut notes = Vec::new();
    if let Some(note) = too_old_note("routing.script", core) {
        notes.push(format!("{note} The rules below are applied as usual."));
        return notes;
    }
    notes.push(format!(
        "routing.script = \"{path}\": HandleRoute in this Lua file picks the outbound for every \
         connection (balancers stay available to the script). Feldjäger cannot see the outbound \
         tags the script returns: renaming or deleting an outbound is not checked against it."
    ));
    let conflicts = routing_script_conflicts(settings);
    if let Some(error) = routing_script_save_error(settings, core) {
        notes.push(error);
    } else if !conflicts.is_empty() {
        if !settings.rules.is_empty() {
            notes.push("This core does not apply the rules below while the script is set.".to_owned());
        }
        notes.push(upgrade_note("routing.script", &conflicts));
    }
    notes.extend(path_notes("routing.script", path, core));
    notes
}

/// Notes for the DNS page: what `dns.script` does, conflicts by core version, `servers[].id`
/// without a script or on an older core, the path.
pub fn dns_script_notes(settings: &DnsSettings, core: Option<XrayCoreVersion>) -> Vec<String> {
    let mut notes = Vec::new();
    let has_ids = settings.servers.iter().any(|server| server.id.is_some());
    if let Some(path) = settings.script.as_deref() {
        match too_old_note("dns.script", core) {
            Some(note) => notes.push(format!("{note} The servers below are queried as usual.")),
            None => {
                notes.push(format!(
                    "dns.script = \"{path}\": HandleDNSQuery in this Lua file answers every lookup that \
                     hosts and the cache do not — the servers below are queried only when the script \
                     calls them (xray.dns, server.ID = servers[].id)."
                ));
                let conflicts = dns_script_conflicts(settings);
                if let Some(error) = dns_script_save_error(settings, core) {
                    notes.push(error);
                } else if !conflicts.is_empty() {
                    notes.push(upgrade_note("dns.script", &conflicts));
                }
                notes.extend(path_notes("dns.script", path, core));
            }
        }
    } else if has_ids {
        notes.push("servers[].id takes effect only with dns.script (a Lua DNS script).".to_owned());
    }
    if has_ids {
        notes.extend(too_old_note("servers[].id", core));
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::config::dns_settings::DnsServerEntry;
    use crate::xray::config::routing_settings::RoutingRuleEntry;

    const NEW: Option<XrayCoreVersion> = Some(XrayCoreVersion::new(26, 10, 21));
    const MID: Option<XrayCoreVersion> = Some(XrayCoreVersion::new(26, 10, 10));
    const OLD: Option<XrayCoreVersion> = Some(XrayCoreVersion::new(26, 9, 30));

    fn routing(script: Option<&str>) -> RoutingSettings {
        RoutingSettings { script: script.map(str::to_owned), ..RoutingSettings::defaults() }
    }

    #[test]
    fn routing_notes_follow_script_path_and_core() {
        assert!(routing_script_notes(&routing(None), NEW).is_empty());
        let notes = routing_script_notes(&routing(Some("/etc/xray/route.lua")), NEW);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("HandleRoute"), "{notes:?}");
        // Unknown core = current core.
        assert_eq!(routing_script_notes(&routing(Some("/etc/xray/route.lua")), None), notes);
        let notes = routing_script_notes(&routing(Some("route.lua")), OLD);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("needs Xray-core v26.10.10") && notes[0].contains("applied as usual"), "{notes:?}");
        let notes = routing_script_notes(&routing(Some("route.lua")), MID);
        assert!(notes[1].contains("not an absolute path"), "{notes:?}");
    }

    /// Audit v26.10.21 A: `domainStrategy` other than AsIs and non-empty `rules` next to a script
    /// stop the Save on v26.10.17+ (and an unknown core), and are an upgrade note on v26.10.10.
    #[test]
    fn routing_conflicts_block_only_on_strict_core() {
        let mut settings = routing(Some("/etc/xray/route.lua"));
        assert!(routing_script_save_error(&settings, NEW).is_none());
        settings.domain_strategy = DomainStrategy::IpIfNonMatch;
        settings.rules.push(RoutingRuleEntry { outbound_tag: Some("direct".to_owned()), ..RoutingRuleEntry::blank() });
        assert_eq!(routing_script_conflicts(&settings), vec!["domainStrategy \"IPIfNonMatch\"", "rules (1)"]);
        let error = routing_script_save_error(&settings, NEW).expect("v26.10.21 refuses");
        assert!(error.starts_with("Xray-core v26.10.21 refuses routing.script together with"), "{error}");
        assert!(routing_script_save_error(&settings, None).expect("unknown = current").contains("v26.10.17+"));
        assert!(routing_script_save_error(&settings, MID).is_none());
        let notes = routing_script_notes(&settings, MID);
        assert!(notes.iter().any(|n| n.contains("does not apply the rules")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("remove them before upgrading")), "{notes:?}");
        assert!(routing_script_notes(&settings, NEW).contains(&error));
        settings.script = None;
        assert!(routing_script_conflicts(&settings).is_empty());
    }

    #[test]
    fn path_notes_cover_extension_and_inline_form() {
        let notes = routing_script_notes(&routing(Some("/etc/xray/route.txt")), NEW);
        assert!(notes.iter().any(|n| n.contains("does not end in .lua")), "{notes:?}");
        assert!(!routing_script_notes(&routing(Some("/etc/xray/route.txt")), MID).iter().any(|n| n.contains(".lua")));
        let notes = routing_script_notes(&routing(Some("base64:ZW5k")), NEW);
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes[1].contains("inline scripts (base64:) are disabled"), "{notes:?}");
        let notes = dns_script_notes(&DnsSettings { script: Some("base64+gzip:x".to_owned()), ..DnsSettings::defaults() }, MID);
        assert!(notes[1].contains("as a file name"), "{notes:?}");
    }

    #[test]
    fn dns_notes_cover_script_and_server_ids() {
        let mut settings = DnsSettings::defaults();
        assert!(dns_script_notes(&settings, OLD).is_empty());
        settings.servers.push(DnsServerEntry { address: "1.1.1.1".to_owned(), id: Some("cf".to_owned()), ..DnsServerEntry::blank() });
        let notes = dns_script_notes(&settings, NEW);
        assert_eq!(notes, vec!["servers[].id takes effect only with dns.script (a Lua DNS script).".to_owned()]);
        assert_eq!(dns_script_notes(&settings, OLD).len(), 2);

        settings.script = Some("/etc/xray/dns.lua".to_owned());
        let notes = dns_script_notes(&settings, NEW);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("HandleDNSQuery"), "{notes:?}");
        let notes = dns_script_notes(&settings, OLD);
        assert_eq!(notes.len(), 2);
        assert!(notes[0].starts_with("dns.script needs") && notes[1].starts_with("servers[].id needs"), "{notes:?}");
    }

    /// Audit v26.10.21 A: the `DNSConfig.Build()` checks, `false` flags and `expectIPs` allowed.
    #[test]
    fn dns_conflicts_match_core_build() {
        let mut settings = DnsSettings { script: Some("/etc/xray/dns.lua".to_owned()), ..DnsSettings::defaults() };
        settings.servers.push(DnsServerEntry {
            address: "1.1.1.1".to_owned(),
            expected_ips: vec!["1.0.0.0/8".to_owned()],
            ..DnsServerEntry::blank()
        });
        assert!(dns_script_conflicts(&settings).is_empty());
        settings.enable_parallel_query = true;
        settings.servers.push(DnsServerEntry {
            address: "8.8.8.8".to_owned(),
            domains: vec!["domain:example.com".to_owned()],
            final_query: true,
            ..DnsServerEntry::blank()
        });
        assert_eq!(dns_script_conflicts(&settings), vec!["enableParallelQuery", "servers[1] domains / finalQuery"]);
        assert!(dns_script_save_error(&settings, NEW).is_some());
        assert!(dns_script_save_error(&settings, MID).is_none());
        assert!(dns_script_notes(&settings, MID).iter().any(|n| n.contains("remove them before upgrading")));
    }
}
