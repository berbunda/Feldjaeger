//! Version-aware notes for the Lua `script` of `routing` and `dns` (XTLS/Xray-core#6823, v26.10.10;
//! Roadmap §4.5, audit v26.10.10 C).
//!
//! With `routing.script` set, `Router.PickRoute` asks only `HandleRoute` in the script — `rules`
//! are not applied (balancers stay reachable through `xray.router.PickOutbound`). With
//! `dns.script` set, `DNS.LookupIP` hands every lookup that `hosts` and the cache do not answer to
//! `HandleDNSQuery`; the servers are queried only through the script (`xray.dns`, `server.ID` =
//! `servers[].id`). A core before v26.10.10 ignores both keys and `servers[].id`.
//!
//! A relative path is resolved by `platform.ResolveLuaFile`: `XRAY_LOCATION_CONFDIR`,
//! `XRAY_LOCATION_CONFIG`, the working directory, the xray binary's directory. `Build()` needs the
//! file to exist (`xray run -test` fails otherwise); the Lua code is compiled only when the router
//! / DNS starts, so a syntax error passes `xray run -test` and stops Xray at start (checked with
//! `xray.exe` 26.10.10).
//!
//! These are notes, never Save blockers: the user may be about to upgrade the core or upload the
//! script.

use super::core_version::{CoreFeature, XrayCoreVersion};
use crate::xray::config::dns_settings::DnsSettings;
use crate::xray::config::routing_settings::RoutingSettings;

fn relative_path_note(key: &str, path: &str) -> Option<String> {
    (!path.starts_with('/')).then(|| {
        format!(
            "{key} \"{path}\" is not an absolute path: Xray looks for it under XRAY_LOCATION_CONFDIR, \
             XRAY_LOCATION_CONFIG, its working directory (/ for the systemd unit) and the xray binary's \
             directory — an absolute path is safer."
        )
    })
}

fn too_old_note(what: &str, core: Option<XrayCoreVersion>) -> Option<String> {
    let installed = core.filter(|_| !CoreFeature::LuaScript.available_in(core))?;
    Some(format!(
        "{what} needs Xray-core {} or newer (XTLS/Xray-core#6823); the installed {installed} ignores it.",
        CoreFeature::LuaScript.min_version()
    ))
}

/// Notes for the Routing page: what `routing.script` does to the rules, the core version, a
/// relative path.
pub fn routing_script_notes(settings: &RoutingSettings, core: Option<XrayCoreVersion>) -> Vec<String> {
    let Some(path) = settings.script.as_deref() else {
        return Vec::new();
    };
    let mut notes = Vec::new();
    match too_old_note("routing.script", core) {
        Some(note) => notes.push(format!("{note} The rules below are applied as usual.")),
        None => notes.push(format!(
            "routing.script = \"{path}\": HandleRoute in this Lua file picks the outbound for every \
             connection — the rules below are not applied (balancers stay available to the script). \
             Feldjäger cannot see the outbound tags the script returns: renaming or deleting an \
             outbound is not checked against it."
        )),
    }
    notes.extend(relative_path_note("routing.script", path));
    notes
}

/// Notes for the DNS page: what `dns.script` does to the servers, `servers[].id` without a script
/// or on an older core, the core version, a relative path.
pub fn dns_script_notes(settings: &DnsSettings, core: Option<XrayCoreVersion>) -> Vec<String> {
    let mut notes = Vec::new();
    let has_ids = settings.servers.iter().any(|server| server.id.is_some());
    if let Some(path) = settings.script.as_deref() {
        match too_old_note("dns.script", core) {
            Some(note) => notes.push(format!("{note} The servers below are queried as usual.")),
            None => notes.push(format!(
                "dns.script = \"{path}\": HandleDNSQuery in this Lua file answers every lookup that \
                 hosts and the cache do not — the servers below are queried only when the script \
                 calls them (xray.dns, server.ID = servers[].id)."
            )),
        }
        notes.extend(relative_path_note("dns.script", path));
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

    const NEW: Option<XrayCoreVersion> = Some(XrayCoreVersion::new(26, 10, 10));
    const OLD: Option<XrayCoreVersion> = Some(XrayCoreVersion::new(26, 9, 30));

    fn routing(script: Option<&str>) -> RoutingSettings {
        RoutingSettings { script: script.map(str::to_owned), ..RoutingSettings::defaults() }
    }

    #[test]
    fn routing_notes_follow_script_path_and_core() {
        assert!(routing_script_notes(&routing(None), NEW).is_empty());
        let notes = routing_script_notes(&routing(Some("/etc/xray/route.lua")), NEW);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("rules below are not applied"), "{notes:?}");
        // Unknown core = current core.
        assert_eq!(routing_script_notes(&routing(Some("/etc/xray/route.lua")), None), notes);
        let notes = routing_script_notes(&routing(Some("route.lua")), OLD);
        assert_eq!(notes.len(), 2);
        assert!(notes[0].contains("needs Xray-core v26.10.10") && notes[0].contains("applied as usual"), "{notes:?}");
        assert!(notes[1].contains("not an absolute path"), "{notes:?}");
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
}
