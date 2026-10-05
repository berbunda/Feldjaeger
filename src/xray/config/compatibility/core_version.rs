//! Version awareness for non-blocking warnings (Roadmap §2.6 stage 0.7).
//!
//! [`CORE_FEATURES`] is the table "mask type / field → first Xray-core release that has it",
//! checked against the version Discovery read from `xray version`. A config that uses a feature
//! the installed core predates gets a warning, never a block: the user may be about to upgrade.
//!
//! Release numbers are the first `XTLS/Xray-core` tag containing the PR's merge commit (verified
//! 2026-10-01 with `compare/<tag>...<commit>`), not the PR's merge date.
//!
//! Unknown installed version (Discovery could not run `xray version`, or no session) means
//! "assume the current core": no "requires newer core" warnings, and the "ignored by Xray-core"
//! warnings keep their latest-core meaning.

use std::fmt;

/// An Xray-core release as `major.minor.patch` (Xray uses `YY.M.D` since v25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XrayCoreVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl XrayCoreVersion {
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self { major, minor, patch }
    }

    /// Loose parse of the Discovery version string: `"26.9.30"`, `"v26.9.30"`, `"Xray 26.9.30 (…)"`.
    /// Missing minor / patch default to 0. `None` when the text has no number at all.
    pub fn parse(text: &str) -> Option<Self> {
        let start = text.find(|c: char| c.is_ascii_digit())?;
        let mut parts = text[start..].split(|c: char| !c.is_ascii_digit());
        let major = parts.next()?.parse().ok()?;
        let mut next = || parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
        let minor = next();
        let patch = next();
        Some(Self::new(major, minor, patch))
    }
}

impl fmt::Display for XrayCoreVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// A config feature (or a schema change) that appeared in a specific Xray-core release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreFeature {
    /// mKCP obfuscation moved to FinalMask: from this release `kcpSettings.header` / `seed` are no
    /// longer applied — a fatal "removed feature" error at load, until
    /// [`Self::KcpConfigSlimmed`] — XTLS/Xray-core#5560.
    KcpHeaderSeedRemoved,
    /// `mkcp-legacy` layer in `finalmask.udp[]`, replacing the `header-*` / `mkcp-original` /
    /// `mkcp-aes128gcm` masks of #5560 — XTLS/Xray-core#6201.
    MkcpLegacyMask,
    /// `KCPConfig` reduced to mtu / tti / capacities / cwndMultiplier / maxSendingWindow: from this
    /// release `congestion` / `readBufferSize` / `writeBufferSize` are no longer read, and
    /// `header` / `seed` are silently ignored instead of failing the load — XTLS/Xray-core#6327
    /// (the only FinalMask change between v26.9.8 and v26.9.9).
    KcpConfigSlimmed,
    /// `xmc` (Minecraft) layer in `finalmask.tcp[]` — XTLS/Xray-core#6210.
    XmcTcpMask,
    /// `xmc` `profiles[]` (signed Minecraft profiles) replacing `usernames` — XTLS/Xray-core#6487.
    XmcProfilesSchema,
    /// `udphop` layer in `finalmask.udp[]`; from this release `finalmask.quicParams.udpHop` is
    /// ignored — XTLS/Xray-core#6327.
    UdpHopUdpMask,
    /// `udphop` without `sockopt`: from this release `settings.sockopt` of the layer is ignored —
    /// XTLS/Xray-core#6754.
    UdpHopSockoptRemoved,
    /// `noise` item `type: "exp"` (`packet` is an expression) — XTLS/Xray-core#6862.
    NoiseExpPacket,
    /// `xdns` object schema (`domains[]` / `resolvers[]` objects, `extraPoll`) replacing the
    /// string form — XTLS/Xray-core#6718.
    XdnsObjectSchema,
}

/// The table of Roadmap §2.6 stage 0.7, oldest first.
pub const CORE_FEATURES: &[CoreFeature] = &[
    CoreFeature::KcpHeaderSeedRemoved,
    CoreFeature::MkcpLegacyMask,
    CoreFeature::XmcTcpMask,
    CoreFeature::XmcProfilesSchema,
    CoreFeature::UdpHopUdpMask,
    CoreFeature::KcpConfigSlimmed,
    CoreFeature::UdpHopSockoptRemoved,
    CoreFeature::NoiseExpPacket,
    CoreFeature::XdnsObjectSchema,
];

impl CoreFeature {
    /// First Xray-core release with this feature.
    pub const fn min_version(self) -> XrayCoreVersion {
        match self {
            Self::KcpHeaderSeedRemoved => XrayCoreVersion::new(26, 1, 31),
            Self::MkcpLegacyMask => XrayCoreVersion::new(26, 6, 1),
            Self::KcpConfigSlimmed => XrayCoreVersion::new(26, 9, 9),
            Self::XmcTcpMask => XrayCoreVersion::new(26, 7, 11),
            Self::XmcProfilesSchema => XrayCoreVersion::new(26, 7, 28),
            Self::UdpHopUdpMask => XrayCoreVersion::new(26, 9, 9),
            Self::UdpHopSockoptRemoved => XrayCoreVersion::new(26, 9, 30),
            Self::NoiseExpPacket => XrayCoreVersion::new(26, 9, 30),
            Self::XdnsObjectSchema => XrayCoreVersion::new(26, 9, 30),
        }
    }

    /// `XTLS/Xray-core` pull request that introduced it.
    pub const fn pull_request(self) -> u32 {
        match self {
            Self::KcpHeaderSeedRemoved => 5560,
            Self::MkcpLegacyMask => 6201,
            Self::KcpConfigSlimmed => 6327,
            Self::XmcTcpMask => 6210,
            Self::XmcProfilesSchema => 6487,
            Self::UdpHopUdpMask => 6327,
            Self::UdpHopSockoptRemoved => 6754,
            Self::NoiseExpPacket => 6862,
            Self::XdnsObjectSchema => 6718,
        }
    }

    /// What the config uses, as the user sees it in JSON.
    pub const fn label(self) -> &'static str {
        match self {
            Self::KcpHeaderSeedRemoved => "mKCP obfuscation in finalmask (kcpSettings.header / seed removed)",
            Self::MkcpLegacyMask => "`mkcp-legacy` UDP mask",
            Self::KcpConfigSlimmed => "slimmed kcpSettings (legacy keys ignored)",
            Self::XmcTcpMask => "`xmc` TCP mask",
            Self::XmcProfilesSchema => "`xmc` profiles[] (signed Minecraft profiles)",
            Self::UdpHopUdpMask => "`udphop` UDP mask",
            Self::UdpHopSockoptRemoved => "`udphop` without `sockopt`",
            Self::NoiseExpPacket => "`noise` item `type: \"exp\"`",
            Self::XdnsObjectSchema => "`xdns` object schema (domains[] / resolvers[] objects)",
        }
    }

    /// Whether the installed core has the feature; an unknown version counts as current.
    pub fn available_in(self, core: Option<XrayCoreVersion>) -> bool {
        core.is_none_or(|version| version >= self.min_version())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_discovery_version_strings() {
        let v = XrayCoreVersion::new;
        assert_eq!(XrayCoreVersion::parse("26.9.30"), Some(v(26, 9, 30)));
        assert_eq!(XrayCoreVersion::parse("v26.7.11"), Some(v(26, 7, 11)));
        assert_eq!(XrayCoreVersion::parse("Xray 25.7.1 (Xray, Penetrates Everything.)"), Some(v(25, 7, 1)));
        assert_eq!(XrayCoreVersion::parse("1.8"), Some(v(1, 8, 0)));
        assert_eq!(XrayCoreVersion::parse("unknown"), None);
        assert_eq!(v(26, 9, 30).to_string(), "v26.9.30");
    }

    #[test]
    fn versions_order_numerically_not_lexically() {
        assert!(XrayCoreVersion::new(26, 9, 9) < XrayCoreVersion::new(26, 9, 30));
        assert!(XrayCoreVersion::new(26, 10, 1) > XrayCoreVersion::new(26, 9, 30));
    }

    #[test]
    fn table_is_sorted_and_boundaries_are_inclusive() {
        assert!(CORE_FEATURES.windows(2).all(|w| w[0].min_version() <= w[1].min_version()));
        let feature = CoreFeature::UdpHopUdpMask;
        assert!(feature.available_in(None));
        assert!(feature.available_in(Some(XrayCoreVersion::new(26, 9, 9))));
        assert!(!feature.available_in(Some(XrayCoreVersion::new(26, 9, 8))));
    }
}
