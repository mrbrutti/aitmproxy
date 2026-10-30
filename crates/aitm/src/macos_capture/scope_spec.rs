//! Scope-spec emitter (macOS NE core prereqs, plan Task 2 — AC8–AC12).
//!
//! The macOS NE provider is a **coarse pre-filter** in front of the authoritative
//! core guard. [`provider_scope_spec`] renders the core's two authorization scopes
//! — the L7 host scope ([`aitm_core::ScopeEntry`]) and the L4 IP scope
//! ([`aitm_proto_l4::types::L4ScopeEntry`]) — into the single
//! [`ScopeSpec`](crate::macos_capture::listener::ScopeSpec) grammar string the
//! provider's `ScopeMatcher` understands.
//!
//! **Under-inclusive, never over-inclusive.** When the provider grammar cannot
//! represent a scope element *exactly*, the token is **skipped**, not widened: the
//! flow then goes direct/uncaptured but works. Widening would make the provider
//! commit to MITM on a flow the core guard then refuses, breaking the user's
//! connection (spec Anti-goals).

use std::net::IpAddr;

use crate::macos_capture::adapter::CAPTURE_INTERFACE;

/// Render the core's L7 host scope and L4 IP scope into the one grammar string the
/// provider's `ScopeMatcher` reads (spec Design §Piece 2).
///
/// Tokens are emitted L7-then-L4 in input order (apex before wildcard for a `*.`
/// entry), de-duplicated preserving first appearance, and joined with a single
/// ASCII space — so the output is deterministic and byte-assertable. Any scope
/// element the grammar cannot represent exactly is **skipped, never widened**.
pub fn provider_scope_spec(
    l7: &[aitm_core::ScopeEntry],
    l4: &[aitm_proto_l4::types::L4ScopeEntry],
) -> crate::macos_capture::listener::ScopeSpec {
    let mut tokens: Vec<String> = Vec::new();
    for entry in l7 {
        for token in l7_tokens(&entry.host) {
            push_unique(&mut tokens, token);
        }
    }
    for entry in l4 {
        if let Some(token) = l4_token(entry) {
            push_unique(&mut tokens, token);
        }
    }
    crate::macos_capture::listener::ScopeSpec {
        spec: tokens.join(" "),
    }
}

/// Push `token` unless an equal token was already emitted (dedup by first
/// appearance). The token lists are tiny, so the linear scan is fine.
fn push_unique(tokens: &mut Vec<String>, token: String) {
    if !tokens.contains(&token) {
        tokens.push(token);
    }
}

/// The provider tokens for one L7 scope entry (`host`, `host:port`, or
/// `*.wildcard`). Core match semantics: [`aitm_core::authority::Authority::matches_scope_entry`]
/// (authority.rs:83).
fn l7_tokens(host: &str) -> Vec<String> {
    let normalized = host.trim().to_ascii_lowercase();
    // `*.suffix`: the core's wildcard matches the apex *and* subdomains
    // (authority.rs:86), but the provider's `*.x` matches subdomains only
    // (FlowHandoff.swift:531). Emit the apex token too so the provider claims the
    // apex as well. An empty suffix is a no-op and is skipped (spec call C5).
    if let Some(suffix) = normalized.strip_prefix("*.") {
        if suffix.is_empty() {
            return Vec::new();
        }
        return vec![suffix.to_string(), format!("*.{suffix}")];
    }
    // Otherwise it is a plain host or `host:port`. A string the core would not
    // treat as a host either is skipped.
    match aitm_core::authority::Authority::parse_with_default(&normalized, 0) {
        // Portless: matches any port of the host → a bare provider token.
        Ok(a) if a.port == 0 => vec![a.host],
        // With a port: matches that port only → a `host:port` provider token
        // (IPv6 bracketed via `Authority`'s `Display`, authority.rs:116-122).
        Ok(a) => vec![a.to_string()],
        Err(_) => Vec::new(),
    }
}

/// The provider token for one L4 scope entry, or `None` when the entry cannot gate
/// an NE-captured flow or the grammar cannot represent it exactly. Gate parity:
/// the NE UDP path tags flows `interface = CAPTURE_INTERFACE`, `direction = Outbound`
/// and checks `L4Guard::check(Capture, …)` (adapter.rs:209-217).
fn l4_token(entry: &aitm_proto_l4::types::L4ScopeEntry) -> Option<String> {
    use aitm_proto_l4::types::{L4Capability, L4Direction};

    // Only a Capture entry on the NE interface in the outbound direction can gate
    // an NE-captured flow; anything else is skipped.
    if entry.capability != L4Capability::Capture
        || entry.interface != CAPTURE_INTERFACE
        || entry.direction != L4Direction::Outbound
    {
        return None;
    }

    // The grammar has no CIDR form, so only a host-prefix CIDR is representable;
    // widening a block to its base address or whole range would be over-inclusive.
    let addr = entry.cidr.addr;
    let is_host_prefix = match addr {
        IpAddr::V4(_) => entry.cidr.prefix == 32,
        IpAddr::V6(_) => entry.cidr.prefix == 128,
    };
    if !is_host_prefix {
        return None;
    }

    // any-port → bare IP; single-port → `ip:port`; a partial range cannot be
    // represented without widening and is skipped.
    let (lo, hi) = (entry.ports.lo, entry.ports.hi);
    if lo == 0 && hi == u16::MAX {
        Some(addr.to_string())
    } else if lo == hi {
        Some(bracket_ip(addr, lo))
    } else {
        None
    }
}

/// Format `ip:port`, bracketing an IPv6 address as `[ip]:port` (the same bracketing
/// as `Authority`'s `Display`, authority.rs:116-122).
fn bracket_ip(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V6(_) => format!("[{addr}]:{port}"),
        IpAddr::V4(_) => format!("{addr}:{port}"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use aitm_proto_l4::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };

    use super::*;
    use crate::macos_capture::adapter::CAPTURE_INTERFACE;

    /// The pinned L7 fixture (spec §"Pinned scope fixture"), in order.
    fn l7_fixture() -> Vec<aitm_core::ScopeEntry> {
        [
            "Example.com",
            "*.api.example.com",
            "10.0.0.5:8080",
            "[2001:db8::1]:443",
        ]
        .into_iter()
        .map(|h| aitm_core::ScopeEntry {
            host: h.to_string(),
        })
        .collect()
    }

    /// Build one L4 scope entry with the fixture's varied fields.
    fn l4_entry(
        addr: &str,
        prefix: u8,
        ports: (u16, u16),
        interface: &str,
        direction: L4Direction,
        capability: L4Capability,
    ) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: addr.parse().expect("fixture addr parses"),
                prefix,
            },
            ports: PortRange {
                lo: ports.0,
                hi: ports.1,
            },
            interface: interface.to_string(),
            direction,
            capability,
            inject_rate: RateCap { pps: 0, burst: 0 },
            source: L4ScopeSource::Config,
        }
    }

    /// The pinned L4 fixture (spec §"Pinned scope fixture"), in order. The last five
    /// entries each exercise one skip rule (AC11).
    fn l4_fixture() -> Vec<L4ScopeEntry> {
        use L4Capability::{Capture, Inject};
        use L4Direction::{Inbound, Outbound};
        vec![
            // Representable: any-port host CIDR → bare IP.
            l4_entry(
                "198.51.100.7",
                32,
                (0, 65535),
                CAPTURE_INTERFACE,
                Outbound,
                Capture,
            ),
            // Representable: single-port host CIDR → ip:port.
            l4_entry(
                "203.0.113.9",
                32,
                (53, 53),
                CAPTURE_INTERFACE,
                Outbound,
                Capture,
            ),
            // Representable: IPv6 any-port host CIDR → bare (unbracketed) IP.
            l4_entry(
                "2001:db8::2",
                128,
                (0, 65535),
                CAPTURE_INTERFACE,
                Outbound,
                Capture,
            ),
            // Non-host CIDR (prefix 24) → skip.
            l4_entry(
                "10.0.0.0",
                24,
                (0, 65535),
                CAPTURE_INTERFACE,
                Outbound,
                Capture,
            ),
            // Partial port range → skip.
            l4_entry(
                "192.0.2.1",
                32,
                (1000, 2000),
                CAPTURE_INTERFACE,
                Outbound,
                Capture,
            ),
            // capability != Capture → skip.
            l4_entry(
                "198.51.100.50",
                32,
                (0, 65535),
                CAPTURE_INTERFACE,
                Outbound,
                Inject,
            ),
            // interface != "macos-ne" → skip.
            l4_entry("198.51.100.51", 32, (0, 65535), "en0", Outbound, Capture),
            // direction != Outbound → skip.
            l4_entry(
                "198.51.100.52",
                32,
                (0, 65535),
                CAPTURE_INTERFACE,
                Inbound,
                Capture,
            ),
        ]
    }

    /// **AC8/AC9/AC11/AC12.** The emitted spec is byte-exact for the representative
    /// fixture: L7 tokens (apex before wildcard) then L4 tokens, input order,
    /// de-duplicated, single-space joined, with every unrepresentable L4 entry
    /// absent.
    #[test]
    fn emits_byte_exact_spec_for_representative_scopes() {
        let spec = provider_scope_spec(&l7_fixture(), &l4_fixture()).spec;
        assert_eq!(
            spec,
            "example.com api.example.com *.api.example.com 10.0.0.5:8080 \
             [2001:db8::1]:443 198.51.100.7 203.0.113.9:53 2001:db8::2"
        );
    }

    /// **AC9/AC10/AC11/AC12.** A faithful Rust mirror of the Swift provider's
    /// `ScopeMatcher`, fed the emitted spec, claims every intended flow and rejects
    /// every out-of-scope flow in the pinned truth-table.
    #[test]
    fn swift_scope_matcher_mirror_claims_and_rejects() {
        let spec = provider_scope_spec(&l7_fixture(), &l4_fixture()).spec;
        let matcher = ScopeMatcherMirror::new(&spec);

        // Claimed (true): the apex and a subdomain of the `*.` entry (AC9), each
        // representable L4 token at an in-range port, and an L7 host/host:port.
        for (host, ip, port) in [
            (Some("example.com"), "1.1.1.1", 443u16),
            (Some("www.api.example.com"), "1.1.1.1", 443),
            (Some("api.example.com"), "1.1.1.1", 443),
            (None, "198.51.100.7", 9999),
            (None, "203.0.113.9", 53),
            (None, "2001:db8::2", 12345),
            (None, "10.0.0.5", 8080),
        ] {
            assert!(
                matcher.matches(host, ip, port),
                "expected in-scope, got rejected: {host:?} {ip} {port}"
            );
        }

        // Rejected (false): out-of-scope host, a `*.` near-miss, a wrong port on a
        // single-port entry, and every skipped L4 entry's address (AC11).
        for (host, ip, port) in [
            (Some("evil.com"), "9.9.9.9", 1u16),
            (Some("api.example.com.evil"), "1.1.1.1", 443),
            (None, "203.0.113.9", 54),
            (None, "10.0.0.5", 9090),
            (None, "192.0.2.1", 1500),
            (None, "10.0.0.1", 1),
            (None, "198.51.100.50", 1),
        ] {
            assert!(
                !matcher.matches(host, ip, port),
                "expected out-of-scope, got claimed: {host:?} {ip} {port}"
            );
        }
    }

    /// **AC11** (direct restatement). None of the skipped L4 addresses leak into the
    /// emitted spec. NB: the discriminator for the skipped `10.0.0.0/24` is its base
    /// address `10.0.0.0`, *not* the substring `10.0.0.` — the latter also matches
    /// the legitimate L7 token `10.0.0.5:8080`.
    #[test]
    fn skips_unrepresentable_l4_entries() {
        let spec = provider_scope_spec(&l7_fixture(), &l4_fixture()).spec;
        assert!(
            !spec.contains("192.0.2.1"),
            "partial-range entry leaked: {spec}"
        );
        assert!(!spec.contains("10.0.0.0"), "non-host CIDR leaked: {spec}");
        assert!(
            !spec.contains("198.51.100.5"),
            "filtered entry leaked: {spec}"
        );
    }

    // ----------------------------------------------------------------------------
    // Faithful Rust mirror of the Swift provider's `ScopeMatcher`
    // (apps/mac/Extension/Sources/FlowHandoff.swift). Each method cites its Swift
    // source lines. Per spec Architect's call C6, IP tokens/flows are compared by
    // parsing to `std::net::IpAddr` and comparing by value — equivalent to the Swift
    // `IPText.canonical` string compare for the fixture's valid inputs.
    // ----------------------------------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum MirrorTarget {
        Host(String),
        Suffix(String),
        Ip(IpAddr),
    }

    struct MirrorEntry {
        target: MirrorTarget,
        port: Option<u16>,
    }

    struct ScopeMatcherMirror {
        entries: Vec<MirrorEntry>,
    }

    impl ScopeMatcherMirror {
        /// Mirror of `init(spec:)` (FlowHandoff.swift:513-518): split on `,;` +
        /// whitespace/newlines, drop empties, parse each lowercased token.
        fn new(spec: &str) -> Self {
            let entries = spec
                .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .filter_map(|tok| Self::parse(&tok.to_ascii_lowercase()))
                .collect();
            Self { entries }
        }

        /// Mirror of `matches(hostname:ip:port:)` (FlowHandoff.swift:520-535).
        fn matches(&self, hostname: Option<&str>, ip: &str, port: u16) -> bool {
            let host = hostname.map(Self::normalize_host);
            // `IPText.canonical(text: ip) ?? ip`: compared by value as `IpAddr`.
            let flow_ip = ip.parse::<IpAddr>().ok();
            for entry in &self.entries {
                if let Some(wanted) = entry.port {
                    if wanted != port {
                        continue;
                    }
                }
                match &entry.target {
                    MirrorTarget::Ip(address) => {
                        if Some(*address) == flow_ip {
                            return true;
                        }
                    }
                    MirrorTarget::Host(name) => {
                        if host.as_deref() == Some(name.as_str()) {
                            return true;
                        }
                    }
                    MirrorTarget::Suffix(suffix) => {
                        if let Some(h) = host.as_deref() {
                            if h.ends_with(&format!(".{suffix}")) {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        }

        /// Mirror of `normalizeHost(_:)` (FlowHandoff.swift:537-541): lowercase and
        /// drop a single trailing dot.
        fn normalize_host(h: &str) -> String {
            let mut s = h.to_ascii_lowercase();
            if s.ends_with('.') {
                s.pop();
            }
            s
        }

        /// Mirror of `parse(_:)` (FlowHandoff.swift:543-575). `token` is lowercased.
        fn parse(token: &str) -> Option<MirrorEntry> {
            // Bracketed IPv6 literal with an optional `:port` (:546-556).
            if let Some(rest0) = token.strip_prefix('[') {
                let close = rest0.find(']')?;
                let host_part = &rest0[..close];
                let rest = &rest0[close + 1..];
                let mut port = None;
                if !rest.is_empty() {
                    let p = rest.strip_prefix(':')?;
                    let n: u16 = p.parse().ok()?;
                    if n == 0 {
                        return None;
                    }
                    port = Some(n);
                }
                let ip = host_part.parse::<IpAddr>().ok()?;
                return Some(MirrorEntry {
                    target: MirrorTarget::Ip(ip),
                    port,
                });
            }
            // Count colons to tell `host:port` from a bare IPv6 literal (:557-565).
            let colons = token.matches(':').count();
            let mut host_part = token;
            let mut port = None;
            if colons == 1 {
                if let Some((h, p)) = token.split_once(':') {
                    host_part = h;
                    let n: u16 = p.parse().ok()?;
                    if n == 0 {
                        return None;
                    }
                    port = Some(n);
                }
            } else if colons >= 2 {
                let ip = token.parse::<IpAddr>().ok()?;
                return Some(MirrorEntry {
                    target: MirrorTarget::Ip(ip),
                    port: None,
                });
            }
            // IP literal (:566-568), `*.`-suffix (:569-572), or plain host (:573-574).
            if let Ok(ip) = host_part.parse::<IpAddr>() {
                return Some(MirrorEntry {
                    target: MirrorTarget::Ip(ip),
                    port,
                });
            }
            if let Some(suffix) = host_part.strip_prefix("*.") {
                let suffix = Self::normalize_host(suffix);
                return if Self::is_valid_hostname(&suffix) {
                    Some(MirrorEntry {
                        target: MirrorTarget::Suffix(suffix),
                        port,
                    })
                } else {
                    None
                };
            }
            let name = Self::normalize_host(host_part);
            if Self::is_valid_hostname(&name) {
                Some(MirrorEntry {
                    target: MirrorTarget::Host(name),
                    port,
                })
            } else {
                None
            }
        }

        /// Mirror of `isValidHostname(_:)` (FlowHandoff.swift:577-583).
        fn is_valid_hostname(s: &str) -> bool {
            if s.is_empty() || s.len() > 253 || s.starts_with('.') || s.contains("..") {
                return false;
            }
            s.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == '_'
            })
        }
    }
}
