//! Scan profiles: the `ScanProfile` tree, its defaults and the built-in profiles (spec D2).
//!
//! A profile is the one knob an operator turns. It is operator-authored YAML (spec
//! D11), so every struct here is `#[serde(default)]` — a profile may name only what
//! it changes — and `#[serde(deny_unknown_fields)]`, so a mistyped key is an error
//! rather than a silently ignored line. The `Default` impls carry the spec's numbers;
//! the built-ins below are those defaults with a handful of fields moved.
//!
//! Hard ceilings are deliberately absent: they live in the `scanner.ceilings` config
//! section (spec D11, Architect's call 15). A profile value above a ceiling is
//! clamped by the engine and reported in `scan.start`'s `clamped` list.

use serde::{Deserialize, Serialize};

use crate::ids::FlowRef;
use crate::vocab::{
    Accuracy, CrawlStrategy, HttpVersionPolicy, InsertionKind, Intensity, L4Transport, LaneKind,
    OnLost, PointTrait, RecordProbes, SessionMode, Speed, UseBrowser,
};

/// Everything a scan job needs to know about how to behave.
///
/// `target` is the only field `scan.start` routinely overwrites: the built-in
/// profiles carry an empty target and the caller supplies the origin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct ScanProfile {
    /// The profile's name. Empty for an inline, unnamed profile.
    pub name: String,
    /// What to scan.
    pub target: ProfileTarget,
    /// Which lanes the job runs. A lane not in this build is reported as skipped.
    pub lanes: Vec<LaneKind>,
    /// How invasive the job may be.
    pub intensity: Intensity,
    /// The time-versus-coverage dial.
    pub speed: Speed,
    /// Which way the scheduler leans on an uncertain verdict.
    pub accuracy: Accuracy,
    /// Which checks run.
    pub checks: CheckSelection,
    /// How the crawler behaves.
    pub crawl: CrawlOptions,
    /// Which insertion points are audited, and which are ignored.
    pub audit: AuditOptions,
    /// Where the job's session comes from.
    pub session: SessionOptions,
    /// The job's probe, time and issue budget.
    pub budget: Budget,
    /// HTTP-lane options.
    pub http: HttpOptions,
    /// WebSocket-lane options.
    pub ws: WsOptions,
    /// L4-lane options.
    pub l4: L4Options,
}

impl Default for ScanProfile {
    fn default() -> Self {
        Self {
            name: String::new(),
            target: ProfileTarget::default(),
            lanes: vec![LaneKind::Http],
            intensity: Intensity::Medium,
            speed: Speed::Normal,
            accuracy: Accuracy::Normal,
            checks: CheckSelection::default(),
            crawl: CrawlOptions::default(),
            audit: AuditOptions::default(),
            session: SessionOptions::default(),
            budget: Budget::default(),
            http: HttpOptions::default(),
            ws: WsOptions::default(),
            l4: L4Options::default(),
        }
    }
}

/// What a scan points at: HTTP origins, L4 endpoints, or both.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct ProfileTarget {
    /// Origins in `http(s)://host[:port]` form. Validated by the engine against scope.
    pub origins: Vec<String>,
    /// L4 endpoints, each needing a matching L4 scope entry with the `Inject` capability.
    pub l4: Vec<L4TargetSpec>,
}

/// One L4 endpoint a scan may address.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct L4TargetSpec {
    /// The target address.
    pub ip: String,
    /// The target port.
    pub port: u16,
    /// The transport the target speaks.
    pub proto: L4Transport,
    /// The grammar to mutate against, if the operator names one.
    pub grammar: Option<String>,
}

impl Default for L4TargetSpec {
    fn default() -> Self {
        Self {
            ip: String::new(),
            port: 0,
            proto: L4Transport::Tcp,
            grammar: None,
        }
    }
}

/// Which checks a job runs, as selectors the engine resolves.
///
/// A selector is a check id, a check class, or `lane:<lane>`. An empty `include`
/// means every check the profile's intensity and lanes allow.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct CheckSelection {
    /// Selectors a check must match to run. Empty means "all applicable".
    pub include: Vec<String>,
    /// Selectors that disqualify a check. Applied after `include`.
    pub exclude: Vec<String>,
}

/// How hard, how wide and how deep the crawler works (Architect's call A3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct CrawlOptions {
    /// Links only, links and forms, or links, forms and handlers.
    pub strategy: CrawlStrategy,
    /// How many links deep from a seed the crawler follows.
    pub max_depth: u32,
    /// How many pages the crawler fetches. `0` disables crawling.
    pub max_pages: u32,
    /// Whether the crawler submits forms it judges safe.
    pub submit_forms: bool,
    /// Whether the crawler clicks event handlers.
    pub click_handlers: bool,
    /// Whether `robots.txt` is read for additional paths.
    pub robots: bool,
    /// Whether `sitemap.xml` is read for additional paths.
    pub sitemap: bool,
    /// Whether the crawler drives a real browser.
    pub use_browser: UseBrowser,
}

impl Default for CrawlOptions {
    fn default() -> Self {
        Self {
            strategy: CrawlStrategy::Normal,
            max_depth: 3,
            max_pages: 200,
            submit_forms: true,
            click_handlers: true,
            robots: true,
            sitemap: true,
            use_browser: UseBrowser::Auto,
        }
    }
}

/// Which insertion points are audited, and how many of them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct AuditOptions {
    /// The insertion kinds a job audits. Defaults to every kind.
    pub kinds: Vec<InsertionKind>,
    /// Rules that take a point out of the audit. Defaults to "skip session points",
    /// which the operator may remove by writing an empty list.
    pub ignore: Vec<IgnoreRule>,
    /// The cap on points taken from a single request.
    pub max_points_per_request: u32,
    /// How many requests a point must appear in before it counts as "frequent"
    /// (audited once rather than per request).
    pub frequent_point_threshold: u32,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            kinds: InsertionKind::ALL.to_vec(),
            ignore: vec![IgnoreRule {
                point_trait: Some(PointTrait::Session),
                ..IgnoreRule::default()
            }],
            max_points_per_request: 64,
            frequent_point_threshold: 8,
        }
    }
}

/// One rule that excludes insertion points from the audit.
///
/// A rule matches a point when **every** key it sets matches. A rule that sets no
/// key would match everything, so it is invalid; see [`IgnoreRule::is_valid`].
/// `name_regex` is compiled by the engine, not here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct IgnoreRule {
    /// Match points of this insertion kind.
    pub kind: Option<InsertionKind>,
    /// Match points whose name matches this regular expression.
    pub name_regex: Option<String>,
    /// Match points carrying this trait. `trait` on the wire; the field cannot
    /// be called that in Rust.
    #[serde(rename = "trait")]
    pub point_trait: Option<PointTrait>,
}

impl IgnoreRule {
    /// Whether the rule sets at least one key, i.e. whether it excludes something
    /// narrower than "every point". The engine rejects a profile containing an
    /// invalid rule with `invalid_profile` rather than silently auditing nothing.
    pub fn is_valid(&self) -> bool {
        self.kind.is_some() || self.name_regex.is_some() || self.point_trait.is_some()
    }
}

/// Where a job's session comes from and what it does when the session dies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct SessionOptions {
    /// Reuse an observed session, or scan unauthenticated.
    pub mode: SessionMode,
    /// The captured flow the session is taken from.
    pub from_flow: Option<FlowRef>,
    /// What the job does when the session stops working.
    pub on_lost: OnLost,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            mode: SessionMode::Observed,
            from_flow: None,
            on_lost: OnLost::Stop,
        }
    }
}

/// What a job is allowed to spend. Every figure is also subject to a config
/// ceiling (spec D11); the lower of the two wins and the clamp is reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct Budget {
    /// Total probes the job may send across every lane.
    pub probes: u32,
    /// Wall-clock seconds the job may run for.
    pub time_s: u64,
    /// Issues after which the job stops reporting and finishes.
    pub max_issues: u32,
    /// Seconds one check may spend on one point (spec D4's `check_timeout`,
    /// Architect's call A4).
    pub check_timeout_s: u64,
    /// When a host is considered too broken to keep probing.
    pub per_host_errors: PerHostErrors,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            probes: 2000,
            time_s: 600,
            max_issues: 1024,
            check_timeout_s: 60,
            per_host_errors: PerHostErrors::default(),
        }
    }
}

/// The circuit breaker for a host that stops answering usefully.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct PerHostErrors {
    /// Consecutive errors from one host that trip the breaker.
    pub consecutive: u32,
    /// The error-to-probe ratio for one host that trips the breaker.
    pub ratio: f32,
}

impl Default for PerHostErrors {
    fn default() -> Self {
        Self {
            consecutive: 10,
            ratio: 0.5,
        }
    }
}

/// HTTP-lane options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct HttpOptions {
    /// The HTTP version probes negotiate, handed to the sender as
    /// `SendOptions.version` (spec D9.1).
    pub version: HttpVersionPolicy,
    /// Which probe flows are kept in the flow store.
    pub record_probes: RecordProbes,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            version: HttpVersionPolicy::Auto,
            record_probes: RecordProbes::IssuesOnly,
        }
    }
}

/// WebSocket-lane options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct WsOptions {
    /// How long a check waits for frames that answer a probe.
    pub reply_window_ms: u32,
    /// The largest frame the lane will send or keep, in bytes.
    pub max_frame_bytes: u32,
}

impl Default for WsOptions {
    fn default() -> Self {
        Self {
            reply_window_ms: 1500,
            max_frame_bytes: 1_048_576,
        }
    }
}

/// L4-lane options, shared by the packet and stream lanes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "snake_case")]
pub struct L4Options {
    /// How many mutated cases the lane sends.
    pub cases: u32,
    /// How many times an interesting case is replayed to confirm it.
    pub reproduce_count: u32,
    /// How often, in cases, the lane checks the target is still alive.
    pub liveness_every: u32,
    /// Consecutive timeouts after which the lane gives up on the target.
    pub consecutive_timeouts: u32,
    /// The lane's own send-rate cap, in bytes per second.
    pub max_bytes_per_s: u32,
    /// Minimum spacing, in milliseconds, between consecutive stimuli to a point
    /// whose baseline is an ICMP error (a closed port): the kernel rate-limits
    /// ICMP errors to about one per second per destination, so an unpaced run
    /// reads silence where the port is simply closed (amendment 46).
    ///
    /// Clamped **up** to the `scanner.ceilings.l4_icmp_pace_ms_min` floor
    /// (default 1000), which the engine reports in `scan.start`'s `clamped`.
    pub icmp_pace_ms: u32,
    /// The messages mutation starts from. Empty means the grammar supplies them.
    pub seeds: Vec<L4Seed>,
    /// Build every case and report what would be sent, sending nothing.
    pub dry_run: bool,
}

impl Default for L4Options {
    fn default() -> Self {
        Self {
            cases: 500,
            reproduce_count: 3,
            liveness_every: 25,
            consecutive_timeouts: 20,
            max_bytes_per_s: 65_536,
            icmp_pace_ms: 1100,
            seeds: Vec::new(),
            dry_run: false,
        }
    }
}

/// One seed message for L4 mutation, written the way the operator has it: a
/// captured flow, a hex string, or base64.
///
/// Untagged, so the YAML is `- hex: "0001"` rather than a variant wrapper. It is
/// read through [`L4SeedRaw`] so a mistyped key is reported by name and a seed
/// with no form or two forms gets a plain "exactly one of" message, instead of
/// serde's opaque "did not match any variant of untagged enum".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, try_from = "L4SeedRaw")]
pub enum L4Seed {
    /// Take the seed bytes from a captured flow.
    Flow {
        /// The captured flow.
        flow: FlowRef,
    },
    /// The seed bytes as hex.
    Hex {
        /// Hex digits, decoded by the lane.
        hex: String,
    },
    /// The seed bytes as base64.
    Base64 {
        /// Base64, decoded by the lane.
        base64: String,
    },
}

/// The wire shape an [`L4Seed`] is read from: the three forms as optional keys,
/// unknown keys rejected by name. [`TryFrom`] then insists on exactly one form.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct L4SeedRaw {
    flow: Option<FlowRef>,
    hex: Option<String>,
    base64: Option<String>,
}

impl TryFrom<L4SeedRaw> for L4Seed {
    type Error = String;

    fn try_from(raw: L4SeedRaw) -> Result<Self, Self::Error> {
        match (raw.flow, raw.hex, raw.base64) {
            (Some(flow), None, None) => Ok(L4Seed::Flow { flow }),
            (None, Some(hex), None) => Ok(L4Seed::Hex { hex }),
            (None, None, Some(base64)) => Ok(L4Seed::Base64 { base64 }),
            (None, None, None) => Err(
                "an L4 seed needs exactly one of `flow`, `hex` or `base64`; none was given"
                    .to_string(),
            ),
            (flow, hex, base64) => {
                let present: Vec<&str> = [
                    flow.is_some().then_some("`flow`"),
                    hex.is_some().then_some("`hex`"),
                    base64.is_some().then_some("`base64`"),
                ]
                .into_iter()
                .flatten()
                .collect();
                Err(format!(
                    "an L4 seed needs exactly one of `flow`, `hex` or `base64`; got {}",
                    present.join(" and ")
                ))
            }
        }
    }
}

impl From<HttpVersionPolicy> for aitm_core::VersionPolicy {
    fn from(policy: HttpVersionPolicy) -> Self {
        match policy {
            HttpVersionPolicy::Auto => aitm_core::VersionPolicy::Auto,
            HttpVersionPolicy::H1 => aitm_core::VersionPolicy::H1,
            HttpVersionPolicy::H2 => aitm_core::VersionPolicy::H2,
            HttpVersionPolicy::H2c => aitm_core::VersionPolicy::H2c,
        }
    }
}

/// The names of the profiles shipped with aitmproxy, in the order
/// [`builtin_profiles`] returns them. `scan.profile.save` refuses these names.
pub const BUILTIN_PROFILE_NAMES: [&str; 7] = [
    "passive-only",
    "map-only",
    "light-http",
    "standard",
    "thorough",
    "l4-stream-safe",
    "l4-full",
];

/// Every built-in profile, in [`BUILTIN_PROFILE_NAMES`] order.
///
/// Each is the defaults above with a few fields moved; `target` is always empty,
/// because `scan.start` fills it from the caller's origin or L4 endpoint.
pub fn builtin_profiles() -> Vec<ScanProfile> {
    // Passive checks over already-captured in-scope flows only: no crawl, no
    // browser, no probes (Architect's call A5).
    let passive_only = ScanProfile {
        name: "passive-only".to_string(),
        intensity: Intensity::Passive,
        crawl: CrawlOptions {
            max_pages: 0,
            use_browser: UseBrowser::Never,
            ..CrawlOptions::default()
        },
        ..ScanProfile::default()
    };

    // Crawl and passive checks: builds the site map without sending a probe.
    let map_only = ScanProfile {
        name: "map-only".to_string(),
        intensity: Intensity::Passive,
        ..ScanProfile::default()
    };

    let light_http = ScanProfile {
        name: "light-http".to_string(),
        intensity: Intensity::Light,
        speed: Speed::Fast,
        ..ScanProfile::default()
    };

    let standard = ScanProfile {
        name: "standard".to_string(),
        lanes: vec![LaneKind::Http, LaneKind::Ws],
        ..ScanProfile::default()
    };

    let thorough = ScanProfile {
        name: "thorough".to_string(),
        lanes: vec![LaneKind::Http, LaneKind::Ws],
        speed: Speed::Thorough,
        accuracy: Accuracy::FewerFalseNegatives,
        crawl: CrawlOptions {
            strategy: CrawlStrategy::Thorough,
            ..CrawlOptions::default()
        },
        ..ScanProfile::default()
    };

    let l4_stream_safe = ScanProfile {
        name: "l4-stream-safe".to_string(),
        lanes: vec![LaneKind::L4Stream],
        l4: L4Options {
            cases: 200,
            dry_run: false,
            ..L4Options::default()
        },
        ..ScanProfile::default()
    };

    let l4_full = ScanProfile {
        name: "l4-full".to_string(),
        lanes: vec![LaneKind::L4Packet, LaneKind::L4Stream],
        l4: L4Options {
            cases: 500,
            ..L4Options::default()
        },
        ..ScanProfile::default()
    };

    vec![
        passive_only,
        map_only,
        light_http,
        standard,
        thorough,
        l4_stream_safe,
        l4_full,
    ]
}

/// The built-in profile with this name, or `None` if there is no such built-in.
pub fn builtin(name: &str) -> Option<ScanProfile> {
    builtin_profiles().into_iter().find(|p| p.name == name)
}

/// Whether the name belongs to a built-in profile. `scan.profile.save` uses this
/// to refuse overwriting one.
pub fn is_builtin_name(name: &str) -> bool {
    BUILTIN_PROFILE_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn l4_seed_untagged_forms() {
        let hex: L4Seed = serde_json::from_str(r#"{"hex":"0001"}"#).expect("hex seed parses");
        assert_eq!(
            hex,
            L4Seed::Hex {
                hex: "0001".to_string()
            }
        );

        let b64: L4Seed = serde_json::from_str(r#"{"base64":"AAE="}"#).expect("base64 seed parses");
        assert_eq!(
            b64,
            L4Seed::Base64 {
                base64: "AAE=".to_string()
            }
        );

        let flow: L4Seed =
            serde_json::from_str(&format!(r#"{{"flow":"{UUID}"}}"#)).expect("flow seed parses");
        match &flow {
            L4Seed::Flow { flow } => assert_eq!(flow.to_string(), UUID),
            other => panic!("expected a flow seed, got {other:?}"),
        }

        assert_eq!(
            serde_json::to_string(&flow).expect("flow seed serializes"),
            format!(r#"{{"flow":"{UUID}"}}"#),
            "an untagged seed carries no variant wrapper"
        );
    }

    /// Panel Q1 — a seed must carry exactly one of `flow`, `hex`, `base64`:
    /// none is an error that says so, two is an error that names both, and a
    /// mistyped key is an error that names the key.
    #[test]
    fn l4_seed_requires_exactly_one_form() {
        let err = serde_json::from_str::<L4Seed>("{}").expect_err("an empty seed is an error");
        assert!(err.to_string().contains("exactly one"), "zero keys: {err}");

        let err = serde_json::from_str::<L4Seed>(r#"{"hex":"00","base64":"AA=="}"#)
            .expect_err("two forms are an error");
        let shown = err.to_string();
        assert!(shown.contains("exactly one"), "two keys: {shown}");
        assert!(
            shown.contains("hex") && shown.contains("base64"),
            "names both keys: {shown}"
        );

        let err = serde_json::from_str::<L4Seed>(r#"{"hxe":"00"}"#)
            .expect_err("a mistyped key is an error");
        assert!(err.to_string().contains("hxe"), "names the key: {err}");
    }

    #[test]
    fn version_policy_maps_onto_core() {
        assert_eq!(
            aitm_core::VersionPolicy::from(HttpVersionPolicy::H2c),
            aitm_core::VersionPolicy::H2c
        );
        assert_eq!(
            aitm_core::VersionPolicy::from(HttpVersionPolicy::Auto),
            aitm_core::VersionPolicy::Auto
        );
        assert_eq!(
            aitm_core::VersionPolicy::from(HttpVersionPolicy::H1),
            aitm_core::VersionPolicy::H1
        );
        assert_eq!(
            aitm_core::VersionPolicy::from(HttpVersionPolicy::H2),
            aitm_core::VersionPolicy::H2
        );
    }

    #[test]
    fn ignore_rule_needs_at_least_one_key() {
        assert!(
            !IgnoreRule::default().is_valid(),
            "a rule with no key would match every point"
        );
        assert!(IgnoreRule {
            kind: Some(InsertionKind::Cookie),
            ..IgnoreRule::default()
        }
        .is_valid());
        assert!(IgnoreRule {
            name_regex: Some("^csrf".to_string()),
            ..IgnoreRule::default()
        }
        .is_valid());
        assert!(IgnoreRule {
            point_trait: Some(PointTrait::Session),
            ..IgnoreRule::default()
        }
        .is_valid());
    }

    #[test]
    fn ignore_rule_wire_key_is_trait() {
        let json = serde_json::to_string(&IgnoreRule {
            point_trait: Some(PointTrait::Session),
            ..IgnoreRule::default()
        })
        .expect("rule serializes");
        assert_eq!(json, r#"{"kind":null,"name_regex":null,"trait":"session"}"#);
    }

    /// Amendment 46 (ICMP-paced points): the pace is a profile knob with a
    /// default of 1100 ms, and an old profile written before the knob existed
    /// still deserialises — it simply gets the default.
    #[test]
    fn l4_options_default_icmp_pace_is_1100() {
        assert_eq!(L4Options::default().icmp_pace_ms, 1100);

        let old: L4Options = serde_json::from_str(r#"{"cases": 5}"#)
            .expect("a profile written before the knob existed still parses");
        assert_eq!(old.cases, 5);
        assert_eq!(old.icmp_pace_ms, 1100);

        let set: L4Options =
            serde_json::from_str(r#"{"cases": 5, "icmp_pace_ms": 2000}"#).expect("the knob parses");
        assert_eq!(set.icmp_pace_ms, 2000);
    }

    /// Tester (T5 stage 5): the new knob keeps `L4Options`' own contract —
    /// `deny_unknown_fields`, so a near-miss spelling is reported by name
    /// instead of silently taking the default pace; and `u32`, so a negative or
    /// out-of-range value is an error rather than a wrapped one. The round trip
    /// through JSON and YAML returns the same options.
    #[test]
    fn l4_options_rejects_a_mistyped_pace_key_and_an_unrepresentable_value() {
        for key in ["icmp_pace", "icmp_pace_msec", "icmpPaceMs", "pace_ms"] {
            let json = format!(r#"{{"cases": 5, "{key}": 2000}}"#);
            let err = serde_json::from_str::<L4Options>(&json)
                .expect_err("a mistyped key is an error, never a silent default");
            assert!(
                err.to_string().contains(key),
                "the error should name {key}: {err}"
            );
        }

        for value in ["-1", "1.5", "4294967296", "\"1100\"", "null"] {
            let json = format!(r#"{{"icmp_pace_ms": {value}}}"#);
            assert!(
                serde_json::from_str::<L4Options>(&json).is_err(),
                "{value} is not a pace in milliseconds"
            );
        }

        let max: L4Options = serde_json::from_str(r#"{"icmp_pace_ms": 4294967295}"#)
            .expect("the largest representable pace parses");
        assert_eq!(max.icmp_pace_ms, u32::MAX);

        let options = L4Options {
            icmp_pace_ms: 2500,
            ..L4Options::default()
        };
        let json = serde_json::to_string(&options).expect("options serialize");
        assert!(
            json.contains("\"icmp_pace_ms\":2500"),
            "the wire key is snake_case: {json}"
        );
        assert_eq!(
            serde_json::from_str::<L4Options>(&json).expect("round trip"),
            options
        );
        let yaml = serde_yaml::to_string(&options).expect("options serialize as yaml");
        assert_eq!(
            serde_yaml::from_str::<L4Options>(&yaml).expect("yaml round trip"),
            options
        );
    }
}
