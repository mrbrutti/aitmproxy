//! Check metadata, verdicts, evidence and PoC hints (spec D2). Task 5 of the T1a plan owns this file.
//!
//! [`CheckMeta`] is what `scan.checks` returns and what the scheduler reasons
//! over; [`Verdict`] is what a `Check` hands back for one insertion point, and
//! [`Evidence`] is the bounded, already-scrubbed proof that travels with an
//! issue. [`Verdict::poc_hint`] is the one field that never reaches the wire: it
//! is `#[serde(skip)]` because `aitm_poc::Assertion` has no serde derives and
//! because a hint is an in-process instruction to the PoC builder, not a result
//! (spec D2, Architect's call 23).

use aitm_core::redact::scrub_text_wide;
use serde::{Deserialize, Serialize};

use crate::ids::FlowRef;
use crate::vocab::{
    CheckCost, CheckOrigin, CheckScope, Confidence, InsertionKind, Intensity, LaneKind, Outcome,
    PointTrait, Technique,
};

/// The largest excerpt [`Evidence::excerpt`] will produce, in bytes (spec D2).
pub const MAX_EXCERPT_BYTES: usize = 256;

/// Everything the scheduler, the catalogue and the UIs know about a check.
///
/// Identical for a native check and a Rhai one: the Rhai bridge builds this from
/// the `add_check` meta map, whose keys are exactly these wire names (spec D4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CheckMeta {
    /// Stable catalogue identifier, also the manual `check.<id>` verb's suffix.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// The vulnerability class (`sqli`, `xss`, ...); groups issues and selectors.
    pub class: String,
    /// The lanes this check can run in.
    pub lanes: Vec<LaneKind>,
    /// The insertion kinds this check applies to.
    pub kinds: Vec<InsertionKind>,
    /// How invasive the check is; a profile admits `intensity <= profile.intensity`.
    pub intensity: Intensity,
    /// Roughly how many probes per point the check spends.
    pub cost: CheckCost,
    /// The detection technique, which also caps `confidence_max`.
    pub technique: Technique,
    /// The severity an issue from this check typically carries.
    pub severity: aitm_poc::Severity,
    /// The strongest confidence this check can reach.
    pub confidence_max: Confidence,
    /// Whether the check needs the point's baseline response before probing.
    #[serde(default)]
    pub needs_baseline: bool,
    /// When present, schedule only on points carrying at least one listed trait
    /// (ignored at `speed: thorough`).
    #[serde(default)]
    pub wants_traits: Option<Vec<PointTrait>>,
    /// Whether the check may mutate `session`-trait points. No v2 check does.
    #[serde(default)]
    pub targets_session: bool,
    /// How often the scheduler runs the check: per point, per node, per origin.
    ///
    /// Absent from a pre-T1b catalogue entry, which reads as
    /// [`CheckScope::Point`] — once per insertion point.
    #[serde(default)]
    pub scope: CheckScope,
    /// The CWE this class maps to.
    #[serde(default)]
    pub cwe: Option<u32>,
    /// What the check looks for.
    pub description: String,
    /// What to do about a finding.
    #[serde(default)]
    pub remediation: Option<String>,
    /// Where the check came from: compiled in, bundled script, operator script.
    pub origin: CheckOrigin,
}

/// A check's result for one insertion point (spec D2).
///
/// **One verdict, or one per exposed path.** A check returns one root verdict
/// and may attach sibling verdicts in [`Verdict::more`] (coordinator item (g),
/// 2026-11-01). Each verdict's [`Verdict::location`], when present, overrides
/// the issue location's `path` (and `name`), so an origin-scoped check such as
/// an exposed-path probe produces one issue per entry — the dedupe key hashes
/// class + location, which is what keeps `/.git/` and `/.env` apart. The
/// engine flattens `more` **one level**: a `more` inside a `more` entry is
/// ignored. Both fields are additive; a verdict written before them reads as
/// "no override, no siblings".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Verdict {
    /// What the check concluded.
    pub outcome: Outcome,
    /// How sure it is, never above the check's `confidence_max`.
    pub confidence: Confidence,
    /// The bounded, scrubbed proof.
    pub evidence: Evidence,
    /// One line of prose for the operator.
    pub detail: String,
    /// In-process instruction to the PoC builder; never serialised (call 23).
    #[serde(skip)]
    pub poc_hint: Option<PocHint>,
    /// Where this verdict's issue lives when that differs from the point: the
    /// engine takes `path` (and `name`) from here over the point's own.
    #[serde(default)]
    pub location: Option<VerdictLocation>,
    /// Sibling verdicts from the same run, each becoming its own issue;
    /// flattened one level by the engine.
    #[serde(default)]
    pub more: Vec<Verdict>,
}

impl Verdict {
    /// Scrub every free-text field a check may have copied from a response, in
    /// place: `detail`, the [`Evidence`] (through [`Evidence::scrub`]), and the
    /// same for every `more` sibling (amendment 67, call C5).
    ///
    /// One rule for both consumers: the Rhai bridge applies it where a script's
    /// verdict is built, the manual `check.<id>` path applies it before the
    /// verdict reaches the bus caller. The scrubber is `aitm_core::redact::
    /// scrub_text_wide`, and the scrub is idempotent — `[redacted]` has nothing
    /// left to redact — so a verdict the bridge already scrubbed comes through
    /// the manual path unchanged.
    pub fn scrub(&mut self) {
        self.detail = scrub_text_wide(&self.detail);
        self.evidence.scrub();
        for sibling in &mut self.more {
            sibling.scrub();
        }
    }

    /// [`Verdict::scrub`] by value.
    pub fn scrubbed(mut self) -> Self {
        self.scrub();
        self
    }
}

/// The part of an issue location a verdict may override (coordinator item (g)).
///
/// An absent field keeps the point's value; a check that found `/.git/` sets
/// `path` and leaves `name` to the point.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct VerdictLocation {
    /// The request path the issue is at, overriding the point's.
    #[serde(default)]
    pub path: Option<String>,
    /// The parameter or element name, overriding the point's.
    #[serde(default)]
    pub name: Option<String>,
}

/// What a check tells the engine to assert when it reproduces the finding.
///
/// No serde: `aitm_poc::Assertion` has none, and a hint is never on the wire.
#[derive(Debug, Clone, PartialEq)]
pub struct PocHint {
    /// What the PoC's response must satisfy for the reproduction to pass.
    pub assertions: Vec<aitm_poc::Assertion>,
    /// A benign control payload whose response must *not* look vulnerable.
    pub control: Option<ControlHint>,
}

/// The benign control arm of a [`PocHint`], mirroring
/// `FindingRecord.reproduction.control_passed`.
#[derive(Debug, Clone, PartialEq)]
pub struct ControlHint {
    /// The harmless payload sent in place of the real one.
    pub payload: String,
    /// What the control's response must satisfy.
    pub expect: Vec<aitm_poc::Assertion>,
}

/// The proof carried by a verdict and, later, by an issue (spec D2).
///
/// Every string here is bounded and scrubbed before it travels: a check hands
/// the raw text, and [`Evidence::scrub`] (reached through [`Verdict::scrub`])
/// scrubs it and then bounds `matched` through [`Evidence::excerpt`].
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Evidence {
    /// The payload that produced the reaction.
    #[serde(default)]
    pub payload: Option<String>,
    /// A scanner constant, or a bounded scrubbed excerpt of what matched.
    #[serde(default)]
    pub matched: Option<String>,
    /// The probe flows that evidence the issue.
    #[serde(default)]
    pub probe_flows: Vec<FlowRef>,
    /// The baseline flow the probes were compared against.
    #[serde(default)]
    pub baseline_flow: Option<FlowRef>,
    /// Timing correlation, for blind time-based techniques.
    #[serde(default)]
    pub timing: Option<Timing>,
    /// Response-length differences, for boolean techniques.
    #[serde(default)]
    pub diff: Option<Diff>,
    /// The layer 4 case that produced the reaction.
    #[serde(default)]
    pub l4: Option<L4Evidence>,
}

impl Evidence {
    /// Scrub the two free-text fields in place: `payload` is scrubbed;
    /// `matched` is scrubbed **then** bounded to [`MAX_EXCERPT_BYTES`]
    /// (amendment 16's order: a cut before the scrub could leave a fragment of
    /// a credential the scrubber no longer recognises).
    pub fn scrub(&mut self) {
        self.payload = self.payload.as_deref().map(scrub_text_wide);
        self.matched = self
            .matched
            .as_deref()
            .map(|text| Self::excerpt(&scrub_text_wide(text)));
    }

    /// A copy of `text` cut to at most [`MAX_EXCERPT_BYTES`] bytes, never
    /// splitting a character.
    ///
    /// This is a bound, not a scrub: [`Evidence::scrub`] scrubs first and then
    /// calls this; a caller using it directly passes text that has already been
    /// through `aitm_core::redact` / `scrub_text_wide`.
    pub fn excerpt(text: &str) -> String {
        if text.len() <= MAX_EXCERPT_BYTES {
            return text.to_string();
        }
        let mut end = MAX_EXCERPT_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    }
}

/// Timing evidence: what was requested against what was observed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Timing {
    /// The delays the payloads asked for, in seconds.
    pub requested_s: Vec<f32>,
    /// The response times observed for each, in milliseconds.
    pub observed_ms: Vec<u32>,
    /// The unpayloaded baseline times, in milliseconds.
    pub baseline_ms: Vec<u32>,
    /// Slope of observed against requested; near 1000 ms/s when correlated.
    pub slope: f32,
    /// Pearson correlation coefficient of the fit.
    pub r: f32,
    /// Whether the check judged the fit a correlation (spec D8.2: a blind timing
    /// technique may claim `firm` only after a correlated repeat).
    ///
    /// The check decides, not the reader of the evidence: it knows how many
    /// repeats it ran and against which threshold. Absent means `false`.
    #[serde(default)]
    pub correlated: bool,
}

/// Response-length evidence for a boolean-blind technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Diff {
    /// Length of the unpayloaded response.
    pub baseline_len: u32,
    /// Length of the response to the "true" payload.
    pub true_len: u32,
    /// Length of the response to the "false" payload.
    pub false_len: u32,
}

/// Everything needed to re-run one layer 4 case (spec D2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct L4Evidence {
    /// The bytes sent, hex-encoded.
    pub sent_hex: String,
    /// Which configured seed the case was mutated from.
    pub seed_id: String,
    /// The RNG seed, so the case is reproducible.
    pub rng_seed: u64,
    /// The mutators applied, in order.
    pub mutation_chain: Vec<String>,
    /// How many messages were sent on the connection before this case.
    pub prior_messages: u32,
    /// How the oracle classified the target's reaction.
    pub oracle: L4Oracle,
    /// Whether the liveness probe passed before the case.
    pub liveness_before: bool,
    /// Whether it passed after the case.
    pub liveness_after: bool,
    /// `[k, n]`: the case reproduced `k` times out of `n` attempts (call A9).
    pub reproduced: (u32, u32),
    /// The scope entry that authorised the target.
    pub scope_entry: String,
}

/// How an L4 oracle read the target's reaction (spec D2, plan call A10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum L4Oracle {
    /// The target replied with its own protocol-level error.
    ProtocolError,
    /// The connection was reset.
    Reset,
    /// An ICMP message came back.
    Icmp {
        /// The ICMP type (3 is destination unreachable).
        #[serde(rename = "type")]
        icmp_type: u8,
        /// The ICMP code (3 is port unreachable).
        code: u8,
    },
    /// Nothing came back within the window.
    Silence,
    /// The liveness probe that followed the case failed.
    LivenessFailed,
    /// The reply came back far outside the observed latency distribution.
    LatencyOutlier,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_never_emits_poc_hint() {
        let verdict = Verdict {
            outcome: Outcome::Vulnerable,
            confidence: Confidence::Firm,
            evidence: Evidence::default(),
            detail: "marker reflected in an HTML text node".into(),
            poc_hint: Some(PocHint {
                assertions: vec![aitm_poc::Assertion::Status(200)],
                control: None,
            }),
            location: None,
            more: Vec::new(),
        };

        let json = serde_json::to_string(&verdict).expect("serializes");
        assert!(!json.contains("poc_hint"), "{json}");

        let back: Verdict = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back.poc_hint, None);
        assert_eq!(back.outcome, Outcome::Vulnerable);
        assert_eq!(back.confidence, Confidence::Firm);
    }

    #[test]
    fn check_meta_round_trips_with_bundled_origin() {
        let meta = CheckMeta {
            id: "sqli-error".into(),
            name: "SQL injection (error-based)".into(),
            class: "sqli".into(),
            lanes: vec![LaneKind::Http],
            kinds: vec![InsertionKind::Query, InsertionKind::BodyParam],
            intensity: Intensity::Medium,
            cost: CheckCost::Light,
            technique: Technique::Error,
            severity: aitm_poc::Severity::High,
            confidence_max: Confidence::Firm,
            needs_baseline: false,
            wants_traits: None,
            targets_session: false,
            scope: CheckScope::Point,
            cwe: Some(89),
            description: "A database error signature reveals the injected quote.".into(),
            remediation: Some("Use parameterised queries.".into()),
            origin: CheckOrigin::Bundled {
                path: "scripts/bundled/active/sqli.rhai".into(),
            },
        };

        let json = serde_json::to_string(&meta).expect("serializes");
        assert!(json.contains(r#""severity":"high""#), "{json}");
        assert!(
            json.contains(r#""kind":"bundled","path":"scripts/bundled/active/sqli.rhai""#),
            "{json}"
        );

        let back: CheckMeta = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, meta);
        assert_eq!(back.cwe, Some(89));
    }

    #[test]
    fn evidence_excerpt_is_bounded() {
        assert_eq!(MAX_EXCERPT_BYTES, 256);
        assert_eq!(Evidence::excerpt(&"a".repeat(300)).len(), 256);
        assert_eq!(Evidence::excerpt("héllo").len(), 6);

        // 400 bytes of two-byte chars: the cut lands on a char boundary.
        let cut = Evidence::excerpt(&"é".repeat(200));
        assert_eq!(cut.len(), 256);
        assert_eq!(cut.chars().count(), 128);
    }

    /// Tester: `excerpt` is the one place a hostile response body reaches a
    /// fixed-size buffer, so the boundary cases must not panic and must not
    /// exceed the cap: empty input, exactly the cap, one byte over, and a
    /// three-byte character straddling the cap (the cut falls back below it).
    #[test]
    fn evidence_excerpt_handles_empty_and_straddling_boundaries() {
        assert_eq!(Evidence::excerpt(""), "");

        let exact = "a".repeat(MAX_EXCERPT_BYTES);
        assert_eq!(
            Evidence::excerpt(&exact),
            exact,
            "at the cap, nothing is cut"
        );

        let over = "a".repeat(MAX_EXCERPT_BYTES + 1);
        assert_eq!(Evidence::excerpt(&over).len(), MAX_EXCERPT_BYTES);

        // 3-byte chars: 256 is not a multiple of 3, so the cut must step back to
        // 255 rather than split a character.
        let straddle = Evidence::excerpt(&"€".repeat(200));
        assert_eq!(straddle.len(), 255);
        assert_eq!(straddle.chars().count(), 85);
        assert!(straddle.chars().all(|c| c == '€'));

        // A 4-byte char that starts one byte before the cap is dropped whole.
        let emoji = format!("{}{}", "a".repeat(MAX_EXCERPT_BYTES - 1), "😀".repeat(4));
        let cut = Evidence::excerpt(&emoji);
        assert_eq!(cut.len(), MAX_EXCERPT_BYTES - 1);
        assert!(!cut.contains('😀'));

        // Every excerpt is valid UTF-8 within the cap, whatever the input.
        for n in 250..=262 {
            let text = "é".repeat(n);
            let out = Evidence::excerpt(&text);
            assert!(
                out.len() <= MAX_EXCERPT_BYTES,
                "{n} chars overflowed the cap"
            );
            assert!(text.starts_with(&out), "{n} chars: excerpt is a prefix");
        }
    }

    /// Coordinator decision 4 (spec D4): `scope` is additive. A catalogue entry
    /// written before T1b carries no `scope` key and reads as the per-point
    /// default, so the scheduler keeps scheduling it once per insertion point.
    #[test]
    fn check_scope_defaults_to_point() {
        let json = r#"{
            "id": "sqli-error",
            "name": "SQL injection (error-based)",
            "class": "sqli",
            "lanes": ["http"],
            "kinds": ["query"],
            "intensity": "medium",
            "cost": "light",
            "technique": "error",
            "severity": "high",
            "confidence_max": "firm",
            "description": "A database error signature reveals the injected quote.",
            "origin": {"kind": "native"}
        }"#;

        let meta: CheckMeta = serde_json::from_str(json).expect("deserializes");
        assert_eq!(meta.scope, CheckScope::Point);
        assert_eq!(CheckScope::default(), CheckScope::Point);

        assert_eq!(
            serde_json::to_string(&CheckScope::Origin).expect("serializes"),
            "\"origin\""
        );
        assert_eq!(
            serde_json::to_string(&CheckScope::Node).expect("serializes"),
            "\"node\""
        );
        assert_eq!(
            serde_json::from_str::<CheckMeta>(
                &serde_json::to_string(&CheckMeta {
                    scope: CheckScope::Origin,
                    ..meta.clone()
                })
                .expect("serializes")
            )
            .expect("deserializes")
            .scope,
            CheckScope::Origin
        );
    }

    /// Coordinator decision 3 (spec D8.2, AC T3-4): a timing check records
    /// whether the fit actually correlated, and evidence written before T1b
    /// reads as "not correlated" rather than claiming a correlation it never had.
    #[test]
    fn timing_correlated_defaults_false() {
        const WITHOUT: &str = r#"{
            "requested_s": [1.0, 3.0],
            "observed_ms": [1020, 3030],
            "baseline_ms": [18, 19],
            "slope": 1005.0,
            "r": 0.999
        }"#;

        let timing: Timing = serde_json::from_str(WITHOUT).expect("deserializes");
        assert!(!timing.correlated);

        let with: Timing = serde_json::from_str(
            r#"{
            "requested_s": [1.0, 3.0],
            "observed_ms": [1020, 3030],
            "baseline_ms": [18, 19],
            "slope": 1005.0,
            "r": 0.999,
            "correlated": true
        }"#,
        )
        .expect("deserializes");
        assert!(with.correlated);

        let json = serde_json::to_string(&with).expect("serializes");
        assert!(json.contains(r#""correlated":true"#), "{json}");
        assert_eq!(
            serde_json::from_str::<Timing>(&json).expect("round trips"),
            with
        );
    }

    #[test]
    fn l4_oracle_icmp_wire_shape() {
        assert_eq!(
            serde_json::to_string(&L4Oracle::Icmp {
                icmp_type: 3,
                code: 3
            })
            .expect("serializes"),
            r#"{"kind":"icmp","type":3,"code":3}"#
        );
        assert_eq!(
            serde_json::to_string(&L4Oracle::Silence).expect("serializes"),
            r#"{"kind":"silence"}"#
        );
        assert_eq!(
            serde_json::from_str::<L4Oracle>(r#"{"kind":"liveness_failed"}"#)
                .expect("deserializes"),
            L4Oracle::LivenessFailed
        );
    }

    #[test]
    fn l4_evidence_reproduced_is_pair() {
        let evidence = L4Evidence {
            sent_hex: "deadbeef".into(),
            seed_id: "seed-1".into(),
            rng_seed: 42,
            mutation_chain: vec!["len_desync".into()],
            prior_messages: 2,
            oracle: L4Oracle::LivenessFailed,
            liveness_before: true,
            liveness_after: false,
            reproduced: (3, 3),
            scope_entry: "127.0.0.1/32:9000".into(),
        };

        let json = serde_json::to_string(&evidence).expect("serializes");
        assert!(json.contains(r#""reproduced":[3,3]"#), "{json}");

        let back: L4Evidence = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, evidence);
    }

    /// Tester: an unknown `scope` token on a catalogue entry is a parse error,
    /// not a silent fall-back to `point` — the scheduler must never run a check
    /// at the wrong cadence because a script misspelt its scope.
    #[test]
    fn check_meta_with_an_unknown_scope_token_is_an_error() {
        let json = r#"{
            "id": "x", "name": "x", "class": "x",
            "lanes": ["http"], "kinds": ["query"],
            "intensity": "passive", "cost": "light", "technique": "passive",
            "severity": "info", "confidence_max": "tentative",
            "description": "x", "origin": {"kind": "native"},
            "scope": "everywhere"
        }"#;
        let err = serde_json::from_str::<CheckMeta>(json).expect_err("an unknown scope is refused");
        assert!(err.to_string().contains("everywhere"), "{err}");
    }

    /// Amendment 67 (call C5): one shared scrub for both consumers. `detail`
    /// is scrubbed at the root and in every `more` sibling, `evidence.matched`
    /// is scrubbed **then** bounded (amendment 16: the exact 256-byte literal
    /// the bridge test pins — cut first, the scrub would leave 249 bytes), and
    /// the scrub is idempotent so a verdict the bridge scrubbed comes through
    /// the manual path unchanged.
    #[test]
    fn verdict_scrub_covers_detail_evidence_and_siblings() {
        let verdict = Verdict {
            outcome: Outcome::Vulnerable,
            confidence: Confidence::Firm,
            evidence: Evidence {
                payload: Some("q=1&access_token=tok-123".into()),
                matched: Some(format!(
                    "{} Cookie: sid=s3cr3t-cookie; Authorization: Bearer abc.def.ghi",
                    "a".repeat(230)
                )),
                ..Evidence::default()
            },
            detail: "echo: Authorization: Bearer abc.def.ghi".into(),
            poc_hint: None,
            location: None,
            more: vec![Verdict {
                outcome: Outcome::Vulnerable,
                confidence: Confidence::Firm,
                evidence: Evidence {
                    payload: Some("sid=s3cr3t".into()),
                    matched: Some("Cookie: sid=s3cr3t-cookie".into()),
                    ..Evidence::default()
                },
                detail: "sibling Cookie: sid=s3cr3t".into(),
                poc_hint: None,
                location: None,
                more: Vec::new(),
            }],
        };

        let once = verdict.clone().scrubbed();
        assert_eq!(once.detail, "echo: Authorization: [redacted]");
        assert_eq!(
            once.evidence.payload.as_deref(),
            Some("q=1&access_token=[redacted]")
        );
        let matched = once.evidence.matched.as_deref().expect("matched is kept");
        assert_eq!(matched.len(), MAX_EXCERPT_BYTES);
        assert_eq!(
            matched,
            format!("{} Cookie: [redacted]; Autho", "a".repeat(230))
        );
        assert!(!matched.contains("s3cr3t"), "{matched:?}");
        assert_eq!(once.more.len(), 1);
        assert_eq!(once.more[0].detail, "sibling Cookie: [redacted]");
        assert_eq!(
            once.more[0].evidence.matched.as_deref(),
            Some("Cookie: [redacted]")
        );
        assert_eq!(
            once.more[0].evidence.payload.as_deref(),
            Some("sid=[redacted]")
        );
        // Untouched: the scrub is about free text only.
        assert_eq!(once.outcome, Outcome::Vulnerable);
        assert_eq!(once.confidence, Confidence::Firm);

        // In-place form agrees with the by-value form, and twice is once.
        let mut in_place = verdict;
        in_place.scrub();
        assert_eq!(in_place, once);
        in_place.scrub();
        assert_eq!(in_place, once, "scrub is idempotent");
    }

    /// Coordinator item (g) (2026-11-01): the multi-verdict contract is
    /// additive. A verdict written before it carries neither `location` nor
    /// `more` and reads as "no override, no siblings"; a `VerdictLocation`
    /// round-trips its `path` so the engine can place one issue per exposed path.
    #[test]
    fn verdict_more_and_location_default_empty() {
        let json = r#"{
            "outcome": "vulnerable",
            "confidence": "firm",
            "evidence": {},
            "detail": "exposed"
        }"#;
        let verdict: Verdict = serde_json::from_str(json).expect("deserializes");
        assert_eq!(verdict.location, None);
        assert!(verdict.more.is_empty());

        let located = Verdict {
            outcome: Outcome::Vulnerable,
            confidence: Confidence::Firm,
            evidence: Evidence::default(),
            detail: "git metadata exposed".into(),
            poc_hint: None,
            location: Some(VerdictLocation {
                path: Some("/.git/".into()),
                name: None,
            }),
            more: vec![Verdict {
                outcome: Outcome::Vulnerable,
                confidence: Confidence::Firm,
                evidence: Evidence::default(),
                detail: "env file exposed".into(),
                poc_hint: None,
                location: Some(VerdictLocation {
                    path: Some("/.env".into()),
                    name: Some("env".into()),
                }),
                more: Vec::new(),
            }],
        };
        let json = serde_json::to_string(&located).expect("serializes");
        assert!(
            json.contains(r#""location":{"path":"/.git/","name":null}"#),
            "{json}"
        );
        let back: Verdict = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(back, located);
        assert_eq!(
            back.location.as_ref().and_then(|l| l.path.as_deref()),
            Some("/.git/")
        );
        assert_eq!(back.more.len(), 1);
        assert_eq!(
            back.more[0]
                .location
                .as_ref()
                .and_then(|l| l.path.as_deref()),
            Some("/.env")
        );
        assert_eq!(
            VerdictLocation::default(),
            VerdictLocation {
                path: None,
                name: None
            }
        );
    }
}
