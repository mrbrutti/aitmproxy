//! Reproduce + record: turn a confirmed injection into a parameterized PoC
//! (`build_poc`) and persist a `FindingRecord` to the configured findings
//! store (`record_finding`).
//!
//! `build_poc` reuses [`CheckDefinition::success_assertion`] for the PoC's
//! `success` — the exact assertion the live `confirm` judged the hit against —
//! so a recorded PoC and the inject engine's own notion of "triggered" can
//! never drift apart. `record_finding` is a thin wrapper over
//! [`aitm_findings::DiskFindingStore`]: the store itself scrubs `title`/`notes`
//! of credential material before anything reaches disk, and this helper never
//! independently copies a param value or a raw header into either field.

use aitm_core::{CommandHost, HttpFlow};
use aitm_findings::{DiskFindingStore, FindingRecord, FindingStore};
use aitm_poc::{Poc, PocBuilder, PocInfo, PocSpec, Severity, StdPocBuilder, Variable};

use crate::checks::{CheckDefinition, Payload};
use crate::discover::InjectionPoint;

/// Severity assigned to a built PoC, keyed by class. A class with no mapping
/// here (a future `CheckDefinition::for_class` addition) defaults to `Medium`
/// rather than silently under- or over-stating it.
fn severity_for(class: &str) -> Severity {
    match class {
        "reflected-xss" => Severity::High,
        "open-redirect" => Severity::Medium,
        _ => Severity::Medium,
    }
}

/// Build a reproducible PoC for one confirmed `(point, payload)` hit.
///
/// `success` is `def`'s own confirming assertion for `payload` — never
/// re-derived — so the recorded PoC and the live engine's judgement of
/// "triggered" cannot disagree. Declaring the `target` variable up front makes
/// `StdPocBuilder` replace the flow's concrete scheme+authority with
/// `{{target}}` in the step URL, so the PoC reproduces against any host, not
/// just the one it was captured from.
pub fn build_poc(
    flow: &HttpFlow,
    def: &CheckDefinition,
    point: &InjectionPoint,
    payload: &Payload,
) -> anyhow::Result<Poc> {
    let spec = PocSpec {
        info: PocInfo {
            name: format!("{} via {}", def.class, point.name),
            severity: severity_for(def.class),
            references: Vec::new(),
            tags: vec![def.class.to_string()],
            cwe: None,
            description: None,
            author: None,
            metadata: None,
        },
        variables: vec![Variable {
            name: "target".to_string(),
            default: None,
            description: "Base URL of the target".to_string(),
            required: true,
        }],
        success: def.success_assertion(payload),
    };
    StdPocBuilder.build(flow, spec)
}

/// Persist `rec` to the configured findings store, returning its id.
///
/// No `findings.dir` configured is a no-op (`Ok` of an empty id), not a
/// failure — the same deny-by-default posture [`crate::report::load_records`]
/// takes when there is nothing configured to read: a scan that never wired a
/// findings store simply records nothing. This helper never touches
/// `rec.title`/`rec.notes` itself; [`DiskFindingStore::record`] scrubs them of
/// credential material at the persistence boundary regardless of what the
/// caller put there.
pub fn record_finding(host: &CommandHost<'_>, rec: FindingRecord) -> anyhow::Result<String> {
    let Some(dir) = host.config().and_then(|c| c.findings.dir.clone()) else {
        return Ok(String::new());
    };
    DiskFindingStore::new(dir).record(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, Config, ConnInfo, FindingsConfig, FlowId, FlowMeta, Frontend, HeaderMap, HttpFlow,
        HttpRequest, HttpVersion, InterceptState, MemFlowStore, ProxyClient, StdGuard,
    };
    use aitm_findings::{FindingArtifacts, Reproduction};
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::discover::Location;

    /// A `ProxyClient` these helpers must never reach: building/recording a PoC
    /// issues no traffic.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("reproduce:: helpers must not send through the proxy client: {req:?}");
        }
    }

    /// A scratch directory, removed when dropped.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("aitm-scanner-reproduce-{}", FlowId::new()));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn flow_with_query(path: &str) -> HttpFlow {
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: "GET".into(),
                scheme: "http".into(),
                authority: "target.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers: HeaderMap::new(),
                body: Body::Empty,
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    /// Run `f` against a host wired with the given config (or none at all).
    fn with_host<R>(config: Option<Config>, f: impl FnOnce(&CommandHost<'_>) -> R) -> R {
        let store = MemFlowStore::new();
        let client = NoSendClient;
        let guard = StdGuard::default();
        let mut host = CommandHost::new(&store, &client, &guard, None);
        if let Some(config) = config {
            host = host.with_config(Arc::new(config));
        }
        f(&host)
    }

    fn config_with_dir(dir: &Path) -> Config {
        Config {
            findings: FindingsConfig {
                dir: Some(dir.to_path_buf()),
            },
            ..Config::default()
        }
    }

    fn base_record(id: &str) -> FindingRecord {
        FindingRecord {
            id: id.to_string(),
            title: "Reflected XSS in q".to_string(),
            class: "reflected-xss".to_string(),
            severity: Severity::High,
            target: "http://target.test/".to_string(),
            discovered_at: SystemTime::now(),
            origin: Frontend::Mcp,
            client_label: None,
            poc_ref: "reflected-xss-q".to_string(),
            reproduction: Reproduction {
                passed: true,
                control_passed: Some(false),
                run_at: SystemTime::now(),
            },
            artifacts: FindingArtifacts {
                finding_capture: FlowId::new(),
                poc_path: "poc.yaml".to_string(),
                screenshot_path: String::new(),
            },
            flows: Vec::new(),
            notes: None,
        }
    }

    #[test]
    fn build_poc_sets_success_assertion() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello");
        let point = InjectionPoint {
            flow: flow.id,
            location: Location::Query,
            name: "q".to_string(),
            example: "hello".to_string(),
        };

        let poc = build_poc(&flow, &def, &point, payload).expect("poc builds");

        assert_eq!(
            poc.success,
            def.success_assertion(payload),
            "the recorded PoC must assert exactly what `confirm` judged the hit against"
        );

        let aitm_poc::Step::Http(step) = &poc.steps[0] else {
            panic!("the PoC carries one http step: {:?}", poc.steps);
        };
        assert!(
            step.url.contains("{{target}}"),
            "the step URL must be parameterized to {{target}}: {}",
            step.url
        );

        // Round-trips via `aitm_poc`'s own serde: the crate's custom
        // `Step`/`Assertion` impls build a generic serde-data-model tree, not
        // raw YAML text, so `serde_json` (already a dependency here) exercises
        // the same code path without a new one.
        let json = serde_json::to_string(&poc).expect("poc serializes");
        let back: Poc = serde_json::from_str(&json).expect("poc deserializes");
        assert_eq!(back.success, poc.success);
    }

    #[test]
    fn record_round_trips() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let rec = base_record("reflected-xss-abc123de");

        let id = with_host(Some(config), |host| record_finding(host, rec.clone()))
            .expect("record_finding succeeds");
        assert_eq!(id, "reflected-xss-abc123de");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert!(stored.reproduction.passed);
        assert_eq!(stored.reproduction.control_passed, Some(false));
    }

    /// A careless caller might copy a source flow's raw `Authorization` header
    /// into free text; the store must still scrub it before it reaches disk.
    #[test]
    fn record_redacts_secret() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let mut rec = base_record("reflected-xss-secrettest");
        rec.title = "Authorization: Bearer abc123".to_string();
        rec.notes = Some("replayed request carried Authorization: Bearer abc123".to_string());

        let id =
            with_host(Some(config), |host| record_finding(host, rec)).expect("record succeeds");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert!(
            !stored.title.contains("abc123"),
            "title leaked the secret: {}",
            stored.title
        );
        assert!(
            !stored.notes.unwrap_or_default().contains("abc123"),
            "notes leaked the secret"
        );
    }
}
