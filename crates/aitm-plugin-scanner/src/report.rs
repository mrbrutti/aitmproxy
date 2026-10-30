//! `scan.report` read helper: load the recorded findings for `scan.report` to
//! render, and convert `aitm_findings::render_index`'s `serde_json::Value`
//! into the transport-neutral `aitm_core::Value` the command bus carries.

use aitm_core::CommandHost;
use aitm_findings::{DiskFindingStore, FindingFilter, FindingRecord, FindingStore};

/// Load every recorded finding, optionally filtered to `target`. Returns an
/// **empty** vec (not an error) when no `findings.dir` is configured — the
/// deny-by-default posture: `scan.report` with no findings store wired has
/// nothing to show, not a failure. A listed finding whose record cannot be read
/// or parsed is silently skipped; surfacing that count difference is the job of
/// `scan.report`, not of this helper.
pub fn load_records(host: &CommandHost<'_>, target: Option<&str>) -> Vec<FindingRecord> {
    let Some(dir) = host.config().and_then(|c| c.findings.dir.clone()) else {
        return Vec::new();
    };
    let store = DiskFindingStore::new(dir);
    let filter = FindingFilter {
        target: target.map(str::to_string),
        ..FindingFilter::default()
    };
    store
        .list(&filter)
        .iter()
        .filter_map(|summary| store.get(&summary.id))
        .collect()
}

/// Convert a `serde_json::Value` (as `aitm_findings::render_index` returns)
/// into the transport-neutral `aitm_core::Value`.
pub fn index_to_value(index: serde_json::Value) -> aitm_core::Value {
    match index {
        serde_json::Value::Null => aitm_core::Value::Null,
        serde_json::Value::Bool(b) => aitm_core::Value::Bool(b),
        // An integer stays an `Int`, any other number is a `Float`, and a number
        // with neither form is `Null` — a value is never invented.
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(aitm_core::Value::Int)
            .or_else(|| n.as_f64().map(aitm_core::Value::Float))
            .unwrap_or(aitm_core::Value::Null),
        serde_json::Value::String(s) => aitm_core::Value::Str(s),
        serde_json::Value::Array(items) => {
            aitm_core::Value::Array(items.into_iter().map(index_to_value).collect())
        }
        serde_json::Value::Object(map) => aitm_core::Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, index_to_value(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Config, FindingsConfig, FlowId, Frontend, HttpFlow, HttpRequest, MemFlowStore, ProxyClient,
        StdGuard, Value,
    };
    use aitm_findings::{FindingArtifacts, Reproduction};
    use aitm_poc::Severity;
    use futures::future::BoxFuture;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::SystemTime;

    /// A `ProxyClient` the read-only helper must never reach.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("report::load_records must not send through the proxy client: {req:?}");
        }
    }

    /// A scratch directory, removed when dropped.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("aitm-scanner-report-{}", FlowId::new()));
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

    /// Run `f` against a host with the given config (or none at all).
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

    fn config_with_findings_dir(dir: Option<PathBuf>) -> Config {
        Config {
            findings: FindingsConfig { dir },
            ..Config::default()
        }
    }

    fn record(id: &str, target: &str) -> FindingRecord {
        FindingRecord {
            id: id.to_string(),
            title: "reflected value".to_string(),
            class: "reflection".to_string(),
            severity: Severity::Low,
            target: target.to_string(),
            discovered_at: SystemTime::now(),
            origin: Frontend::Cli,
            client_label: None,
            poc_ref: "reflection-poc".to_string(),
            reproduction: Reproduction {
                passed: true,
                control_passed: Some(false),
                run_at: SystemTime::now(),
            },
            artifacts: FindingArtifacts {
                finding_capture: FlowId::new(),
                poc_path: "poc.yaml".to_string(),
                screenshot_path: "shot.png".to_string(),
            },
            flows: Vec::new(),
            notes: None,
        }
    }

    #[test]
    fn load_records_empty_without_dir() {
        // No config wired at all, and a config whose `findings.dir` is unset.
        for config in [None, Some(config_with_findings_dir(None))] {
            let wired = config.is_some();

            let records = with_host(config, |host| load_records(host, None));

            assert!(
                records.is_empty(),
                "no findings.dir (config wired: {wired}) must yield no records: {records:?}"
            );
        }
    }

    #[test]
    fn load_records_filters_by_target() {
        let dir = ScratchDir::new();
        let store = DiskFindingStore::new(dir.path());
        store
            .record(record("finding-a", "http://a.test"))
            .expect("record a");
        store
            .record(record("finding-b", "http://b.test"))
            .expect("record b");
        let config = config_with_findings_dir(Some(dir.path().to_path_buf()));

        with_host(Some(config), |host| {
            let mut all: Vec<String> = load_records(host, None).into_iter().map(|r| r.id).collect();
            all.sort();
            assert_eq!(
                all,
                vec!["finding-a", "finding-b"],
                "no filter returns both"
            );

            let only_a = load_records(host, Some("http://a.test"));
            assert_eq!(
                only_a.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                vec!["finding-a"],
                "the target filter returns only the matching record"
            );
            assert_eq!(only_a[0].target, "http://a.test");

            let none = load_records(host, Some("http://c.test"));
            assert!(
                none.is_empty(),
                "an unmatched target yields nothing: {none:?}"
            );
        });
    }

    #[test]
    fn index_to_value_maps_every_variant() {
        assert_eq!(index_to_value(json!(null)), Value::Null);
        assert_eq!(index_to_value(json!(true)), Value::Bool(true));
        assert_eq!(index_to_value(json!(false)), Value::Bool(false));
        assert_eq!(index_to_value(json!(42)), Value::Int(42));
        assert_eq!(index_to_value(json!(-7)), Value::Int(-7));
        assert_eq!(index_to_value(json!(i64::MIN)), Value::Int(i64::MIN));
        assert_eq!(index_to_value(json!(1.5)), Value::Float(1.5));
        assert_eq!(index_to_value(json!(-0.25)), Value::Float(-0.25));
        assert_eq!(index_to_value(json!("x")), Value::Str("x".to_string()));
    }

    #[test]
    fn index_to_value_maps_nested_containers() {
        let index = json!({
            "findings": [
                {"class": "reflection", "passed": true, "score": -3, "ratio": 0.5},
                null,
                [1, "two"]
            ],
            "meta": {"count": 2, "next": null}
        });

        let value = index_to_value(index);

        let expected = Value::Object(
            [
                (
                    "findings".to_string(),
                    Value::Array(vec![
                        Value::Object(
                            [
                                ("class".to_string(), Value::Str("reflection".to_string())),
                                ("passed".to_string(), Value::Bool(true)),
                                ("score".to_string(), Value::Int(-3)),
                                ("ratio".to_string(), Value::Float(0.5)),
                            ]
                            .into_iter()
                            .collect(),
                        ),
                        Value::Null,
                        Value::Array(vec![Value::Int(1), Value::Str("two".to_string())]),
                    ]),
                ),
                (
                    "meta".to_string(),
                    Value::Object(
                        [
                            ("count".to_string(), Value::Int(2)),
                            ("next".to_string(), Value::Null),
                        ]
                        .into_iter()
                        .collect(),
                    ),
                ),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(value, expected);
    }
}
