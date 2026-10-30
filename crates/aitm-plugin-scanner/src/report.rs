//! `scan.report` read helper: load the recorded findings for `scan.report` to
//! render, and convert `aitm_findings::render_index`'s `serde_json::Value`
//! into the transport-neutral `aitm_core::Value` the command bus carries.

use aitm_core::CommandHost;
use aitm_findings::{DiskFindingStore, FindingFilter, FindingRecord, FindingStore};

/// Load every recorded finding, optionally filtered to `target`. Returns an
/// **empty** vec (not an error) when no `findings.dir` is configured — the
/// deny-by-default posture: `scan.report` with no findings store wired has
/// nothing to show, not a failure.
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
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(aitm_core::Value::Int)
            .unwrap_or_else(|| aitm_core::Value::Float(n.as_f64().unwrap_or(0.0))),
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
    use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, StdGuard};
    use futures::future::BoxFuture;

    /// A `ProxyClient` the read-only helper must never reach.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("report::load_records must not send through the proxy client: {req:?}");
        }
    }

    fn host_with_no_config<'a>(
        store: &'a MemFlowStore,
        client: &'a NoSendClient,
        guard: &'a StdGuard,
    ) -> CommandHost<'a> {
        CommandHost::new(store, client, guard, None)
    }

    #[test]
    fn load_records_empty_without_dir() {
        let store = MemFlowStore::new();
        let client = NoSendClient;
        let guard = StdGuard::default();
        let host = host_with_no_config(&store, &client, &guard);
        assert!(host.config().is_none(), "fixture host has no config wired");

        let records = load_records(&host, None);

        assert!(records.is_empty(), "expected no records: {records:?}");
    }

    #[test]
    fn index_to_value_round_trips() {
        let index = serde_json::json!([{"class": "x", "passed": true}]);

        let value = index_to_value(index);

        let aitm_core::Value::Array(items) = value else {
            panic!("expected an Array, got {value:?}");
        };
        assert_eq!(items.len(), 1);
        let aitm_core::Value::Object(obj) = &items[0] else {
            panic!("expected an Object entry, got {:?}", items[0]);
        };
        assert_eq!(
            obj.get("class"),
            Some(&aitm_core::Value::Str("x".to_string()))
        );
        assert_eq!(obj.get("passed"), Some(&aitm_core::Value::Bool(true)));
    }
}
