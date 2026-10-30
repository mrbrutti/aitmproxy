//! Task 10: the persistent findings store and the `findings.*` commands.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aitm_core::{
    CommandHost, Config, FindingsConfig, FlowId, Frontend, HttpFlow, HttpRequest, MemFlowStore,
    Params, PocConfig, ProxyClient, Registry, Sensitivity, StdGuard, Value,
};
use aitm_findings::{
    DiskFindingStore, FindingArtifacts, FindingFilter, FindingRecord, FindingStore, FindingsPlugin,
    Reproduction,
};
use aitm_poc::Severity;
use futures::future::BoxFuture;

const POC_FIXTURE: &str = include_str!("fixtures/reflected-xss-search-q.yaml");

struct StubClient;
impl ProxyClient for StubClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "aitm-find-{tag}-{}-{nanos}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

/// A record with whole-second timestamps (so it round-trips exactly through RFC 3339)
/// and no secret-bearing free text.
fn sample_record() -> FindingRecord {
    FindingRecord {
        id: String::new(),
        title: "Reflected XSS in search q".into(),
        class: "reflected-xss".into(),
        severity: Severity::High,
        target: "http://localhost:9000/search".into(),
        discovered_at: at(1_700_000_000),
        origin: Frontend::Mcp,
        client_label: Some("aitm-mac".into()),
        poc_ref: "reflected-xss-search-q".into(),
        reproduction: Reproduction {
            passed: true,
            control_passed: Some(false),
            run_at: at(1_700_000_001),
        },
        artifacts: FindingArtifacts {
            finding_capture: FlowId::new(),
            poc_path: "/poc/reflected-xss-search-q.yaml".into(),
            screenshot_path: "/out/xss.png".into(),
        },
        flows: vec![FlowId::new(), FlowId::new()],
        notes: Some("the q parameter is reflected unescaped".into()),
    }
}

#[test]
fn record_then_get_and_list() {
    let dir = unique_dir("rec");
    let store = DiskFindingStore::new(dir.clone());

    let rec = sample_record();
    let id = store.record(rec.clone()).expect("record");
    assert!(!id.is_empty(), "an id is assigned");

    let mut expected = rec;
    expected.id = id.clone();
    let got = store.get(&id).expect("get round-trips");
    assert_eq!(got, expected, "get returns exactly what was recorded");

    // Each filter field matches.
    let by_target = store.list(&FindingFilter {
        target: Some(expected.target.clone()),
        ..Default::default()
    });
    assert_eq!(by_target.len(), 1);
    assert_eq!(by_target[0].id, id);
    assert_eq!(
        store
            .list(&FindingFilter {
                class: Some("reflected-xss".into()),
                ..Default::default()
            })
            .len(),
        1
    );
    assert_eq!(
        store
            .list(&FindingFilter {
                severity: Some(Severity::High),
                ..Default::default()
            })
            .len(),
        1
    );
    assert_eq!(
        store
            .list(&FindingFilter {
                since: Some(at(1_700_000_000)),
                ..Default::default()
            })
            .len(),
        1
    );

    // Non-matching filters exclude it.
    assert_eq!(
        store
            .list(&FindingFilter {
                target: Some("http://other".into()),
                ..Default::default()
            })
            .len(),
        0
    );
    assert_eq!(
        store
            .list(&FindingFilter {
                severity: Some(Severity::Low),
                ..Default::default()
            })
            .len(),
        0
    );
    assert_eq!(
        store
            .list(&FindingFilter {
                since: Some(at(1_700_000_100)),
                ..Default::default()
            })
            .len(),
        0
    );
}

#[test]
fn findings_persist_across_restart() {
    let dir = unique_dir("persist");
    let id = {
        let store = DiskFindingStore::new(dir.clone());
        store.record(sample_record()).expect("record")
    };

    // A brand-new store over the same directory sees the finding.
    let reopened = DiskFindingStore::new(dir.clone());
    let got = reopened.get(&id).expect("persisted finding is readable");
    assert_eq!(got.id, id);
    assert_eq!(got.class, "reflected-xss");
    assert_eq!(reopened.list(&FindingFilter::default()).len(), 1);
}

#[test]
fn finding_record_has_no_secrets() {
    // RF#3: a token/credential in a finding's free text must not reach disk.
    let dir = unique_dir("secrets");
    let store = DiskFindingStore::new(dir.clone());

    let mut rec = sample_record();
    rec.notes = Some(
        "repro: send Authorization: Bearer sk-9f8a7b6c5d4e, then token=sk-9f8a7b6c5d4e".into(),
    );
    rec.title = "token=sk-9f8a7b6c5d4e leaked".into();
    let id = store.record(rec).expect("record");

    let yaml = std::fs::read_to_string(dir.join(format!("{id}.yaml"))).expect("yaml on disk");
    assert!(
        !yaml.contains("sk-9f8a7b6c5d4e"),
        "the YAML record leaked a secret:\n{yaml}"
    );
    assert!(
        yaml.contains("[redacted]"),
        "redaction marker present:\n{yaml}"
    );

    let runs = std::fs::read_to_string(dir.join("runs.jsonl")).expect("runs.jsonl on disk");
    assert!(
        !runs.contains("sk-9f8a7b6c5d4e"),
        "runs.jsonl leaked a secret:\n{runs}"
    );

    let got = store.get(&id).expect("get");
    assert!(!got.notes.unwrap().contains("sk-9f8a7b6c5d4e"));
    assert!(!got.title.contains("sk-9f8a7b6c5d4e"));
}

#[test]
fn remove_deletes_yaml_keeps_runs() {
    let dir = unique_dir("remove");
    let store = DiskFindingStore::new(dir.clone());
    let id = store.record(sample_record()).expect("record");

    assert!(dir.join(format!("{id}.yaml")).exists());
    store.remove(&id).expect("remove");
    assert!(!dir.join(format!("{id}.yaml")).exists(), "yaml deleted");
    assert!(dir.join("runs.jsonl").exists(), "runs history kept");
    assert!(store.get(&id).is_none());

    // Idempotent: removing an absent finding succeeds.
    store.remove(&id).expect("idempotent remove");
    // A traversal id is refused.
    assert!(store.remove("../escape").is_err());
    assert!(store.get("../escape").is_none());
}

// ---- command-level tests ----

fn findings_reg() -> Registry {
    let mut reg = Registry::new();
    FindingsPlugin::register(&mut reg);
    reg
}

fn cfg_with_findings(dir: PathBuf) -> Config {
    Config {
        findings: FindingsConfig { dir: Some(dir) },
        ..Config::default()
    }
}

fn call_as(
    reg: &Registry,
    cfg: &Config,
    frontend: Frontend,
    name: &str,
    args: &[(&str, Value)],
) -> anyhow::Result<Value> {
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None)
        .with_config(Arc::new(cfg.clone()))
        .with_frontend(frontend);
    let params = Params::new(
        args.iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    );
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(params, &host)
}

fn record_id(v: &Value) -> String {
    match v {
        Value::Object(o) => match o.get("id") {
            Some(Value::Str(s)) => s.clone(),
            other => panic!("no id: {other:?}"),
        },
        other => panic!("not an object: {other:?}"),
    }
}

#[test]
fn findings_record_is_policy_gated() {
    let reg = findings_reg();

    // Declared sensitivities drive the D2 policy gate (enforced in call_tool).
    assert_eq!(
        reg.command("findings.list").unwrap().sensitivity(),
        Sensitivity::Read
    );
    assert_eq!(
        reg.command("findings.get").unwrap().sensitivity(),
        Sensitivity::Read
    );
    assert_eq!(
        reg.command("findings.record").unwrap().sensitivity(),
        Sensitivity::Write
    );
    assert_eq!(
        reg.command("findings.remove").unwrap().sensitivity(),
        Sensitivity::Sensitive
    );

    let dir = unique_dir("gate");
    let cfg = cfg_with_findings(dir);

    // An operator can record and remove.
    let rec = call_as(
        &reg,
        &cfg,
        Frontend::Operator,
        "findings.record",
        &[
            ("title", Value::Str("IDOR on /account".into())),
            ("class", Value::Str("idor".into())),
            ("severity", Value::Str("high".into())),
            (
                "target",
                Value::Str("http://localhost:9000/account/2".into()),
            ),
            ("poc_ref", Value::Str("idor-account".into())),
        ],
    )
    .expect("operator record");
    let id = record_id(&rec);

    // The agent (Mcp) role is refused `findings.remove` outright (operator/CLI-only).
    let err = call_as(
        &reg,
        &cfg,
        Frontend::Mcp,
        "findings.remove",
        &[("id", Value::Str(id.clone()))],
    )
    .expect_err("agent cannot remove");
    assert!(
        err.to_string().contains("operator/CLI-only"),
        "wrong error: {err}"
    );

    // The operator can.
    call_as(
        &reg,
        &cfg,
        Frontend::Operator,
        "findings.remove",
        &[("id", Value::Str(id))],
    )
    .expect("operator remove");
}

#[test]
fn record_command_roundtrips_through_list_and_get() {
    let reg = findings_reg();
    let dir = unique_dir("cmd");
    let cfg = cfg_with_findings(dir);

    let rec = call_as(
        &reg,
        &cfg,
        Frontend::Mcp,
        "findings.record",
        &[
            ("title", Value::Str("SSRF in fetch".into())),
            ("class", Value::Str("ssrf".into())),
            ("severity", Value::Str("critical".into())),
            ("target", Value::Str("http://localhost:9000/fetch".into())),
            ("poc_ref", Value::Str("ssrf-fetch".into())),
            ("passed", Value::Bool(true)),
            ("control_passed", Value::Bool(false)),
        ],
    )
    .expect("record");
    let id = record_id(&rec);

    let list = call_as(&reg, &cfg, Frontend::Mcp, "findings.list", &[]).expect("list");
    let Value::Array(items) = list else {
        panic!("list not array")
    };
    assert_eq!(items.len(), 1);

    let got = call_as(
        &reg,
        &cfg,
        Frontend::Mcp,
        "findings.get",
        &[("id", Value::Str(id.clone()))],
    )
    .expect("get");
    let Value::Object(o) = got else {
        panic!("get not object")
    };
    assert_eq!(o.get("class"), Some(&Value::Str("ssrf".into())));
    assert_eq!(o.get("severity"), Some(&Value::Str("critical".into())));
    let Some(Value::Object(repro)) = o.get("reproduction") else {
        panic!("no reproduction")
    };
    assert_eq!(repro.get("passed"), Some(&Value::Bool(true)));
    assert_eq!(repro.get("control_passed"), Some(&Value::Bool(false)));
}

#[test]
fn findings_distinct_from_poc_library() {
    // The findings store (history/results) is a different set from the PoC library.
    let mut reg = Registry::new();
    aitm_poc::library::register(&mut reg);
    FindingsPlugin::register(&mut reg);

    let poc_dir = unique_dir("poc-lib");
    std::fs::write(poc_dir.join("reflected-xss-search-q.yaml"), POC_FIXTURE).unwrap();
    let find_dir = unique_dir("find-lib");

    let cfg = Config {
        poc: PocConfig {
            dir: Some(poc_dir),
            out_dir: None,
            ..Default::default()
        },
        findings: FindingsConfig {
            dir: Some(find_dir),
        },
        ..Config::default()
    };

    // One recorded finding, of a different class/id than the library PoC.
    call_as(
        &reg,
        &cfg,
        Frontend::Operator,
        "findings.record",
        &[
            ("title", Value::Str("Open redirect".into())),
            ("class", Value::Str("open-redirect".into())),
            ("severity", Value::Str("medium".into())),
            (
                "target",
                Value::Str("http://localhost:9000/redirect".into()),
            ),
            ("poc_ref", Value::Str("open-redirect-next".into())),
        ],
    )
    .expect("record");

    let ids = |v: Value| -> Vec<String> {
        let Value::Array(items) = v else {
            panic!("not array")
        };
        items
            .iter()
            .map(|it| match it {
                Value::Object(o) => match o.get("id") {
                    Some(Value::Str(s)) => s.clone(),
                    _ => panic!("no id"),
                },
                _ => panic!("not object"),
            })
            .collect()
    };

    let poc_ids = ids(call_as(&reg, &cfg, Frontend::Mcp, "poc.list", &[]).expect("poc.list"));
    let find_ids =
        ids(call_as(&reg, &cfg, Frontend::Mcp, "findings.list", &[]).expect("findings.list"));

    assert_eq!(poc_ids, vec!["reflected-xss-search-q".to_string()]);
    assert_eq!(find_ids.len(), 1);
    assert!(
        find_ids[0].starts_with("open-redirect-"),
        "finding id derived from class: {}",
        find_ids[0]
    );
    // Disjoint sets.
    for p in &poc_ids {
        assert!(!find_ids.contains(p), "poc id {p} leaked into findings");
    }
}
