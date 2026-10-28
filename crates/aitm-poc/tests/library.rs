//! F13: poc.list / poc.get / poc.artifact over the configured PoC directories.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    CommandHost, Config, HttpFlow, HttpRequest, MemFlowStore, Params, PocConfig, ProxyClient,
    Registry, StdGuard, Value,
};
use futures::future::BoxFuture;

const FIXTURE: &str = include_str!("fixtures/reflected-xss-search-q.yaml");

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
    let dir =
        std::env::temp_dir().join(format!("aitm-lib-{tag}-{}-{nanos}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn reg() -> Registry {
    let mut reg = Registry::new();
    aitm_poc::library::register(&mut reg);
    reg
}

fn call(reg: &Registry, cfg: Config, name: &str, args: &[(&str, Value)]) -> anyhow::Result<Value> {
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let client = StubClient;
    let host = CommandHost::new(&store, &client, &guard, None).with_config(Arc::new(cfg));
    let params = Params::new(
        args.iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    );
    reg.command(name)
        .unwrap_or_else(|| panic!("{name} registered"))
        .invoke(params, &host)
}

fn cfg_with(dir: Option<PathBuf>, out_dir: Option<PathBuf>) -> Config {
    Config {
        poc: PocConfig { dir, out_dir },
        ..Config::default()
    }
}

fn arr(v: Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a,
        other => panic!("expected array, got {other:?}"),
    }
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    match v {
        Value::Object(o) => o.get(k).unwrap_or_else(|| panic!("missing {k}: {o:?}")),
        other => panic!("not an object: {other:?}"),
    }
}

#[test]
fn poc_list_enumerates_valid_yaml_only() {
    let lib = unique_dir("list");
    write(&lib, "a.yaml", FIXTURE);
    write(&lib, "b.yml", FIXTURE);
    write(&lib, "notes.txt", FIXTURE); // not a .yaml extension -> skipped
    write(&lib, "broken.yaml", "this: [is, not, valid"); // unparseable -> skipped

    let out = call(&reg(), cfg_with(Some(lib), None), "poc.list", &[]).expect("poc.list ok");
    let items = arr(out);
    assert_eq!(
        items.len(),
        2,
        "only the two valid PoC files are listed: {items:?}"
    );
    for item in &items {
        assert_eq!(
            field(item, "id"),
            &Value::Str("reflected-xss-search-q".into())
        );
        assert_eq!(field(item, "severity"), &Value::Str("high".into()));
    }
}

#[test]
fn poc_list_empty_when_no_dir_configured() {
    let out = call(&reg(), cfg_with(None, None), "poc.list", &[]).expect("poc.list ok");
    assert_eq!(out, Value::Array(vec![]));
}

#[test]
fn poc_get_reads_parses_and_confines() {
    let lib = unique_dir("get");
    let path = write(&lib, "p.yaml", FIXTURE);

    let got = call(
        &reg(),
        cfg_with(Some(lib.clone()), None),
        "poc.get",
        &[("poc_path", Value::Str(path.display().to_string()))],
    )
    .expect("poc.get ok");
    assert_eq!(
        field(&got, "id"),
        &Value::Str("reflected-xss-search-q".into())
    );
    assert_eq!(field(&got, "severity"), &Value::Str("high".into()));
    assert_eq!(field(&got, "yaml"), &Value::Str(FIXTURE.to_string()));

    // A path outside the configured dir is refused.
    let outside = unique_dir("get-outside");
    let other = write(&outside, "evil.yaml", FIXTURE);
    let err = call(
        &reg(),
        cfg_with(Some(lib), None),
        "poc.get",
        &[("poc_path", Value::Str(other.display().to_string()))],
    )
    .expect_err("a path outside the PoC dir must be refused");
    assert!(err.to_string().contains("outside"), "{err}");
}

#[test]
fn poc_get_requires_configured_dir() {
    let err = call(
        &reg(),
        cfg_with(None, None),
        "poc.get",
        &[("poc_path", Value::Str("/tmp/x.yaml".into()))],
    )
    .expect_err("poc.get needs a configured dir");
    assert!(err.to_string().contains("PoC directory"), "{err}");
}

#[test]
fn poc_artifact_reads_confined_bytes() {
    let out_dir = unique_dir("art");
    let png = b"\x89PNG\r\n\x1a\nfake-screenshot".to_vec();
    let art = out_dir.join("screenshot.png");
    std::fs::write(&art, &png).unwrap();

    let got = call(
        &reg(),
        cfg_with(None, Some(out_dir.clone())),
        "poc.artifact",
        &[("path", Value::Str(art.display().to_string()))],
    )
    .expect("poc.artifact ok");
    assert_eq!(got, Value::Bytes(png));

    // A traversal outside the out-dir is refused.
    let outside = unique_dir("art-outside");
    let secret = outside.join("secret.bin");
    std::fs::write(&secret, b"top secret").unwrap();
    let err = call(
        &reg(),
        cfg_with(None, Some(out_dir)),
        "poc.artifact",
        &[("path", Value::Str(secret.display().to_string()))],
    )
    .expect_err("a path outside the out-dir must be refused");
    assert!(err.to_string().contains("outside"), "{err}");
}

#[test]
fn poc_artifact_requires_out_dir() {
    let err = call(
        &reg(),
        cfg_with(None, None),
        "poc.artifact",
        &[("path", Value::Str("/tmp/x.png".into()))],
    )
    .expect_err("poc.artifact needs a configured out-dir");
    assert!(err.to_string().contains("output directory"), "{err}");
}
