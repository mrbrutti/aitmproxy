//! M2 Task 21 (CA-AC27): the assembly exposes the CA it built, the `ca.*`
//! family is reachable through the CLI, the env bridge flips
//! `ca.allow_agent_install`, and the CLI renderer prints values the way an
//! operator reads them.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use aitm::render::render_cli_value;
use aitm::wire::assemble;
use aitm::{env, wire};
use aitm_core::{Config, HttpFlow, HttpRequest, ProxyClient, Value};
use futures::future::BoxFuture;
use serde_json::Value as JsonValue;

const ENV_KEY: &str = "AITM_CA_ALLOW_AGENT_INSTALL";

fn temp_ca_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("aitm-wire-m2-{tag}-{nanos}-{n}"))
}

fn config(tag: &str) -> Config {
    let mut cfg = Config::default();
    cfg.ca.dir = temp_ca_dir(tag);
    cfg
}

/// A `ProxyClient` no `ca.*` command calls.
struct UnusedClient;

impl ProxyClient for UnusedClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async { anyhow::bail!("not called") })
    }
}

fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    match v {
        Value::Object(fields) => fields
            .get(name)
            .unwrap_or_else(|| panic!("no field {name} in {fields:?}")),
        other => panic!("not an object: {other:?}"),
    }
}

// CA-AC27: assemble() hands back the CertAuthority the HTTP module uses, and
// ca.status over the CLI sees the certificate it wrote.
#[test]
fn assemble_exposes_ca_and_status_sees_it() {
    let cfg = config("status");
    let assembled = assemble(&cfg).expect("assemble");

    let cert_path = assembled.ca.cert_path().to_path_buf();
    assert_eq!(cert_path, cfg.ca.dir.join("ca.crt"));
    assert!(cert_path.exists(), "{} must exist", cert_path.display());

    let proxy = assembled.proxy;
    let client: Arc<dyn ProxyClient> = Arc::new(UnusedClient);
    let cli = aitm_cli::Cli::new(proxy.registry_arc()).with_services(
        proxy.store(),
        client,
        proxy.guard(),
        None,
    );
    let status = cli
        .dispatch(&["ca".to_string(), "status".to_string()])
        .expect("ca status");
    assert_eq!(field(&status, "exists"), &Value::Bool(true));
    assert_eq!(
        field(&status, "path"),
        &Value::Str(cert_path.display().to_string())
    );
    assert_eq!(
        field(&status, "dir"),
        &Value::Str(cfg.ca.dir.display().to_string())
    );
}

// The default feature set and build_proxy_with both register the four ca.*
// commands (every build_proxy caller sees them).
#[test]
fn every_build_registers_the_ca_family() {
    let cfg = config("family");
    let proxy = wire::build_proxy(&cfg).expect("build_proxy");
    for name in ["ca.export", "ca.status", "ca.install", "ca.uninstall"] {
        assert!(
            proxy.registry().command(name).is_some(),
            "{name} must be registered by build_proxy"
        );
    }
    let features = wire::Features {
        mutate: false,
        ..wire::Features::default()
    };
    let proxy = wire::build_proxy_with(&cfg, &features).expect("build_proxy_with");
    assert!(proxy.registry().command("ca.status").is_some());
    assert!(proxy.registry().command("flow.mutate").is_none());
}

fn apply_env(cfg: &mut Config, value: Option<&str>) {
    let value = value.map(str::to_string);
    env::apply(cfg, |key| if key == ENV_KEY { value.clone() } else { None });
}

// CA-AC27: AITM_CA_ALLOW_AGENT_INSTALL in 1/true/YES → true; 0 (or anything
// else) → false; unset → unchanged.
#[test]
fn env_apply_matrix() {
    for truthy in ["1", "true", "YES", "True", "yes"] {
        let mut cfg = Config::default();
        assert!(!cfg.ca.allow_agent_install, "default must be off");
        apply_env(&mut cfg, Some(truthy));
        assert!(cfg.ca.allow_agent_install, "{truthy:?} must enable");
    }
    for falsy in ["0", "false", "no", "", "maybe"] {
        let mut cfg = Config::default();
        cfg.ca.allow_agent_install = true;
        apply_env(&mut cfg, Some(falsy));
        assert!(!cfg.ca.allow_agent_install, "{falsy:?} must disable");
    }
    // Unset leaves whatever the config file said.
    for initial in [false, true] {
        let mut cfg = Config::default();
        cfg.ca.allow_agent_install = initial;
        apply_env(&mut cfg, None);
        assert_eq!(cfg.ca.allow_agent_install, initial);
    }
    // The bridge touches nothing else.
    let mut cfg = Config::default();
    let dir_before = cfg.ca.dir.clone();
    let audit_before = cfg.ca.audit_log.clone();
    apply_env(&mut cfg, Some("1"));
    assert_eq!(cfg.ca.dir, dir_before);
    assert_eq!(cfg.ca.audit_log, audit_before);
}

// CA-AC27: Str → the string and a newline; Bytes → raw; else pretty JSON.
#[test]
fn render_cli_value_cases() {
    assert_eq!(render_cli_value(&Value::Str("x".into())), b"x\n");
    assert_eq!(
        render_cli_value(&Value::Str("two\nlines".into())),
        b"two\nlines\n"
    );

    let raw = vec![0u8, 1, 2, 0xff, b'\n', 0x89];
    assert_eq!(render_cli_value(&Value::Bytes(raw.clone())), raw);
    assert_eq!(render_cli_value(&Value::Bytes(Vec::new())), b"");

    let mut inner = BTreeMap::new();
    inner.insert("installed".to_string(), Value::Str("absent".into()));
    let mut fields = BTreeMap::new();
    fields.insert("exists".to_string(), Value::Bool(true));
    fields.insert("count".to_string(), Value::Int(3));
    fields.insert("stores".to_string(), Value::Object(inner));
    fields.insert(
        "detail".to_string(),
        Value::Array(vec![Value::Str("a".into()), Value::Null]),
    );
    let object = Value::Object(fields);

    let out = render_cli_value(&object);
    let text = String::from_utf8(out).expect("UTF-8");
    assert!(text.ends_with('\n'), "{text:?}");
    assert!(
        text.contains("\n  \"exists\": true"),
        "must be pretty-printed: {text:?}"
    );
    let parsed: JsonValue = serde_json::from_str(&text).expect("parses back");
    assert_eq!(parsed, aitm_mcp::json::to_json(&object));

    assert_eq!(render_cli_value(&Value::Int(3)), b"3\n");
    assert_eq!(render_cli_value(&Value::Bool(false)), b"false\n");
    assert_eq!(render_cli_value(&Value::Null), b"null\n");
}
