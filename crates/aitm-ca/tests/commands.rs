//! Task 16 — the four `ca.*` commands as a frontend sees them: `CaPlugin`
//! registered in a `Registry`, invoked through a `CommandHost` that declares
//! its `Frontend`, against a scripted executor, an in-memory audit log and a
//! fixed platform (macOS unless a test pins another). Nothing here touches a
//! real trust store.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, ThreadId};

use aitm_ca::audit::AuditRecord;
use aitm_ca::store::{
    LinuxFamily, Platform, TrustError, TrustErrorKind, DEBIAN_ANCHOR_DIR, FEDORA_ANCHOR_DIR,
};
use aitm_ca::testing::{
    MemoryAuditLog, ScriptedExecutor, CANCEL_STDERR, FIXTURE_FP1, FIXTURE_FP256, MACOS_DETAIL,
    NOT_TRUSTED, VERIFY_OK, VERIFY_SPAWN_FAILURE, VERIFY_USER,
};
use aitm_ca::CaPlugin;
use aitm_core::{
    CaConfig, CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient,
    Registry, StdGuard, Value,
};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

/// The checked-in fixture CA, exactly as `ca.crt` on disk.
const FIXTURE: &[u8] = include_bytes!("fixtures/ca.crt");

const K_USER: &str = "/Users/t/Library/Keychains/login.keychain-db";
const Q_USER: &str = "security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db";
const Q_SYS: &str = "security find-certificate -a -Z /Library/Keychains/System.keychain";

/// The one line the obscura engine's independence is announced with.
const OBSCURA_FLAG: &str = "--ca-cert";

fn add_user() -> String {
    format!("security add-trusted-cert -r trustRoot -p ssl -p basic -k {K_USER} /ca/ca.crt")
}

/// `find-certificate -a -Z` output holding the fixture, so the login keychain
/// reads as present.
fn present_user_output() -> String {
    format!(
        "SHA-256 hash: {}\nSHA-1 hash: {}\nkeychain: \"{K_USER}\"\n",
        FIXTURE_FP256.replace(':', ""),
        FIXTURE_FP1.replace(':', "")
    )
}

/// Spec §D8 "Policy gate", exact.
fn refusal(cmd: &str, verb: &str) -> String {
    format!(
        "{cmd} refused: changing the OS trust store from an agent frontend is disabled. Set \
         ca.allow_agent_install = true in the aitmproxy config (or AITM_CA_ALLOW_AGENT_INSTALL=1 \
         in the environment) to allow it, or run `aitm ca {verb}` yourself from a shell. {cmd} \
         with dry_run=true is always allowed."
    )
}

/// A fresh, non-existent directory under the OS temp dir (`tempfile` is not
/// an allowed dependency).
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("aitm-ca-commands-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// A real CA directory holding only the fixture `ca.crt`.
fn real_ca_dir(tag: &str) -> PathBuf {
    let dir = scratch(tag);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ca.crt"), FIXTURE).unwrap();
    dir
}

fn cfg(dir: impl Into<PathBuf>, allow_agent_install: bool) -> CaConfig {
    CaConfig {
        dir: dir.into(),
        allow_agent_install,
        audit_log: PathBuf::from("/audit/ca-audit.jsonl"),
        ..CaConfig::default()
    }
}

/// A `ProxyClient` stub: the host needs one, but no `ca.*` command calls it.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// The plugin as a frontend sees it: its four commands in a registry, plus
/// the doubles behind them so a test can look at what ran and what was
/// recorded.
struct Harness {
    exec: Arc<ScriptedExecutor>,
    audit: Arc<MemoryAuditLog>,
    reg: Registry,
    store: MemFlowStore,
    guard: StdGuard,
    client: StubClient,
}

impl Harness {
    /// Pinned to macOS, the platform most tests speak.
    fn new(cfg: CaConfig, exec: ScriptedExecutor, audit: MemoryAuditLog) -> Self {
        Self::on(Platform::MacOs, cfg, exec, audit)
    }

    /// Pinned to `platform`, so the command layer is driven through its
    /// Linux and unsupported branches too (CA-AC16, CA-AC17).
    fn on(
        platform: Platform,
        cfg: CaConfig,
        exec: ScriptedExecutor,
        audit: MemoryAuditLog,
    ) -> Self {
        let exec = Arc::new(exec);
        let audit = Arc::new(audit);
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(CaPlugin::with_backend(
            cfg,
            exec.clone(),
            audit.clone(),
            platform,
        )));
        Self {
            exec,
            audit,
            reg,
            store: MemFlowStore::new(),
            guard: StdGuard::default(),
            client: StubClient,
        }
    }

    /// Scripted `/ca/ca.crt` = fixture, flag as given.
    fn scripted(allow_agent_install: bool) -> Self {
        Self::new(
            cfg("/ca", allow_agent_install),
            ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
            MemoryAuditLog::new(),
        )
    }

    fn host(&self, frontend: Frontend) -> CommandHost<'_> {
        CommandHost::new(&self.store, &self.client, &self.guard, None).with_frontend(frontend)
    }

    fn call(
        &self,
        name: &str,
        frontend: Frontend,
        args: &[(&str, Value)],
    ) -> anyhow::Result<Value> {
        let cmd = self
            .reg
            .command(name)
            .unwrap_or_else(|| panic!("{name} is not registered"));
        cmd.invoke(params(args), &self.host(frontend))
    }

    fn confirm(&self, name: &str, args: &[(&str, Value)]) -> Option<String> {
        self.reg
            .command(name)
            .unwrap()
            .confirm_prompt(&params(args))
    }

    fn records(&self) -> Vec<AuditRecord> {
        self.audit.records()
    }
}

fn params(args: &[(&str, Value)]) -> Params {
    Params::new(
        args.iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    )
}

fn str_arg(v: &str) -> Value {
    Value::Str(v.to_string())
}

fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    match v {
        Value::Object(fields) => fields
            .get(name)
            .unwrap_or_else(|| panic!("no field {name} in {fields:?}")),
        other => panic!("not an object: {other:?}"),
    }
}

fn text<'a>(v: &'a Value, name: &str) -> &'a str {
    match field(v, name) {
        Value::Str(s) => s,
        other => panic!("{name} is not a string: {other:?}"),
    }
}

fn flag(v: &Value, name: &str) -> bool {
    match field(v, name) {
        Value::Bool(b) => *b,
        other => panic!("{name} is not a bool: {other:?}"),
    }
}

fn strings(v: &Value, name: &str) -> Vec<String> {
    match field(v, name) {
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Str(s) => s.clone(),
                other => panic!("{name} holds a non-string: {other:?}"),
            })
            .collect(),
        other => panic!("{name} is not an array: {other:?}"),
    }
}

fn err_text(result: anyhow::Result<Value>) -> String {
    match result {
        Ok(v) => panic!("expected an error, got {v:?}"),
        Err(e) => format!("{e:#}"),
    }
}

/// The DER block of the fixture, decoded independently of `CaCert`.
fn fixture_der() -> Vec<u8> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(FIXTURE).unwrap();
    pem.contents
}

// CA-AC1
#[test]
fn export_pem_default() {
    let h = Harness::scripted(false);
    let v = h.call("ca.export", Frontend::Cli, &[]).unwrap();

    assert_eq!(text(&v, "format"), "pem");
    assert_eq!(
        field(&v, "certificate"),
        &Value::Str(String::from_utf8(FIXTURE.to_vec()).unwrap())
    );
    assert_eq!(text(&v, "fingerprint_sha256"), FIXTURE_FP256);
    assert_eq!(text(&v, "fingerprint_sha1"), FIXTURE_FP1);
    assert_eq!(text(&v, "dir"), "/ca");
    assert_eq!(text(&v, "path"), "/ca/ca.crt");
    assert_eq!(field(&v, "written_to"), &Value::Null);

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].command, "ca.export");
    assert_eq!(records[0].outcome, "ok");
    assert_eq!(records[0].frontend, "cli");
    assert_eq!(records[0].scope, None);
    assert_eq!(
        records[0].fingerprint_sha256.as_deref(),
        Some(FIXTURE_FP256)
    );
    assert!(
        !records[0].detail.contains("BEGIN CERTIFICATE"),
        "{}",
        records[0].detail
    );
    // Export runs nothing on the host.
    assert!(h.exec.runs().is_empty());
}

// CA-AC2
#[test]
fn export_der_and_out() {
    let der = fixture_der();
    assert_eq!(&der[..2], &[0x30, 0x82]);

    // DER on the bus.
    let h = Harness::scripted(false);
    let v = h
        .call("ca.export", Frontend::Mcp, &[("format", str_arg("der"))])
        .unwrap();
    assert_eq!(text(&v, "format"), "der");
    assert_eq!(field(&v, "certificate"), &Value::Bytes(der.clone()));
    assert_eq!(field(&v, "written_to"), &Value::Null);
    assert_eq!(h.records()[0].frontend, "mcp");

    // DER to a file, on a real filesystem outside the CA dir.
    let ca_dir = real_ca_dir("export-der-ca");
    let out_dir = scratch("export-der-out");
    fs::create_dir_all(&out_dir).unwrap();
    let out = out_dir.join("root.der");
    let h = Harness::new(
        cfg(&ca_dir, false),
        ScriptedExecutor::new().with_real_fs(),
        MemoryAuditLog::new(),
    );
    let v = h
        .call(
            "ca.export",
            Frontend::Cli,
            &[
                ("format", str_arg("der")),
                ("out", str_arg(&out.display().to_string())),
            ],
        )
        .unwrap();
    assert_eq!(fs::read(&out).unwrap(), der);
    assert_eq!(text(&v, "written_to"), out.display().to_string());
    assert_eq!(text(&v, "dir"), ca_dir.display().to_string());
    assert_eq!(
        text(&v, "path"),
        ca_dir.join("ca.crt").display().to_string()
    );
    assert!(h.records()[0].detail.contains(&out.display().to_string()));

    // PEM to a fresh file: byte-identical to ca.crt.
    let out = out_dir.join("root.pem");
    let v = h
        .call(
            "ca.export",
            Frontend::Cli,
            &[("out", str_arg(&out.display().to_string()))],
        )
        .unwrap();
    assert_eq!(text(&v, "format"), "pem");
    assert_eq!(fs::read(&out).unwrap(), FIXTURE);
    assert_eq!(text(&v, "written_to"), out.display().to_string());

    let _ = fs::remove_dir_all(&ca_dir);
    let _ = fs::remove_dir_all(&out_dir);
}

// CA-AC3
#[test]
fn export_refusals() {
    let h = Harness::scripted(false);

    let e = err_text(h.call("ca.export", Frontend::Cli, &[("format", str_arg("p12"))]));
    assert!(e.contains("format must be pem or der"), "got: {e}");
    // A bad argument is refused before the audit log is touched.
    assert!(h.records().is_empty(), "{:?}", h.records());

    for inside in ["/ca/copy.pem", "/ca/sub/copy.pem", "/ca/./copy.pem"] {
        let e = err_text(h.call("ca.export", Frontend::Cli, &[("out", str_arg(inside))]));
        assert!(
            e.contains("refusing to write into the CA directory"),
            "{inside}: got: {e}"
        );
        assert!(e.contains("/ca"), "{inside}: got: {e}");
    }
    // An `out` refusal is a refused export, so it is audited (spec §D8:
    // every export that got past argument parsing is recorded).
    let records = h.records();
    assert_eq!(records.len(), 3, "{records:?}");
    for rec in &records {
        assert_eq!(rec.command, "ca.export");
        assert_eq!(rec.outcome, "error");
        assert_eq!(rec.fingerprint_sha256.as_deref(), Some(FIXTURE_FP256));
        assert!(
            rec.detail
                .contains("refusing to write into the CA directory"),
            "{}",
            rec.detail
        );
    }

    // An existing file is never overwritten, from any frontend: `--out`
    // over MCP must not be a way to truncate an operator's file.
    let ca_dir = real_ca_dir("export-refuse-ca");
    let out_dir = scratch("export-refuse-out");
    fs::create_dir_all(&out_dir).unwrap();
    let existing = out_dir.join("keep.pem");
    fs::write(&existing, b"precious\n").unwrap();
    let audit_log = out_dir.join("audit").join("ca-audit.jsonl");
    let h = Harness::new(
        CaConfig {
            audit_log: audit_log.clone(),
            ..cfg(&ca_dir, false)
        },
        ScriptedExecutor::new().with_real_fs(),
        MemoryAuditLog::new(),
    );
    let e = err_text(h.call(
        "ca.export",
        Frontend::Mcp,
        &[("out", str_arg(&existing.display().to_string()))],
    ));
    assert!(e.contains("already exists"), "got: {e}");
    assert!(e.contains(&existing.display().to_string()), "got: {e}");
    assert_eq!(fs::read(&existing).unwrap(), b"precious\n");

    // The audit log itself is refused by canonical path: spelled through
    // `..` it is a different string but the same file.
    fs::create_dir_all(audit_log.parent().unwrap()).unwrap();
    fs::write(&audit_log, b"").unwrap();
    let dotted = out_dir
        .join("audit")
        .join("..")
        .join("audit")
        .join("ca-audit.jsonl");
    assert_ne!(dotted, audit_log);
    let e = err_text(h.call(
        "ca.export",
        Frontend::Mcp,
        &[("out", str_arg(&dotted.display().to_string()))],
    ));
    assert!(e.contains("audit log"), "got: {e}");
    assert_eq!(fs::read(&audit_log).unwrap(), b"");

    // The config file beside it is refused even before it exists.
    let config = audit_log.with_file_name("config.yaml");
    assert!(!config.exists());
    let e = err_text(h.call(
        "ca.export",
        Frontend::Mcp,
        &[("out", str_arg(&config.display().to_string()))],
    ));
    assert!(e.contains("config file"), "got: {e}");
    assert!(!config.exists(), "ca.export created the config file");

    // Each refusal was recorded, with the fingerprint, from the agent frontend.
    let records = h.records();
    assert_eq!(records.len(), 3, "{records:?}");
    for rec in &records {
        assert_eq!(rec.command, "ca.export");
        assert_eq!(rec.frontend, "mcp");
        assert_eq!(rec.outcome, "error");
        assert_eq!(rec.fingerprint_sha256.as_deref(), Some(FIXTURE_FP256));
    }
    assert!(
        records[0].detail.contains("already exists"),
        "{}",
        records[0].detail
    );
    assert!(
        records[1].detail.contains("audit log"),
        "{}",
        records[1].detail
    );
    assert!(
        records[2].detail.contains("config file"),
        "{}",
        records[2].detail
    );
    let _ = fs::remove_dir_all(&ca_dir);
    let _ = fs::remove_dir_all(&out_dir);

    // No ca.crt at all.
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new(),
        MemoryAuditLog::new(),
    );
    let e = err_text(h.call("ca.export", Frontend::Cli, &[]));
    assert!(e.contains("/ca/ca.crt"), "got: {e}");
    assert!(e.contains("start the proxy once"), "got: {e}");
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].outcome, "error");
    assert_eq!(records[0].fingerprint_sha256, None);
}

// CA-AC4
#[test]
fn status_without_ca() {
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new(),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Mcp, &[]).unwrap();

    assert!(!flag(&v, "exists"));
    assert_eq!(field(&v, "fingerprint_sha256"), &Value::Null);
    assert_eq!(field(&v, "fingerprint_sha1"), &Value::Null);
    assert_eq!(field(&v, "stores"), &Value::Object(BTreeMap::new()));
    assert_eq!(text(&v, "dir"), "/ca");
    assert_eq!(text(&v, "path"), "/ca/ca.crt");
    assert_eq!(text(&v, "platform"), "macos");
    let detail = strings(&v, "detail");
    assert!(
        detail.iter().any(|d| d.contains("/ca/ca.crt")),
        "{detail:?}"
    );
    assert!(
        detail.iter().any(|d| d.contains(OBSCURA_FLAG)),
        "{detail:?}"
    );
    // Read-only: nothing ran, nothing was recorded.
    assert!(h.exec.runs().is_empty());
    assert!(h.records().is_empty());
}

// CA-AC19 (command level)
#[test]
fn gate_refuses_mcp_and_audits() {
    for (name, verb) in [("ca.install", "install"), ("ca.uninstall", "uninstall")] {
        let h = Harness::scripted(false);
        let err = h.call(name, Frontend::Mcp, &[]).unwrap_err();
        assert_eq!(err.to_string(), refusal(name, verb));
        assert_eq!(h.exec.runs(), Vec::<String>::new(), "{name} ran something");

        let records = h.records();
        assert_eq!(records.len(), 1, "{name}: {records:?}");
        let rec = &records[0];
        assert_eq!(
            rec,
            &AuditRecord {
                ts: rec.ts.clone(),
                command: records[0].command,
                frontend: "mcp",
                outcome: "refused",
                scope: None,
                platform: Some("macos".to_string()),
                fingerprint_sha256: Some(FIXTURE_FP256.to_string()),
                detail: rec.detail.clone(),
            }
        );
        assert_eq!(rec.command, name);
        assert!(rec.detail.contains("refused"), "{}", rec.detail);
    }

    // The default host posture (no frontend declared) is gated too.
    let h = Harness::scripted(false);
    let host = CommandHost::new(&h.store, &h.client, &h.guard, None);
    let err = h
        .reg
        .command("ca.install")
        .unwrap()
        .invoke(params(&[]), &host)
        .unwrap_err();
    assert_eq!(err.to_string(), refusal("ca.install", "install"));
}

// CA-AC20 / CA-AC22
#[test]
fn gate_allows_with_flag_and_cli() {
    // Flag on, agent frontend: the install runs.
    let h = Harness::scripted(true);
    let v = h.call("ca.install", Frontend::Mcp, &[]).unwrap();
    assert!(flag(&v, "changed"));
    assert!(!flag(&v, "dry_run"));
    assert_eq!(text(&v, "scope"), "user");
    assert_eq!(text(&v, "platform"), "macos");
    assert_eq!(text(&v, "location"), K_USER);
    assert_eq!(text(&v, "fingerprint_sha256"), FIXTURE_FP256);
    assert_eq!(
        strings(&v, "commands"),
        vec![Q_USER.to_string(), add_user()]
    );
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string(), add_user()]);
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].command, "ca.install");
    assert_eq!(records[0].outcome, "ok");
    assert_eq!(records[0].frontend, "mcp");
    assert_eq!(records[0].platform.as_deref(), Some("macos"));
    assert_eq!(records[0].scope.as_deref(), Some("user"));
    assert_eq!(
        records[0].fingerprint_sha256.as_deref(),
        Some(FIXTURE_FP256)
    );
    assert!(
        records[0].detail.contains("changed=true"),
        "{}",
        records[0].detail
    );

    // Flag off, human CLI: never gated.
    let h = Harness::scripted(false);
    let v = h.call("ca.install", Frontend::Cli, &[]).unwrap();
    assert!(flag(&v, "changed"));
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string(), add_user()]);
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].frontend, "cli");
    assert_eq!(records[0].outcome, "ok");

    // An explicit scope is honoured and reported.
    let h = Harness::scripted(false);
    let v = h
        .call("ca.install", Frontend::Cli, &[("scope", str_arg("system"))])
        .unwrap();
    assert_eq!(text(&v, "scope"), "system");
    assert_eq!(text(&v, "location"), "/Library/Keychains/System.keychain");
    assert_eq!(h.exec.runs()[0], Q_SYS);
    assert_eq!(h.records()[0].scope.as_deref(), Some("system"));

    // A scope that is not a scope is an argument error, recorded nowhere.
    let h = Harness::scripted(false);
    let e = err_text(h.call(
        "ca.install",
        Frontend::Cli,
        &[("scope", str_arg("everyone"))],
    ));
    assert!(e.contains("scope"), "got: {e}");
    assert!(h.exec.runs().is_empty());
    assert!(h.records().is_empty());
}

// CA-AC11 (command level): a store failure is audited as `error`, with the
// identity the command had resolved by then.
#[test]
fn store_failure_is_audited() {
    let stderr = "SecTrustSettingsSetTrustSettings: The authorization was denied since no user \
                  interaction was possible";
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(&add_user(), 1, "", stderr),
        MemoryAuditLog::new(),
    );
    let (result, capture) = traced(|| h.call("ca.install", Frontend::Cli, &[]));
    let err = result.unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::HeadlessAuth),
        "{err:#}"
    );
    let e = format!("{err:#}");
    assert!(e.contains("GUI session"), "got: {e}");
    assert!(e.contains(stderr), "got: {e}");
    // Query, the failed add, and the post-failure requery (absent: nothing
    // to roll back).
    assert_eq!(
        h.exec.runs(),
        vec![Q_USER.to_string(), add_user(), Q_USER.to_string()]
    );

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    let rec = &records[0];
    assert_eq!(
        rec,
        &AuditRecord {
            ts: rec.ts.clone(),
            command: "ca.install",
            frontend: "cli",
            outcome: "error",
            scope: Some("user".to_string()),
            platform: Some("macos".to_string()),
            fingerprint_sha256: Some(FIXTURE_FP256.to_string()),
            detail: rec.detail.clone(),
        }
    );
    assert!(rec.detail.contains("GUI session"), "{}", rec.detail);
    assert!(!rec.detail.contains("BEGIN CERTIFICATE"), "{}", rec.detail);

    // Spec §D8: the failure is one WARN naming the error kind; no INFO.
    let warns = capture.at(Level::WARN, "aitm_ca");
    assert_eq!(warns.len(), 1, "{capture:?}");
    let f = &warns[0].fields;
    assert_eq!(f.get("command").map(String::as_str), Some("ca.install"));
    assert_eq!(f.get("kind").map(String::as_str), Some("HeadlessAuth"));
    assert_eq!(f.get("scope").map(String::as_str), Some("user"));
    assert_eq!(
        f.get("message").map(String::as_str),
        Some("OS trust store change failed")
    );
    assert!(capture.at(Level::INFO, "aitm_ca").is_empty());
}

// CA-AC17 (command level)
#[test]
fn unsupported_platform_status_and_install() {
    let h = Harness::on(
        Platform::Unsupported("linux".to_string()),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );

    let v = h.call("ca.status", Frontend::Cli, &[]).unwrap();
    assert!(flag(&v, "exists"));
    assert_eq!(text(&v, "fingerprint_sha256"), FIXTURE_FP256);
    assert_eq!(text(&v, "platform"), "unsupported");
    assert_eq!(field(&v, "stores"), &Value::Object(BTreeMap::new()));
    let detail = strings(&v, "detail");
    assert!(
        detail
            .iter()
            .any(|d| d.contains(FEDORA_ANCHOR_DIR) && d.contains(DEBIAN_ANCHOR_DIR)),
        "{detail:?}"
    );
    assert!(
        detail.iter().any(|d| d.contains(OBSCURA_FLAG)),
        "{detail:?}"
    );
    assert!(h.exec.runs().is_empty());
    assert!(h.records().is_empty());

    for (name, expected_records) in [("ca.install", 1), ("ca.uninstall", 2)] {
        let err = h.call(name, Frontend::Cli, &[]).unwrap_err();
        assert_eq!(
            err.downcast_ref::<TrustError>().map(|e| e.kind),
            Some(TrustErrorKind::UnsupportedPlatform),
            "{name}: {err:#}"
        );
        let e = format!("{err:#}");
        for needle in [FEDORA_ANCHOR_DIR, DEBIAN_ANCHOR_DIR, "/ca/ca.crt"] {
            assert!(e.contains(needle), "{name}: got: {e}");
        }
        assert!(
            h.exec.runs().is_empty(),
            "{name} ran something on an unsupported platform"
        );

        let records = h.records();
        assert_eq!(records.len(), expected_records, "{name}: {records:?}");
        let rec = records.last().unwrap();
        assert_eq!(
            rec,
            &AuditRecord {
                ts: rec.ts.clone(),
                command: rec.command,
                frontend: "cli",
                outcome: "error",
                scope: None,
                platform: Some("unsupported".to_string()),
                fingerprint_sha256: Some(FIXTURE_FP256.to_string()),
                detail: rec.detail.clone(),
            }
        );
        assert_eq!(rec.command, name);
        assert!(rec.detail.contains(DEBIAN_ANCHOR_DIR), "{}", rec.detail);
    }
    // Nothing to confirm: invoke fails with the clear error instead.
    assert_eq!(h.confirm("ca.install", &[]), None);
}

// CA-AC16 (command level)
#[test]
fn linux_scope_defaults_to_system() {
    const ANCHOR: &str = "/usr/local/share/ca-certificates/aitmproxy-root-ca.crt";
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );

    // No scope asked for: the platform's only scope, `system`.
    let v = h.call("ca.install", Frontend::Cli, &[]).unwrap();
    assert_eq!(text(&v, "scope"), "system");
    assert_eq!(text(&v, "platform"), "linux-debian");
    assert_eq!(text(&v, "location"), ANCHOR);
    assert!(flag(&v, "changed"));
    assert_eq!(
        h.exec.runs(),
        vec![
            format!("sudo -- tee {ANCHOR}"),
            "sudo -- update-ca-certificates".to_string()
        ]
    );
    assert_eq!(h.exec.stdins()[0].as_deref(), Some(FIXTURE));
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].outcome, "ok");
    assert_eq!(records[0].scope.as_deref(), Some("system"));
    assert_eq!(records[0].platform.as_deref(), Some("linux-debian"));

    // The prompt resolves the same scope and names the anchor.
    let p = h.confirm("ca.install", &[]).expect("install asks");
    assert!(p.contains(&format!("into {ANCHOR} (scope system)?")), "{p}");

    // `scope == "user"` is refused before anything runs, and audited.
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Fedora),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );
    let err = h
        .call("ca.install", Frontend::Cli, &[("scope", str_arg("user"))])
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::UnsupportedScope),
        "{err:#}"
    );
    assert!(
        format!("{err:#}").contains("no per-user OS trust store"),
        "{err:#}"
    );
    assert!(h.exec.runs().is_empty());
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].outcome, "error");
    assert_eq!(records[0].scope.as_deref(), Some("user"));
    assert_eq!(records[0].platform.as_deref(), Some("linux-fedora"));
    assert_eq!(h.confirm("ca.install", &[("scope", str_arg("user"))]), None);
}

// CA-AC21
#[test]
fn dry_run_passes_gate() {
    let h = Harness::scripted(false);
    let v = h
        .call(
            "ca.install",
            Frontend::Mcp,
            &[("dry_run", Value::Bool(true))],
        )
        .unwrap();

    assert!(flag(&v, "dry_run"));
    assert!(flag(&v, "changed"));
    let commands = strings(&v, "commands");
    assert!(
        commands.iter().any(|c| c == &add_user()),
        "commands: {commands:?}"
    );
    // Only the query reached the executor; the mutation was recorded, not run.
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string()]);
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].outcome, "dry_run");
    assert_eq!(records[0].frontend, "mcp");
    assert_eq!(records[0].command, "ca.install");
}

/// Everything a test can observe about one invocation's contact with the
/// host, flattened to strings.
fn observations(h: &Harness) -> Vec<String> {
    let mut all: Vec<String> = h.exec.runs();
    all.extend(
        h.exec
            .stdins()
            .into_iter()
            .flatten()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
    );
    all.extend(h.exec.reads().iter().map(|p| p.display().to_string()));
    all.extend(h.records().into_iter().map(|r| {
        format!(
            "{} {} {:?} {:?} {}",
            r.command, r.outcome, r.scope, r.platform, r.detail
        )
    }));
    all
}

fn sorted_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// CA-AC24
#[test]
fn key_never_touched() {
    let cases: &[(&str, bool)] = if cfg!(unix) {
        &[("no-key", false), ("unreadable-key", true)]
    } else {
        &[("no-key", false)]
    };

    for (tag, with_unreadable_key) in cases {
        let dir = real_ca_dir(&format!("key-{tag}"));
        if *with_unreadable_key {
            let key = dir.join("ca.key");
            fs::write(
                &key,
                b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&key, fs::Permissions::from_mode(0o000)).unwrap();
            }
        }
        let before = sorted_entries(&dir);

        let h = Harness::new(
            cfg(&dir, false),
            ScriptedExecutor::new().with_real_fs(),
            MemoryAuditLog::new(),
        );
        for name in ["ca.export", "ca.status", "ca.install", "ca.uninstall"] {
            let v = h.call(name, Frontend::Cli, &[]);
            assert!(v.is_ok(), "{tag}: {name}: {v:?}");
        }

        let seen = observations(&h);
        assert!(!seen.is_empty());
        for item in &seen {
            assert!(!item.contains("ca.key"), "{tag}: names the key: {item}");
            assert!(
                !item.contains("PRIVATE KEY"),
                "{tag}: carries key material: {item}"
            );
        }
        // Every read was the certificate, and only the certificate.
        let cert_path = dir.join("ca.crt");
        for read in h.exec.reads() {
            assert_eq!(read, cert_path, "{tag}");
        }
        assert_eq!(sorted_entries(&dir), before, "{tag}: the CA dir changed");

        let _ = fs::remove_dir_all(&dir);
    }
}

/// One recorded `tracing` event: the thread it came from, level, target,
/// and every field as text.
#[derive(Debug, Clone)]
struct Captured {
    thread: ThreadId,
    level: Level,
    target: String,
    fields: BTreeMap<String, String>,
}

/// The one subscriber of this test binary. Process-wide rather than scoped
/// with `with_default`: tracing caches each callsite's interest the first
/// time any thread hits it, and a parallel test thread without a subscriber
/// would cache "never" for a callsite before a scoped subscriber existed.
#[derive(Default, Clone)]
struct Capture(Arc<Mutex<Vec<Captured>>>);

impl Capture {
    fn global() -> &'static Capture {
        static CAPTURE: OnceLock<Capture> = OnceLock::new();
        CAPTURE.get_or_init(|| {
            let capture = Capture::default();
            tracing::subscriber::set_global_default(
                tracing_subscriber::registry().with(capture.clone()),
            )
            .expect("the first and only global subscriber of this test binary");
            capture
        })
    }

    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// This thread's events recorded since `start`.
    fn since(&self, start: usize) -> Events {
        let me = thread::current().id();
        Events(
            self.0.lock().unwrap()[start..]
                .iter()
                .filter(|e| e.thread == me)
                .cloned()
                .collect(),
        )
    }
}

/// What one traced closure emitted on its own thread.
#[derive(Debug)]
struct Events(Vec<Captured>);

impl Events {
    fn at(&self, level: Level, target: &str) -> Vec<Captured> {
        self.0
            .iter()
            .filter(|e| e.level == level && e.target == target)
            .cloned()
            .collect()
    }
}

struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
}

impl<S: Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = BTreeMap::new();
        event.record(&mut Fields(&mut fields));
        self.0.lock().unwrap().push(Captured {
            thread: thread::current().id(),
            level: *event.metadata().level(),
            target: event.metadata().target().to_string(),
            fields,
        });
    }
}

/// Run `f` and collect every `tracing` event it emitted on this thread.
fn traced<T>(f: impl FnOnce() -> T) -> (T, Events) {
    let capture = Capture::global();
    let start = capture.len();
    let out = f();
    (out, capture.since(start))
}

// CA-AC25
#[test]
fn tracing_fields() {
    // A successful CLI install.
    let (h, capture) = traced(|| {
        let h = Harness::scripted(false);
        h.call("ca.install", Frontend::Cli, &[]).unwrap();
        h
    });
    let info = capture.at(Level::INFO, "aitm_ca");
    assert_eq!(info.len(), 1, "{capture:?}");
    let f = &info[0].fields;
    assert_eq!(f.get("command").map(String::as_str), Some("ca.install"));
    assert_eq!(
        f.get("fingerprint_sha256").map(String::as_str),
        Some(FIXTURE_FP256)
    );
    assert_eq!(f.get("scope").map(String::as_str), Some("user"));
    assert_eq!(f.get("platform").map(String::as_str), Some("macos"));
    assert_eq!(f.get("frontend").map(String::as_str), Some("cli"));
    assert_eq!(f.get("changed").map(String::as_str), Some("true"));
    assert_eq!(f.get("dry_run").map(String::as_str), Some("false"));
    assert_eq!(
        f.get("message").map(String::as_str),
        Some("OS trust store updated")
    );

    let audit = capture.at(Level::INFO, "aitm_ca::audit");
    assert_eq!(audit.len(), 1, "{capture:?}");
    assert_eq!(
        audit[0].fields.get("outcome").map(String::as_str),
        Some("ok")
    );
    assert_eq!(h.records().len(), 1);

    // Spec §D8: every subprocess is one DEBUG event with the rendered line
    // and its exit code — here the query and the add, in order.
    let debug = capture.at(Level::DEBUG, "aitm_ca");
    let lines: Vec<&str> = debug
        .iter()
        .map(|e| e.fields.get("command_line").map_or("", String::as_str))
        .collect();
    assert_eq!(lines, vec![Q_USER, add_user().as_str()], "{debug:?}");
    for e in &debug {
        assert_eq!(e.fields.get("code").map(String::as_str), Some("0"), "{e:?}");
        assert_eq!(
            e.fields.get("message").map(String::as_str),
            Some("ran trust-store command"),
            "{e:?}"
        );
    }

    // Nothing logged carries the certificate itself.
    for e in &capture.0 {
        for v in e.fields.values() {
            assert!(!v.contains("BEGIN CERTIFICATE"), "{e:?}");
        }
    }

    // A gate refusal.
    let (_, capture) = traced(|| {
        let h = Harness::scripted(false);
        h.call("ca.install", Frontend::Mcp, &[]).unwrap_err();
    });
    let warns = capture.at(Level::WARN, "aitm_ca");
    assert_eq!(warns.len(), 1, "{capture:?}");
    let f = &warns[0].fields;
    assert_eq!(
        f.get("setting").map(String::as_str),
        Some("ca.allow_agent_install")
    );
    assert_eq!(f.get("command").map(String::as_str), Some("ca.install"));
    assert_eq!(f.get("frontend").map(String::as_str), Some("mcp"));
    assert!(capture.at(Level::INFO, "aitm_ca").is_empty());
}

// CA-AC28 (fail-closed half)
#[test]
fn audit_fail_closed() {
    let h = Harness::new(
        cfg("/ca", true),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::failing(),
    );

    for name in ["ca.install", "ca.uninstall", "ca.export"] {
        let e = err_text(h.call(name, Frontend::Cli, &[]));
        assert!(e.contains("audit log"), "{name}: got: {e}");
        assert!(e.contains("/audit/ca-audit.jsonl"), "{name}: got: {e}");
        assert!(e.contains("refusing"), "{name}: got: {e}");
    }
    // Nothing ran and ca.crt was never even opened.
    assert_eq!(h.exec.runs(), Vec::<String>::new());
    assert_eq!(h.exec.reads(), Vec::<PathBuf>::new());
    assert!(h.records().is_empty());

    // Status is read-only and not audited, so it still answers.
    let v = h.call("ca.status", Frontend::Cli, &[]).unwrap();
    assert!(flag(&v, "exists"));
    assert_eq!(text(&v, "fingerprint_sha256"), FIXTURE_FP256);
}

#[test]
fn confirm_prompts() {
    let h = Harness::scripted(false);

    let p = h.confirm("ca.install", &[]).expect("install asks");
    assert!(
        p.starts_with("Install the aitmproxy root CA (SHA-256 "),
        "{p}"
    );
    assert!(p.contains(FIXTURE_FP256), "{p}");
    assert!(p.contains(&format!("into {K_USER} (scope user)?")), "{p}");
    assert!(p.contains(OBSCURA_FLAG), "{p}");
    assert!(p.contains("obscura"), "{p}");

    let p = h
        .confirm("ca.install", &[("scope", str_arg("system"))])
        .expect("install asks");
    assert!(
        p.contains("into /Library/Keychains/System.keychain (scope system)?"),
        "{p}"
    );

    let p = h.confirm("ca.uninstall", &[]).expect("uninstall asks");
    assert_eq!(
        p,
        format!(
            "Remove the aitmproxy root CA (SHA-256 {FIXTURE_FP256}) from {K_USER} (scope user)?"
        )
    );

    // Dry runs change nothing and are not confirmed.
    assert_eq!(
        h.confirm("ca.install", &[("dry_run", Value::Bool(true))]),
        None
    );
    assert_eq!(
        h.confirm("ca.uninstall", &[("dry_run", Value::Bool(true))]),
        None
    );
    // Read-only commands never ask.
    assert_eq!(h.confirm("ca.status", &[]), None);
    assert_eq!(h.confirm("ca.export", &[]), None);
    // Computing a prompt reads ca.crt and runs nothing.
    assert!(h.exec.runs().is_empty());
    assert!(h.exec.reads().iter().all(|p| p == Path::new("/ca/ca.crt")));

    // No ca.crt: no prompt; invoke will fail with the clear error instead.
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new(),
        MemoryAuditLog::new(),
    );
    assert_eq!(h.confirm("ca.install", &[]), None);
    assert_eq!(h.confirm("ca.uninstall", &[]), None);
}

/// The plugin registers exactly the four commands, under the `ca` name.
#[test]
fn registers_four_commands() {
    let h = Harness::scripted(false);
    let names: Vec<&str> = h.reg.commands().map(|c| c.name()).collect();
    assert_eq!(
        names,
        ["ca.export", "ca.status", "ca.install", "ca.uninstall"]
    );
    for cmd in h.reg.commands() {
        let schema = cmd.schema();
        assert!(!schema.description.is_empty(), "{}", cmd.name());
        assert!(
            schema.description.contains("obscura"),
            "{}: {}",
            cmd.name(),
            schema.description
        );
    }
    for gated in ["ca.install", "ca.uninstall"] {
        let d = h.reg.command(gated).unwrap().schema().description;
        assert!(d.contains("ca.allow_agent_install"), "{gated}: {d}");
    }
    let plugin = CaPlugin::with_backend(
        cfg("/ca", false),
        h.exec.clone(),
        h.audit.clone(),
        Platform::MacOs,
    );
    let debug = format!("{plugin:?}");
    assert!(debug.contains("CaPlugin"), "{debug}");
    assert!(debug.contains("/ca"), "{debug}");
    let _cloned = plugin.clone();
}

// SP-AC29 (D17.2): an operator-token connection is a present human, so the
// agent gate lets it through with the flag off.
#[test]
fn operator_install_passes_the_agent_gate() {
    let h = Harness::scripted(false);
    let v = h.call("ca.install", Frontend::Operator, &[]).unwrap();
    assert!(flag(&v, "changed"));
    assert_eq!(text(&v, "scope"), "user");
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string(), add_user()]);

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].command, "ca.install");
    assert_eq!(records[0].frontend, "operator");
    assert_eq!(records[0].outcome, "ok");

    // The sibling verb is gated the same way.
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, &present_user_output(), "")
            .respond(Q_USER, 0, "", ""),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.uninstall", Frontend::Operator, &[]).unwrap();
    assert!(flag(&v, "changed"));
    assert_eq!(h.records()[0].frontend, "operator");
    assert_eq!(h.records()[0].outcome, "ok");
}

// SP-AC29, second half: the agent frontend is still refused without the flag
// and still passes with dry_run.
#[test]
fn mcp_install_is_still_refused_without_the_flag() {
    let h = Harness::scripted(false);
    let e = err_text(h.call("ca.install", Frontend::Mcp, &[]));
    assert!(e.starts_with("ca.install refused"), "got: {e}");
    assert_eq!(h.exec.runs(), Vec::<String>::new());

    let h = Harness::scripted(false);
    let v = h
        .call(
            "ca.install",
            Frontend::Mcp,
            &[("dry_run", Value::Bool(true))],
        )
        .unwrap();
    assert!(flag(&v, "dry_run"));
}

// SP-AC30 (D17.1): scope resolution per platform, through the plugin.
#[test]
fn scope_resolution_per_platform() {
    // macOS, no scope: user.
    let h = Harness::scripted(false);
    let v = h.call("ca.install", Frontend::Cli, &[]).unwrap();
    assert_eq!(text(&v, "scope"), "user");
    assert!(
        h.exec.runs().iter().all(|line| !line.starts_with("sudo")),
        "{:?}",
        h.exec.runs()
    );

    // macOS, scope user: user.
    let h = Harness::scripted(false);
    let v = h
        .call("ca.install", Frontend::Cli, &[("scope", str_arg("user"))])
        .unwrap();
    assert_eq!(text(&v, "scope"), "user");
    assert!(h.exec.runs().iter().all(|line| !line.starts_with("sudo")));

    // Debian, scope user: refused with the Linux hint.
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );
    let err = h
        .call("ca.install", Frontend::Cli, &[("scope", str_arg("user"))])
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::UnsupportedScope),
        "{err:#}"
    );
    assert_eq!(
        err.to_string(),
        "Linux has no per-user OS trust store; use --scope system"
    );

    // Debian, no scope: system.
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.install", Frontend::Cli, &[]).unwrap();
    assert_eq!(text(&v, "scope"), "system");
}

// SP-AC31 (command level): the scripted read-back surfaces as
// `stores.user.trusted == "yes"`.
#[test]
fn ca_status_json_reports_user_trust_yes() {
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, &present_user_output(), "")
            .respond(VERIFY_USER, 0, VERIFY_OK, ""),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    let user = field(field(&v, "stores"), "user");
    assert_eq!(text(user, "installed"), "present");
    assert_eq!(text(user, "trusted"), "yes");
    // The System keychain answered empty: absent, so not trusted, no read-back.
    let system = field(field(&v, "stores"), "system");
    assert_eq!(text(system, "installed"), "absent");
    assert_eq!(text(system, "trusted"), "no");
    assert_eq!(
        h.exec.runs(),
        vec![
            Q_USER.to_string(),
            VERIFY_USER.to_string(),
            Q_SYS.to_string()
        ]
    );
    let detail = strings(&v, "detail");
    assert!(
        detail
            .iter()
            .any(|d| d.contains("trust from `security verify-cert`")),
        "{detail:?}"
    );
    assert!(h.records().is_empty());
}

// SP-AC32 (command level): the audit record and the WARN line name the kind
// `cancelled`; the message starts with the calm literal.
#[test]
fn cancelled_install_warns_with_kind_cancelled() {
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE).respond(
            &add_user(),
            1,
            "",
            CANCEL_STDERR,
        ),
        MemoryAuditLog::new(),
    );
    let (result, capture) = traced(|| h.call("ca.install", Frontend::Operator, &[]));
    let err = result.unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::Cancelled),
        "{err:#}"
    );
    assert!(
        err.to_string().starts_with("ca.install cancelled"),
        "got: {err}"
    );

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].frontend, "operator");
    assert_eq!(records[0].outcome, "error");
    assert!(
        records[0].detail.starts_with("ca.install cancelled"),
        "{}",
        records[0].detail
    );

    let warns = capture.at(Level::WARN, "aitm_ca");
    assert_eq!(warns.len(), 1, "{capture:?}");
    let f = &warns[0].fields;
    assert_eq!(f.get("kind").map(String::as_str), Some("cancelled"));
    assert_eq!(f.get("command").map(String::as_str), Some("ca.install"));
}

// ---------------------------------------------------------------------------
// Stage-5 tester additions (Tasks 33 and 34, spec §D17; SP-AC29, SP-AC31,
// SP-AC32 edges the Coder's tests leave open).
// ---------------------------------------------------------------------------

const K_SYS: &str = "/Library/Keychains/System.keychain";
const DEBIAN_ANCHOR: &str = "/usr/local/share/ca-certificates/aitmproxy-root-ca.crt";
const SUDO_NO_TTY: &str = "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper";
const CANCELLED_FULL: &str = "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted; removed the untrusted copy it left behind";

/// `find-certificate -a -Z` output holding the fixture in the System keychain.
fn present_system_output() -> String {
    format!(
        "SHA-256 hash: {}\nSHA-1 hash: {}\nkeychain: \"{K_SYS}\"\n",
        FIXTURE_FP256.replace(':', ""),
        FIXTURE_FP1.replace(':', "")
    )
}

fn store_text<'a>(v: &'a Value, scope: &str, key: &str) -> &'a str {
    text(field(field(v, "stores"), scope), key)
}

// SP-AC29 (tester): the operator frontend is labelled "operator" on every
// outcome the gate can reach: dry_run, flag on, and the INFO line.
#[test]
fn operator_dry_run_and_flag_on_are_audited_as_operator() {
    // Operator + dry_run, flag off: passes (dry_run always does) and the
    // record says who asked.
    let h = Harness::scripted(false);
    let v = h
        .call(
            "ca.install",
            Frontend::Operator,
            &[("dry_run", Value::Bool(true))],
        )
        .unwrap();
    assert!(flag(&v, "dry_run"));
    assert!(flag(&v, "changed"));
    assert_eq!(text(&v, "scope"), "user");
    assert_eq!(
        strings(&v, "commands"),
        vec![Q_USER.to_string(), add_user()]
    );
    // The mutation was rendered, not run.
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string()]);
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].frontend, "operator");
    assert_eq!(records[0].outcome, "dry_run");
    assert_eq!(records[0].scope.as_deref(), Some("user"));

    // Operator with the flag on: still "operator", never "mcp".
    let (h, capture) = traced(|| {
        let h = Harness::scripted(true);
        let v = h.call("ca.install", Frontend::Operator, &[]).unwrap();
        assert!(flag(&v, "changed"));
        h
    });
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string(), add_user()]);
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].frontend, "operator");
    assert_eq!(records[0].outcome, "ok");
    let info = capture.at(Level::INFO, "aitm_ca");
    assert_eq!(info.len(), 1, "{capture:?}");
    assert_eq!(
        info[0].fields.get("frontend").map(String::as_str),
        Some("operator")
    );
    assert_eq!(
        info[0].fields.get("message").map(String::as_str),
        Some("OS trust store updated")
    );
    assert!(capture.at(Level::WARN, "aitm_ca").is_empty(), "{capture:?}");

    // Operator uninstall, flag off, certificate present: proceeds and is
    // labelled the same.
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, &present_user_output(), "")
            .respond(Q_USER, 0, "", ""),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.uninstall", Frontend::Operator, &[]).unwrap();
    assert!(flag(&v, "changed"));
    assert_eq!(h.exec.runs()[0], Q_USER);
    assert_eq!(
        h.exec.runs()[1],
        "security remove-trusted-cert /ca/ca.crt".to_string()
    );
    assert_eq!(h.records()[0].frontend, "operator");
    assert_eq!(h.records()[0].outcome, "ok");
}

// D17.13 (tester): Linux is unchanged by the gate widening. An operator
// install that cannot get root is still a `NeedsRoot` error with the CLI
// remedy, audited as "operator"/"error", with the kind in the WARN line.
#[test]
fn linux_operator_install_still_needs_root() {
    let tee = format!("sudo -- tee {DEBIAN_ANCHOR}");
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .root(false)
            .respond(&tee, 1, "", SUDO_NO_TTY),
        MemoryAuditLog::new(),
    );
    let (result, capture) = traced(|| h.call("ca.install", Frontend::Operator, &[]));
    let err = result.unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::NeedsRoot),
        "{err:#}"
    );
    let msg = err.to_string();
    assert!(
        msg.starts_with(
            "needs root: run aitm ca install from a shell where sudo can prompt, or start the \
             proxy as root ("
        ),
        "got: {msg}"
    );
    assert!(msg.contains(SUDO_NO_TTY), "got: {msg}");
    // The gate let the operator through (the tee ran); the refresh never did.
    assert_eq!(h.exec.runs(), vec![tee.clone()]);

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].frontend, "operator");
    assert_eq!(records[0].outcome, "error");
    assert_eq!(records[0].scope.as_deref(), Some("system"));
    assert_eq!(records[0].platform.as_deref(), Some("linux-debian"));
    assert_eq!(records[0].detail, msg);

    let warns = capture.at(Level::WARN, "aitm_ca");
    assert_eq!(warns.len(), 1, "{capture:?}");
    assert_eq!(
        warns[0].fields.get("kind").map(String::as_str),
        Some("NeedsRoot")
    );
    assert_eq!(
        warns[0].fields.get("platform").map(String::as_str),
        Some("linux-debian")
    );

    // The Linux status shape is untouched too: one `system` store, no `user`.
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert_eq!(text(&v, "platform"), "linux-debian");
    match field(&v, "stores") {
        Value::Object(stores) => {
            assert_eq!(stores.keys().collect::<Vec<_>>(), vec!["system"]);
        }
        other => panic!("stores is not an object: {other:?}"),
    }
    assert_eq!(store_text(&v, "system", "installed"), "absent");
    // Linux's trust comes from the extracted bundle, which the scripted fs
    // does not hold: unknown (pre-existing Linux behaviour, linux.rs is not
    // in this range). With a bundle that lacks us it reads "no".
    assert_eq!(store_text(&v, "system", "trusted"), "unknown");
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE).file(
            "/etc/ssl/certs/ca-certificates.crt",
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        ),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert_eq!(store_text(&v, "system", "installed"), "absent");
    assert_eq!(store_text(&v, "system", "trusted"), "no");
    assert!(
        h.exec.runs().is_empty(),
        "Linux status is read-only: {:?}",
        h.exec.runs()
    );
}

// SP-AC31 (tester, command level): the other two verify-cert outcomes reach
// the JSON as "no" and "unknown", each with its own detail line, and the
// macOS detail line is deduplicated across the two stores.
#[test]
fn ca_status_json_reports_user_trust_no_and_unknown() {
    // Non-zero exit: "no", with the verify-cert tail in detail.
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, &present_user_output(), "")
            .respond(VERIFY_USER, 1, NOT_TRUSTED, ""),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert!(flag(&v, "exists"));
    assert_eq!(text(&v, "platform"), "macos");
    assert_eq!(store_text(&v, "user", "installed"), "present");
    assert_eq!(store_text(&v, "user", "trusted"), "no");
    assert_eq!(store_text(&v, "user", "location"), K_USER);
    assert_eq!(store_text(&v, "system", "installed"), "absent");
    assert_eq!(store_text(&v, "system", "trusted"), "no");
    assert_eq!(
        h.exec.runs(),
        vec![
            Q_USER.to_string(),
            VERIFY_USER.to_string(),
            Q_SYS.to_string()
        ]
    );
    let detail = strings(&v, "detail");
    assert_eq!(
        detail,
        vec![
            MACOS_DETAIL.to_string(),
            format!("`{VERIFY_USER}` exited 1: {NOT_TRUSTED}"),
            OBSCURA_DETAIL_LINE.to_string(),
        ],
        "{detail:?}"
    );
    assert!(h.records().is_empty(), "ca.status is never audited");

    // Unspawnable: "unknown", with the spawn failure in detail; the System
    // keychain is still absent and "no".
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .unspawnable("verify-cert")
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, &present_user_output(), ""),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert_eq!(store_text(&v, "user", "installed"), "present");
    assert_eq!(store_text(&v, "user", "trusted"), "unknown");
    assert_eq!(store_text(&v, "system", "installed"), "absent");
    assert_eq!(store_text(&v, "system", "trusted"), "no");
    assert_eq!(
        h.exec.runs(),
        vec![
            Q_USER.to_string(),
            VERIFY_USER.to_string(),
            Q_SYS.to_string()
        ]
    );
    let detail = strings(&v, "detail");
    assert_eq!(
        detail,
        vec![
            MACOS_DETAIL.to_string(),
            VERIFY_SPAWN_FAILURE.to_string(),
            OBSCURA_DETAIL_LINE.to_string(),
        ],
        "{detail:?}"
    );

    // Both keychains empty: "no" twice, no verify-cert at all.
    let h = Harness::scripted(false);
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert_eq!(store_text(&v, "user", "installed"), "absent");
    assert_eq!(store_text(&v, "user", "trusted"), "no");
    assert_eq!(store_text(&v, "system", "installed"), "absent");
    assert_eq!(store_text(&v, "system", "trusted"), "no");
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string(), Q_SYS.to_string()]);
    assert_eq!(
        strings(&v, "detail"),
        vec![MACOS_DETAIL.to_string(), OBSCURA_DETAIL_LINE.to_string()]
    );
}

/// The obscura independence line `ca.status` always ends its detail with.
const OBSCURA_DETAIL_LINE: &str = "the embedded browser (obscura) does not use the OS trust store; it trusts this CA through --ca-cert at launch";

// SP-AC31 (tester, System scope path): a certificate held only by the System
// keychain is read back the same way and reported under `stores.system`; a
// certificate in both keychains yields one evaluation per store and one
// deduplicated detail line.
#[test]
fn ca_status_json_system_scope_trust() {
    // Only the System keychain holds it.
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_SYS, 0, &present_system_output(), "")
            .respond(VERIFY_USER, 0, VERIFY_OK, ""),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert_eq!(store_text(&v, "user", "installed"), "absent");
    assert_eq!(store_text(&v, "user", "trusted"), "no");
    assert_eq!(store_text(&v, "system", "installed"), "present");
    assert_eq!(store_text(&v, "system", "trusted"), "yes");
    assert_eq!(store_text(&v, "system", "location"), K_SYS);
    assert_eq!(
        h.exec.runs(),
        vec![
            Q_USER.to_string(),
            Q_SYS.to_string(),
            VERIFY_USER.to_string()
        ]
    );
    assert!(
        h.exec.runs().iter().all(|l| !l.starts_with("sudo")),
        "status never escalates: {:?}",
        h.exec.runs()
    );

    // Both keychains hold it: both say yes, verify-cert ran once per store,
    // the macOS detail line appears once.
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, &present_user_output(), "")
            .respond(Q_SYS, 0, &present_system_output(), "")
            .respond(VERIFY_USER, 0, VERIFY_OK, ""),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert_eq!(store_text(&v, "user", "trusted"), "yes");
    assert_eq!(store_text(&v, "system", "trusted"), "yes");
    assert_eq!(
        h.exec.runs(),
        vec![
            Q_USER.to_string(),
            VERIFY_USER.to_string(),
            Q_SYS.to_string(),
            VERIFY_USER.to_string()
        ]
    );
    assert_eq!(
        strings(&v, "detail"),
        vec![MACOS_DETAIL.to_string(), OBSCURA_DETAIL_LINE.to_string()]
    );

    // Trusted in neither, present in both: two "no" and one verify tail
    // (identical lines are deduplicated too).
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, &present_user_output(), "")
            .respond(Q_SYS, 0, &present_system_output(), "")
            .respond(VERIFY_USER, 1, "", NOT_TRUSTED),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.status", Frontend::Operator, &[]).unwrap();
    assert_eq!(store_text(&v, "user", "trusted"), "no");
    assert_eq!(store_text(&v, "system", "trusted"), "no");
    assert_eq!(
        strings(&v, "detail"),
        vec![
            MACOS_DETAIL.to_string(),
            format!("`{VERIFY_USER}` exited 1: {NOT_TRUSTED}"),
            OBSCURA_DETAIL_LINE.to_string(),
        ]
    );
}

// SP-AC32 (tester, command level): with the rollback path taken, the audit
// record's detail and the WARN `error` field carry the full literal, byte for
// byte, and nothing but `error` is recorded.
#[test]
fn cancelled_install_audit_detail_is_the_full_message() {
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new()
            .file("/ca/ca.crt", FIXTURE)
            .respond(Q_USER, 0, "", "")
            .respond(Q_USER, 0, &present_user_output(), "")
            .respond(&add_user(), 1, "", CANCEL_STDERR),
        MemoryAuditLog::new(),
    );
    let (result, capture) = traced(|| h.call("ca.install", Frontend::Operator, &[]));
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), CANCELLED_FULL);
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::Cancelled)
    );
    assert_eq!(
        h.exec.runs(),
        vec![
            Q_USER.to_string(),
            add_user(),
            Q_USER.to_string(),
            format!(
                "security delete-certificate -Z {} {K_USER}",
                FIXTURE_FP256.replace(':', "")
            ),
        ]
    );

    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    let rec = &records[0];
    assert_eq!(
        rec,
        &AuditRecord {
            ts: rec.ts.clone(),
            command: "ca.install",
            frontend: "operator",
            outcome: "error",
            scope: Some("user".to_string()),
            platform: Some("macos".to_string()),
            fingerprint_sha256: Some(FIXTURE_FP256.to_string()),
            detail: CANCELLED_FULL.to_string(),
        }
    );

    let warns = capture.at(Level::WARN, "aitm_ca");
    assert_eq!(warns.len(), 1, "{capture:?}");
    let f = &warns[0].fields;
    assert_eq!(f.get("kind").map(String::as_str), Some("cancelled"));
    assert_eq!(f.get("error").map(String::as_str), Some(CANCELLED_FULL));
    assert_eq!(f.get("scope").map(String::as_str), Some("user"));
    assert!(capture.at(Level::INFO, "aitm_ca").is_empty(), "{capture:?}");

    // The MCP frontend with the flag on meets the same calm message: the
    // kind does not depend on who asked.
    let h = Harness::new(
        cfg("/ca", true),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE).respond(
            &add_user(),
            1,
            "",
            CANCEL_STDERR,
        ),
        MemoryAuditLog::new(),
    );
    let err = h.call("ca.install", Frontend::Mcp, &[]).unwrap_err();
    assert_eq!(
        err.to_string(),
        "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted"
    );
    assert_eq!(h.records()[0].frontend, "mcp");
    assert_eq!(h.records()[0].outcome, "error");
}

// ---------------------------------------------------------------------------
// Stage-6 fix task C1 (plan correction 7, spec D17.1/D17.14): only the CLI
// may ask for the System keychain on a platform that has a user scope.
// ---------------------------------------------------------------------------

const SYSTEM_NEEDS_TERMINAL_INSTALL: &str = "system scope needs a terminal: run `aitm ca install \
                                             --scope system` yourself; the app and the bus \
                                             clients use the login keychain";
const SYSTEM_NEEDS_TERMINAL_UNINSTALL: &str = "system scope needs a terminal: run `aitm ca \
                                               uninstall --scope system` yourself; the app and \
                                               the bus clients use the login keychain";

fn add_sys_sudo() -> String {
    format!(
        "sudo -- security add-trusted-cert -d -r trustRoot -p ssl -p basic -k {K_SYS} /ca/ca.crt"
    )
}

#[test]
fn non_cli_system_scope_is_refused_before_any_run() {
    // Operator, macOS, scope system: UnsupportedScope, the terminal remedy,
    // audited as error, and the executor never ran.
    let h = Harness::scripted(false);
    let err = h
        .call(
            "ca.install",
            Frontend::Operator,
            &[("scope", str_arg("system"))],
        )
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::UnsupportedScope),
        "{err:#}"
    );
    assert_eq!(err.to_string(), SYSTEM_NEEDS_TERMINAL_INSTALL);
    assert_eq!(h.exec.runs(), Vec::<String>::new());
    let records = h.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0].command, "ca.install");
    assert_eq!(records[0].frontend, "operator");
    assert_eq!(records[0].outcome, "error");
    assert_eq!(records[0].scope.as_deref(), Some("system"));
    assert_eq!(records[0].platform.as_deref(), Some("macos"));
    assert_eq!(
        records[0].fingerprint_sha256.as_deref(),
        Some(FIXTURE_FP256)
    );
    assert_eq!(records[0].detail, SYSTEM_NEEDS_TERMINAL_INSTALL);

    // The sibling verb names itself in the remedy.
    let h = Harness::scripted(false);
    let err = h
        .call(
            "ca.uninstall",
            Frontend::Operator,
            &[("scope", str_arg("system"))],
        )
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::UnsupportedScope),
        "{err:#}"
    );
    assert_eq!(err.to_string(), SYSTEM_NEEDS_TERMINAL_UNINSTALL);
    assert_eq!(h.exec.runs(), Vec::<String>::new());
    assert_eq!(h.records()[0].outcome, "error");

    // An agent with the flag on is a bus client too: same refusal.
    let h = Harness::scripted(true);
    let err = h
        .call("ca.install", Frontend::Mcp, &[("scope", str_arg("system"))])
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::UnsupportedScope),
        "{err:#}"
    );
    assert_eq!(err.to_string(), SYSTEM_NEEDS_TERMINAL_INSTALL);
    assert_eq!(h.exec.runs(), Vec::<String>::new());

    // Windows has a user scope too, so the same rule holds there.
    let h = Harness::on(
        Platform::Windows,
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );
    let err = h
        .call(
            "ca.install",
            Frontend::Operator,
            &[("scope", str_arg("system"))],
        )
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<TrustError>().map(|e| e.kind),
        Some(TrustErrorKind::UnsupportedScope),
        "{err:#}"
    );
    assert_eq!(h.exec.runs(), Vec::<String>::new());

    // The CLI still gets the System keychain through sudo.
    let h = Harness::scripted(false);
    let v = h
        .call("ca.install", Frontend::Cli, &[("scope", str_arg("system"))])
        .unwrap();
    assert_eq!(text(&v, "scope"), "system");
    assert!(flag(&v, "changed"));
    assert_eq!(h.exec.runs(), vec![Q_SYS.to_string(), add_sys_sudo()]);
    assert_eq!(h.records()[0].outcome, "ok");

    // The operator's default scope on macOS is untouched: the login keychain.
    let h = Harness::scripted(false);
    let v = h.call("ca.install", Frontend::Operator, &[]).unwrap();
    assert_eq!(text(&v, "scope"), "user");
    assert_eq!(h.exec.runs(), vec![Q_USER.to_string(), add_user()]);
}

#[test]
fn linux_operator_system_scope_is_unchanged() {
    let tee = format!("sudo -- tee {DEBIAN_ANCHOR}");
    // No scope: the platform's only scope, through sudo, as before.
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );
    let v = h.call("ca.install", Frontend::Operator, &[]).unwrap();
    assert_eq!(text(&v, "scope"), "system");
    assert_eq!(
        h.exec.runs(),
        vec![tee.clone(), "sudo -- update-ca-certificates".to_string()]
    );
    assert_eq!(h.records()[0].outcome, "ok");
    assert_eq!(h.records()[0].frontend, "operator");

    // Explicit `system` on Linux is the only scope there, not a System
    // keychain: still allowed.
    let h = Harness::on(
        Platform::Linux(LinuxFamily::Debian),
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE),
        MemoryAuditLog::new(),
    );
    let v = h
        .call(
            "ca.install",
            Frontend::Operator,
            &[("scope", str_arg("system"))],
        )
        .unwrap();
    assert_eq!(text(&v, "scope"), "system");
    assert_eq!(h.exec.runs()[0], tee);
}

// Stage-6 fix task C1 (finding 2): the calm message hides the tool text, so
// the stderr tail goes to one DEBUG line at the classification site.
#[test]
fn cancelled_install_logs_the_stderr_tail_at_debug() {
    let h = Harness::new(
        cfg("/ca", false),
        ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE).respond(
            &add_user(),
            1,
            "",
            &format!("noise line\n{CANCEL_STDERR}\n"),
        ),
        MemoryAuditLog::new(),
    );
    let (result, capture) = traced(|| h.call("ca.install", Frontend::Operator, &[]));
    let err = result.unwrap_err();
    assert_eq!(
        err.to_string(),
        "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted"
    );

    let debug = capture.at(Level::DEBUG, "aitm_ca");
    let classified: Vec<&Captured> = debug
        .iter()
        .filter(|e| e.fields.contains_key("stderr_tail"))
        .collect();
    assert_eq!(classified.len(), 1, "{debug:?}");
    let f = &classified[0].fields;
    assert_eq!(
        f.get("stderr_tail").map(String::as_str),
        Some(format!("noise line | {CANCEL_STDERR}").as_str())
    );
    assert_eq!(
        f.get("message").map(String::as_str),
        Some("add-trusted-cert classified as cancelled")
    );
    // The tool text stays out of the error, the audit record and the WARN line.
    assert!(!err.to_string().contains("canceled"), "{err}");
    assert!(!h.records()[0].detail.contains("canceled"));
    let warns = capture.at(Level::WARN, "aitm_ca");
    assert_eq!(warns.len(), 1, "{capture:?}");
    assert!(!warns[0]
        .fields
        .get("error")
        .is_some_and(|e| e.contains("canceled")));
}
