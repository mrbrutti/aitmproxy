//! Task 16 — the four `ca.*` commands as a frontend sees them: `CaPlugin`
//! registered in a `Registry`, invoked through a `CommandHost` that declares
//! its `Frontend`, against a scripted executor, an in-memory audit log and a
//! fixed macOS platform. Nothing here touches a real trust store.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, ThreadId};

use aitm_ca::audit::AuditRecord;
use aitm_ca::store::Platform;
use aitm_ca::testing::{MemoryAuditLog, ScriptedExecutor, FIXTURE_FP1, FIXTURE_FP256};
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
    fn new(cfg: CaConfig, exec: ScriptedExecutor, audit: MemoryAuditLog) -> Self {
        let exec = Arc::new(exec);
        let audit = Arc::new(audit);
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(CaPlugin::with_backend(
            cfg,
            exec.clone(),
            audit.clone(),
            Platform::MacOs,
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

    // PEM to a file: byte-identical to ca.crt. Truncates what was there.
    let out = out_dir.join("root.pem");
    fs::write(
        &out,
        b"stale contents much longer than the certificate itself will be\n".repeat(40),
    )
    .unwrap();
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

    for inside in ["/ca/copy.pem", "/ca/sub/copy.pem", "/ca/./copy.pem"] {
        let e = err_text(h.call("ca.export", Frontend::Cli, &[("out", str_arg(inside))]));
        assert!(
            e.contains("refusing to write into the CA directory"),
            "{inside}: got: {e}"
        );
        assert!(e.contains("/ca"), "{inside}: got: {e}");
    }
    // Argument refusals happen before anything else: nothing was recorded.
    assert!(h.records().is_empty(), "{:?}", h.records());

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
