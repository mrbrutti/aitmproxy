//! CA-AC29 — the real-OS round trip: install → status `present` →
//! uninstall → status `absent` against this host's actual trust store, with
//! a throwaway CA and `CaPlugin::new` (real executor, file audit log).
//!
//! Never part of the default suite: every test is `#[ignore]`d **and**
//! returns early unless `AITM_REAL_OS_TESTS=1`. Run by hand (Task 30):
//!
//! ```text
//! AITM_REAL_OS_TESTS=1 cargo test -p aitm-ca --test real_os -- --ignored --nocapture
//! ```
//!
//! On macOS the user-scope install pops the keychain authorization dialog;
//! on Linux every mutation goes through `sudo`.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use aitm_ca::exec::RealExecutor;
// `Executor`'s trait methods (`run`, `home_dir`) are called only by the
// macOS-gated test below, so the import is unused on Linux (`-D warnings`).
#[cfg(target_os = "macos")]
use aitm_ca::exec::Executor;
use aitm_ca::store::Platform;
use aitm_ca::CaPlugin;
use aitm_core::{
    CaConfig, CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient,
    Registry, StdGuard, Value,
};

const FIXTURE: &[u8] = include_bytes!("fixtures/ca.crt");

fn enabled() -> bool {
    std::env::var("AITM_REAL_OS_TESTS").map(|v| v == "1") == Ok(true)
}

struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A throwaway CA directory (fixture `ca.crt` only) and an audit log beside
/// it, driven through the real plugin from the human CLI.
struct RealHarness {
    base: PathBuf,
    // Read only by the macOS-gated test (macos_round_trip); dead on Linux.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    cert_path: PathBuf,
    audit_path: PathBuf,
    reg: Registry,
    store: MemFlowStore,
    guard: StdGuard,
    client: StubClient,
}

impl RealHarness {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!("aitm-ca-real-os-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let dir = base.join("ca");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ca.crt"), FIXTURE).unwrap();
        let audit_path = base.join("ca-audit.jsonl");
        let cfg = CaConfig {
            dir: dir.clone(),
            allow_agent_install: false,
            audit_log: audit_path.clone(),
            ..CaConfig::default()
        };
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(CaPlugin::new(cfg)));
        Self {
            base,
            cert_path: dir.join("ca.crt"),
            audit_path,
            reg,
            store: MemFlowStore::new(),
            guard: StdGuard::default(),
            client: StubClient,
        }
    }

    fn call(&self, name: &str) -> Value {
        let host = CommandHost::new(&self.store, &self.client, &self.guard, None)
            .with_frontend(Frontend::Cli);
        let out = self
            .reg
            .command(name)
            .unwrap()
            .invoke(Params::default(), &host);
        eprintln!("{name} -> {out:?}");
        out.unwrap_or_else(|e| panic!("{name} failed: {e:#}"))
    }

    /// `stores.<default scope>.installed` from `ca.status`.
    fn installed(&self, scope: &str) -> String {
        let status = self.call("ca.status");
        let Value::Object(fields) = &status else {
            panic!("status is not an object: {status:?}");
        };
        let Some(Value::Object(stores)) = fields.get("stores") else {
            panic!("no stores: {status:?}");
        };
        let Some(Value::Object(store)) = stores.get(scope) else {
            panic!("no {scope} store: {status:?}");
        };
        match store.get("installed") {
            Some(Value::Str(s)) => s.clone(),
            other => panic!("installed is {other:?}"),
        }
    }

    fn audit_lines(&self) -> Vec<String> {
        fs::read_to_string(&self.audit_path)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

impl Drop for RealHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// install → present → (platform extra) → uninstall → absent, then the audit
/// log holds one line per mutation (status is read-only and not recorded).
fn round_trip(between: impl FnOnce(&RealHarness)) {
    let exec = RealExecutor::new();
    let platform = Platform::detect(&exec);
    let scope = platform
        .default_scope()
        .unwrap_or_else(|| panic!("no default scope on {platform:?}"))
        .label();
    eprintln!("platform {platform:?}, scope {scope}");

    let h = RealHarness::new();
    h.call("ca.install");
    assert_eq!(h.installed(scope), "present");
    between(&h);
    h.call("ca.uninstall");
    assert_eq!(h.installed(scope), "absent");

    let lines = h.audit_lines();
    eprintln!("audit log:\n{}", lines.join("\n"));
    assert_eq!(
        lines.len(),
        2,
        "one record per mutation; status is not recorded"
    );
    assert!(
        lines[0].contains("\"command\":\"ca.install\""),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].contains("\"command\":\"ca.uninstall\""),
        "{}",
        lines[1]
    );
    for line in &lines {
        assert!(line.contains("\"outcome\":\"ok\""), "{line}");
        assert!(!line.contains("BEGIN CERTIFICATE"), "{line}");
    }
}

/// C8: what a second, direct `add-trusted-cert` does on this macOS is
/// unverified (research Q1); record it rather than assert it.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "real OS trust store; set AITM_REAL_OS_TESTS=1 and run with --ignored"]
fn macos_round_trip() {
    if !enabled() {
        eprintln!("AITM_REAL_OS_TESTS is not 1; skipping");
        return;
    }
    round_trip(|h| {
        let exec = RealExecutor::new();
        let keychain = exec
            .home_dir()
            .expect("home dir")
            .join("Library/Keychains/login.keychain-db")
            .display()
            .to_string();
        let again = aitm_ca::exec::CmdLine {
            program: "security".to_string(),
            args: [
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-p",
                "ssl",
                "-p",
                "basic",
                "-k",
                &keychain,
                &h.cert_path.display().to_string(),
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            stdin: None,
            mutating: true,
        };
        let out = exec.run(&again).expect("security starts");
        println!(
            "C8: second direct `{}` exited {:?}\nstdout: {}\nstderr: {}",
            again.render(),
            out.code,
            out.stdout,
            out.stderr
        );
    });
}

/// C10: `update-ca-certificates --fresh` must leave no dangling bundle link.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "real OS trust store; set AITM_REAL_OS_TESTS=1 and run with --ignored"]
fn linux_round_trip() {
    if !enabled() {
        eprintln!("AITM_REAL_OS_TESTS is not 1; skipping");
        return;
    }
    round_trip(|_| {});
    let exec = RealExecutor::new();
    if let Platform::Linux(aitm_ca::store::LinuxFamily::Debian) = Platform::detect(&exec) {
        let link = std::path::Path::new("/etc/ssl/certs/aitmproxy-root-ca.pem");
        assert!(
            !link.exists() && fs::symlink_metadata(link).is_err(),
            "{} remains after uninstall",
            link.display()
        );
    }
}
