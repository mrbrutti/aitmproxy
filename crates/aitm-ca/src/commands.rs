//! The four `ca.*` commands (`export`, `status`, `install`, `uninstall`):
//! argument parsing, the fail-closed audit open, the `Frontend` policy gate,
//! and the store operation.
//!
//! `invoke` order for install/uninstall (spec §D8 "Command surface"): parse
//! args → open the audit log (failure ⇒ refuse) → policy gate → load `ca.crt`
//! → platform → scope → store op (through `DryRunExecutor` when `dry_run`) →
//! audit record → `tracing` → result. No subprocess runs before the gate
//! passes. `ca.export` has the same shape without the gate and platform
//! steps; `ca.status` is read-only and not audited.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aitm_core::{
    CaConfig, Command, CommandHost, Frontend, ParamDef, ParamSchema, Params, Plugin, Registry,
    TypeDesc, Value,
};
use anyhow::{anyhow, bail, Context as _};
use tracing::{info, warn};

use crate::audit::{now_rfc3339, AuditLog, AuditRecord, FileAuditLog};
use crate::cert::CaCert;
use crate::exec::{DryRunExecutor, Executor, RealExecutor};
use crate::store::{
    store_for, unsupported_message, LinuxFamily, Platform, Scope, TrustError, TrustErrorKind,
    DEBIAN_ANCHOR_DIR, FEDORA_ANCHOR_DIR,
};

/// On every `ca.status` answer and in every prompt: the embedded engine does
/// not look at the OS store.
const OBSCURA_DETAIL: &str = "the embedded browser (obscura) does not use the OS trust store; it \
                              trusts this CA through --ca-cert at launch";

/// The `ca.*` command family as a [`Plugin`]. Cheap to clone: everything it
/// holds is shared.
#[derive(Clone)]
pub struct CaPlugin {
    shared: Arc<Shared>,
}

/// What the four commands share.
struct Shared {
    cfg: CaConfig,
    exec: Arc<dyn Executor>,
    audit: Arc<dyn AuditLog>,
    /// `None`: detect the platform at each invocation.
    platform: Option<Platform>,
}

impl fmt::Debug for CaPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaPlugin")
            .field("cfg", &self.shared.cfg)
            .finish_non_exhaustive()
    }
}

impl CaPlugin {
    /// Real executor, file audit log at `cfg.audit_log`, platform detected
    /// at each invocation.
    pub fn new(cfg: CaConfig) -> Self {
        let audit = Arc::new(FileAuditLog::new(cfg.audit_log.clone()));
        Self {
            shared: Arc::new(Shared {
                cfg,
                exec: Arc::new(RealExecutor::new()),
                audit,
                platform: None,
            }),
        }
    }

    /// Injected executor, audit log and fixed platform (tests, and any host
    /// that wants to drive a foreign platform's logic).
    pub fn with_backend(
        cfg: CaConfig,
        exec: Arc<dyn Executor>,
        audit: Arc<dyn AuditLog>,
        platform: Platform,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                cfg,
                exec,
                audit,
                platform: Some(platform),
            }),
        }
    }
}

impl Plugin for CaPlugin {
    fn name(&self) -> &str {
        "ca"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(Export(self.shared.clone())));
        reg.add_command(Arc::new(Status(self.shared.clone())));
        reg.add_command(Arc::new(Change {
            shared: self.shared.clone(),
            op: Op::Install,
        }));
        reg.add_command(Arc::new(Change {
            shared: self.shared.clone(),
            op: Op::Uninstall,
        }));
    }
}

impl Shared {
    fn exec(&self) -> &dyn Executor {
        self.exec.as_ref()
    }

    fn platform(&self) -> Platform {
        self.platform
            .clone()
            .unwrap_or_else(|| Platform::detect(self.exec()))
    }

    fn cert_path(&self) -> PathBuf {
        self.cfg.dir.join("ca.crt")
    }

    /// Prove the audit log is writable before anything else happens.
    fn open_audit(&self) -> anyhow::Result<()> {
        self.audit.open().map_err(|e| {
            anyhow!(
                "audit log {} is not writable ({e:#}); refusing to change or export the CA until \
                 it is",
                self.cfg.audit_log.display()
            )
        })
    }

    /// `ca.crt`, or the `NoCertificate` error that tells the operator how
    /// to get one.
    fn load_cert(&self) -> anyhow::Result<CaCert> {
        match CaCert::load(&self.cfg.dir, self.exec())? {
            Some(cert) => Ok(cert),
            None => Err(TrustError::new(
                TrustErrorKind::NoCertificate,
                no_cert_message(&self.cert_path()),
            )
            .into()),
        }
    }

    /// Append one record and mirror it as `tracing::info!`.
    fn record(&self, rec: &AuditRecord) -> anyhow::Result<()> {
        self.audit.record(rec)?;
        info!(
            target: "aitm_ca::audit",
            command = rec.command,
            frontend = rec.frontend,
            outcome = rec.outcome,
            scope = rec.scope.as_deref().unwrap_or(""),
            platform = rec.platform.as_deref().unwrap_or(""),
            fingerprint_sha256 = rec.fingerprint_sha256.as_deref().unwrap_or(""),
            detail = rec.detail.as_str(),
            "ca audit"
        );
        Ok(())
    }
}

fn no_cert_message(path: &Path) -> String {
    format!(
        "no CA certificate at {}; start the proxy once (aitm) to generate it. If you ran this \
         under sudo, run it as your own user: aitm escalates only the trust-store commands.",
        path.display()
    )
}

/// The frontend as the audit log names it. A frontend that is not the human
/// CLI is agent-driven for every purpose here (the gated posture).
fn frontend_label(frontend: Frontend) -> &'static str {
    match frontend {
        Frontend::Cli => "cli",
        _ => "mcp",
    }
}

/// One invocation's audit identity, filled in as `invoke` learns more, so
/// every exit path records the same shape.
struct Audit<'a> {
    shared: &'a Shared,
    command: &'static str,
    frontend: &'static str,
    scope: Option<String>,
    platform: Option<String>,
    fingerprint_sha256: Option<String>,
}

impl Audit<'_> {
    fn record(&self, outcome: &'static str, detail: String) -> anyhow::Result<()> {
        self.shared.record(&AuditRecord {
            ts: now_rfc3339(),
            command: self.command,
            frontend: self.frontend,
            outcome,
            scope: self.scope.clone(),
            platform: self.platform.clone(),
            fingerprint_sha256: self.fingerprint_sha256.clone(),
            detail,
        })
    }

    /// Record `outcome` for an action that has happened. A record failure
    /// becomes the command's error, with the outcome still in its text.
    fn done(&self, outcome: &'static str, detail: String) -> anyhow::Result<()> {
        self.record(outcome, detail.clone()).map_err(|e| {
            anyhow!("{e:#}; the command completed ({detail}) but could not be recorded in the audit log")
        })
    }

    /// Record `error` and hand the error back for the caller to return.
    fn fail(&self, err: anyhow::Error) -> anyhow::Error {
        match self.record("error", format!("{err:#}")) {
            Ok(()) => err,
            Err(record_err) => err.context(format!("{record_err:#}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn opt_str<'a>(args: &'a Params, name: &str) -> anyhow::Result<Option<&'a str>> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Str(s)) => Ok(Some(s)),
        Some(other) => bail!("param `{name}` must be a string, got {other:?}"),
    }
}

fn opt_bool(args: &Params, name: &str) -> anyhow::Result<bool> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(other) => bail!("param `{name}` must be a boolean, got {other:?}"),
    }
}

fn param(name: &str, ty: TypeDesc, required: bool, description: &str) -> ParamDef {
    ParamDef {
        name: name.to_string(),
        ty,
        required,
        description: description.to_string(),
    }
}

fn schema(description: &str, params: Vec<ParamDef>, result: TypeDesc) -> ParamSchema {
    ParamSchema {
        description: description.to_string(),
        params,
        result,
    }
}

fn str_value(s: impl Into<String>) -> Value {
    Value::Str(s.into())
}

fn str_array(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::Str).collect())
}

fn opt_str_value(s: Option<String>) -> Value {
    s.map_or(Value::Null, Value::Str)
}

/// `std::fs::canonicalize`, or the path as given when it (or a parent) does
/// not exist yet.
fn canonical_or_self(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Architect's call C12: `ca.export --out` never writes into the CA
/// directory, so the `0700` dir keeps only key and cert. Compared both as
/// given and canonicalised; either match refuses.
fn refuse_inside_ca_dir(out: &Path, ca_dir: &Path) -> anyhow::Result<()> {
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let lexical = parent.starts_with(ca_dir);
    let canonical = canonical_or_self(&parent).starts_with(canonical_or_self(ca_dir));
    if lexical || canonical {
        bail!(
            "refusing to write into the CA directory {}",
            ca_dir.display()
        );
    }
    Ok(())
}

/// `path` with its parent canonicalised (the file itself need not exist
/// yet), so two spellings of one file compare equal.
fn canonical_file(path: &Path) -> PathBuf {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    match path.file_name() {
        Some(name) => canonical_or_self(&parent).join(name),
        None => canonical_or_self(path),
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    a == b || canonical_or_self(a) == canonical_or_self(b) || canonical_file(a) == canonical_file(b)
}

/// Every `out` that `ca.export` refuses, from any frontend: inside the CA
/// directory (C12), the audit log, and the config file beside it. Each is
/// compared by canonical path, so no spelling of the same file gets through;
/// an existing file at any other `out` is refused by [`write_new`].
fn refuse_protected_out(out: &Path, cfg: &CaConfig) -> anyhow::Result<()> {
    refuse_inside_ca_dir(out, &cfg.dir)?;
    let config_file = cfg.audit_log.with_file_name("config.yaml");
    for (protected, what) in [
        (cfg.audit_log.as_path(), "the CA audit log"),
        (config_file.as_path(), "the aitmproxy config file"),
    ] {
        if same_file(out, protected) {
            bail!("refusing to write to {}: it is {what}", out.display());
        }
    }
    Ok(())
}

/// Create `out` and write `bytes`. Never truncates: an existing file,
/// symlink or FIFO at `out` is refused, so `--out` cannot be turned on a
/// file the operator already has.
fn write_new(out: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = match std::fs::File::create_new(out) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => bail!(
            "refusing to write to {}: it already exists (ca.export never overwrites a file)",
            out.display()
        ),
        Err(e) => return Err(e).with_context(|| format!("creating {}", out.display())),
    };
    file.write_all(bytes)
        .with_context(|| format!("writing {}", out.display()))
}

/// Where a scope's store lives, before anything runs: the keychain path,
/// the anchor path, or the Windows store name — the same strings the stores
/// report as `location`. `None` when the platform has no store.
fn location_for(platform: &Platform, scope: Scope, exec: &dyn Executor) -> Option<String> {
    match (platform, scope) {
        (Platform::MacOs, Scope::System) => Some("/Library/Keychains/System.keychain".to_string()),
        (Platform::MacOs, Scope::User) => exec.home_dir().map(|home| {
            home.join("Library/Keychains/login.keychain-db")
                .display()
                .to_string()
        }),
        (Platform::Linux(LinuxFamily::Debian), _) => {
            Some(format!("{DEBIAN_ANCHOR_DIR}/aitmproxy-root-ca.crt"))
        }
        (Platform::Linux(LinuxFamily::Fedora), _) => {
            Some(format!("{FEDORA_ANCHOR_DIR}/aitmproxy-root-ca.pem"))
        }
        (Platform::Windows, Scope::User) => Some(r"CurrentUser\Root".to_string()),
        (Platform::Windows, Scope::System) => Some(r"LocalMachine\Root".to_string()),
        (Platform::Unsupported(_), _) => None,
    }
}

/// The `TrustErrorKind` behind an error, for the failure log line.
fn kind_name(err: &anyhow::Error) -> String {
    err.downcast_ref::<TrustError>()
        .map_or_else(|| "Other".to_string(), |e| format!("{:?}", e.kind))
}

// ---------------------------------------------------------------------------
// ca.export
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Pem,
    Der,
}

impl Format {
    fn parse(args: &Params) -> anyhow::Result<Self> {
        match opt_str(args, "format")? {
            None | Some("pem") => Ok(Format::Pem),
            Some("der") => Ok(Format::Der),
            Some(_) => bail!("format must be pem or der"),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Format::Pem => "pem",
            Format::Der => "der",
        }
    }
}

struct Export(Arc<Shared>);

impl Command for Export {
    fn name(&self) -> &str {
        "ca.export"
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Export the aitmproxy root CA certificate (never its key) as PEM or DER, with its \
             SHA-256 and SHA-1 fingerprints and the CA directory. Always available. This is for \
             TLS clients you bring yourself; the embedded obscura browser already trusts the CA \
             through --ca-cert and needs no export.",
            vec![
                param("format", TypeDesc::Str, false, "pem (default) or der."),
                param(
                    "out",
                    TypeDesc::Str,
                    false,
                    "Also write the certificate to this new file. Refused when the file \
                     already exists, lies inside the CA directory, or is the audit log or \
                     config file; a refusal is audited.",
                ),
            ],
            TypeDesc::Object(vec![
                param("format", TypeDesc::Str, true, "pem or der."),
                param(
                    "certificate",
                    TypeDesc::Any,
                    true,
                    "PEM text (string) or DER (bytes; base64 over MCP).",
                ),
                param(
                    "fingerprint_sha256",
                    TypeDesc::Str,
                    true,
                    "Colon-separated uppercase hex.",
                ),
                param(
                    "fingerprint_sha1",
                    TypeDesc::Str,
                    true,
                    "Colon-separated uppercase hex.",
                ),
                param("dir", TypeDesc::Str, true, "The CA directory."),
                param("path", TypeDesc::Str, true, "The certificate file."),
                param(
                    "written_to",
                    TypeDesc::Str,
                    false,
                    "The file written when `out` was given, else null.",
                ),
            ]),
        )
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let shared = &*self.0;
        let format = Format::parse(&args)?;
        let out = opt_str(&args, "out")?.map(PathBuf::from);

        shared.open_audit()?;
        let mut audit = Audit {
            shared,
            command: "ca.export",
            frontend: frontend_label(host.frontend()),
            scope: None,
            platform: None,
            fingerprint_sha256: None,
        };

        let cert = shared.load_cert().map_err(|e| audit.fail(e))?;
        audit.fingerprint_sha256 = Some(cert.fingerprint_sha256());

        let bytes: &[u8] = match format {
            Format::Pem => cert.pem.as_bytes(),
            Format::Der => &cert.der,
        };
        // `out` is checked only now, after the audit log is open and the
        // certificate is known, so a refusal is recorded with its fingerprint.
        if let Some(out) = &out {
            refuse_protected_out(out, &shared.cfg).map_err(|e| audit.fail(e))?;
            write_new(out, bytes).map_err(|e| audit.fail(e))?;
        }

        let written_to = out.map(|p| p.display().to_string());
        audit.done(
            "ok",
            format!(
                "format={} written_to={}",
                format.label(),
                written_to.as_deref().unwrap_or("")
            ),
        )?;
        info!(
            target: "aitm_ca",
            fingerprint_sha256 = cert.fingerprint_sha256().as_str(),
            format = format.label(),
            written_to = written_to.as_deref().unwrap_or(""),
            "root certificate exported"
        );

        let certificate = match format {
            Format::Pem => Value::Str(cert.pem.clone()),
            Format::Der => Value::Bytes(cert.der.clone()),
        };
        let mut fields = BTreeMap::new();
        fields.insert("format".to_string(), str_value(format.label()));
        fields.insert("certificate".to_string(), certificate);
        fields.insert(
            "fingerprint_sha256".to_string(),
            str_value(cert.fingerprint_sha256()),
        );
        fields.insert(
            "fingerprint_sha1".to_string(),
            str_value(cert.fingerprint_sha1()),
        );
        fields.insert(
            "dir".to_string(),
            str_value(shared.cfg.dir.display().to_string()),
        );
        fields.insert(
            "path".to_string(),
            str_value(cert.path.display().to_string()),
        );
        fields.insert("written_to".to_string(), opt_str_value(written_to));
        Ok(Value::Object(fields))
    }
}

// ---------------------------------------------------------------------------
// ca.status
// ---------------------------------------------------------------------------

struct Status(Arc<Shared>);

impl Command for Status {
    fn name(&self) -> &str {
        "ca.status"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Report the aitmproxy root CA: whether ca.crt exists, its fingerprints and path, \
             and, per trust-store scope on this platform, whether a certificate with its \
             fingerprint is installed and trusted. Read-only, always available, not audited. \
             The embedded obscura browser does not use the OS store (it trusts the CA through \
             --ca-cert), so these fields say nothing about it.",
            vec![],
            TypeDesc::Object(vec![
                param("exists", TypeDesc::Bool, true, "Whether ca.crt exists."),
                param("dir", TypeDesc::Str, true, "The CA directory."),
                param("path", TypeDesc::Str, true, "The certificate file."),
                param(
                    "fingerprint_sha256",
                    TypeDesc::Str,
                    false,
                    "Colon-separated uppercase hex; null when there is no certificate.",
                ),
                param(
                    "fingerprint_sha1",
                    TypeDesc::Str,
                    false,
                    "Colon-separated uppercase hex; null when there is no certificate.",
                ),
                param(
                    "platform",
                    TypeDesc::Str,
                    true,
                    "macos | linux-debian | linux-fedora | windows | unsupported.",
                ),
                param(
                    "stores",
                    TypeDesc::Map(Box::new(TypeDesc::Object(vec![
                        param(
                            "installed",
                            TypeDesc::Str,
                            true,
                            "present | absent | stale | unknown.",
                        ),
                        param("trusted", TypeDesc::Str, true, "yes | no | unknown."),
                        param(
                            "location",
                            TypeDesc::Str,
                            true,
                            "The keychain, anchor file, or store.",
                        ),
                    ]))),
                    true,
                    "One entry per scope (user, system); empty without a certificate or on an \
                     unsupported platform.",
                ),
                param(
                    "detail",
                    TypeDesc::Array(Box::new(TypeDesc::Str)),
                    true,
                    "What was and was not verified.",
                ),
            ]),
        )
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        let shared = &*self.0;
        let path = shared.cert_path();
        let cert = CaCert::load(&shared.cfg.dir, shared.exec())?;
        let platform = shared.platform();

        let mut stores = BTreeMap::new();
        let mut detail: Vec<String> = Vec::new();
        match (&cert, &platform) {
            (None, _) => detail.push(no_cert_message(&path)),
            (Some(cert), Platform::Unsupported(os)) => {
                detail.push(unsupported_message(os, &cert.path));
            }
            (Some(cert), _) => {
                let store = store_for(&platform);
                for scope in platform.scopes() {
                    let st = store.status(cert, *scope, shared.exec())?;
                    let mut entry = BTreeMap::new();
                    entry.insert("installed".to_string(), str_value(st.installed.label()));
                    entry.insert("trusted".to_string(), str_value(st.trusted.label()));
                    entry.insert("location".to_string(), str_value(st.location));
                    stores.insert(scope.label().to_string(), Value::Object(entry));
                    for line in st.detail {
                        if !detail.contains(&line) {
                            detail.push(line);
                        }
                    }
                }
            }
        }
        detail.push(OBSCURA_DETAIL.to_string());

        let mut fields = BTreeMap::new();
        fields.insert("exists".to_string(), Value::Bool(cert.is_some()));
        fields.insert(
            "dir".to_string(),
            str_value(shared.cfg.dir.display().to_string()),
        );
        fields.insert("path".to_string(), str_value(path.display().to_string()));
        fields.insert(
            "fingerprint_sha256".to_string(),
            opt_str_value(cert.as_ref().map(CaCert::fingerprint_sha256)),
        );
        fields.insert(
            "fingerprint_sha1".to_string(),
            opt_str_value(cert.as_ref().map(CaCert::fingerprint_sha1)),
        );
        fields.insert("platform".to_string(), str_value(platform.label()));
        fields.insert("stores".to_string(), Value::Object(stores));
        fields.insert("detail".to_string(), str_array(&detail));
        Ok(Value::Object(fields))
    }
}

// ---------------------------------------------------------------------------
// ca.install / ca.uninstall
// ---------------------------------------------------------------------------

/// Which way the trust store changes. The two commands differ only here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Install,
    Uninstall,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Install => "ca.install",
            Op::Uninstall => "ca.uninstall",
        }
    }

    /// The `aitm ca <verb>` the refusal points at.
    fn verb(self) -> &'static str {
        match self {
            Op::Install => "install",
            Op::Uninstall => "uninstall",
        }
    }

    /// Spec §D8 "Policy gate", exact.
    fn refusal(self) -> String {
        let name = self.name();
        format!(
            "{name} refused: changing the OS trust store from an agent frontend is disabled. Set \
             ca.allow_agent_install = true in the aitmproxy config (or \
             AITM_CA_ALLOW_AGENT_INSTALL=1 in the environment) to allow it, or run `aitm ca {}` \
             yourself from a shell. {name} with dry_run=true is always allowed.",
            self.verb()
        )
    }

    fn description(self) -> String {
        let (what, effect) = match self {
            Op::Install => (
                "Install the aitmproxy root CA into the OS trust store",
                "every TLS client that uses that store will then trust certificates this proxy \
                 mints",
            ),
            Op::Uninstall => (
                "Remove the aitmproxy root CA from the OS trust store",
                "TLS clients that use that store stop trusting certificates this proxy mints",
            ),
        };
        format!(
            "{what} (macOS keychain via `security`, Linux ca-certificates anchors, Windows Root \
             store via certutil); {effect}. Idempotent; identifies the certificate by \
             fingerprint; never reads the CA key. Refused from an agent frontend (MCP) unless \
             ca.allow_agent_install is set in the aitmproxy config; dry_run is always allowed \
             and lists the commands that would run. The embedded obscura browser does not use \
             the OS store (it trusts the CA through --ca-cert) and is unaffected."
        )
    }

    fn prompt(self, fingerprint: &str, location: &str, scope: Scope) -> String {
        match self {
            Op::Install => format!(
                "Install the aitmproxy root CA (SHA-256 {fingerprint}) into {location} (scope \
                 {scope})? Every TLS client that uses that store will then trust certificates \
                 this proxy mints. (The embedded obscura browser is unaffected; it trusts the CA \
                 via --ca-cert.)"
            ),
            Op::Uninstall => format!(
                "Remove the aitmproxy root CA (SHA-256 {fingerprint}) from {location} (scope \
                 {scope})?"
            ),
        }
    }
}

/// Parsed `scope` / `dry_run`.
struct ChangeArgs {
    scope: Option<Scope>,
    dry_run: bool,
}

impl ChangeArgs {
    fn parse(args: &Params) -> anyhow::Result<Self> {
        let scope = match opt_str(args, "scope")? {
            Some(s) => Some(s.parse::<Scope>()?),
            None => None,
        };
        Ok(Self {
            scope,
            dry_run: opt_bool(args, "dry_run")?,
        })
    }
}

struct Change {
    shared: Arc<Shared>,
    op: Op,
}

impl Change {
    /// The scope to act on: the one asked for if the platform has it, else
    /// the platform's least-privileged one.
    fn resolve_scope(platform: &Platform, wanted: Option<Scope>) -> Result<Scope, TrustError> {
        match wanted {
            Some(scope) if platform.scopes().contains(&scope) => Ok(scope),
            Some(scope) => Err(TrustError::new(
                TrustErrorKind::UnsupportedScope,
                match platform {
                    Platform::Linux(_) => {
                        "Linux has no per-user OS trust store; use --scope system".to_string()
                    }
                    other => format!(
                        "scope {scope} is not available on {}; use one of {}",
                        other.label(),
                        other
                            .scopes()
                            .iter()
                            .map(Scope::label)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                },
            )),
            None => platform.default_scope().ok_or_else(|| {
                TrustError::new(
                    TrustErrorKind::UnsupportedPlatform,
                    format!("no trust store on {}", platform.label()),
                )
            }),
        }
    }
}

impl Command for Change {
    fn name(&self) -> &str {
        self.op.name()
    }

    fn sensitivity(&self) -> aitm_core::Sensitivity {
        // Both `ca.install` and `ca.uninstall` touch the OS trust store.
        aitm_core::Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        schema(
            &self.op.description(),
            vec![
                param(
                    "scope",
                    TypeDesc::Str,
                    false,
                    "user | system. Default: user on macOS and Windows, system on Linux.",
                ),
                param(
                    "dry_run",
                    TypeDesc::Bool,
                    false,
                    "Run the read-only queries and list the mutating commands without running \
                     them. Never gated.",
                ),
            ],
            TypeDesc::Object(vec![
                param(
                    "changed",
                    TypeDesc::Bool,
                    true,
                    "Whether the store changed (or, with dry_run, would change).",
                ),
                param("dry_run", TypeDesc::Bool, true, "Echo of the argument."),
                param("scope", TypeDesc::Str, true, "user | system."),
                param(
                    "platform",
                    TypeDesc::Str,
                    true,
                    "macos | linux-debian | linux-fedora | windows.",
                ),
                param(
                    "location",
                    TypeDesc::Str,
                    true,
                    "The keychain, anchor file, or store acted on.",
                ),
                param(
                    "fingerprint_sha256",
                    TypeDesc::Str,
                    true,
                    "Colon-separated uppercase hex.",
                ),
                param(
                    "commands",
                    TypeDesc::Array(Box::new(TypeDesc::Str)),
                    true,
                    "Every command line run, in order, queries included (with dry_run: the \
                     mutating lines that would have run).",
                ),
                param(
                    "detail",
                    TypeDesc::Array(Box::new(TypeDesc::Str)),
                    true,
                    "What happened, in words.",
                ),
            ]),
        )
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let shared = &*self.shared;
        let op = self.op;
        let args = ChangeArgs::parse(&args)?;

        shared.open_audit()?;

        let frontend = host.frontend();
        let mut audit = Audit {
            shared,
            command: op.name(),
            frontend: frontend_label(frontend),
            scope: args.scope.map(|s| s.label().to_string()),
            platform: shared.platform.as_ref().map(|p| p.label().to_string()),
            fingerprint_sha256: None,
        };

        // The policy gate. Nothing runs on the host before it passes; the
        // fingerprint for the record comes from ca.crt alone.
        if frontend != Frontend::Cli && !args.dry_run && !shared.cfg.allow_agent_install {
            audit.fingerprint_sha256 = CaCert::load(&shared.cfg.dir, shared.exec())
                .ok()
                .flatten()
                .map(|c| c.fingerprint_sha256());
            let refusal = op.refusal();
            audit.record("refused", refusal.clone())?;
            warn!(
                target: "aitm_ca",
                command = op.name(),
                frontend = audit.frontend,
                setting = "ca.allow_agent_install",
                "refused: agent-driven trust-store change is disabled"
            );
            return Err(anyhow!(refusal));
        }

        let cert = shared.load_cert().map_err(|e| audit.fail(e))?;
        let fingerprint = cert.fingerprint_sha256();
        audit.fingerprint_sha256 = Some(fingerprint.clone());

        let platform = shared.platform();
        audit.platform = Some(platform.label().to_string());
        if let Platform::Unsupported(os) = &platform {
            return Err(audit.fail(
                TrustError::new(
                    TrustErrorKind::UnsupportedPlatform,
                    unsupported_message(os, &cert.path),
                )
                .into(),
            ));
        }

        let scope = Self::resolve_scope(&platform, args.scope).map_err(|e| audit.fail(e.into()))?;
        audit.scope = Some(scope.label().to_string());

        let store = store_for(&platform);
        let apply = |exec: &dyn Executor| match op {
            Op::Install => store.install(&cert, scope, exec),
            Op::Uninstall => store.uninstall(&cert, scope, exec),
        };
        let result = if args.dry_run {
            apply(&DryRunExecutor::new(shared.exec()))
        } else {
            apply(shared.exec())
        };
        let change = match result {
            Ok(change) => change,
            Err(err) => {
                warn!(
                    target: "aitm_ca",
                    command = op.name(),
                    fingerprint_sha256 = fingerprint.as_str(),
                    scope = scope.label(),
                    platform = platform.label(),
                    kind = kind_name(&err).as_str(),
                    error = format!("{err:#}").as_str(),
                    "OS trust store change failed"
                );
                return Err(audit.fail(err));
            }
        };

        let outcome = if args.dry_run { "dry_run" } else { "ok" };
        audit.done(outcome, format!("changed={}", change.changed))?;

        let message = if args.dry_run {
            "dry run: no changes made"
        } else if change.changed {
            "OS trust store updated"
        } else {
            "OS trust store already in the requested state"
        };
        info!(
            target: "aitm_ca",
            command = op.name(),
            fingerprint_sha256 = fingerprint.as_str(),
            scope = scope.label(),
            platform = platform.label(),
            frontend = audit.frontend,
            changed = change.changed,
            dry_run = args.dry_run,
            "{message}"
        );

        let mut fields = BTreeMap::new();
        fields.insert("changed".to_string(), Value::Bool(change.changed));
        fields.insert("dry_run".to_string(), Value::Bool(args.dry_run));
        fields.insert("scope".to_string(), str_value(scope.label()));
        fields.insert("platform".to_string(), str_value(platform.label()));
        fields.insert("location".to_string(), str_value(change.location));
        fields.insert("fingerprint_sha256".to_string(), str_value(fingerprint));
        fields.insert("commands".to_string(), str_array(&change.commands));
        fields.insert("detail".to_string(), str_array(&change.detail));
        Ok(Value::Object(fields))
    }

    /// The question a human frontend asks first. `None` for a dry run, when
    /// there is no `ca.crt`, or when `invoke` would fail on the platform or
    /// scope anyway (it then fails with the clear error). Reads `ca.crt`
    /// only; runs nothing.
    fn confirm_prompt(&self, args: &Params) -> Option<String> {
        let shared = &*self.shared;
        let args = ChangeArgs::parse(args).ok()?;
        if args.dry_run {
            return None;
        }
        let cert = CaCert::load(&shared.cfg.dir, shared.exec()).ok()??;
        let platform = shared.platform();
        let scope = Self::resolve_scope(&platform, args.scope).ok()?;
        let location = location_for(&platform, scope, shared.exec())?;
        Some(self.op.prompt(&cert.fingerprint_sha256(), &location, scope))
    }
}
