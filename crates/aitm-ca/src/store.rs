//! Platform model: `Platform`, `Scope`, `Presence`, `Trust`, `StoreStatus`,
//! `Change`, the `TrustStore` trait, `TrustError`, and `store_for`.
//!
//! Every store implementation is a plain function of `(cert, scope, exec)`
//! and compiles on every host; only [`Platform::detect`] asks what the host
//! is. That is how a macOS developer unit-tests the Linux and Windows
//! stores: construct one and drive it with a scripted executor.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use crate::cert::CaCert;
use crate::exec::Executor;
use crate::platform::linux::LinuxStore;
use crate::platform::macos::MacOsStore;
use crate::platform::windows::WindowsStore;

/// Which trust store an operation targets: the invoking user's, or the
/// machine's (which needs root or an administrator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    User,
    System,
}

impl Scope {
    /// `"user"` | `"system"` — the wire form and the `--scope` value.
    pub fn label(&self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::System => "system",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for Scope {
    type Err = TrustError;

    /// Exactly `"user"` or `"system"`, lowercase.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(Scope::User),
            "system" => Ok(Scope::System),
            other => Err(TrustError::new(
                TrustErrorKind::UnsupportedScope,
                format!("scope must be user or system, got {other:?}"),
            )),
        }
    }
}

/// The two Linux trust-store layouts aitmproxy knows how to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinuxFamily {
    /// `/usr/local/share/ca-certificates` + `update-ca-certificates`.
    Debian,
    /// `/etc/pki/ca-trust/source/anchors` + `update-ca-trust extract`.
    Fedora,
}

/// Anchor directory whose existence marks a Fedora-family host.
pub const FEDORA_ANCHOR_DIR: &str = "/etc/pki/ca-trust/source/anchors";
/// Anchor directory whose existence marks a Debian-family host.
pub const DEBIAN_ANCHOR_DIR: &str = "/usr/local/share/ca-certificates";

/// The host, as far as trust-store integration is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux(LinuxFamily),
    Windows,
    /// An OS, or a Linux without a known anchor directory, that we have no
    /// integration for; holds the OS name (`"linux"`, `"freebsd"`, …).
    Unsupported(String),
}

impl Platform {
    /// `cfg!(target_os)` picks the OS; on Linux [`detect_linux_family`]
    /// picks the family.
    pub fn detect(exec: &dyn Executor) -> Platform {
        let os = if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            std::env::consts::OS
        };
        Self::detect_with_os(os, exec)
    }

    /// [`Self::detect`] with the OS name supplied, so a test on one host
    /// can exercise another host's branch (the Linux family lookup above
    /// all).
    pub fn detect_with_os(os: &str, exec: &dyn Executor) -> Platform {
        match os {
            "macos" => Platform::MacOs,
            "windows" => Platform::Windows,
            "linux" => detect_linux_family(exec)
                .map(Platform::Linux)
                .unwrap_or_else(|| Platform::Unsupported("linux".to_string())),
            other => Platform::Unsupported(other.to_string()),
        }
    }

    /// `"macos"` | `"linux-debian"` | `"linux-fedora"` | `"windows"` |
    /// `"unsupported"`.
    pub fn label(&self) -> &'static str {
        match self {
            Platform::MacOs => "macos",
            Platform::Linux(LinuxFamily::Debian) => "linux-debian",
            Platform::Linux(LinuxFamily::Fedora) => "linux-fedora",
            Platform::Windows => "windows",
            Platform::Unsupported(_) => "unsupported",
        }
    }

    /// The scopes this platform has, least privileged first.
    pub fn scopes(&self) -> &'static [Scope] {
        match self {
            Platform::MacOs | Platform::Windows => &[Scope::User, Scope::System],
            // Linux has no per-user OS trust store.
            Platform::Linux(_) => &[Scope::System],
            Platform::Unsupported(_) => &[],
        }
    }

    /// The least-privileged scope: `User` on macOS and Windows, `System`
    /// on Linux, none when unsupported.
    pub fn default_scope(&self) -> Option<Scope> {
        self.scopes().first().copied()
    }
}

/// Which Linux family the host is: directory existence first, `os-release`
/// as the tie-break (Architect's call C6). `None` when neither anchor
/// directory exists, which makes the host `Unsupported("linux")`.
pub fn detect_linux_family(exec: &dyn Executor) -> Option<LinuxFamily> {
    let fedora = exec.dir_exists(Path::new(FEDORA_ANCHOR_DIR));
    let debian = exec.dir_exists(Path::new(DEBIAN_ANCHOR_DIR));
    match (fedora, debian) {
        (false, false) => None,
        (true, false) => Some(LinuxFamily::Fedora),
        (false, true) => Some(LinuxFamily::Debian),
        (true, true) => Some(os_release_family(exec)),
    }
}

/// Both anchor directories exist: ask `os-release`. The first file that
/// exists decides; with none, Fedora (first in mkcert's order).
fn os_release_family(exec: &dyn Executor) -> LinuxFamily {
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(Some(bytes)) = exec.read_file(Path::new(path)) {
            return family_from_os_release(&String::from_utf8_lossy(&bytes));
        }
    }
    LinuxFamily::Fedora
}

/// The space-separated tokens of `ID` and `ID_LIKE`, lowercased and
/// unquoted: any of `debian`, `ubuntu` → Debian; `fedora`, `rhel`,
/// `centos` — or anything else — → Fedora.
fn family_from_os_release(text: &str) -> LinuxFamily {
    let debian = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| matches!(key.trim(), "ID" | "ID_LIKE"))
        .flat_map(|(_, value)| value.trim().trim_matches('"').split_whitespace())
        .map(|token| token.trim_matches('"').to_ascii_lowercase())
        .any(|token| token == "debian" || token == "ubuntu");
    if debian {
        LinuxFamily::Debian
    } else {
        LinuxFamily::Fedora
    }
}

/// Whether a certificate with our fingerprint is in a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presence {
    Present,
    Absent,
    /// Our anchor file exists but holds a different certificate (Linux).
    Stale,
    /// Could not determine.
    Unknown,
}

impl Presence {
    pub fn label(&self) -> &'static str {
        match self {
            Presence::Present => "present",
            Presence::Absent => "absent",
            Presence::Stale => "stale",
            Presence::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Presence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Whether the store actually trusts it — separate from [`Presence`]
/// because presence and trust differ by platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trust {
    Yes,
    No,
    Unknown,
}

impl Trust {
    pub fn label(&self) -> &'static str {
        match self {
            Trust::Yes => "yes",
            Trust::No => "no",
            Trust::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Trust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What one scope's store says about the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreStatus {
    pub scope: Scope,
    /// The keychain, anchor file, or store name the answer is about.
    pub location: String,
    pub installed: Presence,
    pub trusted: Trust,
    /// Human-readable caveats (what was and was not verified).
    pub detail: Vec<String>,
}

/// What an install or uninstall did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub changed: bool,
    pub scope: Scope,
    pub location: String,
    /// Every command line that ran, rendered, in order.
    pub commands: Vec<String>,
    pub detail: Vec<String>,
}

/// One platform's trust store. All effects go through `exec`.
pub trait TrustStore: Send + Sync {
    fn platform(&self) -> &Platform;
    fn status(
        &self,
        cert: &CaCert,
        scope: Scope,
        exec: &dyn Executor,
    ) -> anyhow::Result<StoreStatus>;
    fn install(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor) -> anyhow::Result<Change>;
    fn uninstall(&self, cert: &CaCert, scope: Scope, exec: &dyn Executor)
        -> anyhow::Result<Change>;
}

/// The store for a platform we have no integration for: every operation
/// fails with [`TrustErrorKind::UnsupportedPlatform`] and a message that
/// names the OS and the way out. Holds the OS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedStore(pub String);

/// `UnsupportedStore` holds only the OS name, so `platform()` hands back
/// this nameless `Unsupported`; its `label()` is the same `"unsupported"`,
/// and the name itself is in `.0` and in every error message.
static UNSUPPORTED: Platform = Platform::Unsupported(String::new());

impl UnsupportedStore {
    fn refuse(&self, cert: &CaCert) -> anyhow::Error {
        TrustError::new(
            TrustErrorKind::UnsupportedPlatform,
            unsupported_message(&self.0, &cert.path),
        )
        .into()
    }
}

/// The text `ca.status` shows and `ca.install`/`ca.uninstall` fail with on
/// an unsupported host. A Linux with neither anchor directory gets the
/// directory-specific hint.
pub fn unsupported_message(os: &str, cert_path: &Path) -> String {
    if os == "linux" {
        format!(
            "no supported trust-store directory found (looked for {FEDORA_ANCHOR_DIR} and \
             {DEBIAN_ANCHOR_DIR}); install the ca-certificates package, or install {} by hand",
            cert_path.display()
        )
    } else {
        format!(
            "no OS trust-store integration for {os}; export the certificate with aitm ca export \
             and install it by hand"
        )
    }
}

impl TrustStore for UnsupportedStore {
    fn platform(&self) -> &Platform {
        &UNSUPPORTED
    }

    fn status(
        &self,
        cert: &CaCert,
        _scope: Scope,
        _exec: &dyn Executor,
    ) -> anyhow::Result<StoreStatus> {
        Err(self.refuse(cert))
    }

    fn install(
        &self,
        cert: &CaCert,
        _scope: Scope,
        _exec: &dyn Executor,
    ) -> anyhow::Result<Change> {
        Err(self.refuse(cert))
    }

    fn uninstall(
        &self,
        cert: &CaCert,
        _scope: Scope,
        _exec: &dyn Executor,
    ) -> anyhow::Result<Change> {
        Err(self.refuse(cert))
    }
}

/// The store that drives `platform`.
pub fn store_for(platform: &Platform) -> Box<dyn TrustStore> {
    match platform {
        Platform::MacOs => Box::new(MacOsStore),
        Platform::Linux(family) => Box::new(LinuxStore(*family)),
        Platform::Windows => Box::new(WindowsStore),
        Platform::Unsupported(os) => Box::new(UnsupportedStore(os.clone())),
    }
}

/// What every trust store on `platform` says about `cert`, one
/// [`StoreStatus`] per scope in [`Platform::scopes`] order (least privileged
/// first); empty on an unsupported platform, which has no scopes. The one
/// code path behind `ca.status` and the CLI's `checking CA trust` phase, so
/// the two can never disagree on the word (CLI terminal reporting plan C16).
/// Blocking: every store shells out to the OS tools through `exec`.
pub fn trust_statuses(
    cert: &CaCert,
    platform: &Platform,
    exec: &dyn Executor,
) -> anyhow::Result<Vec<StoreStatus>> {
    let store = store_for(platform);
    platform
        .scopes()
        .iter()
        .map(|scope| store.status(cert, *scope, exec))
        .collect()
}

/// Why a store operation failed; the message carries the user-facing hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustErrorKind {
    UnsupportedPlatform,
    UnsupportedScope,
    NoCertificate,
    NeedsRoot,
    HeadlessAuth,
    /// The OS authentication dialog was dismissed (macOS, spec D17.4).
    Cancelled,
    ToolMissing,
    ToolFailed,
    Timeout,
    CopiesRemain,
}

impl TrustErrorKind {
    /// The word the audit record and the failure log line carry: the
    /// variant name, except `Cancelled`, which is `"cancelled"` (spec D17.4,
    /// the word every frontend keys on).
    pub fn label(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "UnsupportedPlatform",
            Self::UnsupportedScope => "UnsupportedScope",
            Self::NoCertificate => "NoCertificate",
            Self::NeedsRoot => "NeedsRoot",
            Self::HeadlessAuth => "HeadlessAuth",
            Self::Cancelled => "cancelled",
            Self::ToolMissing => "ToolMissing",
            Self::ToolFailed => "ToolFailed",
            Self::Timeout => "Timeout",
            Self::CopiesRemain => "CopiesRemain",
        }
    }
}

/// A store operation's failure. `Display` is the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustError {
    pub kind: TrustErrorKind,
    pub message: String,
}

impl TrustError {
    pub fn new(kind: TrustErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TrustError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::ScriptedExecutor;
    use std::path::PathBuf;

    /// A certificate by value: `trust_statuses` never reads it from disk.
    fn cert() -> CaCert {
        CaCert {
            path: PathBuf::from("/ca/ca.crt"),
            pem: String::new(),
            der: Vec::new(),
            sha256: [0; 32],
            sha1: [0; 20],
        }
    }

    #[test]
    fn trust_statuses_on_an_unsupported_platform_is_empty() {
        let exec = ScriptedExecutor::new();
        let got =
            trust_statuses(&cert(), &Platform::Unsupported("plan9".to_string()), &exec).unwrap();
        assert_eq!(got, Vec::<StoreStatus>::new());
        assert!(exec.runs().is_empty(), "ran {:?}", exec.runs());
        assert!(exec.reads().is_empty(), "read {:?}", exec.reads());
    }

    #[test]
    fn trust_statuses_visits_every_scope_in_platform_order() {
        // macOS has two scopes, user first (`Platform::scopes`); the scripted
        // host answers every `security` query with exit 0 and no output, so
        // each store reports the certificate absent.
        let exec = ScriptedExecutor::new();
        let got = trust_statuses(&cert(), &Platform::MacOs, &exec).unwrap();
        let scopes: Vec<Scope> = got.iter().map(|s| s.scope).collect();
        assert_eq!(scopes, vec![Scope::User, Scope::System]);
        assert!(got.iter().all(|s| s.trusted == Trust::No), "{got:?}");

        // Linux has one scope.
        let exec = ScriptedExecutor::new();
        let got = trust_statuses(&cert(), &Platform::Linux(LinuxFamily::Debian), &exec).unwrap();
        let scopes: Vec<Scope> = got.iter().map(|s| s.scope).collect();
        assert_eq!(scopes, vec![Scope::System]);
    }

    // ---- tester, whole-branch pass (plan C16) ----

    #[test]
    fn trust_statuses_windows_and_fedora_scope_orders() {
        let exec = ScriptedExecutor::new();
        let got = trust_statuses(&cert(), &Platform::Windows, &exec).unwrap();
        assert_eq!(
            got.iter().map(|s| s.scope).collect::<Vec<_>>(),
            vec![Scope::User, Scope::System]
        );
        let exec = ScriptedExecutor::new();
        let got = trust_statuses(&cert(), &Platform::Linux(LinuxFamily::Fedora), &exec).unwrap();
        assert_eq!(
            got.iter().map(|s| s.scope).collect::<Vec<_>>(),
            vec![Scope::System]
        );
    }

    /// The first store that cannot answer fails the whole read: the error
    /// propagates, the later scope is never queried, and so `read_ca_trust`
    /// (which maps `Err` to no word) never shows a half-read verdict.
    #[test]
    fn trust_statuses_stops_at_the_first_failing_store() {
        let exec = ScriptedExecutor::new().unspawnable("find-certificate");
        let err = trust_statuses(&cert(), &Platform::MacOs, &exec).unwrap_err();
        assert!(
            err.to_string().contains("find-certificate"),
            "the error names the tool that could not start: {err}"
        );
        assert_eq!(
            exec.runs(),
            vec![
                "security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db"
                    .to_string()
            ],
            "fail fast: the System keychain is never queried after the user one failed"
        );
    }

    /// The word the ready card and `ca.status` share: a certificate present
    /// in the login keychain and passing `verify-cert` is `Yes` there and
    /// `No` in the (empty) System keychain, in scope order.
    #[test]
    fn trust_statuses_reports_a_trusted_user_store() {
        let c = cert();
        let present = format!("SHA-256 hash: {}\n", c.sha256_hex());
        let exec = ScriptedExecutor::new()
            .respond(
                "security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db",
                0,
                &present,
                "",
            )
            .respond(crate::testing::VERIFY_CMD, 0, crate::testing::VERIFY_OK, "");
        let got = trust_statuses(&c, &Platform::MacOs, &exec).unwrap();
        assert_eq!(
            got.iter()
                .map(|s| (s.scope, s.installed, s.trusted))
                .collect::<Vec<_>>(),
            vec![
                (Scope::User, Presence::Present, Trust::Yes),
                (Scope::System, Presence::Absent, Trust::No),
            ]
        );
        assert_eq!(
            got[0].location,
            "/Users/t/Library/Keychains/login.keychain-db"
        );
        assert_eq!(got[1].location, "/Library/Keychains/System.keychain");
    }
}
