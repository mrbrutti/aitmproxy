//! Task 13 — the store model and `MacOsStore`: exact `security` command
//! sequences against the login and System keychains, driven entirely through
//! `ScriptedExecutor`, so nothing here touches a real keychain.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aitm_ca::cert::CaCert;
use aitm_ca::exec::{CmdLine, CmdOutput, Executor};
use aitm_ca::platform::macos::MacOsStore;
use aitm_ca::store::{
    store_for, LinuxFamily, Platform, Presence, Scope, Trust, TrustError, TrustErrorKind,
    TrustStore,
};
use aitm_ca::testing::{ScriptedExecutor, FIXTURE_FP1, FIXTURE_FP256};

/// The checked-in fixture CA, exactly as `ca.crt` on disk.
const FIXTURE: &[u8] = include_bytes!("fixtures/ca.crt");

const K_USER: &str = "/Users/t/Library/Keychains/login.keychain-db";
const K_SYS: &str = "/Library/Keychains/System.keychain";
const Q_USER: &str = "security find-certificate -a -Z /Users/t/Library/Keychains/login.keychain-db";
const Q_SYS: &str = "security find-certificate -a -Z /Library/Keychains/System.keychain";

/// What `security add-trusted-cert` prints on stderr in an SSH session.
const HEADLESS_STDERR: &str = "SecTrustSettingsSetTrustSettings: The authorization was denied since no user interaction was possible";

/// What `security add-trusted-cert` prints on stderr when the authentication
/// dialog is dismissed (spec D17.4's literal, confirmed or corrected by Task 40).
const CANCEL_STDERR: &str =
    "SecTrustSettingsSetTrustSettings: The authorization was canceled by the user.";

/// The trust read-back Task 32 chose, as `status` renders it.
const VERIFY_USER: &str = "security verify-cert -c /ca/ca.crt -l -L -p basic";
/// `verify-cert`'s stdout on exit 0 (Task 32).
const VERIFY_OK: &str = "/ca/ca.crt: certificate verification successful.";
/// `verify-cert`'s output tail on a non-zero exit for an untrusted CA (Task 32).
const NOT_TRUSTED: &str = "Cert Verify Result: CSSMERR_TP_NOT_TRUSTED";

/// Every macOS status answer carries this.
const MACOS_DETAIL: &str = "trust from `security verify-cert`";
/// The one `detail` line naming what ran (spec D17.3, policy per Task 32).
const DETAIL: &str = "macOS: presence from `security find-certificate`; trust from `security verify-cert` (basic policy, local only; our install sets the ssl and basic policies together)";

/// Uppercase hex without separators — the form `find-certificate -Z` prints.
fn fp256_hex() -> String {
    FIXTURE_FP256.replace(':', "")
}

fn fp1_hex() -> String {
    FIXTURE_FP1.replace(':', "")
}

fn cert_at(dir: &str) -> CaCert {
    let exec = ScriptedExecutor::new().file(&format!("{dir}/ca.crt"), FIXTURE);
    CaCert::load(Path::new(dir), &exec)
        .unwrap()
        .expect("fixture is present")
}

fn fixture_cert() -> CaCert {
    cert_at("/ca")
}

/// One certificate block as `security find-certificate -a -Z` prints it.
fn block(sha256: &str, sha1: &str) -> String {
    format!(
        "SHA-256 hash: {sha256}\nSHA-1 hash: {sha1}\nkeychain: \"{K_USER}\"\nversion: 512\nclass: 0x80001000 \nattributes:\n    \"alis\"<blob>=\"aitmproxy\"\n"
    )
}

/// The fixture is in the keychain.
fn present_output() -> String {
    block(&fp256_hex(), &fp1_hex())
}

/// Some other certificate is in the keychain; ours is not.
fn other_output() -> String {
    block(&"AB".repeat(32), &"CD".repeat(20))
}

fn add_user() -> String {
    format!("security add-trusted-cert -r trustRoot -p ssl -p basic -k {K_USER} /ca/ca.crt")
}

fn del_user(hash: &str) -> String {
    format!("security delete-certificate -Z {hash} {K_USER}")
}

fn kind_of(err: &anyhow::Error) -> TrustErrorKind {
    err.downcast_ref::<TrustError>()
        .unwrap_or_else(|| panic!("not a TrustError: {err:#}"))
        .kind
}

// CA-AC5
#[test]
fn status_present_absent_sha1_only() {
    let cert = fixture_cert();
    let store = MacOsStore;

    // (a) A block whose SHA-256 is ours; the trust read-back says trusted.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &present_output(), "")
        .respond(VERIFY_USER, 0, VERIFY_OK, "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Present);
    assert_eq!(st.trusted, Trust::Yes);
    assert_eq!(st.scope, Scope::User);
    assert_eq!(st.location, K_USER);
    assert!(
        st.detail.iter().any(|d| d.contains(MACOS_DETAIL)),
        "detail: {:?}",
        st.detail
    );
    assert_eq!(
        exec.runs(),
        vec![Q_USER.to_string(), VERIFY_USER.to_string()]
    );

    // (b) Only other hashes: absent, so not trusted, and no read-back runs.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &other_output(), "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Absent);
    assert_eq!(st.trusted, Trust::No);
    assert!(st.detail.iter().any(|d| d.contains(MACOS_DETAIL)));
    assert_eq!(exec.runs(), vec![Q_USER.to_string()]);

    // (c) SHA-1 only, as older macOS prints it (uppercase).
    let sha1_only = format!("SHA-1 hash: {}\nkeychain: \"{K_USER}\"\n", fp1_hex());
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &sha1_only, "")
        .respond(VERIFY_USER, 0, VERIFY_OK, "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Present);
    assert_eq!(st.trusted, Trust::Yes);

    // Exit 0 with empty output: nothing in the keychain at all.
    let exec = ScriptedExecutor::new();
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Absent);

    // Exit 1: we cannot tell.
    let exec = ScriptedExecutor::new().respond(
        Q_USER,
        1,
        "",
        "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.",
    );
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Unknown);
    assert_eq!(st.trusted, Trust::Unknown);
    assert!(st.detail.iter().any(|d| d.contains(MACOS_DETAIL)));

    // System scope queries the System keychain, never through sudo; the
    // read-back is the same per-user evaluation.
    let exec = ScriptedExecutor::new()
        .root(false)
        .respond(Q_SYS, 0, &present_output(), "")
        .respond(VERIFY_USER, 0, VERIFY_OK, "");
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!(st.installed, Presence::Present);
    assert_eq!(st.trusted, Trust::Yes);
    assert_eq!(st.scope, Scope::System);
    assert_eq!(st.location, K_SYS);
    assert_eq!(
        exec.runs(),
        vec![Q_SYS.to_string(), VERIFY_USER.to_string()]
    );
}

/// Delegates to a `ScriptedExecutor` but cannot spawn `security verify-cert`
/// (the tool is missing), the way `RealExecutor` fails when a program cannot
/// start.
struct VerifyUnspawnable(ScriptedExecutor);

const VERIFY_SPAWN_FAILURE: &str = "could not start `security verify-cert -c /ca/ca.crt -l -L -p basic`: No such file or directory (os error 2)";

impl Executor for VerifyUnspawnable {
    fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
        if cmd.args.first().map(String::as_str) == Some("verify-cert") {
            // Recorded like every other run, then refused like a missing tool.
            let _ = self.0.run(cmd);
            anyhow::bail!("{VERIFY_SPAWN_FAILURE}");
        }
        self.0.run(cmd)
    }

    fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        self.0.read_file(path)
    }

    fn dir_exists(&self, path: &Path) -> bool {
        self.0.dir_exists(path)
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.0.home_dir()
    }

    fn is_root(&self) -> bool {
        self.0.is_root()
    }
}

// SP-AC31 (D17.3): trust comes from one `verify-cert` evaluation, run only
// when the certificate is present.
#[test]
fn status_reads_trust_with_verify_cert() {
    let cert = fixture_cert();
    let store = MacOsStore;

    // Present + exit 0 with the success text: trusted.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &present_output(), "")
        .respond(VERIFY_USER, 0, VERIFY_OK, "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Present);
    assert_eq!(st.trusted, Trust::Yes);
    assert_eq!(exec.runs().last().map(String::as_str), Some(VERIFY_USER));
    assert_eq!(st.detail, vec![DETAIL.to_string()]);

    // Present + non-zero exit: not trusted, the output tail in detail
    // (whichever stream `security` printed it on).
    for (stdout, stderr) in [("", NOT_TRUSTED), (NOT_TRUSTED, "")] {
        let exec = ScriptedExecutor::new()
            .respond(Q_USER, 0, &present_output(), "")
            .respond(VERIFY_USER, 1, stdout, stderr);
        let st = store.status(&cert, Scope::User, &exec).unwrap();
        assert_eq!(st.installed, Presence::Present);
        assert_eq!(st.trusted, Trust::No);
        assert!(
            st.detail.iter().any(|d| d.contains(NOT_TRUSTED)),
            "detail: {:?}",
            st.detail
        );
        assert!(
            st.detail.iter().any(|d| d.contains(VERIFY_USER)),
            "detail: {:?}",
            st.detail
        );
        assert_eq!(
            exec.runs(),
            vec![Q_USER.to_string(), VERIFY_USER.to_string()]
        );
    }

    // Present + exit 0 without the success text: not trusted, and detail says
    // what was missing.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &present_output(), "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.trusted, Trust::No);
    assert!(
        st.detail
            .iter()
            .any(|d| d.contains("certificate verification successful") && d.contains(VERIFY_USER)),
        "detail: {:?}",
        st.detail
    );

    // Absent: not trusted, and no verify-cert run.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &other_output(), "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Absent);
    assert_eq!(st.trusted, Trust::No);
    assert_eq!(exec.runs(), vec![Q_USER.to_string()]);
    assert_eq!(st.detail, vec![DETAIL.to_string()]);

    // Present + verify-cert unspawnable: unknown, with the failure text.
    let exec = VerifyUnspawnable(ScriptedExecutor::new().respond(Q_USER, 0, &present_output(), ""));
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Present);
    assert_eq!(st.trusted, Trust::Unknown);
    assert!(
        st.detail.iter().any(|d| d.contains(VERIFY_SPAWN_FAILURE)),
        "detail: {:?}",
        st.detail
    );
    assert_eq!(
        exec.0.runs(),
        vec![Q_USER.to_string(), VERIFY_USER.to_string()]
    );
    assert!(st.detail.iter().any(|d| d.contains(MACOS_DETAIL)));
}

// SP-AC32 (D17.4): a dismissed authentication dialog is `Cancelled`, calm,
// and still rolls back the untrusted copy.
#[test]
fn install_cancelled_is_calm_and_rolls_back() {
    let cert = fixture_cert();
    let store = MacOsStore;

    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, "", "")
        .respond(Q_USER, 0, &present_output(), "")
        .respond(&add_user(), 1, "", CANCEL_STDERR);
    let err = store.install(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::Cancelled);
    assert_eq!(
        err.to_string(),
        "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not \
         trusted; removed the untrusted copy it left behind"
    );
    assert_eq!(
        exec.runs(),
        vec![
            Q_USER.to_string(),
            add_user(),
            Q_USER.to_string(),
            del_user(&fp256_hex()),
        ]
    );

    // Nothing left behind: the message is the bare literal.
    let exec = ScriptedExecutor::new().respond(&add_user(), 1, "", CANCEL_STDERR);
    let err = store.install(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::Cancelled);
    assert_eq!(
        err.to_string(),
        "ca.install cancelled: the macOS authentication dialog was dismissed; the CA is not trusted"
    );
    assert_eq!(
        exec.runs(),
        vec![Q_USER.to_string(), add_user(), Q_USER.to_string()]
    );

    // The headless text is still HeadlessAuth, not Cancelled.
    let exec = ScriptedExecutor::new().respond(&add_user(), 1, "", HEADLESS_STDERR);
    let err = store.install(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::HeadlessAuth);
}

// CA-AC9
#[test]
fn install_user_idempotent() {
    let cert = fixture_cert();
    let store = MacOsStore;

    // Absent: query, then add.
    let exec = ScriptedExecutor::new();
    let change = store.install(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), vec![Q_USER.to_string(), add_user()]);
    assert!(change.changed);
    assert_eq!(change.scope, Scope::User);
    assert_eq!(change.location, K_USER);
    assert_eq!(change.commands, exec.runs());

    // Present: the query alone, nothing added.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &present_output(), "");
    let change = store.install(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), vec![Q_USER.to_string()]);
    assert!(!change.changed);
    assert_eq!(change.location, K_USER);
}

// CA-AC10
#[test]
fn install_system_sudo() {
    let cert = fixture_cert();
    let store = MacOsStore;
    let add_sys =
        format!("security add-trusted-cert -d -r trustRoot -p ssl -p basic -k {K_SYS} /ca/ca.crt");

    let exec = ScriptedExecutor::new().root(false);
    let change = store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        vec![Q_SYS.to_string(), format!("sudo -- {add_sys}")]
    );
    assert!(change.changed);
    assert_eq!(change.location, K_SYS);

    let exec = ScriptedExecutor::new().root(true);
    store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), vec![Q_SYS.to_string(), add_sys]);

    // The query is never prefixed, root or not.
    for exec in [
        ScriptedExecutor::new().root(false),
        ScriptedExecutor::new().root(true),
    ] {
        store.install(&cert, Scope::System, &exec).unwrap();
        assert!(exec
            .runs()
            .iter()
            .all(|line| !line.contains("sudo -- security find")));
        assert_eq!(exec.runs()[0], Q_SYS);
    }
}

// CA-AC11
#[test]
fn install_headless_rolls_back() {
    let cert = fixture_cert();
    let store = MacOsStore;

    // Absent before the add, present after it failed (the copy was added,
    // the trust settings were not): roll the copy back.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, "", "")
        .respond(Q_USER, 0, &present_output(), "")
        .respond(&add_user(), 1, "", HEADLESS_STDERR);
    let err = store.install(&cert, Scope::User, &exec).unwrap_err();
    let text = format!("{err:#}");
    assert!(text.contains("GUI session"), "got: {text}");
    assert!(text.contains(HEADLESS_STDERR), "got: {text}");
    assert_eq!(kind_of(&err), TrustErrorKind::HeadlessAuth);
    assert_eq!(
        exec.runs(),
        vec![
            Q_USER.to_string(),
            add_user(),
            Q_USER.to_string(),
            del_user(&fp256_hex()),
        ]
    );

    // Any other failure is ToolFailed; with nothing added there is nothing
    // to roll back, so the post-failure query is the last command.
    let exec = ScriptedExecutor::new().respond(
        &add_user(),
        1,
        "",
        "security: SecCertificateCreateFromData: Unknown format in import.",
    );
    let err = store.install(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::ToolFailed);
    assert!(
        format!("{err:#}").contains("Unknown format in import"),
        "got: {err:#}"
    );
    assert_eq!(
        exec.runs(),
        vec![Q_USER.to_string(), add_user(), Q_USER.to_string()]
    );
}

// CA-AC12
#[test]
fn uninstall_sequence_and_sha1_fallback() {
    let cert = fixture_cert();
    let store = MacOsStore;
    let rm_user = "security remove-trusted-cert /ca/ca.crt".to_string();
    let del256 = del_user(&fp256_hex());
    let del1 = del_user(&fp1_hex().to_lowercase());

    // Present, one copy: query, untrust, delete by SHA-256, re-query.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &present_output(), "")
        .respond(Q_USER, 0, "", "");
    let change = store.uninstall(&cert, Scope::User, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        vec![
            Q_USER.to_string(),
            rm_user.clone(),
            del256.clone(),
            Q_USER.to_string()
        ]
    );
    assert!(change.changed);
    assert_eq!(change.scope, Scope::User);
    assert_eq!(change.location, K_USER);

    // Absent: the query alone.
    let exec = ScriptedExecutor::new();
    let change = store.uninstall(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), vec![Q_USER.to_string()]);
    assert!(!change.changed);

    // Older macOS: delete by SHA-256 fails, so delete by SHA-1 (lowercase).
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &present_output(), "")
        .respond(Q_USER, 0, "", "")
        .respond(
            &del256,
            1,
            "",
            "security: SecKeychainItemDelete: The specified item could not be found in the keychain.",
        );
    let change = store.uninstall(&cert, Scope::User, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        vec![
            Q_USER.to_string(),
            rm_user.clone(),
            del256.clone(),
            del1.clone(),
            Q_USER.to_string()
        ]
    );
    assert!(change.changed);

    // Both deletes fail: ToolFailed.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &present_output(), "")
        .respond(&del256, 1, "", "nope")
        .respond(&del1, 1, "", "nope again");
    let err = store.uninstall(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::ToolFailed);
    assert_eq!(
        exec.runs(),
        vec![
            Q_USER.to_string(),
            rm_user.clone(),
            del256.clone(),
            del1.clone()
        ]
    );

    // Duplicate copies that never go away: at most three delete passes.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &present_output(), "");
    let err = store.uninstall(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::CopiesRemain);
    assert_eq!(
        exec.runs(),
        vec![
            Q_USER.to_string(),
            rm_user,
            del256.clone(),
            Q_USER.to_string(),
            del256.clone(),
            Q_USER.to_string(),
            del256,
            Q_USER.to_string(),
        ]
    );

    // A failed remove-trusted-cert is tolerated and recorded.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &present_output(), "")
        .respond(Q_USER, 0, "", "")
        .respond(
            "security remove-trusted-cert /ca/ca.crt",
            1,
            "",
            "SecTrustSettingsRemoveTrustSettings: The specified item could not be found in the keychain.",
        );
    let change = store.uninstall(&cert, Scope::User, &exec).unwrap();
    assert!(change.changed);
    assert!(
        change
            .detail
            .iter()
            .any(|d| d.contains("remove-trusted-cert")),
        "detail: {:?}",
        change.detail
    );

    // System scope: -d on remove-trusted-cert, sudo on every mutation,
    // never on the query.
    let exec = ScriptedExecutor::new()
        .root(false)
        .respond(Q_SYS, 0, &present_output(), "")
        .respond(Q_SYS, 0, "", "");
    let change = store.uninstall(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        vec![
            Q_SYS.to_string(),
            "sudo -- security remove-trusted-cert -d /ca/ca.crt".to_string(),
            format!(
                "sudo -- security delete-certificate -Z {} {K_SYS}",
                fp256_hex()
            ),
            Q_SYS.to_string(),
        ]
    );
    assert!(change.changed);
    assert_eq!(change.location, K_SYS);
}

/// Records the `CmdLine`s themselves (not just their rendering), so a test
/// can look at the argument vector the OS would receive.
#[derive(Default)]
struct RecordingExec {
    lines: Mutex<Vec<CmdLine>>,
}

impl RecordingExec {
    fn lines(&self) -> Vec<CmdLine> {
        self.lines.lock().unwrap().clone()
    }
}

impl Executor for RecordingExec {
    fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
        self.lines.lock().unwrap().push(cmd.clone());
        Ok(CmdOutput {
            code: Some(0),
            ..CmdOutput::default()
        })
    }

    fn read_file(&self, _path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn dir_exists(&self, _path: &Path) -> bool {
        false
    }

    fn home_dir(&self) -> Option<PathBuf> {
        Some(PathBuf::from("/Users/t"))
    }

    fn is_root(&self) -> bool {
        false
    }
}

// Review Focus #2
#[test]
fn install_with_space_in_cert_path() {
    let path = "/Users/t/Application Support/ca/ca.crt";
    let cert = cert_at("/Users/t/Application Support/ca");
    assert_eq!(cert.path, PathBuf::from(path));

    let exec = RecordingExec::default();
    MacOsStore.install(&cert, Scope::User, &exec).unwrap();

    let lines = exec.lines();
    let add = lines
        .iter()
        .find(|c| c.args.first().map(String::as_str) == Some("add-trusted-cert"))
        .expect("add-trusted-cert ran");
    assert!(add.mutating);
    assert_eq!(add.program, "security");
    // The OS receives the path as one argument, unquoted …
    assert_eq!(add.args.last().map(String::as_str), Some(path));
    // … and the rendered line shows it single-quoted.
    assert_eq!(
        add.render(),
        format!("security add-trusted-cert -r trustRoot -p ssl -p basic -k {K_USER} '{path}'")
    );
}

/// The declared model surface (`Scope`, `Platform`, labels, `store_for`,
/// `UnsupportedStore`) — small pure functions Tasks 14–16 build on.
#[test]
fn store_model_surface() {
    // Scope parses exactly "user" | "system".
    assert_eq!("user".parse::<Scope>().unwrap(), Scope::User);
    assert_eq!("system".parse::<Scope>().unwrap(), Scope::System);
    for bad in ["User", "SYSTEM", "", " user", "all"] {
        assert!(bad.parse::<Scope>().is_err(), "{bad:?} parsed");
    }
    assert_eq!(Scope::User.label(), "user");
    assert_eq!(Scope::System.label(), "system");
    assert_eq!(Scope::System.to_string(), "system");

    // Platform labels, scopes, default scopes.
    let debian = Platform::Linux(LinuxFamily::Debian);
    let fedora = Platform::Linux(LinuxFamily::Fedora);
    let unsupported = Platform::Unsupported("freebsd".to_string());
    assert_eq!(Platform::MacOs.label(), "macos");
    assert_eq!(debian.label(), "linux-debian");
    assert_eq!(fedora.label(), "linux-fedora");
    assert_eq!(Platform::Windows.label(), "windows");
    assert_eq!(unsupported.label(), "unsupported");

    assert_eq!(Platform::MacOs.scopes(), &[Scope::User, Scope::System]);
    assert_eq!(Platform::Windows.scopes(), &[Scope::User, Scope::System]);
    assert_eq!(debian.scopes(), &[Scope::System]);
    assert_eq!(fedora.scopes(), &[Scope::System]);
    assert_eq!(unsupported.scopes(), &[] as &[Scope]);

    assert_eq!(Platform::MacOs.default_scope(), Some(Scope::User));
    assert_eq!(Platform::Windows.default_scope(), Some(Scope::User));
    assert_eq!(debian.default_scope(), Some(Scope::System));
    assert_eq!(unsupported.default_scope(), None);

    // Presence / Trust wire labels.
    assert_eq!(Presence::Present.label(), "present");
    assert_eq!(Presence::Absent.label(), "absent");
    assert_eq!(Presence::Stale.label(), "stale");
    assert_eq!(Presence::Unknown.label(), "unknown");
    assert_eq!(Trust::Yes.label(), "yes");
    assert_eq!(Trust::No.label(), "no");
    assert_eq!(Trust::Unknown.label(), "unknown");

    // store_for hands back a store that knows its platform.
    assert_eq!(store_for(&Platform::MacOs).platform(), &Platform::MacOs);
    assert_eq!(store_for(&fedora).platform(), &fedora);
    assert_eq!(store_for(&debian).platform(), &debian);
    assert_eq!(store_for(&Platform::Windows).platform(), &Platform::Windows);
    assert_eq!(store_for(&unsupported).platform().label(), "unsupported");

    // On this host, detect agrees with the compile target.
    let exec = ScriptedExecutor::new();
    if cfg!(target_os = "macos") {
        assert_eq!(Platform::detect(&exec), Platform::MacOs);
    }
    assert_eq!(
        Platform::detect_with_os("freebsd", &exec),
        Platform::Unsupported("freebsd".to_string())
    );
    assert_eq!(Platform::detect_with_os("macos", &exec), Platform::MacOs);
    assert_eq!(
        Platform::detect_with_os("windows", &exec),
        Platform::Windows
    );

    // UnsupportedStore refuses everything, naming the OS and the way out.
    let cert = fixture_cert();
    let store = store_for(&unsupported);
    let err = store.install(&cert, Scope::System, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::UnsupportedPlatform);
    let text = format!("{err:#}");
    assert!(text.contains("freebsd"), "got: {text}");
    assert!(text.contains("aitm ca export"), "got: {text}");
    assert_eq!(
        kind_of(&store.uninstall(&cert, Scope::System, &exec).unwrap_err()),
        TrustErrorKind::UnsupportedPlatform
    );
    assert_eq!(
        kind_of(&store.status(&cert, Scope::System, &exec).unwrap_err()),
        TrustErrorKind::UnsupportedPlatform
    );
    // Nothing was run or read.
    assert!(exec.runs().is_empty());

    // Linux with no known trust-store directory names both and the file.
    let store = store_for(&Platform::Unsupported("linux".to_string()));
    let text = format!(
        "{:#}",
        store.install(&cert, Scope::System, &exec).unwrap_err()
    );
    assert!(
        text.contains("/etc/pki/ca-trust/source/anchors"),
        "got: {text}"
    );
    assert!(
        text.contains("/usr/local/share/ca-certificates"),
        "got: {text}"
    );
    assert!(text.contains("/ca/ca.crt"), "got: {text}");

    // TrustError displays its message and converts into anyhow via `?`.
    let e = TrustError::new(TrustErrorKind::NeedsRoot, "needs root: hint");
    assert_eq!(e.to_string(), "needs root: hint");
    let as_anyhow: anyhow::Error = e.clone().into();
    assert_eq!(kind_of(&as_anyhow), TrustErrorKind::NeedsRoot);
}

/// Every status answer names what ran for presence and what ran for trust
/// (spec D17.3), present or absent, and nothing else when the read-back
/// succeeded.
#[test]
fn status_present_detail_names_the_trust_check() {
    let cert = fixture_cert();
    let store = MacOsStore;

    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &present_output(), "")
        .respond(VERIFY_USER, 0, VERIFY_OK, "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Present);
    assert_eq!(st.trusted, Trust::Yes);
    assert_eq!(st.detail, vec![DETAIL.to_string()]);
    assert!(
        !st.detail.iter().any(|d| d.contains("UNCONFIRMED")),
        "the old unconfirmed claim is gone: {:?}",
        st.detail
    );

    // Absent: the same line, no trust evaluation ran.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &other_output(), "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(st.installed, Presence::Absent);
    assert_eq!(st.trusted, Trust::No);
    assert_eq!(st.detail, vec![DETAIL.to_string()]);
    assert_eq!(exec.runs(), vec![Q_USER.to_string()]);
}
