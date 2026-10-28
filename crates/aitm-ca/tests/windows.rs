//! Task 15 — `WindowsStore`: `certutil [-user] -store|-addstore|-delstore
//! Root`, keyed on the SHA-1 thumbprint. Unit-tested only (Windows is not a
//! shipped platform); runs on any host through `ScriptedExecutor`.

use std::path::Path;

use aitm_ca::cert::CaCert;
use aitm_ca::platform::windows::WindowsStore;
use aitm_ca::store::{Presence, Scope, Trust, TrustError, TrustErrorKind, TrustStore};
use aitm_ca::testing::{ScriptedExecutor, FIXTURE_FP1};

/// The checked-in fixture CA, exactly as `ca.crt` on disk.
const FIXTURE: &[u8] = include_bytes!("fixtures/ca.crt");

const Q_USER: &str = "certutil -user -store Root";
const Q_SYS: &str = "certutil -store Root";

/// Some other root's thumbprint, as `certutil` prints it. A real Root store
/// is never empty, and a dump with no hash lines at all is `Unknown`, so
/// "absent" means "others are listed, ours is not".
const OTHER: &str = "06 f1 aa 33 0b 92 7b 75 3a 40 e6 8c df 22 e3 44 01 aa 91 1a";

fn fixture_cert() -> CaCert {
    let exec = ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE);
    CaCert::load(Path::new("/ca"), &exec)
        .unwrap()
        .expect("fixture is present")
}

/// The thumbprint as `certutil` wants it: 40 lowercase hex, no separators.
fn fp1_lower() -> String {
    FIXTURE_FP1.replace(':', "").to_lowercase()
}

/// The thumbprint as `certutil -store` prints it: space-separated pairs,
/// here deliberately in mixed case.
fn fp1_spaced_mixed() -> String {
    FIXTURE_FP1
        .split(':')
        .enumerate()
        .map(|(i, pair)| {
            if i % 2 == 0 {
                pair.to_lowercase()
            } else {
                pair.to_uppercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One certificate entry of a `certutil -store Root` dump.
fn entry(index: usize, hash: &str) -> String {
    format!(
        "================ Certificate {index} ================\nSerial Number: 01\nIssuer: CN=Example\n NotBefore: 1/1/2024 12:00 AM\n NotAfter: 1/1/2034 12:00 AM\nSubject: CN=Example\nSignature matches Public Key\nRoot Certificate: Subject matches Issuer\nCert Hash(sha1): {hash}\nNo key provider information\n"
    )
}

fn dump(entries: &[&str]) -> String {
    let mut out = String::from("Root \"Trusted Root Certification Authorities\"\n");
    for (i, hash) in entries.iter().enumerate() {
        out.push_str(&entry(i, hash));
    }
    out.push_str("CertUtil: -store command completed successfully.\n");
    out
}

fn kind_of(err: &anyhow::Error) -> TrustErrorKind {
    err.downcast_ref::<TrustError>()
        .unwrap_or_else(|| panic!("not a TrustError: {err:#}"))
        .kind
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// CA-AC8
#[test]
fn status_parse() {
    let cert = fixture_cert();
    let store = WindowsStore;

    // Ours, printed with spaces and mixed case, among others.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &dump(&[OTHER, &fp1_spaced_mixed()]), "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Present, Trust::Yes));
    assert_eq!(st.scope, Scope::User);
    assert_eq!(exec.runs(), strings(&[Q_USER]));

    // Newer certutil prints the hash without spaces; the label may differ in case.
    let compact = format!("Cert Hash(SHA1): {}\n", fp1_lower().to_uppercase());
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &compact, "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Present, Trust::Yes));

    // Other hashes only.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &dump(&[OTHER]), "");
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Absent, Trust::No));

    // Non-zero exit: unknown, and the detail carries the code.
    let exec = ScriptedExecutor::new().respond(
        Q_USER,
        1,
        "CertUtil: -store command FAILED: 0x80070002\n",
        "",
    );
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(
        (st.installed, st.trusted),
        (Presence::Unknown, Trust::Unknown)
    );
    assert!(
        st.detail.iter().any(|d| d.contains("exited 1")),
        "detail: {:?}",
        st.detail
    );

    // Exit 0 but no hash lines (localised or changed output): unknown.
    let exec = ScriptedExecutor::new().respond(
        Q_USER,
        0,
        "Root \"Vertrauenswürdige Stammzertifizierungsstellen\"\nZertifikathash(sha1): 06 f1\n",
        "",
    );
    let st = store.status(&cert, Scope::User, &exec).unwrap();
    assert_eq!(
        (st.installed, st.trusted),
        (Presence::Unknown, Trust::Unknown)
    );
    assert!(
        st.detail.iter().any(|d| d.contains("could not parse")),
        "detail: {:?}",
        st.detail
    );

    // System scope drops -user; the location names the machine store.
    let exec = ScriptedExecutor::new().respond(Q_SYS, 0, &dump(&[&fp1_spaced_mixed()]), "");
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!(st.installed, Presence::Present);
    assert_eq!(st.scope, Scope::System);
    assert_eq!(exec.runs(), strings(&[Q_SYS]));
    assert_ne!(
        st.location,
        store
            .status(&cert, Scope::User, &ScriptedExecutor::new())
            .unwrap()
            .location
    );
}

// CA-AC18
#[test]
fn install_uninstall() {
    let cert = fixture_cert();
    let store = WindowsStore;
    let add_user = format!("certutil -user -addstore Root {}", cert.path.display());
    let add_sys = format!("certutil -addstore Root {}", cert.path.display());
    let del_user = format!("certutil -user -delstore Root {}", fp1_lower());

    // User, absent: query then add (no -f).
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &dump(&[OTHER]), "");
    let change = store.install(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[Q_USER, &add_user]));
    assert!(change.changed);
    assert_eq!(change.scope, Scope::User);
    assert_eq!(change.commands, exec.runs());

    // Present: the query alone.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &dump(&[&fp1_spaced_mixed()]), "");
    let change = store.install(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[Q_USER]));
    assert!(!change.changed);

    // System: no -user, and never sudo.
    let exec = ScriptedExecutor::new()
        .root(false)
        .respond(Q_SYS, 0, &dump(&[OTHER]), "");
    let change = store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[Q_SYS, &add_sys]));
    assert!(change.changed);
    assert!(exec.runs().iter().all(|l| !l.starts_with("sudo")));

    // Uninstall, present: query then delete by thumbprint.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &dump(&[&fp1_spaced_mixed()]), "");
    let change = store.uninstall(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[Q_USER, &del_user]));
    assert!(change.changed);

    // Uninstall, absent: the query alone.
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, &dump(&[OTHER]), "");
    let change = store.uninstall(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[Q_USER]));
    assert!(!change.changed);

    // Access denied on add: NeedsRoot, with the elevation hint and, for
    // the user scope, the Security Warning dialog hint.
    let denied = "CertUtil: -addstore command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)\nCertUtil: Access is denied. 0x80070005\n";
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &dump(&[OTHER]), "")
        .respond(&add_user, 1, denied, "");
    let err = store.install(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::NeedsRoot);
    let text = format!("{err:#}");
    assert!(text.contains("Administrator"), "got: {text}");
    assert!(text.contains("Security Warning"), "got: {text}");

    let exec = ScriptedExecutor::new()
        .respond(Q_SYS, 0, &dump(&[OTHER]), "")
        .respond(&add_sys, 1, denied, "");
    let err = store.install(&cert, Scope::System, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::NeedsRoot);
    let text = format!("{err:#}");
    assert!(text.contains("Administrator"), "got: {text}");
    assert!(!text.contains("Security Warning"), "got: {text}");

    // Any other add failure is ToolFailed and quotes the tool.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &dump(&[OTHER]), "")
        .respond(
            &add_user,
            1,
            "CertUtil: -addstore command FAILED: 0x80092009 (-2146885623 CRYPT_E_NO_MATCH)\n",
            "",
        );
    let err = store.install(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::ToolFailed);
    assert!(
        format!("{err:#}").contains("CRYPT_E_NO_MATCH"),
        "got: {err:#}"
    );

    // A failed delete is ToolFailed.
    let exec = ScriptedExecutor::new()
        .respond(Q_USER, 0, &dump(&[&fp1_spaced_mixed()]), "")
        .respond(
            &del_user,
            1,
            "CertUtil: -delstore command FAILED: 0x80070490\n",
            "",
        );
    let err = store.uninstall(&cert, Scope::User, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::ToolFailed);

    // An unparsable store dump does not block the change: the Root store
    // is keyed on the thumbprint, so -addstore cannot duplicate and
    // -delstore of a missing thumbprint fails on its own. The detail says
    // the check was skipped.
    let unparsable = "Root \"Trusted Root Certification Authorities\"\nnothing we recognise\n";
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, unparsable, "");
    let change = store.install(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[Q_USER, &add_user]));
    assert!(change.changed);
    assert!(
        change.detail.iter().any(|d| d.contains("could not parse"))
            && change.detail.iter().any(|d| d.contains("anyway")),
        "detail: {:?}",
        change.detail
    );
    let exec = ScriptedExecutor::new().respond(Q_USER, 0, unparsable, "");
    let change = store.uninstall(&cert, Scope::User, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[Q_USER, &del_user]));
    assert!(change.changed);
}
