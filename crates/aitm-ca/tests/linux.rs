//! Task 14 — `LinuxStore` (Debian and Fedora families) and Linux family
//! detection, driven entirely through `ScriptedExecutor`: status reads two
//! files and runs nothing; install and uninstall are `tee`/`rm -f` plus a
//! bundle refresh, each behind `sudo --` unless root.

use std::path::PathBuf;

use aitm_ca::cert::{sha256_of, CaCert};
use aitm_ca::platform::linux::LinuxStore;
use aitm_ca::store::{
    detect_linux_family, store_for, LinuxFamily, Platform, Presence, Scope, Trust, TrustError,
    TrustErrorKind, TrustStore,
};
use aitm_ca::testing::ScriptedExecutor;

/// The checked-in fixture CA, exactly as `ca.crt` on disk.
const FIXTURE: &[u8] = include_bytes!("fixtures/ca.crt");

const DEBIAN_DIR: &str = "/usr/local/share/ca-certificates";
const FEDORA_DIR: &str = "/etc/pki/ca-trust/source/anchors";

const A_DEB: &str = "/usr/local/share/ca-certificates/aitmproxy-root-ca.crt";
const B_DEB: &str = "/etc/ssl/certs/ca-certificates.crt";
const A_FED: &str = "/etc/pki/ca-trust/source/anchors/aitmproxy-root-ca.pem";
const B_FED: &str = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem";

/// The DER of "some other certificate": a PEM block the store can hash
/// but that is not ours. The store never parses X.509, only the PEM.
const OTHER_DER: [u8; 48] = [
    0x30, 0x82, 0x00, 0x2c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
];

/// Standard base64 with padding — enough to wrap `OTHER_DER` in PEM
/// without adding a dependency to the crate.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextet = |shift: u32| TABLE[((n >> shift) & 63) as usize] as char;
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

fn other_pem() -> Vec<u8> {
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64(&OTHER_DER)
    )
    .into_bytes()
}

/// Colon-separated uppercase SHA-256 of the other certificate.
fn other_fp256() -> String {
    sha256_of(&OTHER_DER)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// A bundle holding the other certificate, and ours when `with_ours`.
fn bundle(with_ours: bool) -> Vec<u8> {
    let mut b = other_pem();
    if with_ours {
        b.extend_from_slice(FIXTURE);
    }
    b
}

fn fixture_cert() -> CaCert {
    let exec = ScriptedExecutor::new().file("/ca/ca.crt", FIXTURE);
    CaCert::load(std::path::Path::new("/ca"), &exec)
        .unwrap()
        .expect("fixture is present")
}

fn kind_of(err: &anyhow::Error) -> TrustErrorKind {
    err.downcast_ref::<TrustError>()
        .unwrap_or_else(|| panic!("not a TrustError: {err:#}"))
        .kind
}

fn paths(list: &[&str]) -> Vec<PathBuf> {
    list.iter().map(PathBuf::from).collect()
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// CA-AC6
#[test]
fn debian_status_matrix() {
    let cert = fixture_cert();
    let store = LinuxStore(LinuxFamily::Debian);

    // Anchor is ours, bundle contains it.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, FIXTURE)
        .file(B_DEB, &bundle(true));
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Present, Trust::Yes));
    assert_eq!(st.scope, Scope::System);
    assert_eq!(st.location, A_DEB);
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert_eq!(exec.reads(), paths(&[A_DEB, B_DEB]));

    // Anchor holds another certificate, bundle lacks ours: stale.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, &other_pem())
        .file(B_DEB, &bundle(false));
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Stale, Trust::No));
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert_eq!(exec.reads(), paths(&[A_DEB, B_DEB]));

    // No anchor.
    let exec = ScriptedExecutor::new().file(B_DEB, &bundle(false));
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Absent, Trust::No));
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert_eq!(exec.reads(), paths(&[A_DEB, B_DEB]));

    // Anchor present, bundle missing: trust unknown, and the detail says why.
    let exec = ScriptedExecutor::new().file(A_DEB, FIXTURE);
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        (st.installed, st.trusted),
        (Presence::Present, Trust::Unknown)
    );
    assert!(
        st.detail
            .iter()
            .any(|d| d.contains(B_DEB) && d.contains("not readable")),
        "detail: {:?}",
        st.detail
    );
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert_eq!(exec.reads(), paths(&[A_DEB, B_DEB]));

    // An anchor that is not even PEM is stale too.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, b"garbage")
        .file(B_DEB, &bundle(false));
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!(st.installed, Presence::Stale);
}

// CA-AC7
#[test]
fn fedora_status_paths() {
    let cert = fixture_cert();
    let store = LinuxStore(LinuxFamily::Fedora);

    let exec = ScriptedExecutor::new()
        .file(A_FED, FIXTURE)
        .file(B_FED, &bundle(true));
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Present, Trust::Yes));
    assert_eq!(st.location, A_FED);
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert_eq!(exec.reads(), paths(&[A_FED, B_FED]));

    let exec = ScriptedExecutor::new()
        .file(A_FED, &other_pem())
        .file(B_FED, &bundle(false));
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Stale, Trust::No));

    let exec = ScriptedExecutor::new().file(B_FED, &bundle(false));
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!((st.installed, st.trusted), (Presence::Absent, Trust::No));

    let exec = ScriptedExecutor::new().file(A_FED, FIXTURE);
    let st = store.status(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        (st.installed, st.trusted),
        (Presence::Present, Trust::Unknown)
    );
    assert_eq!(exec.reads(), paths(&[A_FED, B_FED]));
}

// CA-AC13
#[test]
fn debian_install() {
    let cert = fixture_cert();
    let store = LinuxStore(LinuxFamily::Debian);
    let tee = format!("sudo -- tee {A_DEB}");
    let refresh = "sudo -- update-ca-certificates";

    // Absent: write the anchor through tee (PEM on stdin), then refresh.
    let exec = ScriptedExecutor::new()
        .file(B_DEB, &bundle(false))
        .respond(refresh, 0, "Updating certificates in /etc/ssl/certs...\n1 added, 0 removed; done.\nRunning hooks in /etc/ca-certificates/update.d...\ndone.\n", "");
    let change = store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[&tee, refresh]));
    assert_eq!(exec.stdins()[0], Some(FIXTURE.to_vec()));
    assert_eq!(exec.stdins()[1], None);
    assert!(change.changed);
    assert_eq!(change.scope, Scope::System);
    assert_eq!(change.location, A_DEB);
    assert_eq!(change.commands, exec.runs());
    assert!(
        change
            .detail
            .iter()
            .any(|d| d.contains("1 added, 0 removed")),
        "detail: {:?}",
        change.detail
    );

    // Present and trusted: nothing to do.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, FIXTURE)
        .file(B_DEB, &bundle(true));
    let change = store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert!(!change.changed);

    // Present but the bundle was never refreshed: refresh only.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, FIXTURE)
        .file(B_DEB, &bundle(false));
    let change = store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[refresh]));
    assert!(change.changed);

    // Stale anchor: overwrite it and refresh.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, &other_pem())
        .file(B_DEB, &bundle(false));
    let change = store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[&tee, refresh]));
    assert!(change.changed);

    // Root: no sudo prefix anywhere.
    let exec = ScriptedExecutor::new()
        .root(true)
        .file(B_DEB, &bundle(false));
    store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        strings(&[&format!("tee {A_DEB}"), "update-ca-certificates"])
    );

    // Not root and sudo could not help: NeedsRoot with the hint.
    let exec = ScriptedExecutor::new().file(B_DEB, &bundle(false)).respond(
        &tee,
        1,
        "",
        &format!("tee: {A_DEB}: Permission denied"),
    );
    let err = store.install(&cert, Scope::System, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::NeedsRoot);
    assert!(format!("{err:#}").contains("needs root"), "got: {err:#}");
    assert_eq!(exec.runs(), strings(&[&tee]));

    // Headless sudo is NeedsRoot too.
    let exec = ScriptedExecutor::new().file(B_DEB, &bundle(false)).respond(
        &tee,
        1,
        "",
        "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper",
    );
    let err = store.install(&cert, Scope::System, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::NeedsRoot);

    // Any other failure of the refresh is ToolFailed and quotes stderr.
    let exec = ScriptedExecutor::new().file(B_DEB, &bundle(false)).respond(
        refresh,
        2,
        "",
        "update-ca-certificates: something broke",
    );
    let err = store.install(&cert, Scope::System, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::ToolFailed);
    assert!(
        format!("{err:#}").contains("something broke"),
        "got: {err:#}"
    );
}

// CA-AC14
#[test]
fn debian_uninstall() {
    let cert = fixture_cert();
    let store = LinuxStore(LinuxFamily::Debian);
    let rm = format!("sudo -- rm -f {A_DEB}");
    let refresh = "sudo -- update-ca-certificates --fresh";

    // Present: remove the anchor, rebuild the bundle from scratch.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, FIXTURE)
        .file(B_DEB, &bundle(true));
    let change = store.uninstall(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[&rm, refresh]));
    assert!(change.changed);
    assert_eq!(change.location, A_DEB);
    assert!(change.detail.iter().all(|d| !d.contains("stale")));

    // Absent: nothing.
    let exec = ScriptedExecutor::new().file(B_DEB, &bundle(false));
    let change = store.uninstall(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert!(!change.changed);

    // Stale: the file is ours by name, so it goes, and the detail says
    // what was in it.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, &other_pem())
        .file(B_DEB, &bundle(false));
    let change = store.uninstall(&cert, Scope::System, &exec).unwrap();
    assert_eq!(exec.runs(), strings(&[&rm, refresh]));
    assert!(change.changed);
    assert!(
        change
            .detail
            .iter()
            .any(|d| d.contains("stale") && d.contains(&other_fp256())),
        "detail: {:?}",
        change.detail
    );

    // Root: no sudo.
    let exec = ScriptedExecutor::new()
        .root(true)
        .file(A_DEB, FIXTURE)
        .file(B_DEB, &bundle(true));
    store.uninstall(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        strings(&[&format!("rm -f {A_DEB}"), "update-ca-certificates --fresh"])
    );

    // Permission denied on rm: NeedsRoot.
    let exec = ScriptedExecutor::new()
        .file(A_DEB, FIXTURE)
        .file(B_DEB, &bundle(true))
        .respond(
            &rm,
            1,
            "",
            &format!("rm: cannot remove '{A_DEB}': Operation not permitted"),
        );
    let err = store.uninstall(&cert, Scope::System, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::NeedsRoot);
}

// CA-AC15
#[test]
fn fedora_install_uninstall() {
    let cert = fixture_cert();
    let store = LinuxStore(LinuxFamily::Fedora);
    let refresh = "sudo -- update-ca-trust extract";

    let exec = ScriptedExecutor::new().file(B_FED, &bundle(false));
    let change = store.install(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        strings(&[&format!("sudo -- tee {A_FED}"), refresh])
    );
    assert_eq!(exec.stdins()[0], Some(FIXTURE.to_vec()));
    assert!(change.changed);
    assert_eq!(change.location, A_FED);

    let exec = ScriptedExecutor::new()
        .file(A_FED, FIXTURE)
        .file(B_FED, &bundle(true));
    let change = store.uninstall(&cert, Scope::System, &exec).unwrap();
    assert_eq!(
        exec.runs(),
        strings(&[&format!("sudo -- rm -f {A_FED}"), refresh])
    );
    assert!(change.changed);
}

// CA-AC16
#[test]
fn user_scope_rejected() {
    let cert = fixture_cert();
    let exec = ScriptedExecutor::new()
        .file(A_DEB, FIXTURE)
        .file(B_DEB, &bundle(true));

    for family in [LinuxFamily::Debian, LinuxFamily::Fedora] {
        let store = LinuxStore(family);
        for err in [
            store.status(&cert, Scope::User, &exec).unwrap_err(),
            store.install(&cert, Scope::User, &exec).unwrap_err(),
            store.uninstall(&cert, Scope::User, &exec).unwrap_err(),
        ] {
            assert_eq!(kind_of(&err), TrustErrorKind::UnsupportedScope);
            let text = format!("{err:#}");
            assert!(text.contains("no per-user OS trust store"), "got: {text}");
            assert!(text.contains("--scope system"), "got: {text}");
        }
        assert_eq!(Platform::Linux(family).default_scope(), Some(Scope::System));
    }
    // Rejected before anything touched the host.
    assert_eq!(exec.runs(), Vec::<String>::new());
    assert_eq!(exec.reads(), Vec::<PathBuf>::new());
}

// CA-AC17
#[test]
fn family_detection() {
    // Exactly one anchor directory: that family.
    let exec = ScriptedExecutor::new().dir(FEDORA_DIR);
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Fedora));
    assert_eq!(exec.reads(), Vec::<PathBuf>::new());

    let exec = ScriptedExecutor::new().dir(DEBIAN_DIR);
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Debian));
    assert_eq!(exec.reads(), Vec::<PathBuf>::new());

    // Both: os-release breaks the tie.
    let both = || ScriptedExecutor::new().dir(FEDORA_DIR).dir(DEBIAN_DIR);

    let exec = both().file(
        "/etc/os-release",
        b"PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nNAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n",
    );
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Debian));
    assert_eq!(exec.reads(), paths(&["/etc/os-release"]));

    let exec = both().file(
        "/etc/os-release",
        b"NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel fedora\"\n",
    );
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Fedora));

    let exec = both().file("/etc/os-release", b"ID=debian\n");
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Debian));

    let exec = both().file("/etc/os-release", b"ID=\"centos\"\n");
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Fedora));

    // Neither token family: Fedora, first in mkcert's order.
    let exec = both().file("/etc/os-release", b"ID=arch\n");
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Fedora));

    // /etc/os-release missing: /usr/lib/os-release is consulted.
    let exec = both().file("/usr/lib/os-release", b"ID=ubuntu\n");
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Debian));
    assert_eq!(
        exec.reads(),
        paths(&["/etc/os-release", "/usr/lib/os-release"])
    );

    // No os-release at all: Fedora.
    let exec = both();
    assert_eq!(detect_linux_family(&exec), Some(LinuxFamily::Fedora));
    assert_eq!(
        exec.reads(),
        paths(&["/etc/os-release", "/usr/lib/os-release"])
    );

    // Neither directory: no family, and a Linux host is unsupported.
    let exec = ScriptedExecutor::new();
    assert_eq!(detect_linux_family(&exec), None);
    assert_eq!(
        Platform::detect_with_os("linux", &exec),
        Platform::Unsupported("linux".to_string())
    );
    let cert = fixture_cert();
    let store = store_for(&Platform::Unsupported("linux".to_string()));
    let err = store.install(&cert, Scope::System, &exec).unwrap_err();
    assert_eq!(kind_of(&err), TrustErrorKind::UnsupportedPlatform);
    let text = format!("{err:#}");
    assert!(text.contains(FEDORA_DIR), "got: {text}");
    assert!(text.contains(DEBIAN_DIR), "got: {text}");
    assert!(text.contains("/ca/ca.crt"), "got: {text}");
    assert!(text.contains("ca-certificates package"), "got: {text}");
}
