//! Test support shared by this crate's integration tests: the fingerprints of
//! the checked-in fixture CA (`tests/fixtures/ca.crt`), and, from later
//! tasks, the `Executor` and `AuditLog` doubles.
//!
//! The fixture is a self-signed P-256 certificate whose key was discarded at
//! generation; only the certificate is in the tree.

/// SHA-256 fingerprint of `tests/fixtures/ca.crt`, colon form, exactly as
/// `openssl x509 -noout -fingerprint -sha256` prints it.
pub const FIXTURE_FP256: &str =
    "41:88:D2:5C:9E:BD:56:21:31:81:52:AD:D8:CE:78:C4:9C:40:77:C4:07:D1:7F:0D:4B:58:6E:22:E4:4A:CA:43";

/// SHA-1 fingerprint of `tests/fixtures/ca.crt`, colon form, exactly as
/// `openssl x509 -noout -fingerprint -sha1` prints it.
pub const FIXTURE_FP1: &str = "B1:30:2C:92:2B:7C:A0:78:5D:76:E0:A0:00:43:01:51:1C:05:92:90";
