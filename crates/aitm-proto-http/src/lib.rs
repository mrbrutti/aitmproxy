//! `aitm-proto-http` — HTTP/1.1 protocol module (TLS MITM + sans-IO HTTP).

pub mod ca;

pub use ca::{CertAuthority, LeafCert};
