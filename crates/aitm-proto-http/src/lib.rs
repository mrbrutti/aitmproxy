//! `aitm-proto-http` — HTTP/1.1 protocol module (TLS MITM + sans-IO HTTP).

pub mod ca;
pub mod sansio;

pub use ca::{CertAuthority, LeafCert};
pub use sansio::{Http1Machine, HttpSansIoEvent, HttpStateMachine, Side};
