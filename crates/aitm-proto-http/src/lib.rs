//! `aitm-proto-http` — HTTP/1.1 protocol module (TLS MITM + sans-IO HTTP).

pub mod ca;
mod h2;
mod h2_sender;
pub mod module;
pub mod raw_h2;
pub mod sansio;
pub mod sender;
mod translate;

pub use ca::{CertAuthority, LeafCert};
pub use module::HttpModule;
pub use sansio::{Http1Machine, HttpSansIoEvent, HttpStateMachine, Side};
pub use sender::{
    is_h2_not_negotiated, Dialer, HostResolver, Http1Sender, HttpSender, Negotiated, ProbeStream,
    SendError,
};
