//! The error taxonomy: `GuardError` (scope/rate refusals) and `FlowError`
//! (everything that can go wrong driving a flow). Both implement
//! [`std::error::Error`] so they compose with `anyhow` and `?`.

use std::time::Duration;

/// A typed refusal from the scope/rate guard. Every active action passes the
/// guard first; these are the ways it says no.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardError {
    /// The host is not in scope (deny-by-default).
    OutOfScope(String),
    /// SSRF guard: a private/loopback address that is not explicitly in scope.
    PrivateAddressBlocked(String),
    /// A rate limit was hit; retry after the given delay.
    RateLimited { retry_after: Duration },
    /// The concurrency cap is full.
    ConcurrencyExceeded,
    /// The host's error budget is exhausted; it is temporarily disabled.
    HostDisabled,
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::OutOfScope(host) => {
                write!(f, "host {host} is out of scope")
            }
            GuardError::PrivateAddressBlocked(host) => {
                write!(
                    f,
                    "private or loopback address {host} blocked by the SSRF guard and not in scope"
                )
            }
            GuardError::RateLimited { retry_after } => {
                write!(f, "rate limited; retry after {retry_after:?}")
            }
            GuardError::ConcurrencyExceeded => write!(f, "concurrency limit exceeded"),
            GuardError::HostDisabled => write!(f, "host disabled: error budget exhausted"),
        }
    }
}

impl std::error::Error for GuardError {}

/// Everything that can go wrong while driving a single flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// A TLS handshake or certificate failure.
    Tls(String),
    /// An upstream connection or I/O failure.
    Upstream(String),
    /// A protocol parse/encode failure.
    Protocol(String),
    /// The operation timed out.
    Timeout,
    /// The flow was killed by a plugin or command.
    Killed,
    /// A scope/rate guard refusal.
    Guard(GuardError),
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowError::Tls(msg) => write!(f, "TLS error: {msg}"),
            FlowError::Upstream(msg) => write!(f, "upstream error: {msg}"),
            FlowError::Protocol(msg) => write!(f, "protocol error: {msg}"),
            FlowError::Timeout => write!(f, "timed out"),
            FlowError::Killed => write!(f, "flow killed"),
            FlowError::Guard(err) => write!(f, "guard refused: {err}"),
        }
    }
}

impl std::error::Error for FlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FlowError::Guard(err) => Some(err),
            _ => None,
        }
    }
}

impl From<GuardError> for FlowError {
    fn from(err: GuardError) -> Self {
        FlowError::Guard(err)
    }
}
