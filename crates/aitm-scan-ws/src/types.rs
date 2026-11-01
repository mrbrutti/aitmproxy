//! Shared value types and numeric bounds for the WebSocket lane.
//!
//! Owned by **task 1** of the T4 plan and written in wave 1 so that `discover`,
//! `mutate`, `host`, `dialer` and `lane` can be built in parallel in wave 2
//! without any two of them sharing a file (plan call 10).

use std::time::Duration;

/// Where inside a captured WebSocket conversation a payload is placed.
///
/// A [`Locator`] addresses one mutable position: a leaf of a JSON text frame, a
/// pair of a form-encoded text frame, a whole text or binary frame, or a request
/// header of the upgrade handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locator {
    /// A leaf of a JSON text frame, addressed by a dotted/bracket path.
    JsonPath(String),
    /// One pair of a form-urlencoded text frame, addressed by its key.
    FormParam(String),
    /// The whole payload of a text frame.
    WholeText,
    /// The whole payload of a binary frame.
    Binary,
    /// A request header of the upgrade handshake, addressed by its name.
    HandshakeHeader(String),
}

/// Everything the lane needs to re-drive one discovered insertion point.
///
/// The lane keeps these in a registry keyed by point id; `probe_host_for` looks
/// a point up and errors on an id it does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointSpec {
    /// The captured WebSocket conversation the point was discovered in.
    pub ws_flow: aitm_core::FlowId,
    /// The HTTP flow carrying that conversation's upgrade handshake.
    pub handshake: aitm_core::FlowId,
    /// Index into the conversation's messages of the client->server frame the
    /// payload is placed in; `None` when the flow carries no client frame.
    pub frame_index: Option<usize>,
    /// The position inside that frame (or handshake) the payload replaces.
    pub locator: Locator,
}

/// Changes a probe applies to the captured handshake request before dialling.
///
/// `set` replaces (or adds) a header; `strip` removes one. Both are applied over
/// the replayed capture, so a probe states only its difference from the capture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandshakeOverrides {
    /// Headers to set on the handshake request, as `(name, value)` pairs.
    pub set: Vec<(String, String)>,
    /// Names of headers to remove from the handshake request.
    pub strip: Vec<String>,
}

impl HandshakeOverrides {
    /// Overrides that set one header to `value`.
    #[must_use]
    pub fn set(name: &str, value: &str) -> Self {
        Self {
            set: vec![(name.to_string(), value.to_string())],
            strip: Vec::new(),
        }
    }

    /// Overrides that strip one header.
    #[must_use]
    pub fn strip(name: &str) -> Self {
        Self {
            set: Vec::new(),
            strip: vec![name.to_string()],
        }
    }

    /// The same overrides with one more header stripped.
    #[must_use]
    pub fn and_strip(mut self, name: &str) -> Self {
        self.strip.push(name.to_string());
        self
    }
}

/// How the dialer treats the upstream server certificate.
///
/// The lane and the language both dial with [`TlsPolicy::AcceptAny`] (plan call
/// 3): the scanner only ever connects to authorities the operator put in scope,
/// and lab targets routinely carry self-signed certificates. A named item for
/// the security review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsPolicy {
    /// Verify the certificate chain against the webpki root store.
    Verify,
    /// Accept any certificate the server presents.
    AcceptAny,
}

/// Concurrent WebSocket connections a lane's dialer may hold open at once.
pub const MAX_CONNECTIONS: usize = 4;

/// Probe conversations a probe host keeps for `held_flows()` (newest kept).
pub const HELD_PROBES: usize = 16;

/// Open `ws.*` script handles the language admits before refusing a `ws.dial`.
pub const MAX_HANDLES: usize = 4;

/// Upper bound the `ws.recv` script fn clamps its `timeout_ms` argument to.
pub const RECV_TIMEOUT_CAP_MS: u32 = 30_000;

/// Idle time after which the language's driver reaps an open script handle.
pub const HANDLE_IDLE_REAP: Duration = Duration::from_secs(30);

/// The port a scheme implies when an authority carries none.
///
/// `https` and `wss` imply 443; anything else (`http`, `ws`) implies 80.
#[must_use]
pub fn default_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss") {
        443
    } else {
        80
    }
}

/// `authority` with the scheme's [`default_port`] appended when it has none.
///
/// An authority that already names a port is returned unchanged. A bracketed
/// IPv6 literal is handled by looking for the `:` *after* the closing bracket,
/// so `[::1]` gains a port and `[::1]:8443` does not.
#[must_use]
pub fn authority_with_port(scheme: &str, authority: &str) -> String {
    // Everything after the last `]`; the whole authority when there is none.
    let after_brackets = authority.rsplit(']').next().unwrap_or(authority);
    if after_brackets.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:{}", default_port(scheme))
    }
}

#[cfg(test)]
mod tests {
    use super::{authority_with_port, default_port, HandshakeOverrides};

    #[test]
    fn default_port_by_scheme() {
        assert_eq!(default_port("wss"), 443);
        assert_eq!(default_port("https"), 443);
        assert_eq!(default_port("ws"), 80);
        assert_eq!(default_port("http"), 80);
    }

    #[test]
    fn authority_gets_default_port_once() {
        assert_eq!(authority_with_port("ws", "127.0.0.1"), "127.0.0.1:80");
        assert_eq!(authority_with_port("wss", "app.test:8443"), "app.test:8443");
        assert_eq!(authority_with_port("wss", "[::1]"), "[::1]:443");
    }

    #[test]
    fn overrides_builder() {
        assert_eq!(
            HandshakeOverrides::set("Origin", "x").and_strip("Cookie"),
            HandshakeOverrides {
                set: vec![("Origin".into(), "x".into())],
                strip: vec!["Cookie".into()],
            }
        );
    }
}
