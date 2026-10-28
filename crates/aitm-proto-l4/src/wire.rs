//! The single guarded wire-write choke point (M5 Task 6).
//!
//! [`send_on_wire`] is the **only** function in the crate that puts crafted bytes
//! on the wire. It cannot be called without an [`L4Permit`], and the only way to
//! obtain one is [`L4Guard::check`](crate::guard::L4Guard::check) — the permit's
//! constructor is private to the guard module, so it cannot be forged. Thus an
//! unpermitted wire write is **impossible by construction** (AC21): there is no
//! unchecked path from crafted bytes to the network.
//!
//! The permit is threaded by `&mut` so one authorization meters a whole batch:
//! `send_on_wire` calls [`L4Permit::authorize_packet`] before every write, which
//! spends the permit's bounded size + per-call-count budget. (The guard handover
//! for M5 Tasks 4+5 is explicit that the permit must be threaded, not consumed
//! per packet, or the count budget is meaningless.)

use crate::backend::{CaptureInjectBackend, L4Error};
use crate::guard::{L4GuardError, L4Permit};
use crate::types::{L4Action, L4Capability};

/// Put one crafted frame on the wire through the backend — the single guarded
/// choke point for injection and send-and-receive.
///
/// Requires an injection [`L4Permit`] (minted only by
/// [`L4Guard::check`](crate::guard::L4Guard::check)); the call site cannot forge
/// one, so this is the sole path from crafted bytes to the network. The permit is
/// taken by `&mut` so a batch loop threads one authorization: each call spends one
/// slot of the permit's size + count budget via
/// [`authorize_packet`](L4Permit::authorize_packet).
///
/// Order of checks: (1) the permit must authorize **injection** — a `Capture` or
/// `Intercept` permit never spent injection rate, so admitting it here would be a
/// rate-cap bypass; (2) the packet's size and the per-call count budget; (3) the
/// backend write. Any failure before step 3 means nothing reached the wire.
///
/// # Permit is unforgeable
///
/// [`L4Permit`]'s fields are private to the guard module, so it cannot be
/// constructed except via [`L4Guard::check`](crate::guard::L4Guard::check):
///
/// ```compile_fail
/// use aitm_proto_l4::guard::{L4Permit, L4Action};
/// // error[E0451]: fields of `L4Permit` are private — no way to forge the token
/// // `send_on_wire` demands.
/// let _forged = L4Permit { action: L4Action::Inject };
/// ```
///
/// # Errors
///
/// - [`L4Error::Guard`] with [`L4GuardError::CapabilityNotGranted`] if the permit
///   is not an injection permit;
/// - [`L4Error::Guard`] with [`L4GuardError::PacketTooLarge`] /
///   [`L4GuardError::CountExceeded`] if the permit's budget refuses the packet;
/// - [`L4Error::Unavailable`] / [`L4Error::WireWrite`] from the backend.
pub fn send_on_wire(
    permit: &mut L4Permit,
    backend: &dyn CaptureInjectBackend,
    iface: &str,
    bytes: &[u8],
) -> Result<(), L4Error> {
    // (1) Only an injection permit opens the wire-write path. A Capture/Intercept
    // permit did not consume injection rate at check() time; letting it write here
    // would bypass the rate cap. Defense in depth — callers already check(Inject).
    if permit.action() != L4Action::Inject {
        return Err(L4Error::Guard(L4GuardError::CapabilityNotGranted(
            L4Capability::Inject,
        )));
    }
    // (2) Size + per-call count budget, spent on the permit before every write. A
    // refusal here (PacketTooLarge / CountExceeded) returns before any wire write.
    permit.authorize_packet(bytes.len())?;
    // (3) The one and only wire write.
    backend.inject(iface, bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::backend::CaptureSource;
    use crate::config::L4Config;
    use crate::guard::L4Guard;
    use crate::types::{
        IpCidr, L4Capability, L4Direction, L4Proto, L4ScopeEntry, L4ScopeId, L4Target, PortRange,
        RateCap,
    };

    /// An in-memory backend: records injected frames, or simulates the absence of
    /// privilege/libpcap by failing fail-closed. No wire, no privilege.
    struct MockBackend {
        available: bool,
        sent: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockBackend {
        fn available() -> Self {
            Self {
                available: true,
                sent: Mutex::new(Vec::new()),
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(String, Vec<u8>)> {
            self.sent.lock().unwrap().clone()
        }
    }

    struct EmptySource;
    impl CaptureSource for EmptySource {
        fn next_frame(&mut self) -> Result<Option<Vec<u8>>, L4Error> {
            Ok(None)
        }
    }

    impl CaptureInjectBackend for MockBackend {
        fn open_capture(
            &self,
            _iface: &str,
            _filter: Option<&str>,
            _read_timeout: Duration,
        ) -> Result<Box<dyn CaptureSource>, L4Error> {
            if self.available {
                Ok(Box::new(EmptySource))
            } else {
                Err(L4Error::Unavailable("no privilege (mock)".into()))
            }
        }

        fn inject(&self, iface: &str, bytes: &[u8]) -> Result<(), L4Error> {
            if self.available {
                self.sent
                    .lock()
                    .unwrap()
                    .push((iface.to_string(), bytes.to_vec()));
                Ok(())
            } else {
                Err(L4Error::Unavailable("no privilege (mock)".into()))
            }
        }
    }

    fn scope_entry(cap: L4Capability, rate: (u32, u32)) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: "127.0.0.1".parse().unwrap(),
                prefix: 32,
            },
            ports: PortRange { lo: 0, hi: 65535 },
            interface: "lo0".to_string(),
            direction: L4Direction::Outbound,
            capability: cap,
            inject_rate: RateCap {
                pps: rate.0,
                burst: rate.1,
            },
        }
    }

    fn target() -> L4Target {
        L4Target {
            interface: "lo0".to_string(),
            direction: L4Direction::Outbound,
            dst: Some("127.0.0.1".parse().unwrap()),
            dst_port: Some(9),
            proto: L4Proto::Udp,
        }
    }

    fn guard_for(cfg: L4Config, cap: L4Capability, rate: (u32, u32)) -> L4Guard {
        let g = L4Guard::new(&cfg);
        g.add_scope(scope_entry(cap, rate)).unwrap();
        g
    }

    /// AC21 — `send_on_wire` requires an `L4Permit` (its type), and with a valid
    /// injection permit it hands exactly the given frame to the backend. Combined
    /// with the `compile_fail` doctest (the permit is unforgeable), an unpermitted
    /// wire write is impossible by construction.
    #[test]
    fn send_on_wire_requires_permit() {
        let g = guard_for(L4Config::default(), L4Capability::Inject, (100, 100));
        let mut permit = g.check(L4Action::Inject, &target()).unwrap();
        let backend = MockBackend::available();

        assert!(send_on_wire(&mut permit, &backend, "lo0", b"probe").is_ok());

        let sent = backend.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "lo0");
        assert_eq!(sent[0].1, b"probe");
    }

    /// AC17/AC20 — with libpcap/privilege absent the backend fails closed
    /// (`L4Unavailable`), both directly and through the choke point, never panics.
    #[test]
    fn backend_unavailable_without_privilege() {
        let g = guard_for(L4Config::default(), L4Capability::Inject, (100, 100));
        let mut permit = g.check(L4Action::Inject, &target()).unwrap();
        let backend = MockBackend::unavailable();

        // Directly on the backend.
        assert!(matches!(
            backend.inject("lo0", b"x"),
            Err(L4Error::Unavailable(_))
        ));

        // And routed through the single choke point.
        assert!(matches!(
            send_on_wire(&mut permit, &backend, "lo0", b"x"),
            Err(L4Error::Unavailable(_))
        ));
    }

    /// AC21 — a non-injection permit (Capture) must not open the wire-write path:
    /// it never spent injection rate, so admitting it would bypass the rate cap.
    #[test]
    fn send_on_wire_rejects_non_inject_permit() {
        let g = guard_for(L4Config::default(), L4Capability::Capture, (100, 100));
        let mut permit = g.check(L4Action::Capture, &target()).unwrap();
        let backend = MockBackend::available();

        assert_eq!(
            send_on_wire(&mut permit, &backend, "lo0", b"x"),
            Err(L4Error::Guard(L4GuardError::CapabilityNotGranted(
                L4Capability::Inject
            )))
        );
        // Nothing reached the wire.
        assert!(backend.sent().is_empty());
    }

    /// AC6/AC21 — the permit's size budget is spent before the write: an oversize
    /// packet is refused at the choke point and nothing reaches the backend.
    #[test]
    fn send_on_wire_enforces_size_budget() {
        let cfg = L4Config {
            max_packet_bytes: 4,
            ..L4Config::default()
        };
        let g = guard_for(cfg, L4Capability::Inject, (100, 100));
        let mut permit = g.check(L4Action::Inject, &target()).unwrap();
        let backend = MockBackend::available();

        assert_eq!(
            send_on_wire(&mut permit, &backend, "lo0", b"toolong"),
            Err(L4Error::Guard(L4GuardError::PacketTooLarge { max: 4 }))
        );
        assert!(backend.sent().is_empty());
        // The refused oversize packet consumed no count budget: a legal one works.
        assert!(send_on_wire(&mut permit, &backend, "lo0", b"ok").is_ok());
        assert_eq!(backend.sent().len(), 1);
    }

    /// AC6/AC21 — one permit threads a whole batch: `send_on_wire` spends the
    /// per-call count budget across calls, and the call past the ceiling is
    /// refused with nothing further on the wire.
    #[test]
    fn send_on_wire_threads_count_budget() {
        let cfg = L4Config {
            max_packets_per_call: 2,
            ..L4Config::default()
        };
        let g = guard_for(cfg, L4Capability::Inject, (100, 100));
        let mut permit = g.check(L4Action::Inject, &target()).unwrap();
        let backend = MockBackend::available();

        assert!(send_on_wire(&mut permit, &backend, "lo0", b"a").is_ok());
        assert!(send_on_wire(&mut permit, &backend, "lo0", b"b").is_ok());
        assert_eq!(
            send_on_wire(&mut permit, &backend, "lo0", b"c"),
            Err(L4Error::Guard(L4GuardError::CountExceeded { max: 2 }))
        );
        assert_eq!(backend.sent().len(), 2);
    }
}
