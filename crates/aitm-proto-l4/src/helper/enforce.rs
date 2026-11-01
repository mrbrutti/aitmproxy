//! Helper-side guard enforcement and capture filter (spec §5.3, plan P1a.4).
//!
//! The privileged helper never trusts a decision from the core. For every
//! `Inject` it parses the frame itself ([`inject_target`]) and runs the **same**
//! [`L4Guard::check`] and [`L4Permit::authorize_packet`](crate::guard::L4Permit::authorize_packet)
//! the core runs, over the scope it holds from the last [`ScopeSet`], with its
//! own rate buckets. For `CaptureOpen` it refuses an interface no `Capture`
//! entry covers and compiles its own BPF filter with the same
//! [`scope_filter`]; it accepts no filter string from the other side. Same
//! crate, same functions, no re-implementation. Pure: no I/O, no system state.

use crate::capture::scope_filter;
use crate::guard::{interface_covers, L4Guard};
use crate::helper::frame::{inject_target, LinkType};
use crate::helper::proto::ScopeSet;
use crate::types::{L4Action, L4Capability};

/// The helper's own deny-by-default guard, built from a [`ScopeSet`].
///
/// Wraps an [`L4Guard`] over `ScopeSet::to_config()` with the set's
/// `self_ports` applied (they have no home in `L4Config`, so the core applies
/// them separately too). Its rate buckets belong to this instance, so the
/// helper meters independently of the core: a budget the core already spent
/// is not spent here, and vice versa.
pub struct HelperGuard {
    guard: L4Guard,
    /// The `ScopeSet`'s per-packet ceiling, applied by the frame parser before
    /// a byte is decoded (the guard applies it again at `authorize_packet`).
    max_packet_bytes: usize,
}

impl HelperGuard {
    /// Build the helper's guard from the scope the core sent.
    #[must_use]
    pub fn from_scope_set(s: &ScopeSet) -> Self {
        let guard = L4Guard::new(&s.to_config());
        guard.set_self_ports(s.self_ports.iter().copied());
        Self {
            guard,
            max_packet_bytes: s.max_packet_bytes,
        }
    }

    /// Decide one inject: derive the target from `frame` (never from a claim),
    /// check it against the scope for [`L4Action::Inject`], then spend one
    /// packet of size, count and rate budget. The frame is sent only on `Ok`.
    ///
    /// # Errors
    /// The `Display` text of the refusing [`FrameError`](crate::helper::frame::FrameError)
    /// or [`L4GuardError`](crate::guard::L4GuardError), verbatim, so a scope
    /// refusal reads exactly as the core's would.
    pub fn check_inject(
        &self,
        interface: &str,
        link: LinkType,
        frame: &[u8],
    ) -> Result<(), String> {
        let target = inject_target(interface, link, frame, self.max_packet_bytes)
            .map_err(|e| e.to_string())?;
        let mut permit = self
            .guard
            .check(L4Action::Inject, &target)
            .map_err(|e| e.to_string())?;
        permit
            .authorize_packet(frame.len())
            .map_err(|e| e.to_string())
    }

    /// The BPF filter a capture on `interface` opens with, compiled from this
    /// guard's own scope by the shared [`scope_filter`]. `Ok(None)` means the
    /// scope declines to narrow the capture (the per-packet guard still
    /// decides). It takes no filter from the caller.
    ///
    /// # Errors
    /// An interface no `Capture`-capability scope entry covers is refused
    /// before any filter is built.
    pub fn capture_filter(&self, interface: &str) -> Result<Option<String>, String> {
        let covered = self
            .guard
            .list_scope()
            .iter()
            .any(|e| e.capability == L4Capability::Capture && interface_covers(e, interface));
        if !covered {
            return Err(format!(
                "interface {interface} is outside the capture scope"
            ));
        }
        Ok(scope_filter(&self.guard, interface))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::HelperGuard;
    use crate::capture::scope_filter;
    use crate::craft::{EtherSpec, Ipv4Spec, Layer, PacketSpec, UdpSpec};
    use crate::guard::L4Guard;
    use crate::helper::frame::LinkType;
    use crate::helper::proto::ScopeSet;
    use crate::types::{
        IpCidr, L4Capability, L4Direction, L4ScopeEntry, L4ScopeId, L4ScopeSource, PortRange,
        RateCap,
    };

    /// The inject ceiling the `ScopeSet` below carries.
    const MAX_PACKET_BYTES: usize = 1500;

    /// One operator-declared entry: `interface`, 127.0.0.1/32, ports 9000-9999,
    /// outbound, granting `cap` at `pps` packets/sec.
    fn entry(interface: &str, cap: L4Capability, pps: u32) -> L4ScopeEntry {
        L4ScopeEntry {
            id: L4ScopeId::new(),
            cidr: IpCidr {
                addr: Ipv4Addr::LOCALHOST.into(),
                prefix: 32,
            },
            ports: PortRange { lo: 9000, hi: 9999 },
            interface: interface.to_string(),
            direction: L4Direction::Outbound,
            capability: cap,
            inject_rate: RateCap { pps, burst: pps },
            source: L4ScopeSource::Config,
        }
    }

    /// The rig's scope as the core would send it: `lo`, `127.0.0.1/32`,
    /// `9000-9999`, one `Capture` and one `Inject` entry, sane limits, no self
    /// ports.
    fn scope_set() -> ScopeSet {
        ScopeSet {
            scope: vec![
                entry("lo", L4Capability::Capture, 10),
                entry("lo", L4Capability::Inject, 10),
            ],
            global_inject_pps: 100,
            max_packet_bytes: MAX_PACKET_BYTES,
            max_packets_per_call: 8,
            self_ports: Vec::new(),
        }
    }

    /// An Ethernet IPv4/UDP frame 127.0.0.1:40000 → 127.0.0.1:`dst_port` with a
    /// 5-byte payload, framed the way Linux `lo` carries it (zero-MAC Ethernet).
    fn eth_udp(dst_port: u16) -> Vec<u8> {
        PacketSpec {
            layers: vec![
                Layer::Ether(EtherSpec::default()),
                Layer::Ipv4(Ipv4Spec {
                    src: Some(Ipv4Addr::LOCALHOST),
                    dst: Some(Ipv4Addr::LOCALHOST),
                    ..Ipv4Spec::default()
                }),
                Layer::Udp(UdpSpec {
                    src_port: Some(40_000),
                    dst_port: Some(dst_port),
                    ..UdpSpec::default()
                }),
                Layer::Raw(b"probe".to_vec()),
            ],
        }
        .build()
        .expect("craft builds")
    }

    #[test]
    fn inject_below_the_port_range_is_out_of_scope() {
        let hg = HelperGuard::from_scope_set(&scope_set());
        let err = hg
            .check_inject("lo", LinkType::Ethernet, &eth_udp(8999))
            .expect_err("8999 is outside 9000-9999");
        assert!(err.contains("scope"), "{err}");
        assert_eq!(err, "target 127.0.0.1 is out of L4 scope");
    }

    #[test]
    fn inject_inside_scope_is_admitted() {
        let hg = HelperGuard::from_scope_set(&scope_set());
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &eth_udp(9053)),
            Ok(())
        );
    }

    #[test]
    fn inject_on_an_interface_no_entry_names_is_out_of_scope() {
        // Same in-scope bytes, but the helper would send them on `eth9`: the
        // target's interface comes from the helper, and no entry covers it.
        let hg = HelperGuard::from_scope_set(&scope_set());
        assert_eq!(
            hg.check_inject("eth9", LinkType::Ethernet, &eth_udp(9053)),
            Err("target 127.0.0.1 is out of L4 scope".to_string())
        );
    }

    #[test]
    fn oversized_frame_is_refused_by_its_size_before_anything_else() {
        let hg = HelperGuard::from_scope_set(&scope_set());
        let big = vec![0u8; MAX_PACKET_BYTES + 1];
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &big),
            Err("inject frame of 1501 bytes exceeds the limit".to_string())
        );
    }

    #[test]
    fn truncated_frame_is_refused_with_the_parser_text() {
        let hg = HelperGuard::from_scope_set(&scope_set());
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &[0u8; 10]),
            Err("inject frame is truncated".to_string())
        );
    }

    #[test]
    fn helper_meters_its_own_rate_buckets() {
        // An Inject entry allowing 2 pps with a burst of 2: the third packet in
        // the same instant is refused by the helper's own bucket, and a fresh
        // core-side guard over the same ScopeSet is untouched by that spend.
        let s = ScopeSet {
            scope: vec![
                entry("lo", L4Capability::Capture, 10),
                entry("lo", L4Capability::Inject, 2),
            ],
            ..scope_set()
        };
        let hg = HelperGuard::from_scope_set(&s);
        let frame = eth_udp(9053);
        assert_eq!(hg.check_inject("lo", LinkType::Ethernet, &frame), Ok(()));
        assert_eq!(hg.check_inject("lo", LinkType::Ethernet, &frame), Ok(()));
        let third = hg
            .check_inject("lo", LinkType::Ethernet, &frame)
            .expect_err("the burst of 2 is spent");
        assert!(
            third.starts_with("injection rate exceeded; retry after "),
            "{third}"
        );

        let core = L4Guard::new(&s.to_config());
        let target =
            crate::helper::frame::inject_target("lo", LinkType::Ethernet, &frame, MAX_PACKET_BYTES)
                .expect("a target");
        let mut permit = core
            .check(crate::types::L4Action::Inject, &target)
            .expect("the core's buckets are its own");
        assert_eq!(permit.authorize_packet(frame.len()), Ok(()));
    }

    #[test]
    fn capture_filter_refuses_an_interface_no_capture_entry_covers() {
        // `eth9` has an Inject entry but no Capture entry; `wlan0` has nothing.
        let s = ScopeSet {
            scope: vec![
                entry("lo", L4Capability::Capture, 10),
                entry("eth9", L4Capability::Inject, 10),
            ],
            ..scope_set()
        };
        let hg = HelperGuard::from_scope_set(&s);
        assert_eq!(
            hg.capture_filter("eth9"),
            Err("interface eth9 is outside the capture scope".to_string())
        );
        assert_eq!(
            hg.capture_filter("wlan0"),
            Err("interface wlan0 is outside the capture scope".to_string())
        );
    }

    #[test]
    fn capture_filter_is_the_shared_scope_filter_with_self_ports_applied() {
        let s = ScopeSet {
            self_ports: vec![27431],
            ..scope_set()
        };
        let hg = HelperGuard::from_scope_set(&s);

        let reference = L4Guard::new(&s.to_config());
        reference.set_self_ports(s.self_ports.iter().copied());
        let expected = scope_filter(&reference, "lo");

        assert_eq!(hg.capture_filter("lo"), Ok(expected.clone()));
        // Not `None == None`: the literal the kernel will be handed.
        assert_eq!(
            expected,
            Some("(host 127.0.0.1 and portrange 9000-9999) and not port 27431".to_string())
        );
    }

    #[test]
    fn capture_filter_without_self_ports_is_the_bare_scope_clause() {
        let hg = HelperGuard::from_scope_set(&scope_set());
        assert_eq!(
            hg.capture_filter("lo"),
            Ok(Some("host 127.0.0.1 and portrange 9000-9999".to_string()))
        );
    }

    // ---- Tester edge cases (stage 5, unit p1a) ----------------------------

    #[test]
    fn tester_empty_scope_denies_every_inject_and_every_capture() {
        // Deny by default: a ScopeSet with no entries admits nothing, on any
        // interface, and opens no capture.
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            scope: Vec::new(),
            ..scope_set()
        });
        for iface in ["lo", "lo0", "eth0", "*"] {
            assert_eq!(
                hg.check_inject(iface, LinkType::Ethernet, &eth_udp(9053)),
                Err("target 127.0.0.1 is out of L4 scope".to_string()),
                "{iface}"
            );
            assert_eq!(
                hg.capture_filter(iface),
                Err(format!("interface {iface} is outside the capture scope")),
                "{iface}"
            );
        }
    }

    #[test]
    fn tester_global_inject_pps_zero_refuses_an_in_scope_inject_up_front() {
        // A tool-wide ceiling of 0 means "injection disabled": refused before
        // a permit exists, with the guard's own text.
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            global_inject_pps: 0,
            ..scope_set()
        });
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &eth_udp(9053)),
            Err("injection rate exceeded; retry after 1s".to_string())
        );
        // Capture is unaffected by the injection ceiling.
        assert_eq!(
            hg.capture_filter("lo"),
            Ok(Some("host 127.0.0.1 and portrange 9000-9999".to_string()))
        );
        // A per-entry pps of 0 refuses the same way.
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            scope: vec![
                entry("lo", L4Capability::Capture, 10),
                entry("lo", L4Capability::Inject, 0),
            ],
            ..scope_set()
        });
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &eth_udp(9053)),
            Err("injection rate exceeded; retry after 1s".to_string())
        );
    }

    #[test]
    fn tester_max_packet_bytes_zero_refuses_every_frame_by_size() {
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            max_packet_bytes: 0,
            ..scope_set()
        });
        let frame = eth_udp(9053);
        assert_eq!(frame.len(), 47);
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &frame),
            Err("inject frame of 47 bytes exceeds the limit".to_string())
        );
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &[0x45]),
            Err("inject frame of 1 bytes exceeds the limit".to_string())
        );
        // An empty frame is not over a zero ceiling; it is truncated.
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &[]),
            Err("inject frame is truncated".to_string())
        );
    }

    #[test]
    fn tester_max_packets_per_call_zero_refuses_after_scope_passes() {
        // The target is in scope and the rate is open, but the per-call
        // budget is 0: `authorize_packet` refuses with the guard's text.
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            max_packets_per_call: 0,
            ..scope_set()
        });
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &eth_udp(9053)),
            Err("more than 0 packets in one call".to_string())
        );
    }

    #[test]
    fn tester_frame_at_exactly_max_packet_bytes_is_judged_on_its_content() {
        // A frame of exactly the ceiling is not oversized: it reaches the
        // guard and is admitted when in scope.
        let frame = eth_udp(9053);
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            max_packet_bytes: frame.len(),
            ..scope_set()
        });
        assert_eq!(hg.check_inject("lo", LinkType::Ethernet, &frame), Ok(()));
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            max_packet_bytes: frame.len() - 1,
            ..scope_set()
        });
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &frame),
            Err("inject frame of 47 bytes exceeds the limit".to_string())
        );
    }

    #[test]
    fn tester_capture_entry_alone_does_not_grant_inject() {
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            scope: vec![entry("lo", L4Capability::Capture, 10)],
            ..scope_set()
        });
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &eth_udp(9053)),
            Err("scope matches but does not grant the Inject capability".to_string())
        );
    }

    #[test]
    fn tester_runtime_sourced_loopback_entry_cannot_lift_the_denylist() {
        // 127.0.0.1 is on the dangerous-destination denylist. Only a
        // config-declared entry lifts it; the helper honours the same rule as
        // the core when the ScopeSet carries a runtime-added entry.
        let runtime = L4ScopeEntry {
            source: L4ScopeSource::Runtime,
            ..entry("lo", L4Capability::Inject, 10)
        };
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            scope: vec![entry("lo", L4Capability::Capture, 10), runtime],
            ..scope_set()
        });
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &eth_udp(9053)),
            Err(
                "destination 127.0.0.1 is on the dangerous-destination denylist and not explicitly scoped"
                    .to_string()
            )
        );
    }

    #[test]
    fn tester_unparseable_frames_never_reach_the_guard() {
        // Each refusal text is the parser's, so the guard's scope is not even
        // consulted for a frame that cannot be placed.
        let hg = HelperGuard::from_scope_set(&scope_set());
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&0x0806u16.to_be_bytes());
        arp.extend_from_slice(&[0u8; 28]);
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &arp),
            Err("inject frame carries no IP packet".to_string())
        );
        // In-scope IPv4 bytes behind a DLT_NULL header the helper was told is
        // Ethernet: the 14-byte "Ethernet header" eats the IP header.
        let mut null = 2u32.to_ne_bytes().to_vec();
        null.extend_from_slice(&eth_udp(9053)[14..]);
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &null),
            Err("inject frame carries no IP packet".to_string())
        );
        // An in-scope destination behind a fragment: no transport, refused.
        let mut frag = eth_udp(9053);
        frag[14 + 6] = 0x20; // More Fragments
        assert_eq!(
            hg.check_inject("lo", LinkType::Ethernet, &frag),
            Err("inject frame carries no transport the guard can name".to_string())
        );
    }

    #[test]
    fn tester_self_port_zero_is_ignored_in_the_filter() {
        // Port 0 is never a bound listener; the guard drops it, so the filter
        // is the bare scope clause.
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            self_ports: vec![0],
            ..scope_set()
        });
        assert_eq!(
            hg.capture_filter("lo"),
            Ok(Some("host 127.0.0.1 and portrange 9000-9999".to_string()))
        );
        // Two real ports are both excluded, literally.
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            self_ports: vec![28182, 0, 27431],
            ..scope_set()
        });
        assert_eq!(
            hg.capture_filter("lo"),
            Ok(Some(
                "(host 127.0.0.1 and portrange 9000-9999) and not (port 27431 or port 28182)"
                    .to_string()
            ))
        );
    }

    #[test]
    fn tester_wildcard_interface_entry_covers_any_capture_interface() {
        let hg = HelperGuard::from_scope_set(&ScopeSet {
            scope: vec![entry("*", L4Capability::Capture, 10)],
            ..scope_set()
        });
        let reference = L4Guard::new(
            &ScopeSet {
                scope: vec![entry("*", L4Capability::Capture, 10)],
                ..scope_set()
            }
            .to_config(),
        );
        for iface in ["lo", "eth9", "wlan0"] {
            assert_eq!(
                hg.capture_filter(iface),
                Ok(scope_filter(&reference, iface)),
                "{iface}"
            );
            assert_eq!(
                hg.capture_filter(iface),
                Ok(Some("host 127.0.0.1 and portrange 9000-9999".to_string())),
                "{iface}"
            );
        }
    }

    #[test]
    fn tester_capture_filter_takes_no_filter_from_anywhere() {
        // The method has one argument. This pins the signature: a future
        // `filter: &str` parameter would not compile here.
        let f: fn(&HelperGuard, &str) -> Result<Option<String>, String> =
            HelperGuard::capture_filter;
        let hg = HelperGuard::from_scope_set(&scope_set());
        assert_eq!(
            f(&hg, "lo"),
            Ok(Some("host 127.0.0.1 and portrange 9000-9999".to_string()))
        );
    }
}
