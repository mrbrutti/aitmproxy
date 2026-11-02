//! Outcome classification, the latency window and the liveness comparison —
//! owned by scanner v2 track T5, plan task 5.
//!
//! The lane's oracle ladder (spec D8.4 "Oracle and liveness", D8.5): a
//! correlated reply is clean; an `Other` reply is read through
//! [`aitm_proto_l4::icmp`] as an ICMP error (type and code), a TCP reset, or
//! an otherwise unexplained protocol error; silence past the timeout is the
//! candidate crash/hang signal. Only silence and reset are candidates — the
//! classes that make the runner spend a liveness probe.
//!
//! Nothing here sends, waits or touches the wire: `classify` reads an outcome
//! `send_recv` already produced, and the latency window is a fixed-size ring
//! of the last [`LatencyWindow::CAPACITY`] clean round trips.

use std::collections::VecDeque;
use std::time::Duration;

use aitm_proto_l4::icmp::{icmp_error, tcp_rst};
use aitm_proto_l4::sendrecv::SendRecvOutcome;
use aitm_scan_model::L4Oracle;

/// How a single fuzz case's outcome reads on the lane's oracle ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaseClass {
    /// A correlated reply came back: the target answered as it does for the
    /// unmutated seed, so the case changed nothing observable.
    Clean,
    /// An ICMP error came back — a closed UDP port answers `(3, 3)`
    /// (destination unreachable / port unreachable).
    Icmp {
        /// The ICMP type.
        icmp_type: u8,
        /// The ICMP code.
        code: u8,
    },
    /// A TCP reset came back — a closed TCP port's kernel reply.
    Reset,
    /// Something came back that is neither an ICMP error nor a reset: a
    /// wrong-port or wrong-protocol answer the correlator rejected.
    ProtocolError,
    /// Nothing came back within the timeout.
    Silence,
}

impl CaseClass {
    /// The shared-vocabulary oracle this class records in `L4Evidence`, or
    /// `None` for [`CaseClass::Clean`] (a clean case has nothing to report).
    #[must_use]
    pub fn oracle(&self) -> Option<L4Oracle> {
        match *self {
            CaseClass::Clean => None,
            CaseClass::Icmp { icmp_type, code } => Some(L4Oracle::Icmp { icmp_type, code }),
            CaseClass::Reset => Some(L4Oracle::Reset),
            CaseClass::ProtocolError => Some(L4Oracle::ProtocolError),
            CaseClass::Silence => Some(L4Oracle::Silence),
        }
    }

    /// Whether this class is a crash candidate — the classes that make the
    /// runner spend a liveness probe (spec D8.4: "Only silence/reset **and**
    /// two failed liveness probes ... become an `l4-crash` issue").
    ///
    /// An ICMP error or a protocol error is a reaction, not a candidate: the
    /// target answered, so it is alive.
    #[must_use]
    pub fn is_candidate(&self) -> bool {
        matches!(self, CaseClass::Silence | CaseClass::Reset)
    }

    /// The stable label the lane prints in a case record and an issue detail:
    /// `clean`, `icmp(3,3)`, `reset`, `protocol_error`, `silence`.
    #[must_use]
    pub fn label(&self) -> String {
        match *self {
            CaseClass::Clean => "clean".to_string(),
            CaseClass::Icmp { icmp_type, code } => format!("icmp({icmp_type},{code})"),
            CaseClass::Reset => "reset".to_string(),
            CaseClass::ProtocolError => "protocol_error".to_string(),
            CaseClass::Silence => "silence".to_string(),
        }
    }
}

/// One classified case outcome: its class, the reply's size and how long the
/// send-and-receive took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classified {
    /// Where the outcome sits on the oracle ladder.
    pub class: CaseClass,
    /// The reply frame's length in bytes, `0` when nothing came back. The
    /// bytes themselves stay in the recorded flow; only the length travels.
    pub reply_len: usize,
    /// The round trip in milliseconds, saturating at [`u32::MAX`].
    pub elapsed_ms: u32,
}

/// Read a [`SendRecvOutcome`] onto the oracle ladder.
///
/// `Response`/`Responses` are clean (the reply length is the first reply's);
/// `Other` is an ICMP error when [`icmp_error`] decodes one, else a reset when
/// [`tcp_rst`] is set, else a protocol error; `NoResponse` is silence with no
/// reply bytes. `elapsed` is the measured round trip, saturated into
/// milliseconds — a wire-derived packet never reaches arithmetic that panics.
#[must_use]
pub fn classify(outcome: &SendRecvOutcome, elapsed: Duration) -> Classified {
    let elapsed_ms = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);
    let (class, reply_len) = match outcome {
        SendRecvOutcome::Response(pkt) => (CaseClass::Clean, pkt.bytes.len()),
        SendRecvOutcome::Responses(pkts) => (
            CaseClass::Clean,
            pkts.first().map_or(0, |pkt| pkt.bytes.len()),
        ),
        SendRecvOutcome::Other(pkt) => {
            let class = if let Some((icmp_type, code)) = icmp_error(pkt) {
                CaseClass::Icmp { icmp_type, code }
            } else if tcp_rst(pkt) {
                CaseClass::Reset
            } else {
                CaseClass::ProtocolError
            };
            (class, pkt.bytes.len())
        }
        SendRecvOutcome::NoResponse { .. } => (CaseClass::Silence, 0),
    };
    Classified {
        class,
        reply_len,
        elapsed_ms,
    }
}

/// A fixed-size ring of the last [`LatencyWindow::CAPACITY`] clean round trips,
/// used for the oracle ladder's cheapest signal: a reply that came back far
/// outside the observed distribution (spec D8.5, "latency outlier (> 5x median
/// of the last 20)").
///
/// An outlier alone is never a crash — the lane records it as `info`.
#[derive(Debug, Clone, Default)]
pub struct LatencyWindow {
    /// The last [`LatencyWindow::CAPACITY`] samples, oldest first.
    samples: VecDeque<u32>,
}

impl LatencyWindow {
    /// How many samples the window keeps; older ones are dropped.
    pub const CAPACITY: usize = 20;
    /// How many samples the window needs before it calls anything an outlier.
    /// Below this the median is too noisy to multiply.
    pub const MIN_SAMPLES: usize = 10;
    /// How many times the median a sample must exceed to be an outlier.
    pub const FACTOR: u32 = 5;

    /// An empty window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(Self::CAPACITY),
        }
    }

    /// Record one clean round trip, evicting the oldest sample once the window
    /// is full.
    pub fn record(&mut self, ms: u32) {
        if self.samples.len() == Self::CAPACITY {
            self.samples.pop_front();
        }
        self.samples.push_back(ms);
    }

    /// The median of the recorded samples (`sorted[len / 2]`, the upper median
    /// for an even count), or `None` when nothing has been recorded.
    #[must_use]
    pub fn median(&self) -> Option<u32> {
        let mut sorted: Vec<u32> = self.samples.iter().copied().collect();
        sorted.sort_unstable();
        sorted.get(sorted.len() / 2).copied()
    }

    /// Whether `ms` is a latency outlier: the window holds at least
    /// [`LatencyWindow::MIN_SAMPLES`] samples and `ms` exceeds
    /// [`LatencyWindow::FACTOR`] times the median. The multiplication
    /// saturates, so a huge median simply makes nothing an outlier.
    #[must_use]
    pub fn is_outlier(&self, ms: u32) -> bool {
        if self.samples.len() < Self::MIN_SAMPLES {
            return false;
        }
        self.median()
            .is_some_and(|median| ms > median.saturating_mul(Self::FACTOR))
    }
}

/// Whether a liveness probe's class says the target is still the target the
/// baseline saw.
///
/// The comparison is class equality, not "the probe got an answer": a closed
/// UDP port whose baseline is `icmp(3,3)` is alive exactly while `icmp(3,3)`
/// keeps coming back, and a port whose baseline is silence (a filtered or
/// black-holed destination) is alive while it stays silent.
#[must_use]
pub fn liveness_passes(baseline: CaseClass, probe: CaseClass) -> bool {
    baseline == probe
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use aitm_proto_l4::craft::{IcmpSpec, Ipv4Spec, Layer, PacketSpec, TcpSpec, UdpSpec};
    use aitm_proto_l4::flow::L4Packet;
    use aitm_proto_l4::sendrecv::SendRecvOutcome;
    use aitm_proto_l4::types::L4Direction;
    use aitm_scan_model::L4Oracle;

    use super::{classify, liveness_passes, CaseClass, LatencyWindow};

    /// An inbound captured reply carrying `bytes`, the shape `send_recv` hands
    /// the lane inside a [`SendRecvOutcome`].
    fn captured(bytes: Vec<u8>) -> L4Packet {
        L4Packet {
            dir: L4Direction::Inbound,
            timestamp: SystemTime::now(),
            decoded: PacketSpec::summarize(&bytes),
            bytes,
            injected: false,
        }
    }

    /// The echo a live UDP service sends back: ports reversed, payload intact.
    fn udp_echo() -> L4Packet {
        captured(
            PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Udp(UdpSpec {
                        src_port: Some(9),
                        dst_port: Some(40000),
                        ..UdpSpec::default()
                    }),
                    Layer::Raw(b"probe".to_vec()),
                ],
            }
            .build()
            .expect("craft builds the UDP echo frame"),
        )
    }

    /// The kernel's ICMPv4 destination-unreachable / port-unreachable reply.
    fn icmp_3_3() -> L4Packet {
        captured(
            PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Icmp(IcmpSpec {
                        icmp_type: Some(3),
                        code: Some(3),
                        rest_of_header: Some(0),
                        ..IcmpSpec::default()
                    }),
                    Layer::Raw(vec![0u8; 28]),
                ],
            }
            .build()
            .expect("craft builds the port-unreachable frame"),
        )
    }

    /// The kernel's RST|ACK reply at a closed TCP port.
    fn tcp_reset() -> L4Packet {
        captured(
            PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Tcp(TcpSpec {
                        src_port: Some(80),
                        dst_port: Some(40000),
                        flags: Some(0x14),
                        ..TcpSpec::default()
                    }),
                ],
            }
            .build()
            .expect("craft builds the RST frame"),
        )
    }

    #[test]
    fn response_is_clean() {
        let pkt = udp_echo();
        let len = pkt.bytes.len();
        let classified = classify(&SendRecvOutcome::Response(pkt), Duration::from_millis(7));

        assert_eq!(classified.class, CaseClass::Clean);
        assert_eq!(classified.reply_len, len);
        assert_eq!(classified.elapsed_ms, 7);
        assert_eq!(classified.class.oracle(), None);
        assert_eq!(classified.class.label(), "clean");
        assert!(!classified.class.is_candidate());
    }

    #[test]
    fn responses_vec_is_clean() {
        let first = udp_echo();
        let len = first.bytes.len();
        let classified = classify(
            &SendRecvOutcome::Responses(vec![first, udp_echo()]),
            Duration::from_millis(3),
        );

        assert_eq!(classified.class, CaseClass::Clean);
        assert_eq!(classified.reply_len, len);

        // An empty batch is still clean, with nothing to measure.
        let empty = classify(
            &SendRecvOutcome::Responses(vec![]),
            Duration::from_millis(3),
        );
        assert_eq!(empty.class, CaseClass::Clean);
        assert_eq!(empty.reply_len, 0);
    }

    #[test]
    fn other_icmp_is_typed() {
        let pkt = icmp_3_3();
        let len = pkt.bytes.len();
        let classified = classify(&SendRecvOutcome::Other(pkt), Duration::from_millis(1));

        assert_eq!(
            classified.class,
            CaseClass::Icmp {
                icmp_type: 3,
                code: 3
            }
        );
        assert_eq!(classified.reply_len, len);
        assert_eq!(
            classified.class.oracle(),
            Some(L4Oracle::Icmp {
                icmp_type: 3,
                code: 3
            })
        );
        assert_eq!(classified.class.label(), "icmp(3,3)");
        assert!(!classified.class.is_candidate());
    }

    #[test]
    fn other_rst_is_reset() {
        let classified = classify(
            &SendRecvOutcome::Other(tcp_reset()),
            Duration::from_millis(2),
        );

        assert_eq!(classified.class, CaseClass::Reset);
        assert_eq!(classified.class.oracle(), Some(L4Oracle::Reset));
        assert_eq!(classified.class.label(), "reset");
        assert!(classified.class.is_candidate());
    }

    #[test]
    fn other_udp_wrong_port_is_protocol_error() {
        let classified = classify(
            &SendRecvOutcome::Other(udp_echo()),
            Duration::from_millis(4),
        );

        assert_eq!(classified.class, CaseClass::ProtocolError);
        assert_eq!(classified.class.oracle(), Some(L4Oracle::ProtocolError));
        assert_eq!(classified.class.label(), "protocol_error");
        assert!(!classified.class.is_candidate());
    }

    #[test]
    fn no_response_is_silence() {
        let classified = classify(
            &SendRecvOutcome::NoResponse {
                waited: Duration::from_millis(500),
            },
            Duration::from_millis(500),
        );

        assert_eq!(classified.class, CaseClass::Silence);
        assert_eq!(classified.reply_len, 0);
        assert_eq!(classified.elapsed_ms, 500);
        assert_eq!(classified.class.oracle(), Some(L4Oracle::Silence));
        assert_eq!(classified.class.label(), "silence");
        assert!(classified.class.is_candidate());
    }

    #[test]
    fn elapsed_saturates_at_u32_max() {
        let classified = classify(
            &SendRecvOutcome::NoResponse {
                waited: Duration::from_secs(60),
            },
            Duration::from_secs(60 * 60 * 24 * 365),
        );

        assert_eq!(classified.elapsed_ms, u32::MAX);
    }

    #[test]
    fn clean_has_no_oracle() {
        assert_eq!(CaseClass::Clean.oracle(), None);
    }

    #[test]
    fn latency_outlier_needs_min_samples() {
        let mut window = LatencyWindow::new();
        for _ in 0..9 {
            window.record(10);
        }
        assert!(!window.is_outlier(1000));

        window.record(10);
        assert_eq!(window.median(), Some(10));
        assert!(window.is_outlier(51));
        assert!(!window.is_outlier(50));
    }

    #[test]
    fn window_keeps_last_twenty() {
        let mut window = LatencyWindow::new();
        assert_eq!(window.median(), None);
        for ms in 1..=25 {
            window.record(ms);
        }

        assert_eq!(window.median(), Some(16));
    }

    /// Tester (stage 5): a hostile `Other` reply — empty, truncated, a lying
    /// length, ICMPv6, an AF word over garbage — classifies as a protocol
    /// error (the target answered *something*) with the frame's real length,
    /// never as `icmp(...)`, never as a reset, and never panics.
    #[test]
    fn hostile_other_frames_are_protocol_errors() {
        let mut truncated_icmp = vec![
            0x45, 0, 0, 22, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ];
        truncated_icmp.extend_from_slice(&[3, 3]);
        let mut af_garbage = vec![2u8, 0, 0, 0];
        af_garbage.extend_from_slice(&[0xff; 30]);
        let mut icmpv6 = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
        icmpv6.extend_from_slice(&[0u8; 15]);
        icmpv6.push(1);
        icmpv6.extend_from_slice(&[0u8; 15]);
        icmpv6.push(1);
        icmpv6.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 0]);

        for (name, bytes) in [
            ("empty", Vec::new()),
            ("one byte", vec![0x45]),
            ("truncated icmp", truncated_icmp),
            ("af word + garbage", af_garbage),
            ("icmpv6 port unreachable", icmpv6),
            ("all ones", vec![0xff; 1500]),
        ] {
            let len = bytes.len();
            let classified = classify(
                &SendRecvOutcome::Other(captured(bytes)),
                Duration::from_millis(3),
            );
            assert_eq!(classified.class, CaseClass::ProtocolError, "{name}");
            assert_eq!(classified.reply_len, len, "{name}");
            assert_eq!(classified.elapsed_ms, 3, "{name}");
            assert_eq!(
                classified.class.oracle(),
                Some(L4Oracle::ProtocolError),
                "{name}"
            );
            assert!(!classified.class.is_candidate(), "{name}");
        }
    }

    /// Tester (stage 5): a zero-length UDP reply is clean when the correlator
    /// accepted it and a protocol error when it did not; the class comes from
    /// the outcome variant, the bytes only give the length.
    #[test]
    fn zero_length_udp_reply_follows_the_outcome_variant() {
        let empty = captured(
            PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Udp(UdpSpec {
                        src_port: Some(9),
                        dst_port: Some(40000),
                        ..UdpSpec::default()
                    }),
                ],
            }
            .build()
            .expect("craft builds the empty datagram"),
        );
        assert_eq!(empty.bytes.len(), 28);

        let clean = classify(&SendRecvOutcome::Response(empty.clone()), Duration::ZERO);
        assert_eq!(clean.class, CaseClass::Clean);
        assert_eq!(clean.reply_len, 28);
        assert_eq!(clean.elapsed_ms, 0);

        let other = classify(&SendRecvOutcome::Other(empty), Duration::ZERO);
        assert_eq!(other.class, CaseClass::ProtocolError);
        assert_eq!(other.reply_len, 28);
    }

    /// Tester (stage 5): an ICMP type/code other than `(3, 3)` is still an
    /// ICMP reaction with its own label, and `is_outlier` saturates rather than
    /// overflowing on a huge median.
    #[test]
    fn other_icmp_codes_and_saturating_outlier() {
        let host_unreachable = captured(
            PacketSpec {
                layers: vec![
                    Layer::Ipv4(Ipv4Spec {
                        src: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        dst: Some(Ipv4Addr::new(127, 0, 0, 1)),
                        ..Ipv4Spec::default()
                    }),
                    Layer::Icmp(IcmpSpec {
                        icmp_type: Some(11),
                        code: Some(0),
                        rest_of_header: Some(0),
                        ..IcmpSpec::default()
                    }),
                    Layer::Raw(vec![0u8; 28]),
                ],
            }
            .build()
            .expect("craft builds the time-exceeded frame"),
        );
        let classified = classify(
            &SendRecvOutcome::Other(host_unreachable),
            Duration::from_millis(1),
        );
        assert_eq!(
            classified.class,
            CaseClass::Icmp {
                icmp_type: 11,
                code: 0
            }
        );
        assert_eq!(classified.class.label(), "icmp(11,0)");
        assert!(!classified.class.is_candidate());

        let mut window = LatencyWindow::new();
        for _ in 0..LatencyWindow::MIN_SAMPLES {
            window.record(u32::MAX);
        }
        assert_eq!(window.median(), Some(u32::MAX));
        assert!(
            !window.is_outlier(u32::MAX),
            "median x 5 saturates; nothing exceeds it"
        );
        assert!(
            !LatencyWindow::new().is_outlier(u32::MAX),
            "an empty window has no outliers"
        );
    }

    #[test]
    fn liveness_compares_classes() {
        let unreachable = CaseClass::Icmp {
            icmp_type: 3,
            code: 3,
        };
        let host_unreachable = CaseClass::Icmp {
            icmp_type: 3,
            code: 1,
        };

        assert!(liveness_passes(unreachable, unreachable));
        assert!(!liveness_passes(unreachable, CaseClass::Silence));
        assert!(liveness_passes(CaseClass::Clean, CaseClass::Clean));
        assert!(!liveness_passes(unreachable, host_unreachable));
        assert!(liveness_passes(CaseClass::Silence, CaseClass::Silence));
    }
}
