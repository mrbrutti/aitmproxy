//! The oracle decision table and the latency rule (spec S6.1, S6.2).
//!
//! Pure classification: this module reads a finished exchange and says what the
//! target's reaction means. It sends nothing, allocates nothing and keeps no
//! state, so every row of spec S6.1 can be asserted literally in a unit test.
//!
//! The inputs are the transport's [`Ended`] (how the read finished, spec S5.5),
//! the grammar's [`ReplyClass`] for whatever bytes came back (spec S3),
//! whether the reply was empty, and whether the grammar declares that closing
//! on a malformed message is the protocol's own reaction
//! (`Grammar::close_on_malformed_is_expected`, MQTT being the one grammar that
//! says `true`).
//!
//! Amendment **A7** is the rule that makes T6-4 satisfiable: a protocol-error
//! reply **followed by a close** is a clean refusal (T10's P mode, and real
//! Redis and memcached behave the same way), never a finding; the parser-fault
//! candidate is a close carrying **no** protocol-error token (reply empty or
//! `Unknown`) while liveness still passes.

use aitm_scan_model::L4Oracle;

use crate::client::Ended;
use crate::grammar::ReplyClass;

/// What the oracle read off one finished exchange, before liveness runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reading {
    /// Nothing to report: the target behaved. The latency rule (S6.2) may
    /// still turn this case into a [`L4Oracle::LatencyOutlier`] candidate.
    Clean,
    /// The target's reaction, as one of the model's oracles.
    Oracle(L4Oracle),
}

/// The spec S6.1 decision table, as a total function.
///
/// `reply_empty` is `true` when no reply bytes came back at all;
/// `close_expected` is the grammar's `close_on_malformed_is_expected`.
///
/// The rows, in the order they are tested:
///
/// | [`Ended`] | [`ReplyClass`] | result |
/// |---|---|---|
/// | `Silence` | any | `Oracle(Silence)` (a partial reply that timed out is still silence) |
/// | `IcmpUnreachable` | any | `Oracle(Icmp { 3, 3 })` |
/// | `Replied` | `Ok` / `Unknown` | `Clean` (an unknown reply is noted in `detail`, not a finding) |
/// | `Replied` | `ProtocolError` | `Oracle(ProtocolError)` (a refusal, expected for malformed input) |
/// | `Eof` / `Reset` | `ProtocolError` | `Oracle(ProtocolError)` — the A7 clean refusal |
/// | `Eof` / `Reset` | `Ok` | `Clean`: bytes came back, so the parser survived |
/// | `Eof` / `Reset` | empty or `Unknown`, `close_expected == false` | `Oracle(Reset)` — the A7 parser-fault candidate |
/// | `Eof` | empty or `Unknown`, `close_expected == true` | `Oracle(ProtocolError)`: the spec-mandated close (MQTT) |
/// | `Reset` | empty or `Unknown`, `close_expected == true` | `Oracle(Reset)`: an RST is never the mandated reaction |
///
/// A `ProtocolError` class decides the row on its own: if the grammar says the
/// reply carried an error token, A7 calls the case clean whatever else
/// happened. `Ok` needs bytes to be meaningful, so an empty reply falls
/// through to the close rows.
#[must_use]
pub fn read(ended: Ended, class: ReplyClass, reply_empty: bool, close_expected: bool) -> Reading {
    match ended {
        // A timeout is silence even when some bytes arrived first: the
        // transport keeps the partial reply, but no complete reply came back.
        Ended::Silence => Reading::Oracle(L4Oracle::Silence),
        // UDP learned a port-unreachable from ICMP.
        Ended::IcmpUnreachable => Reading::Oracle(L4Oracle::Icmp {
            icmp_type: 3,
            code: 3,
        }),
        Ended::Replied => match class {
            ReplyClass::ProtocolError => Reading::Oracle(L4Oracle::ProtocolError),
            ReplyClass::Ok | ReplyClass::Unknown => Reading::Clean,
        },
        // The peer answered its error token and then closed (A7).
        Ended::Eof | Ended::Reset if class == ReplyClass::ProtocolError => {
            Reading::Oracle(L4Oracle::ProtocolError)
        }
        // Bytes came back and the grammar liked them: the parser survived.
        // An empty reply has nothing to classify, so `Ok` without bytes falls
        // through to the close rows (S6.1 "reply empty or `Unknown`").
        Ended::Eof | Ended::Reset if class == ReplyClass::Ok && !reply_empty => Reading::Clean,
        // MQTT: closing on a malformed message is the protocol's own reaction,
        // so a clean close is a refusal, not a fault. An RST never is.
        Ended::Eof if close_expected => Reading::Oracle(L4Oracle::ProtocolError),
        // A close with no error token: the parser-fault candidate, once the
        // liveness probe that follows passes.
        Ended::Eof | Ended::Reset => Reading::Oracle(L4Oracle::Reset),
    }
}

/// Whether this oracle makes the campaign run its liveness probes
/// (spec S5.6 step 9).
#[must_use]
pub fn triggers_liveness(o: L4Oracle) -> bool {
    matches!(
        o,
        L4Oracle::Silence | L4Oracle::Reset | L4Oracle::Icmp { .. }
    )
}

/// Whether this case is a parser-fault candidate (A7): the peer closed with no
/// protocol-error token and the liveness probe that followed still passed.
#[must_use]
pub fn is_parser_fault_candidate(o: L4Oracle, liveness_after: bool) -> bool {
    matches!(o, L4Oracle::Reset) && liveness_after
}

/// Whether a clean reply's latency is an outlier candidate (spec S6.2):
/// more than five times the median of the window. Without a median (fewer
/// than the required samples) no case is an outlier.
#[must_use]
pub fn latency_outlier(elapsed_ms: u32, median: Option<u32>) -> bool {
    match median {
        Some(m) => u64::from(elapsed_ms) > 5 * u64::from(m),
        None => false,
    }
}

/// Whether the confirming repeat of an outlier candidate confirms it
/// (spec S6.2): more than three times the median.
#[must_use]
pub fn latency_confirms(elapsed_ms: u32, median: u32) -> bool {
    u64::from(elapsed_ms) > 3 * u64::from(median)
}

#[cfg(test)]
mod tests {
    use aitm_scan_model::L4Oracle;

    use super::{
        is_parser_fault_candidate, latency_confirms, latency_outlier, read, triggers_liveness,
        Reading,
    };
    use crate::client::Ended;
    use crate::grammar::ReplyClass;

    #[test]
    fn decision_table() {
        let rows: &[(Ended, ReplyClass, bool, bool, Reading)] = &[
            (Ended::Replied, ReplyClass::Ok, false, false, Reading::Clean),
            (
                Ended::Replied,
                ReplyClass::ProtocolError,
                false,
                false,
                Reading::Oracle(L4Oracle::ProtocolError),
            ),
            (
                Ended::Replied,
                ReplyClass::Unknown,
                false,
                false,
                Reading::Clean,
            ),
            (
                Ended::Silence,
                ReplyClass::Unknown,
                true,
                false,
                Reading::Oracle(L4Oracle::Silence),
            ),
            (
                Ended::Eof,
                ReplyClass::ProtocolError,
                false,
                false,
                Reading::Oracle(L4Oracle::ProtocolError),
            ),
            (Ended::Eof, ReplyClass::Ok, false, false, Reading::Clean),
            (
                Ended::Eof,
                ReplyClass::Unknown,
                true,
                false,
                Reading::Oracle(L4Oracle::Reset),
            ),
            (
                Ended::Eof,
                ReplyClass::Unknown,
                true,
                true,
                Reading::Oracle(L4Oracle::ProtocolError),
            ),
            (
                Ended::Reset,
                ReplyClass::Unknown,
                true,
                true,
                Reading::Oracle(L4Oracle::Reset),
            ),
            (
                Ended::Silence,
                ReplyClass::Ok,
                false,
                false,
                Reading::Oracle(L4Oracle::Silence),
            ),
            (
                Ended::Reset,
                ReplyClass::ProtocolError,
                false,
                false,
                Reading::Oracle(L4Oracle::ProtocolError),
            ),
            (Ended::Reset, ReplyClass::Ok, false, false, Reading::Clean),
            // An empty reply has nothing to classify: `Ok` cannot mean "bytes
            // came back" when none did, so the close decides the row.
            (
                Ended::Eof,
                ReplyClass::Ok,
                true,
                false,
                Reading::Oracle(L4Oracle::Reset),
            ),
            (
                Ended::Eof,
                ReplyClass::Unknown,
                false,
                false,
                Reading::Oracle(L4Oracle::Reset),
            ),
            (
                Ended::Reset,
                ReplyClass::Unknown,
                true,
                false,
                Reading::Oracle(L4Oracle::Reset),
            ),
            (
                Ended::Eof,
                ReplyClass::Unknown,
                false,
                true,
                Reading::Oracle(L4Oracle::ProtocolError),
            ),
            (
                Ended::IcmpUnreachable,
                ReplyClass::Unknown,
                true,
                false,
                Reading::Oracle(L4Oracle::Icmp {
                    icmp_type: 3,
                    code: 3,
                }),
            ),
        ];

        for &(ended, class, empty, close_expected, want) in rows {
            assert_eq!(
                read(ended, class, empty, close_expected),
                want,
                "row ({ended:?}, {class:?}, empty={empty}, close_expected={close_expected})"
            );
        }
    }

    #[test]
    fn latency_rules() {
        assert!(latency_outlier(60, Some(10)));
        assert!(!latency_outlier(50, Some(10)));
        assert!(!latency_outlier(1000, None));
        assert!(latency_confirms(31, 10));
        assert!(!latency_confirms(30, 10));
    }

    #[test]
    fn liveness_and_parser_fault_predicates() {
        assert!(triggers_liveness(L4Oracle::Silence));
        assert!(triggers_liveness(L4Oracle::Reset));
        assert!(triggers_liveness(L4Oracle::Icmp {
            icmp_type: 3,
            code: 3
        }));
        assert!(!triggers_liveness(L4Oracle::ProtocolError));
        assert!(!triggers_liveness(L4Oracle::LatencyOutlier));
        assert!(!triggers_liveness(L4Oracle::LivenessFailed));

        assert!(is_parser_fault_candidate(L4Oracle::Reset, true));
        assert!(!is_parser_fault_candidate(L4Oracle::Reset, false));
        assert!(!is_parser_fault_candidate(L4Oracle::Silence, true));
        assert!(!is_parser_fault_candidate(L4Oracle::ProtocolError, true));
    }
}
