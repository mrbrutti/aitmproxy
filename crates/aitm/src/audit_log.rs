//! The durable audit writer: the JSONL files the `aitm` binary appends every
//! audited command invocation to (spec `docs/superpowers/specs/2026-10-31-durable-audit-design.md`).
//!
//! The log is **best-effort and not tamper-evident**: it exists so that an
//! operator can reconstruct what ran after the in-memory ring has rolled over,
//! not so that a reader can prove nothing was removed.
//!
//! Entries go to one of **three streams**, each its own file with its own queue
//! and size budget, so that a flood of one kind of entry cannot push another
//! kind off the disk: `control` (evidence from the trusted operator and the
//! CLI), `agent` (evidence from every other origin) and `reads` (successful
//! `Read` calls, any origin).
//!
//! This part of the module is the stream vocabulary: [`StreamKind`] and its
//! limits, [`stream_path`] (which file a stream is written to) and
//! [`stream_for`] (which stream an entry belongs to).

use std::path::{Path, PathBuf};

use aitm_core::{AuditLane, Frontend};

/// One of the three audit streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    /// Evidence-lane entries whose origin is trusted control (operator, CLI).
    Control,
    /// Evidence-lane entries of every other origin.
    Agent,
    /// Routine-lane entries: successful `Read` calls, any origin.
    Reads,
}

impl StreamKind {
    /// Every stream, in [`StreamKind::index`] order.
    pub const ALL: [StreamKind; 3] = [StreamKind::Control, StreamKind::Agent, StreamKind::Reads];

    /// Position in [`StreamKind::ALL`].
    pub const fn index(self) -> usize {
        match self {
            StreamKind::Control => 0,
            StreamKind::Agent => 1,
            StreamKind::Reads => 2,
        }
    }

    /// The short name used in thread names and log lines.
    pub const fn label(self) -> &'static str {
        match self {
            StreamKind::Control => "control",
            StreamKind::Agent => "agent",
            StreamKind::Reads => "reads",
        }
    }

    /// Entries the stream's queue holds before it drops the newest. The agent
    /// stream's queue is the deepest because the agent is the origin that can
    /// produce entries fastest; a full queue sheds load rather than blocking
    /// the call path.
    pub const fn queue_capacity(self) -> usize {
        match self {
            StreamKind::Control => 1024,
            StreamKind::Agent => 4096,
            StreamKind::Reads => 2048,
        }
    }

    /// Size at which the active file rotates.
    pub const fn max_bytes(self) -> u64 {
        match self {
            StreamKind::Control => 4 * MIB,
            StreamKind::Agent | StreamKind::Reads => 8 * MIB,
        }
    }

    /// Rotated files kept beside the active one. With [`StreamKind::max_bytes`]
    /// this bounds the stream at `max_bytes * (1 + keep_rotated)` on disk:
    /// 20 MiB, 48 MiB and 24 MiB, at most 92 MiB in all.
    pub const fn keep_rotated(self) -> usize {
        match self {
            StreamKind::Control => 4,
            StreamKind::Agent => 5,
            StreamKind::Reads => 2,
        }
    }
}

/// One mebibyte.
const MIB: u64 = 1024 * 1024;

/// The file `kind` is written to, given the configured base path.
///
/// The control stream is the base itself. The agent and reads streams put
/// `.agent` / `.reads` before the final extension, or append it when there is
/// none: `audit.jsonl` gives `audit.agent.jsonl`, `audit` gives `audit.agent`,
/// `audit.v2.jsonl` gives `audit.v2.agent.jsonl`. The name is assembled from
/// `OsStr`s, so a file name that is not UTF-8 works, and this never panics: a
/// base with no file name at all (`/`) borrows the stem `audit`, so the three
/// paths stay distinct and the later boot checks, not this function, reject it.
pub fn stream_path(base: &Path, kind: StreamKind) -> PathBuf {
    let infix = match kind {
        StreamKind::Control => return base.to_path_buf(),
        StreamKind::Agent => "agent",
        StreamKind::Reads => "reads",
    };
    let mut name = base
        .file_stem()
        .unwrap_or_else(|| "audit".as_ref())
        .to_os_string();
    name.push(".");
    name.push(infix);
    if let Some(extension) = base.extension() {
        name.push(".");
        name.push(extension);
    }
    base.with_file_name(name)
}

/// The stream an entry of `lane` and `origin` belongs to.
///
/// A successful read is `Reads` whoever made it. Evidence goes to `Control`
/// exactly when the origin is trusted control (the operator and the CLI), and
/// to `Agent` otherwise, so an origin this code has never heard of lands in
/// the untrusted stream. Nothing here compares against the agent role.
pub fn stream_for(lane: AuditLane, origin: Frontend) -> StreamKind {
    match lane {
        AuditLane::Routine => StreamKind::Reads,
        AuditLane::Evidence if origin.is_trusted_control() => StreamKind::Control,
        AuditLane::Evidence => StreamKind::Agent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Routine entries are reads, whoever made them; evidence goes to `control`
    /// exactly when the origin is trusted control, and to `agent` otherwise.
    #[test]
    fn stream_for_routes_by_lane_and_trust() {
        let rows = [
            (AuditLane::Routine, Frontend::Cli, StreamKind::Reads),
            (AuditLane::Routine, Frontend::Mcp, StreamKind::Reads),
            (AuditLane::Routine, Frontend::Operator, StreamKind::Reads),
            (AuditLane::Evidence, Frontend::Operator, StreamKind::Control),
            (AuditLane::Evidence, Frontend::Cli, StreamKind::Control),
            (AuditLane::Evidence, Frontend::Mcp, StreamKind::Agent),
        ];
        let mut failures: Vec<String> = Vec::new();
        for (lane, origin, want) in rows {
            let got = stream_for(lane, origin);
            if got != want {
                failures.push(format!(
                    "({lane:?}, {origin:?}): left: {got:?}, right: {want:?}"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// The spec's budget: 20 + 48 + 24 MiB on disk at most, queues 1024 / 4096 / 2048.
    #[test]
    fn stream_limits_total_92_mib() {
        let mib = 1024 * 1024;
        let total: u64 = StreamKind::ALL
            .iter()
            .map(|kind| kind.max_bytes() * (1 + kind.keep_rotated() as u64))
            .sum();
        assert_eq!(total, 96_468_992);
        assert_eq!(
            StreamKind::ALL.map(StreamKind::max_bytes),
            [4 * mib, 8 * mib, 8 * mib]
        );
        assert_eq!(StreamKind::ALL.map(StreamKind::keep_rotated), [4, 5, 2]);
        assert_eq!(
            StreamKind::ALL.map(StreamKind::queue_capacity),
            [1024, 4096, 2048]
        );
    }

    /// `index` is the position in `ALL` (later tasks index arrays with it) and
    /// `label` names the stream in thread names and log lines.
    #[test]
    fn stream_index_and_label_name_each_stream() {
        assert_eq!(
            StreamKind::ALL.map(|kind| (kind.index(), kind.label())),
            [(0, "control"), (1, "agent"), (2, "reads")]
        );
    }

    /// A base with no extension, a dotfile and a base with no file name at all
    /// each give three distinct paths (a derived path equal to the control path
    /// would make two streams write one file).
    #[test]
    fn stream_path_edge_names_stay_distinct() {
        let rows = [
            // (base, agent, reads)
            ("audit.jsonl", "audit.agent.jsonl", "audit.reads.jsonl"),
            ("/a/.audit", "/a/.audit.agent", "/a/.audit.reads"),
            ("/a/audit.", "/a/audit.agent.", "/a/audit.reads."),
            ("/", "/audit.agent", "/audit.reads"),
        ];
        let mut failures: Vec<String> = Vec::new();
        for (base, agent, reads) in rows {
            let base = Path::new(base);
            for (kind, want) in [
                (StreamKind::Control, base),
                (StreamKind::Agent, Path::new(agent)),
                (StreamKind::Reads, Path::new(reads)),
            ] {
                let got = stream_path(base, kind);
                if got != want {
                    failures.push(format!("{base:?} {kind:?}: left: {got:?}, right: {want:?}"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// A file name that is not UTF-8 survives: the derived name is built from
    /// `OsStr`s, never through `str`.
    #[cfg(unix)]
    #[test]
    fn stream_path_keeps_a_non_utf8_name() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = Path::new("/a");
        let named = |bytes: &[u8]| dir.join(OsStr::from_bytes(bytes));
        let base = named(b"au\xffdit.jsonl");
        assert_eq!(
            stream_path(&base, StreamKind::Agent),
            named(b"au\xffdit.agent.jsonl")
        );
        assert_eq!(
            stream_path(&base, StreamKind::Reads),
            named(b"au\xffdit.reads.jsonl")
        );
        assert_eq!(stream_path(&base, StreamKind::Control), base);
    }
}
