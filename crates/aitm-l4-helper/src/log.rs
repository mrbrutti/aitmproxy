//! The one unified-log line per `bpf-permissions` / `bpf-revert` run (spec
//! §3.1 step 6; Constraints "Quiet logs").
//!
//! Each run logs exactly one line, subsystem [`SUBSYSTEM`], category
//! [`CATEGORY`]. The line is built from the receipt the helper itself wrote
//! (counts, the group name, the user names it added) or from the one-sentence
//! error the executor returned; nothing else from the machine is echoed, and
//! no line tells anyone to type a command (plan Rule 2). The same line goes
//! to stderr so an observer in a terminal sees it too.

use aitm_proto_l4::privilege::contract::Receipt;

/// Unified-log subsystem of the helper's permission modes (spec §3.1 step 6).
pub const SUBSYSTEM: &str = "com.mrbrutti.aitmproxy.l4-helper";
/// Unified-log category of the permission modes.
pub const CATEGORY: &str = "bpf";

/// The line for a `bpf-permissions` run.
///
/// `Ok`: `"bpf-permissions applied: 256 nodes, group access_bpf, added matt"`;
/// the user list is `nobody` when the receipt names no one and comma-separated
/// otherwise, each name passed through [`str::escape_debug`] so a control
/// character in an account name cannot break the one-line shape (a printable
/// name such as `josé` stays as it is; control characters, `\` and `"` are
/// escaped); when the receipt carries `errors`, `", {n} nodes refused"` is
/// appended. `Err`: `"{mode} failed: {reason}"`.
#[must_use]
pub fn run_line(mode: &str, r: &Result<Receipt, String>) -> String {
    match r {
        Ok(receipt) => {
            let added = if receipt.members_added.is_empty() {
                "nobody".to_string()
            } else {
                receipt
                    .members_added
                    .iter()
                    .map(|name| name.escape_debug().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let mut line = format!(
                "{mode} applied: {} nodes, group {}, added {added}",
                receipt.nodes, receipt.group
            );
            if !receipt.errors.is_empty() {
                line.push_str(&format!(", {} nodes refused", receipt.errors.len()));
            }
            line
        }
        Err(err) => format!("{mode} failed: {err}"),
    }
}

/// The line for a `bpf-revert` run: `"bpf-revert done"` or
/// `"bpf-revert failed: {reason}"`.
#[must_use]
pub fn revert_line(r: &Result<(), String>) -> String {
    match r {
        Ok(()) => "bpf-revert done".to_string(),
        Err(err) => format!("bpf-revert failed: {err}"),
    }
}

/// Emit one line: to stderr always, and on macOS to the unified log under
/// [`SUBSYSTEM`]/[`CATEGORY`] at `info` when `ok` and `error` otherwise.
pub fn emit(line: &str, ok: bool) {
    eprintln!("{line}");
    unified_log(line, ok);
}

#[cfg(target_os = "macos")]
fn unified_log(line: &str, ok: bool) {
    let log = oslog::OsLog::new(SUBSYSTEM, CATEGORY);
    if ok {
        log.info(line);
    } else {
        log.error(line);
    }
}

#[cfg(not(target_os = "macos"))]
fn unified_log(_line: &str, _ok: bool) {
    // No unified log off macOS; stderr already carries the line.
}
#[cfg(test)]
mod tests {
    use super::*;
    use aitm_proto_l4::privilege::contract::{Receipt, BPF_GROUP, RECEIPT_SCHEMA};

    fn receipt(members_added: &[&str], errors: &[&str]) -> Receipt {
        Receipt {
            schema: RECEIPT_SCHEMA,
            helper_version: "0.5.9".to_string(),
            applied_at: 1_762_000_000_000,
            group: BPF_GROUP.to_string(),
            gid: 701,
            nodes: 256,
            members_added: members_added.iter().map(|m| (*m).to_string()).collect(),
            errors: errors.iter().map(|e| (*e).to_string()).collect(),
        }
    }

    #[test]
    fn run_line_literal() {
        let line = run_line("bpf-permissions", &Ok(receipt(&["matt"], &[])));
        assert_eq!(
            line,
            "bpf-permissions applied: 256 nodes, group access_bpf, added matt"
        );
    }

    #[test]
    fn run_line_with_no_member_says_nobody() {
        let line = run_line("bpf-permissions", &Ok(receipt(&[], &[])));
        assert_eq!(
            line,
            "bpf-permissions applied: 256 nodes, group access_bpf, added nobody"
        );
    }

    #[test]
    fn run_line_with_two_members_lists_both() {
        let line = run_line("bpf-permissions", &Ok(receipt(&["matt", "alice"], &[])));
        assert_eq!(
            line,
            "bpf-permissions applied: 256 nodes, group access_bpf, added matt, alice"
        );
    }

    #[test]
    fn run_line_counts_refused_nodes() {
        let mut r = receipt(
            &["matt"],
            &["/dev/bpf3: major 42 differs from /dev/bpf0's major 23"],
        );
        r.nodes = 255;
        let line = run_line("bpf-permissions", &Ok(r));
        assert_eq!(
            line,
            "bpf-permissions applied: 255 nodes, group access_bpf, added matt, 1 nodes refused"
        );
        let mut r = receipt(&[], &["a", "b"]);
        r.nodes = 254;
        assert_eq!(
            run_line("bpf-permissions", &Ok(r)),
            "bpf-permissions applied: 254 nodes, group access_bpf, added nobody, 2 nodes refused"
        );
    }

    #[test]
    fn run_line_err_literal() {
        let line = run_line(
            "bpf-permissions",
            &Err(
                "/Library/Application Support/Aitmproxy is a symlink; nothing was changed"
                    .to_string(),
            ),
        );
        assert_eq!(
            line,
            "bpf-permissions failed: /Library/Application Support/Aitmproxy is a symlink; nothing was changed"
        );
    }

    #[test]
    fn revert_line_literals() {
        assert_eq!(revert_line(&Ok(())), "bpf-revert done");
        // The executor's failure text for a node (plan Rule 2: a noun phrase,
        // never the name of a command).
        assert_eq!(
            revert_line(&Err(
                "owner of /dev/bpf0 not changed: Operation not permitted (os error 1)".to_string()
            )),
            "bpf-revert failed: owner of /dev/bpf0 not changed: Operation not permitted (os error 1)"
        );
    }

    #[test]
    fn lines_are_single_lines() {
        for line in [
            run_line("bpf-permissions", &Ok(receipt(&["matt"], &["x"]))),
            run_line("bpf-permissions", &Err("boom".to_string())),
            revert_line(&Ok(())),
            revert_line(&Err("boom".to_string())),
            run_line("bpf-permissions", &Ok(receipt(&["ma\ntt"], &[]))),
        ] {
            assert!(!line.contains('\n'), "{line:?}");
        }
        // A control character in a member name is escaped, not emitted: the
        // line stays one line and shows the escape literally. A printable
        // non-ASCII name passes through as it is (QR2-M3: `escape_debug`, not
        // `escape_default`, which would write `jos\u{e9}`); `str::escape_debug`
        // still escapes an apostrophe, so `o'brien` is shown as `o\'brien`.
        let line = run_line(
            "bpf-permissions",
            &Ok(receipt(&["ma\ntt", "al\u{1b}ice", "josé", "o'brien"], &[])),
        );
        assert_eq!(
            line,
            "bpf-permissions applied: 256 nodes, group access_bpf, added ma\\ntt, al\\u{1b}ice, josé, o\\'brien"
        );
    }
}
