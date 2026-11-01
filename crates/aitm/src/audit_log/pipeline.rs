//! The writer's field pipeline (spec Design 6 and 14.5): what every entry goes
//! through, on the stream's own thread, between the queue and the file.
//!
//! The ring hook means any caller of `AuditRing::append_in` reaches the file
//! with an entry it built by hand, so the writer does not trust the entry. Each
//! string field takes these steps, in this order:
//!
//! 1. **Bound**: cut to [`FIELD_BOUND_BYTES`], so no step reads a megabyte.
//! 2. **Pass**: a text pass over the *decoded* text: `scrub_strict` for the
//!    reason, the command and the connection id; `sanitize_client_label` and then
//!    `scrub_strict` for the label. `args` is JSON text and goes through
//!    [`redact_args_text`] instead: parse first, then the tolerant scan.
//! 3. **Registry**: every registered secret, in every stored form, is masked.
//! 4. **Controls**: in `args`, the reason, the command and the connection id a
//!    whitespace control becomes one blank and every other control character
//!    (C0, DEL, C1) becomes U+FFFD, so a hostile target echoed into a field
//!    cannot drive the terminal of whoever runs `cat` on the file.
//! 5. **Cap**, and then the mask of a trailing fragment of a registered secret the
//!    cap (or the producer's own) cut in half. The controls come first so that
//!    U+FFFD, three bytes, is counted by the cap.
//! 6. **Render** with `entry_to_jsonl`, the one renderer of an entry line.
//!
//! For an entry `record_audit` produced, steps 2 to 5 change nothing, so the
//! line is exactly what `entry_to_jsonl` renders (AC17): every cap here is the
//! producer's own and cutting what a cut produced is a no-op.
//!
//! A plain-text pass never runs over JSON text (Design 14.0): the shared
//! plain-text scrubber is not safe there, because a line break is the two
//! characters `\r\n` and a value is followed by `"}`. `args` is parsed, or
//! scanned literal by literal (see `jsonscan`), so a pass only ever reads decoded
//! string content; the registry (which knows the JSON form of a secret) and the
//! control step are the only steps that read `args` as it is written.

use aitm_core::redact_strict::scrub_strict;
use aitm_core::{
    sanitize_client_label, AuditEntry, AuditResult, DEFAULT_ARGS_SUMMARY_CAP,
    DEFAULT_RESULT_REASON_CAP, MAX_CLIENT_LABEL_CHARS,
};

use super::jsonscan::redact_args_text;
use super::registry::{SecretRegistry, CUT_MARK};

/// Every string field is cut to this many bytes before any pass reads it: the
/// work bound of Design 14.5 step 1. Far above every cap below, so nothing a
/// field keeps is ever lost to it.
pub(crate) const FIELD_BOUND_BYTES: usize = 64 * 1024;

/// The longest `command` the file keeps, in characters (no marker).
pub(crate) const MAX_COMMAND_CHARS: usize = 128;

/// The longest `connection_id` the file keeps, in bytes (no marker).
pub(crate) const MAX_CONNECTION_ID_BYTES: usize = 64;

/// How the cap of step 5 cuts one field.
#[derive(Clone, Copy)]
enum Cap {
    /// At most this many bytes on a character boundary, plus the `…` marker when
    /// something was cut (the ring's own rule, so cutting its output is a no-op).
    Marked(usize),
    /// At most this many characters, no marker.
    Chars(usize),
    /// At most this many bytes on a character boundary, no marker.
    Bytes(usize),
}

/// Steps 3 to 5 for one field: what differs from field to field is whether the
/// controls are replaced and how the cap cuts.
#[derive(Clone, Copy)]
struct Tail {
    controls: bool,
    cap: Cap,
}

/// `args`: a JSON text cut at 512 bytes by its producer.
const ARGS: Tail = Tail {
    controls: true,
    cap: Cap::Marked(DEFAULT_ARGS_SUMMARY_CAP),
};

/// The refusal reason: at most 1024 bytes and the marker.
const REASON: Tail = Tail {
    controls: true,
    cap: Cap::Marked(DEFAULT_RESULT_REASON_CAP),
};

const COMMAND: Tail = Tail {
    controls: true,
    cap: Cap::Chars(MAX_COMMAND_CHARS),
};

const CONNECTION_ID: Tail = Tail {
    controls: true,
    cap: Cap::Bytes(MAX_CONNECTION_ID_BYTES),
};

/// The label has no controls left after `sanitize_client_label`, which drops
/// them, so only the cap (a pass can lengthen a label) applies.
const LABEL: Tail = Tail {
    controls: false,
    cap: Cap::Chars(MAX_CLIENT_LABEL_CHARS),
};

impl Tail {
    /// Masks `passed` (a field after its text pass) with every registered
    /// secret, replaces its controls, cuts it, and masks the fragment of a
    /// secret the cut left at its end.
    fn apply(self, registry: &SecretRegistry, passed: &str) -> String {
        let masked = registry.mask(passed);
        let clean = if self.controls {
            replace_controls(&masked)
        } else {
            masked
        };
        let capped = match self.cap {
            Cap::Marked(bytes) => cap_marked(clean, bytes),
            Cap::Chars(chars) => cap_chars(clean, chars),
            Cap::Bytes(bytes) => cap_bytes(clean, bytes),
        };
        registry.mask_trailing_fragment(&capped)
    }
}

/// The text passes of step 2, as function pointers so that a test can watch what
/// they are handed.
#[derive(Clone, Copy)]
struct Passes {
    /// Over a decoded plain-text field: the reason, the command, the connection
    /// id and the label (after `sanitize_client_label`).
    text: fn(&str) -> String,
    /// Over `args`, which is JSON text.
    args: fn(&str) -> String,
}

/// What the writer runs: `scrub_strict` over plain text, [`redact_args_text`] over
/// `args`.
const PASSES: Passes = Passes {
    text: scrub_strict,
    args: redact_args_text,
};

/// The line the writer appends for `entry`, without its line end: `entry` put
/// through the pipeline of the module documentation and rendered by
/// `entry_to_jsonl`. The entry is read, never changed, and its fields are
/// bounded before they are copied, so a megabyte `args` costs 64 KiB.
pub(crate) fn render_line(entry: &AuditEntry, registry: &SecretRegistry) -> String {
    render_with(entry, registry, PASSES)
}

/// [`render_line`] with its text passes given.
///
/// Every field of `AuditEntry` is named below, so a field added to it is a
/// compile error here until someone decides what the pipeline does with it.
fn render_with(entry: &AuditEntry, registry: &SecretRegistry, passes: Passes) -> String {
    let rendered = AuditEntry {
        at: entry.at,
        origin: entry.origin,
        client_label: entry
            .client_label
            .as_deref()
            // The bound is for uniformity: `sanitize_client_label` reads only the
            // first 1024 characters itself, so the cut changes nothing it does.
            .and_then(|label| sanitize_client_label(bounded(label)))
            .map(|label| LABEL.apply(registry, &(passes.text)(&label))),
        connection_id: entry
            .connection_id
            .as_deref()
            .map(|id| CONNECTION_ID.apply(registry, &(passes.text)(bounded(id)))),
        command: COMMAND.apply(registry, &(passes.text)(bounded(&entry.command))),
        args_summary: ARGS.apply(registry, &(passes.args)(bounded(&entry.args_summary))),
        result: match &entry.result {
            AuditResult::Ok => AuditResult::Ok,
            AuditResult::Error(reason) => {
                AuditResult::Error(REASON.apply(registry, &(passes.text)(bounded(reason))))
            }
        },
    };
    aitm_ca::audit::entry_to_jsonl(&rendered)
}

/// `text` cut to [`FIELD_BOUND_BYTES`] on a character boundary.
fn bounded(text: &str) -> &str {
    if text.len() <= FIELD_BOUND_BYTES {
        return text;
    }
    text.get(..floor_boundary(text, FIELD_BOUND_BYTES))
        .unwrap_or_default()
}

/// The largest index at or below `at` that is a character boundary of `text`.
fn floor_boundary(text: &str, mut at: usize) -> usize {
    while at > 0 && !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// A whitespace control (a tab, a line end, NEL) becomes one blank, so words
/// stay apart; every other control character (C0, DEL, C1) becomes U+FFFD.
/// Nothing else changes.
fn replace_controls(text: &str) -> String {
    text.chars()
        .map(|c| match (c.is_control(), c.is_whitespace()) {
            (true, true) => ' ',
            (true, false) => '\u{fffd}',
            (false, _) => c,
        })
        .collect()
}

/// `text` cut to at most `cap` bytes on a character boundary, plus the `…`
/// marker only when something was cut: the ring's own `cap_text`, so applying it to
/// what the ring produced changes nothing.
fn cap_marked(mut text: String, cap: usize) -> String {
    if text.len() > cap {
        text.truncate(floor_boundary(&text, cap));
        text.push_str(CUT_MARK);
    }
    text
}

/// `text` cut to at most `max` characters, with no marker.
fn cap_chars(mut text: String, max: usize) -> String {
    if let Some((index, _)) = text.char_indices().nth(max) {
        text.truncate(index);
    }
    text
}

/// `text` cut to at most `max` bytes on a character boundary, with no marker.
fn cap_bytes(mut text: String, max: usize) -> String {
    if text.len() > max {
        text.truncate(floor_boundary(&text, max));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, UNIX_EPOCH};

    use aitm_core::{AuditEntry, AuditResult, Frontend};
    use serde_json::Value;

    use crate::audit_log::{Registration, SecretRegistry};

    const AT_MS: u64 = 1_700_000_000_123;

    /// An agent-origin entry with nothing but a command: no label, no id, `{}`.
    fn entry(command: &str) -> AuditEntry {
        AuditEntry {
            at: UNIX_EPOCH + Duration::from_millis(AT_MS),
            origin: Frontend::Mcp,
            client_label: None,
            connection_id: None,
            command: command.to_string(),
            args_summary: "{}".to_string(),
            result: AuditResult::Ok,
        }
    }

    /// The line parsed; a line that is not JSON fails the test.
    fn parsed(line: &str) -> Value {
        serde_json::from_str(line).unwrap_or_else(|e| panic!("not JSON ({e}): {line:?}"))
    }

    /// The string at `path` of `value`, or a failure that shows the value.
    fn string_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
        let mut here = value;
        for key in path {
            here = &here[*key];
        }
        here.as_str()
            .unwrap_or_else(|| panic!("{path:?} is not a string in {value}"))
    }

    /// Spec Design 6 and 14.5, the text fields: a hand-built hostile entry has
    /// its label sanitised and scrubbed, its reason scrubbed, its registered
    /// secret masked, every control character replaced and every field cut to
    /// its cap. The expected values are literal.
    #[test]
    fn text_fields_are_scrubbed_registry_masked_controlled_and_capped() {
        const REG: &str = "REGSECRET12XYZ";
        let registry = SecretRegistry::new();
        assert_eq!(
            registry.register("test.registered", REG),
            Registration::Substring
        );
        let hostile = AuditEntry {
            client_label: Some("web-bridge\u{202E}\n token=LABELSECRET12".to_string()),
            connection_id: Some("c".repeat(10 * 1024)),
            command: format!("a\nb{REG}{}", "z".repeat(200)),
            args_summary: format!("{{\"k\":\"{REG}\"}} \u{7f}"),
            result: AuditResult::Error(
                "Bearer REASONSECRET12 \u{1b}[31m \u{9b}2J\u{7f}\nnext".to_string(),
            ),
            ..entry("unused")
        };

        let line = render_line(&hostile, &registry);

        let mut failures: Vec<String> = Vec::new();
        let value = parsed(&line);
        let want_command = format!("a b[redacted]{}", "z".repeat(115));
        for (field, got, want) in [
            (
                "client_label",
                string_at(&value, &["client_label"]),
                "web-bridge  token=[redacted]",
            ),
            (
                "result.error",
                string_at(&value, &["result", "error"]),
                "Bearer [redacted] \u{fffd}[31m \u{fffd}2J\u{fffd} next",
            ),
            (
                "command",
                string_at(&value, &["command"]),
                want_command.as_str(),
            ),
            (
                "connection_id",
                string_at(&value, &["connection_id"]),
                &"c".repeat(64),
            ),
            (
                "args",
                string_at(&value, &["args"]),
                "{\"k\":\"[redacted]\"} \u{fffd}",
            ),
        ] {
            if got != want {
                failures.push(format!("{field}: left: {got:?}, right: {want:?}"));
            }
        }
        for secret in ["LABELSECRET12", "REASONSECRET12", REG] {
            if line.contains(secret) {
                failures.push(format!("{secret} is in the line: {line}"));
            }
        }
        if let Some(byte) = line.bytes().find(|b| *b < 0x20 || *b == 0x7f) {
            failures.push(format!("the line holds the control byte {byte:#04x}"));
        }
        if line.contains('\u{9b}') {
            failures.push("the line holds U+009B".to_string());
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Design 6: the label is at most 64 characters in the file. A pass can make a
    /// label longer than `sanitize_client_label` left it (`pw=a` becomes
    /// `pw=[redacted]`), so the cap is applied after the pass, not before.
    #[test]
    fn a_label_the_pass_lengthens_is_cut_back_to_its_cap() {
        let lengthened = AuditEntry {
            client_label: Some(["pw=a"; 12].join(" ")),
            ..entry("flow.list")
        };
        let value = parsed(&render_line(&lengthened, &SecretRegistry::new()));
        let label = string_at(&value, &["client_label"]);
        let full = ["pw=[redacted]"; 12].join(" ");
        assert_eq!(label.chars().count(), 64);
        assert_eq!(label, full.chars().take(64).collect::<String>());
    }

    /// Design 14.5 step 1, the work bound: whatever a field holds, no text pass
    /// is handed more than 64 KiB of it, `args` included. The two passes are
    /// replaced by ones that note the longest text they were given (through the
    /// seam `render_with`), and every field of the entry is a megabyte long.
    #[test]
    fn no_text_pass_reads_more_than_the_bound() {
        static LONGEST_TEXT: AtomicUsize = AtomicUsize::new(0);
        static LONGEST_ARGS: AtomicUsize = AtomicUsize::new(0);
        fn watch_text(text: &str) -> String {
            LONGEST_TEXT.fetch_max(text.len(), Ordering::SeqCst);
            text.to_string()
        }
        fn watch_args(text: &str) -> String {
            LONGEST_ARGS.fetch_max(text.len(), Ordering::SeqCst);
            text.to_string()
        }

        let huge = "x".repeat(1024 * 1024);
        let hostile = AuditEntry {
            client_label: Some(huge.clone()),
            connection_id: Some(huge.clone()),
            command: huge.clone(),
            args_summary: huge.clone(),
            result: AuditResult::Error(huge),
            ..entry("unused")
        };
        let watching = Passes {
            text: watch_text,
            args: watch_args,
        };
        render_with(&hostile, &SecretRegistry::new(), watching);
        assert_eq!(LONGEST_TEXT.load(Ordering::SeqCst), FIELD_BOUND_BYTES);
        assert_eq!(LONGEST_ARGS.load(Ordering::SeqCst), FIELD_BOUND_BYTES);
    }

    /// Design 14.5 step 2: the strict text pass runs on the label, the reason,
    /// the command and the connection id. The shape is one only the strict
    /// vocabulary knows (`pw` is not a key of the shared scrubber, which
    /// `sanitize_client_label` already applies to a label), so a field that
    /// skipped `scrub_strict` would keep its value.
    #[test]
    fn every_text_field_gets_the_strict_pass() {
        let hostile = AuditEntry {
            client_label: Some("build pw=LABELPW99 ok".to_string()),
            connection_id: Some("conn pw=CONNPW99 end".to_string()),
            command: "run pw=CMDPW99 end".to_string(),
            result: AuditResult::Error("bad pw=REASONPW99 end".to_string()),
            ..entry("unused")
        };
        let line = render_line(&hostile, &SecretRegistry::new());
        let value = parsed(&line);
        let mut failures: Vec<String> = Vec::new();
        for (field, got, want) in [
            (
                "client_label",
                string_at(&value, &["client_label"]),
                "build pw=[redacted] ok",
            ),
            (
                "connection_id",
                string_at(&value, &["connection_id"]),
                "conn pw=[redacted] end",
            ),
            (
                "command",
                string_at(&value, &["command"]),
                "run pw=[redacted] end",
            ),
            (
                "result.error",
                string_at(&value, &["result", "error"]),
                "bad pw=[redacted] end",
            ),
        ] {
            if got != want {
                failures.push(format!("{field}: left: {got:?}, right: {want:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Design 14.4, cut secrets: a field that ends with a prefix of 6 bytes or
    /// more of a registered secret has that fragment masked, in every text field,
    /// with the producer's `…` marker set aside and put back. A fragment of 5
    /// bytes is the documented residual and stays.
    #[test]
    fn a_cut_registered_secret_is_masked_at_a_field_end() {
        const CUT: &str = "CUT12SECRETVALUE0123456789";
        let registry = SecretRegistry::new();
        registry.register("test.cut", CUT);

        let mut failures: Vec<String> = Vec::new();
        for (row, reason, want) in [
            (
                "10 bytes, then the marker",
                "see CUT12SECRE…",
                "see [redacted]…",
            ),
            ("exactly 6 bytes", "see CUT12S…", "see [redacted]…"),
            ("5 bytes stay", "see CUT12…", "see CUT12…"),
            ("no marker", "see CUT12SECRE", "see [redacted]"),
            (
                "not at the end",
                "CUT12SECRE and more",
                "CUT12SECRE and more",
            ),
            (
                "two markers: one is set aside",
                "see CUT12SECRE……",
                "see CUT12SECRE……",
            ),
        ] {
            let entry = AuditEntry {
                result: AuditResult::Error(reason.to_string()),
                ..entry("flow.get")
            };
            let value = parsed(&render_line(&entry, &registry));
            let got = string_at(&value, &["result", "error"]);
            if got != want {
                failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
            }
        }

        // The same fragment at the end of each of the other text fields.
        let cut = AuditEntry {
            client_label: Some("see CUT12SECRE".to_string()),
            connection_id: Some("conn-CUT12SECRE".to_string()),
            command: "run.CUT12SECRE".to_string(),
            args_summary: "{\"note\":\"xx CUT12SECRE…".to_string(),
            ..entry("unused")
        };
        let value = parsed(&render_line(&cut, &registry));
        for (field, got, want) in [
            (
                "client_label",
                string_at(&value, &["client_label"]),
                "see [redacted]",
            ),
            (
                "connection_id",
                string_at(&value, &["connection_id"]),
                "conn-[redacted]",
            ),
            ("command", string_at(&value, &["command"]), "run.[redacted]"),
            (
                "args",
                string_at(&value, &["args"]),
                "{\"note\":\"xx [redacted]…",
            ),
        ] {
            if got != want {
                failures.push(format!("{field}: left: {got:?}, right: {want:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Design 6 and AC17: with nothing registered an honest entry, whatever the
    /// producer's own caps left in it, renders as exactly `entry_to_jsonl`.
    #[test]
    fn an_honest_text_entry_renders_unchanged() {
        let registry = SecretRegistry::new();
        let honest = AuditEntry {
            client_label: Some("aitm-mac".to_string()),
            connection_id: Some("conn_00ff-1".to_string()),
            result: AuditResult::Error("plain reason".to_string()),
            ..entry("flow.list")
        };
        let rows: Vec<(&str, AuditEntry)> = vec![
            ("the plan's entry", honest.clone()),
            ("ok, no label, no id", entry("flow.get")),
            (
                "args cut by the producer's cap",
                AuditEntry {
                    args_summary: format!("{}…", "x".repeat(512)),
                    ..entry("flow.get")
                },
            ),
            (
                "reason cut by the producer's cap",
                AuditEntry {
                    result: AuditResult::Error(format!("{}…", "r".repeat(1024))),
                    ..entry("flow.get")
                },
            ),
            (
                "args cut inside a two-byte character",
                AuditEntry {
                    args_summary: format!("a{}…", "é".repeat(255)),
                    ..entry("flow.get")
                },
            ),
            (
                "the masked Authorization shape (AC47)",
                AuditEntry {
                    args_summary: r#"{"note":"Authorization: [redacted]"}"#.to_string(),
                    ..entry("demo.echo")
                },
            ),
            (
                "the masked Cookie shape with escaped line breaks (AC47)",
                AuditEntry {
                    args_summary: r#"{"raw":"GET /\r\nCookie: [redacted]\r\nHost: x"}"#.to_string(),
                    ..entry("demo.echo")
                },
            ),
            (
                "a declared label",
                AuditEntry {
                    client_label: Some("web-bridge (declared)".to_string()),
                    ..entry("flow.get")
                },
            ),
            (
                "a masked reason",
                AuditEntry {
                    result: AuditResult::Error("Bearer [redacted] was refused".to_string()),
                    ..entry("agent.set")
                },
            ),
        ];

        let mut failures: Vec<String> = Vec::new();
        for (row, honest) in &rows {
            let got = render_line(honest, &registry);
            let want = aitm_ca::audit::entry_to_jsonl(honest);
            if got != want {
                failures.push(format!("{row}: left: {got}, right: {want}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Design 14.5 for hostile `args` of a megabyte: whatever the shape (nesting a
    /// stack could not hold, one huge literal, a password in front of a megabyte,
    /// a secret key whose value is cut by the bound), the line renders at once,
    /// parses, holds no secret, and `args` is within its cap. The literal
    /// expected values show what the pass made of each: the bound (64 KiB, no
    /// marker) cuts first, then the pass, then the cap (512 bytes and `…`).
    #[test]
    fn hostile_args_of_a_megabyte_render_within_the_cap() {
        const MEGA: usize = 1024 * 1024;
        let valid_huge_string = serde_json::to_string(&"y".repeat(MEGA)).unwrap_or_default();
        let rows: Vec<(&str, String, String)> = vec![
            (
                "open brackets",
                "[".repeat(MEGA),
                format!("{}…", "[".repeat(512)),
            ),
            (
                "open objects",
                "{\"a\":".repeat(MEGA / 5),
                format!("{}…", "{\"a\":".repeat(512).get(..512).unwrap_or_default()),
            ),
            (
                "one huge literal",
                format!("{{\"a\":\"{}", "x".repeat(MEGA)),
                format!("{{\"a\":\"{}…", "x".repeat(506)),
            ),
            (
                "a password in front of a megabyte, not JSON",
                format!(" password=ARGSECRET9 {}", "x".repeat(MEGA)),
                format!(" password=[redacted] {}…", "x".repeat(491)),
            ),
            (
                "a secret key whose value the bound cut",
                format!("{{\"password\":\"ARGSECRET9{}", "x".repeat(MEGA)),
                "{\"password\":\"<redacted>".to_string(),
            ),
            (
                "a valid JSON string a megabyte long",
                valid_huge_string,
                format!("\"{}…", "y".repeat(511)),
            ),
        ];
        let mut failures: Vec<String> = Vec::new();
        for (row, args, want) in rows {
            let hostile = AuditEntry {
                args_summary: args,
                ..entry("flow.get")
            };
            let started = std::time::Instant::now();
            let line = render_line(&hostile, &SecretRegistry::new());
            if started.elapsed() > Duration::from_secs(20) {
                failures.push(format!("{row}: took {:?}", started.elapsed()));
            }
            let value = parsed(&line);
            let got = string_at(&value, &["args"]);
            if got != want {
                failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
            }
            if got.len() > 515 {
                failures.push(format!("{row}: args is {} bytes", got.len()));
            }
            if line.contains("ARGSECRET9") {
                failures.push(format!("{row}: the secret is in the line"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Design 6, 14.5 steps 4 and 5: the controls are replaced **before** the
    /// cap, so U+FFFD (three bytes) is counted by it: 400 of U+009B become 170
    /// of U+FFFD (510 bytes) and the marker, 513 bytes.
    #[test]
    fn render_line_caps_after_it_replaces_controls() {
        let hostile = AuditEntry {
            args_summary: "\u{9b}".repeat(400),
            ..entry("flow.get")
        };
        let line = render_line(&hostile, &SecretRegistry::new());
        let value = parsed(&line);
        let args = string_at(&value, &["args"]);
        assert_eq!(args, format!("{}…", "\u{fffd}".repeat(170)));
        assert_eq!(args.len(), 513);
        assert!(!line.contains('\u{9b}'), "no U+009B in {line}");
    }

    /// Design 6: whitespace controls become one blank, every other control
    /// (C0, DEL, C1) becomes U+FFFD, and text with no control is untouched.
    #[test]
    fn controls_are_replaced_by_class() {
        let mut failures: Vec<String> = Vec::new();
        for (row, text, want) in [
            ("tab", "a\tb", "a b"),
            ("newline", "a\nb", "a b"),
            ("carriage return", "a\rb", "a b"),
            ("vertical tab", "a\u{0b}b", "a b"),
            ("form feed", "a\u{0c}b", "a b"),
            ("NEL", "a\u{85}b", "a b"),
            ("NUL", "a\u{0}b", "a\u{fffd}b"),
            ("escape", "a\u{1b}b", "a\u{fffd}b"),
            ("unit separator", "a\u{1f}b", "a\u{fffd}b"),
            ("DEL", "a\u{7f}b", "a\u{fffd}b"),
            ("CSI", "a\u{9b}b", "a\u{fffd}b"),
            ("last C1", "a\u{9f}b", "a\u{fffd}b"),
            ("two in a row", "a\r\nb", "a  b"),
            ("plain text", "héllo wörld 日本 …", "héllo wörld 日本 …"),
            ("a blank stays", "a b", "a b"),
        ] {
            let got = replace_controls(text);
            if got != want {
                failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Design 6: a cut lands on a character boundary; the marker is added only
    /// when something was cut; and cutting what a cut produced changes nothing,
    /// which is what lets an honest entry pass unchanged.
    #[test]
    fn caps_cut_on_a_character_boundary_and_mark_only_what_they_cut() {
        let mut failures: Vec<String> = Vec::new();
        let two_byte = "é".repeat(300);
        let odd = format!("a{two_byte}");
        for (row, text, cap, want) in [
            ("fits", "x".repeat(512), 512, "x".repeat(512)),
            (
                "one over",
                "x".repeat(513),
                512,
                format!("{}…", "x".repeat(512)),
            ),
            (
                "far over",
                "x".repeat(5000),
                512,
                format!("{}…", "x".repeat(512)),
            ),
            (
                "two-byte",
                two_byte.clone(),
                512,
                format!("{}…", "é".repeat(256)),
            ),
            (
                "cut inside a char",
                odd,
                512,
                format!("a{}…", "é".repeat(255)),
            ),
            ("empty", String::new(), 512, String::new()),
        ] {
            let got = cap_marked(text, cap);
            if got != want {
                failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
            }
            let again = cap_marked(got.clone(), cap);
            if again != got {
                failures.push(format!("{row}: not idempotent: {got:?} then {again:?}"));
            }
        }
        for (row, got, want) in [
            (
                "chars: 128 stay",
                cap_chars("é".repeat(128), 128),
                "é".repeat(128),
            ),
            (
                "chars: 129 are cut, no marker",
                cap_chars("é".repeat(129), 128),
                "é".repeat(128),
            ),
            (
                "bytes: 64 stay",
                cap_bytes("c".repeat(64), 64),
                "c".repeat(64),
            ),
            (
                "bytes: cut at the byte cap, no marker",
                cap_bytes("c".repeat(65), 64),
                "c".repeat(64),
            ),
            (
                "bytes: cut inside a char",
                cap_bytes(format!("a{}", "é".repeat(100)), 64),
                format!("a{}", "é".repeat(31)),
            ),
        ] {
            if got != want {
                failures.push(format!("{row}: left: {got:?}, right: {want:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// Design 14.5 step 1: a field is cut to 64 KiB before any pass reads it,
    /// on a character boundary, and a field that fits is the same slice.
    #[test]
    fn a_field_is_bounded_before_any_pass_runs() {
        assert_eq!(FIELD_BOUND_BYTES, 64 * 1024);
        assert_eq!(bounded("short"), "short");
        let even = "é".repeat(FIELD_BOUND_BYTES);
        assert_eq!(bounded(&even).len(), FIELD_BOUND_BYTES);
        let odd = format!("a{}", "é".repeat(FIELD_BOUND_BYTES));
        assert_eq!(bounded(&odd).len(), FIELD_BOUND_BYTES - 1);
        let exact = "x".repeat(FIELD_BOUND_BYTES);
        assert_eq!(bounded(&exact).len(), FIELD_BOUND_BYTES);
    }

    /// The pipeline never runs a text pass over `args` as if it were plain text
    /// (Design 14.0): the honest JSON of the two AC47 shapes is the same line
    /// after it, though `args` now has a real pass (parse first, then the scan).
    #[test]
    fn the_pipeline_never_scrubs_args_as_plain_text() {
        let mut failures: Vec<String> = Vec::new();
        for args in [
            r#"{"note":"Authorization: [redacted]"}"#,
            r#"{"raw":"GET /\r\nCookie: [redacted]\r\nHost: x"}"#,
        ] {
            let honest = AuditEntry {
                args_summary: args.to_string(),
                ..entry("demo.echo")
            };
            let value = parsed(&render_line(&honest, &SecretRegistry::new()));
            let got = string_at(&value, &["args"]);
            if got != args {
                failures.push(format!("left: {got:?}, right: {args:?}"));
            }
        }
        assert!(
            failures.is_empty(),
            "{} row(s) failed:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
