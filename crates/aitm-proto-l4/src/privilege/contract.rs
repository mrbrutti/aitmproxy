//! The privilege contract: the constants and the receipt shared by every end of
//! the L4 capture-privilege boundary (spec §2.1, §3.1).
//!
//! Nothing here touches the filesystem, the network or any system state: these
//! are the literal names, paths and ids the core, the macOS app, the privileged
//! helper and the packaging scripts must agree on, plus the JSON receipt the
//! helper writes and the other two read.

use serde::{Deserialize, Serialize};

/// The group that owns the packet-capture devices once the helper has run; the
/// same arrangement Wireshark's `ChmodBPF` installs (spec §3.1).
pub const BPF_GROUP: &str = "access_bpf";

/// Directory holding the helper's receipt. Root-owned, 0755.
pub const RECEIPT_DIR: &str = "/Library/Application Support/Aitmproxy";

/// The receipt the helper writes after each run, read by the core and the app.
pub const RECEIPT_PATH: &str = "/Library/Application Support/Aitmproxy/l4-helper.json";

/// Schema version of the receipt this build writes and is willing to read.
pub const RECEIPT_SCHEMA: u32 = 1;

/// launchd label of the permissions daemon.
pub const HELPER_LABEL: &str = "com.mrbrutti.aitmproxy.l4-helper";

/// launchd label of the revert daemon (the same binary, second service).
pub const REVERT_LABEL: &str = "com.mrbrutti.aitmproxy.l4-helper-revert";

/// Code-signing identifier of the helper binary.
pub const HELPER_IDENTIFIER: &str = "com.mrbrutti.aitmproxy.l4-helper";

/// Apple Developer team identifier both the app and the helper are signed with.
pub const TEAM_ID: &str = "995PCLM9KH";

/// Bundle identifier of the macOS app.
pub const APP_BUNDLE_ID: &str = "com.mrbrutti.aitmproxy";

/// The one URL the app accepts to bring the Packets card forward. A frontend
/// hands the operator this; it never asks anyone to type a command.
pub const ALLOW_URL: &str = "aitmproxy://packet-capture/allow";

/// Path of the permissions daemon's plist inside the app bundle.
pub const HELPER_PLIST_REL: &str =
    "Contents/Library/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist";

/// Where the Linux packages install the helper.
pub const LINUX_HELPER_PATH: &str = "/usr/lib/aitmproxy/aitm-l4-helper";

/// The polkit action id the Linux helper is launched under.
pub const POLKIT_ACTION: &str = "com.mrbrutti.aitmproxy.l4-helper.run";

/// Where an operator without a suitable build is pointed.
pub const DOWNLOAD_URL: &str = "https://mrbrutti.github.io/aitmproxy/download.html";

/// What the privileged helper recorded about its last run.
///
/// The helper writes it, the core and the macOS app read it: it is how an
/// unprivileged process learns which group owns the capture devices, which
/// helper version applied them, and which users this helper added to that group
/// (so a revert removes only those, never a member another installer added).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Receipt schema version; this build reads only [`RECEIPT_SCHEMA`].
    pub schema: u32,
    /// Version of the helper binary that wrote this receipt.
    pub helper_version: String,
    /// When the run finished, epoch milliseconds.
    pub applied_at: u64,
    /// Group the capture devices were given, normally [`BPF_GROUP`].
    pub group: String,
    /// Numeric id of that group.
    pub gid: u32,
    /// How many capture device nodes the run set.
    pub nodes: u32,
    /// Users this helper added to `group`, carried forward across runs. A revert
    /// removes exactly these and nobody else.
    pub members_added: Vec<String>,
    /// Non-fatal problems from the run, for display.
    pub errors: Vec<String>,
}

/// Only the schema field, so a receipt from a future helper — whose other fields
/// we cannot know — is still refused by version rather than by shape.
#[derive(Deserialize)]
struct SchemaProbe {
    schema: u32,
}

impl Receipt {
    /// Read a receipt from the bytes on disk.
    ///
    /// The schema is checked first: a receipt written by a newer helper yields
    /// [`ReceiptError::Schema`] with the version found, whatever else the
    /// document contains. Malformed bytes yield [`ReceiptError::Json`]. Never
    /// panics — the input is a file any root process could have written.
    pub fn parse(bytes: &[u8]) -> Result<Receipt, ReceiptError> {
        let probe: SchemaProbe = serde_json::from_slice(bytes)
            .map_err(|err| ReceiptError::Json(bounded_json_error(&err)))?;
        if probe.schema != RECEIPT_SCHEMA {
            return Err(ReceiptError::Schema(probe.schema));
        }
        serde_json::from_slice(bytes).map_err(|err| ReceiptError::Json(bounded_json_error(&err)))
    }

    /// Serialize the receipt for the helper to write.
    ///
    /// Serializing a struct of scalars, strings and string vectors cannot fail;
    /// should serde ever disagree, the fallback is a document that no
    /// [`Receipt::parse`] accepts, so a reader sees an error rather than a
    /// silently empty-looking receipt.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }
}

/// Longest JSON parser message carried in an error, in bytes, before it is
/// cut and marked with `…`.
///
/// serde quotes peer-chosen text in its messages: an unknown key's name, a
/// string found where a number belongs. The input these messages describe is
/// a file any root process could have written or a frame the other end of
/// the helper socket sent, so an unbounded message would let that peer put a
/// quarter-megabyte of its own prose — a fake "run sudo …" instruction, say —
/// into the error a frontend shows. 120 bytes keeps serde's classification
/// (`unknown field`, `invalid type: string`, `missing field \`x\``) and
/// enough of the offending text to recognise, and nothing a peer can stretch.
const MAX_JSON_ERROR_TEXT: usize = 120;

/// serde's message for `err`, cut to [`MAX_JSON_ERROR_TEXT`] bytes on a char
/// boundary and marked with `…` when it was longer. A message that fits is
/// returned verbatim, position suffix and all. Shared by every JSON trust
/// boundary in the crate's privilege contract (the receipt and the helper
/// protocol's control bodies).
pub(crate) fn bounded_json_error(err: &serde_json::Error) -> String {
    let text = err.to_string();
    if text.len() <= MAX_JSON_ERROR_TEXT {
        return text;
    }
    let mut cut = String::with_capacity(MAX_JSON_ERROR_TEXT + '…'.len_utf8());
    for c in text.chars() {
        if cut.len() + c.len_utf8() > MAX_JSON_ERROR_TEXT {
            break;
        }
        cut.push(c);
    }
    cut.push('…');
    cut
}

/// Why a receipt could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// The bytes are not the JSON this build expects; carries the parser's
    /// message, cut to a bounded length (the writer chooses the text serde
    /// quotes, not how much of it a reader shows).
    Json(String),
    /// The receipt is a schema this build does not read; carries the version found.
    Schema(u32),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::Json(msg) => write!(f, "malformed receipt JSON: {msg}"),
            ReceiptError::Schema(found) => write!(
                f,
                "unsupported receipt schema {found} (this build reads schema {RECEIPT_SCHEMA})"
            ),
        }
    }
}

impl std::error::Error for ReceiptError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_round_trips_and_refuses_other_schemas() {
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA,
            helper_version: "0.5.9".to_string(),
            applied_at: 1_762_000_000_000,
            group: BPF_GROUP.to_string(),
            gid: 504,
            nodes: 256,
            members_added: vec!["matt".to_string()],
            errors: Vec::new(),
        };

        // Round trip: every field survives `to_json` -> `parse`.
        let bytes = receipt.to_json();
        let parsed = match Receipt::parse(&bytes) {
            Ok(parsed) => parsed,
            Err(err) => panic!("a schema-1 receipt must parse, got {err}"),
        };
        assert_eq!(parsed, receipt);
        assert_eq!(parsed.schema, 1);
        assert_eq!(parsed.helper_version, "0.5.9");
        assert_eq!(parsed.applied_at, 1_762_000_000_000);
        assert_eq!(parsed.group, "access_bpf");
        assert_eq!(parsed.gid, 504);
        assert_eq!(parsed.nodes, 256);
        assert_eq!(parsed.members_added, vec!["matt".to_string()]);
        assert_eq!(parsed.errors, Vec::<String>::new());

        // The on-disk form carries the documented field names, so the app and the
        // core read the same JSON the helper writes.
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(err) => panic!("to_json must write utf-8, got {err}"),
        };
        assert!(
            text.contains(r#""members_added":["matt"]"#),
            "field names are part of the contract, got {text}"
        );

        // A receipt written by a future helper is refused by schema, not by its
        // fields: the schema check runs before the rest of the document.
        let future = br#"{"schema":2,"helper_version":"9.9.9","applied_at":1,"group":"access_bpf","gid":504,"nodes":256,"members_added":[],"errors":[],"rotations":7}"#;
        assert_eq!(Receipt::parse(future), Err(ReceiptError::Schema(2)));
        assert_eq!(
            Receipt::parse(br#"{"schema":2}"#),
            Err(ReceiptError::Schema(2))
        );
        assert_eq!(
            ReceiptError::Schema(2).to_string(),
            "unsupported receipt schema 2 (this build reads schema 1)"
        );

        // Malformed bytes are a Json error, never a panic.
        match Receipt::parse(b"{") {
            Err(ReceiptError::Json(msg)) => {
                assert!(msg.starts_with("EOF while parsing"), "{msg}");
            }
            other => panic!("truncated JSON must be a Json error, got {other:?}"),
        }
        assert!(
            ReceiptError::Json("boom".to_string())
                .to_string()
                .starts_with("malformed receipt JSON: boom"),
            "Display names the cause"
        );

        // The URL the app answers is part of this contract (spec section 3.2).
        assert_eq!(ALLOW_URL, "aitmproxy://packet-capture/allow");
    }

    // ---- Tester edge cases (stage 5, unit p1a) ----------------------------
    //
    // `Receipt::parse` reads a file any root process could have written. None
    // of these inputs may panic, and every refusal must be `Json` (bad shape)
    // or `Schema` (wrong version), never a silently defaulted receipt.

    /// A complete schema-1 document with `schema` replaced by `schema_json`
    /// and `extra` spliced in after it.
    fn doc(schema_json: &str, extra: &str) -> Vec<u8> {
        format!(
            r#"{{"schema":{schema_json},{extra}"helper_version":"0.5.9","applied_at":1762000000000,"group":"access_bpf","gid":504,"nodes":256,"members_added":["matt"],"errors":[]}}"#
        )
        .into_bytes()
    }

    /// The parsed form of [`doc`] when nothing in it is hostile.
    fn expected() -> Receipt {
        Receipt {
            schema: 1,
            helper_version: "0.5.9".to_string(),
            applied_at: 1_762_000_000_000,
            group: "access_bpf".to_string(),
            gid: 504,
            nodes: 256,
            members_added: vec!["matt".to_string()],
            errors: Vec::new(),
        }
    }

    #[test]
    fn tester_baseline_doc_parses_to_the_literal_receipt() {
        // The helper the hostile cases below lean on must itself be sound.
        assert_eq!(Receipt::parse(&doc("1", "")), Ok(expected()));
    }

    #[test]
    fn tester_truncated_json_carries_serdes_message() {
        // The parser's classification is carried through; its position suffix
        // is serde_json's prose and not pinned.
        for (bytes, prefix) in [
            (&b"{"[..], "EOF while parsing an object"),
            (b"", "EOF while parsing a value"),
        ] {
            match Receipt::parse(bytes) {
                Err(ReceiptError::Json(msg)) => assert!(msg.starts_with(prefix), "{msg}"),
                other => panic!("{bytes:?} must be a Json error, got {other:?}"),
            }
        }
    }

    #[test]
    fn tester_schema_of_the_wrong_json_type_is_a_json_error_not_a_schema_error() {
        // A string "1" is not the u32 1: it is refused as malformed, so a
        // writer cannot slip past the version check by quoting the number.
        for schema in [r#""1""#, "1.0", "-1", "true", "null", "[1]", r#"{"v":1}"#] {
            match Receipt::parse(&doc(schema, "")) {
                Err(ReceiptError::Json(msg)) => assert!(
                    msg.contains("invalid type") || msg.contains("invalid value"),
                    "schema {schema}: {msg}"
                ),
                other => panic!("schema {schema} must be a Json error, got {other:?}"),
            }
        }
    }

    #[test]
    fn tester_schema_out_of_u32_range_is_a_json_error() {
        // 2^32 does not fit the u32 field; it must not wrap to schema 0.
        assert!(
            matches!(
                Receipt::parse(&doc("4294967296", "")),
                Err(ReceiptError::Json(_))
            ),
            "2^32 must not wrap"
        );
        // 2^64 + 1 is beyond every integer serde_json carries.
        assert!(matches!(
            Receipt::parse(&doc("18446744073709551617", "")),
            Err(ReceiptError::Json(_))
        ));
        // The largest u32 is a legal (unsupported) schema, refused by version.
        assert_eq!(
            Receipt::parse(&doc("4294967295", "")),
            Err(ReceiptError::Schema(u32::MAX))
        );
        assert_eq!(Receipt::parse(&doc("0", "")), Err(ReceiptError::Schema(0)));
    }

    #[test]
    fn tester_schema_check_wins_over_garbage_fields_only_for_other_schemas() {
        // Schema 2 with every other field of the wrong type: refused by version.
        let garbage = br#"{"schema":2,"helper_version":7,"applied_at":"x","group":[],"gid":-1,"nodes":null,"members_added":"matt","errors":{}}"#;
        assert_eq!(Receipt::parse(garbage), Err(ReceiptError::Schema(2)));
        // The same garbage at schema 1 is a Json error, never a defaulted receipt.
        let garbage_1 = br#"{"schema":1,"helper_version":7,"applied_at":"x","group":[],"gid":-1,"nodes":null,"members_added":"matt","errors":{}}"#;
        assert!(matches!(
            Receipt::parse(garbage_1),
            Err(ReceiptError::Json(_))
        ));
    }

    #[test]
    fn tester_each_field_with_a_wrong_type_or_out_of_range_value_is_a_json_error() {
        let cases: [&[u8]; 12] = [
            // gid: 2^32, negative, string
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":4294967296,"nodes":1,"members_added":[],"errors":[]}"#,
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":-1,"nodes":1,"members_added":[],"errors":[]}"#,
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":"504","nodes":1,"members_added":[],"errors":[]}"#,
            // nodes: 2^32, float
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":1,"nodes":4294967296,"members_added":[],"errors":[]}"#,
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":1,"nodes":1.5,"members_added":[],"errors":[]}"#,
            // applied_at: negative, 2^64
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":-1,"group":"g","gid":1,"nodes":1,"members_added":[],"errors":[]}"#,
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":18446744073709551616,"group":"g","gid":1,"nodes":1,"members_added":[],"errors":[]}"#,
            // helper_version / group: not strings
            br#"{"schema":1,"helper_version":59,"applied_at":1,"group":"g","gid":1,"nodes":1,"members_added":[],"errors":[]}"#,
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":null,"gid":1,"nodes":1,"members_added":[],"errors":[]}"#,
            // members_added: a string, an array of numbers
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":1,"nodes":1,"members_added":"matt","errors":[]}"#,
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":1,"nodes":1,"members_added":[501],"errors":[]}"#,
            // errors: null
            br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":1,"nodes":1,"members_added":[],"errors":null}"#,
        ];
        for (i, bytes) in cases.iter().enumerate() {
            assert!(
                matches!(Receipt::parse(bytes), Err(ReceiptError::Json(_))),
                "case {i}: {}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    #[test]
    fn tester_missing_fields_name_the_field() {
        match Receipt::parse(br#"{"schema":1}"#) {
            Err(ReceiptError::Json(msg)) => assert!(
                msg.starts_with("missing field `helper_version`"),
                "the first missing field is named: {msg}"
            ),
            other => panic!("a schema-only receipt must be a Json error, got {other:?}"),
        }
        // Every field is required: drop `members_added` alone.
        let without = br#"{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":1,"nodes":1,"errors":[]}"#;
        match Receipt::parse(without) {
            Err(ReceiptError::Json(msg)) => {
                assert!(msg.starts_with("missing field `members_added`"), "{msg}");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn tester_duplicate_keys_are_refused_not_last_wins() {
        // If the second `schema` silently won, a writer could put a passing
        // schema first and a refused one second (or the reverse) and have the
        // two readers disagree. serde refuses the duplicate outright.
        match Receipt::parse(&doc("1", r#""schema":2,"#)) {
            Err(ReceiptError::Json(msg)) => {
                assert!(msg.starts_with("duplicate field `schema`"), "{msg}");
            }
            other => panic!("duplicate schema must be a Json error, got {other:?}"),
        }
        match Receipt::parse(&doc("1", r#""gid":0,"#)) {
            Err(ReceiptError::Json(msg)) => {
                assert!(msg.starts_with("duplicate field `gid`"), "{msg}");
            }
            other => panic!("duplicate gid must be a Json error, got {other:?}"),
        }
    }

    #[test]
    fn tester_deep_nesting_never_overflows_the_stack() {
        // 100k nested arrays, far past any recursion limit a naive recursive
        // parser would survive. Pinned outcomes: inside an ignored field the
        // value is skipped iteratively and the receipt is the literal one; as a
        // typed field it is refused at the first bracket; unbalanced it is an
        // EOF error. None of them panics or overflows.
        let open = "[".repeat(100_000);
        let close = "]".repeat(100_000);
        assert_eq!(
            Receipt::parse(&doc("1", &format!(r#""junk":{open}{close},"#))),
            Ok(expected())
        );
        match Receipt::parse(format!(r#"{{"schema":{open}{close}}}"#).as_bytes()) {
            Err(ReceiptError::Json(msg)) => {
                assert!(
                    msg.starts_with("invalid type: sequence, expected u32"),
                    "{msg}"
                );
            }
            other => panic!("a nested schema must be a Json error, got {other:?}"),
        }
        let typed = format!(
            r#"{{"schema":1,"helper_version":"0.5.9","applied_at":1,"group":"g","gid":1,"nodes":1,"members_added":{open}{close},"errors":[]}}"#
        );
        match Receipt::parse(typed.as_bytes()) {
            Err(ReceiptError::Json(msg)) => {
                assert!(
                    msg.starts_with("invalid type: sequence, expected a string"),
                    "{msg}"
                );
            }
            other => panic!("a nested member must be a Json error, got {other:?}"),
        }
        let unbalanced = format!(r#"{{"schema":1,"x":{open}"#);
        match Receipt::parse(unbalanced.as_bytes()) {
            Err(ReceiptError::Json(msg)) => {
                assert!(msg.starts_with("EOF while parsing a list"), "{msg}");
            }
            other => panic!("unbalanced nesting must be a Json error, got {other:?}"),
        }
    }

    #[test]
    fn tester_trailing_bytes_and_non_object_documents_are_json_errors() {
        let mut trailing = doc("1", "");
        trailing.extend_from_slice(b" {\"schema\":1}");
        match Receipt::parse(&trailing) {
            Err(ReceiptError::Json(msg)) => {
                assert!(msg.starts_with("trailing characters"), "{msg}");
            }
            other => panic!("two documents must be a Json error, got {other:?}"),
        }
        for bytes in [
            &b"null"[..],
            b"[]",
            b"1",
            b"\"schema\"",
            b"[{\"schema\":1}]",
            &[0xff, 0xfe, 0x00][..],
        ] {
            assert!(
                matches!(Receipt::parse(bytes), Err(ReceiptError::Json(_))),
                "{bytes:?}"
            );
        }
        // A megabyte of noise is refused promptly and without panic.
        let noise = vec![b'a'; 1 << 20];
        assert!(matches!(Receipt::parse(&noise), Err(ReceiptError::Json(_))));
    }

    #[test]
    fn tester_unknown_fields_at_the_current_schema_are_ignored() {
        // Forward compatibility within a schema: a helper of this schema that
        // records one more thing is still readable, and the known fields are
        // exactly what was written.
        assert_eq!(
            Receipt::parse(&doc("1", r#""rotations":7,"note":{"a":[1,2]},"#)),
            Ok(expected())
        );
    }

    /// Panel SEC-M1. serde's message quotes peer-chosen text verbatim: a
    /// string where a number belongs is echoed in full, so a hostile writer
    /// could plant a quarter-megabyte "run sudo …" sentence in the error a
    /// frontend shows. The stored message is bounded whatever the input, cut
    /// at a char boundary, while a short message is carried unchanged.
    #[test]
    fn fix_sec_m1_json_error_text_is_bounded() {
        let long = "a".repeat(250_000);
        let bytes = format!(r#"{{"schema":"{long}"}}"#);
        match Receipt::parse(bytes.as_bytes()) {
            Err(ReceiptError::Json(msg)) => {
                assert_eq!(msg.len(), 123, "120 bytes of text plus the marker: {msg}");
                assert!(msg.starts_with("invalid type: string \"aaaa"), "{msg}");
                assert!(msg.ends_with('…'), "{msg}");
            }
            other => panic!("a string schema must be a Json error, got {other:?}"),
        }
        // Three-byte chars: the cut lands on a char boundary (22 bytes of
        // prose plus 32 whole euro signs is 118 bytes), never inside a char.
        let euro = "\u{20ac}".repeat(100_000);
        let bytes = format!(r#"{{"schema":"{euro}"}}"#);
        match Receipt::parse(bytes.as_bytes()) {
            Err(ReceiptError::Json(msg)) => {
                assert_eq!(msg.len(), 121, "{msg}");
                assert_eq!(msg.chars().filter(|c| *c == '\u{20ac}').count(), 32);
                assert!(msg.ends_with('…'), "{msg}");
            }
            other => panic!("got {other:?}"),
        }
        // A short message is verbatim: no marker.
        match Receipt::parse(b"{") {
            Err(ReceiptError::Json(msg)) => {
                assert!(msg.starts_with("EOF while parsing an object"), "{msg}");
                assert!(!msg.ends_with('…'), "{msg}");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn tester_extreme_but_legal_values_round_trip() {
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA,
            helper_version: String::new(),
            applied_at: u64::MAX,
            group: "grüppe \"quoted\" \\ \n\t\u{0}".to_string(),
            gid: u32::MAX,
            nodes: 0,
            members_added: (0..1000).map(|i| format!("user{i}")).collect(),
            errors: vec!["line one\nline two".to_string(), String::new()],
        };
        let bytes = receipt.to_json();
        assert_eq!(Receipt::parse(&bytes), Ok(receipt.clone()));
        // The literal JSON carries the extremes unchanged.
        let text = String::from_utf8(bytes).expect("utf-8");
        assert!(
            text.contains(r#""applied_at":18446744073709551615"#),
            "{text}"
        );
        assert!(text.contains(r#""gid":4294967295"#), "{text}");
        assert!(text.contains(r#""nodes":0"#), "{text}");
        assert!(text.contains(r#""helper_version":"""#), "{text}");
    }

    #[test]
    fn tester_contract_constants_are_the_spec_literals() {
        // Spec §3.1, §5.4 and §2: every constant is a name another component
        // (plist, policy file, app, packaging) must match byte for byte.
        assert_eq!(BPF_GROUP, "access_bpf");
        assert_eq!(RECEIPT_DIR, "/Library/Application Support/Aitmproxy");
        assert_eq!(
            RECEIPT_PATH,
            "/Library/Application Support/Aitmproxy/l4-helper.json"
        );
        assert!(RECEIPT_PATH.starts_with(RECEIPT_DIR));
        assert_eq!(RECEIPT_SCHEMA, 1);
        assert_eq!(HELPER_LABEL, "com.mrbrutti.aitmproxy.l4-helper");
        assert_eq!(REVERT_LABEL, "com.mrbrutti.aitmproxy.l4-helper-revert");
        assert_eq!(HELPER_IDENTIFIER, "com.mrbrutti.aitmproxy.l4-helper");
        assert_eq!(TEAM_ID, "995PCLM9KH");
        assert_eq!(APP_BUNDLE_ID, "com.mrbrutti.aitmproxy");
        assert_eq!(
            HELPER_PLIST_REL,
            "Contents/Library/LaunchDaemons/com.mrbrutti.aitmproxy.l4-helper.plist"
        );
        assert!(HELPER_PLIST_REL.ends_with(&format!("{HELPER_LABEL}.plist")));
        assert_eq!(LINUX_HELPER_PATH, "/usr/lib/aitmproxy/aitm-l4-helper");
        assert_eq!(POLKIT_ACTION, "com.mrbrutti.aitmproxy.l4-helper.run");
        assert_eq!(
            DOWNLOAD_URL,
            "https://mrbrutti.github.io/aitmproxy/download.html"
        );
    }
}
