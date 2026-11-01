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
        let probe: SchemaProbe =
            serde_json::from_slice(bytes).map_err(|err| ReceiptError::Json(err.to_string()))?;
        if probe.schema != RECEIPT_SCHEMA {
            return Err(ReceiptError::Schema(probe.schema));
        }
        serde_json::from_slice(bytes).map_err(|err| ReceiptError::Json(err.to_string()))
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

/// Why a receipt could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// The bytes are not the JSON this build expects; carries the parser's message.
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
            Err(ReceiptError::Json(msg)) => assert!(
                msg.contains("EOF") || !msg.is_empty(),
                "the parser's message is carried through, got {msg:?}"
            ),
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
}
