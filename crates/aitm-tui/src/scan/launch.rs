//! Launch bookkeeping (spec D3, D7): the call waiting for its reply, the
//! UI-3 reason a launch is blocked, and the wire-confirm handshake shared by the
//! `l4.*` guarded verbs and the `scan.*` launches.

use std::fmt;
use std::net::IpAddr;

use aitm_scan_model::{LaneKind, ScanProfile};
use serde_json::{json, Value};

use crate::action::CONFIRM_KEY;
use crate::l4::L4ScopeEntry;
use crate::scan::profiles::ProfileEditor;
use crate::text::{clean, truncate};

/// The UI-3 reason when the bus has no L4 layer (spec D7, first clause).
pub const GATE_NO_LAYER: &str =
    "L4 launch disabled: the L4 layer is not on this bus (l4.scope.list)";
/// The UI-3 reason when the draft names no L4 target (spec D7, second clause).
pub const GATE_NO_TARGET: &str = "L4 launch disabled: add an L4 target (ip, port, proto) first";
/// The UI-3 reason for a list row with an L4 lane and no editor open (D7 as
/// amended on the Task 12 security panel; fix round G, G73): a row carries
/// no targets to check, so the operator opens the profile first.
pub const GATE_OPEN_PROFILE: &str =
    "L4 launch disabled: open the profile (⏎) to check its L4 target and scope";
/// The widest a wire-confirm `prompt` grows, in cells (fix round H, H34;
/// D6 hostile-core bounds): bounded once in [`WireConfirm::from_reply`],
/// so the overlay wraps bounded text each frame.
pub const PROMPT_MAX: usize = 2000;
/// The capability word an L4 scope entry needs for a launch (spec D7).
const INJECT: &str = "inject";

/// The two launch verbs (spec D7; fix round G, G68): the one type the
/// pending launch, the launch keys and the refused-launch rule name a
/// verb by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchVerb {
    Start,
    Map,
}

impl LaunchVerb {
    /// The wire verb.
    pub fn as_str(self) -> &'static str {
        match self {
            LaunchVerb::Start => "scan.start",
            LaunchVerb::Map => "scan.map",
        }
    }

    /// The launch verb `verb` names, if it is one.
    pub fn parse(verb: &str) -> Option<Self> {
        match verb {
            "scan.start" => Some(LaunchVerb::Start),
            "scan.map" => Some(LaunchVerb::Map),
            _ => None,
        }
    }
}

impl fmt::Display for LaunchVerb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a launch sends and names (fix round G, G63): the request's
/// arguments and the profile name the start toast falls back on, decided
/// by one precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub args: Value,
    /// The profile the launch names: the draft's name (when it has one),
    /// the list row's, or none for a typed origin.
    pub profile_name: Option<String>,
}

/// The arguments of a `scan.start` / `scan.map` call (spec D7): from an
/// open editor the whole typed draft as `{profile}`, else the Profiles list
/// cursor's `{profile_name}`, else a typed origin as `{target}`; `None` with
/// nothing to launch. The draft is serialised with serde from `ScanProfile`,
/// so the wire carries exactly the type the engine parses. The returned
/// [`Launch`] carries the profile name the same precedence picks.
pub fn launch_args(
    editor: Option<&ProfileEditor>,
    list_name: Option<&str>,
    typed: Option<&str>,
) -> Option<Launch> {
    if let Some(editor) = editor {
        let profile = serde_json::to_value(&editor.draft).ok()?;
        let name = editor.draft.name.clone();
        return Some(Launch {
            args: json!({ "profile": profile }),
            profile_name: (!name.is_empty()).then_some(name),
        });
    }
    if let Some(name) = list_name {
        return Some(Launch {
            args: json!({ "profile_name": name }),
            profile_name: Some(name.to_string()),
        });
    }
    typed.map(|target| Launch {
        args: json!({ "target": target }),
        profile_name: None,
    })
}

/// The UI-3 launch gate (spec D7): `None` when `draft.lanes` has neither L4
/// lane, else the first of the three D7 reasons that applies, in D7 order:
/// the L4 layer missing from the bus, no L4 target in the draft, no L4
/// scope entry with the inject capability. The third names the entry to
/// add for the draft's first L4 target. The client checks presence only;
/// coverage of the target is the server's `out_of_scope` (D9).
pub fn l4_gate(
    draft: &ScanProfile,
    has_l4_scope_list: bool,
    l4_scope: &[L4ScopeEntry],
) -> Option<String> {
    if !wants_l4(&draft.lanes) {
        return None;
    }
    if !has_l4_scope_list {
        return Some(GATE_NO_LAYER.to_string());
    }
    let Some(first) = draft.target.l4.first() else {
        return Some(GATE_NO_TARGET.to_string());
    };
    if l4_scope.iter().any(|e| e.capability == INJECT) {
        return None;
    }
    // A host route: /128 for an IPv6 address, /32 otherwise (fix round G,
    // G66). An ip that parses as nothing still yields a suggestion: G53
    // refuses such a profile at fold, so only a hand-built draft has one.
    let prefix = match first.ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => 128,
        _ => 32,
    };
    Some(format!(
        "L4 launch disabled: no L4 scope entry with the inject capability. Add one with interface \"*\", direction outbound, {}/{prefix} ports {}, capability inject (l4.scope.add).",
        first.ip, first.port
    ))
}

/// The UI-3 launch gate for a Profiles list row with no editor open (D7 as
/// amended; fix round G, G73): `None` unless `lanes` has an L4 lane, else
/// [`GATE_NO_LAYER`] when the bus lacks `l4.scope.list`, else
/// [`GATE_OPEN_PROFILE`] (the row carries no targets or scope to check).
pub fn row_gate(lanes: &[LaneKind], has_l4_scope_list: bool) -> Option<String> {
    if !wants_l4(lanes) {
        None
    } else if !has_l4_scope_list {
        Some(GATE_NO_LAYER.to_string())
    } else {
        Some(GATE_OPEN_PROFILE.to_string())
    }
}

/// Whether `lanes` has an L4 lane, the one test both gates open with (fix
/// round H, H29).
fn wants_l4(lanes: &[LaneKind]) -> bool {
    lanes
        .iter()
        .any(|l| matches!(l, LaneKind::L4Packet | LaneKind::L4Stream))
}

/// A pending confirm-over-the-wire handshake (spec D3, D7), generalised from the
/// L4 inject confirm. The first guarded call (without `_confirm`) returns a
/// `needs_confirmation` reply whose `prompt` is the wire summary; the overlay
/// shows it and, on confirm, the UI re-issues the identical call plus the
/// reserved `_confirm` token. The `l4.*` guarded verbs and the `scan.*`
/// launches share this one type (no alias remains, spec D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireConfirm {
    /// The tool to re-issue (`l4.inject`, `scan.start`, ...).
    pub call: String,
    /// The original args, re-sent verbatim plus `_confirm`.
    pub args: Value,
    /// The wire summary the server built, shown to the operator.
    pub prompt: String,
    /// The single-use confirm token bound to the pending call.
    pub token: String,
}

/// What a guarded verb's reply is (L4 parity, stage-6 fix): the confirm
/// handshake bound to the pending call, a handshake the TUI cannot complete,
/// or a plain result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmReply {
    /// `needs_confirmation` with a token: the overlay to open.
    Handshake(WireConfirm),
    /// `needs_confirmation` without a string `confirm_token`: nothing can be
    /// re-issued, and it is not a success either.
    Malformed,
    /// Not a handshake: the verb's own result.
    Plain,
}

impl WireConfirm {
    /// Classify a reply against the pending `(call, args)` it answers. The
    /// prompt is bounded here, once (fix round H, H34): control characters
    /// stripped and the text cut to [`PROMPT_MAX`] cells.
    pub fn classify(call: &str, args: &Value, reply: &Value) -> ConfirmReply {
        if reply.get("status").and_then(Value::as_str) != Some("needs_confirmation") {
            return ConfirmReply::Plain;
        }
        let Some(token) = reply.get("confirm_token").and_then(Value::as_str) else {
            return ConfirmReply::Malformed;
        };
        let prompt = reply
            .get("prompt")
            .and_then(Value::as_str)
            .unwrap_or("Confirm this action?");
        ConfirmReply::Handshake(Self {
            call: call.to_string(),
            args: args.clone(),
            prompt: truncate(&clean(prompt), PROMPT_MAX),
            token: token.to_string(),
        })
    }

    /// Build from the pending `(call, args)` and a `needs_confirmation` reply.
    /// `None` when the reply is not a handshake the TUI can complete (a plain
    /// result, or a handshake without a token; [`Self::classify`] tells
    /// those apart).
    pub fn from_reply(call: &str, args: &Value, reply: &Value) -> Option<Self> {
        match Self::classify(call, args, reply) {
            ConfirmReply::Handshake(confirm) => Some(confirm),
            ConfirmReply::Malformed | ConfirmReply::Plain => None,
        }
    }

    /// Whether the call under confirmation is a `scan.*` launch (the
    /// family the reducer and the overlay decide by; fix round G, G68).
    pub fn is_scan(&self) -> bool {
        self.call.starts_with("scan.")
    }

    /// The args to re-send on confirm: the originals plus the `_confirm` token.
    pub fn confirmed_args(&self) -> Value {
        let mut args = self.args.clone();
        if let Value::Object(map) = &mut args {
            map.insert(CONFIRM_KEY.to_string(), Value::String(self.token.clone()));
        }
        args
    }
}

/// A `scan.start` / `scan.map` call sent and not yet answered (spec D7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingLaunch {
    /// The verb.
    pub call: LaunchVerb,
    /// What was sent and named: the arguments (re-issued with `_confirm`
    /// after a prompt) and the profile name for the toast (fix round H,
    /// H27: the [`Launch`] moved in whole).
    pub launch: Launch,
}

/// The launch state of the Scan view.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LaunchState {
    pub pending: Option<PendingLaunch>,
    /// The UI-3 reason the launch key is inert, recomputed whenever the
    /// draft, `app.l4.scope` or `app.tools` change; `None` means launchable.
    pub blocked: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classify_tells_a_handshake_from_a_malformed_one_and_a_plain_reply() {
        let args = json!({"spec": {"layers": []}, "dst": "127.0.0.1", "port": 7});
        let reply = json!({"status": "needs_confirmation", "prompt": "Inject 1 UDP to 127.0.0.1:7?", "confirm_token": "tok-9"});
        let ConfirmReply::Handshake(c) = WireConfirm::classify("l4.inject", &args, &reply) else {
            panic!("a complete handshake classifies as Handshake");
        };
        assert_eq!(c.call, "l4.inject");
        assert_eq!(c.prompt, "Inject 1 UDP to 127.0.0.1:7?");
        assert_eq!(c.token, "tok-9");
        assert_eq!(c.confirmed_args()["_confirm"], "tok-9");
        assert_eq!(c.confirmed_args()["dst"], "127.0.0.1");
        // A handshake without a string token cannot be completed.
        assert_eq!(
            WireConfirm::classify(
                "l4.inject",
                &args,
                &json!({"status": "needs_confirmation", "prompt": "P"})
            ),
            ConfirmReply::Malformed
        );
        // A plain success is not a confirmation handshake.
        assert_eq!(
            WireConfirm::classify("l4.inject", &args, &json!({"injected": 1})),
            ConfirmReply::Plain
        );
    }

    #[test]
    fn confirm_round_trip_adds_the_token() {
        let args = json!({"spec": {"layers": []}, "dst": "127.0.0.1", "port": 7});
        let reply = json!({"status": "needs_confirmation", "prompt": "Inject 1 UDP to 127.0.0.1:7?", "confirm_token": "tok-9"});
        let c = WireConfirm::from_reply("l4.inject", &args, &reply).unwrap();
        assert_eq!(c.token, "tok-9");
        assert_eq!(c.confirmed_args()["_confirm"], "tok-9");
        assert_eq!(c.confirmed_args()["dst"], "127.0.0.1");
        // A plain success is not a confirmation handshake.
        assert!(WireConfirm::from_reply("l4.inject", &args, &json!({"injected": 1})).is_none());
    }

    #[test]
    fn launch_args_prefer_the_editor_then_the_list_then_the_typed_origin() {
        let draft = ScanProfile {
            name: "mine".into(),
            ..ScanProfile::default()
        };
        let editor = ProfileEditor::new(draft.clone(), None, false);
        let launch = launch_args(Some(&editor), Some("standard"), Some("https://a.test")).unwrap();
        assert_eq!(
            serde_json::from_value::<ScanProfile>(launch.args["profile"].clone()).unwrap(),
            draft
        );
        assert_eq!(launch.profile_name.as_deref(), Some("mine"));
        // An unnamed draft names no profile (fix round G, G63: one
        // precedence for the request and the toast).
        let unnamed = ProfileEditor::new(ScanProfile::default(), None, false);
        assert_eq!(
            launch_args(Some(&unnamed), Some("standard"), None)
                .unwrap()
                .profile_name,
            None
        );
        assert_eq!(
            launch_args(None, Some("standard"), Some("https://a.test")),
            Some(Launch {
                args: json!({ "profile_name": "standard" }),
                profile_name: Some("standard".to_string()),
            })
        );
        assert_eq!(
            launch_args(None, None, Some("https://a.test")),
            Some(Launch {
                args: json!({ "target": "https://a.test" }),
                profile_name: None,
            })
        );
        assert_eq!(launch_args(None, None, None), None);
        assert_eq!(LaunchVerb::parse("scan.map"), Some(LaunchVerb::Map));
        assert_eq!(LaunchVerb::parse("scan.list"), None);
        assert_eq!(LaunchVerb::Start.to_string(), "scan.start");
    }

    /// Fix round G, G73: a list row's lanes gate `s` without an editor.
    #[test]
    fn the_row_gate_reads_the_lanes_alone() {
        assert_eq!(row_gate(&[LaneKind::Http, LaneKind::Ws], false), None);
        assert_eq!(
            row_gate(&[LaneKind::L4Stream], false).as_deref(),
            Some(GATE_NO_LAYER)
        );
        assert_eq!(
            row_gate(&[LaneKind::Http, LaneKind::L4Packet], true).as_deref(),
            Some(GATE_OPEN_PROFILE)
        );
    }

    #[test]
    fn the_gate_is_open_without_an_l4_lane_and_closed_in_d7_order() {
        use aitm_scan_model::{L4TargetSpec, L4Transport};
        let mut draft = ScanProfile::default();
        assert_eq!(l4_gate(&draft, false, &[]), None, "http only: no gate");
        draft.lanes = vec![LaneKind::L4Packet];
        assert_eq!(l4_gate(&draft, false, &[]).as_deref(), Some(GATE_NO_LAYER));
        assert_eq!(l4_gate(&draft, true, &[]).as_deref(), Some(GATE_NO_TARGET));
        draft.target.l4.push(L4TargetSpec {
            ip: "10.0.0.9".into(),
            port: 53,
            proto: L4Transport::Udp,
            grammar: None,
        });
        let capture = L4ScopeEntry::from_json(&json!({
            "interface": "*", "capability": "capture", "cidr": "0.0.0.0/0",
            "ports": "0-65535", "direction": "both"
        }))
        .unwrap();
        assert_eq!(
            l4_gate(&draft, true, std::slice::from_ref(&capture)).as_deref(),
            Some("L4 launch disabled: no L4 scope entry with the inject capability. Add one with interface \"*\", direction outbound, 10.0.0.9/32 ports 53, capability inject (l4.scope.add).")
        );
        let inject = L4ScopeEntry::from_json(&json!({
            "interface": "*", "capability": "inject", "cidr": "10.0.0.9/32",
            "ports": "53", "direction": "outbound"
        }))
        .unwrap();
        assert_eq!(l4_gate(&draft, true, &[capture, inject]), None);
        draft.target.l4[0].ip = "::1".into();
        assert!(l4_gate(&draft, true, &[])
            .unwrap()
            .contains("::1/128 ports 53"));
        // Fix round G, G66: the prefix follows the parsed address family,
        // not a colon; an ip that is no address (G53 refuses it at fold,
        // so only a hand-built draft carries one) still gets a suggestion.
        draft.target.l4[0].ip = "fe80::1".into();
        assert!(l4_gate(&draft, true, &[])
            .unwrap()
            .contains("fe80::1/128 ports 53"));
        draft.target.l4[0].ip = "not:an:ip".into();
        assert!(l4_gate(&draft, true, &[])
            .unwrap()
            .contains("not:an:ip/32 ports 53"));
    }
}
