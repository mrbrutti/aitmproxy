//! Launch bookkeeping (spec D3, D7): the call waiting for its reply, the
//! UI-3 reason a launch is blocked, and the wire-confirm handshake shared by the
//! `l4.*` guarded verbs and the `scan.*` launches.

use serde_json::Value;

use crate::action::CONFIRM_KEY;

/// A pending confirm-over-the-wire handshake (spec D3, D7), generalised from the
/// L4 inject confirm. The first guarded call (without `_confirm`) returns a
/// `needs_confirmation` reply whose `prompt` is the wire summary; the overlay
/// shows it and, on confirm, the UI re-issues the identical call plus the
/// reserved `_confirm` token. The L4 surface keeps a type alias to this.
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

impl WireConfirm {
    /// Build from the pending `(call, args)` and a `needs_confirmation` reply.
    /// `None` when the reply is not a confirmation handshake.
    pub fn from_reply(call: &str, args: &Value, reply: &Value) -> Option<Self> {
        if reply.get("status").and_then(Value::as_str) != Some("needs_confirmation") {
            return None;
        }
        Some(Self {
            call: call.to_string(),
            args: args.clone(),
            prompt: reply
                .get("prompt")
                .and_then(Value::as_str)
                .unwrap_or("Confirm this action?")
                .to_string(),
            token: reply
                .get("confirm_token")
                .and_then(Value::as_str)?
                .to_string(),
        })
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

/// A `scan.start` / `scan.map` / `scan.discover` call sent and not yet
/// answered.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingLaunch {
    /// The verb.
    pub call: String,
    /// The arguments as sent (re-issued with `_confirm` after a prompt).
    pub args: Value,
    /// The profile the launch named, for the toast.
    pub profile_name: Option<String>,
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
}
