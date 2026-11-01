//! `l4.privilege` and `l4.privilege.request` (spec §2.2, §2.3; plan P1b.10).
//!
//! - [`PrivilegeRead`] (`l4.privilege`, Read) answers the current
//!   [`PrivilegeReport`](crate::privilege::report::PrivilegeReport) for any caller, agent included, and whether or not
//!   `l4.enabled`: with L4 off it says so (`enabled: false`, three
//!   `unsupported`) instead of being absent.
//! - [`PrivilegeRequest`] (`l4.privilege.request`, Sensitive, always
//!   confirmable) starts the platform's permission flow through
//!   [`PrivilegeState::request`]. Its first line refuses every untrusted
//!   (agent) caller, before anything else runs (spec §2.3, §7 T4); `aitm-mcp`
//!   refuses it once more at the policy gate (`is_operator_only`, plan P7.1).
//!
//! [`PrivilegePlugin`] registers both. Audit (§7 T5) rides on the bus's own
//! ring like every verb; nothing here logs.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Plugin, Registry, Sensitivity, TypeDesc,
    Value,
};

use crate::privilege::state::{PrivilegeState, RequestOutcome};

/// The refusal an untrusted (agent) caller gets from `l4.privilege.request`
/// (spec §2.3), before the platform is consulted.
pub const AGENT_REFUSAL: &str = "l4.privilege.request refused: only an operator can ask for \
                                 packet-capture permission; an agent never can.";

/// The spec §2.3 confirm prompt on macOS.
pub const CONFIRM_MACOS: &str = "Ask the Aitmproxy app to set up packet capture? macOS will ask \
                                 an administrator to approve a background helper.";

/// The spec §2.3 confirm prompt on Linux.
pub const CONFIRM_LINUX: &str = "Ask for administrator approval to start the packet-capture \
                                 helper? A password prompt will appear on your desktop or in the \
                                 terminal running aitm.";

/// The prompt on a platform with no permission flow (the spec gives none; the
/// request there is always `cannot_prompt`, so the prompt stays neutral).
pub const CONFIRM_OTHER: &str = "Ask for packet-capture permission on this core?";

/// The confirm prompt for the OS this core was built for.
#[must_use]
pub fn confirm_prompt_text() -> &'static str {
    if cfg!(target_os = "macos") {
        CONFIRM_MACOS
    } else if cfg!(target_os = "linux") {
        CONFIRM_LINUX
    } else {
        CONFIRM_OTHER
    }
}

// ---- l4.privilege -------------------------------------------------------------

/// `l4.privilege` → the current report (Read; agents may call it).
pub struct PrivilegeRead {
    state: Arc<PrivilegeState>,
}

impl PrivilegeRead {
    #[must_use]
    pub fn new(state: Arc<PrivilegeState>) -> Self {
        Self { state }
    }
}

impl Command for PrivilegeRead {
    fn name(&self) -> &str {
        "l4.privilege"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Report whether this core can capture, inject and intercept raw \
                          packets right now, what must be approved first and how (never a \
                          shell command), the privileged helper's status, and the progress of \
                          the last l4.privilege.request. Read-only; agents may call it. It \
                          answers even when L4 is off in this core's config (enabled: false, \
                          every capability unsupported)."
                .into(),
            params: vec![],
            result: TypeDesc::Object(report_fields()),
        }
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(self.state.report().to_value())
    }
}

// ---- l4.privilege.request -----------------------------------------------------

/// `l4.privilege.request` → start the platform's packet-capture permission flow
/// (Sensitive, operator-only, always confirmed).
pub struct PrivilegeRequest {
    state: Arc<PrivilegeState>,
}

impl PrivilegeRequest {
    #[must_use]
    pub fn new(state: Arc<PrivilegeState>) -> Self {
        Self { state }
    }
}

impl Command for PrivilegeRequest {
    fn name(&self) -> &str {
        "l4.privilege.request"
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn confirm_prompt(&self, _args: &Params) -> Option<String> {
        Some(confirm_prompt_text().to_string())
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Ask the operating system for packet-capture permission: on macOS the \
                          Aitmproxy app is asked to set it up and macOS prompts for approval; \
                          on Linux a polkit password prompt starts the packet-capture helper. \
                          Returns at once; poll l4.privilege for the request's progress. \
                          Operator and CLI only: an agent is refused before anything runs."
                .into(),
            params: vec![],
            result: TypeDesc::Object(vec![
                field(
                    "outcome",
                    TypeDesc::Str,
                    "`already_available`, `pending`, `handed_to_app` or `cannot_prompt`.",
                ),
                field("message", TypeDesc::Str, "What happened, for the operator."),
                field(
                    "privilege",
                    TypeDesc::Object(report_fields()),
                    "The l4.privilege report right after the request.",
                ),
            ]),
        }
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        // Spec §2.3, §7 T4: the agent never asks, under any policy. The policy
        // gate in `aitm-mcp` refuses it too; this line holds on every bus.
        if !host.caller_is_trusted_control() {
            anyhow::bail!("{AGENT_REFUSAL}");
        }
        Ok(outcome_to_value(&self.state.request()))
    }
}

/// `{"outcome", "message", "privilege"}` (spec §2.3).
fn outcome_to_value(outcome: &RequestOutcome) -> Value {
    let mut map = BTreeMap::new();
    map.insert(
        "outcome".to_string(),
        Value::Str(outcome.outcome.as_str().to_string()),
    );
    map.insert("message".to_string(), Value::Str(outcome.message.clone()));
    map.insert("privilege".to_string(), outcome.privilege.to_value());
    Value::Object(map)
}

// ---- registration -------------------------------------------------------------

/// The two privilege commands over one shared state.
#[must_use]
pub fn privilege_commands(state: Arc<PrivilegeState>) -> Vec<Arc<dyn Command>> {
    vec![
        Arc::new(PrivilegeRead::new(Arc::clone(&state))),
        Arc::new(PrivilegeRequest::new(state)),
    ]
}

/// Registers `l4.privilege` and `l4.privilege.request`. The `aitm` binary adds
/// it whether or not `l4.enabled` (spec §2.2), so a frontend can always ask.
pub struct PrivilegePlugin {
    state: Arc<PrivilegeState>,
}

impl PrivilegePlugin {
    #[must_use]
    pub fn new(state: Arc<PrivilegeState>) -> Self {
        Self { state }
    }
}

impl Plugin for PrivilegePlugin {
    fn name(&self) -> &str {
        "l4-privilege"
    }

    fn load(&mut self, reg: &mut Registry) {
        for cmd in privilege_commands(Arc::clone(&self.state)) {
            reg.add_command(cmd);
        }
    }
}

/// The top-level fields of a `PrivilegeReport` (spec §2.2), for the schemas.
fn report_fields() -> Vec<ParamDef> {
    vec![
        field(
            "enabled",
            TypeDesc::Bool,
            "`l4.enabled` in this core's config.",
        ),
        field("platform", TypeDesc::Str, "`macos`, `linux` or `other`."),
        field(
            "capabilities",
            TypeDesc::Map(Box::new(TypeDesc::Any)),
            "`capture`, `inject`, `intercept`: each `{state, via}` (available), \
             `{state, reason, how}` (needs_approval) or `{state, reason}` (unsupported).",
        ),
        field(
            "helper",
            TypeDesc::Map(Box::new(TypeDesc::Any)),
            "`{kind, status, version, detail}`: the privileged component as this core sees it.",
        ),
        field(
            "request",
            TypeDesc::Map(Box::new(TypeDesc::Any)),
            "`{state, at, message}` of the last l4.privilege.request on this core, or null.",
        ),
        field(
            "checked_at",
            TypeDesc::Int,
            "When the probe last ran, epoch milliseconds.",
        ),
    ]
}

fn field(name: &str, ty: TypeDesc, description: &str) -> ParamDef {
    ParamDef {
        name: name.into(),
        ty,
        required: true,
        description: description.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use aitm_core::{
        Command, CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, Plugin,
        ProxyClient, Registry, Sensitivity, StdGuard, Value,
    };
    use futures::future::BoxFuture;

    use super::*;
    use crate::config::L4PrivilegeConfig;
    use crate::privilege::derive::{MacInputs, ProbeInputs};
    use crate::privilege::report::{Platform, PrivilegeReport, RequestProgress};
    use crate::privilege::state::{
        Outcome, PrivilegeConfig, PrivilegeState, Prober, ProcessLifetime, Requester,
    };

    /// Words no operator-facing text may carry (plan Rule 2).
    const FORBIDDEN: [&str; 8] = [
        "sudo",
        "setcap",
        "chmod",
        "chgrp",
        "chown",
        "dseditgroup",
        "launchctl",
        "pkexec",
    ];

    // ---- scaffolding ----------------------------------------------------------

    struct StubClient;
    impl ProxyClient for StubClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    /// A prober fixed on one macOS row; the state stamps `request` and the clock.
    struct Fixed(ProbeInputs);

    impl Prober for Fixed {
        fn gather(&self, request: Option<&RequestProgress>) -> ProbeInputs {
            let mut inputs = self.0.clone();
            inputs.request = request.cloned();
            inputs
        }
    }

    /// Row 6: nothing opens, no receipt, no handoff app.
    fn row6() -> ProbeInputs {
        mac_inputs(false)
    }

    /// Row 2: `/dev/bpf*` opens read+write.
    fn row2() -> ProbeInputs {
        mac_inputs(true)
    }

    fn mac_inputs(bpf_rw_opens: bool) -> ProbeInputs {
        ProbeInputs {
            enabled: true,
            platform: Platform::Macos,
            mac: Some(MacInputs {
                bpf_rw_opens,
                receipt: None,
                handoff_app_embeds_helper: false,
            }),
            linux: None,
            request: None,
            now_ms: 0,
        }
    }

    /// A requester that counts its calls and answers a scripted outcome.
    struct Scripted {
        answer: (Outcome, &'static str),
        calls: AtomicU64,
        seen: Mutex<Vec<PrivilegeReport>>,
    }

    impl Scripted {
        fn new(outcome: Outcome, message: &'static str) -> Arc<Self> {
            Arc::new(Self {
                answer: (outcome, message),
                calls: AtomicU64::new(0),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Requester for Arc<Scripted> {
        fn request(&self, _cfg: &PrivilegeConfig, report: &PrivilegeReport) -> (Outcome, String) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(report.clone());
            (self.answer.0, self.answer.1.to_string())
        }
    }

    fn cfg(enabled: bool) -> PrivilegeConfig {
        PrivilegeConfig {
            enabled,
            l4: L4PrivilegeConfig::default(),
            lifetime: ProcessLifetime::Serving,
        }
    }

    /// A state over a fixed row, a settable clock and a scripted requester.
    fn state_with(
        enabled: bool,
        inputs: ProbeInputs,
        requester: Arc<Scripted>,
    ) -> (Arc<PrivilegeState>, Arc<AtomicU64>) {
        let now = Arc::new(AtomicU64::new(0));
        let clock_now = Arc::clone(&now);
        let state = PrivilegeState::with_prober(
            &cfg(enabled),
            Box::new(Fixed(inputs)),
            Arc::new(move || clock_now.load(Ordering::SeqCst)),
        )
        .with_requester(Box::new(requester));
        (Arc::new(state), now)
    }

    fn obj(value: &Value) -> &BTreeMap<String, Value> {
        match value {
            Value::Object(map) => map,
            other => panic!("want an object, got {other:?}"),
        }
    }

    fn str_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
        let mut cursor = value;
        for key in path {
            cursor = obj(cursor)
                .get(*key)
                .unwrap_or_else(|| panic!("missing key `{key}` in {cursor:?}"));
        }
        match cursor {
            Value::Str(text) => text,
            other => panic!("want a string at {path:?}, got {other:?}"),
        }
    }

    fn int_at(value: &Value, path: &[&str]) -> i64 {
        let mut cursor = value;
        for key in path {
            cursor = obj(cursor)
                .get(*key)
                .unwrap_or_else(|| panic!("missing key `{key}` in {cursor:?}"));
        }
        match cursor {
            Value::Int(n) => *n,
            other => panic!("want an int at {path:?}, got {other:?}"),
        }
    }

    fn assert_clean(text: &str) {
        let lower = text.to_lowercase();
        for word in FORBIDDEN {
            assert!(
                !lower.contains(word),
                "operator text names a command `{word}`: {text:?}"
            );
        }
    }

    // ---- tests ------------------------------------------------------------------

    /// Spec §2.3, L4PRIV-AC5: an untrusted (agent) host is refused on the first
    /// line, before the platform requester is even consulted.
    #[test]
    fn agent_host_is_refused_first() {
        let requester = Scripted::new(Outcome::HandedToApp, "handed to the Aitmproxy app");
        let (state, _now) = state_with(true, row6(), Arc::clone(&requester));
        let cmd = PrivilegeRequest::new(state);

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        // A host never given a frontend is `Frontend::Mcp`: the gated posture.
        let agent = CommandHost::new(&mem, &client, &core, None);
        let err = cmd
            .invoke(Params::default(), &agent)
            .expect_err("an agent is refused");
        assert!(
            err.to_string()
                .starts_with("l4.privilege.request refused: only an operator"),
            "refusal text: {err}"
        );
        assert_eq!(
            err.to_string(),
            "l4.privilege.request refused: only an operator can ask for packet-capture \
             permission; an agent never can."
        );
        assert_eq!(requester.calls(), 0, "the requester is never reached");
        assert_clean(&err.to_string());

        // An explicit `Mcp` frontend is refused the same way.
        let mcp = CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Mcp);
        assert!(cmd.invoke(Params::default(), &mcp).is_err());
        assert_eq!(requester.calls(), 0);
    }

    /// `sensitivity()` is `Sensitive` and `confirm_prompt` is always `Some` on
    /// empty params (the expression `aitm-mcp`'s `schema.rs` uses for
    /// `confirmable`), with the spec §2.3 literal for this OS.
    #[test]
    fn request_is_sensitive_and_confirmable() {
        let requester = Scripted::new(Outcome::CannotPrompt, "n/a");
        let (state, _now) = state_with(true, row6(), requester);
        let cmd = PrivilegeRequest::new(state);

        assert_eq!(cmd.sensitivity(), Sensitivity::Sensitive);
        assert!(cmd.mutates());
        let prompt = cmd
            .confirm_prompt(&Params::default())
            .expect("the request always confirms");
        let expected = if cfg!(target_os = "macos") {
            "Ask the Aitmproxy app to set up packet capture? macOS will ask an administrator \
             to approve a background helper."
        } else if cfg!(target_os = "linux") {
            "Ask for administrator approval to start the packet-capture helper? A password \
             prompt will appear on your desktop or in the terminal running aitm."
        } else {
            "Ask for packet-capture permission on this core?"
        };
        assert_eq!(prompt, expected);
        assert_clean(&prompt);
        assert!(cmd.schema().params.is_empty(), "no params");
    }

    /// Row 2 (capture available): `already_available`, nothing dispatched, no
    /// progress recorded.
    #[test]
    fn available_is_already_available() {
        let requester = Scripted::new(Outcome::HandedToApp, "should not be called");
        let (state, _now) = state_with(true, row2(), Arc::clone(&requester));
        let cmd = PrivilegeRequest::new(Arc::clone(&state));

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let operator =
            CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);

        let reply = cmd
            .invoke(Params::default(), &operator)
            .expect("an operator may ask");
        assert_eq!(str_at(&reply, &["outcome"]), "already_available");
        assert_eq!(
            str_at(&reply, &["privilege", "capabilities", "capture", "state"]),
            "available"
        );
        assert_eq!(
            str_at(&reply, &["privilege", "capabilities", "capture", "via"]),
            "process"
        );
        assert_eq!(obj(&obj(&reply)["privilege"])["request"], Value::Null);
        assert_eq!(requester.calls(), 0, "nothing to request");
        assert_clean(str_at(&reply, &["message"]));
        assert_eq!(
            obj(&reply).keys().cloned().collect::<Vec<_>>(),
            vec!["message", "outcome", "privilege"]
        );

        // The CLI is trusted control too.
        let cli = CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Cli);
        assert!(cmd.invoke(Params::default(), &cli).is_ok());
    }

    /// Spec §2.3: one request at a time; a second call while one is pending
    /// returns `pending` with the same progress (same `at`), and the platform is
    /// asked once.
    #[test]
    fn second_call_while_pending_returns_same_progress() {
        let requester = Scripted::new(Outcome::Pending, "waiting for the administrator");
        let (state, now) = state_with(true, row6(), Arc::clone(&requester));
        let cmd = PrivilegeRequest::new(Arc::clone(&state));

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let operator =
            CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);

        now.store(100, Ordering::SeqCst);
        let first = cmd
            .invoke(Params::default(), &operator)
            .expect("first call");
        assert_eq!(str_at(&first, &["outcome"]), "pending");
        assert_eq!(
            str_at(&first, &["message"]),
            "waiting for the administrator"
        );
        assert_eq!(
            str_at(&first, &["privilege", "request", "state"]),
            "pending"
        );
        assert_eq!(int_at(&first, &["privilege", "request", "at"]), 100);
        assert_eq!(
            str_at(&first, &["privilege", "request", "message"]),
            "waiting for the administrator"
        );
        assert_eq!(requester.calls(), 1);

        now.store(2500, Ordering::SeqCst);
        let second = cmd
            .invoke(Params::default(), &operator)
            .expect("second call");
        assert_eq!(str_at(&second, &["outcome"]), "pending");
        assert_eq!(
            str_at(&second, &["message"]),
            "waiting for the administrator"
        );
        assert_eq!(
            int_at(&second, &["privilege", "request", "at"]),
            100,
            "the same progress, not a new one"
        );
        assert_eq!(requester.calls(), 1, "the platform is asked once");

        // `l4.privilege` shows the same in-flight request.
        let read = PrivilegeRead::new(state)
            .invoke(Params::default(), &operator)
            .expect("read");
        assert_eq!(str_at(&read, &["request", "state"]), "pending");
        assert_eq!(int_at(&read, &["request", "at"]), 100);
    }

    /// Spec §2.2, L4PRIV-AC2: `l4.privilege` answers with `l4.enabled: false`:
    /// `"enabled": false` and three `unsupported`, for an agent host too.
    #[test]
    fn read_verb_answers_with_l4_off() {
        let requester = Scripted::new(Outcome::HandedToApp, "unused");
        let mut inputs = row2();
        inputs.enabled = false;
        let (state, _now) = state_with(false, inputs, Arc::clone(&requester));
        let read = PrivilegeRead::new(Arc::clone(&state));

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let agent = CommandHost::new(&mem, &client, &core, None);

        let reply = read
            .invoke(Params::default(), &agent)
            .expect("the read verb answers an agent");
        assert_eq!(obj(&reply)["enabled"], Value::Bool(false));
        for class in ["capture", "inject", "intercept"] {
            assert_eq!(
                str_at(&reply, &["capabilities", class, "state"]),
                "unsupported",
                "{class}"
            );
        }
        assert_eq!(
            str_at(&reply, &["capabilities", "capture", "reason"]),
            "L4 is off in this core's config (l4.enabled)"
        );

        // The request verb with L4 off: `cannot_prompt`, the platform never asked.
        let operator =
            CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);
        let asked = PrivilegeRequest::new(state)
            .invoke(Params::default(), &operator)
            .expect("an operator may ask even with L4 off");
        assert_eq!(str_at(&asked, &["outcome"]), "cannot_prompt");
        assert_eq!(
            str_at(&asked, &["message"]),
            "L4 is off in this core's config (l4.enabled)"
        );
        assert_eq!(
            obj(&obj(&asked)["privilege"])["enabled"],
            Value::Bool(false)
        );
        assert_eq!(requester.calls(), 0);
    }

    /// A `cannot_prompt` answer is recorded as `failed` progress with the
    /// platform's message, so the next `l4.privilege` shows it.
    #[test]
    fn cannot_prompt_records_failed_progress() {
        let requester = Scripted::new(Outcome::CannotPrompt, "the Aitmproxy app is not installed");
        let (state, now) = state_with(true, row6(), Arc::clone(&requester));

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let operator =
            CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);

        now.store(42, Ordering::SeqCst);
        let asked = PrivilegeRequest::new(Arc::clone(&state))
            .invoke(Params::default(), &operator)
            .expect("request");
        assert_eq!(str_at(&asked, &["outcome"]), "cannot_prompt");
        assert_eq!(
            str_at(&asked, &["message"]),
            "the Aitmproxy app is not installed"
        );
        assert_eq!(requester.calls(), 1);
        assert_eq!(str_at(&asked, &["privilege", "request", "state"]), "failed");

        let read = PrivilegeRead::new(Arc::clone(&state))
            .invoke(Params::default(), &operator)
            .expect("read");
        assert_eq!(str_at(&read, &["request", "state"]), "failed");
        assert_eq!(int_at(&read, &["request", "at"]), 42);
        assert_eq!(
            str_at(&read, &["request", "message"]),
            "the Aitmproxy app is not installed"
        );

        // A failed request is not in flight: the next call asks the platform again.
        now.store(99, Ordering::SeqCst);
        let again = PrivilegeRequest::new(state)
            .invoke(Params::default(), &operator)
            .expect("request again");
        assert_eq!(str_at(&again, &["outcome"]), "cannot_prompt");
        assert_eq!(int_at(&again, &["privilege", "request", "at"]), 99);
        assert_eq!(requester.calls(), 2);
    }

    /// `handed_to_app` is recorded as such, and the macOS table's row 4 then
    /// answers `os_dialog` on the very next report (the request invalidates the
    /// cache).
    #[test]
    fn handed_to_app_records_progress_and_flips_the_row() {
        let requester = Scripted::new(Outcome::HandedToApp, "handed to the Aitmproxy app");
        let (state, now) = state_with(true, row6(), Arc::clone(&requester));

        let mem = MemFlowStore::new();
        let client = StubClient;
        let core = StdGuard::default();
        let operator =
            CommandHost::new(&mem, &client, &core, None).with_frontend(Frontend::Operator);

        now.store(7, Ordering::SeqCst);
        let asked = PrivilegeRequest::new(Arc::clone(&state))
            .invoke(Params::default(), &operator)
            .expect("request");
        assert_eq!(str_at(&asked, &["outcome"]), "handed_to_app");
        assert_eq!(
            str_at(&asked, &["privilege", "request", "state"]),
            "handed_to_app"
        );
        assert_eq!(int_at(&asked, &["privilege", "request", "at"]), 7);
        assert_eq!(
            str_at(
                &asked,
                &["privilege", "capabilities", "capture", "how", "kind"]
            ),
            "os_dialog"
        );
        // The requester saw the report it was asked about: row 6, before the handoff.
        let seen = requester.seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].capture.how().map(|how| how.kind.as_str()),
            Some("package")
        );
    }

    /// Tripwire: the wire names, tiers and the plugin registration are pinned.
    #[test]
    fn names_tiers_and_plugin_are_pinned() {
        let requester = Scripted::new(Outcome::CannotPrompt, "n/a");
        let (state, _now) = state_with(true, row6(), requester);

        let read = PrivilegeRead::new(Arc::clone(&state));
        assert_eq!(read.name(), "l4.privilege");
        assert_eq!(read.sensitivity(), Sensitivity::Read);
        assert!(!read.mutates());
        assert_eq!(read.confirm_prompt(&Params::default()), None);
        assert!(read.schema().params.is_empty());
        let description = read.schema().description;
        assert!(
            description.contains("L4 is off"),
            "the read schema says it answers with L4 off: {description}"
        );
        assert_clean(&description);

        let request = PrivilegeRequest::new(Arc::clone(&state));
        assert_eq!(request.name(), "l4.privilege.request");
        assert_eq!(request.sensitivity(), Sensitivity::Sensitive);
        assert_clean(&request.schema().description);

        let names: Vec<String> = privilege_commands(Arc::clone(&state))
            .iter()
            .map(|cmd| cmd.name().to_string())
            .collect();
        assert_eq!(names, vec!["l4.privilege", "l4.privilege.request"]);

        let mut plugin = PrivilegePlugin::new(state);
        assert_eq!(plugin.name(), "l4-privilege");
        let mut reg = Registry::new();
        plugin.load(&mut reg);
        assert!(reg.command("l4.privilege").is_some());
        assert_eq!(
            reg.command("l4.privilege.request")
                .map(|cmd| cmd.sensitivity()),
            Some(Sensitivity::Sensitive)
        );
        assert_eq!(reg.commands().count(), 2);
    }
}
