//! The three message types the TUI is built from. `Action` is what a key or a
//! `:` command means; `App::update` consumes it and may emit `BusRequest`s; the
//! bus task runs those against the proxy and answers with `BusEvent`s. Keeping
//! them as plain data is what makes the app state testable without a terminal
//! or a proxy.

use serde_json::Value;

use crate::model::{AgentPolicy, AgentState, Finding, FlowDetail, ProxyStatus};

/// A tool the bus offers, enough to build the palette and a form: the
/// `tools/list` entry exactly as the bus client decodes it. [`ToolSchema`]
/// adds the form-building view of its schema.
pub use aitm_bus_client::ToolDef as ToolInfo;

/// A user intent, already resolved from the key map for the current mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Quit,
    Tick,
    Resize(u16, u16),
    // Navigation
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    /// Open the inspector for the selection (full-screen on narrow terminals).
    Enter,
    /// Leave the current overlay/mode.
    Back,
    ToggleSidebar,
    SidebarNext,
    SidebarPrev,
    ChipNext,
    ChipPrev,
    ChipIndex(usize),
    ToggleLayout,
    ToggleAutoSelect,
    /// Flow list `s` (spec §D14): set the OS system proxy to this core, or
    /// restore it when `proxy.status.system_proxy` already points at us.
    /// Routed through `:sysproxy on|off`, so the same tool gate applies.
    ToggleSysProxy,
    Help,
    // Flow verbs (mitmproxy idiom, §2.1)
    ToggleIntercept,
    Resume,
    ResumeAll,
    Kill,
    Edit,
    Replay,
    Compose,
    Pin,
    Mark,
    Comment,
    BuildPoc,
    QuickLook,
    CopyUrl,
    OpenExternally,
    // Panels
    OpenFindings,
    OpenScope,
    OpenAgent,
    /// The browser view (§2.7); asks the bus for the DOM and a screenshot
    /// the first time, when it offers `browser.*`.
    OpenBrowser,
    /// The Scan view (scanner-integration Stage 1). Opens the view only and
    /// shows the scope-bound target; viewing never crawls.
    OpenScan,
    /// The L4 panel (`L`, `:l4`): capture / intercept availability from the
    /// status verbs, the running captures and the capture commands (L4 parity
    /// spec §1, AC15). Opening it sends nothing.
    OpenL4,
    /// Scan view `r`: launch a scope-bound `scan.discover` (deny-by-default:
    /// an out-of-scope target is refused; a running crawl blocks re-launch).
    ScanLaunch,
    /// Scan view Tab: move the cursor between the endpoints list and the
    /// injection-points list, so either can be walked and opened with ⏎.
    ScanFocusToggle,
    AgentSet(AgentPolicy),
    // Text prompts
    PaletteOpen,
    FilterOpen,
    /// A character typed into whichever prompt is open.
    Input(char),
    Backspace,
    /// Submit the open prompt.
    Submit,
    /// A `:` command line, e.g. `import /tmp/x.har`, `layout vertical`, `scope add h`.
    Command(String),
    // Inspector
    InspectorPaneToggle,
    InspectorTabNext,
    InspectorTabPrev,
    ScrollBody(i32),
    ToggleFold,
    /// Apply the pending edit and resume (`flow.mutate` then `flow.resume`).
    ApplyAndResume,
    RevertEdit,
    // Panel verbs (keys that are not a typed command line)
    /// Browser view `g`: the URL prompt for `browser.navigate`, prefilled
    /// with the current URL.
    BrowserNavigatePrompt,
    /// Browser view `e`: the expression prompt for `browser.eval`.
    BrowserEvalPrompt,
    /// Browser view `d`: re-read the page (`browser.get_dom`).
    BrowserRefreshDom,
    /// Browser view `s`: `browser.screenshot`.
    BrowserScreenshot,
    /// CA panel `e`: the `[pem|der] [path]` prompt for `ca.export`.
    CaExportPrompt,
    /// Findings `r`: run the selected finding's PoC again (target, then vars).
    PocRerun,
    /// Scope panel `a`: the add-host prompt.
    ScopeAddPrompt,
    /// Scope panel `d`: remove the entry under the cursor (`scope.remove`).
    ScopeRemoveSelected,
    /// Compose `Ctrl-S` / `Ctrl-Enter`: send the form whichever field has focus.
    ComposeSend,
    // L4 operator surface (ui-ext Part 3). Routed in the reducer by the selected
    // flow kind; a no-op on a non-L4 flow.
    /// Build the craft YAML into a hex preview (`l4.craft`).
    L4Build,
    /// Inject the crafted packet (`l4.inject`), triggering confirm-over-the-wire.
    L4Inject,
    /// Answer the inject confirm overlay: `true` re-issues with `_confirm`.
    L4Confirm(bool),
    /// Craft pane `m`: apply the editor's spec to the selected intercept
    /// flow's parked packet (`l4.intercept.mutate {id, spec}`, L4 parity spec
    /// §4 / AC12). The id is the parked packet's from `l4.intercept.list`.
    L4MutateParked,
    /// Craft pane `u`: discard the staged edit of that parked packet
    /// (`l4.intercept.revert {id}`).
    L4RevertParked,
    /// Toggle one per-feature agent gate in the Agent view (`l4.agent.set`).
    L4ToggleGate(crate::l4::L4Gate),
}

/// Work for the bus task.
#[derive(Debug, Clone, PartialEq)]
pub enum BusRequest {
    Refresh,
    Detail(String),
    Intercept(bool),
    Resume(String),
    Kill(String),
    Mutate {
        id: String,
        edits: Value,
    },
    Replay(String),
    Send(Value),
    ScopeAdd(String),
    ScopeRemove(String),
    PocBuild {
        flow_id: String,
        name: Option<String>,
        param: Option<String>,
    },
    PocRun {
        poc_path: String,
        target: Option<String>,
        /// Template variables for the PoC (`poc.run {vars?}`, §4.3).
        vars: Option<Value>,
    },
    AgentSet(AgentPolicy),
    /// `true` → `proxy.pause {}`, `false` → `proxy.resume {}` (F7: two
    /// parameterless tools, each answering the capture state).
    ProxyPause(bool),
    ClearFlows,
    /// `poc.get {poc_path}` (F13): the PoC's YAML and description.
    PocGet(String),
    Mark {
        id: String,
        marks: Vec<String>,
    },
    Comment {
        id: String,
        text: String,
    },
    Import(String),
    /// Any tool by name, from the palette.
    Call {
        name: String,
        args: Value,
    },
}

/// Severity of a status-line toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

/// What the bus task learned.
#[derive(Debug, Clone, PartialEq)]
pub enum BusEvent {
    /// The handshake succeeded: `initialize` answered and `tools/list` read.
    /// `role` is the server-resolved role echoed in the `initialize` result
    /// (`"operator"`/`"agent"`), or `None` when the server did not echo one.
    Connected {
        server: String,
        tools: Vec<ToolInfo>,
        role: Option<String>,
    },
    /// `proxy.status` (F7), read at the handshake and on every slow pass.
    ProxyStatus(ProxyStatus),
    Disconnected(String),
    /// A full pass over `flow.list` + `flow.get`, oldest first.
    Flows(Vec<Value>),
    Detail(Box<FlowDetail>),
    /// `flow.detail` for this id answered with something the model rejects;
    /// the app must stop asking for it (a `Toast` accompanies this).
    DetailFailed(String),
    Intercept(bool),
    Scope(Vec<String>),
    /// The PoC library (`poc.list`, F13): files, none of them run.
    Findings(Vec<Finding>),
    /// What Rhai scripts recorded with `finding(...)` (`findings.list`, M3).
    ScriptFindings(Vec<Finding>),
    Agent(AgentState),
    /// A command completed; `name` is the tool, `value` its structured result.
    CallOk {
        name: String,
        value: Value,
    },
    /// A `tools/call` did not complete: the tool reported an error, the
    /// server answered with a JSON-RPC error or a malformed reply, or the bus
    /// does not offer `name` at all. `message` is the operator-facing text.
    CallFailed {
        name: String,
        message: String,
    },
    /// A notice with no tool behind it (a per-flow poll warning, a malformed
    /// `flow.detail` reply).
    Toast(Level, String),
    /// An unsolicited server line (F4).
    Notification(Value),
    /// A pass over `l4.flow.list` + `l4.flow.get` (ui-ext Part 3): each value is
    /// an `l4.flow.get` object. Emitted only when the bus offers `l4.flow.list`.
    L4Flows(Vec<Value>),
    /// `l4.scope.list`: the L4 scope entries, as serialized `L4ScopeEntry`s.
    L4Scope(Vec<Value>),
    /// `l4.agent.status`: the four per-feature agent gate states.
    L4Agent(Value),
    /// `l4.capture.status` + `l4.intercept.status` (L4 parity spec §1), read on
    /// every slow pass: the two availabilities and the running capture ids.
    L4Availability {
        capture: crate::l4::L4Availability,
        intercept: crate::l4::L4Availability,
        captures: Vec<String>,
    },
    /// `l4.intercept.list` (spec §4): the parked packets, oldest first, each an
    /// `{id, flow, state, dir, length, layers, parked_at}` object. Read only
    /// while intercept is available.
    L4Parked(Vec<Value>),
}

/// One declared parameter of a tool's `inputSchema`, as a form row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// The property name (`id`, `url`, …).
    pub name: String,
    /// The JSON Schema `type`; `any` when the schema does not say.
    pub ty: String,
    /// Listed in the schema's `required` array.
    pub required: bool,
    /// The schema's `description`, empty when absent.
    pub description: String,
}

/// The form-building view of a tool's `inputSchema` (foundation §4.2 step 3:
/// every form is built from the schema, never hard-coded).
pub trait ToolSchema {
    /// Every declared parameter, in the schema's order.
    fn params(&self) -> Vec<Param>;
}

impl ToolSchema for ToolInfo {
    fn params(&self) -> Vec<Param> {
        let required: Vec<&str> = self
            .input_schema
            .get("required")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        self.input_schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|props| {
                props
                    .iter()
                    .map(|(name, schema)| Param {
                        name: name.clone(),
                        ty: schema
                            .get("type")
                            .and_then(Value::as_str)
                            .unwrap_or("any")
                            .to_string(),
                        required: required.contains(&name.as_str()),
                        description: schema
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
