//! The three message types the TUI is built from. `Action` is what a key or a
//! `:` command means; `App::update` consumes it and may emit `BusRequest`s; the
//! bus task runs those against the proxy and answers with `BusEvent`s. Keeping
//! them as plain data is what makes the app state testable without a terminal
//! or a proxy.

use serde_json::Value;

use crate::model::{AgentPolicy, AgentState, Finding, FlowDetail};

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
    ProxyPause(bool),
    ClearFlows,
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
    Connected {
        server: String,
        tools: Vec<ToolInfo>,
        listening: Option<String>,
    },
    Disconnected(String),
    /// A full pass over `flow.list` + `flow.get`, oldest first.
    Flows(Vec<Value>),
    Detail(Box<FlowDetail>),
    /// `flow.detail` for this id answered with something the model rejects;
    /// the app must stop asking for it (a `Toast` accompanies this).
    DetailFailed(String),
    Intercept(bool),
    Scope(Vec<String>),
    Findings(Vec<Finding>),
    Agent(AgentState),
    /// A command completed; `name` is the tool, `value` its structured result.
    CallOk {
        name: String,
        value: Value,
    },
    Toast(Level, String),
    /// An unsolicited server line (F4).
    Notification(Value),
}

/// The form-building view of a tool's `inputSchema` (foundation §4.2 step 3:
/// every form is built from the schema, never hard-coded).
pub trait ToolSchema {
    /// `(name, type, required, description)` for every declared parameter.
    fn params(&self) -> Vec<(String, String, bool, String)>;
}

impl ToolSchema for ToolInfo {
    fn params(&self) -> Vec<(String, String, bool, String)> {
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
                    .map(|(name, schema)| {
                        (
                            name.clone(),
                            schema
                                .get("type")
                                .and_then(Value::as_str)
                                .unwrap_or("any")
                                .to_string(),
                            required.contains(&name.as_str()),
                            schema
                                .get("description")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}
