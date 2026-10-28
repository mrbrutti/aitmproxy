//! The three message types the TUI is built from. `Action` is what a key or a
//! `:` command means; `App::update` consumes it and may emit `BusRequest`s; the
//! bus task runs those against the proxy and answers with `BusEvent`s. Keeping
//! them as plain data is what makes the app state testable without a terminal
//! or a proxy.

use serde_json::Value;

use crate::model::{AgentPolicy, AgentState, Finding, FlowDetail, FlowRow};

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

/// A tool the bus offers, enough to build the palette and a form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

impl ToolInfo {
    /// `(name, type, required, description)` for every declared parameter.
    pub fn params(&self) -> Vec<(String, String, bool, String)> {
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

/// Row data the app keeps for a flow plus whether its detail is loaded.
pub type RowSlot = (FlowRow, bool);
