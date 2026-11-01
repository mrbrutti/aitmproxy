//! The `PrivilegeReport`: what `l4.privilege` answers and what the status verbs
//! carry under their `privilege` key (spec §2.2).
//!
//! Pure data. `to_value` renders the exact JSON shape the spec tables give, with
//! serde-style snake_case strings for every enum, so every frontend decodes one
//! shape. Nothing here names a command an operator could type (spec AC3).

use std::collections::BTreeMap;

use aitm_core::Value;

/// The verb a frontend calls to start the platform's permission flow.
pub const REQUEST_VERB: &str = "l4.privilege.request";

/// The whole answer to `l4.privilege`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeReport {
    /// `l4.enabled` in this core's config.
    pub enabled: bool,
    /// The OS this core runs on.
    pub platform: Platform,
    /// Raw packet capture.
    pub capture: Capability,
    /// Raw packet injection.
    pub inject: Capability,
    /// In-path interception (Linux NFQUEUE).
    pub intercept: Capability,
    /// The privileged component as this core sees it.
    pub helper: Helper,
    /// The last `l4.privilege.request` on this core, if any.
    pub request: Option<RequestProgress>,
    /// When the probe last ran, epoch milliseconds.
    pub checked_at: u64,
}

/// Which OS the report describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Linux,
    Other,
}

impl Platform {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Macos => "macos",
            Platform::Linux => "linux",
            Platform::Other => "other",
        }
    }
}

/// One capability class as this core sees it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Works now, through the process itself or a helper.
    Available { via: Via },
    /// The platform supports it; something must be approved first.
    NeedsApproval { reason: String, how: How },
    /// No way to get it on this core.
    Unsupported { reason: String },
}

impl Capability {
    /// The wire `state` string.
    #[must_use]
    pub fn state_str(&self) -> &'static str {
        match self {
            Capability::Available { .. } => "available",
            Capability::NeedsApproval { .. } => "needs_approval",
            Capability::Unsupported { .. } => "unsupported",
        }
    }

    /// The descriptive reason, when the capability is not available.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Capability::Available { .. } => None,
            Capability::NeedsApproval { reason, .. } | Capability::Unsupported { reason } => {
                Some(reason)
            }
        }
    }

    /// The remedy, when one is offered.
    #[must_use]
    pub fn how(&self) -> Option<&How> {
        match self {
            Capability::NeedsApproval { how, .. } => Some(how),
            _ => None,
        }
    }
}

/// Who performs an available capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Process,
    Helper,
}

impl Via {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Process => "process",
            Via::Helper => "helper",
        }
    }
}

/// What will happen when the operator acts, and the one action to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct How {
    pub kind: HowKind,
    pub label: String,
    pub action: Action,
}

/// What a frontend should expect from the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HowKind {
    /// The Aitmproxy app does it.
    AppAction,
    /// The request is already with the app; macOS is waiting on the operator.
    OsDialog,
    /// Install something first.
    Package,
    /// A polkit password prompt.
    Pkexec,
}

impl HowKind {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HowKind::AppAction => "app_action",
            HowKind::OsDialog => "os_dialog",
            HowKind::Package => "package",
            HowKind::Pkexec => "pkexec",
        }
    }
}

/// The one thing a frontend may do about a `needs_approval`. Never a shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Call `l4.privilege.request` on this core.
    BusVerb,
    /// Open this URL.
    OpenUrl(String),
}

/// The privileged component as this core sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Helper {
    pub kind: HelperKind,
    pub status: HelperStatus,
    pub version: Option<String>,
    pub detail: Option<String>,
}

/// Which privileged component this platform uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperKind {
    MacosBpfPermissions,
    LinuxPkexecHelper,
    LinuxCapHelper,
    None,
}

impl HelperKind {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HelperKind::MacosBpfPermissions => "macos_bpf_permissions",
            HelperKind::LinuxPkexecHelper => "linux_pkexec_helper",
            HelperKind::LinuxCapHelper => "linux_cap_helper",
            HelperKind::None => "none",
        }
    }
}

/// Where the privileged component stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperStatus {
    NotInstalled,
    Installed,
    Applied,
    Running,
    VersionMismatch,
    Unknown,
}

impl HelperStatus {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HelperStatus::NotInstalled => "not_installed",
            HelperStatus::Installed => "installed",
            HelperStatus::Applied => "applied",
            HelperStatus::Running => "running",
            HelperStatus::VersionMismatch => "version_mismatch",
            HelperStatus::Unknown => "unknown",
        }
    }
}

/// Progress of the last `l4.privilege.request` on this core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestProgress {
    pub state: RequestState,
    /// Epoch milliseconds.
    pub at: u64,
    pub message: String,
}

/// Where a request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    Pending,
    HandedToApp,
    Approved,
    Dismissed,
    Failed,
}

impl RequestState {
    /// The wire string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RequestState::Pending => "pending",
            RequestState::HandedToApp => "handed_to_app",
            RequestState::Approved => "approved",
            RequestState::Dismissed => "dismissed",
            RequestState::Failed => "failed",
        }
    }
}

impl PrivilegeReport {
    /// Render the exact spec §2.2 shape: `enabled`, `platform`, `capabilities`
    /// (`capture`, `inject`, `intercept`), `helper`, `request` (null or object)
    /// and `checked_at` (integer epoch ms).
    #[must_use]
    pub fn to_value(&self) -> Value {
        object([
            ("enabled", Value::Bool(self.enabled)),
            ("platform", Value::Str(self.platform.as_str().to_string())),
            (
                "capabilities",
                object([
                    ("capture", self.capture.to_value()),
                    ("inject", self.inject.to_value()),
                    ("intercept", self.intercept.to_value()),
                ]),
            ),
            ("helper", self.helper.to_value()),
            (
                "request",
                self.request
                    .as_ref()
                    .map_or(Value::Null, RequestProgress::to_value),
            ),
            ("checked_at", epoch_ms(self.checked_at)),
        ])
    }
}

impl Capability {
    /// One of the three `Capability` shapes of spec §2.2.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let state = ("state", Value::Str(self.state_str().to_string()));
        match self {
            Capability::Available { via } => {
                object([state, ("via", Value::Str(via.as_str().to_string()))])
            }
            Capability::NeedsApproval { reason, how } => object([
                state,
                ("reason", Value::Str(reason.clone())),
                ("how", how.to_value()),
            ]),
            Capability::Unsupported { reason } => {
                object([state, ("reason", Value::Str(reason.clone()))])
            }
        }
    }
}

impl How {
    /// `{"kind", "label", "action"}`.
    #[must_use]
    pub fn to_value(&self) -> Value {
        object([
            ("kind", Value::Str(self.kind.as_str().to_string())),
            ("label", Value::Str(self.label.clone())),
            ("action", self.action.to_value()),
        ])
    }
}

impl Action {
    /// `{"type":"bus_verb","verb":"l4.privilege.request"}` or
    /// `{"type":"open_url","url":…}`.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Action::BusVerb => object([
                ("type", Value::Str("bus_verb".to_string())),
                ("verb", Value::Str(REQUEST_VERB.to_string())),
            ]),
            Action::OpenUrl(url) => object([
                ("type", Value::Str("open_url".to_string())),
                ("url", Value::Str(url.clone())),
            ]),
        }
    }
}

impl Helper {
    /// `{"kind", "status", "version", "detail"}`; the two optionals render as null.
    #[must_use]
    pub fn to_value(&self) -> Value {
        object([
            ("kind", Value::Str(self.kind.as_str().to_string())),
            ("status", Value::Str(self.status.as_str().to_string())),
            ("version", optional_str(self.version.as_deref())),
            ("detail", optional_str(self.detail.as_deref())),
        ])
    }
}

impl RequestProgress {
    /// `{"state", "at", "message"}`.
    #[must_use]
    pub fn to_value(&self) -> Value {
        object([
            ("state", Value::Str(self.state.as_str().to_string())),
            ("at", epoch_ms(self.at)),
            ("message", Value::Str(self.message.clone())),
        ])
    }
}

/// `Object` from `(key, value)` pairs; keeps the renderers above short.
fn object<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    let mut map = BTreeMap::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    Value::Object(map)
}

fn optional_str(text: Option<&str>) -> Value {
    text.map_or(Value::Null, |text| Value::Str(text.to_string()))
}

/// Epoch milliseconds as the bus integer. A `u64` past `i64::MAX` is some 292
/// million years away; saturate rather than wrap if it ever shows up.
fn epoch_ms(ms: u64) -> Value {
    Value::Int(i64::try_from(ms).unwrap_or(i64::MAX))
}
