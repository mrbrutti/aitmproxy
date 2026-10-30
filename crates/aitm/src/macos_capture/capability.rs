//! Capture-capability state for the macOS embedded core, and the honest
//! degradation it enforces (NE-AC10, Rust capability-state-mapping side).
//!
//! The macOS app runs an embedded, user-level core that cannot capture traffic on
//! its own: capture flows through a Network/System Extension (D9). The app already
//! feature-detects the core it drives and shows a health state; Phase 2 adds this
//! **capture capability** beside it so the UI can tell the operator honestly where
//! the capture path stands, and every wire verb refuses — rather than panicking or
//! silently doing nothing — until the extension is approved and attached.
//!
//! This extends L4OPS-AC18: on the macOS embedded core the degradation reason
//! changes from "use a privileged remote core" to "approve the extension".

use aitm_proto_l4::guard::L4GuardError;

/// Where the macOS capture path is in its lifecycle (D9). The embedded core can
/// only run wire verbs once the extension is approved and its control channel is
/// attached; before that, this state names the honest reason capture is
/// unavailable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureCapability {
    /// The system extension has never been installed or activated.
    ExtensionNotInstalled,
    /// Activation was requested; the operator has not yet completed the two System
    /// Settings prompts.
    PendingApproval,
    /// The extension is approved and its control channel is attached. Wire verbs
    /// may proceed, though no flow is crossing yet.
    ApprovedAttached,
    /// The extension is approved, attached, and actively moving flows.
    Capturing,
    /// The extension is installed but something went wrong; the reason degrades
    /// honestly rather than silently.
    Degraded(String),
}

impl CaptureCapability {
    /// Whether the macOS embedded core may run wire verbs through the extension —
    /// true only once the extension is approved and attached (or capturing).
    pub fn is_attached(&self) -> bool {
        matches!(self, Self::ApprovedAttached | Self::Capturing)
    }

    /// Gate a macOS wire verb on the capture capability.
    ///
    /// Until the extension is approved and attached, every wire verb refuses with
    /// `L4Unavailable` whose reason names the extension as the path to enable
    /// capture (NE-AC10). Once attached, the verb proceeds (`Ok`). Real wire verbs
    /// on the macOS embedded core consult this before touching the capture path.
    pub fn gate_wire_verb(&self) -> Result<(), L4GuardError> {
        if self.is_attached() {
            return Ok(());
        }
        Err(L4GuardError::L4Unavailable(self.degradation_reason()))
    }

    /// The honest reason capture is unavailable in this state. Every variant names
    /// the Network/System Extension as the path; the not-yet-approved states point
    /// the operator at approving it.
    fn degradation_reason(&self) -> String {
        match self {
            Self::ExtensionNotInstalled => "macOS capture runs through the Network/System \
                 Extension, which is not installed; approve the extension to capture live"
                .to_string(),
            Self::PendingApproval => "macOS capture runs through the Network/System Extension, \
                 which is awaiting approval; approve the extension in System Settings to capture \
                 live"
                .to_string(),
            Self::Degraded(why) => format!(
                "macOS capture runs through the Network/System Extension, which is degraded: {why}"
            ),
            // Attached states never degrade; `gate_wire_verb` returns `Ok` first.
            Self::ApprovedAttached | Self::Capturing => unreachable!(
                "attached capability does not degrade; gate_wire_verb returns Ok before this"
            ),
        }
    }
}
