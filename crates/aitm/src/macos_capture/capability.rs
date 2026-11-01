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
    /// The core's feeder is off; carries the off reason (one of the
    /// `capture.status` verb's closed vocabulary: `macos_capture.enabled is
    /// false`, `not a macOS build`, `not started`, `stopped`).
    FeederOff(String),
    /// Feeder listening, no verified provider attached: the normal window
    /// before the extension is approved or while the app has capture off.
    AwaitingProvider,
}

impl CaptureCapability {
    /// The variant's wire name, as the `capture.status` verb emits it. Total over
    /// the seven variants.
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::ExtensionNotInstalled => "extension_not_installed",
            Self::PendingApproval => "pending_approval",
            Self::ApprovedAttached => "approved_attached",
            Self::Capturing => "capturing",
            Self::Degraded(_) => "degraded",
            Self::FeederOff(_) => "feeder_off",
            Self::AwaitingProvider => "awaiting_provider",
        }
    }

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
            Self::FeederOff(why) => format!(
                "macOS capture runs through the Network/System Extension, but this core's \
                 capture feeder is off ({why}); it runs only on a macOS build with \
                 `macos_capture.enabled: true` in the config file"
            ),
            Self::AwaitingProvider => "macOS capture runs through the Network/System Extension; \
                 the core is listening but no extension provider is attached — approve the \
                 extension in System Settings and turn capture on in the app to capture live"
                .to_string(),
            // Attached states never degrade; `gate_wire_verb` returns `Ok` first.
            Self::ApprovedAttached | Self::Capturing => unreachable!(
                "attached capability does not degrade; gate_wire_verb returns Ok before this"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use aitm_proto_l4::guard::L4GuardError;

    use super::CaptureCapability;

    /// **CS-AC12.** `wire_name()` is total: the seven variants map to the seven
    /// wire strings the `capture.status` verb emits.
    #[test]
    fn wire_name_is_total_over_seven_variants() {
        let table: [(CaptureCapability, &str); 7] = [
            (
                CaptureCapability::ExtensionNotInstalled,
                "extension_not_installed",
            ),
            (CaptureCapability::PendingApproval, "pending_approval"),
            (CaptureCapability::ApprovedAttached, "approved_attached"),
            (CaptureCapability::Capturing, "capturing"),
            (CaptureCapability::Degraded("x".into()), "degraded"),
            (CaptureCapability::FeederOff("x".into()), "feeder_off"),
            (CaptureCapability::AwaitingProvider, "awaiting_provider"),
        ];
        for (capability, wire) in table {
            assert_eq!(capability.wire_name(), wire, "{capability:?}");
        }
    }

    /// **CS-AC13.** A feeder that is off names the config on-switch and carries
    /// the off reason.
    #[test]
    fn feeder_off_gate_names_the_config_switch() {
        match CaptureCapability::FeederOff("not started".into()).gate_wire_verb() {
            Err(L4GuardError::L4Unavailable(r)) => {
                assert!(r.contains("macos_capture.enabled"), "got: {r:?}");
                assert!(r.contains("not started"), "got: {r:?}");
            }
            other => panic!("expected L4Unavailable, got {other:?}"),
        }
    }

    /// **CS-AC13.** A listening feeder with no provider points the operator at
    /// approving the extension.
    #[test]
    fn awaiting_provider_gate_names_approval() {
        match CaptureCapability::AwaitingProvider.gate_wire_verb() {
            Err(L4GuardError::L4Unavailable(r)) => {
                assert!(r.contains("approve the extension"), "got: {r:?}");
            }
            other => panic!("expected L4Unavailable, got {other:?}"),
        }
    }

    /// **CS-AC13.** Neither new variant counts as attached.
    #[test]
    fn new_variants_are_not_attached() {
        assert!(!CaptureCapability::FeederOff("x".into()).is_attached());
        assert!(!CaptureCapability::AwaitingProvider.is_attached());
    }
}
