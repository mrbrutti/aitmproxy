//! Spec §2.4: the [`PrivilegeReport`] mapped onto the parity status vocabulary
//! ([`L4Availability`], [`UnavailableCode`]). Pure. The status verbs and the
//! gated verbs both read this, so they can never disagree.
//!
//! The table (plan P1b.4):
//!
//! | Capability | Platform | `L4Availability` |
//! |---|---|---|
//! | `Available` | any | `Available` |
//! | `NeedsApproval` | any | `Unavailable { NeedsPrivilege, gated_reason }` |
//! | `Unsupported`, intercept, L4 enabled | Linux | `NeedsPrivilege` (no `CAP_NET_ADMIN`) |
//! | any other `Unsupported` | any | `UnsupportedPlatform`, the capability's reason |
//!
//! An available intercept with no `l4.intercept` config is `NotConfigured`.
//! Privilege outranks configuration.

use crate::commands::intercept::INTERCEPT_NOT_CONFIGURED;
use crate::module::{L4Availability, UnavailableCode};
use crate::privilege::report::{Capability, Platform, PrivilegeReport};

/// The text the gated verbs refuse with (after `L4 unavailable: `), and the
/// status `reason`: `packet capture is not allowed yet (<how.label>)` for
/// `needs_approval`, the capability's own reason for `unsupported`, `None`
/// when available (plan p1b "Reason text").
#[must_use]
pub fn gated_reason(c: &Capability) -> Option<String> {
    match c {
        Capability::Available { .. } => None,
        Capability::NeedsApproval { how, .. } => {
            Some(format!("packet capture is not allowed yet ({})", how.label))
        }
        Capability::Unsupported { reason } => Some(reason.clone()),
    }
}

/// The capture/inject class. `Unsupported` is never a privilege problem here:
/// on macOS and Linux it is only ever the L4-off row (or a gatherer that
/// supplied nothing), elsewhere there is no backend.
#[must_use]
pub fn capture_availability(r: &PrivilegeReport) -> L4Availability {
    map(&r.capture, UnavailableCode::UnsupportedPlatform)
}

/// The in-path class. Linux intercept with L4 enabled is `Unsupported` only
/// when the core lacks `CAP_NET_ADMIN`, which is `NeedsPrivilege`; every other
/// `Unsupported` (macOS, other platforms, L4 off) is `UnsupportedPlatform`.
/// Only an available intercept reads the config flag.
#[must_use]
pub fn intercept_availability(r: &PrivilegeReport, configured: bool) -> L4Availability {
    let unsupported_code = if r.enabled && r.platform == Platform::Linux {
        UnavailableCode::NeedsPrivilege
    } else {
        UnavailableCode::UnsupportedPlatform
    };
    match map(&r.intercept, unsupported_code) {
        L4Availability::Available if !configured => L4Availability::Unavailable {
            code: UnavailableCode::NotConfigured,
            reason: INTERCEPT_NOT_CONFIGURED.to_string(),
        },
        availability => availability,
    }
}

/// The shared rows: `Available` and `NeedsApproval` read the same for every
/// class; `unsupported_code` is the class's reading of `Unsupported`.
fn map(c: &Capability, unsupported_code: UnavailableCode) -> L4Availability {
    match (c, gated_reason(c)) {
        (Capability::NeedsApproval { .. }, Some(reason)) => L4Availability::Unavailable {
            code: UnavailableCode::NeedsPrivilege,
            reason,
        },
        (Capability::Unsupported { .. }, Some(reason)) => L4Availability::Unavailable {
            code: unsupported_code,
            reason,
        },
        _ => L4Availability::Available,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privilege::derive::{derive, LinuxInputs, MacInputs, ProbeInputs};

    const NOW: u64 = 1_762_000_000_123;

    fn unavailable(code: UnavailableCode, reason: &str) -> L4Availability {
        L4Availability::Unavailable {
            code,
            reason: reason.to_string(),
        }
    }

    /// A macOS report with the given switches; no request, no receipt.
    fn mac_report(enabled: bool, bpf_rw_opens: bool, embeds_helper: bool) -> PrivilegeReport {
        derive(&ProbeInputs {
            enabled,
            platform: Platform::Macos,
            mac: Some(MacInputs {
                bpf_rw_opens,
                receipt: None,
                handoff_app_embeds_helper: embeds_helper,
            }),
            linux: None,
            request: None,
            now_ms: NOW,
        })
    }

    /// A Linux report from process capabilities alone: no helper, no session.
    fn linux_report(enabled: bool, cap_net_raw: bool, cap_net_admin: bool) -> PrivilegeReport {
        derive(&ProbeInputs {
            enabled,
            platform: Platform::Linux,
            mac: None,
            linux: Some(LinuxInputs {
                cap_net_raw,
                cap_net_admin,
                session_connected: false,
                helper: None,
                policy_file_present: false,
                pkexec_present: false,
                prompt_possible: false,
            }),
            request: None,
            now_ms: NOW,
        })
    }

    #[test]
    fn needs_approval_maps_to_needs_privilege() {
        // macOS row 5: the handoff app embeds the helper plist, no receipt.
        let report = mac_report(true, false, true);
        let expected = unavailable(
            UnavailableCode::NeedsPrivilege,
            "packet capture is not allowed yet (Allow packet capture in the Aitmproxy app)",
        );
        assert_eq!(capture_availability(&report), expected);
        assert_eq!(
            gated_reason(&report.capture).as_deref(),
            Some("packet capture is not allowed yet (Allow packet capture in the Aitmproxy app)")
        );
        // Inject is the same capability, so it reads the same.
        assert_eq!(gated_reason(&report.inject), gated_reason(&report.capture));
    }

    #[test]
    fn mac_intercept_is_unsupported_platform() {
        let report = mac_report(true, true, false);
        let expected = unavailable(
            UnavailableCode::UnsupportedPlatform,
            "in-path interception is Linux only",
        );
        // Privilege outranks configuration: configured or not, the answer is the same.
        assert_eq!(intercept_availability(&report, true), expected);
        assert_eq!(intercept_availability(&report, false), expected);
        assert_eq!(
            gated_reason(&report.intercept).as_deref(),
            Some("in-path interception is Linux only")
        );
    }

    #[test]
    fn linux_intercept_without_admin_is_needs_privilege() {
        let report = linux_report(true, true, false);
        let expected = unavailable(
            UnavailableCode::NeedsPrivilege,
            "in-path interception needs the core itself to hold CAP_NET_ADMIN; the \
             packet-capture helper does not provide it yet",
        );
        assert_eq!(intercept_availability(&report, true), expected);
        // Privilege outranks configuration.
        assert_eq!(intercept_availability(&report, false), expected);
        // Capture itself is fine on this core.
        assert_eq!(capture_availability(&report), L4Availability::Available);
    }

    #[test]
    fn privileged_unconfigured_intercept_is_not_configured() {
        let report = linux_report(true, true, true);
        assert_eq!(
            intercept_availability(&report, false),
            unavailable(
                UnavailableCode::NotConfigured,
                "in-path interception is disabled (no `intercept` config)",
            )
        );
        // The report itself says available; only the config is missing.
        assert_eq!(gated_reason(&report.intercept), None);
    }

    #[test]
    fn available_is_available() {
        let mac = mac_report(true, true, false);
        assert_eq!(capture_availability(&mac), L4Availability::Available);
        assert_eq!(gated_reason(&mac.capture), None);

        let linux = linux_report(true, true, true);
        assert_eq!(capture_availability(&linux), L4Availability::Available);
        assert_eq!(
            intercept_availability(&linux, true),
            L4Availability::Available
        );
    }

    /// Interpretation pin: with `l4.enabled: false` every capability is
    /// `unsupported` with the L4-off literal, and that is not a privilege
    /// problem on any platform, Linux intercept included.
    #[test]
    fn l4_off_is_unsupported_platform_everywhere() {
        let off = "L4 is off in this core's config (l4.enabled)";
        let expected = unavailable(UnavailableCode::UnsupportedPlatform, off);

        let linux = linux_report(false, true, true);
        assert_eq!(capture_availability(&linux), expected);
        assert_eq!(intercept_availability(&linux, true), expected);
        assert_eq!(intercept_availability(&linux, false), expected);

        let mac = mac_report(false, true, false);
        assert_eq!(capture_availability(&mac), expected);
        assert_eq!(
            intercept_availability(&mac, true),
            unavailable(
                UnavailableCode::UnsupportedPlatform,
                "in-path interception is Linux only",
            )
        );
    }

    #[test]
    fn other_platform_is_unsupported_platform() {
        let report = derive(&ProbeInputs {
            enabled: true,
            platform: Platform::Other,
            mac: None,
            linux: None,
            request: None,
            now_ms: NOW,
        });
        let expected = unavailable(
            UnavailableCode::UnsupportedPlatform,
            "raw packet capture and injection are supported on macOS and Linux only",
        );
        assert_eq!(capture_availability(&report), expected);
        assert_eq!(intercept_availability(&report, true), expected);
    }
}
