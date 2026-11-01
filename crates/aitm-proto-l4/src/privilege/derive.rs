//! The decision tables of spec §2.2: pure, no I/O. Platform gatherers build a
//! [`ProbeInputs`]; `derive` turns it into a [`PrivilegeReport`], first match wins.

use crate::privilege::contract::{Receipt, DOWNLOAD_URL};
use crate::privilege::report::{
    Action, Capability, Helper, HelperKind, HelperStatus, How, HowKind, Platform, PrivilegeReport,
    RequestProgress, RequestState, Via,
};

/// Everything `derive` looks at. Gathered by the platform files, never here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeInputs {
    /// `l4.enabled` in this core's config.
    pub enabled: bool,
    pub platform: Platform,
    /// Present when `platform` is macOS.
    pub mac: Option<MacInputs>,
    /// Present when `platform` is Linux (Task P1b.2 fills this in).
    pub linux: Option<LinuxInputs>,
    /// The last request on this core.
    pub request: Option<RequestProgress>,
    /// The probe time, epoch milliseconds; becomes `checked_at`.
    pub now_ms: u64,
}

/// What the macOS gatherer found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacInputs {
    /// A `/dev/bpf*` device opened read+write.
    pub bpf_rw_opens: bool,
    /// The helper's receipt, when one was readable.
    pub receipt: Option<Receipt>,
    /// The handoff app (spec §2.3) embeds the helper plist.
    pub handoff_app_embeds_helper: bool,
}

/// What the Linux gatherer found. Placeholder: Task P1b.2 defines the fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxInputs {}

/// The literal reasons and labels of spec §2.2. They are the only text a
/// frontend shows for these rows, so they live here as named constants.
pub mod text {
    /// Row "`l4.enabled` false", every platform.
    pub const L4_OFF: &str = "L4 is off in this core's config (l4.enabled)";
    /// `intercept` on macOS, every row.
    pub const MAC_INTERCEPT: &str = "in-path interception is Linux only";
    /// Row "receipt exists, open fails" when the receipt carries no error.
    pub const MAC_RECEIPT_NOT_USABLE: &str = "Packet capture is set up but this account cannot \
                                             use it yet; open the Aitmproxy app to finish";
    /// Row "no receipt, request handed to the app".
    pub const MAC_APPROVE_LABEL: &str =
        "Approve Aitmproxy in System Settings ▸ General ▸ Login Items & Extensions";
    /// Row "the handoff app embeds the helper plist".
    pub const MAC_ALLOW_LABEL: &str = "Allow packet capture in the Aitmproxy app";
    /// Row "otherwise".
    pub const MAC_INSTALL_LABEL: &str = "Install the Aitmproxy app (DMG or Homebrew cask); it \
                                        asks macOS for packet-capture permission";
    /// Capture and inject on a platform with no backend (Task P1b.2 adds the
    /// Linux rows; until then Linux shares this).
    pub const NO_BACKEND: &str = "raw packet capture and injection are supported on macOS and \
                                 Linux only";
}

/// The whole decision table. Pure; first match wins.
#[must_use]
pub fn derive(inputs: &ProbeInputs) -> PrivilegeReport {
    let (capture, intercept, helper) = match (inputs.platform, &inputs.mac) {
        (Platform::Macos, Some(mac)) => derive_macos(inputs.enabled, mac, inputs.request.as_ref()),
        _ => derive_other(inputs.enabled),
    };
    PrivilegeReport {
        enabled: inputs.enabled,
        platform: inputs.platform,
        inject: capture.clone(),
        capture,
        intercept,
        helper,
        request: inputs.request.clone(),
        checked_at: inputs.now_ms,
    }
}

/// The macOS table of spec §2.2: `(capture-and-inject, intercept, helper)`.
fn derive_macos(
    enabled: bool,
    mac: &MacInputs,
    request: Option<&RequestProgress>,
) -> (Capability, Capability, Helper) {
    let intercept = unsupported(text::MAC_INTERCEPT);
    let handed_to_app = request.is_some_and(|req| req.state == RequestState::HandedToApp);

    // helper.status "as found": the same reading whether or not L4 is enabled.
    let status = match &mac.receipt {
        Some(_) => HelperStatus::Applied,
        None if mac.bpf_rw_opens => HelperStatus::Unknown,
        None if handed_to_app || mac.handoff_app_embeds_helper => HelperStatus::Installed,
        None => HelperStatus::NotInstalled,
    };
    let helper = Helper {
        kind: HelperKind::MacosBpfPermissions,
        status,
        version: mac.receipt.as_ref().map(|r| r.helper_version.clone()),
        detail: None,
    };

    let capture = if !enabled {
        unsupported(text::L4_OFF)
    } else if mac.bpf_rw_opens {
        Capability::Available { via: Via::Process }
    } else if let Some(receipt) = &mac.receipt {
        let reason = receipt
            .errors
            .first()
            .cloned()
            .unwrap_or_else(|| text::MAC_RECEIPT_NOT_USABLE.to_string());
        needs_approval(
            reason,
            HowKind::AppAction,
            text::MAC_ALLOW_LABEL,
            Action::BusVerb,
        )
    } else if handed_to_app {
        needs_approval(
            text::MAC_APPROVE_LABEL,
            HowKind::OsDialog,
            text::MAC_APPROVE_LABEL,
            Action::BusVerb,
        )
    } else if mac.handoff_app_embeds_helper {
        needs_approval(
            text::MAC_ALLOW_LABEL,
            HowKind::AppAction,
            text::MAC_ALLOW_LABEL,
            Action::BusVerb,
        )
    } else {
        needs_approval(
            text::MAC_INSTALL_LABEL,
            HowKind::Package,
            text::MAC_INSTALL_LABEL,
            Action::OpenUrl(DOWNLOAD_URL.to_string()),
        )
    };

    (capture, intercept, helper)
}

/// A platform with no raw-packet backend (and, until Task P1b.2 lands its rows,
/// Linux): everything unsupported, no helper.
fn derive_other(enabled: bool) -> (Capability, Capability, Helper) {
    let reason = if enabled {
        text::NO_BACKEND
    } else {
        text::L4_OFF
    };
    let helper = Helper {
        kind: HelperKind::None,
        status: HelperStatus::Unknown,
        version: None,
        detail: None,
    };
    (unsupported(reason), unsupported(reason), helper)
}

fn unsupported(reason: &str) -> Capability {
    Capability::Unsupported {
        reason: reason.to_string(),
    }
}

fn needs_approval(
    reason: impl Into<String>,
    kind: HowKind,
    label: &str,
    action: Action,
) -> Capability {
    Capability::NeedsApproval {
        reason: reason.into(),
        how: How {
            kind,
            label: label.to_string(),
            action,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privilege::contract::RECEIPT_SCHEMA;
    use aitm_core::Value;

    const NOW: u64 = 1_762_000_000_123;

    fn receipt(errors: Vec<&str>) -> Receipt {
        Receipt {
            schema: RECEIPT_SCHEMA,
            helper_version: "0.5.9".to_string(),
            applied_at: 1_761_999_999_000,
            group: "access_bpf".to_string(),
            gid: 504,
            nodes: 256,
            members_added: vec!["matt".to_string()],
            errors: errors.into_iter().map(str::to_string).collect(),
        }
    }

    fn mac(
        bpf_rw_opens: bool,
        receipt: Option<Receipt>,
        handoff_app_embeds_helper: bool,
    ) -> MacInputs {
        MacInputs {
            bpf_rw_opens,
            receipt,
            handoff_app_embeds_helper,
        }
    }

    fn inputs(enabled: bool, mac: MacInputs, request: Option<RequestProgress>) -> ProbeInputs {
        ProbeInputs {
            enabled,
            platform: Platform::Macos,
            mac: Some(mac),
            linux: None,
            request,
            now_ms: NOW,
        }
    }

    fn handed_to_app() -> RequestProgress {
        RequestProgress {
            state: RequestState::HandedToApp,
            at: NOW - 5_000,
            message: "handed to the Aitmproxy app".to_string(),
        }
    }

    fn unsupported(reason: &str) -> Capability {
        Capability::Unsupported {
            reason: reason.to_string(),
        }
    }

    /// Every macOS row: intercept is unsupported with the spec's literal, and
    /// capture and inject are the same capability.
    fn assert_mac_common(report: &PrivilegeReport) {
        assert_eq!(report.platform, Platform::Macos);
        assert_eq!(
            report.intercept,
            unsupported("in-path interception is Linux only")
        );
        assert_eq!(report.inject, report.capture);
        assert_eq!(report.helper.kind, HelperKind::MacosBpfPermissions);
        assert_eq!(report.checked_at, NOW);
    }

    #[test]
    fn l4_off_is_unsupported() {
        let off = unsupported("L4 is off in this core's config (l4.enabled)");

        // Even with capture working, l4.enabled false wins (first row).
        let report = derive(&inputs(false, mac(true, Some(receipt(vec![])), true), None));
        assert!(!report.enabled);
        assert_mac_common(&report);
        assert_eq!(report.capture, off);
        assert_eq!(report.inject, off);
        // intercept keeps its own literal, but is Unsupported like the other two
        assert!(matches!(report.intercept, Capability::Unsupported { .. }));
        // helper is reported "as found": a receipt means applied ...
        assert_eq!(report.helper.status, HelperStatus::Applied);

        // ... and nothing found means not installed.
        let report = derive(&inputs(false, mac(false, None, false), None));
        assert_eq!(report.capture, off);
        assert_eq!(report.helper.status, HelperStatus::NotInstalled);
    }

    #[test]
    fn rw_open_is_available_process() {
        let report = derive(&inputs(true, mac(true, Some(receipt(vec![])), false), None));
        assert!(report.enabled);
        assert_mac_common(&report);
        assert_eq!(report.capture, Capability::Available { via: Via::Process });
        assert_eq!(report.helper.status, HelperStatus::Applied);
        assert_eq!(report.helper.version.as_deref(), Some("0.5.9"));

        // Someone else fixed it (e.g. Wireshark): no receipt, status unknown.
        let report = derive(&inputs(true, mac(true, None, true), None));
        assert_eq!(report.capture, Capability::Available { via: Via::Process });
        assert_eq!(report.helper.status, HelperStatus::Unknown);
        assert_eq!(report.helper.version, None);
    }

    #[test]
    fn receipt_but_no_open_is_app_action() {
        // The receipt's first error is the reason.
        let report = derive(&inputs(
            true,
            mac(
                false,
                Some(receipt(vec!["could not add matt to access_bpf", "second"])),
                true,
            ),
            None,
        ));
        assert_mac_common(&report);
        match &report.capture {
            Capability::NeedsApproval { reason, how } => {
                assert_eq!(reason, "could not add matt to access_bpf");
                assert_eq!(how.kind, HowKind::AppAction);
                assert_eq!(how.action, Action::BusVerb);
            }
            other => panic!("expected needs_approval, got {other:?}"),
        }
        assert_eq!(report.helper.status, HelperStatus::Applied);

        // No errors: the spec's literal.
        let report = derive(&inputs(
            true,
            mac(false, Some(receipt(vec![])), false),
            None,
        ));
        match &report.capture {
            Capability::NeedsApproval { reason, how } => {
                assert_eq!(
                    reason,
                    "Packet capture is set up but this account cannot use it yet; open the \
                     Aitmproxy app to finish"
                );
                assert_eq!(how.kind, HowKind::AppAction);
            }
            other => panic!("expected needs_approval, got {other:?}"),
        }
        assert_eq!(report.helper.status, HelperStatus::Applied);
    }

    #[test]
    fn handed_to_app_is_os_dialog() {
        let report = derive(&inputs(true, mac(false, None, true), Some(handed_to_app())));
        assert_mac_common(&report);
        match &report.capture {
            Capability::NeedsApproval { how, .. } => {
                assert_eq!(how.kind, HowKind::OsDialog);
                assert_eq!(
                    how.label,
                    "Approve Aitmproxy in System Settings ▸ General ▸ Login Items & Extensions"
                );
                assert_eq!(how.action, Action::BusVerb);
            }
            other => panic!("expected needs_approval, got {other:?}"),
        }
        assert_eq!(report.helper.status, HelperStatus::Installed);
        assert_eq!(report.request, Some(handed_to_app()));

        // A request in another state does not select this row.
        let pending = RequestProgress {
            state: RequestState::Pending,
            ..handed_to_app()
        };
        let report = derive(&inputs(true, mac(false, None, true), Some(pending)));
        assert_eq!(
            report.capture.how().map(|how| how.kind),
            Some(HowKind::AppAction)
        );
    }

    #[test]
    fn embedded_plist_is_app_action() {
        let report = derive(&inputs(true, mac(false, None, true), None));
        assert_mac_common(&report);
        match &report.capture {
            Capability::NeedsApproval { how, .. } => {
                assert_eq!(how.kind, HowKind::AppAction);
                assert_eq!(how.label, "Allow packet capture in the Aitmproxy app");
                assert_eq!(how.action, Action::BusVerb);
            }
            other => panic!("expected needs_approval, got {other:?}"),
        }
        assert_eq!(report.helper.status, HelperStatus::Installed);
    }

    #[test]
    fn otherwise_is_package_with_download_url() {
        let report = derive(&inputs(true, mac(false, None, false), None));
        assert_mac_common(&report);
        match &report.capture {
            Capability::NeedsApproval { how, .. } => {
                assert_eq!(how.kind, HowKind::Package);
                assert_eq!(
                    how.label,
                    "Install the Aitmproxy app (DMG or Homebrew cask); it asks macOS for \
                     packet-capture permission"
                );
                assert_eq!(how.action, Action::OpenUrl(DOWNLOAD_URL.to_string()));
            }
            other => panic!("expected needs_approval, got {other:?}"),
        }
        assert_eq!(report.helper.status, HelperStatus::NotInstalled);

        // to_value renders the spec's JSON shape.
        let value = report.to_value();
        let Value::Object(top) = &value else {
            panic!("to_value must be an object, got {value:?}");
        };
        assert_eq!(
            top.keys().cloned().collect::<Vec<_>>(),
            [
                "capabilities",
                "checked_at",
                "enabled",
                "helper",
                "platform",
                "request"
            ]
        );
        assert_eq!(top.get("enabled"), Some(&Value::Bool(true)));
        assert_eq!(top.get("platform"), Some(&Value::Str("macos".to_string())));
        assert_eq!(top.get("checked_at"), Some(&Value::Int(1_762_000_000_123)));
        assert_eq!(top.get("request"), Some(&Value::Null));

        let Some(Value::Object(caps)) = top.get("capabilities") else {
            panic!(
                "capabilities must be an object, got {:?}",
                top.get("capabilities")
            );
        };
        assert_eq!(
            caps.keys().cloned().collect::<Vec<_>>(),
            ["capture", "inject", "intercept"]
        );
        let Some(Value::Object(capture)) = caps.get("capture") else {
            panic!("capture must be an object, got {:?}", caps.get("capture"));
        };
        assert_eq!(
            capture.get("state"),
            Some(&Value::Str("needs_approval".to_string()))
        );
        let Some(Value::Object(how)) = capture.get("how") else {
            panic!("how must be an object, got {:?}", capture.get("how"));
        };
        assert_eq!(how.get("kind"), Some(&Value::Str("package".to_string())));
        let Some(Value::Object(action)) = how.get("action") else {
            panic!("action must be an object, got {:?}", how.get("action"));
        };
        assert_eq!(
            action.get("type"),
            Some(&Value::Str("open_url".to_string()))
        );
        assert_eq!(
            action.get("url"),
            Some(&Value::Str(
                "https://mrbrutti.github.io/aitmproxy/download.html".to_string()
            ))
        );
        let Some(Value::Object(intercept)) = caps.get("intercept") else {
            panic!(
                "intercept must be an object, got {:?}",
                caps.get("intercept")
            );
        };
        assert_eq!(
            intercept.get("state"),
            Some(&Value::Str("unsupported".to_string()))
        );
        assert_eq!(
            intercept.get("reason"),
            Some(&Value::Str(
                "in-path interception is Linux only".to_string()
            ))
        );

        let Some(Value::Object(helper)) = top.get("helper") else {
            panic!("helper must be an object, got {:?}", top.get("helper"));
        };
        assert_eq!(
            helper.get("kind"),
            Some(&Value::Str("macos_bpf_permissions".to_string()))
        );
        assert_eq!(
            helper.get("status"),
            Some(&Value::Str("not_installed".to_string()))
        );
        assert_eq!(helper.get("version"), Some(&Value::Null));
        assert_eq!(helper.get("detail"), Some(&Value::Null));
    }

    #[test]
    fn to_value_renders_available_bus_verb_and_request() {
        let report = derive(&inputs(
            true,
            mac(true, Some(receipt(vec![])), false),
            Some(handed_to_app()),
        ));
        let Value::Object(top) = report.to_value() else {
            panic!("to_value must be an object");
        };
        let Some(Value::Object(caps)) = top.get("capabilities") else {
            panic!("capabilities must be an object");
        };
        let Some(Value::Object(capture)) = caps.get("capture") else {
            panic!("capture must be an object");
        };
        assert_eq!(
            capture.get("state"),
            Some(&Value::Str("available".to_string()))
        );
        assert_eq!(capture.get("via"), Some(&Value::Str("process".to_string())));
        assert_eq!(capture.get("reason"), None);

        let Some(Value::Object(request)) = top.get("request") else {
            panic!("request must be an object, got {:?}", top.get("request"));
        };
        assert_eq!(
            request.get("state"),
            Some(&Value::Str("handed_to_app".to_string()))
        );
        assert_eq!(request.get("at"), Some(&Value::Int(1_761_999_995_123)));
        assert_eq!(
            request.get("message"),
            Some(&Value::Str("handed to the Aitmproxy app".to_string()))
        );

        let Some(Value::Object(helper)) = top.get("helper") else {
            panic!("helper must be an object");
        };
        assert_eq!(
            helper.get("status"),
            Some(&Value::Str("applied".to_string()))
        );
        assert_eq!(
            helper.get("version"),
            Some(&Value::Str("0.5.9".to_string()))
        );

        // The bus-verb action shape.
        let report = derive(&inputs(true, mac(false, None, true), None));
        let Value::Object(top) = report.to_value() else {
            panic!("to_value must be an object");
        };
        let Some(Value::Object(caps)) = top.get("capabilities") else {
            panic!("capabilities must be an object");
        };
        let Some(Value::Object(inject)) = caps.get("inject") else {
            panic!("inject must be an object");
        };
        let Some(Value::Object(how)) = inject.get("how") else {
            panic!("how must be an object");
        };
        assert_eq!(how.get("kind"), Some(&Value::Str("app_action".to_string())));
        let Some(Value::Object(action)) = how.get("action") else {
            panic!("action must be an object");
        };
        assert_eq!(
            action.get("type"),
            Some(&Value::Str("bus_verb".to_string()))
        );
        assert_eq!(
            action.get("verb"),
            Some(&Value::Str("l4.privilege.request".to_string()))
        );
        assert_eq!(action.get("url"), None);
    }
}
