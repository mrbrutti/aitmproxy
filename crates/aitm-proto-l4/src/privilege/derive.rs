//! The decision tables of spec §2.2: pure, no I/O. Platform gatherers build a
//! [`ProbeInputs`]; `derive` turns it into a [`PrivilegeReport`], first match wins.

use std::path::PathBuf;

use crate::helper::proto::PROTO;
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
    /// Present when `platform` is Linux.
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

/// What the Linux gatherer found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxInputs {
    /// The process's `CapEff` holds `CAP_NET_RAW`.
    pub cap_net_raw: bool,
    /// The process's `CapEff` holds `CAP_NET_ADMIN`.
    pub cap_net_admin: bool,
    /// A helper session is connected and past its peer checks.
    pub session_connected: bool,
    /// The helper binary discovery found (spec §2.2 order), when it found one.
    pub helper: Option<HelperCandidate>,
    /// The polkit policy file is installed.
    pub policy_file_present: bool,
    /// The polkit launcher is on this host.
    pub pkexec_present: bool,
    /// A password prompt could be shown (spec §5.5): a graphical session or a tty.
    pub prompt_possible: bool,
    /// How the last helper session failed its handshake, if it did (spec
    /// §5.2): set by the session owner when `Hello` was answered with another
    /// protocol version or with garbage, cleared when a session attaches.
    pub last_session_error: Option<SessionFailure>,
}

/// Why the last helper session never got past `Hello` (spec §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionFailure {
    /// The helper announced this protocol version; ours is
    /// [`PROTO`](crate::helper::proto::PROTO).
    VersionMismatch(u32),
    /// The handshake was malformed (unknown type, oversized length, bad
    /// JSON, an unexpected message); carries the bounded defect text.
    Protocol(String),
}

impl SessionFailure {
    /// The `helper.detail` text for the `version_mismatch` row: both protocol
    /// numbers when the helper named one, else ours and the defect.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            SessionFailure::VersionMismatch(theirs) => {
                format!("helper speaks protocol {theirs}, this core speaks {PROTO}")
            }
            SessionFailure::Protocol(defect) => {
                format!("helper did not speak protocol {PROTO} ({defect})")
            }
        }
    }
}

/// One helper binary found by discovery, as the gatherer inspected it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperCandidate {
    /// Where it was found.
    pub path: PathBuf,
    /// It is the policy's exec path ([`crate::privilege::contract::LINUX_HELPER_PATH`]).
    pub at_policy_path: bool,
    /// It and every parent are root-owned and not group- or world-writable.
    pub root_owned_chain: bool,
    /// `aitm-l4-helper probe` reports `CAP_NET_RAW` effective (file caps).
    pub file_caps_net_raw: bool,
}

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
    /// `intercept` on Linux without `CAP_NET_ADMIN`.
    pub const LINUX_INTERCEPT: &str = "in-path interception needs the core itself to hold \
                                       CAP_NET_ADMIN; the packet-capture helper does not provide \
                                       it yet";
    /// Row "helper at the policy's exec path, a prompt is possible".
    pub const LINUX_ALLOW_LABEL: &str = "Allow packet capture (asks for an administrator password)";
    /// Row "helper at the policy's exec path, but no prompt is possible".
    pub const LINUX_NO_PROMPT: &str =
        "No password prompt can be shown here (no desktop session or terminal)";
    /// Rows "helper found but not root-owned" and "otherwise".
    pub const LINUX_INSTALL_LABEL: &str =
        "Install the aitm .deb or .rpm to get the packet-capture helper";
    /// Capture and inject on a platform with no backend, or on macOS or Linux
    /// when the platform gatherer supplied no inputs.
    pub const NO_BACKEND: &str = "raw packet capture and injection are supported on macOS and \
                                 Linux only";
}

/// The whole decision table. Pure; first match wins.
#[must_use]
pub fn derive(inputs: &ProbeInputs) -> PrivilegeReport {
    let (capture, intercept, helper) = match (inputs.platform, &inputs.mac, &inputs.linux) {
        (Platform::Macos, Some(mac), _) => {
            derive_macos(inputs.enabled, mac, inputs.request.as_ref())
        }
        (Platform::Linux, _, Some(linux)) => derive_linux(inputs.enabled, linux),
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

/// The Linux table of spec §2.2: `(capture-and-inject, intercept, helper)`.
fn derive_linux(enabled: bool, linux: &LinuxInputs) -> (Capability, Capability, Helper) {
    let candidate = linux.helper.as_ref();
    let file_caps = candidate.is_some_and(|helper| helper.file_caps_net_raw);
    // The packaged install, complete: the only thing the request ever runs
    // through polkit is the policy's exec path, so every part must be in place
    // and the path must be one root alone can write.
    let packaged = candidate.is_some_and(|helper| helper.at_policy_path && helper.root_owned_chain)
        && linux.policy_file_present
        && linux.pkexec_present;
    let untrusted_path = candidate.filter(|helper| !helper.root_owned_chain);

    // helper "as found": the same reading whether or not L4 is enabled.
    let kind = if file_caps {
        HelperKind::LinuxCapHelper
    } else {
        HelperKind::LinuxPkexecHelper
    };
    let (status, detail) = if linux.session_connected {
        (HelperStatus::Running, None)
    } else if let Some(failure) = &linux.last_session_error {
        // Spec §5.2: the last session closed at `Hello` (another protocol
        // version, or garbage). After the connected-session row, before the
        // file-caps row: a helper that is back and attached reads `running`
        // again, and a mismatching file-caps helper is still named as such.
        (HelperStatus::VersionMismatch, Some(failure.detail()))
    } else if file_caps || packaged {
        (HelperStatus::Installed, None)
    } else if let Some(helper) = untrusted_path {
        (
            HelperStatus::NotInstalled,
            Some(helper.path.display().to_string()),
        )
    } else {
        (HelperStatus::NotInstalled, None)
    };
    let found = Helper {
        kind,
        status,
        version: None,
        detail,
    };
    let no_helper = Helper {
        kind: HelperKind::None,
        status: HelperStatus::Unknown,
        version: None,
        detail: None,
    };

    if !enabled {
        let off = unsupported(text::L4_OFF);
        return (off.clone(), off, found);
    }

    let intercept = if linux.cap_net_admin {
        Capability::Available { via: Via::Process }
    } else {
        unsupported(text::LINUX_INTERCEPT)
    };

    let (capture, helper) = if linux.cap_net_raw {
        (Capability::Available { via: Via::Process }, no_helper)
    } else if linux.session_connected || file_caps {
        (Capability::Available { via: Via::Helper }, found)
    } else if packaged && linux.prompt_possible {
        (
            needs_approval(
                text::LINUX_ALLOW_LABEL,
                HowKind::Pkexec,
                text::LINUX_ALLOW_LABEL,
                Action::BusVerb,
            ),
            found,
        )
    } else if packaged {
        (
            needs_approval(
                text::LINUX_NO_PROMPT,
                HowKind::Package,
                text::LINUX_NO_PROMPT,
                Action::BusVerb,
            ),
            found,
        )
    } else {
        // A helper under $HOME or any other path root does not own, or none at
        // all: the package is the remedy either way; `found.detail` names the
        // untrusted path when there is one.
        (
            needs_approval(
                text::LINUX_INSTALL_LABEL,
                HowKind::Package,
                text::LINUX_INSTALL_LABEL,
                Action::OpenUrl(DOWNLOAD_URL.to_string()),
            ),
            found,
        )
    };

    (capture, intercept, helper)
}

/// A platform with no raw-packet backend, or macOS/Linux without their
/// gatherer's inputs: everything unsupported, no helper.
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
    use crate::privilege::contract::{LINUX_HELPER_PATH, RECEIPT_SCHEMA};
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

    // ---- Linux (Task P1b.2) ----

    const HOME_HELPER: &str = "/home/tester/aitmproxy/aitm-l4-helper";

    /// A Linux probe with nothing found: no caps, no session, no helper.
    fn linux_nothing() -> LinuxInputs {
        LinuxInputs {
            cap_net_raw: false,
            cap_net_admin: false,
            session_connected: false,
            helper: None,
            policy_file_present: false,
            pkexec_present: false,
            prompt_possible: false,
            last_session_error: None,
        }
    }

    /// The packaged helper, as the .deb/.rpm installs it, with a prompt possible.
    fn linux_packaged() -> LinuxInputs {
        LinuxInputs {
            helper: Some(candidate(LINUX_HELPER_PATH, true, true, false)),
            policy_file_present: true,
            pkexec_present: true,
            prompt_possible: true,
            ..linux_nothing()
        }
    }

    fn candidate(
        path: &str,
        at_policy_path: bool,
        root_owned_chain: bool,
        file_caps_net_raw: bool,
    ) -> HelperCandidate {
        HelperCandidate {
            path: PathBuf::from(path),
            at_policy_path,
            root_owned_chain,
            file_caps_net_raw,
        }
    }

    fn linux_inputs(enabled: bool, linux: LinuxInputs) -> ProbeInputs {
        ProbeInputs {
            enabled,
            platform: Platform::Linux,
            mac: None,
            linux: Some(linux),
            request: None,
            now_ms: NOW,
        }
    }

    const LINUX_INTERCEPT_OFF: &str = "in-path interception needs the core itself to hold \
                                       CAP_NET_ADMIN; the packet-capture helper does not provide \
                                       it yet";

    /// Every Linux row: inject mirrors capture, no version is known yet, and the
    /// probe time is carried through.
    fn assert_linux_common(report: &PrivilegeReport) {
        assert_eq!(report.platform, Platform::Linux);
        assert_eq!(report.inject, report.capture);
        assert_eq!(report.helper.version, None);
        assert_eq!(report.checked_at, NOW);
    }

    fn needs(report: &PrivilegeReport) -> (&str, &How) {
        match &report.capture {
            Capability::NeedsApproval { reason, how } => (reason.as_str(), how),
            other => panic!("expected needs_approval, got {other:?}"),
        }
    }

    #[test]
    fn linux_l4_off_is_unsupported() {
        let off = unsupported("L4 is off in this core's config (l4.enabled)");
        // Even a fully privileged process: l4.enabled false wins (first row).
        let report = derive(&linux_inputs(
            false,
            LinuxInputs {
                cap_net_raw: true,
                cap_net_admin: true,
                ..linux_packaged()
            },
        ));
        assert!(!report.enabled);
        assert_linux_common(&report);
        assert_eq!(report.capture, off);
        assert_eq!(report.inject, off);
        assert_eq!(report.intercept, off);
        // helper "as found": the packaged helper is installed.
        assert_eq!(report.helper.kind, HelperKind::LinuxPkexecHelper);
        assert_eq!(report.helper.status, HelperStatus::Installed);

        // ... and nothing found is not installed.
        let report = derive(&linux_inputs(false, linux_nothing()));
        assert_eq!(report.capture, off);
        assert_eq!(report.helper.status, HelperStatus::NotInstalled);
    }

    #[test]
    fn process_cap_net_raw_is_available_process() {
        // A helper is installed too, but the process needs none: kind `none`.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                cap_net_raw: true,
                ..linux_packaged()
            },
        ));
        assert!(report.enabled);
        assert_linux_common(&report);
        assert_eq!(report.capture, Capability::Available { via: Via::Process });
        assert_eq!(report.helper.kind, HelperKind::None);
        assert_eq!(report.helper.status, HelperStatus::Unknown);
        assert_eq!(report.helper.detail, None);
    }

    #[test]
    fn connected_session_is_available_helper() {
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                session_connected: true,
                ..linux_packaged()
            },
        ));
        assert_linux_common(&report);
        assert_eq!(report.capture, Capability::Available { via: Via::Helper });
        assert_eq!(report.helper.kind, HelperKind::LinuxPkexecHelper);
        assert_eq!(report.helper.status, HelperStatus::Running);

        // A session over a file-caps helper reports that kind.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                session_connected: true,
                helper: Some(candidate(LINUX_HELPER_PATH, true, true, true)),
                ..linux_nothing()
            },
        ));
        assert_eq!(report.capture, Capability::Available { via: Via::Helper });
        assert_eq!(report.helper.kind, HelperKind::LinuxCapHelper);
        assert_eq!(report.helper.status, HelperStatus::Running);
    }

    #[test]
    fn file_caps_helper_is_available_helper_cap_kind() {
        // No session yet: it starts lazily on first use, so already `available`.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                helper: Some(candidate(
                    "/run/wrappers/bin/aitm-l4-helper",
                    false,
                    true,
                    true,
                )),
                ..linux_nothing()
            },
        ));
        assert_linux_common(&report);
        assert_eq!(report.capture, Capability::Available { via: Via::Helper });
        assert_eq!(report.helper.kind, HelperKind::LinuxCapHelper);
        assert_eq!(report.helper.status, HelperStatus::Installed);
        assert_eq!(report.helper.detail, None);

        // The row does not ask about the policy path: a configured helper path
        // with file caps (the headless fallback, spec §5.6) is enough.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                helper: Some(candidate("/opt/aitm/aitm-l4-helper", false, true, true)),
                ..linux_nothing()
            },
        ));
        assert_eq!(report.capture, Capability::Available { via: Via::Helper });
        assert_eq!(report.helper.kind, HelperKind::LinuxCapHelper);
    }

    #[test]
    fn policy_helper_with_prompt_is_pkexec() {
        let report = derive(&linux_inputs(true, linux_packaged()));
        assert_linux_common(&report);
        let (reason, how) = needs(&report);
        assert_eq!(how.kind, HowKind::Pkexec);
        assert_eq!(
            how.label,
            "Allow packet capture (asks for an administrator password)"
        );
        assert_eq!(
            reason,
            "Allow packet capture (asks for an administrator password)"
        );
        assert_eq!(how.action, Action::BusVerb);
        assert_eq!(report.helper.kind, HelperKind::LinuxPkexecHelper);
        assert_eq!(report.helper.status, HelperStatus::Installed);
        assert_eq!(report.helper.detail, None);

        // The wire string for this kind is the enum value, not a reason.
        let Value::Object(top) = report.to_value() else {
            panic!("to_value must be an object");
        };
        let Some(Value::Object(caps)) = top.get("capabilities") else {
            panic!("capabilities must be an object");
        };
        let Some(Value::Object(capture)) = caps.get("capture") else {
            panic!("capture must be an object");
        };
        let Some(Value::Object(how)) = capture.get("how") else {
            panic!("how must be an object");
        };
        assert_eq!(how.get("kind"), Some(&Value::Str("pkexec".to_string())));
        assert_eq!(top.get("platform"), Some(&Value::Str("linux".to_string())));
        let Some(Value::Object(helper)) = top.get("helper") else {
            panic!("helper must be an object");
        };
        assert_eq!(
            helper.get("kind"),
            Some(&Value::Str("linux_pkexec_helper".to_string()))
        );
    }

    #[test]
    fn policy_helper_without_prompt_is_package() {
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                prompt_possible: false,
                ..linux_packaged()
            },
        ));
        assert_linux_common(&report);
        let (reason, how) = needs(&report);
        assert_eq!(how.kind, HowKind::Package);
        assert_eq!(
            reason,
            "No password prompt can be shown here (no desktop session or terminal)"
        );
        assert_eq!(how.label, reason);
        assert_eq!(how.action, Action::BusVerb);
        assert_eq!(report.helper.kind, HelperKind::LinuxPkexecHelper);
        assert_eq!(report.helper.status, HelperStatus::Installed);

        // "No prompt" is only the answer for a complete install. A helper at the
        // policy path whose policy file or pkexec is missing is a broken install
        // and falls through to the install row, whether or not a prompt is possible.
        for prompt_possible in [true, false] {
            let report = derive(&linux_inputs(
                true,
                LinuxInputs {
                    policy_file_present: false,
                    prompt_possible,
                    ..linux_packaged()
                },
            ));
            let (reason, how) = needs(&report);
            assert_eq!(how.kind, HowKind::Package);
            assert_eq!(
                reason,
                "Install the aitm .deb or .rpm to get the packet-capture helper"
            );
            assert_eq!(report.helper.status, HelperStatus::NotInstalled);
        }
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                pkexec_present: false,
                ..linux_packaged()
            },
        ));
        assert_eq!(
            report.capture.how().map(|how| how.kind),
            Some(HowKind::Package)
        );
        assert_eq!(report.helper.status, HelperStatus::NotInstalled);
    }

    #[test]
    fn helper_under_home_is_package_not_installed() {
        // AC20, unit half: the tarball layout under $HOME.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                helper: Some(candidate(HOME_HELPER, false, false, false)),
                ..linux_nothing()
            },
        ));
        assert_linux_common(&report);
        let (reason, how) = needs(&report);
        assert_eq!(how.kind, HowKind::Package);
        assert_eq!(
            how.label,
            "Install the aitm .deb or .rpm to get the packet-capture helper"
        );
        assert_eq!(reason, how.label);
        assert_eq!(how.action, Action::OpenUrl(DOWNLOAD_URL.to_string()));
        assert_eq!(report.helper.kind, HelperKind::LinuxPkexecHelper);
        assert_eq!(report.helper.status, HelperStatus::NotInstalled);
        assert_eq!(report.helper.detail.as_deref(), Some(HOME_HELPER));

        // The policy path itself with a writable parent is the same row: never
        // `installed`, and the detail names it, prompt or no prompt.
        for prompt_possible in [true, false] {
            let report = derive(&linux_inputs(
                true,
                LinuxInputs {
                    helper: Some(candidate(LINUX_HELPER_PATH, true, false, false)),
                    prompt_possible,
                    ..linux_packaged()
                },
            ));
            assert_eq!(
                report.capture.how().map(|how| how.kind),
                Some(HowKind::Package)
            );
            assert_eq!(report.helper.status, HelperStatus::NotInstalled);
            assert_eq!(report.helper.detail.as_deref(), Some(LINUX_HELPER_PATH));
        }
    }

    #[test]
    fn nothing_is_package_with_download_url() {
        let report = derive(&linux_inputs(true, linux_nothing()));
        assert_linux_common(&report);
        let (reason, how) = needs(&report);
        assert_eq!(how.kind, HowKind::Package);
        assert_eq!(
            how.label,
            "Install the aitm .deb or .rpm to get the packet-capture helper"
        );
        assert_eq!(reason, how.label);
        assert_eq!(how.action, Action::OpenUrl(DOWNLOAD_URL.to_string()));
        assert_eq!(report.helper.kind, HelperKind::LinuxPkexecHelper);
        assert_eq!(report.helper.status, HelperStatus::NotInstalled);
        assert_eq!(report.helper.detail, None);

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
        let Some(Value::Object(action)) = how.get("action") else {
            panic!("action must be an object");
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
    }

    #[test]
    fn linux_intercept_follows_cap_net_admin() {
        // CAP_NET_ADMIN alone: intercept works in-process while capture still
        // needs approval.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                cap_net_admin: true,
                ..linux_packaged()
            },
        ));
        assert_eq!(
            report.intercept,
            Capability::Available { via: Via::Process }
        );
        assert!(matches!(report.capture, Capability::NeedsApproval { .. }));

        // Without it: unsupported with the spec's literal and no remedy, even
        // when a helper session serves capture.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                session_connected: true,
                ..linux_packaged()
            },
        ));
        assert_eq!(report.intercept, unsupported(LINUX_INTERCEPT_OFF));
        assert_eq!(report.intercept.how(), None);
        assert_eq!(report.intercept.reason(), Some(LINUX_INTERCEPT_OFF));
        let Value::Object(top) = report.to_value() else {
            panic!("to_value must be an object");
        };
        let Some(Value::Object(caps)) = top.get("capabilities") else {
            panic!("capabilities must be an object");
        };
        let Some(Value::Object(intercept)) = caps.get("intercept") else {
            panic!("intercept must be an object");
        };
        assert_eq!(
            intercept.get("state"),
            Some(&Value::Str("unsupported".to_string()))
        );
        assert_eq!(intercept.get("how"), None);
    }

    #[test]
    fn other_platform_and_missing_inputs_stay_minimal() {
        let no_backend =
            unsupported("raw packet capture and injection are supported on macOS and Linux only");
        let report = derive(&ProbeInputs {
            enabled: true,
            platform: Platform::Other,
            mac: None,
            linux: None,
            request: None,
            now_ms: NOW,
        });
        assert_eq!(report.capture, no_backend);
        assert_eq!(report.inject, no_backend);
        assert_eq!(report.intercept, no_backend);
        assert_eq!(report.helper.kind, HelperKind::None);
        assert_eq!(report.helper.status, HelperStatus::Unknown);

        // Linux without its gatherer's inputs is treated the same way.
        let report = derive(&ProbeInputs {
            platform: Platform::Linux,
            ..inputs(true, mac(false, None, false), None)
        });
        let report_without_linux = derive(&ProbeInputs {
            mac: None,
            ..ProbeInputs {
                platform: Platform::Linux,
                ..inputs(true, mac(false, None, false), None)
            }
        });
        assert_eq!(report_without_linux.capture, no_backend);
        assert_eq!(report_without_linux.platform, Platform::Linux);
        // A Linux platform tagged with macOS inputs only is not a macOS report.
        assert_eq!(report.capture, no_backend);
    }

    // ---- Task P1b.3: no reply names a command (spec AC3, Rule 2) ----

    /// The commands the product must never tell an operator to run.
    const COMMANDS: [&str; 8] = [
        "sudo",
        "setcap",
        "chmod",
        "chgrp",
        "chown",
        "dseditgroup",
        "launchctl",
        "pkexec",
    ];

    /// Every row of both tables plus the other-platform row, as `derive` builds
    /// them.
    fn every_row() -> Vec<PrivilegeReport> {
        let mut rows = vec![
            // macOS
            derive(&inputs(false, mac(true, Some(receipt(vec![])), true), None)),
            derive(&inputs(false, mac(false, None, false), None)),
            derive(&inputs(true, mac(true, Some(receipt(vec![])), false), None)),
            derive(&inputs(true, mac(true, None, true), None)),
            derive(&inputs(
                true,
                mac(
                    false,
                    Some(receipt(vec!["could not add matt to access_bpf"])),
                    true,
                ),
                None,
            )),
            derive(&inputs(
                true,
                mac(false, Some(receipt(vec![])), false),
                None,
            )),
            derive(&inputs(true, mac(false, None, true), Some(handed_to_app()))),
            derive(&inputs(true, mac(false, None, true), None)),
            derive(&inputs(true, mac(false, None, false), None)),
            // Linux
            derive(&linux_inputs(
                false,
                LinuxInputs {
                    cap_net_raw: true,
                    cap_net_admin: true,
                    ..linux_packaged()
                },
            )),
            derive(&linux_inputs(false, linux_nothing())),
            derive(&linux_inputs(
                true,
                LinuxInputs {
                    cap_net_raw: true,
                    ..linux_packaged()
                },
            )),
            derive(&linux_inputs(
                true,
                LinuxInputs {
                    session_connected: true,
                    ..linux_packaged()
                },
            )),
            derive(&linux_inputs(
                true,
                LinuxInputs {
                    helper: Some(candidate(
                        "/run/wrappers/bin/aitm-l4-helper",
                        false,
                        true,
                        true,
                    )),
                    ..linux_nothing()
                },
            )),
            derive(&linux_inputs(true, linux_packaged())),
            derive(&linux_inputs(
                true,
                LinuxInputs {
                    cap_net_admin: true,
                    ..linux_packaged()
                },
            )),
            derive(&linux_inputs(
                true,
                LinuxInputs {
                    prompt_possible: false,
                    ..linux_packaged()
                },
            )),
            derive(&linux_inputs(
                true,
                LinuxInputs {
                    policy_file_present: false,
                    ..linux_packaged()
                },
            )),
            derive(&linux_inputs(
                true,
                LinuxInputs {
                    helper: Some(candidate(HOME_HELPER, false, false, false)),
                    ..linux_nothing()
                },
            )),
            derive(&linux_inputs(true, linux_nothing())),
        ];
        // Other platform, and macOS/Linux without their gatherer's inputs.
        for platform in [Platform::Other, Platform::Macos, Platform::Linux] {
            for enabled in [false, true] {
                rows.push(derive(&ProbeInputs {
                    enabled,
                    platform,
                    mac: None,
                    linux: None,
                    request: None,
                    now_ms: NOW,
                }));
            }
        }
        rows
    }

    /// Every `reason` and `label` of one report (`detail`, `message` and the
    /// enum wire strings are not operator text).
    fn reasons_and_labels(report: &PrivilegeReport) -> Vec<String> {
        let mut out = Vec::new();
        for capability in [&report.capture, &report.inject, &report.intercept] {
            if let Some(reason) = capability.reason() {
                out.push(reason.to_string());
            }
            if let Some(how) = capability.how() {
                out.push(how.label.clone());
            }
        }
        out
    }

    /// The string literals inside every `fn probe` body of `module.rs`. A body
    /// runs from `fn probe(` to the next `}` at column 0. A `\` before a
    /// newline joins a continued literal, dropping the next line's indentation,
    /// as rustc does; any other `\` keeps the escaped character.
    fn probe_literals(source: &str) -> Vec<String> {
        let mut literals = Vec::new();
        for (start, _) in source.match_indices("fn probe(") {
            let rest = &source[start..];
            let end = rest.find("\n}").map_or(rest.len(), |i| i + 2);
            let mut chars = rest[..end].chars().peekable();
            while let Some(c) = chars.next() {
                if c != '"' {
                    continue;
                }
                let mut literal = String::new();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some('\n') => {
                                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                                    chars.next();
                                }
                            }
                            Some(escaped) => literal.push(escaped),
                            None => break,
                        },
                        c => literal.push(c),
                    }
                }
                literals.push(literal);
            }
        }
        literals
    }

    fn is_word_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_'
    }

    /// The first command `text` names, as a whole word or as the start of a
    /// word, ASCII case-insensitively: `sudo`, `setcap` and `ChmodBPF` all trip;
    /// `CAP_NET_RAW` and `packet-capture` do not.
    fn names_a_command(text: &str) -> Option<&'static str> {
        text.split(|c: char| !is_word_char(c))
            .filter(|word| !word.is_empty())
            .find_map(|word| {
                let word = word.to_ascii_lowercase();
                COMMANDS
                    .iter()
                    .copied()
                    .find(|command| word.starts_with(command))
            })
    }

    #[test]
    fn no_reason_or_label_names_a_command() {
        // The matcher itself, both ways.
        assert_eq!(names_a_command("run `sudo aitm`"), Some("sudo"));
        assert_eq!(names_a_command("install ChmodBPF first"), Some("chmod"));
        assert_eq!(
            names_a_command("needs `setcap cap_net_raw+ep` on the binary"),
            Some("setcap")
        );
        assert_eq!(names_a_command("in-path interception is Linux only"), None);
        assert_eq!(
            names_a_command("a desktop-session launchctl_free CAP_NET_RAW"),
            Some("launchctl")
        );

        let rows = every_row();
        assert!(
            rows.len() >= 26,
            "every row must be built, got {}",
            rows.len()
        );
        let mut texts: Vec<String> = rows.iter().flat_map(reasons_and_labels).collect();
        assert!(texts.iter().any(|t| t.contains("Allow packet capture")));

        let probe = probe_literals(include_str!("../module.rs"));
        // The three platform probes each carry at least one literal, and the
        // scan joined the `\`-continued ones into single strings.
        assert!(probe.len() >= 5, "probe literals not found: {probe:?}");
        assert!(probe.iter().any(|l| l.starts_with("missing CAP_NET_RAW (")));
        assert!(probe
            .iter()
            .any(|l| l.starts_with("missing CAP_NET_ADMIN (")));
        assert!(probe
            .iter()
            .any(|l| l.starts_with("no read+write access to any /dev/bpf* device")));
        assert!(probe.iter().all(|l| !l.ends_with('\\')));
        texts.extend(probe);

        let offending: Vec<(String, &str)> = texts
            .into_iter()
            .filter_map(|t| names_a_command(&t).map(|c| (t, c)))
            .collect();
        assert!(
            offending.is_empty(),
            "operator text names a command (Rule 2, AC3): {offending:#?}"
        );
    }

    // ---- fix task 2026-11-01: I3 (spec §5.2 `version_mismatch`) ----

    /// A session that failed its handshake (another protocol, or garbage) is
    /// `helper.status: version_mismatch` with the detail naming the protocols,
    /// placed after the connected-session row and before the file-caps row:
    /// a connected session still reads `running`; the capture rows are
    /// untouched by it.
    #[test]
    fn linux_session_failure_is_version_mismatch_until_a_session_connects() {
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                last_session_error: Some(SessionFailure::VersionMismatch(2)),
                ..linux_packaged()
            },
        ));
        assert_linux_common(&report);
        assert_eq!(report.helper.status, HelperStatus::VersionMismatch);
        assert_eq!(report.helper.status.as_str(), "version_mismatch");
        assert_eq!(report.helper.kind, HelperKind::LinuxPkexecHelper);
        assert_eq!(
            report.helper.detail.as_deref(),
            Some("helper speaks protocol 2, this core speaks 1")
        );
        let (reason, how) = needs(&report);
        assert_eq!(
            reason,
            "Allow packet capture (asks for an administrator password)"
        );
        assert_eq!(how.kind, HowKind::Pkexec);

        // Garbage instead of a HelloAck: the defect is the detail.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                last_session_error: Some(SessionFailure::Protocol(
                    "unknown message type 0xff".to_string(),
                )),
                ..linux_packaged()
            },
        ));
        assert_eq!(report.helper.status, HelperStatus::VersionMismatch);
        assert_eq!(
            report.helper.detail.as_deref(),
            Some("helper did not speak protocol 1 (unknown message type 0xff)")
        );

        // The connected-session row comes first.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                session_connected: true,
                last_session_error: Some(SessionFailure::VersionMismatch(2)),
                ..linux_packaged()
            },
        ));
        assert_eq!(report.helper.status, HelperStatus::Running);
        assert_eq!(report.helper.detail, None);
        assert_eq!(report.capture, Capability::Available { via: Via::Helper });

        // The file-caps row comes after: its kind and capture stand, the
        // status says what the last session did.
        let report = derive(&linux_inputs(
            true,
            LinuxInputs {
                helper: Some(candidate(LINUX_HELPER_PATH, true, true, true)),
                last_session_error: Some(SessionFailure::VersionMismatch(3)),
                ..linux_packaged()
            },
        ));
        assert_eq!(report.helper.kind, HelperKind::LinuxCapHelper);
        assert_eq!(report.helper.status, HelperStatus::VersionMismatch);
        assert_eq!(report.capture, Capability::Available { via: Via::Helper });

        // L4 off: the row is still read "as found".
        let report = derive(&linux_inputs(
            false,
            LinuxInputs {
                last_session_error: Some(SessionFailure::VersionMismatch(2)),
                ..linux_packaged()
            },
        ));
        assert_eq!(report.helper.status, HelperStatus::VersionMismatch);
    }
}
