//! NE-AC10 (Rust / capability-state-mapping side): the macOS embedded core
//! degrades honestly. Until the Network/System Extension is approved and
//! attached, every macOS wire verb refuses with `L4Unavailable` whose reason
//! names the extension as the path to enable capture (extending L4OPS-AC18 from
//! "use a privileged remote core" to "approve the extension"); once attached, a
//! wire verb proceeds.

use aitm::macos_capture::capability::CaptureCapability;
use aitm_proto_l4::guard::L4GuardError;

#[test]
fn degraded_until_attached_names_extension() {
    // Before approval: a wire verb is refused with a reason that tells the
    // operator exactly how to enable capture — by approving the extension.
    let not_installed = CaptureCapability::ExtensionNotInstalled;
    match not_installed.gate_wire_verb() {
        Err(L4GuardError::L4Unavailable(reason)) => {
            assert!(
                reason.contains("approve the extension"),
                "degradation reason must name approving the extension as the path, got: {reason:?}"
            );
        }
        other => panic!("expected L4Unavailable before approval, got {other:?}"),
    }

    // Once approved and attached: the same wire verb proceeds — it must not
    // return L4Unavailable.
    let attached = CaptureCapability::ApprovedAttached;
    assert!(
        !matches!(
            attached.gate_wire_verb(),
            Err(L4GuardError::L4Unavailable(_))
        ),
        "an approved-attached capability must let the wire verb proceed, not degrade"
    );
}
