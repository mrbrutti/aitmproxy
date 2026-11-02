//! Cross-crate pin of the scanner job push method name (scanner-v2 T1b, stage-6
//! fix item 1).
//!
//! `JOB_NOTIFICATION_METHOD` is declared in two crates — `aitm-scan-model`
//! (the result model every lane shares) and `aitm-mcp` (the server that renders
//! the push line). Both are the wire: an agent subscribes on the one name the
//! model documents and the server emits. This binary depends on both, so it is
//! the one place that can see them side by side and pin them to each other and
//! to the literal the spec and the MCP fixtures carry.

const WIRE_METHOD: &str = "notifications/aitm/job";

#[test]
fn job_notification_method_is_one_name_across_crates() {
    assert_eq!(
        aitm_mcp::JOB_NOTIFICATION_METHOD,
        aitm_scan_model::JOB_NOTIFICATION_METHOD,
        "aitm-mcp and aitm-scan-model must publish the same job push method"
    );
    assert_eq!(aitm_mcp::JOB_NOTIFICATION_METHOD, WIRE_METHOD);
    assert_eq!(aitm_scan_model::JOB_NOTIFICATION_METHOD, WIRE_METHOD);
}
