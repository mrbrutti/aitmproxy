//! Tester (stage 5), SP-AC19 edges: wrong-typed `system_proxy` values are
//! errors (never silently defaulted), an empty section is the off default
//! with the C6 state file beside the CA audit log, and bypass entries keep
//! their text and order.
//!
//! Spec: docs/superpowers/specs/2026-10-31-system-proxy-automation-design.md
//! Plan: docs/superpowers/plans/2026-10-31-system-proxy-automation-plan.md (Task 5)

use aitm::config_file::parse_settings;

#[test]
fn system_proxy_wrong_types_are_errors() {
    for yaml in [
        "system_proxy:\n  auto: maybe\n",
        "system_proxy:\n  auto: [true]\n",
        "system_proxy:\n  bypass: corp.test\n",
        "system_proxy:\n  bypass: {host: corp.test}\n",
        "system_proxy:\n  state_file: [a, b]\n",
        "system_proxy: 42\n",
        "system_proxy: [auto]\n",
        "system_proxy:\n  auto: true\n  Auto: true\n",
    ] {
        assert!(parse_settings(yaml).is_err(), "accepted: {yaml:?}");
    }
}

#[test]
fn empty_section_is_the_off_default_with_the_state_file_beside_the_audit_log() {
    for yaml in ["system_proxy: {}\n", "system_proxy:\n", "system_proxy: ~\n"] {
        let s = parse_settings(yaml).unwrap_or_else(|e| panic!("{yaml:?}: {e}"));
        assert!(!s.system_proxy.auto, "{yaml:?}");
        assert!(s.system_proxy.bypass.is_empty(), "{yaml:?}");
        let state_file = s
            .system_proxy
            .state_file
            .clone()
            .unwrap_or_else(|| panic!("{yaml:?}: C6 fills state_file"));
        assert_eq!(
            state_file,
            s.core
                .ca
                .audit_log
                .with_file_name("system-proxy-state.json"),
            "{yaml:?}"
        );
        assert_eq!(
            state_file.file_name().and_then(|n| n.to_str()),
            Some("system-proxy-state.json")
        );
        assert_eq!(state_file.parent(), s.core.ca.audit_log.parent());
    }
}

#[test]
fn bypass_entries_keep_their_text_and_order() {
    let s = parse_settings(
        "system_proxy:\n  bypass: [\"*.corp.test\", \"10.0.0.0/8\", \"localhost\", \"*.corp.test\"]\n",
    )
    .unwrap();
    assert_eq!(
        s.system_proxy.bypass,
        vec!["*.corp.test", "10.0.0.0/8", "localhost", "*.corp.test"],
        "no normalisation or de-duplication at parse time (that is the engine's §D5 merge)"
    );
    assert!(!s.system_proxy.auto);
}
