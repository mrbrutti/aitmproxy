//! M3 Task 12: the additive `Step::Script(ScriptStep)` variant (AC-M3-11,
//! round-trip half). The executor seam and runner dispatch are Task 13.

use aitm_poc::model::ScriptStep;
use aitm_poc::{Poc, Step};

const SCRIPT_POC: &str = r#"
id: script-step-round-trip
info:
  name: one script step
  severity: low
steps:
  - script:
      name: s
      script: "return pass;"
success:
  - type: status
    status: 200
"#;

/// AC-M3-11: a one-step PoC whose step is `script:` deserializes to
/// `Step::Script(ScriptStep { script, name })` and re-serializes to equal YAML.
#[test]
fn script_step_round_trips() {
    let poc: Poc = serde_yaml::from_str(SCRIPT_POC).expect("script-step PoC deserializes");
    assert_eq!(poc.steps.len(), 1);
    assert_eq!(
        poc.steps[0],
        Step::Script(ScriptStep {
            script: "return pass;".to_string(),
            name: Some("s".to_string()),
        })
    );

    let reserialized = serde_yaml::to_string(&poc).expect("Poc re-serializes to YAML");
    let poc2: Poc = serde_yaml::from_str(&reserialized).expect("re-serialized YAML deserializes");
    assert_eq!(
        poc, poc2,
        "Poc with a script step must round-trip unchanged"
    );

    // The on-disk step shape is preserved exactly: `script:` with `name` + `script`.
    let original: serde_yaml::Value = serde_yaml::from_str(SCRIPT_POC).expect("valid YAML");
    let again: serde_yaml::Value = serde_yaml::from_str(&reserialized).expect("valid YAML");
    assert_eq!(
        original["steps"][0], again["steps"][0],
        "the script step's YAML must re-serialize equal:\n{reserialized}"
    );
}

/// A `script` step with no `name` deserializes with `name == None` and does not
/// emit a `name:` key when re-serialized.
#[test]
fn script_step_name_is_optional() {
    let yaml = r#"
id: script-step-unnamed
info:
  name: unnamed script step
  severity: low
steps:
  - script:
      script: "fail"
success:
  - type: status
    status: 200
"#;
    let poc: Poc = serde_yaml::from_str(yaml).expect("unnamed script step deserializes");
    assert_eq!(
        poc.steps[0],
        Step::Script(ScriptStep {
            script: "fail".to_string(),
            name: None,
        })
    );
    let reserialized = serde_yaml::to_string(&poc).expect("serialize");
    let again: serde_yaml::Value = serde_yaml::from_str(&reserialized).expect("valid YAML");
    assert!(
        again["steps"][0]["script"].get("name").is_none(),
        "an absent name must not be serialized:\n{reserialized}"
    );
}

/// The additive `Step::Protocol` seam makes any non-fixed step key a protocol
/// namespace, not a parse error (a registry-less deserializer cannot know which
/// namespaces are registered). So `frobnicate:` now parses into
/// `Step::Protocol { ns: "frobnicate", .. }`. This is never a silent skip: an
/// unregistered namespace is rejected with a clear error at *run* time (covered
/// by `protocol_step::unknown_protocol_step_errors_at_run`), which the seam
/// spec's "clear error at parse/run" contract allows.
#[test]
fn unknown_step_parses_as_protocol_namespace() {
    let yaml = r#"
id: unknown-step
info:
  name: unknown step
  severity: low
steps:
  - frobnicate: {}
success:
  - type: status
    status: 200
"#;
    let poc: Poc =
        serde_yaml::from_str(yaml).expect("a non-fixed step key parses as a protocol step");
    assert_eq!(poc.steps.len(), 1);
    let Step::Protocol { ns, .. } = &poc.steps[0] else {
        panic!(
            "an unknown step key must become Step::Protocol, got: {:?}",
            poc.steps[0]
        );
    };
    assert_eq!(ns, "frobnicate", "the protocol namespace is the step key");
}
