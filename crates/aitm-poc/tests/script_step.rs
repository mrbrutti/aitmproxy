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

/// Adding the `script` arm must not loosen the fallback: an unknown step type
/// is still rejected with `unknown step type`.
#[test]
fn unknown_step_still_errors() {
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
    let err = serde_yaml::from_str::<Poc>(yaml).expect_err("unknown step type must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown step type"),
        "error must say `unknown step type`, got: {msg}"
    );
    assert!(
        msg.contains("frobnicate"),
        "error must name the unknown step, got: {msg}"
    );
}
