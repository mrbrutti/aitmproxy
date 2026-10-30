//! Task 20: `aitm-poc` YAML serde round-trip (AC-L1/AC13) and schema validation (AC-L7).

use aitm_poc::{validate, Poc, Severity, Step};

const EXAMPLE1: &str = include_str!("fixtures/reflected-xss-search-q.yaml");

/// AC-L1 / AC13: Example 1 deserializes into the `Poc` model and round-trips equal.
#[test]
fn example1_roundtrips() {
    let poc: Poc = serde_yaml::from_str(EXAMPLE1).expect("Example 1 deserializes into Poc");
    assert_eq!(poc.id, "reflected-xss-search-q");
    assert_eq!(poc.info.severity, Severity::High);

    // Schema validation accepts the normative example.
    let raw: serde_yaml::Value = serde_yaml::from_str(EXAMPLE1).expect("valid YAML");
    validate(&raw).expect("Example 1 passes schema validation");

    let reserialized = serde_yaml::to_string(&poc).expect("Poc re-serializes to YAML");
    let poc2: Poc = serde_yaml::from_str(&reserialized).expect("re-serialized YAML deserializes");
    assert_eq!(poc, poc2, "Poc must round-trip through YAML unchanged");
}

/// AC13: `info` extras (description/author/metadata) and unmodeled `http` keys
/// (matchers/matchers-condition/raw/path) survive a round-trip instead of being
/// silently dropped.
#[test]
fn preserves_unmodeled_fields() {
    let yaml = r#"
id: preserve-me
info:
  name: round-trip fidelity
  severity: medium
  description: a reflected parameter
  author: tester
  metadata:
    verified: true
    source: manual
steps:
  - http:
      method: GET
      url: "{{target}}/x"
      matchers-condition: and
      matchers:
        - type: status
          status: 200
      raw: "GET /x HTTP/1.1"
success:
  type: status
  status: 200
"#;
    let poc: Poc = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(
        poc.info.description.as_deref(),
        Some("a reflected parameter")
    );
    assert_eq!(poc.info.author.as_deref(), Some("tester"));
    assert!(poc.info.metadata.is_some(), "metadata must be retained");
    let aitm_poc::Step::Http(step) = &poc.steps[0] else {
        panic!("http step");
    };
    assert!(
        step.extra.contains_key("matchers"),
        "matchers kept in extra"
    );
    assert!(step.extra.contains_key("matchers-condition"));
    assert!(step.extra.contains_key("raw"));

    // Round-trips to an equal Poc (the extras are serialized back).
    let reserialized = serde_yaml::to_string(&poc).expect("serialize");
    let poc2: Poc = serde_yaml::from_str(&reserialized).expect("re-parse");
    assert_eq!(poc, poc2, "unmodeled fields must survive the round-trip");
    assert!(
        reserialized.contains("description")
            && reserialized.contains("author")
            && reserialized.contains("matchers"),
        "the serialized form keeps the extra keys:\n{reserialized}"
    );
}

/// AC-L7: a PoC missing the required `id` key is rejected with a message naming `id`.
#[test]
fn missing_id_rejected() {
    let yaml = r#"
info:
  name: no id here
  severity: low
steps:
  - http:
      method: GET
      url: "http://example.test/"
success:
  - type: status
    status: 200
"#;
    let raw: serde_yaml::Value = serde_yaml::from_str(yaml).expect("valid YAML");
    let err = validate(&raw).expect_err("missing id must be rejected");
    assert!(
        err.to_string().contains("id"),
        "error must mention the missing `id` field, got: {err}"
    );
}

/// AC-L7: a step whose key is not one of the four fixed types is a protocol
/// `<ns>:` step: it validates and parses into `Step::Protocol`, never silently
/// dropped. Runtime rejection of an *unregistered* namespace is covered by
/// `protocol_step.rs::unknown_protocol_step_errors_at_run`.
#[test]
fn unknown_namespace_parses_as_protocol_step() {
    let yaml = r#"
id: has-protocol-step
info:
  name: protocol step
  severity: low
steps:
  - telnet:
      host: example.test
success:
  - type: status
    status: 200
"#;
    let raw: serde_yaml::Value = serde_yaml::from_str(yaml).expect("valid YAML");
    validate(&raw).expect("a protocol-namespace step must validate");
    let poc = aitm_poc::loader::parse_poc(yaml).expect("protocol step parses");
    match &poc.steps[0] {
        Step::Protocol { ns, .. } => assert_eq!(ns, "telnet"),
        other => panic!("expected Step::Protocol, got {other:?}"),
    }
}

/// A malformed protocol-namespace step is still rejected at validation with a
/// clear, key-naming error: an unknown sibling beside the namespace key, or an
/// empty step map. A well-formed `<ns>:` plus the permitted `extract:` sibling
/// validates.
#[test]
fn malformed_protocol_step_rejected_with_clear_error() {
    let doc = |step: &str| {
        let yaml = format!(
            "id: p\ninfo:\n  name: n\n  severity: low\nsteps:\n  - {step}\nsuccess:\n  - dsl: 'true'\n"
        );
        serde_yaml::from_str::<serde_yaml::Value>(&yaml).expect("valid YAML")
    };

    let err = validate(&doc("{ telnet: { host: x }, bogus: 1 }"))
        .expect_err("an unknown sibling key must be rejected");
    assert!(
        err.to_string().contains("bogus") && err.to_string().contains("telnet"),
        "error must name the ns and the stray key, got: {err}"
    );

    let err = validate(&doc(
        "{ telnet: { host: x }, extract: [], other: 1, more: 2 }",
    ))
    .expect_err("more than ns + extract must be rejected");
    assert!(err.to_string().contains("other"), "got: {err}");

    validate(&doc("{ telnet: { host: x }, extract: [] }"))
        .expect("ns + extract sibling is the permitted protocol shape");

    validate(&doc("{}")).expect_err("an empty step map must be rejected");
}
