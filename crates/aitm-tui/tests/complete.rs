//! Task 7 (TUI, UI-ext plan): the Rhai + PoC-YAML completion engine returns the
//! candidates the shared completion conformance fixtures pin
//! (`docs/design/languages/*.completion.conformance.json`), so the terminal
//! offers exactly the set the web and macOS surfaces do (spec AC3, AC4). The
//! fixtures also back the completion-popup component's candidate source.

use aitm_tui::ui::complete::{poc_yaml_candidates, rhai_candidates, Candidate, CompleteState};
use serde_json::Value;

fn fixtures(name: &str) -> Vec<Value> {
    let full = format!(
        "{}/../../docs/design/languages/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read {full}: {e}"));
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn labels(c: &[Candidate]) -> Vec<String> {
    c.iter().map(|x| x.label.clone()).collect()
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn expected(f: &Value) -> Vec<String> {
    f["expected_candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn rhai_completion_matches_the_conformance_fixture() {
    for f in fixtures("rhai.completion.conformance.json") {
        let ctx = f["context"].as_str().unwrap();
        let caret = f["caret"].as_u64().unwrap() as usize;
        let got = labels(&rhai_candidates(ctx, caret));
        assert_eq!(
            sorted(got.clone()),
            sorted(expected(&f)),
            "fixture {}: got {got:?}",
            f["name"]
        );
    }
}

#[test]
fn poc_yaml_completion_matches_the_conformance_fixture() {
    for f in fixtures("poc.completion.conformance.json") {
        let ctx = f["context"].as_str().unwrap();
        let caret = f["caret"].as_u64().unwrap() as usize;
        let got = labels(&poc_yaml_candidates(ctx, caret));
        assert_eq!(
            sorted(got.clone()),
            sorted(expected(&f)),
            "fixture {}: got {got:?}",
            f["name"]
        );
    }
}

#[test]
fn rhai_members_carry_a_signature_detail() {
    // the catalog's signature is surfaced as the popup hint
    let c = rhai_candidates("fn on_request(flow) {\n    flow.", 31);
    let id = c.iter().find(|x| x.label == "id").expect("flow.id offered");
    assert!(!id.detail.is_empty());
}

#[test]
fn popup_state_moves_and_clamps() {
    let items = vec![
        Candidate {
            label: "a".into(),
            detail: String::new(),
        },
        Candidate {
            label: "b".into(),
            detail: String::new(),
        },
        Candidate {
            label: "c".into(),
            detail: String::new(),
        },
    ];
    let mut s = CompleteState::new(items, 4, 10);
    assert_eq!(s.current().unwrap().label, "a");
    s.down();
    assert_eq!(s.current().unwrap().label, "b");
    s.down();
    s.down(); // clamps at the last item
    assert_eq!(s.current().unwrap().label, "c");
    s.up();
    s.up();
    s.up(); // clamps at the first
    assert_eq!(s.current().unwrap().label, "a");
}
