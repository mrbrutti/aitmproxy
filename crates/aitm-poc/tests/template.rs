//! Task 21: templating (AC-L4) — `{{var}}` resolution, caller override, and
//! runtime placeholders.

use aitm_core::Value;
use aitm_poc::template::{PocTemplate, Template, VarBindings};

/// AC-L4: a caller `--var` binding overrides the `variables` default.
#[test]
fn var_and_override() {
    let mut defaults = VarBindings::new();
    defaults.insert("param", Value::Str("q".into()));
    let tmpl = PocTemplate::new(defaults);

    // Absent binding → the default.
    assert_eq!(tmpl.render("{{param}}", &VarBindings::new()).unwrap(), "q");

    // Caller binding beats the default.
    let mut over = VarBindings::new();
    over.insert("param", Value::Str("qq".into()));
    assert_eq!(tmpl.render("{{param}}", &over).unwrap(), "qq");
}

/// AC-L4: runtime placeholders are computed from the target URL.
#[test]
fn runtime_placeholders() {
    let tmpl = PocTemplate::new(VarBindings::new());
    let mut vars = VarBindings::new();
    vars.insert("target", Value::Str("https://ex.test:8443/a".into()));

    assert_eq!(
        tmpl.render("{{Hostname}}|{{Port}}|{{Scheme}}", &vars)
            .unwrap(),
        "ex.test|8443|https"
    );
    assert_eq!(tmpl.render("{{Path}}", &vars).unwrap(), "/a");
    assert_eq!(
        tmpl.render("{{RootURL}}", &vars).unwrap(),
        "https://ex.test:8443"
    );
}
