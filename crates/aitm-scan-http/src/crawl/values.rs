//! Inert generated form values for crawl submissions (task 14).
//!
//! Both crawl engines fill a form before they submit it (spec **D8.1**,
//! "type+submit on forms with inert values"). What they type matters: the
//! crawler's job is to *reach* the route behind the form, not to exercise it,
//! so every generated value is deliberately inert — a marked literal that
//! satisfies the control's type and nothing more. No payload, no metacharacter,
//! no address that resolves: an email is `@example.invalid` (RFC 6761, never
//! deliverable) and a URL is the target's own origin, so a form that mails or
//! fetches what it is given cannot be turned into an outbound request by the
//! crawl. The marker (the job's short id) makes every row the crawl created
//! recognisable in the target's data afterwards.
//!
//! The page's own values are preferred wherever the page has one: a hidden
//! field keeps its CSRF token, a radio or checkbox submits its own `value`, a
//! `<select>` takes its first option. A control the crawler cannot fill
//! honestly — a file upload, an empty select, a hidden field with no value —
//! yields `None` and is left out of the submission entirely.

// Removed by the tasks that fill the crawl engines consuming these helpers.
#![allow(dead_code)]

use std::collections::HashSet;

use url::Url;

use crate::crawl::extract::{FieldKind, FieldSpec, FormSpec};
use crate::url_norm::{resolve, same_origin};

/// The prefix every generated value carries, so a row the crawler created is
/// recognisable in the target's data.
const PREFIX: &str = "aitm";

/// The value for a control the generator fills with a number: the smallest
/// plausible one, which satisfies `min=1`/`required` without meaning anything.
const NUMBER: &str = "1";

/// The value for a `date`-shaped control: a fixed, unambiguous ISO date.
const DATE: &str = "2026-01-01";

/// The domain generated addresses live in: RFC 6761 reserves `.invalid`, so a
/// target that mails what the crawler typed cannot deliver it anywhere.
const EMAIL_DOMAIN: &str = "example.invalid";

/// The inert value for one control, or `None` when the crawler has nothing
/// honest to submit for it (a file upload, an empty `<select>`, a hidden field
/// the page left valueless).
///
/// `marker` is the job's short id and `origin` the target origin, used verbatim
/// for `url`-typed controls so a fetch the form triggers stays on the target.
pub(crate) fn value_for(field: &FieldSpec, marker: &str, origin: &str) -> Option<String> {
    let generated = || format!("{PREFIX}-{marker}");
    match &field.kind {
        FieldKind::Text | FieldKind::Textarea | FieldKind::Other(_) => Some(generated()),
        FieldKind::Email => Some(format!("{PREFIX}-{marker}@{EMAIL_DOMAIN}")),
        // Upper case, a symbol and a digit: the shape a sign-up policy asks
        // for, so the crawler reaches the route behind the form instead of a
        // validation error page.
        FieldKind::Password => Some(format!("Aitm-{marker}!1")),
        FieldKind::Number | FieldKind::Tel => Some(NUMBER.to_string()),
        FieldKind::Date => Some(DATE.to_string()),
        FieldKind::Url => Some(origin.to_string()),
        // The page's own values, never a generated one.
        FieldKind::Checkbox | FieldKind::Radio | FieldKind::Hidden => field.value.clone(),
        FieldKind::Select => field.options.first().cloned(),
        // Nothing to upload, and nothing inert to invent.
        FieldKind::File => None,
    }
}

/// Every name/value pair a crawl submission of `form` sends, in document
/// order.
///
/// One pair per name for checkbox and radio groups — the checked member if the
/// page checked one, else the first — at the position the group first appears.
/// Controls [`value_for`] cannot fill are skipped, exactly as a browser omits
/// an unset file input.
pub(crate) fn form_pairs_for(form: &FormSpec, marker: &str, origin: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut groups_done: HashSet<&str> = HashSet::new();

    for field in &form.fields {
        let chosen = if is_group(&field.kind) {
            if !groups_done.insert(field.name.as_str()) {
                continue;
            }
            group_member(form, &field.name).unwrap_or(field)
        } else {
            field
        };
        if let Some(value) = value_for(chosen, marker, origin) {
            pairs.push((field.name.clone(), value));
        }
    }
    pairs
}

/// Whether a control is one of a named group of which a browser submits at
/// most one member.
fn is_group(kind: &FieldKind) -> bool {
    matches!(kind, FieldKind::Checkbox | FieldKind::Radio)
}

/// The member of the `name` group the crawler submits: the checked one, or
/// `None` when the page checked none and the caller should keep the first.
fn group_member<'a>(form: &'a FormSpec, name: &str) -> Option<&'a FieldSpec> {
    form.fields
        .iter()
        .find(|f| is_group(&f.kind) && f.name == name && f.checked)
}

/// Where a crawl submission of `form` goes, or `None` when the crawler must
/// not submit it.
///
/// The action resolves against the page's `<base href>` when it has one and the
/// page's own URL otherwise, as a browser would; a missing action is the page
/// itself. Two rules keep the submission inside the engagement: the method must
/// be `GET` or `POST` (a crawler never fires `PUT`, `DELETE` or anything else a
/// form declares), and the resolved action must share `origin` — a form on the
/// target that posts to a third party is a credential leak, not a route to
/// crawl.
pub(crate) fn form_action(
    form: &FormSpec,
    page: &Url,
    origin: &Url,
    base: Option<&str>,
) -> Option<Url> {
    let method = form.method.trim();
    if !(method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST")) {
        return None;
    }

    let action = form.action.as_deref().map(str::trim).unwrap_or_default();
    let target = if action.is_empty() {
        // HTML's rule: no action, or an empty one, submits to this document.
        page.clone()
    } else {
        let against = base
            .and_then(|href| resolve(page, href))
            .unwrap_or_else(|| page.clone());
        resolve(&against, action)?
    };

    same_origin(&target, origin).then_some(target)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crawl::extract::{extract, FieldKind, FieldSpec, FormSpec};
    use crate::url_norm::parse_absolute;

    const MARKER: &str = "7f3a";
    const ORIGIN: &str = "http://t:8080";

    /// The Task 4 form, built by the real extractor so this test pins the pair
    /// generator against the shapes the crawler actually hands it.
    fn task4_form() -> FormSpec {
        let html = concat!(
            r#"<form action="/search" method="get"><input name="q">"#,
            r#"<select name="s"><option value="a">A</option><option value="b">B</option></select>"#,
            r#"<input type="hidden" name="h" value="1">"#,
            r#"<input type="radio" name="r" value="x" checked>"#,
            r#"<input type="radio" name="r" value="y"><input type="submit"></form>"#,
        );
        let mut forms = extract(html).forms;
        assert_eq!(forms.len(), 1, "fixture has one form");
        forms.remove(0)
    }

    fn field(
        name: &str,
        kind: FieldKind,
        value: Option<&str>,
        options: &[&str],
        checked: bool,
    ) -> FieldSpec {
        FieldSpec {
            name: name.to_string(),
            kind,
            value: value.map(str::to_string),
            options: options.iter().map(|o| (*o).to_string()).collect(),
            checked,
        }
    }

    fn plain(kind: FieldKind) -> FieldSpec {
        field("q", kind, None, &[], false)
    }

    fn value(kind: FieldKind) -> Option<String> {
        value_for(&plain(kind), MARKER, ORIGIN)
    }

    #[test]
    fn value_pins() {
        assert_eq!(value(FieldKind::Text).as_deref(), Some("aitm-7f3a"));
        assert_eq!(value(FieldKind::Textarea).as_deref(), Some("aitm-7f3a"));
        assert_eq!(
            value(FieldKind::Other("color".to_string())).as_deref(),
            Some("aitm-7f3a")
        );
        assert_eq!(
            value(FieldKind::Email).as_deref(),
            Some("aitm-7f3a@example.invalid")
        );
        assert_eq!(value(FieldKind::Password).as_deref(), Some("Aitm-7f3a!1"));
        assert_eq!(value(FieldKind::Number).as_deref(), Some("1"));
        assert_eq!(value(FieldKind::Tel).as_deref(), Some("1"));
        assert_eq!(value(FieldKind::Date).as_deref(), Some("2026-01-01"));
        assert_eq!(value(FieldKind::Url).as_deref(), Some("http://t:8080"));
        assert_eq!(value(FieldKind::File), None);

        // A select takes its first option, and offers nothing when it has none.
        let select = field("s", FieldKind::Select, None, &["a", "b"], false);
        assert_eq!(value_for(&select, MARKER, ORIGIN).as_deref(), Some("a"));
        assert_eq!(value(FieldKind::Select), None);

        // A hidden field keeps the page's own value, and is skipped without one.
        let hidden = field("h", FieldKind::Hidden, Some("1"), &[], false);
        assert_eq!(value_for(&hidden, MARKER, ORIGIN).as_deref(), Some("1"));
        assert_eq!(value(FieldKind::Hidden), None);

        // A checkbox or radio submits its own value, never a generated one.
        let radio = field("r", FieldKind::Radio, Some("x"), &[], true);
        assert_eq!(value_for(&radio, MARKER, ORIGIN).as_deref(), Some("x"));
        let check = field("c", FieldKind::Checkbox, Some("on"), &[], false);
        assert_eq!(value_for(&check, MARKER, ORIGIN).as_deref(), Some("on"));
    }

    #[test]
    fn form_pairs_pins() {
        let pairs = form_pairs_for(&task4_form(), MARKER, ORIGIN);
        let seen: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![("q", "aitm-7f3a"), ("s", "a"), ("h", "1"), ("r", "x"),]
        );
    }

    #[test]
    fn form_pairs_takes_the_first_radio_when_none_is_checked() {
        let form = FormSpec {
            index: 0,
            action: None,
            method: "POST".to_string(),
            enctype: None,
            fields: vec![
                field("r", FieldKind::Radio, Some("x"), &[], false),
                field("r", FieldKind::Radio, Some("y"), &[], false),
                field("f", FieldKind::File, None, &[], false),
            ],
        };
        let pairs = form_pairs_for(&form, MARKER, ORIGIN);
        assert_eq!(pairs, vec![("r".to_string(), "x".to_string())]);
    }

    fn form_with(action: Option<&str>, method: &str) -> FormSpec {
        FormSpec {
            index: 0,
            action: action.map(str::to_string),
            method: method.to_string(),
            enctype: None,
            fields: Vec::new(),
        }
    }

    #[test]
    fn form_action_rules() {
        let page = parse_absolute("http://t:8080/").expect("page parses");
        let origin = parse_absolute("http://t:8080/").expect("origin parses");
        let action = |form: &FormSpec, base: Option<&str>| {
            form_action(form, &page, &origin, base).map(|u| u.to_string())
        };

        assert_eq!(
            action(&form_with(Some("/search"), "GET"), None).as_deref(),
            Some("http://t:8080/search")
        );
        assert_eq!(
            action(&form_with(Some("/login"), "POST"), None).as_deref(),
            Some("http://t:8080/login")
        );
        // Off-origin actions are never submitted.
        assert_eq!(
            action(&form_with(Some("https://evil.test/x"), "GET"), None),
            None
        );
        // Only GET and POST are submittable.
        assert_eq!(action(&form_with(Some("/search"), "PUT"), None), None);
        // No action means this page.
        assert_eq!(
            action(&form_with(None, "GET"), None).as_deref(),
            Some("http://t:8080/")
        );
        // A `<base href>` is what a relative action resolves against.
        assert_eq!(
            action(&form_with(Some("go"), "GET"), Some("/app/")).as_deref(),
            Some("http://t:8080/app/go")
        );
    }
}
