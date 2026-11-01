//! The small payload and signature tables (sqli-error, ssti, cmdi) — written by task 5 of the T4 plan.
//!
//! The WebSocket checks `ws-sql-error`, `ws-ssti` and `ws-cmdi-echo` reuse the
//! HTTP lane's payload sets and signatures through the WS oracle (spec D8.3).
//! Those tables are duplicated here on purpose: track T3's crate is not a
//! dependency of this one, so sharing them would couple the two lanes before T3
//! lands (plan call 1, last item; follow-up to share once it does).
//!
//! Everything in this module is pure data and pure functions: no I/O, no
//! dependency on the transport or the probe host. The sets are deliberately
//! tiny and fixed — three SQL error payloads, eight DBMS signatures, four SSTI
//! templates and five `echo` forms (plan call 16) — because each entry costs one
//! dial against the target.
//!
//! Every probe here is an inert detection probe: a quote that provokes a
//! database error message, an arithmetic canary a template engine would render,
//! and an `echo` form whose only effect is reflecting a marker the scanner
//! generated. None of them read, write or exfiltrate target data.
//!
//! **Evidence rule.** The value a check puts in `Evidence.matched` comes from
//! this module — the signature constant or the marker-bearing expectation —
//! never the server's own text, which may carry data the redaction rule keeps
//! out of a verdict.

/// The canary a reflection probe places at an insertion point.
///
/// `<marker><'>`: `<`, `>` and `'` prove an unencoded HTML-context reflection
/// and all three survive JSON re-serialisation unchanged. A `"` or a `\` would
/// not — `serde_json` escapes them when the canary is placed in a JSON string,
/// and the echoed `\"` would read as "encoded" at every JSON point (plan call
/// 16).
#[must_use]
pub fn reflection_canary(marker: &str) -> String {
    format!("{marker}<'>")
}

/// How a reply frame echoed a [`reflection_canary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reflection {
    /// The exact canary came back: the metacharacters were not encoded.
    Unencoded,
    /// The marker came back but the canary did not: the metacharacters were
    /// encoded, stripped or otherwise transformed.
    Encoded,
    /// Neither the canary nor the marker came back.
    Absent,
}

/// Classify how `body` echoed the canary built from `marker`.
#[must_use]
pub fn classify_reflection(body: &str, marker: &str) -> Reflection {
    if body.contains(&reflection_canary(marker)) {
        Reflection::Unencoded
    } else if body.contains(marker) {
        Reflection::Encoded
    } else {
        Reflection::Absent
    }
}

/// The three payloads `ws-sql-error` places, in order, stopping on the first
/// reply that carries a signature.
///
/// Each one only unbalances the quoting of the field it replaces, so a server
/// that interpolates it into SQL answers with a syntax error instead of data.
pub const SQL_ERROR_PAYLOADS: [&str; 3] = ["'", "\"", "' OR '1'='1"];

/// `(dbms, lowercase needle)` pairs of database error text.
///
/// The needle is already lowercase because [`sql_error_signature`] matches
/// case-insensitively by lowercasing the body once; it is also the exact string
/// a check reports as `Evidence.matched`.
pub const SQL_ERROR_SIGNATURES: [(&str, &str); 8] = [
    ("mysql", "you have an error in your sql syntax"),
    ("mysql", "warning: mysql"),
    ("postgresql", "syntax error at or near"),
    ("postgresql", "pg::syntaxerror"),
    ("sqlite", "sqlite3::"),
    ("sqlite", "unrecognized token"),
    ("mssql", "unclosed quotation mark"),
    ("oracle", "ora-01756"),
];

/// The first [`SQL_ERROR_SIGNATURES`] needle present in `body`, matched
/// case-insensitively.
///
/// Returns the signature constant, not the server's text: that constant is what
/// a check records as `Evidence.matched`.
#[must_use]
pub fn sql_error_signature(body: &str) -> Option<&'static str> {
    let lowered = body.to_lowercase();
    SQL_ERROR_SIGNATURES
        .iter()
        .find(|(_, needle)| lowered.contains(needle))
        .map(|(_, needle)| *needle)
}

/// Left operand of the SSTI arithmetic canary.
pub const SSTI_A: u32 = 1543;

/// Right operand of the SSTI arithmetic canary.
pub const SSTI_B: u32 = 7;

/// `(payload, expected)` pairs for the four template syntaxes `ws-ssti` tries.
///
/// The payload is the marker followed by `A*B` in one template syntax
/// (`{{..}}`, `${..}`, `<%= .. %>`, `#{..}`); the expectation is the marker
/// followed by the product. Carrying the marker through both is what makes the
/// canary safe to match on: a reply that merely contains the product (a page
/// that prints `10801` of its own accord) never fires, because the product has
/// to be rendered immediately next to this scan's marker.
#[must_use]
pub fn ssti_probes(marker: &str) -> Vec<(String, String)> {
    let expected = format!("{marker}{}", SSTI_A * SSTI_B);
    [
        format!("{{{{{SSTI_A}*{SSTI_B}}}}}"),
        format!("${{{SSTI_A}*{SSTI_B}}}"),
        format!("<%= {SSTI_A}*{SSTI_B} %>"),
        format!("#{{{SSTI_A}*{SSTI_B}}}"),
    ]
    .into_iter()
    .map(|template| (format!("{marker}{template}"), expected.clone()))
    .collect()
}

/// HTML-escape the five characters a safe rendering path replaces: `&`, `<`,
/// `>`, `"` and `'`, in that order.
///
/// This is the escaping a patched target applies before echoing a field back,
/// and it is why [`payload_present`] has to look for the escaped form too.
#[must_use]
pub fn html_escape_min(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Whether `body` carries `payload` as the server would have echoed it:
/// raw, HTML-escaped, or escaped as a JSON string.
///
/// A plain `body.contains(payload)` is not enough, and getting this wrong
/// invents vulnerabilities. Against a patched target that echoes the field and
/// HTML-escapes it, `& echo <marker>` comes back as `&amp; echo <marker>`: the
/// literal is absent while the marker is present, which is exactly the shape
/// [`cmdi_hit`] reads as a command having run (plan call 37 — this fired
/// `Vulnerable/Firm` on the hardened seed in a real-target run). Encoding an
/// echo is not executing it, so every encoding a reflection can arrive in has
/// to count as the payload being present.
fn payload_present(body: &str, payload: &str) -> bool {
    if body.contains(payload) {
        return true;
    }
    let escaped = html_escape_min(payload);
    if body.contains(&escaped) {
        return true;
    }
    // `&#39;` is the other common spelling of an escaped apostrophe.
    if escaped.contains("&#x27;") && body.contains(&escaped.replace("&#x27;", "&#39;")) {
        return true;
    }
    // JSON string escaping (`"` -> `\"`, control characters -> `\uXXXX`) for a
    // payload echoed into a JSON field. Serialising a `&str` cannot fail, but
    // this path returns a verdict, so a failure means "not present" rather
    // than a panic.
    serde_json::to_string(payload)
        .ok()
        .as_deref()
        .and_then(|json| json.strip_prefix('"').and_then(|j| j.strip_suffix('"')))
        .is_some_and(|inner| body.contains(inner))
}

/// Whether `body` evaluated an SSTI probe rather than echoing it.
///
/// True only when the expectation is present *and* the payload is not — in any
/// encoding a reflection could arrive in, see [`payload_present`]: a server
/// that reflects the template source has not evaluated it, however it escaped
/// the reflection on the way out.
#[must_use]
pub fn ssti_hit(body: &str, payload: &str, expected: &str) -> bool {
    body.contains(expected) && !payload_present(body, payload)
}

/// The five command-separator forms `ws-cmdi-echo` tries, in order.
///
/// Each wraps `echo <marker>`: if the field reaches a shell, the only effect is
/// that the scanner's own marker is printed back. Nothing is read, written or
/// run beyond that echo.
#[must_use]
pub fn cmdi_probes(marker: &str) -> Vec<String> {
    vec![
        format!(";echo {marker}"),
        format!("|echo {marker}"),
        format!("$(echo {marker})"),
        format!("`echo {marker}`"),
        format!("& echo {marker}"),
    ]
}

/// Whether `body` ran a command-injection probe rather than echoing it.
///
/// True only when the marker is present *and* the payload is not — in any
/// encoding a reflection could arrive in, see [`payload_present`]: a server
/// that sends `;echo mk` back, raw or as `&amp; echo mk`, has reflected input,
/// not run a command.
#[must_use]
pub fn cmdi_hit(body: &str, payload: &str, marker: &str) -> bool {
    body.contains(marker) && !payload_present(body, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reflection_canary_is_json_safe() {
        assert_eq!(reflection_canary("mk"), "mk<'>");
        // No character of the canary is escaped by JSON re-serialisation, so an
        // echo at a JSON point reads as unencoded rather than as "encoded".
        assert_eq!(
            serde_json::to_string(&reflection_canary("mk")).unwrap(),
            "\"mk<'>\""
        );
    }

    #[test]
    fn reflection_classes() {
        assert_eq!(
            classify_reflection("x mk<'> y", "mk"),
            Reflection::Unencoded
        );
        assert_eq!(
            classify_reflection("x mk&lt;&#39;&gt;", "mk"),
            Reflection::Encoded
        );
        assert_eq!(classify_reflection("nothing", "mk"), Reflection::Absent);
    }

    #[test]
    fn sql_signature_is_case_insensitive_and_returns_the_constant() {
        assert_eq!(
            sql_error_signature("You have an error in your SQL syntax near ''"),
            Some("you have an error in your sql syntax")
        );
        assert_eq!(sql_error_signature("ok"), None);
    }

    #[test]
    fn ssti_pairs_marker_with_product() {
        let probes = ssti_probes("mk");
        assert_eq!(probes.len(), 4);
        assert_eq!(
            probes[0],
            ("mk{{1543*7}}".to_string(), "mk10801".to_string())
        );
        assert!(ssti_hit("mk10801", "mk{{1543*7}}", "mk10801"));
        assert!(!ssti_hit("49", "mk{{1543*7}}", "mk10801"));
        // The literal payload echoed back is a reflection, not an evaluation.
        assert!(!ssti_hit("mk{{1543*7}} mk10801", "mk{{1543*7}}", "mk10801"));
    }

    #[test]
    fn cmdi_hit_requires_marker_without_literal() {
        assert!(cmdi_hit("mk\n", ";echo mk", "mk"));
        assert!(!cmdi_hit(";echo mk", ";echo mk", "mk"));
    }

    #[test]
    fn cmdi_hit_sees_an_html_escaped_payload_as_present() {
        // The patched seed echoes the field and HTML-escapes it: `& echo mk`
        // comes back as `&amp; echo mk`. The literal is "absent" only in the
        // narrowest sense — the server reflected, it did not run a command —
        // so this must not read as a hit (plan call 37, real-target run).
        let body = r#"{"msg":"&amp; echo mk7f3a9e","html":"<b>&amp; echo mk7f3a9e</b>"}"#;
        assert!(!cmdi_hit(body, "& echo mk7f3a9e", "mk7f3a9e"));
    }

    #[test]
    fn escaped_payload_forms_count_as_present() {
        assert_eq!(
            html_escape_min("& < > \" ' x"),
            "&amp; &lt; &gt; &quot; &#x27; x"
        );
        // The `&#39;` spelling of the apostrophe is accepted too.
        assert!(!cmdi_hit("it&#39;s mk", "it's mk", "mk"));
        // A payload echoed into a JSON string comes back with its quotes and
        // backslashes escaped; that is still an echo.
        assert!(!cmdi_hit(r#"{"msg":"say \"mk\""}"#, r#"say "mk""#, "mk"));
        // An SSTI template reflected HTML-escaped is a reflection, not a
        // render, even when the body happens to carry the product as well.
        assert!(!ssti_hit(
            "mk&lt;%= 1543*7 %&gt; mk10801",
            "mk<%= 1543*7 %>",
            "mk10801"
        ));
    }

    #[test]
    fn payload_tables_are_the_fixed_small_sets() {
        assert_eq!(SQL_ERROR_PAYLOADS, ["'", "\"", "' OR '1'='1"]);
        assert_eq!(SQL_ERROR_SIGNATURES.len(), 8);
        assert_eq!(
            SQL_ERROR_SIGNATURES[0],
            ("mysql", "you have an error in your sql syntax")
        );
        // Needles are stored lowercase: `sql_error_signature` lowercases the
        // body once and compares against them as they are.
        for (_, needle) in SQL_ERROR_SIGNATURES {
            assert_eq!(needle, needle.to_lowercase());
        }
        assert_eq!(SSTI_A * SSTI_B, 10801);
        assert_eq!(
            ssti_probes("mk"),
            vec![
                ("mk{{1543*7}}".to_string(), "mk10801".to_string()),
                ("mk${1543*7}".to_string(), "mk10801".to_string()),
                ("mk<%= 1543*7 %>".to_string(), "mk10801".to_string()),
                ("mk#{1543*7}".to_string(), "mk10801".to_string()),
            ]
        );
        assert_eq!(
            cmdi_probes("mk"),
            vec![
                ";echo mk".to_string(),
                "|echo mk".to_string(),
                "$(echo mk)".to_string(),
                "`echo mk`".to_string(),
                "& echo mk".to_string(),
            ]
        );
    }
}
