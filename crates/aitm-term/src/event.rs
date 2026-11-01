//! The seam between the `tracing` layer and the reporter (plan C9).
//!
//! The layer turns a WARN+ event into a [`UiEvent`], redacts it with
//! [`redact_fields`] and hands it to an [`EventSender`]; the reporter owns the
//! closure behind the sender. No secret crosses the seam.

use std::fmt;
use std::sync::Arc;

/// What a redacted field's value becomes.
pub const REDACTED: &str = "<redacted>";

/// A tracing event, flattened for the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiEvent {
    pub level: tracing::Level,
    pub target: String,
    /// The event's `message` field.
    pub message: String,
    /// Every other field, in record order.
    pub fields: Vec<(String, String)>,
}

/// Where the tracing layer sends events: a shared closure, so the layer and
/// the reporter can be built independently.
#[derive(Clone)]
pub struct EventSender(Arc<dyn Fn(UiEvent) + Send + Sync>);

impl EventSender {
    pub fn new(f: impl Fn(UiEvent) + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    pub fn send(&self, ev: UiEvent) {
        (self.0)(ev)
    }
}

impl fmt::Debug for EventSender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EventSender(..)")
    }
}

/// A field name that must never reach a sink in clear: equal to, or ending
/// with, one of these, case-insensitively (plan C9's three, plus the HTTP
/// credential names a proxy's WARN lines carry; fix task S4).
const SECRET_SUFFIXES: [&str; 11] = [
    "token",
    "secret",
    "password",
    "authorization",
    "cookie",
    "passwd",
    "credential",
    "credentials",
    "api_key",
    "apikey",
    "bearer",
];

/// Replace the value of every secret-named field with [`REDACTED`].
pub fn redact_fields(fields: &mut [(String, String)]) {
    for (name, value) in fields.iter_mut() {
        if is_secret_name(name) {
            *value = REDACTED.to_string();
        }
    }
}

fn is_secret_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    SECRET_SUFFIXES.iter().any(|suffix| lower.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn redact_fields_masks_token_secret_password_names() {
        let mut got = fields(&[
            ("engine", "obscura"),
            ("token", "abc"),
            ("Operator_Token", "x"),
            ("my_secret", "y"),
            ("password", "z"),
            ("port", "8080"),
        ]);
        redact_fields(&mut got);
        let values: Vec<&str> = got.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(
            values,
            [
                "obscura",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "8080"
            ]
        );
        assert_eq!(REDACTED, "<redacted>");
        let names: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "engine",
                "token",
                "Operator_Token",
                "my_secret",
                "password",
                "port"
            ],
            "redaction touches values only"
        );
    }

    #[test]
    fn event_sender_delivers_to_the_closure() {
        let received: Arc<Mutex<Vec<UiEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let sender = EventSender::new(move |ev| {
            sink.lock().expect("test mutex").push(ev);
        });

        let ev = UiEvent {
            level: tracing::Level::WARN,
            target: "aitm::wire".to_string(),
            message: "embedded browser unavailable; browser.* commands will error".to_string(),
            fields: fields(&[("engine", "obscura")]),
        };
        sender.clone().send(ev.clone());

        let got = received.lock().expect("test mutex");
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].message,
            "embedded browser unavailable; browser.* commands will error"
        );
        assert_eq!(got[0], ev);
    }

    // ---- tester additions ----

    #[test]
    fn redact_fields_matches_suffixes_case_insensitively_and_leaves_lookalikes() {
        let mut got = fields(&[
            ("TOKEN", "a"),
            ("api-secret", "b"),
            ("PassWord", "c"),
            ("tokenizer", "d"),
            ("", "e"),
        ]);
        redact_fields(&mut got);
        let values: Vec<&str> = got.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(values, ["<redacted>", "<redacted>", "<redacted>", "d", "e"]);

        // Fix task S4: the HTTP credential names a proxy's WARN lines carry.
        let mut got = fields(&[
            ("authorization", "f"),
            ("Proxy_Authorization", "g"),
            ("cookie", "h"),
            ("Set_Cookie", "i"),
            ("passwd", "j"),
            ("credential", "k"),
            ("credentials", "l"),
            ("api_key", "m"),
            ("APIKEY", "n"),
            ("bearer", "o"),
            ("authorized", "p"),
            ("cookie_jar", "q"),
        ]);
        redact_fields(&mut got);
        let values: Vec<&str> = got.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(
            values,
            [
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "<redacted>",
                "p",
                "q"
            ]
        );

        let mut none: Vec<(String, String)> = Vec::new();
        redact_fields(&mut none);
        assert!(none.is_empty());
    }
}
