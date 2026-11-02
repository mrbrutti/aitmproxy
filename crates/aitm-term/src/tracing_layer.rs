//! `UiLayer`: the `tracing` layer that folds WARN+ events into the view
//! (spec D7; plan task 5).
//!
//! The layer sits in the `tracing_subscriber::registry()` beside the file
//! layer (plan T9). For every event at least as severe as its minimum it
//! flattens the fields into a [`UiEvent`] (`message` apart, the rest in
//! record order), redacts secret-named fields with [`redact_fields`] and
//! hands the event to the [`EventSender`] the reporter owns (plan C9). No
//! secret crosses the seam, and nothing here writes to any stream: the
//! reporter decides how, and whether, the event is shown.
//!
//! The level check lives in `on_event`, not in `enabled`, so this layer never
//! silences an event for the layers beside it (the file layer still records
//! INFO).

use std::fmt;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crate::event::{redact_fields, EventSender, UiEvent};

/// Folds `tracing` events at or above a minimum level into [`UiEvent`]s.
#[derive(Debug)]
pub struct UiLayer {
    events: EventSender,
    min: Level,
}

impl UiLayer {
    /// A layer that sends every event at least as severe as `min` to
    /// `events`, with secret-named fields redacted.
    pub fn new(events: EventSender, min: Level) -> Self {
        Self { events, min }
    }
}

impl<S> Layer<S> for UiLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = *metadata.level();
        // `tracing` orders levels by verbosity: TRACE > DEBUG > INFO > WARN >
        // ERROR, so "less severe than the minimum" is "greater than".
        if level > self.min {
            return;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        redact_fields(&mut visitor.fields);

        self.events.send(UiEvent {
            level,
            target: metadata.target().to_string(),
            message: visitor.message,
            fields: visitor.fields,
        });
    }
}

/// Flattens an event's fields: `message` on its own, the rest as text pairs
/// in the order they were recorded.
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl FieldVisitor {
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.push((field.name().to_string(), value));
        }
    }
}

impl Visit for FieldVisitor {
    /// Non-string values, `?value` fields and `%value` fields (whose
    /// `Debug` is their `Display`) all arrive here; `{:?}` of a message's
    /// `format_args!` is its text without quotes.
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }

    /// Strings stay verbatim: `engine = "obscura"` records `obscura`.
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventSender, UiEvent};
    use std::sync::{Arc, Mutex};
    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt;

    /// An `EventSender` that appends every event to a shared vector.
    fn collector() -> (EventSender, Arc<Mutex<Vec<UiEvent>>>) {
        let events: Arc<Mutex<Vec<UiEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let sender = EventSender::new(move |ev| {
            sink.lock().expect("test mutex").push(ev);
        });
        (sender, events)
    }

    fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn ui_layer_records_message_and_fields_in_order() {
        let (sender, events) = collector();
        let subscriber = tracing_subscriber::registry().with(UiLayer::new(sender, Level::WARN));

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                engine = "obscura",
                error = %std::io::Error::other("nope"),
                "embedded browser unavailable; browser.* commands will error"
            );
        });

        let got = events.lock().expect("test mutex");
        assert_eq!(got.len(), 1, "exactly one event: {got:?}");
        assert_eq!(got[0].level, Level::WARN);
        assert_eq!(got[0].target, "aitm_term::tracing_layer::tests");
        assert_eq!(
            got[0].message,
            "embedded browser unavailable; browser.* commands will error"
        );
        assert_eq!(
            got[0].fields,
            fields(&[("engine", "obscura"), ("error", "nope")]),
            "strings verbatim (no quotes), Display fields as their display text, record order kept"
        );
    }

    #[test]
    fn ui_layer_drops_events_below_the_minimum() {
        let (sender, events) = collector();
        let subscriber = tracing_subscriber::registry().with(UiLayer::new(sender, Level::WARN));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("hidden");
            assert!(
                events.lock().expect("test mutex").is_empty(),
                "INFO is below WARN and must not reach the view"
            );
            tracing::error!("boom");
        });

        let got = events.lock().expect("test mutex");
        assert_eq!(got.len(), 1, "only the ERROR event: {got:?}");
        assert_eq!(got[0].level, Level::ERROR);
        assert_eq!(got[0].message, "boom");
        assert_eq!(got[0].fields, Vec::<(String, String)>::new());
    }

    #[test]
    fn ui_layer_redacts_secret_fields_before_sending() {
        let (sender, events) = collector();
        let subscriber = tracing_subscriber::registry().with(UiLayer::new(sender, Level::WARN));

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(token = "deadbeef", "x");
        });

        let got = events.lock().expect("test mutex");
        assert_eq!(got.len(), 1, "exactly one event: {got:?}");
        assert_eq!(got[0].message, "x");
        assert_eq!(got[0].fields, fields(&[("token", "<redacted>")]));
        let dumped = format!("{:?}", *got);
        assert!(
            !dumped.contains("deadbeef"),
            "the secret must not survive anywhere in the sent event: {dumped}"
        );
        assert!(dumped.contains("<redacted>"));
    }

    // ---- tester additions ----

    #[test]
    fn ui_layer_through_the_reporter_renders_token_as_redacted() {
        use crate::caps::Caps;
        use crate::reporter::{Reporter, Verbosity};
        use crate::testing::SharedSink;

        let sink = SharedSink::new();
        let reporter = Reporter::new(Caps::plain(), Box::new(sink.clone()), Verbosity::Normal);
        let subscriber =
            tracing_subscriber::registry().with(UiLayer::new(reporter.events(), Level::WARN));

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                token = "deadbeefcafebabe",
                url = "http://127.0.0.1:8082/",
                "bridge token minted"
            );
            tracing::info!(token = "deadbeefcafebabe", "below the view");
        });
        reporter.finish();

        assert_eq!(
            sink.text(),
            "warning: bridge token minted token=<redacted> url=http://127.0.0.1:8082/\n"
        );
        assert!(
            !sink.text().contains("deadbeef"),
            "the secret must not reach the sink: {:?}",
            sink.text()
        );
        assert!(!sink.bytes().contains(&0x1b));
    }

    #[test]
    fn ui_layer_handles_an_event_with_no_message_and_no_fields() {
        let (sender, events) = collector();
        let subscriber = tracing_subscriber::registry().with(UiLayer::new(sender, Level::WARN));

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("");
        });

        let got = events.lock().expect("test mutex");
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].message, "");
        assert_eq!(got[0].fields, Vec::<(String, String)>::new());
        assert_eq!(got[0].target, "aitm_term::tracing_layer::tests");
    }
}
