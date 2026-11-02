//! The legacy `scan.discover` one-shot state (spec D12): today's hand-rolled
//! read, moved here unchanged. The `focus` field of the old `ScanState` is
//! gone; the legacy lists are walked through `SitemapState.pane` from Task 4.

use std::collections::HashMap;

use serde_json::Value;

/// One discovered injection point, mirroring an entry of `scan.discover`'s
/// `injection_points` array (`{flow, location, name, example}`). The `example`
/// is whatever the scanner handed us (redacted at the source for cookies and
/// secret-named parameters); the UI renders it verbatim and never re-derives a
/// raw value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InjectionPointRow {
    /// The flow this point was discovered in.
    pub flow: String,
    /// Where it lives (`query`, `body_param`, `header`, `cookie`,
    /// `path_segment`, `redirect`).
    pub location: String,
    /// The parameter / header / segment name.
    pub name: String,
    /// The observed (already-redacted) example value.
    pub example: String,
}

impl InjectionPointRow {
    /// Read one `injection_points` entry; missing fields read as empty.
    pub fn from_json(v: &Value) -> Self {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Self {
            flow: s("flow"),
            location: s("location"),
            name: s("name"),
            example: s("example"),
        }
    }
}

/// What `scan.discover` has reported so far (scanner-integration Stage 1).
/// Plain data; `App::on_bus` fills it and the Site map tab draws it as nodes
/// and points on a legacy bus (D2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacyState {
    /// A `scan.discover` crawl is in flight; disables re-launch until it
    /// settles (the Browser `busy` precedent).
    pub running: bool,
    /// The scope-bound target URL the last launch sent.
    pub target: Option<String>,
    /// The reached endpoints from the last result (each a flow in the store).
    pub endpoints: Vec<String>,
    /// AC3 endpoint to flow links from the last result: the scrubbed endpoint
    /// URL (as it appears in `endpoints`) to the flow id it was reached as.
    /// Not every endpoint has an entry; Enter on an unlinked endpoint opens
    /// nothing.
    pub endpoint_flows: HashMap<String, String>,
    /// The discovered injection points from the last result.
    pub points: Vec<InjectionPointRow>,
    /// The injection-point list cursor.
    pub cursor: usize,
    /// The endpoints-list cursor.
    pub endpoint_cursor: usize,
    /// The last `scan.discover` failure, shown until the next launch.
    pub error: Option<String>,
}

/// The one legacy Jobs row's state (D2: running / done / error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LegacyRun {
    /// Nothing launched yet.
    #[default]
    Idle,
    Running,
    /// A result arrived for the last launch.
    Done,
    /// The last launch failed.
    Error,
}

impl LegacyRun {
    /// Classify the state: in flight wins, then a recorded error, then a
    /// launch that has a target (its result is on screen), else idle.
    pub fn of(state: &LegacyState) -> Self {
        if state.running {
            LegacyRun::Running
        } else if state.error.is_some() {
            LegacyRun::Error
        } else if state.target.is_some() {
            LegacyRun::Done
        } else {
            LegacyRun::Idle
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn point_row_reads_missing_fields_as_empty() {
        let row = InjectionPointRow::from_json(&serde_json::json!({"flow": "f1", "name": "q"}));
        assert_eq!(
            row,
            InjectionPointRow {
                flow: "f1".into(),
                location: String::new(),
                name: "q".into(),
                example: String::new(),
            }
        );
    }

    #[test]
    fn legacy_run_classifies_in_priority_order() {
        let mut s = LegacyState::default();
        assert_eq!(LegacyRun::of(&s), LegacyRun::Idle);
        s.target = Some("http://h/".into());
        assert_eq!(LegacyRun::of(&s), LegacyRun::Done);
        s.error = Some("x".into());
        assert_eq!(LegacyRun::of(&s), LegacyRun::Error);
        s.running = true;
        assert_eq!(LegacyRun::of(&s), LegacyRun::Running);
    }
}
