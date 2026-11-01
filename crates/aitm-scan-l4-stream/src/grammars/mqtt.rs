//! The `mqtt` grammar (spec S3 row 6 (MQTT 3.1.1)). Stub: a later T6 task fills it.

use std::sync::Arc;

use crate::grammar::Grammar;
use crate::grammars::Pending;
use crate::spec::GrammarKind;

/// The `mqtt` grammar, pending its own task.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Pending::grammar(GrammarKind::Mqtt)
}
