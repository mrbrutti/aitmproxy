//! The `smtp` grammar (spec S3 row 7 (SMTP)). Stub: a later T6 task fills it.

use std::sync::Arc;

use crate::grammar::Grammar;
use crate::grammars::Pending;
use crate::spec::GrammarKind;

/// The `smtp` grammar, pending its own task.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Pending::grammar(GrammarKind::Smtp)
}
