//! The `ftp` grammar (spec S3 row 8 (FTP)). Stub: a later T6 task fills it.

use std::sync::Arc;

use crate::grammar::Grammar;
use crate::grammars::Pending;
use crate::spec::GrammarKind;

/// The `ftp` grammar, pending its own task.
#[must_use]
pub fn grammar() -> Arc<dyn Grammar> {
    Pending::grammar(GrammarKind::Ftp)
}
