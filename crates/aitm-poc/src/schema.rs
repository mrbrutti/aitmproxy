//! Schema validation of a raw PoC document (AC-L7).
//!
//! `validate` runs on the parsed-but-untyped `serde_yaml::Value` so it can reject
//! a malformed document with a clear, field-named error instead of the generic
//! message a failed `Poc` deserialize would give. It checks the required top-level
//! keys and that every step names a known step type.

/// A PoC validation or parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocError {
    /// A required top-level key is absent.
    MissingField(String),
    /// A step uses a key that is not a known step type.
    UnknownStep(String),
    /// The document is structurally malformed (not a mapping, bad `steps`, …).
    Malformed(String),
}

impl std::fmt::Display for PocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PocError::MissingField(name) => write!(f, "missing required field `{name}`"),
            PocError::UnknownStep(key) => write!(f, "unknown step type `{key}`"),
            PocError::Malformed(msg) => write!(f, "malformed PoC document: {msg}"),
        }
    }
}

impl std::error::Error for PocError {}

/// The step keys M1 understands. `script` is grammar-only until the M2 Rhai runtime.
const KNOWN_STEPS: [&str; 4] = ["http", "browser", "extract", "script"];

/// Validate a raw PoC document: required keys present, every step a known type.
pub fn validate(doc: &serde_yaml::Value) -> Result<(), PocError> {
    let map = doc
        .as_mapping()
        .ok_or_else(|| PocError::Malformed("top level must be a mapping".to_string()))?;

    for key in ["id", "info", "steps", "success"] {
        if !map.contains_key(key) {
            return Err(PocError::MissingField(key.to_string()));
        }
    }

    let steps = doc
        .get("steps")
        .and_then(|s| s.as_sequence())
        .ok_or_else(|| PocError::Malformed("`steps` must be a list".to_string()))?;

    for step in steps {
        let step_map = step
            .as_mapping()
            .ok_or_else(|| PocError::Malformed("each step must be a mapping".to_string()))?;
        // A step entry has exactly one key naming its type.
        let key = step_map
            .iter()
            .next()
            .and_then(|(k, _)| k.as_str())
            .ok_or_else(|| PocError::Malformed("a step has no step-type key".to_string()))?;
        if !KNOWN_STEPS.contains(&key) {
            return Err(PocError::UnknownStep(key.to_string()));
        }
    }

    Ok(())
}
