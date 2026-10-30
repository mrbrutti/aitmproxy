//! Schema validation of a raw PoC document (AC-L7).
//!
//! `validate` runs on the parsed-but-untyped `serde_yaml::Value` so it can reject
//! a malformed document with a clear, field-named error instead of the generic
//! message a failed `Poc` deserialize would give. It checks the required top-level
//! keys and that every step is a mapping led by a string key. A key that is not
//! one of the four fixed step types (`http`/`browser`/`extract`/`script`) is a
//! protocol `<ns>:` step: an unregistered namespace is a run-time error, never a
//! parse or validation error (see `Step::Protocol`).

/// A PoC validation or parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocError {
    /// A required top-level key is absent.
    MissingField(String),
    /// The document is structurally malformed (not a mapping, bad `steps`, …).
    Malformed(String),
}

impl std::fmt::Display for PocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PocError::MissingField(name) => write!(f, "missing required field `{name}`"),
            PocError::Malformed(msg) => write!(f, "malformed PoC document: {msg}"),
        }
    }
}

impl std::error::Error for PocError {}

/// The fixed step types; any other leading key is a protocol namespace.
const FIXED_STEPS: [&str; 4] = ["http", "browser", "extract", "script"];

/// Validate a raw PoC document: required keys present, `steps` a list, and every
/// step a mapping whose first key is a string. A first key beyond the four fixed
/// step types names a protocol namespace; it is accepted when well-formed (the
/// namespace key plus an optional `extract` sibling) and rejected as malformed
/// otherwise. An unregistered namespace still passes here and is refused at run
/// time by the registry lookup.
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
        // The four fixed types keep their existing checks. Any other leading key
        // is a protocol `<ns>:` step: exactly that key plus, optionally, the
        // step-level `extract` sibling. Anything else is malformed.
        if !FIXED_STEPS.contains(&key) {
            for (sibling, _) in step_map.iter() {
                let sibling = sibling.as_str().ok_or_else(|| {
                    PocError::Malformed(format!(
                        "protocol step `{key}:` has a non-string sibling key"
                    ))
                })?;
                if sibling != key && sibling != "extract" {
                    return Err(PocError::Malformed(format!(
                        "protocol step `{key}:` has an unexpected sibling key `{sibling}` \
                         (only `extract` is allowed)"
                    )));
                }
            }
        }
    }

    Ok(())
}
