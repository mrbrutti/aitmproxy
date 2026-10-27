//! `aitm-poc` — reproducible-PoC engine (artifact model, serde, templating, matchers, runner).
//!
//! Milestone 1 ships the declarative subset: the YAML artifact model and its serde
//! mapping (`model`), schema validation (`schema`), `{{var}}` templating
//! (`template`), the matcher/extractor DSL evaluation (`matcher`/`extract`/`dsl`),
//! and the `PocBuilder` (`builder`). The `PocRunner` and the Rhai `script` step
//! land in later waves.

pub mod model;
pub mod schema;

pub use model::{
    Assertion, BrowserAction, BrowserStep, ExtractSource, ExtractStep, HttpStep, Poc, PocInfo,
    Severity, Step, Variable,
};
pub use schema::{validate, PocError};
