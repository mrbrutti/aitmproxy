//! `aitm-poc` — reproducible-PoC engine (artifact model, serde, templating, matchers, runner).
//!
//! Milestone 1 ships the declarative subset: the YAML artifact model and its serde
//! mapping (`model`), schema validation (`schema`), `{{var}}` templating
//! (`template`), the matcher/extractor DSL evaluation (`matcher`/`extract`/`dsl`),
//! the `PocBuilder` (`builder`), and the `PocRunner` (`runner`). The Rhai
//! `script` step lands in a later milestone.

pub mod builder;
pub mod dsl;
pub mod extract;
pub mod matcher;
pub mod model;
pub mod runner;
pub mod schema;
pub mod template;

pub use builder::{PocBuildCommand, PocBuilder, PocSpec, StdPocBuilder};
pub use extract::{run_extractors, Extraction, Extractor, ExtractorKind};
pub use matcher::{evaluate, MatchContext};
pub use model::{
    Assertion, BrowserAction, BrowserStep, ExtractSource, ExtractStep, HttpStep, MatchPart, Poc,
    PocInfo, Severity, Step, Variable,
};
pub use runner::{AssertionOutcome, PocRunCommand, PocRunResult, PocRunner, StdPocRunner};
pub use schema::{validate, PocError};
pub use template::{PocTemplate, Template, VarBindings};
