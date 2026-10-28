//! `aitm-poc` — reproducible-PoC engine (artifact model, serde, templating, matchers, runner).
//!
//! Milestone 1 ships the declarative subset: the YAML artifact model and its serde
//! mapping (`model`), schema validation (`schema`), `{{var}}` templating
//! (`template`), the matcher/extractor DSL evaluation (`matcher`/`extract`/`dsl`),
//! the `PocBuilder` (`builder`), and the `PocRunner` (`runner`). Milestone 3 adds
//! the `script` step (`Step::Script`) and the `ScriptStepExecutor` seam the runner
//! dispatches it through; the Rhai implementation lives in `aitm-plugin-rhai`, so
//! this crate stays Rhai-free.

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
    PocInfo, ScriptStep, Severity, Step, Variable,
};
pub use runner::{
    AssertionOutcome, PocRunCommand, PocRunResult, PocRunner, ScriptStepCtx, ScriptStepError,
    ScriptStepExecutor, ScriptVerdict, ScriptedPocRunCommand, StdPocRunner, StepOutcome,
};
pub use schema::{validate, PocError};
pub use template::{PocTemplate, Template, VarBindings};
