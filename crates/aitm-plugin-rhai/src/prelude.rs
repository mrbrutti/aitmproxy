//! The bundled prelude (`prelude.rhai`): plain-Rhai helpers compiled once under
//! the hardened engine and made available to every script (plan Task 11).
//!
//! The helpers are the spec §2a sugar layer — `ok(resp)`, `contains_ci(hay,
//! needle)`, `json(map)` — versioned with the script `API` contract. They are
//! plain Rhai so a reader can open `prelude.rhai` and see exactly what each
//! does; nothing here widens the sandbox.

use std::path::PathBuf;

use rhai::{Engine, Module, Scope};

use crate::error::ScriptError;

/// The prelude source, bundled into the binary.
pub const PRELUDE_SRC: &str = include_str!("prelude.rhai");

/// How the prelude names itself in a `ScriptError`.
const PRELUDE_NAME: &str = "prelude";
const PRELUDE_PATH: &str = "prelude.rhai";

/// Compile the prelude under `engine` (so it is bound by the same limits as
/// any script) into a module whose functions are the helpers.
pub fn load_prelude(engine: &Engine) -> Result<Module, ScriptError> {
    let ast = engine.compile(PRELUDE_SRC).map_err(|err| {
        let pos = err.position();
        compile_error(pos.line(), pos.position(), err.to_string())
    })?;
    Module::eval_ast_as_new(Scope::new(), &ast, engine).map_err(|err| {
        let pos = err.position();
        compile_error(pos.line(), pos.position(), err.to_string())
    })
}

/// The loader's hook: compile the prelude and register it into the engine's
/// global namespace so every script and PoC step can call the helpers
/// without an import.
pub fn register_prelude(engine: &mut Engine) -> Result<(), ScriptError> {
    let module = load_prelude(engine)?;
    engine.register_global_module(module.into());
    Ok(())
}

fn compile_error(line: Option<usize>, column: Option<usize>, message: String) -> ScriptError {
    ScriptError::Compile {
        script: PRELUDE_NAME.to_string(),
        path: PathBuf::from(PRELUDE_PATH),
        line: line.unwrap_or(0),
        column: column.unwrap_or(0),
        message,
        hint: None,
    }
}
