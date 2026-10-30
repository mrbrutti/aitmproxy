//! `RhaiLoader`: builds the shared engine, compiles each script once, validates,
//! and yields one `LoadedScript` per script (plan Task 9).
//!
//! One hardened engine (Task 2) carries the whole host surface — the flow API
//! (Task 5), every `ScriptCapability` provider M3 ships (Tasks 6, 7) and the
//! bundled prelude (Task 11) — registered once in [`RhaiLoader::new`]. Each
//! `.rhai` file is then compiled once into an `AST`, its metadata read off the
//! AST without running it (`const NAME`, `const API`, the hooks it defines),
//! and wrapped as a [`LoadedScript`] the [`crate::plugin::ScriptHost`] dispatches
//! from its single chain position.
//!
//! **Error policy (spec §8).** A script that does not compile is skipped with
//! a logged, positioned [`ScriptError::Compile`] and the rest still load, so a
//! typo never costs the engagement its proxy; `strict` flips that to
//! fail-fast — [`RhaiLoader::load_all`] then yields no plugins and every
//! error, so CI sees them all in one run. A missing or unsupported `API` is a
//! one-line warning, not a failure (spec §2 rule 1).
//!
//! **Ordering.** [`RhaiLoader::load_all`] keeps `cfg.scripts` order, which is
//! the chain order the wiring registers scripts in after the native plugins
//! (spec §8).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aitm_core::CallerTrust;
use aitm_plugin::language::ProtocolLanguage;
use rhai::{Dynamic, Engine, ParseError, ParseErrorType, AST};

use crate::command::register_reg_api;
use crate::config::{RhaiConfig, ScriptEntry, ScriptMeta};
use crate::engine::{build_engine, Budget};
use crate::error::ScriptError;
use crate::flow_api::register_flow_api;
use crate::host_core::{
    FindingCapability, LogCapability, Options, ScriptCapability, ScriptServices,
};
use crate::host_net::{BrowserCapability, HttpCapability, ScopeCapability, StoreCapability};
use crate::plugin::{ErrorSink, LoadedScript};
use crate::poc_step::VarsCapability;
use crate::prelude::register_prelude;

/// The script `API` contract this build supports: M3's first and only one.
pub const SUPPORTED_API: &str = "1";

/// Every hook a script may define (spec §3), in the order a flow meets them,
/// with the parameters each is called with.
const HOOKS: [(&str, &[&str]); 10] = [
    ("load", &["reg"]),
    ("configure", &[]),
    ("on_request_headers", &["flow"]),
    ("on_request", &["flow"]),
    ("on_response_headers", &["flow"]),
    ("on_response", &["flow"]),
    ("on_ws_start", &["flow"]),
    ("on_ws_message", &["flow", "msg"]),
    ("on_ws_end", &["flow"]),
    ("on_error", &["flow", "err"]),
];

/// Log target for what the loader does and skips, so an operator can read
/// "what is loaded" off the log as well as off the config.
const LOADER_TARGET: &str = "aitm_plugin_rhai::loader";

/// What a script's `load(reg)` registers, found by a static scan of its source
/// (see [`scan_registers`]); empty when the names are not literals.
///
/// Kept apart from [`ScriptMeta`]: only `script.validate` reports it, and
/// `script.reload` / `script.list` must not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registers {
    /// First arguments of `reg.add_command("...", ...)`, in source order.
    pub commands: Vec<String>,
    /// First arguments of `reg.add_option("...", ...)`, in source order.
    pub options: Vec<String>,
}

/// A validated script: its declared metadata plus what it registers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    pub meta: ScriptMeta,
    pub registers: Registers,
}

/// The path a script compiled from a string carries: [`ScriptMeta::path`] is
/// required but there is no file.
const SOURCE_PATH: &str = "<source>";

/// What a script compiled from a string is called when it declares no `NAME`
/// (the file-stem default has no file to come from).
const SOURCE_STEM: &str = "script";

/// The one sandboxed engine plus everything a compiled script needs to become
/// a plugin.
pub struct RhaiLoader {
    engine: Arc<Engine>,
    services: ScriptServices,
    cfg: RhaiConfig,
    /// Each registered capability's `(namespace, min_api)`. A script that
    /// declares an older `API` than a namespace's `min_api` is denied the whole
    /// load — deny-by-default never hands a lower-API script a namespace written
    /// for a newer contract (spec §6a; the forward-compat gate the host surface
    /// relies on to expand capabilities).
    capabilities: Vec<(String, String)>,
    /// Shared by every plugin this loader yields; the wiring binds the chain
    /// into it once the chain exists (see [`ErrorSink`]).
    errors: Arc<ErrorSink>,
}

impl RhaiLoader {
    /// Build the shared sandboxed engine and register the whole host surface:
    /// the flow API, each capability provider's namespace, then the prelude
    /// (compiled under the same limits, so a config that cannot run the
    /// prelude cannot run anything and is refused here).
    pub fn new(cfg: RhaiConfig, services: ScriptServices) -> Result<Self, ScriptError> {
        let capabilities = m3_capabilities(&cfg);
        Self::new_with_capabilities(cfg, services, capabilities)
    }

    /// `new`, but with an explicit capability set instead of the M3 defaults —
    /// the seam a future protocol crate adds its own provider through, and the
    /// one a test drives the `min_api` gate with.
    pub fn new_with_capabilities(
        cfg: RhaiConfig,
        services: ScriptServices,
        capabilities: Vec<Arc<dyn ScriptCapability>>,
    ) -> Result<Self, ScriptError> {
        Self::build(cfg, services, capabilities, &[])
    }

    /// `new`, but with the M3 built-in capabilities **plus** a set of seam
    /// [`ProtocolLanguage`]s installed on the same engine (Task 7). Each
    /// language's `<ns>.*` host fns are registered through the
    /// [`crate::host_registry`] seam, and each namespace's
    /// [`ProtocolLanguage::api_version`] joins the loader's version gate as its
    /// `min_api`, so a script whose `const API` is older than a seam namespace's
    /// version is refused that namespace exactly like a built-in one (AC9).
    pub fn new_with_languages(
        cfg: RhaiConfig,
        services: ScriptServices,
        languages: &[&dyn ProtocolLanguage],
    ) -> Result<Self, ScriptError> {
        let capabilities = m3_capabilities(&cfg);
        Self::build(cfg, services, capabilities, languages)
    }

    /// Build the shared engine: register the flow API, the `load(reg)` bridge,
    /// each built-in capability's namespace, then every seam language's `<ns>.*`
    /// host fns, then the prelude. The version gate (`capabilities`) collects
    /// both the built-in capabilities' `(namespace, min_api)` and each seam
    /// namespace's `(namespace, api_version)`, so `check_api` enforces them with
    /// one rule (Task 7, AC9).
    fn build(
        cfg: RhaiConfig,
        services: ScriptServices,
        capabilities: Vec<Arc<dyn ScriptCapability>>,
        languages: &[&dyn ProtocolLanguage],
    ) -> Result<Self, ScriptError> {
        let mut engine = build_engine(&cfg.limits, cfg.hook_timeout);
        register_flow_api(&mut engine);
        // The `load(reg)` bridge: without it a script's `reg.add_command` is an
        // unknown function and no script could register anything (Task 10).
        register_reg_api(&mut engine);
        let mut cap_requirements = Vec::with_capacity(capabilities.len() + languages.len());
        for capability in &capabilities {
            tracing::debug!(
                target: LOADER_TARGET,
                namespace = capability.namespace(),
                min_api = capability.min_api(),
                "registered script capability"
            );
            capability.register(&mut engine, &services);
            cap_requirements.push((
                capability.namespace().to_string(),
                capability.min_api().to_string(),
            ));
        }
        // Seam-registered protocol languages: install their `<ns>.*` host fns on
        // the same engine, and record each namespace's `api_version` as its
        // `min_api` so the version gate covers seam namespaces too (AC9).
        let language_versions = crate::host_registry::install_languages(&mut engine, languages)?;
        for (namespace, api_version) in language_versions {
            tracing::debug!(
                target: LOADER_TARGET,
                namespace = %namespace,
                api_version = %api_version,
                "registered protocol language namespace"
            );
            cap_requirements.push((namespace, api_version));
        }
        register_prelude(&mut engine)?;
        Ok(Self {
            engine: Arc::new(engine),
            services,
            cfg,
            capabilities: cap_requirements,
            errors: Arc::default(),
        })
    }

    /// The shared engine, for the PoC step executor that runs on it too.
    pub fn engine(&self) -> Arc<Engine> {
        Arc::clone(&self.engine)
    }

    /// The sink every loaded plugin emits `Event::Error` through; the wiring
    /// binds the chain into it once built.
    pub fn error_sink(&self) -> Arc<ErrorSink> {
        Arc::clone(&self.errors)
    }

    /// The services the host surface was registered against, so the PoC step
    /// executor is built from the same handles as the plugins.
    pub fn services(&self) -> &ScriptServices {
        &self.services
    }

    /// The longest string the sandbox lets a script hold, which also bounds a
    /// script source the `script.validate { source }` command will compile.
    pub fn max_string_size(&self) -> usize {
        self.cfg.limits.max_string_size
    }

    /// The configured `script.save` directory, if the operator opted in.
    pub fn scripts_dir(&self) -> Option<&Path> {
        self.cfg.scripts_dir.as_deref()
    }

    /// Whether an agent frontend may run the script-authoring commands
    /// (`rhai.allow_agent_authoring`; off by default).
    pub fn allow_agent_authoring(&self) -> bool {
        self.cfg.allow_agent_authoring
    }

    /// The run budget the configuration gives every hook, step and command.
    pub fn budget(&self) -> Budget {
        Budget::of(&self.cfg)
    }

    /// Compile every enabled entry in `cfg.scripts`, in declaration order.
    /// Returns one plugin per script that compiled plus the errors of those
    /// that did not; with `strict`, any error means no plugins and every
    /// error, so the caller fails fast.
    pub fn load_all(&self) -> (Vec<LoadedScript>, Vec<ScriptError>) {
        let mut plugins = Vec::new();
        let mut errors = Vec::new();
        for entry in self.cfg.scripts.iter().filter(|entry| entry.enabled) {
            match self.load_one(entry) {
                Ok(plugin) => plugins.push(plugin),
                Err(err) => {
                    tracing::error!(target: LOADER_TARGET, path = %entry.path.display(), "{err}");
                    errors.push(err);
                }
            }
        }
        if self.cfg.strict && !errors.is_empty() {
            tracing::error!(
                target: LOADER_TARGET,
                failed = errors.len(),
                "strict: not loading any script while one fails"
            );
            return (Vec::new(), errors);
        }
        (plugins, errors)
    }

    /// Compile one file into a plugin over the shared engine, carrying the
    /// entry's options for `option(...)`.
    pub fn load_one(&self, entry: &ScriptEntry) -> Result<LoadedScript, ScriptError> {
        let (ast, meta) = self.compile(&entry.path)?;
        self.check_api(&meta)?;
        tracing::info!(
            target: LOADER_TARGET,
            script = %meta.name,
            path = %meta.path.display(),
            hooks = ?meta.hooks,
            "loaded script"
        );
        let options = Options::new(entry.options.clone());
        Ok(LoadedScript::new(
            meta,
            Arc::clone(&self.engine),
            ast,
            self.services.clone(),
            options,
            &self.cfg,
        )
        // A script loaded from disk via config is operator-authored: the operator
        // placed it (or pointed config at it), so its hooks/`load` seam calls are
        // operator-trust. `script.save` by an agent overrides this to `Agent` on
        // the returned script (commands.rs), so an agent-saved script keeps agent
        // trust in-session (spec AC6, Open-Q 1).
        .with_authoring_trust(CallerTrust::Operator)
        .with_error_sink(Arc::clone(&self.errors)))
    }

    /// Refuse a script that declares an older `API` than any registered
    /// capability's `min_api`: with one shared engine a namespace cannot be
    /// stripped from a single script, so deny-by-default withholds the whole
    /// script rather than silently hand it a capability written for a newer
    /// contract (spec §6a, I13). Today every M3 capability is API `1`, so a
    /// current script passes; the gate only bites when a future provider
    /// raises its `min_api`.
    fn check_api(&self, meta: &ScriptMeta) -> Result<(), ScriptError> {
        for (namespace, min_api) in &self.capabilities {
            if !api_satisfies(&meta.api, min_api) {
                return Err(ScriptError::CapabilityDenied {
                    script: meta.name.clone(),
                    declared: meta.api.clone(),
                    namespace: namespace.clone(),
                    min_api: min_api.clone(),
                });
            }
        }
        Ok(())
    }

    /// Parse and compile only; no plugin is built and nothing is registered.
    /// Backs `script.validate`.
    pub fn validate(&self, path: &Path) -> Result<ScriptMeta, ScriptError> {
        self.compile(path).map(|(_, meta)| meta)
    }

    /// `validate`, plus what the file's `load(reg)` registers. The file is read
    /// once and the same text is compiled and scanned. Backs `script.validate
    /// { path }`.
    pub fn validate_with_registers(&self, path: &Path) -> Result<Validated, ScriptError> {
        let stem = file_stem(path);
        let src = read_script(path, &stem)?;
        let (_, meta) = self.compile_source(&src, path, stem)?;
        Ok(Validated {
            registers: scan_registers(&src),
            meta,
        })
    }

    /// Compile a script held in a string on the shared engine and describe it,
    /// registering nothing, reading no file and building no plugin. A syntax
    /// error is the same positioned [`ScriptError::Compile`] a file gives,
    /// named `script` at path `<source>`. Backs `script.validate { source }`;
    /// the caller bounds `source` by [`RhaiLoader::max_string_size`].
    pub fn validate_source(&self, source: &str) -> Result<Validated, ScriptError> {
        let path = PathBuf::from(SOURCE_PATH);
        let (_, meta) = self.compile_source(source, &path, SOURCE_STEM.to_string())?;
        Ok(Validated {
            registers: scan_registers(source),
            meta,
        })
    }

    /// Read, compile, and describe one script. The AST is named after the
    /// script so host verbs can attribute what they record to it. Backs
    /// `script.reload`, which swaps the AST into the running plugin.
    pub fn compile(&self, path: &Path) -> Result<(AST, ScriptMeta), ScriptError> {
        let stem = file_stem(path);
        let src = read_script(path, &stem)?;
        self.compile_source(&src, path, stem)
    }

    fn compile_source(
        &self,
        src: &str,
        path: &Path,
        stem: String,
    ) -> Result<(AST, ScriptMeta), ScriptError> {
        let mut ast = self
            .engine
            .compile(src)
            .map_err(|err| compile_error(stem.clone(), path, &err))?;
        let meta = extract_meta(&ast, path, stem);
        ast.set_source(meta.name.as_str());
        Ok((ast, meta))
    }
}

/// Read a script file, or the positioned-format error saying why not.
fn read_script(path: &Path, stem: &str) -> Result<String, ScriptError> {
    fs::read_to_string(path).map_err(|err| ScriptError::Compile {
        script: stem.to_string(),
        path: path.to_path_buf(),
        line: 0,
        column: 0,
        message: format!("cannot read {}: {err}", path.display()),
        hint: Some("check the path under `scripts:` in the config (or the `--script` flag)".into()),
    })
}

/// Best-effort static scan for what `load(reg)` registers, without running it.
///
/// Rhai exposes no AST walk without its `internals` feature, which the sandbox
/// forbids (M3 spec §7), so this is a single lexical pass over the source. In
/// code (not inside a comment or a string) it matches `. add_command (` or
/// `. add_option (` followed by a plain `"..."` literal that is the whole
/// first argument, and records that literal's decoded text. Skipped, so never
/// matched inside: `//` and nested `/* */` comments, `"..."`, `'.'`, `` `...` ``
/// and `#"..."#` literals. A first argument that is not a lone string literal
/// (a variable, `"a" + b`) is left out — the lists are then shorter, never
/// wrong. Names are de-duplicated and kept in source order.
pub fn scan_registers(src: &str) -> Registers {
    let b = src.as_bytes();
    let mut out = Registers::default();
    let mut i = 0;
    while i < b.len() {
        let next = b.get(i + 1).copied();
        match b[i] {
            b'/' if next == Some(b'/') => {
                i = b[i..]
                    .iter()
                    .position(|&c| c == b'\n')
                    .map_or(b.len(), |n| i + n);
            }
            b'/' if next == Some(b'*') => i = skip_block_comment(b, i),
            b'"' | b'\'' => i = skip_quoted(b, i),
            b'`' => {
                i = b[i + 1..]
                    .iter()
                    .position(|&c| c == b'`')
                    .map_or(b.len(), |n| i + n + 2)
            }
            b'#' => i = skip_raw_string(b, i),
            b'.' => match register_call(b, i) {
                Some((target, name, end)) => {
                    let list = match target {
                        RegisterKind::Command => &mut out.commands,
                        RegisterKind::Option => &mut out.options,
                    };
                    if !list.contains(&name) {
                        list.push(name);
                    }
                    i = end;
                }
                None => i += 1,
            },
            _ => i += 1,
        }
    }
    out
}

#[derive(Clone, Copy)]
enum RegisterKind {
    Command,
    Option,
}

/// Index just past the `*/` closing the comment opened at `start` (comments
/// nest in Rhai), or the end of the source.
fn skip_block_comment(b: &[u8], start: usize) -> usize {
    let (mut depth, mut i) = (0usize, start);
    while i < b.len() {
        match (b[i], b.get(i + 1).copied()) {
            (b'/', Some(b'*')) => {
                depth += 1;
                i += 2;
            }
            (b'*', Some(b'/')) => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    b.len()
}

/// Index just past the closing quote of the `"` or `'` literal opened at
/// `start`, honoring backslash escapes, or the end of the source.
fn skip_quoted(b: &[u8], start: usize) -> usize {
    let quote = b[start];
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            c if c == quote => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

/// Past a raw string `#"..."#` (any number of `#`) opened at `start`; one
/// step when the `#` is not a raw string (`#{` map literal, `#!` shebang).
fn skip_raw_string(b: &[u8], start: usize) -> usize {
    let hashes = b[start..].iter().take_while(|&&c| c == b'#').count();
    if b.get(start + hashes) != Some(&b'"') {
        return start + hashes;
    }
    let mut closing = vec![b'"'];
    closing.extend(std::iter::repeat_n(b'#', hashes));
    let body = start + hashes + 1;
    b[body..]
        .windows(closing.len())
        .position(|w| w == closing.as_slice())
        .map_or(b.len(), |n| body + n + closing.len())
}

fn skip_whitespace(b: &[u8], mut i: usize) -> usize {
    while b.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

/// At a `.` in code: `add_command` / `add_option`, `(`, then a string literal
/// that is the entire first argument. Returns which call, the literal's decoded
/// text, and the index past the literal.
fn register_call(b: &[u8], dot: usize) -> Option<(RegisterKind, String, usize)> {
    let start = skip_whitespace(b, dot + 1);
    let len = b[start..]
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric() || **c == b'_')
        .count();
    let kind = match &b[start..start + len] {
        b"add_command" => RegisterKind::Command,
        b"add_option" => RegisterKind::Option,
        _ => return None,
    };
    let open = skip_whitespace(b, start + len);
    if b.get(open) != Some(&b'(') {
        return None;
    }
    let quote = skip_whitespace(b, open + 1);
    if b.get(quote) != Some(&b'"') {
        return None;
    }
    let (name, end) = decode_string(b, quote + 1)?;
    // `"a" + b` is an expression, not a literal name.
    matches!(b.get(skip_whitespace(b, end)), Some(b',' | b')')).then_some((kind, name, end))
}

/// Decode a `"` string body starting just past its opening quote; returns the
/// text and the index past the closing quote. `None` for an escape this does
/// not understand or an unterminated string.
fn decode_string(b: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = Vec::new();
    let mut i = start;
    loop {
        match *b.get(i)? {
            b'"' => return Some((String::from_utf8_lossy(&out).into_owned(), i + 1)),
            b'\\' => {
                let escape = *b.get(i + 1)?;
                i += 2;
                let digits = match escape {
                    b'n' => Some(b'\n'),
                    b't' => Some(b'\t'),
                    b'r' => Some(b'\r'),
                    b'0' => Some(0),
                    b'\\' | b'"' | b'\'' => Some(escape),
                    _ => None,
                };
                if let Some(byte) = digits {
                    out.push(byte);
                    continue;
                }
                let width = match escape {
                    b'x' => 2,
                    b'u' => 4,
                    b'U' => 8,
                    _ => return None,
                };
                let hex = std::str::from_utf8(b.get(i..i + width)?).ok()?;
                let ch = char::from_u32(u32::from_str_radix(hex, 16).ok()?)?;
                out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                i += width;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
}

/// The providers M3 ships (spec §6a). A namespace missing from this list does
/// not exist for scripts. `browser` decides SSRF under the host's policy and
/// `scope.add` is offered only when the config allows it.
///
/// `vars` is here rather than in the PoC executor because the engine is built
/// once and shared: its verbs must exist on the engine before any step runs,
/// even though the handle itself is pushed per step.
fn m3_capabilities(cfg: &RhaiConfig) -> Vec<Arc<dyn ScriptCapability>> {
    vec![
        Arc::new(LogCapability),
        Arc::new(FindingCapability),
        Arc::new(HttpCapability),
        Arc::new(BrowserCapability::new(cfg.ssrf.clone())),
        Arc::new(StoreCapability),
        Arc::new(ScopeCapability::new(cfg.allow_scope_add)),
        Arc::new(VarsCapability),
    ]
}

/// Whether a script declaring `declared` meets a capability's `min_api`.
/// Versions are compared numerically where both parse as integers (so `"2"`
/// satisfies `"1"` but `"1"` does not satisfy `"2"`); anything non-numeric must
/// match exactly, which is deny-by-default for an unrecognized version string.
pub fn api_satisfies(declared: &str, min_api: &str) -> bool {
    match (declared.parse::<u32>(), min_api.parse::<u32>()) {
        (Ok(declared), Ok(min_api)) => declared >= min_api,
        _ => declared == min_api,
    }
}

/// What the script is called when it declares no `NAME` (spec §2 rule 1).
fn file_stem(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("script")
        .to_string()
}

/// A parse failure in the pinned shape: the script, where, what, and — for
/// the classes with an obvious fix — how.
fn compile_error(script: String, path: &Path, err: &ParseError) -> ScriptError {
    let pos = err.position();
    ScriptError::Compile {
        script,
        path: path.to_path_buf(),
        line: pos.line().unwrap_or(0),
        column: pos.position().unwrap_or(0),
        message: err.err_type().to_string(),
        hint: hint_for(err.err_type()),
    }
}

fn hint_for(kind: &ParseErrorType) -> Option<String> {
    match kind {
        ParseErrorType::MissingToken(token, _) => Some(format!("add the missing '{token}'")),
        ParseErrorType::UnexpectedEOF => Some(
            "the file ends mid-statement; look for an unclosed brace, bracket, or string".into(),
        ),
        ParseErrorType::Reserved(word) => Some(format!(
            "'{word}' is a reserved word in Rhai and cannot be used as a name"
        )),
        _ => None,
    }
}

/// `NAME`, `API` and the hooks present, read off the AST's top-level literal
/// constants and function table without running the script. Anything odd
/// but survivable — no `API`, an unsupported one, a hook with the wrong
/// parameters, an `on_…` function that is not a hook — is a warning that
/// names the fix; the script still loads.
fn extract_meta(ast: &AST, path: &Path, stem: String) -> ScriptMeta {
    let mut name = None;
    let mut api = None;
    for (var, _, value) in ast.iter_literal_variables(true, false) {
        match var {
            "NAME" => name = string_const(&stem, var, value),
            "API" => api = string_const(&stem, var, value),
            _ => {}
        }
    }
    let name = name.unwrap_or(stem);

    let api = api.unwrap_or_else(|| {
        tracing::warn!(
            target: LOADER_TARGET,
            script = %name,
            "declares no `const API`; assuming the current version '{SUPPORTED_API}'"
        );
        SUPPORTED_API.to_string()
    });
    if api != SUPPORTED_API {
        let warning = ScriptError::ApiVersion {
            script: name.clone(),
            declared: api.clone(),
            supported: SUPPORTED_API.to_string(),
        };
        tracing::warn!(target: LOADER_TARGET, "{warning}");
    }

    let functions: Vec<(String, usize)> = ast
        .iter_functions()
        .map(|f| (f.name.to_string(), f.params.len()))
        .collect();
    warn_hook_shapes(&name, &functions);
    let hooks = HOOKS
        .iter()
        .filter(|(hook, _)| functions.iter().any(|(f, _)| f == hook))
        .map(|(hook, _)| hook.to_string())
        .collect();

    ScriptMeta {
        name,
        api,
        path: path.to_path_buf(),
        hooks,
    }
}

/// A declared `NAME`/`API` as a non-empty string, else a warning and the
/// default.
fn string_const(script: &str, var: &str, value: Dynamic) -> Option<String> {
    match value.into_immutable_string() {
        Ok(text) if !text.is_empty() => Some(text.to_string()),
        _ => {
            tracing::warn!(
                target: LOADER_TARGET,
                script,
                "`const {var}` must be a non-empty string; ignoring it"
            );
            None
        }
    }
}

/// The two hook mistakes a compile cannot catch (spec §2 rule 6: wrong
/// argument count, unknown hook name), each with the spelling that works.
fn warn_hook_shapes(script: &str, functions: &[(String, usize)]) {
    for (name, arity) in functions {
        match HOOKS.iter().find(|(hook, _)| hook == name) {
            Some((hook, params)) if params.len() != *arity => tracing::warn!(
                target: LOADER_TARGET,
                script,
                "hook '{hook}' is declared with {arity} parameter(s) but is called with {}; \
                 it will fail on every event. help: fn {hook}({})",
                params.len(),
                params.join(", ")
            ),
            None if name.starts_with("on_") => tracing::warn!(
                target: LOADER_TARGET,
                script,
                "'{name}' is not a hook and will never be called. help: the hooks are {}",
                HOOKS
                    .iter()
                    .map(|(hook, _)| *hook)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            _ => {}
        }
    }
}
