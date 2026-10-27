//! `poc.run` (data-flow 6): execute a `Poc` with no agent and emit the three
//! artifacts.
//!
//! The runner walks the ordered steps, resolving `{{placeholders}}` against the
//! caller bindings layered over the PoC's variable defaults:
//!
//! - **http** steps template the URL / headers / body, pass the authority through
//!   the scope+rate [`ScopeRateGuard`], send via the [`ProxyClient`], store the
//!   captured flow (the anchor for the *finding capture* artifact), and feed the
//!   response into the match context. Inline `extract`s bind variables for later
//!   steps.
//! - **browser** steps dispatch to the [`BrowserDriver`]: `navigate` is
//!   scope-guarded on the URL's host; `eval` records an observed value; a
//!   `screenshot` is kept for the *screenshot* artifact; `click`/`type` drive the
//!   page.
//! - **extract** steps bind a variable from the current response context.
//!
//! After the steps, `success` is rendered against the bindings, any `browser-eval`
//! it names is evaluated through the driver, and the tree is judged — the PoC
//! **passes iff `success` is true**. The runner then writes the finding capture
//! (already in the store), the YAML PoC file, and the screenshot PNG, and returns
//! a [`PocRunResult`].

use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use aitm_core::{
    Body, ClickTarget, Command, CommandHost, FlowId, HeaderMap, HttpRequest, HttpVersion, ParamDef,
    ParamSchema, Params, Registry, TypeDesc, Value,
};
use futures::future::BoxFuture;

use crate::extract::{apply, Extractor};
use crate::matcher::{evaluate, MatchContext};
use crate::model::{Assertion, BrowserAction, Poc, Step};
use crate::template::{PocTemplate, Template, VarBindings};

/// Execute a `Poc` with no agent and emit the three artifacts.
pub trait PocRunner: Send + Sync {
    fn run<'a>(
        &'a self,
        poc: &'a Poc,
        bindings: VarBindings,
        host: &'a CommandHost<'a>,
    ) -> BoxFuture<'a, anyhow::Result<PocRunResult>>;
}

/// The outcome of a run: the pass verdict, the three artifact handles, and the
/// per-assertion breakdown of `success`.
#[derive(Debug, Clone)]
pub struct PocRunResult {
    pub passed: bool,
    /// (1) The triggering request/response flow, present in the store.
    pub finding_capture: FlowId,
    /// (2) The replayable PoC file (YAML).
    pub poc_path: PathBuf,
    /// (3) PNG of the vuln triggering (empty path when the PoC has no screenshot step).
    pub screenshot_path: PathBuf,
    /// Each leaf assertion of `success` and whether it matched.
    pub evaluated: Vec<AssertionOutcome>,
}

/// One leaf assertion of `success` and its verdict.
#[derive(Debug, Clone)]
pub struct AssertionOutcome {
    pub assertion: String,
    pub matched: bool,
}

/// The default runner. Artifacts are written under `out_dir` (a fresh
/// per-run subdirectory); defaults to the system temp directory.
#[derive(Debug, Clone)]
pub struct StdPocRunner {
    out_dir: PathBuf,
}

impl Default for StdPocRunner {
    fn default() -> Self {
        Self {
            out_dir: std::env::temp_dir(),
        }
    }
}

impl StdPocRunner {
    /// A runner writing artifacts under the system temp directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// A runner writing artifacts under `dir`.
    pub fn with_output_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            out_dir: dir.into(),
        }
    }
}

impl PocRunner for StdPocRunner {
    fn run<'a>(
        &'a self,
        poc: &'a Poc,
        bindings: VarBindings,
        host: &'a CommandHost<'a>,
    ) -> BoxFuture<'a, anyhow::Result<PocRunResult>> {
        Box::pin(async move { self.run_inner(poc, bindings, host).await })
    }
}

impl StdPocRunner {
    async fn run_inner(
        &self,
        poc: &Poc,
        bindings: VarBindings,
        host: &CommandHost<'_>,
    ) -> anyhow::Result<PocRunResult> {
        // Fail a malformed PoC before any request is sent: compile every regex and
        // parse every DSL expression, and reject an unsafe `id`.
        precheck(poc)?;
        let tmpl = PocTemplate::from_poc(poc)?;

        // Bindings grow as extractors bind variables for later steps.
        let mut live = bindings;
        let mut ctx = MatchContext::default();
        let mut finding: Option<FlowId> = None;
        let mut screenshot: Option<Vec<u8>> = None;

        for step in &poc.steps {
            match step {
                Step::Http(http) => {
                    let req = build_request(http, &tmpl, &live)?;
                    // The `ProxyClient` guards the authority (scope/rate) and
                    // stores the captured flow; the runner neither re-checks nor
                    // re-inserts. The returned flow's id anchors the finding.
                    let flow = host.client().send(req).await?;
                    finding = Some(flow.id);

                    if let Some(resp) = &flow.response {
                        ctx.status = resp.status;
                        ctx.body = body_to_string(&resp.body);
                        ctx.headers = resp
                            .headers
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect();
                    }

                    // Inline extractors bind variables for later steps.
                    for ex_step in &http.extract {
                        bind_extractor(&Extractor::from(ex_step), &mut ctx, &mut live);
                    }
                }
                Step::Browser(browser) => {
                    let driver = host.browser().ok_or_else(|| {
                        anyhow::anyhow!(
                            "poc.run: PoC has a browser step but no browser is configured"
                        )
                    })?;
                    match &browser.action {
                        BrowserAction::Navigate { url } => {
                            let url = tmpl.render(url, &live)?;
                            // SSRF pre-flight (resolve + classify, url::Url parse)
                            // before the scope/rate check, so a PoC cannot drive
                            // the browser at a private/loopback target off-scope.
                            let target = aitm_browser::check_url(
                                &url,
                                &aitm_core::SsrfPolicy::default(),
                                &host.guard().list_scope(),
                                &aitm_browser::SystemResolver,
                            )?;
                            let authority = format!("{}:{}", target.host, target.addr.port());
                            let _permit = host.guard().check_active(&authority)?;
                            driver.navigate(&url).await?;
                            drop(_permit);
                        }
                        BrowserAction::Click { target } => {
                            let target = tmpl.render(target, &live)?;
                            driver.click(ClickTarget::Selector(target)).await?;
                        }
                        BrowserAction::Type { selector, text } => {
                            let selector = tmpl.render(selector, &live)?;
                            let text = tmpl.render(text, &live)?;
                            driver.type_text(&selector, &text).await?;
                        }
                        BrowserAction::Eval { expr } => {
                            let expr = tmpl.render(expr, &live)?;
                            let value = driver.eval(&expr).await?;
                            ctx.browser.insert(expr, value);
                        }
                        BrowserAction::Screenshot { .. } => {
                            screenshot = Some(driver.screenshot().await?);
                        }
                    }
                }
                Step::Extract(ex_step) => {
                    bind_extractor(&Extractor::from(ex_step), &mut ctx, &mut live);
                }
            }
        }

        // Resolve `{{placeholders}}` inside the success tree, then evaluate any
        // browser-eval it names through the driver.
        let success = render_assertion(&poc.success, &tmpl, &live)?;
        eval_browser_assertions(&success, host, &mut ctx).await?;

        let evaluated = collect_outcomes(&success, &ctx);
        let passed = evaluate(&success, &ctx);

        let finding_capture = finding.ok_or_else(|| {
            anyhow::anyhow!("poc.run: no HTTP flow was captured to anchor the finding")
        })?;

        let (poc_path, screenshot_path) = self.write_artifacts(poc, screenshot.as_deref())?;

        Ok(PocRunResult {
            passed,
            finding_capture,
            poc_path,
            screenshot_path,
            evaluated,
        })
    }

    /// Write the YAML PoC file and (if a screenshot was taken) the PNG, into a
    /// fresh per-run directory. Returns their paths.
    fn write_artifacts(
        &self,
        poc: &Poc,
        screenshot: Option<&[u8]>,
    ) -> anyhow::Result<(PathBuf, PathBuf)> {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // The id is validated by `precheck` before this runs, so it is a safe
        // single path component.
        let dir = self.out_dir.join(format!("aitm-poc-{}-{}", poc.id, nanos));
        std::fs::create_dir_all(&dir)?;
        restrict_dir(&dir)?;

        let poc_path = dir.join(format!("{}.poc.yaml", poc.id));
        std::fs::write(&poc_path, serde_yaml::to_string(poc)?)?;
        restrict_file(&poc_path)?;

        let screenshot_path = match screenshot {
            Some(bytes) => {
                let path = dir.join("screenshot.png");
                std::fs::write(&path, bytes)?;
                restrict_file(&path)?;
                path
            }
            None => PathBuf::new(),
        };

        Ok((poc_path, screenshot_path))
    }
}

/// Tighten an artifact directory to owner-only (`0700`) on Unix. A finding's
/// request/response and screenshot may hold sensitive data, so they are not
/// world-readable.
#[cfg(unix)]
fn restrict_dir(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Tighten an artifact file to owner-only (`0600`) on Unix.
#[cfg(unix)]
fn restrict_file(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_dir(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

/// A filesystem-safe PoC id: `^[a-z0-9][a-z0-9-]{0,63}$`. Used to build the
/// artifact directory name, so it can never contain path separators or `..`.
pub fn is_valid_poc_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let first_ok = bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit();
    first_ok
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Reject a PoC that cannot be run safely: an unsafe id, a regex that does not
/// compile, or a DSL expression that does not parse. Runs before any request.
fn precheck(poc: &Poc) -> anyhow::Result<()> {
    if !is_valid_poc_id(&poc.id) {
        anyhow::bail!(
            "poc.run: PoC id {:?} is not a safe identifier (expected ^[a-z0-9][a-z0-9-]{{0,63}}$)",
            poc.id
        );
    }
    check_assertion(&poc.success)?;
    for step in &poc.steps {
        match step {
            Step::Http(http) => {
                for ex in &http.extract {
                    check_extract(ex)?;
                }
            }
            Step::Extract(ex) => check_extract(ex)?,
            Step::Browser(_) => {}
        }
    }
    Ok(())
}

fn check_assertion(assertion: &Assertion) -> anyhow::Result<()> {
    match assertion {
        Assertion::Regex { regex, .. } => regex::Regex::new(regex)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("poc.run: invalid regex matcher {regex:?}: {e}")),
        Assertion::Dsl(expr) => crate::dsl::check(expr)
            .map_err(|e| anyhow::anyhow!("poc.run: invalid dsl matcher {expr:?}: {e}")),
        Assertion::All(items) | Assertion::Any(items) => items.iter().try_for_each(check_assertion),
        Assertion::Not(inner) => check_assertion(inner),
        Assertion::Status(_) | Assertion::Word { .. } | Assertion::BrowserEval { .. } => Ok(()),
    }
}

fn check_extract(step: &crate::model::ExtractStep) -> anyhow::Result<()> {
    if let crate::model::ExtractSource::Regex(pattern) = &step.source {
        regex::Regex::new(pattern)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("poc.run: invalid regex extractor {pattern:?}: {e}"))?;
    }
    Ok(())
}

/// Build a captured-request shape from a templated http step.
fn build_request(
    http: &crate::model::HttpStep,
    tmpl: &PocTemplate,
    live: &VarBindings,
) -> anyhow::Result<HttpRequest> {
    let url = tmpl.render(&http.url, live)?;
    let (scheme, authority, path) = parse_url(&url)?;

    let mut headers = HeaderMap::new();
    for (name, value) in &http.headers {
        headers
            .try_set(&tmpl.render(name, live)?, &tmpl.render(value, live)?)
            .map_err(|e| anyhow::anyhow!("poc.run: http step header: {e}"))?;
    }

    let body = match &http.body {
        Some(text) => Body::Bytes(tmpl.render(text, live)?.into_bytes()),
        None => Body::Empty,
    };

    Ok(HttpRequest {
        method: http.method.clone(),
        scheme,
        authority,
        path,
        version: HttpVersion::Http11,
        headers,
        body,
        timestamp: SystemTime::now(),
    })
}

/// Split a URL into `(scheme, authority, path+query)`.
fn parse_url(url: &str) -> anyhow::Result<(String, String, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("poc.run: step URL `{url}` has no scheme"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), "/".to_string()),
    };
    Ok((scheme.to_string(), authority, path))
}

/// Evaluate one extractor against the context, binding it both for `dsl` matchers
/// (`ctx.vars`) and for later-step templating (`live`).
fn bind_extractor(ex: &Extractor, ctx: &mut MatchContext, live: &mut VarBindings) {
    if let Some(value) = apply(ex, ctx) {
        ctx.vars.insert(ex.name.clone(), value.clone());
        live.insert(ex.name.clone(), value);
    }
}

fn body_to_string(body: &Body) -> String {
    match body {
        Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

/// Render `{{placeholders}}` inside an assertion tree against the bindings.
fn render_assertion(
    assertion: &Assertion,
    tmpl: &PocTemplate,
    live: &VarBindings,
) -> anyhow::Result<Assertion> {
    Ok(match assertion {
        Assertion::Status(code) => Assertion::Status(*code),
        Assertion::Word { word, part } => Assertion::Word {
            word: tmpl.render(word, live)?,
            part: *part,
        },
        Assertion::Regex { regex, part } => Assertion::Regex {
            regex: tmpl.render(regex, live)?,
            part: *part,
        },
        Assertion::Dsl(d) => Assertion::Dsl(tmpl.render(d, live)?),
        Assertion::BrowserEval { expr, equals } => Assertion::BrowserEval {
            expr: tmpl.render(expr, live)?,
            equals: render_value(equals, tmpl, live)?,
        },
        Assertion::All(items) => Assertion::All(render_each(items, tmpl, live)?),
        Assertion::Any(items) => Assertion::Any(render_each(items, tmpl, live)?),
        Assertion::Not(inner) => Assertion::Not(Box::new(render_assertion(inner, tmpl, live)?)),
    })
}

fn render_each(
    items: &[Assertion],
    tmpl: &PocTemplate,
    live: &VarBindings,
) -> anyhow::Result<Vec<Assertion>> {
    items
        .iter()
        .map(|a| render_assertion(a, tmpl, live))
        .collect()
}

fn render_value(value: &Value, tmpl: &PocTemplate, live: &VarBindings) -> anyhow::Result<Value> {
    Ok(match value {
        Value::Str(s) => Value::Str(tmpl.render(s, live)?),
        other => other.clone(),
    })
}

/// Evaluate every `browser-eval` named anywhere in the (resolved) assertion tree
/// through the driver, recording the observed value in the match context.
fn eval_browser_assertions<'a>(
    assertion: &'a Assertion,
    host: &'a CommandHost<'a>,
    ctx: &'a mut MatchContext,
) -> BoxFuture<'a, anyhow::Result<()>> {
    Box::pin(async move {
        match assertion {
            Assertion::BrowserEval { expr, .. } => {
                if ctx.browser.contains_key(expr) {
                    return Ok(());
                }
                let driver = host.browser().ok_or_else(|| {
                    anyhow::anyhow!(
                        "poc.run: success has a browser-eval but no browser is configured"
                    )
                })?;
                let value = driver.eval(expr).await?;
                ctx.browser.insert(expr.clone(), value);
            }
            Assertion::All(items) | Assertion::Any(items) => {
                for item in items {
                    eval_browser_assertions(item, host, ctx).await?;
                }
            }
            Assertion::Not(inner) => eval_browser_assertions(inner, host, ctx).await?,
            _ => {}
        }
        Ok(())
    })
}

/// Flatten the leaf assertions of `success` into reported outcomes.
fn collect_outcomes(assertion: &Assertion, ctx: &MatchContext) -> Vec<AssertionOutcome> {
    let mut out = Vec::new();
    push_outcomes(assertion, ctx, &mut out);
    out
}

fn push_outcomes(assertion: &Assertion, ctx: &MatchContext, out: &mut Vec<AssertionOutcome>) {
    match assertion {
        Assertion::All(items) | Assertion::Any(items) => {
            for item in items {
                push_outcomes(item, ctx, out);
            }
        }
        Assertion::Not(inner) => push_outcomes(inner, ctx, out),
        leaf => out.push(AssertionOutcome {
            assertion: describe(leaf),
            matched: evaluate(leaf, ctx),
        }),
    }
}

fn describe(assertion: &Assertion) -> String {
    match assertion {
        Assertion::Status(code) => format!("status == {code}"),
        Assertion::Word { word, .. } => format!("word: {word}"),
        Assertion::Regex { regex, .. } => format!("regex: {regex}"),
        Assertion::Dsl(d) => format!("dsl: {d}"),
        Assertion::BrowserEval { expr, equals } => {
            format!("browser-eval {expr} == {equals:?}")
        }
        // Combinators are flattened before this point.
        Assertion::All(_) => "all(..)".to_string(),
        Assertion::Any(_) => "any(..)".to_string(),
        Assertion::Not(_) => "not(..)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// poc.run command
// ---------------------------------------------------------------------------

/// The `poc.run` command: load a PoC from `poc_path`, run it with the given
/// variable bindings, and return the verdict plus the three artifact paths.
///
/// `invoke` is synchronous while the runner is async; the future is driven to
/// completion here. A frontend must invoke `poc.run` off a current-thread Tokio
/// runtime's own thread (via `spawn_blocking`), the same convention `flow.replay`
/// and the browser commands use.
pub struct PocRunCommand;

impl Command for PocRunCommand {
    fn name(&self) -> &str {
        "poc.run"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description:
                "Run a reproducible PoC (YAML) with no agent and emit the three artifacts."
                    .to_string(),
            params: vec![
                ParamDef {
                    name: "poc_path".to_string(),
                    ty: TypeDesc::Str,
                    required: true,
                    description: "Path to the PoC YAML file to execute.".to_string(),
                },
                ParamDef {
                    name: "target".to_string(),
                    ty: TypeDesc::Str,
                    required: false,
                    description: "Base URL bound to the `target` variable.".to_string(),
                },
                ParamDef {
                    name: "vars".to_string(),
                    ty: TypeDesc::Map(Box::new(TypeDesc::Any)),
                    required: false,
                    description: "Additional variable bindings (name → value).".to_string(),
                },
            ],
            result: TypeDesc::Object(Vec::new()),
        }
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let poc_path = args.get_str("poc_path")?;
        let path = std::path::Path::new(poc_path);
        // Only load a plainly-named YAML file, never a symlink (which could point
        // the loader at an arbitrary file).
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => {}
            _ => anyhow::bail!("poc.run: `{poc_path}` must be a .yaml file"),
        }
        let meta = std::fs::symlink_metadata(path)
            .map_err(|e| anyhow::anyhow!("poc.run: cannot stat `{poc_path}`: {e}"))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("poc.run: refusing to load `{poc_path}`: it is a symlink");
        }
        // Cap the document size before parsing (billion-laughs / huge-doc guard).
        const MAX_POC_BYTES: u64 = 1024 * 1024;
        if meta.len() > MAX_POC_BYTES {
            anyhow::bail!("poc.run: `{poc_path}` exceeds the {MAX_POC_BYTES}-byte PoC size cap");
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("poc.run: cannot read `{poc_path}`: {e}"))?;
        // Validate the raw document, then type it. Parse errors are reported
        // without echoing the offending file content.
        let raw: serde_yaml::Value = serde_yaml::from_str(&text)
            .map_err(|_| anyhow::anyhow!("poc.run: `{poc_path}` is not valid YAML"))?;
        crate::schema::validate(&raw)
            .map_err(|e| anyhow::anyhow!("poc.run: `{poc_path}` failed validation: {e}"))?;
        let poc: Poc = serde_yaml::from_value(raw)
            .map_err(|_| anyhow::anyhow!("poc.run: `{poc_path}` is not a valid PoC document"))?;

        let mut bindings = VarBindings::new();
        if let Ok(target) = args.get_str("target") {
            bindings.insert("target", Value::Str(target.to_string()));
        }
        if let Ok(vars) = args.get_object("vars") {
            for (name, value) in vars {
                bindings.insert(name.clone(), value.clone());
            }
        }

        let result = futures::executor::block_on(StdPocRunner::new().run(&poc, bindings, host))?;

        let mut obj = std::collections::BTreeMap::new();
        obj.insert("passed".to_string(), Value::Bool(result.passed));
        obj.insert(
            "finding_capture".to_string(),
            Value::Str(result.finding_capture.to_string()),
        );
        obj.insert(
            "poc_path".to_string(),
            Value::Str(result.poc_path.display().to_string()),
        );
        obj.insert(
            "screenshot_path".to_string(),
            Value::Str(result.screenshot_path.display().to_string()),
        );
        obj.insert(
            "evaluated".to_string(),
            Value::Array(
                result
                    .evaluated
                    .into_iter()
                    .map(|o| {
                        let mut m = std::collections::BTreeMap::new();
                        m.insert("assertion".to_string(), Value::Str(o.assertion));
                        m.insert("matched".to_string(), Value::Bool(o.matched));
                        Value::Object(m)
                    })
                    .collect(),
            ),
        );
        Ok(Value::Object(obj))
    }
}

/// Register `poc.run` on a registry (called from binary assembly, Task 28).
pub fn register(registry: &mut Registry) {
    registry.add_command(Arc::new(PocRunCommand));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Assertion, PocInfo, Severity};

    fn poc_with(id: &str, success: Assertion) -> Poc {
        Poc {
            id: id.to_string(),
            info: PocInfo {
                name: "t".into(),
                severity: Severity::Low,
                references: vec![],
                tags: vec![],
                cwe: None,
            },
            variables: vec![],
            steps: vec![],
            success,
        }
    }

    #[test]
    fn valid_ids() {
        assert!(is_valid_poc_id("reflected-xss-search-q"));
        assert!(is_valid_poc_id("a1"));
        assert!(!is_valid_poc_id(""));
        assert!(!is_valid_poc_id("-leading"));
        assert!(!is_valid_poc_id("Has-Upper"));
        assert!(!is_valid_poc_id("has/slash"));
        assert!(!is_valid_poc_id("../escape"));
    }

    #[test]
    fn precheck_rejects_bad_id_regex_and_dsl() {
        assert!(precheck(&poc_with("BadId", Assertion::Status(200))).is_err());
        assert!(precheck(&poc_with("ok", Assertion::regex("("))).is_err());
        assert!(precheck(&poc_with("ok", Assertion::Dsl("status_code ==".into()))).is_err());
        // A well-formed PoC passes the precheck.
        assert!(precheck(&poc_with(
            "ok",
            Assertion::All(vec![
                Assertion::Status(200),
                Assertion::regex("a[0-9]+"),
                Assertion::Dsl("status_code == 200".into()),
            ]),
        ))
        .is_ok());
    }
}
