//! The `browser.*` commands.
//!
//! Each is a thin wrapper over the host's [`BrowserDriver`]. `browser.navigate`
//! is an active action: it runs the SSRF guard, then the scope/rate guard, and
//! only then touches the driver. The others act on the page already loaded.

use std::collections::BTreeMap;
use std::sync::Arc;

use aitm_core::{
    BrowserDriver, ClickTarget, Command, CommandHost, NavOutcome, ParamDef, ParamSchema, Params,
    Plugin, Registry, SsrfPolicy, TypeDesc, Value,
};
use futures::executor::block_on;

use crate::ssrf::{check_url, HostResolver, SystemResolver};

/// Register the six `browser.*` commands. `policy` governs `browser.navigate`'s
/// SSRF check; scope comes from the `CommandHost` at invoke time.
pub fn register_browser_commands(reg: &mut Registry, policy: SsrfPolicy) {
    let resolver: Arc<dyn HostResolver> = Arc::new(SystemResolver);
    reg.add_command(Arc::new(Navigate { policy, resolver }));
    reg.add_command(Arc::new(Click));
    reg.add_command(Arc::new(Type));
    reg.add_command(Arc::new(Screenshot));
    reg.add_command(Arc::new(Eval));
    reg.add_command(Arc::new(GetDom));
}

/// The same registration as a [`Plugin`], for the proxy's plugin list.
pub struct BrowserPlugin {
    policy: SsrfPolicy,
}

impl BrowserPlugin {
    pub fn new(policy: SsrfPolicy) -> Self {
        Self { policy }
    }
}

impl Plugin for BrowserPlugin {
    fn name(&self) -> &str {
        "browser"
    }

    fn load(&mut self, reg: &mut Registry) {
        register_browser_commands(reg, self.policy.clone());
    }
}

fn driver<'h>(host: &'h CommandHost<'_>) -> anyhow::Result<&'h dyn BrowserDriver> {
    host.browser()
        .ok_or_else(|| anyhow::anyhow!("no browser is configured on this host"))
}

fn param(name: &str, ty: TypeDesc, required: bool, description: &str) -> ParamDef {
    ParamDef {
        name: name.to_string(),
        ty,
        required,
        description: description.to_string(),
    }
}

fn schema(description: &str, params: Vec<ParamDef>, result: TypeDesc) -> ParamSchema {
    ParamSchema {
        description: description.to_string(),
        params,
        result,
    }
}

fn number(args: &Params, name: &str) -> anyhow::Result<f64> {
    match args.get(name) {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        Some(other) => anyhow::bail!("param `{name}` must be a number, got {other:?}"),
        None => anyhow::bail!("click needs `selector`, or both `x` and `y`"),
    }
}

fn nav_outcome(outcome: NavOutcome) -> Value {
    let mut fields = BTreeMap::new();
    fields.insert("final_url".to_string(), Value::Str(outcome.final_url));
    fields.insert(
        "status".to_string(),
        outcome
            .status
            .map_or(Value::Null, |s| Value::Int(i64::from(s))),
    );
    Value::Object(fields)
}

struct Navigate {
    policy: SsrfPolicy,
    resolver: Arc<dyn HostResolver>,
}

impl Command for Navigate {
    fn name(&self) -> &str {
        "browser.navigate"
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Load a URL in the embedded browser (SSRF- and scope-guarded).",
            vec![param(
                "url",
                TypeDesc::Str,
                true,
                "The http(s) URL to load.",
            )],
            TypeDesc::Object(vec![
                param("final_url", TypeDesc::Str, true, "URL after redirects."),
                param("status", TypeDesc::Int, false, "HTTP status, when known."),
            ]),
        )
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let url = args.get_str("url")?;
        let target = check_url(
            url,
            &self.policy,
            &host.guard().list_scope(),
            self.resolver.as_ref(),
        )?;
        let authority = format!("{}:{}", target.host, target.addr.port());
        let _permit = host.guard().check_active(&authority)?;
        let outcome = block_on(driver(host)?.navigate(url))?;
        Ok(nav_outcome(outcome))
    }
}

struct Click;

impl Command for Click {
    fn name(&self) -> &str {
        "browser.click"
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Click an element by CSS selector, or a point by viewport coordinates.",
            vec![
                param("selector", TypeDesc::Str, false, "CSS selector to click."),
                param("x", TypeDesc::Float, false, "Viewport x, when no selector."),
                param("y", TypeDesc::Float, false, "Viewport y, when no selector."),
            ],
            TypeDesc::Any,
        )
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let target = match args.get("selector") {
            Some(Value::Str(selector)) => ClickTarget::Selector(selector.clone()),
            _ => ClickTarget::Point {
                x: number(&args, "x")?,
                y: number(&args, "y")?,
            },
        };
        block_on(driver(host)?.click(target))?;
        Ok(Value::Null)
    }
}

struct Type;

impl Command for Type {
    fn name(&self) -> &str {
        "browser.type"
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Type text into the element matching a CSS selector.",
            vec![
                param(
                    "selector",
                    TypeDesc::Str,
                    true,
                    "CSS selector of the input.",
                ),
                param("text", TypeDesc::Str, true, "Text to type."),
            ],
            TypeDesc::Any,
        )
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let selector = args.get_str("selector")?;
        let text = args.get_str("text")?;
        block_on(driver(host)?.type_text(selector, text))?;
        Ok(Value::Null)
    }
}

struct Screenshot;

impl Command for Screenshot {
    fn name(&self) -> &str {
        "browser.screenshot"
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Capture the current page as PNG bytes.",
            vec![],
            TypeDesc::Bytes,
        )
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Bytes(block_on(driver(host)?.screenshot())?))
    }
}

struct Eval;

impl Command for Eval {
    fn name(&self) -> &str {
        "browser.eval"
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Evaluate a JavaScript expression in the page and return its value.",
            vec![param("expr", TypeDesc::Str, true, "JavaScript expression.")],
            TypeDesc::Any,
        )
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let expr = args.get_str("expr")?;
        block_on(driver(host)?.eval(expr))
    }
}

struct GetDom;

impl Command for GetDom {
    fn name(&self) -> &str {
        "browser.get_dom"
    }

    fn schema(&self) -> ParamSchema {
        schema("The page's current outer HTML.", vec![], TypeDesc::Str)
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str(block_on(driver(host)?.get_dom())?))
    }
}
