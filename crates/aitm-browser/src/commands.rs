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

/// Register the seven `browser.*` commands. `policy` governs `browser.navigate`'s
/// SSRF check; scope comes from the `CommandHost` at invoke time, and the
/// egress posture `browser.confine` toggles comes from the host as well.
pub fn register_browser_commands(reg: &mut Registry, policy: SsrfPolicy) {
    let resolver: Arc<dyn HostResolver> = Arc::new(SystemResolver);
    reg.add_command(Arc::new(Navigate { policy, resolver }));
    reg.add_command(Arc::new(Click));
    reg.add_command(Arc::new(Type));
    reg.add_command(Arc::new(Screenshot));
    reg.add_command(Arc::new(Eval));
    reg.add_command(Arc::new(GetDom));
    reg.add_command(Arc::new(Confine));
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
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
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
        // This check is defence in depth, NOT the authoritative SSRF control
        // (audit minor d). It resolves `url` once, then hands the *raw* `url` to
        // the browser, which re-resolves it at connect time — a DNS-rebinding
        // TOCTOU window where the second lookup could return a private address
        // this check never saw. We cannot close it by pinning navigation to
        // `target.addr`: a browser dialing an IP literal breaks TLS SNI, the
        // Host header, and certificate validation, so the rewrite would fail
        // every HTTPS target. The authoritative enforcement is the SSRF-filtering
        // connector on the proxy port, which re-resolves and re-checks every
        // connection the browser makes (the rebind-safe path); this command-level
        // check only rejects the obvious cases early, before touching the driver.
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
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
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
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
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
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
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
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Write
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
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Read
    }

    fn schema(&self) -> ParamSchema {
        schema("The page's current outer HTML.", vec![], TypeDesc::Str)
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        Ok(Value::Str(block_on(driver(host)?.get_dom())?))
    }
}

/// `browser.confine {on}`: set the standing browser-egress posture. Unlike the
/// other `browser.*` commands this never touches the driver — it flips the
/// [`EgressConfinement`](aitm_core::EgressConfinement) the proxy's connector
/// consults on every browser connection. Enabling tightens (out-of-scope public
/// hosts are refused), disabling widens, so it is `Sensitive`, like `scope.add`.
struct Confine;

impl Command for Confine {
    fn name(&self) -> &str {
        "browser.confine"
    }
    fn sensitivity(&self) -> aitm_core::Sensitivity {
        aitm_core::Sensitivity::Sensitive
    }

    fn schema(&self) -> ParamSchema {
        schema(
            "Confine the embedded browser's egress to the current scope (on), or \
             restore free public browsing (off). Private/loopback handling is \
             unaffected either way.",
            vec![param(
                "on",
                TypeDesc::Bool,
                true,
                "true to confine browser egress to scope; false to lift it.",
            )],
            TypeDesc::Object(vec![param(
                "confined",
                TypeDesc::Bool,
                true,
                "The effective posture after the toggle (base OR any live campaign hold).",
            )]),
        )
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        let on = args.get_bool("on")?;
        let egress = host
            .egress()
            .ok_or_else(|| anyhow::anyhow!("browser egress posture not available on this host"))?;
        egress.set_base(on);
        let mut fields = BTreeMap::new();
        fields.insert("confined".to_string(), Value::Bool(egress.confined()));
        Ok(Value::Object(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        EgressConfinement, HttpFlow, HttpRequest, MemFlowStore, ProxyClient, Sensitivity, StdGuard,
    };
    use futures::future::BoxFuture;

    /// A `ProxyClient` that `browser.confine` must never reach.
    struct NoClient;

    impl ProxyClient for NoClient {
        fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            Box::pin(async { anyhow::bail!("browser.confine does not use the proxy client") })
        }
    }

    fn on(value: bool) -> Params {
        let mut map = BTreeMap::new();
        map.insert("on".to_string(), Value::Bool(value));
        Params::new(map)
    }

    fn confined_field(result: &Value) -> bool {
        match result {
            Value::Object(fields) => match fields.get("confined") {
                Some(Value::Bool(b)) => *b,
                other => panic!("`confined` must be a bool, got {other:?}"),
            },
            other => panic!("result must be an object, got {other:?}"),
        }
    }

    /// AC9: `browser.confine {on}` sets the posture's base and reports it back.
    #[test]
    fn browser_confine_toggles_posture() {
        let store = MemFlowStore::new();
        let guard = StdGuard::default();
        let egress = EgressConfinement::new(false);
        let host = CommandHost::new(&store, &NoClient, &guard, None).with_egress(&egress);
        assert!(!egress.confined(), "fixture starts free");

        let result = Confine.invoke(on(true), &host).expect("toggle on");
        assert!(confined_field(&result));
        assert!(egress.confined(), "the shared posture flipped on");

        let result = Confine.invoke(on(false), &host).expect("toggle off");
        assert!(!confined_field(&result));
        assert!(!egress.confined(), "the shared posture flipped back off");
    }

    /// Toggling the browser-egress boundary is an authorization decision, so
    /// the command sits in the operator-gated tier like `scope.add`.
    #[test]
    fn browser_confine_is_sensitive() {
        assert_eq!(Confine.sensitivity(), Sensitivity::Sensitive);
    }

    /// A host assembled without a posture handle refuses clearly rather than
    /// pretending the toggle took effect.
    #[test]
    fn browser_confine_without_handle_errors() {
        let store = MemFlowStore::new();
        let guard = StdGuard::default();
        let host = CommandHost::new(&store, &NoClient, &guard, None);
        assert!(host.egress().is_none());

        let err = Confine
            .invoke(on(true), &host)
            .expect_err("no posture wired");
        assert!(
            err.to_string()
                .contains("browser egress posture not available on this host"),
            "{err}"
        );
    }
}
