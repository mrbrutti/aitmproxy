//! The three bus verbs `proxy.system.status|set|unset` (spec §D6, §D10).
//!
//! `status` is a read any frontend may make. `set` and `unset` are
//! operator-only: they refuse a caller that is not a present human control
//! surface before any command runs, and `set` additionally refuses a
//! process that is not serving (`listening == false`, §D10), because a
//! one-shot process would exit and restore at once.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aitm_core::{
    Command, CommandHost, ParamDef, ParamSchema, Params, Plugin, Registry, Sensitivity, TypeDesc,
    Value,
};
use anyhow::bail;

use crate::{SetRequest, SystemProxy};

/// `proxy.system.set` refused for an agent (SP-AC15).
pub const OPERATOR_ONLY_MSG: &str =
    "proxy.system.set is operator-only: an agent can never change the system proxy";

/// `proxy.system.unset` refused for an agent (SP-AC15).
pub const OPERATOR_ONLY_UNSET_MSG: &str =
    "proxy.system.unset is operator-only: an agent can never change the system proxy";

/// `proxy.system.set` refused for a process that is not serving (§D10).
pub const NEEDS_RUNNING_CORE_MSG: &str = "proxy.system.set needs a running core: use the app, the TUI or the web UI, or start aitm with `system_proxy.auto: true`";

/// The `proxy.system.*` verbs as a [`Plugin`].
pub struct SysProxyPlugin {
    sp: Arc<SystemProxy>,
    /// `true` while this process serves on `ours`; a one-shot `Mode::Cli`
    /// process never sets it.
    listening: Arc<AtomicBool>,
}

impl SysProxyPlugin {
    pub fn new(sp: Arc<SystemProxy>, listening: Arc<AtomicBool>) -> Self {
        Self { sp, listening }
    }
}

impl Plugin for SysProxyPlugin {
    fn name(&self) -> &str {
        "sysproxy"
    }

    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(ProxySystemStatus {
            sp: self.sp.clone(),
        }));
        reg.add_command(Arc::new(ProxySystemSet {
            sp: self.sp.clone(),
            listening: self.listening.clone(),
        }));
        reg.add_command(Arc::new(ProxySystemUnset {
            sp: self.sp.clone(),
        }));
    }
}

/// The agent gate shared by the two mutating verbs: a caller that is not a
/// present human control surface (an MCP agent, or any frontend not
/// classified as trusted) is refused before anything runs.
fn refuse_agents(host: &CommandHost, msg: &'static str) -> anyhow::Result<()> {
    if !host.caller_is_trusted_control() {
        bail!(msg);
    }
    Ok(())
}

/// `proxy.system.status` (§D6): a fresh read, no side effects.
pub(crate) struct ProxySystemStatus {
    sp: Arc<SystemProxy>,
}

impl Command for ProxySystemStatus {
    fn name(&self) -> &str {
        "proxy.system.status"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Read the OS system proxy: where it points relative to this core, \
                          whether this core manages it, and the per-service rows on macOS."
                .to_string(),
            params: vec![],
            result: TypeDesc::Any,
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Read
    }

    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<Value> {
        Ok(self.sp.status().to_value())
    }
}

/// `proxy.system.set` (§D6, §D10): operator-only, serving processes only.
pub(crate) struct ProxySystemSet {
    sp: Arc<SystemProxy>,
    listening: Arc<AtomicBool>,
}

impl ProxySystemSet {
    /// The optional `bypass: Array(Str)` param; absent means `[]`.
    fn parse_bypass(args: &Params) -> anyhow::Result<Vec<String>> {
        match args.get("bypass") {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| match v {
                    Value::Str(s) => Ok(s.clone()),
                    other => bail!("each `bypass` entry must be a string, got {other:?}"),
                })
                .collect(),
            Some(other) => bail!("param `bypass` must be an array of strings, got {other:?}"),
        }
    }
}

impl Command for ProxySystemSet {
    fn name(&self) -> &str {
        "proxy.system.set"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Point the OS system proxy (HTTP and HTTPS) at this core, recording \
                          the previous setting so it is restored on unset or exit. Operator-only."
                .to_string(),
            params: vec![ParamDef {
                name: "bypass".to_string(),
                ty: TypeDesc::Array(Box::new(TypeDesc::Str)),
                required: false,
                description: "Extra hosts that skip the system proxy (merged with the defaults \
                              and system_proxy.bypass)"
                    .to_string(),
            }],
            result: TypeDesc::Any,
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn invoke(&self, args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        refuse_agents(host, OPERATOR_ONLY_MSG)?;
        if !self.listening.load(Ordering::SeqCst) {
            bail!(NEEDS_RUNNING_CORE_MSG);
        }
        let bypass = Self::parse_bypass(&args)?;
        let (status, changed, commands) = self.sp.set(&SetRequest { bypass })?;
        let mut map = object(status.to_value());
        map.insert("changed".to_string(), Value::Bool(changed));
        map.insert("commands".to_string(), strings(&commands));
        Ok(Value::Object(map))
    }

    /// `"system proxy → 127.0.0.1:8080 (2 services, 1240 ms)"`; an
    /// unchanged or non-writing outcome falls back to the status `detail`.
    fn summarize(&self, _args: &Params, result: &Value) -> Option<String> {
        if get(result, "changed") != Some(&Value::Bool(true)) {
            return detail(result);
        }
        let ours = get(result, "ours")?;
        let host = as_str(get(ours, "host")?)?;
        let port = as_int(get(ours, "port")?)?;
        let services = as_array(get(result, "services")?)?.len();
        let ms = as_int(get(result, "last_change_ms")?)?;
        Some(format!(
            "system proxy → {host}:{port} ({services} services, {ms} ms)"
        ))
    }
}

/// `proxy.system.unset` (§D6): operator-only; works one-shot (§D10).
pub(crate) struct ProxySystemUnset {
    sp: Arc<SystemProxy>,
}

impl Command for ProxySystemUnset {
    fn name(&self) -> &str {
        "proxy.system.unset"
    }

    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Restore the OS system proxy this core set, service by service, from \
                          the recorded previous setting; services another tool changed since \
                          are left alone. Operator-only."
                .to_string(),
            params: vec![],
            result: TypeDesc::Any,
        }
    }

    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Sensitive
    }

    fn invoke(&self, _args: Params, host: &CommandHost) -> anyhow::Result<Value> {
        refuse_agents(host, OPERATOR_ONLY_UNSET_MSG)?;
        let (outcome, changed, commands) = self.sp.unset()?;
        let mut map = object(outcome.status.to_value());
        map.insert("changed".to_string(), Value::Bool(changed));
        map.insert("commands".to_string(), strings(&commands));
        map.insert("restored".to_string(), strings(&outcome.restored));
        map.insert("left_alone".to_string(), strings(&outcome.left_alone));
        Ok(Value::Object(map))
    }

    /// `"system proxy restored → 127.0.0.1:9090 (2 services, 980 ms)"`: the
    /// endpoint is the first restored service's HTTP endpoint as read back
    /// after the restore (its previous setting), or `off`. With nothing
    /// restored the status `detail` says why.
    fn summarize(&self, _args: &Params, result: &Value) -> Option<String> {
        if get(result, "changed") != Some(&Value::Bool(true)) {
            return detail(result);
        }
        let restored = as_array(get(result, "restored")?)?;
        let first = restored.first().and_then(as_str)?;
        let http = as_array(get(result, "services")?)?
            .iter()
            .find(|row| get(row, "service").and_then(as_str) == Some(first))
            .and_then(|row| get(row, "http"))
            .or_else(|| get(get(result, "effective")?, "http"));
        let endpoint = http
            .and_then(http_endpoint)
            .unwrap_or_else(|| "off".to_string());
        let ms = as_int(get(result, "last_change_ms")?)?;
        Some(format!(
            "system proxy restored → {endpoint} ({} services, {ms} ms)",
            restored.len()
        ))
    }
}

// --- Value helpers -------------------------------------------------------

fn object(v: Value) -> BTreeMap<String, Value> {
    match v {
        Value::Object(map) => map,
        other => BTreeMap::from([("status".to_string(), other)]),
    }
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::Str(s.clone())).collect())
}

fn get<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    match v {
        Value::Object(map) => map.get(name),
        _ => None,
    }
}

fn as_str(v: &Value) -> Option<&str> {
    match v {
        Value::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i),
        _ => None,
    }
}

fn as_array(v: &Value) -> Option<&Vec<Value>> {
    match v {
        Value::Array(items) => Some(items),
        _ => None,
    }
}

fn detail(result: &Value) -> Option<String> {
    as_str(get(result, "detail")?).map(str::to_string)
}

/// `host:port` for an enabled `ProtocolProxy` object, else `None`.
fn http_endpoint(p: &Value) -> Option<String> {
    if get(p, "enabled") != Some(&Value::Bool(true)) {
        return None;
    }
    let host = as_str(get(p, "host")?)?;
    let port = as_int(get(p, "port")?)?;
    Some(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aitm_ca::exec::Executor;
    use aitm_ca::testing::ScriptedExecutor;
    use aitm_core::{
        CommandHost, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient, Registry,
        Sensitivity, StdGuard, TypeDesc, Value,
    };

    use super::*;
    use crate::{Endpoint, Mechanism, SystemProxy, SystemProxyConfig, STATE_FILE_NAME};

    const LIST: &str = "/usr/sbin/networksetup -listallnetworkservices";
    const LIST_OUT: &str = "An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n";
    const SCUTIL: &str = "/usr/sbin/scutil --proxy";
    const DE: &str = "'Display Ethernet'";
    const WIFI: &str = "Wi-Fi";
    const BYPASS_OUT: &str = "*.local\n169.254/16\n";

    /// A `ProxyClient` the host needs but no `proxy.system.*` verb calls.
    struct StubClient;

    impl ProxyClient for StubClient {
        fn send(
            &self,
            _req: HttpRequest,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
            Box::pin(async { anyhow::bail!("stub client") })
        }
    }

    fn ours() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aitm-sysproxy-plugin-{tag}-{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// `-getwebproxy` / `-getsecurewebproxy` output; port 0 is "Enabled: No".
    fn proxy_out(host: &str, port: u16) -> String {
        if port == 0 {
            "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n".to_string()
        } else {
            format!("Enabled: Yes\nServer: {host}\nPort: {port}\nAuthenticated Proxy Enabled: 0\n")
        }
    }

    /// `scutil --proxy` output; port 0 is both disabled.
    fn scutil_out(host: &str, port: u16) -> String {
        if port == 0 {
            return "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n".to_string();
        }
        format!("<dictionary> {{\n  ExceptionsList : <array> {{\n    0 : *.local\n    1 : 169.254/16\n  }}\n  HTTPEnable : 1\n  HTTPPort : {port}\n  HTTPProxy : {host}\n  HTTPSEnable : 1\n  HTTPSPort : {port}\n  HTTPSProxy : {host}\n}}\n")
    }

    fn get_web(svc: &str) -> String {
        format!("/usr/sbin/networksetup -getwebproxy {svc}")
    }
    fn get_secure(svc: &str) -> String {
        format!("/usr/sbin/networksetup -getsecurewebproxy {svc}")
    }
    fn get_bypass(svc: &str) -> String {
        format!("/usr/sbin/networksetup -getproxybypassdomains {svc}")
    }

    /// Queue one round of answers: `Display Ethernet` at `de`, `Wi-Fi` at `wifi`.
    fn answer_round(
        exec: ScriptedExecutor,
        de: (&str, u16),
        wifi: (&str, u16),
    ) -> ScriptedExecutor {
        exec.respond(LIST, 0, LIST_OUT, "")
            .respond(&get_web(DE), 0, &proxy_out(de.0, de.1), "")
            .respond(&get_secure(DE), 0, &proxy_out(de.0, de.1), "")
            .respond(&get_bypass(DE), 0, BYPASS_OUT, "")
            .respond(&get_web(WIFI), 0, &proxy_out(wifi.0, wifi.1), "")
            .respond(&get_secure(WIFI), 0, &proxy_out(wifi.0, wifi.1), "")
            .respond(&get_bypass(WIFI), 0, BYPASS_OUT, "")
    }

    /// The §D7 before-state: `Display Ethernet` at `127.0.0.1:9090`, `Wi-Fi` off.
    fn before_round(exec: ScriptedExecutor) -> ScriptedExecutor {
        answer_round(exec, ("127.0.0.1", 9090), ("", 0))
    }

    fn at_us_round(exec: ScriptedExecutor) -> ScriptedExecutor {
        answer_round(exec, ("127.0.0.1", 8080), ("127.0.0.1", 8080))
    }

    /// The plugin as a frontend sees it: its three verbs in a registry over
    /// a scripted macOS executor and a temp-dir state file.
    struct Rig {
        exec: Arc<ScriptedExecutor>,
        reg: Registry,
        store: MemFlowStore,
        guard: StdGuard,
        client: StubClient,
        dir: PathBuf,
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn rig(tag: &str, exec: ScriptedExecutor, listening: bool) -> Rig {
        let dir = temp_dir(tag);
        let exec = Arc::new(exec.with_real_fs());
        let cfg = SystemProxyConfig {
            auto: false,
            bypass: vec![],
            state_file: Some(dir.join(STATE_FILE_NAME)),
        };
        let as_exec: Arc<dyn Executor> = exec.clone();
        let sp = Arc::new(SystemProxy::with_mechanism(
            as_exec,
            &cfg,
            ours(),
            None,
            Mechanism::Networksetup,
        ));
        let mut reg = Registry::new();
        reg.add_plugin(Box::new(SysProxyPlugin::new(
            sp,
            Arc::new(AtomicBool::new(listening)),
        )));
        Rig {
            exec,
            reg,
            store: MemFlowStore::new(),
            guard: StdGuard::default(),
            client: StubClient,
            dir,
        }
    }

    impl Rig {
        fn call(&self, name: &str, frontend: Frontend, args: Params) -> anyhow::Result<Value> {
            let cmd = self
                .reg
                .command(name)
                .unwrap_or_else(|| panic!("{name} registered"));
            let host = CommandHost::new(&self.store, &self.client, &self.guard, None)
                .with_frontend(frontend);
            cmd.invoke(args, &host)
        }

        fn command(&self, name: &str) -> &Arc<dyn aitm_core::Command> {
            self.reg
                .command(name)
                .unwrap_or_else(|| panic!("{name} registered"))
        }
    }

    fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
        match v {
            Value::Object(map) => map
                .get(name)
                .unwrap_or_else(|| panic!("field `{name}` in {v:?}")),
            other => panic!("expected an object, got {other:?}"),
        }
    }

    fn bypass_args(items: &[&str]) -> Params {
        Params::new(BTreeMap::from([(
            "bypass".to_string(),
            Value::Array(items.iter().map(|s| Value::Str(s.to_string())).collect()),
        )]))
    }

    /// SP-AC15: an agent over MCP is refused before any command runs.
    #[test]
    fn set_refuses_mcp_with_zero_runs() {
        let r = rig("mcp-set", ScriptedExecutor::new(), true);
        let err = r
            .call("proxy.system.set", Frontend::Mcp, Params::default())
            .expect_err("Mcp is refused");
        assert!(err.to_string().contains("operator-only"), "message: {err}");
        assert_eq!(err.to_string(), OPERATOR_ONLY_MSG);
        assert!(r.exec.runs().is_empty(), "ran: {:?}", r.exec.runs());

        let err = r
            .call("proxy.system.unset", Frontend::Mcp, Params::default())
            .expect_err("Mcp is refused");
        assert!(err.to_string().contains("operator-only"), "message: {err}");
        assert!(err.to_string().starts_with("proxy.system.unset "));
        assert!(r.exec.runs().is_empty(), "ran: {:?}", r.exec.runs());
    }

    /// SP-AC15 / §D10: a process that is not serving cannot set.
    #[test]
    fn set_refuses_a_one_shot_process() {
        let r = rig("one-shot-set", ScriptedExecutor::new(), false);
        let err = r
            .call("proxy.system.set", Frontend::Cli, Params::default())
            .expect_err("one-shot set is refused");
        assert!(
            err.to_string().contains("needs a running core"),
            "message: {err}"
        );
        assert_eq!(err.to_string(), NEEDS_RUNNING_CORE_MSG);
        assert!(r.exec.runs().is_empty(), "ran: {:?}", r.exec.runs());
    }

    /// SP-AC15 / §D10: status and unset work one-shot.
    #[test]
    fn unset_and_status_work_one_shot() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "");
        let r = rig("one-shot-read", before_round(exec), false);

        let status = r
            .call("proxy.system.status", Frontend::Cli, Params::default())
            .expect("status works one-shot");
        assert_eq!(field(&status, "state"), &Value::Str("other".into()));
        assert_eq!(field(&status, "host"), &Value::Str("127.0.0.1".into()));
        assert_eq!(field(&status, "port"), &Value::Int(9090));
        assert_eq!(field(&status, "managed_by_us"), &Value::Bool(false));
        assert!(r.exec.runs().contains(&SCUTIL.to_string()));

        let unset = r
            .call("proxy.system.unset", Frontend::Cli, Params::default())
            .expect("unset works one-shot with no file");
        assert_eq!(field(&unset, "changed"), &Value::Bool(false));
        assert_eq!(field(&unset, "commands"), &Value::Array(vec![]));
        assert_eq!(field(&unset, "restored"), &Value::Array(vec![]));
        assert_eq!(field(&unset, "left_alone"), &Value::Array(vec![]));
        assert_eq!(
            field(&unset, "detail"),
            &Value::Str("not managed by this core; nothing to restore".into())
        );
        assert!(
            !r.exec.runs().iter().any(|l| l.contains(" -set")),
            "no mutating line: {:?}",
            r.exec.runs()
        );
    }

    /// SP-AC17 (schema half): exactly one optional `bypass: Array(Str)`.
    #[test]
    fn set_schema_has_one_optional_bypass_array() {
        let r = rig("schema", ScriptedExecutor::new(), true);
        let set = r.command("proxy.system.set");
        assert_eq!(set.name(), "proxy.system.set");
        assert_eq!(set.sensitivity(), Sensitivity::Sensitive);
        let schema = set.schema();
        assert_eq!(schema.params.len(), 1);
        assert_eq!(schema.params[0].name, "bypass");
        assert!(!schema.params[0].required);
        assert!(
            matches!(&schema.params[0].ty, TypeDesc::Array(inner) if matches!(**inner, TypeDesc::Str)),
            "ty: {:?}",
            schema.params[0].ty
        );

        let status = r.command("proxy.system.status");
        assert_eq!(status.sensitivity(), Sensitivity::Read);
        assert!(status.schema().params.is_empty());
        let unset = r.command("proxy.system.unset");
        assert_eq!(unset.sensitivity(), Sensitivity::Sensitive);
        assert!(unset.schema().params.is_empty());
    }

    /// The operator path: the SP-AC5 round, six `-set*` lines, `changed`.
    #[test]
    fn operator_set_returns_changed_and_commands() {
        let exec = ScriptedExecutor::new().respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "");
        let r = rig("operator-set", at_us_round(before_round(exec)), true);

        let args = bypass_args(&["corp.test"]);
        let result = r
            .call("proxy.system.set", Frontend::Operator, args.clone())
            .expect("operator set succeeds");
        assert_eq!(field(&result, "changed"), &Value::Bool(true));
        assert_eq!(field(&result, "state"), &Value::Str("points_at_us".into()));
        let Value::Array(commands) = field(&result, "commands") else {
            panic!("commands is an array: {result:?}");
        };
        assert_eq!(commands.len(), 6);
        for line in commands {
            let Value::Str(line) = line else {
                panic!("a rendered line is a string: {line:?}");
            };
            assert!(line.contains(" -set"), "line: {line}");
        }
        assert!(
            commands
                .iter()
                .any(|l| matches!(l, Value::Str(s) if s.ends_with(" corp.test"))),
            "the extra bypass host reaches the write: {commands:?}"
        );

        // §D6 summarize: endpoint, service count, write-phase ms.
        let summary = r
            .command("proxy.system.set")
            .summarize(&args, &result)
            .expect("set has a summary");
        let Value::Int(ms) = field(&result, "last_change_ms") else {
            panic!("last_change_ms is set after a write: {result:?}");
        };
        assert_eq!(
            summary,
            format!("system proxy → 127.0.0.1:8080 (2 services, {ms} ms)")
        );
    }

    /// §D6 summarize for unset: the first restored service's previous HTTP
    /// endpoint, from the status read back after the restore.
    #[test]
    fn unset_summarize_names_the_restored_endpoint() {
        let exec = ScriptedExecutor::new()
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 8080), "")
            .respond(SCUTIL, 0, &scutil_out("127.0.0.1", 9090), "");
        // set: before read, writes, verify read (at us); unset: judge read
        // (at us), restore, read back (before-state again).
        let exec = before_round(at_us_round(at_us_round(before_round(exec))));
        let r = rig("unset-summary", exec, true);
        r.call("proxy.system.set", Frontend::Operator, Params::default())
            .expect("set succeeds");

        let result = r
            .call("proxy.system.unset", Frontend::Operator, Params::default())
            .expect("unset succeeds");
        assert_eq!(field(&result, "changed"), &Value::Bool(true));
        assert_eq!(
            field(&result, "restored"),
            &Value::Array(vec![
                Value::Str("Display Ethernet".into()),
                Value::Str("Wi-Fi".into())
            ])
        );
        let summary = r
            .command("proxy.system.unset")
            .summarize(&Params::default(), &result)
            .expect("unset has a summary");
        let Value::Int(ms) = field(&result, "last_change_ms") else {
            panic!("last_change_ms is set after a restore: {result:?}");
        };
        assert_eq!(
            summary,
            format!("system proxy restored → 127.0.0.1:9090 (2 services, {ms} ms)")
        );
    }
}
