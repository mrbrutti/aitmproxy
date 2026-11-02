//! The remote invocation path (spec D8): prepare the verb from the local
//! registry, connect to the core's operator bus, run the verb there, relay
//! its confirmation question to the operator, and render the answer exactly
//! as the in-process path would.
//!
//! `aitm-bus-client` is used unchanged: [`TcpTransport`] dials, [`BusClient`]
//! speaks JSON-RPC, [`BusError`] is what it reports. Every string that comes
//! back from the core (an error text, a JSON-RPC message, a `tools/list`
//! name, the confirmation prompt) passes through [`sanitize`] as it enters
//! this module, before it is matched, logged or shown (plan C8, spec D10):
//! the renderer sanitizes an [`aitm_term::error::ErrorReport`] again on
//! output, but the prompt goes through the [`Confirmer`]'s own `write!`, and
//! a gate sentence is matched here.
//!
//! What each failure means for the operator (which spec D9 panel) is decided
//! by the entry point in [`super::run`], which knows where the address came
//! from; this module only says what happened ([`RemoteError`]).

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::{BusClient, BusError, ServerInfo, TcpTransport};
use aitm_cli::dispatch::parse_flags;
use aitm_cli::Confirmer;
use aitm_core::{Command, Params, Registry, TypeDesc, Value};
use aitm_mcp::json::from_json;
use aitm_term::text::sanitize;
use serde_json::{Map, Value as JsonValue};
use tracing::debug;

use super::refuse::verb_words;
use crate::render::render_cli_value;

/// `initialize.clientInfo.name`: what the core's audit line records as the
/// client label (spec D8 "Audit"; not a reserved label).
pub const CLIENT_NAME: &str = "aitm-cli";

/// The role `initialize` must echo for an operator-token connection.
const OPERATOR_ROLE: &str = "operator";
/// The JSON-RPC code the bus answers a refused token with.
const TOKEN_REFUSED: i64 = -32001;
/// The reserved flag every verb accepts: answers the confirmation question.
const YES_FLAG: &str = "--yes";
/// The reserved argument of the operator confirm handshake (spec D8 step 8).
const CONFIRM_KEY: &str = "_confirm";
/// The `status` a confirm-gated call answers with before it runs.
const NEEDS_CONFIRMATION: &str = "needs_confirmation";
/// The [`RemoteError::Lost`] detail for a connection the OS refused; the
/// entry point maps it to R2/R2'/R3/R4 by the address's source.
pub(crate) const REFUSED: &str = "refused";
/// The `Str` arguments a live verb reads as paths on the core's machine; a
/// relative value means the operator's directory (plan C11, research F24a).
pub(crate) const PATH_ARGUMENTS: &[&str] = &["poc_path", "path"];

/// The verb a one-shot asked for, as the local registry understands it.
pub enum Prepared {
    /// The registry knows the verb: its flags are typed by its schema.
    Typed {
        cmd: Arc<dyn Command>,
        params: Params,
        /// `--yes` was given.
        yes: bool,
    },
    /// The registry lacks the verb: the core decides whether it exists
    /// (spec D8 step 6) and validates its flags, parsed generically.
    Unresolved {
        dotted: String,
        /// The flag tokens as typed, `--yes` removed.
        flags: Vec<String>,
        yes: bool,
    },
}

impl Prepared {
    /// The dotted verb name.
    pub fn dotted(&self) -> &str {
        match self {
            Prepared::Typed { cmd, .. } => cmd.name(),
            Prepared::Unresolved { dotted, .. } => dotted,
        }
    }

    /// Whether `--yes` was given.
    pub fn yes(&self) -> bool {
        match self {
            Prepared::Typed { yes, .. } | Prepared::Unresolved { yes, .. } => *yes,
        }
    }
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Prepared::Typed { cmd, params, yes } => f
                .debug_struct("Typed")
                .field("cmd", &cmd.name())
                .field("params", params)
                .field("yes", yes)
                .finish(),
            Prepared::Unresolved { dotted, flags, yes } => f
                .debug_struct("Unresolved")
                .field("dotted", dotted)
                .field("flags", flags)
                .field("yes", yes)
                .finish(),
        }
    }
}

/// argv → the verb and its arguments, exactly as `Cli::dispatch` resolves
/// them (plan C9): the leading non-flag tokens are the dotted name, a bare
/// `--yes` is removed, the rest are the verb's flags, typed by the registry's
/// schema through [`parse_flags`] when the registry knows the verb.
///
/// The usage errors keep today's words so W1 classifies them (exit 2):
/// `expected a command before flags, got \`--x\`` and `unknown command
/// \`nonsense\`; run with no arguments to list commands`. A name the registry
/// lacks is an unknown command only when it cannot be a verb at all (a single
/// word: every verb is `group.verb`); a dotted name the registry lacks is
/// [`Prepared::Unresolved`], for the core to know or refuse.
pub fn prepare(registry: &Registry, argv: &[String]) -> anyhow::Result<Prepared> {
    let path_len = argv.iter().take_while(|a| !is_flag(a)).count();
    if path_len == 0 {
        match argv.first() {
            Some(flag) => anyhow::bail!("expected a command before flags, got `{flag}`"),
            None => anyhow::bail!("usage: aitm <command> [--flag value]..."),
        }
    }
    let dotted = argv[..path_len].join(".");
    let rest = &argv[path_len..];
    let yes = rest.iter().any(|t| t == YES_FLAG);
    let flags: Vec<String> = rest.iter().filter(|t| *t != YES_FLAG).cloned().collect();
    match registry.command(&dotted) {
        Some(cmd) => {
            let params = parse_flags(&flags, &cmd.schema(), cmd.name())?;
            Ok(Prepared::Typed {
                cmd: Arc::clone(cmd),
                params,
                yes,
            })
        }
        None if dotted.contains('.') => Ok(Prepared::Unresolved { dotted, flags, yes }),
        None => Err(unknown_command(&dotted)),
    }
}

/// Today's `unknown command` usage error, byte for byte: W1 classifies it
/// by this prefix (`USAGE_PREFIXES`, exit 2). The one literal, for a name
/// the registry lacks ([`prepare`]) and one the core's `tools/list` lacks
/// too (the entry point).
pub(super) fn unknown_command(dotted: &str) -> anyhow::Error {
    anyhow::anyhow!("unknown command `{dotted}`; run with no arguments to list commands")
}

/// `tok` is a flag: `--` and at least one more character (`--` alone and
/// `-x` are not), as `aitm-cli` reads it.
fn is_flag(tok: &str) -> bool {
    tok.len() > 2 && tok.starts_with("--")
}

/// Flags for a verb the local registry lacks (plan C10): `--k v` and `--k=v`
/// give `v` as JSON when it parses, else as a string; a bare `--k` (the next
/// token is a flag, or absent) is `true`; a repeated key is the error `flag
/// --k given more than once`. The core validates names and types.
pub fn generic_arguments(flags: &[String]) -> anyhow::Result<Map<String, JsonValue>> {
    let mut map = Map::new();
    let mut toks = flags.iter().peekable();
    while let Some(tok) = toks.next() {
        let Some(flag) = tok.strip_prefix("--").filter(|f| !f.is_empty()) else {
            anyhow::bail!("unexpected argument `{tok}`; flags are `--name value`");
        };
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (flag, None),
        };
        if map.contains_key(name) {
            anyhow::bail!("flag --{name} given more than once");
        }
        let raw = match inline {
            Some(v) => Some(v),
            None => toks.next_if(|t| !is_flag(t)).cloned(),
        };
        let value = match raw {
            None => JsonValue::Bool(true),
            Some(raw) => serde_json::from_str(&raw).unwrap_or(JsonValue::String(raw)),
        };
        map.insert(name.to_string(), value);
    }
    Ok(map)
}

/// Make the [`PATH_ARGUMENTS`] of `args` absolute against `cwd` (plan C11):
/// a non-empty string value that does not start with `/` is joined to
/// `cwd`; nothing else is rewritten.
pub fn absolutize_paths(args: &mut JsonValue, cwd: &Path) {
    let Some(obj) = args.as_object_mut() else {
        return;
    };
    for key in PATH_ARGUMENTS {
        if let Some(JsonValue::String(value)) = obj.get_mut(*key) {
            if !value.is_empty() && !value.starts_with('/') {
                *value = cwd.join(value.as_str()).display().to_string();
            }
        }
    }
}

/// What went wrong on the remote path. Which spec D9 panel it is depends on
/// where the address came from, which [`super::run`] knows; the panels are
/// its only rendering (it has no `Display`: nothing prints it as text).
#[derive(Debug)]
pub enum RemoteError {
    /// The budget elapsed before the answer.
    Timeout(Duration),
    /// The bus answered `-32001`: the token was refused (R7).
    Refused,
    /// The connection failed or dropped; the detail is the bus error's text,
    /// [`REFUSED`] when the OS refused the connection.
    Lost(String),
    /// `initialize` answered a role other than `operator` (R8).
    Agent,
    /// The verb ran and reported failure; the text is the core's own.
    Tool(String),
    /// A JSON-RPC error other than the token refusal.
    Rpc { code: i64, message: String },
    /// The reply did not have the shape the protocol promises.
    Protocol(String),
    /// The operator answered no to the core's question.
    Aborted(String),
    /// The question could not be asked (no terminal, no `--yes`).
    Confirm(anyhow::Error),
}

/// Every text the bus reports is sanitized here, once, on entry: the core's
/// `isError` text, a JSON-RPC message, a protocol complaint (which quotes the
/// raw reply) and the transport's close reason.
impl From<BusError> for RemoteError {
    fn from(err: BusError) -> Self {
        match err {
            BusError::Rpc {
                code: TOKEN_REFUSED,
                ..
            } => RemoteError::Refused,
            BusError::Rpc { code, message } => RemoteError::Rpc {
                code,
                message: sanitize(&message).into_owned(),
            },
            BusError::Tool(text) => RemoteError::Tool(sanitize(&text).into_owned()),
            BusError::Transport(err) => {
                RemoteError::Lost(sanitize(&format!("{err:#}")).into_owned())
            }
            BusError::Protocol(text) => RemoteError::Protocol(sanitize(&text).into_owned()),
        }
    }
}

/// Run `fut` under `budget`: the bus error becomes a [`RemoteError`], the
/// budget elapsing [`RemoteError::Timeout`].
async fn bounded<T>(
    budget: Duration,
    fut: impl Future<Output = Result<T, BusError>>,
) -> Result<T, RemoteError> {
    match tokio::time::timeout(budget, fut).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(RemoteError::from(err)),
        Err(_elapsed) => Err(RemoteError::Timeout(budget)),
    }
}

/// Dial `addr` and present `token` (spec D8 step 6), under `budget`. A
/// connection the OS refused is `Lost(REFUSED)`; any other connect failure is
/// `Lost` with its text; the budget elapsing is `Timeout`.
pub async fn connect(
    addr: SocketAddr,
    token: &str,
    budget: Duration,
) -> Result<BusClient, RemoteError> {
    match tokio::time::timeout(budget, TcpTransport::connect(addr, token)).await {
        Ok(Ok(transport)) => Ok(BusClient::new(Box::new(transport))),
        Ok(Err(err)) => Err(connect_error(&err)),
        Err(_elapsed) => Err(RemoteError::Timeout(budget)),
    }
}

/// `ConnectionRefused` anywhere in the chain is [`REFUSED`]; anything else
/// keeps the chain's text.
fn connect_error(err: &anyhow::Error) -> RemoteError {
    let refused = err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused)
    });
    if refused {
        RemoteError::Lost(REFUSED.to_string())
    } else {
        RemoteError::Lost(format!("{err:#}"))
    }
}

/// `initialize` as [`CLIENT_NAME`] (spec D8 step 6), under `budget`. A
/// `-32001` is [`RemoteError::Refused`]; a role other than `operator` is
/// [`RemoteError::Agent`].
pub async fn handshake(client: &BusClient, budget: Duration) -> Result<ServerInfo, RemoteError> {
    let info = bounded(
        budget,
        client.initialize(CLIENT_NAME, env!("CARGO_PKG_VERSION")),
    )
    .await?;
    if info.role.as_deref() != Some(OPERATOR_ROLE) {
        return Err(RemoteError::Agent);
    }
    Ok(info)
}

/// Whether the core's `tools/list` names `dotted` (spec D8 step 6, for a
/// verb the local registry lacks), under `budget`. Each name is sanitized
/// before the comparison, so a name that only looks like `dotted` on screen
/// never matches.
pub async fn resolve_remote_name(
    client: &BusClient,
    dotted: &str,
    budget: Duration,
) -> Result<bool, RemoteError> {
    let tools = bounded(budget, client.tools_list()).await?;
    Ok(tools.iter().any(|tool| sanitize(&tool.name) == dotted))
}

/// `tools/call dotted` under `budget` (spec D8 steps 7 and 8). A
/// `needs_confirmation` answer is the core's question: unless `yes`, it is
/// put to `confirmer` sanitized (plan C8); a no is [`RemoteError::Aborted`]
/// with `aborted: <verb words> not run`; a yes, or `yes`, re-sends the
/// identical call with `_confirm: <token>` on the same connection and
/// returns that answer.
pub async fn call(
    client: &BusClient,
    dotted: &str,
    args: JsonValue,
    budget: Duration,
    confirmer: &dyn Confirmer,
    yes: bool,
) -> Result<JsonValue, RemoteError> {
    let first = bounded(budget, client.call(dotted, args.clone())).await?;
    let Some((prompt, token)) = confirmation_request(&first) else {
        return Ok(first);
    };
    if !yes {
        let prompt = sanitize(prompt);
        let confirmed = confirmer.confirm(&prompt).map_err(RemoteError::Confirm)?;
        if !confirmed {
            return Err(RemoteError::Aborted(format!(
                "aborted: {} not run",
                verb_words(dotted)
            )));
        }
    }
    let mut confirmed_args = args;
    match confirmed_args.as_object_mut() {
        Some(obj) => {
            obj.insert(
                CONFIRM_KEY.to_string(),
                JsonValue::String(token.to_string()),
            );
        }
        None => {
            return Err(RemoteError::Protocol(
                "the arguments of a confirm-gated call must be an object".to_string(),
            ))
        }
    }
    let second = bounded(budget, client.call(dotted, confirmed_args)).await?;
    if confirmation_request(&second).is_some() {
        return Err(RemoteError::Protocol(format!(
            "the core asked to confirm {} twice",
            verb_words(dotted)
        )));
    }
    Ok(second)
}

/// The `(prompt, confirm_token)` of a `needs_confirmation` answer; `None`
/// for any other result.
fn confirmation_request(result: &JsonValue) -> Option<(&str, &str)> {
    let obj = result.as_object()?;
    if obj.get("status")?.as_str()? != NEEDS_CONFIRMATION {
        return None;
    }
    let token = obj.get("confirm_token")?.as_str()?;
    let prompt = obj
        .get("prompt")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    Some((prompt, token))
}

/// The core's answer as the bytes the in-process path would print (spec D8
/// step 10, decision (f)): the `Value` `ty` describes is rebuilt, then
/// [`render_cli_value`] prints it. The declared result schema guides the
/// rebuild and never gates it: the core already validated its own answer,
/// and an incomplete declaration must not print an error against a healthy
/// core. Three steps ([`rebuild_value`]), and never a failure:
///
/// 1. The strict `from_json`, which is where the schema adds information
///    (`Bytes` from base64).
/// 2. When it refuses, [`lenient`] runs once: the same conversion, except
///    that a `null` answered for a field the schema marks optional is kept
///    as `Value::Null`, so the printed object keeps every key the core
///    answered and the bytes stay identical to the local path's (G6); and a
///    declared `Object` with no fields, at any depth, means "some object"
///    (fifteen commands declare `result: TypeDesc::Object(Vec::new())`,
///    `findings.list` and `poc.list` an array of it) and is converted
///    structurally, as `TypeDesc::Any`.
/// 3. When that refuses too the answer is converted structurally so the
///    operator sees it, with one `debug!` naming the declared schema and the
///    answer's JSON kind, never its content (security S5).
pub fn render(result: &JsonValue, ty: &TypeDesc) -> Vec<u8> {
    render_cli_value(&rebuild_value(result, ty))
}

/// The three steps [`render`] documents, as the `Value` to print.
fn rebuild_value(result: &JsonValue, ty: &TypeDesc) -> Value {
    if let Ok(value) = from_json(result, ty) {
        return value;
    }
    if let Ok(value) = lenient(result, ty) {
        return value;
    }
    debug!(
        ?ty,
        kind = json_kind(result),
        "the core's answer does not fit the verb's declared result schema; showing it as is"
    );
    structural(result)
}

/// `from_json` as `TypeDesc::Any`: structural, and infallible for `Any`.
fn structural(j: &JsonValue) -> Value {
    from_json(j, &TypeDesc::Any).unwrap_or(Value::Null)
}

/// Step 2 of [`render`]: the strict conversion, except that a `null`
/// answered for a field `ty` marks optional is [`Value::Null`], and a
/// declared `Object` with no fields is "some object" and takes whatever the
/// core answered structurally, through nested declared objects and the
/// arrays and maps of them; every other leaf is `from_json`'s. What the
/// strict conversion refuses for any other reason (a key the schema does
/// not declare, a missing required field, a leaf of the wrong type) is
/// refused here too, so step 3 decides it. Leaf errors are `from_json`'s
/// and quote the answer; [`rebuild_value`] discards the error and never
/// logs it.
fn lenient(j: &JsonValue, ty: &TypeDesc) -> anyhow::Result<Value> {
    match (ty, j) {
        (TypeDesc::Object(defs), _) if defs.is_empty() => Ok(structural(j)),
        (TypeDesc::Object(defs), JsonValue::Object(fields)) => {
            let mut out = BTreeMap::new();
            for def in defs {
                match fields.get(&def.name) {
                    Some(JsonValue::Null) if !def.required => {
                        out.insert(def.name.clone(), Value::Null);
                    }
                    Some(v) => {
                        out.insert(def.name.clone(), lenient(v, &def.ty)?);
                    }
                    None if def.required => {
                        anyhow::bail!("missing required field `{}`", def.name)
                    }
                    None => {}
                }
            }
            if fields.keys().any(|k| !defs.iter().any(|d| &d.name == k)) {
                anyhow::bail!("a key the schema does not declare");
            }
            Ok(Value::Object(out))
        }
        (TypeDesc::Array(item), JsonValue::Array(items)) => items
            .iter()
            .map(|v| lenient(v, item))
            .collect::<anyhow::Result<Vec<_>>>()
            .map(Value::Array),
        (TypeDesc::Map(item), JsonValue::Object(fields)) => fields
            .iter()
            .map(|(k, v)| Ok((k.clone(), lenient(v, item)?)))
            .collect::<anyhow::Result<BTreeMap<_, _>>>()
            .map(Value::Object),
        _ => from_json(j, ty),
    }
}

/// The answer's JSON kind, for the one `debug!` step 3 writes: the word
/// only, never the content.
fn json_kind(j: &JsonValue) -> &'static str {
    match j {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "boolean",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aitm_core::ParamDef;

    /// The remote path sanitizes with the renderer's own function (plan C8),
    /// so the two cannot drift; these are its contract cases.
    #[test]
    fn remote_text_is_sanitized_with_the_renderers_function() {
        assert_eq!(sanitize("plain"), "plain");
        assert_eq!(sanitize("a\x1b]0;x\x07b"), "a\u{FFFD}]0;x\u{FFFD}b");
        assert_eq!(sanitize("a\x1b[2Ab"), "a\u{FFFD}[2Ab");
        assert_eq!(sanitize("a\u{9b}2Jb"), "a\u{FFFD}2Jb");
        assert_eq!(sanitize("a\x7fb\0c"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(sanitize("one\ntwo\r\nthree\tfour"), "one two  three four");
        assert_eq!(sanitize("a\u{202E}b\u{200B}c"), "a\u{FFFD}b\u{FFFD}c");

        // Every bus text is sanitized as it becomes a `RemoteError`.
        assert!(matches!(
            RemoteError::from(BusError::Tool("x refused\x1b[2J".into())),
            RemoteError::Tool(t) if t == "x refused\u{FFFD}[2J"
        ));
        assert!(matches!(
            RemoteError::from(BusError::Rpc { code: -32600, message: "bad\u{202E}".into() }),
            RemoteError::Rpc { code: -32600, message } if message == "bad\u{FFFD}"
        ));
        assert!(matches!(
            RemoteError::from(BusError::Protocol("odd\x07".into())),
            RemoteError::Protocol(t) if t == "odd\u{FFFD}"
        ));
        assert!(matches!(
            RemoteError::from(BusError::Transport(anyhow::anyhow!("closed\x1b"))),
            RemoteError::Lost(t) if t == "closed\u{FFFD}"
        ));
    }

    #[test]
    fn confirmation_request_reads_only_the_handshake_shape() {
        let ask = serde_json::json!({
            "status": "needs_confirmation",
            "prompt": "really?",
            "confirm_token": "t1",
        });
        assert_eq!(confirmation_request(&ask), Some(("really?", "t1")));
        let no_token = serde_json::json!({"status": "needs_confirmation", "prompt": "x"});
        assert_eq!(confirmation_request(&no_token), None);
        let other = serde_json::json!({"status": "ok"});
        assert_eq!(confirmation_request(&other), None);
        assert_eq!(confirmation_request(&serde_json::json!(["a"])), None);
    }

    #[test]
    fn bus_errors_map_to_remote_errors() {
        assert!(matches!(
            RemoteError::from(BusError::Rpc {
                code: -32001,
                message: "refused".into()
            }),
            RemoteError::Refused
        ));
        assert!(matches!(
            RemoteError::from(BusError::Rpc {
                code: -32601,
                message: "no such method".into()
            }),
            RemoteError::Rpc { code: -32601, .. }
        ));
        assert!(matches!(
            RemoteError::from(BusError::Tool("x failed".into())),
            RemoteError::Tool(t) if t == "x failed"
        ));
        assert!(matches!(
            RemoteError::from(BusError::Transport(anyhow::anyhow!("eof"))),
            RemoteError::Lost(t) if t == "eof"
        ));
        let refused =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                .context("connecting to the bus at 127.0.0.1:1");
        assert!(matches!(connect_error(&refused), RemoteError::Lost(t) if t == REFUSED));
        let reset = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert!(matches!(connect_error(&reset), RemoteError::Lost(t) if t != REFUSED));
    }

    #[test]
    fn generic_arguments_takes_a_bare_flag_before_the_end_and_before_a_flag() {
        let got = generic_arguments(&["--a".to_string(), "--b".to_string()]).expect("ok");
        assert_eq!(
            JsonValue::Object(got),
            serde_json::json!({"a": true, "b": true})
        );
        let err = generic_arguments(&["x".to_string()]).expect_err("not a flag");
        assert_eq!(
            err.to_string(),
            "unexpected argument `x`; flags are `--name value`"
        );
    }

    #[test]
    fn absolutize_leaves_non_objects_and_other_keys_alone() {
        let mut arr = serde_json::json!(["x.yaml"]);
        absolutize_paths(&mut arr, Path::new("/w"));
        assert_eq!(arr, serde_json::json!(["x.yaml"]));
        let mut obj = serde_json::json!({"poc_path": "", "path": 3, "name": "x.yaml"});
        absolutize_paths(&mut obj, Path::new("/w"));
        assert_eq!(
            obj,
            serde_json::json!({"poc_path": "", "path": 3, "name": "x.yaml"})
        );
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Tester — C10 edge cases: a value is JSON only when the whole token
    /// parses (`123abc`, `1.2.3.4`, `0x10`, `example.com` stay strings;
    /// `123`, `-1`, `1e3`, `true`, `null`, `[1,2]` do not), a quoted JSON
    /// string loses its quotes, `--k=` is the empty string, `--k=a=b` splits
    /// once, a bare flag before another flag or at the end is `true`, and
    /// `--`, `-x` and a loose word are refused with the one sentence.
    #[test]
    fn tester_generic_arguments_json_lookalikes_stay_strings() {
        let got = generic_arguments(&strs(&[
            "--a",
            "123abc",
            "--b",
            "123",
            "--c",
            "1.2.3.4",
            "--d",
            "true",
            "--e",
            "null",
            "--f",
            "[1,2]",
            "--g=",
            "--h=a=b",
            "--i",
            "-1",
            "--j",
            "example.com",
            "--k",
            "0x10",
            "--l",
            "1e3",
            "--m",
            "--n",
            " spaced ",
            "--o",
            "\"quoted\"",
            "--p",
        ]))
        .expect("parses");
        assert_eq!(
            JsonValue::Object(got),
            serde_json::json!({
                "a": "123abc", "b": 123, "c": "1.2.3.4", "d": true, "e": null,
                "f": [1, 2], "g": "", "h": "a=b", "i": -1, "j": "example.com",
                "k": "0x10", "l": 1000.0, "m": true, "n": " spaced ", "o": "quoted",
                "p": true
            })
        );
        for bad in [
            strs(&["--"]),
            strs(&["-x", "1"]),
            strs(&["--k", "1", "loose"]),
        ] {
            let err = generic_arguments(&bad).expect_err("refused");
            assert!(
                err.to_string().starts_with("unexpected argument `")
                    && err.to_string().ends_with("`; flags are `--name value`"),
                "{bad:?}: {err}"
            );
        }
        let err = generic_arguments(&strs(&["--k=1", "--k", "2"])).expect_err("repeated");
        assert_eq!(err.to_string(), "flag --k given more than once");
        assert!(generic_arguments(&[]).expect("empty").is_empty());
    }

    /// Tester — C11: only a non-empty relative string under `poc_path` or
    /// `path` at the top level is joined to `cwd` (`./x` and `~/x` included,
    /// verbatim); absolute, empty, null, numeric, nested and non-object
    /// values are untouched.
    #[test]
    fn tester_absolutize_touches_only_relative_nonempty_top_level_strings() {
        let mut v = serde_json::json!({
            "poc_path": "./x.yaml",
            "path": "~/y",
            "nested": {"path": "z"},
            "list": ["path"],
            "name": "q.yaml"
        });
        absolutize_paths(&mut v, Path::new("/w"));
        assert_eq!(
            v,
            serde_json::json!({
                "poc_path": "/w/./x.yaml",
                "path": "/w/~/y",
                "nested": {"path": "z"},
                "list": ["path"],
                "name": "q.yaml"
            })
        );
        let untouched = serde_json::json!({"poc_path": "/abs/x.yaml", "path": null, "other": 1});
        let mut same = untouched.clone();
        absolutize_paths(&mut same, Path::new("/w"));
        assert_eq!(same, untouched);
        let mut root = serde_json::json!({"path": "x"});
        absolutize_paths(&mut root, Path::new("/"));
        assert_eq!(root, serde_json::json!({"path": "/x"}));
        for mut other in [
            serde_json::json!("x.yaml"),
            serde_json::json!(null),
            serde_json::json!(["poc_path"]),
        ] {
            let before = other.clone();
            absolutize_paths(&mut other, Path::new("/w"));
            assert_eq!(other, before);
        }
    }

    /// Tester — D8 step 10 edges: zero bytes render as zero bytes; a nested
    /// object through `TypeDesc::Any` (a verb the registry lacks) prints the
    /// pretty JSON with sorted keys; a scalar through `Any` prints as the
    /// in-process path would; a bytes answer through `Any` is its base64
    /// text (the schema is unknown); shape mismatches are errors.
    #[test]
    fn tester_render_empty_bytes_and_any_values() {
        assert_eq!(
            render(&serde_json::json!(""), &TypeDesc::Bytes),
            Vec::<u8>::new()
        );
        let nested = serde_json::json!({"b": [1, {"c": null, "d": 2.5}], "a": "x", "e": true});
        assert_eq!(
            String::from_utf8(render(&nested, &TypeDesc::Any)).unwrap(),
            "{\n  \"a\": \"x\",\n  \"b\": [\n    1,\n    {\n      \"c\": null,\n      \"d\": 2.5\n    }\n  ],\n  \"e\": true\n}\n"
        );
        assert_eq!(
            render(&serde_json::json!("plain"), &TypeDesc::Any),
            b"plain\n"
        );
        assert_eq!(render(&serde_json::json!([]), &TypeDesc::Any), b"[]\n");
        assert_eq!(render(&serde_json::json!(null), &TypeDesc::Any), b"null\n");
        assert_eq!(
            render(&serde_json::json!("iVBORw=="), &TypeDesc::Any),
            b"iVBORw==\n"
        );
        assert_eq!(
            render(&serde_json::json!("iVBORw=="), &TypeDesc::Bytes),
            [0x89, 0x50, 0x4e, 0x47]
        );
        // Step 3: an answer the declared schema cannot explain is still
        // shown, structurally, never as an error against a healthy core.
        assert_eq!(render(&serde_json::json!(5), &TypeDesc::Bytes), b"5\n");
        assert_eq!(
            render(&serde_json::json!("not base64!"), &TypeDesc::Bytes),
            b"not base64!\n"
        );
        assert_eq!(
            render(
                &serde_json::json!({}),
                &TypeDesc::Array(Box::new(TypeDesc::Str))
            ),
            b"{}\n"
        );
        assert_eq!(render(&serde_json::json!("x"), &TypeDesc::Int), b"x\n");
    }

    /// Tester — `prepare` edges: `--yes` anywhere is stripped from the flags
    /// of a typed and an unresolved verb; a three-segment path is the dotted
    /// name; `--` alone is a path token (not a flag), so `aitm --` is an
    /// unknown command, and an empty argv is the usage line.
    #[test]
    fn tester_prepare_strips_yes_anywhere_and_treats_dashdash_as_a_word() {
        let registry = Registry::new();
        match prepare(&registry, &strs(&["--yes", "custom", "verb", "--k", "1"])) {
            Err(err) => assert!(
                err.to_string()
                    .starts_with("expected a command before flags, got `--yes`"),
                "{err}"
            ),
            Ok(other) => panic!("a leading --yes is a flag before the command: {other:?}"),
        }
        match prepare(
            &registry,
            &strs(&["a", "b", "c", "--yes", "--k", "1", "--yes"]),
        )
        .expect("unresolved")
        {
            Prepared::Unresolved { dotted, flags, yes } => {
                assert_eq!(dotted, "a.b.c");
                assert_eq!(flags, strs(&["--k", "1"]));
                assert!(yes);
            }
            Prepared::Typed { .. } => panic!("an empty registry knows nothing"),
        }
        let err = prepare(&registry, &strs(&["--"])).expect_err("-- alone");
        assert_eq!(
            err.to_string(),
            "unknown command `--`; run with no arguments to list commands"
        );
        let err = prepare(&registry, &[]).expect_err("empty argv");
        assert_eq!(err.to_string(), "usage: aitm <command> [--flag value]...");
        let err = prepare(&registry, &strs(&["-x"])).expect_err("single dash");
        assert_eq!(
            err.to_string(),
            "unknown command `-x`; run with no arguments to list commands"
        );
    }

    fn def(name: &str, ty: TypeDesc, required: bool) -> ParamDef {
        ParamDef {
            name: name.to_string(),
            ty,
            required,
            description: String::new(),
        }
    }

    /// Run `f` under a `DEBUG`-level subscriber writing to a buffer: what it
    /// returned, and every line it logged.
    fn capture_debug_log<T>(f: impl FnOnce() -> T) -> (T, String) {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("buf").extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let log = String::from_utf8(buf.0.lock().expect("buf").clone()).expect("utf8 log");
        (out, log)
    }

    /// Quality Q14: a declared `Object` with no fields means "some object"
    /// at any depth, not only at the top. `findings.list` and `poc.list`
    /// declare `Array(Object([]))` and answer free-form objects: the walker
    /// shows them structurally, so a healthy call never reaches the
    /// fallback and never logs its `debug!`.
    #[test]
    fn lenient_treats_an_empty_declared_object_as_some_object_at_any_depth() {
        let schema = TypeDesc::Array(Box::new(TypeDesc::Object(Vec::new())));
        let answer = serde_json::json!([
            {"id": "f1", "severity": "high", "evidence": {"url": "https://a/"}},
            {"id": "f2", "tags": ["x", "y"]}
        ]);
        assert!(
            from_json(&answer, &schema).is_err(),
            "strict refuses the undeclared keys"
        );
        let expected = structural(&answer);
        assert_eq!(
            lenient(&answer, &schema).expect("some object, at any depth"),
            expected
        );
        let (bytes, log) = capture_debug_log(|| render(&answer, &schema));
        assert_eq!(bytes, render_cli_value(&expected));
        assert_eq!(
            String::from_utf8(bytes).expect("utf8"),
            "[\n  {\n    \"evidence\": {\n      \"url\": \"https://a/\"\n    },\n    \"id\": \"f1\",\n    \
             \"severity\": \"high\"\n  },\n  {\n    \"id\": \"f2\",\n    \"tags\": [\n      \"x\",\n      \
             \"y\"\n    ]\n  }\n]\n"
        );
        assert!(
            !log.contains("does not fit the verb's declared result schema"),
            "a healthy call must not log the fallback: {log}"
        );

        // Under a declared field as well, beside an optional `null` the
        // walker keeps; and whatever kind the core answered for "some object"
        // (the old top-level rule showed it as is, this one still does).
        let nested = TypeDesc::Object(vec![
            def("items", schema.clone(), true),
            def("note", TypeDesc::Str, false),
        ]);
        let answer = serde_json::json!({"items": [{"a": 1}, {"b": [2]}], "note": null});
        assert_eq!(
            lenient(&answer, &nested).expect("nested"),
            Value::Object(BTreeMap::from([
                (
                    "items".to_string(),
                    structural(&serde_json::json!([{"a": 1}, {"b": [2]}]))
                ),
                ("note".to_string(), Value::Null),
            ]))
        );
        assert_eq!(
            lenient(&serde_json::json!([1]), &TypeDesc::Object(Vec::new())).expect("as is"),
            Value::Array(vec![Value::Int(1)])
        );
    }

    /// Spec D8 step 10 against a healthy core (tester defect, 2026-11-01):
    /// `proxy.status` and `config.get` declare `result: Object(Vec::new())`,
    /// "some object", and answer keys the schema never names. Step 2
    /// (`lenient`'s empty-object arm) renders the answer structurally,
    /// byte-identical to the local path.
    #[test]
    fn render_untyped_object_schema_accepts_undeclared_keys() {
        let answer =
            serde_json::json!({"address": "127.0.0.1:8080", "flows": 0, "capturing": true});
        assert_eq!(
            String::from_utf8(render(&answer, &TypeDesc::Object(Vec::new()))).unwrap(),
            "{\n  \"address\": \"127.0.0.1:8080\",\n  \"capturing\": true,\n  \"flows\": 0\n}\n"
        );
    }

    /// The second recorded shape: `capture.status` declares
    /// `provider.attached_at: Int, required: false` and the core answers
    /// `null`, which the strict `from_json` refuses. Step 2 keeps the `null`
    /// as `Value::Null`, so the line prints exactly as the local path prints
    /// the core's own `Value` (G6 parity).
    #[test]
    fn render_keeps_a_null_answered_for_a_nested_optional_int() {
        let schema = TypeDesc::Object(vec![
            def("state", TypeDesc::Str, true),
            def(
                "provider",
                TypeDesc::Object(vec![
                    def("state", TypeDesc::Str, true),
                    def("attached_at", TypeDesc::Int, false),
                ]),
                true,
            ),
        ]);
        let answer = serde_json::json!({"provider": {"attached_at": null, "state": "detached"}, "state": "on"});
        let remote = render(&answer, &schema);
        assert_eq!(
            String::from_utf8(remote.clone()).unwrap(),
            "{\n  \"provider\": {\n    \"attached_at\": null,\n    \"state\": \"detached\"\n  },\n  \"state\": \"on\"\n}\n"
        );
        let local = Value::Object(BTreeMap::from([
            (
                "provider".to_string(),
                Value::Object(BTreeMap::from([
                    ("attached_at".to_string(), Value::Null),
                    ("state".to_string(), Value::Str("detached".to_string())),
                ])),
            ),
            ("state".to_string(), Value::Str("on".to_string())),
        ]));
        assert_eq!(remote, render_cli_value(&local));
    }

    /// Quality Q4: the one walker keeps a declared-optional `null` at every
    /// depth (an object field, a field of an array item, a field of a map
    /// value), omits a missing optional field as the strict path does, and
    /// refuses what the strict path refuses for any other reason, so step 3
    /// decides those.
    #[test]
    fn lenient_keeps_optional_nulls_at_every_depth_and_refuses_the_rest() {
        let item = TypeDesc::Object(vec![
            def("n", TypeDesc::Int, false),
            def("s", TypeDesc::Str, true),
        ]);
        let schema = TypeDesc::Object(vec![
            def("one", item.clone(), true),
            def("many", TypeDesc::Array(Box::new(item.clone())), true),
            def("by_name", TypeDesc::Map(Box::new(item.clone())), false),
            def("note", TypeDesc::Str, false),
            def("absent", TypeDesc::Str, false),
        ]);
        let answer = serde_json::json!({
            "one": {"n": null, "s": "a"},
            "many": [{"n": 1, "s": "b"}, {"n": null, "s": "c"}],
            "by_name": {"k": {"n": null, "s": "d"}},
            "note": null
        });
        assert!(
            from_json(&answer, &schema).is_err(),
            "strict refuses a null"
        );
        let obj = |n: Value, s: &str| {
            Value::Object(BTreeMap::from([
                ("n".to_string(), n),
                ("s".to_string(), Value::Str(s.to_string())),
            ]))
        };
        let expected = Value::Object(BTreeMap::from([
            (
                "by_name".to_string(),
                Value::Object(BTreeMap::from([("k".to_string(), obj(Value::Null, "d"))])),
            ),
            (
                "many".to_string(),
                Value::Array(vec![obj(Value::Int(1), "b"), obj(Value::Null, "c")]),
            ),
            ("note".to_string(), Value::Null),
            ("one".to_string(), obj(Value::Null, "a")),
        ]));
        assert_eq!(lenient(&answer, &schema).expect("lenient"), expected);
        assert_eq!(rebuild_value(&answer, &schema), expected);
        for (label, refused) in [
            (
                "undeclared key",
                serde_json::json!({"one": {"n": 1, "s": "a"}, "many": [], "extra": 1}),
            ),
            ("missing required", serde_json::json!({"many": []})),
            (
                "null for a required field",
                serde_json::json!({"one": {"s": null}, "many": []}),
            ),
            (
                "wrong leaf type",
                serde_json::json!({"one": {"n": "x", "s": "a"}, "many": []}),
            ),
            (
                "null for an array item",
                serde_json::json!({"one": {"s": "a"}, "many": [null]}),
            ),
            ("not an object", serde_json::json!([1])),
        ] {
            assert!(lenient(&refused, &schema).is_err(), "{label}");
            // Step 3 shows it anyway, structurally.
            assert_eq!(
                rebuild_value(&refused, &schema),
                structural(&refused),
                "{label}"
            );
        }
        assert_eq!(json_kind(&serde_json::json!(null)), "null");
        assert_eq!(json_kind(&serde_json::json!(true)), "boolean");
        assert_eq!(json_kind(&serde_json::json!(1.5)), "number");
        assert_eq!(json_kind(&serde_json::json!("x")), "string");
        assert_eq!(json_kind(&serde_json::json!([])), "array");
        assert_eq!(json_kind(&serde_json::json!({})), "object");
    }

    /// Security S5 / quality Q4: the structural-fallback `debug!` names the
    /// declared schema and the answer's JSON kind, nothing else. A key the
    /// core chose (here one carrying a terminal escape) and the value under
    /// it never reach the log.
    #[test]
    fn fallback_debug_names_the_schema_and_kind_never_the_answer() {
        let schema = TypeDesc::Object(vec![def("state", TypeDesc::Str, true)]);
        let answer = serde_json::json!({"state": "on", "evil\u{1b}[2J": "secret-value"});
        let (bytes, log) = capture_debug_log(|| render(&answer, &schema));
        // Step 3 showed the answer as is: both keys are printed (S6: stdout is data).
        let shown = String::from_utf8(bytes).expect("utf8");
        assert!(shown.contains("\"state\": \"on\""), "{shown}");
        assert!(shown.contains("secret-value"), "{shown}");
        assert!(
            log.contains("does not fit the verb's declared result schema"),
            "{log}"
        );
        assert!(log.contains("kind=\"object\""), "{log}");
        assert!(log.contains("ty=Object("), "{log}");
        assert!(log.contains("name: \"state\""), "{log}");
        assert!(!log.contains("evil"), "{log}");
        assert!(!log.contains("secret-value"), "{log}");
        assert!(!log.contains('\u{1b}'), "{log}");
    }

    /// The strict path stays where it adds information: a `Bytes` result
    /// decodes from base64 to the raw bytes (the structural fallback would
    /// print the base64 text), and a `Bytes` field beside an optional `null`
    /// still decodes once the `null` is tolerated.
    #[test]
    fn render_bytes_still_decode_on_the_strict_path() {
        assert_eq!(
            render(&serde_json::json!("iVBORw=="), &TypeDesc::Bytes),
            [0x89, 0x50, 0x4e, 0x47]
        );
        let schema = TypeDesc::Object(vec![
            def("png", TypeDesc::Bytes, true),
            def("note", TypeDesc::Str, false),
        ]);
        let answer = serde_json::json!({"png": "iVBORw==", "note": null});
        assert_eq!(
            rebuild_value(&answer, &schema),
            Value::Object(BTreeMap::from([
                ("note".to_string(), Value::Null),
                (
                    "png".to_string(),
                    Value::Bytes(vec![0x89, b'P', b'N', b'G'])
                ),
            ]))
        );
    }
}
