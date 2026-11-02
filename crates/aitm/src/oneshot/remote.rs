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

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use aitm_bus_client::{BusClient, BusError, ServerInfo, TcpTransport};
use aitm_cli::dispatch::parse_flags;
use aitm_cli::Confirmer;
use aitm_core::{Command, Params, Registry, TypeDesc};
use aitm_mcp::json::from_json;
use aitm_term::text::sanitize;
use serde_json::{Map, Value as JsonValue};

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
pub const REFUSED: &str = "refused";
/// The `Str` arguments a live verb reads as paths on the core's machine; a
/// relative value means the operator's directory (plan C11, research F24a).
pub const PATH_ARGUMENTS: &[&str] = &["poc_path", "path"];

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
        None => anyhow::bail!("unknown command `{dotted}`; run with no arguments to list commands"),
    }
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
/// where the address came from, which [`super::run`] knows.
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

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteError::Timeout(d) => write!(f, "no answer within {} ms", d.as_millis()),
            RemoteError::Refused => f.write_str("the core refused the operator token"),
            RemoteError::Lost(detail) => write!(f, "connection lost: {detail}"),
            RemoteError::Agent => f.write_str("the core would treat this connection as an agent"),
            RemoteError::Tool(text) => f.write_str(text),
            RemoteError::Rpc { code, message } => write!(f, "bus rpc error {code}: {message}"),
            RemoteError::Protocol(text) => write!(f, "bus protocol error: {text}"),
            RemoteError::Aborted(text) => f.write_str(text),
            RemoteError::Confirm(err) => write!(f, "{err:#}"),
        }
    }
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
/// step 10, decision (f)): `from_json` rebuilds the `Value` `ty` describes
/// (bytes from base64), then [`render_cli_value`] prints it.
pub fn render(result: &JsonValue, ty: &TypeDesc) -> anyhow::Result<Vec<u8>> {
    let value = from_json(result, ty)?;
    Ok(render_cli_value(&value))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
