//! `aitm web` (design §4.9 / F15): serve the embedded operator UI and the
//! `/bus` WebSocket bridge to the in-process command bus.
//!
//! - `assets`: the Vite build embedded by `build.rs`, plus routing over it.
//! - `http`: the hyper server and router.
//! - `bridge`: the RFC 6455 handshake and the line relay into `McpServer`.
//! - This module: the subcommand's arguments and their resolution.
//!
//! The bridge is deliberately thin. It authenticates with the same token line
//! `LoopbackTcp` uses, classifies that token against the two bridge tokens in
//! [`WebState`] to resolve the connection's role, and hands every line to
//! `McpServer::handle_on` under that role; all command policy lives in the core.
//! An operator bridge token exists only when `mcp.operator_token` is configured;
//! otherwise the bridge is agent-only (`Frontend::Mcp`).
//!
//! The `McpServer` in [`WebState`] is agent-facing: the agent bridge token
//! resolves to `Frontend::Mcp`, so it is subject to the agent policy gate and
//! the audit ring like any other agent. Build it with
//! `tui::with_shared_governance`, so it reads the policy `agent.set` writes and
//! records into the ring `agent.activity` reads. The `Ask` approval hub is not
//! shared with the primary server; see `tui::with_shared_governance`.

pub mod assets;
pub mod bridge;
pub mod http;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use aitm_mcp::McpServer;

pub use http::{router, serve, serve_until};

/// Default bind address for `aitm web`.
/// 8080 is the proxy and 8081 the embedded browser's dedicated proxy port
/// (`BrowserConfig::proxy_addr`), so the web UI takes the next one.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8082";
/// Overrides the default bind address when `--listen` is absent.
pub const LISTEN_ENV: &str = "AITM_WEB_LISTEN";
/// Supplies the token when `--token` is absent.
pub const TOKEN_ENV: &str = "AITM_WEB_TOKEN";
/// Set to `1` to allow a non-loopback bind without TLS (warned, not refused).
pub const INSECURE_BIND_ENV: &str = "AITM_WEB_INSECURE_BIND";

/// Usage text for `aitm web --help`.
pub const USAGE: &str = "\
Usage: aitm [--config <path>] web [--listen <addr>] [--token <token>] [--no-open]

Run the proxy (as `aitm` does) and also serve the web operator UI.

Options:
  --listen <addr>   Bind address for the UI and its /bus bridge
                    [default: 127.0.0.1:8082; env: AITM_WEB_LISTEN]
  --token <token>   Bridge token the UI must present as its first message
                    [default: generated; env: AITM_WEB_TOKEN]
  --no-open         Do not open a browser (accepted; nothing is opened yet)
  -h, --help        Print this help

Non-loopback addresses are refused until TLS for remote access lands (F15);
use an SSH tunnel, or set AITM_WEB_INSECURE_BIND=1 to bind anyway.
";

/// Shared by every connection: the bus to relay into and the bridge tokens to
/// demand. Both tokens are the bridge's own ephemeral per-run tokens, NOT the
/// mcp agent/operator tokens (those never travel to the browser). A first-line
/// match on `agent_token` resolves the connection to [`aitm_core::Frontend::Mcp`];
/// a match on `operator_token` (when configured) to
/// [`aitm_core::Frontend::Operator`].
pub struct WebState {
    pub mcp: Arc<McpServer>,
    /// The agent bridge token, always present.
    pub agent_token: String,
    /// The operator bridge token; `Some` only when `mcp.operator_token` is
    /// configured (operator role exists at all). `None` ⇒ the web UI is
    /// agent-only, exactly as before this change.
    pub operator_token: Option<String>,
    /// Rate-limiter for the bad-token refusal warn, shared across every
    /// connection via the `Arc`-shared `WebState` so a stale tab reconnecting
    /// across connections logs at most one line per [`bridge::BAD_TOKEN_WINDOW`].
    pub bad_token_throttle: bridge::BadTokenThrottle,
}

/// `aitm web …` after argument parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebCommand {
    /// `--help`: print [`USAGE`] and exit.
    Help,
    /// Run the server with these (unresolved) options.
    Run(WebArgs),
}

/// Raw `aitm web` options before environment and defaults are applied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebArgs {
    pub listen: Option<String>,
    pub token: Option<String>,
    pub no_open: bool,
}

/// Parse the arguments after `web`.
pub fn parse_args(args: &[String]) -> anyhow::Result<WebCommand> {
    let mut out = WebArgs::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(WebCommand::Help),
            "--no-open" => out.no_open = true,
            "--listen" => out.listen = Some(value_of(&mut it, "--listen")?),
            "--token" => out.token = Some(value_of(&mut it, "--token")?),
            other => {
                if let Some(v) = other.strip_prefix("--listen=") {
                    out.listen = Some(v.to_owned());
                } else if let Some(v) = other.strip_prefix("--token=") {
                    out.token = Some(v.to_owned());
                } else {
                    anyhow::bail!("unknown argument to `aitm web`: {other}\n\n{USAGE}");
                }
            }
        }
    }
    Ok(WebCommand::Run(out))
}

fn value_of<'a>(it: &mut impl Iterator<Item = &'a String>, flag: &str) -> anyhow::Result<String> {
    it.next()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a value"))
}

/// Resolved `aitm web` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSettings {
    pub listen: SocketAddr,
    pub token: String,
    /// `true` when the bind is off-loopback and was allowed by
    /// [`INSECURE_BIND_ENV`]; the caller warns.
    pub insecure_bind: bool,
}

impl WebArgs {
    /// Apply the environment (`env(name)`) and defaults; generate a token when
    /// none is given; refuse a non-loopback bind unless explicitly allowed.
    pub fn resolve(&self, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<WebSettings> {
        let listen = self
            .listen
            .clone()
            .or_else(|| env(LISTEN_ENV))
            .unwrap_or_else(|| DEFAULT_LISTEN.to_owned());
        let listen: SocketAddr = listen
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --listen address {listen:?}: {e}"))?;
        let insecure_bind = if is_loopback(listen.ip()) {
            false
        } else if env(INSECURE_BIND_ENV).as_deref() == Some("1") {
            true
        } else {
            anyhow::bail!(
                "refusing to bind the web UI on {listen}: TLS for remote access is not \
                 available yet (F15); use an SSH tunnel to 127.0.0.1, or set \
                 {INSECURE_BIND_ENV}=1 to bind anyway"
            );
        };
        let token = match self.token.clone().or_else(|| env(TOKEN_ENV)) {
            Some(t) if !t.trim().is_empty() => t,
            Some(_) => anyhow::bail!("the web token must not be empty"),
            None => generate_token(),
        };
        Ok(WebSettings {
            listen,
            token,
            insecure_bind,
        })
    }
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// 64 hex characters: two v4 UUIDs in simple form.
pub fn generate_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// The URL the operator opens: the token travels in the fragment, which the
/// browser never sends to the server; the UI moves it into sessionStorage.
pub fn ui_url(bound: SocketAddr, token: &str) -> String {
    format!("http://{bound}/#t={token}")
}

/// The URL that connects as an operator: like [`ui_url`] but with an
/// `expect=operator` fragment the UI checks against the resolved role (a
/// client-side expectation only, never sent to the server). `token` is the
/// ephemeral operator *bridge* token, not the mcp operator token.
pub fn operator_ui_url(bound: SocketAddr, token: &str) -> String {
    format!("http://{bound}/#t={token}&expect=operator")
}

/// Log that `aitm web` is listening. Takes ONLY the bound address: the token is
/// the one bus-auth secret and lives in the URL fragment ([`ui_url`]), so it is
/// deliberately out of scope here and can never reach a tracing sink. The
/// operator gets the full link from the one-time `println!` in `main`, which is
/// not a logging sink, not from the logs.
pub fn log_listening(bound: SocketAddr) {
    tracing::info!(%bound, "web UI listening");
}

/// One legible, prominent startup block for `aitm web`, printed to **stdout**
/// (never a tracing sink). It is the operator's first-run map: the Web UI URL
/// (with its `#t=` token), the Operator URL when operator access is configured,
/// the proxy and browser/obscura listen addresses, and the bus state.
///
/// The URLs carry the bus token *on purpose* — this is stdout, which the
/// operator reads to open the UI; the token is the one bus-auth secret and must
/// stay here, out of every logging sink (see [`log_listening`], which omits it).
/// Labels are padded so every value lines up in one column.
///
/// `advice` is the one decrypt-advice sentence
/// ([`aitm_core::NOTHING_DECRYPTED_ADVICE`]) when Scope is empty at launch (spec
/// D8): printed as its own `Scope` line, and omitted entirely when `None`.
pub fn startup_summary(
    web_url: &str,
    operator_url: Option<&str>,
    proxy: SocketAddr,
    browser: SocketAddr,
    bus: &str,
    advice: Option<&str>,
) -> String {
    use std::fmt::Write as _;
    let rule = "─".repeat(60);
    let mut out = String::new();
    // Writing into the owned `String` is infallible, so the `writeln!` results are
    // discarded deliberately.
    let _ = writeln!(out, "{rule}");
    let _ = writeln!(out, "  aitm web");
    let _ = writeln!(out, "{rule}");
    let _ = writeln!(out, "  Web UI     {web_url}");
    if let Some(op) = operator_url {
        let _ = writeln!(out, "  Operator   {op}");
    }
    let _ = writeln!(out, "  Proxy      {proxy}");
    let _ = writeln!(out, "  Browser    {browser}  (SSRF-filtered)");
    let _ = writeln!(out, "  Bus        {bus}");
    if let Some(advice) = advice {
        let _ = writeln!(out, "  Scope      {advice}");
    }
    out.push_str(&rule);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn help_flag_wins() {
        assert_eq!(parse_args(&args(&["--help"])).unwrap(), WebCommand::Help);
        assert_eq!(
            parse_args(&args(&["--listen", "x", "-h"])).unwrap(),
            WebCommand::Help
        );
    }

    #[test]
    fn flags_parse_in_both_forms() {
        let WebCommand::Run(a) = parse_args(&args(&[
            "--listen",
            "127.0.0.1:9000",
            "--token=abc",
            "--no-open",
        ]))
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(a.listen.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(a.token.as_deref(), Some("abc"));
        assert!(a.no_open);
        let WebCommand::Run(b) = parse_args(&args(&[
            "--listen=127.0.0.1:9000",
            "--token",
            "abc",
            "--no-open",
        ]))
        .unwrap() else {
            panic!("expected Run");
        };
        assert_eq!(a, b);
    }

    #[test]
    fn bad_arguments_are_errors() {
        assert!(parse_args(&args(&["--listen"])).is_err());
        assert!(parse_args(&args(&["--bogus"])).is_err());
        assert!(parse_args(&args(&["extra"])).is_err());
    }

    #[test]
    fn defaults_bind_loopback_and_generate_a_token() {
        let s = WebArgs::default().resolve(no_env).unwrap();
        assert_eq!(s.listen, DEFAULT_LISTEN.parse::<SocketAddr>().unwrap());
        assert_eq!(s.token.len(), 64);
        assert!(s.token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!s.insecure_bind);
        assert_ne!(s.token, WebArgs::default().resolve(no_env).unwrap().token);
    }

    #[test]
    fn env_fills_in_listen_and_token() {
        let env = |k: &str| match k {
            LISTEN_ENV => Some("127.0.0.2:1234".to_owned()),
            TOKEN_ENV => Some("tok".to_owned()),
            _ => None,
        };
        let s = WebArgs::default().resolve(env).unwrap();
        assert_eq!(s.listen, "127.0.0.2:1234".parse::<SocketAddr>().unwrap());
        assert_eq!(s.token, "tok");
        // Flags beat the environment.
        let a = WebArgs {
            listen: Some("[::1]:1".into()),
            token: Some("flag".into()),
            no_open: false,
        };
        let s = a.resolve(env).unwrap();
        assert_eq!(s.listen, "[::1]:1".parse::<SocketAddr>().unwrap());
        assert_eq!(s.token, "flag");
    }

    #[test]
    fn non_loopback_bind_is_refused_unless_opted_in() {
        let a = WebArgs {
            listen: Some("0.0.0.0:8081".into()),
            ..Default::default()
        };
        let err = a.resolve(no_env).unwrap_err().to_string();
        assert!(
            err.contains("TLS for remote access is not available yet (F15)"),
            "{err}"
        );
        assert!(err.contains("SSH tunnel"), "{err}");
        let s = a
            .resolve(|k| (k == INSECURE_BIND_ENV).then(|| "1".to_owned()))
            .unwrap();
        assert!(s.insecure_bind);
    }

    #[test]
    fn empty_token_is_an_error_and_bad_listen_is_an_error() {
        let a = WebArgs {
            token: Some("  ".into()),
            ..Default::default()
        };
        assert!(a.resolve(no_env).is_err());
        let a = WebArgs {
            listen: Some("nope".into()),
            ..Default::default()
        };
        assert!(a.resolve(no_env).is_err());
    }

    #[test]
    fn ui_url_carries_the_token_in_the_fragment() {
        let url = ui_url("127.0.0.1:8081".parse().unwrap(), "abc");
        assert_eq!(url, "http://127.0.0.1:8081/#t=abc");
    }

    #[test]
    fn operator_ui_url_adds_the_expect_operator_fragment() {
        let url = operator_ui_url("127.0.0.1:8082".parse().unwrap(), "deadbeef");
        assert_eq!(url, "http://127.0.0.1:8082/#t=deadbeef&expect=operator");
    }

    /// AC3: the one startup summary block carries every endpoint the operator
    /// needs — the Web UI URL (with its token), the proxy and browser listen
    /// addresses, and the bus state — and the Operator URL only when configured.
    #[test]
    fn startup_summary_lists_every_endpoint() {
        // With an operator URL configured, it appears on its own line.
        let s = startup_summary(
            "http://127.0.0.1:8082/#t=deadbeef",
            Some("http://127.0.0.1:8082/#t=optok&expect=operator"),
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            "ready",
            None,
        );
        assert!(s.contains("http://127.0.0.1:8082/#t=deadbeef"), "{s}");
        assert!(s.contains("127.0.0.1:8080"), "{s}");
        assert!(s.contains("127.0.0.1:8081"), "{s}");
        assert!(s.contains("ready"), "{s}");
        assert!(
            s.contains("http://127.0.0.1:8082/#t=optok&expect=operator"),
            "{s}"
        );

        // Without an operator URL, the block still carries every other field
        // and never mentions the operator fragment.
        let s = startup_summary(
            "http://127.0.0.1:8082/#t=deadbeef",
            None,
            "127.0.0.1:8080".parse().unwrap(),
            "127.0.0.1:8081".parse().unwrap(),
            "ready",
            None,
        );
        assert!(s.contains("http://127.0.0.1:8082/#t=deadbeef"), "{s}");
        assert!(s.contains("127.0.0.1:8080"), "{s}");
        assert!(s.contains("127.0.0.1:8081"), "{s}");
        assert!(!s.contains("expect=operator"), "{s}");
    }

    /// AC13: the startup summary carries the one decrypt-advice sentence as its own
    /// `Scope` line exactly when the caller hands it one (an empty Scope at launch),
    /// and no `Scope` line at all otherwise. The summary prints the sentence, it
    /// never composes it: `main` passes `aitm_core::NOTHING_DECRYPTED_ADVICE`.
    #[test]
    fn startup_summary_prints_the_advice_only_when_given() {
        let advice = "Nothing is decrypted until a host is in Scope.";
        let proxy: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let browser: SocketAddr = "127.0.0.1:8081".parse().unwrap();

        let with = startup_summary(
            "http://127.0.0.1:8082/#t=deadbeef",
            None,
            proxy,
            browser,
            "ready",
            Some(advice),
        );
        assert!(
            with.lines()
                .any(|l| l == "  Scope      Nothing is decrypted until a host is in Scope."),
            "{with}"
        );
        assert_eq!(with.matches(advice).count(), 1, "said once: {with}");

        let without = startup_summary(
            "http://127.0.0.1:8082/#t=deadbeef",
            None,
            proxy,
            browser,
            "ready",
            None,
        );
        assert!(!without.contains("Scope"), "{without}");
        assert!(!without.contains(advice), "{without}");
        // The advice is one extra line; everything else is the same block.
        assert_eq!(with.lines().count(), without.lines().count() + 1);
        assert!(with.starts_with(&without[..without.rfind('\n').unwrap()]));
    }

    /// C4 regression: the "listening" log carries the bound address but never
    /// the bus token, even though the operator URL for the same bind does.
    #[test]
    fn log_listening_never_carries_the_token() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl tracing_subscriber::fmt::MakeWriter<'_> for Buf {
            type Writer = Buf;
            fn make_writer(&self) -> Buf {
                self.clone()
            }
        }

        // A stand-in secret shaped like a real token (64 hex chars).
        let token = "deadbeefcafebabe".repeat(4);
        let bound: SocketAddr = "127.0.0.1:8082".parse().unwrap();
        // The operator URL does carry the token; the log must not.
        assert!(ui_url(bound, &token).contains(&token));

        let sink = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Buf(sink.clone()))
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || log_listening(bound));

        let logged = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("web UI listening"), "{logged}");
        assert!(logged.contains("127.0.0.1:8082"), "{logged}");
        assert!(!logged.contains(&token), "token leaked into logs: {logged}");
    }
}
