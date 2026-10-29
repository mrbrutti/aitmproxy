//! `aitm web` (design §4.9 / F15): serve the embedded operator UI and the
//! `/bus` WebSocket bridge to the in-process command bus.
//!
//! - `assets`: the Vite build embedded by `build.rs`, plus routing over it.
//! - `http`: the hyper server and router.
//! - `bridge`: the RFC 6455 handshake and the line relay into `McpServer`.
//! - This module: the subcommand's arguments and their resolution.
//!
//! The bridge is deliberately thin. It authenticates with the same token line
//! `LoopbackTcp` uses and hands every line to `McpServer::handle`; all command
//! policy lives in the core. (The core still identifies these calls as
//! `Frontend::Mcp` — the `Operator` identity is F1.)

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

/// Shared by every connection: the bus to relay into and the token to demand.
pub struct WebState {
    pub mcp: Arc<McpServer>,
    pub token: String,
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

/// Log that `aitm web` is listening. Takes ONLY the bound address: the token is
/// the one bus-auth secret and lives in the URL fragment ([`ui_url`]), so it is
/// deliberately out of scope here and can never reach a tracing sink. The
/// operator gets the full link from the one-time `println!` in `main`, which is
/// not a logging sink, not from the logs.
pub fn log_listening(bound: SocketAddr) {
    tracing::info!(%bound, "web UI listening");
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
