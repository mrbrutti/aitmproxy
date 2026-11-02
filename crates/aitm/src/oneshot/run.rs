//! The one-shot entry point (spec D8): what the `Mode::Cli` arm of `main`
//! calls once the local host has booted. A **local** verb runs through
//! today's in-process `Cli::dispatch`; a **live** verb resolves the running
//! core, connects as the operator, runs there and renders the core's answer
//! through the same renderer. Every failure is an [`ErrorReport`] (the spec
//! D9 panels, with the `Log` footer) or the plain `anyhow` error today's
//! dispatcher raised (usage errors, aborts), for `main` to classify with
//! `report_for`. Nothing here exits the process (plan C7).
//!
//! The audit line a live verb leaves is the core's doing (spec D8 "Audit"):
//! the connection speaks as [`super::remote::CLIENT_NAME`] and the core
//! records origin `operator`, that label and the command.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aitm_cli::{Cli, TtyConfirmer};
use aitm_core::{Config, Params, TypeDesc};
use aitm_mcp::json::to_json;
use aitm_mcp::pointer::{self, CorePointer};
use aitm_term::error::ErrorReport;
use aitm_term::reporter::Reporter;
use serde_json::Value as JsonValue;

use super::args::BusArgs;
use super::refuse::{self, verb_words, CoreRef, TokenSource};
use super::remote::{self, Prepared, RemoteError};
use super::resolve::{self, Resolver, Source, Target, Warning};
use super::verbs::{budget, placement, Placement, HANDSHAKE_BUDGET};
use crate::render::render_cli_value;
use crate::tui::Services;

/// What `main` hands the one-shot: the verb's argv (the one-shot's own flags
/// already split out), the loaded config and where it came from, the local
/// host's services and `Cli`, the reporter, the log path and the environment.
pub struct Inputs<'a> {
    /// `Mode::Cli`'s argv: the verb and its flags, `--bus`/`--token-file`
    /// removed.
    pub argv: &'a [String],
    /// The one-shot's own flags (spec D7).
    pub bus_args: &'a BusArgs,
    /// The loaded config.
    pub cfg: &'a Config,
    /// The effective config path (`--config` → `AITM_CONFIG` → default).
    pub effective_path: &'a Path,
    /// Whether `--config`/`AITM_CONFIG` named the config.
    pub explicit_config: bool,
    /// The local host's service handles (its registry parses the flags).
    pub services: &'a Services,
    /// The in-process CLI a local verb runs through.
    pub cli: Cli,
    /// Where warnings and the call's phase go.
    pub reporter: &'a Reporter,
    /// The log file, for every panel's footer.
    pub log: Option<&'a Path>,
    /// The process environment, by variable name.
    pub env: &'a dyn Fn(&str) -> Option<String>,
}

/// Why a one-shot printed nothing: a panel to render as it is, or the plain
/// error today's dispatcher raised, for `report_for` to classify.
#[derive(Debug)]
pub enum OneShotError {
    /// A spec D9 panel (or a usage report), ready to render.
    Report(ErrorReport),
    /// A dispatcher, parser or confirmation error with today's words.
    Other(anyhow::Error),
}

/// Where a [`RemoteError`] happened; with the address's [`Source`] it
/// decides the spec D9 panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// `TcpTransport::connect`.
    Connect,
    /// `initialize` (and `tools/list` for a verb the registry lacks).
    Handshake,
    /// `tools/call`.
    Call,
}

/// What the panels need to name the core, the verb and the token's locator.
pub struct Site<'a> {
    /// The dotted verb.
    pub dotted: &'a str,
    /// The core that was dialed.
    pub target: &'a Target,
    /// The one-shot's own flags, for the token's locator (R7).
    pub bus_args: &'a BusArgs,
    /// The effective config path, named when the target has no config.
    pub effective_path: &'a Path,
    /// Whether `--config`/`AITM_CONFIG` named the config.
    pub explicit_config: bool,
    /// The verb's call budget (R10).
    pub budget: Duration,
    /// Epoch seconds now, for the ages R2 prints.
    pub now_unix: u64,
}

/// Run the one-shot: the rendered stdout bytes, or why there are none.
pub async fn run(i: Inputs<'_>) -> Result<Vec<u8>, OneShotError> {
    let prepared = remote::prepare(&i.services.registry, i.argv).map_err(OneShotError::Other)?;
    let dotted = prepared.dotted().to_string();
    match placement(&dotted) {
        Placement::Local => {
            // `--bus`/`--token-file` are ignored with one warning; a bare
            // `AITM_BUS` is ambient and ignored silently (spec D7).
            if i.bus_args.bus.is_some() || i.bus_args.token_file.is_some() {
                i.reporter
                    .warn(&warning_text(&Warning::BusIgnored(verb_words(&dotted))));
            }
            let value = i.cli.dispatch(i.argv).map_err(OneShotError::Other)?;
            Ok(render_cli_value(&value))
        }
        Placement::Live => run_live(&i, prepared, &dotted).await,
    }
}

/// Spec D8 steps 5–10 for a live verb.
async fn run_live(
    i: &Inputs<'_>,
    prepared: Prepared,
    dotted: &str,
) -> Result<Vec<u8>, OneShotError> {
    let log = || i.log.map(Path::to_path_buf);
    let run_dir = pointer::run_dir(i.env);
    let resolver = Resolver {
        env: i.env,
        liveness: &pointer::liveness,
        owner_uid: resolve::owner_uid(&run_dir),
        now_unix: now_unix(),
        run_dir,
    };
    let (target, warnings) = resolve::resolve(
        &resolver,
        i.bus_args,
        i.cfg,
        i.effective_path,
        i.explicit_config,
        dotted,
        i.argv,
    )
    .map_err(|report| OneShotError::Report(report.with_log(log())))?;
    for warning in &warnings {
        i.reporter.warn(&warning_text(warning));
    }

    let known = matches!(prepared, Prepared::Typed { .. });
    let yes = prepared.yes();
    let call_budget = budget(dotted, known);
    let site = Site {
        dotted,
        target: &target,
        bus_args: i.bus_args,
        effective_path: i.effective_path,
        explicit_config: i.explicit_config,
        budget: call_budget,
        now_unix: resolver.now_unix,
    };
    // The connect, `initialize` and (for a verb the registry lacks)
    // `tools/list` share one handshake budget (spec D8 step 6).
    let started = Instant::now();
    let remaining = || HANDSHAKE_BUDGET.saturating_sub(started.elapsed());
    let refuse_early = |err: RemoteError, stage: Stage| {
        let others = match (stage, &target.source) {
            (Stage::Call, _) => Vec::new(),
            (_, Source::ConfigPort) => resolve::live_pointers(&resolver)
                .iter()
                .map(|found| core_ref(&found.pointer))
                .collect(),
            _ => Vec::new(),
        };
        refusal(err, stage, &site, &others, log())
    };

    let client = match remote::connect(target.addr, &target.token, HANDSHAKE_BUDGET).await {
        Ok(client) => client,
        Err(err) => return Err(refuse_early(err, Stage::Connect)),
    };
    if let Err(err) = remote::handshake(&client, remaining()).await {
        return Err(refuse_early(err, Stage::Handshake));
    }

    let (mut args, result_ty) = match prepared {
        Prepared::Typed { cmd, params, .. } => (params_json(&params), cmd.schema().result),
        Prepared::Unresolved { dotted, flags, .. } => {
            let known_remotely =
                match remote::resolve_remote_name(&client, &dotted, remaining()).await {
                    Ok(known) => known,
                    Err(err) => return Err(refuse_early(err, Stage::Handshake)),
                };
            if !known_remotely {
                return Err(OneShotError::Other(anyhow::anyhow!(
                    "unknown command `{dotted}`; run with no arguments to list commands"
                )));
            }
            let map = remote::generic_arguments(&flags).map_err(OneShotError::Other)?;
            (JsonValue::Object(map), TypeDesc::Any)
        }
    };
    if let Ok(cwd) = std::env::current_dir() {
        remote::absolutize_paths(&mut args, &cwd);
    }

    let words = verb_words(dotted);
    let addr = target.addr;
    let confirmer = TtyConfirmer::from_stdin();
    let phase = i.reporter.phase(&format!("{words} · core {addr}"));
    let result = remote::call(&client, dotted, args, call_budget, &confirmer, yes).await;
    let result = phase
        .finish_with(result, |_| format!("{words} answered · core {addr}"))
        .map_err(|err| refusal(err, Stage::Call, &site, &[], log()))?;
    remote::render(&result, &result_ty).map_err(OneShotError::Other)
}

/// The spec D9 panel for `err` at `stage`, given where the address came from
/// (plan: the `Source`-aware mapping). `others` are the live pointers R2
/// names beside a configured port that refused. An abort or an unaskable
/// question is today's plain error instead ([`OneShotError::Other`]).
pub fn refusal(
    err: RemoteError,
    stage: Stage,
    site: &Site<'_>,
    others: &[CoreRef],
    log: Option<PathBuf>,
) -> OneShotError {
    let verb = site.dotted;
    let addr = site.target.addr;
    let config = site.target.config.as_deref().unwrap_or(site.effective_path);
    let report = match err {
        RemoteError::Timeout(_) => match stage {
            Stage::Call => refuse::no_answer(addr, Some(verb), site.budget),
            Stage::Connect | Stage::Handshake => refuse::no_answer(addr, None, HANDSHAKE_BUDGET),
        },
        RemoteError::Lost(detail) => match stage {
            Stage::Call => refuse::lost(addr, verb, &detail),
            Stage::Connect | Stage::Handshake => not_listening(site, config, others),
        },
        RemoteError::Refused => refuse::token_refused(addr, &token_source(site, config)),
        RemoteError::Agent => refuse::connected_as_agent(addr, config),
        RemoteError::Tool(text) if refuse::is_cli_only_gate(&text) => {
            refuse::cli_only_gate(&text, addr, config)
        }
        RemoteError::Tool(text) => refuse::tool_failure(&text),
        RemoteError::Rpc { message, .. } => ErrorReport::failure(message),
        RemoteError::Protocol(text) => ErrorReport::failure(text),
        RemoteError::Aborted(text) => return OneShotError::Other(anyhow::anyhow!(text)),
        RemoteError::Confirm(err) => return OneShotError::Other(err.context(verb.to_string())),
    };
    OneShotError::Report(report.with_log(log))
}

/// R2, R2', R3 or R4 by the address's source (spec D7 step 5).
fn not_listening(site: &Site<'_>, config: &Path, others: &[CoreRef]) -> ErrorReport {
    let verb = site.dotted;
    let addr = site.target.addr;
    match &site.target.source {
        Source::ExplicitFlag => refuse::not_listening_explicit(verb, addr, false),
        Source::ExplicitEnv => refuse::not_listening_explicit(verb, addr, true),
        Source::ConfigPort => refuse::not_listening_config_port(
            verb,
            addr,
            config,
            site.explicit_config,
            others,
            site.now_unix,
        ),
        Source::ConfigEndpointFile(endpoint_file) => {
            refuse::stale_endpoint_file(addr, endpoint_file, config, site.explicit_config)
        }
        Source::Pointer { path, pid, .. } => refuse::pointer_not_listening(verb, addr, path, *pid),
    }
}

/// Where the refused token came from (R7): `--token-file` or
/// `AITM_BUS_TOKEN` for an explicit address, else the config it was read from.
fn token_source(site: &Site<'_>, config: &Path) -> TokenSource {
    match site.target.source {
        Source::ExplicitFlag | Source::ExplicitEnv => match &site.bus_args.token_file {
            Some(path) => TokenSource::TokenFile(path.clone()),
            None => TokenSource::Env,
        },
        Source::ConfigPort | Source::ConfigEndpointFile(_) | Source::Pointer { .. } => {
            TokenSource::Config(config.to_path_buf())
        }
    }
}

/// A resolver warning as the operator reads it (spec D7).
pub fn warning_text(warning: &Warning) -> String {
    match warning {
        Warning::WideConfig(path) => format!(
            "{} is readable by other users · chmod 600 {}",
            path.display(),
            path.display()
        ),
        Warning::BusIgnored(verb) => {
            format!("--bus ignored · {verb} runs on this machine, not on a core")
        }
    }
}

/// Typed params as the `tools/call` arguments object.
fn params_json(params: &Params) -> JsonValue {
    JsonValue::Object(
        params
            .iter()
            .map(|(name, value)| (name.to_string(), to_json(value)))
            .collect(),
    )
}

/// A live pointer as a panel names it.
fn core_ref(ptr: &CorePointer) -> CoreRef {
    CoreRef {
        addr: ptr.bus,
        pid: Some(ptr.pid),
        started_unix: Some(ptr.started_unix),
        config: Some(ptr.config.clone()),
    }
}

/// Epoch seconds now; `0` on a clock before 1970.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::Value;
    use std::collections::BTreeMap;

    #[test]
    fn warning_texts_are_the_spec_sentences() {
        assert_eq!(
            warning_text(&Warning::WideConfig(PathBuf::from("/x/config.yaml"))),
            "/x/config.yaml is readable by other users · chmod 600 /x/config.yaml"
        );
        assert_eq!(
            warning_text(&Warning::BusIgnored("ca status".to_string())),
            "--bus ignored · ca status runs on this machine, not on a core"
        );
    }

    #[test]
    fn params_become_the_arguments_object() {
        let mut map = BTreeMap::new();
        map.insert("host".to_string(), Value::Str("example.com".to_string()));
        map.insert("n".to_string(), Value::Int(3));
        map.insert("raw".to_string(), Value::Bytes(vec![0x89, b'P']));
        assert_eq!(
            params_json(&Params::new(map)),
            serde_json::json!({"host": "example.com", "n": 3, "raw": "iVA="})
        );
    }

    #[test]
    fn a_confirm_failure_keeps_todays_context() {
        let target = Target {
            addr: "127.0.0.1:1".parse().expect("addr"),
            token: "optoken-test-x".to_string(),
            source: Source::ExplicitFlag,
            config: None,
        };
        let bus = BusArgs::default();
        let site = Site {
            dotted: "scope.add",
            target: &target,
            bus_args: &bus,
            effective_path: Path::new("/x/config.yaml"),
            explicit_config: false,
            budget: Duration::from_secs(30),
            now_unix: 0,
        };
        let err = refusal(
            RemoteError::Confirm(anyhow::anyhow!(
                "needs confirmation but stdin is not a terminal; pass --yes to confirm \
                 non-interactively"
            )),
            Stage::Call,
            &site,
            &[],
            None,
        );
        match err {
            OneShotError::Other(e) => {
                assert_eq!(e.to_string(), "scope.add");
                assert_eq!(
                    e.chain().nth(1).map(ToString::to_string).as_deref(),
                    Some(
                        "needs confirmation but stdin is not a terminal; pass --yes to confirm \
                         non-interactively"
                    )
                );
            }
            OneShotError::Report(r) => panic!("not a panel: {r:?}"),
        }
        // An explicit address without a config names the effective config in R8.
        match refusal(RemoteError::Agent, Stage::Handshake, &site, &[], None) {
            OneShotError::Report(r) => assert_eq!(
                r.why,
                vec![
                    "The token in /x/config.yaml is that core's agent token, not its operator \
                      token, and an agent may not change Scope. Nothing was changed."
                        .to_string()
                ]
            ),
            OneShotError::Other(e) => panic!("expected a panel: {e:#}"),
        }
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    const TOKEN: &str = "optoken-test-run";
    const LOG: &str = "/l/aitm.log";

    fn tty_100() -> aitm_term::caps::Caps {
        aitm_term::caps::Caps {
            tty: true,
            color: false,
            unicode: true,
            animate: true,
            width: 100,
            ci: false,
        }
    }

    fn sources() -> Vec<Source> {
        vec![
            Source::ExplicitFlag,
            Source::ExplicitEnv,
            Source::ConfigPort,
            Source::ConfigEndpointFile(PathBuf::from("/e/bus.addr")),
            Source::Pointer {
                path: PathBuf::from("/r/4821.json"),
                pid: 4821,
                started_unix: 0,
            },
        ]
    }

    fn errors() -> Vec<(RemoteError, Stage)> {
        vec![
            (RemoteError::Timeout(Duration::from_secs(30)), Stage::Call),
            (RemoteError::Timeout(Duration::from_secs(2)), Stage::Connect),
            (
                RemoteError::Timeout(Duration::from_millis(5)),
                Stage::Handshake,
            ),
            (
                RemoteError::Lost(remote::REFUSED.to_string()),
                Stage::Connect,
            ),
            (
                RemoteError::Lost("reset by peer".to_string()),
                Stage::Handshake,
            ),
            (RemoteError::Lost("eof".to_string()), Stage::Call),
            (RemoteError::Refused, Stage::Handshake),
            (RemoteError::Agent, Stage::Handshake),
            (
                RemoteError::Tool("x refused: y from an agent frontend is off".to_string()),
                Stage::Call,
            ),
            (RemoteError::Tool("plain failure".to_string()), Stage::Call),
            (
                RemoteError::Rpc {
                    code: -32601,
                    message: "no such method".to_string(),
                },
                Stage::Call,
            ),
            (RemoteError::Protocol("odd reply".to_string()), Stage::Call),
        ]
    }

    /// Tester — D10: no panel the entry point builds carries the token, for
    /// every `RemoteError` × `Stage` × `Source`, with and without a token
    /// file, rendered plain and rich and `Debug`; every panel gets the log
    /// footer; an abort and an unaskable question are plain errors without
    /// the token too.
    #[test]
    fn tester_refusals_never_carry_the_token() {
        let others = [CoreRef {
            addr: "127.0.0.1:50512".parse().expect("addr"),
            pid: Some(4821),
            started_unix: Some(0),
            config: Some(PathBuf::from("/y/c.yaml")),
        }];
        let bus_variants = [
            BusArgs::default(),
            BusArgs {
                bus: Some("127.0.0.1:1".to_string()),
                token_file: Some(PathBuf::from("/t/tok")),
            },
        ];
        let mut panels = 0;
        for source in sources() {
            let explicit = matches!(source, Source::ExplicitFlag | Source::ExplicitEnv);
            let target = Target {
                addr: "127.0.0.1:1".parse().expect("addr"),
                token: TOKEN.to_string(),
                source,
                config: (!explicit).then(|| PathBuf::from("/x/c.yaml")),
            };
            for bus in &bus_variants {
                let site = Site {
                    dotted: "tls.passthrough.add",
                    target: &target,
                    bus_args: bus,
                    effective_path: Path::new("/x/config.yaml"),
                    explicit_config: true,
                    budget: Duration::from_secs(600),
                    now_unix: 720,
                };
                for (err, stage) in errors() {
                    let label = format!("{err:?} at {stage:?} from {:?}", target.source);
                    match refusal(err, stage, &site, &others, Some(PathBuf::from(LOG))) {
                        OneShotError::Report(report) => {
                            assert_eq!(report.log, Some(PathBuf::from(LOG)), "{label}");
                            assert_eq!(report.exit_code(), 1, "{label}");
                            for text in [
                                report.render_plain(&aitm_term::glyphs::RICH),
                                report.render(&tty_100(), Some(Path::new("/Users/matt"))),
                                format!("{report:?}"),
                            ] {
                                assert!(!text.contains(TOKEN), "{label}: {text}");
                                assert!(!text.contains("optoken"), "{label}: {text}");
                            }
                            panels += 1;
                        }
                        OneShotError::Other(e) => panic!("{label}: expected a panel, got {e:#}"),
                    }
                }
                for err in [
                    RemoteError::Aborted("aborted: tls passthrough add not run".to_string()),
                    RemoteError::Confirm(anyhow::anyhow!("no terminal")),
                ] {
                    match refusal(err, Stage::Call, &site, &[], None) {
                        OneShotError::Other(e) => {
                            assert!(!format!("{e:#} {e:?}").contains("optoken"));
                        }
                        OneShotError::Report(r) => panic!("not a panel: {r:?}"),
                    }
                }
            }
        }
        assert_eq!(panels, 5 * 2 * 12);
    }

    /// Tester — the panels not pinned elsewhere: a JSON-RPC error other than
    /// `-32001` and a protocol complaint are bare `Failure` reports whose
    /// headline is the bus text, no why, no fix, the log footer on; a
    /// handshake timeout at the connect stage is the handshake form; a lost
    /// connection at the handshake stage is the not-listening family; R2
    /// from a configured port lists every other core it was given.
    #[test]
    fn tester_rpc_protocol_and_stage_mapping_edges() {
        let target = Target {
            addr: "127.0.0.1:9090".parse().expect("addr"),
            token: TOKEN.to_string(),
            source: Source::ConfigPort,
            config: Some(PathBuf::from("/x/c.yaml")),
        };
        let bus = BusArgs::default();
        let site = Site {
            dotted: "scope.list",
            target: &target,
            bus_args: &bus,
            effective_path: Path::new("/x/config.yaml"),
            explicit_config: false,
            budget: Duration::from_secs(30),
            now_unix: 1_000,
        };
        let report = |err, stage, others: &[CoreRef]| match refusal(
            err,
            stage,
            &site,
            others,
            Some(PathBuf::from(LOG)),
        ) {
            OneShotError::Report(r) => r,
            OneShotError::Other(e) => panic!("expected a panel: {e:#}"),
        };

        let rpc = report(
            RemoteError::Rpc {
                code: -32601,
                message: "no such method".to_string(),
            },
            Stage::Call,
            &[],
        );
        assert_eq!(rpc.what, "no such method");
        assert!(rpc.why.is_empty());
        assert_eq!(rpc.fix, None);
        assert_eq!(rpc.command, None);
        assert_eq!(rpc.log, Some(PathBuf::from(LOG)));

        let protocol = report(
            RemoteError::Protocol("reply to `tools/call` is not JSON".to_string()),
            Stage::Call,
            &[],
        );
        assert_eq!(protocol.what, "reply to `tools/call` is not JSON");
        assert!(protocol.why.is_empty());

        let connect_timeout = report(
            RemoteError::Timeout(Duration::from_secs(2)),
            Stage::Connect,
            &[],
        );
        assert_eq!(
            connect_timeout.what,
            "the core at 127.0.0.1:9090 accepted the connection but did not answer within 2 s"
        );

        let two_others = [
            CoreRef {
                addr: "127.0.0.1:50512".parse().expect("addr"),
                pid: Some(1),
                started_unix: Some(1_000 - 60),
                config: Some(PathBuf::from("/a.yaml")),
            },
            CoreRef {
                addr: "127.0.0.1:50513".parse().expect("addr"),
                pid: Some(2),
                started_unix: Some(1_000),
                config: Some(PathBuf::from("/b.yaml")),
            },
        ];
        let lost = report(
            RemoteError::Lost("reset by peer".to_string()),
            Stage::Handshake,
            &two_others,
        );
        assert_eq!(lost.what, "no running core at 127.0.0.1:9090");
        assert_eq!(lost.why.len(), 3, "{:?}", lost.why);
        assert_eq!(
            lost.why[0],
            "/x/c.yaml sets mcp.transport.loopback_tcp.port 9090, but nothing is listening there, so scope list has nothing to change. Nothing was changed."
        );
        assert_eq!(
            lost.why[1],
            "A different core is running at 127.0.0.1:50512 (pid 1, started 1 min ago, config /a.yaml); pass --bus 127.0.0.1:50512 to use it."
        );
        assert_eq!(
            lost.why[2],
            "A different core is running at 127.0.0.1:50513 (pid 2, started just now, config /b.yaml); pass --bus 127.0.0.1:50513 to use it."
        );
        assert_eq!(lost.command.as_ref().map(|c| c.0.as_str()), Some("aitm"));
    }

    /// Tester — the wide-config warning and the bus-ignored warning are the
    /// only two; `warning_text` prints a path with a space unquoted (the
    /// reporter sanitizes, never quotes) and the verb in its space form.
    #[test]
    fn tester_warning_texts_edges() {
        assert_eq!(
            warning_text(&Warning::WideConfig(PathBuf::from(
                "/Users/matt/Library/Application Support/aitmproxy/config.yaml"
            ))),
            "/Users/matt/Library/Application Support/aitmproxy/config.yaml is readable by other users · chmod 600 /Users/matt/Library/Application Support/aitmproxy/config.yaml"
        );
        assert_eq!(
            warning_text(&Warning::BusIgnored(verb_words("proxy.system.unset"))),
            "--bus ignored · proxy system unset runs on this machine, not on a core"
        );
    }
}
