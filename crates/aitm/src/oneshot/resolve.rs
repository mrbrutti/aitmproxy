//! Resolving the running core and its operator token (spec D7 precedence).
//!
//! A live verb needs an address to dial and the operator token that address
//! accepts. [`resolve`] finds both, in the spec's order: an explicit `--bus`
//! or `AITM_BUS` (step 1), the loaded config's own loopback transport
//! (step 2), then the pointers serving cores publish under `run/cores`
//! (step 3). The dial itself and what its failures mean (R2/R2'/R3/R4/R7/R8)
//! belong to the remote path; this module returns the [`Target`] to dial or
//! the refusal that made dialing pointless (R1, R5, R6, R11, R15 and the
//! usage errors).
//!
//! A pointer is dialed only when its writer still holds the advisory lock
//! ([`live_pointers`]): one whose lock is free is deleted before any byte is
//! sent, so the operator token never reaches a port a dead core's address
//! may have been recycled to (spec D4, D10). A pointer the trust rules reject
//! is skipped and never deleted. A token is read from a config file only
//! when that file is a regular file owned by this user
//! ([`read_operator_token`], spec D7 rule 6); it never appears in a log, a
//! `Debug` or an error.

use std::fmt;
use std::fs::{self, DirBuilder};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use aitm_core::{Config, McpTransport};
use aitm_mcp::pointer::{self, CorePointer, Found, Liveness};
use aitm_term::error::ErrorReport;
use tracing::debug;

use super::args::{check_loopback, needs_token, parse_bus, token_file_needs_bus, BusArgs};
use super::refuse::{self, CoreRef};
use crate::config_file;
use crate::startup::errors::report_for;

/// The explicit address, the TUI's name (spec D7 decision (a)).
const BUS_ENV: &str = "AITM_BUS";
/// The explicit token, the TUI's name.
const BUS_TOKEN_ENV: &str = "AITM_BUS_TOKEN";

/// What [`resolve`] reads the world through. Production passes the real
/// environment, [`aitm_mcp::pointer::liveness`], [`owner_uid`] of the run dir
/// and the clock; the unit tests inject closures (plan rule 2, C3).
pub struct Resolver<'a> {
    /// The process environment, by variable name.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// Whether a pointer's writer still holds its lock.
    pub liveness: &'a dyn Fn(&Path) -> Liveness,
    /// The uid every trusted pointer and token-bearing config must be owned
    /// by, as a function of the run dir: the owner of the user's own run dir
    /// (plan rule 7). Called only when the pointer directory is consulted
    /// (step 3), so an explicit address or a configured transport neither
    /// creates nor reads it. Production passes [`owner_uid`].
    pub owner_uid: &'a dyn Fn(&Path) -> u32,
    /// Epoch seconds now, for the ages the panels print.
    pub now_unix: u64,
    /// The pointer directory, `run/cores`.
    pub run_dir: PathBuf,
}

/// Where the resolved address came from; the dial's refusals depend on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `--bus <host:port>`.
    ExplicitFlag,
    /// `AITM_BUS`.
    ExplicitEnv,
    /// The loaded config's `mcp.transport.loopback_tcp.port`.
    ConfigPort,
    /// The loaded config's `endpoint_file`, whose content named the address.
    ConfigEndpointFile(PathBuf),
    /// A live core pointer.
    Pointer {
        /// The pointer file.
        path: PathBuf,
        /// The core's pid, as the pointer says.
        pid: u32,
        /// When its bus bound, as the pointer says.
        started_unix: u64,
    },
}

/// The core to dial. `Debug` redacts the token.
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    /// The operator bus address; always loopback.
    pub addr: SocketAddr,
    /// The operator token to present. Never format, log or print it.
    pub token: String,
    /// Where `addr` came from.
    pub source: Source,
    /// The config file the token was read from: the effective config for a
    /// configured transport, the pointer's `config` for a pointer, `None` for
    /// an explicit address.
    pub config: Option<PathBuf>,
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target")
            .field("addr", &self.addr)
            .field("token", &format_args!("<redacted>"))
            .field("source", &self.source)
            .field("config", &self.config)
            .finish()
    }
}

/// Something the operator should hear once, on stderr, without stopping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// The token-bearing config has a group or other permission bit (spec D7
    /// rule 6): `<path> is readable by other users · chmod 600 <path>`.
    WideConfig(PathBuf),
    /// `--bus` was given with a local verb (the space form): `--bus ignored ·
    /// <verb> runs on this machine, not on a core`. Raised by the entry
    /// point, declared here with its sibling.
    BusIgnored(String),
}

/// Why a token-bearing config yielded no token (spec D7 rule 6, plan C12).
#[derive(Debug)]
pub enum TokenProblem {
    /// Not a regular file after following symlinks (R15).
    NotRegular,
    /// Not owned by the run dir's owner (R15).
    Foreign,
    /// Its metadata could not be read.
    Unreadable(std::io::Error),
    /// `config_file::load` refused it.
    Parse(anyhow::Error),
}

/// Find the core a live verb should dial and the token to present (spec D7
/// steps 1–3 and 6; step 5, the dial and its refusals, is the remote path's).
///
/// 1. `--bus` or `AITM_BUS` wins; the token is `--token-file`'s content, else
///    `AITM_BUS_TOKEN`; nothing else is consulted.
/// 2. A loopback transport in `cfg` names its `endpoint_file`'s address when
///    that file holds a loopback address, else `127.0.0.1:<port>` when the
///    port is fixed; the token is `cfg.mcp.operator_token` or **R6**.
/// 3. Otherwise the live pointers under `r.run_dir`: the ones whose `config`
///    is `effective_path` (both canonicalized) are preferred; one candidate
///    is dialed, two or more are **R11**, none is **R1** (**R5** when `cfg`
///    opts out of the operator bus over stdio or HTTP). The token is read
///    from the pointer's config (**R15** when that is not this user's regular
///    file); `operator: false` or no token is **R6**.
///
/// `dotted` is the verb (`scope.add`) and `argv` the one-shot's arguments as
/// typed, both for the panels only.
#[expect(
    clippy::result_large_err,
    reason = "the plan pins the ErrorReport return"
)]
pub fn resolve(
    r: &Resolver<'_>,
    bus: &BusArgs,
    cfg: &Config,
    effective_path: &Path,
    explicit_config: bool,
    dotted: &str,
    argv: &[String],
) -> Result<(Target, Vec<Warning>), ErrorReport> {
    // Step 1: an explicit address consults nothing else.
    let explicit = match (&bus.bus, env_value(r, BUS_ENV)) {
        (Some(text), _) => Some((text.clone(), Source::ExplicitFlag)),
        (None, Some(text)) => Some((text, Source::ExplicitEnv)),
        (None, None) => None,
    };
    if let Some((text, source)) = explicit {
        let addr = parse_bus(&text).map_err(ErrorReport::usage)?;
        check_loopback(addr)?;
        let token = match &bus.token_file {
            Some(path) => {
                aitm_bus_client::read_token_file(path).map_err(|err| report_for(&err, None))?
            }
            None => env_value(r, BUS_TOKEN_ENV).ok_or_else(needs_token)?,
        };
        return Ok((
            Target {
                addr,
                token,
                source,
                config: None,
            },
            Vec::new(),
        ));
    }
    if bus.token_file.is_some() {
        return Err(token_file_needs_bus());
    }

    // Step 2: the loaded config's own loopback transport.
    if let Some((addr, source)) = configured_address(&cfg.mcp.transport) {
        let token = cfg
            .mcp
            .operator_token
            .as_deref()
            .filter(|token| !token.is_empty());
        let Some(token) = token else {
            return Err(refuse::no_operator_token(
                addr,
                effective_path,
                effective_path.exists(),
            ));
        };
        return Ok((
            Target {
                addr,
                token: token.to_string(),
                source,
                config: Some(effective_path.to_path_buf()),
            },
            Vec::new(),
        ));
    }

    // Step 3: the live pointers, preferring the effective config's own. The
    // run dir is consulted (created `0700` when absent) only from here on.
    let owner_uid = (r.owner_uid)(&r.run_dir);
    let live = live_pointers_owned_by(r, owner_uid);
    let wanted = canonical(effective_path);
    let preferred: Vec<&Found> = live
        .iter()
        .filter(|found| canonical(&found.pointer.config) == wanted)
        .collect();
    let candidates = if preferred.is_empty() {
        live.iter().collect()
    } else {
        preferred
    };
    let chosen = match candidates.as_slice() {
        [] => {
            return Err(nothing_found_or_opt_out(
                cfg,
                effective_path,
                &r.run_dir,
                explicit_config,
                dotted,
            ));
        }
        [one] => *one,
        many => {
            // Canonical paths on both sides, as the preference above compared
            // them, so a tie among symlinked configs reads "Both", not "Neither".
            let cores: Vec<CoreRef> = many
                .iter()
                .map(|found| CoreRef {
                    config: Some(canonical(&found.pointer.config)),
                    ..core_ref(&found.pointer)
                })
                .collect();
            return Err(refuse::two_cores(dotted, &cores, &wanted, r.now_unix, argv));
        }
    };

    // Step 6: the token from the pointer's config; `operator: false` first,
    // so an agent-only bus is refused before any file is read.
    let ptr = &chosen.pointer;
    if !ptr.operator {
        return Err(refuse::no_operator_token(
            ptr.bus,
            &ptr.config,
            ptr.config.exists(),
        ));
    }
    let (token, warning) = match read_operator_token(&ptr.config, owner_uid) {
        Ok(read) => read,
        Err(TokenProblem::NotRegular | TokenProblem::Foreign) => {
            return Err(refuse::foreign_config(&ptr.config));
        }
        Err(TokenProblem::Unreadable(err)) => {
            let err = anyhow::Error::new(err)
                .context(format!("reading config file {}", ptr.config.display()));
            return Err(report_for(&err, None));
        }
        Err(TokenProblem::Parse(err)) => return Err(report_for(&err, None)),
    };
    let Some(token) = token else {
        return Err(refuse::no_operator_token(ptr.bus, &ptr.config, true));
    };
    Ok((
        Target {
            addr: ptr.bus,
            token,
            source: Source::Pointer {
                path: chosen.path.clone(),
                pid: ptr.pid,
                started_unix: ptr.started_unix,
            },
            config: Some(ptr.config.clone()),
        },
        warning.into_iter().collect(),
    ))
}

/// A non-empty environment variable; an empty one is unset, as the TUI reads
/// `AITM_BUS`.
fn env_value(r: &Resolver<'_>, key: &str) -> Option<String> {
    (r.env)(key).filter(|value| !value.is_empty())
}

/// Spec D7 step 2: a loopback transport's address, from its `endpoint_file`
/// when that holds a loopback address, else `127.0.0.1:<port>` when the port
/// is fixed. `None` for a stdio or HTTP transport, or an ephemeral port with
/// no usable endpoint file: step 3 decides.
fn configured_address(transport: &McpTransport) -> Option<(SocketAddr, Source)> {
    let McpTransport::LoopbackTcp {
        port,
        endpoint_file,
        ..
    } = transport
    else {
        return None;
    };
    if let Some(path) = endpoint_file {
        if let Some(addr) = endpoint_address(path) {
            return Some((addr, Source::ConfigEndpointFile(path.clone())));
        }
    }
    (*port != 0).then(|| {
        (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *port),
            Source::ConfigPort,
        )
    })
}

/// The endpoint file's content as a loopback address; `None` when the file
/// is missing, does not parse, or names another interface.
fn endpoint_address(path: &Path) -> Option<SocketAddr> {
    let text = fs::read_to_string(path).ok()?;
    let addr: SocketAddr = text.trim().parse().ok()?;
    addr.ip().is_loopback().then_some(addr)
}

/// **R1**, or **R5** when the loaded config opts out of the operator bus over
/// a transport a second client cannot reach (stdio or HTTP). A loopback
/// transport carries operator access itself, so its opt-out is still R1.
fn nothing_found_or_opt_out(
    cfg: &Config,
    effective_path: &Path,
    run_dir: &Path,
    explicit_config: bool,
    dotted: &str,
) -> ErrorReport {
    let transport_word = match &cfg.mcp.transport {
        McpTransport::Stdio => Some("stdio"),
        McpTransport::StreamableHttp { .. } => Some("HTTP"),
        McpTransport::LoopbackTcp { .. } => None,
    };
    match transport_word {
        Some(word) if !cfg.mcp.operator_bus.enabled => {
            refuse::no_operator_bus_configured(effective_path, word)
        }
        _ => refuse::nothing_found(dotted, effective_path, run_dir, explicit_config),
    }
}

/// The path with symlinks resolved, or as given when it does not exist.
fn canonical(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// A pointer as a panel names it.
fn core_ref(ptr: &CorePointer) -> CoreRef {
    CoreRef {
        addr: ptr.bus,
        pid: Some(ptr.pid),
        started_unix: Some(ptr.started_unix),
        config: Some(ptr.config.clone()),
    }
}

/// Read `mcp.operator_token` from `path` (spec D7 rule 6, plan C12): follow
/// symlinks, then the target must be a regular file
/// ([`TokenProblem::NotRegular`]) owned by `owner_uid`
/// ([`TokenProblem::Foreign`]); a group or other permission bit is one
/// [`Warning::WideConfig`] and the read proceeds. The parse is
/// `config_file::load`, side-effect free. An empty token is `None`.
pub fn read_operator_token(
    path: &Path,
    owner_uid: u32,
) -> Result<(Option<String>, Option<Warning>), TokenProblem> {
    let meta = fs::metadata(path).map_err(TokenProblem::Unreadable)?;
    if !meta.is_file() {
        return Err(TokenProblem::NotRegular);
    }
    if meta.uid() != owner_uid {
        return Err(TokenProblem::Foreign);
    }
    let warning = (meta.mode() & 0o077 != 0).then(|| Warning::WideConfig(path.to_path_buf()));
    let cfg = config_file::load(Some(path)).map_err(TokenProblem::Parse)?;
    let token = cfg.mcp.operator_token.filter(|token| !token.is_empty());
    Ok((token, warning))
}

/// The pointers under `r.run_dir` worth considering: trusted
/// ([`pointer::scan`]), parsed, and with a writer that still holds the lock
/// or a probe that could not tell ([`Liveness::Unknown`] counts as alive,
/// plan C3). A pointer whose lock is free is deleted, with one `debug!`; an
/// untrusted one is skipped, with one `debug!`, and never deleted.
pub fn live_pointers(r: &Resolver<'_>) -> Vec<Found> {
    live_pointers_owned_by(r, (r.owner_uid)(&r.run_dir))
}

/// [`live_pointers`] with the run dir's owner already known, so `resolve`
/// consults the dir once for the scan and the token read alike.
fn live_pointers_owned_by(r: &Resolver<'_>, owner_uid: u32) -> Vec<Found> {
    pointer::scan(&r.run_dir, owner_uid)
        .into_iter()
        .filter_map(|entry| {
            let found = match entry {
                Ok(found) => found,
                Err((path, problem)) => {
                    debug!(path = %path.display(), ?problem, "skipping an untrusted core pointer");
                    return None;
                }
            };
            match (r.liveness)(&found.path) {
                Liveness::Alive | Liveness::Unknown => Some(found),
                Liveness::Dead => {
                    debug!(
                        path = %found.path.display(),
                        pid = found.pointer.pid,
                        "removing a stale core pointer; its writer no longer holds the lock"
                    );
                    pointer::remove(&found.path);
                    None
                }
            }
        })
        .collect()
}

/// The uid every pointer and token-bearing config must be owned by: the owner
/// of `run_dir`, created `0700` when absent (plan rule 7). When the directory
/// can be neither created nor read, `u32::MAX`, which no file is owned by, so
/// nothing is trusted.
pub fn owner_uid(run_dir: &Path) -> u32 {
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    if let Err(err) = builder.create(run_dir) {
        debug!(path = %run_dir.display(), %err, "could not create the core pointer dir");
    }
    match fs::metadata(run_dir) {
        Ok(meta) => meta.uid(),
        Err(err) => {
            debug!(path = %run_dir.display(), %err, "could not read the core pointer dir; trusting nothing");
            u32::MAX
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_term::error::{ErrorKind, FixCommand};
    use std::cell::Cell;
    use std::fs::{self, File, Permissions};
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    const NOW: u64 = 1_762_000_000;
    /// A pointer's `started_unix` twelve minutes before `NOW`.
    const STARTED: u64 = NOW - 720;

    /// A unique empty temp directory for one test, removed by the test. The
    /// path is canonical (`/tmp` is a symlink on macOS), so the paths a
    /// panel prints after canonicalizing equal the ones the tests build.
    fn temp_root(tag: &str) -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aitm-oneshot-resolve-t8-{}-{n}-{tag}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp root");
        fs::canonicalize(&dir).expect("canonical temp root")
    }

    fn lo(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn args(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    /// An environment of exactly these variables.
    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |key| {
            pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.to_string())
        }
    }

    fn resolver<'a>(
        env: &'a dyn Fn(&str) -> Option<String>,
        liveness: &'a dyn Fn(&Path) -> Liveness,
        cores: &Path,
    ) -> Resolver<'a> {
        Resolver {
            env,
            liveness,
            owner_uid: &owner_uid,
            now_unix: NOW,
            run_dir: cores.to_path_buf(),
        }
    }

    /// A config with a loopback transport; `operator_token` as given.
    fn loopback_cfg(port: u16, endpoint_file: Option<PathBuf>, token: Option<&str>) -> Config {
        let mut cfg = Config::default();
        cfg.mcp.transport = McpTransport::LoopbackTcp {
            port,
            token: "agent-token-test".to_string(),
            endpoint_file,
        };
        cfg.mcp.operator_token = token.map(str::to_string);
        cfg
    }

    fn ptr(pid: u32, port: u16, config: &Path) -> CorePointer {
        CorePointer {
            v: 1,
            pid,
            bus: lo(port),
            operator: true,
            config: config.to_path_buf(),
            started_unix: STARTED,
            version: "0.5.11".to_string(),
        }
    }

    /// A pointer file nobody locks, at `mode`.
    fn write_unlocked(cores: &Path, line: &str, name: &str, mode: u32) -> PathBuf {
        fs::create_dir_all(cores).expect("cores dir");
        let path = cores.join(name);
        File::create(&path)
            .expect("create pointer")
            .write_all(line.as_bytes())
            .expect("write pointer");
        fs::set_permissions(&path, Permissions::from_mode(mode)).expect("chmod pointer");
        path
    }

    /// A config file holding only `mcp.operator_token: <token>`, at `mode`.
    fn write_config(path: &Path, token: &str, mode: u32) {
        fs::write(path, format!("mcp:\n  operator_token: {token}\n")).expect("write config");
        fs::set_permissions(path, Permissions::from_mode(mode)).expect("chmod config");
    }

    fn what(result: Result<(Target, Vec<Warning>), ErrorReport>) -> ErrorReport {
        match result {
            Err(report) => report,
            Ok((target, _)) => panic!("expected a refusal, resolved {target:?}"),
        }
    }

    #[test]
    fn explicit_flag_wins_and_needs_a_token() {
        let root = temp_root("explicit");
        let cores = root.join("cores");
        let tfile = root.join("token");
        fs::write(&tfile, "optoken-test-flag\n").expect("token file");
        fs::set_permissions(&tfile, Permissions::from_mode(0o600)).expect("chmod token file");
        // A config that step 2 would resolve on its own; the flag must win.
        let cfg = loopback_cfg(9090, None, Some("optoken-test-cfg"));
        let config = root.join("config.yaml");
        let argv = args(&["scope", "list"]);
        let r = resolver(&no_env, &pointer::liveness, &cores);

        let flag = BusArgs {
            bus: Some("127.0.0.1:1".to_string()),
            token_file: Some(tfile.clone()),
        };
        let (target, warnings) = resolve(&r, &flag, &cfg, &config, false, "scope.list", &argv)
            .expect("explicit flag resolves");
        assert_eq!(target.addr, lo(1));
        assert_eq!(target.token, "optoken-test-flag");
        assert_eq!(target.source, Source::ExplicitFlag);
        assert_eq!(target.config, None);
        assert_eq!(warnings, Vec::<Warning>::new());
        // The token never reaches a `Debug`.
        let debug = format!("{target:?}");
        assert!(debug.contains("<redacted>"), "{debug}");
        assert!(!debug.contains("optoken-test"), "{debug}");
        assert!(debug.contains("127.0.0.1:1"), "{debug}");

        // `--bus` without `--token-file` and no `AITM_BUS_TOKEN`: a usage error.
        let bare = BusArgs {
            bus: Some("127.0.0.1:1".to_string()),
            token_file: None,
        };
        let report = what(resolve(
            &r,
            &bare,
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(
            report.what,
            "--bus needs --token-file <path> or AITM_BUS_TOKEN"
        );
        assert_eq!(report.command, Some(FixCommand("aitm --help".to_string())));

        // `--bus` with the token from the environment.
        let token_env = env_of(&[("AITM_BUS_TOKEN", "optoken-test-env")]);
        let r_token_env = resolver(&token_env, &pointer::liveness, &cores);
        let (target, _) = resolve(
            &r_token_env,
            &bare,
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        )
        .expect("flag with env token");
        assert_eq!(target.addr, lo(1));
        assert_eq!(target.token, "optoken-test-env");
        assert_eq!(target.source, Source::ExplicitFlag);

        // `AITM_BUS` + `AITM_BUS_TOKEN`, no flags.
        let both = env_of(&[
            ("AITM_BUS", "127.0.0.1:2"),
            ("AITM_BUS_TOKEN", "optoken-test-env"),
        ]);
        let r_env = resolver(&both, &pointer::liveness, &cores);
        let (target, warnings) = resolve(
            &r_env,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        )
        .expect("env resolves");
        assert_eq!(target.addr, lo(2));
        assert_eq!(target.token, "optoken-test-env");
        assert_eq!(target.source, Source::ExplicitEnv);
        assert_eq!(target.config, None);
        assert_eq!(warnings, Vec::<Warning>::new());

        // `AITM_BUS` with `--token-file`: the file is the token, the env the address.
        let bus_env = env_of(&[("AITM_BUS", "127.0.0.1:3")]);
        let r_bus_env = resolver(&bus_env, &pointer::liveness, &cores);
        let file_only = BusArgs {
            bus: None,
            token_file: Some(tfile.clone()),
        };
        let (target, _) = resolve(
            &r_bus_env,
            &file_only,
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        )
        .expect("env address with file token");
        assert_eq!(target.addr, lo(3));
        assert_eq!(target.token, "optoken-test-flag");
        assert_eq!(target.source, Source::ExplicitEnv);

        // `AITM_BUS` alone is a usage error too, and an empty one is unset.
        let report = what(resolve(
            &r_bus_env,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(
            report.what,
            "--bus needs --token-file <path> or AITM_BUS_TOKEN"
        );
        let empty_env = env_of(&[("AITM_BUS", ""), ("AITM_BUS_TOKEN", "")]);
        let r_empty = resolver(&empty_env, &pointer::liveness, &cores);
        let (target, _) = resolve(
            &r_empty,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        )
        .expect("empty env falls through to the config");
        assert_eq!(target.source, Source::ConfigPort);

        // `--token-file` without an address.
        let report = what(resolve(
            &r,
            &file_only,
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(
            report.what,
            "--token-file needs --bus <host:port> or AITM_BUS"
        );

        // Off-loopback and unparsable addresses are usage errors.
        let off = BusArgs {
            bus: Some("10.0.0.5:9090".to_string()),
            token_file: Some(tfile.clone()),
        };
        let report = what(resolve(&r, &off, &cfg, &config, false, "scope.list", &argv));
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.what, "--bus 10.0.0.5:9090 is not a loopback address");
        let bad = BusArgs {
            bus: Some("nonsense".to_string()),
            token_file: Some(tfile.clone()),
        };
        let report = what(resolve(&r, &bad, &cfg, &config, false, "scope.list", &argv));
        assert_eq!(report.kind, ErrorKind::Usage);
        assert_eq!(report.what, "--bus nonsense: invalid socket address syntax");

        // A token file that cannot be read is a failure naming the file, never the token.
        let missing = BusArgs {
            bus: Some("127.0.0.1:1".to_string()),
            token_file: Some(root.join("absent")),
        };
        let report = what(resolve(
            &r,
            &missing,
            &cfg,
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(
            report.what,
            format!(
                "reading the bus token file {}",
                root.join("absent").display()
            )
        );
        assert!(!report.why.is_empty(), "{report:?}");

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn config_port_and_endpoint_file() {
        let root = temp_root("config");
        let cores = root.join("cores");
        let config = root.join("config.yaml");
        fs::write(&config, "listen: 127.0.0.1:18080\n").expect("config file");
        let argv = args(&["scope", "add", "--host", "x"]);
        let r = resolver(&no_env, &pointer::liveness, &cores);

        // A fixed port and a token.
        let cfg = loopback_cfg(9090, None, Some("optoken-test-cfg"));
        let (target, warnings) = resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        )
        .expect("config port resolves");
        assert_eq!(target.addr, lo(9090));
        assert_eq!(target.token, "optoken-test-cfg");
        assert_eq!(target.source, Source::ConfigPort);
        assert_eq!(target.config, Some(config.clone()));
        assert_eq!(warnings, Vec::<Warning>::new());

        // An endpoint file wins over the port.
        let epath = root.join("bus.addr");
        fs::write(&epath, "127.0.0.1:60680\n").expect("endpoint file");
        let cfg = loopback_cfg(9090, Some(epath.clone()), Some("optoken-test-cfg"));
        let (target, _) = resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        )
        .expect("endpoint file resolves");
        assert_eq!(target.addr, lo(60680));
        assert_eq!(target.source, Source::ConfigEndpointFile(epath.clone()));
        assert_eq!(target.config, Some(config.clone()));

        // A missing, unparsable or off-loopback endpoint file falls back to the port.
        let cfg = loopback_cfg(9090, Some(root.join("gone.addr")), Some("optoken-test-cfg"));
        let (target, _) = resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        )
        .expect("missing endpoint file falls back");
        assert_eq!(target.addr, lo(9090));
        assert_eq!(target.source, Source::ConfigPort);
        fs::write(&epath, "not an address\n").expect("garbage endpoint file");
        let cfg = loopback_cfg(9090, Some(epath.clone()), Some("optoken-test-cfg"));
        let (target, _) = resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        )
        .expect("garbage endpoint file falls back");
        assert_eq!(target.source, Source::ConfigPort);
        fs::write(&epath, "10.0.0.5:1\n").expect("off-loopback endpoint file");
        let cfg = loopback_cfg(9090, Some(epath.clone()), Some("optoken-test-cfg"));
        let (target, _) = resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        )
        .expect("off-loopback endpoint file falls back");
        assert_eq!(target.source, Source::ConfigPort);
        assert_eq!(target.addr, lo(9090));

        // No operator token: R6, naming the address and the config.
        let cfg = loopback_cfg(9090, None, None);
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(
            report.what,
            "the core at 127.0.0.1:9090 has no operator token"
        );
        assert_eq!(
            report.why,
            vec![format!(
                "{} sets no mcp.operator_token, so a one-shot could only connect as an agent, and an agent may not change Scope. Nothing was changed.",
                config.display()
            )]
        );
        assert_eq!(
            report.command,
            Some(FixCommand("aitm operator-token generate".to_string()))
        );
        let cfg = loopback_cfg(9090, None, Some(""));
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        ));
        assert_eq!(
            report.what,
            "the core at 127.0.0.1:9090 has no operator token"
        );

        // An ephemeral port with no endpoint file gives no address: step 3, and
        // with no pointer, R1.
        let cfg = loopback_cfg(0, None, Some("optoken-test-cfg"));
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &cfg,
            &config,
            false,
            "scope.add",
            &argv,
        ));
        assert_eq!(report.what, "no running core found");

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn pointer_dir_prefers_the_matching_config_and_deletes_the_dead() {
        let root = temp_root("pointers");
        let cores = root.join("cores");
        let cfg_a = root.join("a.yaml");
        let cfg_b = root.join("b.yaml");
        write_config(&cfg_a, "optoken-test-a", 0o600);
        write_config(&cfg_b, "optoken-test-b", 0o600);

        // Dead: a `0600` pointer nobody locks (its writer is gone).
        let dead = write_unlocked(
            &cores,
            &ptr(100, 50511, &cfg_a).to_json_line(),
            "100.json",
            0o600,
        );
        // Live, started from the effective config: the one to dial.
        let matching = pointer::write(&cores, &ptr(200, 50512, &cfg_a)).expect("write matching");
        // Live, started from another config: ignored while a match exists.
        let other = pointer::write(&cores, &ptr(300, 50513, &cfg_b)).expect("write other");
        assert!(dead.exists());

        let argv = args(&["scope", "add", "--host", "x"]);
        let r = resolver(&no_env, &pointer::liveness, &cores);
        let (target, warnings) = resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_a,
            false,
            "scope.add",
            &argv,
        )
        .expect("the matching pointer resolves");
        assert_eq!(target.addr, lo(50512));
        assert_eq!(target.token, "optoken-test-a");
        assert_eq!(
            target.source,
            Source::Pointer {
                path: cores.join("200.json"),
                pid: 200,
                started_unix: STARTED,
            }
        );
        assert_eq!(target.config, Some(cfg_a.clone()));
        assert_eq!(warnings, Vec::<Warning>::new());

        assert!(!dead.exists(), "the dead pointer is deleted");
        assert!(matching.path.exists(), "the dialed pointer is kept");
        assert!(other.path.exists(), "the other live pointer is kept");

        // No match: the one live pointer is dialed, with the other config's token.
        drop(matching);
        let cfg_c = root.join("c.yaml");
        write_config(&cfg_c, "optoken-test-c", 0o600);
        let (target, _) = resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_c,
            false,
            "scope.add",
            &argv,
        )
        .expect("the single live pointer resolves");
        assert_eq!(target.addr, lo(50513));
        assert_eq!(target.token, "optoken-test-b");
        assert_eq!(target.config, Some(cfg_b.clone()));

        // `operator: false` is R6 before any token is read.
        drop(other);
        let mut agent_only = ptr(400, 50514, &cfg_b);
        agent_only.operator = false;
        let _agent_only = pointer::write(&cores, &agent_only).expect("write agent-only");
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_b,
            false,
            "scope.add",
            &argv,
        ));
        assert_eq!(
            report.what,
            "the core at 127.0.0.1:50514 has no operator token"
        );
        assert_eq!(
            report.command,
            Some(FixCommand("aitm operator-token generate".to_string()))
        );

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn two_matching_pointers_refuse() {
        let root = temp_root("two");
        let cores = root.join("cores");
        let cfg_a = root.join("a.yaml");
        let cfg_b = root.join("b.yaml");
        write_config(&cfg_a, "optoken-test-a", 0o600);
        write_config(&cfg_b, "optoken-test-b", 0o600);
        let _one = pointer::write(&cores, &ptr(200, 50512, &cfg_a)).expect("write one");
        let _two = pointer::write(&cores, &ptr(300, 50513, &cfg_a)).expect("write two");

        let argv = args(&["scope", "add", "--host", "x"]);
        let r = resolver(&no_env, &pointer::liveness, &cores);
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_a,
            false,
            "scope.add",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.what, "two running cores found");
        assert_eq!(
            report.why,
            vec![
                format!(
                    "127.0.0.1:50512 · pid 200 · started 12 min ago · {}",
                    cfg_a.display()
                ),
                format!(
                    "127.0.0.1:50513 · pid 300 · started 12 min ago · {}",
                    cfg_a.display()
                ),
                format!(
                    "Both were started from {}, so aitm cannot tell which one scope add means. Nothing was changed.",
                    cfg_a.display()
                ),
            ]
        );
        assert_eq!(
            report.command,
            Some(FixCommand(
                "aitm --bus <addr> scope add --host x".to_string()
            ))
        );

        // Neither matches the effective config: still a tie, worded so.
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_b,
            false,
            "scope.add",
            &argv,
        ));
        assert_eq!(report.what, "two running cores found");
        assert_eq!(
            report.why[2],
            format!(
                "Neither was started from {}, so aitm cannot tell which one scope add means. Nothing was changed.",
                cfg_b.display()
            )
        );

        // A third pointer that matches breaks the tie in its favour.
        let _three = pointer::write(&cores, &ptr(400, 50514, &cfg_b)).expect("write three");
        let (target, _) = resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_b,
            false,
            "scope.add",
            &argv,
        )
        .expect("the one matching pointer wins");
        assert_eq!(target.addr, lo(50514));
        assert_eq!(target.token, "optoken-test-b");

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Two live pointers whose `config` is a symlinked path to the effective
    /// config: the preference compares canonical paths, so both tie; the
    /// panel must say so in canonical terms too ("Both", not "Neither").
    #[test]
    fn symlinked_config_tie_reads_both() {
        let root = temp_root("symlink-tie");
        let cores = root.join("cores");
        let real = root.join("real");
        fs::create_dir_all(&real).expect("real dir");
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink the config dir");
        let real_cfg = real.join("a.yaml");
        write_config(&real_cfg, "optoken-test-a", 0o600);
        let linked_cfg = link.join("a.yaml");
        let _one = pointer::write(&cores, &ptr(200, 50512, &linked_cfg)).expect("write one");
        let _two = pointer::write(&cores, &ptr(300, 50513, &linked_cfg)).expect("write two");

        let argv = args(&["scope", "list"]);
        let r = resolver(&no_env, &pointer::liveness, &cores);
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &real_cfg,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.what, "two running cores found");
        let canonical_cfg = fs::canonicalize(&real_cfg).expect("canonical config");
        assert_eq!(
            report.why,
            vec![
                format!(
                    "127.0.0.1:50512 · pid 200 · started 12 min ago · {}",
                    canonical_cfg.display()
                ),
                format!(
                    "127.0.0.1:50513 · pid 300 · started 12 min ago · {}",
                    canonical_cfg.display()
                ),
                format!(
                    "Both were started from {}, so aitm cannot tell which one scope list means. Nothing was changed.",
                    canonical_cfg.display()
                ),
            ]
        );
        assert!(report.why[2].contains("Both were started from"));

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn nothing_found_and_opt_out() {
        let root = temp_root("nothing");
        let cores = root.join("cores");
        let config = root.join("config.yaml");
        let argv = args(&["scope", "list"]);
        let r = resolver(&no_env, &pointer::liveness, &cores);

        // The default config (stdio, operator bus on), an empty pointer dir: R1.
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(report.what, "no running core found");
        assert_eq!(
            report.why,
            vec![format!(
                "Looked for a core started from {} and for any core published under {}; none is running, so scope list has nothing to change. Nothing was changed.",
                config.display(),
                cores.display()
            )]
        );
        assert_eq!(report.command, Some(FixCommand("aitm".to_string())));
        let explicit = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &config,
            true,
            "scope.list",
            &argv,
        ));
        assert_eq!(
            explicit.command,
            Some(FixCommand(format!("aitm --config {}", config.display())))
        );

        // A pointer dir that does not exist is as empty.
        let r_missing = Resolver {
            run_dir: root.join("absent"),
            ..resolver(&no_env, &pointer::liveness, &cores)
        };
        let report = what(resolve(
            &r_missing,
            &BusArgs::default(),
            &Config::default(),
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.what, "no running core found");

        // The opt-out over stdio: R5.
        let mut opted_out = Config::default();
        opted_out.mcp.operator_bus.enabled = false;
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &opted_out,
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(
            report.what,
            "this config serves MCP over stdio and no operator bus, which a second client cannot reach"
        );
        assert_eq!(
            report.why,
            vec![format!(
                "{} sets mcp.operator_bus.enabled: false, so a core started from it has no address a one-shot can dial. Nothing was changed.",
                config.display()
            )]
        );
        assert_eq!(report.command, None);

        // Over HTTP the headline says so.
        let mut http = Config::default();
        http.mcp.operator_bus.enabled = false;
        http.mcp.transport = McpTransport::streamable_http_default("agent-token-test".to_string());
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &http,
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(
            report.what,
            "this config serves MCP over HTTP and no operator bus, which a second client cannot reach"
        );

        // An opted-out loopback transport on an ephemeral port is not R5: that
        // transport carries operator access itself, so the panel is R1.
        let mut loopback = loopback_cfg(0, None, Some("optoken-test-cfg"));
        loopback.mcp.operator_bus.enabled = false;
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &loopback,
            &config,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.what, "no running core found");

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn read_operator_token_warns_on_wide_modes() {
        let root = temp_root("token");
        let cores = root.join("cores");
        let uid = owner_uid(&cores);

        let wide = root.join("wide.yaml");
        write_config(&wide, "optoken-test-wide", 0o644);
        let (token, warning) = read_operator_token(&wide, uid).expect("a wide config reads");
        assert_eq!(token.as_deref(), Some("optoken-test-wide"));
        assert_eq!(warning, Some(Warning::WideConfig(wide.clone())));

        let group = root.join("group.yaml");
        write_config(&group, "optoken-test-group", 0o640);
        let (token, warning) =
            read_operator_token(&group, uid).expect("a group-readable config reads");
        assert_eq!(token.as_deref(), Some("optoken-test-group"));
        assert_eq!(warning, Some(Warning::WideConfig(group.clone())));

        let tight = root.join("tight.yaml");
        write_config(&tight, "optoken-test-tight", 0o600);
        let (token, warning) = read_operator_token(&tight, uid).expect("a 0600 config reads");
        assert_eq!(token.as_deref(), Some("optoken-test-tight"));
        assert_eq!(warning, None);

        // Symlinks are followed (dotfile managers); the target decides.
        let link = root.join("link.yaml");
        std::os::unix::fs::symlink(&tight, &link).expect("symlink");
        let (token, warning) = read_operator_token(&link, uid).expect("a symlink reads");
        assert_eq!(token.as_deref(), Some("optoken-test-tight"));
        assert_eq!(warning, None);

        // A directory is not a regular file.
        let dir = root.join("dir.yaml");
        fs::create_dir(&dir).expect("dir");
        assert!(matches!(
            read_operator_token(&dir, uid),
            Err(TokenProblem::NotRegular)
        ));

        // Another uid's file is foreign.
        assert!(matches!(
            read_operator_token(&tight, uid.wrapping_add(1)),
            Err(TokenProblem::Foreign)
        ));

        // No key, or an empty value: no token, but no error.
        let keyless = root.join("keyless.yaml");
        fs::write(&keyless, "listen: 127.0.0.1:18080\n").expect("keyless config");
        fs::set_permissions(&keyless, Permissions::from_mode(0o600)).expect("chmod");
        let (token, warning) = read_operator_token(&keyless, uid).expect("a keyless config reads");
        assert_eq!(token, None);
        assert_eq!(warning, None);
        let empty = root.join("empty.yaml");
        write_config(&empty, "\"\"", 0o600);
        let (token, _) = read_operator_token(&empty, uid).expect("an empty token reads");
        assert_eq!(token, None);

        // A missing file and a broken one are reported by kind.
        match read_operator_token(&root.join("absent.yaml"), uid) {
            Err(TokenProblem::Unreadable(err)) => {
                assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        let broken = root.join("broken.yaml");
        fs::write(&broken, "mcp: [\n").expect("broken config");
        fs::set_permissions(&broken, Permissions::from_mode(0o600)).expect("chmod");
        match read_operator_token(&broken, uid) {
            Err(TokenProblem::Parse(err)) => {
                assert!(
                    err.to_string().contains(&broken.display().to_string()),
                    "{err:#}"
                );
            }
            other => panic!("expected Parse, got {other:?}"),
        }

        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn untrusted_pointers_are_never_dialed() {
        let root = temp_root("untrusted");
        let cores = root.join("cores");
        let cfg_a = root.join("a.yaml");
        write_config(&cfg_a, "optoken-test-a", 0o600);
        let line = ptr(200, 50512, &cfg_a).to_json_line();

        // A `0644` pointer, a `v: 2` pointer, an off-loopback pointer.
        let wide = write_unlocked(&cores, &line, "1.json", 0o644);
        let v2 = write_unlocked(
            &cores,
            &line.replacen("\"v\":1", "\"v\":2", 1),
            "2.json",
            0o600,
        );
        let off = write_unlocked(
            &cores,
            &line.replace("127.0.0.1:50512", "10.0.0.5:1"),
            "3.json",
            0o600,
        );

        // Trust is decided before the lock is probed: this closure must never run.
        let never = |path: &Path| -> Liveness {
            panic!("untrusted pointer {} must never be probed", path.display())
        };
        let argv = args(&["scope", "list"]);
        let r = resolver(&no_env, &never, &cores);
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_a,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.what, "no running core found");
        assert!(wide.exists(), "a wide pointer is never deleted");
        assert!(v2.exists(), "an unknown-version pointer is never deleted");
        assert!(off.exists(), "an off-loopback pointer is never deleted");
        assert!(live_pointers(&r).is_empty());

        // A valid, locked pointer owned by another uid is foreign: skipped, kept.
        let good = pointer::write(&cores, &ptr(400, 50514, &cfg_a)).expect("write good");
        let foreign_uid = |dir: &Path| owner_uid(dir).wrapping_add(1);
        let foreign = Resolver {
            owner_uid: &foreign_uid,
            ..resolver(&no_env, &never, &cores)
        };
        let report = what(resolve(
            &foreign,
            &BusArgs::default(),
            &Config::default(),
            &cfg_a,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.what, "no running core found");
        assert!(good.path.exists(), "a foreign pointer is never deleted");

        // The same pointer under its own uid is live.
        let r_live = resolver(&no_env, &pointer::liveness, &cores);
        let live = live_pointers(&r_live);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].path, good.path);
        assert_eq!(live[0].pointer.pid, 400);

        drop(good);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn unknown_liveness_counts_as_alive() {
        let root = temp_root("unknown");
        let cores = root.join("cores");
        let cfg_a = root.join("a.yaml");
        write_config(&cfg_a, "optoken-test-a", 0o600);
        // Nobody holds this pointer's lock, but the probe cannot tell.
        let path = write_unlocked(
            &cores,
            &ptr(200, 50512, &cfg_a).to_json_line(),
            "200.json",
            0o600,
        );

        let unknown = |_: &Path| Liveness::Unknown;
        let argv = args(&["scope", "list"]);
        let r = resolver(&no_env, &unknown, &cores);
        let (target, warnings) = resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &cfg_a,
            false,
            "scope.list",
            &argv,
        )
        .expect("an unknown probe is treated as alive");
        assert_eq!(target.addr, lo(50512));
        assert_eq!(target.token, "optoken-test-a");
        assert_eq!(
            target.source,
            Source::Pointer {
                path: path.clone(),
                pid: 200,
                started_unix: STARTED,
            }
        );
        assert_eq!(warnings, Vec::<Warning>::new());
        assert!(path.exists(), "an unknown pointer is kept");

        // A probe that says dead deletes it and finds nothing.
        let dead = |_: &Path| Liveness::Dead;
        let r_dead = resolver(&no_env, &dead, &cores);
        let report = what(resolve(
            &r_dead,
            &BusArgs::default(),
            &Config::default(),
            &cfg_a,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.what, "no running core found");
        assert!(!path.exists(), "a dead pointer is deleted");

        fs::remove_dir_all(&root).expect("cleanup");
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    /// A width-100 TTY with no colour, for the rich render of a panel.
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

    /// Tester — D7 step 1 "nothing else is consulted": with `--bus` given, a
    /// live pointer and a dead pointer in the run dir and a configured
    /// loopback port with its own token are all ignored: the liveness probe
    /// never runs, the dead pointer is not deleted, the flag beats
    /// `AITM_BUS`, the file beats `AITM_BUS_TOKEN`, and no config is named.
    #[test]
    fn tester_explicit_address_consults_neither_pointers_nor_config() {
        let root = temp_root("tester-explicit");
        let cores = root.join("cores");
        let cfg_a = root.join("a.yaml");
        write_config(&cfg_a, "optoken-test-pointer", 0o600);
        let live = pointer::write(&cores, &ptr(200, 50512, &cfg_a)).expect("live pointer");
        let dead = write_unlocked(
            &cores,
            &ptr(100, 50511, &cfg_a).to_json_line(),
            "100.json",
            0o600,
        );
        let tfile = root.join("token");
        fs::write(&tfile, "optoken-test-file\n").expect("token file");
        fs::set_permissions(&tfile, Permissions::from_mode(0o600)).expect("chmod");
        let cfg = loopback_cfg(9090, None, Some("optoken-test-cfg"));
        let never = |path: &Path| -> Liveness {
            panic!(
                "the liveness probe ran on {} with --bus given",
                path.display()
            )
        };
        let env = env_of(&[
            ("AITM_BUS", "127.0.0.1:7"),
            ("AITM_BUS_TOKEN", "optoken-test-env"),
        ]);
        let r = resolver(&env, &never, &cores);
        let flag = BusArgs {
            bus: Some("127.0.0.1:1".to_string()),
            token_file: Some(tfile.clone()),
        };
        let argv = args(&["scope", "add", "--host", "x"]);
        let (target, warnings) =
            resolve(&r, &flag, &cfg, &cfg_a, false, "scope.add", &argv).expect("explicit");
        assert_eq!(target.addr, lo(1));
        assert_eq!(target.token, "optoken-test-file");
        assert_eq!(target.source, Source::ExplicitFlag);
        assert_eq!(target.config, None);
        assert!(warnings.is_empty());
        assert!(dead.exists(), "no pointer is deleted on the explicit path");
        assert!(live.path.exists());

        // The token never reaches a `Debug` through the containers the entry
        // point holds.
        let wrapped: Result<(Target, Vec<Warning>), ()> = Ok((target.clone(), warnings));
        assert!(!format!("{wrapped:?}").contains("optoken-test"));
        assert!(!format!("{:?}", vec![&target]).contains("optoken-test"));
        assert!(format!("{:?}", Some(&target)).contains("<redacted>"));

        drop(live);
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — D7 rule 6, R13: a token-bearing config that fails to parse
    /// (a type error in another key, an unknown key, a wrong shape) is W1's
    /// `report_for` shape, names the file, and never prints the token that
    /// sits beside the broken key, plain, rich or `Debug`. A live pointer
    /// naming a config that does not exist is `reading config file <path>`.
    #[test]
    fn tester_r13_panels_never_print_the_token() {
        let root = temp_root("tester-r13");
        let cores = root.join("cores");
        let cfg = root.join("broken.yaml");
        let argv = args(&["scope", "list"]);
        let docs = [
            "mcp:\n  operator_token: optoken-test-leak\n  operator_bus:\n    port: 99999\n",
            "mcp:\n  operator_token: optoken-test-leak\n  bogus_key: 1\n",
            "mcp:\n  operator_token: optoken-test-leak\n  operator_bus: [1, 2]\n",
            "mcp:\n  operator_token: optoken-test-leak\nlisten: [not, an, addr]\n",
        ];
        for doc in docs {
            fs::write(&cfg, doc).expect("config");
            fs::set_permissions(&cfg, Permissions::from_mode(0o644)).expect("chmod");
            let live = pointer::write(&cores, &ptr(200, 50512, &cfg)).expect("live pointer");
            let r = resolver(&no_env, &pointer::liveness, &cores);
            let report = what(resolve(
                &r,
                &BusArgs::default(),
                &Config::default(),
                &cfg,
                false,
                "scope.list",
                &argv,
            ));
            assert_eq!(report.kind, ErrorKind::Failure, "{doc:?}");
            let plain = report.render_plain(&aitm_term::glyphs::RICH);
            let rich = report.render(&tty_100(), Some(Path::new("/Users/matt")));
            assert!(
                plain.contains(cfg.to_str().unwrap()),
                "{doc:?}: the panel names the file: {plain}"
            );
            for text in [plain, rich, format!("{report:?}")] {
                assert!(!text.contains("optoken-test"), "{doc:?}: {text}");
            }
            drop(live);
        }

        let gone = root.join("gone.yaml");
        let _live = pointer::write(&cores, &ptr(300, 50513, &gone)).expect("live pointer");
        let r = resolver(&no_env, &pointer::liveness, &cores);
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &gone,
            false,
            "scope.list",
            &argv,
        ));
        assert_eq!(report.kind, ErrorKind::Failure);
        assert_eq!(
            report.what,
            format!("reading config file {}", gone.display())
        );
        assert_eq!(report.why.len(), 1, "{:?}", report.why);
        assert!(report.why[0].contains("os error 2"), "{:?}", report.why);
        assert_eq!(report.command, None);

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — `read_operator_token`: `''` is as absent as `""`; a token
    /// with surrounding spaces or an inline comment is the bare value; a
    /// `0000` config (no group or other bit) draws no wide warning and, being
    /// unreadable, is reported by kind rather than read around.
    #[test]
    fn tester_read_operator_token_quoting_and_unreadable_modes() {
        let root = temp_root("tester-token-quoting");
        let cores = root.join("cores");
        let uid = owner_uid(&cores);

        let single = root.join("single.yaml");
        write_config(&single, "''", 0o600);
        assert_eq!(read_operator_token(&single, uid).expect("reads").0, None);
        let commented = root.join("commented.yaml");
        fs::write(
            &commented,
            "mcp:\n  operator_token: optoken-test-c   # rotate me\n",
        )
        .expect("config");
        fs::set_permissions(&commented, Permissions::from_mode(0o600)).expect("chmod");
        assert_eq!(
            read_operator_token(&commented, uid).expect("reads").0,
            Some("optoken-test-c".to_string())
        );
        let quoted = root.join("quoted.yaml");
        write_config(&quoted, "\"optoken-test-q\"", 0o600);
        assert_eq!(
            read_operator_token(&quoted, uid).expect("reads").0,
            Some("optoken-test-q".to_string())
        );

        let dark = root.join("dark.yaml");
        write_config(&dark, "optoken-test-dark", 0o000);
        if fs::read(&dark).is_ok() {
            eprintln!("skipping the 0000 case: this user can read a 0000 file (root)");
            fs::remove_dir_all(&root).expect("cleanup");
            return;
        }
        match read_operator_token(&dark, uid) {
            Err(TokenProblem::Parse(err)) => {
                let text = format!("{err:#}");
                assert!(text.contains(dark.to_str().unwrap()), "{text}");
                assert!(!text.contains("optoken-test"), "{text}");
            }
            other => panic!("expected Parse (unreadable), got {other:?}"),
        }
        fs::set_permissions(&dark, Permissions::from_mode(0o600)).expect("restore");

        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester edge (2026-11-01): an explicit `--bus` consults no pointer, so
    /// the run dir is neither created nor read; a pointer-dir resolution over
    /// the same absent dir creates it `0700`.
    #[test]
    fn explicit_bus_leaves_an_absent_run_dir_absent() {
        let root = temp_root("lazy-run-dir");
        let absent = root.join("run").join("cores");
        let env = env_of(&[("AITM_BUS_TOKEN", "optoken-test-env")]);
        let consulted = Cell::new(0u32);
        let counting = |dir: &Path| {
            consulted.set(consulted.get() + 1);
            owner_uid(dir)
        };
        let r = Resolver {
            env: &env,
            liveness: &pointer::liveness,
            owner_uid: &counting,
            now_unix: NOW,
            run_dir: absent.clone(),
        };
        let flag = BusArgs {
            bus: Some("127.0.0.1:50512".to_string()),
            token_file: None,
        };
        let argv = args(&["scope", "add", "--host", "example.com"]);
        let config = root.join("config.yaml");
        let (target, warnings) = resolve(
            &r,
            &flag,
            &Config::default(),
            &config,
            false,
            "scope.add",
            &argv,
        )
        .expect("explicit flag resolves");
        assert_eq!(target.addr, lo(50512));
        assert_eq!(target.token, "optoken-test-env");
        assert_eq!(target.source, Source::ExplicitFlag);
        assert_eq!(target.config, None);
        assert_eq!(warnings, Vec::<Warning>::new());
        assert_eq!(
            consulted.get(),
            0,
            "an explicit address never consults the run dir"
        );
        assert!(
            !absent.exists(),
            "an explicit address never creates the run dir"
        );
        assert!(!root.join("run").exists(), "nor its parent");

        // The same resolver on the pointer path consults the dir: created 0700.
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &config,
            false,
            "scope.add",
            &argv,
        ));
        assert_eq!(report.what, "no running core found");
        assert_eq!(
            consulted.get(),
            1,
            "the pointer path consults the run dir once"
        );
        assert_eq!(
            fs::metadata(&absent)
                .expect("the pointer path created the run dir")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — `owner_uid` on a run dir that cannot be created (its parent
    /// is a file) is `u32::MAX`, so nothing passes trust and the resolution
    /// is R1 rather than a dial of someone else's pointer.
    #[test]
    fn tester_owner_uid_trusts_nothing_when_the_run_dir_cannot_exist() {
        let root = temp_root("tester-owner-uid");
        let blocker = root.join("file");
        fs::write(&blocker, "not a dir").expect("blocker");
        let impossible = blocker.join("cores");
        assert_eq!(owner_uid(&impossible), u32::MAX);
        let r = Resolver {
            env: &no_env,
            liveness: &pointer::liveness,
            owner_uid: &owner_uid,
            now_unix: NOW,
            run_dir: impossible.clone(),
        };
        let report = what(resolve(
            &r,
            &BusArgs::default(),
            &Config::default(),
            &root.join("config.yaml"),
            false,
            "scope.list",
            &args(&["scope", "list"]),
        ));
        assert_eq!(report.what, "no running core found");
        fs::remove_dir_all(&root).expect("cleanup");
    }

    /// Tester — AC-R14-31, the FIFO half: a FIFO at the token-bearing path is
    /// `TokenProblem::NotRegular` from its metadata alone; it is never
    /// opened (nobody writes the pipe, so an open would block forever), and
    /// through `resolve` it is R15. Run on a helper thread with a deadline so
    /// a regression hangs the probe, not the suite.
    #[test]
    fn tester_read_operator_token_refuses_a_fifo_without_opening_it() {
        let root = temp_root("tester-fifo");
        let cores = root.join("cores");
        let fifo = root.join("fifo.yaml");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(made.success(), "mkfifo {}", fifo.display());
        let uid = owner_uid(&cores);

        let (tx, rx) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(matches!(
                read_operator_token(&probe, uid),
                Err(TokenProblem::NotRegular)
            ));
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("read_operator_token must not block on a FIFO"),
            "a FIFO is NotRegular"
        );

        // Through `resolve`: a live pointer naming the FIFO as its config is R15.
        let _live = pointer::write(&cores, &ptr(200, 50512, &fifo)).expect("live pointer");
        let (tx, rx) = std::sync::mpsc::channel();
        let (cores_t, fifo_t) = (cores.clone(), fifo.clone());
        std::thread::spawn(move || {
            let r = Resolver {
                env: &no_env,
                liveness: &pointer::liveness,
                owner_uid: &owner_uid,
                now_unix: NOW,
                run_dir: cores_t,
            };
            let report = what(resolve(
                &r,
                &BusArgs::default(),
                &Config::default(),
                &fifo_t,
                false,
                "scope.list",
                &args(&["scope", "list"]),
            ));
            let _ = tx.send((report.what.clone(), report.why.clone()));
        });
        let (what_line, why) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("resolve must not block on a FIFO config");
        assert_eq!(
            what_line,
            format!(
                "the config {} is not a regular file owned by this user",
                fifo.display()
            )
        );
        assert_eq!(
            why,
            vec!["aitm reads an operator token only from a regular file it owns. Nothing was changed.".to_string()]
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
