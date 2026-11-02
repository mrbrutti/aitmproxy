//! The ready card (spec D10, T7, M1, M6; plan Task 10, calls C16, C17, C18,
//! C25, C27): [`ReadyInputs`], [`ready_card`], the T7 vocabulary helpers and
//! the aitm-ca trust read.
//!
//! R14 (`2026-11-01-cli-oneshot-live-core-design.md` D5, D14; its plan Task
//! 9, call C16) adds [`OperatorBusWord`], the `Operator bus` row directly
//! after `Bus`, the ` · operator` suffix on a shared `Bus` row, and makes the
//! Scope next step conditional on the card's own core being reachable by a
//! one-shot. The renderer in `aitm-term` is untouched: the label is 12
//! characters, within T3's 14-column field.
//!
//! Everything here is a pure function of values `run()` already holds (the
//! bound listeners, the config, the system-proxy summary, the log path), so
//! the card is unit-tested by literal rows. The one exception is
//! [`read_ca_trust`], which shells out to the OS trust store; it is called
//! only in serving modes (spec amendment A). The headline is composed exactly
//! as the TUI pill (`crates/aitm-tui/src/ui/bars.rs`) and the CA word is
//! reduced exactly as `CaTrustWord::from_json` (`crates/aitm-tui/src/model.rs`)
//! so the three surfaces never disagree. Addressed by path
//! (`startup::card::…`), never re-exported from `mod.rs`.

use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

use aitm_ca::cert::CaCert;
use aitm_ca::exec::RealExecutor;
use aitm_ca::store::{trust_statuses, Platform, StoreStatus, Trust};
use aitm_core::{BrowserEngine, McpTransport, NOTHING_DECRYPTED_ADVICE};
use aitm_sysproxy::{Recovery, State, Summary};
use aitm_term::card::{Card, Row};
use aitm_term::error::FixCommand;
use aitm_term::style::Role;
use aitm_term::text;

/// The next step under an empty `Scope` row (spec D10, M1).
pub(crate) const SCOPE_ADD_COMMAND: &str = "aitm scope add --host <host>";
/// The next step under an `untrusted` `CA` row (spec D10, M1).
pub(crate) const CA_INSTALL_COMMAND: &str = "aitm ca install";
/// The next step under an `off` or `points at <host>:<port>` `System proxy`
/// row (spec T7).
pub(crate) const PROXY_SYSTEM_SET_COMMAND: &str = "aitm proxy system set";
/// The `Operator bus` row's label (R14 spec D5): 12 characters, within T3's
/// 14-column label field.
pub const OPERATOR_BUS_LABEL: &str = "Operator bus";
/// The `Browser` row's trailing note (spec M6; one plain string in wave 1,
/// plan C24).
const SSRF_NOTE: &str = "(SSRF-filtered)";

/// Which serving mode the card is for; it picks the row set (spec D10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeWord {
    /// Bare `aitm`: the `Bus` row carries the transport word.
    Server,
    /// `aitm web`: URL rows first, `Bus` is `ready` (M6).
    Web,
    /// `aitm tui`: no card is printed (D11); treated as `Server` if asked.
    Tui,
}

/// The MCP bus as the `Bus` row and the TUI say it (spec T7, plan C25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusWord {
    Stdio,
    /// The loopback TCP port; `0` is an ephemeral port the OS picks.
    Loopback(u16),
    Http(SocketAddr),
    Off,
}

impl fmt::Display for BusWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BusWord::Stdio => f.write_str("stdio (MCP)"),
            BusWord::Loopback(0) => f.write_str("loopback 127.0.0.1 (ephemeral port)"),
            BusWord::Loopback(port) => write!(f, "loopback 127.0.0.1:{port}"),
            BusWord::Http(addr) => write!(f, "http {addr}"),
            BusWord::Off => f.write_str("off"),
        }
    }
}

/// The [`BusWord`] for a configured transport. `Off` is never produced here:
/// a config always names a transport; the caller picks `Off` when the bus is
/// not served.
pub fn bus_word(t: &McpTransport) -> BusWord {
    match t {
        McpTransport::Stdio => BusWord::Stdio,
        McpTransport::LoopbackTcp { port, .. } => BusWord::Loopback(*port),
        McpTransport::StreamableHttp { bind, .. } => BusWord::Http(*bind),
    }
}

/// The operator bus as the card says it (R14 spec D5; `operator_bus::start`
/// returns it). It decides the `Operator bus` row ([`operator_bus_row`]),
/// the ` · operator` suffix on the `Bus` row ([`bus_row_value`]) and whether
/// the Scope next step is promised ([`scope_row`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorBusWord {
    /// The configured loopback MCP transport already serves the operator
    /// (one listener): the `Bus` row gains ` · operator`; no row of its own.
    Shared,
    /// A dedicated loopback listener at this address: the `Operator bus`
    /// row, plain.
    Dedicated(SocketAddr),
    /// Not served; the reason (`mcp.operator_bus.enabled: false`,
    /// `no mcp.operator_token`, `could not write mcp.operator_token to
    /// <path>`) follows `off · ` on a warning row.
    Off(String),
}

impl OperatorBusWord {
    /// Whether a one-shot can reach this core as the operator (R14 D5,
    /// D14): `Shared` or `Dedicated`.
    fn reachable(&self) -> bool {
        !matches!(self, OperatorBusWord::Off(_))
    }
}

/// The CA trust verdict once read (spec T7). An unread state is `None` on
/// the caller's side and never becomes `Untrusted` (TUI D17.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaWord {
    Trusted,
    Untrusted,
}

/// Everything the ready card is made of (spec D10, plan C7 for `home`).
/// Borrowed, so `run()` passes its own values without cloning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyInputs<'a> {
    pub mode: ModeWord,
    pub proxy: SocketAddr,
    pub browser: SocketAddr,
    pub bus: BusWord,
    /// The operator bus (R14 D5): the `Operator bus` row, the ` · operator`
    /// suffix on `Bus`, and whether the Scope next step is promised.
    pub operator_bus: OperatorBusWord,
    /// `web::ui_url`; shown as the `Web UI` row in web mode.
    pub web_url: Option<&'a str>,
    /// `web::operator_ui_url`; shown as the `Operator` row only when an
    /// operator token is configured (M6).
    pub operator_url: Option<&'a str>,
    /// The trust read-back; `None` when unread or when every store said
    /// `unknown`.
    pub ca: Option<CaWord>,
    /// `cfg.scope.entries.len()`.
    pub scope_hosts: usize,
    /// `sysproxy.summary()` after the startup recovery.
    pub system_proxy: &'a Summary,
    pub intercept_armed: bool,
    pub capture_paused: bool,
    /// The opened log file; `None` omits the `Log` row (AC-W1-17).
    pub log: Option<&'a Path>,
    /// `$HOME` for `~` shortening of the `Log` row; `Some` only when the
    /// stream animates (plan C7), so a pipe sees the full path (M1p).
    pub home: Option<&'a Path>,
}

/// The pill line, composed exactly as `crates/aitm-tui/src/ui/bars.rs`:
/// `aitmproxy · listening <proxy>`, then ` · CA trusted` / ` · CA untrusted`
/// when the word is known, then ` · intercept armed` or, failing that,
/// ` · capture paused` (spec T7). The `●` glyph is the renderer's.
pub fn pill(i: &ReadyInputs) -> String {
    let mut line = format!("aitmproxy · listening {}", i.proxy);
    match i.ca {
        Some(CaWord::Trusted) => line.push_str(" · CA trusted"),
        Some(CaWord::Untrusted) => line.push_str(" · CA untrusted"),
        None => {}
    }
    if i.intercept_armed {
        line.push_str(" · intercept armed");
    } else if i.capture_paused {
        line.push_str(" · capture paused");
    }
    line
}

/// The T7 reduction over the trust stores, as `CaTrustWord::from_json` does
/// it in `crates/aitm-tui/src/model.rs`: any store `trusted == yes` →
/// `Trusted`; else any `no` → `Untrusted`; else `None` (every store answered
/// `unknown`, or there are no stores).
pub fn ca_word(stores: &[StoreStatus]) -> Option<CaWord> {
    if stores.iter().any(|s| s.trusted == Trust::Yes) {
        Some(CaWord::Trusted)
    } else if stores.iter().any(|s| s.trusted == Trust::No) {
        Some(CaWord::Untrusted)
    } else {
        None
    }
}

/// The `checking CA trust` phase's done summary (spec D10).
pub fn ca_phase_summary(w: Option<CaWord>) -> &'static str {
    match w {
        Some(CaWord::Trusted) => "CA trusted",
        Some(CaWord::Untrusted) => "CA untrusted",
        None => "CA trust unknown",
    }
}

/// The `System proxy` row's value and next step (spec T7): `off` and
/// `points at <host>:<port>` carry `aitm proxy system set`; the rest have no
/// next step.
pub fn system_proxy_row(s: &Summary) -> (String, Option<FixCommand>) {
    let set = || Some(FixCommand(PROXY_SYSTEM_SET_COMMAND.to_string()));
    match &s.state {
        State::Off => ("off".to_string(), set()),
        State::PointsAtUs => ("points at this proxy".to_string(), None),
        State::Other { host, port } => (format!("points at {host}:{port}"), set()),
        State::NeedsPrivilege => ("needs privilege".to_string(), None),
        State::Unsupported => ("unsupported on this platform".to_string(), None),
        State::Unknown => ("unknown".to_string(), None),
    }
}

/// How the `System proxy` value is painted: plain when it points at this
/// proxy or the platform has no mechanism (nothing to act on), warning
/// otherwise (`off`, `other`, `needs privilege`, `unknown`).
fn system_proxy_role(state: &State) -> Role {
    match state {
        State::PointsAtUs | State::Unsupported => Role::Plain,
        State::Off | State::Other { .. } | State::NeedsPrivilege | State::Unknown => Role::Warning,
    }
}

/// The `Scope` row's value and next step (spec T7; R14 D5/D14, which re-pin
/// AC-W1-6): the core's [`NOTHING_DECRYPTED_ADVICE`] verbatim when Scope is
/// empty, plus `aitm scope add --host <host>` only when `reachable` (a
/// one-shot can reach this core as the operator: the operator bus is
/// `Shared` or `Dedicated`, never `Off`); `1 host in Scope` /
/// `<n> hosts in Scope` otherwise, never with a next step.
pub fn scope_row(n: usize, reachable: bool) -> (String, Option<FixCommand>) {
    match n {
        0 => (
            NOTHING_DECRYPTED_ADVICE.to_string(),
            reachable.then(|| FixCommand(SCOPE_ADD_COMMAND.to_string())),
        ),
        1 => ("1 host in Scope".to_string(), None),
        n => (format!("{n} hosts in Scope"), None),
    }
}

/// The `Bus` row's value (spec T7; R14 D5, plan C16): `ready` on the Web
/// card, the [`BusWord`] otherwise, with ` · operator` appended when the
/// operator bus is `Shared` (that one listener serves the operator too, so
/// there is no `Operator bus` row to say it).
pub fn bus_row_value(bus: &BusWord, mode: ModeWord, ob: &OperatorBusWord) -> String {
    let base = match mode {
        ModeWord::Web => "ready".to_string(),
        ModeWord::Server | ModeWord::Tui => bus.to_string(),
    };
    match ob {
        OperatorBusWord::Shared => format!("{base} · operator"),
        OperatorBusWord::Dedicated(_) | OperatorBusWord::Off(_) => base,
    }
}

/// The `Operator bus` row (R14 D5, plan C16): the address, plain, for a
/// `Dedicated` bus; `off · <reason>` as a warning for `Off`; `None` for
/// `Shared`, whose word rides on the `Bus` row. Never a next step: the
/// reason names the config key or the path itself.
pub fn operator_bus_row(ob: &OperatorBusWord) -> Option<Row> {
    match ob {
        OperatorBusWord::Shared => None,
        OperatorBusWord::Dedicated(addr) => Some(plain_row(OPERATOR_BUS_LABEL, addr.to_string())),
        OperatorBusWord::Off(reason) => Some(Row {
            label: OPERATOR_BUS_LABEL,
            value: format!("off · {reason}"),
            value_role: Role::Warning,
            next: None,
        }),
    }
}

/// The `restoring system proxy` phase's done summary (plan C18), or `None`
/// when the phase is not shown: `Nothing` (the mode does not manage the
/// system proxy) and `Failed` (its `warn!` reaches the view through the
/// tracing layer instead).
pub fn recovery_summary(r: &Recovery) -> Option<String> {
    match r {
        Recovery::Nothing | Recovery::Failed(_) => None,
        Recovery::Set(_) => Some("system proxy set to this proxy".to_string()),
        Recovery::Adopted { pid } => Some(format!("system proxy adopted · watchdog {pid}")),
        Recovery::Restored { restored, .. } => {
            let n = restored.len();
            let noun = if n == 1 { "service" } else { "services" };
            Some(format!("system proxy restored · {n} {noun}"))
        }
        Recovery::Forgot => Some("system proxy state file forgotten".to_string()),
    }
}

/// The `starting obscura` phase's done summary (spec T7, plan C17):
/// `obscura probed <version>` (the line `cli-startup.sh` matches), or
/// `obscura probed` when the engine reported no version; another engine is
/// `browser ready (<engine>)`.
///
/// The engine's `--version` output names itself (`obscura aitm-v1`), so a
/// leading engine name, case-insensitive and followed by one or more spaces,
/// is dropped from `version` before formatting (live dry-run finding D4);
/// the word after `probed` is the version alone.
pub fn browser_summary(engine: &BrowserEngine, version: Option<&str>) -> String {
    match (engine, version.and_then(obscura_version)) {
        (BrowserEngine::Obscura, Some(version)) => format!("obscura probed {version}"),
        (BrowserEngine::Obscura, None) => "obscura probed".to_string(),
        (BrowserEngine::Chrome, _) => "browser ready (chrome)".to_string(),
        (BrowserEngine::Firefox, _) => "browser ready (firefox)".to_string(),
    }
}

/// `version` trimmed, minus a leading `obscura` engine name (any case) and
/// the whitespace after it; `None` when nothing is left (a blank string or
/// the bare engine name carries no version).
fn obscura_version(version: &str) -> Option<&str> {
    let version = version.trim();
    let (head, tail) = version
        .split_once(char::is_whitespace)
        .unwrap_or((version, ""));
    let rest = if head.eq_ignore_ascii_case("obscura") {
        tail.trim()
    } else {
        version
    };
    (!rest.is_empty()).then_some(rest)
}

/// A row painted plain with no next step.
fn plain_row(label: &'static str, value: impl Into<String>) -> Row {
    Row {
        label,
        value: value.into(),
        value_role: Role::Plain,
        next: None,
    }
}

/// The ready card (spec D10; M1 for `Server`, M6 for `Web`; R14 D5 for the
/// operator bus). Rows in order: the mode's own rows (`Web UI`, `Operator`
/// when configured, `Proxy`, `Browser` for web), `Bus` ([`bus_row_value`]),
/// `Operator bus` directly after it when the plan has a row
/// ([`operator_bus_row`]), then `Scope` (its next step only when the operator
/// bus is reachable), `CA` only when untrusted, `System proxy`, and `Log`
/// last and dim when a log file is open.
pub fn ready_card(i: &ReadyInputs) -> Card {
    let mut rows = Vec::with_capacity(9);
    if i.mode == ModeWord::Web {
        if let Some(url) = i.web_url {
            rows.push(plain_row("Web UI", url));
        }
        if let Some(url) = i.operator_url {
            rows.push(plain_row("Operator", url));
        }
        rows.push(plain_row("Proxy", i.proxy.to_string()));
        rows.push(plain_row("Browser", format!("{}  {SSRF_NOTE}", i.browser)));
    }
    rows.push(plain_row(
        "Bus",
        bus_row_value(&i.bus, i.mode, &i.operator_bus),
    ));
    if let Some(row) = operator_bus_row(&i.operator_bus) {
        rows.push(row);
    }

    let (value, next) = scope_row(i.scope_hosts, i.operator_bus.reachable());
    rows.push(Row {
        label: "Scope",
        value,
        value_role: Role::Plain,
        next: next.map(|FixCommand(c)| c),
    });

    if i.ca == Some(CaWord::Untrusted) {
        rows.push(Row {
            label: "CA",
            value: "untrusted".to_string(),
            value_role: Role::Warning,
            next: Some(CA_INSTALL_COMMAND.to_string()),
        });
    }

    let (value, next) = system_proxy_row(i.system_proxy);
    rows.push(Row {
        label: "System proxy",
        value,
        value_role: system_proxy_role(&i.system_proxy.state),
        next: next.map(|FixCommand(c)| c),
    });

    if let Some(log) = i.log {
        rows.push(Row {
            label: "Log",
            value: text::tilde(log, i.home),
            value_role: Role::Dim,
            next: None,
        });
    }

    Card {
        headline: pill(i),
        headline_role: Role::Success,
        rows,
    }
}

/// The `checking CA trust` phase: the CA word for the certificate in
/// `ca_dir`, read through the same aitm-ca path as `ca.status`
/// ([`trust_statuses`], plan C16) so the two cannot disagree.
///
/// **Blocking.** It shells out to the OS trust store (`security`,
/// `trust`/`update-ca-trust`, `certutil`) through a [`RealExecutor`] and may
/// take as long as those tools do, so `main` calls it on the runtime thread
/// like the system-proxy recovery, and only in serving modes (bare `aitm`,
/// `aitm web`, `aitm tui`); never for a one-shot verb and never on the
/// pre-boot paths (spec amendment A).
///
/// `None` whenever there is nothing to say: no `ca.crt`, an unreadable one,
/// a store error, or every store answering `unknown` (spec D10).
pub fn read_ca_trust(ca_dir: &Path) -> Option<CaWord> {
    let exec = RealExecutor::new();
    let cert = CaCert::load(ca_dir, &exec).ok()??;
    let platform = Platform::detect(&exec);
    let statuses = trust_statuses(&cert, &platform, &exec).ok()?;
    ca_word(&statuses)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};

    use aitm_ca::store::{Presence, Scope, StoreStatus, Trust};
    use aitm_core::{BrowserEngine, McpTransport, NOTHING_DECRYPTED_ADVICE};
    use aitm_sysproxy::{Endpoint, Mechanism, Recovery, State, Status, Summary};
    use aitm_term::caps::Caps;
    use aitm_term::card::Row;
    use aitm_term::error::FixCommand;
    use aitm_term::glyphs::RICH;
    use aitm_term::style::Role;

    const LOG: &str = "/Users/matt/Library/Application Support/aitmproxy/logs/aitm.log";
    const TILDE_LOG: &str = "~/Library/Application Support/aitmproxy/logs/aitm.log";
    const WEB_URL: &str = "http://127.0.0.1:8082/#t=abc";
    const OPERATOR_URL: &str = "http://127.0.0.1:8082/#t=def&expect=operator";

    /// M1's ready block, byte for byte, colour off (spec M1), plus the R14
    /// `Operator bus` row directly after `Bus`: the R14 spec's D5 block for
    /// bare `aitm` after first run.
    const M1: &str = concat!(
        "● aitmproxy · listening 127.0.0.1:8080 · CA untrusted\n",
        "  Bus           stdio (MCP)\n",
        "  Operator bus  127.0.0.1:50512\n",
        "  Scope         Nothing is decrypted until a host is in Scope.\n",
        "                ▸ aitm scope add --host <host>\n",
        "  CA            untrusted\n",
        "                ▸ aitm ca install\n",
        "  System proxy  off\n",
        "                ▸ aitm proxy system set\n",
        "  Log           ~/Library/Application Support/aitmproxy/logs/aitm.log\n",
    );

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn fix(command: &str) -> Option<FixCommand> {
        Some(FixCommand(command.to_string()))
    }

    fn status(trusted: Trust) -> StoreStatus {
        StoreStatus {
            scope: Scope::User,
            location: "/Users/t/Library/Keychains/login.keychain-db".to_string(),
            installed: Presence::Unknown,
            trusted,
            detail: Vec::new(),
        }
    }

    fn summary(state: State) -> Summary {
        Summary {
            state,
            host: None,
            port: None,
            managed_by_us: false,
            setting: false,
            supported: true,
            detail: String::new(),
        }
    }

    fn row(label: &'static str, value: &str, value_role: Role, next: Option<&str>) -> Row {
        Row {
            label,
            value: value.to_string(),
            value_role,
            next: next.map(str::to_string),
        }
    }

    fn labels(rows: &[Row]) -> Vec<&'static str> {
        rows.iter().map(|r| r.label).collect()
    }

    /// M1's inputs: bare `aitm`, stdio bus, a dedicated operator bus at
    /// `127.0.0.1:50512` (R14 D5), untrusted CA, empty Scope, the system
    /// proxy off, the default log, `~` = `/Users/matt`.
    fn m1_inputs<'a>(
        system_proxy: &'a Summary,
        log: Option<&'a Path>,
        home: Option<&'a Path>,
    ) -> ReadyInputs<'a> {
        ReadyInputs {
            mode: ModeWord::Server,
            proxy: addr("127.0.0.1:8080"),
            browser: addr("127.0.0.1:8081"),
            bus: BusWord::Stdio,
            operator_bus: OperatorBusWord::Dedicated(addr("127.0.0.1:50512")),
            web_url: None,
            operator_url: None,
            ca: Some(CaWord::Untrusted),
            scope_hosts: 0,
            system_proxy,
            intercept_armed: false,
            capture_paused: false,
            log,
            home,
        }
    }

    /// A UTF-8 TTY, colour off, so the rich form has no escape byte.
    fn tty_no_color() -> Caps {
        Caps {
            tty: true,
            color: false,
            unicode: true,
            animate: true,
            width: 80,
            ci: false,
        }
    }

    #[test]
    fn ca_word_reduction() {
        assert_eq!(
            ca_word(&[status(Trust::Yes), status(Trust::No)]),
            Some(CaWord::Trusted)
        );
        assert_eq!(
            ca_word(&[status(Trust::No), status(Trust::Yes)]),
            Some(CaWord::Trusted),
            "any yes wins regardless of order"
        );
        assert_eq!(
            ca_word(&[status(Trust::No), status(Trust::Unknown)]),
            Some(CaWord::Untrusted)
        );
        assert_eq!(
            ca_word(&[status(Trust::Unknown), status(Trust::Unknown)]),
            None
        );
        assert_eq!(ca_word(&[]), None);
    }

    #[test]
    fn ca_phase_summary_words() {
        assert_eq!(ca_phase_summary(Some(CaWord::Trusted)), "CA trusted");
        assert_eq!(ca_phase_summary(Some(CaWord::Untrusted)), "CA untrusted");
        assert_eq!(ca_phase_summary(None), "CA trust unknown");
    }

    #[test]
    fn system_proxy_row_words() {
        assert_eq!(
            system_proxy_row(&summary(State::Off)),
            ("off".to_string(), fix("aitm proxy system set"))
        );
        assert_eq!(
            system_proxy_row(&summary(State::PointsAtUs)),
            ("points at this proxy".to_string(), None)
        );
        assert_eq!(
            system_proxy_row(&summary(State::Other {
                host: "10.0.0.5".to_string(),
                port: 3128,
            })),
            (
                "points at 10.0.0.5:3128".to_string(),
                fix("aitm proxy system set")
            )
        );
        assert_eq!(
            system_proxy_row(&summary(State::NeedsPrivilege)),
            ("needs privilege".to_string(), None)
        );
        assert_eq!(
            system_proxy_row(&summary(State::Unsupported)),
            ("unsupported on this platform".to_string(), None)
        );
        assert_eq!(
            system_proxy_row(&summary(State::Unknown)),
            ("unknown".to_string(), None)
        );
    }

    #[test]
    fn scope_row_counts() {
        assert_eq!(
            scope_row(0, true),
            (
                "Nothing is decrypted until a host is in Scope.".to_string(),
                fix("aitm scope add --host <host>")
            )
        );
        assert_eq!(scope_row(0, true).0, NOTHING_DECRYPTED_ADVICE);
        assert_eq!(scope_row(1, true), ("1 host in Scope".to_string(), None));
        assert_eq!(scope_row(2, true), ("2 hosts in Scope".to_string(), None));
        assert_eq!(scope_row(49, true), ("49 hosts in Scope".to_string(), None));
    }

    #[test]
    fn bus_word_display() {
        assert_eq!(BusWord::Stdio.to_string(), "stdio (MCP)");
        assert_eq!(
            BusWord::Loopback(5555).to_string(),
            "loopback 127.0.0.1:5555"
        );
        assert_eq!(
            BusWord::Loopback(0).to_string(),
            "loopback 127.0.0.1 (ephemeral port)"
        );
        assert_eq!(
            BusWord::Http(addr("127.0.0.1:3000")).to_string(),
            "http 127.0.0.1:3000"
        );
        assert_eq!(BusWord::Off.to_string(), "off");

        assert_eq!(bus_word(&McpTransport::Stdio), BusWord::Stdio);
        assert_eq!(
            bus_word(&McpTransport::LoopbackTcp {
                port: 5555,
                token: String::new(),
                endpoint_file: None,
            }),
            BusWord::Loopback(5555)
        );
        assert_eq!(
            bus_word(&McpTransport::streamable_http_default(String::new())),
            BusWord::Http(addr("127.0.0.1:8084"))
        );
    }

    #[test]
    fn pill_matches_the_tui_composition() {
        let off = summary(State::Off);
        let mut i = m1_inputs(&off, None, None);

        i.ca = Some(CaWord::Trusted);
        i.intercept_armed = true;
        assert_eq!(
            pill(&i),
            "aitmproxy · listening 127.0.0.1:8080 · CA trusted · intercept armed"
        );

        i.ca = None;
        i.intercept_armed = false;
        assert_eq!(pill(&i), "aitmproxy · listening 127.0.0.1:8080");

        i.capture_paused = true;
        assert_eq!(
            pill(&i),
            "aitmproxy · listening 127.0.0.1:8080 · capture paused"
        );

        // `bars.rs` checks `intercept_armed` first: armed wins over paused.
        i.intercept_armed = true;
        assert_eq!(
            pill(&i),
            "aitmproxy · listening 127.0.0.1:8080 · intercept armed"
        );

        i.intercept_armed = false;
        i.capture_paused = false;
        i.ca = Some(CaWord::Untrusted);
        assert_eq!(
            pill(&i),
            "aitmproxy · listening 127.0.0.1:8080 · CA untrusted"
        );
    }

    #[test]
    fn ready_card_for_m1_inputs() {
        let off = summary(State::Off);
        let i = m1_inputs(&off, Some(Path::new(LOG)), Some(Path::new("/Users/matt")));
        let card = ready_card(&i);

        assert_eq!(
            card.headline,
            "aitmproxy · listening 127.0.0.1:8080 · CA untrusted"
        );
        assert_eq!(card.headline_role, Role::Success);
        assert_eq!(
            card.rows,
            vec![
                row("Bus", "stdio (MCP)", Role::Plain, None),
                row("Operator bus", "127.0.0.1:50512", Role::Plain, None),
                row(
                    "Scope",
                    NOTHING_DECRYPTED_ADVICE,
                    Role::Plain,
                    Some("aitm scope add --host <host>")
                ),
                row("CA", "untrusted", Role::Warning, Some("aitm ca install")),
                row(
                    "System proxy",
                    "off",
                    Role::Warning,
                    Some("aitm proxy system set")
                ),
                row("Log", TILDE_LOG, Role::Dim, None),
            ]
        );
        // The whole M1 block falls out of the T3 renderer.
        assert_eq!(card.render_rich(&tty_no_color(), &RICH), M1);

        // No home (a pipe, C7): the full log path.
        let piped = ReadyInputs {
            home: None,
            ..i.clone()
        };
        assert_eq!(ready_card(&piped).rows[5], row("Log", LOG, Role::Dim, None));

        // Trusted: the pill says so and the CA row is gone.
        let trusted = ReadyInputs {
            ca: Some(CaWord::Trusted),
            ..i.clone()
        };
        let card = ready_card(&trusted);
        assert_eq!(
            card.headline,
            "aitmproxy · listening 127.0.0.1:8080 · CA trusted"
        );
        assert_eq!(
            labels(&card.rows),
            vec!["Bus", "Operator bus", "Scope", "System proxy", "Log"]
        );

        // Unread: no word, no row (T7, an unread state never renders as
        // untrusted).
        let unread = ReadyInputs {
            ca: None,
            ..i.clone()
        };
        let card = ready_card(&unread);
        assert_eq!(card.headline, "aitmproxy · listening 127.0.0.1:8080");
        assert_eq!(
            labels(&card.rows),
            vec!["Bus", "Operator bus", "Scope", "System proxy", "Log"]
        );

        // Two hosts in Scope: the count, no next step.
        let scoped = ReadyInputs {
            scope_hosts: 2,
            ..i.clone()
        };
        assert_eq!(
            ready_card(&scoped).rows[2],
            row("Scope", "2 hosts in Scope", Role::Plain, None)
        );

        // No log file (AC-W1-17): the Log row is omitted.
        let no_log = ReadyInputs {
            log: None,
            ..i.clone()
        };
        assert_eq!(
            labels(&ready_card(&no_log).rows),
            vec!["Bus", "Operator bus", "Scope", "CA", "System proxy"]
        );

        // The bus word is the Bus row's value in server mode.
        let loopback = ReadyInputs {
            bus: BusWord::Loopback(5555),
            ..i.clone()
        };
        assert_eq!(
            ready_card(&loopback).rows[0],
            row("Bus", "loopback 127.0.0.1:5555", Role::Plain, None)
        );
    }

    #[test]
    fn system_proxy_row_roles_in_the_card() {
        let i_for = |s: &Summary| -> (String, Role) {
            let inputs = m1_inputs(s, None, None);
            let card = ready_card(&inputs);
            let r = card
                .rows
                .iter()
                .find(|r| r.label == "System proxy")
                .expect("System proxy row");
            (r.value.clone(), r.value_role)
        };
        assert_eq!(
            i_for(&summary(State::Off)),
            ("off".to_string(), Role::Warning)
        );
        assert_eq!(
            i_for(&summary(State::Other {
                host: "10.0.0.5".to_string(),
                port: 3128
            })),
            ("points at 10.0.0.5:3128".to_string(), Role::Warning)
        );
        assert_eq!(
            i_for(&summary(State::NeedsPrivilege)),
            ("needs privilege".to_string(), Role::Warning)
        );
        assert_eq!(
            i_for(&summary(State::Unknown)),
            ("unknown".to_string(), Role::Warning)
        );
        assert_eq!(
            i_for(&summary(State::PointsAtUs)),
            ("points at this proxy".to_string(), Role::Plain)
        );
    }

    #[test]
    fn ready_card_for_m6_web_inputs() {
        let at_us = summary(State::PointsAtUs);
        let i = ReadyInputs {
            mode: ModeWord::Web,
            proxy: addr("127.0.0.1:8080"),
            browser: addr("127.0.0.1:8081"),
            // The web card says `ready` whatever the bus transport is (T7).
            bus: BusWord::Loopback(8083),
            operator_bus: OperatorBusWord::Dedicated(addr("127.0.0.1:50512")),
            web_url: Some(WEB_URL),
            operator_url: Some(OPERATOR_URL),
            ca: Some(CaWord::Trusted),
            scope_hosts: 0,
            system_proxy: &at_us,
            intercept_armed: false,
            capture_paused: false,
            log: Some(Path::new(LOG)),
            home: Some(Path::new("/Users/matt")),
        };
        let card = ready_card(&i);

        assert_eq!(
            card.headline,
            "aitmproxy · listening 127.0.0.1:8080 · CA trusted"
        );
        assert_eq!(
            card.rows,
            vec![
                row("Web UI", WEB_URL, Role::Plain, None),
                row("Operator", OPERATOR_URL, Role::Plain, None),
                row("Proxy", "127.0.0.1:8080", Role::Plain, None),
                row(
                    "Browser",
                    "127.0.0.1:8081  (SSRF-filtered)",
                    Role::Plain,
                    None
                ),
                row("Bus", "ready", Role::Plain, None),
                row("Operator bus", "127.0.0.1:50512", Role::Plain, None),
                row(
                    "Scope",
                    NOTHING_DECRYPTED_ADVICE,
                    Role::Plain,
                    Some("aitm scope add --host <host>")
                ),
                row("System proxy", "points at this proxy", Role::Plain, None),
                row("Log", TILDE_LOG, Role::Dim, None),
            ]
        );

        // AC-W1-24: the URL rows keep their shape, value at column 17.
        let rich = card.render_rich(&tty_no_color(), &RICH);
        assert!(
            rich.contains("  Web UI        http://127.0.0.1:8082/#t=abc\n"),
            "{rich:?}"
        );
        assert!(
            rich.contains("  Operator      http://127.0.0.1:8082/#t=def&expect=operator\n"),
            "{rich:?}"
        );
        let plain = card.render_plain(&RICH);
        assert!(
            plain.contains("Operator: http://127.0.0.1:8082/#t=def&expect=operator\n"),
            "{plain:?}"
        );
        assert!(
            plain.contains("Web UI: http://127.0.0.1:8082/#t=abc\n"),
            "{plain:?}"
        );

        // No operator token configured (M6): the Operator row is absent.
        let no_operator = ReadyInputs {
            operator_url: None,
            ..i.clone()
        };
        assert_eq!(
            labels(&ready_card(&no_operator).rows),
            vec![
                "Web UI",
                "Proxy",
                "Browser",
                "Bus",
                "Operator bus",
                "Scope",
                "System proxy",
                "Log"
            ]
        );
    }

    #[test]
    fn recovery_and_browser_summaries() {
        assert_eq!(recovery_summary(&Recovery::Nothing), None);
        assert_eq!(
            recovery_summary(&Recovery::Adopted { pid: 42 }),
            Some("system proxy adopted · watchdog 42".to_string())
        );
        assert_eq!(
            recovery_summary(&Recovery::Forgot),
            Some("system proxy state file forgotten".to_string())
        );
        assert_eq!(recovery_summary(&Recovery::Failed("x".to_string())), None);
        assert_eq!(
            recovery_summary(&Recovery::Restored {
                restored: vec!["Wi-Fi".to_string(), "Ethernet".to_string()],
                left_alone: Vec::new(),
            }),
            Some("system proxy restored · 2 services".to_string())
        );
        assert_eq!(
            recovery_summary(&Recovery::Restored {
                restored: vec!["Wi-Fi".to_string()],
                left_alone: vec!["Ethernet".to_string()],
            }),
            Some("system proxy restored · 1 service".to_string())
        );
        let set = Status {
            state: State::PointsAtUs,
            detail: String::new(),
            ours: Endpoint {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            mechanism: Mechanism::Networksetup,
            supported: true,
            managed_by_us: true,
            setting: true,
            effective: None,
            services: Vec::new(),
            bypass_default: Vec::new(),
            guidance: None,
            remedy: None,
            last_change_ms: None,
            watchdog_pid: None,
            state_file: PathBuf::from("/tmp/sysproxy.json"),
        };
        assert_eq!(
            recovery_summary(&Recovery::Set(Box::new(set))),
            Some("system proxy set to this proxy".to_string())
        );

        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("0.3.1")),
            "obscura probed 0.3.1"
        );
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, None),
            "obscura probed"
        );
        assert_eq!(
            browser_summary(&BrowserEngine::Chrome, None),
            "browser ready (chrome)"
        );
        assert_eq!(
            browser_summary(&BrowserEngine::Firefox, None),
            "browser ready (firefox)"
        );
    }

    /// Live dry-run finding D4: obscura's `--version` output is
    /// `obscura aitm-v1`, so the raw string printed `obscura probed obscura
    /// aitm-v1`. Spec T7 is `obscura probed <version>` (the plan's live regex
    /// is `^obscura probed \S+$`): a leading engine name, case-insensitive
    /// and followed by one or more spaces, is dropped and the rest trimmed.
    #[test]
    fn browser_summary_strips_the_engine_name_from_the_version() {
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("obscura aitm-v1")),
            "obscura probed aitm-v1"
        );
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("Obscura   aitm-v1")),
            "obscura probed aitm-v1"
        );
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("  obscura aitm-v1 \n")),
            "obscura probed aitm-v1"
        );
        // A bare engine name carries no version: same line as `None`.
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("obscura")),
            "obscura probed"
        );
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("   ")),
            "obscura probed"
        );
        // A version that merely contains the name is left alone.
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("aitm-v1 (obscura)")),
            "obscura probed aitm-v1 (obscura)"
        );
        // The pre-existing forms are unchanged.
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, Some("0.3.1")),
            "obscura probed 0.3.1"
        );
        assert_eq!(
            browser_summary(&BrowserEngine::Obscura, None),
            "obscura probed"
        );
    }

    #[test]
    fn read_ca_trust_without_a_certificate_is_none() {
        // No `ca.crt` → `CaCert::load` is `Ok(None)` and the read stops
        // before it asks the platform anything; no process is spawned.
        let dir = std::env::temp_dir().join(format!(
            "aitm-card-no-cert-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_ca_trust(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);

        // A directory that does not exist at all reads the same way.
        assert_eq!(
            read_ca_trust(Path::new("/nonexistent/aitm-card-test/ca")),
            None
        );
    }

    // ---- tester, whole-branch pass (spec D10, T7, M1p, M6; AC-W1-5/6/7/8) ----

    /// Every `BusWord` is the Server (and Tui) card's `Bus` value verbatim;
    /// the Web card says `ready` whatever the transport is.
    #[test]
    fn ready_card_bus_row_for_every_bus_word() {
        let off = summary(State::Off);
        let table = [
            (BusWord::Stdio, "stdio (MCP)"),
            (BusWord::Loopback(0), "loopback 127.0.0.1 (ephemeral port)"),
            (BusWord::Loopback(65535), "loopback 127.0.0.1:65535"),
            (BusWord::Http(addr("127.0.0.1:8084")), "http 127.0.0.1:8084"),
            (BusWord::Http(addr("[::1]:8084")), "http [::1]:8084"),
            (BusWord::Off, "off"),
        ];
        for (bus, text) in table {
            for mode in [ModeWord::Server, ModeWord::Tui] {
                let i = ReadyInputs {
                    mode,
                    bus,
                    ..m1_inputs(&off, None, None)
                };
                let card = ready_card(&i);
                assert_eq!(
                    card.rows[0],
                    row("Bus", text, Role::Plain, None),
                    "{mode:?} {bus:?}"
                );
                assert_eq!(
                    labels(&card.rows),
                    vec!["Bus", "Operator bus", "Scope", "CA", "System proxy"],
                    "{mode:?} {bus:?}"
                );
            }
            let web = ReadyInputs {
                mode: ModeWord::Web,
                bus,
                web_url: Some(WEB_URL),
                ..m1_inputs(&off, None, None)
            };
            let card = ready_card(&web);
            assert_eq!(
                card.rows[3],
                row("Bus", "ready", Role::Plain, None),
                "{bus:?}"
            );
        }
    }

    /// Every `State` as the `System proxy` row: value, role and next step
    /// (spec T7); the row is always present and sits right before `Log`.
    #[test]
    fn ready_card_system_proxy_row_for_every_state() {
        let table: [(State, &str, Role, Option<&str>); 6] = [
            (
                State::Off,
                "off",
                Role::Warning,
                Some("aitm proxy system set"),
            ),
            (State::PointsAtUs, "points at this proxy", Role::Plain, None),
            (
                State::Other {
                    host: "proxy.corp.example".to_string(),
                    port: 8888,
                },
                "points at proxy.corp.example:8888",
                Role::Warning,
                Some("aitm proxy system set"),
            ),
            (
                State::NeedsPrivilege,
                "needs privilege",
                Role::Warning,
                None,
            ),
            (
                State::Unsupported,
                "unsupported on this platform",
                Role::Plain,
                None,
            ),
            (State::Unknown, "unknown", Role::Warning, None),
        ];
        for (state, value, role, next) in table {
            let s = summary(state.clone());
            let i = m1_inputs(&s, Some(Path::new(LOG)), None);
            let card = ready_card(&i);
            let n = card.rows.len();
            assert_eq!(
                card.rows[n - 2],
                row("System proxy", value, role, next),
                "{state:?}"
            );
            assert_eq!(card.rows[n - 1].label, "Log", "{state:?}");
            assert_eq!(
                system_proxy_row(&s),
                (value.to_string(), next.map(|c| FixCommand(c.to_string()))),
                "{state:?}"
            );
        }
    }

    /// The T7 reduction over ten stores: one `yes` anywhere wins, one `no`
    /// among unknowns is `Untrusted`, all unknown is no word.
    #[test]
    fn ca_word_over_ten_stores() {
        let ten = |fill: Trust| -> Vec<StoreStatus> { (0..10).map(|_| status(fill)).collect() };
        assert_eq!(ca_word(&ten(Trust::Unknown)), None);
        assert_eq!(ca_word(&ten(Trust::No)), Some(CaWord::Untrusted));
        assert_eq!(ca_word(&ten(Trust::Yes)), Some(CaWord::Trusted));

        let mut last_yes = ten(Trust::Unknown);
        last_yes[9].trusted = Trust::Yes;
        assert_eq!(ca_word(&last_yes), Some(CaWord::Trusted));

        let mut first_no = ten(Trust::Unknown);
        first_no[0].trusted = Trust::No;
        assert_eq!(ca_word(&first_no), Some(CaWord::Untrusted));

        let mut nine_no_one_yes = ten(Trust::No);
        nine_no_one_yes[9].trusted = Trust::Yes;
        assert_eq!(ca_word(&nine_no_one_yes), Some(CaWord::Trusted));
    }

    /// `read_ca_trust` answers `None` before any trust-store tool runs when
    /// the certificate cannot be loaded: no PEM at all, a PEM block of the
    /// wrong label, two CERTIFICATE blocks, or a key file with no
    /// certificate. Hermetic: none of these reaches `Platform::detect`.
    #[test]
    fn read_ca_trust_with_an_unloadable_certificate_is_none() {
        let base = std::env::temp_dir().join(format!(
            "aitm-card-bad-cert-{}-{}",
            std::process::id(),
            line!()
        ));
        let cases: [(&str, &str); 4] = [
            ("not-pem", "not a certificate\n"),
            (
                "wrong-label",
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            ),
            (
                "two-blocks",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            ),
            ("empty", ""),
        ];
        for (name, pem) in cases {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("ca.crt"), pem).unwrap();
            assert_eq!(read_ca_trust(&dir), None, "{name}");
        }
        let key_only = base.join("key-only");
        std::fs::create_dir_all(&key_only).unwrap();
        std::fs::write(key_only.join("ca.key"), "not a key\n").unwrap();
        assert_eq!(
            read_ca_trust(&key_only),
            None,
            "a key without a certificate"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The Tui card, were it asked for, is the Server card (D11 prints none).
    #[test]
    fn ready_card_tui_mode_is_the_server_card() {
        let off = summary(State::Off);
        let server = m1_inputs(&off, Some(Path::new(LOG)), Some(Path::new("/Users/matt")));
        let tui = ReadyInputs {
            mode: ModeWord::Tui,
            ..server.clone()
        };
        assert_eq!(ready_card(&tui), ready_card(&server));
    }

    /// A Web card with no URLs omits the URL rows rather than printing a
    /// placeholder.
    #[test]
    fn ready_card_web_without_urls_has_no_url_rows() {
        let at_us = summary(State::PointsAtUs);
        let i = ReadyInputs {
            mode: ModeWord::Web,
            web_url: None,
            operator_url: None,
            ca: Some(CaWord::Trusted),
            ..m1_inputs(&at_us, Some(Path::new(LOG)), None)
        };
        assert_eq!(
            labels(&ready_card(&i).rows),
            vec![
                "Proxy",
                "Browser",
                "Bus",
                "Operator bus",
                "Scope",
                "System proxy",
                "Log"
            ]
        );
    }

    /// AC-W1-5 / M1p: the plain card for M1's inputs on a pipe (no `~`),
    /// byte for byte, no pill line, `Label: value · command` rows.
    #[test]
    fn plain_card_for_m1p_inputs_is_byte_exact() {
        let off = summary(State::Off);
        let piped = m1_inputs(&off, Some(Path::new(LOG)), None);
        assert_eq!(
            ready_card(&piped).render_plain(&RICH),
            concat!(
                "Bus: stdio (MCP)\n",
                "Operator bus: 127.0.0.1:50512\n",
                "Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>\n",
                "CA: untrusted · aitm ca install\n",
                "System proxy: off · aitm proxy system set\n",
                "Log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log\n",
            )
        );
        // A `home` given to a pipe is still honoured by the renderer-agnostic
        // card (C7 says the caller passes `None`); nothing else changes.
        let with_home = m1_inputs(&off, Some(Path::new(LOG)), Some(Path::new("/Users/matt")));
        assert_eq!(
            ready_card(&with_home).render_plain(&RICH).lines().last(),
            Some("Log: ~/Library/Application Support/aitmproxy/logs/aitm.log")
        );
        // AC-W1-5: zero escape bytes and no carriage return in the plain form.
        let plain = ready_card(&piped).render_plain(&RICH);
        assert!(!plain.as_bytes().contains(&0x1b));
        assert!(!plain.contains('\r'));
    }

    /// M6 piped: the Web card's plain rows in order, URLs whole.
    #[test]
    fn plain_card_for_m6_web_inputs_is_byte_exact() {
        let at_us = summary(State::PointsAtUs);
        let i = ReadyInputs {
            mode: ModeWord::Web,
            web_url: Some(WEB_URL),
            operator_url: Some(OPERATOR_URL),
            ca: Some(CaWord::Trusted),
            ..m1_inputs(&at_us, Some(Path::new(LOG)), None)
        };
        assert_eq!(
            ready_card(&i).render_plain(&RICH),
            concat!(
                "Web UI: http://127.0.0.1:8082/#t=abc\n",
                "Operator: http://127.0.0.1:8082/#t=def&expect=operator\n",
                "Proxy: 127.0.0.1:8080\n",
                "Browser: 127.0.0.1:8081  (SSRF-filtered)\n",
                "Bus: ready\n",
                "Operator bus: 127.0.0.1:50512\n",
                "Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>\n",
                "System proxy: points at this proxy\n",
                "Log: /Users/matt/Library/Application Support/aitmproxy/logs/aitm.log\n",
            )
        );
    }

    #[test]
    fn recovery_summary_restored_with_no_services() {
        assert_eq!(
            recovery_summary(&Recovery::Restored {
                restored: Vec::new(),
                left_alone: vec!["Wi-Fi".to_string()],
            }),
            Some("system proxy restored · 0 services".to_string())
        );
    }

    // ---- R14 one-shot verbs on a running core (spec D5, D14; plan Task 9;
    // AC-R14-1/2/5/6, the card half) ----

    /// `Dedicated` is a plain `Operator bus` row carrying the address; `Off`
    /// is `off · <reason>` painted as a warning; `Shared` has no row of its
    /// own (its word rides on the `Bus` row instead, C16).
    #[test]
    fn operator_bus_row_dedicated_and_off() {
        assert_eq!(
            operator_bus_row(&OperatorBusWord::Dedicated(addr("127.0.0.1:50512"))),
            Some(Row {
                label: "Operator bus",
                value: "127.0.0.1:50512".to_string(),
                value_role: Role::Plain,
                next: None,
            })
        );
        assert_eq!(
            operator_bus_row(&OperatorBusWord::Off(
                "mcp.operator_bus.enabled: false".to_string()
            )),
            Some(row(
                "Operator bus",
                "off · mcp.operator_bus.enabled: false",
                Role::Warning,
                None
            ))
        );
        assert_eq!(
            operator_bus_row(&OperatorBusWord::Off(
                "could not write mcp.operator_token to /tmp/cfg.yaml".to_string()
            ))
            .map(|r| r.value),
            Some("off · could not write mcp.operator_token to /tmp/cfg.yaml".to_string())
        );
        assert_eq!(operator_bus_row(&OperatorBusWord::Shared), None);
        assert_eq!(OPERATOR_BUS_LABEL, "Operator bus");
        assert_eq!(OPERATOR_BUS_LABEL.len(), 12, "within T3's 14-column label");
    }

    /// AC-R14-6: the shared plan appends ` · operator` to the `Bus` value
    /// (every `BusWord` form; `ready · operator` on the Web card); a
    /// dedicated or off bus leaves the value exactly as W1 wrote it.
    #[test]
    fn bus_row_gets_the_operator_suffix_when_shared() {
        let dedicated = OperatorBusWord::Dedicated(addr("127.0.0.1:50512"));
        let off = OperatorBusWord::Off("mcp.operator_bus.enabled: false".to_string());
        assert_eq!(
            bus_row_value(
                &BusWord::Loopback(9090),
                ModeWord::Server,
                &OperatorBusWord::Shared
            ),
            "loopback 127.0.0.1:9090 · operator"
        );
        assert_eq!(
            bus_row_value(
                &BusWord::Loopback(0),
                ModeWord::Server,
                &OperatorBusWord::Shared
            ),
            "loopback 127.0.0.1 (ephemeral port) · operator"
        );
        assert_eq!(
            bus_row_value(&BusWord::Stdio, ModeWord::Server, &dedicated),
            "stdio (MCP)"
        );
        assert_eq!(
            bus_row_value(&BusWord::Stdio, ModeWord::Web, &OperatorBusWord::Shared),
            "ready · operator"
        );
        assert_eq!(
            bus_row_value(&BusWord::Loopback(9090), ModeWord::Web, &dedicated),
            "ready"
        );
        assert_eq!(
            bus_row_value(&BusWord::Stdio, ModeWord::Server, &off),
            "stdio (MCP)"
        );
        assert_eq!(
            bus_row_value(
                &BusWord::Http(addr("127.0.0.1:8084")),
                ModeWord::Tui,
                &OperatorBusWord::Shared
            ),
            "http 127.0.0.1:8084 · operator"
        );
    }

    /// D14 (AC-W1-6 re-pinned): the Scope next step is promised only when a
    /// one-shot can reach this core as the operator; the counts are W1's.
    #[test]
    fn scope_row_promises_only_when_reachable() {
        assert_eq!(
            scope_row(0, true),
            (
                NOTHING_DECRYPTED_ADVICE.to_string(),
                fix("aitm scope add --host <host>")
            )
        );
        assert_eq!(
            scope_row(0, false),
            (NOTHING_DECRYPTED_ADVICE.to_string(), None)
        );
        assert_eq!(scope_row(2, true), ("2 hosts in Scope".to_string(), None));
        assert_eq!(scope_row(2, false), ("2 hosts in Scope".to_string(), None));
        assert_eq!(scope_row(1, false), ("1 host in Scope".to_string(), None));
    }

    /// AC-R14-1/5 piped: the `Operator bus` line sits directly after `Bus`;
    /// with the bus off the row carries the reason and the Scope line has no
    /// ` · aitm scope add` tail. AC-R14-6: the shared plan prints no
    /// `Operator bus` line and the Scope promise stands.
    #[test]
    fn ready_card_plain_has_the_operator_bus_row_after_bus() {
        let off_proxy = summary(State::Off);
        let dedicated = ReadyInputs {
            operator_bus: OperatorBusWord::Dedicated(addr("127.0.0.1:50512")),
            ..m1_inputs(&off_proxy, None, None)
        };
        let plain = ready_card(&dedicated).render_plain(&RICH);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(
            lines[..3],
            [
                "Bus: stdio (MCP)",
                "Operator bus: 127.0.0.1:50512",
                "Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>",
            ]
        );

        let off = ReadyInputs {
            operator_bus: OperatorBusWord::Off("mcp.operator_bus.enabled: false".to_string()),
            ..m1_inputs(&off_proxy, None, None)
        };
        let plain = ready_card(&off).render_plain(&RICH);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(
            lines[..3],
            [
                "Bus: stdio (MCP)",
                "Operator bus: off · mcp.operator_bus.enabled: false",
                "Scope: Nothing is decrypted until a host is in Scope.",
            ]
        );
        assert!(!plain.contains("aitm scope add"), "{plain:?}");

        let shared = ReadyInputs {
            bus: BusWord::Loopback(9090),
            operator_bus: OperatorBusWord::Shared,
            ..m1_inputs(&off_proxy, None, None)
        };
        let plain = ready_card(&shared).render_plain(&RICH);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(
            lines[..2],
            [
                "Bus: loopback 127.0.0.1:9090 · operator",
                "Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>",
            ]
        );
        assert!(!plain.contains("Operator bus"), "{plain:?}");

        // The Web card on the shared plan: `ready · operator`, still no
        // `Operator bus` line.
        let web_shared = ReadyInputs {
            mode: ModeWord::Web,
            web_url: Some(WEB_URL),
            ..shared.clone()
        };
        let plain = ready_card(&web_shared).render_plain(&RICH);
        assert!(plain.contains("Bus: ready · operator\n"), "{plain:?}");
        assert!(!plain.contains("Operator bus"), "{plain:?}");
    }

    /// AC-R14-1 (TTY): the 12-character label pads to T3's 14-column field,
    /// so the value starts at column 17 like every other row; the `off`
    /// value renders with its reason and the Scope row below it has no fix
    /// line (AC-R14-5).
    #[test]
    fn ready_card_rich_pads_the_operator_bus_label() {
        let off_proxy = summary(State::Off);
        let i = ReadyInputs {
            operator_bus: OperatorBusWord::Dedicated(addr("127.0.0.1:50512")),
            ..m1_inputs(&off_proxy, None, None)
        };
        let rich = ready_card(&i).render_rich(&tty_no_color(), &RICH);
        assert_eq!(rich.lines().nth(1), Some("  Bus           stdio (MCP)"));
        assert_eq!(rich.lines().nth(2), Some("  Operator bus  127.0.0.1:50512"));

        let off = ReadyInputs {
            operator_bus: OperatorBusWord::Off("mcp.operator_bus.enabled: false".to_string()),
            ..i.clone()
        };
        let rich = ready_card(&off).render_rich(&tty_no_color(), &RICH);
        assert_eq!(
            rich.lines().nth(2),
            Some("  Operator bus  off · mcp.operator_bus.enabled: false")
        );
        assert_eq!(
            rich.lines().nth(3),
            Some("  Scope         Nothing is decrypted until a host is in Scope.")
        );
        assert_eq!(rich.lines().nth(4), Some("  CA            untrusted"));
    }

    // ---- tester additions (stage 5, R14 pass 1) ----

    /// Tester — AC-R14-2/5 on the Web and TUI cards (D5 says every surface):
    /// the `Operator bus` row follows `Bus` on both; `Off` carries the reason
    /// as a warning and drops the Scope next step on both; the Web card on
    /// the shared plan says `Bus: ready · operator` and nothing else moves;
    /// the rich Web card pads the label like every other row.
    #[test]
    fn tester_web_and_tui_cards_carry_the_operator_bus_row() {
        let off_proxy = summary(State::Off);
        let base = m1_inputs(&off_proxy, None, None);

        let web_off = ReadyInputs {
            mode: ModeWord::Web,
            web_url: Some(WEB_URL),
            operator_bus: OperatorBusWord::Off("no mcp.operator_token".to_string()),
            ..base.clone()
        };
        let card = ready_card(&web_off);
        assert_eq!(
            labels(&card.rows),
            vec![
                "Web UI",
                "Proxy",
                "Browser",
                "Bus",
                "Operator bus",
                "Scope",
                "CA",
                "System proxy"
            ]
        );
        assert_eq!(
            card.rows[4],
            row(
                "Operator bus",
                "off · no mcp.operator_token",
                Role::Warning,
                None
            )
        );
        let plain = card.render_plain(&RICH);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(lines[3], "Bus: ready");
        assert_eq!(lines[4], "Operator bus: off · no mcp.operator_token");
        assert_eq!(
            lines[5],
            "Scope: Nothing is decrypted until a host is in Scope."
        );
        assert!(!plain.contains("aitm scope add"), "{plain:?}");
        let rich = card.render_rich(&tty_no_color(), &RICH);
        assert!(
            rich.contains("\n  Bus           ready\n  Operator bus  off · no mcp.operator_token\n  Scope         Nothing is decrypted until a host is in Scope.\n"),
            "{rich:?}"
        );

        let tui_dedicated = ReadyInputs {
            mode: ModeWord::Tui,
            operator_bus: OperatorBusWord::Dedicated(addr("127.0.0.1:50512")),
            ..base.clone()
        };
        let plain = ready_card(&tui_dedicated).render_plain(&RICH);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(
            lines[..3],
            [
                "Bus: stdio (MCP)",
                "Operator bus: 127.0.0.1:50512",
                "Scope: Nothing is decrypted until a host is in Scope. · aitm scope add --host <host>",
            ]
        );

        let tui_off = ReadyInputs {
            mode: ModeWord::Tui,
            operator_bus: OperatorBusWord::Off("mcp.operator_bus.enabled: false".to_string()),
            ..base.clone()
        };
        let plain = ready_card(&tui_off).render_plain(&RICH);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(
            lines[..3],
            [
                "Bus: stdio (MCP)",
                "Operator bus: off · mcp.operator_bus.enabled: false",
                "Scope: Nothing is decrypted until a host is in Scope.",
            ]
        );

        // Scope non-empty with the bus off: the count, no next step, the
        // reason still on its own row.
        let tui_off_scoped = ReadyInputs {
            scope_hosts: 3,
            ..tui_off.clone()
        };
        let plain = ready_card(&tui_off_scoped).render_plain(&RICH);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(lines[2], "Scope: 3 hosts in Scope");
        assert!(!plain.contains("aitm scope add"), "{plain:?}");
    }

    /// Tester — the `off` reason is printed as given, in full: the long
    /// mint-failure form with a path containing a space stays on the row
    /// unshortened in the plain render (panels and cards never shorten a
    /// path they were given in a reason).
    #[test]
    fn tester_off_reason_prints_in_full() {
        let reason =
            "could not write mcp.operator_token to /Users/matt/Library/Application Support/aitmproxy/config.yaml";
        let row = operator_bus_row(&OperatorBusWord::Off(reason.to_string())).expect("a row");
        assert_eq!(row.value, format!("off · {reason}"));
        assert_eq!(row.value_role, Role::Warning);
        assert_eq!(row.next, None);
        let off_proxy = summary(State::Off);
        let i = ReadyInputs {
            operator_bus: OperatorBusWord::Off(reason.to_string()),
            ..m1_inputs(&off_proxy, None, None)
        };
        let plain = ready_card(&i).render_plain(&RICH);
        assert!(
            plain.contains(&format!("Operator bus: off · {reason}\n")),
            "{plain:?}"
        );
    }
}
