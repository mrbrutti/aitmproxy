//! macOS: `networksetup` per service for snapshots and writes, `scutil --proxy`
//! for the effective view (spec §D3). Every OS read and write is a rendered
//! [`CmdLine`] run through the executor, so the exact lines are unit-tested
//! against canned output on any host.

use aitm_ca::exec::{CmdLine, Executor};

use crate::platform::{cmd, PlatformOps, Snapshot};
use crate::state::Previous;
use crate::{
    merge_bypass, remedy, Effective, Endpoint, Mechanism, ProtocolProxy, ReadError, ServiceRow,
    WriteError, BYPASS_DEFAULT,
};

/// Spawned by absolute path so a planted `networksetup` on `PATH` never wins.
pub const NETWORKSETUP: &str = "/usr/sbin/networksetup";
pub const SCUTIL: &str = "/usr/sbin/scutil";
/// What `networksetup` prints (exit 1) when the caller may not change network
/// settings; the only text that maps to `NeedsPrivilege`.
pub const ADMIN_ERROR: &str = "** Error: Command requires admin privileges.";
/// The `detail` for zero enabled services (§D3).
pub const NO_ENABLED_SERVICE: &str = "no enabled network service";

/// Printed by `networksetup` and `scutil` when the caller has no
/// SystemConfiguration session (the Claude sandbox, research 16 §2.4).
const AUTHORIZATION_FAILED: &str = "AuthorizationCreate() failed";
/// `-listallnetworkservices` header line.
const SERVICES_HEADER: &str = "An asterisk (*) denotes";
/// `-getproxybypassdomains` with nothing set prints this instead of domains.
const NO_BYPASS_DOMAINS: &str = "There aren't any bypass domains set on";
/// The word `-setproxybypassdomains` takes to clear the list.
const EMPTY_WORD: &str = "Empty";

/// `-listallnetworkservices`: drop the header line and every `*`-prefixed
/// (disabled) service; the rest in list order.
pub fn parse_services(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim_end)
        .filter(|line| {
            !line.is_empty() && !line.starts_with('*') && !line.starts_with(SERVICES_HEADER)
        })
        .map(str::to_string)
        .collect()
}

/// The value after `<key>:` on the first line that starts with `<key>:`.
fn field<'a>(stdout: &'a str, key: &str) -> Option<&'a str> {
    stdout
        .lines()
        .find_map(|line| {
            line.strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(':'))
        })
        .map(str::trim)
}

/// `-getwebproxy` / `-getsecurewebproxy`: `Enabled: Yes|No`, `Server:`,
/// `Port:`. A missing or unparsable port is `0`; a missing server is `""`.
pub fn parse_get_proxy(stdout: &str) -> ProtocolProxy {
    ProtocolProxy {
        enabled: field(stdout, "Enabled").is_some_and(|v| v.eq_ignore_ascii_case("yes")),
        host: field(stdout, "Server").unwrap_or_default().to_string(),
        port: field(stdout, "Port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    }
}

/// `Authenticated Proxy Enabled: 1` on a `-get*proxy` read.
pub fn parse_get_proxy_authenticated(stdout: &str) -> bool {
    field(stdout, "Authenticated Proxy Enabled") == Some("1")
}

/// `-getproxybypassdomains`: one domain per line; the literal
/// `There aren't any bypass domains set on <svc>.` means empty.
pub fn parse_bypass(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(NO_BYPASS_DOMAINS))
        .map(str::to_string)
        .collect()
}

/// `scutil --proxy`: a `key : value` dump with nested `<array> {` / `<dictionary> {`
/// blocks. Only the top-level keys count (a `__SCOPED__` sub-dictionary is
/// skipped). An empty dictionary (the sandbox) or an `AuthorizationCreate()
/// failed` line is `Unavailable`, never "off".
pub fn parse_scutil(stdout: &str) -> Result<Effective, ReadError> {
    if stdout.contains(AUTHORIZATION_FAILED) {
        return Err(ReadError::Unavailable(format!(
            "scutil --proxy: {}",
            stdout.trim()
        )));
    }
    let mut http = ProtocolProxy::default();
    let mut https = ProtocolProxy::default();
    let mut bypass = Vec::new();
    let mut saw_enable = false;
    // Nesting depth: 0 outside, 1 inside the top dictionary. `exceptions`
    // is the depth of the ExceptionsList array body while we are in it.
    let mut depth = 0usize;
    let mut exceptions: Option<usize> = None;
    for raw in stdout.lines() {
        let line = raw.trim();
        if line == "}" {
            if exceptions == Some(depth) {
                exceptions = None;
            }
            depth = depth.saturating_sub(1);
            continue;
        }
        let opens = line.ends_with('{');
        let body = line.trim_end_matches('{').trim();
        if let Some((key, value)) = body.split_once(':').map(|(k, v)| (k.trim(), v.trim())) {
            if exceptions == Some(depth) {
                bypass.push(value.to_string());
            } else if depth == 1 {
                match key {
                    "ExceptionsList" if opens => exceptions = Some(depth + 1),
                    "HTTPEnable" => {
                        saw_enable = true;
                        http.enabled = value == "1";
                    }
                    "HTTPSEnable" => {
                        saw_enable = true;
                        https.enabled = value == "1";
                    }
                    "HTTPProxy" => http.host = value.to_string(),
                    "HTTPSProxy" => https.host = value.to_string(),
                    "HTTPPort" => http.port = scutil_port(key, value)?,
                    "HTTPSPort" => https.port = scutil_port(key, value)?,
                    _ => {}
                }
            }
        }
        if opens {
            depth += 1;
        }
    }
    if !saw_enable {
        return Err(ReadError::Unavailable(
            "scutil --proxy returned an empty dictionary (no SystemConfiguration access?)"
                .to_string(),
        ));
    }
    Ok(Effective {
        http,
        https,
        bypass,
    })
}

fn scutil_port(key: &str, value: &str) -> Result<u16, ReadError> {
    value
        .parse()
        .map_err(|_| ReadError::Failed(format!("scutil --proxy: {key} is not a port: {value:?}")))
}

/// What `read_services_full` returns: every enabled service's row, plus the
/// names of those whose proxy is `Authenticated Proxy Enabled: 1` (their
/// password cannot be restored, so a set must not write them; §D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacosServices {
    pub rows: Vec<ServiceRow>,
    pub authenticated: Vec<String>,
}

/// The three mutating lines of a set for one service (§D3): web, secure web,
/// then the whole bypass list in one replace. An empty list renders the
/// `Empty` word, which is what `networksetup` takes for "none".
pub(crate) fn render_write(service: &str, ours: &Endpoint, bypass: &[String]) -> [CmdLine; 3] {
    let port = ours.port.to_string();
    [
        cmd(
            NETWORKSETUP,
            &["-setwebproxy", service, &ours.host, &port],
            true,
        ),
        cmd(
            NETWORKSETUP,
            &["-setsecurewebproxy", service, &ours.host, &port],
            true,
        ),
        render_bypass(service, bypass),
    ]
}

/// The §D3 restore lines for the services named in `only`, in `previous`
/// order: per protocol, `-set<proto> <svc> <host> <port>` then
/// `-set<proto>state <svc> on|off` when the previous host is non-empty, or
/// only `-set<proto>state <svc> off` when it was never configured; then the
/// previous bypass list (`Empty` when it was empty).
pub(crate) fn render_restore(previous: &[ServiceRow], only: &[String]) -> Vec<CmdLine> {
    let mut lines = Vec::new();
    for row in previous.iter().filter(|r| only.contains(&r.service)) {
        render_restore_protocol(&mut lines, &row.service, "-setwebproxy", &row.http);
        render_restore_protocol(&mut lines, &row.service, "-setsecurewebproxy", &row.https);
        lines.push(render_bypass(&row.service, &row.bypass));
    }
    lines
}

fn render_restore_protocol(
    lines: &mut Vec<CmdLine>,
    service: &str,
    setter: &str,
    prev: &ProtocolProxy,
) {
    let state_setter = format!("{setter}state");
    if prev.host.is_empty() {
        lines.push(cmd(NETWORKSETUP, &[&state_setter, service, "off"], true));
        return;
    }
    let port = prev.port.to_string();
    lines.push(cmd(
        NETWORKSETUP,
        &[setter, service, &prev.host, &port],
        true,
    ));
    let on_off = if prev.enabled { "on" } else { "off" };
    lines.push(cmd(NETWORKSETUP, &[&state_setter, service, on_off], true));
}

fn render_bypass(service: &str, bypass: &[String]) -> CmdLine {
    let mut args = vec!["-setproxybypassdomains", service];
    if bypass.is_empty() {
        args.push(EMPTY_WORD);
    } else {
        args.extend(bypass.iter().map(String::as_str));
    }
    cmd(NETWORKSETUP, &args, true)
}

/// Run one query; an executor error, a non-zero exit, or the authorization
/// text become the matching `ReadError`.
fn run_query(exec: &dyn Executor, line: &CmdLine) -> Result<String, ReadError> {
    let rendered = line.render();
    let out = exec
        .run(line)
        .map_err(|e| ReadError::Failed(format!("{rendered}: {e}")))?;
    if out.stdout.contains(AUTHORIZATION_FAILED) || out.stderr.contains(AUTHORIZATION_FAILED) {
        return Err(ReadError::Unavailable(format!(
            "{rendered}: {}",
            first_line(&out.stderr, &out.stdout)
        )));
    }
    if !out.success() {
        return Err(ReadError::Failed(format!(
            "{rendered}: exit {:?}: {}",
            out.code,
            first_line(&out.stderr, &out.stdout)
        )));
    }
    Ok(out.stdout)
}

/// Run one mutating line. `ADMIN_ERROR` anywhere in the output is
/// `NeedsPrivilege(remedy)`; any other non-zero exit is `Failed` naming the
/// line; an executor error that timed out is `Hung`, any other is `Failed`.
fn run_mutating(exec: &dyn Executor, line: &CmdLine, remedy: &str) -> Result<String, WriteError> {
    let rendered = line.render();
    let out = match exec.run(line) {
        Ok(out) => out,
        Err(e) if e.to_string().contains("timed out") => return Err(WriteError::Hung(rendered)),
        Err(e) => return Err(WriteError::Failed(format!("{rendered}: {e}"))),
    };
    if out.stdout.contains(ADMIN_ERROR) || out.stderr.contains(ADMIN_ERROR) {
        return Err(WriteError::NeedsPrivilege(remedy.to_string()));
    }
    if !out.success() {
        return Err(WriteError::Failed(format!(
            "{rendered}: exit {:?}: {}",
            out.code,
            first_line(&out.stderr, &out.stdout)
        )));
    }
    Ok(rendered)
}

/// The first non-empty line of `a`, else of `b`, for an error message.
fn first_line<'a>(a: &'a str, b: &'a str) -> &'a str {
    a.lines()
        .chain(b.lines())
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("")
}

fn networksetup_services(previous: &Previous) -> Result<&[ServiceRow], WriteError> {
    match previous {
        Previous::Networksetup { services } => Ok(services),
        other => Err(WriteError::Failed(format!(
            "previous snapshot is not a networksetup one: {other:?}"
        ))),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct MacosOps;

impl MacosOps {
    /// `-listallnetworkservices`, then `-getwebproxy`, `-getsecurewebproxy`,
    /// `-getproxybypassdomains` per enabled service, in list order. Zero
    /// enabled services is `Unavailable(NO_ENABLED_SERVICE)`.
    pub(crate) fn read_services_full(
        &self,
        exec: &dyn Executor,
    ) -> Result<MacosServices, ReadError> {
        let listed = run_query(
            exec,
            &cmd(NETWORKSETUP, &["-listallnetworkservices"], false),
        )?;
        let services = parse_services(&listed);
        if services.is_empty() {
            return Err(ReadError::Unavailable(NO_ENABLED_SERVICE.to_string()));
        }
        let mut rows = Vec::with_capacity(services.len());
        let mut authenticated = Vec::new();
        for service in services {
            let web = run_query(exec, &cmd(NETWORKSETUP, &["-getwebproxy", &service], false))?;
            let secure = run_query(
                exec,
                &cmd(NETWORKSETUP, &["-getsecurewebproxy", &service], false),
            )?;
            let bypass = run_query(
                exec,
                &cmd(NETWORKSETUP, &["-getproxybypassdomains", &service], false),
            )?;
            if parse_get_proxy_authenticated(&web) || parse_get_proxy_authenticated(&secure) {
                authenticated.push(service.clone());
            }
            rows.push(ServiceRow {
                service,
                http: parse_get_proxy(&web),
                https: parse_get_proxy(&secure),
                bypass: parse_bypass(&bypass),
            });
        }
        Ok(MacosServices {
            rows,
            authenticated,
        })
    }
}

impl PlatformOps for MacosOps {
    fn mechanism(&self) -> Mechanism {
        Mechanism::Networksetup
    }

    fn read_effective(&self, exec: &dyn Executor) -> Result<Effective, ReadError> {
        let out = run_query(exec, &cmd(SCUTIL, &["--proxy"], false))?;
        parse_scutil(&out)
    }

    fn read_services(&self, exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError> {
        self.read_services_full(exec).map(|full| full.rows)
    }

    /// The rows of [`Self::read_services_full`] minus the authenticated
    /// services, which are returned as `skipped` (§D3: their password cannot
    /// be restored, so they are never written).
    fn snapshot(&self, exec: &dyn Executor) -> Result<Snapshot, ReadError> {
        let MacosServices {
            rows,
            authenticated,
        } = self.read_services_full(exec)?;
        let services = rows
            .into_iter()
            .filter(|row| !authenticated.contains(&row.service))
            .collect();
        Ok(Snapshot {
            previous: Previous::Networksetup { services },
            skipped: authenticated,
        })
    }

    /// Per service in `previous`, in order: the three lines of
    /// [`render_write`] with bypass = previous ∪ default ∪ `bypass_extra`.
    /// Stops at the first failure. Authenticated services are already
    /// absent from the `previous` that [`Self::snapshot`] built, so none is
    /// written here.
    fn write(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        ours: &Endpoint,
        bypass_extra: &[String],
    ) -> Result<Vec<String>, WriteError> {
        let services = networksetup_services(previous)?;
        let remedy = remedy(ours);
        let extra: Vec<String> = BYPASS_DEFAULT
            .iter()
            .map(|s| s.to_string())
            .chain(bypass_extra.iter().cloned())
            .collect();
        let mut ran = Vec::with_capacity(services.len() * 3);
        for row in services {
            let bypass = merge_bypass(&row.bypass, &extra);
            for line in render_write(&row.service, ours, &bypass) {
                ran.push(run_mutating(exec, &line, &remedy)?);
            }
        }
        Ok(ran)
    }

    /// The [`render_restore`] lines for `only`, run in order; stops at the
    /// first failure. `restore` is given no `ours`, so a `NeedsPrivilege`
    /// here carries the failing rendered line rather than the §D3 sentence;
    /// the engine fills `Status.remedy` from `crate::remedy(&ours)`.
    fn restore(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        only: &[String],
    ) -> Result<Vec<String>, WriteError> {
        let services = networksetup_services(previous)?;
        let mut ran = Vec::new();
        for line in render_restore(services, only) {
            let rendered = line.render();
            ran.push(run_mutating(exec, &line, &rendered)?);
        }
        Ok(ran)
    }
}

#[cfg(test)]
mod tests {
    use aitm_ca::exec::CmdLine;
    use aitm_ca::testing::ScriptedExecutor;

    use super::*;
    use crate::{merge_bypass, ProtocolProxy, BYPASS_DEFAULT};

    fn ours() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }

    fn on(host: &str, port: u16) -> ProtocolProxy {
        ProtocolProxy {
            enabled: true,
            host: host.into(),
            port,
        }
    }

    fn off() -> ProtocolProxy {
        ProtocolProxy::default()
    }

    fn strs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// The two-service `previous` of the spec's §D7 document.
    fn d7_previous() -> Vec<ServiceRow> {
        vec![
            ServiceRow {
                service: "Display Ethernet".into(),
                http: on("127.0.0.1", 9090),
                https: on("127.0.0.1", 9090),
                bypass: strs(&["*.local", "169.254/16"]),
            },
            ServiceRow {
                service: "Wi-Fi".into(),
                http: off(),
                https: off(),
                bypass: strs(&["*.local", "169.254/16"]),
            },
        ]
    }

    fn rendered(lines: &[CmdLine]) -> Vec<String> {
        lines.iter().map(CmdLine::render).collect()
    }

    const SCUTIL_FULL: &str = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  FTPPassive : 1\n  HTTPEnable : 1\n  HTTPPort : 9090\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  HTTPSPort : 9090\n  HTTPSProxy : 127.0.0.1\n}\n";

    /// SP-AC1.
    #[test]
    fn parse_services_drops_header_and_disabled() {
        let out = "An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n";
        assert_eq!(parse_services(out), vec!["Display Ethernet", "Wi-Fi"]);
    }

    /// SP-AC2.
    #[test]
    fn parse_get_proxy_enabled_and_disabled() {
        let on_out =
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n";
        assert_eq!(
            parse_get_proxy(on_out),
            ProtocolProxy {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 9090
            }
        );
        assert!(!parse_get_proxy_authenticated(on_out));

        let off_out = "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n";
        assert_eq!(
            parse_get_proxy(off_out),
            ProtocolProxy {
                enabled: false,
                host: String::new(),
                port: 0
            }
        );

        let auth_out =
            "Enabled: Yes\nServer: proxy.corp\nPort: 3128\nAuthenticated Proxy Enabled: 1\n";
        assert!(parse_get_proxy_authenticated(auth_out));
    }

    /// §D3: one domain per line; the literal "There aren't any…" line is empty.
    #[test]
    fn parse_bypass_lines_and_the_empty_literal() {
        assert_eq!(
            parse_bypass("*.local\n169.254/16\n"),
            vec!["*.local", "169.254/16"]
        );
        assert_eq!(
            parse_bypass("There aren't any bypass domains set on Wi-Fi.\n"),
            Vec::<String>::new()
        );
    }

    /// SP-AC3.
    #[test]
    fn parse_scutil_full_disabled_and_sandbox() {
        let full = parse_scutil(SCUTIL_FULL).unwrap();
        assert_eq!(full.http, on("127.0.0.1", 9090));
        assert_eq!(full.https, on("127.0.0.1", 9090));
        assert_eq!(full.bypass, vec!["*.local", "169.254/16"]);

        let disabled =
            parse_scutil("<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n}\n").unwrap();
        assert_eq!(disabled.http, off());
        assert_eq!(disabled.https, off());
        assert_eq!(disabled.bypass, Vec::<String>::new());

        assert!(matches!(
            parse_scutil("<dictionary> {\n}\n"),
            Err(ReadError::Unavailable(_))
        ));
        assert!(matches!(
            parse_scutil("AuthorizationCreate() failed: -60008\n"),
            Err(ReadError::Unavailable(_))
        ));
    }

    /// SP-AC6.
    #[test]
    fn restore_renders_the_spec_lines() {
        let previous = d7_previous();
        let lines = render_restore(&previous, &strs(&["Display Ethernet", "Wi-Fi"]));
        assert!(lines.iter().all(|l| l.mutating));
        assert_eq!(
            rendered(&lines),
            vec![
                "/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 9090",
                "/usr/sbin/networksetup -setwebproxystate 'Display Ethernet' on",
                "/usr/sbin/networksetup -setsecurewebproxy 'Display Ethernet' 127.0.0.1 9090",
                "/usr/sbin/networksetup -setsecurewebproxystate 'Display Ethernet' on",
                "/usr/sbin/networksetup -setproxybypassdomains 'Display Ethernet' *.local 169.254/16",
                "/usr/sbin/networksetup -setwebproxystate Wi-Fi off",
                "/usr/sbin/networksetup -setsecurewebproxystate Wi-Fi off",
                "/usr/sbin/networksetup -setproxybypassdomains Wi-Fi *.local 169.254/16",
            ]
        );

        // `only` filters; previous order is kept.
        let only_wifi = render_restore(&previous, &strs(&["Wi-Fi"]));
        assert_eq!(only_wifi.len(), 3);
        assert!(rendered(&only_wifi).iter().all(|l| l.contains(" Wi-Fi ")));

        // An empty previous list renders the `Empty` word.
        let mut empty_bypass = previous.clone();
        empty_bypass[1].bypass.clear();
        let lines = render_restore(&empty_bypass, &strs(&["Wi-Fi"]));
        assert_eq!(
            rendered(&lines).last().map(String::as_str),
            Some("/usr/sbin/networksetup -setproxybypassdomains Wi-Fi Empty")
        );
    }

    /// SP-AC5, the rendering half.
    #[test]
    fn write_renders_three_lines_per_service() {
        let extra: Vec<String> = BYPASS_DEFAULT
            .iter()
            .map(|s| s.to_string())
            .chain(std::iter::once("corp.test".to_string()))
            .collect();
        let merged = merge_bypass(&strs(&["*.local", "169.254/16"]), &extra);
        let lines = render_write("Display Ethernet", &ours(), &merged);
        assert!(lines.iter().all(|l| l.mutating));
        assert_eq!(
            rendered(&lines),
            vec![
                "/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 8080",
                "/usr/sbin/networksetup -setsecurewebproxy 'Display Ethernet' 127.0.0.1 8080",
                "/usr/sbin/networksetup -setproxybypassdomains 'Display Ethernet' *.local 169.254/16 localhost 127.0.0.1 ::1 corp.test",
            ]
        );
    }

    /// `MacosOps::write` over the §D7 previous: six mutating lines, previous ∪
    /// default ∪ extra per service, in service order.
    #[test]
    fn write_runs_six_lines_in_service_order() {
        let exec = ScriptedExecutor::new();
        let previous = Previous::Networksetup {
            services: d7_previous(),
        };
        let ran = MacosOps
            .write(&exec, &previous, &ours(), &strs(&["corp.test"]))
            .unwrap();
        let expected = vec![
            "/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 8080",
            "/usr/sbin/networksetup -setsecurewebproxy 'Display Ethernet' 127.0.0.1 8080",
            "/usr/sbin/networksetup -setproxybypassdomains 'Display Ethernet' *.local 169.254/16 localhost 127.0.0.1 ::1 corp.test",
            "/usr/sbin/networksetup -setwebproxy Wi-Fi 127.0.0.1 8080",
            "/usr/sbin/networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080",
            "/usr/sbin/networksetup -setproxybypassdomains Wi-Fi *.local 169.254/16 localhost 127.0.0.1 ::1 corp.test",
        ];
        assert_eq!(ran, expected);
        assert_eq!(exec.runs(), expected);
    }

    /// SP-AC9, the mapping half.
    #[test]
    fn admin_error_maps_to_needs_privilege() {
        let exec = ScriptedExecutor::new().respond(
            "/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 8080",
            1,
            ADMIN_ERROR,
            "",
        );
        let previous = Previous::Networksetup {
            services: d7_previous(),
        };
        let err = MacosOps.write(&exec, &previous, &ours(), &[]).unwrap_err();
        let WriteError::NeedsPrivilege(remedy) = err else {
            panic!("expected NeedsPrivilege, got {err:?}");
        };
        assert!(remedy.contains("Require an administrator password"));
        assert!(remedy.contains("127.0.0.1:8080"));
        let sets: Vec<_> = exec
            .runs()
            .into_iter()
            .filter(|l| l.contains(" -set"))
            .collect();
        assert_eq!(sets.len(), 1);
    }

    /// A non-zero exit without the admin text is `Failed` naming the line.
    #[test]
    fn other_write_failure_is_failed_with_the_rendered_line() {
        let line = "/usr/sbin/networksetup -setsecurewebproxy 'Display Ethernet' 127.0.0.1 8080";
        let exec = ScriptedExecutor::new().respond(line, 2, "", "boom");
        let previous = Previous::Networksetup {
            services: d7_previous(),
        };
        let err = MacosOps.write(&exec, &previous, &ours(), &[]).unwrap_err();
        let WriteError::Failed(msg) = err else {
            panic!("expected Failed, got {err:?}");
        };
        assert!(msg.contains(line));
        assert_eq!(exec.runs().len(), 2);
    }

    /// `read_services_full`: the list read, then the three `-get*` reads per
    /// enabled service, all non-mutating; an authenticated service is in the
    /// rows and named in `authenticated`.
    #[test]
    fn read_services_runs_three_gets_per_service_and_flags_authenticated() {
        let exec = ScriptedExecutor::new()
            .respond(
                "/usr/sbin/networksetup -listallnetworkservices",
                0,
                "An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getwebproxy 'Display Ethernet'",
                0,
                "Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getsecurewebproxy 'Display Ethernet'",
                0,
                "Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getproxybypassdomains 'Display Ethernet'",
                0,
                "*.local\n169.254/16\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getwebproxy Wi-Fi",
                0,
                "Enabled: Yes\nServer: proxy.corp\nPort: 3128\nAuthenticated Proxy Enabled: 1\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getsecurewebproxy Wi-Fi",
                0,
                "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getproxybypassdomains Wi-Fi",
                0,
                "There aren't any bypass domains set on Wi-Fi.\n",
                "",
            );
        let full = MacosOps.read_services_full(&exec).unwrap();
        assert_eq!(
            full.rows,
            vec![
                ServiceRow {
                    service: "Display Ethernet".into(),
                    http: on("127.0.0.1", 9090),
                    https: on("127.0.0.1", 9090),
                    bypass: strs(&["*.local", "169.254/16"]),
                },
                ServiceRow {
                    service: "Wi-Fi".into(),
                    http: on("proxy.corp", 3128),
                    https: off(),
                    bypass: vec![],
                },
            ]
        );
        assert_eq!(full.authenticated, vec!["Wi-Fi"]);
        assert_eq!(
            exec.runs(),
            vec![
                "/usr/sbin/networksetup -listallnetworkservices",
                "/usr/sbin/networksetup -getwebproxy 'Display Ethernet'",
                "/usr/sbin/networksetup -getsecurewebproxy 'Display Ethernet'",
                "/usr/sbin/networksetup -getproxybypassdomains 'Display Ethernet'",
                "/usr/sbin/networksetup -getwebproxy Wi-Fi",
                "/usr/sbin/networksetup -getsecurewebproxy Wi-Fi",
                "/usr/sbin/networksetup -getproxybypassdomains Wi-Fi",
            ]
        );
        // The trait method is the rows alone.
        assert_eq!(MacosOps.read_services(&exec).unwrap(), full.rows);
    }

    /// Zero enabled services is `Unavailable`, never an empty `Ok`.
    #[test]
    fn read_services_with_none_enabled_is_unavailable() {
        let exec = ScriptedExecutor::new().respond(
            "/usr/sbin/networksetup -listallnetworkservices",
            0,
            "An asterisk (*) denotes that a network service is disabled.\n*Wi-Fi\n",
            "",
        );
        assert_eq!(
            MacosOps.read_services(&exec),
            Err(ReadError::Unavailable("no enabled network service".into()))
        );
        assert_eq!(exec.runs().len(), 1);
    }

    /// `read_effective` runs `scutil --proxy` once; the sandbox's empty
    /// dictionary is `Unavailable`.
    #[test]
    fn read_effective_runs_scutil_and_maps_sandbox_to_unavailable() {
        let exec = ScriptedExecutor::new().respond("/usr/sbin/scutil --proxy", 0, SCUTIL_FULL, "");
        let eff = MacosOps.read_effective(&exec).unwrap();
        assert_eq!(eff.http, on("127.0.0.1", 9090));
        assert_eq!(exec.runs(), vec!["/usr/sbin/scutil --proxy"]);

        let exec = ScriptedExecutor::new().respond(
            "/usr/sbin/scutil --proxy",
            0,
            "<dictionary> {\n}\n",
            "",
        );
        assert!(matches!(
            MacosOps.read_effective(&exec),
            Err(ReadError::Unavailable(_))
        ));
    }

    /// `MacosOps::restore` runs the rendered restore lines and returns them.
    #[test]
    fn restore_runs_only_the_named_services() {
        let exec = ScriptedExecutor::new();
        let previous = Previous::Networksetup {
            services: d7_previous(),
        };
        let ran = MacosOps
            .restore(&exec, &previous, &strs(&["Wi-Fi"]))
            .unwrap();
        assert_eq!(
            ran,
            vec![
                "/usr/sbin/networksetup -setwebproxystate Wi-Fi off",
                "/usr/sbin/networksetup -setsecurewebproxystate Wi-Fi off",
                "/usr/sbin/networksetup -setproxybypassdomains Wi-Fi *.local 169.254/16",
            ]
        );
        assert_eq!(exec.runs(), ran);
        assert!(!exec.runs().iter().any(|l| l.contains("Display Ethernet")));
    }

    /// Gap 1: `snapshot` is the rows minus the authenticated services, which
    /// are reported as `skipped` so the engine can name them.
    #[test]
    fn snapshot_excludes_authenticated_services_and_names_them() {
        let exec = ScriptedExecutor::new()
            .respond(
                "/usr/sbin/networksetup -listallnetworkservices",
                0,
                "An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getwebproxy 'Display Ethernet'",
                0,
                "Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getsecurewebproxy 'Display Ethernet'",
                0,
                "Enabled: Yes\nServer: 127.0.0.1\nPort: 9090\nAuthenticated Proxy Enabled: 0\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getproxybypassdomains 'Display Ethernet'",
                0,
                "*.local\n169.254/16\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getwebproxy Wi-Fi",
                0,
                "Enabled: Yes\nServer: proxy.corp\nPort: 3128\nAuthenticated Proxy Enabled: 1\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getsecurewebproxy Wi-Fi",
                0,
                "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0\n",
                "",
            )
            .respond(
                "/usr/sbin/networksetup -getproxybypassdomains Wi-Fi",
                0,
                "There aren't any bypass domains set on Wi-Fi.\n",
                "",
            );
        let snapshot = MacosOps.snapshot(&exec).unwrap();
        assert_eq!(snapshot.skipped, vec!["Wi-Fi".to_string()]);
        assert_eq!(
            snapshot.previous,
            Previous::Networksetup {
                services: vec![ServiceRow {
                    service: "Display Ethernet".into(),
                    http: on("127.0.0.1", 9090),
                    https: on("127.0.0.1", 9090),
                    bypass: strs(&["*.local", "169.254/16"]),
                }],
            }
        );
        assert_eq!(exec.runs().len(), 7, "the list and three gets per service");
        assert!(exec.runs().iter().all(|l| !l.contains(" -set")));
    }
}

/// Tester (stage 5) additions: malformed, empty and oversized `networksetup`
/// / `scutil` output, argv safety of service names and bypass entries, and
/// the executor failure kinds (`Hung`, start failure, stderr admin error).
#[cfg(test)]
mod tester_tests {
    use std::path::{Path, PathBuf};

    use aitm_ca::exec::{CmdLine, CmdOutput, Executor};
    use aitm_ca::testing::ScriptedExecutor;

    use super::*;
    use crate::ProtocolProxy;

    const LIST: &str = "/usr/sbin/networksetup -listallnetworkservices";
    const LIST_OUT: &str = "An asterisk (*) denotes that a network service is disabled.\nDisplay Ethernet\n*Thunderbolt Bridge\nWi-Fi\n";

    fn ours() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }

    fn on(host: &str, port: u16) -> ProtocolProxy {
        ProtocolProxy {
            enabled: true,
            host: host.into(),
            port,
        }
    }

    fn d7_previous() -> Previous {
        Previous::Networksetup {
            services: vec![
                ServiceRow {
                    service: "Display Ethernet".into(),
                    http: on("127.0.0.1", 9090),
                    https: on("127.0.0.1", 9090),
                    bypass: vec!["*.local".into(), "169.254/16".into()],
                },
                ServiceRow {
                    service: "Wi-Fi".into(),
                    http: ProtocolProxy::default(),
                    https: ProtocolProxy::default(),
                    bypass: vec![],
                },
            ],
        }
    }

    /// Empty and malformed output never panics and never reads as a
    /// configured proxy.
    #[test]
    fn parsers_survive_empty_and_malformed_output() {
        assert_eq!(parse_services(""), Vec::<String>::new());
        assert_eq!(
            parse_services("An asterisk (*) denotes that a network service is disabled.\n"),
            Vec::<String>::new()
        );
        assert_eq!(
            parse_services("An asterisk (*) denotes that a network service is disabled.\r\nWi-Fi  \r\n\r\n*Off\r\n"),
            vec!["Wi-Fi"],
            "CRLF and trailing blanks are trimmed, blank lines dropped"
        );

        assert_eq!(parse_get_proxy(""), ProtocolProxy::default());
        assert_eq!(parse_get_proxy("garbage\n"), ProtocolProxy::default());
        assert_eq!(
            parse_get_proxy("Enabled: Yes\nServer: 127.0.0.1\nPort: abc\n"),
            ProtocolProxy {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 0
            },
            "an unparsable port is 0"
        );
        assert_eq!(
            parse_get_proxy("Enabled: Yes\nServer: 127.0.0.1\nPort: 99999\n").port,
            0,
            "a port above u16 is 0, not a wrap-around"
        );
        assert_eq!(
            parse_get_proxy("Enabled: yes\nServer:127.0.0.1\nPort:  9090 \n"),
            on("127.0.0.1", 9090),
            "case and spacing around the colon are tolerated"
        );
        assert!(!parse_get_proxy_authenticated(""));
        assert!(!parse_get_proxy_authenticated(
            "Authenticated Proxy Enabled: 2\n"
        ));

        assert_eq!(parse_bypass(""), Vec::<String>::new());
        assert_eq!(parse_bypass("\n  \n"), Vec::<String>::new());

        assert!(matches!(parse_scutil(""), Err(ReadError::Unavailable(_))));
        assert!(matches!(
            parse_scutil("garbage\n"),
            Err(ReadError::Unavailable(_))
        ));
        assert!(matches!(
            parse_scutil("<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : abc\n}\n"),
            Err(ReadError::Failed(m)) if m.contains("HTTPPort")
        ));
        assert!(matches!(
            parse_scutil("<dictionary> {\n  HTTPSEnable : 1\n  HTTPSPort : 70000\n}\n"),
            Err(ReadError::Failed(m)) if m.contains("HTTPSPort")
        ));
        let half =
            parse_scutil("<dictionary> {\n  HTTPEnable : 1\n  HTTPSEnable : 0\n}\n").unwrap();
        assert_eq!(
            half.http,
            ProtocolProxy {
                enabled: true,
                host: String::new(),
                port: 0
            },
            "enabled with no host/port keys is carried as-is, not dropped"
        );
        assert_eq!(half.https, ProtocolProxy::default());

        // Only the top-level keys count: a `__SCOPED__` per-interface
        // dictionary with its own proxy and ExceptionsList is ignored.
        let scoped = "<dictionary> {\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      HTTPEnable : 1\n      HTTPPort : 9090\n      HTTPProxy : 10.0.0.5\n      ExceptionsList : <array> {\n        0 : scoped.test\n      }\n    }\n  }\n}\n";
        let e = parse_scutil(scoped).unwrap();
        assert_eq!(e.http, ProtocolProxy::default());
        assert_eq!(e.https, ProtocolProxy::default());
        assert_eq!(e.bypass, Vec::<String>::new());
    }

    /// Oversized output: tens of thousands of services or bypass entries
    /// parse whole, in order, without truncation.
    #[test]
    fn oversized_output_parses_whole() {
        let mut services =
            String::from("An asterisk (*) denotes that a network service is disabled.\n");
        for i in 0..20_000 {
            services.push_str(&format!("Service {i}\n"));
        }
        let parsed = parse_services(&services);
        assert_eq!(parsed.len(), 20_000);
        assert_eq!(parsed[19_999], "Service 19999");

        let mut dump = String::from("<dictionary> {\n  ExceptionsList : <array> {\n");
        for i in 0..50_000 {
            dump.push_str(&format!("    {i} : host{i}.test\n"));
        }
        dump.push_str("  }\n  HTTPEnable : 1\n  HTTPPort : 8080\n  HTTPProxy : 127.0.0.1\n  HTTPSEnable : 1\n  HTTPSPort : 8080\n  HTTPSProxy : 127.0.0.1\n}\n");
        let e = parse_scutil(&dump).unwrap();
        assert_eq!(e.bypass.len(), 50_000);
        assert_eq!(e.bypass[49_999], "host49999.test");
        assert_eq!(e.http, on("127.0.0.1", 8080));

        let bypass: Vec<String> = (0..10_000).map(|i| format!("h{i}.test\n")).collect();
        assert_eq!(parse_bypass(&bypass.concat()).len(), 10_000);
    }

    /// Argv safety: a service name with a quote and bypass entries with
    /// shell metacharacters are each ONE argv word; nothing is split,
    /// interpreted or re-quoted on the way to `networksetup`.
    #[test]
    fn service_names_and_bypass_entries_are_single_argv_words() {
        let svc = "Matt's iPhone USB";
        let bypass = vec![
            "evil; rm -rf /".to_string(),
            "$(whoami).test".to_string(),
            "a b".to_string(),
            String::new(),
        ];
        let lines = render_write(svc, &ours(), &bypass);
        assert_eq!(lines[0].program, NETWORKSETUP);
        assert_eq!(
            lines[0].args,
            vec!["-setwebproxy", svc, "127.0.0.1", "8080"]
        );
        assert_eq!(
            lines[1].args,
            vec!["-setsecurewebproxy", svc, "127.0.0.1", "8080"]
        );
        assert_eq!(
            lines[2].args,
            vec![
                "-setproxybypassdomains",
                svc,
                "evil; rm -rf /",
                "$(whoami).test",
                "a b",
                ""
            ]
        );
        assert!(lines.iter().all(|l| l.stdin.is_none() && l.mutating));
        // The rendered (logged) form quotes the words with whitespace and
        // escapes the apostrophe, so the log line is unambiguous.
        assert!(
            lines[0]
                .render()
                .starts_with(r"/usr/sbin/networksetup -setwebproxy 'Matt'\''s iPhone USB' "),
            "{}",
            lines[0].render()
        );

        let previous = vec![ServiceRow {
            service: svc.into(),
            http: on("10.0.0.5", 3128),
            https: on("10.0.0.5", 3128),
            bypass: vec!["a b".into()],
        }];
        let restore = render_restore(&previous, &[svc.to_string()]);
        assert_eq!(restore.len(), 5);
        assert!(restore.iter().all(|l| l.args[1] == svc));
        assert_eq!(restore[4].args, vec!["-setproxybypassdomains", svc, "a b"]);
        assert!(
            render_restore(&previous, &["Wi-Fi".to_string()]).is_empty(),
            "a name not in `previous` renders nothing"
        );
        assert!(render_restore(&[], &[svc.to_string()]).is_empty());
    }

    /// Executor failure kinds on a write: a timeout is `Hung(line)` and the
    /// sequence stops there; a start failure is `Failed` naming the line;
    /// the admin text on stderr is `NeedsPrivilege` too; a wrong snapshot
    /// kind is refused before any run.
    #[test]
    fn write_failure_kinds_are_typed_and_stop_the_sequence() {
        struct HangOn {
            inner: ScriptedExecutor,
            line: &'static str,
        }
        impl Executor for HangOn {
            fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
                let out = self.inner.run(cmd)?;
                if cmd.render() == self.line {
                    anyhow::bail!("`{}` timed out after 30s", self.line);
                }
                Ok(out)
            }
            fn read_file(&self, path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
                self.inner.read_file(path)
            }
            fn dir_exists(&self, path: &Path) -> bool {
                self.inner.dir_exists(path)
            }
            fn home_dir(&self) -> Option<PathBuf> {
                self.inner.home_dir()
            }
            fn is_root(&self) -> bool {
                self.inner.is_root()
            }
        }
        let hung = "/usr/sbin/networksetup -setsecurewebproxy 'Display Ethernet' 127.0.0.1 8080";
        let exec = HangOn {
            inner: ScriptedExecutor::new(),
            line: hung,
        };
        let err = MacosOps
            .write(&exec, &d7_previous(), &ours(), &[])
            .unwrap_err();
        assert_eq!(err, WriteError::Hung(hung.to_string()));
        assert_eq!(exec.inner.runs().len(), 2, "stopped at the hung line");

        struct CannotStart;
        impl Executor for CannotStart {
            fn run(&self, cmd: &CmdLine) -> anyhow::Result<CmdOutput> {
                anyhow::bail!(
                    "could not start `{}`: No such file or directory",
                    cmd.program
                )
            }
            fn read_file(&self, _: &Path) -> anyhow::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn dir_exists(&self, _: &Path) -> bool {
                false
            }
            fn home_dir(&self) -> Option<PathBuf> {
                None
            }
            fn is_root(&self) -> bool {
                false
            }
        }
        let err = MacosOps
            .write(&CannotStart, &d7_previous(), &ours(), &[])
            .unwrap_err();
        let WriteError::Failed(m) = err else {
            panic!("expected Failed, got {err:?}");
        };
        assert!(
            m.contains("-setwebproxy 'Display Ethernet' 127.0.0.1 8080"),
            "{m}"
        );
        assert!(m.contains("could not start"), "{m}");

        let first = "/usr/sbin/networksetup -setwebproxy 'Display Ethernet' 127.0.0.1 8080";
        let exec = ScriptedExecutor::new().respond(first, 1, "", ADMIN_ERROR);
        assert!(matches!(
            MacosOps.write(&exec, &d7_previous(), &ours(), &[]),
            Err(WriteError::NeedsPrivilege(r)) if r.contains("127.0.0.1:8080")
        ));
        assert_eq!(exec.runs().len(), 1);

        // A restore that hits the admin error carries the failing line (the
        // engine fills the §D3 sentence), and stops.
        let restore_line = "/usr/sbin/networksetup -setwebproxystate Wi-Fi off";
        let exec = ScriptedExecutor::new().respond(restore_line, 1, ADMIN_ERROR, "");
        let err = MacosOps
            .restore(&exec, &d7_previous(), &["Wi-Fi".to_string()])
            .unwrap_err();
        assert_eq!(err, WriteError::NeedsPrivilege(restore_line.to_string()));
        assert_eq!(exec.runs().len(), 1);

        // A snapshot of another mechanism is refused before any run.
        let exec = ScriptedExecutor::new();
        let gs = Previous::Gsettings {
            keys: std::collections::BTreeMap::new(),
        };
        assert!(matches!(
            MacosOps.write(&exec, &gs, &ours(), &[]),
            Err(WriteError::Failed(m)) if m.contains("not a networksetup")
        ));
        assert!(matches!(
            MacosOps.restore(&exec, &gs, &["gsettings".to_string()]),
            Err(WriteError::Failed(_))
        ));
        assert!(exec.runs().is_empty());
    }

    /// Read failure kinds: a non-zero list exit is `Failed` with the code
    /// and stderr; the authorization text is `Unavailable`; a per-service
    /// read failing mid-way stops the sequence; `scutil` exiting non-zero
    /// is `Failed`.
    #[test]
    fn read_failure_kinds_are_typed_and_stop_the_sequence() {
        let exec = ScriptedExecutor::new().respond(LIST, 1, "", "boom");
        assert!(matches!(
            MacosOps.read_services(&exec),
            Err(ReadError::Failed(m)) if m.contains("exit Some(1)") && m.contains("boom")
        ));

        let exec =
            ScriptedExecutor::new().respond(LIST, 0, "AuthorizationCreate() failed: -60008\n", "");
        assert!(matches!(
            MacosOps.read_services(&exec),
            Err(ReadError::Unavailable(_))
        ));
        assert_eq!(exec.runs().len(), 1);

        let exec = ScriptedExecutor::new()
            .respond(LIST, 0, LIST_OUT, "")
            .respond(
                "/usr/sbin/networksetup -getsecurewebproxy 'Display Ethernet'",
                1,
                "",
                "nope",
            );
        assert!(matches!(
            MacosOps.read_services(&exec),
            Err(ReadError::Failed(m)) if m.contains("nope")
        ));
        assert_eq!(exec.runs().len(), 3, "list, web, the failing secure read");

        let exec = ScriptedExecutor::new().respond("/usr/sbin/scutil --proxy", 1, "", "boom");
        assert!(matches!(
            MacosOps.read_effective(&exec),
            Err(ReadError::Failed(m)) if m.contains("boom")
        ));
        assert!(matches!(
            MacosOps.snapshot(&ScriptedExecutor::new().respond(LIST, 1, "", "x")),
            Err(ReadError::Failed(_))
        ));
    }
}
