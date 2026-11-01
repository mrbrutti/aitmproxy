//! Linux: `gsettings` (GNOME) and `kwriteconfig6|5` + `dbus-send` (KDE)
//! (spec §D4). Detection is a pure function over (`target_os`, env, PATH);
//! every read and write is a [`CmdLine`] through the executor, so the
//! mechanisms are unit-tested on any host.
//!
//! `gsettings` is spawned by its absolute path; the KDE tools and
//! `dbus-send` are named on `PATH` (§D2) but resolved to their absolute
//! paths once, at detection, and spawned by those (a `PATH` that changes
//! afterwards cannot swap the tool). An executor `Err` that starts with
//! `could not start` is the tool missing. No privilege is ever needed here,
//! so `NeedsPrivilege` is never produced.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::PathBuf;

use aitm_ca::exec::{CmdLine, Executor};

use crate::platform::{cmd, PlatformOps, Snapshot};
use crate::state::Previous;
use crate::{
    bypass_for, Effective, Endpoint, Mechanism, ProtocolProxy, ReadError, ServiceRow, WriteError,
};

pub const GSETTINGS: &str = "/usr/bin/gsettings";

/// The six keys, in `gsettings get` order. Writes use the same keys with
/// `mode` moved last (the switch, §D4).
pub const GSETTINGS_KEYS: [(&str, &str); 6] = [
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy", "ignore-hosts"),
];

/// `kioslaverc` `[Proxy Settings]` keys, in read and write order.
pub const KDE_KEYS: [&str; 4] = ["ProxyType", "httpProxy", "httpsProxy", "NoProxyFor"];

/// The synthetic service names Linux rows carry (the state file's
/// `service_names()` spells them the same way).
pub(crate) const GSETTINGS_SERVICE: &str = "gsettings";
pub(crate) const KDE_SERVICE: &str = "kde";

const KIOSLAVERC: &str = "kioslaverc";
const KDE_GROUP: &str = "Proxy Settings";
const DBUS_SEND: &str = "dbus-send";
const NOT_PERSISTED: &str = "gsettings did not persist the change (no dconf session?)";

/// What [`detect`] found: the mechanism plus the facts a bare
/// [`Mechanism`] cannot carry (which KDE tool major is on `PATH`, whether
/// `gsettings` is there too). `SystemProxy::detect_with` is the caller; it
/// builds a KDE's ops with [`KdeOps::resolved`] and every other mechanism's
/// with `platform::ops_for`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Detected {
    Gsettings,
    Kde {
        kwrite: &'static str,
        kread: &'static str,
        gsettings_too: bool,
    },
    None,
}

impl Detected {
    pub(crate) fn mechanism(&self) -> Mechanism {
        match self {
            Detected::Gsettings => Mechanism::Gsettings,
            Detected::Kde { .. } => Mechanism::Kde,
            Detected::None => Mechanism::None,
        }
    }
}

/// The §D4 table, first match wins, no command run:
///
/// | `XDG_CURRENT_DESKTOP` contains `KDE` and `kwriteconfig6` or `kwriteconfig5` on `PATH` | `Kde` (6 preferred) |
/// | `gsettings` on `PATH` and (`DBUS_SESSION_BUS_ADDRESS` or `DISPLAY`/`WAYLAND_DISPLAY` set) | `Gsettings` |
/// | anything else, and every `target_os != "linux"` | `None` |
pub(crate) fn detect(
    target_os: &str,
    env: &dyn Fn(&str) -> Option<String>,
    on_path: &dyn Fn(&str) -> bool,
) -> Detected {
    if target_os != "linux" {
        return Detected::None;
    }
    let is_set = |name: &str| env(name).is_some_and(|v| !v.is_empty());
    let has_gsettings = on_path("gsettings");
    if env("XDG_CURRENT_DESKTOP").is_some_and(|d| d.contains("KDE")) {
        for (kwrite, kread) in [
            ("kwriteconfig6", "kreadconfig6"),
            ("kwriteconfig5", "kreadconfig5"),
        ] {
            if on_path(kwrite) {
                return Detected::Kde {
                    kwrite,
                    kread,
                    gsettings_too: has_gsettings,
                };
            }
        }
    }
    if has_gsettings
        && (is_set("DBUS_SESSION_BUS_ADDRESS") || is_set("DISPLAY") || is_set("WAYLAND_DISPLAY"))
    {
        return Detected::Gsettings;
    }
    Detected::None
}

/// The first of `path`'s entries that has `tool` as a file, joined with
/// it: the `PATH` walk behind detection (`Path::is_file`, no command run),
/// and the absolute path the KDE tools are then spawned by. Empty entries
/// are skipped: a leading or doubled `:` must not make the working
/// directory a tool source.
pub(crate) fn resolve_on_path(path: Option<&OsStr>, tool: &str) -> Option<PathBuf> {
    let path = path?;
    std::env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
}

/// The ops for a bare [`Mechanism::Kde`], which names the mechanism but
/// not the tool major (the state file, the `with_mechanism` constructor):
/// the §D4 [`detect`] over `os`, `env` and `resolve` when it says KDE;
/// otherwise (the desktop word is absent from this environment, or the OS
/// word is not `linux` on a test host) `PATH` alone picks the major,
/// `kwriteconfig6` unless only `kwriteconfig5` is present, and no gsettings
/// mirror is assumed: a restore follows the snapshot's content regardless.
/// Either way the tools are stored by the absolute path `resolve` found.
pub(crate) fn kde_ops_resolved(
    os: &str,
    env: &dyn Fn(&str) -> Option<String>,
    resolve: &dyn Fn(&str) -> Option<PathBuf>,
) -> KdeOps {
    let on_path = |tool: &str| resolve(tool).is_some();
    if let Detected::Kde {
        kwrite,
        kread,
        gsettings_too,
    } = detect(os, env, &on_path)
    {
        return KdeOps::resolved(kwrite, kread, gsettings_too, resolve);
    }
    let (kwrite, kread) = if !on_path("kwriteconfig6") && on_path("kwriteconfig5") {
        ("kwriteconfig5", "kreadconfig5")
    } else {
        ("kwriteconfig6", "kreadconfig6")
    };
    KdeOps::resolved(kwrite, kread, false, resolve)
}

/// [`kde_ops_resolved`] over this process: `std::env::consts::OS`, the real
/// environment and its `PATH`. What the watchdog and `ops_for` use.
pub(crate) fn kde_ops_from_host() -> KdeOps {
    let path = std::env::var_os("PATH");
    kde_ops_resolved(
        std::env::consts::OS,
        &|name| std::env::var(name).ok(),
        &|tool| resolve_on_path(path.as_deref(), tool),
    )
}

/// [`detect`] reduced to the mechanism word.
pub fn detect_mechanism(
    target_os: &str,
    env: &dyn Fn(&str) -> Option<String>,
    has_tool: &dyn Fn(&str) -> bool,
) -> Mechanism {
    detect(target_os, env, has_tool).mechanism()
}

// ---- GVariant text -------------------------------------------------------

/// `'127.0.0.1'`: a GVariant string literal, `\` and `'` escaped.
pub fn gvariant_string(s: &str) -> String {
    format!("'{}'", s.replace('\\', r"\\").replace('\'', r"\'"))
}

/// `['a', 'b c']`; the empty list is `@as []`, as `gsettings get` prints it.
pub fn gvariant_string_list(items: &[String]) -> String {
    if items.is_empty() {
        return "@as []".to_string();
    }
    let inner: Vec<String> = items.iter().map(|s| gvariant_string(s)).collect();
    format!("[{}]", inner.join(", "))
}

/// The text inside a GVariant string literal (`'manual'` → `manual`);
/// unquoted input is returned trimmed.
pub fn parse_gvariant_string(s: &str) -> String {
    let s = s.trim();
    let quoted = (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
        || (s.starts_with('"') && s.ends_with('"') && s.len() >= 2);
    if !quoted {
        return s.to_string();
    }
    unescape(&s[1..s.len() - 1])
}

/// The items of a GVariant `as` literal (`['a', 'b c']`, `@as []`).
pub fn parse_gvariant_string_list(s: &str) -> Vec<String> {
    let s = s.trim();
    let s = s.strip_prefix("@as").map_or(s, str::trim_start);
    let Some(body) = s.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return Vec::new();
    };
    let mut items = Vec::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\'' && c != '"' {
            continue;
        }
        let quote = c;
        let mut raw = String::new();
        let mut escaped = false;
        for c in chars.by_ref() {
            if escaped {
                raw.push('\\');
                raw.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == quote {
                break;
            } else {
                raw.push(c);
            }
        }
        items.push(unescape(&raw));
    }
    items
}

fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `8080`, `uint16 8080`, `int32 8080` → 8080; anything else → 0.
fn parse_port(s: &str) -> u16 {
    s.trim()
        .rsplit(' ')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

// ---- running a command -----------------------------------------------------

/// Run one line; non-zero exit is a failure naming the line.
fn run_read(exec: &dyn Executor, line: &CmdLine) -> Result<String, ReadError> {
    let rendered = line.render();
    let out = exec.run(line).map_err(|e| {
        let msg = e.to_string();
        if msg.starts_with("could not start") {
            ReadError::ToolMissing(line.program.clone())
        } else {
            ReadError::Failed(format!("`{rendered}`: {msg}"))
        }
    })?;
    if !out.success() {
        return Err(ReadError::Failed(format!(
            "`{rendered}` exited {}: {}",
            out.code.map_or("signal".to_string(), |c| c.to_string()),
            out.stderr.trim()
        )));
    }
    Ok(out.stdout.trim_end_matches(['\n', '\r']).to_string())
}

fn run_write(exec: &dyn Executor, line: &CmdLine) -> Result<(), WriteError> {
    let rendered = line.render();
    let out = exec.run(line).map_err(|e| {
        let msg = e.to_string();
        if msg.starts_with("could not start") {
            WriteError::ToolMissing(line.program.clone())
        } else if msg.contains("timed out") {
            WriteError::Hung(rendered.clone())
        } else {
            WriteError::Failed(format!("`{rendered}`: {msg}"))
        }
    })?;
    if !out.success() {
        return Err(WriteError::Failed(format!(
            "`{rendered}` exited {}: {}",
            out.code.map_or("signal".to_string(), |c| c.to_string()),
            out.stderr.trim()
        )));
    }
    Ok(())
}

fn read_as_write(e: ReadError) -> WriteError {
    match e {
        ReadError::ToolMissing(p) => WriteError::ToolMissing(p),
        ReadError::Unavailable(m) | ReadError::Failed(m) => WriteError::Failed(m),
    }
}

// ---- gsettings ---------------------------------------------------------------

/// The state-file key for one gsettings key: `<schema> <key>` (§D7).
fn gsettings_key_name(schema: &str, key: &str) -> String {
    format!("{schema} {key}")
}

fn gsettings_get(schema: &str, key: &str) -> CmdLine {
    cmd(GSETTINGS, &["get", schema, key], false)
}

fn gsettings_set(schema: &str, key: &str, value: &str) -> CmdLine {
    cmd(GSETTINGS, &["set", schema, key, value], true)
}

/// The six `get`s, raw GVariant text keyed by `<schema> <key>`; the
/// rendered lines are appended to `lines`.
fn gsettings_read_keys(
    exec: &dyn Executor,
    lines: &mut Vec<String>,
) -> Result<BTreeMap<String, String>, ReadError> {
    let mut keys = BTreeMap::new();
    for (schema, key) in GSETTINGS_KEYS {
        let line = gsettings_get(schema, key);
        lines.push(line.render());
        let value = run_read(exec, &line)?;
        keys.insert(gsettings_key_name(schema, key), value);
    }
    Ok(keys)
}

fn gsettings_value<'a>(keys: &'a BTreeMap<String, String>, schema: &str, key: &str) -> &'a str {
    keys.get(&gsettings_key_name(schema, key))
        .map_or("", String::as_str)
}

/// The effective view of the six keys: `enabled = (mode == 'manual')` and
/// a non-empty host, so a half-configured desktop never reads as `→ :0`.
fn gsettings_effective(keys: &BTreeMap<String, String>) -> Effective {
    let manual =
        parse_gvariant_string(gsettings_value(keys, "org.gnome.system.proxy", "mode")) == "manual";
    let proto = |schema: &str| {
        let host = parse_gvariant_string(gsettings_value(keys, schema, "host"));
        ProtocolProxy {
            enabled: manual && !host.is_empty(),
            host,
            port: parse_port(gsettings_value(keys, schema, "port")),
        }
    };
    Effective {
        http: proto("org.gnome.system.proxy.http"),
        https: proto("org.gnome.system.proxy.https"),
        bypass: parse_gvariant_string_list(gsettings_value(
            keys,
            "org.gnome.system.proxy",
            "ignore-hosts",
        )),
    }
}

fn row(service: &str, effective: Effective) -> ServiceRow {
    ServiceRow {
        service: service.to_string(),
        http: effective.http,
        https: effective.https,
        bypass: effective.bypass,
    }
}

/// The `gsettings` row the six raw key values describe: what
/// `read_services` would return for them, so a snapshot can be judged
/// against `wrote` without a second read.
pub(crate) fn gsettings_row(keys: &BTreeMap<String, String>) -> ServiceRow {
    row(GSETTINGS_SERVICE, gsettings_effective(keys))
}

/// The `kde` row the four raw kioslaverc values describe.
pub(crate) fn kde_row(kioslaverc: &BTreeMap<String, String>) -> ServiceRow {
    row(KDE_SERVICE, kde_effective(kioslaverc))
}

/// The six `set`s in §D4 order, `mode 'manual'` last.
fn gsettings_write_values(
    ours: &Endpoint,
    bypass: &[String],
) -> Vec<(&'static str, &'static str, String)> {
    let host = gvariant_string(&ours.host);
    let port = ours.port.to_string();
    vec![
        ("org.gnome.system.proxy.http", "host", host.clone()),
        ("org.gnome.system.proxy.http", "port", port.clone()),
        ("org.gnome.system.proxy.https", "host", host),
        ("org.gnome.system.proxy.https", "port", port),
        (
            "org.gnome.system.proxy",
            "ignore-hosts",
            gvariant_string_list(bypass),
        ),
        ("org.gnome.system.proxy", "mode", "'manual'".to_string()),
    ]
}

/// Six `get`s (the live before-state; a dead tool fails here, before any
/// mutation), six `set`s, six `get`s again. The previous `ignore-hosts`
/// list the union extends is `previous_keys`' when given, else the live one.
/// Any read-back differing from what was written is the memory-backend
/// failure of §D4.
fn gsettings_write(
    exec: &dyn Executor,
    previous_keys: Option<&BTreeMap<String, String>>,
    ours: &Endpoint,
    bypass_extra: &[String],
) -> Result<Vec<String>, WriteError> {
    let mut lines = Vec::with_capacity(18);
    let live = gsettings_read_keys(exec, &mut lines).map_err(read_as_write)?;
    let previous_list = parse_gvariant_string_list(gsettings_value(
        previous_keys.unwrap_or(&live),
        "org.gnome.system.proxy",
        "ignore-hosts",
    ));
    let bypass = bypass_for(&previous_list, bypass_extra);
    let written = gsettings_write_values(ours, &bypass);
    for (schema, key, value) in &written {
        let line = gsettings_set(schema, key, value);
        lines.push(line.render());
        run_write(exec, &line)?;
    }
    let after = gsettings_read_keys(exec, &mut lines).map_err(read_as_write)?;
    let persisted = written
        .iter()
        .all(|(schema, key, value)| gsettings_value(&after, schema, key) == value);
    if !persisted {
        return Err(WriteError::Failed(NOT_PERSISTED.to_string()));
    }
    Ok(lines)
}

/// The six `set`s with the raw previous text, verbatim, `mode` last.
fn gsettings_restore(
    exec: &dyn Executor,
    previous_keys: &BTreeMap<String, String>,
) -> Result<Vec<String>, WriteError> {
    let mut lines = Vec::with_capacity(6);
    let order = GSETTINGS_KEYS
        .iter()
        .skip(1)
        .chain(GSETTINGS_KEYS.iter().take(1));
    for (schema, key) in order {
        let line = gsettings_set(schema, key, gsettings_value(previous_keys, schema, key));
        lines.push(line.render());
        run_write(exec, &line)?;
    }
    Ok(lines)
}

/// GNOME and everything that honours `org.gnome.system.proxy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GsettingsOps;

impl PlatformOps for GsettingsOps {
    fn mechanism(&self) -> Mechanism {
        Mechanism::Gsettings
    }

    fn read_effective(&self, exec: &dyn Executor) -> Result<Effective, ReadError> {
        let keys = gsettings_read_keys(exec, &mut Vec::new())?;
        Ok(gsettings_effective(&keys))
    }

    fn read_services(&self, exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError> {
        Ok(vec![row(GSETTINGS_SERVICE, self.read_effective(exec)?)])
    }

    /// The before-state for the state file: six `get`s, raw text.
    fn snapshot(&self, exec: &dyn Executor) -> Result<Snapshot, ReadError> {
        let keys = gsettings_read_keys(exec, &mut Vec::new())?;
        Ok(Snapshot {
            previous: Previous::Gsettings { keys },
            skipped: Vec::new(),
        })
    }

    fn write(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        ours: &Endpoint,
        bypass_extra: &[String],
    ) -> Result<Vec<String>, WriteError> {
        let Previous::Gsettings { keys } = previous else {
            return Err(WriteError::Failed(
                "previous state is not a gsettings snapshot".to_string(),
            ));
        };
        gsettings_write(exec, Some(keys), ours, bypass_extra)
    }

    fn restore(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        only: &[String],
    ) -> Result<Vec<String>, WriteError> {
        if !only.iter().any(|s| s == GSETTINGS_SERVICE) {
            return Ok(Vec::new());
        }
        let keys = match previous {
            Previous::Gsettings { keys } => keys,
            Previous::Kde {
                gsettings: Some(keys),
                ..
            } => keys,
            _ => {
                return Err(WriteError::Failed(
                    "previous state is not a gsettings snapshot".to_string(),
                ))
            }
        };
        gsettings_restore(exec, keys)
    }
}

// ---- KDE -----------------------------------------------------------------------

/// `kwrite`/`kread` are `kwriteconfig6`/`kreadconfig6` or the 5 variants
/// and `dbus_send` the KIO signal tool, each the absolute path detection
/// resolved on `PATH` (a tool not found keeps its bare name, so the spawn
/// failure names it); `gsettings_too` mirrors the writes into gsettings
/// for GTK apps (§D4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KdeOps {
    pub kwrite: PathBuf,
    pub kread: PathBuf,
    pub dbus_send: PathBuf,
    pub gsettings_too: bool,
}

/// `http://127.0.0.1 8080`, the KDE value format (§D4, from field reports).
fn kde_proxy_value(ours: &Endpoint) -> String {
    format!("http://{} {}", ours.host, ours.port)
}

/// `http://host port` (KDE's spelling) or `host:port` → the protocol row;
/// `enabled` is the caller's `ProxyType == 1` and needs a non-empty host.
fn parse_kde_proxy(value: &str, enabled: bool) -> ProtocolProxy {
    let value = value.trim();
    let no_scheme = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .trim_end_matches('/');
    let (host, port) = match no_scheme.split_once(char::is_whitespace) {
        Some((host, port)) => (host, port.trim()),
        None => no_scheme.rsplit_once(':').unwrap_or((no_scheme, "")),
    };
    ProtocolProxy {
        enabled: enabled && !host.is_empty(),
        host: host.to_string(),
        port: port.parse().unwrap_or(0),
    }
}

fn parse_kde_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// `name` as `resolve` finds it on `PATH`, else the bare name.
fn tool_path(name: &str, resolve: &dyn Fn(&str) -> Option<PathBuf>) -> PathBuf {
    resolve(name).unwrap_or_else(|| PathBuf::from(name))
}

/// A resolved path as the `program` of a [`CmdLine`].
fn program(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

impl KdeOps {
    /// The ops for the tool names [`detect`] chose, each resolved to its
    /// absolute path on `PATH` through `resolve` (`dbus-send` too).
    pub(crate) fn resolved(
        kwrite: &str,
        kread: &str,
        gsettings_too: bool,
        resolve: &dyn Fn(&str) -> Option<PathBuf>,
    ) -> KdeOps {
        KdeOps {
            kwrite: tool_path(kwrite, resolve),
            kread: tool_path(kread, resolve),
            dbus_send: tool_path(DBUS_SEND, resolve),
            gsettings_too,
        }
    }

    fn kread_line(&self, key: &str) -> CmdLine {
        cmd(
            &program(&self.kread),
            &["--file", KIOSLAVERC, "--group", KDE_GROUP, "--key", key],
            false,
        )
    }

    fn kwrite_line(&self, key: &str, value: &str) -> CmdLine {
        cmd(
            &program(&self.kwrite),
            &[
                "--file", KIOSLAVERC, "--group", KDE_GROUP, "--key", key, value,
            ],
            true,
        )
    }

    fn signal_line(&self) -> CmdLine {
        cmd(
            &program(&self.dbus_send),
            &[
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ],
            true,
        )
    }

    /// The four `kreadconfig` values, raw (an absent key reads as `""`).
    fn read_kioslaverc(&self, exec: &dyn Executor) -> Result<BTreeMap<String, String>, ReadError> {
        let mut map = BTreeMap::new();
        for key in KDE_KEYS {
            let value = run_read(exec, &self.kread_line(key))?;
            map.insert(key.to_string(), value.trim().to_string());
        }
        Ok(map)
    }

    /// The four `kwriteconfig` lines then the KIO signal.
    fn write_kioslaverc(
        &self,
        exec: &dyn Executor,
        values: &[(&str, String)],
        lines: &mut Vec<String>,
    ) -> Result<(), WriteError> {
        for (key, value) in values {
            let line = self.kwrite_line(key, value);
            lines.push(line.render());
            run_write(exec, &line)?;
        }
        let signal = self.signal_line();
        lines.push(signal.render());
        run_write(exec, &signal)
    }
}

fn kde_effective(kioslaverc: &BTreeMap<String, String>) -> Effective {
    let value = |key: &str| kioslaverc.get(key).map_or("", String::as_str);
    let manual = value("ProxyType") == "1";
    Effective {
        http: parse_kde_proxy(value("httpProxy"), manual),
        https: parse_kde_proxy(value("httpsProxy"), manual),
        bypass: parse_kde_list(value("NoProxyFor")),
    }
}

impl PlatformOps for KdeOps {
    fn mechanism(&self) -> Mechanism {
        Mechanism::Kde
    }

    fn read_effective(&self, exec: &dyn Executor) -> Result<Effective, ReadError> {
        Ok(kde_effective(&self.read_kioslaverc(exec)?))
    }

    /// The before-state for the state file: the four kioslaverc keys and,
    /// when `gsettings_too`, the six gsettings keys.
    fn snapshot(&self, exec: &dyn Executor) -> Result<Snapshot, ReadError> {
        let kioslaverc = self.read_kioslaverc(exec)?;
        let gsettings = if self.gsettings_too {
            Some(gsettings_read_keys(exec, &mut Vec::new())?)
        } else {
            None
        };
        Ok(Snapshot {
            previous: Previous::Kde {
                kioslaverc,
                gsettings,
            },
            skipped: Vec::new(),
        })
    }

    /// The `kde` row and, when `gsettings_too`, the `gsettings` row.
    fn read_services(&self, exec: &dyn Executor) -> Result<Vec<ServiceRow>, ReadError> {
        let mut rows = vec![row(KDE_SERVICE, self.read_effective(exec)?)];
        if self.gsettings_too {
            rows.push(row(GSETTINGS_SERVICE, GsettingsOps.read_effective(exec)?));
        }
        Ok(rows)
    }

    /// gsettings first when mirrored (§D4), then `ProxyType 1`, the two
    /// proxies, `NoProxyFor`, and the KIO signal.
    fn write(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        ours: &Endpoint,
        bypass_extra: &[String],
    ) -> Result<Vec<String>, WriteError> {
        let Previous::Kde {
            kioslaverc,
            gsettings,
        } = previous
        else {
            return Err(WriteError::Failed(
                "previous state is not a KDE snapshot".to_string(),
            ));
        };
        let mut lines = Vec::new();
        if self.gsettings_too {
            lines.extend(gsettings_write(
                exec,
                gsettings.as_ref(),
                ours,
                bypass_extra,
            )?);
        }
        let previous_list = kioslaverc
            .get("NoProxyFor")
            .map(|v| parse_kde_list(v))
            .unwrap_or_default();
        let bypass = bypass_for(&previous_list, bypass_extra);
        let proxy = kde_proxy_value(ours);
        let values = [
            ("ProxyType", "1".to_string()),
            ("httpProxy", proxy.clone()),
            ("httpsProxy", proxy),
            ("NoProxyFor", bypass.join(",")),
        ];
        self.write_kioslaverc(exec, &values, &mut lines)?;
        Ok(lines)
    }

    /// `kde` in `only`: the four previous values back (an absent or empty
    /// `ProxyType` → `0`) and the signal; `gsettings` in `only` with a
    /// mirrored snapshot: the six gsettings keys back, verbatim, first.
    fn restore(
        &self,
        exec: &dyn Executor,
        previous: &Previous,
        only: &[String],
    ) -> Result<Vec<String>, WriteError> {
        let Previous::Kde {
            kioslaverc,
            gsettings,
        } = previous
        else {
            return Err(WriteError::Failed(
                "previous state is not a KDE snapshot".to_string(),
            ));
        };
        let mut lines = Vec::new();
        if let Some(keys) = gsettings {
            if only.iter().any(|s| s == GSETTINGS_SERVICE) {
                lines.extend(gsettings_restore(exec, keys)?);
            }
        }
        if only.iter().any(|s| s == KDE_SERVICE) {
            let values: Vec<(&str, String)> = KDE_KEYS
                .iter()
                .map(|key| {
                    let previous = kioslaverc.get(*key).map_or("", String::as_str);
                    let value = if *key == "ProxyType" && previous.is_empty() {
                        "0".to_string()
                    } else {
                        previous.to_string()
                    };
                    (*key, value)
                })
                .collect();
            self.write_kioslaverc(exec, &values, &mut lines)?;
        }
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aitm_ca::exec::CmdLine;
    use aitm_ca::testing::ScriptedExecutor;

    use super::*;
    use crate::BYPASS_DEFAULT;

    fn ours() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }

    fn defaults() -> Vec<String> {
        BYPASS_DEFAULT.iter().map(|s| s.to_string()).collect()
    }

    fn line(program: &str, args: &[&str]) -> String {
        CmdLine {
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            stdin: None,
            mutating: false,
        }
        .render()
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    fn tools_of(names: &[&str]) -> impl Fn(&str) -> bool {
        let set: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        move |t: &str| set.iter().any(|s| s == t)
    }

    /// A resolver that finds `names` under `/fake/bin`, like a `PATH` with
    /// one entry would.
    fn tools_at(names: &[&str]) -> impl Fn(&str) -> Option<std::path::PathBuf> {
        let set: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        move |t: &str| {
            set.iter()
                .any(|s| s == t)
                .then(|| std::path::Path::new("/fake/bin").join(t))
        }
    }

    /// `KdeOps` for tools resolved under `/fake/bin`; a tool not in `found`
    /// keeps its bare name (so a missing one is still reported by name).
    fn kde_at(kwrite: &str, kread: &str, found: &[&str], gsettings_too: bool) -> KdeOps {
        let at = |t: &str| {
            if found.contains(&t) {
                std::path::Path::new("/fake/bin").join(t)
            } else {
                std::path::PathBuf::from(t)
            }
        };
        KdeOps {
            kwrite: at(kwrite),
            kread: at(kread),
            dbus_send: at("dbus-send"),
            gsettings_too,
        }
    }

    /// SP-AC10: the §D4 detection table, pure over (os, env, PATH).
    #[test]
    fn detect_table() {
        // KDE desktop with kwriteconfig6 on PATH → Kde, 6 variants, no gsettings.
        let d = detect(
            "linux",
            &env_of(&[("XDG_CURRENT_DESKTOP", "KDE")]),
            &tools_of(&["kwriteconfig6"]),
        );
        assert_eq!(
            d,
            Detected::Kde {
                kwrite: "kwriteconfig6",
                kread: "kreadconfig6",
                gsettings_too: false
            }
        );
        assert_eq!(d.mechanism(), Mechanism::Kde);
        assert_eq!(
            detect_mechanism(
                "linux",
                &env_of(&[("XDG_CURRENT_DESKTOP", "KDE")]),
                &tools_of(&["kwriteconfig6"]),
            ),
            Mechanism::Kde
        );

        // KDE with only the 5 tools and gsettings present → 5 variants, gsettings_too.
        assert_eq!(
            detect(
                "linux",
                &env_of(&[("XDG_CURRENT_DESKTOP", "KDE")]),
                &tools_of(&["kwriteconfig5", "gsettings"]),
            ),
            Detected::Kde {
                kwrite: "kwriteconfig5",
                kread: "kreadconfig5",
                gsettings_too: true
            }
        );

        // KDE named but no kwriteconfig at all; gsettings + DISPLAY → Gsettings.
        assert_eq!(
            detect(
                "linux",
                &env_of(&[("XDG_CURRENT_DESKTOP", "KDE"), ("DISPLAY", ":0")]),
                &tools_of(&["gsettings"]),
            ),
            Detected::Gsettings
        );

        // The cis-lab case: gsettings + a session bus, no DISPLAY → Gsettings.
        let d = detect(
            "linux",
            &env_of(&[("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/501/bus")]),
            &tools_of(&["gsettings"]),
        );
        assert_eq!(d, Detected::Gsettings);
        assert_eq!(d.mechanism(), Mechanism::Gsettings);

        // gsettings present but no bus and no display → None.
        let d = detect("linux", &env_of(&[]), &tools_of(&["gsettings"]));
        assert_eq!(d, Detected::None);
        assert_eq!(d.mechanism(), Mechanism::None);
        assert_eq!(
            detect_mechanism("linux", &env_of(&[]), &tools_of(&["gsettings"])),
            Mechanism::None
        );

        // A display without the gsettings tool → None.
        assert_eq!(
            detect("linux", &env_of(&[("DISPLAY", ":0")]), &tools_of(&[])),
            Detected::None
        );

        // Any other OS → None, whatever env and PATH say.
        assert_eq!(
            detect(
                "windows",
                &env_of(&[("XDG_CURRENT_DESKTOP", "KDE"), ("DISPLAY", ":0")]),
                &tools_of(&["kwriteconfig6", "gsettings"]),
            ),
            Detected::None
        );
        assert_eq!(
            detect_mechanism(
                "macos",
                &env_of(&[("DISPLAY", ":0")]),
                &tools_of(&["gsettings"]),
            ),
            Mechanism::None
        );
    }

    /// F1.3: the `PATH` probe behind detection, on a real directory. Only a
    /// file in a listed entry counts; a directory of that name, an entry
    /// that does not exist, an empty entry and an absent `PATH` do not.
    /// S2: the resolved form is the file's absolute path.
    #[test]
    fn resolve_on_path_finds_files_in_path_entries_only() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aitm-sysproxy-path-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(dir.join("kwriteconfig5"), b"#!/bin/sh\n").expect("write tool");
        std::fs::create_dir(dir.join("kwriteconfig6")).expect("create decoy dir");

        let path = std::env::join_paths([
            std::path::PathBuf::from("/nonexistent-aitm-sysproxy"),
            std::path::PathBuf::new(),
            dir.clone(),
        ])
        .expect("join paths");
        assert!(resolve_on_path(Some(&path), "kwriteconfig5").is_some());
        assert_eq!(
            resolve_on_path(Some(&path), "kwriteconfig5"),
            Some(dir.join("kwriteconfig5")),
            "the resolved form is the file in the PATH entry that has it"
        );
        assert_eq!(resolve_on_path(Some(&path), "kwriteconfig6"), None);
        assert_eq!(resolve_on_path(None, "kwriteconfig5"), None);
        assert!(
            resolve_on_path(Some(&path), "kwriteconfig6").is_none(),
            "a directory is not a tool"
        );
        assert!(resolve_on_path(Some(&path), "gsettings").is_none());
        assert!(
            resolve_on_path(None, "kwriteconfig5").is_none(),
            "no PATH, no tools"
        );
        assert!(
            resolve_on_path(Some(std::ffi::OsStr::new("")), "kwriteconfig5").is_none(),
            "an empty PATH entry is not the working directory"
        );

        std::fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// F1.3: a bare `Mechanism::Kde` (the state file names the mechanism,
    /// not the tool major) resolves its tools at runtime: the §D4 detection
    /// when the environment says KDE, else `PATH` alone, 6 preferred and 5
    /// when only 5 is present; the 6 names when nothing is found, so the
    /// error names the tool a current Plasma host would have.
    #[test]
    fn kde_ops_resolved_follows_detection_then_path() {
        let kde = env_of(&[("XDG_CURRENT_DESKTOP", "KDE")]);
        // S2: every tool found on PATH is stored by its absolute path; one
        // not found keeps its bare name so the error still names it.
        let found5 = ["kwriteconfig5", "kreadconfig5", "dbus-send"];
        assert_eq!(
            kde_ops_resolved("linux", &kde, &tools_at(&found5)),
            kde_at("kwriteconfig5", "kreadconfig5", &found5, false)
        );
        let all6 = [
            "kwriteconfig6",
            "kreadconfig6",
            "kwriteconfig5",
            "kreadconfig5",
            "gsettings",
            "dbus-send",
        ];
        assert_eq!(
            kde_ops_resolved("linux", &kde, &tools_at(&all6)),
            kde_at("kwriteconfig6", "kreadconfig6", &all6, true)
        );
        // No desktop word (a core started from a unit file, a watchdog with
        // a trimmed environment): PATH decides the major; no mirror is
        // assumed, the snapshot's content decides what is restored.
        assert_eq!(
            kde_ops_resolved(
                "linux",
                &env_of(&[]),
                &tools_at(&["kwriteconfig5", "kreadconfig5", "gsettings"])
            ),
            kde_at(
                "kwriteconfig5",
                "kreadconfig5",
                &["kwriteconfig5", "kreadconfig5"],
                false
            )
        );
        assert_eq!(
            kde_ops_resolved(
                "linux",
                &env_of(&[]),
                &tools_at(&["kwriteconfig6", "kreadconfig6"])
            ),
            kde_at(
                "kwriteconfig6",
                "kreadconfig6",
                &["kwriteconfig6", "kreadconfig6"],
                false
            )
        );
        assert_eq!(
            kde_ops_resolved("macos", &env_of(&[]), &tools_at(&[])),
            kde_at("kwriteconfig6", "kreadconfig6", &[], false),
            "nothing found: bare names, so a spawn failure names the tool"
        );
        assert_eq!(
            crate::platform::ops_for(Mechanism::Kde).mechanism(),
            Mechanism::Kde
        );
    }

    const PREV_LIST: &str = "['localhost', '127.0.0.0/8', '::1']";
    const WRITTEN_LIST: &str =
        "['localhost', '127.0.0.0/8', '::1', '127.0.0.1', '*.local', '169.254/16']";

    fn get(schema: &str, key: &str) -> String {
        line(GSETTINGS, &["get", schema, key])
    }

    fn set(schema: &str, key: &str, value: &str) -> String {
        line(GSETTINGS, &["set", schema, key, value])
    }

    fn previous_gsettings() -> Previous {
        Previous::Gsettings {
            keys: BTreeMap::from([
                (
                    "org.gnome.system.proxy mode".to_string(),
                    "'none'".to_string(),
                ),
                (
                    "org.gnome.system.proxy.http host".to_string(),
                    "''".to_string(),
                ),
                (
                    "org.gnome.system.proxy.http port".to_string(),
                    "8080".to_string(),
                ),
                (
                    "org.gnome.system.proxy.https host".to_string(),
                    "''".to_string(),
                ),
                (
                    "org.gnome.system.proxy.https port".to_string(),
                    "0".to_string(),
                ),
                (
                    "org.gnome.system.proxy ignore-hosts".to_string(),
                    PREV_LIST.to_string(),
                ),
            ]),
        }
    }

    /// The six `get`s answering the before-state; `after` queues the read-back.
    fn scripted_gsettings(after: Option<[&str; 6]>) -> ScriptedExecutor {
        let before = ["'none'", "''", "8080", "''", "0", PREV_LIST];
        let mut exec = ScriptedExecutor::new();
        for (i, (schema, key)) in GSETTINGS_KEYS.iter().enumerate() {
            exec = exec.respond(&get(schema, key), 0, before[i], "");
            if let Some(after) = after {
                exec = exec.respond(&get(schema, key), 0, after[i], "");
            }
        }
        exec
    }

    /// SP-AC11 rendering half: gets, the six sets in §D4 order (`mode` last),
    /// gets again; a read-back that kept `mode` at `'none'` is a failure.
    #[test]
    fn gsettings_set_renders_in_order_and_reads_back() {
        let exec = scripted_gsettings(Some([
            "'manual'",
            "'127.0.0.1'",
            "8080",
            "'127.0.0.1'",
            "8080",
            WRITTEN_LIST,
        ]));
        let lines = GsettingsOps
            .write(&exec, &previous_gsettings(), &ours(), &defaults())
            .expect("write succeeds");

        let gets: Vec<String> = GSETTINGS_KEYS.iter().map(|(s, k)| get(s, k)).collect();
        let sets = vec![
            set("org.gnome.system.proxy.http", "host", "'127.0.0.1'"),
            set("org.gnome.system.proxy.http", "port", "8080"),
            set("org.gnome.system.proxy.https", "host", "'127.0.0.1'"),
            set("org.gnome.system.proxy.https", "port", "8080"),
            set("org.gnome.system.proxy", "ignore-hosts", WRITTEN_LIST),
            set("org.gnome.system.proxy", "mode", "'manual'"),
        ];
        let mut expected = gets.clone();
        expected.extend(sets.clone());
        expected.extend(gets);
        assert_eq!(exec.runs(), expected);
        assert_eq!(lines, expected);
        // The spec's literal lines, byte for byte, where the argv has no whitespace.
        assert_eq!(
            sets[0],
            "/usr/bin/gsettings set org.gnome.system.proxy.http host '127.0.0.1'"
        );
        assert_eq!(
            sets[5],
            "/usr/bin/gsettings set org.gnome.system.proxy mode 'manual'"
        );
        // The list is ONE argv word (C1).
        assert!(sets[4].ends_with(&format!(
            "ignore-hosts '{}'",
            WRITTEN_LIST.replace('\'', r"'\''")
        )));

        // Memory backend: the read-back keeps `'none'` for mode.
        let exec = scripted_gsettings(None);
        let err = GsettingsOps
            .write(&exec, &previous_gsettings(), &ours(), &defaults())
            .expect_err("non-persisting backend fails");
        match err {
            WriteError::Failed(m) => assert!(m.contains("did not persist"), "{m}"),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(exec.runs().len(), 18);
    }

    /// The effective view and the synthetic row come from the same six gets;
    /// restore writes the raw previous text back verbatim, `mode` last.
    #[test]
    fn gsettings_read_and_restore() {
        let exec = scripted_gsettings(None);
        let eff = GsettingsOps.read_effective(&exec).expect("read");
        assert_eq!(
            eff,
            Effective {
                http: ProtocolProxy {
                    enabled: false,
                    host: String::new(),
                    port: 8080
                },
                https: ProtocolProxy {
                    enabled: false,
                    host: String::new(),
                    port: 0
                },
                bypass: vec!["localhost".into(), "127.0.0.0/8".into(), "::1".into()],
            }
        );
        let rows = GsettingsOps.read_services(&exec).expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].service, GSETTINGS_SERVICE);
        assert_eq!(rows[0].bypass, eff.bypass);
        assert_eq!(
            GsettingsOps.snapshot(&exec).expect("snapshot").previous,
            previous_gsettings()
        );

        let exec = ScriptedExecutor::new();
        let lines = GsettingsOps
            .restore(
                &exec,
                &previous_gsettings(),
                &[GSETTINGS_SERVICE.to_string()],
            )
            .expect("restore");
        let expected = vec![
            set("org.gnome.system.proxy.http", "host", "''"),
            set("org.gnome.system.proxy.http", "port", "8080"),
            set("org.gnome.system.proxy.https", "host", "''"),
            set("org.gnome.system.proxy.https", "port", "0"),
            set("org.gnome.system.proxy", "ignore-hosts", PREV_LIST),
            set("org.gnome.system.proxy", "mode", "'none'"),
        ];
        assert_eq!(exec.runs(), expected);
        assert_eq!(lines, expected);

        // Not named in `only` → nothing runs.
        let exec = ScriptedExecutor::new();
        let lines = GsettingsOps
            .restore(&exec, &previous_gsettings(), &[])
            .expect("restore");
        assert!(lines.is_empty());
        assert!(exec.runs().is_empty());
    }

    fn kw(key: &str, value: &str) -> String {
        line(
            "kwriteconfig6",
            &[
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                key,
                value,
            ],
        )
    }

    fn kr(key: &str) -> String {
        line(
            "kreadconfig6",
            &[
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                key,
            ],
        )
    }

    fn dbus() -> String {
        line(
            "dbus-send",
            &[
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ],
        )
    }

    fn kde6() -> KdeOps {
        KdeOps {
            kwrite: "kwriteconfig6".into(),
            kread: "kreadconfig6".into(),
            dbus_send: "dbus-send".into(),
            gsettings_too: false,
        }
    }

    /// S2: the lines a detected KDE renders spawn the tools by the absolute
    /// path detection resolved on `PATH`, never by a bare name the spawn
    /// would look up again.
    #[test]
    fn kde_tools_render_by_their_resolved_absolute_path() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("aitm-sysproxy-kde-path-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        for tool in ["kwriteconfig6", "kreadconfig6", "dbus-send"] {
            std::fs::write(dir.join(tool), b"#!/bin/sh\n").expect("write tool");
        }
        let path = dir.clone().into_os_string();
        let resolve = |tool: &str| resolve_on_path(Some(&path), tool);
        let kde = kde_ops_resolved(
            "linux",
            &env_of(&[("XDG_CURRENT_DESKTOP", "KDE")]),
            &resolve,
        );
        assert_eq!(
            kde,
            KdeOps {
                kwrite: dir.join("kwriteconfig6"),
                kread: dir.join("kreadconfig6"),
                dbus_send: dir.join("dbus-send"),
                gsettings_too: false,
            }
        );
        let kw = dir.join("kwriteconfig6").to_string_lossy().into_owned();
        let kr_path = dir.join("kreadconfig6").to_string_lossy().into_owned();
        let dbus_path = dir.join("dbus-send").to_string_lossy().into_owned();

        let exec = ScriptedExecutor::new();
        let lines = kde
            .write(&exec, &previous_kde(), &ours(), &[])
            .expect("write");
        let kioslaverc = ["--file", "kioslaverc", "--group", "Proxy Settings", "--key"];
        let kw_line = |key: &str, value: &str| {
            let mut args = kioslaverc.to_vec();
            args.push(key);
            args.push(value);
            line(&kw, &args)
        };
        assert_eq!(
            lines,
            vec![
                kw_line("ProxyType", "1"),
                kw_line("httpProxy", "http://127.0.0.1 8080"),
                kw_line("httpsProxy", "http://127.0.0.1 8080"),
                kw_line("NoProxyFor", "localhost,127.0.0.1,::1,*.local,169.254/16"),
                line(
                    &dbus_path,
                    &[
                        "--type=signal",
                        "/KIO/Scheduler",
                        "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                        "string:",
                    ],
                ),
            ]
        );
        assert_eq!(exec.runs(), lines);

        let exec = ScriptedExecutor::new();
        kde.read_effective(&exec).expect("read");
        let mut read_args = kioslaverc.to_vec();
        read_args.push("ProxyType");
        assert_eq!(exec.runs()[0], line(&kr_path, &read_args));
        std::fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    /// Q7: a `write` handed another mechanism's snapshot is refused before
    /// any run, as `restore` already is on both Linux mechanisms.
    #[test]
    fn write_refuses_a_mismatched_previous_kind_before_any_run() {
        let exec = ScriptedExecutor::new();
        assert!(matches!(
            GsettingsOps.write(&exec, &previous_kde(), &ours(), &[]),
            Err(WriteError::Failed(m)) if m.contains("not a gsettings snapshot")
        ));
        assert!(matches!(
            kde6().write(&exec, &previous_gsettings(), &ours(), &[]),
            Err(WriteError::Failed(m)) if m.contains("not a KDE snapshot")
        ));
        let mac = Previous::Networksetup { services: vec![] };
        assert!(matches!(
            GsettingsOps.write(&exec, &mac, &ours(), &[]),
            Err(WriteError::Failed(_))
        ));
        assert!(matches!(
            kde6().write(&exec, &mac, &ours(), &[]),
            Err(WriteError::Failed(_))
        ));
        assert!(exec.runs().is_empty(), "{:?}", exec.runs());
    }

    fn previous_kde() -> Previous {
        Previous::Kde {
            kioslaverc: BTreeMap::from([
                ("ProxyType".to_string(), "0".to_string()),
                ("httpProxy".to_string(), String::new()),
                ("httpsProxy".to_string(), String::new()),
                ("NoProxyFor".to_string(), String::new()),
            ]),
            gsettings: None,
        }
    }

    /// SP-AC12: four `kwriteconfig6` lines then the `dbus-send` signal; unset
    /// writes the four previous values back and signals again.
    #[test]
    fn kde_set_and_unset_render() {
        let exec = ScriptedExecutor::new();
        let lines = kde6()
            .write(&exec, &previous_kde(), &ours(), &defaults())
            .expect("write");
        let expected = vec![
            kw("ProxyType", "1"),
            kw("httpProxy", "http://127.0.0.1 8080"),
            kw("httpsProxy", "http://127.0.0.1 8080"),
            kw("NoProxyFor", "localhost,127.0.0.1,::1,*.local,169.254/16"),
            dbus(),
        ];
        assert_eq!(exec.runs(), expected);
        assert_eq!(lines, expected);
        // The spec's literal spellings.
        assert_eq!(
            expected[0],
            "kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key ProxyType 1"
        );
        assert_eq!(
            expected[1],
            "kwriteconfig6 --file kioslaverc --group 'Proxy Settings' --key httpProxy 'http://127.0.0.1 8080'"
        );
        assert_eq!(
            expected[4],
            "dbus-send --type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration string:"
        );

        let exec = ScriptedExecutor::new();
        let lines = kde6()
            .restore(&exec, &previous_kde(), &[KDE_SERVICE.to_string()])
            .expect("restore");
        let expected = vec![
            kw("ProxyType", "0"),
            kw("httpProxy", ""),
            kw("httpsProxy", ""),
            kw("NoProxyFor", ""),
            dbus(),
        ];
        assert_eq!(exec.runs(), expected);
        assert_eq!(lines, expected);

        // An absent ProxyType restores as 0.
        let exec = ScriptedExecutor::new();
        kde6()
            .restore(
                &exec,
                &Previous::Kde {
                    kioslaverc: BTreeMap::new(),
                    gsettings: None,
                },
                &[KDE_SERVICE.to_string()],
            )
            .expect("restore");
        assert_eq!(exec.runs()[0], kw("ProxyType", "0"));
    }

    /// The KDE snapshot and effective view come from `kreadconfig6`; with
    /// `gsettings_too` the gsettings writes come first and are snapshotted.
    #[test]
    fn kde_reads_and_mirrors_gsettings() {
        let exec = ScriptedExecutor::new()
            .respond(&kr("ProxyType"), 0, "1\n", "")
            .respond(&kr("httpProxy"), 0, "http://127.0.0.1 9090\n", "")
            .respond(&kr("httpsProxy"), 0, "http://127.0.0.1 9090\n", "")
            .respond(&kr("NoProxyFor"), 0, "localhost,*.local\n", "");
        let eff = kde6().read_effective(&exec).expect("read");
        assert_eq!(
            eff,
            Effective {
                http: ProtocolProxy {
                    enabled: true,
                    host: "127.0.0.1".into(),
                    port: 9090
                },
                https: ProtocolProxy {
                    enabled: true,
                    host: "127.0.0.1".into(),
                    port: 9090
                },
                bypass: vec!["localhost".into(), "*.local".into()],
            }
        );
        assert_eq!(
            exec.runs(),
            vec![
                kr("ProxyType"),
                kr("httpProxy"),
                kr("httpsProxy"),
                kr("NoProxyFor")
            ]
        );
        let rows = kde6().read_services(&exec).expect("rows");
        assert_eq!(rows[0].service, KDE_SERVICE);
        assert_eq!(rows[0].http, eff.http);
        assert_eq!(
            kde6().snapshot(&exec).expect("snapshot").previous,
            Previous::Kde {
                kioslaverc: BTreeMap::from([
                    ("ProxyType".to_string(), "1".to_string()),
                    ("httpProxy".to_string(), "http://127.0.0.1 9090".to_string()),
                    (
                        "httpsProxy".to_string(),
                        "http://127.0.0.1 9090".to_string()
                    ),
                    ("NoProxyFor".to_string(), "localhost,*.local".to_string()),
                ]),
                gsettings: None,
            }
        );

        // gsettings_too: snapshot carries the six keys; write mirrors first.
        let both = KdeOps {
            kwrite: "kwriteconfig6".into(),
            kread: "kreadconfig6".into(),
            dbus_send: "dbus-send".into(),
            gsettings_too: true,
        };
        let exec = scripted_gsettings(Some([
            "'manual'",
            "'127.0.0.1'",
            "8080",
            "'127.0.0.1'",
            "8080",
            WRITTEN_LIST,
        ]));
        let snap = both.snapshot(&exec).expect("snapshot").previous;
        let Previous::Kde { gsettings, .. } = &snap else {
            panic!("kde snapshot");
        };
        let Previous::Gsettings { keys } = previous_gsettings() else {
            unreachable!()
        };
        assert_eq!(gsettings.as_ref(), Some(&keys));

        let exec = scripted_gsettings(Some([
            "'manual'",
            "'127.0.0.1'",
            "8080",
            "'127.0.0.1'",
            "8080",
            WRITTEN_LIST,
        ]));
        let previous = Previous::Kde {
            kioslaverc: BTreeMap::new(),
            gsettings: Some(keys),
        };
        let lines = both
            .write(&exec, &previous, &ours(), &defaults())
            .expect("write");
        assert_eq!(lines.len(), 18 + 5);
        assert!(lines[0].starts_with("/usr/bin/gsettings get "));
        assert_eq!(lines[18], kw("ProxyType", "1"));
        assert_eq!(lines[22], dbus());
        // A KDE-only NoProxyFor with an empty gsettings list still carries the
        // merged union from the kioslaverc side (previous was empty here).
        assert_eq!(
            lines[21],
            kw("NoProxyFor", "localhost,127.0.0.1,::1,*.local,169.254/16")
        );
    }

    /// A tool that could not be started is `ToolMissing(program)`.
    #[test]
    fn missing_tool_is_reported_by_name() {
        struct NoTools;
        impl Executor for NoTools {
            fn run(&self, cmd: &CmdLine) -> anyhow::Result<aitm_ca::exec::CmdOutput> {
                anyhow::bail!("could not start `{}`", cmd.render())
            }
            fn read_file(&self, _: &std::path::Path) -> anyhow::Result<Option<Vec<u8>>> {
                Ok(None)
            }
            fn dir_exists(&self, _: &std::path::Path) -> bool {
                false
            }
            fn home_dir(&self) -> Option<std::path::PathBuf> {
                None
            }
            fn is_root(&self) -> bool {
                false
            }
        }
        assert_eq!(
            GsettingsOps.read_effective(&NoTools),
            Err(ReadError::ToolMissing(GSETTINGS.to_string()))
        );
        assert_eq!(
            kde6().write(&NoTools, &previous_kde(), &ours(), &defaults()),
            Err(WriteError::ToolMissing("kwriteconfig6".to_string()))
        );
    }

    /// GVariant text helpers round-trip the shapes `gsettings get` prints.
    #[test]
    fn gvariant_round_trips() {
        assert_eq!(
            parse_gvariant_string_list("['a', 'b c']"),
            vec!["a".to_string(), "b c".to_string()]
        );
        assert_eq!(
            gvariant_string_list(&["a".into(), "b c".into()]),
            "['a', 'b c']"
        );
        assert_eq!(parse_gvariant_string("'manual'"), "manual");
        assert_eq!(gvariant_string("127.0.0.1"), "'127.0.0.1'");
        assert_eq!(parse_gvariant_string("''"), "");
        assert_eq!(parse_gvariant_string_list("@as []"), Vec::<String>::new());
        assert_eq!(parse_gvariant_string_list("[]"), Vec::<String>::new());
        assert_eq!(gvariant_string_list(&[]), "@as []");
        assert_eq!(
            parse_gvariant_string_list(&gvariant_string_list(&["it's".into()])),
            vec!["it's".to_string()]
        );
    }

    /// Gap 6: `manual` with an empty host is not an enabled proxy, so a
    /// half-configured desktop never renders as `HTTPS → :0`.
    #[test]
    fn manual_mode_with_an_empty_host_is_not_enabled() {
        let mut exec = ScriptedExecutor::new();
        let answers = ["'manual'", "'127.0.0.1'", "8080", "''", "0", "@as []"];
        for (i, (schema, key)) in GSETTINGS_KEYS.iter().enumerate() {
            exec = exec.respond(&get(schema, key), 0, answers[i], "");
        }
        let eff = GsettingsOps.read_effective(&exec).expect("read");
        assert_eq!(
            eff.http,
            ProtocolProxy {
                enabled: true,
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            eff.https,
            ProtocolProxy {
                enabled: false,
                host: String::new(),
                port: 0
            }
        );
        assert_eq!(eff.bypass, Vec::<String>::new());

        let exec = ScriptedExecutor::new()
            .respond(&kr("ProxyType"), 0, "1\n", "")
            .respond(&kr("httpProxy"), 0, "http://127.0.0.1 8080\n", "")
            .respond(&kr("httpsProxy"), 0, "\n", "")
            .respond(&kr("NoProxyFor"), 0, "\n", "");
        let eff = kde6().read_effective(&exec).expect("read");
        assert!(eff.http.enabled);
        assert_eq!(eff.http.port, 8080);
        assert!(!eff.https.enabled);
        assert_eq!(eff.https.host, "");
    }

    /// Gap 1: the inherent snapshots are the trait's `snapshot`, unchanged.
    #[test]
    fn trait_snapshot_is_the_mechanism_snapshot() {
        let exec = scripted_gsettings(None);
        let ops: &dyn PlatformOps = &GsettingsOps;
        let snap = ops.snapshot(&exec).expect("snapshot");
        assert_eq!(snap.previous, previous_gsettings());
        assert!(snap.skipped.is_empty());

        let exec = ScriptedExecutor::new()
            .respond(&kr("ProxyType"), 0, "0\n", "")
            .respond(&kr("httpProxy"), 0, "\n", "")
            .respond(&kr("httpsProxy"), 0, "\n", "")
            .respond(&kr("NoProxyFor"), 0, "\n", "");
        let kde = kde6();
        let ops: &dyn PlatformOps = &kde;
        let snap = ops.snapshot(&exec).expect("snapshot");
        assert_eq!(snap.previous, previous_kde());
        assert!(snap.skipped.is_empty());
    }
}

/// Tester (stage 5) additions: malformed GVariant text, garbage `gsettings`
/// read-backs, and write failures mid-sequence for both Linux mechanisms.
#[cfg(test)]
mod tester_tests {
    use std::collections::BTreeMap;

    use aitm_ca::exec::CmdLine;
    use aitm_ca::testing::ScriptedExecutor;

    use super::*;
    use crate::BYPASS_DEFAULT;

    fn ours() -> Endpoint {
        Endpoint {
            host: "127.0.0.1".into(),
            port: 8080,
        }
    }

    fn defaults() -> Vec<String> {
        BYPASS_DEFAULT.iter().map(|s| s.to_string()).collect()
    }

    fn line(program: &str, args: &[&str]) -> String {
        CmdLine {
            program: program.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
            stdin: None,
            mutating: false,
        }
        .render()
    }

    fn get(schema: &str, key: &str) -> String {
        line(GSETTINGS, &["get", schema, key])
    }

    fn set(schema: &str, key: &str, value: &str) -> String {
        line(GSETTINGS, &["set", schema, key, value])
    }

    /// The six `get`s answering `answers`, in `GSETTINGS_KEYS` order.
    fn gets_answering(answers: [&str; 6]) -> ScriptedExecutor {
        let mut exec = ScriptedExecutor::new();
        for (i, (schema, key)) in GSETTINGS_KEYS.iter().enumerate() {
            exec = exec.respond(&get(schema, key), 0, answers[i], "");
        }
        exec
    }

    fn previous_none() -> Previous {
        Previous::Gsettings {
            keys: BTreeMap::from([
                (
                    "org.gnome.system.proxy mode".to_string(),
                    "'none'".to_string(),
                ),
                (
                    "org.gnome.system.proxy.http host".to_string(),
                    "''".to_string(),
                ),
                (
                    "org.gnome.system.proxy.http port".to_string(),
                    "8080".to_string(),
                ),
                (
                    "org.gnome.system.proxy.https host".to_string(),
                    "''".to_string(),
                ),
                (
                    "org.gnome.system.proxy.https port".to_string(),
                    "0".to_string(),
                ),
                (
                    "org.gnome.system.proxy ignore-hosts".to_string(),
                    "['localhost']".to_string(),
                ),
            ]),
        }
    }

    /// Malformed GVariant text never panics; unterminated or unbracketed
    /// lists are empty, unquoted strings are returned trimmed, escapes
    /// round-trip, and ports outside `u16` or non-numeric are 0.
    #[test]
    fn gvariant_parsers_survive_malformed_text() {
        assert_eq!(parse_gvariant_string_list(""), Vec::<String>::new());
        assert_eq!(parse_gvariant_string_list("garbage"), Vec::<String>::new());
        assert_eq!(
            parse_gvariant_string_list("['unterminated"),
            Vec::<String>::new()
        );
        assert_eq!(parse_gvariant_string_list("['a', 'b"), Vec::<String>::new());
        assert_eq!(parse_gvariant_string_list("[garbage, 'a']"), vec!["a"]);
        assert_eq!(
            parse_gvariant_string_list(r#"["dq", 'sq']"#),
            vec!["dq", "sq"]
        );
        assert_eq!(
            parse_gvariant_string_list(r"['back\\slash', 'tab\tx']"),
            vec!["back\\slash".to_string(), "tab\tx".to_string()]
        );
        assert_eq!(
            parse_gvariant_string_list("  @as []  "),
            Vec::<String>::new()
        );

        assert_eq!(parse_gvariant_string(""), "");
        assert_eq!(parse_gvariant_string("'"), "'");
        assert_eq!(parse_gvariant_string("manual"), "manual");
        assert_eq!(parse_gvariant_string("  'manual'\n"), "manual");
        assert_eq!(parse_gvariant_string(r"'it\'s'"), "it's");
        assert_eq!(gvariant_string("it's"), r"'it\'s'");
        assert_eq!(gvariant_string(r"a\b"), r"'a\\b'");
        for s in ["", "plain", "it's", "a\\b", "x y", "';rm -rf /"] {
            assert_eq!(parse_gvariant_string(&gvariant_string(s)), s, "{s:?}");
            assert_eq!(
                parse_gvariant_string_list(&gvariant_string_list(&[s.to_string()])),
                vec![s.to_string()],
                "{s:?}"
            );
        }

        assert_eq!(parse_port("abc"), 0);
        assert_eq!(parse_port(""), 0);
        assert_eq!(parse_port("70000"), 0);
        assert_eq!(parse_port("-1"), 0);
        assert_eq!(parse_port(" 8080 "), 8080);
        assert_eq!(parse_port("uint16 8080"), 8080);
        assert_eq!(parse_port("int32 8080"), 8080);
    }

    /// Garbage read-backs give a disabled row (never `→ :0`, never a panic):
    /// a non-`'manual'` mode disables both protocols whatever the hosts say.
    #[test]
    fn gsettings_garbage_reads_are_a_disabled_row_not_a_panic() {
        let exec = gets_answering([
            "garbage",
            "",
            "abc",
            "'127.0.0.1'",
            "not a port",
            "nonsense",
        ]);
        let eff = GsettingsOps.read_effective(&exec).expect("read");
        assert_eq!(
            eff.http,
            ProtocolProxy {
                enabled: false,
                host: String::new(),
                port: 0
            }
        );
        assert_eq!(
            eff.https,
            ProtocolProxy {
                enabled: false,
                host: "127.0.0.1".into(),
                port: 0
            }
        );
        assert_eq!(eff.bypass, Vec::<String>::new());
        let rows = GsettingsOps.read_services(&exec).expect("rows");
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].http.enabled && !rows[0].https.enabled);

        // A failing `get` is a typed read failure, not a default row.
        let exec = ScriptedExecutor::new().respond(
            &get("org.gnome.system.proxy", "mode"),
            1,
            "",
            "No such schema",
        );
        assert!(matches!(
            GsettingsOps.read_effective(&exec),
            Err(ReadError::Failed(m)) if m.contains("No such schema")
        ));
        assert_eq!(exec.runs().len(), 1, "stopped at the first failing get");
    }

    /// A `gsettings set` that fails mid-sequence is `Failed` naming the line
    /// and stderr; the later sets never run, so `mode` is never flipped to
    /// `'manual'` with half the keys written.
    #[test]
    fn gsettings_write_failure_mid_sequence_stops_before_the_mode_flip() {
        let failing = set("org.gnome.system.proxy.https", "host", "'127.0.0.1'");
        let exec = gets_answering(["'none'", "''", "8080", "''", "0", "['localhost']"]).respond(
            &failing,
            1,
            "",
            "dconf: error",
        );
        let err = GsettingsOps
            .write(&exec, &previous_none(), &ours(), &defaults())
            .unwrap_err();
        let WriteError::Failed(m) = err else {
            panic!("expected Failed, got {err:?}");
        };
        assert!(m.contains(&failing), "{m}");
        assert!(m.contains("dconf: error"), "{m}");
        let runs = exec.runs();
        assert_eq!(
            runs.len(),
            6 + 3,
            "six gets, two good sets, the failing third: {runs:?}"
        );
        assert_eq!(runs[8], failing);
        assert!(
            !runs.iter().any(|l| l.ends_with("mode 'manual'")),
            "mode never flipped: {runs:?}"
        );

        // A restore that fails is `Failed` too and stops at the failing line.
        let failing = set("org.gnome.system.proxy.http", "port", "8080");
        let exec = ScriptedExecutor::new().respond(&failing, 1, "", "read-only");
        let err = GsettingsOps
            .restore(&exec, &previous_none(), &[GSETTINGS_SERVICE.to_string()])
            .unwrap_err();
        assert!(matches!(err, WriteError::Failed(m) if m.contains("read-only")));
        assert_eq!(exec.runs().len(), 2);
    }

    /// A `kwriteconfig` that fails is `Failed` and the KIO signal is not
    /// sent; a `kreadconfig` that fails is a typed read failure.
    #[test]
    fn kde_write_failure_is_failed_and_the_signal_is_not_sent() {
        let kde = KdeOps {
            kwrite: "kwriteconfig6".into(),
            kread: "kreadconfig6".into(),
            dbus_send: "dbus-send".into(),
            gsettings_too: false,
        };
        let failing = line(
            "kwriteconfig6",
            &[
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "httpProxy",
                "http://127.0.0.1 8080",
            ],
        );
        let exec = ScriptedExecutor::new().respond(&failing, 1, "", "cannot write");
        let previous = Previous::Kde {
            kioslaverc: BTreeMap::new(),
            gsettings: None,
        };
        let err = kde
            .write(&exec, &previous, &ours(), &defaults())
            .unwrap_err();
        assert!(
            matches!(err, WriteError::Failed(ref m) if m.contains("cannot write")),
            "{err:?}"
        );
        let runs = exec.runs();
        assert_eq!(
            runs.len(),
            2,
            "ProxyType, then the failing httpProxy: {runs:?}"
        );
        assert!(!runs.iter().any(|l| l.starts_with("dbus-send")));

        let failing_read = line(
            "kreadconfig6",
            &[
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "ProxyType",
            ],
        );
        let exec = ScriptedExecutor::new().respond(&failing_read, 2, "", "no such file");
        assert!(matches!(
            kde.read_effective(&exec),
            Err(ReadError::Failed(m)) if m.contains("no such file")
        ));
        assert_eq!(exec.runs().len(), 1);

        // A gsettings snapshot handed to the KDE restore is refused before any run.
        let exec = ScriptedExecutor::new();
        assert!(matches!(
            kde.restore(&exec, &previous_none(), &[KDE_SERVICE.to_string()]),
            Err(WriteError::Failed(_))
        ));
        assert!(exec.runs().is_empty());
    }
}
