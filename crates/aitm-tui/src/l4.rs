//! The L4 operator surface's model and view-helpers (ui-ext Part 3,
//! L4OPS-AC7–AC13). Everything here is plain data the reducer folds and the
//! renderer draws, like the rest of the UI: it parses the live `l4.*` bus
//! (feature-detected from `tools/list`), holds the inspector's packet cursor,
//! the YAML craft editor and its `build()` hex preview, the four per-feature
//! agent gates, and the inject confirm-over-the-wire handshake.
//!
//! Honest degradation (foundation §2.10(c)) is the rule. A terminal cannot draw
//! a graphical tree, so a packet's layer tree renders as a labelled indented
//! **text** tree ([`layer_tree_lines`]) rather than being dropped. A packet's
//! on-wire `bytes` (L4 parity spec §2) are present only when the core let this
//! caller see them (§2.2); a packet without them shows its headers and length
//! and an honest note. Every byte renders through [`hex_dump`] /
//! [`ascii_column`], so no raw control byte reaches the terminal (§2.3).
//!
//! Availability (spec §1) is read from `l4.capture.status` /
//! `l4.intercept.status` on every slow poll and never cached for the session;
//! until the first reply it is [`L4Availability::pending`].

use serde_json::{json, Value};

use crate::action::ToolInfo;
use crate::base64;

/// The marker an older core's gated verbs put in their error text; the
/// availability `reason` is exactly what follows it (spec §1 compatibility).
pub const UNAVAILABLE_MARKER: &str = "L4 unavailable: ";

/// The one pending literal TUI, web and macOS share (plan decision 9).
pub const PENDING_REASON: &str = "Reading L4 availability…";

/// The inspector's packet window (spec §2: the core's default `limit`).
pub const INSPECT_LIMIT: u64 = 256;

/// One packet of an L4 flow, from `l4.flow.get`'s `packets[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Packet {
    /// `inbound` / `outbound`, relative to the host.
    pub dir: String,
    /// The packet's byte length.
    pub length: u64,
    /// Whether aitmproxy authored and sent it (`l4.inject` / `l4.send_recv`).
    pub injected: bool,
    /// Decoded layer names, outermost first (e.g. `["IPv4","UDP","Raw"]`).
    pub layers: Vec<String>,
    /// Milliseconds since the Unix epoch, UTC (spec §2); `None` on an older core.
    pub timestamp: Option<i64>,
    /// `TCP`, `UDP`, `ICMP`, `ICMPv6` (spec §2), when the core decoded one.
    pub proto: Option<String>,
    /// Source / destination IP address strings (spec §2).
    pub src: Option<String>,
    pub dst: Option<String>,
    /// TCP/UDP ports (spec §2); `None` otherwise.
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// The on-wire bytes, decoded from the base64 `bytes` key. `None` when the
    /// key is absent: the caller may not see them (spec §2.2) or the core
    /// predates §2. Never confused with an empty packet.
    pub bytes: Option<Vec<u8>>,
}

fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn opt_port(v: &Value, key: &str) -> Option<u16> {
    v.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
}

fn str_list(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|l| l.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

impl L4Packet {
    fn from_json(v: &Value) -> Self {
        Self {
            dir: v
                .get("dir")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string(),
            length: v.get("length").and_then(Value::as_u64).unwrap_or(0),
            injected: v.get("injected").and_then(Value::as_bool).unwrap_or(false),
            layers: str_list(v, "layers"),
            timestamp: v.get("timestamp").and_then(Value::as_i64),
            proto: opt_str(v, "proto"),
            src: opt_str(v, "src"),
            dst: opt_str(v, "dst"),
            src_port: opt_port(v, "src_port"),
            dst_port: opt_port(v, "dst_port"),
            bytes: v
                .get("bytes")
                .and_then(Value::as_str)
                .and_then(base64::decode),
        }
    }

    /// A one-line decoded summary for the packet list: the layer stack, or
    /// `raw` when nothing decoded.
    pub fn summary(&self) -> String {
        if self.layers.is_empty() {
            "raw".to_string()
        } else {
            self.layers.join(" / ")
        }
    }

    /// The `→` / `←` arrow for the direction (outbound leaves the host).
    pub fn arrow(&self) -> &'static str {
        match self.dir.as_str() {
            "outbound" => "→",
            "inbound" => "←",
            _ => "·",
        }
    }
}

/// A whole L4 flow (`l4.flow.get`): a capture / craft / send-recv / intercept
/// session and its packet log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Flow {
    pub id: String,
    /// `capture`, `craft`, `send_recv`, or `intercept`.
    pub kind: String,
    pub interface: String,
    pub filter: Option<String>,
    /// The NFQUEUE number, for intercept flows.
    pub queue: Option<u16>,
    pub packet_count: u64,
    pub injected_count: u64,
    pub packets: Vec<L4Packet>,
    /// Flow creation, ms since the Unix epoch (spec §2); `None` on an older core.
    pub started_at: Option<i64>,
    /// The flow-level `proto` word from the first decodable packet (spec §2).
    pub transport: Option<String>,
    /// Flow-level addresses and ports from the first decodable packet (spec §2),
    /// so a list row shows its target without reading packets.
    pub src: Option<String>,
    pub dst: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl L4Flow {
    /// Parse an `l4.flow.get` object. `None` without an `id`.
    pub fn from_json(v: &Value) -> Option<Self> {
        let id = v.get("id")?.as_str()?.to_string();
        Some(Self {
            id,
            kind: v
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("capture")
                .to_string(),
            interface: v
                .get("interface")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            filter: opt_str(v, "filter"),
            queue: opt_port(v, "queue"),
            packet_count: v.get("packet_count").and_then(Value::as_u64).unwrap_or(0),
            injected_count: v.get("injected_count").and_then(Value::as_u64).unwrap_or(0),
            packets: v
                .get("packets")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(L4Packet::from_json).collect())
                .unwrap_or_default(),
            started_at: v.get("started_at").and_then(Value::as_i64),
            transport: opt_str(v, "proto"),
            src: opt_str(v, "src"),
            dst: opt_str(v, "dst"),
            src_port: opt_port(v, "src_port"),
            dst_port: opt_port(v, "dst_port"),
        })
    }

    /// The `TCP` / `UDP` / `ICMP` sub-label: the flow-level `proto` (spec §2)
    /// when the core sent one, else the first packet's layers.
    pub fn proto(&self) -> Option<&'static str> {
        self.transport
            .as_deref()
            .and_then(proto_label)
            .or_else(|| self.packets.first().and_then(|p| proto_of(&p.layers)))
    }

    /// The list row's target cell: the bound interface (+ filter note). The
    /// richer `iface cidr:port ↕dir` needs fields `l4.flow.get` does not carry,
    /// so the interface is the honest target here.
    pub fn target(&self) -> String {
        match &self.filter {
            Some(f) if !f.is_empty() => format!("{} · {f}", self.interface),
            _ => self.interface.clone(),
        }
    }

    /// Whether this is an in-path interception session (a parked packet).
    pub fn is_intercept(&self) -> bool {
        self.kind == "intercept"
    }

    /// The parked packet of an interception session: the most recent one.
    pub fn parked(&self) -> Option<&L4Packet> {
        if self.is_intercept() {
            self.packets.last()
        } else {
            None
        }
    }
}

/// The `TCP` / `UDP` / `ICMP` transport sub-label for a layer list, if any.
pub fn proto_of(layers: &[String]) -> Option<&'static str> {
    // Innermost transport wins — scan inner-to-outer, matching the web
    // (`protoSubLabel`) and macOS (`L4Proto.fromLayers`) rule so the three
    // surfaces print the same sub-label.
    layers.iter().rev().find_map(|l| proto_label(l))
}

/// The sub-label for one layer / `proto` word (`ICMPv6` folds into `ICMP`).
fn proto_label(word: &str) -> Option<&'static str> {
    match word.to_ascii_uppercase().as_str() {
        "TCP" => Some("TCP"),
        "UDP" => Some("UDP"),
        "ICMP" | "ICMPV6" => Some("ICMP"),
        _ => None,
    }
}

// ------------------------------------------------------------ availability

/// What `l4.capture.status` / `l4.intercept.status` say about a capability
/// class on this core now (L4 parity spec §1). Re-read on every slow poll,
/// never cached for the session; [`L4Availability::pending`] until the first
/// reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Availability {
    pub available: bool,
    /// `available` | `needs_privilege` | `unsupported_platform` |
    /// `not_configured`; `None` from an older core or an error.
    pub code: Option<String>,
    /// The core's reason, verbatim; `None` when available.
    pub reason: Option<String>,
}

impl L4Availability {
    /// Parse a status reply: the §1 object (bool `available`, copying `code` and
    /// `reason`), or an older core's bare array (available). Anything else is
    /// honestly unavailable.
    pub fn from_reply(v: &Value) -> Self {
        if let Some(available) = v.get("available").and_then(Value::as_bool) {
            return Self {
                available,
                code: opt_str(v, "code"),
                reason: opt_str(v, "reason"),
            };
        }
        if v.is_array() {
            return Self {
                available: true,
                code: None,
                reason: None,
            };
        }
        Self {
            available: false,
            code: None,
            reason: Some("unrecognised l4 status reply".to_string()),
        }
    }

    /// An older core's tool error: `Some` iff `message` carries
    /// [`UNAVAILABLE_MARKER`]; the reason is exactly the text after it.
    pub fn from_error(message: &str) -> Option<Self> {
        let (_, reason) = message.split_once(UNAVAILABLE_MARKER)?;
        Some(Self {
            available: false,
            code: None,
            reason: Some(reason.to_string()),
        })
    }

    /// Before the first status reply: unavailable, reason [`PENDING_REASON`].
    pub fn pending() -> Self {
        Self {
            available: false,
            code: None,
            reason: Some(PENDING_REASON.to_string()),
        }
    }
}

impl Default for L4Availability {
    fn default() -> Self {
        Self::pending()
    }
}

/// The ids a status reply lists under `key` (`captures` / `sessions`): string
/// entries as they are, object entries by their `id`; an older core's bare
/// array the same way.
pub fn status_ids(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .or_else(|| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    e.as_str()
                        .or_else(|| e.get("id").and_then(Value::as_str))
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------- parked packets

/// One `l4.intercept.list` entry: a packet parked in-path (spec §4). The core
/// lists them oldest first; the verdict verbs take this `id`, never the flow's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Parked {
    pub id: String,
    /// The intercept flow (session) it belongs to.
    pub flow: String,
    pub state: String,
    pub length: u64,
    pub layers: Vec<String>,
    /// Epoch ms when it was parked; `None` on an older core.
    pub parked_at: Option<i64>,
}

impl L4Parked {
    /// Parse one entry. `None` without string `id` and `flow`.
    pub fn from_json(v: &Value) -> Option<Self> {
        Some(Self {
            id: opt_str(v, "id")?,
            flow: opt_str(v, "flow")?,
            state: opt_str(v, "state").unwrap_or_else(|| "parked".to_string()),
            length: v.get("length").and_then(Value::as_u64).unwrap_or(0),
            layers: str_list(v, "layers"),
            parked_at: v.get("parked_at").and_then(Value::as_i64),
        })
    }

    /// Parse an `l4.intercept.list` reply in the core's order; not an array →
    /// nothing parked.
    pub fn list_from_json(v: &Value) -> Vec<Self> {
        v.as_array()
            .map(|a| a.iter().filter_map(Self::from_json).collect())
            .unwrap_or_default()
    }
}

// ------------------------------------------------------------- slow reads

/// The slow pass's `l4.*` reads, in order (spec §1, §4): the L4 scope and
/// agent panels, then both status verbs every time (availability is never
/// cached for the session), then `l4.intercept.list` only while intercept is
/// available — a core whose intercept is unavailable is never asked for its
/// parked list. Only verbs the bus offers (`has`) are listed. The statuses
/// precede the list so a status read in one pass governs that pass's list.
pub fn slow_l4_reads(has: impl Fn(&str) -> bool, intercept_available: bool) -> Vec<&'static str> {
    const ALWAYS: [&str; 4] = [
        "l4.scope.list",
        "l4.agent.status",
        "l4.capture.status",
        "l4.intercept.status",
    ];
    let mut out: Vec<&'static str> = ALWAYS.into_iter().filter(|t| has(t)).collect();
    if intercept_available && has("l4.intercept.list") {
        out.push("l4.intercept.list");
    }
    out
}

/// Fold one status verb's outcome (spec §1): a reply through
/// [`L4Availability::from_reply`] and [`status_ids`] under `key` (`captures` /
/// `sessions`); a tool error through [`L4Availability::from_error`], or, when
/// it is not an `L4 unavailable: ` error, honestly unavailable with the error
/// text as the reason. An error lists no ids. A transport error never reaches
/// here: it ends the bus session.
pub fn fold_status(outcome: Result<&Value, &str>, key: &str) -> (L4Availability, Vec<String>) {
    match outcome {
        Ok(v) => (L4Availability::from_reply(v), status_ids(v, key)),
        Err(text) => (
            L4Availability::from_error(text).unwrap_or_else(|| L4Availability {
                available: false,
                code: None,
                reason: Some(text.to_string()),
            }),
            Vec::new(),
        ),
    }
}

// ------------------------------------------------------- tool-shaped args

fn tool<'a>(tools: &'a [ToolInfo], name: &str) -> Option<&'a ToolInfo> {
    tools.iter().find(|t| t.name == name)
}

/// Whether `l4.flow.get` declares the §2 `limit` window in its inputSchema
/// (an older core does not; the UI then omits it).
pub fn supports_window(tools: &[ToolInfo]) -> bool {
    tool(tools, "l4.flow.get").is_some_and(|t| {
        t.input_schema
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|p| p.contains_key("limit"))
    })
}

/// The list poll's `l4.flow.get` args: `{"id", "limit": 0}` with the window
/// (flow fields only), `{"id"}` against an older core.
pub fn flow_get_args(id: &str, window: bool) -> Value {
    if window {
        json!({"id": id, "limit": 0})
    } else {
        json!({"id": id})
    }
}

/// The inspector's `l4.flow.get` args: the first window of packets.
pub fn inspect_args(id: &str) -> Value {
    json!({"id": id, "offset": 0, "limit": INSPECT_LIMIT})
}

/// Spec §3 / AC39: the scope-add control exists only when `tools/list` offers
/// `l4.scope.add` with `confirmable: true` (a core with unit (a')).
pub fn supports_operator_scope_add(tools: &[ToolInfo]) -> bool {
    tool(tools, "l4.scope.add").is_some_and(|t| t.confirmable)
}

/// The usage line of `:scope add l4` (shown as the toast on a bad line and as
/// the scope panel's hint).
pub const SCOPE_ADD_L4_USAGE: &str =
    "usage: :scope add l4 <cidr> <ports> <iface> <inbound|outbound> <capture|inject|intercept>";

/// The `l4.scope.add` args of `:scope add l4 <cidr> <ports> <iface> <direction>
/// <capability>` (spec §3 / AC13): exactly five words, the direction and
/// capability from their closed vocabularies; everything else is `Err` with the
/// usage line. The strings go to the core verbatim: its `entry_from_params`
/// validates the CIDR, ports and interface name.
pub fn scope_add_args(words: &str) -> Result<Value, &'static str> {
    let w: Vec<&str> = words.split_whitespace().collect();
    let [cidr, ports, interface, direction, capability] = w[..] else {
        return Err(SCOPE_ADD_L4_USAGE);
    };
    if !matches!(direction, "inbound" | "outbound") {
        return Err(SCOPE_ADD_L4_USAGE);
    }
    if !matches!(capability, "capture" | "inject" | "intercept") {
        return Err(SCOPE_ADD_L4_USAGE);
    }
    Ok(json!({
        "cidr": cidr,
        "ports": ports,
        "interface": interface,
        "direction": direction,
        "capability": capability,
    }))
}

// ------------------------------------------------------------- packet text

/// The ASCII column of a hex view (spec §2.3 / AC40): printable ASCII
/// 0x20–0x7e as itself, every other byte as `.`, so no control byte reaches the
/// terminal.
pub fn ascii_column(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// A hex dump, 16 bytes per row: `<offset:08x>  <hex, space-separated>  <ascii>`.
/// Empty input → no rows.
pub fn hex_dump(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "{:08x}  {:<47}  {}",
                i * 16,
                hex.join(" "),
                ascii_column(chunk)
            )
        })
        .collect()
}

/// Epoch milliseconds (UTC, spec §2) as a `HH:MM:SS.mmm` clock, the same 12
/// cells HTTP rows get from `model::clock_of`. Pure arithmetic; no calendar.
pub fn clock_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let sod = secs.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60,
        millis
    )
}

/// One `addr:port` endpoint; an IPv6 address is bracketed; a missing port is
/// omitted.
fn endpoint(addr: &str, port: Option<u16>) -> String {
    let host = if addr.contains(':') {
        format!("[{addr}]")
    } else {
        addr.to_string()
    };
    match port {
        Some(p) => format!("{host}:{p}"),
        None => host,
    }
}

/// The §2 fields of a packet as `(label, value)` rows for the detail pane:
/// `time`, `proto`, `endpoints` (`src:port → dst:port`), `length`, `injected`.
/// A field the core did not send reads `—`. The values are the core's text and
/// are rendered through the inert path by the caller.
pub fn packet_fields(p: &L4Packet) -> Vec<(&'static str, String)> {
    let time = p.timestamp.map_or_else(|| "—".to_string(), clock_ms);
    let proto = p
        .proto
        .clone()
        .or_else(|| proto_of(&p.layers).map(str::to_string))
        .unwrap_or_else(|| "—".to_string());
    let endpoints = match (&p.src, &p.dst) {
        (Some(s), Some(d)) => format!("{} → {}", endpoint(s, p.src_port), endpoint(d, p.dst_port)),
        (Some(s), None) => format!("{} → ?", endpoint(s, p.src_port)),
        (None, Some(d)) => format!("? → {}", endpoint(d, p.dst_port)),
        (None, None) => "—".to_string(),
    };
    vec![
        ("time", time),
        ("proto", proto),
        ("endpoints", endpoints),
        ("length", format!("{} B", p.length)),
        (
            "injected",
            if p.injected { "yes" } else { "no" }.to_string(),
        ),
    ]
}

/// A packet's layer tree as an honest, **labelled** indented text tree
/// (ui-ext §3.2: a terminal cannot draw a graphical tree, so render it as text —
/// never drop it). Outermost layer first, each nested one a step deeper.
pub fn layer_tree_lines(layers: &[String]) -> Vec<String> {
    let mut lines = vec!["layer tree (text):".to_string()];
    if layers.is_empty() {
        lines.push("  (no decoded layers)".to_string());
        return lines;
    }
    for (depth, layer) in layers.iter().enumerate() {
        let indent = "  ".repeat(depth + 1);
        let branch = if depth == 0 { "" } else { "└ " };
        lines.push(format!("{indent}{branch}{layer}"));
    }
    lines
}

/// One `l4.scope.list` entry, keeping the fields the TUI shows and matches on
/// (the authoritative CIDR/port matching is the core's `L4Guard`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4ScopeEntry {
    /// The core's scope id (`l4.scope.remove` takes it); empty from a core
    /// that does not list ids.
    pub id: String,
    pub interface: String,
    /// `capture` | `inject` | `intercept`.
    pub capability: String,
    pub cidr: String,
    pub ports: String,
    pub direction: String,
    /// Provenance (unit (a) A5): `config` | `runtime`; empty from a core
    /// before it, shown as-is and never invented.
    pub source: String,
}

impl L4ScopeEntry {
    /// Parse one serialized `L4ScopeEntry`. `None` without an `interface`.
    pub fn from_json(v: &Value) -> Option<Self> {
        let interface = v.get("interface").and_then(Value::as_str)?.to_string();
        let text = |key: &str| {
            v.get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        // `l4.scope.list` serializes `cidr` and `ports` as STRINGS ("127.0.0.1/32",
        // "0-65535") — see `commands::scope_entry_to_value`. Read them as such (the
        // web + macOS surfaces do the same); collapse the port range to its display
        // form.
        let cidr = v
            .get("cidr")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let ports = v
            .get("ports")
            .and_then(Value::as_str)
            .map(|s| match s.split_once('-') {
                Some(("0", "65535")) => "any".to_string(),
                Some((lo, hi)) if lo == hi => lo.to_string(),
                _ => s.to_string(),
            })
            .unwrap_or_else(|| "any".to_string());
        Some(Self {
            id: text("id"),
            interface,
            capability: v
                .get("capability")
                .and_then(Value::as_str)
                .unwrap_or("capture")
                .to_string(),
            cidr,
            ports,
            direction: v
                .get("direction")
                .and_then(Value::as_str)
                .unwrap_or("outbound")
                .to_string(),
            source: text("source"),
        })
    }

    /// Whether this entry's interface covers `iface` (an empty / `any`
    /// interface covers all).
    pub fn covers_interface(&self, iface: &str) -> bool {
        self.interface.is_empty() || self.interface == "any" || self.interface == iface
    }

    /// A one-line display label for the scope panel.
    pub fn label(&self) -> String {
        format!(
            "{} {}:{} {} · {}",
            self.interface, self.cidr, self.ports, self.direction, self.capability
        )
    }
}

/// Which per-feature agent gate (`l4.agent.*`), one per L4 capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Gate {
    Capture,
    Inject,
    Intercept,
    Widen,
}

impl L4Gate {
    pub const ALL: [L4Gate; 4] = [
        L4Gate::Capture,
        L4Gate::Inject,
        L4Gate::Intercept,
        L4Gate::Widen,
    ];

    /// The wire `capability` word (`l4.agent.set {capability}`).
    pub fn wire(self) -> &'static str {
        match self {
            L4Gate::Capture => "capture",
            L4Gate::Inject => "inject",
            L4Gate::Intercept => "intercept",
            L4Gate::Widen => "widen",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            L4Gate::Capture => "Capture",
            L4Gate::Inject => "Inject",
            L4Gate::Intercept => "Intercept",
            L4Gate::Widen => "Widen",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            L4Gate::Capture => "the agent may start/stop L4 capture",
            L4Gate::Inject => "the agent may put crafted packets on the wire",
            L4Gate::Intercept => "the agent may park/forward/drop in-path packets",
            L4Gate::Widen => "the agent may widen L4 scope",
        }
    }
}

/// The four per-capability agent gate states (`l4.agent.status`). `present` is
/// false when the bus offers no `l4.agent.status`: the Agent view then shows the
/// toggles **read-only** with an honest note (foundation honest-gating rule;
/// L4OPS-AC11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct L4Gates {
    pub capture: bool,
    pub inject: bool,
    pub intercept: bool,
    pub widen: bool,
    pub present: bool,
}

impl L4Gates {
    /// Parse an `l4.agent.status` result (`{capture, inject, intercept, widen}`).
    pub fn from_json(v: &Value) -> Self {
        let b = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
        Self {
            capture: b("capture"),
            inject: b("inject"),
            intercept: b("intercept"),
            widen: b("widen"),
            present: true,
        }
    }

    pub fn get(self, gate: L4Gate) -> bool {
        match gate {
            L4Gate::Capture => self.capture,
            L4Gate::Inject => self.inject,
            L4Gate::Intercept => self.intercept,
            L4Gate::Widen => self.widen,
        }
    }
}

/// A pending inject confirm-over-the-wire handshake (M4 D4, L4OPS-AC10). The
/// first `l4.inject` (without `_confirm`) returns a `needs_confirmation` reply
/// whose `prompt` is the wire summary — destination, packet summary, count,
/// matched scope entry, minted permit budget. The overlay shows it; on confirm
/// the UI re-issues the identical call plus the reserved `_confirm` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4Confirm {
    /// The tool to re-issue (`l4.inject`, `l4.intercept.forward`, …).
    pub call: String,
    /// The original args, re-sent verbatim plus `_confirm`.
    pub args: Value,
    /// The wire summary the server built, shown to the operator.
    pub prompt: String,
    /// The single-use confirm token bound to the pending call.
    pub token: String,
}

impl L4Confirm {
    /// Build from the pending `(call, args)` and a `needs_confirmation` reply.
    /// `None` when the reply is not a confirmation handshake.
    pub fn from_reply(call: &str, args: &Value, reply: &Value) -> Option<Self> {
        if reply.get("status").and_then(Value::as_str) != Some("needs_confirmation") {
            return None;
        }
        Some(Self {
            call: call.to_string(),
            args: args.clone(),
            prompt: reply
                .get("prompt")
                .and_then(Value::as_str)
                .unwrap_or("Confirm this action?")
                .to_string(),
            token: reply
                .get("confirm_token")
                .and_then(Value::as_str)?
                .to_string(),
        })
    }

    /// The args to re-send on confirm: the originals plus the `_confirm` token.
    pub fn confirmed_args(&self) -> Value {
        let mut args = self.args.clone();
        if let Value::Object(map) = &mut args {
            map.insert("_confirm".to_string(), Value::String(self.token.clone()));
        }
        args
    }
}

/// The default `PacketSpec` the craft editor opens with: a loopback UDP probe,
/// valid for `l4.craft` (outermost layer first; `raw` is a byte list).
pub const DEFAULT_CRAFT_YAML: &str = "\
# A PacketSpec, outermost layer first. `l4.craft` builds it to on-wire bytes;
# `b` builds a hex preview, `s` injects it (guarded, confirm-over-the-wire).
layers:
  - ipv4:
      dst: 127.0.0.1
  - udp:
      dst_port: 7
  - raw: [112, 114, 111, 98, 101]
";

/// The inspector's YAML craft editor and its `build()` hex preview
/// (L4OPS-AC8). The Rhai craft path is deferred to the protocol-extensible seam
/// (a hook only, ui-ext §3.2); YAML is always available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CraftBuffer {
    /// The YAML `PacketSpec` source.
    pub lines: Vec<String>,
    /// The highlighted line in the editor.
    pub cursor_line: usize,
    /// The last `l4.craft` bytes, shown as hex.
    pub preview: Option<Vec<u8>>,
    /// The last `l4.craft` summary layers.
    pub preview_layers: Vec<String>,
    /// A parse / craft error, surfaced verbatim.
    pub error: Option<String>,
}

impl Default for CraftBuffer {
    fn default() -> Self {
        Self {
            lines: DEFAULT_CRAFT_YAML.lines().map(str::to_string).collect(),
            cursor_line: 0,
            preview: None,
            preview_layers: Vec::new(),
            error: None,
        }
    }
}

impl CraftBuffer {
    /// The YAML source as one string.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }
}

/// The L4 inspector's panes (ui-ext §3.2): the packet list + layer tree + hex,
/// the YAML craft editor, and the in-path intercept controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum L4Pane {
    #[default]
    Packets,
    Craft,
    Intercept,
}

impl L4Pane {
    pub const ALL: [L4Pane; 3] = [L4Pane::Packets, L4Pane::Craft, L4Pane::Intercept];

    pub fn label(self) -> &'static str {
        match self {
            L4Pane::Packets => "Packets",
            L4Pane::Craft => "Craft",
            L4Pane::Intercept => "Intercept",
        }
    }

    /// The next pane in the cycle (Tab).
    pub fn next(self) -> Self {
        match self {
            L4Pane::Packets => L4Pane::Craft,
            L4Pane::Craft => L4Pane::Intercept,
            L4Pane::Intercept => L4Pane::Packets,
        }
    }
}

/// All the L4 operator surface's state (`App::l4`). Plain data; `App::update`
/// folds it and `ui::l4` draws it.
#[derive(Debug, Clone, Default)]
pub struct L4State {
    /// Full L4 flows keyed by id (the list row lives in `App::flows`).
    pub flows: std::collections::HashMap<String, L4Flow>,
    /// The L4 scope entries (`l4.scope.list`).
    pub scope: Vec<L4ScopeEntry>,
    /// The per-feature agent gates (`l4.agent.status`).
    pub gates: L4Gates,
    /// The selected packet in the inspector's Packets pane.
    pub packet_cursor: usize,
    /// Which inspector pane is active.
    pub pane: L4Pane,
    /// The YAML craft editor + hex preview.
    pub craft: CraftBuffer,
    /// A pending inject (call, args) awaiting the `needs_confirmation` reply.
    pub pending: Option<(String, Value)>,
    /// The confirm-over-the-wire overlay, once the reply arrives.
    pub confirm: Option<L4Confirm>,
    /// `l4.capture.status` (capture + inject), re-read every slow poll (§1).
    pub capture: L4Availability,
    /// `l4.intercept.status`, re-read every slow poll (§1).
    pub intercept: L4Availability,
    /// The running capture flow ids (`l4.capture.status.captures`).
    pub captures: Vec<String>,
    /// `l4.intercept.list`, in the core's order (oldest first, §4).
    pub parked: Vec<L4Parked>,
}

impl L4State {
    /// The parked packet the intercept bar acts on for `flow`: the first
    /// listed, which the core orders oldest first (plan decision 3).
    pub fn parked_for(&self, flow: &str) -> Option<&L4Parked> {
        self.parked.iter().find(|p| p.flow == flow)
    }

    /// Whether an L4 flow is in scope: an `l4.scope.list` entry covers its
    /// interface (the courtesy signal; the guard is the enforcement, Part 5).
    /// With no scope at all, nothing is in scope (deny-by-default).
    pub fn in_scope(&self, flow: &L4Flow) -> bool {
        self.scope
            .iter()
            .any(|e| e.covers_interface(&flow.interface))
    }

    /// Whether the agent-inject gate specifically authorises injecting on
    /// `flow`'s interface (an `inject`-capability entry covering it).
    pub fn inject_in_scope(&self, flow: &L4Flow) -> bool {
        self.scope
            .iter()
            .any(|e| e.capability == "inject" && e.covers_interface(&flow.interface))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flow_parses_and_sublabels_its_transport() {
        let v = json!({
            "id": "l4-1", "kind": "capture", "interface": "lo0",
            "filter": "udp port 7", "packet_count": 2, "injected_count": 1,
            "packets": [
                {"dir": "outbound", "length": 33, "injected": true, "layers": ["IPv4","UDP","Raw"]},
                {"dir": "inbound", "length": 33, "injected": false, "layers": ["IPv4","UDP","Raw"]}
            ]
        });
        let f = L4Flow::from_json(&v).unwrap();
        assert_eq!(f.kind, "capture");
        assert_eq!(f.proto(), Some("UDP"));
        assert_eq!(f.packets.len(), 2);
        assert!(f.packets[0].injected);
        assert_eq!(f.packets[0].summary(), "IPv4 / UDP / Raw");
        assert_eq!(f.packets[0].arrow(), "→");
        assert!(f.target().contains("lo0"));
    }

    #[test]
    fn layer_tree_is_labelled_text_and_indented() {
        let lines = layer_tree_lines(&["IPv4".into(), "UDP".into(), "Raw".into()]);
        assert_eq!(lines[0], "layer tree (text):");
        assert!(lines[1].trim_end().ends_with("IPv4"));
        // Each layer is indented one step deeper than the last.
        let indent = |s: &str| s.len() - s.trim_start().len();
        assert!(indent(&lines[2]) > indent(&lines[1]));
        assert!(indent(&lines[3]) > indent(&lines[2]));
        assert_eq!(layer_tree_lines(&[])[1].trim(), "(no decoded layers)");
    }

    #[test]
    fn scope_covers_by_interface_and_gates_parse() {
        // Strings, exactly as `l4.scope.list` emits them over the real bus.
        let e = L4ScopeEntry::from_json(&json!({
            "interface": "lo0", "capability": "inject",
            "cidr": "127.0.0.0/8",
            "ports": "0-65535", "direction": "outbound"
        }))
        .unwrap();
        assert!(e.covers_interface("lo0"));
        assert!(!e.covers_interface("eth0"));
        assert_eq!(e.ports, "any");
        assert!(e.label().contains("127.0.0.0/8"));

        let g = L4Gates::from_json(
            &json!({"capture": true, "inject": false, "intercept": true, "widen": false}),
        );
        assert!(g.present);
        assert!(g.get(L4Gate::Capture));
        assert!(!g.get(L4Gate::Inject));
    }

    #[test]
    fn confirm_round_trip_adds_the_token() {
        let args = json!({"spec": {"layers": []}, "dst": "127.0.0.1", "port": 7});
        let reply = json!({"status": "needs_confirmation", "prompt": "Inject 1 UDP to 127.0.0.1:7?", "confirm_token": "tok-9"});
        let c = L4Confirm::from_reply("l4.inject", &args, &reply).unwrap();
        assert_eq!(c.token, "tok-9");
        assert_eq!(c.confirmed_args()["_confirm"], "tok-9");
        assert_eq!(c.confirmed_args()["dst"], "127.0.0.1");
        // A plain success is not a confirmation handshake.
        assert!(L4Confirm::from_reply("l4.inject", &args, &json!({"injected": 1})).is_none());
    }

    #[test]
    fn in_scope_needs_a_covering_entry() {
        let mut st = L4State::default();
        let flow =
            L4Flow::from_json(&json!({"id":"x","kind":"capture","interface":"lo0","packets":[]}))
                .unwrap();
        assert!(!st.in_scope(&flow), "deny-by-default with empty scope");
        st.scope.push(L4ScopeEntry {
            id: "S1".into(),
            interface: "lo0".into(),
            capability: "capture".into(),
            cidr: "127.0.0.0/8".into(),
            ports: "any".into(),
            direction: "outbound".into(),
            source: "config".into(),
        });
        assert!(st.in_scope(&flow));
        assert!(
            !st.inject_in_scope(&flow),
            "capture entry does not grant inject"
        );
    }
}
