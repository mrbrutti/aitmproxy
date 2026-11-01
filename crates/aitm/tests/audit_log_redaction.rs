//! The audit corpus: secret-bearing shapes through the real path to the files
//! (spec Design 14.7; AC52, AC55 to AC57, AC61 and the corpus half of AC47).
//!
//! The path is the production one and nothing in it is stubbed but the two
//! commands a call is made to: a real `McpServer` (built by `tui::server` and
//! `tui::with_shared_governance` over one `assemble`) takes a `tools/call` on an
//! agent connection with a minted connection id, `record_audit` makes the entry,
//! the shared `AuditRing` holds it, and the real writer, attached with the
//! production `aitm::audit_log::start_tuned` (a scratch directory,
//! `AuditLogSetting::Path`), writes it to the three files. A small size cap makes
//! the agent file rotate, so the run leaves numbered files, and every file whose
//! name starts with `audit` is read, the rotated ones included. No socket is
//! bound.
//!
//! Every row carries a made-up canary (`CNRY` + the row number as two digits +
//! `x` + eight hex digits, unique per row and per run), never a real credential.
//! The assertions collect: every offending row is listed in one failure message,
//! so one run names every leak. A rotated-away or lost file cannot hide a leak
//! because the number of entry lines over all the files must equal the number of
//! audited calls.
//!
//! Rows are numbered as the spec numbers them (AC55). R1 to R39, R50, R51, R53
//! and R54 are the first half of the corpus; R40 to R49 (the credential shapes),
//! R52 (a real `StdPocBuilder` build), R55 (a script source) and R56 to R74 (the
//! known tokens, the multi-secret strings) are the second. From R75 on are extra
//! rows the amended redaction rules name that AC55's 74 do not (bracket-notation
//! form keys, apostrophes in userinfo and in unquoted values, camelCase keys,
//! bracketed values under a secret key, Rust `Debug` wrappers, an error reason
//! echoing a shape, the header shapes of rule D); from R100 on the rows are
//! generated: every shape of rule P5 in four positions (bare in a note, in a kept
//! `Referer` header, in a URL query, in an error reason echoed back) and every
//! registered secret (the four configured tokens, the bridge token minted at run
//! time and the environment secret) in every position a secret can sit.
//!
//! Two kinds of row differ in what the *source* can know. A canary row carries a
//! value that a pass of the source recognises (a frame, a shape, a header name),
//! so the ring entry, the pushed line and the file must all be clean. A row built
//! with [`Row::secret`] carries a value that only the writer's registry knows (a
//! token under an innocuous key, in a `#t=` fragment, in a label, cut in half by
//! the cap): the ring and the pushed line still hold it, by design (the registry
//! is for the disk), the row says so with [`Row::in_ring`], and the test asserts
//! the ring still holds it, so a row cannot pass because a source pass took the
//! value out first. The secrets are the run's own tokens, shared by many rows, so
//! a leak is attributed to the row whose line holds it.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aitm::audit_log::{start, start_at, start_tuned, AuditLogHandle, Registration, Tuning};
use aitm::tui::{self, TuiLog};
use aitm::wire::{assemble_with_scripts, Assembled, Features, ScriptWiring};
use aitm_core::{
    origin_label, AgentPolicy, AuditEntry, AuditLogSetting, AuditResult, AuditRing, AuditSink,
    Body, Command, CommandHost, Config, ConnInfo, FlowId, FlowMeta, Frontend, HeaderMap, HttpFlow,
    HttpRequest, HttpResponse, HttpVersion, InterceptState, McpTransport, ParamDef, ParamSchema,
    Params, Plugin, Registry, Sensitivity, TypeDesc, Value as CoreValue, DEFAULT_ARGS_SUMMARY_CAP,
};
use aitm_mcp::redact_args::redact_value;
use aitm_mcp::{ConnCtx, McpServer, NotificationSink};
use aitm_poc::builder::{PocBuilder, PocSpec, StdPocBuilder};
use aitm_poc::{Assertion, PocInfo, Severity, Variable};
use serde_json::{json, Map, Value};

/// The most a shutdown is given to flush; every run asserts it finished.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);

/// The size at which every stream's file rotates in the corpus run: small enough
/// that the agent file (which holds every call) rotates, and large enough that
/// the retention (five rotated files) does not drop the oldest. The completeness
/// guard fails when this is wrong either way; change this number, never the guard.
///
/// 12 KiB held the 105 calls of the first half of the corpus; the second half and
/// the generated rows bring the run to over 300 calls, about 90 KB of lines, which
/// six files of 12 KiB cannot hold (the guard counted 261 lines for 313 calls), so
/// the cap is 24 KiB: three numbered files and the active one.
const CAP_BYTES: u64 = 24 * 1024;

/// The label the agent connection declares.
const AGENT_LABEL: &str = "corpus-agent";

/// The keys of an entry line, exactly (spec Design 6).
const ENTRY_KEYS: [&str; 7] = [
    "at",
    "origin",
    "client_label",
    "connection_id",
    "command",
    "args",
    "result",
];

// ----------------------------------------------------------------- the stubs

/// Every optional, `Any`-typed parameter `demo.accept` takes: the argument names
/// the commands under audit really use (header collections, rule S and D carriers,
/// a browser fill, PoC variables, free text), so rules S and D apply to the
/// shapes as they would to a real command. `row` is the row id the test puts
/// beside the shape, to join a file line to its ring entry.
const ACCEPT_PARAMS: [&str; 16] = [
    "headers", "pairs", "entries", "request", "edits", "selector", "text", "vars", "note", "raw",
    "body", "poc_text", "source", "url", "form", "row",
];

/// A `Write` command that accepts any of [`ACCEPT_PARAMS`] and answers `ok`, so
/// the audit entry carries exactly the arguments the call sent.
struct AcceptCmd;

impl Command for AcceptCmd {
    fn name(&self) -> &str {
        "demo.accept"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }
    fn schema(&self) -> ParamSchema {
        ParamSchema {
            description: "Accept anything.".into(),
            params: ACCEPT_PARAMS
                .iter()
                .map(|name| ParamDef {
                    name: (*name).into(),
                    ty: TypeDesc::Any,
                    required: false,
                    description: String::new(),
                })
                .collect(),
            result: TypeDesc::Str,
        }
    }
    fn invoke(&self, _args: Params, _host: &CommandHost) -> anyhow::Result<CoreValue> {
        Ok(CoreValue::Str("ok".into()))
    }
}

/// A `Write` command whose `invoke` always fails, quoting its `note`, so the
/// reason the audit entry keeps is what the caller sent.
struct FailCmd;

impl Command for FailCmd {
    fn name(&self) -> &str {
        "demo.fail"
    }
    fn sensitivity(&self) -> Sensitivity {
        Sensitivity::Write
    }
    fn schema(&self) -> ParamSchema {
        let param = |name: &str, ty: TypeDesc, required: bool| ParamDef {
            name: name.into(),
            ty,
            required,
            description: String::new(),
        };
        ParamSchema {
            description: "Fail quoting the note.".into(),
            params: vec![
                param("note", TypeDesc::Str, true),
                param("row", TypeDesc::Any, false),
            ],
            result: TypeDesc::Any,
        }
    }
    fn invoke(&self, args: Params, _host: &CommandHost) -> anyhow::Result<CoreValue> {
        let note = args.get_str("note")?;
        Err(anyhow::anyhow!("rejected: {note}"))
    }
}

/// The plugin that registers the two stubs.
struct DemoPlugin;

impl Plugin for DemoPlugin {
    fn name(&self) -> &str {
        "demo"
    }
    fn load(&mut self, reg: &mut Registry) {
        reg.add_command(Arc::new(AcceptCmd));
        reg.add_command(Arc::new(FailCmd));
    }
}

// ------------------------------------------------------------ small helpers

/// A unique scratch directory that removes itself on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aitm-audit-corpus-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create the scratch directory");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// splitmix64: a few well-spread bits from one.
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A seed that differs per run and per call of this function.
fn run_seed() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    mix(nanos ^ (u64::from(std::process::id()) << 32) ^ mix(n))
}

/// The canary of row `n`: `CNRY` + the row number as two digits + `x` + eight hex
/// digits, unique per row and, by the seed, per run.
fn canary(seed: u64, n: u32) -> String {
    canary_k(seed, n, 0)
}

/// The `k`-th canary of row `n`: the same format, a different value. A row that
/// carries several secrets in different frames gives each its own, so the failure
/// message names the frame that leaked. `canary_k(seed, n, 0)` is `canary(seed, n)`.
fn canary_k(seed: u64, n: u32, k: u32) -> String {
    let salt = u64::from(n) ^ (u64::from(k) << 40);
    format!("CNRY{n:02}x{:08x}", mix(seed ^ salt) & 0xffff_ffff)
}

/// `canary` repeated, hex digit by hex digit, up to `len` characters: the body of
/// a credential shape that needs a minimum length (a `ghp_` token is 36).
fn pad_to(canary: &str, len: usize) -> String {
    let filler: Vec<char> = canary.chars().filter(char::is_ascii_hexdigit).collect();
    let mut padded = canary.to_string();
    let mut next = filler.iter().cycle();
    while padded.len() < len {
        if let Some(c) = next.next() {
            padded.push(*c);
        }
    }
    padded
}

/// Standard base64 with padding (no new dependency).
fn b64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let byte = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        for i in 0..4usize {
            if i <= chunk.len() {
                let sextet = (n >> (18 - 6 * i)) & 63;
                out.push(char::from(ALPHABET[sextet as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Whether `haystack` holds `needle` as a byte string.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Whether any string in `value` (a leaf or an object key) contains `needle`.
fn value_holds(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(s) => s.contains(needle),
        Value::Array(items) => items.iter().any(|v| value_holds(v, needle)),
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| k.contains(needle) || value_holds(v, needle)),
        _ => false,
    }
}

/// `value` with every string leaf replaced by `""`: the paths of a JSON value.
fn blank_strings(value: &Value) -> Value {
    match value {
        Value::String(_) => Value::String(String::new()),
        Value::Array(items) => Value::Array(items.iter().map(blank_strings).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), blank_strings(v)))
                .collect::<Map<String, Value>>(),
        ),
        other => other.clone(),
    }
}

/// The first `width` characters of `text`, for a failure message.
fn clip(text: &str, width: usize) -> String {
    let head: String = text.chars().take(width).collect();
    if head.len() < text.len() {
        format!("{head}...")
    } else {
        head
    }
}

// ---------------------------------------------------------- tokens and the rig

/// The value of the environment secret `E`: long enough and unlike a switch or a
/// short digit run, so the writer's environment value rule registers it.
fn env_secret_value() -> String {
    format!("env-secret-{:016x}", mix(run_seed()))
}

/// The secrets the rig registers with the writer: the five tokens (each 64 hex
/// digits, `aitm::web::generate_token`) and an environment secret. The known-token
/// rows place them in every position a secret can sit.
struct Tokens {
    /// `T1`: the transport token (`LoopbackTcp`).
    transport: String,
    /// `T2`: `mcp.operator_token`.
    operator: String,
    /// `T3`: `mcp.agent_token`.
    agent: String,
    /// `T4`: the web agent bridge token, handed to `start`.
    web: String,
    /// `T5`: minted after the start with `generate_bridge_token`.
    bridge: String,
    /// `E`: the value of `ANTHROPIC_API_KEY` in the injected environment.
    env: String,
}

impl Tokens {
    /// Six secrets of the right shapes, registered nowhere: for a test that walks
    /// the rows without a writer.
    fn sample() -> Tokens {
        let token = aitm::web::generate_token;
        Tokens {
            transport: token(),
            operator: token(),
            agent: token(),
            web: token(),
            bridge: token(),
            env: env_secret_value(),
        }
    }

    /// `T1`, `T2`, `T3`, `T4`, `T5`, `E`, with the names the rows' labels use.
    fn named(&self) -> [(&'static str, &str); 6] {
        [
            ("T1", &self.transport),
            ("T2", &self.operator),
            ("T3", &self.agent),
            ("T4", &self.web),
            ("T5", &self.bridge),
            ("E", &self.env),
        ]
    }

    fn all(&self) -> [&str; 6] {
        [
            &self.transport,
            &self.operator,
            &self.agent,
            &self.web,
            &self.bridge,
            &self.env,
        ]
    }
}

/// One `assemble`, the stubs wired in as `main.rs` wires its command providers,
/// and the production writer attached to its audit ring.
struct Rig {
    cfg: Config,
    assembled: Assembled,
    handle: AuditLogHandle,
    /// The directory the three files (and every rotated one) are in.
    dir: PathBuf,
    tokens: Tokens,
    /// Declared last so it is removed after everything above is dropped.
    _scratch: Scratch,
}

impl Rig {
    fn start(tag: &str, tuning: Tuning) -> Rig {
        let scratch = Scratch::new(tag);
        let token = aitm::web::generate_token;
        let (transport, operator, agent, web) = (token(), token(), token(), token());
        let env_secret = env_secret_value();

        let mut cfg = Config::default();
        cfg.mcp.policy = AgentPolicy::Auto;
        cfg.mcp.transport = McpTransport::LoopbackTcp {
            port: 0,
            token: transport.clone(),
            endpoint_file: None,
        };
        cfg.mcp.operator_token = Some(operator.clone());
        cfg.mcp.agent_token = Some(agent.clone());
        cfg.ca.dir = scratch.0.join("ca");
        cfg.ca.audit_log = scratch.0.join("ca-audit.jsonl");
        let dir = scratch.0.join("audit");
        cfg.mcp.audit_log = AuditLogSetting::Path(dir.join("audit.jsonl"));

        let assembled = assemble_with_scripts(
            &cfg,
            &Features::default(),
            ScriptWiring {
                commands: vec![Box::new(DemoPlugin)],
                ..ScriptWiring::default()
            },
        )
        .expect("assemble");
        let env = vec![("ANTHROPIC_API_KEY".to_string(), env_secret.clone())];
        let handle = start_tuned(&cfg, &assembled.audit_ring, Some(&web), &env, tuning)
            .expect("the writer starts on a scratch directory")
            .expect("an explicit path starts the writer");
        let bridge = handle.generate_bridge_token();
        Rig {
            cfg,
            assembled,
            handle,
            dir,
            tokens: Tokens {
                transport,
                operator,
                agent,
                web,
                bridge,
                env: env_secret,
            },
            _scratch: scratch,
        }
    }

    /// A server built the way `main.rs` builds its primary and its `aitm web`
    /// server: `tui::server` plus `tui::with_shared_governance`.
    fn server(&self) -> McpServer {
        let services = tui::services(&self.assembled.proxy, &self.cfg, None, TuiLog::Off);
        tui::with_shared_governance(
            tui::server(&self.cfg, self.cfg.mcp.transport.clone(), &services),
            &self.assembled.agent_state,
            &self.assembled.audit_ring,
        )
    }

    /// What is wrong with the rig itself: a token that is not 64 hex digits or
    /// that the registry does not mask. A rig whose writer did not register its
    /// tokens would run the next task's rows against nothing.
    fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let registry = self.handle.registry();
        for (i, secret) in self.tokens.all().iter().enumerate() {
            if i < 5 && !(secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit())) {
                problems.push(format!("token {} is not 64 hex digits", i + 1));
            }
            let masked = registry.mask(&format!("a {secret} b"));
            if masked != "a [redacted] b" {
                problems.push(format!(
                    "the registry does not mask secret {} of the rig: {masked:?}",
                    i + 1
                ));
            }
        }
        if registry.len() != 6 {
            problems.push(format!(
                "the registry holds {} secrets, the rig registered 6",
                registry.len()
            ));
        }
        problems
    }
}

// ------------------------------------------------------------ one JSON-RPC call

fn rpc_line(method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string()
}

/// The parsed reply to one request on `conn`.
fn request_on(srv: &McpServer, conn: &ConnCtx, method: &str, params: Value) -> Value {
    let reply = srv
        .handle_on(conn, &rpc_line(method, params))
        .unwrap_or_else(|| panic!("a reply to {method}"));
    serde_json::from_str(&reply).expect("the reply is JSON")
}

/// `tools/call` of `name` with `arguments` on `conn`.
fn tool_call(srv: &McpServer, conn: &ConnCtx, name: &str, arguments: &Value) -> Value {
    request_on(
        srv,
        conn,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

fn is_error(reply: &Value) -> bool {
    reply["result"]["isError"] == json!(true)
}

/// A streaming connection as a transport builds it: a minted `conn_id`, so the
/// server names it in `initialize` and in every audit line it makes.
fn streaming(srv: &McpServer, role: Frontend, label: Option<&str>) -> ConnCtx {
    let mut conn = ConnCtx::new(role);
    conn.conn_id = srv.next_conn_id();
    conn.client_label = label.map(str::to_string);
    conn
}

// ---------------------------------------------------------------------- rows

/// How a row reaches the ring.
#[derive(Debug, PartialEq, Eq)]
enum Via {
    /// `tools/call demo.accept`: the call succeeds.
    Accept,
    /// `tools/call demo.fail`: the call fails, quoting `note` in its reason.
    Fail,
    /// A hand-built entry through `ring.append` carrying this `args` text: the
    /// writer is the last line for an entry from any caller of the ring hook.
    Append(String),
}

/// One row of the corpus or of the benign table.
struct Row {
    /// `R07` for a corpus row, `B03` and `H02` for the benign table.
    id: String,
    /// The shape, for a failure message.
    what: String,
    via: Via,
    /// The arguments of the call, an object (`Value::Null` for [`Via::Append`]).
    /// The row id is added beside them as `row`.
    args: Value,
    /// Byte strings that must appear in no file (the canary and each listed
    /// encoding); empty for a benign row.
    forbidden: Vec<String>,
    /// Whether the canary itself is in the input. A row whose secret is only
    /// there inside an encoding (a `Basic` credential) lists the encoding and
    /// sends no plain canary.
    canary_sent: bool,
    /// Forbidden strings the input does not hold literally: the JSON form of a
    /// secret, which exists only once the call has been rendered. They are
    /// exempt from the "the row really sends it" check.
    derived: Vec<String>,
    /// Plain words that must still be in the entry's `args` (a name the rules
    /// keep, the text around a masked value): a row whose `args` were wiped
    /// would otherwise pass.
    keep: Vec<String>,
    /// For a benign row: the path into the parsed `args` and the exact value that
    /// must be read back there.
    survives: Option<(Vec<String>, String)>,
    /// The label the connection of this call declares; `None` is the corpus
    /// agent's own.
    client_label: Option<String>,
    /// Secrets registered with the running writer (`register_secret`) just before
    /// this row's call, as the operator bridge token is: the registry holds them
    /// only from now on.
    registers: Vec<String>,
    /// The forbidden strings are one of the run's tokens, which many rows carry:
    /// a leak is attributed to the row whose own line holds it.
    shared: bool,
    /// What the row's entry line carries to be told from every other. The row id
    /// (`"row":"R07"`) unless the call is cut before it, as a long `note` is.
    marker: Option<String>,
    /// Strings the ring entry (its `args`, its reason or its label) must still
    /// hold: only the writer's registry can take them out of the file, so a row
    /// that lists one proves the registry did, not a pass of the source. The ring
    /// and the pushed line are not asserted clean of them.
    in_ring: Vec<String>,
    /// What the ring's `args` must end with (the source's cut and its marker).
    ring_ends: Option<String>,
    /// What the file's `args` must end with (the masked fragment and the marker):
    /// a leak that is only a leftover of the secret cannot hide before it.
    file_args_ends: Option<String>,
    /// What the file's `client_label` must be.
    file_label: Option<String>,
}

impl Row {
    fn new(n: u32, what: impl Into<String>, via: Via, args: Value, canary: &str) -> Row {
        Row {
            id: format!("R{n:02}"),
            what: what.into(),
            via,
            args,
            forbidden: vec![canary.to_string()],
            canary_sent: true,
            derived: Vec::new(),
            keep: Vec::new(),
            survives: None,
            client_label: None,
            registers: Vec::new(),
            shared: false,
            marker: None,
            in_ring: Vec::new(),
            ring_ends: None,
            file_args_ends: None,
            file_label: None,
        }
    }

    /// A row that carries one of the run's registered secrets (`secret`, in full).
    /// Besides the whole secret, its head is forbidden: a mask that took out only
    /// the end of it would leave the head, and the whole would not be found.
    fn secret(n: u32, what: impl Into<String>, via: Via, args: Value, secret: &str) -> Row {
        let mut row = Row::new(n, what, via, args, secret);
        row.forbidden.push(head_of(secret).to_string());
        row.shared = true;
        row
    }

    /// The canary is in the input only inside an encoding the row lists with
    /// [`Row::also`] (the plain canary is still asserted absent).
    fn encoded(mut self) -> Row {
        self.canary_sent = false;
        self
    }

    /// An encoding of the secret that must be absent too.
    fn also(mut self, encoding: &str) -> Row {
        self.forbidden.push(encoding.to_string());
        self
    }

    /// A form of the secret that exists only after rendering and must be absent
    /// too (it is not in the input).
    fn derived(mut self, form: &str) -> Row {
        self.forbidden.push(form.to_string());
        self.derived.push(form.to_string());
        self
    }

    /// A word the entry must still hold.
    fn keep(mut self, word: impl Into<String>) -> Row {
        self.keep.push(word.into());
        self
    }

    /// The call is made on a connection that declares `label`.
    fn label(mut self, label: &str) -> Row {
        self.client_label = Some(label.to_string());
        self
    }

    /// Register `secret` with the running writer just before the call.
    fn registers(mut self, secret: &str) -> Row {
        self.registers.push(secret.to_string());
        self
    }

    /// The entry line is told from the others by `marker`, not by the row id.
    fn marked(mut self, marker: &str) -> Row {
        self.marker = Some(marker.to_string());
        self
    }

    /// The ring must still hold `held` (see the `in_ring` field).
    fn in_ring(mut self, held: &str) -> Row {
        self.in_ring.push(held.to_string());
        self
    }

    /// Only the writer's registry can take this row's secret out: the ring holds
    /// every forbidden string, whole.
    fn registry_only(mut self) -> Row {
        self.in_ring = self.forbidden.clone();
        self
    }

    /// The forbidden strings are one of the run's secrets: a leak is attributed
    /// to the row whose line holds it.
    fn shared(mut self) -> Row {
        self.shared = true;
        self
    }

    /// Another registered secret in the same row: forbidden whole and by its head.
    fn and_secret(self, secret: &str) -> Row {
        self.also(secret).also(head_of(secret))
    }

    /// Another id than `R<n>`, for a row of a group that shares one number (the
    /// three calls of one PoC).
    fn with_id(mut self, id: &str) -> Row {
        self.id = id.to_string();
        self
    }

    /// The ring's `args` must end with `end`.
    fn ring_ends(mut self, end: &str) -> Row {
        self.ring_ends = Some(end.to_string());
        self
    }

    /// The file's `args` must end with `end`.
    fn file_ends(mut self, end: &str) -> Row {
        self.file_args_ends = Some(end.to_string());
        self
    }

    /// The file's `client_label` must be `label`.
    fn file_label(mut self, label: &str) -> Row {
        self.file_label = Some(label.to_string());
        self
    }

    /// A benign row: `value` sent at `path` inside `args` must come back as it
    /// was sent.
    fn benign(id: String, what: &str, args: Value, path: &[&str], value: &str) -> Row {
        let mut row = Row::new(0, what, Via::Accept, args, "");
        row.id = id;
        row.forbidden = Vec::new();
        row.canary_sent = false;
        row.survives = Some((
            path.iter().map(|part| (*part).to_string()).collect(),
            value.to_string(),
        ));
        row
    }

    /// The arguments as the call sends them: the shape and the row id.
    fn full_args(&self) -> Value {
        let mut args = self.args.clone();
        if let Value::Object(map) = &mut args {
            map.insert("row".into(), json!(self.id));
        }
        args
    }

    /// Whether the row really sends `needle` (a forbidden string no input holds
    /// proves nothing).
    fn sends(&self, needle: &str) -> bool {
        let in_label = self
            .client_label
            .as_deref()
            .is_some_and(|label| label.contains(needle));
        in_label
            || match &self.via {
                Via::Append(text) => text.contains(needle),
                Via::Accept | Via::Fail => value_holds(&self.args, needle),
            }
    }

    /// Whether the forbidden string `needle` has to be in the input.
    fn must_send(&self, position: usize, needle: &str) -> bool {
        !self.derived.iter().any(|d| d == needle) && (position > 0 || self.canary_sent)
    }

    /// The text that tells this row's entry line from every other, found in the
    /// line's `args`.
    fn marker_text(&self) -> String {
        match &self.marker {
            Some(marker) => marker.clone(),
            None => format!(r#""row":"{}""#, self.id),
        }
    }

    /// Whether the entry line whose decoded `args` is `args` is this row's.
    fn owns(&self, args: &str) -> bool {
        args.contains(&self.marker_text())
    }
}

/// The start of a registered secret that a forbidden check looks for as well as
/// the whole: 12 characters of a 64-hex token, 20 of the environment secret. It
/// is long enough not to occur by chance in a file and short enough that any
/// mask leaving more than a stub of the secret is found.
fn head_of(secret: &str) -> &str {
    let keep = if secret.starts_with("env-secret-") {
        20
    } else {
        12
    };
    secret.get(..keep.min(secret.len())).unwrap_or(secret)
}

/// The corpus: AC55's rows in the order the spec numbers them, the extra rows
/// from R75 on, then the generated ones from R100 on. Each canary is built by
/// [`canary`] from `seed`; the known-token rows carry the secrets of `tokens`,
/// which the rig has registered with the writer.
fn rows(seed: u64, tokens: &Tokens) -> Vec<Row> {
    let mut all = first_rows(seed);
    all.extend(shape_rows(seed));
    all.extend(tool_and_token_rows(seed, tokens));
    all.extend(generated_shape_rows(seed));
    all.extend(generated_token_rows(seed, tokens));
    all
}

/// R1 to R39, R50, R51, R53, R54 and R75 to R99.
fn first_rows(seed: u64) -> Vec<Row> {
    // The base64 encoder is test-local: pin it, or a row built on it would pass
    // for the wrong reason (an encoding that decodes to nothing is masked by no
    // pass and would never be found).
    assert_eq!(b64(b"user:pw"), "dXNlcjpwdw==");
    assert_eq!(b64(b"ab"), "YWI=");
    assert_eq!(b64(b"abc"), "YWJj");

    let c = |n: u32| canary(seed, n);
    let accept = |n: u32, what: &str, args: Value| Row::new(n, what, Via::Accept, args, &c(n));
    let fail = |n: u32, what: &str, args: Value| Row::new(n, what, Via::Fail, args, &c(n));
    // `user:C` as the base64 a `Basic` credential carries.
    let basic = |n: u32, user: &str| b64(format!("{user}:{}", c(n)).as_bytes());

    let b2 = basic(2, "user");
    let b3 = basic(3, "proxy");
    let b10 = basic(10, "user");
    let b38 = basic(38, "user");
    let ghp37 = format!("ghp_{}", pad_to(&c(37), 36));

    vec![
        // ---- headers, in every container shape
        accept(
            1,
            "headers map: Authorization: Bearer C",
            json!({"headers": {"Authorization": format!("Bearer {}", c(1))}}),
        )
        .keep("Authorization"),
        accept(
            2,
            "headers map: authorization: Basic <b64 of user:C>",
            json!({"headers": {"authorization": format!("Basic {b2}")}}),
        )
        .also(&b2)
        .encoded()
        .keep("authorization"),
        accept(
            3,
            "headers map: Proxy-Authorization: Basic <b64 of proxy:C>",
            json!({"headers": {"Proxy-Authorization": format!("Basic {b3}")}}),
        )
        .also(&b3)
        .encoded()
        .keep("Proxy-Authorization"),
        accept(
            4,
            "headers map: Cookie: a=1; b=2; session=C",
            json!({"headers": {"Cookie": format!("a=1; b=2; session={}", c(4))}}),
        )
        .keep("Cookie"),
        accept(
            5,
            "headers map: Set-Cookie: id=C; Path=/; HttpOnly",
            json!({"headers": {"Set-Cookie": format!("id={}; Path=/; HttpOnly", c(5))}}),
        )
        .keep("Set-Cookie"),
        accept(
            6,
            "headers map: X-Api-Key: C",
            json!({"headers": {"X-Api-Key": c(6)}}),
        )
        .keep("X-Api-Key"),
        accept(
            7,
            "headers map: X-Debug-Access: C (an innocuous name)",
            json!({"headers": {"X-Debug-Access": c(7)}}),
        )
        .keep("X-Debug-Access"),
        // R8 must stay (AC56 asserts it too): a routing header is the evidence.
        // The canary rides a second header of the map, an innocuous name.
        accept(
            8,
            "headers map: X-Forwarded-Host: evil.test stays, X-Trace: C goes",
            json!({"headers": {"X-Forwarded-Host": "evil.test", "X-Trace": c(8)}}),
        )
        .keep("X-Forwarded-Host")
        .keep("evil.test")
        .keep("X-Trace"),
        accept(
            9,
            "headers pairs: [Cookie, foo=C]",
            json!({"headers": [["Cookie", format!("foo={}", c(9))]]}),
        )
        .keep("Cookie"),
        accept(
            10,
            "headers pairs: [Authorization, Basic <b64 of user:C>]",
            json!({"headers": [["Authorization", format!("Basic {b10}")]]}),
        )
        .also(&b10)
        .encoded()
        .keep("Authorization"),
        accept(
            11,
            "headers pairs: [X-Custom, C]",
            json!({"headers": [["X-Custom", c(11)]]}),
        )
        .keep("X-Custom"),
        accept(
            12,
            "headers objects: {name: Cookie, value: C}",
            json!({"headers": [{"name": "Cookie", "value": c(12)}]}),
        )
        .keep("Cookie"),
        accept(
            13,
            "pairs objects (no header key): {name: Authorization, value: C}",
            json!({"pairs": [{"name": "Authorization", "value": c(13)}]}),
        )
        .keep("Authorization"),
        accept(
            14,
            "entries pairs (no header key): [Set-Cookie, C=1]",
            json!({"entries": [["Set-Cookie", format!("{}=1", c(14))]]}),
        )
        .keep("Set-Cookie"),
        accept(
            15,
            "request.meta.request_headers: {X-Zed: C}",
            json!({"request": {"meta": {"request_headers": {"X-Zed": c(15)}}}}),
        )
        .keep("request_headers")
        .keep("X-Zed"),
        accept(
            16,
            "request.meta.response_headers: {Set-Cookie: C=1}",
            json!({"request": {"meta": {"response_headers": {
                "Set-Cookie": format!("{}=1", c(16))
            }}}}),
        )
        .keep("response_headers")
        .keep("Set-Cookie"),
        accept(
            17,
            "edits.headers: {X-Evil: C}",
            json!({"edits": {"headers": {"X-Evil": c(17)}}}),
        )
        .keep("X-Evil"),
        // ---- header lines in free text
        accept(
            18,
            "raw CRLF block with Authorization: Bearer C",
            json!({"raw": format!(
                "GET / HTTP/1.1\r\nHost: h.test\r\nAuthorization: Bearer {}\r\nAccept: */*\r\n\r\n",
                c(18)
            )}),
        )
        .keep("Host: h.test")
        .keep("Authorization"),
        accept(
            19,
            "raw with Cookie: a=b; c=C; d=e",
            json!({"raw": format!(
                "GET / HTTP/1.1\r\nCookie: a=b; c={}; d=e\r\nHost: h.test\r\n\r\n",
                c(19)
            )}),
        )
        .keep("Host: h.test"),
        accept(
            20,
            "raw with a Set-Cookie: x=C; Path=/ line",
            json!({"raw": format!(
                "HTTP/1.1 200 OK\r\nSet-Cookie: x={}; Path=/\r\nContent-Length: 0\r\n\r\n",
                c(20)
            )}),
        )
        .keep("200 OK"),
        accept(
            21,
            "raw with Cookie: sid=\"C\" (a quoted value)",
            json!({"raw": format!(
                "GET / HTTP/1.1\r\nCookie: sid=\"{}\"\r\nHost: h.test\r\n\r\n",
                c(21)
            )}),
        )
        .keep("Host: h.test"),
        accept(
            22,
            "raw with Set-Cookie: JSESSIONID=\"C\"; Path=/",
            json!({"raw": format!(
                "HTTP/1.1 200 OK\r\nSet-Cookie: JSESSIONID=\"{}\"; Path=/\r\n\r\n",
                c(22)
            )}),
        )
        .keep("200 OK"),
        accept(
            23,
            "raw with Authorization: Digest username=\"u\", response=\"C\"",
            json!({"raw": format!(
                "GET / HTTP/1.1\r\nAuthorization: Digest username=\"u\", response=\"{}\"\r\n\r\n",
                c(23)
            )}),
        )
        .keep("GET /"),
        accept(
            24,
            "raw ending in a header line, no line end after it",
            json!({"raw": format!("GET / HTTP/1.1\r\nHost: h.test\r\nCookie: a=b; z={}", c(24))}),
        )
        .keep("Host: h.test"),
        // R25: a hand-built entry whose `args` is unparseable (the cap cut it),
        // carrying the escaped line breaks of a header block. The source never
        // saw it; the writer's tolerant scan is the only thing between it and
        // the file.
        Row::new(
            25,
            "hand-built entry, cut args with an escaped \\r\\nCookie: a=b; z=C\\r\\n",
            Via::Append(format!(
                r#"{{"row":"R25","note":"GET /\r\nCookie: a=b; z={}\r\nHo…"#,
                c(25)
            )),
            Value::Null,
            &c(25),
        )
        .keep("GET /"),
        accept(
            26,
            "raw with Proxy-Authorization: Basic C",
            json!({"raw": format!(
                "CONNECT h.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
                c(26)
            )}),
        )
        .keep("CONNECT"),
        accept(
            27,
            "prose, then Cookie: a=b; z=C on one line",
            json!({"note": format!("the proxy log shows Cookie: a=b; z={} and then stops", c(27))}),
        )
        .keep("the proxy log shows"),
        // ---- bodies and URLs
        accept(
            28,
            "body JSON string with escaped quotes {\"user\":\"u\",\"password\":\"C\"}",
            json!({"body": format!(r#"{{"user":"u","password":"{}"}}"#, c(28))}),
        )
        .keep("user"),
        accept(
            29,
            "body JSON string {\"login\":\"u\",\"pass\":\"C\"}",
            json!({"body": format!(r#"{{"login":"u","pass":"{}"}}"#, c(29))}),
        )
        .keep("login"),
        accept(
            30,
            "body JSON string {\"u\":\"x\",\"pw\":\"C\"}",
            json!({"body": format!(r#"{{"u":"x","pw":"{}"}}"#, c(30))}),
        )
        .keep("pw"),
        accept(
            31,
            "form user=u&passphrase=C",
            json!({"form": format!("user=u&passphrase={}", c(31))}),
        )
        .keep("user=u"),
        accept(
            32,
            "form private_key=C&x=1",
            json!({"form": format!("private_key={}&x=1", c(32))}),
        )
        .keep("x=1"),
        accept(
            33,
            "form access_key=C",
            json!({"form": format!("access_key={}", c(33))}),
        )
        .keep("access_key"),
        accept(
            34,
            "URL query ?access_token=C&page=2",
            json!({"url": format!("https://x.test/cb?access_token={}&page=2", c(34))}),
        )
        .keep("page=2"),
        accept(
            35,
            "URL query ?api_key=C",
            json!({"url": format!("https://x.test/cb?api_key={}", c(35))}),
        )
        .keep("x.test"),
        accept(
            36,
            "URL userinfo https://user:C@host.test/p",
            json!({"url": format!("https://user:{}@host.test/p", c(36))}),
        )
        .keep("host.test"),
        accept(
            37,
            "URL userinfo with no colon: https://<ghp_ shape C>@github.com/",
            json!({"url": format!("https://{ghp37}@github.com/")}),
        )
        .also(&ghp37)
        .keep("github.com"),
        accept(
            38,
            "Basic <b64 of user:C> outside any header",
            json!({"note": format!("replayed the login with Basic {b38} against the form")}),
        )
        .also(&b38)
        .encoded()
        .keep("replayed the login"),
        accept(
            39,
            "otp=C and totp: C, mid-line",
            json!({"note": format!("code x otp={} then y totp: {} done", c(39), c(39))}),
        )
        .keep("otp"),
        // ---- tools
        accept(
            50,
            "poc.run-shaped vars {admin_pass: C}",
            json!({"vars": {"admin_pass": c(50), "target": "http://t.test", "user": "admin"}}),
        )
        .keep("admin_pass")
        .keep("http://t.test"),
        accept(
            51,
            "poc.run-shaped vars {pw: C}",
            json!({"vars": {"pw": c(51), "target": "http://t.test"}}),
        )
        .keep("pw")
        .keep("http://t.test"),
        accept(
            53,
            "browser fill {selector: #password, text: C}",
            json!({"selector": "#password", "text": c(53)}),
        )
        .keep("#password"),
        accept(
            54,
            "browser fill {selector: input[name=api_token], text: C}",
            json!({"selector": "input[name=api_token]", "text": c(54)}),
        )
        .keep("api_token"),
        // ---- extra rows (R75 on): the shapes the amended rules read
        accept(
            75,
            "form with a bracket-notation key: user[password]=C",
            json!({"form": format!("user[password]={}&remember=1", c(75))}),
        )
        .keep("remember=1"),
        accept(
            76,
            "form with an empty-bracket key: password[]=C",
            json!({"form": format!("x=1&password[]={}", c(76))}),
        )
        .keep("x=1"),
        accept(
            77,
            "URL userinfo with apostrophes in the user and the password",
            json!({"url": format!("https://o'brien:O'{}@host.test/p", c(77))}),
        )
        .keep("host.test"),
        accept(
            78,
            "a quote inside an unquoted value: password=O'C&remember=1",
            json!({"note": format!("login ok password=O'{}&remember=1", c(78))}),
        )
        .keep("login ok"),
        accept(
            79,
            "camelCase key in vars: userPass",
            json!({"vars": {"userPass": c(79), "target": "http://t.test"}}),
        )
        .keep("userPass")
        .keep("http://t.test"),
        accept(
            80,
            "camelCase keys in text: adminPw=C and sessionKey: C",
            json!({"note": format!("set adminPw={} and sessionKey: {} then go", c(80), c(80))}),
        )
        .keep("set "),
        accept(
            81,
            "a bracketed value under a secret key: \"tokens\":[\"C\"]",
            json!({"note": format!(r#"state {{"tokens":["{}"],"n":1}} end"#, c(81))}),
        )
        .keep("state "),
        accept(
            82,
            "Rust Debug of a secret key in a note: Object({\"password\": Str(\"C\")})",
            json!({"note": format!(r#"got Object({{"password": Str("{}")}})"#, c(82))}),
        )
        .keep("got "),
        fail(
            83,
            "reason echoing Rust Debug: Object({\"password\": Str(\"C\")})",
            json!({"note": format!(r#"bad request Object({{"password": Str("{}")}})"#, c(83))}),
        )
        .keep("bad request"),
        fail(
            84,
            "reason echoing a header line: Cookie: a=b; z=C",
            json!({"note": format!("bad header Cookie: a=b; z={} at line 3", c(84))}),
        )
        .keep("bad header"),
        fail(
            85,
            "reason echoing a bracket-notation form key",
            json!({"note": format!("rejected form user[password]={}&x=1", c(85))}),
        )
        .keep("rejected form"),
        fail(
            86,
            "reason echoing URL userinfo",
            json!({"note": format!("cannot reach https://user:{}@host.test/p", c(86))}),
        )
        .keep("cannot reach"),
        fail(
            87,
            "reason echoing a JSON body",
            json!({"note": format!(r#"bad body {{"user":"u","password":"{}"}}"#, c(87))}),
        )
        .keep("bad body"),
        accept(
            88,
            "XML element named by a secret key: <password>C</password>",
            json!({"note": format!("<form><password>{}</password></form>", c(88))}),
        )
        .keep("<form>"),
        accept(
            89,
            "curl -u user:C",
            json!({"note": format!("curl -u user:{} https://x.test/ done", c(89))}),
        )
        .keep("https://x.test/"),
        accept(
            90,
            "a command-line flag: --password C",
            json!({"note": format!("curl --password {} https://x.test/ done", c(90))}),
        )
        .keep("https://x.test/"),
        accept(
            91,
            "a body string with literal escaped quotes (one backslash level)",
            json!({"body": format!(r#"{{\"user\":\"u\",\"password\":\"{}\"}}"#, c(91))}),
        )
        .keep("user"),
        accept(
            92,
            "raw with a folded Cookie header line",
            json!({"raw": format!(
                "GET / HTTP/1.1\r\nCookie: a=b;\r\n z={}\r\nHost: h.test\r\n\r\n",
                c(92)
            )}),
        )
        .keep("Host: h.test"),
        accept(
            93,
            "request.hdrs: {X-Zed: C}",
            json!({"request": {"hdrs": {"X-Zed": c(93)}}}),
        )
        .keep("hdrs")
        .keep("X-Zed"),
        accept(
            94,
            "edits.extra_headers pairs: [X-Debug, C]",
            json!({"edits": {"extra_headers": [["X-Debug", c(94)]]}}),
        )
        .keep("extra_headers")
        .keep("X-Debug"),
        accept(
            95,
            "headers as header text with line breaks",
            json!({"headers": format!("X-Debug: {}\r\nAccept: text/html", c(95))}),
        )
        .keep("Accept: text/html"),
        accept(
            96,
            "header_name beside header_value",
            json!({"request": {"header_name": "X-Debug", "header_value": c(96)}}),
        )
        .keep("X-Debug"),
        accept(
            97,
            "kept header Referer carrying ?token=C",
            json!({"headers": {"Referer": format!("https://x.test/cb?token={}", c(97))}}),
        )
        .keep("Referer")
        .keep("https://x.test/cb"),
        accept(
            98,
            "headers map: Sec-WebSocket-Protocol with a bearer subprotocol",
            json!({"headers": {
                "Sec-WebSocket-Protocol":
                    format!("base64url.bearer.authorization.k8s.io.{}", c(98))
            }}),
        )
        .keep("Sec-WebSocket-Protocol"),
        accept(
            99,
            "a list under a secret key in vars: {password: [x, C]}",
            json!({"vars": {"password": ["x", c(99)], "target": "http://t.test"}}),
        )
        .keep("password")
        .keep("http://t.test"),
    ]
}

/// Benign values sent as `note` (AC56): AC44's two lists first, then values a PoC
/// or a scope carries. Each must come back byte for byte.
const BENIGN_NOTES: &[(&str, &str)] = &[
    ("a flow id", "0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c"),
    ("a task id", "task-0f8fad5b-d9cb-469f-a165-9b4f5e5a1d3c"),
    (
        "a 64-hex hash",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ),
    (
        "a 64-hex digest",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ),
    ("a host and port", "auth.example.com:8443"),
    ("a hostname", "build-07.corp.example.test"),
    ("an ordinary URL", "https://example.test/a/b?x=1&y=two#frag"),
    ("an ssh URL with a user", "ssh://git@github.com/o/r"),
    ("an scp-style remote", "git@github.com:o/r.git"),
    ("the word basic in prose", "basic information"),
    (
        "the Cookie header in prose",
        "the Cookie header is described in RFC 6265",
    ),
    ("a short sk- slug", "sk-prod-eu-1.example.test"),
    (
        "keys that only look like secret keys",
        "author=bob&authority=example.com&inside=1&bypass=1&passed=true",
    ),
    ("ordinary JSON text", r#"{"a":1,"b":[true,null],"c":"d"}"#),
    ("an Accept line", "Accept: text/html"),
    ("an X-Forwarded-For line", "X-Forwarded-For: 203.0.113.9"),
    ("the AKIA prefix alone", "AKIA"),
    ("a short AKIA word", "AKIAFOO"),
    ("a short ghp_ word", "ghp_short"),
    ("the JWT prefix alone", "eyJ"),
    (
        "PoC placeholders in a URL",
        "{{target}}/login?user={{user}}",
    ),
    (
        "PoC placeholders in a path",
        "{{base_url}}/api/{{version}}/items?id={{id}}",
    ),
    ("an XML element named author", "<author>bob</author>"),
    ("a flag named passed", "--passed ok"),
    (
        "a host and port in a query value",
        "redirect=auth.example.com:8443&x=1",
    ),
    ("an ordinary sentence", "the login page redirects to /home"),
    ("an IPv4 and a port", "203.0.113.9:8080"),
    ("a path with a colon", "/api/v1/items/42:archive?mode=full"),
];

/// Benign header values (AC56), each sent in a `headers` map of its own.
const BENIGN_HEADERS: &[(&str, &str)] = &[
    ("Accept", "text/html"),
    ("Content-Type", "application/json"),
    ("Host", "h.test"),
    ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)"),
    ("X-Forwarded-For", "203.0.113.9"),
    ("X-Forwarded-Host", "evil.test"),
    ("Referer", "https://x.test/a?x=1"),
    ("Sec-Fetch-Mode", "cors"),
    ("Accept-Language", "en-US,en;q=0.9"),
];

/// The benign table (AC56) as rows: `B01`.. for the notes, `H01`.. for the headers.
fn benign_rows() -> Vec<Row> {
    let mut rows = Vec::new();
    for (i, (what, value)) in BENIGN_NOTES.iter().enumerate() {
        rows.push(Row::benign(
            format!("B{:02}", i + 1),
            what,
            json!({ "note": value }),
            &["note"],
            value,
        ));
    }
    for (i, (name, value)) in BENIGN_HEADERS.iter().enumerate() {
        let mut headers = Map::new();
        headers.insert((*name).to_string(), json!(value));
        rows.push(Row::benign(
            format!("H{:02}", i + 1),
            "a benign header value",
            json!({ "headers": headers }),
            &["headers", name],
            value,
        ));
    }
    rows
}

/// The corpus and the benign table, in the order they are called.
fn all_rows(seed: u64, tokens: &Tokens) -> Vec<Row> {
    let mut all = rows(seed, tokens);
    all.extend(benign_rows());
    all
}

/// The first number of the generated shape rows.
const SHAPE_ROW_BASE: u32 = 100;

/// The first number of the known-token matrix.
const TOKEN_ROW_BASE: u32 = 300;

/// How a credential shape is built around a canary: the recipes of AC55, with
/// the canary inside the body of the shape.
#[derive(Clone, Copy)]
enum Family {
    /// `eyJhbGciOiJIUzI1NiJ9.eyJ` + C + `.` + C.
    Jwt,
    /// A compact JWE: a header and four segments, each with a canary of its own.
    Jwe,
    /// A PEM private key block with this label, C at the head of its body line.
    Pem(&'static str),
    /// A four-letter AWS prefix and C, upper-cased, padded to 16 characters.
    Aws(&'static str),
    /// A prefix and C padded to this many characters.
    Padded(&'static str, usize),
    /// A Slack prefix, `123456789012-` and C.
    Slack(&'static str),
}

/// Every shape of P5, the name a failure message uses, and the row of AC55 that
/// holds it bare in a note (the others are generated).
const SHAPES: &[(&str, Option<u32>, Family)] = &[
    ("JWT", Some(40), Family::Jwt),
    ("PEM private key", Some(41), Family::Pem("PRIVATE KEY")),
    ("AWS access key id AKIA", Some(42), Family::Aws("AKIA")),
    ("GitHub ghp_", Some(43), Family::Padded("ghp_", 36)),
    (
        "GitHub github_pat_",
        Some(44),
        Family::Padded("github_pat_", 22),
    ),
    ("GitLab glpat-", Some(45), Family::Padded("glpat-", 20)),
    ("Slack xoxb-", Some(46), Family::Slack("xoxb-")),
    ("Stripe sk_live_", Some(47), Family::Padded("sk_live_", 16)),
    ("sk- API key", Some(48), Family::Padded("sk-", 32)),
    ("Google AIza", Some(49), Family::Padded("AIza", 35)),
    ("GitHub gho_", None, Family::Padded("gho_", 36)),
    ("GitHub ghu_", None, Family::Padded("ghu_", 36)),
    ("GitHub ghs_", None, Family::Padded("ghs_", 36)),
    ("GitHub ghr_", None, Family::Padded("ghr_", 36)),
    ("Slack xoxa-", None, Family::Slack("xoxa-")),
    ("Slack xoxp-", None, Family::Slack("xoxp-")),
    ("Slack xoxr-", None, Family::Slack("xoxr-")),
    ("Slack xoxs-", None, Family::Slack("xoxs-")),
    ("Stripe rk_live_", None, Family::Padded("rk_live_", 16)),
    ("AWS session key id ASIA", None, Family::Aws("ASIA")),
    ("compact JWE", None, Family::Jwe),
    ("PEM RSA private key", None, Family::Pem("RSA PRIVATE KEY")),
];

/// A credential shape built around its canaries.
struct Built {
    /// The shape as it is written in text.
    text: String,
    /// The canaries inside it: what must be in no file.
    secrets: Vec<String>,
}

fn build_shape(family: Family, seed: u64, n: u32) -> Built {
    let c = |k: u32| canary_k(seed, n, k);
    match family {
        Family::Jwt => Built {
            text: format!("eyJhbGciOiJIUzI1NiJ9.eyJ{}.{}", c(0), c(0)),
            secrets: vec![c(0)],
        },
        Family::Jwe => Built {
            text: format!(
                "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIn0.{}.{}.{}.{}",
                c(0),
                c(1),
                c(2),
                c(3)
            ),
            secrets: (0..4).map(c).collect(),
        },
        Family::Pem(label) => Built {
            text: format!(
                "-----BEGIN {label}-----\n{}\n-----END {label}-----",
                pad_to(&c(0), 64)
            ),
            secrets: vec![c(0)],
        },
        Family::Aws(prefix) => {
            let upper = c(0).to_uppercase();
            Built {
                text: format!("{prefix}{}", pad_to(&upper, 16)),
                secrets: vec![upper],
            }
        }
        Family::Padded(prefix, len) => Built {
            text: format!("{prefix}{}", pad_to(&c(0), len)),
            secrets: vec![c(0)],
        },
        Family::Slack(prefix) => Built {
            text: format!("{prefix}123456789012-{}", c(0)),
            secrets: vec![c(0)],
        },
    }
}

/// Where a shape sits in a call.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    /// Bare in a free-text note.
    Note,
    /// In the value of a header the source keeps (`Referer`): only the shape
    /// pass can find it there.
    Header,
    /// In the value of an innocuous query key.
    Url,
    /// In the note of a call that fails, so that the reason echoes it back.
    Reason,
}

impl Position {
    fn label(self) -> &'static str {
        match self {
            Position::Note => "bare in a note",
            Position::Header => "in a Referer header value",
            Position::Url => "in a URL query value",
            Position::Reason => "in an error reason echoed back",
        }
    }
}

/// One shape row: `built` at `position`, every canary of it forbidden, and the
/// words around it kept.
fn shape_row(n: u32, name: &str, built: &Built, position: Position) -> Row {
    let text = &built.text;
    let (via, args, keep): (Via, Value, &[&str]) = match position {
        Position::Note => (
            Via::Accept,
            json!({"note": format!("the response leaked {text} in the body")}),
            &["the response leaked", "in the body"],
        ),
        Position::Header => (
            Via::Accept,
            json!({"headers": {"Referer": format!("https://x.test/cb/{text}")}}),
            &["Referer", "https://x.test/cb/"],
        ),
        Position::Url => (
            Via::Accept,
            json!({"url": format!("https://x.test/cb?ref={text}&page=2")}),
            &["page=2"],
        ),
        Position::Reason => (
            Via::Fail,
            json!({"note": format!("upstream refused {text} as invalid")}),
            &["upstream refused"],
        ),
    };
    let mut row = Row::new(
        n,
        format!("{name} shape {}", position.label()),
        via,
        args,
        &built.secrets[0],
    );
    for more in &built.secrets[1..] {
        row = row.also(more);
    }
    for word in keep {
        row = row.keep(*word);
    }
    row
}

/// R40 to R49: the ten shapes of AC55, each bare in a note.
fn shape_rows(seed: u64) -> Vec<Row> {
    SHAPES
        .iter()
        .filter_map(|(name, principal, family)| {
            let n = (*principal)?;
            Some(shape_row(
                n,
                name,
                &build_shape(*family, seed, n),
                Position::Note,
            ))
        })
        .collect()
}

/// Every shape of P5 in the positions the numbered rows leave out: bare in a
/// note (for the shapes AC55 numbers none for), in a kept header's value, in a
/// URL query and in an error reason. A PEM block is not put in a URL: nothing
/// writes one there but percent-encoded, which no pass reads.
fn generated_shape_rows(seed: u64) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut n = SHAPE_ROW_BASE;
    for (name, principal, family) in SHAPES {
        let mut positions = vec![Position::Header, Position::Url, Position::Reason];
        if principal.is_none() {
            positions.insert(0, Position::Note);
        }
        for position in positions {
            if position == Position::Url && matches!(family, Family::Pem(_)) {
                continue;
            }
            rows.push(shape_row(n, name, &build_shape(*family, seed, n), position));
            n += 1;
        }
    }
    assert!(
        n < TOKEN_ROW_BASE,
        "the generated shape rows overran the token rows' numbers: {n}"
    );
    rows
}

/// R52, R55 and R56 to R74.
fn tool_and_token_rows(seed: u64, tokens: &Tokens) -> Vec<Row> {
    let c = |n: u32| canary(seed, n);
    let ck = |n: u32, k: u32| canary_k(seed, n, k);
    let [(_, t1), (_, t2), (_, t3), (_, t4), (_, t5), (_, env)] = tokens.named();

    // R52: a real build's YAML (and the two calls around it), see `poc_rows`.
    let mut rows = poc_rows(seed, 52);

    // R55: a script `source` with a constant named for a password and a Stripe key.
    let (password, stripe) = (ck(55, 0), ck(55, 1));
    rows.push(
        Row::new(
            55,
            "a script source: const PASSWORD = \"C\"; and a sk_live_ shape",
            Via::Accept,
            json!({"source": format!(
                "const PASSWORD = \"{password}\";\nconst STRIPE = \"sk_live_{}\";\nfn main() {{ call(STRIPE) }}",
                pad_to(&stripe, 16)
            )}),
            &password,
        )
        .also(&stripe)
        .keep("fn main"),
    );

    // R56 to R60: T1 to T5, bare under `note`. Nothing in the source knows them
    // (a 64-hex string is no frame and no shape), so only the registry takes
    // them out of the file, and the ring still holds them.
    for (i, (name, secret)) in [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5)]
        .into_iter()
        .enumerate()
    {
        rows.push(
            Row::secret(
                56 + i as u32,
                format!("{name} bare under note"),
                Via::Accept,
                json!({"note": format!("session established with {secret} for the run")}),
                secret,
            )
            .registry_only()
            .keep("session established with")
            .keep("for the run"),
        );
    }
    // R61 to R65: T1 to T5 as the `#t=` fragment of the operator link.
    for (i, (name, secret)) in [("T1", t1), ("T2", t2), ("T3", t3), ("T4", t4), ("T5", t5)]
        .into_iter()
        .enumerate()
    {
        rows.push(
            Row::secret(
                61 + i as u32,
                format!("{name} as http://127.0.0.1:8082/#t=<T>"),
                Via::Accept,
                json!({"url": format!("http://127.0.0.1:8082/#t={secret}")}),
                secret,
            )
            .registry_only()
            .keep("http://127.0.0.1:8082/#t="),
        );
    }
    // R66: T1 as a `Referer` value. The name is a benign one, so the source keeps
    // the value: only the registry catches it.
    rows.push(
        Row::secret(
            66,
            "T1 as a Referer header value (a benign name)",
            Via::Accept,
            json!({"headers": {"Referer": format!("http://127.0.0.1:8082/#t={t1}")}}),
            t1,
        )
        .registry_only()
        .keep("Referer")
        .keep("http://127.0.0.1:8082/#t="),
    );
    // R67: a token with `+/=` in it, registered while the writer runs, in its raw,
    // upper-case and lower-case percent-encoded forms.
    let raw67 = format!("{}+/=Zk9q", c(67));
    let upper67 = format!("{}%2B%2F%3DZk9q", c(67));
    let lower67 = format!("{}%2b%2f%3dZk9q", c(67));
    rows.push(
        Row::new(
            67,
            "a token with +/= (registered at run time): raw, upper-case and lower-case percent forms",
            Via::Accept,
            json!({"note": format!("raw {raw67} upper {upper67} lower {lower67} end")}),
            &c(67),
        )
        .registers(&raw67)
        .also(&raw67)
        .also(&upper67)
        .also(&lower67)
        .registry_only()
        .keep("raw ")
        .keep(" end"),
    );
    // R68: a token with `"` and `\` in it, registered while the writer runs. The
    // call fails quoting it, so the reason holds the raw form (plain text) and the
    // `args` text holds the JSON form (inside a JSON string), and the file line
    // holds that JSON form escaped once more.
    let raw68 = format!("{}\"q\\z9", c(68));
    let json68 = format!("{}\\\"q\\\\z9", c(68));
    let twice68 = format!("{}\\\\\\\"q\\\\\\\\z9", c(68));
    rows.push(
        Row::new(
            68,
            "a token with a quote and a backslash (registered at run time): raw and JSON forms",
            Via::Fail,
            json!({"note": format!("bad token {raw68} refused")}),
            &c(68),
        )
        .registers(&raw68)
        .also(&raw68)
        .derived(&json68)
        .derived(&twice68)
        .in_ring(&c(68))
        .in_ring(&raw68)
        .in_ring(&json68)
        .in_ring(&twice68)
        .keep("bad token")
        .keep("refused"),
    );
    // R69: T2 quoted in the reason of a failing call.
    rows.push(
        Row::secret(
            69,
            "T2 quoted in the reason of demo.fail",
            Via::Fail,
            json!({"note": format!("token \"{t2}\" was refused")}),
            t2,
        )
        .registry_only()
        .keep("was refused"),
    );
    // R70: T3 as the label the connection declares.
    rows.push(
        Row::secret(
            70,
            "T3 as the declared client label",
            Via::Accept,
            json!({}),
            t3,
        )
        .label(t3)
        .registry_only()
        .file_label("[redacted]"),
    );
    // R71: T4 straddling the 512-byte cap.
    rows.push(cap_row(71, "T4", t4, 20, &c(71)));
    // R72: the environment secret, bare.
    rows.push(
        Row::secret(
            72,
            "E (ANTHROPIC_API_KEY of the environment) bare under note",
            Via::Accept,
            json!({"note": format!("environment holds {env} today")}),
            env,
        )
        .registry_only()
        .keep("environment holds")
        .keep("today"),
    );
    // R73: one string with five frames, each carrying a canary of its own.
    let akia73 = ck(73, 2).to_uppercase();
    rows.push(
        Row::new(
            73,
            "one string with Bearer C, password=C, an AKIA shape, a JWT and a Cookie: line",
            Via::Accept,
            json!({"note": format!(
                "replay log\r\nBearer {}\r\nform password={}\r\naws key AKIA{}\r\ntoken eyJhbGciOiJIUzI1NiJ9.eyJ{}.{}\r\nCookie: a=b; z={}\r\nend of replay",
                ck(73, 0),
                ck(73, 1),
                pad_to(&akia73, 16),
                ck(73, 3),
                ck(73, 3),
                ck(73, 4)
            )}),
            &ck(73, 0),
        )
        .also(&ck(73, 1))
        .also(&akia73)
        .also(&ck(73, 3))
        .also(&ck(73, 4))
        .keep("replay log")
        .keep("end of replay"),
    );
    // R74: T1 and T2 in one header value.
    rows.push(
        Row::secret(
            74,
            "T1 and T2 in one Referer header value",
            Via::Accept,
            json!({"headers": {"Referer": format!("http://127.0.0.1:8082/#t={t1}&alt={t2}")}}),
            t1,
        )
        .and_secret(t2)
        .registry_only()
        .keep("Referer")
        .keep("&alt="),
    );
    rows
}

/// A row whose note is cut by the source's 512-byte cap `into` bytes inside the
/// registered secret `secret` (`name` for the failure message): the note is the
/// row's canary `marker` (which tells the row's line from the others, the row id
/// being cut off), `x` up to the cut, then the secret. The ring keeps the first
/// `into` bytes of the secret and the `…` the cap adds; only the writer's mask of
/// a trailing fragment can take them out, and the file's `args` must end with the
/// `x` run, the mask and the marker.
fn cap_row(n: u32, name: &str, secret: &str, into: usize, marker: &str) -> Row {
    // The entry's `args` begin `{"note":"`: 9 bytes.
    let before = DEFAULT_ARGS_SUMMARY_CAP - 9 - into;
    let filler = "x".repeat(before - marker.len());
    let fragment = secret.get(..into).unwrap_or(secret);
    let mut row = Row::secret(
        n,
        format!("{name} cut {into} bytes in by the 512-byte cap"),
        Via::Accept,
        json!({"note": format!("{marker}{filler}{secret}")}),
        secret,
    )
    .marked(marker)
    .in_ring(fragment)
    .ring_ends(&format!("{fragment}…"))
    .file_ends("xxxxxx[redacted]…");
    // The head is in the ring only when the cut leaves at least that much.
    if into >= head_of(secret).len() {
        row = row.in_ring(head_of(secret));
    } else {
        row.forbidden.retain(|f| f != head_of(secret));
    }
    row
}

/// Every registered secret in every position a secret can sit: under an
/// innocuous key, in a hidden and in a kept header, in a URL (path, query,
/// userinfo), in JSON text inside a string, inside a percent-encoded URL, in the
/// reason of a failing call, in a label (whole and cut), cut in half by the
/// 512-byte cap, in a hand-built entry (whole and cut), and several at once.
fn generated_token_rows(seed: u64, tokens: &Tokens) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut n = TOKEN_ROW_BASE;
    let mut next = || {
        n += 1;
        n - 1
    };
    for (name, secret) in tokens.named() {
        let head = head_of(secret);
        let secret_row = |n: u32, what: &str, via: Via, args: Value| {
            Row::secret(n, format!("{name} {what}"), via, args, secret)
        };
        // Under an innocuous key.
        rows.push(
            secret_row(
                next(),
                "under an innocuous key (vars.region)",
                Via::Accept,
                json!({"vars": {"region": secret, "target": "http://t.test"}}),
            )
            .registry_only()
            .keep("region")
            .keep("http://t.test"),
        );
        // In the value of a header the source hides by default (not benign).
        rows.push(
            secret_row(
                next(),
                "in the value of X-Trace (not a benign header)",
                Via::Accept,
                json!({"headers": {"X-Trace": secret}}),
            )
            .keep("X-Trace"),
        );
        // In the value of a benign header: only the registry catches it.
        rows.push(
            secret_row(
                next(),
                "in a Referer value as #t=<token> (a benign header)",
                Via::Accept,
                json!({"headers": {"Referer": format!("http://127.0.0.1:8082/#t={secret}")}}),
            )
            .registry_only()
            .keep("Referer")
            .keep("http://127.0.0.1:8082/#t="),
        );
        // In a URL: the path, the query, the userinfo (with and without a colon).
        rows.push(
            secret_row(
                next(),
                "in a URL path",
                Via::Accept,
                json!({"url": format!("https://x.test/api/{secret}/items")}),
            )
            .registry_only()
            .keep("/items"),
        );
        rows.push(
            secret_row(
                next(),
                "in a URL query value",
                Via::Accept,
                json!({"url": format!("https://x.test/cb?ref={secret}&page=2")}),
            )
            .registry_only()
            .keep("page=2"),
        );
        rows.push(
            secret_row(
                next(),
                "as the password of URL userinfo",
                Via::Accept,
                json!({"url": format!("https://svc:{secret}@host.test/p")}),
            )
            .keep("host.test"),
        );
        rows.push(
            secret_row(
                next(),
                "as URL userinfo with no colon",
                Via::Accept,
                json!({"url": format!("https://{secret}@host.test/p")}),
            )
            .keep("host.test"),
        );
        // Inside JSON text that is itself a string.
        rows.push(
            secret_row(
                next(),
                "inside a JSON-escaped string",
                Via::Accept,
                json!({"body": format!(r#"{{"ref":"{secret}","n":1}}"#)}),
            )
            .registry_only()
            .keep("ref"),
        );
        // Inside a percent-encoded URL (the secret has no character that changes).
        rows.push(
            secret_row(
                next(),
                "inside a percent-encoded nested URL",
                Via::Accept,
                json!({"url": format!("https://x.test/login?next=https%3A%2F%2Fy.test%2Fcb%3Fref%3D{secret}")}),
            )
            .registry_only()
            .keep("https://x.test/login?next="),
        );
        // In the reason of a failing call (and in its args).
        rows.push(
            secret_row(
                next(),
                "in an error reason echoed back",
                Via::Fail,
                json!({"note": format!("upstream refused {secret} as invalid")}),
            )
            .registry_only()
            .keep("upstream refused"),
        );
        // As the label, whole and at the head of a longer one (cut at 64).
        rows.push(
            secret_row(
                next(),
                "as the declared client label",
                Via::Accept,
                json!({}),
            )
            .label(secret)
            .registry_only()
            .file_label("[redacted]"),
        );
        let label = format!("agent-{secret}");
        let kept: String = label.chars().take(64).collect();
        let held = kept.strip_prefix("agent-").unwrap_or(&kept).to_string();
        rows.push(
            secret_row(
                next(),
                "after agent- in a label the 64-character cap cuts",
                Via::Accept,
                json!({}),
            )
            .label(&label)
            .in_ring(&held)
            .in_ring(head)
            .file_label("agent-[redacted]"),
        );
        // Cut in half by the 512-byte cap: a long fragment and the shortest one the
        // registry masks (6 bytes).
        for into in [20, 6] {
            let rn = next();
            rows.push(cap_row(rn, name, secret, into, &canary(seed, rn)));
        }
        // A hand-built entry that reaches the ring hook whole, and one cut inside
        // the secret: the writer alone stands between them and the file.
        let rn = next();
        let id = format!("R{rn:02}");
        rows.push(
            secret_row(
                rn,
                "in a hand-built entry (ring.append)",
                Via::Append(format!(r#"{{"row":"{id}","note":"seen {secret} here"}}"#)),
                Value::Null,
            )
            .keep("seen "),
        );
        let rn = next();
        let id = format!("R{rn:02}");
        let fragment = secret.get(..20).unwrap_or(secret);
        rows.push(
            Row::new(
                rn,
                format!("{name} cut inside, in a hand-built entry (ring.append)"),
                Via::Append(format!(r#"{{"row":"{id}","note":"seen {fragment}…"#)),
                Value::Null,
                fragment,
            )
            .also(head)
            .shared()
            .file_ends("seen [redacted]…"),
        );
    }
    // Several at once.
    let [(_, t1), (_, t2), (_, t3), (_, t4), (_, t5), (_, env)] = tokens.named();
    rows.push(
        Row::secret(
            next(),
            "all six in one note",
            Via::Accept,
            json!({"note": format!("a={t1} b={t2} c={t3} d={t4} e={t5} f={env}")}),
            t1,
        )
        .and_secret(t2)
        .and_secret(t3)
        .and_secret(t4)
        .and_secret(t5)
        .and_secret(env)
        .registry_only()
        .keep("a=")
        .keep(" f="),
    );
    rows.push(
        Row::secret(
            next(),
            "all six in one Referer value",
            Via::Accept,
            json!({"headers": {"Referer": format!(
                "http://127.0.0.1:8082/#t={t1}&a={t2}&b={t3}&c={t4}&d={t5}&e={env}"
            )}}),
            t1,
        )
        .and_secret(t2)
        .and_secret(t3)
        .and_secret(t4)
        .and_secret(t5)
        .and_secret(env)
        .registry_only()
        .keep("Referer")
        .keep("&e="),
    );
    rows.push(
        Row::secret(
            next(),
            "five secrets back to back, two and three",
            Via::Accept,
            json!({"note": format!("x{t1}{t2}y {t3}{t4}{t5}z")}),
            t1,
        )
        .and_secret(t2)
        .and_secret(t3)
        .and_secret(t4)
        .and_secret(t5)
        .registry_only()
        .keep("x[redacted]")
        .keep("z"),
    );
    let last = next();
    assert!(
        last < TOKEN_ROW_BASE + 700,
        "the token matrix overran: {last}"
    );
    rows
}

// ------------------------------------------------------------------ the run

/// What the ring and the push line carried for one row.
struct Seen {
    /// The entry the call (or the append) put in the ring.
    ring: AuditEntry,
    /// The `params` of the `notifications/aitm/agent` line the operator watcher
    /// received for the call; `None` for an appended entry.
    pushed: Option<Value>,
}

/// One file of the audit directory, as bytes.
struct Named {
    name: String,
    bytes: Vec<u8>,
}

/// One line of one file, parsed.
struct FileLine {
    file: String,
    raw: String,
    json: Value,
    /// The `args` text of an entry line.
    args: String,
}

/// A whole run: every row called, the writer shut down, every `audit*` file read.
struct Run {
    rows: Vec<Row>,
    /// One per row, in the order of `rows`.
    seen: Vec<Seen>,
    /// Every file whose name starts with `audit`, active and numbered, by name.
    files: Vec<Named>,
    /// Every line of every file that parses as JSON, in file-name order, parsed
    /// once.
    lines: Vec<FileLine>,
    /// What went wrong while running, and the completeness guard: asserted empty
    /// by every test before it reads a file.
    problems: Vec<String>,
}

impl Run {
    /// Runs the corpus and the benign table through the real path with the files
    /// rotating at [`CAP_BYTES`].
    fn execute(tag: &str) -> Run {
        let seed = run_seed();
        Run::execute_rows(tag, CAP_BYTES, |tokens| all_rows(seed, tokens))
    }

    /// Starts the rig, builds the rows from the secrets it registered (a row may
    /// carry any of them), and calls every row.
    fn execute_rows(tag: &str, cap: u64, build: impl FnOnce(&Tokens) -> Vec<Row>) -> Run {
        let rig = Rig::start(tag, Tuning::production().with_cap_bytes(cap));
        let rows = build(&rig.tokens);
        let mut problems = rig.problems();
        let srv = rig.server();
        let ring = Arc::clone(&rig.assembled.audit_ring);

        // The agent every call is made as: a minted connection id and a label.
        let agent = streaming(&srv, Frontend::Mcp, Some(AGENT_LABEL));
        let init = request_on(&srv, &agent, "initialize", json!({}));
        let agent_conn_id = init["result"]["connection_id"]
            .as_str()
            .unwrap_or_else(|| panic!("initialize carries no connection_id: {init}"))
            .to_string();

        // An operator watching the agent stream: the push line of every call.
        let mut watcher = streaming(&srv, Frontend::Operator, None);
        watcher.out = Some(NotificationSink::new(64));
        let drain = |watcher: &ConnCtx| -> Vec<Value> {
            watcher
                .out
                .as_ref()
                .expect("the watcher has a sink")
                .drain()
                .into_iter()
                .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
                .filter(|line| line["method"] == json!("notifications/aitm/agent"))
                .map(|line| line["params"].clone())
                .collect()
        };
        let subscribed = tool_call(&srv, &watcher, "flow.subscribe", &json!({}));
        if is_error(&subscribed) {
            problems.push(format!("the operator could not subscribe: {subscribed}"));
        }
        drain(&watcher);
        // `flow.subscribe` is a streaming control call and is not audited: the
        // count of audited calls starts at none.
        let mut audited = 0usize;

        let mut seen = Vec::with_capacity(rows.len());
        for row in &rows {
            // A secret the row registers is known to the writer from here on, as a
            // token minted while the process runs is (a registration is not
            // retroactive: the rows before this one never saw it).
            for secret in &row.registers {
                let how = rig
                    .handle
                    .register_secret(&format!("corpus.{}", row.id), secret);
                if how != Registration::Substring {
                    problems.push(format!(
                        "{}: the secret the row registers was taken in as {how:?}, not as a substring",
                        row.id
                    ));
                }
            }
            // A row that sets a label is called on a connection of its own.
            let own_conn = row
                .client_label
                .as_deref()
                .map(|label| streaming(&srv, Frontend::Mcp, Some(label)));
            let conn = own_conn.as_ref().unwrap_or(&agent);
            let before = ring.len();
            let mut pushed = None;
            match &row.via {
                Via::Accept | Via::Fail => {
                    let (name, wants_error) = match row.via {
                        Via::Fail => ("demo.fail", true),
                        _ => ("demo.accept", false),
                    };
                    let reply = tool_call(&srv, conn, name, &row.full_args());
                    if is_error(&reply) != wants_error {
                        problems.push(format!(
                            "{}: {name} was expected to {} but replied {}",
                            row.id,
                            if wants_error { "fail" } else { "succeed" },
                            clip(&reply.to_string(), 300)
                        ));
                    }
                    let mut lines = drain(&watcher);
                    if lines.len() == 1 {
                        pushed = lines.pop();
                    } else {
                        problems.push(format!(
                            "{}: the watcher received {} push lines for one call",
                            row.id,
                            lines.len()
                        ));
                    }
                }
                Via::Append(text) => {
                    ring.append(AuditEntry {
                        at: SystemTime::now(),
                        origin: Frontend::Mcp,
                        client_label: Some(AGENT_LABEL.to_string()),
                        connection_id: Some(agent_conn_id.clone()),
                        command: "demo.accept".to_string(),
                        args_summary: text.clone(),
                        result: AuditResult::Ok,
                    });
                }
            }
            audited += 1;
            if ring.len() != before + 1 {
                problems.push(format!(
                    "{}: the ring held {before} entries and then {}, not {}",
                    row.id,
                    ring.len(),
                    before + 1
                ));
            }
            match ring.recent(None, Some(1)).pop() {
                Some(entry) => seen.push(Seen {
                    ring: entry,
                    pushed,
                }),
                None => panic!("{}: the ring is empty after the call", row.id),
            }
        }

        let report = rig.handle.shutdown(SHUTDOWN_BUDGET);
        if !report.complete {
            problems.push(format!("the writer did not flush in time: {report:?}"));
        }
        if ring.len() != audited {
            problems.push(format!(
                "the ring holds {} entries for {audited} calls",
                ring.len()
            ));
        }
        let files = read_audit_files(&rig.dir);
        let lines = parse_lines(&files);
        let mut run = Run {
            rows,
            seen,
            files,
            lines,
            problems,
        };
        let guard = run.completeness(audited);
        run.problems.extend(guard);
        run
    }

    /// The completeness guard: the entry lines over every file equal the audited
    /// calls (so a rotated-away or lost file cannot hide a leak), and the agent
    /// stream rotated (a numbered file exists) without reaching its retention.
    fn completeness(&self, audited: usize) -> Vec<String> {
        let mut problems = Vec::new();
        let entries = self
            .lines
            .iter()
            .filter(|line| line.json.get("command").is_some())
            .count();
        if entries != audited {
            problems.push(format!(
                "{entries} entry lines over {} files for {audited} audited calls: an entry was \
                 lost or a file rotated away (change CAP_BYTES, never this guard); files: {:?}",
                self.files.len(),
                self.files.iter().map(|f| &f.name).collect::<Vec<_>>()
            ));
        }
        let names: BTreeSet<&str> = self.files.iter().map(|f| f.name.as_str()).collect();
        if !names.contains("audit.agent.jsonl.1") {
            problems.push(format!(
                "the agent stream did not rotate (no audit.agent.jsonl.1): {names:?}"
            ));
        }
        if names.contains("audit.agent.jsonl.6") {
            problems.push(format!(
                "the agent stream holds an audit.agent.jsonl.6: {names:?}"
            ));
        }
        problems
    }

    /// The one entry line that is `row`'s: its `args` carries the row's marker
    /// (the row id, unless the row says another).
    fn line_for(&self, row: &Row) -> Result<&FileLine, String> {
        let mut found = self.lines.iter().filter(|line| row.owns(&line.args));
        match (found.next(), found.next()) {
            (Some(line), None) => Ok(line),
            (None, _) => Err(format!(
                "{}: no entry line carries the row's marker {}",
                row.id,
                row.marker_text()
            )),
            (Some(_), Some(_)) => Err(format!(
                "{}: more than one entry line carries the row's marker {}",
                row.id,
                row.marker_text()
            )),
        }
    }

    /// The agent stream's entry lines, oldest first: the numbered files from the
    /// highest number down, then the active file.
    fn agent_entry_lines(&self) -> Vec<String> {
        let number = |name: &str| -> Option<Option<usize>> {
            if name == "audit.agent.jsonl" {
                return Some(None);
            }
            name.strip_prefix("audit.agent.jsonl.")?
                .parse::<usize>()
                .ok()
                .map(Some)
        };
        let mut files: Vec<(Option<usize>, &Named)> = self
            .files
            .iter()
            .filter_map(|f| number(&f.name).map(|n| (n, f)))
            .collect();
        // Highest number first, the active file (no number) last.
        files.sort_by_key(|(n, _)| std::cmp::Reverse(n.unwrap_or(0)));
        let (active, mut rotated): (Vec<_>, Vec<_>) =
            files.into_iter().partition(|(n, _)| n.is_none());
        rotated.extend(active);
        rotated
            .into_iter()
            .flat_map(|(_, file)| {
                String::from_utf8_lossy(&file.bytes)
                    .split_terminator('\n')
                    .filter(|raw| {
                        serde_json::from_str::<Value>(raw)
                            .map(|v| v.get("command").is_some())
                            .unwrap_or(false)
                    })
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Every parseable line of every file, in file-name order. A line that does not
/// parse is for the shape test to name; it is not here.
fn parse_lines(files: &[Named]) -> Vec<FileLine> {
    let mut lines = Vec::new();
    for file in files {
        let text = String::from_utf8_lossy(&file.bytes);
        for raw in text.split_terminator('\n') {
            if let Ok(json) = serde_json::from_str::<Value>(raw) {
                let args = json["args"].as_str().unwrap_or_default().to_string();
                lines.push(FileLine {
                    file: file.name.clone(),
                    raw: raw.to_string(),
                    json,
                    args,
                });
            }
        }
    }
    lines
}

/// Every file of `dir` whose name starts with `audit`, as bytes, by name.
fn read_audit_files(dir: &Path) -> Vec<Named> {
    let mut files: Vec<Named> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with("audit").then(|| Named {
                bytes: fs::read(entry.path())
                    .unwrap_or_else(|e| panic!("read {}: {e}", entry.path().display())),
                name,
            })
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files
}

/// Asserts `failures` is empty, listing every one.
fn assert_none(what: &str, failures: &[String]) {
    assert!(
        failures.is_empty(),
        "{what}: {} failure(s)\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// --------------------------------------------------------------------- tests

/// The lines of the files, as written, that hold `needle`: the file's name and
/// the line. Every line is looked at, a line that does not parse included.
fn raw_lines_holding(files: &[Named], needle: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for file in files {
        if !contains_bytes(&file.bytes, needle.as_bytes()) {
            continue;
        }
        let text = String::from_utf8_lossy(&file.bytes);
        let before = found.len();
        for line in text.split('\n').filter(|line| line.contains(needle)) {
            found.push((file.name.clone(), line.to_string()));
        }
        if found.len() == before {
            found.push((file.name.clone(), "(no single line holds it)".to_string()));
        }
    }
    found
}

/// The decoded `args` of an entry line as written, empty when it does not parse.
fn args_of_line(raw: &str) -> String {
    serde_json::from_str::<Value>(raw)
        .ok()
        .and_then(|json| json["args"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// AC55. No canary, no listed encoding of one, and no registered secret appears
/// in any byte of any file, rotated files included. The ring entry and the pushed
/// line (which the same source function makes) are clean too, except of the
/// secrets that only the writer's registry knows (the row says so, and the test
/// asserts the ring still holds them); each row keeps the words that show it went
/// through, and a hand-built entry (R25) is cleaned by the writer alone. Every
/// offending row is collected into one message, with its input and the line that
/// holds the leak.
#[test]
fn no_canary_reaches_any_file_through_the_real_path() {
    let run = Run::execute("ac55");
    assert_none("the run", &run.problems);
    assert_none("canaries in the audit files", &corpus_failures(&run));
}

/// Everything AC55 asserts of a finished run, collected: for every row, the
/// forbidden strings are in no file and (unless the row says the ring holds them)
/// not in the ring entry or the pushed line, what the row says the ring holds is
/// there, and the file line keeps the row's words. Then a registered secret in a
/// line that is no row's.
fn corpus_failures(run: &Run) -> Vec<String> {
    let mut failures = Vec::new();
    for (row, seen) in run.rows.iter().zip(&run.seen) {
        let is_call = !matches!(row.via, Via::Append(_));
        for (i, needle) in row.forbidden.iter().enumerate() {
            // The canary (the first forbidden string) is sent unless the row
            // hides it inside an encoding; every other listed string is sent
            // unless it is a form that exists only once the call is rendered.
            if row.must_send(i, needle) && !row.sends(needle) {
                failures.push(format!(
                    "{} [{}]: the row never sends `{needle}`, so it proves nothing",
                    row.id, row.what
                ));
            }
            for (file, line) in raw_lines_holding(&run.files, needle) {
                // A secret the whole run carries sits in many rows' lines: the
                // row whose line holds it answers for it (and the check after the
                // loop answers for a line that is no row's).
                if row.shared && !row.owns(&args_of_line(&line)) {
                    continue;
                }
                failures.push(format!(
                    "{} [{}]: `{needle}` reached {file}\n    input:  {}\n    output: {line}",
                    row.id,
                    row.what,
                    match &row.via {
                        Via::Append(text) => text.clone(),
                        _ => row.full_args().to_string(),
                    },
                ));
            }
            // The source's own surfaces, for a call (an appended entry is raw by
            // construction: it is what the writer must clean). A string the row
            // says the ring holds is not asserted clean.
            if is_call && !row.in_ring.iter().any(|held| held == needle) {
                let ring = &seen.ring;
                let reason = match &ring.result {
                    AuditResult::Error(reason) => reason.as_str(),
                    AuditResult::Ok => "",
                };
                let pushed = seen
                    .pushed
                    .as_ref()
                    .map(Value::to_string)
                    .unwrap_or_default();
                for (surface, text) in [
                    ("the ring's args_summary", ring.args_summary.as_str()),
                    ("the ring's reason", reason),
                    (
                        "the ring's client_label",
                        ring.client_label.as_deref().unwrap_or_default(),
                    ),
                    ("the pushed line", pushed.as_str()),
                ] {
                    if text.contains(needle.as_str()) {
                        failures.push(format!(
                            "{} [{}]: `{needle}` is in {surface}: {}",
                            row.id,
                            row.what,
                            clip(text, 400)
                        ));
                    }
                }
            }
        }
        // What only the registry can take out must still be in the ring: a row
        // whose secret a pass of the source now masks no longer proves the
        // registry, and says so here instead of passing for the wrong reason.
        if is_call {
            let ring = &seen.ring;
            let reason = match &ring.result {
                AuditResult::Error(reason) => reason.as_str(),
                AuditResult::Ok => "",
            };
            let pushed = seen
                .pushed
                .as_ref()
                .map(Value::to_string)
                .unwrap_or_default();
            let everything = format!(
                "{}\n{reason}\n{}\n{pushed}",
                ring.args_summary,
                ring.client_label.as_deref().unwrap_or_default()
            );
            for held in &row.in_ring {
                if !everything.contains(held.as_str()) {
                    failures.push(format!(
                        "{} [{}]: the ring no longer holds `{held}` (a pass of the source takes \
                         it out, or the cut moved), so the row does not prove the registry: {}",
                        row.id,
                        row.what,
                        clip(&everything, 400)
                    ));
                }
            }
            if let Some(end) = &row.ring_ends {
                if !ring.args_summary.ends_with(end.as_str()) {
                    failures.push(format!(
                        "{} [{}]: the ring's args do not end with `{end}`: {}",
                        row.id,
                        row.what,
                        clip(&ring.args_summary, 600)
                    ));
                }
            }
        }
        // The row must still be there: the file line exists, and holds its words.
        match run.line_for(row) {
            Err(why) => failures.push(why),
            Ok(line) => {
                for word in &row.keep {
                    if !line.args.contains(word.as_str()) {
                        failures.push(format!(
                            "{} [{}]: the args in {} lost `{word}`: {}",
                            row.id,
                            row.what,
                            line.file,
                            clip(&line.args, 400)
                        ));
                    }
                }
                if let Some(end) = &row.file_args_ends {
                    if !line.args.ends_with(end.as_str()) {
                        failures.push(format!(
                            "{} [{}]: the args in {} do not end with `{end}`: {}",
                            row.id,
                            row.what,
                            line.file,
                            line.args
                                .get(line.args.len().saturating_sub(120)..)
                                .unwrap_or(&line.args)
                        ));
                    }
                }
                if let Some(label) = &row.file_label {
                    let written = line.json["client_label"].as_str();
                    if written != Some(label.as_str()) {
                        failures.push(format!(
                            "{} [{}]: the client_label in {} is {written:?}, not `{label}`",
                            row.id, row.what, line.file
                        ));
                    }
                }
            }
        }
    }
    // A registered secret in a line that is no row's: nothing to attribute it to.
    let shared: BTreeSet<&str> = run
        .rows
        .iter()
        .filter(|row| row.shared)
        .flat_map(|row| row.forbidden.iter().map(String::as_str))
        .collect();
    for needle in shared {
        for (file, line) in raw_lines_holding(&run.files, needle) {
            let args = args_of_line(&line);
            let owned = run.rows.iter().any(|row| {
                row.shared && row.forbidden.iter().any(|f| f == needle) && row.owns(&args)
            });
            if !owned {
                failures.push(format!(
                    "`{needle}` reached {file} in a line that belongs to no row that carries it: {}",
                    clip(&line, 400)
                ));
            }
        }
    }
    failures
}

/// AC56. Each benign value comes through the real path byte for byte: the
/// file's line is exactly `entry_to_jsonl` of the ring entry (so its `args`
/// equals the ring's), the value read back from the parsed `args` is the value
/// sent, and the pushed line carries the same `args`.
#[test]
fn benign_values_survive_the_real_path_byte_for_byte() {
    let run = Run::execute("ac56");
    assert_none("the run", &run.problems);

    let mut failures = Vec::new();
    let mut checked = 0;
    for (row, seen) in run.rows.iter().zip(&run.seen) {
        let Some((path, value)) = &row.survives else {
            continue;
        };
        checked += 1;
        let line = match run.line_for(row) {
            Ok(line) => line,
            Err(why) => {
                failures.push(why);
                continue;
            }
        };
        let rendered = aitm_ca::audit::entry_to_jsonl(&seen.ring);
        if line.raw != rendered {
            failures.push(format!(
                "{} [{}]: the file line is not the ring's entry_to_jsonl\n    file: {}\n    ring: {rendered}",
                row.id, row.what, line.raw
            ));
        }
        if seen.ring.args_summary != line.args {
            failures.push(format!(
                "{} [{}]: file args {:?} differ from ring args {:?}",
                row.id, row.what, line.args, seen.ring.args_summary
            ));
        }
        let parsed: Value = match serde_json::from_str(&line.args) {
            Ok(parsed) => parsed,
            Err(e) => {
                failures.push(format!("{} [{}]: args do not parse: {e}", row.id, row.what));
                continue;
            }
        };
        let read_back = path.iter().fold(&parsed, |at, key| &at[key.as_str()]);
        if read_back != &Value::String(value.clone()) {
            failures.push(format!(
                "{} [{}]: sent {value:?}, read back {read_back}",
                row.id, row.what
            ));
        }
        let pushed_args = seen.pushed.as_ref().map(|p| p["args"].clone());
        if pushed_args != Some(json!(line.args)) {
            failures.push(format!(
                "{} [{}]: the pushed args {pushed_args:?} differ from the file's {:?}",
                row.id, row.what, line.args
            ));
        }
    }
    assert_eq!(checked, benign_rows().len(), "every benign row was checked");
    assert_none("benign values", &failures);
}

/// AC57, and the writer half of AC47. Every line of every file parses as JSON;
/// an entry line has exactly the seven keys and a marker line has `marker`; for
/// every row whose ring `args` parses, the file's `args` parses and has the same
/// paths (the value with every string blanked is equal); ring and file are one
/// text for every call whose `args` and reason fit their caps; and what the
/// writer wrote is a fixed point of the writer: fed back through a second real
/// writer, every agent entry line comes out byte for byte as it went in.
#[test]
fn every_line_is_valid_json_with_the_same_shape() {
    let run = Run::execute("ac57");
    assert_none("the run", &run.problems);

    let mut failures = Vec::new();
    for file in &run.files {
        if !file.bytes.ends_with(b"\n") {
            failures.push(format!("{}: does not end in a line end", file.name));
        }
        let Ok(text) = std::str::from_utf8(&file.bytes) else {
            failures.push(format!("{}: is not UTF-8", file.name));
            continue;
        };
        for (i, raw) in text.split_terminator('\n').enumerate() {
            let at = format!("{} line {}", file.name, i + 1);
            let json: Value = match serde_json::from_str(raw) {
                Ok(json) => json,
                Err(e) => {
                    failures.push(format!("{at}: not JSON ({e}): {}", clip(raw, 200)));
                    continue;
                }
            };
            let Some(object) = json.as_object() else {
                failures.push(format!("{at}: not an object: {}", clip(raw, 200)));
                continue;
            };
            if object.contains_key("marker") {
                if object.contains_key("command") {
                    failures.push(format!("{at}: a marker line with a command: {raw}"));
                }
                continue;
            }
            let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
            if keys != ENTRY_KEYS.iter().copied().collect::<BTreeSet<_>>() {
                failures.push(format!(
                    "{at}: the keys are {keys:?}, not the seven of an entry"
                ));
            }
        }
    }

    for (row, seen) in run.rows.iter().zip(&run.seen) {
        let line = match run.line_for(row) {
            Ok(line) => line,
            Err(why) => {
                failures.push(why);
                continue;
            }
        };
        if let Ok(ring_json) = serde_json::from_str::<Value>(&seen.ring.args_summary) {
            match serde_json::from_str::<Value>(&line.args) {
                Ok(file_json) => {
                    if blank_strings(&ring_json) != blank_strings(&file_json) {
                        failures.push(format!(
                            "{} [{}]: the file's args have other paths than the ring's\n    ring: {}\n    file: {}",
                            row.id, row.what, seen.ring.args_summary, line.args
                        ));
                    }
                }
                Err(e) => failures.push(format!(
                    "{} [{}]: the ring's args parse but the file's do not ({e}): {}",
                    row.id,
                    row.what,
                    clip(&line.args, 300)
                )),
            }
        }
        // The pushed line and the ring entry are one text (the source makes both).
        if !matches!(row.via, Via::Append(_)) {
            let pushed = seen.pushed.as_ref().map(|p| p["args"].clone());
            if pushed != Some(json!(seen.ring.args_summary)) {
                failures.push(format!(
                    "{} [{}]: the pushed args {pushed:?} differ from the ring's {:?}",
                    row.id, row.what, seen.ring.args_summary
                ));
            }
        }
        // A call's entry is what record_audit made; the writer changes nothing of
        // it (AC17) while it fits the caps. An appended entry is raw: not compared.
        // Neither is a row whose secret only the registry knows: the ring still
        // holds it, and taking it out is the writer's whole job.
        let cut = seen.ring.args_summary.ends_with('…')
            || matches!(&seen.ring.result, AuditResult::Error(r) if r.ends_with('…'));
        if !matches!(row.via, Via::Append(_)) && !cut && row.in_ring.is_empty() {
            let rendered = aitm_ca::audit::entry_to_jsonl(&seen.ring);
            if line.raw != rendered {
                failures.push(format!(
                    "{} [{}]: ring and file differ\n    ring: {rendered}\n    file: {}",
                    row.id, row.what, line.raw
                ));
            }
        }
    }
    failures.extend(fixed_point_failures(&run));
    assert_none("the shape of the files", &failures);
}

/// What the writer wrote, fed back through a second real writer (the production
/// `start_at` on a fresh ring), and the lines that come out different. The
/// entries are rebuilt from the lines of the agent stream, which holds every call
/// of the run.
fn fixed_point_failures(run: &Run) -> Vec<String> {
    let first = run.agent_entry_lines();
    let mut failures = Vec::new();
    if first.is_empty() {
        failures.push("the agent stream holds no entry line to feed back".to_string());
        return failures;
    }
    let origins = [Frontend::Cli, Frontend::Mcp, Frontend::Operator];
    let ring = Arc::new(AuditRing::default());
    let scratch = Scratch::new("refeed");
    let base = scratch.0.join("audit").join("audit.jsonl");
    let handle = start_at(&ring, &base, &scratch.0.join("ca-audit.jsonl"), true)
        .expect("the second writer starts")
        .expect("an explicit path starts the writer");
    for raw in &first {
        let json: Value = serde_json::from_str(raw).expect("a line the first run wrote parses");
        let origin = origins
            .iter()
            .copied()
            .find(|o| origin_label(*o) == json["origin"].as_str().unwrap_or_default());
        let Some(origin) = origin else {
            failures.push(format!("an origin no frontend has: {raw}"));
            continue;
        };
        let text = |key: &str| json[key].as_str().map(str::to_string);
        ring.append(AuditEntry {
            at: UNIX_EPOCH + Duration::from_millis(json["at"].as_u64().unwrap_or(0)),
            origin,
            client_label: text("client_label"),
            connection_id: text("connection_id"),
            command: text("command").unwrap_or_default(),
            args_summary: text("args").unwrap_or_default(),
            result: match json["result"]["error"].as_str() {
                Some(reason) => AuditResult::Error(reason.to_string()),
                None => AuditResult::Ok,
            },
        });
    }
    let report = handle.shutdown(SHUTDOWN_BUDGET);
    assert!(report.complete, "the second writer flushed: {report:?}");
    let second_files = read_audit_files(base.parent().expect("the base has a directory"));
    let second: Vec<String> = second_files
        .iter()
        .filter(|f| f.name == "audit.agent.jsonl")
        .flat_map(|f| {
            String::from_utf8_lossy(&f.bytes)
                .split_terminator('\n')
                .filter(|raw| raw.contains("\"command\""))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    if second.len() != first.len() {
        failures.push(format!(
            "the second writer wrote {} entry lines for {} fed back",
            second.len(),
            first.len()
        ));
    }
    for (before, after) in first.iter().zip(&second) {
        if before != after {
            failures.push(format!(
                "the writer's pass is not a fixed point\n    first:  {before}\n    second: {after}"
            ));
        }
    }
    failures
}

/// The corpus half of AC47 (Ambiguity 16). For the arguments of every row of the
/// corpus and of the benign table, as the call sends them, the source's own
/// function is idempotent: `redact_value(redact_value(v)) == redact_value(v)`.
/// (The writer half, a fixed point of the whole writer pass, is asserted over the
/// files in `every_line_is_valid_json_with_the_same_shape`.)
#[test]
fn corpus_args_are_idempotent_under_redact_value() {
    let mut failures = Vec::new();
    let mut checked = 0;
    // The walk needs no writer: the known-token rows carry sample secrets.
    for row in all_rows(run_seed(), &Tokens::sample()) {
        if row.args.is_null() {
            continue;
        }
        checked += 1;
        let args = row.full_args();
        let once = redact_value(&args);
        let twice = redact_value(&once);
        if once != twice {
            failures.push(format!(
                "{} [{}]\n    once:  {once}\n    twice: {twice}",
                row.id, row.what
            ));
        }
        // A row whose secret only the writer's registry knows is one `redact_value`
        // does not change, by design.
        if once == args && !row.forbidden.is_empty() && row.in_ring.is_empty() {
            failures.push(format!(
                "{} [{}]: redact_value changed nothing of a row that carries a secret",
                row.id, row.what
            ));
        }
    }
    assert!(checked > 60, "the table was walked: {checked} rows");
    assert_none("idempotence of redact_value", &failures);
}

// ------------------------------------------------------------------- the PoC

/// The four credentials of AC61's captured request, and three shapes that the
/// builder leaves in headers it does not read as credentials (it scrubs those
/// values with the old shared scrubber, which does not know the shapes of P5).
struct PocSecrets {
    /// In `Authorization: Bearer <this>`.
    authorization: String,
    /// In `Cookie: sid=<this>; theme=dark`.
    cookie: String,
    /// In `?access_token=<this>&q=hi`.
    access_token: String,
    /// In the form body `user=a&password=<this>`.
    password: String,
    /// In `Referer`, as the body of an AWS access key id (upper case).
    referer: String,
    /// In `X-Note`, as both later segments of a JWT.
    note: String,
    /// In `X-Trace`, as the body of a `ghp_` token.
    trace: String,
}

impl PocSecrets {
    fn new(seed: u64, n: u32) -> PocSecrets {
        let c = |k: u32| canary_k(seed, n, k);
        PocSecrets {
            authorization: c(0),
            cookie: c(1),
            access_token: c(2),
            password: c(3),
            referer: c(4).to_uppercase(),
            note: c(5),
            trace: c(6),
        }
    }

    /// The four of AC61.
    fn credentials(&self) -> [&str; 4] {
        [
            &self.authorization,
            &self.cookie,
            &self.access_token,
            &self.password,
        ]
    }

    /// The three the builder leaves in the YAML.
    fn left_by_the_builder(&self) -> [&str; 3] {
        [&self.referer, &self.note, &self.trace]
    }
}

/// A captured request that carries `secrets`, built the way
/// `crates/aitm-poc/tests/builder.rs` builds its flows.
fn poc_flow(secrets: &PocSecrets) -> HttpFlow {
    // The headers the builder keeps come first, so that the YAML lists them before
    // the credential headers (see `poc_rows` for why the order matters).
    let mut headers = HeaderMap::new();
    headers.set("Host", "vuln.test");
    headers.set(
        "Referer",
        &format!("https://x.test/cb/AKIA{}", pad_to(&secrets.referer, 16)),
    );
    headers.set(
        "X-Note",
        &format!(
            "see eyJhbGciOiJIUzI1NiJ9.eyJ{}.{} here",
            secrets.note, secrets.note
        ),
    );
    headers.set("X-Trace", &format!("ghp_{}", pad_to(&secrets.trace, 36)));
    headers.set(
        "Authorization",
        &format!("Bearer {}", secrets.authorization),
    );
    headers.set("Cookie", &format!("sid={}; theme=dark", secrets.cookie));
    HttpFlow {
        id: FlowId::new(),
        request: HttpRequest {
            method: "POST".into(),
            scheme: "http".into(),
            authority: "vuln.test".into(),
            path: format!("/x?access_token={}&q=hi", secrets.access_token),
            version: HttpVersion::Http11,
            headers,
            body: Body::Bytes(format!("user=a&password={}", secrets.password).into_bytes()),
            timestamp: SystemTime::now(),
        },
        response: Some(HttpResponse {
            status: 200,
            version: HttpVersion::Http11,
            headers: HeaderMap::new(),
            trailers: HeaderMap::new(),
            body: Body::Empty,
            timestamp: SystemTime::now(),
        }),
        client_conn: ConnInfo {
            peer: "127.0.0.1:0".parse().expect("a socket address"),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        },
        server_conn: None,
        metadata: FlowMeta::default(),
        intercept: InterceptState::Observed,
    }
}

/// What the agent chooses for the build: a name (`tag` makes it, and so the
/// YAML's `id:` line, unique to the build), a description that names the
/// placeholders the PoC will carry (early in the YAML, where the 512-byte cap
/// leaves it), the variables to parameterize by, and the success assertion.
fn poc_spec(tag: &str) -> PocSpec {
    PocSpec {
        info: PocInfo {
            name: format!("Replay of the login {tag}"),
            severity: Severity::High,
            references: vec![],
            tags: vec!["auth".into()],
            cwe: None,
            description: Some("Replays {{target}}/x with {{authorization}} and {{cookie}}".into()),
            author: None,
            metadata: None,
        },
        variables: vec![
            Variable {
                name: "target".into(),
                default: None,
                description: "Base URL".into(),
                required: true,
            },
            Variable {
                name: "param".into(),
                default: Some(CoreValue::Str("q".into())),
                description: "Reflected parameter".into(),
                required: false,
            },
        ],
        success: Assertion::Status(200),
    }
}

/// The three calls an agent makes with a PoC built by the real `StdPocBuilder`
/// from a flow that carries credentials (R52; AC61 with another number):
/// `R<n>a` sends the whole YAML as `poc_text` (770 bytes, so the 512-byte cap cuts
/// it inside the `variables`, and only its head, with the placeholders of its
/// description, is in the entry); `R<n>` sends the steps alone, which fit, with
/// the placeholders of the URL and of the credential headers and the three shapes
/// the builder leaves; `R<n>b` runs it, the `vars` being the values of the four
/// credentials.
fn poc_rows(seed: u64, n: u32) -> Vec<Row> {
    let secrets = PocSecrets::new(seed, n);
    let tag = format!("{n:02} {:08x}", mix(seed ^ u64::from(n)) & 0xffff_ffff);
    let poc = StdPocBuilder
        .build(&poc_flow(&secrets), poc_spec(&tag))
        .expect("a real build");
    let yaml = serde_yaml::to_string(&poc).expect("a PoC serialises");
    let steps = serde_yaml::to_string(&poc.steps).expect("the steps serialise");
    let [referer, note, trace] = secrets.left_by_the_builder();
    let [authorization, cookie, access_token, password] = secrets.credentials();

    vec![
        Row::new(
            n,
            "a built PoC's steps as poc_text (the shapes the builder left in its headers)",
            Via::Accept,
            json!({"poc_text": steps}),
            referer,
        )
        .also(note)
        .also(trace)
        .keep("{{target}}/x?access_token=[redacted]&{{param}}=hi")
        .keep("Referer: https://x.test/cb/[redacted]"),
        Row::new(
            n,
            "a built PoC's whole YAML as poc_text (longer than the cap)",
            Via::Accept,
            json!({"poc_text": yaml}),
            referer,
        )
        .also(note)
        .also(trace)
        .with_id(&format!("R{n:02}a"))
        // The cap cuts the entry before its `row`: the YAML's unique first line is
        // what tells it from the others.
        .marked(&format!("id: {}", poc.id))
        .keep("{{target}}"),
        Row::new(
            n,
            "the vars an agent runs the PoC with: the four credentials",
            Via::Accept,
            json!({"vars": {
                "authorization": format!("Bearer {authorization}"),
                "cookie": format!("sid={cookie}; theme=dark"),
                "access_token": access_token,
                "password": password,
                "target": "http://vuln.test",
            }}),
            authorization,
        )
        .also(cookie)
        .also(access_token)
        .also(password)
        .with_id(&format!("R{n:02}b"))
        .keep("http://vuln.test"),
    ]
}

/// The `{{name}}` placeholders in `text`, by name.
fn placeholders(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else { break };
        found.insert(after[..close].to_string());
        rest = &after[close + 2..];
    }
    found
}

/// AC61. A PoC built by the real `StdPocBuilder` over a request that carries an
/// `Authorization` bearer, a cookie, a query token and a form password goes
/// through the audited call as an agent would send it (`poc_text`, and `vars`
/// for the run), and no credential reaches a file. The 770-byte YAML is longer
/// than the 512-byte cap, which cuts it; what the cap leaves is the same text in
/// the ring and in the file (the writer changes nothing of a clean entry), every
/// `{{placeholder}}` in the ring's `args` is in the file's, and the placeholder
/// syntax is still there: the builder's own redaction (a `{{var}}` where a
/// credential was) and the audit's do not fight.
#[test]
fn a_built_poc_passes_through_the_audit_clean() {
    let seed = run_seed();
    // A small cap, so that the three lines make the agent file rotate.
    let run = Run::execute_rows("ac61", 1024, |_| poc_rows(seed, 61));
    assert_none("the run", &run.problems);
    let mut failures = corpus_failures(&run);

    let (steps_row, whole_row, vars_row) = (&run.rows[0], &run.rows[1], &run.rows[2]);
    let yaml_args = whole_row.args["poc_text"].as_str().unwrap_or_default();
    assert!(
        json!({"poc_text": yaml_args}).to_string().len() > DEFAULT_ARGS_SUMMARY_CAP,
        "the YAML is longer than the 512-byte cap (it is the point of the row)"
    );
    for (row, seen) in run.rows.iter().zip(&run.seen) {
        let line = match run.line_for(row) {
            Ok(line) => line,
            Err(why) => {
                failures.push(why);
                continue;
            }
        };
        // The entry is clean already, so the writer changes nothing of it.
        if line.args != seen.ring.args_summary {
            failures.push(format!(
                "{} [{}]: the file's args differ from the ring's\n    ring: {}\n    file: {}",
                row.id, row.what, seen.ring.args_summary, line.args
            ));
        }
        // Every placeholder the ring shows is in the file.
        let in_ring = placeholders(&seen.ring.args_summary);
        let in_file = placeholders(&line.args);
        if !in_ring.is_subset(&in_file) {
            failures.push(format!(
                "{} [{}]: the ring shows the placeholders {in_ring:?}, the file {in_file:?}",
                row.id, row.what
            ));
        }
    }
    // The cap cuts the whole YAML; its head carries the description's placeholders.
    let whole_ring = &run.seen[1].ring.args_summary;
    if !whole_ring.ends_with('…') {
        failures.push(format!(
            "the whole YAML was not cut by the cap: {}",
            clip(whole_ring, 700)
        ));
    }
    let expected_head: BTreeSet<String> = ["authorization", "cookie", "target"]
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    let seen_head = placeholders(whole_ring);
    if seen_head != expected_head {
        failures.push(format!(
            "the whole YAML's entry shows the placeholders {seen_head:?}, not {expected_head:?}: {}",
            clip(whole_ring, 700)
        ));
    }
    // The steps fit: the builder's placeholders are all there, in the file too.
    let steps_file = run
        .line_for(steps_row)
        .map(|line| line.args.clone())
        .unwrap_or_default();
    let expected_steps: BTreeSet<String> = ["param", "target"]
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    let seen_steps = placeholders(&steps_file);
    if !expected_steps.is_subset(&seen_steps) {
        failures.push(format!(
            "the steps' file args show the placeholders {seen_steps:?}, not {expected_steps:?} \
             at least: {steps_file}"
        ));
    }
    // The vars of the run: the names stay, every value is gone.
    let vars_file = run
        .line_for(vars_row)
        .map(|line| line.args.clone())
        .unwrap_or_default();
    for name in ["authorization", "cookie", "access_token", "password"] {
        if !vars_file.contains(&format!("\"{name}\":\"<redacted>\"")) {
            failures.push(format!(
                "the vars' file args do not show {name} as <redacted>: {vars_file}"
            ));
        }
    }
    assert_none("the built PoC through the audit", &failures);
}

// ------------------------------------------------------- the configured sources

/// AC52. `start` registers every source of a secret before the sink is
/// attached: the transport token, `mcp.operator_token`, `mcp.agent_token`, the
/// web agent bridge token it is handed and the environment secret (by its
/// name), and not an environment variable whose name does not say "secret". Hand-built
/// entries that reach the ring hook carry each of the five bare, as the `#t=`
/// fragment of a URL and as the value of a `Referer` header (a header the
/// source keeps, so only the registry catches it), and none of them is in any
/// file; the values of `SSH_AUTH_SOCK` and `HOME` are, unmasked. The same for a
/// `StreamableHttp` transport token.
#[test]
fn start_registers_every_configured_source() {
    let mut failures = Vec::new();
    for streamable in [false, true] {
        failures.extend(registered_sources_failures(streamable));
    }
    assert_none("the sources `start` registers", &failures);
}

fn registered_sources_failures(streamable: bool) -> Vec<String> {
    let kind = if streamable {
        "StreamableHttp"
    } else {
        "LoopbackTcp"
    };
    let scratch = Scratch::new("ac52");
    let token = aitm::web::generate_token;
    let (t1, t2, t3, t4) = (token(), token(), token(), token());
    let env_secret = env_secret_value();
    let unmasked = [
        format!("/tmp/sock52x{:08x}", mix(run_seed()) & 0xffff_ffff),
        format!("/home/u52x{:08x}", mix(run_seed()) & 0xffff_ffff),
    ];
    let env = vec![
        ("ANTHROPIC_API_KEY".to_string(), env_secret.clone()),
        ("SSH_AUTH_SOCK".to_string(), unmasked[0].clone()),
        ("HOME".to_string(), unmasked[1].clone()),
    ];

    let mut cfg = Config::default();
    cfg.mcp.transport = if streamable {
        McpTransport::streamable_http_default(t1.clone())
    } else {
        McpTransport::LoopbackTcp {
            port: 0,
            token: t1.clone(),
            endpoint_file: None,
        }
    };
    cfg.mcp.operator_token = Some(t2.clone());
    cfg.mcp.agent_token = Some(t3.clone());
    cfg.ca.dir = scratch.0.join("ca");
    cfg.ca.audit_log = scratch.0.join("ca-audit.jsonl");
    let dir = scratch.0.join("audit");
    cfg.mcp.audit_log = AuditLogSetting::Path(dir.join("audit.jsonl"));

    let ring = Arc::new(AuditRing::default());
    let handle = start(&cfg, &ring, Some(&t4), &env)
        .expect("the writer starts on a scratch directory")
        .expect("an explicit path starts the writer");

    let mut failures = Vec::new();
    let sources = [
        ("the transport token", &t1),
        ("mcp.operator_token", &t2),
        ("mcp.agent_token", &t3),
        ("the web agent bridge token", &t4),
        ("ANTHROPIC_API_KEY", &env_secret),
    ];
    // The self-check: five secrets registered, each masked, the two ordinary
    // environment values untouched.
    let registry = handle.registry();
    if registry.len() != sources.len() {
        failures.push(format!(
            "[{kind}] the registry holds {} secrets, not the {} the sources hold",
            registry.len(),
            sources.len()
        ));
    }
    for (source, secret) in &sources {
        let masked = registry.mask(&format!("a {secret} b"));
        if masked != "a [redacted] b" {
            failures.push(format!(
                "[{kind}] {source} is not registered: mask gave {masked:?}"
            ));
        }
    }
    for value in &unmasked {
        if registry.mask(value) != *value {
            failures.push(format!(
                "[{kind}] the registry masks an ordinary environment value, {value}"
            ));
        }
    }

    // The hand-built entries.
    let append = |args: String| {
        ring.append(AuditEntry {
            at: SystemTime::now(),
            origin: Frontend::Mcp,
            client_label: Some(AGENT_LABEL.to_string()),
            connection_id: None,
            command: "demo.accept".to_string(),
            args_summary: args,
            result: AuditResult::Ok,
        });
    };
    let mut audited = 0;
    for (_, secret) in &sources {
        for args in [
            json!({"note": format!("seen {secret} here")}),
            json!({"url": format!("http://127.0.0.1:8082/#t={secret}")}),
            json!({"headers": {"Referer": secret}}),
        ] {
            append(args.to_string());
            audited += 1;
        }
    }
    append(json!({"note": format!("cwd {} sock {}", unmasked[1], unmasked[0])}).to_string());
    audited += 1;

    let report = handle.shutdown(SHUTDOWN_BUDGET);
    if !report.complete {
        failures.push(format!("[{kind}] the writer did not flush: {report:?}"));
    }
    let files = read_audit_files(&dir);
    let entries = parse_lines(&files)
        .iter()
        .filter(|line| line.json.get("command").is_some())
        .count();
    if entries != audited {
        failures.push(format!(
            "[{kind}] {entries} entry lines for {audited} appended entries"
        ));
    }
    for (source, secret) in &sources {
        for (file, line) in raw_lines_holding(&files, secret) {
            failures.push(format!(
                "[{kind}] {source} reached {file}: {}",
                clip(&line, 300)
            ));
        }
    }
    for value in &unmasked {
        if !files
            .iter()
            .any(|f| contains_bytes(&f.bytes, value.as_bytes()))
        {
            failures.push(format!(
                "[{kind}] {value} is in no file: an ordinary environment value was masked"
            ));
        }
    }
    failures
}

/// FINDING (task W15, fixed by the fix task that followed it). When a
/// cap leaves a fragment of a registered secret that is 6 to 9 bytes long, the
/// writer masks it with the 10-byte `[redacted]` *after* it capped `args`, so the
/// entry's `args` ends up to 4 bytes past the cap (519 bytes for a 6-byte
/// fragment, against 512 and the 3-byte marker). Nothing leaks, but the size
/// bound of Design 6 does not hold, and the line is not a fixed point of the
/// writer: a second pass over it cuts the mask to `[redac…`. The writer now
/// cuts the text before the fragment until the mask fits.
#[test]
fn a_masked_short_fragment_keeps_args_within_the_cap() {
    let run = Run::execute("overrun");
    assert_none("the run", &run.problems);
    let limit = DEFAULT_ARGS_SUMMARY_CAP + "…".len();
    let mut failures = Vec::new();
    let mut checked = 0;
    // The rows whose cut leaves the shortest fragment the registry masks: 6 bytes,
    // against the 10 of its mask.
    for row in run
        .rows
        .iter()
        .filter(|row| row.what.contains(" cut 6 bytes in by the 512-byte cap"))
    {
        checked += 1;
        match run.line_for(row) {
            Err(why) => failures.push(why),
            Ok(line) if line.args.len() > limit => failures.push(format!(
                "{} [{}]: the file's args are {} bytes, over the {limit} the cap and its marker allow: ...{}",
                row.id,
                row.what,
                line.args.len(),
                line.args
                    .get(line.args.len().saturating_sub(40)..)
                    .unwrap_or_default()
            )),
            Ok(_) => {}
        }
    }
    assert!(
        checked >= 6,
        "the rows that cut a short fragment ran: {checked}"
    );
    assert_none("the writer's cap on args", &failures);
}

/// FINDING (task W15, fixed by the fix task that followed it). A
/// registered secret that holds a quote or a backslash is masked in its raw form
/// (a plain text field) and in its JSON form (inside `args`, which is JSON text),
/// but not when it sits inside a string field that is itself JSON text, say a
/// `body` holding a document: the writer then sees the form that escaping the JSON
/// form once more makes (`\\\"` for `"`), which the registry does not store. A
/// 64-hex token (what `generate_token` makes) has no such character, so the
/// tokens the process mints are not exposed; a configured one that does have one
/// was. The registry now stores the JSON form at depths 1 to 3.
#[test]
fn a_registered_secret_with_a_quote_is_masked_inside_json_text_in_a_string() {
    let seed = run_seed();
    // A small cap and a second call make the agent file rotate (the guard).
    let run = Run::execute_rows("json-in-json", 256, |_| {
        let c = canary(seed, 91);
        let secret = format!("{c}\"q\\z9");
        let document = serde_json::to_string(&json!({"k": secret})).expect("a document");
        vec![
            Row::new(
                91,
                "a secret with a quote and a backslash inside JSON text inside a string",
                Via::Accept,
                json!({"body": document}),
                &c,
            )
            .registers(&secret)
            .registry_only(),
            Row::new(
                92,
                "a second call, so that the file rotates",
                Via::Accept,
                json!({"note": "hello"}),
                &canary(seed, 92),
            )
            .encoded(),
        ]
    });
    assert_none("the run", &run.problems);
    assert_none("the secret in the audit files", &corpus_failures(&run));
}
