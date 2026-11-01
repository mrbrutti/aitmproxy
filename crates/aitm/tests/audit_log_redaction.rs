//! The audit corpus, part A: secret-bearing shapes through the real path to the
//! files (spec Design 14.7; AC55 to AC57 and the corpus half of AC47).
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
//! Rows are numbered as the spec numbers them (AC55). This file holds the rows of
//! task W14 (R1 to R39, R50, R51, R53 and R54) and, from R75 on, extra rows the
//! amended redaction rules name that AC55's 74 do not (bracket-notation form keys,
//! apostrophes in userinfo and in unquoted values, camelCase keys, bracketed
//! values under a secret key, Rust `Debug` wrappers, an error reason echoing a
//! shape, the header shapes of rule D). The rest of AC55 (R40 to R49, R52 and R55
//! to R74) is added to [`rows`] by the next task, with the same rig.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aitm::audit_log::{start_at, start_tuned, AuditLogHandle, Tuning};
use aitm::tui::{self, TuiLog};
use aitm::wire::{assemble_with_scripts, Assembled, Features, ScriptWiring};
use aitm_core::{
    origin_label, AgentPolicy, AuditEntry, AuditLogSetting, AuditResult, AuditRing, AuditSink,
    Command, CommandHost, Config, Frontend, McpTransport, ParamDef, ParamSchema, Params, Plugin,
    Registry, Sensitivity, TypeDesc, Value as CoreValue,
};
use aitm_mcp::redact_args::redact_value;
use aitm_mcp::{ConnCtx, McpServer, NotificationSink};
use serde_json::{json, Map, Value};

/// The most a shutdown is given to flush; every run asserts it finished.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(5);

/// The size at which every stream's file rotates in the corpus run: small enough
/// that the agent file (which holds every call) rotates, and large enough that
/// the retention (five rotated files) does not drop the oldest. The completeness
/// guard fails when this is wrong either way; change this number, never the guard.
const CAP_BYTES: u64 = 12 * 1024;

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
    format!("CNRY{n:02}x{:08x}", mix(seed ^ u64::from(n)) & 0xffff_ffff)
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

/// The secrets the rig registers with the writer: the five tokens (each 64 hex
/// digits, `aitm::web::generate_token`) and an environment secret. The rows of
/// the next task place them; this task proves the rig holds them.
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
        let env_secret = format!("env-secret-{:016x}", mix(run_seed()));

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
    what: &'static str,
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
    /// Plain words that must still be in the entry's `args` (a name the rules
    /// keep, the text around a masked value): a row whose `args` were wiped
    /// would otherwise pass.
    keep: Vec<&'static str>,
    /// For a benign row: the path into the parsed `args` and the exact value that
    /// must be read back there.
    survives: Option<(Vec<String>, String)>,
}

impl Row {
    fn new(n: u32, what: &'static str, via: Via, args: Value, canary: &str) -> Row {
        Row {
            id: format!("R{n:02}"),
            what,
            via,
            args,
            forbidden: vec![canary.to_string()],
            canary_sent: true,
            keep: Vec::new(),
            survives: None,
        }
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

    /// A word the entry must still hold.
    fn keep(mut self, word: &'static str) -> Row {
        self.keep.push(word);
        self
    }

    /// A benign row: `value` sent at `path` inside `args` must come back as it
    /// was sent.
    fn benign(id: String, what: &'static str, args: Value, path: &[&str], value: &str) -> Row {
        Row {
            id,
            what,
            via: Via::Accept,
            args,
            forbidden: Vec::new(),
            canary_sent: false,
            keep: Vec::new(),
            survives: Some((
                path.iter().map(|part| (*part).to_string()).collect(),
                value.to_string(),
            )),
        }
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
        match &self.via {
            Via::Append(text) => text.contains(needle),
            Via::Accept | Via::Fail => value_holds(&self.args, needle),
        }
    }
}

/// The corpus rows of this task: AC55's R1 to R39, R50, R51, R53 and R54, then
/// the extra rows from R75 on. Each canary is built by [`canary`] from `seed`.
fn rows(seed: u64) -> Vec<Row> {
    // The base64 encoder is test-local: pin it, or a row built on it would pass
    // for the wrong reason (an encoding that decodes to nothing is masked by no
    // pass and would never be found).
    assert_eq!(b64(b"user:pw"), "dXNlcjpwdw==");
    assert_eq!(b64(b"ab"), "YWI=");
    assert_eq!(b64(b"abc"), "YWJj");

    let c = |n: u32| canary(seed, n);
    let accept =
        |n: u32, what: &'static str, args: Value| Row::new(n, what, Via::Accept, args, &c(n));
    let fail = |n: u32, what: &'static str, args: Value| Row::new(n, what, Via::Fail, args, &c(n));
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
fn all_rows(seed: u64) -> Vec<Row> {
    let mut all = rows(seed);
    all.extend(benign_rows());
    all
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
    /// What went wrong while running, and the completeness guard: asserted empty
    /// by every test before it reads a file.
    problems: Vec<String>,
}

impl Run {
    /// Runs the corpus and the benign table through the real path with the files
    /// rotating at [`CAP_BYTES`].
    fn execute(tag: &str) -> Run {
        Run::execute_rows(tag, all_rows(run_seed()), CAP_BYTES)
    }

    fn execute_rows(tag: &str, rows: Vec<Row>, cap: u64) -> Run {
        let rig = Rig::start(tag, Tuning::production().with_cap_bytes(cap));
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
            let before = ring.len();
            let mut pushed = None;
            match &row.via {
                Via::Accept | Via::Fail => {
                    let (name, wants_error) = match row.via {
                        Via::Fail => ("demo.fail", true),
                        _ => ("demo.accept", false),
                    };
                    let reply = tool_call(&srv, &agent, name, &row.full_args());
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
        let mut run = Run {
            rows,
            seen,
            files,
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
            .lines()
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

    /// Every parseable line of every file, in file-name order. A line that does
    /// not parse is for the shape test to name; it is not here.
    fn lines(&self) -> Vec<FileLine> {
        let mut lines = Vec::new();
        for file in &self.files {
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

    /// The one entry line whose `args` carries `"row":"<id>"`.
    fn line_for(&self, id: &str) -> Result<FileLine, String> {
        let marker = format!(r#""row":"{id}""#);
        let mut found: Vec<FileLine> = self
            .lines()
            .into_iter()
            .filter(|line| line.args.contains(&marker))
            .collect();
        match found.len() {
            1 => Ok(found.remove(0)),
            n => Err(format!("{id}: {n} entry lines carry the row id, not 1")),
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

/// AC55 (the rows of this task). No canary, and no listed encoding of one,
/// appears in any byte of any file, rotated files included. The ring entry and
/// the pushed line (which the same source function makes) are clean too, each
/// row keeps the words that show it went through, and a hand-built entry (R25)
/// is cleaned by the writer alone. Every offending row is collected into one
/// message, with its input and the line that holds the leak.
#[test]
fn no_canary_reaches_any_file_through_the_real_path() {
    let run = Run::execute("ac55");
    assert_none("the run", &run.problems);

    let mut failures = Vec::new();
    for (row, seen) in run.rows.iter().zip(&run.seen) {
        for (i, needle) in row.forbidden.iter().enumerate() {
            // The canary (the first forbidden string) is sent unless the row
            // hides it inside an encoding; every other listed string is sent.
            let must_send = i > 0 || row.canary_sent;
            if must_send && !row.sends(needle) {
                failures.push(format!(
                    "{} [{}]: the row never sends `{needle}`, so it proves nothing",
                    row.id, row.what
                ));
            }
            for file in &run.files {
                if contains_bytes(&file.bytes, needle.as_bytes()) {
                    let text = String::from_utf8_lossy(&file.bytes);
                    let line = text.lines().find(|l| l.contains(needle.as_str()));
                    failures.push(format!(
                        "{} [{}]: `{needle}` reached {}\n    input:  {}\n    output: {}",
                        row.id,
                        row.what,
                        file.name,
                        match &row.via {
                            Via::Append(text) => text.clone(),
                            _ => row.full_args().to_string(),
                        },
                        line.unwrap_or("(no line)")
                    ));
                }
            }
            // The source's own surfaces, for a call (an appended entry is raw by
            // construction: it is what the writer must clean).
            if !matches!(row.via, Via::Append(_)) {
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
        // The row must still be there: the file line exists, and holds its words.
        match run.line_for(&row.id) {
            Err(why) => failures.push(why),
            Ok(line) => {
                for word in &row.keep {
                    if !line.args.contains(word) {
                        failures.push(format!(
                            "{} [{}]: the args in {} lost `{word}`: {}",
                            row.id,
                            row.what,
                            line.file,
                            clip(&line.args, 400)
                        ));
                    }
                }
            }
        }
    }
    assert_none("canaries in the audit files", &failures);
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
        let line = match run.line_for(&row.id) {
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
        let line = match run.line_for(&row.id) {
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
        let cut = seen.ring.args_summary.ends_with('…')
            || matches!(&seen.ring.result, AuditResult::Error(r) if r.ends_with('…'));
        if !matches!(row.via, Via::Append(_)) && !cut {
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
    for row in all_rows(run_seed()) {
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
        if once == args && !row.forbidden.is_empty() {
            failures.push(format!(
                "{} [{}]: redact_value changed nothing of a row that carries a secret",
                row.id, row.what
            ));
        }
    }
    assert!(checked > 60, "the table was walked: {checked} rows");
    assert_none("idempotence of redact_value", &failures);
}
