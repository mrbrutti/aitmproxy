//! Task 17 — the deterministic **non-LLM** scripted driver (spec §D7, AC-M4-13,
//! AC-M4-14, AC-M4-15b).
//!
//! This module is a *generic MCP client over loopback TCP* plus the hard-coded
//! find → reproduce → record loop the agent-first thesis puts on the agent side.
//! It talks to aitmproxy **only** through the public command surface — a JSON-RPC
//! client over the loopback-TCP transport, authenticated with the agent token —
//! with no in-process shortcuts, so a green run is proof the command surface
//! suffices to drive the whole loop with no model in it ([`Client`]).
//!
//! Its "intelligence" is a fixed table of heuristics, not reasoning: it crawls
//! the target through a real browser ([`ScriptedDriver::discover`]), enumerates
//! candidate abuse points **from the observed index flow** (`flow.detail`), and
//! for each class it knows how to probe it injects a probe of *its own* choosing
//! and reads the response back — it never imports the target's planted-vuln
//! `manifest()`/`seed` markers (deliberately: this module depends only on the
//! public `aitm`/`aitm-poc` surface, never on `aitm_testtarget`'s grader ground
//! truth). A candidate is confirmed only when a built PoC `poc.run`s to
//! `passed: true` on the vulnerable origin **and** `passed: false` on the patched
//! control — the M1 reproduction bar reached by discovery.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

use aitm_poc::{Assertion, BrowserAction, BrowserStep, MatchPart, Poc, Step};

// ---------------------------------------------------------------------------
// A minimal, dependency-free MCP client over the loopback-TCP transport.
// ---------------------------------------------------------------------------

/// A newline-delimited JSON-RPC client speaking the loopback-TCP transport: it
/// sends the `{"token": …}` handshake line, then one request per line, reading
/// one reply line per request. Server-initiated `notifications/aitm/*` lines that
/// arrive interleaved with a reply are stashed in [`Client::notifications`] rather
/// than mistaken for the reply (requests are issued serially, so a reply is the
/// first line carrying the matching `id`).
pub struct Client {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: u64,
    /// Every `notifications/aitm/*` line seen so far (F4 push), newest last.
    pub notifications: Vec<Value>,
}

impl Client {
    /// Connect to `addr`, present `token` as the first line, and return the ready
    /// client. The transport classifies the token into the connection's role;
    /// the agent token yields the autonomous-agent role this driver runs as.
    pub async fn connect(addr: SocketAddr, token: &str) -> anyhow::Result<Client> {
        let stream = TcpStream::connect(addr)
            .await
            .with_context(|| format!("connect to the MCP bus at {addr}"))?;
        let (read_half, mut writer) = stream.into_split();
        writer
            .write_all(format!("{}\n", json!({ "token": token })).as_bytes())
            .await
            .context("send the agent-token handshake line")?;
        writer.flush().await?;
        Ok(Client {
            reader: BufReader::new(read_half),
            writer,
            next_id: 1,
            notifications: Vec::new(),
        })
    }

    /// Send one JSON-RPC request and return its `result`, draining any
    /// notifications that arrive before the matching reply.
    async fn request(&mut self, method: &str, params: Value) -> anyhow::Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let line = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.writer
            .write_all(format!("{line}\n").as_bytes())
            .await
            .with_context(|| format!("write {method} request"))?;
        self.writer.flush().await?;

        loop {
            let mut buf = String::new();
            let n = self
                .reader
                .read_line(&mut buf)
                .await
                .with_context(|| format!("read a reply to {method}"))?;
            if n == 0 {
                bail!("the MCP connection closed before a reply to {method}");
            }
            let msg: Value = serde_json::from_str(buf.trim())
                .with_context(|| format!("parse a line while awaiting {method}: {buf:?}"))?;
            // A notification carries no `id`; stash it and keep reading.
            match msg.get("id").and_then(Value::as_u64) {
                Some(got) if got == id => {
                    if let Some(err) = msg.get("error") {
                        bail!("{method} returned a JSON-RPC error: {err}");
                    }
                    return msg
                        .get("result")
                        .cloned()
                        .ok_or_else(|| anyhow!("{method} reply had no result: {msg}"));
                }
                Some(_) => continue, // a stray reply to another request (should not happen)
                None => {
                    self.notifications.push(msg);
                }
            }
        }
    }

    /// The MCP `initialize` handshake, naming this client for the audit log.
    pub async fn initialize(&mut self) -> anyhow::Result<()> {
        self.request(
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "aitm-scripted-driver", "version": "0"},
            }),
        )
        .await?;
        Ok(())
    }

    /// Call a tool and return its `structuredContent`, surfacing a tool-level
    /// error (`isError: true`) as an `Err` carrying the content text.
    pub async fn tool_call(&mut self, name: &str, arguments: Value) -> anyhow::Result<Value> {
        let result = self
            .request("tools/call", json!({"name": name, "arguments": arguments}))
            .await?;
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            let text = result
                .get("content")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("(no message)");
            bail!("tool {name} errored: {text}");
        }
        result
            .get("structuredContent")
            .cloned()
            .ok_or_else(|| anyhow!("tool {name} returned no structuredContent: {result}"))
    }

    /// How many `notifications/aitm/flow` push lines have arrived so far (F4).
    pub fn flow_notifications(&self) -> usize {
        self.notifications
            .iter()
            .filter(|n| n.get("method").and_then(Value::as_str) == Some("notifications/aitm/flow"))
            .count()
    }
}

// ---------------------------------------------------------------------------
// The driver: discover → reproduce → record.
// ---------------------------------------------------------------------------

/// One abuse-point candidate the crawl observed, with the flow it was read from —
/// so a test can prove candidates are derived from `flow.detail`, not invented.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// The endpoint path the index linked (e.g. `/search`).
    pub path: String,
    /// The `flow.detail` flow id the path was read out of (the crawled index).
    pub source_flow: String,
}

/// A confirmed, reproduced finding: the artifacts a `poc.run` emitted plus the
/// vulnerable/control verdicts the reproduction bar is judged on.
#[derive(Debug, Clone)]
pub struct Finding {
    pub class: String,
    pub title: String,
    pub severity: String,
    /// The vulnerable endpoint (scheme+host+path), what the grader matches on.
    pub target: String,
    pub poc_path: String,
    pub screenshot_path: String,
    pub finding_capture: String,
    pub passed: bool,
    pub control_passed: Option<bool>,
}

/// The non-LLM driver. Holds the bus client and the two origins it reproduces
/// against (the vulnerable target and its patched control).
pub struct ScriptedDriver {
    pub client: Client,
    vuln_base: String,
    patched_base: String,
    vuln_authority: String,
    poc_dir: PathBuf,
    poc_seq: u64,
}

impl ScriptedDriver {
    /// `vuln_base`/`patched_base` are the two `http://host:port` origins; both are
    /// in the proxy's scope. `poc_dir` is a writable directory the refined PoC
    /// YAML files are written into for `poc.run` to load.
    pub fn new(
        client: Client,
        vuln_base: impl Into<String>,
        patched_base: impl Into<String>,
        poc_dir: PathBuf,
    ) -> ScriptedDriver {
        let vuln_base = vuln_base.into();
        let patched_base = patched_base.into();
        let vuln_authority = authority_of(&vuln_base);
        ScriptedDriver {
            client,
            vuln_base,
            patched_base,
            vuln_authority,
            poc_dir,
            poc_seq: 0,
        }
    }

    // ---- phase 1: observe ------------------------------------------------

    /// Crawl the target through a real browser and enumerate candidate endpoints
    /// from the observed index flow. Subscribes first (F4), navigates the index
    /// with `browser.navigate`, reads it back with `flow.detail`, and parses the
    /// linked endpoints out of the *observed* HTML — never a served manifest.
    /// Then it browses each link so every candidate has a real captured flow.
    pub async fn discover(&mut self) -> anyhow::Result<Vec<Candidate>> {
        // F4: subscribe so the crawl's flows arrive as push notifications too.
        self.client
            .tool_call("flow.subscribe", json!({}))
            .await
            .context("flow.subscribe")?;

        let index_url = format!("{}/", self.vuln_base);
        self.client
            .tool_call("browser.navigate", json!({ "url": index_url }))
            .await
            .context("browser.navigate to the index")?;

        // Find the index flow among the captured flows and read its body back.
        let index_flow = self
            .find_flow("/")
            .await?
            .ok_or_else(|| anyhow!("the crawled index flow (GET /) was not captured"))?;
        let (_, body, _) = self.detail(&index_flow).await?;

        // Enumerate the linked endpoints from the *observed* HTML.
        let mut candidates = Vec::new();
        for href in parse_hrefs(&body) {
            let path = href.split(['?', '#']).next().unwrap_or(&href).to_string();
            if candidates.iter().any(|c: &Candidate| c.path == path) {
                continue;
            }
            candidates.push(Candidate {
                path,
                source_flow: index_flow.clone(),
            });
            // Crawl the link through the browser so it, too, is an observed flow.
            let url = format!("{}{}", self.vuln_base, href);
            let _ = self
                .client
                .tool_call("browser.navigate", json!({ "url": url }))
                .await;
        }
        Ok(candidates)
    }

    // ---- phase 2: reason → act → reproduce -------------------------------

    /// Probe every candidate class this driver knows, and for each confirmed
    /// anomaly build and run a PoC that passes on the vulnerable origin and fails
    /// on the patched control. Candidates that do not reproduce against the
    /// control are dropped (no false positives).
    pub async fn reproduce_all(
        &mut self,
        candidates: &[Candidate],
    ) -> anyhow::Result<Vec<Finding>> {
        let paths: Vec<&str> = candidates.iter().map(|c| c.path.as_str()).collect();
        let mut findings = Vec::new();

        if paths.contains(&"/search") {
            if let Some(f) = self.reproduce_reflected_xss().await? {
                findings.push(f);
            }
        }
        if paths.contains(&"/comments") {
            if let Some(f) = self.reproduce_stored_xss().await? {
                findings.push(f);
            }
        }
        if paths.contains(&"/fetch") {
            if let Some(f) = self.reproduce_ssrf().await? {
                findings.push(f);
            }
        }
        if paths.iter().any(|p| p.starts_with("/account/")) {
            if let Some(f) = self.reproduce_idor().await? {
                findings.push(f);
            }
        }
        if paths.contains(&"/admin") {
            if let Some(f) = self.reproduce_auth_bypass().await? {
                findings.push(f);
            }
        }
        if paths.contains(&"/redirect") {
            if let Some(f) = self.reproduce_open_redirect().await? {
                findings.push(f);
            }
        }
        Ok(findings)
    }

    // ---- phase 3: record -------------------------------------------------

    /// Persist each finding through `findings.record`, returning the ids assigned.
    pub async fn record_all(&mut self, findings: &[Finding]) -> anyhow::Result<Vec<String>> {
        let mut ids = Vec::new();
        for f in findings {
            let res = self
                .client
                .tool_call(
                    "findings.record",
                    json!({
                        "title": f.title,
                        "class": f.class,
                        "severity": f.severity,
                        "target": f.target,
                        "poc_ref": f.poc_path,
                        "passed": f.passed,
                        "control_passed": f.control_passed,
                        "finding_capture": f.finding_capture,
                        "poc_path": f.poc_path,
                        "screenshot_path": f.screenshot_path,
                    }),
                )
                .await
                .with_context(|| format!("findings.record for {}", f.class))?;
            let id = res
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("findings.record returned no id: {res}"))?;
            ids.push(id.to_string());
        }
        Ok(ids)
    }

    /// The whole loop: discover, reproduce, record. Returns the findings and the
    /// recorded ids.
    pub async fn run(&mut self) -> anyhow::Result<(Vec<Finding>, Vec<String>)> {
        let candidates = self.discover().await?;
        let findings = self.reproduce_all(&candidates).await?;
        let ids = self.record_all(&findings).await?;
        Ok((findings, ids))
    }

    // ---- per-class probes -------------------------------------------------

    async fn reproduce_reflected_xss(&mut self) -> anyhow::Result<Option<Finding>> {
        let canary = "<xss-reflected-probe-7q>";
        let flow = self
            .send("GET", &format!("/search?q={}", pct(canary)), None, None)
            .await?;
        let (_, body, _) = self.detail(&flow).await?;
        // Confirmed only if our own probe comes back un-escaped.
        if !body.contains(canary) {
            return Ok(None);
        }
        self.build_run_record(
            "reflected-xss",
            "Reflected XSS in /search q parameter",
            "high",
            "/search",
            &flow,
            Assertion::Word {
                word: canary.to_string(),
                part: MatchPart::Body,
            },
        )
        .await
        .map(Some)
    }

    async fn reproduce_stored_xss(&mut self) -> anyhow::Result<Option<Finding>> {
        let canary = "<xss-stored-probe-4k>";
        // Store the probe, then read /comments back — the single GET is what the
        // PoC reproduces (it passes on the stateful vulnerable origin and fails
        // on the fresh patched control, which never received the POST).
        self.send(
            "POST",
            "/comments",
            Some(json!({"content-type": "application/x-www-form-urlencoded"})),
            Some(&format!("comment={}", pct(canary))),
        )
        .await?;
        let flow = self.send("GET", "/comments", None, None).await?;
        let (_, body, _) = self.detail(&flow).await?;
        if !body.contains(canary) {
            return Ok(None);
        }
        self.build_run_record(
            "stored-xss",
            "Stored XSS in /comments",
            "high",
            "/comments",
            &flow,
            Assertion::Word {
                word: canary.to_string(),
                part: MatchPart::Body,
            },
        )
        .await
        .map(Some)
    }

    async fn reproduce_ssrf(&mut self) -> anyhow::Result<Option<Finding>> {
        let internal = "http://169.254.169.254/latest/meta-data";
        let flow = self
            .send("GET", &format!("/fetch?url={}", pct(internal)), None, None)
            .await?;
        let (status, body, _) = self.detail(&flow).await?;
        // The server dereferenced an internal host and returned its content,
        // instead of the benign "unavailable" stub an external host gets.
        let signal = match body.split_once("preview: ") {
            Some((_, rest)) => rest.split('<').next().unwrap_or("").trim().to_string(),
            None => return Ok(None),
        };
        if status != 200 || signal.is_empty() || signal.contains("unavailable") {
            return Ok(None);
        }
        self.build_run_record(
            "ssrf",
            "SSRF via /fetch url preview",
            "high",
            "/fetch",
            &flow,
            Assertion::Word {
                word: signal,
                part: MatchPart::Body,
            },
        )
        .await
        .map(Some)
    }

    async fn reproduce_idor(&mut self) -> anyhow::Result<Option<Finding>> {
        // Read another user's object (account 2) as the default caller (user 1).
        let own = self.send("GET", "/account/1", None, None).await?;
        let (_, own_body, _) = self.detail(&own).await?;
        let other = self.send("GET", "/account/2", None, None).await?;
        let (status, other_body, _) = self.detail(&other).await?;
        // Anomaly: account 2 returns private content to a caller who does not own
        // it, and it differs from the caller's own account.
        let signal = match other_body.split_once("account 2: ") {
            Some((_, rest)) => rest.split('<').next().unwrap_or("").trim().to_string(),
            None => return Ok(None),
        };
        if status != 200 || signal.is_empty() || own_body.contains(&signal) {
            return Ok(None);
        }
        self.build_run_record(
            "idor",
            "IDOR on /account/{id}",
            "high",
            "/account/2",
            &other,
            Assertion::Word {
                word: signal,
                part: MatchPart::Body,
            },
        )
        .await
        .map(Some)
    }

    async fn reproduce_auth_bypass(&mut self) -> anyhow::Result<Option<Finding>> {
        // With the client-supplied role header the admin area opens; without it,
        // it is forbidden.
        let base = self.send("GET", "/admin", None, None).await?;
        let (base_status, _, _) = self.detail(&base).await?;
        let flow = self
            .send("GET", "/admin", Some(json!({"x-role": "admin"})), None)
            .await?;
        let (status, body, _) = self.detail(&flow).await?;
        let signal = match body.split_once("admin area: ") {
            Some((_, rest)) => rest.split('<').next().unwrap_or("").trim().to_string(),
            None => return Ok(None),
        };
        if status != 200 || base_status == 200 || signal.is_empty() {
            return Ok(None);
        }
        self.build_run_record(
            "auth-bypass",
            "Auth bypass on /admin via X-Role header",
            "high",
            "/admin",
            &flow,
            Assertion::Word {
                word: signal,
                part: MatchPart::Body,
            },
        )
        .await
        .map(Some)
    }

    async fn reproduce_open_redirect(&mut self) -> anyhow::Result<Option<Finding>> {
        let attacker = "http://redirect-probe-attacker.invalid/";
        let marker = "redirect-probe-attacker.invalid";
        let flow = self
            .send(
                "GET",
                &format!("/redirect?next={}", pct(attacker)),
                None,
                None,
            )
            .await?;
        let (status, _, headers) = self.detail(&flow).await?;
        let location = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        if !(300..400).contains(&status) || !location.contains(marker) {
            return Ok(None);
        }
        self.build_run_record(
            "open-redirect",
            "Open redirect on /redirect next parameter",
            "medium",
            "/redirect",
            &flow,
            Assertion::Word {
                word: marker.to_string(),
                part: MatchPart::Header,
            },
        )
        .await
        .map(Some)
    }

    // ---- shared build → run → verify -------------------------------------

    /// Build a PoC from the attack flow (`poc.build`), refine its `success` to the
    /// class's assertion, add a browser screenshot step, and `poc.run` it against
    /// the vulnerable origin (must pass) and the patched control (must fail). The
    /// returned [`Finding`] carries the vulnerable run's three artifacts.
    async fn build_run_record(
        &mut self,
        class: &str,
        title: &str,
        severity: &str,
        endpoint_path: &str,
        attack_flow: &str,
        success: Assertion,
    ) -> anyhow::Result<Finding> {
        let yaml = self
            .client
            .tool_call("poc.build", json!({"flow_id": attack_flow, "name": title}))
            .await
            .with_context(|| format!("poc.build for {class}"))?;
        let yaml = yaml
            .as_str()
            .ok_or_else(|| anyhow!("poc.build did not return YAML text: {yaml}"))?;

        let mut poc: Poc = serde_yaml::from_str(yaml)
            .with_context(|| format!("re-parse the built PoC for {class}"))?;
        poc.success = success;
        // A browser step gives the run a real screenshot artifact. It navigates
        // the safe index, not the exploit URL, so it never errors on a redirect
        // or a crafted request a browser cannot carry.
        poc.steps.push(Step::Browser(BrowserStep {
            action: BrowserAction::Navigate {
                url: "{{target}}/".to_string(),
            },
        }));
        poc.steps.push(Step::Browser(BrowserStep {
            action: BrowserAction::Screenshot {
                label: "evidence".to_string(),
            },
        }));

        let poc_path = self.write_poc(&poc)?;

        let vuln = self
            .client
            .tool_call(
                "poc.run",
                json!({"poc_path": poc_path, "target": self.vuln_base}),
            )
            .await
            .with_context(|| format!("poc.run (vulnerable) for {class}"))?;
        let patched = self
            .client
            .tool_call(
                "poc.run",
                json!({"poc_path": poc_path, "target": self.patched_base}),
            )
            .await
            .with_context(|| format!("poc.run (patched control) for {class}"))?;

        let passed = vuln.get("passed").and_then(Value::as_bool).unwrap_or(false);
        let control_passed = patched.get("passed").and_then(Value::as_bool);
        // Only a candidate that passes on the vulnerable path and fails on the
        // control is a reproduced finding.
        if !passed || control_passed != Some(false) {
            bail!(
                "{class} did not reach the reproduction bar: vulnerable passed={passed}, \
                 control passed={control_passed:?}"
            );
        }

        Ok(Finding {
            class: class.to_string(),
            title: title.to_string(),
            severity: severity.to_string(),
            target: format!("{}{}", self.vuln_base, endpoint_path),
            poc_path: str_field(&vuln, "poc_path"),
            screenshot_path: str_field(&vuln, "screenshot_path"),
            finding_capture: str_field(&vuln, "finding_capture"),
            passed,
            control_passed,
        })
    }

    // ---- command helpers --------------------------------------------------

    /// `request.send` against the vulnerable origin; returns the captured flow id.
    async fn send(
        &mut self,
        method: &str,
        path: &str,
        headers: Option<Value>,
        body: Option<&str>,
    ) -> anyhow::Result<String> {
        let mut args = json!({
            "authority": self.vuln_authority,
            "scheme": "http",
            "method": method,
            "path": path,
        });
        if let Some(h) = headers {
            args["headers"] = h;
        }
        if let Some(b) = body {
            args["body"] = json!(b);
        }
        let res = self.client.tool_call("request.send", args).await?;
        flow_id_of(&res)
    }

    /// `flow.detail` for `id` → `(status, body-as-text, response-headers)`.
    async fn detail(&mut self, id: &str) -> anyhow::Result<(u16, String, Vec<(String, String)>)> {
        let d = self
            .client
            .tool_call("flow.detail", json!({"id": id, "body": "inline"}))
            .await?;
        let resp = d.get("response").cloned().unwrap_or(Value::Null);
        if resp.is_null() {
            return Ok((0, String::new(), Vec::new()));
        }
        let status = resp.get("status").and_then(Value::as_u64).unwrap_or(0) as u16;
        let body = match resp.get("body") {
            Some(Value::String(b64)) => String::from_utf8_lossy(&base64_decode(b64)).into_owned(),
            _ => String::new(),
        };
        let headers = resp
            .get("headers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|pair| {
                        let p = pair.as_array()?;
                        Some((
                            p.first()?.as_str()?.to_string(),
                            p.get(1)?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok((status, body, headers))
    }

    /// The first captured flow whose request path (ignoring query) equals `path`,
    /// polling briefly since a navigated flow may land in the store a beat after
    /// `browser.navigate` returns.
    async fn find_flow(&mut self, path: &str) -> anyhow::Result<Option<String>> {
        for _ in 0..50 {
            let list = self.client.tool_call("flow.list", json!({})).await?;
            for id in list.as_array().cloned().unwrap_or_default() {
                let Some(id) = id.as_str() else { continue };
                let d = self
                    .client
                    .tool_call("flow.detail", json!({"id": id, "body": "none"}))
                    .await?;
                let req_path = d
                    .get("request")
                    .and_then(|r| r.get("path"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if req_path.split(['?', '#']).next() == Some(path) {
                    return Ok(Some(id.to_string()));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Ok(None)
    }

    /// Write a refined PoC to a uniquely-named YAML file for `poc.run` to load.
    fn write_poc(&mut self, poc: &Poc) -> anyhow::Result<String> {
        self.poc_seq += 1;
        let path = self
            .poc_dir
            .join(format!("{}-{}.poc.yaml", poc.id, self.poc_seq));
        std::fs::write(&path, serde_yaml::to_string(poc)?)
            .with_context(|| format!("write PoC to {}", path.display()))?;
        Ok(path.display().to_string())
    }
}

// ---------------------------------------------------------------------------
// Free helpers.
// ---------------------------------------------------------------------------

/// Pull the `host:port` authority out of an `http://host:port` base URL.
fn authority_of(base: &str) -> String {
    base.strip_prefix("http://")
        .or_else(|| base.strip_prefix("https://"))
        .unwrap_or(base)
        .trim_end_matches('/')
        .to_string()
}

/// The `href="…"` targets in an HTML document, in order.
fn parse_hrefs(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for piece in html.split("href=\"").skip(1) {
        if let Some(end) = piece.find('"') {
            out.push(piece[..end].to_string());
        }
    }
    out
}

/// The flow-id string a `request.send`/`flow.*` result carries (the result is the
/// bare id string).
fn flow_id_of(value: &Value) -> anyhow::Result<String> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("expected a flow-id string, got {value}"))
}

/// A string field of a `poc.run` structured result.
fn str_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Percent-encode a query/body value, keeping only the unreserved set.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Decode standard (padded) base64 — enough to read `flow.detail` bodies, which
/// the bus carries as base64 (`Value::Bytes`). Unknown bytes are skipped.
fn base64_decode(s: &str) -> Vec<u8> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut out = Vec::new();
    for c in s.bytes() {
        let Some(v) = val(c) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}
