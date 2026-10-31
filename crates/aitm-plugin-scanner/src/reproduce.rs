//! Reproduce + record: turn a confirmed injection into a parameterized PoC
//! (`build_poc`) and persist a `FindingRecord` to the configured findings
//! store (`record_finding`).
//!
//! `build_poc` builds the PoC from the *mutated* request — the captured request
//! with the payload applied at the injection point — so replaying the PoC sends
//! the payload and can trigger `CheckDefinition::success_assertion`, the exact
//! assertion the live `confirm` judged the hit against. A recorded PoC and the
//! inject engine's own notion of "triggered" can therefore never drift apart.
//!
//! A PoC is shareable, so it must never carry a credential from the captured
//! request. [`StdPocBuilder`] masks credential headers and runs a text scrub
//! over the step's URL and body — a scrub that erases the inject payload at a
//! secret-named point and corrupts a JSON body — so `build_poc` re-derives the
//! URL and body from the mutated request and scrubs them, and the rest of what
//! it copies, itself (see `Scrubber`): every secret-named
//! header, query parameter, form field and JSON key becomes a required `{{var}}`
//! placeholder the runner must be given at run time, and every other value is
//! passed through `scrub_embedded` — [`aitm_core::redact::scrub_text`] plus the
//! same widened name vocabulary ([`is_secret_name`]) the name scrub uses, so a
//! credential embedded in an innocuously named value cannot slip past a
//! narrower list. `record_finding` is a thin
//! wrapper over [`aitm_findings::DiskFindingStore`]: the store itself scrubs
//! `title`/`notes` of credential material before anything reaches disk, and the
//! record's `target` is scrubbed here.

use std::collections::HashSet;

use aitm_core::redact::scrub_text;
use aitm_core::{Body, CommandHost, HttpFlow, HttpRequest};
use aitm_findings::{DiskFindingStore, FindingRecord, FindingStore};
use aitm_poc::{
    HttpStep, Poc, PocBuilder, PocInfo, PocSpec, Severity, StdPocBuilder, Step, Variable,
};

use crate::checks::{CheckDefinition, Payload, CLASS_OPEN_REDIRECT, CLASS_REFLECTED_XSS};
use crate::crawl::strip_userinfo;
use crate::discover::{is_secret_name, InjectionPoint, EXTRA_SECRET_NEEDLES};

/// Characters of the (network-supplied) injection-point name that feed the PoC
/// name and, through its slug, the PoC id. Bounded so the id always fits
/// `aitm_poc`'s 64-character limit: `<class> via <name>` is at most
/// `13 + 5 + 32` characters.
const MAX_POINT_NAME_CHARS: usize = 32;

/// Characters kept of a header / parameter name when it becomes a variable name.
const MAX_VAR_NAME_CHARS: usize = 48;

/// Distinct secret-named variables one PoC may declare. A hostile captured body
/// can carry a huge number of distinct `tokenN=` keys; past this many, every
/// further secret folds into the single [`CATCH_ALL_VAR`] instead of minting a
/// variable each (so a PoC carries at most `MAX_SECRET_VARS + 1` secret
/// variables, plus `target`).
const MAX_SECRET_VARS: usize = 64;

/// The one variable every secret past [`MAX_SECRET_VARS`] shares. Not a secret
/// name itself, so no real key can claim it before the cap is reached.
const CATCH_ALL_VAR: &str = "redacted";

/// Total percent-decode iterations applied to a form value before it is
/// scrubbed: the first is `form_urlencoded`'s own parse, the rest catch a secret
/// that was encoded more than once (`next=%252Fcb%253Fsid%253D…`).
const MAX_DECODE_PASSES: usize = 3;

/// The first `max` characters of `s`.
fn cap_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// The request's URL with its concrete `scheme://authority` replaced by
/// `{{target}}` — the same parameterization [`StdPocBuilder`] applies when the
/// `target` variable is declared, so the PoC reproduces against any host. Path
/// and query are untouched (the caller scrubs them).
fn target_url(request: &HttpRequest) -> String {
    let url = format!("{}://{}{}", request.scheme, request.authority, request.path);
    let prefix = format!("{}://{}", request.scheme, request.authority);
    url.replacen(&prefix, "{{target}}", 1)
}

/// A buffered, non-empty request body as text (invalid UTF-8 replaced, never an
/// error); `None` for no body or one still streaming — what [`StdPocBuilder`]
/// puts in a step.
fn body_text(body: &Body) -> Option<String> {
    match body {
        Body::Bytes(bytes) if !bytes.is_empty() => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        _ => None,
    }
}

/// The severity a built PoC carries for `class`: reflected-XSS is `Medium`,
/// open-redirect is `Low`. `None` for a class this mapping does not cover, so
/// [`build_poc`] chooses the default instead of this function inventing one; a
/// test pins that every `CheckDefinition::registered_classes` entry is covered.
fn severity_for(class: &str) -> Option<Severity> {
    match class {
        CLASS_REFLECTED_XSS => Some(Severity::Medium),
        CLASS_OPEN_REDIRECT => Some(Severity::Low),
        _ => None,
    }
}

/// Build a reproducible, credential-free PoC for one confirmed
/// `(point, payload)` hit.
///
/// The PoC is built from a clone of `flow` whose request has `payload` applied
/// at `point` (`crate::inject::mutate_request`), so the step carries the
/// payload and replaying it can satisfy `success`. `success` is `def`'s own
/// confirming assertion for `payload` — never re-derived. Declaring the
/// `target` variable up front makes `StdPocBuilder` replace the flow's concrete
/// scheme+authority with `{{target}}` in the step URL, so the PoC reproduces
/// against any host, not just the one it was captured from.
///
/// Errors when `point` is no longer present in `flow`'s request.
pub fn build_poc(
    flow: &HttpFlow,
    def: &CheckDefinition,
    point: &InjectionPoint,
    payload: &Payload,
) -> anyhow::Result<Poc> {
    let point_name = cap_chars(&point.name, MAX_POINT_NAME_CHARS);
    let request =
        crate::inject::mutate_request(&flow.request, point, &payload.value).ok_or_else(|| {
            anyhow::anyhow!(
                "build_poc: injection point `{point_name}` is not present in the flow's request"
            )
        })?;
    let mut mutated = flow.clone();
    mutated.request = request;

    let spec = PocSpec {
        info: PocInfo {
            name: format!("{} via {point_name}", def.class),
            // An unmapped class (none exists today: a test pins every
            // registered class) is `Info` rather than an invented severity.
            severity: severity_for(def.class).unwrap_or(Severity::Info),
            references: Vec::new(),
            tags: vec![def.class.to_string()],
            cwe: None,
            description: None,
            author: None,
            metadata: None,
        },
        variables: vec![Variable {
            name: "target".to_string(),
            default: None,
            description: "Base URL of the target".to_string(),
            required: true,
        }],
        success: def.success_assertion(payload),
    };
    let mut poc = StdPocBuilder.build(&mutated, spec)?;

    let mut scrubber = Scrubber::new(&payload.value);
    for step in &mut poc.steps {
        if let Step::Http(http) = step {
            scrubber.scrub_step(http, &mutated.request);
        }
    }
    // A name the builder already declared (a credential header it templated) is
    // not declared twice. O(1) per secret: a linear scan here would be quadratic
    // in the number of secret-named keys the captured request controls.
    let mut declared: HashSet<String> = poc.variables.iter().map(|v| v.name.clone()).collect();
    for var in scrubber.secrets {
        if declared.insert(var.name.clone()) {
            poc.variables.push(var);
        }
    }
    Ok(poc)
}

/// Strips request credentials out of a built [`HttpStep`].
///
/// Three layers, outermost first:
/// 1. a header, query parameter, form field or JSON key whose *name* reads as a
///    secret ([`is_secret_name`]) has its value replaced by a `{{var}}`
///    placeholder, and the variable is recorded in `secrets` (required, no
///    default) so the runner must be handed the credential at run time;
/// 2. every other value is decoded (repeatedly, for a form value) and passed
///    through [`scrub_embedded`], which catches a credential embedded in an
///    innocuously named value (`next=%2Fcb%3Fsid%3D…`, `X-Return-To: …?jwt=…`,
///    `Bearer …`) under the *same* name vocabulary layer 1 uses;
/// 3. a body that is neither a form nor JSON is passed through
///    [`scrub_embedded`] whole, and a `Referer` / `Referrer` header is cut back
///    to origin + path first (a PoC does not need its query).
///
/// `scrub_embedded` is applied per decoded component, never over the finished
/// string: a whole-string pass would corrupt the `{{var}}` placeholders
/// (`access_token={{access_token}}` reads as a `key=value` credential) and mask
/// the injected payload at a secret-named point.
///
/// `payload` is the scanner's own inert constant, never a request secret, so a
/// value equal to it is left alone — a redirect parameter named `return_token`
/// must still carry the payload or the PoC could not reproduce.
///
/// Distinct secret variables are tracked in `seen` (O(1) dedupe) and capped at
/// [`MAX_SECRET_VARS`]; see [`Scrubber::placeholder`].
struct Scrubber<'a> {
    payload: &'a str,
    secrets: Vec<Variable>,
    /// Names already declared in `secrets`.
    seen: HashSet<String>,
}

impl<'a> Scrubber<'a> {
    fn new(payload: &'a str) -> Self {
        Self {
            payload,
            secrets: Vec::new(),
            seen: HashSet::new(),
        }
    }

    /// Scrub `step`, the [`StdPocBuilder`] step built from `request` (the
    /// mutated request).
    ///
    /// The step's `url` and `body` are *re-derived from `request`*, not read
    /// from `step`: the builder has already run [`scrub_text`] over both, and
    /// that text pass is unsafe here. It reads `return_token=<payload>` as a
    /// credential and erases the injected payload, and its `Bearer\s+\S+` rule
    /// swallows the closing `"}` of a JSON string value, leaving a body no JSON
    /// parser accepts. Re-deriving the two lets this scrubber do it
    /// structurally instead (payload exempt, JSON kept valid). The headers are
    /// the builder's own — it has already placeholdered the credential ones —
    /// and are scrubbed further below.
    fn scrub_step(&mut self, step: &mut HttpStep, request: &HttpRequest) {
        let content_type = request
            .headers
            .get("content-type")
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        step.url = self.scrub_url(&target_url(request));
        for (name, value) in &mut step.headers {
            *value = if is_secret_name(name) {
                self.placeholder(name)
            } else if name.eq_ignore_ascii_case("referer") || name.eq_ignore_ascii_case("referrer")
            {
                // A PoC does not need the Referer's query (or fragment), and it
                // is exactly where a session id rides along: keep origin + path.
                scrub_embedded(origin_and_path(value))
            } else {
                scrub_embedded(value)
            };
        }
        step.body = body_text(&request.body).map(|body| self.scrub_body(&body, &content_type));
    }

    /// The `{{var}}` placeholder for a redacted `key`, recording its variable.
    ///
    /// Dedupe is a `HashSet` lookup, not a scan of `secrets`. Once
    /// [`MAX_SECRET_VARS`] distinct names are declared, a *new* name reuses the
    /// single [`CATCH_ALL_VAR`] placeholder instead of minting a variable — an
    /// already-declared name still gets its own placeholder back.
    fn placeholder(&mut self, key: &str) -> String {
        let mut name = secret_var_name(key);
        if !self.seen.contains(&name) && self.secrets.len() >= MAX_SECRET_VARS {
            name = CATCH_ALL_VAR.to_string();
        }
        if self.seen.insert(name.clone()) {
            let description = if name == CATCH_ALL_VAR {
                format!(
                    "Credentials redacted from the captured request beyond the first {MAX_SECRET_VARS} distinct names (not stored in the PoC)"
                )
            } else {
                format!(
                    "Credential redacted from the captured request: `{name}` (not stored in the PoC)"
                )
            };
            self.secrets.push(Variable {
                name: name.clone(),
                default: None,
                description,
                required: true,
            });
        }
        format!("{{{{{name}}}}}")
    }

    fn scrub_url(&mut self, url: &str) -> String {
        match url.split_once('?') {
            Some((base, query)) => format!("{}?{}", scrub_text(base), self.scrub_pairs(query)),
            None => scrub_text(url),
        }
    }

    /// Scrub a `k=v&k=v` string (a query string or a form body), preserving the
    /// order and the parameters themselves.
    fn scrub_pairs(&mut self, input: &str) -> String {
        let mut out = Vec::new();
        for segment in input.split('&').filter(|s| !s.is_empty()) {
            let (key, value) = url::form_urlencoded::parse(segment.as_bytes())
                .next()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .unwrap_or_default();
            if !segment.contains('=') {
                // A key-only segment is not a pair. A body labelled as a form
                // that is not one (a JSON document, a bare token) arrives here
                // whole, so its "key" is scrubbed as free text.
                out.push(form_encode(&scrub_decoded(&key)));
                continue;
            }
            let is_payload = value == self.payload;
            if is_secret_name(&key) && !value.is_empty() && !is_payload {
                out.push(format!("{}={}", form_encode(&key), self.placeholder(&key)));
                continue;
            }
            let value = if is_payload {
                value
            } else {
                scrub_decoded(&value)
            };
            out.push(format!("{}={}", form_encode(&key), form_encode(&value)));
        }
        out.join("&")
    }

    fn scrub_body(&mut self, body: &str, content_type: &str) -> String {
        if content_type.contains("application/x-www-form-urlencoded") {
            return self.scrub_pairs(body);
        }
        if content_type.contains("json") {
            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(body) {
                self.scrub_json(&mut json);
                if let Ok(text) = serde_json::to_string(&json) {
                    return text;
                }
            }
        }
        scrub_embedded(body)
    }

    fn scrub_json(&mut self, value: &mut serde_json::Value) {
        use serde_json::Value;
        match value {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let is_payload = matches!(child, Value::String(s) if s == self.payload);
                    if is_secret_name(key) && !is_payload {
                        *child = Value::String(self.placeholder(key));
                    } else {
                        self.scrub_json(child);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.scrub_json(item);
                }
            }
            Value::String(text) => {
                if text != self.payload {
                    *text = scrub_embedded(text);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

/// Mask credential material embedded in a value that is *not* itself under a
/// secret name, using the one vocabulary the name scrub uses.
///
/// [`scrub_text`] alone only knows `api_key` / `token` / `secret` / `password` /
/// `pwd` / `credential` / `cookie` and `Bearer`, so a `sid=`, `jwt=`, `csrf=`,
/// `session=` or `auth=` pair — all of which [`is_secret_name`] masks when they
/// are the *name* of a header or parameter — passed straight through when
/// embedded in a `Referer`-style or URL-valued value. This closes that gap in
/// three steps:
///
/// 1. URL userinfo is stripped ([`strip_userinfo`]: `//user:pw@host` →
///    `//host`) — first, so a `user:pw@` prefix cannot make the next steps
///    swallow the host;
/// 2. [`scrub_text`] masks its own base vocabulary;
/// 3. every `key=value` / `key: value` whose *key* contains an
///    [`EXTRA_SECRET_NEEDLES`] needle has its value replaced by `[redacted]`
///    ([`redact_needle_pairs`]).
fn scrub_embedded(text: &str) -> String {
    redact_needle_pairs(&scrub_text(&strip_userinfo(text)))
}

/// Whether `b` can be part of a `key` in a `key=value` pair.
fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

/// Whether `b` ends an unquoted value: ASCII whitespace or a pair, list or JSON
/// delimiter. A non-ASCII byte never does, so a value is over- rather than
/// under-redacted.
fn ends_value(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'&' | b';' | b',' | b'"' | b'\'' | b'}')
}

/// Whether `key` contains an [`EXTRA_SECRET_NEEDLES`] needle (ASCII
/// case-insensitive, as a substring — exactly how `discover::is_secret_name`
/// matches the same slice).
fn names_a_secret(key: &str) -> bool {
    let key = key.as_bytes();
    // No per-key allocation: this runs once per key run of a body that may be
    // megabytes long. (`windows(0)` would panic, so an empty needle is skipped.)
    EXTRA_SECRET_NEEDLES.iter().any(|needle| {
        let needle = needle.as_bytes();
        !needle.is_empty()
            && key
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle))
    })
}

/// Redact the value of every `key=value` / `key: value` pair in `text` whose key
/// reads as a secret under [`EXTRA_SECRET_NEEDLES`].
///
/// Equivalent to replacing, case-insensitively,
/// `(["']?[a-z0-9_.-]*(?:needle…)[a-z0-9_.-]*["']?[ \t]*[=:][ \t]*["']?)<value>`
/// with `${1}[redacted]`, where `<value>` is a run up to `[\s&;,"'}]` — or, when
/// it opens with a quote, everything up to the matching unescaped quote, so a
/// JSON value holding spaces is masked whole. Optional quotes around the key
/// and value make a JSON-encoded pair (`"sid":"…"`) match the way
/// `scrub_text`'s own pass does.
///
/// Written as one linear scan, not a regex: the crate carries no `regex`
/// dependency, and each key run and each value is consumed exactly once, so a
/// hostile ~10 MiB body cannot make this quadratic. An empty value is left
/// alone (nothing to leak).
fn redact_needle_pairs(text: &str) -> String {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(text.len());
    // Start of the text not yet copied into `out`.
    let mut copied = 0;
    let mut i = 0;
    while i < len {
        if !is_key_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let key_start = i;
        while i < len && is_key_byte(bytes[i]) {
            i += 1;
        }
        // `key_start..i` is all ASCII, so these are char boundaries.
        if !names_a_secret(&text[key_start..i]) {
            continue;
        }

        // key, optional closing quote, blanks, `=` or `:`, blanks, optional
        // opening quote, then the value.
        let mut j = i;
        if j < len && matches!(bytes[j], b'"' | b'\'') {
            j += 1;
        }
        while j < len && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        if j >= len || !matches!(bytes[j], b'=' | b':') {
            continue;
        }
        j += 1;
        while j < len && matches!(bytes[j], b' ' | b'\t') {
            j += 1;
        }
        let quote = match bytes.get(j) {
            Some(&q) if matches!(q, b'"' | b'\'') => {
                j += 1;
                Some(q)
            }
            _ => None,
        };
        let value_start = j;
        let value_end = match quote.and_then(|q| closing_quote(bytes, value_start, q)) {
            Some(end) => end,
            // Unquoted, or an opening quote that never closes: the plain rule.
            None => {
                let mut end = value_start;
                while end < len && !ends_value(bytes[end]) {
                    end += 1;
                }
                end
            }
        };
        if value_end == value_start {
            continue;
        }
        // `value_start` follows an ASCII byte and `value_end` precedes one (or
        // is the end of the text), so both are char boundaries.
        out.push_str(&text[copied..value_start]);
        out.push_str("[redacted]");
        copied = value_end;
        i = value_end;
    }
    out.push_str(&text[copied..]);
    out
}

/// The index of the unescaped `quote` byte that closes a quoted value starting
/// at `from`, or `None` if it never closes.
fn closing_quote(bytes: &[u8], from: usize, quote: u8) -> Option<usize> {
    let mut k = from;
    while k < bytes.len() {
        match bytes[k] {
            b'\\' => k += 2,
            b if b == quote => return Some(k),
            _ => k += 1,
        }
    }
    None
}

/// `value` with a `Referer` / `Referrer` header cut back to origin + path: the
/// query and the fragment, where a session id or token rides along, are dropped.
fn origin_and_path(value: &str) -> &str {
    let end = value.find(['?', '#']).unwrap_or(value.len());
    &value[..end]
}

/// [`scrub_embedded`] for a form value (or key-only segment) that
/// `form_urlencoded` has already decoded once. A decoded value that still
/// carries an encoded `=` / `:` is a secret hidden under a second layer of
/// encoding (`next=%252Fcb%253Fsid%253D…` decodes to `%2Fcb%3Fsid%3D…`, which no
/// `key=value` scan can see), so it is decoded again — [`MAX_DECODE_PASSES`]
/// iterations in total, counting the first.
fn scrub_decoded(decoded: &str) -> String {
    let mut text = decoded.to_string();
    for _ in 1..MAX_DECODE_PASSES {
        if !has_encoded_separator(&text) {
            break;
        }
        text = percent_decode(&text);
    }
    scrub_embedded(&text)
}

/// Whether `s` contains a percent-encoded `=` (`%3D`) or `:` (`%3A`), in either
/// hex case.
fn has_encoded_separator(s: &str) -> bool {
    s.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1] == b'3' && matches!(w[2], b'D' | b'd' | b'A' | b'a'))
}

/// Percent-decode `s`: each valid `%XX` becomes its byte; a malformed or
/// truncated sequence and every other byte (including `+`, which is a literal
/// plus here, not a space) is kept as written. Invalid UTF-8 in the result is
/// replaced, never an error.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| {
                char::from(b)
                    .to_digit(16)
                    .and_then(|d| u8::try_from(d).ok())
            };
            if let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(high * 16 + low);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `application/x-www-form-urlencoded` percent-encoding, the same serializer
/// `inject::mutate_query` writes the payload with.
fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// A template-variable name for a redacted header / parameter / key: lowercase
/// ASCII, every other character `_`, led by a letter or `_` (`X-API-Key` →
/// `x_api_key`, the same name `aitm_poc`'s builder gives its credential headers).
fn secret_var_name(key: &str) -> String {
    let mut name: String = key
        .chars()
        .take(MAX_VAR_NAME_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if !name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') {
        name.insert_str(0, "v_");
    }
    name
}

/// Persist `rec` to the configured findings store, returning its id.
///
/// Errors when no `findings.dir` is configured — the same refusal the
/// `findings.record` command gives — rather than reporting an empty id as a
/// successful record while persisting nothing. The record's `target` is scrubbed
/// (`crate::crawl::safe_target`: userinfo removed, credential material masked)
/// before it is written. [`DiskFindingStore::record`] scrubs `title`/`notes` of
/// credential material at the persistence boundary regardless of what the
/// caller put there.
pub fn record_finding(host: &CommandHost<'_>, mut rec: FindingRecord) -> anyhow::Result<String> {
    let Some(dir) = host.config().and_then(|c| c.findings.dir.clone()) else {
        anyhow::bail!("record_finding: no findings directory is configured");
    };
    rec.target = crate::crawl::safe_target(&rec.target);
    DiskFindingStore::new(dir).record(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{
        Body, Config, ConnInfo, FindingsConfig, FlowId, FlowMeta, Frontend, HeaderMap, HttpFlow,
        HttpRequest, HttpVersion, InterceptState, MemFlowStore, ProxyClient, StdGuard,
    };
    use aitm_findings::{FindingArtifacts, Reproduction};
    use futures::future::BoxFuture;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::SystemTime;

    use crate::discover::Location;

    /// A `ProxyClient` these helpers must never reach: building/recording a PoC
    /// issues no traffic.
    struct NoSendClient;

    impl ProxyClient for NoSendClient {
        fn send(&self, req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
            panic!("reproduce:: helpers must not send through the proxy client: {req:?}");
        }
    }

    /// A scratch directory, removed when dropped.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("aitm-scanner-reproduce-{}", FlowId::new()));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn conn() -> ConnInfo {
        ConnInfo {
            peer: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sni: None,
            alpn: None,
            tls: false,
            established: SystemTime::now(),
        }
    }

    fn flow_with_query(path: &str) -> HttpFlow {
        flow_with("GET", path, &[], None)
    }

    /// A captured flow with an explicit method, headers and (optional) body.
    fn flow_with(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> HttpFlow {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.set(name, value);
        }
        HttpFlow {
            id: FlowId::new(),
            request: HttpRequest {
                method: method.into(),
                scheme: "http".into(),
                authority: "target.test".into(),
                path: path.into(),
                version: HttpVersion::Http11,
                headers: map,
                body: body.map_or(Body::Empty, |b| Body::Bytes(b.as_bytes().to_vec())),
                timestamp: SystemTime::now(),
            },
            response: None,
            client_conn: conn(),
            server_conn: None,
            metadata: FlowMeta::default(),
            intercept: InterceptState::Observed,
        }
    }

    fn point(flow: &HttpFlow, location: Location, name: &str, example: &str) -> InjectionPoint {
        InjectionPoint {
            flow: flow.id,
            location,
            name: name.to_string(),
            example: example.to_string(),
        }
    }

    /// The single http step of a built PoC.
    fn http_step(poc: &Poc) -> &aitm_poc::HttpStep {
        let aitm_poc::Step::Http(step) = &poc.steps[0] else {
            panic!("the PoC carries one http step: {:?}", poc.steps);
        };
        step
    }

    /// Run `f` against a host wired with the given config (or none at all).
    fn with_host<R>(config: Option<Config>, f: impl FnOnce(&CommandHost<'_>) -> R) -> R {
        let store = MemFlowStore::new();
        let client = NoSendClient;
        let guard = StdGuard::default();
        let mut host = CommandHost::new(&store, &client, &guard, None);
        if let Some(config) = config {
            host = host.with_config(Arc::new(config));
        }
        f(&host)
    }

    fn config_with_dir(dir: &Path) -> Config {
        Config {
            findings: FindingsConfig {
                dir: Some(dir.to_path_buf()),
            },
            ..Config::default()
        }
    }

    fn base_record(id: &str) -> FindingRecord {
        FindingRecord {
            id: id.to_string(),
            title: "Reflected XSS in q".to_string(),
            class: "reflected-xss".to_string(),
            severity: Severity::High,
            target: "http://target.test/".to_string(),
            discovered_at: SystemTime::now(),
            origin: Frontend::Mcp,
            client_label: None,
            poc_ref: "reflected-xss-q".to_string(),
            reproduction: Reproduction {
                passed: true,
                control_passed: Some(false),
                run_at: SystemTime::now(),
            },
            artifacts: FindingArtifacts {
                finding_capture: FlowId::new(),
                poc_path: "poc.yaml".to_string(),
                screenshot_path: String::new(),
            },
            flows: Vec::new(),
            notes: None,
        }
    }

    #[test]
    fn build_poc_sets_success_assertion() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello");
        let point = InjectionPoint {
            flow: flow.id,
            location: Location::Query,
            name: "q".to_string(),
            example: "hello".to_string(),
        };

        let poc = build_poc(&flow, &def, &point, payload).expect("poc builds");

        assert_eq!(
            poc.success,
            def.success_assertion(payload),
            "the recorded PoC must assert exactly what `confirm` judged the hit against"
        );

        let aitm_poc::Step::Http(step) = &poc.steps[0] else {
            panic!("the PoC carries one http step: {:?}", poc.steps);
        };
        assert!(
            step.url.contains("{{target}}"),
            "the step URL must be parameterized to {{target}}: {}",
            step.url
        );

        // Round-trips via `aitm_poc`'s own serde: the crate's custom
        // `Step`/`Assertion` impls build a generic serde-data-model tree, not
        // raw YAML text, so `serde_json` (already a dependency here) exercises
        // the same code path without a new one.
        let json = serde_json::to_string(&poc).expect("poc serializes");
        let back: Poc = serde_json::from_str(&json).expect("poc deserializes");
        assert_eq!(back.success, poc.success);
    }

    /// A built PoC carries the pinned severity for its class: reflected-XSS is
    /// `Medium`, open-redirect is `Low`, and a class the mapping does not know
    /// falls back to `Info` — never a silent over-statement.
    #[test]
    fn build_poc_severity_follows_the_class_mapping() {
        let flow = flow_with_query("/search?q=hello");
        let q = point(&flow, Location::Query, "q", "hello");

        let xss = CheckDefinition::reflected_xss();
        let poc = build_poc(&flow, &xss, &q, &xss.payloads[0]).expect("xss poc builds");
        assert_eq!(poc.info.severity, Severity::Medium);

        let redirect_flow = flow_with_query("/go?next=http%3A%2F%2Fapp.test%2F");
        let next = point(
            &redirect_flow,
            Location::Redirect,
            "next",
            "http://app.test/",
        );
        let open = CheckDefinition::open_redirect();
        let poc = build_poc(&redirect_flow, &open, &next, &open.payloads[0])
            .expect("open-redirect poc builds");
        assert_eq!(poc.info.severity, Severity::Low);

        // A hand-built definition for a class no mapping covers.
        let unmapped = CheckDefinition {
            class: "not-a-registered-class",
            locations: &[Location::Query],
            payloads: vec![Payload {
                value: "aitm-unmapped".to_string(),
                marker: None,
            }],
            mode: crate::checks::AttackMode::BatteringRam,
        };
        let poc = build_poc(&flow, &unmapped, &q, &unmapped.payloads[0])
            .expect("unmapped-class poc builds");
        assert_eq!(poc.info.severity, Severity::Info);
    }

    /// Every class `checks::registered_classes` lists has a severity, so a new
    /// class cannot ship and silently build as `Info`.
    #[test]
    fn severity_mapping_covers_every_registered_class() {
        for class in CheckDefinition::registered_classes() {
            assert!(
                severity_for(class).is_some(),
                "`{class}` is registered but has no severity mapping"
            );
        }
        assert_eq!(severity_for("reflected-xss"), Some(Severity::Medium));
        assert_eq!(severity_for("open-redirect"), Some(Severity::Low));
        assert_eq!(severity_for("nope"), None);
    }

    #[test]
    fn record_round_trips() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let rec = base_record("reflected-xss-abc123de");

        let id = with_host(Some(config), |host| record_finding(host, rec.clone()))
            .expect("record_finding succeeds");
        assert_eq!(id, "reflected-xss-abc123de");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert!(stored.reproduction.passed);
        assert_eq!(stored.reproduction.control_passed, Some(false));
    }

    /// A careless caller might copy a source flow's raw `Authorization` header
    /// into free text; the store must still scrub it before it reaches disk.
    #[test]
    fn record_redacts_secret() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let mut rec = base_record("reflected-xss-secrettest");
        rec.title = "Authorization: Bearer abc123".to_string();
        rec.notes = Some("replayed request carried Authorization: Bearer abc123".to_string());

        let id =
            with_host(Some(config), |host| record_finding(host, rec)).expect("record succeeds");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert!(
            !stored.title.contains("abc123"),
            "title leaked the secret: {}",
            stored.title
        );
        assert!(
            !stored.notes.unwrap_or_default().contains("abc123"),
            "notes leaked the secret"
        );
    }

    // ---- Item 1: the PoC reproduces AND never leaks a request secret --------

    #[test]
    fn build_poc_reproduces_and_scrubs_secrets() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?access_token=QSECRET654&q=hello",
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("X-Auth-Token", "HDRSECRET456"),
                ("X-CSRF-Token", "CSRFSECRET321"),
                ("Authorization", "Bearer abc123"),
            ],
            Some("username=admin&password=PWSECRET789&q=hello"),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for secret in [
            "QSECRET654",
            "HDRSECRET456",
            "CSRFSECRET321",
            "abc123",
            "PWSECRET789",
        ] {
            assert!(
                !serialized.contains(secret),
                "the shareable PoC leaked `{secret}`: {serialized}"
            );
        }

        // It reproduces: the step carries the payload at `q`, not the benign
        // value, so replaying it can trigger the `success` assertion.
        let step = http_step(&poc);
        assert!(
            step.url.contains("q=%3Caitm-canary-0001%3E"),
            "the step URL must carry the payload at `q`: {}",
            step.url
        );
        assert!(
            !step.url.contains("q=hello"),
            "the benign value must be gone: {}",
            step.url
        );
        assert_eq!(poc.success, def.success_assertion(payload));

        // The non-secret structure survives; each secret became a placeholder.
        assert!(step.url.starts_with("{{target}}/search?"), "{}", step.url);
        assert!(
            step.url.contains("access_token={{access_token}}"),
            "{}",
            step.url
        );
        assert_eq!(
            step.body.as_deref(),
            Some("username=admin&password={{password}}&q=hello")
        );
        let header = |name: &str| {
            step.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(header("X-Auth-Token"), Some("{{x_auth_token}}"));
        assert_eq!(header("X-CSRF-Token"), Some("{{x_csrf_token}}"));
        assert_eq!(header("Authorization"), Some("{{authorization}}"));
        for var in [
            "target",
            "access_token",
            "password",
            "x_auth_token",
            "x_csrf_token",
            "authorization",
        ] {
            assert_eq!(
                poc.variables.iter().filter(|v| v.name == var).count(),
                1,
                "variable `{var}` must be declared exactly once: {:?}",
                poc.variables
            );
        }
    }

    #[test]
    fn build_poc_injects_into_a_form_body_point() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some("user=admin&password=PWSECRET789&q=hello"),
        );
        let q = point(&flow, Location::BodyParam, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("user=admin&password={{password}}&q=%3Caitm-canary-0001%3E")
        );
    }

    #[test]
    fn build_poc_scrubs_json_body_and_referer() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[
                ("Content-Type", "application/json"),
                ("Referer", "http://target.test/app?access_token=REFSECRET1"),
            ],
            Some(
                r#"{"user":"admin","password":"JSONPW1","nested":{"api_key":"JSONKEY2"},"note":"Bearer JSONBEARER3"}"#,
            ),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for secret in ["REFSECRET1", "JSONPW1", "JSONKEY2", "JSONBEARER3"] {
            assert!(
                !serialized.contains(secret),
                "leaked `{secret}`: {serialized}"
            );
        }
        let step = http_step(&poc);
        // Compare as parsed JSON, not as a byte string: serde_json's key order
        // depends on the `preserve_order` feature, which other workspace crates
        // enable, so the serialized order differs between an isolated and a
        // whole-workspace build. The structure is what matters.
        let body: serde_json::Value =
            serde_json::from_str(step.body.as_deref().expect("a json body")).expect("valid json");
        assert_eq!(
            body,
            serde_json::json!({
                "user": "admin",
                "password": "{{password}}",
                "nested": {"api_key": "{{api_key}}"},
                "note": "Bearer [redacted]",
            })
        );
        let referer = step
            .headers
            .iter()
            .find(|(n, _)| n == "Referer")
            .map(|(_, v)| v.as_str());
        // The Referer query is dropped outright (a PoC does not need it): only
        // origin + path survive, so nothing in the query can leak.
        assert_eq!(referer, Some("http://target.test/app"));
    }

    #[test]
    fn build_poc_scrubs_a_body_with_no_content_type() {
        // No declared type, so the body cannot be parsed as a form or JSON: the
        // whole-body `scrub_text` backstop still masks the credential.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[],
            Some("username=admin&password=PWSECRET789&q=hello"),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("username=admin&password=[redacted]&q=hello")
        );
    }

    #[test]
    fn secret_names_match_the_shared_and_discover_vocabulary() {
        for name in [
            "access_token",
            "X-Auth-Token",
            "X-CSRF-Token",
            "csrf",
            "PHPSESSID",
            "sessionid",
            "sid",
            "jwt",
            "Authorization",
            "password",
            "x-api-key",
        ] {
            assert!(is_secret_name(name), "`{name}` must read as a secret");
        }
        for name in ["q", "page", "username", "next", "Content-Type", "Referer"] {
            assert!(!is_secret_name(name), "`{name}` is not a secret");
        }
    }

    #[test]
    fn secret_var_names_are_template_identifiers() {
        assert_eq!(secret_var_name("X-API-Key"), "x_api_key");
        assert_eq!(secret_var_name("access_token"), "access_token");
        assert_eq!(secret_var_name("1st-token"), "v_1st_token");
        assert_eq!(secret_var_name(""), "v_");
        assert_eq!(secret_var_name("tok\u{e9}n"), "tok_n");
        assert_eq!(secret_var_name(&"t".repeat(500)).len(), MAX_VAR_NAME_CHARS);
    }

    #[test]
    fn build_poc_scrubs_secret_embedded_in_a_param_value() {
        // A redirect-style value that itself carries a credential, percent-encoded
        // the way a browser would send it: the framing a raw-text scrub cannot see.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/go?q=hello&next=%2Fcb%3Faccess_token%3DNESTED999%26x%3D1");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(!url.contains("NESTED999"), "embedded secret leaked: {url}");
        assert!(url.contains("q=%3Caitm-canary-0001%3E"), "{url}");
        assert!(
            url.contains("next=%2Fcb%3Faccess_token%3D%5Bredacted%5D%26x%3D1"),
            "{url}"
        );
    }

    #[test]
    fn build_poc_keeps_payload_at_a_secret_named_point() {
        // The scanner's own payload constant is not a secret; a redirect param
        // that happens to be named like one must still carry it, or the PoC
        // could never reproduce.
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/cb?return_token=https%3A%2F%2Fapp.example%2F&sid=ZZSECRET");
        let p = point(
            &flow,
            Location::Redirect,
            "return_token",
            "https://app.example/",
        );

        let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(
            url.contains("return_token=https%3A%2F%2Faitm-scan-sentinel.invalid%2F"),
            "the payload must survive at the secret-named point: {url}"
        );
        assert!(!url.contains("ZZSECRET"), "{url}");
        assert!(url.contains("sid={{sid}}"), "{url}");
    }

    #[test]
    fn build_poc_keeps_payload_at_a_secret_named_json_body_point() {
        // The body half of the same rule: a JSON key named like a secret that is
        // the injection point still carries the payload, the neighbouring secret
        // is masked, and the document stays valid JSON.
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/cb",
            &[("Content-Type", "application/json")],
            Some(r#"{"return_token":"https://app.example/","password":"JSONPW9"}"#),
        );
        let p = point(
            &flow,
            Location::Redirect,
            "return_token",
            "https://app.example/",
        );

        let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

        let step = http_step(&poc);
        let body: serde_json::Value =
            serde_json::from_str(step.body.as_deref().expect("a json body")).expect("valid json");
        assert_eq!(
            body,
            serde_json::json!({
                "return_token": "https://aitm-scan-sentinel.invalid/",
                "password": "{{password}}",
            })
        );
        assert_eq!(step.url, "{{target}}/cb");
    }

    #[test]
    fn build_poc_gives_a_bodyless_request_no_body() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let step = http_step(&poc);
        assert_eq!(step.body, None);
        assert!(step.url.starts_with("{{target}}/search?q="), "{}", step.url);
    }

    #[test]
    fn build_poc_errs_when_the_point_is_absent_from_the_flow() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/search?q=hello");
        let gone = point(&flow, Location::Query, "missing", "x");

        let err = build_poc(&flow, &def, &gone, payload).expect_err("no such point");

        assert!(err.to_string().contains("missing"), "{err}");
    }

    // ---- Item 9: the PoC id stays valid whatever the point is called ---------

    #[test]
    fn build_poc_caps_point_name_to_a_valid_id() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let long = "a".repeat(500);
        let flow = flow_with_query(&format!("/search?{long}=hello"));
        let p = point(&flow, Location::Query, &long, "hello");

        let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

        assert!(
            aitm_poc::runner::is_valid_poc_id(&poc.id),
            "an unbounded point name made an invalid PoC id: {:?}",
            poc.id
        );
        assert_eq!(poc.id, format!("reflected-xss-via-{}", "a".repeat(32)));
        assert_eq!(
            poc.info.name,
            format!("reflected-xss via {}", "a".repeat(32))
        );
    }

    #[test]
    fn build_poc_id_is_valid_for_hostile_point_names() {
        let def = CheckDefinition::open_redirect();
        let payload = def.payloads.first().expect("a payload");
        for name in ["../../etc/passwd", "UPPER Case \u{e9}", "---", "\u{1F600}"] {
            let enc: String = url::form_urlencoded::byte_serialize(name.as_bytes()).collect();
            let flow = flow_with_query(&format!("/x?{enc}=https%3A%2F%2Fapp.example%2F"));
            let p = point(&flow, Location::Redirect, name, "x");

            let poc = build_poc(&flow, &def, &p, payload).expect("poc builds");

            assert!(
                aitm_poc::runner::is_valid_poc_id(&poc.id),
                "name {name:?} produced invalid id {:?}",
                poc.id
            );
        }
    }

    // ---- Item 2: no findings dir is an error, and the target is scrubbed -----

    #[test]
    fn record_finding_errs_without_dir() {
        let rec = base_record("reflected-xss-nodir");
        let no_config = with_host(None, |host| record_finding(host, rec.clone()));
        assert!(no_config.is_err(), "no config: {no_config:?}");

        let default_config = with_host(Some(Config::default()), |host| record_finding(host, rec));
        let err = default_config.expect_err("default config has no findings dir");
        assert!(
            err.to_string().contains("no findings directory"),
            "the error must say why: {err}"
        );
    }

    #[test]
    fn record_scrubs_target() {
        let dir = ScratchDir::new();
        let config = config_with_dir(dir.path());
        let mut rec = base_record("reflected-xss-targetscrub");
        rec.target = "http://user:USERPW1@target.test/p?access_token=TGTSECRET2".to_string();

        let id =
            with_host(Some(config), |host| record_finding(host, rec)).expect("record succeeds");

        let stored = DiskFindingStore::new(dir.path())
            .get(&id)
            .expect("the record was persisted");
        assert_eq!(
            stored.target,
            "http://target.test/p?access_token=[redacted]"
        );
    }

    // ---- N1: the embedded-value scrub shares the name scrub's vocabulary -----

    /// A header value of `step`, by case-insensitive name.
    fn header_of<'a>(step: &'a aitm_poc::HttpStep, name: &str) -> Option<&'a str> {
        step.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The reviewer's measured leak: every one of these names is in the shared
    /// name vocabulary, but none is in `scrub_text`'s, so a `Referer` carrying
    /// them was emitted verbatim.
    #[test]
    fn build_poc_drops_the_referer_query_and_leaks_no_session_id() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "GET",
            "/search?access_token=QSECRET654&q=hello",
            &[
                (
                    "Referer",
                    "http://t/app?PHPSESSID=REFPHP1&sid=REFSID2&jwt=REFJWT3&auth=REFAUTH4&session=REFSESS5&csrf=REFCSRF6",
                ),
                ("Referrer", "http://t/cb#sid=FRAGSID7"),
            ],
            None,
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for leaked in [
            "REFPHP1",
            "REFSID2",
            "REFJWT3",
            "REFAUTH4",
            "REFSESS5",
            "REFCSRF6",
            "FRAGSID7",
            "QSECRET654",
        ] {
            assert!(
                !serialized.contains(leaked),
                "the shareable PoC leaked `{leaked}`: {serialized}"
            );
        }
        let step = http_step(&poc);
        // Only origin + path survive: the query (and a fragment) is gone.
        assert_eq!(header_of(step, "Referer"), Some("http://t/app"));
        assert_eq!(header_of(step, "Referrer"), Some("http://t/cb"));
        // Controls: a token-named param is still masked and the PoC still
        // carries the payload, so it reproduces.
        assert!(
            step.url.contains("access_token={{access_token}}"),
            "{}",
            step.url
        );
        assert!(
            step.url.contains("q=%3Caitm-canary-0001%3E"),
            "the step URL must carry the payload at `q`: {}",
            step.url
        );
        assert_eq!(poc.success, def.success_assertion(payload));
    }

    /// The needle layer on its own: a non-`Referer` header whose name is not a
    /// secret, so only the embedded-value scrub can mask what it carries.
    #[test]
    fn build_poc_scrubs_session_ids_embedded_in_a_non_secret_header() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "GET",
            "/search?q=hello",
            &[(
                "X-Return-To",
                "http://t/cb?PHPSESSID=HDRPHP1&sid=HDRSID2&jwt=HDRJWT3&auth=HDRAUTH4&session=HDRSESS5&csrf=HDRCSRF6&access_token=HDRTOK7&page=2",
            )],
            None,
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            header_of(http_step(&poc), "X-Return-To"),
            Some(
                "http://t/cb?PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]&access_token=[redacted]&page=2"
            )
        );
    }

    #[test]
    fn build_poc_scrubs_session_ids_embedded_in_a_redirect_param() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query(
            "/go?q=hello&next=%2Fcb%3Fsid%3DNEXTSID%26jwt%3DNEXTJWT%26session%3DNEXTSESS",
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        for leaked in ["NEXTSID", "NEXTJWT", "NEXTSESS"] {
            assert!(!url.contains(leaked), "embedded `{leaked}` leaked: {url}");
        }
        assert!(
            url.contains(
                "next=%2Fcb%3Fsid%3D%5Bredacted%5D%26jwt%3D%5Bredacted%5D%26session%3D%5Bredacted%5D"
            ),
            "{url}"
        );
        // Control: the payload is still injected.
        assert!(url.contains("q=%3Caitm-canary-0001%3E"), "{url}");
    }

    #[test]
    fn build_poc_scrubs_session_ids_in_a_json_string_leaf() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[("Content-Type", "application/json")],
            Some(r#"{"redirect":"http://t/cb?sid=JSONSID1&jwt=JSONJWT2","msg":"csrf: JSONCSRF3"}"#),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let body: serde_json::Value =
            serde_json::from_str(http_step(&poc).body.as_deref().expect("a json body"))
                .expect("valid json");
        assert_eq!(
            body,
            serde_json::json!({
                "redirect": "http://t/cb?sid=[redacted]&jwt=[redacted]",
                "msg": "csrf: [redacted]",
            })
        );
    }

    #[test]
    fn build_poc_scrubs_session_ids_in_an_untyped_body() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[],
            Some("username=admin&sid=BODYSID1&jwt=BODYJWT2"),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("username=admin&sid=[redacted]&jwt=[redacted]")
        );
    }

    /// A regression guard: the `Cookie` header is masked by name (it was before
    /// this change too), and a session cookie value never reaches the PoC.
    #[test]
    fn build_poc_masks_a_session_cookie_header() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "GET",
            "/search?q=hello",
            &[("Cookie", "PHPSESSID=COOKIESID1; theme=dark")],
            None,
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        assert!(!serialized.contains("COOKIESID1"), "{serialized}");
        assert_eq!(header_of(http_step(&poc), "Cookie"), Some("{{cookie}}"));
    }

    #[test]
    fn scrub_embedded_masks_every_shared_vocabulary_name() {
        assert_eq!(
            scrub_embedded("PHPSESSID=A&sid=B&jwt=C&auth=D&session=E&csrf=F&page=2"),
            "PHPSESSID=[redacted]&sid=[redacted]&jwt=[redacted]&auth=[redacted]&session=[redacted]&csrf=[redacted]&page=2"
        );
        // `key: value` framing, with and without spacing.
        assert_eq!(scrub_embedded("X-CSRF: abc"), "X-CSRF: [redacted]");
        assert_eq!(scrub_embedded("sid:abc"), "sid:[redacted]");
        assert_eq!(scrub_embedded("sid = abc"), "sid = [redacted]");
        // JSON framing, including a quoted value that holds spaces.
        assert_eq!(
            scrub_embedded(r#"{"sid":"S1","jwt": "J2", "n":1}"#),
            r#"{"sid":"[redacted]","jwt": "[redacted]", "n":1}"#
        );
        assert_eq!(
            scrub_embedded(r#"{"session":"a b c","n":1}"#),
            r#"{"session":"[redacted]","n":1}"#
        );
        // The base vocabulary still applies (one pass, two vocabularies).
        assert_eq!(
            scrub_embedded("access_token=T&sid=S"),
            "access_token=[redacted]&sid=[redacted]"
        );
        // URL userinfo is stripped.
        assert_eq!(
            scrub_embedded("go to http://user:pw@host/p?x=1"),
            "go to http://host/p?x=1"
        );
    }

    /// One vocabulary: the embedded-value scrub is built from the very slice
    /// `is_secret_name` matches, so a needle added there is masked here too.
    #[test]
    fn scrub_embedded_covers_every_extra_secret_needle() {
        for needle in EXTRA_SECRET_NEEDLES {
            assert!(is_secret_name(needle), "`{needle}` is a secret name");
            assert_eq!(
                scrub_embedded(&format!("x_{needle}_y=V1&z=2")),
                format!("x_{needle}_y=[redacted]&z=2")
            );
            let upper = needle.to_ascii_uppercase();
            assert_eq!(
                scrub_embedded(&format!("{upper}: V1")),
                format!("{upper}: [redacted]")
            );
        }
    }

    #[test]
    fn scrub_embedded_handles_quotes_and_escapes() {
        // An escaped quote inside a quoted value does not end it early.
        assert_eq!(
            scrub_embedded(r#"{"sid":"a\"b c","n":1}"#),
            r#"{"sid":"[redacted]","n":1}"#
        );
        // Single quotes, and a quote with blanks around the separator.
        assert_eq!(
            scrub_embedded("{'jwt' : 'a b','n':1}"),
            "{'jwt' : '[redacted]','n':1}"
        );
        // An opening quote that never closes falls back to the plain rule: the
        // value still ends at `&`, and the rest of the text survives.
        assert_eq!(scrub_embedded("sid=\"abc&x=1"), "sid=\"[redacted]&x=1");
        // An empty quoted value has nothing to redact.
        assert_eq!(scrub_embedded(r#"{"sid":"","n":1}"#), r#"{"sid":"","n":1}"#);
    }

    #[test]
    fn scrub_embedded_leaves_innocent_text_and_empty_values_alone() {
        for untouched in [
            "page=2&q=hello",
            "sid=&x=1",
            "session expired",
            "auth",
            "",
            "plain text with no pairs",
        ] {
            assert_eq!(scrub_embedded(untouched), untouched);
        }
        // Over-matching is deliberate (a leaked session id costs more than a
        // redacted `subsidiary`), as in `discover::is_secret_name`.
        assert_eq!(scrub_embedded("subsidiary=acme"), "subsidiary=[redacted]");
        // Non-ASCII around a match never panics on a char boundary.
        assert_eq!(
            scrub_embedded("h\u{e9}llo sid=w\u{f6}rld \u{fc}n\u{ef}"),
            "h\u{e9}llo sid=[redacted] \u{fc}n\u{ef}"
        );
    }

    // ---- M1: secret variables are deduped in O(1) and bounded ---------------

    #[test]
    fn build_poc_bounds_the_secret_variables_a_hostile_request_can_mint() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let mut path = String::from("/search?q=hello");
        for i in 0..200 {
            path.push_str(&format!("&token{i}=BULK{i:03}SECRET"));
        }
        // A name declared before the cap is hit keeps its own placeholder after
        // it; only a *new* name past the cap folds into the catch-all.
        path.push_str("&token3=AGAINSECRET");
        let flow = flow_with_query(&path);
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");
        let serialized = serde_json::to_string(&poc).expect("poc serializes");

        for i in 0..200 {
            let value = format!("BULK{i:03}SECRET");
            assert!(!serialized.contains(&value), "`{value}` leaked");
        }
        // `target` + 64 named secret variables + one catch-all.
        assert_eq!(poc.variables.len(), 66, "{:?}", poc.variables);
        let names: std::collections::HashSet<&str> =
            poc.variables.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names.len(), 66, "variable names must stay unique");
        assert!(names.contains("token0") && names.contains("token63"));
        assert!(!names.contains("token64"), "past the cap, no new variable");
        assert!(names.contains("redacted"), "the catch-all is declared");
        let redacted = poc
            .variables
            .iter()
            .find(|v| v.name == "redacted")
            .expect("catch-all variable");
        assert!(redacted.required && redacted.default.is_none());
        let url = &http_step(&poc).url;
        assert!(url.contains("token63={{token63}}"), "{url}");
        assert!(url.contains("token64={{redacted}}"), "{url}");
        assert!(url.contains("token199={{redacted}}"), "{url}");
        assert!(url.ends_with("&token3={{token3}}"), "{url}");
        assert!(!serialized.contains("AGAINSECRET"), "repeat value leaked");
    }

    // ---- M4: key-only segments and nested encodings --------------------------

    #[test]
    fn build_poc_scrubs_a_json_body_mislabelled_as_a_form() {
        // Not form data at all: the whole body is one key-only segment, which
        // used to be re-emitted unscrubbed.
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with(
            "POST",
            "/search?q=hello",
            &[("Content-Type", "application/x-www-form-urlencoded")],
            Some(r#"{"password":"FORMJSONPW1"}"#),
        );
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let serialized = serde_json::to_string(&poc).expect("poc serializes");
        assert!(!serialized.contains("FORMJSONPW1"), "{serialized}");
        assert_eq!(
            http_step(&poc).body.as_deref(),
            Some("%7B%22password%22%3A%22%5Bredacted%5D%22%7D")
        );
    }

    #[test]
    fn build_poc_scrubs_a_double_encoded_embedded_secret() {
        let def = CheckDefinition::reflected_xss();
        let payload = def.payloads.first().expect("a payload");
        let flow = flow_with_query("/go?q=hello&next=%252Fcb%253Faccess_token%253DDBLSECRET1");
        let q = point(&flow, Location::Query, "q", "hello");

        let poc = build_poc(&flow, &def, &q, payload).expect("poc builds");

        let url = &http_step(&poc).url;
        assert!(
            !url.contains("DBLSECRET1"),
            "double-encoded secret leaked: {url}"
        );
        assert!(
            url.contains("next=%2Fcb%3Faccess_token%3D%5Bredacted%5D"),
            "{url}"
        );
        assert!(url.contains("q=%3Caitm-canary-0001%3E"), "{url}");
    }

    #[test]
    fn percent_decode_decodes_valid_sequences_only() {
        assert_eq!(percent_decode("%2Fcb%3Fa%3dB%3A"), "/cb?a=B:");
        assert_eq!(percent_decode("%C3%A9"), "\u{e9}");
        // Malformed sequences and a trailing `%` stay as written; `+` is not a space.
        assert_eq!(percent_decode("100%zz%4"), "100%zz%4");
        assert_eq!(percent_decode("a+b%"), "a+b%");
        assert_eq!(percent_decode(""), "");
    }
}
