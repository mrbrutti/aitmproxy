//! Insertion points v2: `enumerate_v2` and its options (task 10).
//!
//! One captured request in, one list of [`InsertionPoint`]s out (spec D8.1,
//! "Insertion points v2"). Everything the audit later mutates is named here, so
//! this file decides three things a reviewer should be able to check quickly:
//!
//! - **What is a point.** Query values, every path segment (the last one as a
//!   file name when it reads like one), body values by format (form, JSON leaf,
//!   XML text and attribute, multipart value and filename, else the whole body),
//!   headers, cookies, and — only at `intensity >= medium` — parameter *names*.
//! - **What is never a point.** The hop-by-hop and framing headers (mutating
//!   them changes the request's shape rather than the application's input),
//!   `content-type` (plan call A8: it decides which kind the body parses to),
//!   `cookie` (cookies are enumerated one by one instead), any HTTP/2 pseudo
//!   header, and anything an [`IgnoreRule`] matches — by default every point
//!   carrying [`PointTrait::Session`], which is how a job avoids logging itself
//!   out by probing its own session cookie.
//! - **What a point may show.** Every `example` goes through
//!   [`redact::example`], and a point carrying [`PointTrait::Session`] shows the
//!   literal [`redact::REDACTED`] whatever its name is (crate redaction rule,
//!   D8.1 / AC T2-6). No value, URL or body reaches a log line here: the debug
//!   lines carry counts and the flow id only.
//!
//! Work is bounded at every step: the parsers cap their own output
//! (`MAX_PAIRS`, `MAX_XML_SLOTS`, `MAX_MULTIPART_PARTS`), a body over
//! [`MAX_BODY_PARSE_BYTES`] is not parsed at all, and the surviving points are
//! cut to `max_points_per_request` with the overflow counted rather than
//! silently dropped.

use std::collections::HashSet;

use anyhow::{bail, Result};
use regex::Regex;

use aitm_core::{HttpFlow, HttpRequest};
use aitm_scan_model::{
    FlowRef, IgnoreRule, InsertionKind, InsertionPoint, Intensity, LaneKind, ParamRef, PointTrait,
    ScanProfile, SessionMaterial,
};

use crate::limits::MAX_BODY_PARSE_BYTES;
use crate::params::{self, BodyFormat, JsonStep};
use crate::template::{looks_like_filename, traits_for};
use crate::{multipart, redact, xml};

/// Headers that are never insertion points, ASCII-lowercased.
///
/// The framing and hop-by-hop set (`host`, `content-length`,
/// `transfer-encoding`, `connection`, `keep-alive`, `proxy-connection`, `te`,
/// `trailer`, `upgrade`, `expect`) describes the message rather than the
/// application's input, `cookie` is enumerated as one point per cookie, and
/// `content-type` is excluded by plan call A8 because changing it changes which
/// kind the body parses to. Any name starting with `:` is an HTTP/2 pseudo
/// header and is excluded too.
const EXCLUDED_HEADERS: [&str; 11] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "cookie",
    "content-type",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
];

/// [`PointTrait`]'s declaration order, so two points with the same traits always
/// compare and serialise equal (plan call A12).
const TRAIT_ORDER: [PointTrait; 8] = [
    PointTrait::Url,
    PointTrait::Filename,
    PointTrait::Number,
    PointTrait::Email,
    PointTrait::Base64,
    PointTrait::Json,
    PointTrait::Id,
    PointTrait::Session,
];

/// One [`IgnoreRule`] with its regex compiled.
///
/// A rule matches a point when **every** key it sets matches; a rule that sets
/// no key would match every point, so [`CompiledIgnore::compile`] refuses it.
struct CompiledRule {
    kind: Option<InsertionKind>,
    name: Option<Regex>,
    point_trait: Option<PointTrait>,
}

/// The profile's `audit.ignore` list, ready to apply.
pub(crate) struct CompiledIgnore {
    rules: Vec<CompiledRule>,
}

impl CompiledIgnore {
    /// Compile every rule.
    ///
    /// # Errors
    ///
    /// Returns `Err` when a rule sets no key (it would silently take every point
    /// out of the audit) or when its `name_regex` does not compile. The message
    /// names the offending pattern — a profile is operator-authored, so the
    /// operator has to be told which line is wrong.
    pub(crate) fn compile(rules: &[IgnoreRule]) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            if !rule.is_valid() {
                bail!(
                    "audit.ignore rule {index} sets no key (kind, name_regex or trait), \
                     which would ignore every insertion point"
                );
            }
            let name = match &rule.name_regex {
                Some(pattern) => Some(Regex::new(pattern).map_err(|err| {
                    anyhow::anyhow!(
                        "audit.ignore rule {index}: name_regex {pattern:?} does not compile: {err}"
                    )
                })?),
                None => None,
            };
            compiled.push(CompiledRule {
                kind: rule.kind,
                name,
                point_trait: rule.point_trait,
            });
        }
        Ok(Self { rules: compiled })
    }

    /// Whether any rule takes this point out of the audit.
    pub(crate) fn matches(&self, kind: InsertionKind, name: &str, traits: &[PointTrait]) -> bool {
        self.rules.iter().any(|rule| {
            rule.kind.is_none_or(|want| want == kind)
                && rule.name.as_ref().is_none_or(|re| re.is_match(name))
                && rule.point_trait.is_none_or(|want| traits.contains(&want))
        })
    }
}

/// What [`enumerate_v2`] is allowed to produce for one request.
pub(crate) struct EnumerateOptions<'a> {
    /// Parameter-name points need `medium` or above.
    pub intensity: Intensity,
    /// The kinds the job audits; a point of any other kind is dropped.
    pub kinds: &'a [InsertionKind],
    /// The job's compiled `audit.ignore` list.
    pub ignore: &'a CompiledIgnore,
    /// The per-request cap (`audit.max_points_per_request`).
    pub max_points: u32,
    /// The job's session material, if it has one: a cookie or header named in
    /// it carries [`PointTrait::Session`].
    pub session: Option<&'a SessionMaterial>,
}

impl<'a> EnumerateOptions<'a> {
    /// The options a profile asks for.
    pub(crate) fn from_profile(
        profile: &'a ScanProfile,
        ignore: &'a CompiledIgnore,
        session: Option<&'a SessionMaterial>,
    ) -> Self {
        Self {
            intensity: profile.intensity,
            kinds: &profile.audit.kinds,
            ignore,
            max_points: profile.audit.max_points_per_request,
            session,
        }
    }
}

/// What one request yielded.
pub(crate) struct Enumerated {
    /// The points to audit, in candidate order, capped at `max_points`.
    pub points: Vec<InsertionPoint>,
    /// Every deduped `(kind, name)` candidate **before** filtering, for the site
    /// map's `params` list (a node still shows that it carries a session cookie
    /// even though the cookie is never probed).
    pub seen: Vec<ParamRef>,
    /// Candidates dropped by the per-request cap.
    pub overflow: u32,
    /// Candidates dropped by an [`IgnoreRule`].
    pub ignored: u32,
    /// Candidates dropped because their kind is not in `opts.kinds`.
    pub kind_filtered: u32,
}

/// A point before the kind, ignore and cap filters run.
struct Candidate {
    kind: InsertionKind,
    name: String,
    path: Option<String>,
    traits: Vec<PointTrait>,
    example: String,
}

/// Collects candidates in order, dropping repeats of a `(kind, name, path)`.
struct Collector<'a> {
    candidates: Vec<Candidate>,
    seen_keys: HashSet<(InsertionKind, String, Option<String>)>,
    session: Option<&'a SessionMaterial>,
}

impl<'a> Collector<'a> {
    fn new(session: Option<&'a SessionMaterial>) -> Self {
        Self {
            candidates: Vec::new(),
            seen_keys: HashSet::new(),
            session,
        }
    }

    /// Record one candidate, unless its `(kind, name, path)` is already taken.
    ///
    /// `value` is the observed value the traits and the example are derived
    /// from; `json` adds [`PointTrait::Json`] (every `json_value` point carries
    /// it as the scheduler's content-type signal, plan call A12).
    fn push(
        &mut self,
        kind: InsertionKind,
        name: &str,
        path: Option<String>,
        value: &str,
        json: bool,
    ) {
        if name.is_empty() {
            return;
        }
        let key = (kind, name.to_string(), path.clone());
        if !self.seen_keys.insert(key) {
            return;
        }

        let mut found = traits_for(value);
        if json {
            found.push(PointTrait::Json);
        }
        if session_trait(kind, name, self.session) {
            found.push(PointTrait::Session);
        }
        let traits: Vec<PointTrait> = TRAIT_ORDER
            .iter()
            .copied()
            .filter(|point_trait| found.contains(point_trait))
            .collect();

        // D8.1: a session point never shows its value, whatever it is named.
        let example = if traits.contains(&PointTrait::Session) {
            redact::REDACTED.to_string()
        } else {
            redact::example(kind, name, value)
        };

        self.candidates.push(Candidate {
            kind,
            name: name.to_string(),
            path,
            traits,
            example,
        });
    }
}

/// Whether a point carries session state: its name is a session cookie or (case
/// insensitively) a session header of this job, or it reads as a secret.
fn session_trait(kind: InsertionKind, name: &str, session: Option<&SessionMaterial>) -> bool {
    if redact::is_secret_name(name) {
        return true;
    }
    let Some(material) = session else {
        return false;
    };
    match kind {
        // Cookie names are case-sensitive (RFC 6265); header names are not.
        InsertionKind::Cookie => material.cookies.iter().any(|(known, _)| known == name),
        InsertionKind::Header => material
            .headers
            .iter()
            .any(|(known, _)| known.eq_ignore_ascii_case(name)),
        _ => false,
    }
}

/// Every insertion point of one captured request (spec D8.1).
///
/// Candidate order is query, path, body, headers, cookies, then parameter
/// names, and that order is what survives the per-request cap: the points most
/// likely to be application input come first.
pub(crate) fn enumerate_v2(flow: &HttpFlow, opts: &EnumerateOptions<'_>) -> Enumerated {
    let req = &flow.request;
    let url = request_url_text(req);
    let split = params::split_path(&req.path);
    let mut collector = Collector::new(opts.session);

    // 1. Query values.
    let query_pairs = split.query.map(params::form_pairs).unwrap_or_default();
    for (name, value) in &query_pairs {
        collector.push(InsertionKind::Query, name, None, value, false);
    }

    // 2. Path segments, the last one as a file name when it reads like one.
    let segments: Vec<&str> = split.path.split('/').filter(|s| !s.is_empty()).collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        let kind = if last && looks_like_filename(segment) {
            InsertionKind::PathFilename
        } else {
            InsertionKind::PathSegment
        };
        // 1-based index, so `build_request` replaces the right segment even
        // when two segments share a text (plan call A9).
        collector.push(kind, segment, Some((index + 1).to_string()), segment, false);
    }

    // 3. Body values, by format.
    let body = parsed_body(flow, req);
    if let Some((format, bytes)) = &body {
        body_candidates(flow, format, bytes, &mut collector);
    }

    // 4. Headers, minus the framing, hop-by-hop and pseudo headers.
    for (name, value) in req.headers.iter() {
        if is_excluded_header(name) {
            continue;
        }
        collector.push(InsertionKind::Header, name, None, value, false);
    }

    // 5. Cookies, one point per cookie of every `Cookie` header.
    for (_, header) in req
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
    {
        for (name, value) in params::cookie_pairs(header) {
            collector.push(InsertionKind::Cookie, &name, None, &value, false);
        }
    }

    // 6. Parameter *names*, from `medium` upwards only: renaming a parameter is
    //    a mutation of the request's shape, not of one of its values.
    if opts.intensity >= Intensity::Medium {
        for (name, _) in &query_pairs {
            collector.push(InsertionKind::ParamNameQuery, name, None, name, false);
        }
        if let Some((format, bytes)) = &body {
            for name in body_param_names(format, bytes) {
                collector.push(InsertionKind::ParamNameBody, &name, None, &name, false);
            }
        }
    }

    finish(flow, req, &url, collector.candidates, opts)
}

/// Apply the kind, ignore and cap filters and build the points.
fn finish(
    flow: &HttpFlow,
    req: &HttpRequest,
    url: &str,
    candidates: Vec<Candidate>,
    opts: &EnumerateOptions<'_>,
) -> Enumerated {
    let mut seen: Vec<ParamRef> = Vec::new();
    let mut points: Vec<InsertionPoint> = Vec::new();
    let (mut overflow, mut ignored, mut kind_filtered) = (0_u32, 0_u32, 0_u32);

    for candidate in candidates {
        if !seen
            .iter()
            .any(|param| param.kind == candidate.kind && param.name == candidate.name)
        {
            seen.push(ParamRef {
                kind: candidate.kind,
                name: candidate.name.clone(),
            });
        }

        if !opts.kinds.contains(&candidate.kind) {
            kind_filtered = kind_filtered.saturating_add(1);
            continue;
        }
        if opts
            .ignore
            .matches(candidate.kind, &candidate.name, &candidate.traits)
        {
            ignored = ignored.saturating_add(1);
            continue;
        }
        if points.len() as u64 >= u64::from(opts.max_points) {
            overflow = overflow.saturating_add(1);
            continue;
        }

        points.push(InsertionPoint {
            id: format!(
                "{}:{}:{}",
                flow.id,
                kind_token(candidate.kind),
                points.len()
            ),
            lane: LaneKind::Http,
            kind: candidate.kind,
            name: candidate.name,
            path: candidate.path,
            example: Some(candidate.example),
            flow: Some(FlowRef(flow.id)),
            site_node: None,
            traits: candidate.traits,
            frequency: 1,
            method: Some(req.method.clone()),
            url: Some(url.to_string()),
        });
    }

    if overflow > 0 || ignored > 0 || kind_filtered > 0 {
        tracing::debug!(
            flow = %flow.id,
            kept = points.len(),
            overflow,
            ignored,
            kind_filtered,
            "insertion points filtered"
        );
    }

    Enumerated {
        points,
        seen,
        overflow,
        ignored,
        kind_filtered,
    }
}

/// The request's URL as captured: `scheme://authority/path?query`.
fn request_url_text(req: &HttpRequest) -> String {
    format!("{}://{}{}", req.scheme, req.authority, req.path)
}

/// Whether this header name is never an insertion point.
fn is_excluded_header(name: &str) -> bool {
    name.starts_with(':')
        || EXCLUDED_HEADERS
            .iter()
            .any(|excluded| name.eq_ignore_ascii_case(excluded))
}

/// The body to walk for points, or `None` when there is nothing to walk: no
/// body, a body still streaming, or one over [`MAX_BODY_PARSE_BYTES`].
fn parsed_body<'a>(flow: &HttpFlow, req: &'a HttpRequest) -> Option<(BodyFormat, &'a [u8])> {
    let format = params::body_format(req);
    if matches!(format, BodyFormat::None | BodyFormat::Unavailable) {
        tracing::debug!(
            flow = %flow.id,
            reason = if format == BodyFormat::None { "no body" } else { "body still streaming" },
            "no body insertion points"
        );
        return None;
    }
    let bytes = params::body_bytes(&req.body)?;
    if bytes.len() > MAX_BODY_PARSE_BYTES {
        tracing::debug!(
            flow = %flow.id,
            len = bytes.len(),
            cap = MAX_BODY_PARSE_BYTES,
            reason = "body over the parse cap",
            "no body insertion points"
        );
        return None;
    }
    Some((format, bytes))
}

/// The body's own candidates, by format.
fn body_candidates(
    flow: &HttpFlow,
    format: &BodyFormat,
    bytes: &[u8],
    collector: &mut Collector<'_>,
) {
    match format {
        BodyFormat::Form => {
            let text = String::from_utf8_lossy(bytes);
            for (name, value) in params::form_pairs(&text) {
                collector.push(InsertionKind::BodyParam, &name, None, &value, false);
            }
        }
        BodyFormat::Json => {
            let Ok(root) = serde_json::from_slice::<serde_json::Value>(bytes) else {
                tracing::debug!(flow = %flow.id, "json body does not parse; no body points");
                return;
            };
            for leaf in params::json_leaves(&root) {
                let name = json_leaf_name(&leaf.path);
                collector.push(
                    InsertionKind::JsonValue,
                    &name,
                    Some(leaf.path.clone()),
                    &json_scalar_text(&leaf.value),
                    true,
                );
            }
        }
        BodyFormat::Xml => {
            let slots = match xml::scan(bytes) {
                Ok(slots) => slots,
                Err(err) => {
                    tracing::debug!(flow = %flow.id, error = %err, "xml body does not parse; no body points");
                    return;
                }
            };
            for slot in slots {
                // A namespace declaration is markup, not user input: the server
                // never reads it as data, and mutating it only breaks the
                // document. `xmlns:prefix` declarations cannot be told apart
                // from a plain attribute here (the tokenizer strips the prefix),
                // so only the default declaration is skipped.
                if slot.kind == xml::XmlSlotKind::Attr
                    && (slot.name == "xmlns" || slot.path.ends_with("@xmlns"))
                {
                    continue;
                }
                let kind = match slot.kind {
                    xml::XmlSlotKind::Text => InsertionKind::XmlValue,
                    xml::XmlSlotKind::Attr => InsertionKind::XmlAttr,
                };
                collector.push(
                    kind,
                    &slot.name,
                    Some(slot.path.clone()),
                    &slot.value,
                    false,
                );
            }
        }
        BodyFormat::Multipart { boundary } => {
            let parts = match multipart::parse(bytes, boundary) {
                Ok(parts) => parts,
                Err(err) => {
                    tracing::debug!(flow = %flow.id, error = %err, "multipart body does not parse; no body points");
                    return;
                }
            };
            for part in parts {
                // A part with no `name=` cannot be addressed by a mutation.
                let Some(name) = part.name.as_deref() else {
                    continue;
                };
                let value = bytes
                    .get(part.value_span.clone())
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default();
                collector.push(InsertionKind::MultipartValue, name, None, &value, false);
                if let Some(filename) = part.filename.as_deref() {
                    collector.push(
                        InsertionKind::MultipartFilename,
                        name,
                        None,
                        filename,
                        false,
                    );
                }
            }
        }
        BodyFormat::Other => {
            let text = String::from_utf8_lossy(bytes);
            collector.push(InsertionKind::EntireBody, "body", None, &text, false);
        }
        BodyFormat::None | BodyFormat::Unavailable => {}
    }
}

/// The body keys a `param_name_body` point may rename: form keys and top-level
/// JSON object keys only (plan call A10).
fn body_param_names(format: &BodyFormat, bytes: &[u8]) -> Vec<String> {
    match format {
        BodyFormat::Form => {
            let text = String::from_utf8_lossy(bytes);
            params::form_pairs(&text)
                .into_iter()
                .map(|(name, _)| name)
                .collect()
        }
        BodyFormat::Json => serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|root| {
                root.as_object()
                    .map(|map| map.keys().cloned().collect::<Vec<String>>())
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The name of a JSON leaf: the last step of its path (`profile.address.city`
/// is named `city`, `items[0]` is named `0`).
fn json_leaf_name(path: &str) -> String {
    match params::parse_json_path(path).ok().and_then(|steps| {
        steps.last().map(|step| match step {
            JsonStep::Key(key) => key.clone(),
            JsonStep::Index(index) => index.to_string(),
        })
    }) {
        Some(name) => name,
        // Unreachable for a path this crate wrote; the whole path is still a
        // usable name, and a panic here would be on parsed body content.
        None => path.to_string(),
    }
}

/// A JSON scalar as the text a check sees: a string without its quotes, any
/// other scalar as it is written.
fn json_scalar_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The snake_case wire token of an insertion kind, as serde renders it.
pub(crate) fn kind_token(kind: InsertionKind) -> &'static str {
    match kind {
        InsertionKind::Query => "query",
        InsertionKind::BodyParam => "body_param",
        InsertionKind::JsonValue => "json_value",
        InsertionKind::XmlValue => "xml_value",
        InsertionKind::XmlAttr => "xml_attr",
        InsertionKind::MultipartValue => "multipart_value",
        InsertionKind::MultipartFilename => "multipart_filename",
        InsertionKind::Header => "header",
        InsertionKind::Cookie => "cookie",
        InsertionKind::PathSegment => "path_segment",
        InsertionKind::PathFilename => "path_filename",
        InsertionKind::ParamNameQuery => "param_name_query",
        InsertionKind::ParamNameBody => "param_name_body",
        InsertionKind::EntireBody => "entire_body",
        InsertionKind::WsJsonValue => "ws_json_value",
        InsertionKind::WsText => "ws_text",
        InsertionKind::WsFormParam => "ws_form_param",
        InsertionKind::WsBinary => "ws_binary",
        InsertionKind::WsHandshakeHeader => "ws_handshake_header",
        InsertionKind::L4Field => "l4_field",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{enumerate_v2, kind_token, CompiledIgnore, EnumerateOptions, Enumerated};

    use aitm_core::{Body, HttpFlow, StreamBody};
    use aitm_scan_model::{
        FlowRef, IgnoreRule, InsertionKind, InsertionPoint, Intensity, LaneKind, ParamRef,
        PointTrait, ScanProfile, SessionMaterial,
    };

    use crate::testutil::{captured_flow, request};

    use InsertionKind::{
        Cookie, EntireBody, Header, JsonValue, MultipartFilename, MultipartValue, ParamNameBody,
        ParamNameQuery, PathFilename, PathSegment, Query, XmlAttr, XmlValue,
    };

    /// The request the plan pins task 10 against.
    const PINNED_URL: &str = "http://t:8080/files/reports/summary.pdf?q=1&next=https://e.test/";
    const PINNED_BODY: &[u8] = br#"{"profile":{"address":{"city":"Lisbon"}},"n":3}"#;

    /// The multipart body pinned by task 7, CRLF throughout.
    const MULTIPART_BODY: &[u8] = b"--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XyZ\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nfile-bytes\r\n--XyZ--\r\n";

    fn pinned_flow() -> HttpFlow {
        captured_flow(
            request(
                "POST",
                PINNED_URL,
                &[
                    ("X-Client", "abc"),
                    ("Cookie", "sid=S3; theme=dark"),
                    ("Authorization", "Bearer tok"),
                ],
                Some(("application/json", PINNED_BODY)),
            ),
            200,
            &[],
            b"",
        )
    }

    /// The job's session material: one cookie, no headers.
    fn material() -> SessionMaterial {
        SessionMaterial {
            cookies: vec![("sid".to_string(), "S3".to_string())],
            headers: Vec::new(),
        }
    }

    /// `(kind, name, path)` for every returned point.
    fn triples(out: &Enumerated) -> Vec<(InsertionKind, String, Option<String>)> {
        out.points
            .iter()
            .map(|p| (p.kind, p.name.clone(), p.path.clone()))
            .collect()
    }

    fn has(out: &Enumerated, kind: InsertionKind, name: &str, path: Option<&str>) -> bool {
        triples(out).contains(&(kind, name.to_string(), path.map(str::to_string)))
    }

    fn has_named(out: &Enumerated, kind: InsertionKind, name: &str) -> bool {
        out.points.iter().any(|p| p.kind == kind && p.name == name)
    }

    fn point<'a>(out: &'a Enumerated, kind: InsertionKind, name: &str) -> &'a InsertionPoint {
        out.points
            .iter()
            .find(|p| p.kind == kind && p.name == name)
            .unwrap_or_else(|| panic!("no {kind:?} point named {name} in {:?}", triples(out)))
    }

    /// A point id carries the kind's wire token, so the token must be the one
    /// serde writes for that kind and not a hand-rolled spelling.
    #[test]
    fn kind_tokens_match_the_wire() {
        for kind in InsertionKind::ALL {
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", kind_token(kind)),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn enumerate_pins() {
        let flow = pinned_flow();
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let session = material();
        let opts = EnumerateOptions::from_profile(&profile, &ignore, Some(&session));
        let out = enumerate_v2(&flow, &opts);

        // Query, path, JSON, header, cookie and parameter-name points.
        assert!(has(&out, Query, "q", None), "{:?}", triples(&out));
        assert!(has(&out, Query, "next", None));
        assert_eq!(point(&out, Query, "next").traits, vec![PointTrait::Url]);
        assert!(has(&out, PathSegment, "files", Some("1")));
        assert!(has(&out, PathSegment, "reports", Some("2")));
        assert!(has(&out, PathFilename, "summary.pdf", Some("3")));
        assert_eq!(
            point(&out, PathFilename, "summary.pdf").traits,
            vec![PointTrait::Filename]
        );
        assert!(has(&out, JsonValue, "city", Some("profile.address.city")));
        assert_eq!(
            point(&out, JsonValue, "city").traits,
            vec![PointTrait::Json]
        );
        assert_eq!(
            point(&out, JsonValue, "city").example.as_deref(),
            Some("Lisbon")
        );
        assert!(has(&out, JsonValue, "n", Some("n")));
        assert_eq!(
            point(&out, JsonValue, "n").traits,
            vec![PointTrait::Number, PointTrait::Json, PointTrait::Id]
        );
        assert!(has(&out, Header, "X-Client", None));
        assert_eq!(
            point(&out, Header, "X-Client").example.as_deref(),
            Some("abc")
        );
        assert!(has(&out, Cookie, "theme", None));
        assert_eq!(
            point(&out, Cookie, "theme").example.as_deref(),
            Some("<redacted>")
        );
        assert!(has(&out, ParamNameQuery, "q", None));
        assert!(has(&out, ParamNameQuery, "next", None));
        assert!(has(&out, ParamNameBody, "profile", None));
        assert!(has(&out, ParamNameBody, "n", None));

        // Session material, credentials, hop-by-hop headers and the body itself
        // are never points.
        assert!(!has_named(&out, Cookie, "sid"));
        assert!(!has_named(&out, Header, "Authorization"));
        assert!(!has_named(&out, Header, "Host"));
        assert!(!has_named(&out, Header, "Content-Type"));
        assert!(!has_named(&out, Header, "Content-Length"));
        assert!(!out.points.iter().any(|p| p.kind == EntireBody));
        assert_eq!(out.ignored, 2);

        // Everything that was a candidate is in `seen`, filtered or not.
        assert!(out.seen.contains(&ParamRef {
            kind: Cookie,
            name: "sid".to_string(),
        }));
        assert!(out.seen.contains(&ParamRef {
            kind: Header,
            name: "Authorization".to_string(),
        }));

        // Every point carries the request it came from.
        for p in &out.points {
            assert_eq!(p.lane, LaneKind::Http);
            assert_eq!(p.method.as_deref(), Some("POST"));
            assert_eq!(p.url.as_deref(), Some(PINNED_URL));
            assert_eq!(p.flow, Some(FlowRef(flow.id)));
            assert_eq!(p.frequency, 1);
        }
        let mut ids: Vec<&str> = out.points.iter().map(|p| p.id.as_str()).collect();
        let count = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), count, "point ids are not pairwise distinct");
    }

    #[test]
    fn light_has_no_param_names() {
        let flow = pinned_flow();
        let profile = ScanProfile {
            intensity: Intensity::Light,
            ..ScanProfile::default()
        };
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions::from_profile(&profile, &ignore, None),
        );

        assert!(!out
            .points
            .iter()
            .any(|p| p.kind == ParamNameQuery || p.kind == ParamNameBody));
        assert!(has(&out, Query, "q", None));
    }

    #[test]
    fn cap_counts_overflow() {
        let flow = pinned_flow();
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let session = material();
        let uncapped = enumerate_v2(
            &flow,
            &EnumerateOptions::from_profile(&profile, &ignore, Some(&session)),
        );
        let total = uncapped.points.len();
        assert!(total > 3, "the pinned flow yields {total} points");
        assert_eq!(uncapped.overflow, 0);

        let capped = enumerate_v2(
            &flow,
            &EnumerateOptions {
                intensity: profile.intensity,
                kinds: &profile.audit.kinds,
                ignore: &ignore,
                max_points: 3,
                session: Some(&session),
            },
        );
        assert_eq!(capped.points.len(), 3);
        assert_eq!(capped.overflow as usize, total - 3);
    }

    #[test]
    fn kinds_filter() {
        let flow = pinned_flow();
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions {
                intensity: profile.intensity,
                kinds: &[Query],
                ignore: &ignore,
                max_points: profile.audit.max_points_per_request,
                session: None,
            },
        );

        assert!(!out.points.is_empty());
        assert!(out.points.iter().all(|p| p.kind == Query));
        assert!(out.kind_filtered > 0);
    }

    #[test]
    fn ignore_regex() {
        let flow = pinned_flow();
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&[IgnoreRule {
            kind: Some(Header),
            name_regex: Some("(?i)^x-".to_string()),
            point_trait: None,
        }])
        .unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions {
                intensity: profile.intensity,
                kinds: &profile.audit.kinds,
                ignore: &ignore,
                max_points: profile.audit.max_points_per_request,
                session: None,
            },
        );

        assert!(!has_named(&out, Header, "X-Client"));
        assert_eq!(out.ignored, 1);
        // A rule scoped to one kind leaves every other kind alone.
        assert!(has(&out, Query, "q", None));
        assert!(has_named(&out, Cookie, "sid"));
    }

    #[test]
    fn ignore_compile_errors() {
        let empty = CompiledIgnore::compile(&[IgnoreRule::default()]);
        assert!(empty.is_err(), "a rule with no key must be refused");

        let bad = CompiledIgnore::compile(&[IgnoreRule {
            name_regex: Some("(".to_string()),
            ..IgnoreRule::default()
        }]);
        let message = match bad {
            Ok(_) => panic!("an unparsable regex must be refused"),
            Err(err) => err.to_string(),
        };
        assert!(message.contains('('), "{message}");
    }

    #[test]
    fn xml_and_multipart_kinds() {
        let xml = captured_flow(
            request(
                "POST",
                "http://t:8080/x",
                &[],
                Some(("text/xml", br#"<order id="7"><item>W</item></order>"#)),
            ),
            200,
            &[],
            b"",
        );
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let out = enumerate_v2(
            &xml,
            &EnumerateOptions::from_profile(&profile, &ignore, None),
        );
        assert!(
            has(&out, XmlAttr, "id", Some("order@id")),
            "{:?}",
            triples(&out)
        );
        assert!(has(&out, XmlValue, "item", Some("order.item")));

        let multipart = captured_flow(
            request(
                "POST",
                "http://t:8080/upload",
                &[],
                Some(("multipart/form-data; boundary=XyZ", MULTIPART_BODY)),
            ),
            200,
            &[],
            b"",
        );
        let out = enumerate_v2(
            &multipart,
            &EnumerateOptions::from_profile(&profile, &ignore, None),
        );
        assert!(
            has(&out, MultipartValue, "title", None),
            "{:?}",
            triples(&out)
        );
        assert_eq!(
            point(&out, MultipartValue, "title").example.as_deref(),
            Some("hello")
        );
        assert!(has(&out, MultipartValue, "doc", None));
        assert!(has(&out, MultipartFilename, "doc", None));
        assert_eq!(
            point(&out, MultipartFilename, "doc").traits,
            vec![PointTrait::Filename]
        );
        assert_eq!(
            point(&out, MultipartFilename, "doc").example.as_deref(),
            Some("a.txt")
        );
    }

    #[test]
    fn entire_body_only_for_unrecognised() {
        let flow = captured_flow(
            request(
                "POST",
                "http://t:8080/x",
                &[],
                Some(("text/plain", b"hello")),
            ),
            200,
            &[],
            b"",
        );
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions::from_profile(&profile, &ignore, None),
        );

        let bodies: Vec<_> = out.points.iter().filter(|p| p.kind == EntireBody).collect();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].name, "body");
        assert_eq!(bodies[0].path, None);
        assert_eq!(bodies[0].example.as_deref(), Some("hello"));

        let json = pinned_flow();
        let out = enumerate_v2(
            &json,
            &EnumerateOptions::from_profile(&profile, &ignore, None),
        );
        assert!(!out.points.iter().any(|p| p.kind == EntireBody));
    }

    #[test]
    fn streamed_and_huge_bodies_skip() {
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();

        let mut streamed = pinned_flow();
        streamed.request.body = Body::Streamed(StreamBody);
        let out = enumerate_v2(
            &streamed,
            &EnumerateOptions::from_profile(&profile, &ignore, None),
        );
        assert!(!out.points.iter().any(|p| is_body_kind(p.kind)));
        assert!(
            has(&out, Query, "q", None),
            "non-body points still enumerate"
        );

        let mut huge = pinned_flow();
        huge.request.body = Body::Bytes(vec![b'a'; 3 * 1024 * 1024]);
        let out = enumerate_v2(
            &huge,
            &EnumerateOptions::from_profile(&profile, &ignore, None),
        );
        assert!(!out.points.iter().any(|p| is_body_kind(p.kind)));
        assert!(has(&out, Query, "q", None));
    }

    fn is_body_kind(kind: InsertionKind) -> bool {
        matches!(
            kind,
            InsertionKind::BodyParam
                | JsonValue
                | XmlValue
                | XmlAttr
                | MultipartValue
                | MultipartFilename
                | EntireBody
                | ParamNameBody
        )
    }

    #[test]
    fn session_header_name_marks_trait() {
        let flow = captured_flow(
            request(
                "GET",
                "http://t:8080/x?q=1",
                &[("X-Api-Key", "k"), ("X-Tenant", "acme")],
                None,
            ),
            200,
            &[],
            b"",
        );
        let session = SessionMaterial {
            cookies: Vec::new(),
            headers: vec![
                ("X-Api-Key".to_string(), "k".to_string()),
                ("x-tenant".to_string(), "acme".to_string()),
            ],
        };
        let profile = ScanProfile::default();

        let default_ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions::from_profile(&profile, &default_ignore, Some(&session)),
        );
        assert!(!has_named(&out, Header, "X-Api-Key"));
        assert!(!has_named(&out, Header, "X-Tenant"));
        assert_eq!(out.ignored, 2);

        let no_ignore = CompiledIgnore::compile(&[]).unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions {
                intensity: profile.intensity,
                kinds: &profile.audit.kinds,
                ignore: &no_ignore,
                max_points: profile.audit.max_points_per_request,
                session: Some(&session),
            },
        );
        let key = point(&out, Header, "X-Api-Key");
        assert!(key.traits.contains(&PointTrait::Session));
        assert_eq!(key.example.as_deref(), Some("<redacted>"));
        // `X-Tenant` reads as no secret: only the session material marks it.
        let tenant = point(&out, Header, "X-Tenant");
        assert!(tenant.traits.contains(&PointTrait::Session));
        assert_eq!(tenant.example.as_deref(), Some("<redacted>"));
    }

    // --- tester additions (stage 5, whole branch) ----------------------------

    /// The per-request cap keeps candidate order (query values first) and
    /// counts every survivor it drops; it runs after the ignore rules, so the
    /// ignored count does not move; a cap of zero keeps nothing but still
    /// reports every candidate in `seen`.
    #[test]
    fn cap_keeps_candidate_order_and_zero_keeps_nothing() {
        let flow = pinned_flow();
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let session = material();
        let opts = |max_points: u32| EnumerateOptions {
            intensity: profile.intensity,
            kinds: &profile.audit.kinds,
            ignore: &ignore,
            max_points,
            session: Some(&session),
        };
        let total = enumerate_v2(&flow, &opts(u32::MAX)).points.len() as u32;
        assert!(total > 2);

        let two = enumerate_v2(&flow, &opts(2));
        assert_eq!(
            triples(&two),
            vec![
                (Query, "q".to_string(), None),
                (Query, "next".to_string(), None),
            ]
        );
        assert_eq!(two.overflow, total - 2);
        assert_eq!(two.ignored, 2, "the cap runs after the ignore rules");
        assert_eq!(two.points[0].id, format!("{}:query:0", flow.id));
        assert_eq!(two.points[1].id, format!("{}:query:1", flow.id));

        let none = enumerate_v2(&flow, &opts(0));
        assert!(none.points.is_empty());
        assert_eq!(none.overflow, total);
        assert!(none.seen.iter().any(|p| p.kind == Query && p.name == "q"));
        assert!(none
            .seen
            .iter()
            .any(|p| p.kind == Cookie && p.name == "sid"));
    }

    /// A value under a secret-looking name never reaches an `example`, whatever
    /// kind carries it (AC T2-6): a query `token`, a form `password`, an
    /// `X-Auth-Token` header, any cookie. Plain values still show, so the
    /// redaction is a rule and not a blanket.
    #[test]
    fn secret_named_values_never_reach_an_example() {
        let flow = captured_flow(
            request(
                "POST",
                "http://t:8080/reset?token=abc123&q=plain",
                &[
                    ("X-Auth-Token", "t0k3n"),
                    ("Cookie", "theme=dark"),
                    ("X-Client", "shown"),
                ],
                Some((
                    "application/x-www-form-urlencoded",
                    b"password=hunter2&user=bob",
                )),
            ),
            200,
            &[],
            b"",
        );
        let profile = ScanProfile::default();
        let no_ignore = CompiledIgnore::compile(&[]).unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions {
                intensity: Intensity::Medium,
                kinds: &profile.audit.kinds,
                ignore: &no_ignore,
                max_points: u32::MAX,
                session: None,
            },
        );

        for (kind, name) in [
            (Query, "token"),
            (InsertionKind::BodyParam, "password"),
            (Header, "X-Auth-Token"),
            (Cookie, "theme"),
        ] {
            assert_eq!(
                point(&out, kind, name).example.as_deref(),
                Some("<redacted>"),
                "{kind:?} {name}"
            );
        }
        for (kind, name) in [
            (Query, "token"),
            (InsertionKind::BodyParam, "password"),
            (Header, "X-Auth-Token"),
        ] {
            assert!(
                point(&out, kind, name)
                    .traits
                    .contains(&PointTrait::Session),
                "{kind:?} {name} carries the session trait"
            );
        }
        assert_eq!(point(&out, Query, "q").example.as_deref(), Some("plain"));
        assert_eq!(
            point(&out, InsertionKind::BodyParam, "user")
                .example
                .as_deref(),
            Some("bob")
        );
        assert_eq!(
            point(&out, Header, "X-Client").example.as_deref(),
            Some("shown")
        );

        let examples: Vec<&str> = out
            .points
            .iter()
            .filter_map(|p| p.example.as_deref())
            .collect();
        for secret in ["abc123", "hunter2", "t0k3n", "dark"] {
            assert!(
                !examples.iter().any(|example| example.contains(secret)),
                "{secret} leaked into an example: {examples:?}"
            );
        }

        // The whole-body example is scrubbed, not copied.
        let plain = captured_flow(
            request(
                "POST",
                "http://t:8080/x",
                &[],
                Some(("text/plain", b"note sid=abc123 end")),
            ),
            200,
            &[],
            b"",
        );
        let out = enumerate_v2(
            &plain,
            &EnumerateOptions::from_profile(&profile, &no_ignore, None),
        );
        let body = point(&out, EntireBody, "body");
        assert_eq!(body.example.as_deref(), Some("note sid=[redacted] end"));
    }

    /// Empty and malformed inputs enumerate nothing broken and never panic: a
    /// bare `GET`, a query made of separators, and bodies whose declared format
    /// does not parse (the query points still come out).
    #[test]
    fn empty_and_malformed_inputs_do_not_panic() {
        let profile = ScanProfile::default();
        let ignore = CompiledIgnore::compile(&profile.audit.ignore).unwrap();
        let opts = EnumerateOptions::from_profile(&profile, &ignore, None);

        let bare = captured_flow(request("GET", "http://t:8080/", &[], None), 200, &[], b"");
        let out = enumerate_v2(&bare, &opts);
        assert!(out.points.is_empty(), "{:?}", triples(&out));
        assert!(out.seen.is_empty());
        assert_eq!((out.overflow, out.ignored, out.kind_filtered), (0, 0, 0));

        let separators = captured_flow(
            request("GET", "http://t:8080/x?&&==&a&=b", &[], None),
            200,
            &[],
            b"",
        );
        let out = enumerate_v2(&separators, &opts);
        assert!(out.points.iter().all(|p| !p.name.is_empty()));
        assert!(has(&out, Query, "a", None), "{:?}", triples(&out));

        for (content_type, body) in [
            ("application/json", &b"{\"a\":"[..]),
            ("application/json", &[0xff_u8, 0xfe][..]),
            ("text/xml", &b"<a><b>"[..]),
            (
                "multipart/form-data; boundary=XyZ",
                &b"--nope\r\n\r\nx\r\n--nope--\r\n"[..],
            ),
            ("application/x-www-form-urlencoded", &b"&&=&"[..]),
        ] {
            let flow = captured_flow(
                request(
                    "POST",
                    "http://t:8080/x?q=1",
                    &[],
                    Some((content_type, body)),
                ),
                200,
                &[],
                b"",
            );
            let out = enumerate_v2(&flow, &opts);
            assert!(
                !out.points.iter().any(|p| is_body_kind(p.kind)),
                "{content_type}: {:?}",
                triples(&out)
            );
            assert!(has(&out, Query, "q", None), "{content_type}");
        }
    }

    /// An ignore rule matches only when every key it sets matches; a rule
    /// scoped to one kind never reaches another kind's point of the same name;
    /// two rules are an OR.
    #[test]
    fn ignore_rule_requires_every_key_to_match() {
        let flow = pinned_flow();
        let profile = ScanProfile::default();
        let session = material();
        let run = |rules: &[IgnoreRule]| {
            let ignore = CompiledIgnore::compile(rules).unwrap();
            enumerate_v2(
                &flow,
                &EnumerateOptions {
                    intensity: profile.intensity,
                    kinds: &profile.audit.kinds,
                    ignore: &ignore,
                    max_points: u32::MAX,
                    session: Some(&session),
                },
            )
        };

        // Header + `^sid$`: the cookie `sid` is another kind, so it stays.
        let out = run(&[IgnoreRule {
            kind: Some(Header),
            name_regex: Some("^sid$".to_string()),
            point_trait: None,
        }]);
        assert!(has_named(&out, Cookie, "sid"));
        assert_eq!(out.ignored, 0);

        // Cookie + session trait: the session cookie goes, the Authorization
        // header stays (and still shows no value).
        let out = run(&[IgnoreRule {
            kind: Some(Cookie),
            name_regex: None,
            point_trait: Some(PointTrait::Session),
        }]);
        assert!(!has_named(&out, Cookie, "sid"));
        assert!(has_named(&out, Header, "Authorization"));
        assert_eq!(
            point(&out, Header, "Authorization").example.as_deref(),
            Some("<redacted>")
        );
        assert_eq!(out.ignored, 1);

        // Two rules: either may match.
        let out = run(&[
            IgnoreRule {
                kind: Some(Cookie),
                name_regex: None,
                point_trait: None,
            },
            IgnoreRule {
                kind: None,
                name_regex: Some("(?i)^x-client$".to_string()),
                point_trait: None,
            },
        ]);
        assert!(!has_named(&out, Cookie, "sid"));
        assert!(!has_named(&out, Cookie, "theme"));
        assert!(!has_named(&out, Header, "X-Client"));
        assert_eq!(out.ignored, 3);
    }

    /// Every `Cookie` header of a request is enumerated, in order, and every
    /// cookie's example is withheld whatever it is called.
    #[test]
    fn every_cookie_header_is_enumerated_and_redacted() {
        let flow = captured_flow(
            request(
                "GET",
                "http://t:8080/x",
                &[("Cookie", "a=1; b=2"), ("Cookie", "c=3")],
                None,
            ),
            200,
            &[],
            b"",
        );
        let profile = ScanProfile::default();
        let no_ignore = CompiledIgnore::compile(&[]).unwrap();
        let out = enumerate_v2(
            &flow,
            &EnumerateOptions::from_profile(&profile, &no_ignore, None),
        );

        let cookies: Vec<(&str, Option<&str>)> = out
            .points
            .iter()
            .filter(|p| p.kind == Cookie)
            .map(|p| (p.name.as_str(), p.example.as_deref()))
            .collect();
        assert_eq!(
            cookies,
            vec![
                ("a", Some("<redacted>")),
                ("b", Some("<redacted>")),
                ("c", Some("<redacted>")),
            ]
        );
    }
}
