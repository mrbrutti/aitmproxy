//! The Scan surface's model (scanner v2 TUI spec D1, D3, D9, D10).
//!
//! Plain data and pure helpers only: the reducer in `app.rs` owns every
//! transition, `ui::scan` draws. Sub-modules hold one tab's state each
//! ([`profiles`], [`jobs`], [`sitemap`], [`issues`]), the launch bookkeeping
//! ([`launch`]) and the legacy `scan.discover` state ([`legacy`]); every type is
//! re-exported here so callers write `crate::scan::JobsState`.
//!
//! Wire shapes come from `aitm_scan_model`; [`parse_result`] is the one door a
//! `scan.*` reply passes through, and a reply that does not match the contract
//! becomes a [`ScanError`] with `code: None` (D10) so the previous state stays
//! on screen.

pub mod issues;
pub mod jobs;
pub mod launch;
pub mod legacy;
pub mod profiles;
pub mod sitemap;

use std::collections::BTreeSet;

use aitm_scan_model::ScanErrorCode;
use serde_json::Value;

pub use issues::*;
pub use jobs::*;
pub use launch::*;
pub use legacy::*;
pub use profiles::*;
pub use sitemap::*;

/// The four tabs of `Mode::Scan` (spec D2), in strip order.
///
/// `Default` is `Profiles`, the first tab; the reducer lands a legacy-only bus
/// on `Jobs` at first open (D2), so the derive only fixes the zero value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanTab {
    #[default]
    Profiles,
    Jobs,
    SiteMap,
    Issues,
}

/// How many `Tick`s (250 ms each) between two `scan.status` polls of a live
/// job (spec D6: about one second).
pub const STATUS_POLL_TICKS: u64 = 4;

/// How many `Tick`s between two `scan.list` polls while the Scan view is
/// shown (spec D6: ten seconds).
pub const LIST_POLL_TICKS: u64 = 40;

/// How many `scan.status` requests may leave the reducer per `scan.list` fold
/// and per status-timer firing (spec D6, hostile-core bounds; the Architect's
/// number). The rest wait for the next firing; the tag dedupe already keeps
/// one request per job in flight.
pub const MAX_STATUS_FOLLOWUPS: usize = 16;

/// The `limit` of every `scan.issues` page the TUI asks for (spec D6).
pub const ISSUES_PAGE_LIMIT: usize = 512;

impl ScanTab {
    /// The tab a `scan.*` verb's error line belongs to (spec D9: "the owning
    /// tab"). Launch, list, status and cancel are the Jobs tab's; the Jobs
    /// tab keeps no error of its own and reads `ScanState::last_error`.
    pub fn owning(verb: &str) -> ScanTab {
        match verb {
            "scan.profile.list"
            | "scan.profile.get"
            | "scan.profile.save"
            | "scan.profile.delete"
            | "scan.checks"
            | "scan.session.preview" => ScanTab::Profiles,
            "scan.sitemap" => ScanTab::SiteMap,
            "scan.issues" | "scan.issue" | "scan.issue.update" => ScanTab::Issues,
            _ => ScanTab::Jobs,
        }
    }

    /// Every tab, in the order the strip shows them (`1` to `4`).
    pub const ALL: [ScanTab; 4] = [
        ScanTab::Profiles,
        ScanTab::Jobs,
        ScanTab::SiteMap,
        ScanTab::Issues,
    ];

    /// The strip label.
    pub fn label(self) -> &'static str {
        match self {
            ScanTab::Profiles => "Profiles",
            ScanTab::Jobs => "Jobs",
            ScanTab::SiteMap => "Site map",
            ScanTab::Issues => "Issues",
        }
    }
}

/// Everything the Scan view holds (spec D3).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ScanState {
    /// The tab on screen.
    pub tab: ScanTab,
    pub profiles: ProfilesState,
    pub jobs: JobsState,
    pub sitemap: SitemapState,
    pub issues: IssuesState,
    pub launch: LaunchState,
    /// The `scan.discover` one-shot state (D12).
    pub legacy: LegacyState,
    /// Tags of tagged calls awaiting their reply (dedupe, D6).
    pub inflight: BTreeSet<String>,
    /// The most recent `scan.*` failure, shown until the next successful
    /// reply under the same tag (D13: a keyed verb's error outlives a
    /// sibling key's success).
    pub last_error: Option<ScanError>,
    /// A non-error notice for the banner (D11: `already <state>` when `x`
    /// lands on a terminal job): the answer to one key, cleared by the next
    /// key or by the next reply that changes the tab. Drawn in secondary
    /// text, never in the error hue, and never recorded as a `ScanError`.
    pub notice: Option<String>,
    /// The tick the view was first opened on; `None` until then.
    pub opened_at_tick: Option<u64>,
}

impl ScanState {
    /// Record a `scan.*` failure where its tab shows it: the owning tab's
    /// error line (the Jobs tab has none of its own) and `last_error`, the
    /// view-wide fallback the banner reads.
    pub fn set_error(&mut self, err: ScanError) {
        match ScanTab::owning(&err.verb) {
            ScanTab::Profiles => self.profiles.error = Some(err.clone()),
            ScanTab::SiteMap => self.sitemap.error = Some(err.clone()),
            ScanTab::Issues => self.issues.error = Some(err.clone()),
            ScanTab::Jobs => {}
        }
        self.last_error = Some(err);
    }

    /// A successful reply under `tag` clears the error that exact tag left
    /// behind (spec D13): a single-slot verb's tag is the verb itself, a
    /// keyed verb's is `<verb>:<key>`, so job B's success never clears job
    /// A's error.
    pub fn clear_error(&mut self, tag: &str) {
        let same = |e: &Option<ScanError>| e.as_ref().is_some_and(|e| e.tag == tag);
        if same(&self.last_error) {
            self.last_error = None;
        }
        match ScanTab::owning(tag_parts(tag).0) {
            ScanTab::Profiles if same(&self.profiles.error) => self.profiles.error = None,
            ScanTab::SiteMap if same(&self.sitemap.error) => self.sitemap.error = None,
            ScanTab::Issues if same(&self.issues.error) => self.issues.error = None,
            _ => {}
        }
    }

    /// The focused pane's cursor and its row count, for the shared `nav()`
    /// keys (spec D11). `None` when the focused pane has no walkable list
    /// here: the Jobs detail scroll is the Jobs task's and the Issues detail
    /// flow cursor is the Issues task's, and an editor pane is dead while no
    /// profile is open.
    ///
    /// The Site map panes walk the lists [`MapSource::from`] picks for
    /// `offer`: the v2 nodes and points on a v2 bus, the legacy
    /// `scan.discover` endpoints and injection points otherwise (D12: the
    /// legacy result renders as nodes and points in the same two panes),
    /// which is how today's cursors survive the move.
    pub fn cursor_mut(&mut self, offer: ScanOffer) -> Option<(&mut usize, usize)> {
        match self.tab {
            ScanTab::Profiles => match self.profiles.pane {
                ProfilePane::List => {
                    let n = self.profiles.list.len();
                    Some((&mut self.profiles.cursor, n))
                }
                ProfilePane::Fields => {
                    let n = EDITOR_FIELDS.len();
                    self.profiles.editor.as_mut().map(|e| (&mut e.field, n))
                }
                ProfilePane::Origins => self.profiles.editor.as_mut().map(|e| {
                    let n = e.origin_choices.len();
                    (&mut e.origin_cursor, n)
                }),
                ProfilePane::Checks => {
                    let n = self.profiles.checks.len();
                    self.profiles
                        .editor
                        .as_mut()
                        .map(|e| (&mut e.tree_cursor, n))
                }
            },
            ScanTab::Jobs => match self.jobs.pane {
                JobPane::List => {
                    let n = self.jobs.order.len();
                    Some((&mut self.jobs.cursor, n))
                }
                JobPane::Detail => None,
            },
            ScanTab::SiteMap => match (MapSource::from(offer), self.sitemap.pane) {
                (MapSource::Legacy, MapPane::Nodes) => {
                    let n = self.legacy.endpoints.len();
                    Some((&mut self.legacy.endpoint_cursor, n))
                }
                (MapSource::Legacy, MapPane::Points) => {
                    let n = self.legacy.points.len();
                    Some((&mut self.legacy.cursor, n))
                }
                (MapSource::V2, MapPane::Nodes) => {
                    let n = self.sitemap.nodes.len();
                    Some((&mut self.sitemap.node_cursor, n))
                }
                (MapSource::V2, MapPane::Points) => {
                    let n = self.sitemap.points.len();
                    Some((&mut self.sitemap.point_cursor, n))
                }
            },
            ScanTab::Issues => match self.issues.pane {
                IssuePane::List => {
                    let n = self.issues.list.len();
                    Some((&mut self.issues.cursor, n))
                }
                IssuePane::Detail => None,
            },
        }
    }

    /// The flow `Enter` opens from the Site map's focused pane, read from the
    /// same lists [`ScanState::cursor_mut`] walks for `offer` (spec D11,
    /// D12; AC3 for the legacy endpoint link). `None` when the pane is empty,
    /// the row names no flow, or the active tab is not the Site map.
    pub fn sitemap_selected_flow(&self, offer: ScanOffer) -> Option<String> {
        if self.tab != ScanTab::SiteMap {
            return None;
        }
        match (MapSource::from(offer), self.sitemap.pane) {
            (MapSource::Legacy, MapPane::Nodes) => self
                .legacy
                .endpoints
                .get(self.legacy.endpoint_cursor)
                .and_then(|e| self.legacy.endpoint_flows.get(e).cloned()),
            (MapSource::Legacy, MapPane::Points) => self
                .legacy
                .points
                .get(self.legacy.cursor)
                .map(|p| p.flow.clone()),
            (MapSource::V2, MapPane::Nodes) => self
                .sitemap
                .nodes
                .get(self.sitemap.node_cursor)
                .and_then(|n| n.flows.first())
                .map(ToString::to_string),
            (MapSource::V2, MapPane::Points) => self
                .sitemap
                .points
                .get(self.sitemap.point_cursor)
                .and_then(|p| p.flow.as_ref())
                .map(ToString::to_string),
        }
    }

    /// Tab / BackTab: focus the active tab's next (or previous) pane.
    pub fn step_pane(&mut self, forward: bool) {
        let dir = if forward { Dir::Next } else { Dir::Prev };
        match self.tab {
            ScanTab::Profiles => {
                self.profiles.pane = step(
                    &[
                        ProfilePane::List,
                        ProfilePane::Fields,
                        ProfilePane::Origins,
                        ProfilePane::Checks,
                    ],
                    self.profiles.pane,
                    dir,
                )
            }
            ScanTab::Jobs => {
                self.jobs.pane = step(&[JobPane::List, JobPane::Detail], self.jobs.pane, dir)
            }
            ScanTab::SiteMap => {
                self.sitemap.pane = step(&[MapPane::Nodes, MapPane::Points], self.sitemap.pane, dir)
            }
            ScanTab::Issues => {
                self.issues.pane =
                    step(&[IssuePane::List, IssuePane::Detail], self.issues.pane, dir)
            }
        }
    }

    /// Esc / `q`: close a focused secondary pane back to its list pane
    /// (D11). `true` when one was open, so the caller knows the key was
    /// spent here and the view stays. On a legacy bus nothing changes in
    /// behaviour (D12): the key is never spent here, so one Esc leaves the
    /// view as it did before the tabs.
    pub fn close_pane(&mut self, offer: ScanOffer) -> bool {
        if offer == ScanOffer::Legacy {
            return false;
        }
        match self.tab {
            ScanTab::Profiles if self.profiles.pane != ProfilePane::List => {
                self.profiles.pane = ProfilePane::List;
                true
            }
            ScanTab::Jobs if self.jobs.pane != JobPane::List => {
                self.jobs.pane = JobPane::List;
                true
            }
            ScanTab::SiteMap if self.sitemap.pane != MapPane::Nodes => {
                self.sitemap.pane = MapPane::Nodes;
                true
            }
            ScanTab::Issues if self.issues.pane != IssuePane::List => {
                self.issues.pane = IssuePane::List;
                true
            }
            _ => false,
        }
    }
}

/// Which way a wrapping step goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    Next,
    Prev,
}

/// The next (or previous) entry of `all` after `cur`, wrapping. An entry not
/// in `all` stays put. The one wrap helper of the crate: the reducer's chip
/// and sidebar steps use it too.
pub(crate) fn step<T: PartialEq + Copy>(all: &[T], cur: T, dir: Dir) -> T {
    match all.iter().position(|x| *x == cur) {
        Some(i) => {
            let n = all.len();
            all[match dir {
                Dir::Next => (i + 1) % n,
                Dir::Prev => (i + n - 1) % n,
            }]
        }
        None => cur,
    }
}

/// What the bus can serve the Scan view (spec D2): the v2 scanner, the legacy
/// one-shot `scan.discover`, or nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOffer {
    /// `scan.start` is on the bus: the full surface (each control still gated
    /// by its own verb).
    V2,
    /// Only `scan.discover`: today's one-shot crawl, degraded elsewhere.
    Legacy,
    /// Neither verb: the sidebar row is hidden and every tab says so.
    None,
}

/// What a bus without any scanner is told (spec D2): the banner of every tab
/// and the `:scan <target>` refusal toast share this one sentence.
pub const NO_SCANNER: &str = "the scanner is not on this bus (scan.start / scan.discover)";

/// The detail of a [`ScanError::missing_verb`]: the inline text D2 fixes for
/// a control whose verb the bus lacks, minus the verb itself. Private: the
/// one spelling is `ScanError::missing_verb(verb).wording()`.
const MISSING_VERB: &str = "is not on this bus";

/// The detail of the uncoded error a `scan.status` / `scan.cancel` reply gets
/// when its `job` is not the key of the tag it answers (spec D6, hostile-core
/// bounds): nothing is folded from such a reply.
pub const OTHER_JOB: &str = "reply named a different job";

/// A failed `scan.*` call, coded when the core's message carries a D9 code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    /// The tag of the call that failed: the verb itself for a single-slot
    /// verb, `<verb>:<key>` for a keyed one (spec D13: the error is cleared
    /// by the next success under this exact tag, so job B's success never
    /// clears job A's error).
    pub tag: String,
    /// The verb that failed.
    pub verb: String,
    /// The parsed code, `None` for a message outside the `scan: <code>: ...`
    /// shape (including a contract mismatch from [`parse_result`]).
    pub code: Option<ScanErrorCode>,
    /// The core's detail after the code, or the whole message when uncoded.
    pub detail: String,
}

impl ScanError {
    /// An error under `tag`, the tag of the call that failed; the verb is
    /// the tag's verb part ([`tag_parts`]), so a bare verb tags itself.
    fn new(tag: &str, code: Option<ScanErrorCode>, detail: impl Into<String>) -> Self {
        Self {
            tag: tag.to_string(),
            verb: tag_parts(tag).0.to_string(),
            code,
            detail: detail.into(),
        }
    }

    /// Read a `CallTaggedFailed` message under its `tag`. A message that
    /// does not parse as `scan: <code>: <detail>` is kept verbatim with
    /// `code: None`.
    pub fn from_message(tag: &str, message: &str) -> Self {
        match ScanErrorCode::parse_message(message) {
            Some((code, detail)) => Self::new(tag, Some(code), detail),
            None => Self::new(tag, None, message),
        }
    }

    /// An uncoded error under `tag` with `detail` as its whole text after
    /// the verb (a contract mismatch, a reply naming another key): what
    /// [`parse_result`] and the hostile-core checks record.
    pub fn uncoded(tag: &str, detail: impl Into<String>) -> Self {
        Self::new(tag, None, detail)
    }

    /// A verb this bus does not offer (spec D2): uncoded under the bare
    /// verb, so [`ScanError::wording`] reads `<verb> is not on this bus`.
    pub fn missing_verb(verb: &str) -> Self {
        Self::uncoded(verb, MISSING_VERB)
    }

    /// The operator wording (spec D9): the code's fixed text, then `: `, then
    /// the detail; an uncoded error reads `<verb>: <detail>`, except a
    /// missing verb, which reads `<verb> is not on this bus` (D2's inline
    /// text, the verb named once).
    pub fn wording(&self) -> String {
        match self.code {
            Some(code) => format!("{}: {}", code_wording(code), self.detail),
            None if self.detail == MISSING_VERB => format!("{} {}", self.verb, self.detail),
            None => format!("{}: {}", self.verb, self.detail),
        }
    }
}

/// The D9 table.
fn code_wording(code: ScanErrorCode) -> &'static str {
    match code {
        ScanErrorCode::NotFound => {
            "No longer known to the core (it may have restarted); the list is being refreshed"
        }
        ScanErrorCode::Busy => {
            "Scanner busy: the job limit is reached or this origin already has a running job; wait or cancel one in Jobs (x)"
        }
        ScanErrorCode::OutOfScope => {
            "Out of scope: add the HTTP host to Scope (S) or an L4 scope entry with the inject capability covering the target"
        }
        ScanErrorCode::RefusedAgent => {
            "Refused for the agent role: this client is not the operator; check the token the TUI was started with"
        }
        ScanErrorCode::RefusedL4 => {
            "L4 refused: enable `l4.enabled` in config (and the agent L4 gates for an agent-started job)"
        }
        ScanErrorCode::LaneUnavailable => {
            "No requested lane can run on this core; pick other lanes or a build that has them"
        }
        ScanErrorCode::InvalidProfile => {
            "Profile rejected; fix the named field and launch or save again"
        }
        ScanErrorCode::UnknownCheck => {
            "Unknown check selector; remove it from include/exclude (the tree lists only loaded checks)"
        }
        ScanErrorCode::ConfirmRequired => {
            "The core wanted a confirmation this client did not send (the token may have expired); launch again to get a fresh prompt"
        }
    }
}

/// Parse a `scan.*` reply into its D10 type. A mismatch is a [`ScanError`]
/// under `tag` (the tag of the call the reply answers; a bare verb for a
/// single-slot one) with `code: None` and the serde message in the detail
/// (the verb is not in the detail: `wording()` prefixes it); nothing panics
/// on bus data. The reply is read in place, never cloned.
pub fn parse_result<T: serde::de::DeserializeOwned>(
    tag: &str,
    value: &Value,
) -> Result<T, ScanError> {
    T::deserialize(value)
        .map_err(|e| ScanError::uncoded(tag, format!("reply did not match the contract ({e})")))
}

/// Whether `s` is a job id in its wire form: `scan-` followed by exactly eight
/// lowercase hex digits (spec D6, hostile-core bounds). An id from a push
/// line or a `scan.list` row is used as a tag key, an argument and an
/// `inflight` entry only when this holds; the rest are ignored.
pub fn is_job_id(s: &str) -> bool {
    is_wire_id(s, "scan-")
}

/// Whether `s` is an issue id in its wire form: `issue-` followed by exactly
/// eight lowercase hex digits (spec D6, hostile-core bounds; fix round D,
/// D1). An id from a `scan.issues` row or an `issue` push line is used as a
/// tag key, an argument or a `read` entry only when this holds; a row that
/// fails it is dropped by the fold.
pub fn is_issue_id(s: &str) -> bool {
    is_wire_id(s, "issue-")
}

/// `prefix` then exactly eight lowercase hex digits: the one shape every
/// scanner id has on the wire.
fn is_wire_id(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 8
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The tag of a keyed tagged call: `<verb>:<key>` (spec D5).
pub fn tag_keyed(verb: &str, key: &str) -> String {
    format!("{verb}:{key}")
}

/// Split a tag back into its verb and optional key at the first `:`; a bare
/// verb has no key.
pub fn tag_parts(tag: &str) -> (&str, Option<&str>) {
    match tag.split_once(':') {
        Some((verb, key)) => (verb, Some(key)),
        None => (tag, None),
    }
}

/// Reduce a scan target (`host`, `host:port`, `http://host/path?q`,
/// `[v6]:port`) to the bare host the scope guard checks.
///
/// A port is stripped only from a bracketed IPv6 literal (`[::1]:8080`) or
/// from a `host:digits` pair holding exactly one colon; a bare IPv6 literal
/// (`::1`, `fe80::1`) holds more and is kept whole (the rule is "the whole
/// authority holds at most one colon").
pub fn scan_host(raw: &str) -> String {
    let s = raw.trim();
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    let s = s.find(['/', '?', '#']).map_or(s, |i| &s[..i]);
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((v6, _)) = rest.split_once(']') {
            return v6.to_string();
        }
    }
    match s.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && !host.contains(':') =>
        {
            host.to_string()
        }
        _ => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tabs_default_to_profiles_and_label_the_strip() {
        assert_eq!(ScanTab::default(), ScanTab::Profiles);
        assert_eq!(ScanTab::SiteMap.label(), "Site map");
    }

    #[test]
    fn scan_host_strips_scheme_port_and_path() {
        assert_eq!(scan_host("http://127.0.0.1:8080/x?y#z"), "127.0.0.1");
        assert_eq!(scan_host(" example.test:443 "), "example.test");
        assert_eq!(scan_host("example.test"), "example.test");
    }

    /// Fix round A, A4: a bare IPv6 literal keeps its last group; only a
    /// `host:digits` pair or a bracketed `[v6]:port` loses a port.
    #[test]
    fn scan_host_keeps_a_bare_ipv6_literal() {
        assert_eq!(scan_host("::1"), "::1");
        assert_eq!(scan_host("[::1]:8080"), "::1");
        assert_eq!(scan_host("host:8080"), "host");
        assert_eq!(scan_host("fe80::1"), "fe80::1");
        assert_eq!(scan_host("[fe80::1]"), "fe80::1");
        assert_eq!(scan_host("host:abc"), "host:abc");
    }

    #[test]
    fn tag_parts_splits_only_once() {
        assert_eq!(
            tag_parts("scan.issue:issue:with:colons"),
            ("scan.issue", Some("issue:with:colons"))
        );
    }
}
