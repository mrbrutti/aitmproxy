//! The Scan surface's model (scanner v2 TUI spec D1, D3, D9, D10).
//!
//! Plain data and pure helpers only: the reducer in `app.rs` owns every
//! transition, `ui::scan` draws. Sub-modules hold one tab's state each
//! ([`profiles`], [`jobs`], [`sitemap`], [`issues`]), the launch bookkeeping
//! ([`launch`]), the legacy `scan.discover` state ([`legacy`]) and the wire
//! vocabulary ([`tokens`]); every type is
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
pub mod tokens;

use std::collections::BTreeSet;

use aitm_scan_model::{JobId, JobStatus, ListResult, ScanErrorCode};
use serde_json::Value;

use crate::action::Action;

use crate::text::{clean, truncate};

pub use issues::*;
pub use jobs::*;
pub use launch::*;
pub use legacy::*;
pub use profiles::*;
pub use sitemap::*;
pub use tokens::*;

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

/// The widest any one string a Detail pane reads grows, in cells (D6
/// hostile-core bounds; fix round G, G11, E19): the Issues and Jobs folds
/// cut every free-text field of a read issue or a full status to this,
/// once, so the per-frame line building runs over bounded text only.
pub const DETAIL_VALUE_MAX: usize = 400;

/// The widest a `ScanError`'s core-controlled `detail` grows, in cells
/// (fix round G, G82; D6 hostile-core bounds): bounded once in
/// [`ScanError::new`], the one choke point, so the banner, the Profiles
/// footer wrap, the toast and every clone of the error read bounded text.
pub const ERROR_DETAIL_MAX: usize = 240;

/// ` +n` when `dropped` entries were cut off a list at fold, empty
/// otherwise: the one suffix every Detail line that lists bounded entries
/// ends in (the Jobs lanes, checks, clamps and targets, the Issues `job`
/// line; fix round I, I4).
pub(crate) fn more(dropped: usize) -> String {
    if dropped > 0 {
        format!(" +{dropped}")
    } else {
        String::new()
    }
}

/// The tab a `scan.*` verb's error line belongs to (spec D9: "the owning
/// tab"; plan task 13). The profile verbs, the catalogue, the session
/// preview and the two launch verbs are the Profiles tab's (a launch is
/// made there, and a refused one is answered in its footer, D13); list,
/// status and cancel are the Jobs tab's (`JobsState::error`, fix round H,
/// H56); the site map and the issue verbs their tabs'. A verb outside the
/// D3 set falls to Jobs, so an unknown verb's error is never lost.
pub fn owning_tab(verb: &str) -> ScanTab {
    match verb {
        "scan.checks" | "scan.session.preview" | "scan.start" | "scan.map" => ScanTab::Profiles,
        _ if verb.starts_with("scan.profile.") => ScanTab::Profiles,
        "scan.sitemap" => ScanTab::SiteMap,
        "scan.issues" | "scan.issue" | "scan.issue.update" => ScanTab::Issues,
        // The Jobs verbs (list, status, cancel) and any verb outside D3.
        _ => ScanTab::Jobs,
    }
}

impl ScanTab {
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
    /// The view-wide record of the last `scan.*` failure, kept until the
    /// next successful reply under the same tag (D13: a keyed verb's error
    /// outlives a sibling key's success). Read by the tests only (fix
    /// round H, H67): the toast is built from the `ScanError` in
    /// `App::on_scan_failed`, and a banner reads its tab's own slot
    /// ([`ScanState::error_slot`]; D13 as ruled 2026-11-01, fix round H,
    /// H56), never this.
    pub last_error: Option<ScanError>,
    /// A non-error notice for the banner (D11: `already <state>` when `x`
    /// lands on a terminal job): the answer to one key, cleared by the next
    /// key only, never by a reply (spec D3; fix round F, F15), so a
    /// background poll cannot erase it before the operator reads it. Drawn
    /// in secondary text, never in the error hue, and never recorded as a
    /// `ScanError`.
    pub notice: Option<String>,
    /// The tick the view was first opened on; `None` until then.
    pub opened_at_tick: Option<u64>,
    /// The tag of the `not_found` error whose self-heal requested a
    /// `scan.list` (`scan.status:<job>` or `scan.cancel:<job>`; D13 as
    /// amended, fix round G, G74): that list's success clears it, since no
    /// success under the tag itself can ever come.
    pub heal_pending: Option<String>,
}

impl ScanState {
    /// Record a `scan.*` failure where its tab shows it: the owning tab's
    /// error slot (every tab has one) and `last_error`, the view-wide
    /// record the tests read (the toast is built from the `ScanError` in
    /// `App::on_scan_failed`, not from either; H67).
    pub fn set_error(&mut self, err: ScanError) {
        *self.error_slot_mut(owning_tab(&err.verb)) = Some(err.clone());
        self.last_error = Some(err);
    }

    /// The error slot of `tab` (every tab has one; spec D13 as ruled
    /// 2026-11-01, fix round H, H56): the one tab-to-slot dispatch
    /// (fix round H, H68), read by the banner and the tests.
    pub fn error_slot(&self, tab: ScanTab) -> &Option<ScanError> {
        match tab {
            ScanTab::Profiles => &self.profiles.error,
            ScanTab::Jobs => &self.jobs.error,
            ScanTab::SiteMap => &self.sitemap.error,
            ScanTab::Issues => &self.issues.error,
        }
    }

    /// [`ScanState::error_slot`], to write ([`ScanState::set_error`] and
    /// [`ScanState::clear_error`]).
    pub fn error_slot_mut(&mut self, tab: ScanTab) -> &mut Option<ScanError> {
        match tab {
            ScanTab::Profiles => &mut self.profiles.error,
            ScanTab::Jobs => &mut self.jobs.error,
            ScanTab::SiteMap => &mut self.sitemap.error,
            ScanTab::Issues => &mut self.issues.error,
        }
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
        let slot = self.error_slot_mut(owning_tab(tag_parts(tag).0));
        if same(slot) {
            *slot = None;
        }
    }

    /// Fold a `scan.status` / `scan.cancel` reply into the Jobs tab
    /// ([`JobsState::fold_status`]) and let go of the keyed Jobs error its
    /// job can no longer answer (spec D13 as ruled 2026-11-01; fix round H,
    /// H66): a `scan.status:<job>` / `scan.cancel:<job>` error with any code
    /// is cleared, from the Jobs slot and `last_error` alike, when this
    /// reply is that job's and turns it terminal, since no success under
    /// the tag can come for a job that has ended. Another job's reply never
    /// clears it (D13: job B's success never clears job A's error).
    pub fn fold_job_status(&mut self, status: JobStatus) {
        let ended = status.state.is_terminal().then(|| status.job.clone());
        self.jobs.fold_status(status);
        if ended.is_some() && ended.as_deref() == self.jobs_error_job() {
            self.release_jobs_error();
        }
    }

    /// Fold a `scan.list` reply into the Jobs tab ([`JobsState::fold_list`],
    /// whose status follow-ups this returns) and let go of the keyed Jobs
    /// error its job can no longer answer (D13 as ruled; H66): one whose
    /// job the list dropped from `order`, or lists terminal, is cleared
    /// from the Jobs slot and `last_error` alike. A job that was never in
    /// `order` has not left the list, so its error stays (D13). The
    /// `not_found` self-heal's list (`heal_pending`, fix round G, G74) still
    /// clears its own tag in the reducer; this covers every other code.
    pub fn fold_job_list(&mut self, list: ListResult) -> Vec<JobId> {
        let was_listed = self
            .jobs_error_job()
            .is_some_and(|job| self.jobs.order.iter().any(|j| j == job));
        let followups = self.jobs.fold_list(list);
        let settled = self.jobs_error_job().is_some_and(|job| {
            if self.jobs.order.iter().any(|j| j == job) {
                self.jobs
                    .state_of(job)
                    .is_some_and(|state| state.is_terminal())
            } else {
                was_listed
            }
        });
        if settled {
            self.release_jobs_error();
        }
        followups
    }

    /// The job the Jobs slot's error names: the key of a keyed
    /// `scan.status:<job>` / `scan.cancel:<job>` tag (H66). `None` for no
    /// error, another verb's, or a bare tag.
    fn jobs_error_job(&self) -> Option<&str> {
        let err = self.jobs.error.as_ref()?;
        if !matches!(err.verb.as_str(), "scan.status" | "scan.cancel") {
            return None;
        }
        tag_parts(&err.tag).1
    }

    /// Clear the Jobs slot's error under its own tag ([`ScanState::clear_error`]),
    /// so `last_error` goes with it when it is the same error (H66).
    fn release_jobs_error(&mut self) {
        if let Some(tag) = self.jobs.error.as_ref().map(|e| e.tag.clone()) {
            self.clear_error(&tag);
        }
    }

    /// The refused launch the Profiles footer answers (spec D13's refused
    /// state): the Profiles tab's error when it is a launch verb's
    /// `out_of_scope`, `refused_agent`, `refused_l4` or `confirm_required`.
    /// It is cleared like any error, by the next success under its tag, so
    /// the row leaves with the next launch that goes through.
    pub fn refused_launch(&self) -> Option<&ScanError> {
        self.profiles
            .error
            .as_ref()
            .filter(|e| e.is_refused_launch())
    }

    /// The focused pane's cursor and its row count, for the shared `nav()`
    /// keys (spec D11). `None` when the focused pane has no walkable list
    /// here: the Jobs detail scroll is the Jobs task's, the Issues detail
    /// flow cursor the Issues task's, the Profiles Checks pane walks the
    /// flattened tree in the reducer (fix round G, G32), and an editor pane
    /// is dead while no profile is open.
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
                ProfilePane::Checks => None,
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
                    // The grouped node list `show_legacy` built from the
                    // endpoints (fix round G, G22), one node per endpoint.
                    let n = self.sitemap.nodes.len();
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
                    // The offset within the selected node's points (fix
                    // round G, G24).
                    let n = self.sitemap.node_points(self.sitemap.node_cursor).len();
                    Some((&mut self.sitemap.point_offset, n))
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
            // The node under the legacy cursor is the grouped list's (fix
            // round G, G22); its id is the endpoint URL `endpoint_flows`
            // is keyed by (AC3).
            (MapSource::Legacy, MapPane::Nodes) => self
                .sitemap
                .nodes
                .get(self.legacy.endpoint_cursor)
                .and_then(|n| self.legacy.endpoint_flows.get(&n.id).cloned()),
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
                .selected_point()
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
    ///
    /// The detail is bounded here, once (fix round G, G82): control
    /// characters stripped and the text cut to [`ERROR_DETAIL_MAX`] cells,
    /// then shrunk to what is kept, so no consumer walks or holds more.
    fn new(tag: &str, code: Option<ScanErrorCode>, detail: impl Into<String>) -> Self {
        let mut detail = truncate(&clean(&detail.into()), ERROR_DETAIL_MAX);
        detail.shrink_to_fit();
        Self {
            tag: tag.to_string(),
            verb: tag_parts(tag).0.to_string(),
            code,
            detail,
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
            Some(code) => {
                let mut text = code_wording(code).to_string();
                // The refresh clause only where the self-heal ran (D9 as
                // amended on the Task 13 spec panel; fix round G, G75): a
                // keyed `scan.status` / `scan.cancel` tag.
                if self.not_found_job().is_some() {
                    text.push_str(REFRESHING);
                }
                format!("{text}: {}", self.detail)
            }
            None if self.detail == MISSING_VERB => format!("{} {}", self.verb, self.detail),
            None => format!("{}: {}", self.verb, self.detail),
        }
    }

    /// Whether this is a launch (`scan.start` / `scan.map`) the core
    /// refused with a code the operator can act on from the Profiles tab
    /// (spec D13's refused state): `out_of_scope`, `refused_agent`,
    /// `refused_l4` or `confirm_required`. The launch key stays live for
    /// these; the footer shows the wording in the warning hue.
    pub fn is_refused_launch(&self) -> bool {
        LaunchVerb::parse(&self.verb).is_some()
            && matches!(
                self.code,
                Some(
                    ScanErrorCode::OutOfScope
                        | ScanErrorCode::RefusedAgent
                        | ScanErrorCode::RefusedL4
                        | ScanErrorCode::ConfirmRequired
                )
            )
    }

    /// The job a `not_found` self-heal answers for (spec call 8; D13 as
    /// amended; fix round G, G78): the tag's key when the code is
    /// `not_found` and the verb a keyed `scan.status:<job>` or
    /// `scan.cancel:<job>`. The reducer drops that job and lists again;
    /// the wording keeps its refresh clause only then (G75).
    pub fn not_found_job(&self) -> Option<&str> {
        if self.code != Some(ScanErrorCode::NotFound)
            || !matches!(self.verb.as_str(), "scan.status" | "scan.cancel")
        {
            return None;
        }
        tag_parts(&self.tag).1
    }
}

/// The D9 `not_found` wording without its refresh clause: what a tag the
/// self-heal does not answer reads (G75).
const NOT_FOUND: &str = "No longer known to the core (it may have restarted)";
/// The refresh clause [`ScanError::wording`] appends to [`NOT_FOUND`]
/// where the self-heal ran (G75; fix round H, H30: the D9 sentence lives
/// once).
const REFRESHING: &str = "; the list is being refreshed";

/// The D9 table; `not_found` without its refresh clause ([`REFRESHING`]).
fn code_wording(code: ScanErrorCode) -> &'static str {
    match code {
        ScanErrorCode::NotFound => NOT_FOUND,
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

/// One step of a Scan cursor or scroll over `len` entries (D11): `Up`/`Down`
/// by one, `PageUp`/`PageDown` by `page`, `Home`/`End` to the ends, any
/// other action stays; the result is clamped to the last entry (0 when
/// there is none). The one walk the Jobs list, the Jobs detail scroll, the
/// Site map, Profiles and Issues cursors share.
pub(crate) fn walk(action: &Action, cursor: usize, len: usize, page: usize) -> usize {
    let last = len.saturating_sub(1);
    match action {
        Action::Up => cursor.saturating_sub(1),
        Action::Down => cursor + 1,
        Action::PageUp => cursor.saturating_sub(page),
        Action::PageDown => cursor + page,
        Action::Home => 0,
        Action::End => last,
        _ => cursor,
    }
    .min(last)
}

/// One step of a Detail pane's scroll over `len` lines: [`walk`] on the
/// `u16` the pane keeps at `at`, saturating at the type's end (fix round
/// F, F11). The Jobs and Issues Detail panes and the help overlay share it.
pub(crate) fn scroll(at: &mut u16, action: &Action, len: usize, page: usize) {
    let next = walk(action, usize::from(*at), len, page);
    *at = u16::try_from(next).unwrap_or(u16::MAX);
}

/// Whether a timer-driven read is due (spec D6; fix round G, G28): `every`
/// or more ticks have passed since `last`, the tick the previous request
/// left on; never before a first request has left (`None`), so a tab whose
/// entry read was quiet (the verb missing) asks nothing on the timer.
pub(crate) fn due(last: Option<u64>, now: u64, every: u64) -> bool {
    last.is_some_and(|l| now.saturating_sub(l) >= every)
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

    /// Fix round H, H68: one error slot per tab, reached through
    /// `error_slot` / `error_slot_mut`. A failure under a tab's verb fills
    /// that tab's slot and no other; writing `None` through the mutable
    /// accessor empties the same slot `set_error` filled.
    #[test]
    fn error_slot_is_the_owning_tabs_and_no_other() {
        for (verb, tab) in [
            ("scan.start", ScanTab::Profiles),
            ("scan.list", ScanTab::Jobs),
            ("scan.sitemap", ScanTab::SiteMap),
            ("scan.issues", ScanTab::Issues),
        ] {
            let mut state = ScanState::default();
            state.set_error(ScanError::uncoded(verb, "boom"));
            for other in ScanTab::ALL {
                assert_eq!(
                    state.error_slot(other).as_ref().map(|e| e.tag.as_str()),
                    (other == tab).then_some(verb),
                    "{verb}: the {tab:?} slot alone, read on {other:?}"
                );
            }
            *state.error_slot_mut(tab) = None;
            assert!(
                ScanTab::ALL.iter().all(|t| state.error_slot(*t).is_none()),
                "{verb}: emptied through the mutable slot"
            );
            // The same slot the tab's own state field holds.
            *state.error_slot_mut(tab) = Some(ScanError::uncoded(verb, "again"));
            let held = match tab {
                ScanTab::Profiles => &state.profiles.error,
                ScanTab::Jobs => &state.jobs.error,
                ScanTab::SiteMap => &state.sitemap.error,
                ScanTab::Issues => &state.issues.error,
            };
            assert_eq!(held.as_ref().map(|e| e.detail.as_str()), Some("again"));
        }
    }

    /// Plan task 13: every D3 verb has an owning tab; the launch verbs are
    /// the Profiles tab's, the unknown fall to Jobs.
    #[test]
    fn owning_tab_routes_every_d3_verb() {
        for verb in [
            "scan.profile.list",
            "scan.profile.get",
            "scan.profile.save",
            "scan.profile.delete",
            "scan.checks",
            "scan.session.preview",
            "scan.start",
            "scan.map",
        ] {
            assert_eq!(owning_tab(verb), ScanTab::Profiles, "{verb}");
        }
        // The Jobs verbs and any verb outside D3 share the fallback arm
        // (fix round G, G79).
        for verb in [
            "scan.list",
            "scan.status",
            "scan.cancel",
            "scan.discover",
            "x",
        ] {
            assert_eq!(owning_tab(verb), ScanTab::Jobs, "{verb}");
        }
        assert_eq!(owning_tab("scan.sitemap"), ScanTab::SiteMap);
        for verb in ["scan.issues", "scan.issue", "scan.issue.update"] {
            assert_eq!(owning_tab(verb), ScanTab::Issues, "{verb}");
        }
    }

    #[test]
    fn a_refused_launch_is_one_of_four_codes_on_a_launch_verb() {
        assert!(ScanError::from_message("scan.start", "scan: out_of_scope: x").is_refused_launch());
        assert!(
            ScanError::from_message("scan.map", "scan: confirm_required: x").is_refused_launch()
        );
        assert!(!ScanError::from_message("scan.start", "scan: busy: x").is_refused_launch());
        assert!(!ScanError::from_message("scan.list", "scan: out_of_scope: x").is_refused_launch());
        assert!(!ScanError::from_message("scan.start", "boom").is_refused_launch());
    }

    /// Fix round G, G75 (D9 as amended): the refresh clause only on a
    /// keyed status or cancel tag.
    #[test]
    fn not_found_keeps_the_refresh_clause_only_where_the_heal_ran() {
        let long =
            "No longer known to the core (it may have restarted); the list is being refreshed: x";
        assert_eq!(
            ScanError::from_message("scan.status:scan-1a2b3c4d", "scan: not_found: x").wording(),
            long
        );
        assert_eq!(
            ScanError::from_message("scan.cancel:scan-1a2b3c4d", "scan: not_found: x").wording(),
            long
        );
        assert_eq!(
            ScanError::from_message("scan.start", "scan: not_found: x").wording(),
            "No longer known to the core (it may have restarted): x"
        );
        assert_eq!(
            ScanError::from_message("scan.status", "scan: not_found: x").wording(),
            "No longer known to the core (it may have restarted): x",
            "a bare status tag ran no heal"
        );
    }

    /// Fix round G, G78: the self-heal predicate names the job only for a
    /// keyed status or cancel `not_found`.
    #[test]
    fn not_found_job_names_only_a_keyed_status_or_cancel() {
        let status = ScanError::from_message("scan.status:scan-1a2b3c4d", "scan: not_found: gone");
        assert_eq!(status.not_found_job(), Some("scan-1a2b3c4d"));
        let cancel = ScanError::from_message("scan.cancel:scan-1a2b3c4d", "scan: not_found: gone");
        assert_eq!(cancel.not_found_job(), Some("scan-1a2b3c4d"));
        let start = ScanError::from_message("scan.start", "scan: not_found: gone");
        assert_eq!(start.not_found_job(), None, "a launch tag heals nothing");
        let bare = ScanError::from_message("scan.status", "scan: not_found: gone");
        assert_eq!(bare.not_found_job(), None, "an unkeyed tag names no job");
        let busy = ScanError::from_message("scan.status:scan-1a2b3c4d", "scan: busy: x");
        assert_eq!(busy.not_found_job(), None, "another code heals nothing");
        assert!(ScanError::from_message("scan.map", "scan: out_of_scope: x").is_refused_launch());
        assert!(!ScanError::from_message("scan.list", "scan: out_of_scope: x").is_refused_launch());
    }

    /// Fix round G, G28: the one since-last-request rule.
    #[test]
    fn due_counts_from_the_last_request() {
        assert!(!due(None, 100, 20), "never before a request left");
        assert!(due(Some(0), 20, 20));
        assert!(!due(Some(1), 20, 20));
        assert!(due(Some(5), 45, 40));
        assert!(
            !due(Some(50), 45, 40),
            "a clock behind the stamp is not due"
        );
    }

    #[test]
    fn tag_parts_splits_only_once() {
        assert_eq!(
            tag_parts("scan.issue:issue:with:colons"),
            ("scan.issue", Some("issue:with:colons"))
        );
    }
}
