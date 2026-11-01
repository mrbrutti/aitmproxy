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

    /// The tab's position in [`ScanTab::ALL`] (0-based).
    pub fn index(self) -> usize {
        match self {
            ScanTab::Profiles => 0,
            ScanTab::Jobs => 1,
            ScanTab::SiteMap => 2,
            ScanTab::Issues => 3,
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
    /// reply of that verb.
    pub last_error: Option<ScanError>,
    /// The tick the view was first opened on; `None` until then.
    pub opened_at_tick: Option<u64>,
}

impl ScanState {
    /// The focused pane's cursor and its row count, for the shared `nav()`
    /// keys (spec D11). `None` when the focused pane has no walkable list
    /// here: the Jobs detail scroll is the Jobs task's and the Issues detail
    /// flow cursor is the Issues task's, and an editor pane is dead while no
    /// profile is open.
    ///
    /// The Site map panes walk the v2 lists when `scan.sitemap` has filled
    /// them and the legacy `scan.discover` lists otherwise (D12: the legacy
    /// result renders as nodes and points in the same two panes), which is
    /// how today's endpoint and injection-point cursors survive the move.
    pub fn cursor_mut(&mut self) -> Option<(&mut usize, usize)> {
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
            ScanTab::SiteMap => match self.sitemap.pane {
                MapPane::Nodes => {
                    if self.sitemap.nodes.is_empty() {
                        let n = self.legacy.endpoints.len();
                        Some((&mut self.legacy.endpoint_cursor, n))
                    } else {
                        let n = self.sitemap.nodes.len();
                        Some((&mut self.sitemap.node_cursor, n))
                    }
                }
                MapPane::Points => {
                    if self.sitemap.points.is_empty() {
                        let n = self.legacy.points.len();
                        Some((&mut self.legacy.cursor, n))
                    } else {
                        let n = self.sitemap.points.len();
                        Some((&mut self.sitemap.point_cursor, n))
                    }
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

    /// Tab / BackTab: focus the active tab's next (or previous) pane.
    pub fn step_pane(&mut self, forward: bool) {
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
                    forward,
                )
            }
            ScanTab::Jobs => {
                self.jobs.pane = step(&[JobPane::List, JobPane::Detail], self.jobs.pane, forward)
            }
            ScanTab::SiteMap => {
                self.sitemap.pane = step(
                    &[MapPane::Nodes, MapPane::Points],
                    self.sitemap.pane,
                    forward,
                )
            }
            ScanTab::Issues => {
                self.issues.pane = step(
                    &[IssuePane::List, IssuePane::Detail],
                    self.issues.pane,
                    forward,
                )
            }
        }
    }

    /// Esc / `q`: close a focused secondary pane back to its list pane
    /// (D11). `true` when one was open, so the caller knows the key was
    /// spent here and the view stays.
    pub fn close_pane(&mut self) -> bool {
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

/// The next (or previous) entry of `all` after `cur`, wrapping. An entry not
/// in `all` stays put.
fn step<T: Copy + PartialEq>(all: &[T], cur: T, forward: bool) -> T {
    match all.iter().position(|x| *x == cur) {
        Some(i) => {
            let n = all.len();
            all[if forward {
                (i + 1) % n
            } else {
                (i + n - 1) % n
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

/// A failed `scan.*` call, coded when the core's message carries a D9 code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    /// The verb that failed.
    pub verb: String,
    /// The parsed code, `None` for a message outside the `scan: <code>: ...`
    /// shape (including a contract mismatch from [`parse_result`]).
    pub code: Option<ScanErrorCode>,
    /// The core's detail after the code, or the whole message when uncoded.
    pub detail: String,
}

impl ScanError {
    /// Read a `CallTaggedFailed` message. A message that does not parse as
    /// `scan: <code>: <detail>` is kept verbatim with `code: None`.
    pub fn from_message(verb: &str, message: &str) -> Self {
        match ScanErrorCode::parse_message(message) {
            Some((code, detail)) => Self {
                verb: verb.to_string(),
                code: Some(code),
                detail: detail.to_string(),
            },
            None => Self {
                verb: verb.to_string(),
                code: None,
                detail: message.to_string(),
            },
        }
    }

    /// The operator wording (spec D9): the code's fixed text, then `: `, then
    /// the detail; an uncoded error reads `<verb>: <detail>`.
    pub fn wording(&self) -> String {
        match self.code {
            Some(code) => format!("{}: {}", code_wording(code), self.detail),
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
/// with `code: None` and the serde message in the detail; nothing panics on
/// bus data.
pub fn parse_result<T: serde::de::DeserializeOwned>(
    verb: &str,
    value: &Value,
) -> Result<T, ScanError> {
    serde_json::from_value(value.clone()).map_err(|e| ScanError {
        verb: verb.to_string(),
        code: None,
        detail: format!("{verb}: reply did not match the contract ({e})"),
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

/// Reduce a scan target (`host`, `host:port`, `http://host/path?q`) to the bare
/// host the scope guard checks.
pub fn scan_host(raw: &str) -> String {
    let s = raw.trim();
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    s.rsplit_once(':').map_or(s, |(h, _)| h).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tabs_index_their_strip_order() {
        for (i, tab) in ScanTab::ALL.iter().enumerate() {
            assert_eq!(tab.index(), i);
        }
        assert_eq!(ScanTab::default(), ScanTab::Profiles);
        assert_eq!(ScanTab::SiteMap.label(), "Site map");
    }

    #[test]
    fn scan_host_strips_scheme_port_and_path() {
        assert_eq!(scan_host("http://127.0.0.1:8080/x?y#z"), "127.0.0.1");
        assert_eq!(scan_host(" example.test:443 "), "example.test");
        assert_eq!(scan_host("example.test"), "example.test");
    }

    #[test]
    fn tag_parts_splits_only_once() {
        assert_eq!(
            tag_parts("scan.issue:issue:with:colons"),
            ("scan.issue", Some("issue:with:colons"))
        );
    }
}
