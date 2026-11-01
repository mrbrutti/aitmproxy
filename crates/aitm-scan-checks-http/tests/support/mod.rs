//! The scripted [`ProbeHost`] every native-check test sends through.
//!
//! A check is pure logic: it decides what to send, reads what came back and
//! returns a verdict (spec D2). So a check test needs no socket and no server —
//! it needs a host that answers from a script and remembers what it was asked.
//! [`ScriptedHost`] is that host, and it is deliberately general, because every
//! later check task in this plan reuses it:
//!
//! - responses come from a table of `(payload substring, response)` pairs, first
//!   match wins, with a fallback for everything else, so a test says "when you
//!   see `1=1`, answer this" without caring how the check phrases the rest;
//! - every stimulus is recorded in order with its payload, its mode **and the
//!   target it would have gone to**, so a test can assert both what was sent and
//!   where — the open-redirect canary check depends on the second;
//! - `marker`, `budget_left`, `deadline`, `cancelled`, `baseline_fails` and the
//!   whole [`ScanProfile`] are caller-configurable, so the `Speed`/`Accuracy`
//!   branches of the blind checks and the stop-early contract in
//!   [`aitm_scan_model::Check::run`]'s doc are testable without a clock.
//!
//! The budget is real: every probe spends one and a probe with none left fails,
//! so a check that ignores `budget_left()` cannot quietly overspend here either.

// Shared by several test binaries; each one uses a different part of it.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;

use aitm_scan_model::{
    Accuracy, InsertionKind, InsertionPoint, LaneKind, Payload, PayloadMode, PointTrait, ProbeHost,
    ProbeResponse, RawProbe, ScanProfile, Speed,
};

/// The origin every scripted point lives on. Loopback and obviously the
/// project's own: no test here may name a host it does not control.
pub const TARGET_URL: &str = "http://127.0.0.1:8099/search";

/// One stimulus the host was asked to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// The payload text the check placed at the point.
    pub payload: String,
    /// How the check asked for it to be combined with the existing value.
    pub mode: PayloadMode,
    /// The URL the request would have gone to.
    pub target: String,
}

/// A `ProbeHost` that answers from a script and records what it was asked.
pub struct ScriptedHost {
    marker: String,
    target: String,
    baseline: ProbeResponse,
    baseline_fails: bool,
    probes_fail: bool,
    table: Vec<(String, ProbeResponse)>,
    fallback: ProbeResponse,
    sent: Mutex<Vec<Sent>>,
    baseline_calls: AtomicUsize,
    budget: AtomicU32,
    deadline: Instant,
    cancelled: bool,
    profile: ScanProfile,
}

impl Default for ScriptedHost {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedHost {
    /// A host with an empty script: every probe gets `200 text/html` with an
    /// empty body, the budget is sixteen and the deadline a minute out.
    #[must_use]
    pub fn new() -> Self {
        Self {
            marker: "abcd".to_string(),
            target: TARGET_URL.to_string(),
            baseline: html(200, ""),
            baseline_fails: false,
            probes_fail: false,
            table: Vec::new(),
            fallback: html(200, ""),
            sent: Mutex::new(Vec::new()),
            baseline_calls: AtomicUsize::new(0),
            budget: AtomicU32::new(16),
            deadline: Instant::now() + Duration::from_secs(60),
            cancelled: false,
            profile: ScanProfile::default(),
        }
    }

    /// Answer `resp` to the first probe whose payload contains `needle`.
    ///
    /// Entries are tried in the order they were added, so a specific rule goes
    /// before a general one.
    #[must_use]
    pub fn on(mut self, needle: &str, resp: ProbeResponse) -> Self {
        self.table.push((needle.to_string(), resp));
        self
    }

    /// Answer `resp` to every probe no table entry matched.
    #[must_use]
    pub fn with_fallback(mut self, resp: ProbeResponse) -> Self {
        self.fallback = resp;
        self
    }

    /// The response [`ProbeHost::baseline`] returns.
    #[must_use]
    pub fn with_baseline(mut self, resp: ProbeResponse) -> Self {
        self.baseline = resp;
        self
    }

    /// Make [`ProbeHost::baseline`] fail, as a lane does when the point's flow
    /// is gone or the guard refused the destination.
    #[must_use]
    pub fn with_baseline_fails(mut self, fails: bool) -> Self {
        self.baseline_fails = fails;
        self
    }

    /// Make every probe fail after it is recorded, as a lane does when the
    /// guard refuses the destination or the upstream connection dies.
    #[must_use]
    pub fn with_probes_failing(mut self, fails: bool) -> Self {
        self.probes_fail = fails;
        self
    }

    /// The job marker a check builds its canaries from.
    #[must_use]
    pub fn with_marker(mut self, marker: &str) -> Self {
        self.marker = marker.to_string();
        self
    }

    /// The URL recorded against every stimulus.
    #[must_use]
    pub fn with_target(mut self, url: &str) -> Self {
        self.target = url.to_string();
        self
    }

    /// Probes this host will still accept; the rest fail.
    #[must_use]
    pub fn with_budget(self, left: u32) -> Self {
        self.budget.store(left, Ordering::SeqCst);
        self
    }

    /// When the check run must be finished. Pass an `Instant` in the past to
    /// test the past-deadline branch.
    #[must_use]
    pub fn with_deadline(mut self, at: Instant) -> Self {
        self.deadline = at;
        self
    }

    /// Report the job as cancelled.
    #[must_use]
    pub fn with_cancelled(mut self, cancelled: bool) -> Self {
        self.cancelled = cancelled;
        self
    }

    /// The whole profile, for a check that reads more than speed and accuracy.
    #[must_use]
    pub fn with_profile(mut self, profile: ScanProfile) -> Self {
        self.profile = profile;
        self
    }

    /// The profile's time-versus-coverage dial.
    #[must_use]
    pub fn with_speed(mut self, speed: Speed) -> Self {
        self.profile.speed = speed;
        self
    }

    /// Which way the job leans on an uncertain verdict.
    #[must_use]
    pub fn with_accuracy(mut self, accuracy: Accuracy) -> Self {
        self.profile.accuracy = accuracy;
        self
    }

    /// Everything the host was asked to send, in order.
    #[must_use]
    pub fn sent_probes(&self) -> Vec<Sent> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The payload text of every stimulus, in order.
    #[must_use]
    pub fn sent(&self) -> Vec<String> {
        self.sent_probes().into_iter().map(|s| s.payload).collect()
    }

    /// The URL of every stimulus, in order.
    #[must_use]
    pub fn sent_targets(&self) -> Vec<String> {
        self.sent_probes().into_iter().map(|s| s.target).collect()
    }

    /// How many times the check asked for the baseline.
    #[must_use]
    pub fn baseline_calls(&self) -> usize {
        self.baseline_calls.load(Ordering::SeqCst)
    }

    /// Charge one probe, or report that the budget is gone.
    fn spend(&self) -> anyhow::Result<()> {
        let spent = self
            .budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            });
        if spent.is_err() {
            anyhow::bail!("the scripted host's probe budget is exhausted");
        }
        Ok(())
    }

    /// The scripted answer for `payload`: first table entry whose needle the
    /// payload contains, else the fallback.
    fn answer(&self, payload: &str) -> ProbeResponse {
        self.table
            .iter()
            .find(|(needle, _)| payload.contains(needle.as_str()))
            .map_or_else(|| self.fallback.clone(), |(_, resp)| resp.clone())
    }
}

impl ProbeHost for ScriptedHost {
    fn baseline(&self) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            self.baseline_calls.fetch_add(1, Ordering::SeqCst);
            if self.baseline_fails {
                anyhow::bail!("the scripted host has no baseline for this point");
            }
            self.spend()?;
            Ok(self.baseline.clone())
        })
    }

    fn probe<'a>(&'a self, payload: &'a Payload) -> BoxFuture<'a, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            self.sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Sent {
                    payload: payload.value.clone(),
                    mode: payload.mode,
                    target: self.target.clone(),
                });
            self.spend()?;
            if self.probes_fail {
                anyhow::bail!("the scripted host refused this probe");
            }
            Ok(self.answer(&payload.value))
        })
    }

    fn probe_raw(&self, req: RawProbe) -> BoxFuture<'_, anyhow::Result<ProbeResponse>> {
        Box::pin(async move {
            self.sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Sent {
                    payload: String::from_utf8_lossy(&req.body).into_owned(),
                    mode: PayloadMode::Replace,
                    target: req.url.clone(),
                });
            self.spend()?;
            if self.probes_fail {
                anyhow::bail!("the scripted host refused this raw probe");
            }
            Ok(self.answer(&req.url))
        })
    }

    fn marker(&self) -> String {
        self.marker.clone()
    }

    fn budget_left(&self) -> u32 {
        self.budget.load(Ordering::SeqCst)
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }

    fn profile(&self) -> &ScanProfile {
        &self.profile
    }

    fn cancelled(&self) -> bool {
        self.cancelled
    }

    fn held_flows(&self) -> Vec<aitm_core::Flow> {
        Vec::new()
    }
}

/// A response with an explicit status, header list and body.
#[must_use]
pub fn response(status: u16, headers: &[(&str, &str)], body: &str) -> ProbeResponse {
    ProbeResponse {
        status: Some(status),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        body: body.as_bytes().to_vec(),
        elapsed_ms: 11,
        flow: None,
        ws_frames: None,
        l4: None,
    }
}

/// An HTML response.
#[must_use]
pub fn html(status: u16, body: &str) -> ProbeResponse {
    response(
        status,
        &[("Content-Type", "text/html; charset=utf-8")],
        body,
    )
}

/// A JSON response.
#[must_use]
pub fn json(status: u16, body: &str) -> ProbeResponse {
    response(status, &[("Content-Type", "application/json")], body)
}

/// A redirect, with the realistic header order a server actually sends:
/// `Location` is **not** first, which is what a header matcher must cope with.
#[must_use]
pub fn redirect(status: u16, location: &str) -> ProbeResponse {
    response(
        status,
        &[
            ("Date", "Sat, 01 Nov 2026 00:00:00 GMT"),
            ("Server", "aitm-testtarget"),
            ("Content-Type", "text/html; charset=utf-8"),
            ("Location", location),
            ("Content-Length", "0"),
        ],
        "",
    )
}

/// An insertion point of `kind` named `name` on `url`, as a lane would hand one
/// to a check.
#[must_use]
pub fn point(kind: InsertionKind, name: &str, url: &str) -> InsertionPoint {
    InsertionPoint {
        id: format!("p-{name}"),
        lane: LaneKind::Http,
        kind,
        name: name.to_string(),
        path: None,
        example: Some("seed".to_string()),
        flow: None,
        site_node: None,
        traits: Vec::new(),
        frequency: 1,
        method: Some("GET".to_string()),
        url: Some(url.to_string()),
    }
}

/// The same point, carrying `traits`.
#[must_use]
pub fn point_with_traits(
    kind: InsertionKind,
    name: &str,
    url: &str,
    traits: Vec<PointTrait>,
) -> InsertionPoint {
    let mut p = point(kind, name, url);
    p.traits = traits;
    p
}
