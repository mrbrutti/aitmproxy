//! Scanner v2 TUI, plan task 9: the Site map tab (spec D6, D8, D10, D11,
//! D12, D13) and the origin rule.
//!
//! Entering the tab reads `scan.sitemap {query}`; the reply renders the nodes
//! grouped under `host[:port]` headers and the selected node's points; `n`
//! appends the next page while `next_cursor` is `Some`; `J` toggles the job
//! query and refetches; `Enter` opens a node's first flow or a point's flow
//! through the flow store with the one "not in the flow list" toast; a
//! crawling job refreshes the map every forty ticks and a terminal line for a
//! matching job refreshes it at once. `origin_choices` and `typed_origin`
//! are the D8 rule: `https://host` from scope, one `http://host[:port]` per
//! plain-http authority captured, a typed scheme kept, an IPv6 host
//! bracketed, any other colon-bearing host refused.
//!
//! Fixture-driven: this proves the reducer, the rule and the rendering only.
//! Acceptance is the pty cell against a real core (spec Acceptance criteria,
//! "Live").

mod common;

use aitm_tui::action::{Action, BusEvent, BusRequest};
use aitm_tui::app::{App, Mode};
use aitm_tui::caps::TermCaps;
use aitm_tui::model::FlowRow;
use aitm_tui::scan::{
    origin_choices, typed_origin, IssueFilterKey, MapPane, OriginChoice, OriginError, OriginSource,
    ScanTab, AUDITED_MARK, ORIGIN_HOST_ERROR, POINT_TRAITS_MAX, SITEMAP_PAGE_LIMIT,
    SITEMAP_POLL_TICKS, SITEMAP_TOTAL_LIMIT, SITEMAP_VALUE_MAX,
};
use common::*;
use serde_json::{json, Value};

const TOOLS: &[&str] = &[
    "scan.start",
    "scan.list",
    "scan.status",
    "scan.sitemap",
    "scan.issues",
    "scan.cancel",
];

const JOB: &str = "scan-1a2b3c4d";
/// The one flow of `scan.sitemap.json`'s node and of its first point.
const NODE_FLOW: &str = "550e8400-e29b-41d4-a716-446655440000";
/// The flow of `scan.sitemap.json`'s second (cookie) point.
const COOKIE_FLOW: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

/// A connected v2 app at 200x50 on the Profiles tab offering `tools`, the
/// `scan.list` its open issued already settled empty, so nothing is in
/// flight.
fn app_with(tools: &[&str]) -> App {
    let mut app = App::new(TermCaps::full(), "127.0.0.1:9090");
    let _ = app.update(Action::Resize(200, 50));
    let _ = connect(&mut app, tools, None);
    let _ = app.update(Action::OpenScan);
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value: json!({ "jobs": [] }),
    });
    assert_eq!(app.mode, Mode::Scan);
    assert_eq!(app.scan.tab, ScanTab::Profiles);
    assert!(
        app.scan.inflight.is_empty(),
        "nothing in flight at the start"
    );
    app
}

fn app() -> App {
    app_with(TOOLS)
}

/// The `scan.sitemap` request under its single-slot tag.
fn sitemap_request(args: Value) -> BusRequest {
    BusRequest::CallTagged {
        tag: "scan.sitemap".into(),
        name: "scan.sitemap".into(),
        args,
    }
}

/// A `scan.sitemap` reply under its tag.
fn sitemap_reply(body: Value) -> BusEvent {
    BusEvent::CallTaggedOk {
        tag: "scan.sitemap".into(),
        name: "scan.sitemap".into(),
        value: body,
    }
}

/// The `scan.sitemap` requests among `reqs`, as their arguments.
fn sitemap_requests(reqs: &[BusRequest]) -> Vec<&Value> {
    reqs.iter()
        .filter_map(|r| match r {
            BusRequest::CallTagged { name, args, .. } if name == "scan.sitemap" => Some(args),
            _ => None,
        })
        .collect()
}

/// A `notifications/aitm/job` push line.
fn job_line(params: Value) -> BusEvent {
    BusEvent::Notification(json!({
        "jsonrpc": "2.0",
        "method": "notifications/aitm/job",
        "params": params,
    }))
}

/// The `scan.status.json` reply for `JOB` with its state and phase replaced.
fn status_reply(state: &str, phase: &str) -> BusEvent {
    let mut body = fixture("scan.status.json");
    body["state"] = json!(state);
    body["phase"] = json!(phase);
    BusEvent::CallTaggedOk {
        tag: format!("scan.status:{JOB}"),
        name: "scan.status".into(),
        value: body,
    }
}

/// Enter the Site map tab and settle its entry read with `scan.sitemap.json`.
fn open_site_map(app: &mut App) {
    let reqs = app.update(Action::ScanTab(ScanTab::SiteMap));
    assert_eq!(
        reqs,
        vec![sitemap_request(json!({}))],
        "entering the Site map reads it with the empty query (D6)"
    );
    let _ = app.on_bus(sitemap_reply(fixture("scan.sitemap.json")));
    assert!(
        !app.scan.inflight.contains("scan.sitemap"),
        "the entry read is settled: {:?}",
        app.scan.inflight
    );
}

/// The pane segment (between box or pane rules) of the first row carrying
/// `needle`, trimmed.
fn pane_row(text: &str, needle: &str) -> String {
    let line = line_with(text, needle).unwrap_or_else(|| panic!("no row with {needle:?}:\n{text}"));
    line.split('│')
        .find(|seg| seg.contains(needle))
        .expect("the needle's pane")
        .trim()
        .to_string()
}

fn screen(app: &App) -> String {
    text_of(app, 200, 50)
}

/// A `flow.get` summary with its scheme set.
fn summary_with_scheme(id: &str, scheme: &str, authority: &str) -> FlowRow {
    let mut v = summary(id, "GET", authority, "/login", Some(200), "none");
    v["scheme"] = json!(scheme);
    FlowRow::from_summary(&v, 1).expect("a summary with an id parses")
}

fn origins(choices: &[OriginChoice]) -> Vec<&str> {
    choices.iter().map(|c| c.origin.as_str()).collect()
}

/// T7-10: the fixture renders the host header, the node line with its
/// counts and the audited mark, and the selected node's two points with
/// the example verbatim (redacted at the source); `n` asks for the next
/// page with the cursor, the second page appends, and without a cursor
/// `n` sends nothing.
#[test]
fn sitemap_renders_nodes_points_and_pages() {
    let mut app = app();
    open_site_map(&mut app);
    let text = screen(&app);
    assert!(
        line_with(&text, "127.0.0.1:8080").is_some(),
        "the host header groups the node: {text}"
    );
    // The rows as drawn, trimmed to their pane (fix round G, G30): the
    // node under the cursor with its method, counts and audited mark, the
    // fixed-width point rows (the first under the Points cursor).
    assert_eq!(
        pane_row(&text, "/account/{id}"),
        format!("> GET  /account/{{id}}  flows 1 · pts 2 · {AUDITED_MARK}")
    );
    assert_eq!(
        pane_row(&text, "profile.address.city"),
        "> json_value   city           profile.address.city     json     Lisbon"
    );
    assert_eq!(
        pane_row(&text, "<redacted>"),
        "cookie       theme          -                        id       <redacted>"
    );
    assert!(
        line_with(&text, "1 nodes · 2 points of node-1 · n next page").is_some(),
        "the summary line: {text}"
    );

    let reqs = app.update(Action::ScanNextPage);
    assert_eq!(
        reqs,
        vec![sitemap_request(json!({ "cursor": "node-2" }))],
        "n asks for the next page with the cursor"
    );
    let mut second = fixture("scan.sitemap.json");
    second["nodes"][0]["id"] = json!("node-2");
    second["nodes"][0]["path_template"] = json!("/second");
    second["nodes"][0]["audited"] = json!(false);
    second["points"] = json!([]);
    second["next_cursor"] = Value::Null;
    let _ = app.on_bus(sitemap_reply(second));
    assert_eq!(app.scan.sitemap.nodes.len(), 2, "the second page appends");
    assert_eq!(app.scan.sitemap.points.len(), 2, "the points are kept");
    assert_eq!(app.scan.sitemap.next_cursor, None);
    let text = screen(&app);
    let second_line = line_with(&text, "/second").unwrap_or_else(|| panic!("{text}"));
    assert!(
        !second_line.contains(AUDITED_MARK),
        "an unaudited node has no mark: {second_line:?}"
    );
    assert!(
        line_with(&text, "2 nodes · 2 points of node-1").is_some(),
        "the summary counts both pages and drops the paging hint: {text}"
    );
    let reqs = app.update(Action::ScanNextPage);
    assert!(reqs.is_empty(), "no cursor, no request: {reqs:?}");
}

/// Fix round G, G20: a point whose node is not yet listed is kept, sorted
/// last and not drawn; when `n` appends the page that carries its node the
/// point re-attaches and renders under that node.
#[test]
fn an_orphan_point_reattaches_when_its_node_arrives() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
    let mut first = fixture("scan.sitemap.json");
    first["points"][1]["site_node"] = json!("node-2");
    first["points"][1]["name"] = json!("orphan-theme");
    let _ = app.on_bus(sitemap_reply(first));
    assert_eq!(app.scan.sitemap.points.len(), 2, "the orphan is kept");
    assert_eq!(app.scan.sitemap.node_points(0), 0..1);
    let text = screen(&app);
    assert!(
        line_with(&text, "orphan-theme").is_none(),
        "an orphan is not drawn: {text}"
    );

    let _ = app.update(Action::ScanNextPage);
    let mut second = fixture("scan.sitemap.json");
    second["nodes"][0]["id"] = json!("node-2");
    second["nodes"][0]["path_template"] = json!("/second");
    second["points"] = json!([]);
    second["next_cursor"] = Value::Null;
    let _ = app.on_bus(sitemap_reply(second));
    assert_eq!(app.scan.sitemap.nodes.len(), 2);
    assert_eq!(app.scan.sitemap.node_points(1), 1..2, "re-attached");
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.sitemap.node_cursor, 1);
    let text = screen(&app);
    let line = line_with(&text, "orphan-theme")
        .unwrap_or_else(|| panic!("the point renders under node-2:\n{text}"));
    assert!(line.contains("cookie"), "{line:?}");
    assert!(
        line_with(&text, "2 nodes · 1 points of node-2").is_some(),
        "the summary counts the re-attached point: {text}"
    );
}

/// T7-10: `Enter` on a node opens its first flow and on a point its flow,
/// both through the flow store: a flow the store lacks is refused with the
/// one "not in the flow list" toast and the view stays; once a `Flows`
/// event carries the id the same key opens the inspector on it.
#[test]
fn enter_opens_the_nodes_first_flow_via_row() {
    let mut app = app();
    open_site_map(&mut app);
    assert_eq!(app.scan.sitemap.pane, MapPane::Nodes);
    app.selected = None;

    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Scan, "no inspector for an unknown flow");
    assert_eq!(app.selected, None);
    let t = toast(&app);
    assert!(
        t.contains(NODE_FLOW) && t.contains("not in the flow list"),
        "the refusal names the flow: {t:?}"
    );

    let _ = app.on_bus(BusEvent::Flows(vec![summary(
        NODE_FLOW,
        "GET",
        "127.0.0.1:8080",
        "/account/1",
        Some(200),
        "none",
    )]));
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Inspector, "the node's first flow opens");
    assert_eq!(app.selected.as_deref(), Some(NODE_FLOW));

    // The Points pane: the second point's flow is not in the store.
    app.mode = Mode::Scan;
    let _ = app.update(Action::ScanPaneNext);
    assert_eq!(app.scan.sitemap.pane, MapPane::Points);
    let _ = app.update(Action::Down);
    assert_eq!(
        app.scan.sitemap.point_offset, 1,
        "Down walks the node's points"
    );
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Scan);
    let t = toast(&app);
    assert!(
        t.contains(COOKIE_FLOW) && t.contains("not in the flow list"),
        "the refusal names the point's flow: {t:?}"
    );
    let _ = app.update(Action::Up);
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Inspector, "the first point's flow opens");
    assert_eq!(app.selected.as_deref(), Some(NODE_FLOW));
}

/// T7-10: `J` on the Site map toggles `query.job` between the Jobs
/// cursor's job and none, refetching each time with exactly that query; the
/// Issues filters are not touched.
#[test]
fn j_toggles_the_job_query_and_refetches() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value: fixture("scan.list.json"),
    });
    assert_eq!(app.scan.jobs.cursor_job().map(String::as_str), Some(JOB));
    open_site_map(&mut app);

    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Job));
    assert_eq!(app.scan.sitemap.query.job.as_deref(), Some(JOB));
    assert_eq!(
        sitemap_requests(&reqs),
        vec![&json!({ "job": JOB })],
        "the query names the job: {reqs:?}"
    );
    assert_eq!(
        app.scan.issues.filters.job, None,
        "the Issues filter is not touched"
    );
    let _ = app.on_bus(sitemap_reply(fixture("scan.sitemap.json")));

    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Job));
    assert_eq!(app.scan.sitemap.query.job, None);
    assert_eq!(
        sitemap_requests(&reqs),
        vec![&json!({})],
        "the query drops the job: {reqs:?}"
    );
}

/// Fix round G, G31: `J` with no job under the Jobs cursor leaves the
/// query unchanged and refetches nothing; with one it toggles and
/// refetches as before.
#[test]
fn j_without_a_jobs_cursor_job_refetches_nothing() {
    let mut app = app();
    open_site_map(&mut app);
    assert_eq!(app.scan.jobs.cursor_job(), None);
    let reqs = app.update(Action::ScanFilter(IssueFilterKey::Job));
    assert!(sitemap_requests(&reqs).is_empty(), "{reqs:?}");
    assert_eq!(app.scan.sitemap.query.job, None);
}

/// Fix round G, G15, G16, G17 (D6 hostile-core bounds): a point's traits
/// are deduped and capped at `POINT_TRAITS_MAX` at fold and its line is
/// built there; a `next_cursor` over `CURSOR_MAX` bytes is dropped (`n`
/// sends nothing) and recorded as an uncoded error; appended pages stop
/// at `SITEMAP_TOTAL_LIMIT` nodes, after which the cursor is dropped and
/// the summary says so.
#[test]
fn traits_cursor_and_total_are_bounded_at_fold() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
    let mut page = fixture("scan.sitemap.json");
    page["points"][0]["traits"] = json!(vec!["url"; 1_000_000]);
    page["next_cursor"] = json!("c".repeat(1 << 20));
    let _ = app.on_bus(sitemap_reply(page));
    let traits = &app.scan.sitemap.points[0].traits;
    assert!(traits.len() <= POINT_TRAITS_MAX, "{}", traits.len());
    assert_eq!(traits, &vec![aitm_scan_model::PointTrait::Url]);
    assert_eq!(app.scan.sitemap.point_lines.len(), 2);
    assert!(app.scan.sitemap.point_lines[0].contains("url"));
    assert_eq!(
        app.scan.sitemap.next_cursor, None,
        "an oversized cursor is dropped"
    );
    let err = app.scan.sitemap.error.as_ref().expect("recorded");
    assert_eq!(err.tag, "scan.sitemap");
    assert_eq!(err.detail, "next_cursor exceeds 1024 bytes");
    assert!(
        app.update(Action::ScanNextPage).is_empty(),
        "n sends nothing"
    );
    let text = screen(&app);
    assert!(line_with(&text, "profile.address.city").is_some(), "{text}");

    // Sixteen full pages reach the limit; the seventeenth is never asked
    // for (`n` is inert once the cursor is dropped).
    let mut app = app_with(TOOLS);
    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
    let template = fixture("scan.sitemap.json")["nodes"][0].clone();
    for page_no in 0..16 {
        let nodes: Vec<Value> = (0..SITEMAP_PAGE_LIMIT)
            .map(|k| {
                let mut n = template.clone();
                n["id"] = json!(format!("node-{page_no}-{k}"));
                n
            })
            .collect();
        let reqs = app.on_bus(sitemap_reply(json!({
            "nodes": nodes,
            "points": [],
            "next_cursor": format!("page-{}", page_no + 1),
        })));
        assert!(reqs.is_empty(), "{reqs:?}");
        let reqs = app.update(Action::ScanNextPage);
        assert_eq!(
            sitemap_requests(&reqs).len(),
            usize::from(page_no < 15),
            "page {page_no}: {reqs:?}"
        );
    }
    assert_eq!(app.scan.sitemap.nodes.len(), SITEMAP_TOTAL_LIMIT);
    assert_eq!(app.scan.sitemap.lines.len(), SITEMAP_TOTAL_LIMIT);
    assert_eq!(app.scan.sitemap.next_cursor, None);
    assert!(
        app.scan.sitemap.summary().contains("limit reached"),
        "{}",
        app.scan.sitemap.summary()
    );
    assert!(app.update(Action::ScanNextPage).is_empty());
    let _ = text_of(&app, 200, 50);
}

/// D6 cadence: while the Site map is shown and a job is crawling, the map
/// is re-read forty ticks after the last read; a job that is auditing, or
/// another tab, reads nothing. A terminal line for a job matching the
/// query re-reads at once.
#[test]
fn a_crawling_job_refreshes_the_map_on_the_timer_and_on_its_terminal_line() {
    let mut app = app();
    let _ = app.on_bus(BusEvent::CallTaggedOk {
        tag: "scan.list".into(),
        name: "scan.list".into(),
        value: fixture("scan.list.json"),
    });
    let _ = app.on_bus(status_reply("running", "crawling"));
    open_site_map(&mut app);
    let mut sitemap_reads = 0;
    for _ in 0..SITEMAP_POLL_TICKS {
        sitemap_reads += sitemap_requests(&app.update(Action::Tick)).len();
    }
    assert_eq!(
        sitemap_reads, 1,
        "one re-read forty ticks after the entry read"
    );
    let _ = app.on_bus(sitemap_reply(fixture("scan.sitemap.json")));

    let _ = app.on_bus(status_reply("running", "auditing"));
    let mut sitemap_reads = 0;
    for _ in 0..SITEMAP_POLL_TICKS {
        sitemap_reads += sitemap_requests(&app.update(Action::Tick)).len();
    }
    assert_eq!(sitemap_reads, 0, "an auditing job does not move the map");

    let _ = app.on_bus(status_reply("running", "crawling"));
    let _ = app.update(Action::ScanTab(ScanTab::Jobs));
    let mut sitemap_reads = 0;
    for _ in 0..SITEMAP_POLL_TICKS {
        sitemap_reads += sitemap_requests(&app.update(Action::Tick)).len();
    }
    assert_eq!(sitemap_reads, 0, "another tab reads nothing");

    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
    let _ = app.on_bus(sitemap_reply(fixture("scan.sitemap.json")));
    let reqs = app.on_bus(job_line(fixture("job.finished.json")));
    assert_eq!(
        sitemap_requests(&reqs),
        vec![&json!({})],
        "a terminal line for a matching job re-reads the map: {reqs:?}"
    );
}

/// T7-12 (D8): a concrete scope entry yields `https://host`; every distinct
/// plain-http authority captured for that host adds `http://host[:port]`,
/// the port dropped when it is 80; a wildcard entry yields nothing.
#[test]
fn origin_choices_follow_the_captured_schemes() {
    let mut flows = vec![summary_with_scheme("f1", "https", "auth.shop-staging.test")];
    let scope = vec!["auth.shop-staging.test".to_string()];
    let choices = origin_choices(&scope, &flows);
    assert_eq!(origins(&choices), vec!["https://auth.shop-staging.test"]);
    assert_eq!(choices[0].source, OriginSource::FromScope);

    flows.push(summary_with_scheme(
        "f2",
        "http",
        "auth.shop-staging.test:8080",
    ));
    let choices = origin_choices(&scope, &flows);
    assert_eq!(
        origins(&choices),
        vec![
            "https://auth.shop-staging.test",
            "http://auth.shop-staging.test:8080"
        ]
    );
    assert_eq!(choices[1].source, OriginSource::FromFlows);

    flows.push(summary_with_scheme(
        "f3",
        "http",
        "auth.shop-staging.test:80",
    ));
    flows.push(summary_with_scheme(
        "f4",
        "http",
        "auth.shop-staging.test:8080",
    ));
    flows.push(summary_with_scheme("f5", "http", "other.test"));
    let choices = origin_choices(&scope, &flows);
    assert_eq!(
        origins(&choices),
        vec![
            "https://auth.shop-staging.test",
            "http://auth.shop-staging.test:8080",
            "http://auth.shop-staging.test"
        ],
        "one choice per distinct authority, port 80 dropped, other hosts skipped"
    );

    assert!(
        origin_choices(&["*.shop-staging.test".to_string()], &flows).is_empty(),
        "a wildcard entry yields no choice"
    );
}

/// T7-12 (D8): a typed scheme is kept and the origin is the authority
/// alone; a bare host gets the first choice `origin_choices` would give
/// it; an IPv6 host is bracketed; any other colon-bearing host is refused.
#[test]
fn typed_origins_keep_their_scheme() {
    assert_eq!(
        typed_origin("https://api.shop-staging.test:8443/admin?x=1", &[]),
        Ok("https://api.shop-staging.test:8443".to_string())
    );
    let https_flows = vec![summary_with_scheme("f1", "https", "auth.shop-staging.test")];
    assert_eq!(
        typed_origin("auth.shop-staging.test", &https_flows),
        Ok("https://auth.shop-staging.test".to_string())
    );
    assert_eq!(
        typed_origin("::1", &[]),
        Ok("https://[::1]".to_string()),
        "a bare IPv6 host is bracketed"
    );
    assert_eq!(
        typed_origin("http://[::1]:8080/path", &[]),
        Ok("http://[::1]:8080".to_string())
    );
    assert_eq!(
        typed_origin("[fe80::1]", &[]),
        Ok("https://[fe80::1]".to_string())
    );
    for bad in ["host:abc", "http://a:b:c/", "https://", ""] {
        assert_eq!(
            typed_origin(bad, &[]),
            Err(OriginError::Host),
            "{bad:?} is refused"
        );
    }
}

/// D8 on the legacy path (D12): `:scan <host:port>` with a port that is not
/// a number passes the scope check on its host but fails the origin rule:
/// the error is toasted and nothing reaches the wire.
#[test]
fn a_colon_bearing_legacy_target_is_refused_with_a_toast_and_no_call() {
    let mut app = legacy_app(200, 50);
    let reqs = app.run_command("scan auth.shop-staging.test:abc");
    assert_eq!(app.mode, Mode::Scan, "the view still opens");
    assert!(!app.scan.legacy.running, "nothing was launched");
    assert!(
        !reqs
            .iter()
            .any(|r| matches!(r, BusRequest::Call { name, .. } if name == "scan.discover")),
        "nothing reaches the wire: {reqs:?}"
    );
    assert_eq!(toast(&app), ORIGIN_HOST_ERROR);
}

/// D6 hostile-core bounds: a page of thousands of nodes with very long
/// strings is cut to the page limit, its strings are bounded when folded,
/// and the view renders at any size without panicking; an empty page
/// renders the empty state.
#[test]
fn huge_and_empty_pages_render_within_bounds() {
    let mut app = app();
    let _ = app.update(Action::ScanTab(ScanTab::SiteMap));
    let long = "x".repeat(5000);
    let node = |k: usize| {
        json!({
            "id": format!("node-{k}"),
            "method": long,
            "scheme": "http",
            "host": format!("{long}{k}"),
            "port": 8080,
            "path_template": long,
            "flows": [NODE_FLOW],
            "points": 1,
            "audited": true,
        })
    };
    let nodes: Vec<Value> = (0..2000).map(node).collect();
    let points: Vec<Value> = (0..2000)
        .map(|k| {
            json!({
                "id": format!("point-{k}"),
                "lane": "http",
                "kind": "json_value",
                "name": long,
                "path": long,
                "example": long,
                "flow": NODE_FLOW,
                "site_node": format!("node-{k}"),
                "traits": ["json"],
                "frequency": 1,
            })
        })
        .collect();
    let _ = app.on_bus(sitemap_reply(json!({
        "nodes": nodes,
        "points": points,
        "next_cursor": long,
    })));
    assert_eq!(app.scan.sitemap.nodes.len(), SITEMAP_PAGE_LIMIT);
    assert_eq!(app.scan.sitemap.points.len(), SITEMAP_PAGE_LIMIT);
    // A cut string is at most the cap in cells plus the ellipsis; a cell
    // is at most four bytes, so the char count is bounded by it too.
    assert!(
        app.scan.sitemap.nodes[0].path_template.chars().count() <= 4 * SITEMAP_VALUE_MAX + 1,
        "the path is bounded at fold time"
    );
    for (w, h) in [(200, 50), (90, 40), (20, 5), (3, 2)] {
        let text = text_of(&app, w, h);
        assert!(
            text.lines().all(|l| l.chars().count() <= usize::from(w)),
            "{w}x{h} rows fit"
        );
    }
    let _ = app.update(Action::End);
    let _ = app.update(Action::ScanPaneNext);
    let _ = app.update(Action::End);
    let _ = app.update(Action::Enter);

    let _ = app.on_bus(sitemap_reply(json!({})));
    assert!(app.scan.sitemap.nodes.is_empty());
    let text = screen(&app);
    assert!(
        line_with(&text, "no site map yet").is_some(),
        "the empty state: {text}"
    );
    let _ = app.update(Action::Down);
    let _ = app.update(Action::Enter);
    assert_eq!(app.mode, Mode::Scan);
}

/// Fix round G, G24: the Points cursor is an offset within the selected
/// node, so the walk stops at that node's points without a sentinel; a
/// Nodes walk resets it, a fold clamps it, and `selected_point` is what
/// `Enter` and the view read.
#[test]
fn the_point_cursor_is_an_offset_within_the_selected_node() {
    let mut app = app();
    open_site_map(&mut app);
    assert_eq!(app.scan.sitemap.point_offset, 0);
    assert_eq!(
        app.scan.sitemap.selected_point().map(|p| p.name.as_str()),
        Some("city")
    );
    let _ = app.update(Action::ScanPaneNext);
    assert_eq!(app.scan.sitemap.pane, MapPane::Points);
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.sitemap.point_offset, 1);
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.sitemap.point_offset, 1, "the node has two points");
    let _ = app.update(Action::End);
    assert_eq!(app.scan.sitemap.point_offset, 1);
    assert_eq!(
        app.scan.sitemap.selected_point().map(|p| p.name.as_str()),
        Some("theme")
    );
    let text = screen(&app);
    let row = line_with(&text, "theme").unwrap_or_else(|| panic!("{text}"));
    assert!(
        row.contains("> cookie"),
        "the cursor marks the second point: {row:?}"
    );
    let _ = app.update(Action::Home);
    assert_eq!(app.scan.sitemap.point_offset, 0);

    // A second node without points: walking the Nodes pane onto it resets
    // the offset and leaves nothing selected.
    let _ = app.update(Action::End);
    let _ = app.update(Action::ScanNextPage);
    let mut second = fixture("scan.sitemap.json");
    second["nodes"][0]["id"] = json!("node-2");
    second["nodes"][0]["path_template"] = json!("/second");
    second["points"] = json!([]);
    second["next_cursor"] = Value::Null;
    let _ = app.on_bus(sitemap_reply(second));
    assert_eq!(
        app.scan.sitemap.point_offset, 1,
        "a fold keeps a still-valid offset"
    );
    let _ = app.update(Action::ScanPanePrev);
    assert_eq!(app.scan.sitemap.pane, MapPane::Nodes);
    let _ = app.update(Action::Down);
    assert_eq!(app.scan.sitemap.node_cursor, 1);
    assert_eq!(
        app.scan.sitemap.point_offset, 0,
        "a Nodes walk resets the offset"
    );
    assert_eq!(app.scan.sitemap.selected_point(), None);
    let _ = app.update(Action::ScanPaneNext);
    let _ = app.update(Action::Down);
    assert_eq!(
        app.scan.sitemap.point_offset, 0,
        "no points: nothing to walk"
    );
    let reqs = app.update(Action::Enter);
    assert!(reqs.is_empty());
    assert_eq!(app.mode, Mode::Scan, "Enter on no point opens nothing");
}
