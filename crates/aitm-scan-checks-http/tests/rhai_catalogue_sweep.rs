//! T3 plan Task 16 — the sweep over the whole shipped `active/` directory.
//!
//! The per-script suites (`rhai_injection.rs`, `rhai_file_and_xml.rs`,
//! `rhai_crlf_and_nosql.rs`, `rhai_site_level.rs`, `rhai_new_scripts.rs`) each
//! prove one script's logic. This file proves things about the *directory*:
//! that every file in it is a single well-formed check on the real bridge,
//! that the ids are exactly the fifteen the catalogue claims, that each of the
//! six classes spec D6 says must be reproducible really hands back a hint the
//! PoC engine can parse, that nothing sleeps or registers a command, and that
//! `scripts/bundled/README.md` lists exactly the checks that exist — Rhai and
//! native both. A new check that is not in the README's table fails here, by
//! design: the catalogue page is part of the contract, not commentary.
//!
//! Everything runs on the **real** T1b bridge through `tests/rhai_harness`
//! (decision D-2b-1) and on canned replies from the model's own
//! `RecordingHost`. No socket is opened. This is the inner loop; acceptance
//! evidence is Task 17's real scan against the project's own test target.

mod rhai_harness;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aitm_core::{SsrfPolicy, StdGuard};
use aitm_poc::Assertion;
use aitm_scan_checks_http::checks_with;
use aitm_scan_model::point::InsertionPoint;
use aitm_scan_model::testing::RecordingHost;
use aitm_scan_model::vocab::{InsertionKind, Outcome, PointTrait};

use rhai_harness::{active_dir, matchers_parse, point, run, Loaded, Replies};

/// The marker `RecordingHost` hands every check. The scripts whose oracle has
/// to recognise its own canary build it from `probe.marker()`, because a reply
/// table cannot know what the bridge's real `rand_text_alpha` minted.
const MARKER: &str = "aitm7f3a";

/// The fifteen shipped active checks, by id, sorted.
const DECLARED_IDS: [&str; 15] = [
    "cmdi",
    "cors",
    "crlf",
    "header-reflection",
    "headers",
    "ldapi",
    "methods",
    "nosqli",
    "nosqli-json",
    "path_traversal",
    "paths",
    "sqli",
    "ssrf",
    "ssti",
    "xxe",
];

/// The two ids that were **retired** when the native checks landed: a class is
/// implemented in one place, so neither may reappear in a catalogue table.
const RETIRED_IDS: [&str; 2] = ["open_redirect", "xss"];

/// Every `*.rhai` under `scripts/bundled/active/`, by file name, sorted.
fn active_files() -> Vec<String> {
    let dir = active_dir();
    let mut files: Vec<String> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", dir.display()))
        .map(|entry| entry.expect("a readable directory entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rhai"))
        .collect();
    files.sort();
    files
}

/// `scripts/bundled/README.md`, the catalogue page this sweep holds to the tree.
fn readme_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("scripts")
        .join("bundled")
        .join("README.md")
}

/// The ten native ids, read through the slot `crates/aitm/src/wire.rs` calls
/// at startup — the same construction `tests/catalogue.rs` makes.
fn native_ids() -> Vec<String> {
    checks_with(SsrfPolicy::default(), Arc::new(StdGuard::default()))
        .into_iter()
        .map(|check| check.meta().id.clone())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_active_script_declares_exactly_one_check() {
    let files = active_files();

    assert_eq!(
        files.len(),
        15,
        "scripts/bundled/active/ holds the fifteen shipped checks, found {files:?}"
    );

    for file in &files {
        let loaded = Loaded::load(file).unwrap_or_else(|err| panic!("{file} does not load: {err}"));
        assert_eq!(
            loaded.checks().len(),
            1,
            "{file} must register exactly one check"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_declared_meta_deserialises_into_check_meta() {
    let mut ids: Vec<String> = Vec::new();

    for file in active_files() {
        let check = Loaded::load(&file)
            .unwrap_or_else(|err| panic!("{file} does not load: {err}"))
            .single()
            .unwrap_or_else(|err| panic!("{err}"));
        // Reaching `meta()` at all is the assertion: the bridge refuses a map
        // it cannot deserialise into a `CheckMeta` at `load(reg)` time, so a
        // bad key or token would have failed `Loaded::load` above.
        ids.push(check.meta().id.clone());
    }
    ids.sort();

    assert_eq!(ids, DECLARED_IDS, "the shipped catalogue's ids");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_six_poc_classes_supply_a_hint() {
    // sqli — a quote appended to the value the application accepts provokes a
    // database error signature.
    let sqli = hint_of(
        "check-sqli.rhai",
        point(
            InsertionKind::Query,
            "id",
            "http://127.0.0.1:8080/item",
            Some("1"),
            &[],
        ),
        Replies::plain(200, "Item 1")
            .when(
                "1'",
                500,
                "You have an error in your SQL syntax; check the manual that corresponds to \
                 your MySQL server version near \"''\" at line 1",
            )
            .build(),
    )
    .await;
    assert_one_non_empty_all("check-sqli.rhai", &sqli);

    // ssti — a Jinja/Twig page renders the expression, so 73*79 comes back as
    // its product next to the job marker.
    let ssti = hint_of(
        "check-ssti.rhai",
        point(
            InsertionKind::Query,
            "name",
            "http://127.0.0.1:8080/greet",
            Some("world"),
            &[],
        ),
        Replies::plain(200, "Hello world!")
            .when("{{73*79}}", 200, "<h1>Hello aitm7f3a5767!</h1>")
            .build(),
    )
    .await;
    assert_one_non_empty_all("check-ssti.rhai", &ssti);

    // cmdi — a shell ran the separator's right-hand side: the two halves of the
    // marker come back joined and the `echo` command text is gone.
    let cmdi = hint_of(
        "check-command-injection.rhai",
        point(
            InsertionKind::Query,
            "host",
            "http://127.0.0.1:8080/ping",
            Some("1"),
            &[],
        ),
        Replies::plain(200, "ping: 1 is unreachable")
            .when("echo AITM", 200, "PING 1 ... 0 received\nAITM7F3A\n")
            .build(),
    )
    .await;
    assert_one_non_empty_all("check-command-injection.rhai", &cmdi);

    // path-traversal — the document root is walked out of and the account file
    // comes back.
    let traversal = hint_of(
        "check-path-traversal.rhai",
        point(
            InsertionKind::Query,
            "file",
            "http://127.0.0.1:8080/download",
            Some("readme.txt"),
            &[PointTrait::Filename],
        ),
        Replies::plain(404, "File not found")
            .when(
                "etc/passwd",
                200,
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n",
            )
            .build(),
    )
    .await;
    assert_one_non_empty_all("check-path-traversal.rhai", &traversal);

    // crlf — a front end percent-decodes the break and writes the canary header
    // the value carried into the reply's own header block.
    let crlf = hint_of(
        "check-crlf-injection.rhai",
        point(
            InsertionKind::Query,
            "next",
            "http://127.0.0.1:8080/login",
            Some("/home"),
            &[],
        ),
        Replies::plain(200, "Redirecting")
            .when_headers(
                "%0d%0aX-Aitm-Crlf:%20aitm7f3a",
                200,
                &[("x-aitm-crlf", MARKER)],
                "Redirecting",
            )
            .build(),
    )
    .await;
    assert_one_non_empty_all("check-crlf-injection.rhai", &crlf);

    // xxe — the parser resolves the one external entity and prints the file.
    let xxe = hint_of(
        "check-xxe.rhai",
        point(
            InsertionKind::EntireBody,
            "body",
            "http://127.0.0.1:8080/api/orders",
            Some("<order><id>1</id></order>"),
            &[],
        ),
        Replies::plain(200, "<ok/>")
            .when(
                "file:///etc/passwd",
                200,
                "<aitm7f3a>root:x:0:0:root:/root:/bin/bash</aitm7f3a>",
            )
            .build(),
    )
    .await;
    assert_one_non_empty_all("check-xxe.rhai", &xxe);
}

/// Run `file`'s check against `pt` and `host`, require a `vulnerable` verdict,
/// and hand back the `poc_hint` matchers the bridge parsed off it.
async fn hint_of(file: &str, pt: InsertionPoint, host: Arc<RecordingHost>) -> Vec<Assertion> {
    let check = Loaded::load(file)
        .unwrap_or_else(|err| panic!("{file} does not load: {err}"))
        .single()
        .unwrap_or_else(|err| panic!("{err}"));

    let verdict = run(&check, &pt, &host).await;

    assert_eq!(
        verdict.outcome,
        Outcome::Vulnerable,
        "{file} must call its vulnerable shape vulnerable, said: {}",
        verdict.detail
    );
    matchers_parse(&verdict).unwrap_or_else(|err| panic!("{file}: {err}"))
}

/// The hint's matcher list as the bridge stores it: one `Assertion`, which a
/// `matchers: [..]` list always parses to as an implicit `all`, with at least
/// one leaf under it.
fn assert_one_non_empty_all(file: &str, matchers: &[Assertion]) {
    assert_eq!(
        matchers.len(),
        1,
        "{file}: a `matchers` list is parsed into exactly one assertion, got {matchers:?}"
    );
    match &matchers[0] {
        Assertion::All(inner) => assert!(
            !inner.is_empty(),
            "{file}: the hint's `all` has no matcher under it"
        ),
        other => panic!("{file}: a `matchers` list parses as `all`, got {other:?}"),
    }
}

#[test]
fn no_active_script_calls_sleep() {
    for file in active_files() {
        let source = fs::read_to_string(active_dir().join(&file)).expect("a readable script");
        assert!(
            !source.contains("sleep("),
            "{file} calls sleep(): a check never waits, it reads `elapsed_ms` and \
             gives the pairs to probe.timing_fit"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_active_script_registers_a_command() {
    for file in active_files() {
        let loaded =
            Loaded::load(&file).unwrap_or_else(|err| panic!("{file} does not load: {err}"));
        assert!(
            !loaded.source().contains("add_command"),
            "{file} names add_command: an active check registers a check, and the \
             engine's catalogue bridge gives it its check.<id> verb"
        );
        assert_eq!(
            loaded.command_names(),
            Vec::<String>::new(),
            "{file} registered a command"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_readme_table_lists_every_check() {
    let path = readme_path();
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    let rows = catalogue_table_ids(&text);

    assert_eq!(
        rows.len(),
        25,
        "the two catalogue tables hold one row per check, found {rows:?}"
    );

    let mut expected: BTreeSet<String> = DECLARED_IDS.iter().map(|id| (*id).to_string()).collect();
    expected.extend(native_ids());
    assert_eq!(
        expected.len(),
        25,
        "fifteen Rhai ids and ten native ids, all distinct"
    );

    let listed: BTreeSet<String> = rows.iter().cloned().collect();
    let missing: Vec<&String> = expected.difference(&listed).collect();
    let extra: Vec<&String> = listed.difference(&expected).collect();

    assert!(
        missing.is_empty(),
        "scripts/bundled/README.md's catalogue tables do not list {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "scripts/bundled/README.md's catalogue tables list {extra:?}, which no check declares"
    );

    for retired in RETIRED_IDS {
        assert!(
            !listed.contains(retired),
            "scripts/bundled/README.md still has a catalogue row for the retired `{retired}`"
        );
    }
}

/// The first-column id of every row of the README's two catalogue tables — the
/// Rhai one and the native one, which sit between the `active/` heading and
/// the `l4/` one. Rows are the lines that open with a back-ticked cell, so the
/// headings, the prose and the other tables on the page are not read.
fn catalogue_table_ids(readme: &str) -> Vec<String> {
    let lines: Vec<&str> = readme.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with("### HTTP") && line.contains("active checks"))
        .expect("the README has an `### HTTP — active checks` heading");
    let end = lines
        .iter()
        .position(|line| line.starts_with("### L4"))
        .expect("the README has an `### L4` heading");
    assert!(
        start < end,
        "the catalogue tables sit between the active-checks heading and the L4 one"
    );

    lines[start..end]
        .iter()
        .filter(|line| line.starts_with("| `"))
        .map(|line| {
            line.split('`')
                .nth(1)
                .expect("a row that opens with a back-tick closes it")
                .to_string()
        })
        .collect()
}
