//! Stage-6 fix (wave-2/3 security review of plan T1b): the `probe.*` host
//! functions bounded against a hostile in-scope target.
//!
//! - `probe.levenshtein_ratio` runs natively on the worker thread, where
//!   neither the check budget nor `scan.cancel` can interrupt it, over bodies
//!   the target chose. It must be bounded work whatever the input size.
//! - `probe.raw`'s `method` is copied onto the wire; a method carrying CR/LF
//!   would split a second request onto the connection. Only an HTTP token is a
//!   method.
//!
//! Scripts are loaded the way `tests/check_bridge.rs` loads them, through the
//! real loader and bridge, and probes land on a `RecordingHost`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aitm_core::{HttpFlow, HttpRequest, MemFlowStore, ProxyClient, Registry, StdGuard};
use aitm_plugin_rhai::command::ScriptRegHandle;
use aitm_plugin_rhai::config::RhaiConfig;
use aitm_plugin_rhai::error::ScriptError;
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::host_probe::LEVENSHTEIN_MAX_BYTES;
use aitm_plugin_rhai::levenshtein_ratio;
use aitm_plugin_rhai::loader::RhaiLoader;
use aitm_scan_model::check::Verdict;
use aitm_scan_model::registry::CheckRegistry;
use aitm_scan_model::testing::{query_point, RecordingHost};
use aitm_scan_model::traits::ProbeHost;
use aitm_scan_model::vocab::CheckOrigin;
use rhai::{Engine, AST};

/// A client no check here reaches: every probe goes through the `RecordingHost`.
struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

fn services() -> ScriptServices {
    ScriptServices {
        store: Arc::new(MemFlowStore::new()),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

/// The production loader: its engine carries the whole host surface, `probe.*`
/// included.
fn loader() -> RhaiLoader {
    RhaiLoader::new(RhaiConfig::default(), services()).expect("the loader builds")
}

/// Compile `src` as the script named `name`, the way the loader does.
fn compile_named(engine: &Engine, name: &str, src: &str) -> Arc<AST> {
    let mut ast = engine.compile(src).expect("the script compiles");
    ast.set_source(name);
    Arc::new(ast)
}

/// Run `src`'s `load(reg)` through the real bridge, registering its checks into
/// `checks` under the script's own name.
fn run_load(
    loader: &RhaiLoader,
    checks: &Arc<CheckRegistry>,
    name: &str,
    src: &str,
) -> Result<Registry, ScriptError> {
    let engine = loader.engine();
    let ast = compile_named(&engine, name, src);
    let mut registry = Registry::new();
    ScriptRegHandle::new(&mut registry)
        .with_checks(
            Arc::clone(checks),
            CheckOrigin::Custom {
                path: name.to_string(),
            },
        )
        .run_load(&engine, &ast)?;
    Ok(registry)
}

/// The meta map every check in this file declares, as script text.
const META: &str = r#"#{ id: "bounds-check", name: "Bounds", class: "demo", lanes: ["http"],
     kinds: ["query"], intensity: "light", cost: "light",
     technique: "reflected", severity: "low", confidence_max: "certain",
     description: "d" }"#;

/// A script whose `load(reg)` registers one check with `body` as its closure.
fn check_script(body: &str) -> String {
    format!("fn load(reg) {{\n    reg.add_check({META}, |point| {body});\n}}")
}

/// The URL every `probe.raw` in this file aims at.
const RAW_URL: &str = "http://127.0.0.1:8080/x";

/// Load one check with `body` as its closure and run it against a recording
/// host answering `200 ok`. Returns the verdict and the host.
async fn verdict_of(body: &str) -> (Verdict, Arc<RecordingHost>) {
    let loader = loader();
    let checks = Arc::new(CheckRegistry::new());
    run_load(&loader, &checks, "<source>", &check_script(body)).expect("the script loads");

    let snapshot = checks.snapshot();
    assert_eq!(snapshot.len(), 1, "exactly one check is registered");
    let point = query_point("http://127.0.0.1:8080/search", "q");
    let host = RecordingHost::shared_new(200, "ok");
    let probe_host: &dyn ProbeHost = host.as_ref();
    let verdict = snapshot[0].run(&point, probe_host).await;
    (verdict, host)
}

/// A closure that calls `probe.raw(req)` and returns the error text, or
/// `"sent"` when the probe went through.
fn raw_script(req: &str) -> String {
    format!(
        r#"{{ let out = "sent";
             try {{ probe.raw({req}); }}
             catch (e) {{ out = "" + e; }}
             out }}"#
    )
}

/// Textbook Levenshtein distance, the slow way, for the differential check.
fn reference_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut table = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in table.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in table[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let substitution = table[i - 1][j - 1] + usize::from(a[i - 1] != b[j - 1]);
            table[i][j] = substitution
                .min(table[i - 1][j] + 1)
                .min(table[i][j - 1] + 1);
        }
    }
    table[a.len()][b.len()]
}

/// A tiny deterministic generator so the differential check is reproducible.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn word(&mut self, max_len: usize, alphabet: &[char]) -> String {
        let len = (self.next() % (max_len as u64 + 1)) as usize;
        (0..len)
            .map(|_| alphabet[(self.next() % alphabet.len() as u64) as usize])
            .collect()
    }
}

/// [Important] Two distinct 1 MiB bodies — the largest a `response_map` body
/// gets — cost no more than two 32 KiB ones, because only the first
/// `LEVENSHTEIN_MAX_BYTES` of each are compared. The strings differ at every
/// position, so no prefix/suffix shortcut can hide the work.
///
/// The bound is asserted two ways. Relative: the 1 MiB pair takes at most 4x
/// the 32 KiB pair measured in the same run on the same host — the unbounded
/// comparison would take ~1000x, whatever the load — which is the property the
/// cap guarantees. Absolute: under 10 s in the unoptimized test profile, where
/// the bit-parallel comparison at the cap measures 1.0–2.2 s on this host at
/// load averages of 20–70 and the cell-by-cell DP measured 38 s.
#[test]
fn levenshtein_ratio_is_bounded_on_huge_inputs() {
    const MIB: usize = 1024 * 1024;
    let a = "ab".repeat(MIB / 2);
    let b = "ba".repeat(MIB / 2);
    assert_eq!(a.len(), MIB);
    assert_eq!(b.len(), MIB);
    let (small_a, small_b) = (&a[..LEVENSHTEIN_MAX_BYTES], &b[..LEVENSHTEIN_MAX_BYTES]);

    let started = Instant::now();
    let small_ratio = levenshtein_ratio(small_a, small_b);
    let at_cap = started.elapsed();

    let started = Instant::now();
    let ratio = levenshtein_ratio(&a, &b);
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "two 1 MiB bodies took {elapsed:?}; the comparison must be bounded"
    );
    assert!(
        elapsed <= at_cap * 4 + Duration::from_millis(50),
        "1 MiB bodies took {elapsed:?} against {at_cap:?} for bodies at the cap; \
         work past the cap must not count"
    );
    assert!((0.0..=1.0).contains(&ratio), "ratio out of range: {ratio}");
    assert_eq!(
        ratio, small_ratio,
        "the 1 MiB pair is compared as its 32 KiB prefixes"
    );

    // The small case is unchanged: kitten/sitting is 3 edits over 7 chars.
    assert!(
        (levenshtein_ratio("kitten", "sitting") - 0.5714).abs() < 1e-3,
        "{}",
        levenshtein_ratio("kitten", "sitting")
    );
    assert_eq!(levenshtein_ratio("", ""), 1.0);
}

/// The cap is 32 KiB per input, bytes past it are never compared, and the cut
/// lands on a char boundary (a 3-byte char straddling byte 32 768 must not
/// panic the worker).
#[test]
fn levenshtein_ratio_compares_only_the_first_cap_bytes() {
    assert_eq!(LEVENSHTEIN_MAX_BYTES, 32 * 1024);

    let shared = "x".repeat(LEVENSHTEIN_MAX_BYTES);
    let a = format!("{shared}tail-one");
    let b = format!("{shared}a-different-tail");
    assert_eq!(
        levenshtein_ratio(&a, &b),
        1.0,
        "bytes past the cap must not take part in the comparison"
    );

    // 32 768 % 3 == 2: the cap falls inside a '€'.
    let euros = "€".repeat(LEVENSHTEIN_MAX_BYTES / 3 + 8);
    let mut other = euros.clone();
    other.push_str("¥¥¥¥");
    assert_eq!(levenshtein_ratio(&euros, &euros), 1.0);
    assert_eq!(levenshtein_ratio(&euros, &other), 1.0);

    // Just under the cap the whole string still counts: one edit in 32 767.
    let short = "y".repeat(LEVENSHTEIN_MAX_BYTES - 1);
    let mut edited = short.clone();
    edited.replace_range(100..101, "z");
    let expected = 1.0 - 1.0 / (LEVENSHTEIN_MAX_BYTES - 1) as f32;
    assert!(
        (levenshtein_ratio(&short, &edited) - expected).abs() < 1e-6,
        "{}",
        levenshtein_ratio(&short, &edited)
    );
}

/// Whatever the distance algorithm, the ratio must equal the textbook
/// definition — including inputs longer than a machine word, where a
/// bit-parallel implementation crosses word boundaries.
#[test]
fn levenshtein_ratio_matches_the_textbook_distance() {
    let alphabet: Vec<char> = "abcé€".chars().collect();
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for round in 0..400 {
        let max_len = if round % 4 == 0 { 300 } else { 70 };
        let a = rng.word(max_len, &alphabet);
        let b = rng.word(max_len, &alphabet);
        let longest = a.chars().count().max(b.chars().count());
        let expected = if longest == 0 {
            1.0
        } else {
            1.0 - reference_distance(&a, &b) as f32 / longest as f32
        };
        let got = levenshtein_ratio(&a, &b);
        assert!(
            (got - expected).abs() < 1e-6,
            "round {round}: {a:?} vs {b:?}: got {got}, expected {expected}"
        );
    }

    // Fixed points a reader can check by hand.
    assert_eq!(levenshtein_ratio("abc", "abc"), 1.0);
    assert_eq!(levenshtein_ratio("abc", ""), 0.0);
    assert_eq!(levenshtein_ratio("", "xyz"), 0.0);
    assert_eq!(levenshtein_ratio("flaw", "lawn"), 0.5);
    let sixty_five = "a".repeat(65);
    let mut last_changed = sixty_five.clone();
    last_changed.replace_range(64..65, "b");
    assert!((levenshtein_ratio(&sixty_five, &last_changed) - (1.0 - 1.0 / 65.0)).abs() < 1e-6);
}

/// The script-facing verb gives the same figure as the Rust function.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn levenshtein_ratio_is_available_to_a_check() {
    let (verdict, _host) = verdict_of(r#""" + probe.levenshtein_ratio("kitten", "sitting")"#).await;
    let ratio: f64 = verdict
        .detail
        .parse()
        .unwrap_or_else(|_| panic!("a float in the detail, got {:?}", verdict.detail));
    assert!((ratio - 0.5714).abs() < 1e-3, "{ratio}");
}

/// [Minor] `probe.raw`'s `method` must be an RFC 9110 token: a method with
/// CR/LF in it would smuggle a second request onto the connection, and an
/// empty one is not a method. Each refusal names `method` and reaches no host;
/// an unusual but well-formed token (`PURGE`) goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_refuses_a_non_token_method() {
    let smuggle =
        format!(r#"#{{ method: "GET / HTTP/1.1\r\nHost: a\r\n\r\nPOST", url: "{RAW_URL}" }}"#);
    let (verdict, host) = verdict_of(&raw_script(&smuggle)).await;
    assert!(
        verdict.detail.contains("method"),
        "the refusal must name the field: {:?}",
        verdict.detail
    );
    assert!(
        host.raw_urls().is_empty(),
        "a refused request must never reach the host: {:?}",
        host.raw_urls()
    );

    let empty = format!(r#"#{{ method: "", url: "{RAW_URL}" }}"#);
    let (verdict, host) = verdict_of(&raw_script(&empty)).await;
    assert!(
        verdict.detail.contains("method"),
        "an empty method is refused by name: {:?}",
        verdict.detail
    );
    assert!(host.raw_urls().is_empty(), "{:?}", host.raw_urls());

    let spaced = format!(r#"#{{ method: "GET X", url: "{RAW_URL}" }}"#);
    let (verdict, host) = verdict_of(&raw_script(&spaced)).await;
    assert!(verdict.detail.contains("method"), "{:?}", verdict.detail);
    assert!(host.raw_urls().is_empty(), "{:?}", host.raw_urls());

    let too_long = format!(r#"#{{ method: "{}", url: "{RAW_URL}" }}"#, "M".repeat(33));
    let (verdict, host) = verdict_of(&raw_script(&too_long)).await;
    assert!(verdict.detail.contains("method"), "{:?}", verdict.detail);
    assert!(host.raw_urls().is_empty(), "{:?}", host.raw_urls());

    let not_a_string = format!(r#"#{{ method: 7, url: "{RAW_URL}" }}"#);
    let (verdict, host) = verdict_of(&raw_script(&not_a_string)).await;
    assert!(verdict.detail.contains("method"), "{:?}", verdict.detail);
    assert!(host.raw_urls().is_empty(), "{:?}", host.raw_urls());

    let purge = format!(r#"#{{ method: "PURGE", url: "{RAW_URL}" }}"#);
    let (verdict, host) = verdict_of(&raw_script(&purge)).await;
    assert_eq!(verdict.detail, "sent", "a well-formed token is accepted");
    assert_eq!(host.raw_urls(), vec![RAW_URL.to_string()]);

    // No method at all is still a GET.
    let default = format!(r#"#{{ url: "{RAW_URL}" }}"#);
    let (verdict, host) = verdict_of(&raw_script(&default)).await;
    assert_eq!(verdict.detail, "sent");
    assert_eq!(host.raw_urls(), vec![RAW_URL.to_string()]);
}
