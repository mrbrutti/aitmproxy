//! Stage-6 fix (scanner-v2 live e2e, `tests/e2e/scan/test_t1_catalogue.py`
//! core C): a script whose `reg.add_check` meta is missing `kinds` is refused
//! (spec D4, AC T1-6) — and the refusal must be *visible*: one log line, at
//! `error`, on the script tier's target, carrying the script name and the full
//! `ScriptError` Display that names the key. Both when the host runs `load(reg)`
//! at startup and when `script.reload` re-runs it.
//!
//! The recorder below is a bare `tracing::Subscriber`: this crate has no
//! `tracing-subscriber` dev-dependency and the assertion needs only the level,
//! the target and the rendered fields. It is installed as the process-wide
//! default, so this file holds exactly one test.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use aitm_core::{
    CommandHost, FlowId, Frontend, HttpFlow, HttpRequest, MemFlowStore, Params, ProxyClient,
    Registry, StdGuard, Value,
};
use aitm_plugin_rhai::config::{RhaiConfig, ScriptEntry};
use aitm_plugin_rhai::host_core::{MemoryFindingSink, ScriptServices};
use aitm_plugin_rhai::wire;
use tracing::field::{Field, Visit};
use tracing::{span, Event, Level, Metadata, Subscriber};

/// One event the recorder saw: its level, target, `message` and the other
/// fields rendered `name=value`.
#[derive(Debug, Clone)]
struct Recorded {
    level: Level,
    target: String,
    message: String,
    fields: String,
}

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Recorded>>,
}

impl Recorder {
    fn events(&self) -> Vec<Recorded> {
        self.events.lock().expect("recorder lock").clone()
    }

    /// The events at `warn` or above on the script tier's target.
    fn script_warnings(&self) -> Vec<Recorded> {
        self.events()
            .into_iter()
            .filter(|e| e.target == "aitm_plugin_rhai::script" && e.level <= Level::WARN)
            .collect()
    }
}

#[derive(Default)]
struct FieldText {
    message: String,
    fields: String,
}

impl Visit for FieldText {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

impl Subscriber for Recorder {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }
    fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
    fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut text = FieldText::default();
        event.record(&mut text);
        let meta = event.metadata();
        self.events.lock().expect("recorder lock").push(Recorded {
            level: *meta.level(),
            target: meta.target().to_string(),
            message: text.message,
            fields: text.fields,
        });
    }
    fn enter(&self, _: &span::Id) {}
    fn exit(&self, _: &span::Id) {}
}

struct StubClient;

impl ProxyClient for StubClient {
    fn send(
        &self,
        _req: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<HttpFlow>> + Send + '_>> {
        Box::pin(async { anyhow::bail!("stub client") })
    }
}

/// A per-test temp dir of `.rhai` files, removed on drop.
struct TempScripts(PathBuf);

impl TempScripts {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "aitm-rhai-load-error-log-{}-{}",
            std::process::id(),
            FlowId::new()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let path = self.0.join(format!("{name}.rhai"));
        std::fs::write(&path, body).expect("write script");
        path
    }
}

impl Drop for TempScripts {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The e2e cell's `e2e-broken` script: a full `CheckMeta` map minus `kinds`.
const BROKEN_SRC: &str = r#"// e2e-broken.rhai — a catalogue entry that is missing the required `kinds`.
const NAME = "e2e-broken";
const API  = "1";

fn load(reg) {
    reg.add_check(#{
        id: "e2e-broken",
        name: "E2E broken",
        class: "e2e",
        lanes: ["http"],
        intensity: "light",
        cost: "light",
        technique: "reflected",
        severity: "info",
        confidence_max: "tentative",
        needs_baseline: false,
        description: "e2e",
    }, |point| #{
        outcome: "clean",
        confidence: "tentative",
        evidence: #{},
        detail: "ok",
    });
}
"#;

/// The one line the operator must find in the log for a refused script.
const EXPECTED_MESSAGE_HEAD: &str =
    "script `e2e-broken`: reg.add_check `e2e-broken`: `kinds`: missing field `kinds`";

fn services(store: &Arc<MemFlowStore>) -> ScriptServices {
    ScriptServices {
        store: store.clone(),
        client: Arc::new(StubClient),
        browser: None,
        guard: Arc::new(StdGuard::default()),
        findings: Arc::new(MemoryFindingSink::new()),
        rt: tokio::runtime::Handle::current(),
    }
}

fn reload(registry: &Registry, store: &MemFlowStore, name: &str) -> anyhow::Result<Value> {
    let cmd = registry
        .command("script.reload")
        .expect("script.reload is registered");
    let client = StubClient;
    let guard = StdGuard::default();
    let host = CommandHost::new(store, &client, &guard, None).with_frontend(Frontend::Cli);
    cmd.invoke(
        Params::new(BTreeMap::from([(
            "name".to_string(),
            Value::Str(name.to_string()),
        )])),
        &host,
    )
}

fn assert_names_script_and_key(event: &Recorded, when: &str) {
    assert_eq!(event.level, Level::ERROR, "{when}: {event:?}");
    assert_eq!(
        event.target, "aitm_plugin_rhai::script",
        "{when}: {event:?}"
    );
    assert!(
        event.message.starts_with(EXPECTED_MESSAGE_HEAD),
        "{when}: the message is the ScriptError Display naming the key: {:?}",
        event.message
    );
    assert!(
        event.fields.contains("script=e2e-broken"),
        "{when}: the script field names the script: {:?}",
        event.fields
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_script_missing_kinds_logs_one_error_naming_it_at_startup_and_on_reload() {
    let recorder = Arc::new(Recorder::default());
    tracing::subscriber::set_global_default(Arc::clone(&recorder))
        .expect("this file installs the one global subscriber");

    let dir = TempScripts::new();
    let path = dir.write("e2e-broken", BROKEN_SRC);
    let store = Arc::new(MemFlowStore::new());
    let cfg = RhaiConfig {
        scripts: vec![ScriptEntry::new(&path)],
        ..RhaiConfig::default()
    };
    let tier = wire::build(cfg, services(&store)).expect("tier builds");
    assert!(
        tier.errors.is_empty(),
        "the script compiles; the refusal happens in load(reg): {:?}",
        tier.errors
    );
    let checks = Arc::clone(&tier.checks);
    assert!(
        recorder.script_warnings().is_empty(),
        "nothing is refused before load(reg) runs: {:?}",
        recorder.script_warnings()
    );

    // Startup: the registry runs every plugin's `load`, so the host runs the
    // script's `load(reg)` and the bad meta is refused.
    let mut registry = Registry::new();
    registry.add_plugin(Box::new(tier.host));
    registry.add_plugin(Box::new(tier.commands));

    let startup = recorder.script_warnings();
    assert_eq!(
        startup.len(),
        1,
        "exactly one warn-or-above line for the refused script at startup: {startup:?}"
    );
    assert_names_script_and_key(&startup[0], "startup");
    assert!(
        !checks
            .snapshot()
            .iter()
            .any(|c| c.meta().id == "e2e-broken"),
        "the refused check is not in the catalogue"
    );

    // Reload: `script.reload` re-runs `load(reg)`; the same refusal is logged
    // again (one more line) and returned to the caller.
    let err = reload(&registry, &store, "e2e-broken")
        .expect_err("reloading the still-broken script is an error");
    assert!(
        err.to_string().contains("`kinds`"),
        "the reload error names the key: {err}"
    );
    let after_reload = recorder.script_warnings();
    assert_eq!(
        after_reload.len(),
        2,
        "one more warn-or-above line for the refused reload: {after_reload:?}"
    );
    assert_names_script_and_key(&after_reload[1], "reload");
}
