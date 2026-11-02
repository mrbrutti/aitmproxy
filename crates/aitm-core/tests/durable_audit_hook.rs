//! The ring's durable hook (durable-audit spec, AC34) and the `mcp.audit_log`
//! setting type: public API only.

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use aitm_core::{
    AuditEntry, AuditLane, AuditLogSetting, AuditResult, AuditRing, AuditSink, CaConfig,
    DurableAudit, DurableAuditStatus, Frontend, McpConfig,
};

fn entry(command: &str) -> AuditEntry {
    AuditEntry {
        at: SystemTime::now(),
        origin: Frontend::Operator,
        client_label: None,
        connection_id: None,
        command: command.to_string(),
        args_summary: "{}".to_string(),
        result: AuditResult::Ok,
    }
}

/// A sink that records `(lane, command)` pairs and reports a fixed status.
#[derive(Debug, Default)]
struct StubSink {
    seen: Mutex<Vec<(AuditLane, String)>>,
}

impl StubSink {
    fn calls(&self) -> Vec<(AuditLane, String)> {
        self.seen.lock().expect("stub lock").clone()
    }
}

impl DurableAudit for StubSink {
    fn record(&self, lane: AuditLane, entry: AuditEntry) {
        self.seen
            .lock()
            .expect("stub lock")
            .push((lane, entry.command));
    }

    fn status(&self) -> DurableAuditStatus {
        DurableAuditStatus {
            degraded: true,
            dropped: 7,
            write_failures: 3,
        }
    }
}

/// A sink that calls back into the ring from inside `record`; it deadlocks if
/// the ring still holds its lock when it calls the hook.
#[derive(Debug)]
struct ReentrantSink {
    ring: Arc<AuditRing>,
    /// `(len, recent.len())` as the sink saw the ring from inside `record`.
    seen: Mutex<Vec<(usize, usize)>>,
}

impl DurableAudit for ReentrantSink {
    fn record(&self, _lane: AuditLane, _entry: AuditEntry) {
        let len = self.ring.len();
        let recent = self.ring.recent(None, None).len();
        self.seen
            .lock()
            .expect("reentrant lock")
            .push((len, recent));
    }

    fn status(&self) -> DurableAuditStatus {
        DurableAuditStatus::default()
    }
}

#[test]
fn the_ring_hook_is_set_once_and_lock_free() {
    let ring = AuditRing::new(8);
    assert_eq!(ring.durable_status(), None);

    let first = Arc::new(StubSink::default());
    assert!(
        ring.attach_durable(first.clone()),
        "the first attach_durable must succeed"
    );
    assert_eq!(
        ring.durable_status(),
        Some(DurableAuditStatus {
            degraded: true,
            dropped: 7,
            write_failures: 3,
        })
    );

    let second = Arc::new(StubSink::default());
    assert!(
        !ring.attach_durable(second.clone()),
        "a second attach_durable must return false"
    );

    ring.append_in(AuditLane::Routine, entry("e"));
    assert_eq!(first.calls(), vec![(AuditLane::Routine, "e".to_string())]);
    assert!(
        second.calls().is_empty(),
        "the second sink must never be called"
    );

    AuditSink::append(&ring, entry("f"));
    assert_eq!(
        first.calls(),
        vec![
            (AuditLane::Routine, "e".to_string()),
            (AuditLane::Evidence, "f".to_string()),
        ]
    );
    assert!(second.calls().is_empty());
    // The hook changes nothing the ring keeps.
    assert_eq!(ring.routine_len(), 1);
    assert_eq!(ring.evidence_len(), 1);

    // A sink that calls back into the ring must not deadlock: the ring's lock
    // is released before the hook runs.
    let ring = Arc::new(AuditRing::new(8));
    let reentrant = Arc::new(ReentrantSink {
        ring: ring.clone(),
        seen: Mutex::new(Vec::new()),
    });
    assert!(ring.attach_durable(reentrant.clone()));

    let (done_tx, done_rx) = mpsc::channel();
    let worker_ring = ring.clone();
    thread::spawn(move || {
        worker_ring.append_in(AuditLane::Evidence, entry("g"));
        let _ = done_tx.send(());
    });
    assert!(
        done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
        "the ring lock was held across the hook"
    );
    assert_eq!(ring.len(), 1);
    assert_eq!(
        *reentrant.seen.lock().expect("reentrant lock"),
        vec![(1, 1)],
        "the sink must see the entry already in the ring"
    );
}

#[test]
fn audit_log_setting_defaults_and_resolves() {
    assert_eq!(McpConfig::default().audit_log, AuditLogSetting::Default);

    // The default sits beside the CA audit log, in the same per-user directory.
    let ca = CaConfig::default().audit_log;
    let resolved = AuditLogSetting::Default.resolved_path();
    assert_eq!(resolved, Some(ca.with_file_name("audit.jsonl")));
    let path = resolved.as_deref().expect("Default resolves to a path");
    assert_eq!(
        path.file_name().and_then(|n| n.to_str()),
        Some("audit.jsonl")
    );
    assert_eq!(path.parent(), ca.parent());

    assert_eq!(AuditLogSetting::Off.resolved_path(), None);
    assert_eq!(
        AuditLogSetting::Path(PathBuf::from("/x/a.jsonl")).resolved_path(),
        Some(PathBuf::from("/x/a.jsonl"))
    );
}
