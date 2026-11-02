//! The job bus: a generic progress channel.
//!
//! Any long-running command (`session.load`, `l4.capture`, `poc.run`, a scanner
//! job) publishes [`JobEvent`]s here; a frontend subscribes and renders them.
//! The bus is deliberately uninterpreted: `kind` and `payload` are the
//! publisher's vocabulary, and a server that does not know a `kind` still
//! forwards it verbatim, so a new kind of job needs no change here or in any
//! server. Publishing never blocks and never fails — a job must not be held up,
//! or stopped, by the absence or the slowness of a listener.

use crate::value::Value;

/// One progress event from a running job.
///
/// `job` is the publisher's job id, `kind` the job family (e.g. `scan`),
/// `event` the step within it (e.g. `started`, `progress`, `finished`), `seq` a
/// per-job counter the receiver can use to spot a gap after a lagged subscriber,
/// and `payload` whatever the publisher wants to carry (servers pass it through).
#[derive(Debug, Clone, PartialEq)]
pub struct JobEvent {
    /// The publisher's job id (e.g. `scan-1a2b3c4d`).
    pub job: String,
    /// The job family, which no consumer has to interpret (e.g. `scan`).
    pub kind: String,
    /// The step within the job (e.g. `started`, `progress`, `finished`).
    pub event: String,
    /// A per-job counter, so a receiver can detect a gap.
    pub seq: u64,
    /// Publisher-defined detail, forwarded verbatim.
    pub payload: Value,
}

/// How many events the bus buffers per subscriber before the slowest ones start
/// losing the oldest (a broadcast channel's `Lagged`). Progress is disposable:
/// a lagging frontend drops events rather than back-pressuring the job.
pub const DEFAULT_JOB_BUS_CAPACITY: usize = 1024;

/// A fan-out channel of [`JobEvent`]s from running jobs to any number of
/// listeners. Cheap to clone the receivers out of; the bus itself is shared by
/// `Arc`.
#[derive(Debug)]
pub struct JobBus {
    tx: tokio::sync::broadcast::Sender<JobEvent>,
}

impl JobBus {
    /// A bus buffering `capacity` events per subscriber. A capacity of `0` is
    /// not a valid broadcast channel, so it is raised to `1`: a misconfigured
    /// capacity degrades delivery, it never panics.
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// Send `event` to every current subscriber and return how many received
    /// it. With no subscriber this is `0`, which is not an error: a job runs
    /// whether or not anyone is watching.
    pub fn publish(&self, event: JobEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }

    /// A receiver that sees every event published from now on.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<JobEvent> {
        self.tx.subscribe()
    }

    /// How many subscribers are currently attached.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for JobBus {
    /// A bus with [`DEFAULT_JOB_BUS_CAPACITY`].
    fn default() -> Self {
        Self::new(DEFAULT_JOB_BUS_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;
    use std::collections::BTreeMap;

    fn event(seq: u64) -> JobEvent {
        JobEvent {
            job: "scan-1a2b3c4d".to_string(),
            kind: "scan".to_string(),
            event: "progress".to_string(),
            seq,
            payload: Value::Object(BTreeMap::new()),
        }
    }

    #[test]
    fn publish_without_subscribers_returns_zero() {
        let bus = JobBus::default();
        assert_eq!(bus.receiver_count(), 0);
        assert_eq!(bus.publish(event(1)), 0);
    }

    #[tokio::test]
    async fn subscriber_receives_events_in_order() {
        let bus = JobBus::new(DEFAULT_JOB_BUS_CAPACITY);
        let mut rx = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1);
        for seq in 1..=3 {
            assert_eq!(bus.publish(event(seq)), 1);
        }
        let mut seen = Vec::new();
        for _ in 0..3 {
            let ev = rx.recv().await.expect("the bus is open");
            seen.push(ev.seq);
        }
        assert_eq!(seen, vec![1, 2, 3]);
        assert_eq!(bus.receiver_count(), 1);
    }

    #[test]
    fn capacity_is_at_least_one() {
        let bus = JobBus::new(0);
        let _rx = bus.subscribe();
        assert_eq!(bus.publish(event(1)), 1);
    }

    /// Tester: a subscriber slower than the buffer is told how many events it
    /// lost (`Lagged(n)`) and then resumes at the newest survivors — progress is
    /// dropped, never back-pressured, and `seq` lets it see the gap.
    #[tokio::test]
    async fn lagged_subscriber_is_told_what_it_missed_then_sees_the_newest() {
        let bus = JobBus::new(2);
        let mut rx = bus.subscribe();
        for seq in 1..=5 {
            assert_eq!(
                bus.publish(event(seq)),
                1,
                "a full buffer never fails publish"
            );
        }

        match rx.recv().await {
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => assert_eq!(n, 3),
            other => panic!("expected Lagged(3), got {other:?}"),
        }
        assert_eq!(rx.recv().await.expect("open").seq, 4);
        assert_eq!(rx.recv().await.expect("open").seq, 5);
    }

    /// Tester: every attached subscriber gets every event, a dropped one stops
    /// counting, and the job keeps publishing after its last listener leaves.
    #[tokio::test]
    async fn every_subscriber_receives_every_event_and_dropping_one_is_harmless() {
        let bus = JobBus::default();
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2);

        assert_eq!(bus.publish(event(1)), 2);
        assert_eq!(a.recv().await.expect("open"), event(1));
        assert_eq!(b.recv().await.expect("open"), event(1));

        drop(a);
        assert_eq!(bus.receiver_count(), 1);
        assert_eq!(bus.publish(event(2)), 1);
        assert_eq!(b.recv().await.expect("open").seq, 2);

        drop(b);
        assert_eq!(bus.receiver_count(), 0);
        assert_eq!(bus.publish(event(3)), 0, "no listener is not an error");
    }

    /// Tester: a subscriber sees only what is published after it attached; a
    /// late UI polls `scan.status` for truth rather than replaying history.
    #[tokio::test]
    async fn a_late_subscriber_does_not_see_earlier_events() {
        let bus = JobBus::default();
        assert_eq!(bus.publish(event(1)), 0);
        let mut rx = bus.subscribe();
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(bus.publish(event(2)), 1);
        assert_eq!(rx.recv().await.expect("open").seq, 2);
    }

    /// Tester: publishing into a full buffer nobody drains never blocks the
    /// publisher — ten thousand events against a one-slot buffer return at once.
    #[test]
    fn publish_never_blocks_on_an_unread_full_buffer() {
        let bus = JobBus::new(1);
        let _rx = bus.subscribe();
        let started = std::time::Instant::now();
        for seq in 0..10_000 {
            assert_eq!(bus.publish(event(seq)), 1);
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "publish must not wait on a slow subscriber"
        );
    }

    /// Tester: the payload and every field arrive verbatim, nested structure
    /// included — the bus forwards a `kind` it does not understand untouched.
    #[tokio::test]
    async fn event_fields_and_payload_arrive_verbatim() {
        let bus = JobBus::default();
        let mut rx = bus.subscribe();
        let payload = Value::Object(BTreeMap::from([
            ("state".to_string(), Value::Str("running".to_string())),
            (
                "probes".to_string(),
                Value::Object(BTreeMap::from([
                    ("sent".to_string(), Value::Int(12)),
                    ("budget".to_string(), Value::Int(2000)),
                ])),
            ),
            (
                "lanes".to_string(),
                Value::Array(vec![Value::Str("http".to_string()), Value::Null]),
            ),
        ]));
        let sent = JobEvent {
            job: "ld-0001".to_string(),
            kind: "session.load".to_string(),
            event: "progress".to_string(),
            seq: u64::MAX,
            payload,
        };
        assert_eq!(bus.publish(sent.clone()), 1);
        assert_eq!(rx.recv().await.expect("open"), sent);
    }
}
