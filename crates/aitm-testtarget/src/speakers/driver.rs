//! The shared TCP/UDP driver behind the nine L4 speakers (spec D5).
//!
//! A [`Speaker`] is pure; this module owns the sockets, the log and the
//! clock. One task per service: `run_tcp` accepts connections and hands each
//! to its own [`Speaker`] instance, `run_udp` feeds every datagram to one
//! speaker. The driver turns each [`Step`] into writes, log entries and
//! closes through the pure [`apply`] decision table, and enforces the
//! [`CrashWindow`]: a Vulnerable-mode [`Step::Trigger`] logs `downtime`,
//! closes the connection, **drops the TCP listener and rebinds the same port
//! once the window has passed** (connects are refused meanwhile); a UDP
//! service keeps its socket and drops every datagram silently while down.
//!
//! Everything read from a socket is treated as hostile input: no `unwrap`
//! or `expect` touches it, parse failures become the speaker's own
//! protocol-error steps, and a write error just closes that connection with
//! reason `error`.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};

use super::{dns, ftp, memcached, modbus, mqtt, resp, smtp, tlv, udp_payload};
use super::{CrashWindow, Parsed, Proto, ServiceDef, Speaker, Step, CRASH_WINDOW, IDLE_TIMEOUT};
use crate::log::{Classified, CloseReason, ControlLog, Dir, ServiceInfo};
use crate::SeedMode;

/// Every service binds here; the OS picks the port.
const LOOPBACK_ANY: (&str, u16) = ("127.0.0.1", 0);

/// Bytes read from a TCP stream per `read`; the per-connection buffer grows
/// from these chunks up to the speaker's `max_buffer()`.
const READ_CHUNK: usize = 8192;

/// Largest UDP payload a datagram can carry.
const MAX_DATAGRAM: usize = 65_535;

/// Rebind retry cadence and budget against `AddrInUse` after a crash window
/// (plan P3: every 50 ms, up to 2 s).
const REBIND_RETRY: Duration = Duration::from_millis(50);
const REBIND_BUDGET: Duration = Duration::from_secs(2);

/// Back-off after an `accept` / `recv_from` error so a persistent failure
/// (EMFILE, a closed socket) cannot spin the task.
const SOCKET_ERROR_BACKOFF: Duration = Duration::from_millis(10);

/// The nine services in spec D5 table order.
pub fn all() -> Vec<ServiceDef> {
    vec![
        tlv::DEF,
        dns::DEF,
        udp_payload::DEF,
        resp::DEF,
        memcached::DEF,
        modbus::DEF,
        mqtt::DEF,
        smtp::DEF,
        ftp::DEF,
    ]
}

/// One bound L4 service, as `/services` and the builder report it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RunningService {
    pub name: &'static str,
    pub grammar: &'static str,
    pub proto: Proto,
    pub addr: SocketAddr,
}

/// The nine running speakers. Dropping it aborts every driver task (and,
/// through each task's `JoinSet`, every open connection).
pub struct L4Services {
    services: Vec<RunningService>,
    tasks: Vec<JoinHandle<()>>,
}

impl L4Services {
    /// Bind every service in [`all`] on `127.0.0.1:0`, register each as an
    /// `l4` row in `/services`, and spawn its driver task. A bind failure
    /// returns the error after aborting the tasks already spawned.
    pub(crate) async fn start(mode: SeedMode, log: Arc<ControlLog>) -> io::Result<L4Services> {
        let mut this = L4Services {
            services: Vec::new(),
            tasks: Vec::new(),
        };
        // `c-<8 hex>` connection ids, shared by the TCP services of this set.
        let conn_ids = Arc::new(AtomicU64::new(0));
        for def in all() {
            let window = Arc::new(CrashWindow::new());
            let (addr, task) = match def.proto {
                Proto::Tcp => {
                    let listener = TcpListener::bind(LOOPBACK_ANY).await?;
                    let addr = listener.local_addr()?;
                    let task = tokio::spawn(run_tcp(
                        def,
                        listener,
                        mode,
                        log.clone(),
                        window,
                        conn_ids.clone(),
                    ));
                    (addr, task)
                }
                Proto::Udp => {
                    let socket = UdpSocket::bind(LOOPBACK_ANY).await?;
                    let addr = socket.local_addr()?;
                    let task = tokio::spawn(run_udp(def, socket, mode, log.clone(), window));
                    (addr, task)
                }
            };
            log.register_service(ServiceInfo {
                name: def.name.to_string(),
                proto: def.proto.as_str(),
                addr,
                role: "l4",
                alpn: None,
                grammar: Some(def.grammar),
            });
            this.services.push(RunningService {
                name: def.name,
                grammar: def.grammar,
                proto: def.proto,
                addr,
            });
            this.tasks.push(task);
        }
        Ok(this)
    }

    /// The bound services in [`all`] order.
    pub fn services(&self) -> &[RunningService] {
        &self.services
    }

    /// The address of the service called `name`, if it is one of ours.
    pub fn addr(&self, name: &str) -> Option<SocketAddr> {
        self.services
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.addr)
    }
}

impl Drop for L4Services {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

// --- The pure decision table -------------------------------------------------

/// What the driver does for one [`Step`], in order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    /// Write these bytes (never empty) and log them `out` / `ok`.
    Write(Vec<u8>),
    /// Keep the connection open.
    Keep,
    /// Close the connection with this reason.
    CloseConn(CloseReason),
    /// Open the crash window: log `downtime`, close with reason `trigger`,
    /// take the listener down.
    Crash,
}

/// The driver's reading of a [`Step`] (spec D5 semantics, plan P2):
/// `Reply`/`ProtocolError`/`Denylisted` write when non-empty and keep;
/// `Fault` writes when non-empty and closes `error`; `Close` writes when
/// given and closes `quit`; `Trigger` crashes.
pub(crate) fn apply(step: Step) -> Vec<Action> {
    let write = |bytes: Vec<u8>| (!bytes.is_empty()).then_some(Action::Write(bytes));
    let (write, then) = match step {
        Step::Reply(b) | Step::ProtocolError(b) | Step::Denylisted(b) => (write(b), Action::Keep),
        Step::Fault(b) => (write(b), Action::CloseConn(CloseReason::Error)),
        Step::Close(b) => (b.and_then(write), Action::CloseConn(CloseReason::Quit)),
        Step::Trigger => (None, Action::Crash),
    };
    write.into_iter().chain(std::iter::once(then)).collect()
}

/// The `classified` token of an `in` message for a step (the enum twin of
/// [`super::classify`]).
pub(crate) fn classified(step: &Step) -> Classified {
    match step {
        Step::Reply(_) | Step::Close(_) => Classified::Ok,
        Step::ProtocolError(_) | Step::Fault(_) => Classified::ProtocolError,
        Step::Denylisted(_) => Classified::Denylisted,
        Step::Trigger => Classified::Trigger,
    }
}

/// `up_at_ms` for a window opened at `down_at_ms`.
fn up_at_ms(down_at_ms: u64) -> u64 {
    let window_ms = u64::try_from(CRASH_WINDOW.as_millis()).unwrap_or(u64::MAX);
    down_at_ms.saturating_add(window_ms)
}

fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

// --- TCP ---------------------------------------------------------------------

/// Why a connection handler returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ConnEnd {
    /// The connection closed; the listener keeps serving.
    Closed,
    /// The connection hit a Vulnerable-mode trigger; the listener must go
    /// down for the crash window.
    Crashed,
}

/// What one iteration of the read loop observed.
enum Event {
    Data(usize),
    Eof,
    Idle,
    ReadError,
    /// The service crashed on another connection.
    Down,
}

/// One accepted TCP connection and its speaker.
struct TcpConn {
    service: &'static str,
    conn_id: String,
    stream: TcpStream,
    speaker: Box<dyn Speaker>,
    mode: SeedMode,
    log: Arc<ControlLog>,
    window: Arc<CrashWindow>,
    buf: Vec<u8>,
    bytes_in: u64,
    bytes_out: u64,
}

impl TcpConn {
    async fn run(mut self, mut down: watch::Receiver<bool>) -> ConnEnd {
        if let Some(banner) = self.speaker.banner() {
            if self.write(&banner).await.is_err() {
                return self.close(CloseReason::Error);
            }
        }
        let mut scratch = vec![0u8; READ_CHUNK];
        loop {
            let pending = !self.buf.is_empty();
            let event = tokio::select! {
                event = read_event(&mut self.stream, &mut scratch, pending) => event,
                // `changed` errs once the sender is gone, which also means
                // this listener generation is over: treat both as down.
                _ = down.changed() => Event::Down,
            };
            match event {
                Event::Down => return self.close(CloseReason::Trigger),
                Event::Eof => return self.close(CloseReason::Eof),
                Event::ReadError => return self.close(CloseReason::Error),
                Event::Idle => {
                    if let Some(end) = self.idle(CloseReason::Error).await {
                        return end;
                    }
                }
                Event::Data(n) => {
                    self.bytes_in = self.bytes_in.saturating_add(as_u64(n));
                    self.buf.extend_from_slice(&scratch[..n]);
                    if let Some(end) = self.drain_messages().await {
                        return end;
                    }
                    if self.buf.len() > self.speaker.max_buffer() {
                        if let Some(end) = self.idle(CloseReason::Oversize).await {
                            return end;
                        }
                    }
                }
            }
        }
    }

    /// Parse whole messages off the front of the buffer until the speaker
    /// says the rest is incomplete.
    async fn drain_messages(&mut self) -> Option<ConnEnd> {
        while !self.buf.is_empty() {
            match self.speaker.parse(self.mode, &self.buf) {
                Parsed::Incomplete => return None,
                Parsed::Message {
                    consumed,
                    verb,
                    step,
                } => {
                    // A speaker never consumes more than it was given, and
                    // consuming nothing would re-parse the same bytes
                    // forever; both are speaker bugs this guard contains.
                    let consumed = consumed.clamp(1, self.buf.len());
                    let input: Vec<u8> = self.buf.drain(..consumed).collect();
                    if let Some(end) = self
                        .step(&input, verb.as_deref(), step, CloseReason::Error)
                        .await
                    {
                        return Some(end);
                    }
                }
            }
        }
        None
    }

    /// Hand the whole pending buffer to `on_idle` (after [`IDLE_TIMEOUT`] or
    /// past `max_buffer()`); a `Fault` then closes with `fault_reason`.
    async fn idle(&mut self, fault_reason: CloseReason) -> Option<ConnEnd> {
        let step = self.speaker.on_idle(self.mode, &self.buf);
        let input = std::mem::take(&mut self.buf);
        self.step(&input, None, step, fault_reason).await
    }

    /// Log the `in` message and carry out the step's actions.
    async fn step(
        &mut self,
        input: &[u8],
        verb: Option<&str>,
        step: Step,
        fault_reason: CloseReason,
    ) -> Option<ConnEnd> {
        self.log.l4_message(
            self.service,
            &self.conn_id,
            Dir::In,
            input,
            verb,
            classified(&step),
        );
        for action in apply(step) {
            match action {
                Action::Write(bytes) => {
                    if self.write(&bytes).await.is_err() {
                        return Some(self.close(CloseReason::Error));
                    }
                }
                Action::Keep => {}
                // `Fault` closes `error` after idle, `oversize` past the cap.
                Action::CloseConn(CloseReason::Error) => return Some(self.close(fault_reason)),
                Action::CloseConn(reason) => return Some(self.close(reason)),
                Action::Crash => return Some(self.crash(input)),
            }
        }
        None
    }

    /// Write and log one outbound message (`out`, `ok`).
    async fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stream.write_all(bytes).await?;
        self.bytes_out = self.bytes_out.saturating_add(as_u64(bytes.len()));
        self.log.l4_message(
            self.service,
            &self.conn_id,
            Dir::Out,
            bytes,
            None,
            Classified::Ok,
        );
        Ok(())
    }

    /// Log the close with this connection's byte counters.
    fn close(&self, reason: CloseReason) -> ConnEnd {
        self.log.l4_close(
            self.service,
            &self.conn_id,
            reason,
            self.bytes_in,
            self.bytes_out,
        );
        ConnEnd::Closed
    }

    /// Open the crash window for `input` and close with reason `trigger`.
    fn crash(&self, input: &[u8]) -> ConnEnd {
        let down_at_ms = ControlLog::now_ms();
        self.window.trigger_at(Instant::now());
        self.log.l4_downtime(
            self.service,
            &self.conn_id,
            down_at_ms,
            up_at_ms(down_at_ms),
            input,
        );
        self.close(CloseReason::Trigger);
        ConnEnd::Crashed
    }
}

/// One read; with bytes pending the read is bounded by [`IDLE_TIMEOUT`] so
/// an incomplete message reaches `on_idle`, otherwise it waits indefinitely.
async fn read_event(stream: &mut TcpStream, scratch: &mut [u8], pending: bool) -> Event {
    let read = if pending {
        match timeout(IDLE_TIMEOUT, stream.read(scratch)).await {
            Ok(read) => read,
            Err(_elapsed) => return Event::Idle,
        }
    } else {
        stream.read(scratch).await
    };
    match read {
        Ok(0) => Event::Eof,
        Ok(n) => Event::Data(n),
        Err(_) => Event::ReadError,
    }
}

/// Accept loop with the crash window: serve `listener` until a connection
/// crashes, then drop it, signal every open connection, wait out the window
/// and rebind the same address.
async fn run_tcp(
    def: ServiceDef,
    first: TcpListener,
    mode: SeedMode,
    log: Arc<ControlLog>,
    window: Arc<CrashWindow>,
    conn_ids: Arc<AtomicU64>,
) {
    let Ok(addr) = first.local_addr() else {
        return;
    };
    let mut next = Some(first);
    loop {
        let listener = match next.take() {
            Some(listener) => listener,
            None => match rebind(addr).await {
                Some(listener) => listener,
                // The port could not be reclaimed within the budget; the
                // service stays down rather than moving ports under the
                // operator.
                None => return,
            },
        };
        let (down_tx, down_rx) = watch::channel(false);
        let mut conns: JoinSet<ConnEnd> = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let n = conn_ids.fetch_add(1, Ordering::SeqCst) + 1;
                        let conn_id = format!("c-{n:08x}");
                        log.l4_accept(def.name, &conn_id, peer);
                        let conn = TcpConn {
                            service: def.name,
                            conn_id,
                            stream,
                            speaker: (def.new_conn)(),
                            mode,
                            log: log.clone(),
                            window: window.clone(),
                            buf: Vec::new(),
                            bytes_in: 0,
                            bytes_out: 0,
                        };
                        conns.spawn(conn.run(down_rx.clone()));
                    }
                    Err(_) => sleep(SOCKET_ERROR_BACKOFF).await,
                },
                Some(finished) = conns.join_next(), if !conns.is_empty() => {
                    if matches!(finished, Ok(ConnEnd::Crashed)) {
                        break;
                    }
                }
            }
        }
        // Crash: refuse connects (drop the listener), end every other open
        // connection with reason `trigger`, and come back when the window
        // the trigger opened has elapsed.
        drop(listener);
        let _ = down_tx.send(true);
        if let Some(remaining) = window.remaining_at(Instant::now()) {
            sleep(remaining).await;
        }
        // Dropping the set aborts any connection that has not exited yet.
        drop(conns);
    }
}

/// Bind `addr` again after a crash window, retrying `AddrInUse` every
/// [`REBIND_RETRY`] for up to [`REBIND_BUDGET`].
async fn rebind(addr: SocketAddr) -> Option<TcpListener> {
    let deadline = Instant::now() + REBIND_BUDGET;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => return Some(listener),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse && Instant::now() < deadline => {
                sleep(REBIND_RETRY).await;
            }
            Err(_) => return None,
        }
    }
}

// --- UDP ---------------------------------------------------------------------

/// Datagram loop: one speaker for the service, `conn_id = u-<peer port>`,
/// every datagram dropped silently while the crash window is open.
async fn run_udp(
    def: ServiceDef,
    socket: UdpSocket,
    mode: SeedMode,
    log: Arc<ControlLog>,
    window: Arc<CrashWindow>,
) {
    let mut speaker = (def.new_conn)();
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            Err(_) => {
                sleep(SOCKET_ERROR_BACKOFF).await;
                continue;
            }
        };
        if window.is_down_at(Instant::now()) {
            continue;
        }
        let datagram = &buf[..n];
        let conn_id = format!("u-{}", peer.port());
        let (verb, step) = match speaker.parse(mode, datagram) {
            // A datagram is a whole message; one the speaker cannot even
            // frame is a protocol error with no reply.
            Parsed::Incomplete => (None, Step::ProtocolError(Vec::new())),
            Parsed::Message { verb, step, .. } => (verb, step),
        };
        log.l4_message(
            def.name,
            &conn_id,
            Dir::In,
            datagram,
            verb.as_deref(),
            classified(&step),
        );
        for action in apply(step) {
            match action {
                Action::Write(bytes) => {
                    if socket.send_to(&bytes, peer).await.is_ok() {
                        log.l4_message(def.name, &conn_id, Dir::Out, &bytes, None, Classified::Ok);
                    }
                }
                // No connection to keep or close over UDP.
                Action::Keep | Action::CloseConn(_) => {}
                Action::Crash => {
                    let down_at_ms = ControlLog::now_ms();
                    window.trigger_at(Instant::now());
                    log.l4_downtime(
                        def.name,
                        &conn_id,
                        down_at_ms,
                        up_at_ms(down_at_ms),
                        datagram,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::CloseReason;
    use crate::speakers::{classify, Proto, Step};

    #[test]
    fn all_has_nine_distinct_names_and_grammars() {
        let defs = all();
        assert_eq!(defs.len(), 9);
        let names: Vec<&str> = defs.iter().map(|d| d.name).collect();
        assert_eq!(
            names,
            vec![
                "l4-tlv-crash",
                "l4-dns-fault",
                "l4-udp-payload-crash",
                "l4-resp",
                "l4-memcached",
                "l4-modbus",
                "l4-mqtt",
                "l4-smtp",
                "l4-ftp",
            ],
            "D5 order"
        );
        let grammars: Vec<&str> = defs.iter().map(|d| d.grammar).collect();
        assert_eq!(
            grammars,
            vec![
                "tlv",
                "dns",
                "raw",
                "resp",
                "memcached",
                "modbus",
                "mqtt",
                "smtp",
                "ftp"
            ]
        );
        let protos: Vec<Proto> = defs.iter().map(|d| d.proto).collect();
        assert_eq!(
            protos,
            vec![
                Proto::Tcp,
                Proto::Udp,
                Proto::Udp,
                Proto::Tcp,
                Proto::Tcp,
                Proto::Tcp,
                Proto::Tcp,
                Proto::Tcp,
                Proto::Tcp,
            ]
        );
        for d in &defs {
            assert_eq!(
                (d.new_conn)().name(),
                d.name,
                "{} speaker names itself",
                d.name
            );
        }
    }

    #[test]
    fn apply_step_table() {
        let x = b"x".to_vec();
        // Reply: write when non-empty, always keep.
        assert_eq!(apply(Step::Reply(vec![])), vec![Action::Keep]);
        assert_eq!(
            apply(Step::Reply(x.clone())),
            vec![Action::Write(x.clone()), Action::Keep]
        );
        // ProtocolError: write when non-empty, keep the connection.
        assert_eq!(apply(Step::ProtocolError(vec![])), vec![Action::Keep]);
        assert_eq!(
            apply(Step::ProtocolError(x.clone())),
            vec![Action::Write(x.clone()), Action::Keep]
        );
        // Denylisted: write, keep.
        assert_eq!(
            apply(Step::Denylisted(x.clone())),
            vec![Action::Write(x.clone()), Action::Keep]
        );
        // Fault: write when non-empty, then close with reason `error`.
        assert_eq!(
            apply(Step::Fault(vec![])),
            vec![Action::CloseConn(CloseReason::Error)]
        );
        assert_eq!(
            apply(Step::Fault(x.clone())),
            vec![
                Action::Write(x.clone()),
                Action::CloseConn(CloseReason::Error)
            ]
        );
        // Trigger: crash.
        assert_eq!(apply(Step::Trigger), vec![Action::Crash]);
        // Close: write when given, then close with reason `quit`.
        assert_eq!(
            apply(Step::Close(None)),
            vec![Action::CloseConn(CloseReason::Quit)]
        );
        assert_eq!(
            apply(Step::Close(Some(x.clone()))),
            vec![Action::Write(x), Action::CloseConn(CloseReason::Quit)]
        );
    }

    #[test]
    fn classified_agrees_with_classify_token() {
        let steps = [
            Step::Reply(vec![1]),
            Step::ProtocolError(vec![]),
            Step::Denylisted(vec![1]),
            Step::Fault(vec![]),
            Step::Trigger,
            Step::Close(None),
        ];
        for step in steps {
            let token = serde_json::to_value(classified(&step)).expect("serialize token");
            assert_eq!(token, serde_json::json!(classify(&step)), "{step:?}");
        }
    }

    #[test]
    fn addr_finds_a_service_by_name() {
        let a: std::net::SocketAddr = "127.0.0.1:4001".parse().expect("addr");
        let b: std::net::SocketAddr = "127.0.0.1:4002".parse().expect("addr");
        let svc = L4Services {
            services: vec![
                RunningService {
                    name: "l4-resp",
                    grammar: "resp",
                    proto: Proto::Tcp,
                    addr: a,
                },
                RunningService {
                    name: "l4-dns-fault",
                    grammar: "dns",
                    proto: Proto::Udp,
                    addr: b,
                },
            ],
            tasks: Vec::new(),
        };
        assert_eq!(svc.services().len(), 2);
        assert_eq!(svc.addr("l4-resp"), Some(a));
        assert_eq!(svc.addr("l4-dns-fault"), Some(b));
        assert_eq!(svc.addr("l4-mqtt"), None);
    }

    // --- Tester additions (stage 5) ---

    #[test]
    fn up_at_is_down_plus_the_window() {
        assert_eq!(up_at_ms(0), 5000);
        assert_eq!(up_at_ms(1_700_000_000_000), 1_700_000_005_000);
        assert_eq!(up_at_ms(u64::MAX), u64::MAX);
    }
}
