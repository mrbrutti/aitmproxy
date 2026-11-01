//! L4 speakers: the pure protocol responders behind the shared TCP/UDP
//! driver (spec D5).
//!
//! A [`Speaker`] never touches a socket. The driver (`driver.rs`, Task A19)
//! feeds it the bytes it has buffered, the speaker says how many it consumed
//! and which [`Step`] to take, and the driver writes, logs and closes. One
//! deliberate parse bug per speaker yields [`Step::Trigger`] in
//! `SeedMode::Vulnerable` (the 5 s [`CrashWindow`]) and [`Step::Fault`] in
//! `SeedMode::Patched` (the row's protocol-error reply, then close).
//!
//! Everything here is a plain value or a mutex over one `Option<Instant>`, so
//! the state machine is unit-testable with a mocked clock.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::SeedMode;

pub mod dns;
pub mod driver;
pub mod ftp;
pub mod memcached;
pub mod modbus;
pub mod mqtt;
pub mod resp;
pub mod smtp;
pub mod tlv;
pub mod udp_payload;

pub use driver::{L4Services, RunningService};

/// How long a Vulnerable-mode trigger keeps a service down (spec D5).
pub const CRASH_WINDOW: Duration = Duration::from_secs(5);

/// Read idle after which the driver hands a non-empty buffer to
/// [`Speaker::on_idle`] (the "after a 200 ms idle" triggers of spec D5).
pub const IDLE_TIMEOUT: Duration = Duration::from_millis(200);

/// Transport a service listens on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// The `proto` token used by `/services`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// What the driver does after a speaker parsed one message.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Step {
    /// Write the bytes (nothing when empty) and keep the connection; logged `ok`.
    Reply(Vec<u8>),
    /// Write the bytes (nothing when empty) and keep the connection; logged
    /// `protocol_error`.
    ProtocolError(Vec<u8>),
    /// A denylisted command arrived: write the bytes, keep the connection;
    /// logged `denylisted` so a cell can prove none came.
    Denylisted(Vec<u8>),
    /// Patched-mode answer to a Vulnerable trigger: write the bytes if
    /// non-empty, then close with reason `error`; the listener stays up.
    Fault(Vec<u8>),
    /// Vulnerable-mode crash: the driver opens the [`CrashWindow`], logs
    /// `downtime`, drops the connection and the listener.
    Trigger,
    /// Orderly end (`QUIT`, `DISCONNECT`): write the bytes if any, then close
    /// with reason `quit`.
    Close(Option<Vec<u8>>),
}

/// Result of [`Speaker::parse`] on the buffered bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Parsed {
    /// Not a whole message yet; the driver keeps reading.
    Incomplete,
    /// One message parsed. `consumed` bytes leave the buffer; `verb` is what
    /// was parsed (`PING`, `version`, `fc3`, `CONNECT`, `A`, `frame`, ...) or
    /// `None` when the bytes did not parse; `step` is what to do.
    Message {
        consumed: usize,
        verb: Option<String>,
        step: Step,
    },
}

/// A pure protocol responder. One instance per connection (TCP) or per
/// service (UDP); the driver owns the socket and the log.
pub trait Speaker: Send {
    /// Service name as listed in `/services` (`l4-resp`, ...).
    fn name(&self) -> &'static str;
    /// Bytes written on accept, before any input (SMTP/FTP greet).
    fn banner(&self) -> Option<Vec<u8>> {
        None
    }
    /// Parse the front of `buf`; called again until it returns
    /// [`Parsed::Incomplete`].
    fn parse(&mut self, mode: SeedMode, buf: &[u8]) -> Parsed;
    /// Called with the non-empty, still-incomplete buffer after
    /// [`IDLE_TIMEOUT`] of silence, or when the buffer exceeds
    /// [`Speaker::max_buffer`].
    fn on_idle(&mut self, mode: SeedMode, buf: &[u8]) -> Step;
    /// Largest buffer the driver holds for this speaker before `on_idle`.
    fn max_buffer(&self) -> usize;
}

/// Static description of one L4 service.
#[derive(Clone, Copy)]
pub struct ServiceDef {
    pub name: &'static str,
    pub grammar: &'static str,
    pub proto: Proto,
    pub new_conn: fn() -> Box<dyn Speaker>,
}

/// The 5 s downtime after a Vulnerable trigger, as a clock-free state
/// machine: the driver passes `Instant`s in, tests pass synthetic ones.
pub struct CrashWindow {
    down_until: Mutex<Option<Instant>>,
}

impl Default for CrashWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl CrashWindow {
    /// A window that is up.
    pub fn new() -> Self {
        Self {
            down_until: Mutex::new(None),
        }
    }

    /// Open the window at `now`; returns the instant the service is up again
    /// (`now + CRASH_WINDOW`).
    pub fn trigger_at(&self, now: Instant) -> Instant {
        let until = now + CRASH_WINDOW;
        *self.lock() = Some(until);
        until
    }

    /// Whether the service is still down at `now`.
    pub fn is_down_at(&self, now: Instant) -> bool {
        self.remaining_at(now).is_some()
    }

    /// Time left in the window at `now`, `None` once it has elapsed (or was
    /// never opened).
    pub fn remaining_at(&self, now: Instant) -> Option<Duration> {
        let until = (*self.lock())?;
        if now < until {
            Some(until - now)
        } else {
            None
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Instant>> {
        // The guarded value is one Option<Instant>; a poisoned lock still
        // holds a valid one, so recover rather than propagate the panic.
        self.down_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Outcome of scanning a buffer for one CRLF-terminated line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineScan<'a> {
    /// `line` excludes the CRLF; `consumed` includes it.
    Complete { line: &'a [u8], consumed: usize },
    /// No CRLF yet and the line could still fit in `max` bytes.
    Incomplete,
    /// The first CRLF lies past `max` bytes, or no CRLF exists within the
    /// first `max + 1` bytes (so one can no longer arrive in time).
    TooLong,
}

/// Find the first CRLF-terminated line of at most `max` bytes at the front
/// of `buf` (spec D5's over-long-line rule, shared by RESP, memcached, SMTP
/// and FTP).
pub fn take_line(buf: &[u8], max: usize) -> LineScan<'_> {
    // A CRLF that keeps the line within `max` bytes starts at an index
    // <= max, so it lies entirely inside the first max + 2 bytes.
    let horizon = buf.len().min(max.saturating_add(2));
    if let Some(cr) = buf[..horizon].windows(2).position(|w| w == b"\r\n") {
        return LineScan::Complete {
            line: &buf[..cr],
            consumed: cr + 2,
        };
    }
    if buf.len() <= max {
        return LineScan::Incomplete;
    }
    // Exactly max + 1 bytes ending in a lone CR: its LF may still arrive.
    if buf.len() == max + 1 && buf[max] == b'\r' {
        return LineScan::Incomplete;
    }
    LineScan::TooLong
}

/// The `classified` token the driver logs for a step (spec D2:
/// `ok|protocol_error|denylisted|trigger`).
pub fn classify(step: &Step) -> &'static str {
    match step {
        Step::Reply(_) | Step::Close(_) => "ok",
        Step::ProtocolError(_) | Step::Fault(_) => "protocol_error",
        Step::Denylisted(_) => "denylisted",
        Step::Trigger => "trigger",
    }
}

/// The step for a speaker's deliberate bug: the Vulnerable origin crashes,
/// the Patched control answers `p_reply` and closes.
pub fn mode_bug(mode: SeedMode, p_reply: Vec<u8>) -> Step {
    match mode {
        SeedMode::Vulnerable => Step::Trigger,
        SeedMode::Patched => Step::Fault(p_reply),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SeedMode;
    use std::time::{Duration, Instant};

    #[test]
    fn crash_window_is_five_seconds() {
        let w = CrashWindow::new();
        let t0 = Instant::now();
        assert!(!w.is_down_at(t0), "fresh window is up");
        assert_eq!(w.remaining_at(t0), None);
        assert_eq!(w.trigger_at(t0), t0 + Duration::from_secs(5));
        assert!(w.is_down_at(t0));
        assert!(w.is_down_at(t0 + Duration::from_millis(4999)));
        assert!(!w.is_down_at(t0 + Duration::from_millis(5000)));
        assert_eq!(
            w.remaining_at(t0 + Duration::from_millis(4999)),
            Some(Duration::from_millis(1))
        );
        assert_eq!(w.remaining_at(t0 + Duration::from_millis(5000)), None);
    }

    #[test]
    fn take_line_too_long() {
        let no_crlf = vec![b'a'; 1025];
        assert_eq!(take_line(&no_crlf, 1024), LineScan::TooLong);

        let mut long_complete = vec![b'a'; 4096];
        long_complete.extend_from_slice(b"\r\n");
        assert_eq!(take_line(&long_complete, 1024), LineScan::TooLong);

        let mut exact = vec![b'a'; 1024];
        exact.extend_from_slice(b"\r\n");
        assert_eq!(
            take_line(&exact, 1024),
            LineScan::Complete {
                line: &exact[..1024],
                consumed: 1026
            }
        );

        assert_eq!(
            take_line(b"NOOP\r\nrest", 1024),
            LineScan::Complete {
                line: b"NOOP",
                consumed: 6
            }
        );

        assert_eq!(take_line(b"NOO", 1024), LineScan::Incomplete);
        assert_eq!(take_line(b"", 1024), LineScan::Incomplete);
        // 1024 bytes then a lone CR: the LF may still arrive at index 1025.
        let mut cr_pending = vec![b'a'; 1024];
        cr_pending.push(b'\r');
        assert_eq!(take_line(&cr_pending, 1024), LineScan::Incomplete);
    }

    #[test]
    fn mode_bug_splits_by_mode() {
        assert_eq!(mode_bug(SeedMode::Vulnerable, b"x".to_vec()), Step::Trigger);
        assert_eq!(
            mode_bug(SeedMode::Patched, b"x".to_vec()),
            Step::Fault(b"x".to_vec())
        );
    }

    #[test]
    fn classify_names_the_log_token() {
        assert_eq!(classify(&Step::Reply(b"+PONG\r\n".to_vec())), "ok");
        assert_eq!(
            classify(&Step::ProtocolError(b"-ERR\r\n".to_vec())),
            "protocol_error"
        );
        assert_eq!(classify(&Step::Fault(Vec::new())), "protocol_error");
        assert_eq!(
            classify(&Step::Denylisted(b"-ERR denylisted command\r\n".to_vec())),
            "denylisted"
        );
        assert_eq!(classify(&Step::Trigger), "trigger");
        assert_eq!(classify(&Step::Close(Some(b"+OK\r\n".to_vec()))), "ok");
        assert_eq!(classify(&Step::Close(None)), "ok");
    }

    #[test]
    fn proto_as_str() {
        assert_eq!(Proto::Tcp.as_str(), "tcp");
        assert_eq!(Proto::Udp.as_str(), "udp");
    }
}
