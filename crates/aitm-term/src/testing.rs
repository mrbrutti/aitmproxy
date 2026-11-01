//! Test doubles shared by this crate's unit tests and by `aitm`'s (precedent:
//! `aitm-ca/src/testing.rs`): an in-memory sink the renderer writes to and a
//! clock that moves only when told.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::clock::Clock;

/// A `Write` sink whose bytes every clone shares, so a test keeps one handle
/// and gives the reporter another.
#[derive(Debug, Clone, Default)]
pub struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything written so far.
    pub fn bytes(&self) -> Vec<u8> {
        self.lock().clone()
    }

    /// Everything written so far, lossily decoded.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    /// A poisoned lock still holds the bytes written before the panic.
    fn lock(&self) -> MutexGuard<'_, Vec<u8>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.lock().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A clock that advances only through [`FakeClock::advance`].
#[derive(Debug)]
pub struct FakeClock {
    base: Instant,
    elapsed: Mutex<Duration>,
}

impl FakeClock {
    /// Shared, because the reporter holds the clock as `Arc<dyn Clock>` and
    /// the test keeps its own handle to advance it.
    pub fn new() -> Arc<FakeClock> {
        Arc::new(FakeClock {
            base: Instant::now(),
            elapsed: Mutex::new(Duration::ZERO),
        })
    }

    pub fn advance(&self, d: Duration) {
        *self.elapsed() += d;
    }

    fn elapsed(&self) -> MutexGuard<'_, Duration> {
        self.elapsed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.base + *self.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    #[test]
    fn fake_clock_advances_only_when_told() {
        let clock = FakeClock::new();
        let first = clock.now();
        let second = clock.now();
        assert_eq!(first, second, "time must not pass on its own");

        clock.advance(Duration::from_millis(150));
        assert_eq!(clock.now() - first, Duration::from_millis(150));
    }

    #[test]
    fn shared_sink_collects_bytes_across_clones() {
        let sink = SharedSink::new();
        let mut writer = sink.clone();
        writer
            .write_all(b"aitmproxy 0.5.11\n")
            .expect("in-memory write");
        writer
            .write_all("✓ done\n".as_bytes())
            .expect("in-memory write");
        writer.flush().expect("in-memory flush");

        assert_eq!(sink.bytes(), "aitmproxy 0.5.11\n✓ done\n".as_bytes());
        assert_eq!(sink.text(), "aitmproxy 0.5.11\n✓ done\n");
        assert_eq!(SharedSink::default().bytes(), Vec::<u8>::new());
    }
}
