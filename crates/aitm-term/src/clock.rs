//! The clock seam: the reporter's 100 ms first-draw rule reads time through
//! [`Clock`] so unit tests drive it with `testing::FakeClock` instead of
//! sleeping.

use std::time::Instant;

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

/// The real clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_never_runs_backwards() {
        let clock = SystemClock;
        let a = clock.now();
        let b = clock.now();
        assert!(b >= a);
        assert_eq!(b, std::cmp::max(a, b));
    }
}
