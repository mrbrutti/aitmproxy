//! Task 6: the scope/rate guard, SSRF address classification, and config types.

use aitm_core::{
    classify_host, GuardError, HostClass, LimitConfig, ScopeEntry, ScopeRateGuard, StdGuard,
};

fn scoped(host: &str) -> ScopeEntry {
    ScopeEntry { host: host.into() }
}

#[test]
fn deny_by_default() {
    let guard = StdGuard::default();
    assert!(matches!(
        guard.check_active("ex.test"),
        Err(GuardError::OutOfScope(_))
    ));
    guard.add_scope(scoped("ex.test"));
    assert!(guard.check_active("ex.test").is_ok());
}

#[test]
fn classify_private() {
    assert!(matches!(classify_host("127.0.0.1"), HostClass::Loopback));
    assert!(matches!(classify_host("10.0.0.5"), HostClass::Private));
    assert!(matches!(classify_host("93.184.216.34"), HostClass::Public));
}

#[test]
fn concurrency_cap() {
    let guard = StdGuard::new(LimitConfig {
        max_concurrency: 1,
        ..Default::default()
    });
    guard.add_scope(scoped("ex.test"));

    let permit = guard.check_active("ex.test").expect("first permit granted");
    assert!(matches!(
        guard.check_active("ex.test"),
        Err(GuardError::ConcurrencyExceeded)
    ));

    drop(permit);
    assert!(
        guard.check_active("ex.test").is_ok(),
        "dropping the permit should free the slot"
    );
}

#[test]
fn rate_limit_burst() {
    let guard = StdGuard::new(LimitConfig {
        per_host_rps: 2,
        ..Default::default()
    });
    guard.add_scope(scoped("ex.test"));

    let mut rate_limited = 0;
    for _ in 0..5 {
        if let Err(GuardError::RateLimited { .. }) = guard.check_active("ex.test") {
            rate_limited += 1;
        }
    }
    assert!(
        rate_limited >= 1,
        "a 5-call burst at per_host_rps=2 must throttle at least once"
    );
}
