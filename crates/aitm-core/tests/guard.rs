//! Task 6: the scope/rate guard, SSRF address classification, and config types.

use aitm_core::{
    classify_host, ssrf_check, BackoffConfig, GuardError, HostClass, LimitConfig, ScopeEntry,
    ScopeRateGuard, SsrfPolicy, StdGuard,
};

/// Once a host's error budget is exhausted it is disabled, then eligible again
/// after the backoff window (so `HostDisabled` and `BackoffConfig` are live).
#[test]
fn host_disable_then_backoff_recovery() {
    let guard = StdGuard::new(LimitConfig {
        global_rps: 1000,
        per_host_rps: 1000,
        max_concurrency: 1000,
        host_error_budget: 2,
        backoff: BackoffConfig {
            base: std::time::Duration::from_millis(60),
            max: std::time::Duration::from_secs(1),
            factor: 2.0,
        },
        ..LimitConfig::default()
    });
    guard.add_scope(scoped("ex.test"));

    assert!(guard.check_active("ex.test").is_ok());
    guard.record_error("ex.test"); // 1 < budget
    assert!(guard.check_active("ex.test").is_ok());
    guard.record_error("ex.test"); // reaches budget 2 → disabled
    assert!(matches!(
        guard.check_active("ex.test"),
        Err(GuardError::HostDisabled)
    ));

    // After the backoff window the host is eligible again.
    std::thread::sleep(std::time::Duration::from_millis(90));
    assert!(
        guard.check_active("ex.test").is_ok(),
        "host should recover after the backoff window"
    );
}

fn scoped(host: &str) -> ScopeEntry {
    ScopeEntry { host: host.into() }
}

/// The SSRF connector decision: private/loopback refused unless the host or IP
/// literal is explicitly in scope (a wildcard does not lift the block).
#[test]
fn ssrf_connector_decision() {
    let policy = SsrfPolicy::default();
    let none: Vec<ScopeEntry> = vec![];

    // A public target is always allowed.
    assert!(ssrf_check(
        &policy,
        &none,
        "example.test:443",
        "93.184.216.34".parse().unwrap()
    )
    .is_ok());

    // Loopback / private are blocked with no scope.
    assert!(matches!(
        ssrf_check(
            &policy,
            &none,
            "localhost:3000",
            "127.0.0.1".parse().unwrap()
        ),
        Err(GuardError::PrivateAddressBlocked(_))
    ));
    assert!(matches!(
        ssrf_check(&policy, &none, "internal:80", "10.0.0.5".parse().unwrap()),
        Err(GuardError::PrivateAddressBlocked(_))
    ));

    // A public-looking hostname that resolves to a private dst is still blocked.
    assert!(matches!(
        ssrf_check(
            &policy,
            &none,
            "evil.test:80",
            "169.254.169.254".parse().unwrap()
        ),
        Err(GuardError::PrivateAddressBlocked(_))
    ));

    // An exact host:port scope entry lifts the block; a wildcard does not.
    let scope = vec![scoped("127.0.0.1:3000")];
    assert!(ssrf_check(
        &policy,
        &scope,
        "127.0.0.1:3000",
        "127.0.0.1".parse().unwrap()
    )
    .is_ok());
    assert!(ssrf_check(
        &policy,
        &scope,
        "127.0.0.1:3001",
        "127.0.0.1".parse().unwrap()
    )
    .is_err());
    let wild = vec![scoped("*.local")];
    assert!(ssrf_check(&policy, &wild, "db.local:5432", "10.1.2.3".parse().unwrap()).is_err());

    // An explicit IP-literal scope entry lifts the block for that IP.
    let ip_scope = vec![scoped("10.0.0.5")];
    assert!(ssrf_check(
        &policy,
        &ip_scope,
        "internal:80",
        "10.0.0.5".parse().unwrap()
    )
    .is_ok());
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

    // The per-host bucket holds exactly `per_host_rps` tokens; an instant 5-call
    // burst refills a negligible fraction, so exactly the first 2 pass.
    let mut permitted = 0;
    let mut rate_limited = 0;
    for _ in 0..5 {
        match guard.check_active("ex.test") {
            Ok(_) => permitted += 1,
            Err(GuardError::RateLimited { .. }) => rate_limited += 1,
            Err(other) => panic!("unexpected refusal: {other:?}"),
        }
    }
    assert_eq!(permitted, 2, "exactly per_host_rps calls pass the burst");
    assert_eq!(rate_limited, 3, "the remaining 3 are rate-limited");
}
