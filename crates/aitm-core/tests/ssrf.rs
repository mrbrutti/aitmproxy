//! Browser scope-confined egress (scanner S2): the `confine_to_scope` branch of
//! [`ssrf_check`]. In confined mode a *public* target must additionally be in
//! scope (normal wildcard-aware hostname match); the private/loopback block and
//! its DNS-rebinding refusal are unchanged under either posture. Every case here
//! is decided before any dial, so no network is touched.

use std::net::IpAddr;

use aitm_core::{ssrf_check, GuardError, ScopeEntry, SsrfPolicy};

/// A genuinely public literal. Do NOT use the TEST-NET ranges (`192.0.2.*`,
/// `198.51.100.*`, `203.0.113.*`): the classifier treats those as `Private`.
const PUBLIC_DST: &str = "93.184.216.34";

fn scoped(host: &str) -> ScopeEntry {
    ScopeEntry { host: host.into() }
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test literal must parse")
}

/// AC1: confined + public authority/dst that is not in scope → `OutOfScope`,
/// carrying the requested host.
#[test]
fn confined_refuses_out_of_scope_public() {
    let policy = SsrfPolicy::default();
    let none: Vec<ScopeEntry> = vec![];

    let r = ssrf_check(&policy, &none, true, "example.test:443", ip(PUBLIC_DST));
    assert!(
        matches!(r, Err(GuardError::OutOfScope(ref h)) if h == "example.test:443"),
        "empty scope must refuse a public host under confinement, got {r:?}"
    );

    // A non-empty scope that does not cover the host refuses too.
    let scope = vec![scoped("target.example")];
    assert!(matches!(
        ssrf_check(&policy, &scope, true, "other.example:443", ip(PUBLIC_DST)),
        Err(GuardError::OutOfScope(_))
    ));

    // A public IP-literal authority is held to the same allowlist.
    assert!(matches!(
        ssrf_check(&policy, &scope, true, "93.184.216.34:80", ip(PUBLIC_DST)),
        Err(GuardError::OutOfScope(_))
    ));
}

/// AC2: a scoped public hostname passes under confinement, both as an exact
/// entry and under a `*.wildcard` (the normal scope match, not the strict
/// address-only one the private lift uses).
#[test]
fn confined_allows_in_scope_public_exact_and_wildcard() {
    let policy = SsrfPolicy::default();

    let exact = vec![scoped("target.example")];
    assert!(ssrf_check(&policy, &exact, true, "target.example:443", ip(PUBLIC_DST)).is_ok());
    // Scope matching folds case.
    assert!(ssrf_check(&policy, &exact, true, "TARGET.example:443", ip(PUBLIC_DST)).is_ok());

    let wild = vec![scoped("*.target.example")];
    assert!(ssrf_check(
        &policy,
        &wild,
        true,
        "api.target.example:443",
        ip(PUBLIC_DST)
    )
    .is_ok());
    // The apex is covered by its own wildcard.
    assert!(ssrf_check(&policy, &wild, true, "target.example:443", ip(PUBLIC_DST)).is_ok());
    // A sibling domain off the wildcard is still refused.
    assert!(matches!(
        ssrf_check(
            &policy,
            &wild,
            true,
            "api.other.example:443",
            ip(PUBLIC_DST)
        ),
        Err(GuardError::OutOfScope(_))
    ));
}

/// A `host:port` scope entry is honored under confinement exactly as
/// `StdGuard::in_scope` honors it: the match is on the full requested authority,
/// not the bare host, so a port-qualified entry matching the request passes while
/// a mismatching port is refused.
#[test]
fn confined_honors_port_qualified_scope_entry() {
    let policy = SsrfPolicy::default();
    let scope = vec![scoped("target.example:443")];

    // Same host:port as scoped → in scope.
    assert!(
        ssrf_check(&policy, &scope, true, "target.example:443", ip(PUBLIC_DST)).is_ok(),
        "a request to the scoped host:port must pass under confinement"
    );
    // A different port than the scoped entry is not covered.
    assert!(
        matches!(
            ssrf_check(&policy, &scope, true, "target.example:8443", ip(PUBLIC_DST)),
            Err(GuardError::OutOfScope(_))
        ),
        "a port the entry did not scope must be refused"
    );
}

/// AC3: free (unconfined) mode is today's behaviour — a public target is always
/// allowed regardless of scope.
#[test]
fn free_allows_out_of_scope_public() {
    let policy = SsrfPolicy::default();
    let none: Vec<ScopeEntry> = vec![];
    assert!(ssrf_check(&policy, &none, false, "example.test:443", ip(PUBLIC_DST)).is_ok());
    assert!(ssrf_check(&policy, &none, false, "93.184.216.34:80", ip(PUBLIC_DST)).is_ok());
}

/// AC4: the private/loopback default is identical under both postures — an
/// out-of-scope private target is refused, and a scoped IP-literal lifts it —
/// because confinement only ever runs on the public branch.
#[test]
fn confinement_does_not_change_private() {
    let policy = SsrfPolicy::default();
    let none: Vec<ScopeEntry> = vec![];

    for confine in [false, true] {
        assert!(
            matches!(
                ssrf_check(&policy, &none, confine, "internal:80", ip("10.0.0.5")),
                Err(GuardError::PrivateAddressBlocked(_))
            ),
            "private dst must stay blocked (confine={confine})"
        );
        assert!(
            matches!(
                ssrf_check(&policy, &none, confine, "localhost:3000", ip("127.0.0.1")),
                Err(GuardError::PrivateAddressBlocked(_))
            ),
            "loopback must stay blocked (confine={confine})"
        );
        assert!(
            matches!(
                ssrf_check(
                    &policy,
                    &none,
                    confine,
                    "evil.test:80",
                    ip("169.254.169.254")
                ),
                Err(GuardError::PrivateAddressBlocked(_))
            ),
            "metadata address must stay blocked (confine={confine})"
        );
    }

    // The documented lift: an explicit IP literal / host:port literal in scope.
    // Note `internal` is not scoped by name; the lift is by address and must not
    // be second-guessed by the hostname allowlist.
    let ip_scope = vec![scoped("10.0.0.5")];
    let lh = vec![scoped("127.0.0.1:3000")];
    for confine in [false, true] {
        assert!(
            ssrf_check(&policy, &ip_scope, confine, "internal:80", ip("10.0.0.5")).is_ok(),
            "scoped IP literal must lift the block (confine={confine})"
        );
        assert!(
            ssrf_check(&policy, &lh, confine, "127.0.0.1:3000", ip("127.0.0.1")).is_ok(),
            "scoped loopback literal must lift the block (confine={confine})"
        );
    }
}

/// AC5: DNS rebinding — a scoped *hostname* (exact or wildcard) that resolves
/// private/loopback is refused under both postures. Confinement must not turn
/// the hostname allowlist into a lift for the private branch.
#[test]
fn confinement_does_not_change_rebinding() {
    let policy = SsrfPolicy::default();
    let exact = vec![scoped("evil.test")];
    let wild = vec![scoped("*.evil.test")];

    for confine in [false, true] {
        assert!(
            matches!(
                ssrf_check(&policy, &exact, confine, "evil.test:80", ip("127.0.0.1")),
                Err(GuardError::PrivateAddressBlocked(_))
            ),
            "scoped name → loopback must be refused (confine={confine})"
        );
        assert!(
            matches!(
                ssrf_check(
                    &policy,
                    &exact,
                    confine,
                    "evil.test:80",
                    ip("169.254.169.254")
                ),
                Err(GuardError::PrivateAddressBlocked(_))
            ),
            "scoped name → metadata must be refused (confine={confine})"
        );
        assert!(
            matches!(
                ssrf_check(&policy, &wild, confine, "api.evil.test:80", ip("10.1.2.3")),
                Err(GuardError::PrivateAddressBlocked(_))
            ),
            "wildcard-scoped name → private must be refused (confine={confine})"
        );
    }
}
