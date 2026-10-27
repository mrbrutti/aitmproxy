//! The SSRF guard: resolve a URL's host, classify every address it resolves to,
//! and block private/loopback targets unless the host is explicitly in scope.
//!
//! Classification runs on the *resolved* addresses (plus the literal, so
//! `localhost` counts without DNS), which is what defeats a public-looking
//! hostname that points at RFC1918 or loopback space.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use aitm_core::{classify_host, GuardError, HostClass, ScopeEntry, ScopeRateGuard, SsrfPolicy};

/// Validates a navigation target against policy + scope before it is loaded.
pub trait SsrfGuard: Send + Sync {
    /// Resolve the URL's host and validate it against policy + scope before load.
    fn check(&self, url: &str) -> Result<ResolvedTarget, GuardError>;
}

/// A navigation target the guard allowed: the host as written and the address
/// it resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub host: String,
    pub addr: SocketAddr,
}

/// Name → addresses. Injectable so the guard is testable without the network.
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// The operating system's resolver.
pub struct SystemResolver;

impl HostResolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        Ok((host, port).to_socket_addrs()?.map(|a| a.ip()).collect())
    }
}

/// The default guard: policy + the scope held by a [`ScopeRateGuard`].
pub struct StdSsrfGuard {
    policy: SsrfPolicy,
    scope: Arc<dyn ScopeRateGuard>,
    resolver: Arc<dyn HostResolver>,
}

impl StdSsrfGuard {
    /// A guard over `scope`, resolving names with the system resolver.
    pub fn new(policy: SsrfPolicy, scope: Arc<dyn ScopeRateGuard>) -> Self {
        Self::with_resolver(policy, scope, Arc::new(SystemResolver))
    }

    /// A guard with an explicit resolver.
    pub fn with_resolver(
        policy: SsrfPolicy,
        scope: Arc<dyn ScopeRateGuard>,
        resolver: Arc<dyn HostResolver>,
    ) -> Self {
        Self {
            policy,
            scope,
            resolver,
        }
    }
}

impl SsrfGuard for StdSsrfGuard {
    fn check(&self, url: &str) -> Result<ResolvedTarget, GuardError> {
        check_url(
            url,
            &self.policy,
            &self.scope.list_scope(),
            self.resolver.as_ref(),
        )
    }
}

/// The guard decision as a function, so `browser.navigate` can run it against
/// whatever scope its `CommandHost` carries.
///
/// A URL that cannot be parsed, is not `http(s)`, has no host, or does not
/// resolve is refused as `OutOfScope`: a target we cannot name cannot be in
/// scope. Only an exact `host` or `host:port` entry lifts a private/loopback
/// block — a wildcard does not.
pub(crate) fn check_url(
    url: &str,
    policy: &SsrfPolicy,
    scope: &[ScopeEntry],
    resolver: &dyn HostResolver,
) -> Result<ResolvedTarget, GuardError> {
    let refused = || GuardError::OutOfScope(url.to_string());

    let parsed = url::Url::parse(url).map_err(|_| refused())?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(refused());
    }
    let host = parsed
        .host_str()
        .ok_or_else(refused)?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = parsed.port_or_known_default().ok_or_else(refused)?;

    let addrs = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => resolver.resolve(&host, port).map_err(|_| refused())?,
    };
    let Some(first) = addrs.first().copied() else {
        return Err(refused());
    };

    let blocked = std::iter::once(classify_host(&host))
        .chain(addrs.iter().map(|ip| classify_host(&ip.to_string())))
        .any(|class| match class {
            HostClass::Loopback => policy.block_loopback,
            HostClass::Private => policy.block_private,
            HostClass::Public => false,
        });
    if blocked && !(policy.allow_if_in_scope && explicitly_in_scope(scope, &host, port)) {
        return Err(GuardError::PrivateAddressBlocked(host));
    }

    Ok(ResolvedTarget {
        host,
        addr: SocketAddr::new(first, port),
    })
}

fn explicitly_in_scope(scope: &[ScopeEntry], host: &str, port: u16) -> bool {
    let with_port = format!("{host}:{port}");
    scope
        .iter()
        .any(|e| e.host.eq_ignore_ascii_case(host) || e.host.eq_ignore_ascii_case(&with_port))
}
