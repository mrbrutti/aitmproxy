//! Task 19: the SSRF guard and the `browser.*` commands.
//!
//! Everything here runs without Chromium except the last test, which drives a
//! real browser through the permitted path; it is part of the default suite but
//! inert unless `AITM_CHROME=1` is set (mirrors the soak test's `AITM_SOAK`).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use aitm_browser::{
    register_browser_commands, BrowserPlugin, HostResolver, SsrfGuard, SsrfPolicy, StdSsrfGuard,
};
use aitm_core::{
    CommandHost, GuardError, HttpFlow, HttpRequest, MemFlowStore, Params, Plugin, ProxyClient,
    Registry, ScopeEntry, ScopeRateGuard, StdGuard, Value,
};
use futures::future::BoxFuture;

const COMMANDS: [&str; 6] = [
    "browser.navigate",
    "browser.click",
    "browser.type",
    "browser.screenshot",
    "browser.eval",
    "browser.get_dom",
];

/// A `ProxyClient` no browser command should ever reach.
struct NoClient;

impl ProxyClient for NoClient {
    fn send(&self, _req: HttpRequest) -> BoxFuture<'_, anyhow::Result<HttpFlow>> {
        Box::pin(async {
            Err(anyhow::anyhow!(
                "browser commands do not use the proxy client"
            ))
        })
    }
}

/// Canned DNS so the resolver path is exercised without the network.
struct FakeDns(Vec<(&'static str, IpAddr)>);

impl HostResolver for FakeDns {
    fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
        let ips: Vec<IpAddr> = self
            .0
            .iter()
            .filter(|(name, _)| *name == host)
            .map(|(_, ip)| *ip)
            .collect();
        if ips.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no fake record for {host}"),
            ));
        }
        Ok(ips)
    }
}

fn params(pairs: &[(&str, Value)]) -> Params {
    Params::new(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip literal")
}

// --- SsrfGuard ---------------------------------------------------------------

/// AC12 (guard half): loopback is blocked with `PrivateAddressBlocked`, and the
/// same URL is permitted once that exact `host:port` is in scope.
#[test]
fn private_blocked_then_scoped() {
    let scope = Arc::new(StdGuard::default());
    let ssrf = StdSsrfGuard::new(SsrfPolicy::default(), scope.clone());

    let err = ssrf
        .check("http://127.0.0.1:9000/")
        .expect_err("loopback with empty scope must be blocked");
    assert_eq!(err, GuardError::PrivateAddressBlocked("127.0.0.1".into()));

    scope.add_scope(ScopeEntry {
        host: "127.0.0.1:9000".into(),
    });
    let target = ssrf
        .check("http://127.0.0.1:9000/")
        .expect("permitted once in scope");
    assert_eq!(target.host, "127.0.0.1");
    assert_eq!(
        target.addr,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)
    );
}

#[test]
fn portless_scope_entry_permits_the_host_on_any_port() {
    let scope = Arc::new(StdGuard::default());
    scope.add_scope(ScopeEntry {
        host: "10.1.2.3".into(),
    });
    let ssrf = StdSsrfGuard::new(SsrfPolicy::default(), scope);
    assert!(ssrf.check("http://10.1.2.3:8080/").is_ok());
    assert!(ssrf.check("https://10.1.2.3/").is_ok());
}

/// Review Focus #3: a public-looking hostname that resolves to a private IP is
/// blocked — classification happens on the resolved address, not the literal.
#[test]
fn dns_to_private_blocked() {
    let scope = Arc::new(StdGuard::default());
    let dns = Arc::new(FakeDns(vec![("evil.test", ip("10.0.0.5"))]));
    let ssrf = StdSsrfGuard::with_resolver(SsrfPolicy::default(), scope, dns);

    let err = ssrf
        .check("http://evil.test/")
        .expect_err("hostname resolving to RFC1918 must be blocked");
    assert_eq!(err, GuardError::PrivateAddressBlocked("evil.test".into()));
}

#[test]
fn dns_with_one_private_record_among_public_is_blocked() {
    let scope = Arc::new(StdGuard::default());
    let dns = Arc::new(FakeDns(vec![
        ("mixed.test", ip("93.184.216.34")),
        ("mixed.test", ip("127.0.0.1")),
    ]));
    let ssrf = StdSsrfGuard::with_resolver(SsrfPolicy::default(), scope, dns);
    assert!(matches!(
        ssrf.check("http://mixed.test/"),
        Err(GuardError::PrivateAddressBlocked(_))
    ));
}

#[test]
fn public_host_resolves_without_scope() {
    let scope = Arc::new(StdGuard::default());
    let dns = Arc::new(FakeDns(vec![("public.test", ip("93.184.216.34"))]));
    let ssrf = StdSsrfGuard::with_resolver(SsrfPolicy::default(), scope, dns);

    let target = ssrf
        .check("https://public.test/search?q=1")
        .expect("public addresses are not the SSRF guard's concern");
    assert_eq!(target.host, "public.test");
    assert_eq!(
        target.addr,
        SocketAddr::new(ip("93.184.216.34"), 443),
        "https default port"
    );
}

#[test]
fn policy_can_allow_loopback() {
    let scope = Arc::new(StdGuard::default());
    let policy = SsrfPolicy {
        block_loopback: false,
        ..SsrfPolicy::default()
    };
    let ssrf = StdSsrfGuard::new(policy, scope);
    assert!(ssrf.check("http://localhost:3000/").is_ok());
    assert!(matches!(
        ssrf.check("http://10.0.0.1/"),
        Err(GuardError::PrivateAddressBlocked(_))
    ));
}

#[test]
fn unparsable_or_hostless_url_is_refused() {
    let scope = Arc::new(StdGuard::default());
    let ssrf = StdSsrfGuard::new(SsrfPolicy::default(), scope);
    assert!(matches!(
        ssrf.check("not a url"),
        Err(GuardError::OutOfScope(_))
    ));
    assert!(matches!(
        ssrf.check("file:///etc/passwd"),
        Err(GuardError::OutOfScope(_))
    ));
}

// --- browser.* commands ------------------------------------------------------

#[test]
fn browser_commands_registered() {
    let mut reg = Registry::new();
    reg.add_plugin(Box::new(BrowserPlugin::new(SsrfPolicy::default())));
    for name in COMMANDS {
        assert!(reg.command(name).is_some(), "{name} is not registered");
    }
    assert_eq!(reg.commands().count(), COMMANDS.len());
    assert_eq!(BrowserPlugin::new(SsrfPolicy::default()).name(), "browser");
}

/// AC16: `browser.navigate` is refused out of scope and permitted after
/// `scope.add` — the guard decision is made before the driver is touched.
#[test]
fn navigate_is_scope_gated() {
    let mut reg = Registry::new();
    register_browser_commands(&mut reg, SsrfPolicy::default());
    let navigate = reg.command("browser.navigate").expect("registered").clone();

    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &NoClient, &guard, None);
    let args = params(&[("url", Value::Str("http://93.184.216.34/".into()))]);

    let err = navigate
        .invoke(args.clone(), &host)
        .expect_err("public host, empty scope");
    assert!(err.to_string().contains("out of scope"), "{err}");

    guard.add_scope(ScopeEntry {
        host: "93.184.216.34".into(),
    });
    let err = navigate
        .invoke(args, &host)
        .expect_err("this host has no browser wired in");
    assert!(
        err.to_string().contains("browser"),
        "scope passed, so the failure must now be the missing driver: {err}"
    );
}

/// AC12 (command half, blocked side): the SSRF guard runs inside
/// `browser.navigate` itself, before the scope guard and the driver.
#[test]
fn navigate_blocks_private_address_at_the_command() {
    let mut reg = Registry::new();
    register_browser_commands(&mut reg, SsrfPolicy::default());
    let navigate = reg.command("browser.navigate").expect("registered").clone();

    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &NoClient, &guard, None);

    let err = navigate
        .invoke(
            params(&[("url", Value::Str("http://127.0.0.1:9000/".into()))]),
            &host,
        )
        .expect_err("loopback, empty scope");
    assert!(err.to_string().contains("SSRF guard"), "{err}");
}

#[test]
fn page_commands_need_a_browser() {
    let mut reg = Registry::new();
    register_browser_commands(&mut reg, SsrfPolicy::default());
    let store = MemFlowStore::new();
    let guard = StdGuard::default();
    let host = CommandHost::new(&store, &NoClient, &guard, None);

    let err = reg
        .command("browser.screenshot")
        .expect("registered")
        .invoke(Params::default(), &host)
        .expect_err("no driver");
    assert!(err.to_string().contains("browser"), "{err}");
}

/// AC12 (command half, permitted side): with the exact `host:port` in scope the
/// navigation reaches a real driver. The loopback listener doubles as the
/// browser's `--proxy-server`, answering any absolute-form request with 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn navigate_permitted_after_scope_reaches_driver() {
    if std::env::var_os("AITM_CHROME").is_none() {
        eprintln!("skipped; set AITM_CHROME=1 to run the Chromium-backed test (AC12)");
        return;
    }
    use aitm_browser::{BrowserConfig, ChromeDriver};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let body = "<html><body>ok</body></html>";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });

    let driver = Arc::new(
        ChromeDriver::launch(&BrowserConfig {
            proxy_addr: addr,
            ..BrowserConfig::default()
        })
        .await
        .expect("launch headless Chromium"),
    );

    let url = format!("http://127.0.0.1:{}/", addr.port());
    let outcome = tokio::task::spawn_blocking(move || {
        let mut reg = Registry::new();
        register_browser_commands(&mut reg, SsrfPolicy::default());
        let navigate = reg.command("browser.navigate").expect("registered").clone();
        let store = MemFlowStore::new();
        let guard = StdGuard::default();
        guard.add_scope(ScopeEntry {
            host: format!("127.0.0.1:{}", addr.port()),
        });
        let host = CommandHost::new(&store, &NoClient, &guard, Some(&*driver));
        navigate.invoke(params(&[("url", Value::Str(url))]), &host)
    })
    .await
    .expect("join")
    .expect("navigation permitted once in scope");

    let Value::Object(fields) = outcome else {
        panic!("navigate returns an object, got {outcome:?}");
    };
    assert!(
        matches!(fields.get("final_url"), Some(Value::Str(u)) if u.starts_with("http://127.0.0.1:"))
    );
}
