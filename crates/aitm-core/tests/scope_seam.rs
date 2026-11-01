//! The scope seam on the protocol-module context (spec D1/D2, AC8, AC14).
//!
//! A module asks `ModuleCtx::in_scope(authority)` before it terminates TLS. With
//! no guard attached the answer is `false` for every authority (deny-by-default);
//! with one attached it is exactly `ScopeRateGuard::in_scope`, i.e.
//! `Authority::matches_scope_entry` over the live entries. `NextLayerHint::
//! tunnel_authority` is the one port rule both modules compute the authority with.

use std::net::SocketAddr;
use std::sync::Arc;

use aitm_core::{
    Authority, ByteStream, Event, EventSink, FlowId, MemFlowStore, ModuleCtx, NextLayerHint,
    ScopeEntry, ScopeRateGuard, StdGuard, UpstreamConnector, Verdict,
};
use futures::future::BoxFuture;

struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _ev: Event) -> BoxFuture<'_, Verdict> {
        Box::pin(async { Verdict::Continue })
    }
}

struct NoDial;

impl UpstreamConnector for NoDial {
    fn connect(
        &self,
        _authority: &str,
        _dst: SocketAddr,
    ) -> BoxFuture<'_, anyhow::Result<ByteStream>> {
        Box::pin(async { anyhow::bail!("no dial in a scope-seam test") })
    }
}

fn ctx() -> ModuleCtx {
    ModuleCtx::new(
        Arc::new(MemFlowStore::new()),
        Arc::new(NoopSink),
        Arc::new(NoDial),
    )
}

fn guard_with(entries: &[&str]) -> Arc<dyn ScopeRateGuard> {
    let guard = StdGuard::default();
    for host in entries {
        guard.add_scope(ScopeEntry {
            host: (*host).to_string(),
        });
    }
    Arc::new(guard)
}

fn hint(dst: &str) -> NextLayerHint {
    NextLayerHint {
        dst: dst.parse().expect("socket addr"),
        is_tls: false,
        client_hello_sni: None,
        alpn: Vec::new(),
        first_bytes: Vec::new(),
        from_upgrade: false,
        peer_identity: None,
        capture_interface: None,
    }
}

/// AC14: a context nobody attached a guard to reports nothing in scope.
#[test]
fn module_ctx_without_scope_is_never_in_scope() {
    let ctx = ctx();
    assert!(!ctx.in_scope("example.com:443"));
    assert!(!ctx.in_scope("127.0.0.1:8080"));
    assert!(!ctx.in_scope("[::1]:443"));
}

/// AC8 via the seam: with a guard attached the answer is the guard's, with the
/// scope-entry rules (a bare host admits every port).
#[test]
fn module_ctx_with_scope_forwards_to_the_guard() {
    let ctx = ctx().with_scope(guard_with(&["example.com"]));
    assert!(ctx.in_scope("example.com:443"));
    assert!(ctx.in_scope("example.com:8443"));
    assert!(!ctx.in_scope("other.test:443"));
}

/// The child context for an upgrade hand-off keeps the parent's guard, so the
/// module taking over sees the same scope the HTTP module decided on.
#[test]
fn module_ctx_for_upgrade_keeps_the_scope() {
    let parent = ctx().with_scope(guard_with(&["example.com"]));
    let (upstream, _peer) = tokio::io::duplex(8);
    let child = parent.for_upgrade(FlowId::new(), Box::pin(upstream), hint("127.0.0.1:1"));
    assert!(child.in_scope("example.com:443"));
    assert!(!child.in_scope("other.test:443"));

    let orphan = ctx();
    let (upstream, _peer) = tokio::io::duplex(8);
    let child = orphan.for_upgrade(FlowId::new(), Box::pin(upstream), hint("127.0.0.1:1"));
    assert!(!child.in_scope("example.com:443"));
}

/// D1: the tunnel authority of a CONNECT is `host:port` from its request line,
/// normalised the way `Authority::new` normalises (lowercase, brackets off), with
/// 443 when the line carries no port.
#[test]
fn tunnel_authority_from_connect_line() {
    let mut h = hint("127.0.0.1:54321");
    h.first_bytes = b"CONNECT Example.COM:8443 HTTP/1.1\r\nHost: Example.COM:8443\r\n\r\n".to_vec();
    assert_eq!(
        h.tunnel_authority(),
        Some(Authority::new("example.com", 8443))
    );

    h.first_bytes = b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n".to_vec();
    let v6 = h
        .tunnel_authority()
        .expect("an IPv6 literal authority parses");
    assert_eq!(v6.host, "::1");
    assert_eq!(v6.port, 443);
    assert_eq!(v6.to_string(), "[::1]:443");

    h.first_bytes = b"CONNECT example.com HTTP/1.1\r\n\r\n".to_vec();
    assert_eq!(
        h.tunnel_authority(),
        Some(Authority::new("example.com", 443))
    );

    // The CONNECT line wins over an SNI the acceptor may also have seen.
    h.client_hello_sni = Some("sni.example".to_string());
    h.first_bytes = b"CONNECT connect.example:9443 HTTP/1.1\r\n\r\n".to_vec();
    assert_eq!(
        h.tunnel_authority(),
        Some(Authority::new("connect.example", 9443))
    );
}

/// D1: on the explicit-proxy path a raw TLS connection's authority is `sni:443`
/// (the acceptor's `dst` is the client's peer address, not a destination).
#[test]
fn tunnel_authority_from_sni_defaults_443_on_the_proxy_path() {
    let mut h = hint("127.0.0.1:54321");
    h.is_tls = true;
    h.first_bytes = vec![0x16, 0x03, 0x01];
    h.client_hello_sni = Some("Api.Example.COM".to_string());
    assert_eq!(
        h.tunnel_authority(),
        Some(Authority::new("api.example.com", 443))
    );
}

/// D1: on the capture path (`capture_interface` set) `dst` is the original
/// destination, so the authority takes its port.
#[test]
fn tunnel_authority_from_sni_uses_dst_port_on_the_capture_path() {
    let mut h = hint("93.184.216.34:8443");
    h.is_tls = true;
    h.first_bytes = vec![0x16, 0x03, 0x01];
    h.client_hello_sni = Some("api.example.com".to_string());
    h.capture_interface = Some("macos-ne".to_string());
    assert_eq!(
        h.tunnel_authority(),
        Some(Authority::new("api.example.com", 8443))
    );
}

/// No CONNECT line and no SNI is no tunnel authority (the connection cannot be
/// decrypted by name); a CONNECT line cut before its terminating space is not
/// trusted as an authority; an upgrade hand-off continues an already-decrypted
/// connection and never names a tunnel of its own.
#[test]
fn tunnel_authority_is_none_without_connect_or_sni() {
    let mut h = hint("127.0.0.1:54321");
    h.first_bytes = b"GET / HTTP/1.1\r\n\r\n".to_vec();
    assert_eq!(h.tunnel_authority(), None);

    h.is_tls = true;
    h.first_bytes = vec![0x16, 0x03, 0x01];
    assert_eq!(h.tunnel_authority(), None, "TLS with no SNI");

    h.is_tls = false;
    h.first_bytes = b"CONNECT example.com:44".to_vec();
    assert_eq!(h.tunnel_authority(), None, "truncated CONNECT line");

    h.first_bytes = b"CONNECT  HTTP/1.1\r\n\r\n".to_vec();
    assert_eq!(h.tunnel_authority(), None, "empty CONNECT authority");

    let mut handoff = hint("127.0.0.1:54321");
    handoff.from_upgrade = true;
    handoff.alpn = vec!["websocket".to_string()];
    handoff.client_hello_sni = Some("ws.example".to_string());
    assert_eq!(handoff.tunnel_authority(), None, "upgrade hand-off");
}
