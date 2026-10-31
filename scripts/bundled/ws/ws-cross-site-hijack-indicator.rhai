// ws-cross-site-hijack-indicator.rhai — flag a cookie-authenticated WebSocket
// handshake, the precondition for Cross-Site WebSocket Hijacking when the
// server does not validate Origin. OWASP A01:2021 Broken Access Control.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "ws-cross-site-hijack-indicator";
const API  = "1";

fn on_ws_start(flow) {
    if flow.request.headers.get("Cookie") == "" { return; }
    let origin = flow.request.headers.get("Origin");
    flow.mark("ws-cswsh-candidate");
    finding(#{
        name: "Cookie-authenticated WebSocket handshake",
        severity: "low",
        flow_id: flow.id,
        detail: `The WebSocket handshake to ${flow.request.url} is authenticated by cookie (Origin: ${origin}); confirm the server validates Origin to prevent Cross-Site WebSocket Hijacking.`,
        tags: ["websocket", "cswsh", "owasp-a01"],
    });
}
