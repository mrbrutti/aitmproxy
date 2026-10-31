// ws-secret-in-frame.rhai — flag credentials/tokens inside WebSocket text frames.
// OWASP A02 Cryptographic Failures / A09 Logging Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "ws-secret-in-frame";
const API  = "1";

fn on_ws_message(flow, msg) {
    if msg.opcode != "text" { return; }
    let t = msg.text;
    if t == "" { return; }
    let pat = "(?i)(\"?(password|passwd|api[_-]?key|secret|access[_-]?token|session)\"?\\s*[:=]\\s*\"?[^\"&\\s]{6,})|(eyJ[0-9A-Za-z_-]{10,}\\.[0-9A-Za-z_-]{10,}\\.)";
    if regex_match(pat, t) {
        flow.mark("ws-secret");
        finding(#{
            name: "Secret or token in WebSocket frame",
            severity: "medium",
            flow_id: flow.id,
            detail: `A ${msg.direction} WebSocket frame on ${flow.request.url} carries what looks like a credential or token.`,
            tags: ["websocket", "secret-leak", "owasp-a02", "owasp-a09"],
        });
    }
}
