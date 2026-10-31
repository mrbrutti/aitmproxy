// ws-pii-in-frame.rhai — flag personal data (email / card-like numbers) inside
// WebSocket text frames. OWASP A02:2021 Cryptographic Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "ws-pii-in-frame";
const API  = "1";

fn on_ws_message(flow, msg) {
    if msg.opcode != "text" { return; }
    let t = msg.text;
    if t == "" { return; }
    let email = regex_match("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", t);
    let card  = regex_match("(?:^|[^0-9])(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})(?:[^0-9]|$)", t);
    if email || card {
        let what = if card { "a card-like number" } else { "an email address" };
        flow.mark("ws-pii");
        finding(#{
            name: "Personal data in WebSocket frame",
            severity: "low",
            flow_id: flow.id,
            detail: `A ${msg.direction} WebSocket frame on ${flow.request.url} contains ${what}.`,
            tags: ["websocket", "pii", "owasp-a02"],
        });
    }
}
