// ws-cleartext-transport.rhai — flag WebSocket connections over plaintext ws://
// rather than wss://. OWASP A02:2021 Cryptographic Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "ws-cleartext-transport";
const API  = "1";

fn on_ws_start(flow) {
    if flow.request.url.starts_with("ws://") {
        flow.mark("ws-cleartext");
        finding(#{
            name: "WebSocket over cleartext ws://",
            severity: "medium",
            flow_id: flow.id,
            detail: `The WebSocket to ${flow.request.url} uses plaintext ws://; frames can be read and tampered with on-path. Use wss://.`,
            tags: ["websocket", "transport-security", "owasp-a02"],
        });
    }
}
