// csrf-token-missing.rhai — flag cookie-authenticated state-changing requests
// that carry no anti-CSRF token. OWASP A01:2021 Broken Access Control.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "csrf-token-missing";
const API  = "1";

fn on_request(flow) {
    let m = flow.request.method;
    if m == "GET" || m == "HEAD" || m == "OPTIONS" { return; }
    // Only cookie-authenticated requests are CSRF-relevant.
    if flow.request.headers.get("Cookie") == "" { return; }
    // Token-bearing APIs (Authorization) are not classic CSRF targets.
    if flow.request.headers.get("Authorization") != "" { return; }

    let has_token = false;
    for k in flow.request.headers.keys() {
        let lk = k.to_lower();
        if lk.contains("csrf") || lk.contains("xsrf") { has_token = true; }
    }
    let body = flow.request.body;
    if contains_ci(body, "csrf") || contains_ci(body, "xsrf") || contains_ci(body, "authenticity_token") {
        has_token = true;
    }
    if !has_token {
        flow.mark("csrf-token-missing");
        finding(#{
            name: "State-changing request without CSRF token",
            severity: "medium",
            flow_id: flow.id,
            detail: `${m} ${flow.request.path} is cookie-authenticated but carries no CSRF token; verify CSRF protection.`,
            tags: ["csrf", "owasp-a01"],
        });
    }
}
