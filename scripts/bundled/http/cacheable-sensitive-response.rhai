// cacheable-sensitive-response.rhai — flag an authenticated response that is
// cacheable (no Cache-Control: no-store/private). OWASP A05 Misconfiguration.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "cacheable-sensitive-response";
const API  = "1";

fn on_response(flow) {
    // "Authenticated" heuristic: the request sent a cookie or bearer token.
    let authed = flow.request.headers.get("Cookie") != ""
        || contains_ci(flow.request.headers.get("Authorization"), "bearer");
    if !authed { return; }
    if flow.response.status != 200 { return; }
    let cc = flow.response.headers.get("Cache-Control");
    if !contains_ci(cc, "no-store") && !contains_ci(cc, "private") {
        flow.mark("cacheable-sensitive");
        finding(#{
            name: "Authenticated response is cacheable",
            severity: "low",
            flow_id: flow.id,
            detail: `The authenticated response for ${flow.request.path} lacks Cache-Control: no-store/private and may be stored by shared caches.`,
            tags: ["caching", "information-disclosure", "owasp-a05"],
        });
    }
}
