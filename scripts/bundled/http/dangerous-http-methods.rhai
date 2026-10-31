// dangerous-http-methods.rhai — flag risky methods advertised in an Allow
// header or an enabled TRACE. OWASP A05:2021 Security Misconfiguration.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "dangerous-http-methods";
const API  = "1";

fn on_response(flow) {
    // A 200 to a TRACE request is Cross-Site Tracing exposure.
    if flow.request.method == "TRACE" && flow.response.status == 200 {
        flow.mark("trace-enabled");
        finding(#{
            name: "HTTP TRACE enabled",
            severity: "low",
            flow_id: flow.id,
            detail: `${flow.request.path} answers TRACE with 200 (Cross-Site Tracing risk).`,
            tags: ["http-methods", "owasp-a05"],
        });
        return;
    }
    let allow = flow.response.headers.get("Allow").to_upper();
    let risky = [];
    for m in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"] {
        if allow.contains(m) { risky.push(m); }
    }
    if risky.len() > 0 {
        flow.mark("dangerous-methods");
        finding(#{
            name: "Risky HTTP methods advertised",
            severity: "info",
            flow_id: flow.id,
            detail: `${flow.request.path} advertises Allow: ${allow}; confirm ${risky} are intended and authorised.`,
            tags: ["http-methods", "owasp-a05"],
        });
    }
}
