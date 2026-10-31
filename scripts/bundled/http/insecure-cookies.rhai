// insecure-cookies.rhai — flag Set-Cookie without Secure, HttpOnly, or SameSite.
// OWASP A05:2021 Misconfiguration / A07 Identification & Authentication Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "insecure-cookies";
const API  = "1";

fn on_response(flow) {
    let sc = flow.response.headers.get("Set-Cookie");
    if sc == "" { return; }
    let https = flow.request.url.starts_with("https://");
    let issues = [];
    if https && !contains_ci(sc, "secure") { issues.push("no Secure"); }
    if !contains_ci(sc, "httponly") { issues.push("no HttpOnly"); }
    if !contains_ci(sc, "samesite") { issues.push("no SameSite"); }
    if issues.len() > 0 {
        flow.mark("insecure-cookie");
        finding(#{
            name: "Insecure cookie attributes",
            severity: "low",
            flow_id: flow.id,
            detail: `Set-Cookie on ${flow.request.path} is missing: ${issues}.`,
            tags: ["cookies", "session", "owasp-a05", "owasp-a07"],
        });
    }
}
