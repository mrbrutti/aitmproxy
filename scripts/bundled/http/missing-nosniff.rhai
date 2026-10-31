// missing-nosniff.rhai — flag responses without X-Content-Type-Options: nosniff.
// OWASP A05:2021 Security Misconfiguration (MIME sniffing).
//
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "missing-nosniff";
const API  = "1";

fn on_response(flow) {
    let v = flow.response.headers.get("X-Content-Type-Options");
    if !contains_ci(v, "nosniff") {
        flow.mark("missing-nosniff");
        finding(#{
            name: "Missing X-Content-Type-Options: nosniff",
            severity: "info",
            flow_id: flow.id,
            detail: `Response for ${flow.request.path} does not set X-Content-Type-Options: nosniff; browsers may MIME-sniff the body.`,
            tags: ["headers", "owasp-a05"],
        });
    }
}
