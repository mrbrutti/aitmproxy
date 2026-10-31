// mixed-content.rhai — flag an HTTPS page that references http:// sub-resources.
// OWASP A02:2021 Cryptographic Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "mixed-content";
const API  = "1";

fn on_response(flow) {
    if !flow.request.url.starts_with("https://") { return; }
    let ct = flow.response.headers.get("Content-Type");
    if !contains_ci(ct, "text/html") { return; }
    let body = flow.response.body;
    if regex_match("(?i)(src|href)\\s*=\\s*[\"']http://", body) {
        flow.mark("mixed-content");
        finding(#{
            name: "Mixed content on HTTPS page",
            severity: "low",
            flow_id: flow.id,
            detail: `The HTTPS page ${flow.request.path} references http:// sub-resources, which can be tampered with on-path.`,
            tags: ["transport-security", "owasp-a02"],
        });
    }
}
