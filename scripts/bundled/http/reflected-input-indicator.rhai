// reflected-input-indicator.rhai — flag a request parameter value reflected
// unencoded into an HTML response (passive reflected-XSS sink signal).
// OWASP A03:2021 Injection (Cross-Site Scripting).
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "reflected-input-indicator";
const API  = "1";

fn on_response(flow) {
    let ct = flow.response.headers.get("Content-Type");
    if !contains_ci(ct, "text/html") { return; }
    let body = flow.response.body;
    if body == "" { return; }
    for k in flow.request.query.keys() {
        let v = flow.request.query.get(k);
        // Only values that look like they could carry markup, long enough to be
        // a meaningful match, reflected verbatim into the HTML.
        if v.len() >= 6 && (v.contains("<") || v.contains("\"") || v.contains("'")) && body.contains(v) {
            flow.mark("reflected-input");
            finding(#{
                name: "Unencoded reflected input",
                severity: "medium",
                flow_id: flow.id,
                detail: `The \"${k}\" parameter is reflected verbatim into the HTML response on ${flow.request.path}; test for reflected XSS.`,
                tags: ["xss", "injection", "owasp-a03"],
            });
            return;
        }
    }
}
