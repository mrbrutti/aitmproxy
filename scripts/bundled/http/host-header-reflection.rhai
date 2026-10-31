// host-header-reflection.rhai — flag the request Host (or X-Forwarded-Host)
// reflected into an absolute Location/link, a host-header-injection signal.
// OWASP A03 Injection / A10 SSRF-adjacent routing abuse.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "host-header-reflection";
const API  = "1";

fn on_response(flow) {
    let xfh = flow.request.headers.get("X-Forwarded-Host");
    if xfh == "" { return; }
    let loc = flow.response.headers.get("Location");
    let body = flow.response.body;
    if contains_ci(loc, xfh) || (body != "" && body.contains(xfh)) {
        flow.mark("host-header-reflection");
        finding(#{
            name: "X-Forwarded-Host reflected in response",
            severity: "medium",
            flow_id: flow.id,
            detail: `${flow.request.path} reflects the client-supplied X-Forwarded-Host (${xfh}) into the response; test for host-header injection / cache poisoning.`,
            tags: ["host-header", "injection", "owasp-a03"],
        });
    }
}
