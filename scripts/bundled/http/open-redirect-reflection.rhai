// open-redirect-reflection.rhai — flag a redirect whose Location echoes a
// request parameter value (passive open-redirect signal).
// OWASP A01:2021 Broken Access Control (unvalidated redirect).
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "open-redirect-reflection";
const API  = "1";

fn on_response(flow) {
    let status = flow.response.status;
    if status < 300 || status >= 400 { return; }
    let loc = flow.response.headers.get("Location");
    if loc == "" { return; }
    for k in flow.request.query.keys() {
        let v = flow.request.query.get(k);
        if v.len() >= 4 && contains_ci(loc, v) {
            flow.mark("open-redirect");
            finding(#{
                name: "Possible open redirect",
                severity: "medium",
                flow_id: flow.id,
                detail: `${flow.request.path} redirects to a Location that reflects the \"${k}\" parameter; verify the target is validated against an allow-list.`,
                tags: ["open-redirect", "owasp-a01"],
            });
            return;
        }
    }
}
