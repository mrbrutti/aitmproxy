// addons/guard-admin-writes.rhai — short-circuit writes to /admin that lack a
// token, and note it as a finding for the agent to collect.
const NAME = "guard-admin-writes";
const API  = "1";

fn on_request(flow) {
    let req = flow.request;

    if req.path.starts_with("/admin") && req.method != "GET" {
        if !req.headers.has("X-Admin-Token") {
            flow.set_response(403, #{ "Content-Type": "text/plain" }, "blocked by aitm");
            finding(#{
                name: "unauthenticated admin write blocked",
                severity: "medium",
                flow_id: flow.id,
                detail: `${req.method} ${req.path} without X-Admin-Token`,
                tags: ["access-control"],
            });
            return halt();                       // stop the chain; nothing forwarded
        }
        req.headers.set("X-Reviewed", "aitm");   // otherwise tag and continue
    }
}
