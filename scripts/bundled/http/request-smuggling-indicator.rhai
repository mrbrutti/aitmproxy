// request-smuggling-indicator.rhai — flag a request carrying both
// Content-Length and Transfer-Encoding, the classic CL.TE / TE.CL ambiguity.
// OWASP A05 Misconfiguration (also request smuggling).
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "request-smuggling-indicator";
const API  = "1";

fn on_request(flow) {
    let has_cl = flow.request.headers.has("Content-Length");
    let te = flow.request.headers.get("Transfer-Encoding");
    if has_cl && te != "" {
        flow.mark("smuggling-ambiguity");
        finding(#{
            name: "Ambiguous Content-Length + Transfer-Encoding",
            severity: "medium",
            flow_id: flow.id,
            detail: `${flow.request.method} ${flow.request.path} carries both Content-Length and Transfer-Encoding (${te}); front/back-end disagreement enables request smuggling.`,
            tags: ["request-smuggling", "owasp-a05"],
        });
    }
}
