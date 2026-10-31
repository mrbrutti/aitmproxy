// directory-listing.rhai — flag auto-generated directory index pages.
// OWASP A05:2021 Security Misconfiguration.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "directory-listing";
const API  = "1";

fn on_response(flow) {
    if flow.response.status != 200 { return; }
    let body = flow.response.body;
    if body.contains("<title>Index of /") || body.contains("Directory Listing For")
        || regex_match("(?i)<h1>Index of /", body) {
        flow.mark("directory-listing");
        finding(#{
            name: "Directory listing enabled",
            severity: "low",
            flow_id: flow.id,
            detail: `${flow.request.path} returns an auto-generated directory index, exposing the file tree.`,
            tags: ["information-disclosure", "owasp-a05"],
        });
    }
}
