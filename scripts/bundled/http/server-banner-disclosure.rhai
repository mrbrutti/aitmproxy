// server-banner-disclosure.rhai — flag version banners that aid fingerprinting:
// Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, X-Generator.
// OWASP A05:2021 Security Misconfiguration.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "server-banner-disclosure";
const API  = "1";

fn on_response(flow) {
    let banners = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"];
    let found = [];
    for h in banners {
        let v = flow.response.headers.get(h);
        if v != "" { found.push(`${h}: ${v}`); }
    }
    // A bare product name in Server is low signal; a version number is the tell.
    let server = flow.response.headers.get("Server");
    if server != "" && regex_match("[0-9]+\\.[0-9]+", server) {
        found.push(`Server: ${server}`);
    }
    if found.len() > 0 {
        flow.mark("version-disclosure");
        finding(#{
            name: "Server/framework version disclosure",
            severity: "info",
            flow_id: flow.id,
            detail: `${flow.request.path} discloses: ${found}.`,
            tags: ["information-disclosure", "fingerprint", "owasp-a05"],
        });
    }
}
