// private-address-disclosure.rhai — flag internal RFC1918 IP addresses leaking
// in response headers or body. OWASP A05:2021 Security Misconfiguration.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "private-address-disclosure";
const API  = "1";

fn on_response(flow) {
    let pat = "(?:^|[^0-9])(10\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}|192\\.168\\.[0-9]{1,3}\\.[0-9]{1,3}|172\\.(?:1[6-9]|2[0-9]|3[01])\\.[0-9]{1,3}\\.[0-9]{1,3})";
    let found = regex_extract(pat, flow.response.body, 1);
    if found == "" {
        found = regex_extract(pat, flow.response.headers.get("Location"), 1);
    }
    if found != "" {
        flow.mark("private-ip-leak");
        finding(#{
            name: "Internal IP address disclosed",
            severity: "info",
            flow_id: flow.id,
            detail: `${flow.request.path} discloses an internal RFC1918 address (${found}).`,
            tags: ["information-disclosure", "owasp-a05"],
        });
    }
}
