// check-security-headers.rhai — operator command `check.headers { url }`:
// actively fetch a URL and report missing security response headers.
// OWASP A05:2021 Security Misconfiguration.
//
// ACTIVE: sends one GET through the proxy's own client, which is scope- and
// rate-gated (deny-by-default). It runs only when the operator invokes the
// command; it registers no automatic hook. For authorised testing only.
const NAME = "check-security-headers";
const API  = "1";

fn hget(h, name) {
    let want = name.to_lower();
    for k in h.keys() { if k.to_lower() == want { return h[k]; } }
    ""
}

fn load(reg) {
    reg.add_command("check.headers", "Fetch { url } and report missing security headers", |args| {
        if type_of(args.url) != "string" { return "usage: check.headers { url: \"https://host/path\" }"; }
        let resp = http.send(#{ method: "GET", url: args.url });
        if resp.status == () { return `request to ${args.url} produced no response`; }
        let wanted = ["Strict-Transport-Security", "Content-Security-Policy",
                      "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"];
        let missing = [];
        for h in wanted { if hget(resp.headers, h) == "" { missing.push(h); } }
        if missing.len() > 0 {
            finding(#{
                name: "Missing security headers (active)",
                severity: "low",
                flow_id: resp.flow_id,
                detail: `${args.url} (HTTP ${resp.status}) is missing: ${missing}.`,
                tags: ["headers", "active", "owasp-a05"],
            });
        }
        `checked ${args.url}: ${missing.len()} header(s) missing`
    });
}
