// check-http-methods.rhai — operator command `check.methods { url }`: send an
// OPTIONS request and report the advertised Allow methods, flagging risky ones.
// OWASP A05:2021 Security Misconfiguration.
//
// ACTIVE: one scope-/rate-gated OPTIONS request, operator-invoked only.
// For authorised testing only.
const NAME = "check-http-methods";
const API  = "1";

fn hget(h, name) {
    let want = name.to_lower();
    for k in h.keys() { if k.to_lower() == want { return h[k]; } }
    ""
}

fn load(reg) {
    reg.add_command("check.methods", "Send OPTIONS to { url } and report Allow", |args| {
        if type_of(args.url) != "string" { return "usage: check.methods { url }"; }
        let resp = http.send(#{ method: "OPTIONS", url: args.url });
        if resp.status == () { return `no response from ${args.url}`; }
        let allow = hget(resp.headers, "Allow");
        if allow == "" { return `OPTIONS ${args.url}: no Allow header (status ${resp.status})`; }
        let au = allow.to_upper();
        let risky = [];
        for m in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"] { if au.contains(m) { risky.push(m); } }
        if risky.len() > 0 {
            finding(#{
                name: "Risky HTTP methods allowed (active)",
                severity: "info",
                flow_id: resp.flow_id,
                detail: `${args.url} allows ${allow}; confirm ${risky} are intended.`,
                tags: ["http-methods", "active", "owasp-a05"],
            });
        }
        `Allow: ${allow}`
    });
}
