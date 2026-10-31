// check-open-redirect.rhai — operator command `check.open_redirect { url, param }`:
// set a redirect parameter to a canary target and report if the server redirects
// to it. OWASP A01:2021 Broken Access Control (unvalidated redirect).
//
// ACTIVE: one scope-/rate-gated request, operator-invoked only. The canary
// target is an inert marker host. For authorised testing only.
const NAME = "check-open-redirect";
const API  = "1";

fn hget(h, name) {
    let want = name.to_lower();
    for k in h.keys() { if k.to_lower() == want { return h[k]; } }
    ""
}

fn load(reg) {
    reg.add_command("check.open_redirect", "Set { url, param } to a canary and check the redirect", |args| {
        if type_of(args.url) != "string" { return "usage: check.open_redirect { url, param }"; }
        let param = if type_of(args.param) == "string" { args.param } else { "next" };
        let canary = "https://aitm-redirect-canary.example/x";
        let sep = if args.url.contains("?") { "&" } else { "?" };
        let probe = `${args.url}${sep}${url_encode(param)}=${url_encode(canary)}`;
        let resp = http.send(#{ method: "GET", url: probe });
        if resp.status == () { return `no response from ${probe}`; }
        let loc = hget(resp.headers, "Location");
        if resp.status >= 300 && resp.status < 400 && contains_ci(loc, "aitm-redirect-canary.example") {
            finding(#{
                name: "Open redirect (active canary)",
                severity: "medium",
                flow_id: resp.flow_id,
                detail: `${args.url} redirected (${resp.status}) to the canary host via \"${param}\"; the redirect target is not validated.`,
                tags: ["open-redirect", "active", "owasp-a01"],
            });
            return "VULNERABLE: redirected to canary";
        }
        `not redirected to canary (status ${resp.status})`
    });
}
