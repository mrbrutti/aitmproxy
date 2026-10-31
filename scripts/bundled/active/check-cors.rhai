// check-cors.rhai — operator command `check.cors { url }`: send a cross-origin
// preflight-style request with a canary Origin and report whether the server
// reflects it (optionally with credentials). OWASP A05 Misconfiguration.
//
// ACTIVE: one scope-/rate-gated request via the proxy client, operator-invoked
// only. The Origin is a harmless canary. For authorised testing only.
const NAME = "check-cors";
const API  = "1";

fn hget(h, name) {
    let want = name.to_lower();
    for k in h.keys() { if k.to_lower() == want { return h[k]; } }
    ""
}

fn load(reg) {
    reg.add_command("check.cors", "Probe { url } CORS with a canary Origin", |args| {
        if type_of(args.url) != "string" { return "usage: check.cors { url: \"https://host/api\" }"; }
        let canary = "https://aitm-cors-canary.example";
        let resp = http.send(#{ method: "GET", url: args.url, headers: #{ "Origin": canary } });
        if resp.status == () { return `no response from ${args.url}`; }
        let acao = hget(resp.headers, "Access-Control-Allow-Origin");
        let creds = contains_ci(hget(resp.headers, "Access-Control-Allow-Credentials"), "true");
        if acao == canary {
            let sev = if creds { "high" } else { "medium" };
            finding(#{
                name: "CORS reflects arbitrary Origin (active)",
                severity: sev,
                flow_id: resp.flow_id,
                detail: `${args.url} reflected the canary Origin in Access-Control-Allow-Origin (credentials=${creds}).`,
                tags: ["cors", "active", "owasp-a05"],
            });
            return `VULNERABLE: origin reflected (credentials=${creds})`;
        } else if acao == "*" {
            return "ACAO is * (no credentials possible)";
        }
        `not reflected (ACAO: ${acao})`
    });
}
