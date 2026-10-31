// check-crlf-injection.rhai — operator/agent command `check.crlf { url, param }`:
// confirm CRLF / HTTP response-header injection by injecting a header via a
// parameter and checking it appears in the response headers. OWASP A03.
//
// ACTIVE: scope-/rate-gated GETs, invoked only. The injected header is an inert
// canary; no cache poisoning or session fixation is attempted. Authorised only.
const NAME = "check-crlf-injection";
const API  = "1";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${value}`
}
fn hget(h, name) {
    let want = name.to_lower();
    for k in h.keys() { if k.to_lower() == want { return h[k]; } }
    ""
}

fn load(reg) {
    reg.add_command("check.crlf", "Confirm CRLF header injection in { url, param }", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.crlf { url, param }";
        }
        let canary = rand_text_alpha(6);
        let encodings = [
            `x%0d%0aX-Aitm-Crlf:%20${canary}`,
            `x%0d%0aX-Aitm-Crlf:${canary}`,
            `x%E5%98%8D%E5%98%8AX-Aitm-Crlf:${canary}`, // unicode CRLF overlong
        ];
        for pl in encodings {
            let r = http.send(#{ method: "GET", url: q(args.url, args.param, pl) });
            if r.status == () { continue; }
            if contains_ci(hget(r.headers, "X-Aitm-Crlf"), canary) {
                finding(#{
                    name: "CRLF / HTTP response header injection",
                    severity: "high",
                    flow_id: r.flow_id,
                    detail: `\"${args.param}\" on ${args.url} injected a response header (X-Aitm-Crlf). This enables header injection, cache poisoning and XSS.`,
                    tags: ["crlf", "header-injection", "active", "owasp-a03"],
                });
                return "VULNERABLE: CRLF injection confirmed";
            }
        }
        "no CRLF injection confirmed"
    });
}
