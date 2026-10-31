// check-ssti.rhai — operator/agent command `check.ssti { url, param, value? }`:
// confirm Server-Side Template Injection by sending an arithmetic marker in the
// major template syntaxes and checking the server evaluated it. OWASP A03.
//
// ACTIVE: scope-/rate-gated GETs, invoked only. The payload is an arithmetic
// expression whose evaluated result (a unique product) proves evaluation; it is
// not a code-execution payload. For authorised testing only.
const NAME = "check-ssti";
const API  = "1";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${url_encode(value)}`
}

fn load(reg) {
    reg.add_command("check.ssti", "Confirm template injection in { url, param }", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.ssti { url, param }";
        }
        // Two primes so the product (1product) is unlikely to occur by chance.
        let a = 73; let b = 79; let want = `${a * b}`; // 5767
        let tag = rand_text_alpha(4);
        // {{..}} Jinja/Twig, ${..} FreeMarker/JSP-EL, #{..} Ruby/Thymeleaf, <%= %> ERB
        let payloads = [
            `${tag}{{${a}*${b}}}`,
            `${tag}` + "${" + `${a}*${b}` + "}",
            `${tag}#{${a}*${b}}`,
            `${tag}<%= ${a}*${b} %>`,
        ];
        for pl in payloads {
            let r = http.send(#{ method: "GET", url: q(args.url, args.param, pl) });
            if r.status == () { continue; }
            if r.body.contains(`${tag}${want}`) {
                finding(#{
                    name: "Server-Side Template Injection",
                    severity: "critical",
                    flow_id: r.flow_id,
                    detail: `\"${args.param}\" on ${args.url} evaluated a template expression (${a}*${b} rendered as ${want}). SSTI typically leads to remote code execution.`,
                    tags: ["ssti", "injection", "rce", "active", "owasp-a03"],
                });
                return "VULNERABLE: SSTI confirmed (expression evaluated)";
            }
        }
        "no template injection confirmed"
    });
}
