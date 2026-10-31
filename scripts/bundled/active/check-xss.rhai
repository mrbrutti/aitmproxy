// check-xss.rhai — operator/agent command `check.xss { url, param }`: confirm
// reflected XSS by injecting a unique canary with active markup in several
// contexts and verifying it is reflected UNENCODED (its angle brackets/quotes
// survive). OWASP A03 Injection (Cross-Site Scripting).
//
// ACTIVE: scope-/rate-gated GETs, invoked only. The canary is a benign marker
// element (no script that calls out or runs an exploit); detection is confirmed
// by unencoded reflection, not by execution. For authorised testing only.
const NAME = "check-xss";
const API  = "1";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${url_encode(value)}`
}

fn load(reg) {
    reg.add_command("check.xss", "Confirm reflected XSS in { url, param } (unencoded reflection)", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.xss { url, param }";
        }
        let tag = `aitm` + rand_text_alpha(5);
        // Distinct break-out probes for HTML body, attribute, and JS-string contexts.
        let probes = [
            `<${tag}>x</${tag}>`,       // element injection
            `"><${tag}>`,               // attribute break-out
            `';${tag}//`,               // JS string break-out marker
        ];
        for pl in probes {
            let r = http.send(#{ method: "GET", url: q(args.url, args.param, pl) });
            if r.status == () { continue; }
            let ct = "";
            for k in r.headers.keys() { if k.to_lower() == "content-type" { ct = r.headers[k]; } }
            // Reflected verbatim (with the raw < > or ") and the response is HTML:
            // the markup was not entity-encoded, so a real payload would execute.
            if contains_ci(ct, "html") && r.body.contains(pl) {
                finding(#{
                    name: "Reflected Cross-Site Scripting (XSS)",
                    severity: "high",
                    flow_id: r.flow_id,
                    detail: `\"${args.param}\" on ${args.url} reflected an unencoded markup canary (${pl}) into the HTML response. The parameter is XSS-injectable.`,
                    tags: ["xss", "injection", "active", "owasp-a03"],
                });
                return "VULNERABLE: reflected XSS confirmed (unencoded reflection)";
            }
        }
        "no reflected XSS confirmed"
    });
}
