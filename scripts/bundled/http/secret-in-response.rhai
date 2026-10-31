// secret-in-response.rhai — flag high-entropy credential patterns leaking in a
// response body or headers: cloud keys, tokens, and private keys.
// OWASP A05:2021 Misconfiguration / A02 Cryptographic Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "secret-in-response";
const API  = "1";

fn scan(flow, where, text) {
    if text == "" { return false; }
    let patterns = #{
        "AWS access key id": "AKIA[0-9A-Z]{16}",
        "Google API key": "AIza[0-9A-Za-z_-]{35}",
        "Slack token": "xox[baprs]-[0-9A-Za-z-]{10,}",
        "GitHub token": "gh[pousr]_[0-9A-Za-z]{36,}",
        "Private key block": "-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
        "Stripe secret key": "sk_live_[0-9A-Za-z]{24,}",
    };
    for name in patterns.keys() {
        if regex_match(patterns[name], text) {
            flow.mark("secret-leak");
            finding(#{
                name: `Secret exposed in ${where}`,
                severity: "critical",
                flow_id: flow.id,
                detail: `${flow.request.path} response ${where} contains what looks like a ${name}. Confirm and rotate if real.`,
                tags: ["secret-leak", "owasp-a02", "owasp-a05"],
            });
            return true;
        }
    }
    false
}

fn on_response(flow) {
    if scan(flow, "body", flow.response.body) { return; }
    // Also scan response header values (e.g. a token echoed into a custom
    // header or Set-Cookie), matching this script's stated coverage.
    let h = flow.response.headers;
    for k in h.keys() {
        if scan(flow, `header ${k}`, h.get(k)) { return; }
    }
}
