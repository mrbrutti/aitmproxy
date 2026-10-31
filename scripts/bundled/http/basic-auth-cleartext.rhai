// basic-auth-cleartext.rhai — flag HTTP Basic/Digest credentials sent over a
// plaintext (http://) connection. OWASP A02:2021 Cryptographic Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "basic-auth-cleartext";
const API  = "1";

fn on_request(flow) {
    if flow.request.url.starts_with("https://") { return; }
    let auth = flow.request.headers.get("Authorization");
    if contains_ci(auth, "basic ") || contains_ci(auth, "digest ") {
        flow.mark("cleartext-credentials");
        finding(#{
            name: "Credentials sent over cleartext HTTP",
            severity: "high",
            flow_id: flow.id,
            detail: `${flow.request.method} ${flow.request.path} sends an Authorization header over plaintext http; anyone on-path can read the credentials.`,
            tags: ["transport-security", "credentials", "owasp-a02"],
        });
    }
}
