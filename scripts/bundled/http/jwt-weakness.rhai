// jwt-weakness.rhai — detect JSON Web Tokens in requests and flag a dangerous
// "alg":"none" header. OWASP A02 Cryptographic Failures / A07 Auth Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "jwt-weakness";
const API  = "1";

fn check(flow, where, token) {
    // JWT: three base64url segments separated by dots.
    let header_b64 = regex_extract("eyJ[0-9A-Za-z_-]+", token, 0);
    if header_b64 == "" { return; }
    let decoded = "";
    try { decoded = b64_decode(header_b64); } catch (e) { return; }
    if regex_match("(?i)\"alg\"\\s*:\\s*\"none\"", decoded) {
        flow.mark("jwt-alg-none");
        finding(#{
            name: "JWT with alg=none",
            severity: "high",
            flow_id: flow.id,
            detail: `A JWT in the ${where} on ${flow.request.path} declares alg=none; if the server honours it, tokens can be forged.`,
            tags: ["jwt", "auth", "owasp-a02", "owasp-a07"],
        });
    }
}

fn on_request(flow) {
    check(flow, "Authorization header", flow.request.headers.get("Authorization"));
    check(flow, "Cookie header", flow.request.headers.get("Cookie"));
}
