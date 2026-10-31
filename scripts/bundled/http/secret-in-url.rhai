// secret-in-url.rhai — flag credentials/tokens carried in the request query
// string, where they leak into logs, history, and Referer headers.
// OWASP A09:2021 Logging Failures / A02 Cryptographic Failures.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "secret-in-url";
const API  = "1";

fn on_request(flow) {
    let risky = ["password", "passwd", "pwd", "token", "access_token", "api_key",
                 "apikey", "secret", "session", "sessionid", "auth", "jwt"];
    for k in flow.request.query.keys() {
        let lk = k.to_lower();
        for r in risky {
            if lk == r || lk.contains(r) {
                flow.mark("secret-in-url");
                finding(#{
                    name: "Sensitive value in URL query",
                    severity: "medium",
                    flow_id: flow.id,
                    detail: `${flow.request.path} carries a sensitive parameter (\"${k}\") in the query string; it leaks via logs, browser history and Referer.`,
                    tags: ["information-disclosure", "owasp-a09", "owasp-a02"],
                });
                return;
            }
        }
    }
}
