// check-ldap-injection.rhai — operator/agent command
// `check.ldapi { url, param, value? }`: confirm LDAP injection via error-based
// detection and an authentication/response differential. OWASP A03 Injection.
//
// ACTIVE: scope-/rate-gated GETs, invoked only. Payloads are LDAP filter
// metacharacters that change a query's truth value, not destructive operations.
// For authorised testing only.
const NAME = "check-ldap-injection";
const API  = "1";

const LDAP_ERR = "(?i)(LDAP:.*error|javax\\.naming|com\\.sun\\.jndi|invalid DN syntax|bad search filter|Protocol error.*ldap|OpenLDAP)";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${url_encode(value)}`
}

fn load(reg) {
    reg.add_command("check.ldapi", "Confirm LDAP injection in { url, param }", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.ldapi { url, param }";
        }
        let base = if type_of(args.value) == "string" { args.value } else { "x" };

        // 1) Error-based: an unbalanced filter paren.
        let e = http.send(#{ method: "GET", url: q(args.url, args.param, base + ")(|(cn=*") });
        if e.status != () && regex_match(LDAP_ERR, e.body) {
            finding(#{
                name: "LDAP injection (error-based)",
                severity: "high",
                flow_id: e.flow_id,
                detail: `An LDAP filter metacharacter in \"${args.param}\" on ${args.url} produced an LDAP error. The parameter reaches an LDAP query unsafely.`,
                tags: ["ldap-injection", "injection", "active", "owasp-a03"],
            });
            return "VULNERABLE: LDAP error-based injection confirmed";
        }

        // 2) Differential: a wildcard/always-true filter vs the baseline.
        let b = http.send(#{ method: "GET", url: q(args.url, args.param, base) });
        let t = http.send(#{ method: "GET", url: q(args.url, args.param, "*)(cn=*))%00") });
        if b.status != () && t.status != () {
            let d = t.body.len() - b.body.len();
            let ad = if d < 0 { -d } else { d };
            let thresh = if b.body.len() / 10 > 80 { b.body.len() / 10 } else { 80 };
            if t.status == 200 && ad > thresh {
                finding(#{
                    name: "LDAP injection (filter differential)",
                    severity: "high",
                    flow_id: t.flow_id,
                    detail: `An always-true LDAP filter in \"${args.param}\" on ${args.url} changed the response size materially (${b.body.len()} -> ${t.body.len()} bytes).`,
                    tags: ["ldap-injection", "injection", "active", "owasp-a03"],
                });
                return "VULNERABLE: LDAP filter injection confirmed";
            }
        }
        "no LDAP injection confirmed"
    });
}
