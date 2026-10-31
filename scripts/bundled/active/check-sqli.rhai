// check-sqli.rhai — operator/agent command
// `check.sqli { url, param, value? }`: confirm SQL injection in a query
// parameter by (1) error-based detection and (2) a boolean differential
// (TRUE condition ≈ baseline, FALSE condition diverges). OWASP A03 Injection.
//
// ACTIVE: a few scope-/rate-gated GETs through the proxy client, invoked only.
// The payloads are detection conditions (1=1 / 1=2, a single quote); they read
// nothing and change nothing in the database. For authorised testing only.
const NAME = "check-sqli";
const API  = "1";

const SQL_ERR = "(?i)(SQL syntax.*MySQL|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLSTATE\\[|SQLiteException|Unclosed quotation mark|SqlException|psycopg2\\.|sqlalchemy\\.exc\\.|Warning.*mysqli?_|quoted string not properly terminated)";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${url_encode(value)}`
}
fn body_of(url) {
    let r = http.send(#{ method: "GET", url: url });
    if r.status == () { return (); }
    r
}
fn diff(a, b) { let d = a - b; if d < 0 { -d } else { d } }

fn load(reg) {
    reg.add_command("check.sqli", "Confirm SQL injection in { url, param, value? } (error + boolean)", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.sqli { url, param, value? }";
        }
        let base = if type_of(args.value) == "string" { args.value } else { "1" };
        let p = args.param;

        // 1) Error-based: a lone quote that breaks a string context.
        let err = body_of(q(args.url, p, base + "'"));
        if err != () && regex_match(SQL_ERR, err.body) {
            finding(#{
                name: "SQL injection (error-based)",
                severity: "critical",
                flow_id: err.flow_id,
                detail: `Injecting a single quote into \"${p}\" on ${args.url} produced a database error. The parameter is injectable.`,
                tags: ["sqli", "injection", "active", "owasp-a03"],
            });
            return "VULNERABLE: error-based SQLi confirmed";
        }

        // 2) Boolean differential: TRUE should match the baseline, FALSE diverge.
        let baseline = body_of(q(args.url, p, base));
        if baseline == () { return "no response from baseline request"; }
        let blen = baseline.body.len();

        // Try a numeric and a string-break context.
        let pairs = [
            [` AND 1=1`, ` AND 1=2`],
            [`' AND '1'='1`, `' AND '1'='2`],
            [`" AND "1"="1`, `" AND "1"="2`],
        ];
        for pair in pairs {
            let t = body_of(q(args.url, p, base + pair[0]));
            let f = body_of(q(args.url, p, base + pair[1]));
            if t == () || f == () { continue; }
            let tlen = t.body.len();
            let flen = f.body.len();
            let thresh = if blen / 20 > 40 { blen / 20 } else { 40 };
            // TRUE tracks the baseline, FALSE departs from both.
            if diff(tlen, blen) <= thresh && diff(flen, tlen) > thresh {
                finding(#{
                    name: "SQL injection (boolean-based blind)",
                    severity: "critical",
                    flow_id: t.flow_id,
                    detail: `\"${p}\" on ${args.url} shows a boolean differential: a TRUE condition matches the baseline (${blen}≈${tlen} bytes) while a FALSE condition diverges (${flen} bytes). The parameter is injectable.`,
                    tags: ["sqli", "injection", "active", "owasp-a03"],
                });
                return "VULNERABLE: boolean-based SQLi confirmed";
            }
        }
        "no SQL injection confirmed"
    });
}
