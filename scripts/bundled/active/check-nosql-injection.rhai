// check-nosql-injection.rhai — operator/agent command
// `check.nosqli { url, param, value? }`: confirm NoSQL (Mongo-style) operator
// injection by comparing a normal query to one using a `$ne`/`$gt` operator,
// plus error-based detection. OWASP A03 Injection.
//
// ACTIVE: scope-/rate-gated GETs, invoked only. The payloads are query operators
// that change result sets, not destructive writes. For authorised testing only.
const NAME = "check-nosql-injection";
const API  = "1";

const NOSQL_ERR = "(?i)(MongoError|CastError|BSONError|E11000|unexpected token|\\$where|mongoose)";

fn url_with(url, raw) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${raw}`
}

fn load(reg) {
    reg.add_command("check.nosqli", "Confirm NoSQL operator injection in { url, param, value? }", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.nosqli { url, param, value? }";
        }
        let base = if type_of(args.value) == "string" { args.value } else { "1" };
        let p = url_encode(args.param);

        // Baseline.
        let b = http.send(#{ method: "GET", url: url_with(args.url, `${p}=${url_encode(base)}`) });
        if b.status == () { return "no response from baseline"; }

        // Error-based: a bare operator object often trips a parser.
        let e = http.send(#{ method: "GET", url: url_with(args.url, `${p}[$ne]=`) });
        if e.status != () && regex_match(NOSQL_ERR, e.body) {
            finding(#{
                name: "NoSQL injection (error-based)",
                severity: "high",
                flow_id: e.flow_id,
                detail: `A NoSQL operator in \"${args.param}\" on ${args.url} produced a database error. The parameter reaches a NoSQL query unsafely.`,
                tags: ["nosql-injection", "injection", "active", "owasp-a03"],
            });
            return "VULNERABLE: NoSQL error-based injection confirmed";
        }

        // Differential: `$ne` of an impossible value should widen the result set.
        let ne = http.send(#{ method: "GET", url: url_with(args.url, `${p}[$ne]=${url_encode(base)}aitmX`) });
        if ne.status != () && e.status != () {
            let d = ne.body.len() - b.body.len();
            let ad = if d < 0 { -d } else { d };
            let thresh = if b.body.len() / 10 > 80 { b.body.len() / 10 } else { 80 };
            if b.status == 200 && ad > thresh {
                finding(#{
                    name: "NoSQL injection (operator differential)",
                    severity: "high",
                    flow_id: ne.flow_id,
                    detail: `A $ne operator in \"${args.param}\" on ${args.url} changed the response size materially (${b.body.len()} -> ${ne.body.len()} bytes), indicating the operator altered the query.`,
                    tags: ["nosql-injection", "injection", "active", "owasp-a03"],
                });
                return "VULNERABLE: NoSQL operator injection confirmed";
            }
        }
        "no NoSQL injection confirmed"
    });
}
