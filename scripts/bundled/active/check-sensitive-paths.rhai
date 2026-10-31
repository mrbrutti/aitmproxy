// check-sensitive-paths.rhai — operator command `check.paths { base }`: probe a
// small fixed list of well-known sensitive paths under a base URL and report any
// that return content. OWASP A05 Misconfiguration / A01 Broken Access Control.
//
// ACTIVE: a handful of scope-/rate-gated GETs (the rate guard throttles them),
// operator-invoked only. The path list is small and read-only. For authorised
// testing only.
const NAME = "check-sensitive-paths";
const API  = "1";

const PATHS = ["/.git/HEAD", "/.env", "/server-status", "/actuator/health",
               "/.well-known/security.txt", "/phpinfo.php", "/web.config"];

fn load(reg) {
    reg.add_command("check.paths", "Probe { base } for well-known sensitive paths", |args| {
        if type_of(args.base) != "string" { return "usage: check.paths { base: \"https://host\" }"; }
        let base = args.base;
        if base.ends_with("/") { base = base.sub_string(0, base.len() - 1); }
        let hits = [];
        for p in PATHS {
            let url = `${base}${p}`;
            let resp = http.send(#{ method: "GET", url: url });
            if resp.status == 200 {
                hits.push(p);
                finding(#{
                    name: "Sensitive path reachable (active)",
                    severity: "medium",
                    flow_id: resp.flow_id,
                    detail: `${url} returned HTTP 200.`,
                    tags: ["information-disclosure", "active", "owasp-a05", "owasp-a01"],
                });
            }
        }
        `probed ${PATHS.len()} paths under ${base}: ${hits.len()} reachable`
    });
}
