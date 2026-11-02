// check-sensitive-paths.rhai — catalogue check `paths`, class `exposed-path`.
//
// A short, fixed list of well-known paths that should never answer on a
// deployed origin: a version-control directory, a dotfile of secrets, a status
// page, a management endpoint. Each is one plain read-only GET, and the list is
// exactly the shipped script's — the check invents no paths of its own.
//
// An origin-level audit (`scope: "origin"`): the paths hang off the origin, not
// off the point's own path. Every path that answered is its own verdict — the
// check returns an array, the bridge makes the first the root and the rest its
// `more` siblings, and each carries `location: #{ path }` so `/.git/HEAD` and
// `/.env` dedupe as two issues rather than one. OWASP A01 / A05. CWE-538.
const NAME = "check-sensitive-paths";
const API  = "1";

// The shipped list, unchanged: seven paths, no more.
const PATHS = ["/.git/HEAD", "/.env", "/server-status", "/actuator/health",
               "/.well-known/security.txt", "/phpinfo.php", "/web.config"];

const META = #{
    id: "paths",
    name: "Well-known sensitive path is reachable",
    class: "exposed-path",
    lanes: ["http"],
    kinds: ["query"],
    scope: "origin",
    intensity: "light",
    cost: "medium",
    technique: "observe",
    severity: "medium",
    confidence_max: "firm",
    needs_baseline: false,
    cwe: 538,
    description: "Requests a fixed list of seven well-known sensitive paths under the origin and reports every one that answers with HTTP 200.",
    remediation: "Stop serving version-control, configuration and management paths from the web root, and return 404 for them at the edge.",
};

// `https://host:port` from a URL: everything before the path's first slash.
fn origin_of(url) {
    let scheme_end = url.index_of("//");
    if scheme_end < 0 { return url; }
    let path_start = url.index_of("/", scheme_end + 2);
    if path_start < 0 { url } else { url.sub_string(0, path_start) }
}

fn load(reg) {
    reg.add_check(META, |point| {
        // `point.url` is `()` when the lane recorded no URL for this point, and
        // an origin-scoped audit has no origin to attribute an answer to.
        if type_of(point.url) != "string" {
            return #{
                outcome: "inconclusive",
                confidence: "tentative",
                detail: "This insertion point carries no URL, so there is no origin to audit.",
            };
        }

        let origin = origin_of(point.url);
        let verdicts = [];
        for path in PATHS {
            let url = origin + path;
            let reply = probe.raw(#{ method: "GET", url: url });
            if reply.status == 200 {
                // `matched` is what the path answered; the model bounds it at
                // 256 bytes, so the script hands it over whole.
                verdicts.push(#{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{ payload: "GET " + url, matched: reply.body },
                    detail: `${path} answered ${reply.status} on ${origin}; this well-known path should not be served.`,
                    location: #{ path: path },
                });
            }
        }

        if verdicts.len() > 0 { return verdicts; }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: "GET " + origin + PATHS[0], matched: () },
            detail: `None of the ${PATHS.len()} well-known sensitive paths answered on ${origin}.`,
        }
    });
}
