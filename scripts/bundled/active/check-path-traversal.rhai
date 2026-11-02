// check-path-traversal.rhai — check `path_traversal`, class `path-traversal`.
//
// Where a value becomes part of a filesystem path, enough parent-directory
// steps walk out of the document root. The probe asks for one of two files
// every system has and nobody minds showing — the POSIX account list and the
// Windows ini — and matches their signature. Nothing else is read, which is
// what keeps a traversal proof benign.
//
// `wants_traits: ["filename"]` keeps the check off values that never look
// like a path, unless the profile asks for `speed: thorough` (spec D4).
// OWASP A01 Broken Access Control / A03 Injection. CWE-22.
const NAME = "check-path-traversal";
const API  = "1";

const NIX_SIG = "root:.*:0:0:";
const WIN_SIG = "(?i)\\[(fonts|extensions|mci extensions)\\]";

const META = #{
    id: "path_traversal",
    name: "Path traversal / local file inclusion",
    class: "path-traversal",
    lanes: ["http"],
    kinds: ["query", "body_param", "json_value", "path_filename", "multipart_filename"],
    intensity: "medium",
    cost: "medium",
    technique: "reflected",
    severity: "critical",
    confidence_max: "firm",
    needs_baseline: false,
    wants_traits: ["filename"],
    cwe: 22,
    description: "Walks out of the document root with the usual traversal encodings and reports when a well-known system file comes back.",
    remediation: "Resolve the path and verify it stays inside the intended directory; prefer an opaque id over a caller-supplied name.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let base = if type_of(point.example) == "string" { point.example } else { "index.html" };
        // Plain, percent-encoded, doubled-up, absolute, and the Windows pair.
        let payloads = [
            "../../../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//....//etc/passwd",
            "/etc/passwd",
            "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "../../../../../../windows/win.ini",
        ];

        for payload in payloads {
            let reply = probe.send(payload);
            let signature = if regex_match(NIX_SIG, reply.body) { NIX_SIG }
                else if regex_match(WIN_SIG, reply.body) { WIN_SIG } else { () };
            if signature != () {
                return #{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{ payload: payload, matched: "system file signature" },
                    detail: `"${point.name}" returned the contents of a system file for traversal payload ${payload}.`,
                    poc_hint: #{
                        matchers: [ #{ type: "regex", regex: signature, part: "body" } ],
                        control: #{
                            payload: base,
                            matchers: [ #{ not: #{ type: "regex", regex: signature, part: "body" } } ],
                        },
                    },
                };
            }
        }
        #{
            outcome: "clean", confidence: "firm",
            evidence: #{ payload: payloads[0], matched: () },
            detail: "No traversal encoding reached a file outside the document root.",
        }
    });
}
