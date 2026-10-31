// sensitive-path-exposed.rhai — flag a successful response to a well-known
// sensitive path (VCS metadata, dotfiles, admin/debug endpoints).
// OWASP A05:2021 Misconfiguration / A01 Broken Access Control.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "sensitive-path-exposed";
const API  = "1";

fn on_response(flow) {
    let s = flow.response.status;
    if s != 200 && s != 206 && s != 401 && s != 403 { return; }
    let p = flow.request.path.to_lower();
    let hits = ["/.git/", "/.svn/", "/.env", "/.htaccess", "/.aws/credentials",
                "/wp-config.php", "/config.php.bak", "/phpinfo.php", "/server-status",
                "/actuator", "/.ds_store", "/web.config", "/id_rsa", "/.npmrc"];
    for h in hits {
        if p.contains(h) {
            let sev = if s == 200 || s == 206 { "high" } else { "info" };
            flow.mark("sensitive-path");
            finding(#{
                name: "Sensitive path reachable",
                severity: sev,
                flow_id: flow.id,
                detail: `${flow.request.path} (HTTP ${s}) exposes a sensitive path pattern (\"${h}\").`,
                tags: ["information-disclosure", "owasp-a05", "owasp-a01"],
            });
            return;
        }
    }
}
