// cors-misconfiguration.rhai — flag dangerous Access-Control-Allow-Origin values:
// a wildcard, or an origin reflected together with allow-credentials.
// OWASP A05:2021 Security Misconfiguration.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "cors-misconfiguration";
const API  = "1";

fn on_response(flow) {
    let acao = flow.response.headers.get("Access-Control-Allow-Origin");
    if acao == "" { return; }
    let creds = contains_ci(flow.response.headers.get("Access-Control-Allow-Credentials"), "true");
    let origin = flow.request.headers.get("Origin");

    if acao == "*" {
        flow.mark("cors-wildcard");
        finding(#{
            name: "CORS allows any origin",
            severity: "low",
            flow_id: flow.id,
            detail: `${flow.request.path} returns Access-Control-Allow-Origin: * .`,
            tags: ["cors", "owasp-a05"],
        });
    } else if origin != "" && acao == origin && creds {
        flow.mark("cors-reflected-credentials");
        finding(#{
            name: "CORS reflects Origin with credentials",
            severity: "high",
            flow_id: flow.id,
            detail: `${flow.request.path} reflects the request Origin (${origin}) in Access-Control-Allow-Origin while allowing credentials; any site can read authenticated responses.`,
            tags: ["cors", "owasp-a05", "owasp-a01"],
        });
    }
    if contains_ci(acao, "null") {
        flow.mark("cors-null-origin");
        finding(#{
            name: "CORS allows the null origin",
            severity: "medium",
            flow_id: flow.id,
            detail: `${flow.request.path} returns Access-Control-Allow-Origin: null; sandboxed iframes and some attacker contexts can pass this check.`,
            tags: ["cors", "owasp-a05"],
        });
    }
}
