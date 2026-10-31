// verbose-error-disclosure.rhai — flag stack traces and framework error pages
// in response bodies (debug mode left on in production).
// OWASP A05:2021 Security Misconfiguration / A04 Insecure Design.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "verbose-error-disclosure";
const API  = "1";

fn on_response(flow) {
    let body = flow.response.body;
    if body == "" { return; }
    let signs = [
        "Traceback (most recent call last)",
        "at java.", "javax.servlet", "org.springframework",
        "System.Web.", "Microsoft .NET", "ASP.NET",
        "Warning: ", "Fatal error:", "Notice: ", "on line ",
        "Exception in thread", "panic:", "goroutine ",
        "ActiveRecord::", "NoMethodError",
    ];
    for s in signs {
        if body.contains(s) {
            flow.mark("verbose-error");
            finding(#{
                name: "Verbose error / stack trace in response",
                severity: "medium",
                flow_id: flow.id,
                detail: `Response for ${flow.request.path} contains a debug/stack-trace marker (\"${s}\"); disable debug output in production.`,
                tags: ["information-disclosure", "owasp-a05", "owasp-a04"],
            });
            return;
        }
    }
}
