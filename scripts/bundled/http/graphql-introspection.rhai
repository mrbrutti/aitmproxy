// graphql-introspection.rhai — flag a GraphQL endpoint that returns schema
// introspection data. OWASP A05:2021 Security Misconfiguration.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "graphql-introspection";
const API  = "1";

fn on_response(flow) {
    let p = flow.request.path.to_lower();
    if !p.contains("graphql") && !p.contains("/gql") { return; }
    let body = flow.response.body;
    if body.contains("__schema") && body.contains("queryType") {
        flow.mark("graphql-introspection");
        finding(#{
            name: "GraphQL introspection enabled",
            severity: "low",
            flow_id: flow.id,
            detail: `${flow.request.path} returns GraphQL introspection data, revealing the full API schema.`,
            tags: ["graphql", "information-disclosure", "owasp-a05"],
        });
    }
}
