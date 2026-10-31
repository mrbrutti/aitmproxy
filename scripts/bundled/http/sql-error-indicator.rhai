// sql-error-indicator.rhai — flag database error strings in responses, a strong
// passive signal of SQL injection exposure. OWASP A03:2021 Injection.
// Passive: observe-only, no traffic, no mutation. Authorised testing only.
const NAME = "sql-error-indicator";
const API  = "1";

fn on_response(flow) {
    let body = flow.response.body;
    if body == "" { return; }
    let pat = "(?i)(SQL syntax.*MySQL|valid MySQL result|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLSTATE\\[|SQLiteException|Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|System\\.Data\\.SqlClient\\.SqlException|psycopg2\\.|sqlalchemy\\.exc\\.)";
    if regex_match(pat, body) {
        flow.mark("sql-error");
        finding(#{
            name: "SQL error message in response",
            severity: "high",
            flow_id: flow.id,
            detail: `Response for ${flow.request.path} contains a database error string; the endpoint likely passes input into a query unsafely.`,
            tags: ["injection", "sqli", "owasp-a03"],
        });
    }
}
