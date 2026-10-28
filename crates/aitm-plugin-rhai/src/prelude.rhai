// aitmproxy bundled prelude — API 1.
//
// Thin sugar every script and PoC step can call without importing anything.
// Plain Rhai, compiled once under the sandboxed engine. Keep it small: a
// helper belongs here only when it makes a common check read as one word.

// `ok(resp)` — true for a 2xx response (an http.send result or flow.response).
fn ok(resp) {
    resp.status >= 200 && resp.status < 300
}

// `contains_ci(hay, needle)` — case-insensitive substring check.
fn contains_ci(hay, needle) {
    hay.to_lower().contains(needle.to_lower())
}

// `json(map)` — the JSON text of an object map, e.g. for a request body.
fn json(m) {
    m.to_json()
}
