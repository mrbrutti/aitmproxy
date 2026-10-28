// broken.rhai — does not compile: the call on line 5 is missing its closing
// parenthesis. The loader must skip it (or fail fast under `strict`) and name
// this file, line and column.
fn on_request(flow) {
    flow.request.headers.set("X-Aitm", "1";
}
