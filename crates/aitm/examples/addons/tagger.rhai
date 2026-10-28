// addons/tagger.rhai — add a header to every request, flag 5xx responses,
// and expose a liveness command. Nothing here is required but the hooks you want.
const NAME = "tagger";
const API  = "1";

fn load(reg) {
    reg.add_option("tag", "seen-by-aitm", "value for the X-Aitm header");
    reg.add_command("tagger.ping", "liveness check", |args| "pong");
}

fn on_request(flow) {
    flow.request.headers.set("X-Aitm", option("tag"));
}

fn on_response(flow) {
    if flow.response.status >= 500 {
        flow.mark("server-error");
        log.warn(`5xx on ${flow.request.path}`);   // JS-style template literal
    }
}
