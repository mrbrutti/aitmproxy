// check-command-injection.rhai — operator/agent command
// `check.cmdi { url, param, value? }`: confirm OS command injection using a
// marker whose *executed* form differs from its literal form, so a reflection
// cannot be mistaken for execution. OWASP A03 Injection.
//
// ACTIVE: scope-/rate-gated GETs, invoked only. The injected command is a benign
// `echo` of a random marker (no data access, no destructive action); detection
// is confirmed only when the shell-concatenated marker appears. Authorised only.
const NAME = "check-command-injection";
const API  = "1";

fn q(url, param, value) {
    let sep = if url.contains("?") { "&" } else { "?" };
    `${url}${sep}${url_encode(param)}=${url_encode(value)}`
}

fn load(reg) {
    reg.add_command("check.cmdi", "Confirm OS command injection in { url, param }", |args| {
        if type_of(args.url) != "string" || type_of(args.param) != "string" {
            return "usage: check.cmdi { url, param }";
        }
        let base = if type_of(args.value) == "string" { args.value } else { "1" };
        // Marker split so only shell execution reassembles it: literal reflection
        // shows "A$(echo B)C"; execution shows "ABC".
        let r1 = rand_text_alpha(3).to_upper();
        let r2 = rand_text_alpha(3).to_upper();
        let executed = `${r1}${r2}`;
        // Separators for *nix (;, |, &&, $()  ``) and a Windows &.
        let payloads = [
            `${base};echo ${r1}${r2}`,
            `${base}|echo ${r1}${r2}`,
            `${base}&&echo ${r1}${r2}`,
            `${base}$(echo ${r1})${r2}`,
            `${base}` + "`echo " + `${r1}` + "`" + `${r2}`,
            `${base}&echo ${r1}${r2}`,
        ];
        for pl in payloads {
            let r = http.send(#{ method: "GET", url: q(args.url, args.param, pl) });
            if r.status == () { continue; }
            // Confirm the executed concatenation is present AND the raw payload is not
            // (so a plain reflection of the payload does not false-positive).
            if r.body.contains(executed) && !r.body.contains(`echo ${r1}`) {
                finding(#{
                    name: "OS command injection",
                    severity: "critical",
                    flow_id: r.flow_id,
                    detail: `\"${args.param}\" on ${args.url} executed an injected shell command (echo marker reassembled as ${executed}). This is remote command execution.`,
                    tags: ["command-injection", "rce", "injection", "active", "owasp-a03"],
                });
                return "VULNERABLE: command injection confirmed";
            }
        }
        "no command injection confirmed"
    });
}
