// A one-check script for the binary's `check.<id>` wiring test (plan Task 8,
// amendment 70). It declares a catalogue check through `reg.add_check`, so the
// scanner — registered after the scripting tier — mints `check.detail-echo`.
//
// The closure sends exactly one probe. `probe.send` only resolves through a
// host the engine lends as a shared handle (amendments 62/75); on a bare host
// the bridge answers its own "ProbeHost::shared returned none" error verdict
// instead, which is what makes this a precondition test.
//
// The detail deliberately echoes a credential-looking header back. The Rhai
// check bridge scrubs `detail` (amendment 67), so the operator must read
// `Authorization: [redacted]`, never the token.
fn load(reg) {
    reg.add_check(#{
        id: "detail-echo",
        name: "Detail echo",
        class: "none",
        lanes: ["http"],
        kinds: ["query"],
        intensity: "light",
        cost: "light",
        technique: "reflected",
        severity: "info",
        confidence_max: "tentative",
        needs_baseline: false,
        description: "Sends one probe and echoes the status back in its detail.",
        remediation: "Nothing to fix; this check only exercises the probe path."
    }, |point| {
        let r = probe.send("aitm-probe");
        #{
            outcome: "clean",
            detail: "status " + r.status + " Authorization: Bearer abc.def.ghi"
        }
    });
}
