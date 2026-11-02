// check-command-injection.rhai — catalogue check `cmdi`, class `cmdi`.
//
// The marker is split in two halves that only a shell rejoins. A server that
// echoes the request shows the literal command text; a server that runs it
// shows the halves joined and the command word gone. That asymmetry is the
// whole detection: a reflection cannot be mistaken for execution. The
// injected command is a benign echo of random letters.
//
// The shipped script's timing half is gone — native `cmdi-time` owns that
// technique, and a check never sleeps (spec D4). OWASP A03. CWE-78.
const NAME = "check-command-injection";
const API  = "1";

const META = #{
    id: "cmdi",
    name: "OS command injection",
    class: "cmdi",
    lanes: ["http"],
    kinds: ["query", "body_param", "json_value"],
    intensity: "medium",
    cost: "medium",
    technique: "reflected",
    severity: "critical",
    confidence_max: "certain",
    needs_baseline: false,
    cwe: 78,
    description: "Appends a benign split echo marker through the common shell separators and reports when the reply carries the marker reassembled.",
    remediation: "Call the program directly with an argument vector instead of a shell string, and allow-list the values that may reach it.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        let base = if type_of(point.example) == "string" { point.example } else { "1" };
        let first = rand_text_alpha(3).to_upper();
        let second = rand_text_alpha(3).to_upper();
        let executed = first + second;
        let literal = "echo " + first;
        // Separators for a POSIX shell (; | && $() backticks) and a Windows one.
        let payloads = [
            base + ";echo " + executed,
            base + "|echo " + executed,
            base + "&&echo " + executed,
            base + "$(echo " + first + ")" + second,
            base + "`echo " + first + "`" + second,
            base + "&echo " + executed,
        ];

        for payload in payloads {
            let reply = probe.send(payload);
            // Reassembled marker present AND the literal command absent.
            if reply.body.contains(executed) && !reply.body.contains(literal) {
                return #{
                    outcome: "vulnerable",
                    confidence: "certain",
                    evidence: #{ payload: payload, matched: executed },
                    detail: `"${point.name}" ran an injected shell command: the split echo marker came back joined as ${executed} with the command text gone. This is remote command execution.`,
                    poc_hint: #{
                        matchers: [ #{ type: "word", word: executed, part: "body" },
                                    #{ not: #{ type: "word", word: literal, part: "body" } } ],
                        control: #{
                            payload: base,
                            matchers: [ #{ not: #{ type: "word", word: executed, part: "body" } } ],
                        },
                    },
                };
            }
        }
        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: payloads[0], matched: () },
            detail: "No separator reassembled the echo marker, so nothing reached a shell.",
        }
    });
}
