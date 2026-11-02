// check-nosqli-json.rhai — catalogue check `nosqli-json`, class `nosqli`.
//
// The JSON sibling of `nosqli`, in the two shapes a JSON request has.
//
// **One JSON value** (`json_value`): a value slot can hold an object as easily
// as a string, so the operator goes in whole — the point's string value is
// replaced by a one-key operator document. A store that compares the document
// instead of the string answers with a different result set, and that size
// difference against the point's own baseline is the finding.
//
// **The whole JSON body** (`entire_body`): the document-level shape (spec
// amendment 65). Here the point *is* the document, so the check rebuilds it
// from the point's example, puts a one-key operator document into each string
// field in turn, and — only where an operator moved the answer — sends a
// string control at the same field. An answer that flips to 2xx (or widens
// materially) for the operator while the baseline and the control do not is a
// comparison the store ran on the document rather than on a string. The
// example is the body the lane captured, scrubbed, so a secret field is probed
// as `[redacted]`; a document the example does not hold whole is
// `inconclusive`, never a guess.
//
// Read-only: both operators only widen a comparison, neither writes. New in
// the v2 catalogue (spec D8.2) — the shipped scripts had no JSON-body check.
//
// OWASP A03 Injection. CWE-943.
const NAME = "check-nosqli-json";
const API  = "1";

// How many of a document's string fields one pass visits, in the document's
// own key order. Two operators and at most one control go to each, so this is
// what the check may cost a job on a wide body.
const MAX_FIELDS = 8;

const META = #{
    id: "nosqli-json",
    name: "NoSQL operator injection (JSON body)",
    class: "nosqli",
    lanes: ["http"],
    kinds: ["json_value", "entire_body"],
    intensity: "medium",
    cost: "light",
    technique: "boolean",
    severity: "critical",
    confidence_max: "firm",
    needs_baseline: true,
    wants_traits: ["json"],
    cwe: 943,
    description: "Replaces a JSON string value — or each string field of a whole JSON body — with a one-key query-operator document, and reports an answer that changes against the baseline while a string control at the same field does not.",
    remediation: "Validate the JSON body against a schema that says every one of these fields is a string, and reject an object in a value position before the query is built.",
};

fn load(reg) {
    reg.add_check(META, |point| {
        if point.kind == "entire_body" {
            return document_verdict(point);
        }
        value_verdict(point)
    });
}

// --- the value shape ---------------------------------------------------

// `json_value`: the point addresses one value, and the host swaps the operator
// document in for it.
fn value_verdict(point) {
    let baseline = probe.baseline();
    // "not equal to nothing" and "greater than the empty string": both match
    // every document the honest comparison narrowed away.
    let operators = [`{"$ne": null}`, `{"$gt": ""}`];
    let threshold = size_threshold(baseline);

    for operator in operators {
        let widened = probe.send(#{ value: operator, mode: "replace" });
        let delta = size_delta(baseline, widened);

        if baseline.status == 200 && widened.status == 200 && delta > threshold {
            return #{
                outcome: "vulnerable",
                confidence: "firm",
                evidence: #{
                    payload: operator,
                    matched: `result set ${baseline.body.len()} -> ${widened.body.len()} bytes`,
                },
                detail: `"${point.name}" accepted a query operator in place of its JSON string value and the result set changed materially (${baseline.body.len()} -> ${widened.body.len()} bytes).`,
            };
        }
    }

    #{
        outcome: "clean",
        confidence: "firm",
        evidence: #{ payload: operators[0], matched: () },
        detail: "A query operator in this JSON value did not change the result set.",
    }
}

// --- the document shape ------------------------------------------------

// `entire_body`: the point is the whole JSON body, so the check owns the
// document and decides where the operator goes.
fn document_verdict(point) {
    // A cut example, a body that is not an object, a point with no example at
    // all: the document-level operator has no document to sit in, and a probe
    // built from half a body would be a guess.
    if !is_whole_json_object(point.example) {
        return not_a_document();
    }
    let body = point.example;
    body.trim();
    let doc = parse_json(body);
    if type_of(doc) != "map" {
        return not_a_document();
    }

    let baseline = probe.baseline();
    let threshold = size_threshold(baseline);
    let operators = [#{ "$ne": () }, #{ "$gt": "" }];
    // The control: the same field holding a plain string, carrying the job's
    // own marker so no stored record can match it. It separates "the store
    // compared the document" from "any value it has not seen answers this way".
    let control_value = "aitm" + probe.marker();

    // Only a string field is a field a schema declared a string, and only
    // there is an object an operator rather than a shape the route expects.
    let fields = [];
    for key in doc.keys() {
        if fields.len() >= MAX_FIELDS {
            break;
        }
        if type_of(doc[key]) == "string" {
            fields.push(key);
        }
    }

    let last_document = ();

    for field in fields {
        let original = doc[field];

        for operator in operators {
            if probe.budget_left() < 1 {
                doc[field] = original;
                return out_of_budget(last_document);
            }
            doc[field] = operator;
            let document = doc.to_json();
            last_document = document;
            let widened = probe.send(document);

            let flipped = is_2xx(widened.status) && !is_2xx(baseline.status);
            let grew = size_delta(baseline, widened) > threshold;
            if !flipped && !grew {
                continue;
            }

            // Something moved: spend one probe on the control before calling
            // it a finding.
            if probe.budget_left() < 1 {
                doc[field] = original;
                return out_of_budget(document);
            }
            doc[field] = control_value;
            let control = probe.send(doc.to_json());

            if flipped && !is_2xx(control.status) {
                doc[field] = original;
                return #{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{
                        payload: document,
                        matched: `status ${baseline.status} -> ${widened.status} with an operator at "${field}"; the string control answered ${control.status}`,
                    },
                    location: #{ name: field },
                    detail: `The JSON body's "${field}" took a query-operator document where a string was declared: the store answered ${widened.status} to the operator and ${control.status} to a plain string at the same field, against a baseline of ${baseline.status}. An operator in a value position makes the comparison match records the honest one narrowed away.`,
                };
            }

            if grew && size_delta(baseline, control) <= threshold {
                doc[field] = original;
                return #{
                    outcome: "vulnerable",
                    confidence: "firm",
                    evidence: #{
                        payload: document,
                        matched: `result set ${baseline.body.len()} -> ${widened.body.len()} bytes with an operator at "${field}"; the string control answered ${control.body.len()} bytes`,
                    },
                    location: #{ name: field },
                    detail: `The JSON body's "${field}" took a query-operator document where a string was declared and the result set changed materially (${baseline.body.len()} -> ${widened.body.len()} bytes), while a plain string at the same field left it at ${control.body.len()} bytes.`,
                };
            }

            // The control moved too: whatever changed, it was not the
            // operator. Put the field back and try the next one.
            doc[field] = original;
        }

        doc[field] = original;
    }

    #{
        outcome: "clean",
        confidence: "firm",
        evidence: #{ payload: last_document, matched: () },
        detail: "A query-operator document at any string field of this JSON body did not change the answer.",
    }
}

// Whether `text` is a *whole* JSON object, decided without parsing it.
//
// The engine's `parse_json` answers malformed text with a Rhai **parse**
// error, and a parse error is not catchable by `try`/`catch`, so a document
// has to be judged before it is handed over. The case this is here for is the
// cut example: the lane shows a point's value up to a cap, and what is cut
// ends inside a string or with a brace still open. So does a body whose
// scrub took the `{` of a nested secret-named object. A text that passes here
// and still does not parse (complete but invalid) ends the check as an
// `error` verdict, which the engine records like any other failed check.
fn is_whole_json_object(text) {
    if type_of(text) != "string" {
        return false;
    }
    // `trim` is a mutating method in Rhai: it edits the copy and answers `()`.
    let doc = text;
    doc.trim();
    if !doc.starts_with("{") || !doc.ends_with("}") {
        return false;
    }

    let depth = 0;
    let in_string = false;
    let escaped = false;
    for ch in doc {
        if escaped {
            escaped = false;
        } else if in_string {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
        } else if ch == '{' || ch == '[' {
            depth += 1;
        } else if ch == '}' || ch == ']' {
            depth -= 1;
            if depth < 0 {
                return false;
            }
        }
    }
    !in_string && depth == 0
}

// The verdict for a point whose example is not the document it came from.
fn not_a_document() {
    #{
        outcome: "inconclusive",
        confidence: "tentative",
        evidence: #{ payload: (), matched: () },
        detail: "the JSON document is longer than the point's example; document-level operators need the whole body",
    }
}

// --- shared --------------------------------------------------------------

// How many bytes a reply must differ from the baseline by before the
// difference is a result set rather than a timestamp: a tenth of the baseline,
// and never less than 80.
fn size_threshold(baseline) {
    if baseline.body.len() / 10 > 80 { baseline.body.len() / 10 } else { 80 }
}

// The absolute size difference between a reply and the baseline.
fn size_delta(baseline, reply) {
    let delta = reply.body.len() - baseline.body.len();
    if delta < 0 { -delta } else { delta }
}

// Whether a reply's status says the request succeeded. A probe that never got
// a status answers `()`, which is not a success.
fn is_2xx(status) {
    type_of(status) == "i64" && status >= 200 && status < 300
}

// The verdict for a document the budget ran out under: what was tried is not
// a clean bill of health for the fields that were not.
fn out_of_budget(document) {
    #{
        outcome: "inconclusive",
        confidence: "tentative",
        evidence: #{ payload: document, matched: () },
        detail: "the probe budget ran out before every string field of this JSON body had been tried",
    }
}
