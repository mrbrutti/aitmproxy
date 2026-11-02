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
// as `[redacted]`; a document the example does not hold whole — cut, or with a
// secret the scrub left unquoted — is `inconclusive`, never a guess, and so is
// a document with no string field to put an operator in.
//
// Read-only: both operators only widen a comparison, neither writes. New in
// the v2 catalogue (spec D8.2) — the shipped scripts had no JSON-body check.
//
// OWASP A03 Injection. CWE-943.
const NAME = "check-nosqli-json";
const API  = "1";

// How many of a document's string fields one pass visits: the first eight
// string fields by key, in sorted key order (a Rhai map is a `BTreeMap`, so it
// keeps no document order). Two operators and at most one control go to each,
// so this is what the check may cost a job on a wide body.
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
    // A point with no example at all has no document to own.
    if type_of(point.example) != "string" {
        return not_a_document();
    }
    // `trim` is a mutating method in Rhai: it edits the copy and answers `()`.
    let body = point.example;
    body.trim();
    // One pass over the text, read by both guards below. Neither parses: the
    // engine's `parse_json` answers malformed text with a Rhai *parse* error,
    // and a parse error is not catchable by `try`/`catch`, so a document has
    // to be judged before it is handed over.
    let reading = outside_quoted_strings(body);

    // A whole body the lane's scrub already broke: a secret-named field whose
    // value was not a quoted string loses the quotes with the value, so the
    // mask stands bare where the value was. Asked first, because the scrub of
    // a nested secret-named object takes that object's `{` with the value and
    // leaves a body that does not balance either — and the reason it does not
    // balance is the scrub, not a cut.
    if holds_a_bare_mask(reading) {
        return masked_before_the_check();
    }
    // A cut example, or a body that is not one JSON object: the document-level
    // operator has no document to sit in, and a probe built from half a body
    // would be a guess.
    if !is_whole_json_object(body, reading) {
        return not_a_document();
    }
    let doc = parse_json(body);
    // Belt: after the guards above, `parse_json` can only answer a map or die,
    // and this arm cannot run. It is kept for the day the bridge gives the
    // script a real JSON parser, which could answer anything.
    if type_of(doc) != "map" {
        return not_a_document();
    }

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

    // Every field a number, a boolean or null: there is no slot a schema
    // declared a string, so there is nowhere an operator document would be an
    // operator rather than the shape the route expects. Answered before the
    // baseline below, which is a real request: a document the check has
    // nowhere to probe costs the job nothing at all.
    if fields.is_empty() {
        return no_string_field();
    }

    let baseline = probe.baseline();
    let threshold = size_threshold(baseline);
    let operators = [#{ "$ne": () }, #{ "$gt": "" }];
    // The control: the same field holding a plain string, carrying the job's
    // own marker so no stored record can match it. It separates "the store
    // compared the document" from "any value it has not seen answers this way".
    let control_value = "aitm" + probe.marker();

    let last_document = ();

    for field in fields {
        let original = doc[field];

        for operator in operators {
            if probe.budget_left() < 1 {
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
                return out_of_budget(document);
            }
            doc[field] = control_value;
            let control = probe.send(doc.to_json());

            if flipped && !is_2xx(control.status) {
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

// --- reading a document without parsing it -------------------------------

// Everything in `text` that stands *outside* a quoted string, in order, and
// whether every string the text opened was closed again.
//
// One pass serves both guards below, so there is one place where a string
// ends: the structure a document is judged on is exactly the part a quoted
// string must not be read as, and a mask standing in the outside text is a
// mask that replaced a value rather than one inside a string.
fn outside_quoted_strings(text) {
    let outside = "";
    let in_string = false;
    let escaped = false;
    for ch in text {
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
        } else {
            outside += ch;
        }
    }
    #{ outside: outside, closed: !in_string }
}

// Whether `body` is a *whole* JSON object, read off `reading` without parsing.
//
// The case this is here for is the cut example: the lane shows a point's value
// up to a cap, and what is cut ends inside a string or with a brace still
// open. Completeness is only half the question — a complete body can still be
// invalid, which `holds_a_bare_mask` answers for the one shape that reaches
// the check that way.
fn is_whole_json_object(body, reading) {
    if !body.starts_with("{") || !body.ends_with("}") || !reading.closed {
        return false;
    }
    let depth = 0;
    for ch in reading.outside {
        if ch == '{' || ch == '[' {
            depth += 1;
        } else if ch == '}' || ch == ']' {
            depth -= 1;
            if depth < 0 {
                return false;
            }
        }
    }
    depth == 0
}

// Whether the scrub's mask token stands where a value should be.
//
// The lane scrubs an example before the check sees it, and a secret-named
// field whose value is *not* a quoted string — a number, an object, `true`,
// `null` — has the whole value run replaced, mask and all:
// `{"user":"a","api_key":12345}` arrives as `{"user":"a","api_key":[redacted]}`
// and `{"user":"a","auth":{"token":"t"}}` as
// `{"user":"a","auth":[redacted]"token":"[redacted]"}}`. The first balances, so
// completeness cannot catch it; the second does not, so completeness would
// blame a cut. The bare mask names the real reason for both. A mask *inside* a
// quoted string (`"password":"[redacted]"`) is an ordinary string value and is
// probed like any other.
//
// The token is the one `aitm_core::redact::MASK` writes. Nothing in Rhai can
// read that constant, so two Rust tests pin the spelling instead: the
// scrubber-built examples in `crates/aitm-scan-checks-http/tests/rhai_new_scripts.rs`
// and `crates/aitm/tests/rhai_nosqli_production_parser.rs`.
fn holds_a_bare_mask(reading) {
    reading.outside.contains("[redacted]")
}

// --- the document branch's verdicts --------------------------------------

// What every `inconclusive` below is: nothing was proved, nothing is claimed,
// and the detail says only why the check stopped.
fn inconclusive(detail, payload) {
    #{
        outcome: "inconclusive",
        confidence: "tentative",
        evidence: #{ payload: payload, matched: () },
        detail: detail,
    }
}

// The verdict for an example the scrub broke before the check saw it. Said
// apart from the cut case: the body was whole, a secret in it was not.
fn masked_before_the_check() {
    inconclusive("a secret in this JSON body was masked before the check saw it; document-level operators need the whole body", ())
}

// The verdict for a document with no string field. Nothing was tried, so
// nothing is clean: `clean` is for operators that were sent and did not move
// the answer.
fn no_string_field() {
    inconclusive("this JSON body has no string field to place an operator document at", ())
}

// The verdict for a point whose example is not the document it came from.
fn not_a_document() {
    inconclusive("the JSON document is longer than the point's example; document-level operators need the whole body", ())
}

// The verdict for a document the budget ran out under: what was tried is not
// a clean bill of health for the fields that were not.
fn out_of_budget(document) {
    inconclusive("the probe budget ran out before every string field of this JSON body had been tried", document)
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
