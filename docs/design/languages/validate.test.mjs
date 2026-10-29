// Self-validation for the shared language-definition files and their
// conformance fixtures. No dependencies: `node --test docs/design/languages/validate.test.mjs`.
//
// The three operator UIs (web / TUI / macOS) generate their highlighters,
// completion sources, filter parsers and flow-kind renderers from the JSON
// files next to this one. This test pins the shapes they rely on and proves
// the fixtures are internally consistent, so a surface can trust a fixture
// failure to mean *its* implementation drifted, not the fixture.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const FILES = [
  "rhai.grammar.json",
  "rhai.api.json",
  "poc-yaml.schema.json",
  "filter.grammar.json",
  "flow-kinds.json",
  "filter.conformance.json",
  "rhai.completion.conformance.json",
  "poc.completion.conformance.json",
];

const load = (name) => JSON.parse(readFileSync(join(here, name), "utf8"));
const set = (xs) => [...xs].sort();

// The foundation's syntax tokens (tokens.json) plus the additive comment /
// keyword / text tokens the UI spec adds (spec §1.1 `map_token`).
const SYNTAX_TOKENS = ["key", "string", "number", "boolean", "punct", "comment", "keyword", "text"];

// ---------------------------------------------------------------------------
// every file parses
// ---------------------------------------------------------------------------

for (const f of FILES) {
  test(`${f} parses as JSON`, () => {
    assert.doesNotThrow(() => load(f));
  });
}

// ---------------------------------------------------------------------------
// rhai.grammar.json
// ---------------------------------------------------------------------------

test("rhai.grammar.json: shape + map_token targets", () => {
  const g = load("rhai.grammar.json");
  for (const k of ["keywords", "operators", "punctuation"]) {
    assert.ok(Array.isArray(g[k]) && g[k].length > 0, `${k}[] present`);
  }
  for (const k of ["comment", "string", "number", "identifier"]) {
    assert.ok(g.lexical?.[k], `lexical.${k} present`);
  }
  for (const w of "fn let const if else while loop for in return break continue switch".split(" ")) {
    assert.ok(g.keywords.includes(w), `keyword ${w}`);
  }
  assert.deepEqual(set(g.literals), ["()", "false", "true"]);
  assert.ok(g.map_token && Object.keys(g.map_token).length > 0, "map_token present");
  for (const [cls, tok] of Object.entries(g.map_token)) {
    assert.ok(SYNTAX_TOKENS.includes(tok), `map_token.${cls} -> ${tok} is a syntax token`);
  }
  // Spec §1.1: keywords -> keyword, identifiers -> text.
  assert.equal(g.map_token.keyword, "keyword");
  assert.equal(g.map_token.identifier, "text");
});

// ---------------------------------------------------------------------------
// rhai.api.json — must mirror the plugin-system spec catalog exactly
// ---------------------------------------------------------------------------

const API_SECTIONS = ["hooks", "flow", "msg", "globals", "dsl", "reg", "vars", "denied"];
const HOOKS = [
  "configure",
  "load",
  "on_error",
  "on_request",
  "on_request_headers",
  "on_response",
  "on_response_headers",
  "on_ws_end",
  "on_ws_message",
  "on_ws_start",
];
const GLOBALS = [
  "browser.click",
  "browser.evaluate",
  "browser.get_dom",
  "browser.navigate",
  "browser.screenshot",
  "browser.type_text",
  "contains_ci",
  "finding",
  "halt",
  "http.send",
  "json",
  "log",
  "log.error",
  "log.info",
  "log.warn",
  "ok",
  "option",
  "scope.add",
  "scope.list",
  "store.get",
  "store.query",
];
const DSL = [
  "b64_decode",
  "b64_encode",
  "hex_encode",
  "md5",
  "rand_int",
  "rand_text_alpha",
  "regex_extract",
  "regex_match",
  "sha256",
  "url_encode",
];
const MSG = ["msg.data", "msg.direction", "msg.drop", "msg.opcode", "msg.set_bytes", "msg.set_text", "msg.text"];
const FLOW_TOP = [
  "flow.backup",
  "flow.comment",
  "flow.id",
  "flow.intercept",
  "flow.is_replay",
  "flow.kind",
  "flow.kill",
  "flow.mark",
  "flow.marks",
  "flow.request",
  "flow.response",
  "flow.resume",
  "flow.revert",
  "flow.set_response",
];

function apiNames(api) {
  const out = [];
  for (const s of API_SECTIONS) for (const e of api[s]) out.push(e.name);
  return out;
}

test("rhai.api.json: shape", () => {
  const api = load("rhai.api.json");
  assert.equal(api.api_version, "1");
  for (const s of API_SECTIONS) {
    assert.ok(Array.isArray(api[s]) && api[s].length > 0, `${s}[] present`);
    for (const e of api[s]) {
      assert.equal(typeof e.name, "string", `${s} entry has a name`);
      assert.ok(e.description?.length > 0, `${e.name} has a description`);
      if ("signature" in e) assert.ok(e.signature.length > 0, `${e.name} signature non-empty`);
    }
  }
  const names = apiNames(api);
  assert.equal(new Set(names).size, names.length, "entry names are unique across the catalog");
});

test("rhai.api.json: hooks are exactly the plugin-system hook table", () => {
  const api = load("rhai.api.json");
  assert.deepEqual(set(api.hooks.map((h) => h.name)), HOOKS);
  for (const h of api.hooks) {
    assert.ok(h.signature.startsWith(`${h.name}(`), `${h.name} signature`);
    assert.ok(h.snippet?.includes(`fn ${h.name}(`), `${h.name} has a top-level snippet`);
  }
});

test("rhai.api.json: globals / dsl / msg / flow mirror the plugin-system catalog", () => {
  const api = load("rhai.api.json");
  assert.deepEqual(set(api.globals.map((e) => e.name)), GLOBALS);
  assert.deepEqual(set(api.dsl.map((e) => e.name)), DSL);
  assert.deepEqual(set(api.msg.map((e) => e.name)), MSG);
  const flowTop = api.flow.filter((e) => e.name.split(".").length === 2).map((e) => e.name);
  assert.deepEqual(set(flowTop), set(FLOW_TOP));
  for (const e of api.flow) assert.ok(e.name.startsWith("flow."), `${e.name} under flow.`);
  for (const e of api.msg) assert.ok(e.name.startsWith("msg."), `${e.name} under msg.`);
});

test("rhai.api.json: every dotted member's parent object is catalogued", () => {
  const api = load("rhai.api.json");
  const names = new Set(apiNames(api));
  // namespaces: objects the engine injects that have members but are not themselves callable
  for (const ns of ["flow", "msg", "http", "browser", "store", "scope", "reg", "vars", "denied"]) names.add(ns);
  for (const n of names) {
    const parts = n.split(".");
    if (parts.length > 1) {
      const parent = parts.slice(0, -1).join(".");
      assert.ok(names.has(parent), `${n}: parent ${parent} is catalogued`);
    }
  }
});

// ---------------------------------------------------------------------------
// poc-yaml.schema.json
// ---------------------------------------------------------------------------

/** Resolve a `$ref` of the form `#/$defs/<name>`. */
function deref(schema, node) {
  while (node?.$ref) {
    const m = /^#\/\$defs\/(.+)$/.exec(node.$ref);
    assert.ok(m && schema.$defs?.[m[1]], `resolvable $ref ${node.$ref}`);
    node = schema.$defs[m[1]];
  }
  return node;
}

/** Walk `info.severity` / `steps[].http.matchers[]` style paths. "" is the root. */
function schemaNode(schema, path) {
  let node = deref(schema, schema);
  if (path === "") return node;
  for (const seg of path.split(".")) {
    const m = /^([^[\]]+)((?:\[\])*)$/.exec(seg);
    assert.ok(m, `path segment ${seg}`);
    node = deref(schema, node.keys?.[m[1]]);
    assert.ok(node, `schema path ${path}: no key ${m[1]}`);
    for (let i = 0; i < m[2].length / 2; i++) {
      node = deref(schema, node.items);
      assert.ok(node, `schema path ${path}: ${m[1]} has no items`);
    }
  }
  return node;
}

function* schemaNodes(schema, node = schema, path = "$") {
  yield [path, node];
  const n = deref(schema, node);
  for (const [k, v] of Object.entries(n.keys ?? {})) yield* schemaNodes(schema, v, `${path}.${k}`);
  if (n.items) yield* schemaNodes(schema, n.items, `${path}[]`);
}

test("poc-yaml.schema.json: top level + step shapes", () => {
  const s = load("poc-yaml.schema.json");
  assert.deepEqual(set(Object.keys(s.keys)), ["id", "info", "steps", "success", "variables"]);
  for (const k of ["id", "info", "steps", "success"]) assert.equal(s.keys[k].required, true, `${k} required`);
  assert.deepEqual(set(Object.keys(schemaNode(s, "info").keys)), [
    "author",
    "cwe",
    "description",
    "metadata",
    "name",
    "reference",
    "severity",
    "tags",
  ]);
  assert.deepEqual(set(Object.keys(schemaNode(s, "variables[]").keys)), ["default", "description", "name", "required"]);
  const step = schemaNode(s, "steps[]");
  assert.deepEqual(set(Object.keys(step.keys)), ["browser", "extract", "http", "script"]);
  assert.deepEqual(set(step.one_of_keys), ["browser", "extract", "http", "script"]);
  assert.deepEqual(set(Object.keys(schemaNode(s, "steps[].http").keys)), [
    "body",
    "extract",
    "headers",
    "matchers",
    "matchers-condition",
    "method",
    "path",
    "raw",
    "url",
  ]);
  assert.deepEqual(set(Object.keys(schemaNode(s, "steps[].script").keys)), ["name", "script"]);
});

test("poc-yaml.schema.json: enums match the PoC spec", () => {
  const s = load("poc-yaml.schema.json");
  const en = (p) => set(schemaNode(s, p).enum);
  assert.deepEqual(en("info.severity"), ["critical", "high", "info", "low", "medium"]);
  assert.deepEqual(en("steps[].browser.action"), ["click", "eval", "navigate", "screenshot", "type"]);
  assert.deepEqual(en("steps[].http.matchers-condition"), ["and", "or"]);
  assert.deepEqual(en("steps[].http.matchers[].type"), ["binary", "browser-eval", "dsl", "regex", "size", "status", "word"]);
  assert.deepEqual(en("steps[].http.matchers[].part"), ["all", "body", "header"]);
  assert.deepEqual(en("steps[].http.matchers[].condition"), ["and", "or"]);
  assert.deepEqual(en("steps[].http.extract[].type"), ["browser-eval", "dsl", "json", "kval", "regex"]);
  assert.deepEqual(en("steps[].http.extract[].from"), ["all", "body", "header"]);
  assert.deepEqual(set(Object.keys(schemaNode(s, "success").keys)), ["all", "any", "not"]);
});

test("poc-yaml.schema.json: every node is described; enums are non-empty strings", () => {
  const s = load("poc-yaml.schema.json");
  let count = 0;
  for (const [path, node] of schemaNodes(s)) {
    if (path === "$") continue;
    count++;
    const n = deref(s, node);
    assert.ok(n.description?.length > 0, `${path} has a description`);
    if (n.enum) {
      assert.ok(n.enum.length > 0 && n.enum.every((v) => typeof v === "string"), `${path} enum`);
    }
  }
  assert.ok(count > 30, "walked a non-trivial tree");
});

// ---------------------------------------------------------------------------
// filter.grammar.json
// ---------------------------------------------------------------------------

const ALL_ATOMS = [
  "~u", "~d", "~m", "~s", "~h", "~b", "~q", "~c", "~t", "~a", "~scope", "~ws", "~paused", "~killed",
  "~l4", "~tcp", "~udp", "~icmp",
];

test("filter.grammar.json: atoms, combinators, stacked model", () => {
  const g = load("filter.grammar.json");
  assert.deepEqual(set(g.atoms.map((a) => a.atom)), set(ALL_ATOMS));
  for (const a of g.atoms) {
    assert.ok(["pattern", "literal", "none"].includes(a.args), `${a.atom} args kind`);
    assert.ok(a.description?.length > 0, `${a.atom} description`);
    if (a.alias_of) assert.ok(g.atoms.some((x) => x.atom === a.alias_of && !x.alias_of), `${a.atom} alias target`);
  }
  assert.equal(g.atoms.find((a) => a.atom === "~t").alias_of, "~c");
  assert.deepEqual(set(g.combinators.map((c) => c.symbol)), set(["&", "|", "!", "(", ")"]));
  assert.equal(g.bare_word, "~u");
  assert.ok(Array.isArray(g.stacked_fields) && g.stacked_fields.length > 0);
  assert.deepEqual(set(g.operators.map((o) => o.name)), set(["contains", "equals", "wildcard", "regex", "jsonpath", "full-text"]));
  assert.ok(g.bijection?.field_to_atom && g.bijection?.operator_to_text, "bijection documented");
  for (const [f, a] of Object.entries(g.bijection.field_to_atom)) {
    assert.ok(g.stacked_fields.includes(f), `bijection field ${f} is a stacked field`);
    assert.ok(g.atoms.some((x) => x.atom === a), `bijection ${f} -> ${a} is an atom`);
  }
  for (const f of g.bijection.unmapped_fields) assert.ok(g.stacked_fields.includes(f), `unmapped field ${f}`);
  for (const f of g.stacked_fields) {
    assert.ok(f in g.bijection.field_to_atom || g.bijection.unmapped_fields.includes(f), `${f} is mapped or declared unmapped`);
  }
  for (const [t, cls] of Object.entries(g.map_token)) {
    assert.ok(SYNTAX_TOKENS.includes(cls), `map_token.${t} -> ${cls}`);
  }
});

// ---------------------------------------------------------------------------
// flow-kinds.json
// ---------------------------------------------------------------------------

test("flow-kinds.json: http / websocket / l4 descriptors", () => {
  const kinds = load("flow-kinds.json");
  assert.ok(Array.isArray(kinds));
  assert.deepEqual(set(kinds.map((k) => k.kind)), ["http", "l4", "websocket"]);
  for (const k of kinds) {
    assert.ok(k.badge?.label && k.badge?.token, `${k.kind} badge {label, token}`);
    for (const key of ["list_cells", "inspector", "detail_cmd", "realtime"]) {
      assert.ok(k[key] && typeof k[key] === "object", `${k.kind}.${key}`);
    }
  }
  const l4 = kinds.find((k) => k.kind === "l4");
  assert.equal(l4.badge.token, "l4");
  assert.equal(l4.badge.label, "L4");
  assert.equal(l4.status, "m5-gated");
  assert.equal(kinds.find((k) => k.kind === "websocket").badge.label, "WS");
});

// ---------------------------------------------------------------------------
// filter.conformance.json — checked against a reference parser written here
// ---------------------------------------------------------------------------

const DELIMS = new Set([" ", "\t", "(", ")", "&", "|"]);
const fail = (code) => Object.assign(new Error(code), { code });

/** A `/re/` at `i` that closes before a delimiter/end; mirrors TUI `scan_regex`. */
function scanRegex(s, start) {
  let i = start + 1;
  let src = "";
  while (i < s.length) {
    if (s[i] === "\\" && i + 1 < s.length) {
      src += s[i] + s[i + 1];
      i += 2;
    } else if (s[i] === "/" && (i + 1 >= s.length || DELIMS.has(s[i + 1]))) {
      return { src, next: i + 1 };
    } else {
      src += s[i++];
    }
  }
  return null;
}

function tokenize(s) {
  const out = [];
  let i = 0;
  const push = (type, start, end, value) => out.push({ type, text: s.slice(start, end), start, end, value });
  while (i < s.length) {
    const c = s[i];
    if (c === " " || c === "\t") i++;
    else if (c === "(") push("lparen", i, ++i);
    else if (c === ")") push("rparen", i, ++i);
    else if (c === "&") push("and", i, ++i);
    else if (c === "|") push("or", i, ++i);
    else if (c === "!") push("not", i, ++i);
    else if (c === '"' || c === "'") {
      const close = s.indexOf(c, i + 1);
      if (close < 0) throw fail("unterminated-quote");
      push("string", i, close + 1, s.slice(i + 1, close));
      i = close + 1;
    } else if (c === "~") {
      let j = i + 1;
      while (j < s.length && /[A-Za-z0-9_]/.test(s[j])) j++;
      if (j === i + 1) throw fail("missing-atom-name");
      push("atom", i, j, s.slice(i, j));
      i = j;
    } else if (c === "/" && scanRegex(s, i)) {
      const { src, next } = scanRegex(s, i);
      push("regex", i, next, src);
      i = next;
    } else {
      let j = i;
      while (j < s.length && !DELIMS.has(s[j])) j++;
      push("word", i, j, s.slice(i, j));
      i = j;
    }
  }
  return out;
}

function makeParser(grammar) {
  const atoms = new Map(grammar.atoms.map((a) => [a.atom, a]));
  return (input) => {
    const toks = tokenize(input);
    let pos = 0;
    const peek = () => toks[pos];
    const orExpr = () => {
      let left = andExpr();
      while (peek()?.type === "or") {
        pos++;
        left = { op: "or", left, right: andExpr() };
      }
      return left;
    };
    const andExpr = () => {
      let left = notExpr();
      for (;;) {
        const t = peek();
        if (t?.type === "and") pos++;
        else if (!t || t.type === "or" || t.type === "rparen") break;
        left = { op: "and", left, right: notExpr() };
      }
      return left;
    };
    const notExpr = () => {
      if (peek()?.type === "not") {
        pos++;
        return { op: "not", arg: notExpr() };
      }
      return atomExpr();
    };
    const atomExpr = () => {
      const t = peek();
      if (!t) throw fail("unexpected-end");
      pos++;
      if (t.type === "lparen") {
        const e = orExpr();
        if (peek()?.type !== "rparen") throw fail("unbalanced-paren");
        pos++;
        return e;
      }
      if (t.type === "word" || t.type === "string") {
        return { op: "atom", atom: grammar.bare_word, arg: { kind: "wild", value: t.value } };
      }
      if (t.type === "regex") return { op: "atom", atom: grammar.bare_word, arg: { kind: "regex", value: t.value } };
      if (t.type !== "atom") throw fail("unexpected-token");
      const def = atoms.get(t.value);
      if (!def) throw fail("unknown-atom");
      const atom = def.alias_of ?? def.atom;
      const kind = atoms.get(atom).args;
      if (kind === "none") return { op: "atom", atom };
      const a = peek();
      if (!a || !["word", "string", "regex"].includes(a.type)) throw fail("missing-argument");
      pos++;
      if (a.type === "regex") {
        if (kind === "literal") throw fail("regex-not-allowed");
        return { op: "atom", atom, arg: { kind: "regex", value: a.value } };
      }
      return { op: "atom", atom, arg: { kind: kind === "pattern" ? "wild" : "literal", value: a.value } };
    };
    if (toks.length === 0) return { tokens: toks, ast: null };
    const ast = orExpr();
    if (pos < toks.length) throw fail("unexpected-token");
    return { tokens: toks, ast };
  };
}

const PREC = { or: 1, and: 2, not: 3, atom: 4 };

/** Canonical text form a surface emits from an AST (README "Filter fixture"). */
function serialize(n, min = 0) {
  let text;
  if (n.op === "atom") {
    text = n.atom;
    if (n.arg) text += " " + fmtArg(n.arg);
  } else if (n.op === "not") {
    text = "!" + serialize(n.arg, PREC.not);
  } else if (n.op === "and") {
    text = serialize(n.left, PREC.and) + " & " + serialize(n.right, PREC.and + 1);
  } else {
    text = serialize(n.left, PREC.or) + " | " + serialize(n.right, PREC.or + 1);
  }
  return PREC[n.op] < min ? `(${text})` : text;
}

function fmtArg({ kind, value }) {
  if (kind === "regex") return `/${value}/`;
  if (value === "" || /[\s()&|"']/.test(value) || /^[~!/]/.test(value)) {
    assert.ok(!(value.includes('"') && value.includes("'")), "fixture arg must be quotable");
    return value.includes('"') ? `'${value}'` : `"${value}"`;
  }
  return value;
}

const strip = (toks) => toks.map(({ type, text, start, end }) => ({ type, text, start, end }));

function* astAtoms(n) {
  if (!n) return;
  if (n.op === "atom") yield n.atom;
  else if (n.op === "not") yield* astAtoms(n.arg);
  else {
    yield* astAtoms(n.left);
    yield* astAtoms(n.right);
  }
}

test("filter.conformance.json: ≥12 entries; tokens + AST agree with the reference parser", () => {
  const grammar = load("filter.grammar.json");
  const parse = makeParser(grammar);
  const fx = load("filter.conformance.json");
  assert.ok(Array.isArray(fx) && fx.length >= 12, `≥12 entries (have ${fx.length})`);
  const inputs = new Set();
  for (const e of fx) {
    assert.ok(!inputs.has(e.input), `duplicate fixture input ${JSON.stringify(e.input)}`);
    inputs.add(e.input);
    let got;
    let err = null;
    try {
      got = parse(e.input);
    } catch (x) {
      if (!x.code) throw x;
      err = x.code;
      // tokens are still defined for parse-time errors (tokenizer succeeded)
      got = { tokens: tokenize(e.input), ast: null };
    }
    const label = JSON.stringify(e.input);
    assert.deepEqual(e.tokens, strip(got.tokens), `tokens for ${label}`);
    assert.deepEqual(e.ast, got.ast, `ast for ${label}`);
    assert.equal(e.error ?? null, err, `error for ${label}`);
    for (const t of e.tokens) assert.equal(e.input.slice(t.start, t.end), t.text, `span for ${label}`);
    for (const t of e.tokens) assert.ok(t.type in grammar.map_token, `token type ${t.type} is mapped`);
    if (!err && e.ast) {
      assert.equal(e.canonical, serialize(e.ast), `canonical for ${label}`);
      assert.deepEqual(parse(e.canonical).ast, e.ast, `canonical re-parses to the same AST for ${label}`);
    }
  }
});

test("filter.conformance.json: coverage — every atom, combinator, bare word, round-trip pair", () => {
  const grammar = load("filter.grammar.json");
  const fx = load("filter.conformance.json");
  const ok = fx.filter((e) => !e.error);
  // every atom the grammar defines appears as a token in a valid fixture
  const used = new Set(ok.flatMap((e) => e.tokens.filter((t) => t.type === "atom").map((t) => t.text)));
  for (const a of grammar.atoms) assert.ok(used.has(a.atom), `atom ${a.atom} is exercised`);
  // and every atom a fixture uses is defined (also covers ASTs)
  const defined = new Set(grammar.atoms.map((a) => a.atom));
  for (const e of fx) {
    for (const t of e.tokens.filter((t) => t.type === "atom")) {
      if (e.error !== "unknown-atom") assert.ok(defined.has(t.text), `${t.text} defined`);
    }
    for (const a of astAtoms(e.ast)) assert.ok(defined.has(a), `ast atom ${a} defined`);
  }
  // combinators + structure
  const types = new Set(ok.flatMap((e) => e.tokens.map((t) => t.type)));
  for (const t of ["and", "or", "not", "lparen", "rparen", "word", "string", "regex", "atom"]) {
    assert.ok(types.has(t), `token type ${t} is exercised`);
  }
  // juxtaposition (implicit AND): an `and` node with no `&` token
  assert.ok(ok.some((e) => e.ast?.op === "and" && !e.tokens.some((t) => t.type === "and")), "implicit AND exercised");
  // precedence: `|` lower than `&`, and parentheses override it
  assert.ok(ok.some((e) => e.ast?.op === "or" && e.ast.right.op === "and"), "a | b & c groups as a | (b & c)");
  assert.ok(ok.some((e) => e.ast?.op === "and" && e.ast.left.op === "or"), "(a | b) & c");
  // bare word == ~u
  assert.ok(
    ok.some((e) => !e.input.includes("~") && e.ast?.op === "atom" && e.ast.atom === "~u" && e.ast.arg.kind === "wild"),
    "bare word parses as ~u",
  );
  // alias normalisation
  assert.ok(ok.some((e) => e.tokens.some((t) => t.text === "~t") && [...astAtoms(e.ast)].includes("~c")), "~t normalises to ~c");
  // error coverage
  const errs = new Set(fx.filter((e) => e.error).map((e) => e.error));
  for (const c of ["missing-argument", "unbalanced-paren", "regex-not-allowed"]) assert.ok(errs.has(c), `error ${c} exercised`);
  // empty input is a valid "no filter"
  assert.ok(fx.some((e) => e.input === "" && e.ast === null && !e.error), "empty input -> null AST");
  // copy-between-surfaces round-trip pair: different text, identical AST + canonical form
  const pairs = ok.filter((e) => e.roundtrip_with);
  assert.ok(pairs.length >= 2, "a round-trip pair is present");
  for (const e of pairs) {
    const other = fx.find((x) => x.input === e.roundtrip_with);
    assert.ok(other, `partner of ${JSON.stringify(e.input)} exists`);
    assert.equal(other.roundtrip_with, e.input, "pair is mutual");
    assert.notEqual(other.input, e.input, "pair differs textually");
    assert.deepEqual(other.ast, e.ast, "pair parses to the identical AST");
    assert.equal(other.canonical, e.canonical, "pair has one canonical form");
  }
});

// ---------------------------------------------------------------------------
// completion fixtures
// ---------------------------------------------------------------------------

const IDENT = /[A-Za-z0-9_-]/;

/** The identifier prefix immediately left of `caret`. */
function prefixAt(text, caret) {
  let i = caret;
  while (i > 0 && IDENT.test(text[i - 1])) i--;
  return { start: i, prefix: text.slice(i, caret) };
}

test("rhai.completion.conformance.json: fixtures agree with rhai.api.json", () => {
  const api = load("rhai.api.json");
  const fx = load("rhai.completion.conformance.json");
  assert.ok(Array.isArray(fx) && fx.length >= 8, "≥8 entries");
  const names = new Set(apiNames(api));
  const kinds = new Set();
  const paths = new Set();
  for (const e of fx) {
    kinds.add(e.kind);
    paths.add(e.path);
    assert.ok(Number.isInteger(e.caret) && e.caret >= 0 && e.caret <= e.context.length, `${e.name}: caret in range`);
    assert.ok(Array.isArray(e.expected_candidates) && e.expected_candidates.length > 0, `${e.name}: candidates`);
    const { start, prefix } = prefixAt(e.context, e.caret);
    // the receiver chain left of the prefix must equal `path`
    let receiver = "";
    if (e.context[start - 1] === ".") {
      let j = start - 1;
      while (j > 0 && /[A-Za-z0-9_.]/.test(e.context[j - 1])) j--;
      receiver = e.context.slice(j, start - 1);
    }
    assert.equal(receiver, e.path, `${e.name}: receiver chain`);
    assert.equal(e.kind, receiver === "" ? "top-level" : "member", `${e.name}: kind`);
    for (const c of e.expected_candidates) {
      assert.ok(c.startsWith(prefix), `${e.name}: ${c} starts with prefix ${JSON.stringify(prefix)}`);
      const full = e.path ? `${e.path}.${c}` : c;
      assert.ok(names.has(full), `${e.name}: ${full} is in rhai.api.json`);
    }
    if (e.kind === "member") {
      // member contexts are exact: every catalogued child (with the prefix), nothing else
      const children = [...names]
        .filter((n) => n.startsWith(e.path + ".") && !n.slice(e.path.length + 1).includes("."))
        .map((n) => n.slice(e.path.length + 1))
        .filter((n) => n.startsWith(prefix));
      assert.deepEqual(set(e.expected_candidates), set(children), `${e.name}: exact member set`);
    }
  }
  assert.deepEqual(set(kinds), ["member", "top-level"]);
  // the contexts the spec's AC3 names
  for (const p of ["", "flow", "flow.request", "flow.response", "msg", "flow.request.headers"]) {
    assert.ok(paths.has(p), `context path ${JSON.stringify(p)} is covered`);
  }
  const topLevel = fx.filter((e) => e.kind === "top-level").flatMap((e) => e.expected_candidates);
  for (const h of HOOKS) assert.ok(topLevel.includes(h), `hook ${h} is offered at top level somewhere`);
});

test("poc.completion.conformance.json: fixtures agree with poc-yaml.schema.json", () => {
  const s = load("poc-yaml.schema.json");
  const fx = load("poc.completion.conformance.json");
  assert.ok(Array.isArray(fx) && fx.length >= 8, "≥8 entries");
  const kinds = new Set();
  const paths = new Set();
  for (const e of fx) {
    kinds.add(e.kind);
    paths.add(e.path);
    assert.ok(Number.isInteger(e.caret) && e.caret >= 0 && e.caret <= e.context.length, `${e.name}: caret in range`);
    assert.ok(e.expected_candidates.length > 0, `${e.name}: candidates`);
    const { prefix } = prefixAt(e.context, e.caret);
    const node = schemaNode(s, e.path);
    const line = e.context.slice(0, e.caret).split("\n").pop();
    if (e.kind === "key") {
      assert.ok(!line.includes(":") || /^\s*-\s+\w*$/.test(line) || /^\s*(- )?[\w-]*$/.test(line), `${e.name}: caret is at a key position`);
      const want = Object.keys(node.keys).filter((k) => k.startsWith(prefix));
      assert.deepEqual(set(e.expected_candidates), set(want), `${e.name}: exact key set at ${e.path || "<root>"}`);
    } else {
      assert.equal(e.kind, "enum", `${e.name}: kind`);
      assert.ok(Array.isArray(node.enum), `${e.name}: ${e.path} has an enum`);
      const key = /([\w-]+):\s*[\w-]*$/.exec(line)?.[1];
      assert.equal(key, e.path.split(".").pop().replace(/\[\]/g, ""), `${e.name}: caret is after the key's colon`);
      const want = node.enum.filter((v) => v.startsWith(prefix));
      assert.deepEqual(set(e.expected_candidates), set(want), `${e.name}: exact enum set at ${e.path}`);
    }
  }
  assert.deepEqual(set(kinds), ["enum", "key"]);
  // the contexts the spec's AC4 names
  for (const p of ["", "info", "info.severity", "steps[]", "steps[].browser.action", "steps[].http.matchers[].type"]) {
    assert.ok(paths.has(p), `context path ${JSON.stringify(p)} is covered`);
  }
});
