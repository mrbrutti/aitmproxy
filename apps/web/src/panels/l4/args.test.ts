// L4 parity (plan 2026-10-31-l4-parity-fixes, unit (c), task C1): the argument builders every L4
// action goes through, the availability seam (spec §1) and the `tools/list` feature detects. Pure
// logic with inputs built here (AC18, AC19, AC20, AC39), plus a live schema block that runs only
// against a real core (`AITM_BUS_ADDR`) and is skipped in the gate.
import { describe, expect, it } from 'vitest';
import {
  availabilityFromError,
  availabilityFromReply,
  captureStartArgs,
  captureStopArgs,
  flowGetArgs,
  L4_ARG_BUILDERS,
  mutateArgs,
  parkedFor,
  PENDING_AVAILABILITY,
  revertArgs,
  scopeAddArgs,
  statusIds,
  stopAllArgs,
  supportsFlowWindow,
  supportsOperatorScopeAdd,
  verdictArgs,
  type L4ParkedWire,
  type L4ScopeDraft,
  type PacketSpec,
} from './model';

const parked = (id: string, flow: string): L4ParkedWire => ({
  id,
  flow,
  state: 'parked',
  dir: 'inbound',
  length: 36,
  layers: ['IPv4', 'UDP'],
  parked_at: 1_761_900_000_000,
});

describe('capture builders (AC18, AC19)', () => {
  it('captureStartArgs emits exactly interface + direction, never filter', () => {
    const args = captureStartArgs('lo0', 'inbound');
    expect(args).toEqual({ interface: 'lo0', direction: 'inbound' });
    expect(Object.keys(args)).toEqual(['interface', 'direction']);
    expect(args).not.toHaveProperty('filter');
  });

  it('captureStopArgs / stopAllArgs emit {id} per running capture', () => {
    expect(captureStopArgs('C1')).toEqual({ id: 'C1' });
    expect(stopAllArgs(['C1', 'C2'])).toEqual([{ id: 'C1' }, { id: 'C2' }]);
    expect(stopAllArgs([])).toEqual([]);
  });
});

describe('parked-packet builders (AC20)', () => {
  const spec: PacketSpec = { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: [1] }] };

  it('Forward/Drop send the parked id', () => {
    expect(verdictArgs('P1')).toEqual({ id: 'P1' });
    expect(Object.keys(verdictArgs('P1'))).toEqual(['id']);
  });

  it('Mutate sends {id, spec}; Revert sends {id}', () => {
    expect(mutateArgs('P1', spec)).toEqual({ id: 'P1', spec });
    expect(Object.keys(mutateArgs('P1', spec))).toEqual(['id', 'spec']);
    expect(revertArgs('P1')).toEqual({ id: 'P1' });
  });

  it('parkedFor picks the first listed (oldest) parked packet of the flow', () => {
    const list = [parked('P1', 'F'), parked('P2', 'G'), parked('P3', 'G')];
    expect(parkedFor(list, 'G')?.id).toBe('P2');
    expect(parkedFor(list, 'F')?.id).toBe('P1');
    expect(parkedFor(list, 'H')).toBeNull();
    expect(parkedFor([], 'F')).toBeNull();
  });
});

describe('scope add builder (AC22 args)', () => {
  it('scopeAddArgs maps the AC5 draft one-to-one', () => {
    const draft: L4ScopeDraft = {
      cidr: '127.0.0.1/32',
      ports: '9100-9199',
      interface: 'lo0',
      direction: 'inbound',
      capability: 'capture',
    };
    expect(scopeAddArgs(draft)).toEqual({
      cidr: '127.0.0.1/32',
      ports: '9100-9199',
      interface: 'lo0',
      direction: 'inbound',
      capability: 'capture',
    });
    expect(Object.keys(scopeAddArgs(draft))).toEqual(['cidr', 'ports', 'interface', 'direction', 'capability']);
  });
});

describe('flow.get window (spec §2)', () => {
  it('list rows use limit 0, the inspector a 256 window, an older core gets only {id}', () => {
    expect(flowGetArgs('F', 'list', true)).toEqual({ id: 'F', limit: 0 });
    expect(flowGetArgs('F', 'inspect', true)).toEqual({ id: 'F', offset: 0, limit: 256 });
    expect(flowGetArgs('F', 'list', false)).toEqual({ id: 'F' });
    expect(flowGetArgs('F', 'inspect', false)).toEqual({ id: 'F' });
  });

  it('supportsFlowWindow is true iff l4.flow.get declares limit', () => {
    const withLimit = [{ name: 'l4.flow.get', inputSchema: { properties: { id: {}, offset: {}, limit: {} } } }];
    const without = [{ name: 'l4.flow.get', inputSchema: { properties: { id: {} } } }];
    expect(supportsFlowWindow(withLimit)).toBe(true);
    expect(supportsFlowWindow(without)).toBe(false);
    expect(supportsFlowWindow([{ name: 'l4.flow.list', inputSchema: { properties: { limit: {} } } }])).toBe(false);
    expect(supportsFlowWindow([])).toBe(false);
  });
});

describe('availability seam (spec §1)', () => {
  it('maps the new status object', () => {
    expect(availabilityFromReply({ available: false, code: 'needs_privilege', reason: 'X', captures: [] })).toEqual({
      available: false,
      code: 'needs_privilege',
      reason: 'X',
    });
    expect(availabilityFromReply({ available: true, code: 'available', reason: null, sessions: [] })).toEqual({
      available: true,
      code: 'available',
      reason: null,
    });
  });

  it('a bare array (older core) means available', () => {
    expect(availabilityFromReply([])).toEqual({ available: true, code: null, reason: null });
    expect(availabilityFromReply(['C1'])).toEqual({ available: true, code: null, reason: null });
  });

  it('an older core error carrying "L4 unavailable: " is unavailable with the text after it', () => {
    expect(availabilityFromError('l4.capture.status: L4 unavailable: X')).toEqual({ available: false, code: null, reason: 'X' });
    expect(availabilityFromError('boom')).toBeNull();
  });

  it('PENDING_AVAILABILITY is the shared pending literal', () => {
    expect(PENDING_AVAILABILITY.reason).toBe('Reading L4 availability…');
    expect(PENDING_AVAILABILITY.available).toBe(false);
  });

  it('statusIds reads the payload under its key, or the bare array', () => {
    expect(statusIds({ available: true, code: 'available', reason: null, captures: ['C1', 'C2'] }, 'captures')).toEqual(['C1', 'C2']);
    expect(statusIds({ available: false, code: 'needs_privilege', reason: 'X', captures: [] }, 'captures')).toEqual([]);
    expect(
      statusIds({ available: true, code: 'available', reason: null, sessions: [{ flow: 'I1', interface: 'lo', queue: 0, parked: 2 }] }, 'sessions'),
    ).toEqual(['I1']);
    expect(statusIds(['C9'], 'captures')).toEqual(['C9']);
    expect(statusIds(null, 'captures')).toEqual([]);
  });
});

describe('scope-add control only where confirmable (AC39)', () => {
  it('supportsOperatorScopeAdd needs l4.scope.add with confirmable: true', () => {
    expect(supportsOperatorScopeAdd([{ name: 'l4.scope.add', confirmable: true }])).toBe(true);
    expect(supportsOperatorScopeAdd([{ name: 'l4.scope.add' }])).toBe(false);
    expect(supportsOperatorScopeAdd([{ name: 'l4.scope.add', confirmable: false }])).toBe(false);
    expect(supportsOperatorScopeAdd([{ name: 'l4.scope.add', confirmable: 'true' }])).toBe(false);
    expect(supportsOperatorScopeAdd([{ name: 'l4.scope.list', confirmable: true }])).toBe(false);
    expect(supportsOperatorScopeAdd([])).toBe(false);
  });
});

describe('L4_ARG_BUILDERS table', () => {
  it('names every verb the builders emit, with the keys they emit', () => {
    const table = Object.fromEntries(L4_ARG_BUILDERS.map((b) => [b.tool, [...b.keys]]));
    expect(table).toEqual({
      'l4.capture.start': ['interface', 'direction'],
      'l4.capture.stop': ['id'],
      'l4.intercept.forward': ['id'],
      'l4.intercept.drop': ['id'],
      'l4.intercept.mutate': ['id', 'spec'],
      'l4.intercept.revert': ['id'],
      'l4.scope.add': ['cidr', 'ports', 'interface', 'direction', 'capability'],
      'l4.flow.get': ['id', 'offset', 'limit'],
    });
  });

  it('agrees with the builders themselves', () => {
    const keys = (tool: string) => L4_ARG_BUILDERS.find((b) => b.tool === tool)!.keys;
    expect(Object.keys(captureStartArgs('lo0', 'outbound'))).toEqual(keys('l4.capture.start'));
    expect(Object.keys(captureStopArgs('C'))).toEqual(keys('l4.capture.stop'));
    expect(Object.keys(verdictArgs('P'))).toEqual(keys('l4.intercept.forward'));
    expect(Object.keys(verdictArgs('P'))).toEqual(keys('l4.intercept.drop'));
    expect(Object.keys(mutateArgs('P', { layers: [] }))).toEqual(keys('l4.intercept.mutate'));
    expect(Object.keys(revertArgs('P'))).toEqual(keys('l4.intercept.revert'));
    expect(
      Object.keys(scopeAddArgs({ cidr: 'a', ports: 'b', interface: 'c', direction: 'inbound', capability: 'capture' })),
    ).toEqual(keys('l4.scope.add'));
    expect(Object.keys(flowGetArgs('F', 'inspect', true))).toEqual(keys('l4.flow.get'));
  });
});

// ---- not constants (tester): distinct inputs give distinct outputs ----------------------------------
//
// The blocks above each call a builder with one input, so a builder replaced by a constant would
// still pass them. These pin that every builder carries its argument through.

describe('builders carry their arguments (not constants)', () => {
  it('captureStartArgs / captureStopArgs / verdictArgs / revertArgs / mutateArgs follow their inputs', () => {
    expect(captureStartArgs('en0', 'outbound')).toEqual({ interface: 'en0', direction: 'outbound' });
    expect(captureStartArgs('lo', 'inbound')).toEqual({ interface: 'lo', direction: 'inbound' });
    expect(captureStartArgs('en0', 'outbound')).not.toEqual(captureStartArgs('lo0', 'inbound'));
    expect(captureStopArgs('C2')).toEqual({ id: 'C2' });
    expect(stopAllArgs(['Z'])).toEqual([{ id: 'Z' }]);
    expect(verdictArgs('P2')).toEqual({ id: 'P2' });
    expect(verdictArgs('P2')).not.toEqual(verdictArgs('P1'));
    expect(revertArgs('9f3c')).toEqual({ id: '9f3c' });
    const specA: PacketSpec = { layers: [{ raw: [1] }] };
    const specB: PacketSpec = { layers: [{ raw: [2] }] };
    expect(mutateArgs('P2', specA)).toEqual({ id: 'P2', spec: specA });
    expect(mutateArgs('P2', specA).spec).toBe(specA);
    expect(mutateArgs('P2', specA)).not.toEqual(mutateArgs('P2', specB));
  });

  it('scopeAddArgs maps a second, different draft one-to-one (inject / outbound / IPv6)', () => {
    const draft: L4ScopeDraft = { cidr: '::1/128', ports: '', interface: 'lo', direction: 'outbound', capability: 'inject' };
    expect(scopeAddArgs(draft)).toEqual({ cidr: '::1/128', ports: '', interface: 'lo', direction: 'outbound', capability: 'inject' });
    expect(scopeAddArgs(draft)).not.toBe(draft);
  });

  it('flowGetArgs carries the id and the offset', () => {
    expect(flowGetArgs('G', 'list', true)).toEqual({ id: 'G', limit: 0 });
    expect(flowGetArgs('G', 'inspect', true, 512)).toEqual({ id: 'G', offset: 512, limit: 256 });
    expect(flowGetArgs('G', 'inspect', false, 512)).toEqual({ id: 'G' });
  });

  it('availabilityFromReply / availabilityFromError carry the reply through, and say so for an unknown shape', () => {
    expect(availabilityFromReply({ available: false, code: 'unsupported_platform', reason: 'Y', sessions: [] })).toEqual({
      available: false,
      code: 'unsupported_platform',
      reason: 'Y',
    });
    // A non-string code / reason is null, not a stringified value.
    expect(availabilityFromReply({ available: true, code: 7, reason: 0 })).toEqual({ available: true, code: null, reason: null });
    // Neither shape: unavailable with a visible reason, never a guess of "available".
    for (const odd of [null, undefined, 'ok', 42, {}, { captures: [] }, { available: 'true' }]) {
      const a = availabilityFromReply(odd);
      expect(a.available, JSON.stringify(odd) ?? 'undefined').toBe(false);
      expect(a.reason, JSON.stringify(odd) ?? 'undefined').toBe('unrecognised L4 status reply');
    }
    expect(availabilityFromError('x: L4 unavailable: needs CAP_NET_RAW')).toEqual({ available: false, code: null, reason: 'needs CAP_NET_RAW' });
    expect(availabilityFromError('L4 unavailable: ')).toEqual({ available: false, code: null, reason: '' });
    expect(availabilityFromError('')).toBeNull();
    expect(availabilityFromError('L4 unavailable')).toBeNull();
    expect(PENDING_AVAILABILITY.code).toBeNull();
    expect(Object.isFrozen(PENDING_AVAILABILITY)).toBe(true);
  });

  it('parkedFor / statusIds / supportsOperatorScopeAdd read their inputs, not a fixed answer', () => {
    expect(parkedFor([parked('Q7', 'Z')], 'Z')?.id).toBe('Q7');
    expect(statusIds({ available: true, code: 'available', reason: null, captures: ['A', 'B', 'C'] }, 'captures')).toEqual(['A', 'B', 'C']);
    expect(statusIds({ available: true, code: 'available', reason: null, captures: ['A'] }, 'sessions')).toEqual([]);
    expect(statusIds({ sessions: [{ id: 'S1' }, { flow: 'S2' }, { neither: 1 }, 3] }, 'sessions')).toEqual(['S1', 'S2']);
    expect(supportsOperatorScopeAdd([{ name: 'other' }, { name: 'l4.scope.add', confirmable: true }])).toBe(true);
    expect(supportsOperatorScopeAdd([{ name: 'l4.scope.add', confirmable: 1 }])).toBe(false);
  });
});

// ---- store tripwire (task C3) ---------------------------------------------------------------------
//
// `store.ts` must reach every argument-taking L4 verb through a C1 builder, never an object literal
// (AC18–AC20), must hold no `firstParkedId` (verdicts take a parked id, spec §4) and must route read
// failures through one `createOnceLog` (spec §7(c), AC23). The source is read with node `fs`, loaded
// the way the live block below loads `node:net` (no `@types/node` in this package).

async function readL4Source(name: string): Promise<string> {
  const fsModule = 'node:fs';
  const pathModule = 'node:path';
  const urlModule = 'node:url';
  const fs = (await import(/* @vite-ignore */ fsModule)) as { readFileSync(path: string, encoding: 'utf8'): string };
  const path = (await import(/* @vite-ignore */ pathModule)) as { dirname(p: string): string; join(...parts: string[]): string };
  const url = (await import(/* @vite-ignore */ urlModule)) as { fileURLToPath(u: string): string };
  // Not `new URL(name, import.meta.url)`: Vite rewrites that form into an asset glob over the folder.
  const here = url.fileURLToPath(import.meta.url);
  return fs.readFileSync(path.join(path.dirname(here), name), 'utf8');
}

/** The verbs whose argument must be a C1 builder call wherever the store names them. */
const ARG_VERB = String.raw`l4\.(?:flow\.get|capture\.start|capture\.stop|intercept\.[a-z_]+)`;
/** `call('<verb>'…` and `app.call<T>('<verb>'…`: the literal, then `)` (no args) or `, <argument>`. */
const CALL_SITE = new RegExp(String.raw`\bcall(?:<[^>]*>)?\(\s*'(${ARG_VERB})'\s*(\)|,\s*)`, 'g');
/** `beginGuarded(call, '<verb>', <argument>)` / `confirmGuarded(call, '<verb>', <argument>, token)`. */
const GUARDED_SITE = new RegExp(String.raw`\b(?:beginGuarded|confirmGuarded)\(\s*[^,()]+,\s*'(${ARG_VERB})'\s*(\)|,\s*)`, 'g');
const BUILDER_CALL = /^(flowGetArgs|captureStartArgs|captureStopArgs|verdictArgs|mutateArgs|revertArgs)\(/;
/** The two intercept reads take no arguments; a call with no second argument is right for them. */
const NO_ARG_VERBS = new Set(['l4.intercept.status', 'l4.intercept.list']);
/** The store must name each of these literally (so the check above actually sees the call). */
const MUST_CALL = [
  'l4.flow.get',
  'l4.capture.start',
  'l4.capture.stop',
  'l4.intercept.forward',
  'l4.intercept.drop',
  'l4.intercept.mutate',
  'l4.intercept.revert',
];

describe('store_reads_through_builders (C3 tripwire)', () => {
  it('store.ts passes every argument-taking L4 verb a C1 builder, has no firstParkedId, logs failures once', async () => {
    const src = await readL4Source('store.ts');
    const problems: string[] = [];
    if (src.includes('firstParkedId')) problems.push('store.ts still has firstParkedId (verdicts take a parked id, spec §4)');
    if (!src.includes('createOnceLog(')) problems.push('store.ts does not route read failures through createOnceLog(');
    const seen = new Set<string>();
    for (const re of [CALL_SITE, GUARDED_SITE]) {
      for (const m of src.matchAll(re)) {
        const verb = m[1]!;
        seen.add(verb);
        if (m[2] === ')') {
          if (!NO_ARG_VERBS.has(verb)) problems.push(`${verb}: called with no argument`);
          continue;
        }
        const argument = src.slice(m.index! + m[0].length);
        if (!BUILDER_CALL.test(argument)) {
          problems.push(`${verb}: argument is not a C1 builder call: ${argument.split('\n')[0]!.slice(0, 48)}`);
        }
      }
    }
    for (const verb of MUST_CALL) if (!seen.has(verb)) problems.push(`${verb}: store.ts never calls it by its literal name`);
    expect(problems).toEqual([]);
  });
});

// ---- capture-controls tripwire (task C4, AC18 "no filter", AC19) ----------------------------------
//
// The web never sends a `filter` key to `l4.capture.start` (spec §7(c): the core derives the BPF
// filter from L4 scope; a free-form operator string would be a second, unguarded definition of what
// gets captured). Every non-test `.ts`/`.tsx` under `apps/web/src` is walked with node `fs`; at each
// `'l4.capture.start'` call-site literal, that line and the two after it must not mention `filter`,
// and `CaptureControls.tsx` must not contain the word at all (no prop, signal or label).

interface WalkedFile {
  rel: string;
  text: string;
}

async function readWebSources(): Promise<WalkedFile[]> {
  const fsModule = 'node:fs';
  const pathModule = 'node:path';
  const urlModule = 'node:url';
  const fs = (await import(/* @vite-ignore */ fsModule)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
    readdirSync(path: string, opts: { withFileTypes: true }): { name: string; isDirectory(): boolean; isFile(): boolean }[];
  };
  const path = (await import(/* @vite-ignore */ pathModule)) as {
    dirname(p: string): string;
    join(...parts: string[]): string;
    relative(from: string, to: string): string;
  };
  const url = (await import(/* @vite-ignore */ urlModule)) as { fileURLToPath(u: string): string };
  const here = url.fileURLToPath(import.meta.url);
  // panels/l4/args.test.ts → apps/web/src
  const srcRoot = path.join(path.dirname(here), '..', '..');
  const out: WalkedFile[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!/\.tsx?$/.test(entry.name) || /\.test\.tsx?$/.test(entry.name) || /\.d\.ts$/.test(entry.name)) continue;
      out.push({ rel: path.relative(srcRoot, full), text: fs.readFileSync(full, 'utf8') });
    }
  };
  walk(srcRoot);
  return out;
}

/** A call-site literal: an opening quote right before the verb (a backticked doc mention is not one). */
const CAPTURE_START_LITERAL = /['"]l4\.capture\.start\b/;

describe('no_filter_on_capture_start (C4 tripwire, AC18)', () => {
  it('no non-test source passes filter to l4.capture.start, and CaptureControls.tsx has no filter at all', async () => {
    const files = await readWebSources();
    expect(files.length).toBeGreaterThan(10);
    const problems: string[] = [];
    let sawCaptureControls = false;
    let sawCallSite = false;
    for (const { rel, text } of files) {
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (!CAPTURE_START_LITERAL.test(lines[i]!)) continue;
        sawCallSite = true;
        const window = lines.slice(i, i + 3).join('\n');
        if (/filter/i.test(window)) problems.push(`${rel}:${i + 1}: l4.capture.start call mentions filter`);
      }
      if (rel.endsWith('panels/l4/CaptureControls.tsx')) {
        sawCaptureControls = true;
        lines.forEach((line, i) => {
          if (/filter/i.test(line)) problems.push(`${rel}:${i + 1}: contains "filter": ${line.trim().slice(0, 72)}`);
        });
      }
    }
    expect(sawCaptureControls, 'walk must reach panels/l4/CaptureControls.tsx').toBe(true);
    expect(sawCallSite, 'walk must see at least one l4.capture.start call site').toBe(true);
    expect(problems).toEqual([]);
  });

  it('CaptureControls renders a direction select, a Start with the reason, and a Stop per running id (AC19)', async () => {
    const src = await readL4Source('CaptureControls.tsx');
    // What the live browser script (cua-l4.mjs) locates: the landmark and the Start button text.
    expect(src).toContain('aria-label="Capture"');
    expect(src).toContain('Start capture');
    expect(src).toContain('data-testid="l4-capture-start"');
    // The direction select replaces the filter input.
    expect(src).toContain('aria-label="Capture direction"');
    expect(src).toContain('<option value="inbound">');
    expect(src).toContain('<option value="outbound">');
    // Start is disabled with the core's reason as visible text and as the title.
    expect(src).toContain('disabled={!props.capture.available}');
    expect(src).toContain('data-testid="l4-capture-reason"');
    expect(src).toMatch(/title=\{[^}]*props\.capture\.reason/);
    // One Stop per running id, calling onStop(id).
    expect(src).toContain('aria-label={`Stop capture ${id}`}');
    expect(src).toContain('props.onStop(id)');
    // The old props are gone.
    expect(src).not.toContain('canCapture');
    expect(src).not.toContain('activeCaptures');
  });
});

// ---- inert packet text tripwire (task C6, spec §2.3, AC40) -----------------------------------------
//
// The web never inserts packet-derived text by raw HTML insertion: every byte of a packet reaches
// the DOM as a text node (`hexRows` → `<pre>` text). Every file under `panels/l4/` — components,
// model, styles and the tests themselves — is read with node `fs` and must not contain either DOM
// property name. The two names are assembled from fragments here so this file passes its own check.

const RAW_HTML_SINKS = [['inner', 'HTML'].join(''), ['dangerouslySet', 'Inner', 'HTML'].join('')];

async function readPanelsL4Files(): Promise<WalkedFile[]> {
  const fsModule = 'node:fs';
  const pathModule = 'node:path';
  const urlModule = 'node:url';
  const fs = (await import(/* @vite-ignore */ fsModule)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
    readdirSync(path: string, opts: { withFileTypes: true }): { name: string; isDirectory(): boolean; isFile(): boolean }[];
  };
  const path = (await import(/* @vite-ignore */ pathModule)) as {
    dirname(p: string): string;
    join(...parts: string[]): string;
    relative(from: string, to: string): string;
  };
  const url = (await import(/* @vite-ignore */ urlModule)) as { fileURLToPath(u: string): string };
  const dir = path.dirname(url.fileURLToPath(import.meta.url));
  const out: WalkedFile[] = [];
  const walk = (d: string) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push({ rel: path.relative(dir, full), text: fs.readFileSync(full, 'utf8') });
    }
  };
  walk(dir);
  return out;
}

describe('no_innerhtml_under_panels_l4 (C6 tripwire, AC40)', () => {
  it('no file under panels/l4/ names a raw HTML insertion sink', async () => {
    const files = await readPanelsL4Files();
    expect(files.map((f) => f.rel)).toContain('LayerTree.tsx');
    expect(files.map((f) => f.rel)).toContain('args.test.ts');
    const problems: string[] = [];
    for (const f of files) for (const sink of RAW_HTML_SINKS) if (f.text.includes(sink)) problems.push(`${f.rel}: contains ${sink}`);
    expect(problems).toEqual([]);
  });

  it('LayerTree renders hexRows as text and says "no bytes from this core" without bytes', async () => {
    const src = await readL4Source('LayerTree.tsx');
    expect(src).toContain('hexRows(');
    expect(src).toContain('base64ToBytes(');
    expect(src).toContain('no bytes from this core');
    expect(src).not.toContain('Raw bytes are not carried');
  });
});

// ---- scope-add gating tripwire (task C7, spec §3 last bullet, AC22, AC39) -------------------------
//
// The add form exists only where the core offers `l4.scope.add` with `confirmable: true`: in
// `CaptureControls.tsx` the form's testid must sit inside a `<Show when={supportsOperatorScopeAdd(`
// … `</Show>` span, so against a core without (a') there is no form, not a form that can only fail.
// In `store.ts` the verb is sent only from `addScope` / `confirmAddScope`, each through the shared
// confirm-over-the-wire path (`beginGuarded` / `confirmGuarded`) with the C1 builder's arguments.

/** The index just past the `</Show>` that closes the `<Show` opening at `openAt`, or -1. */
function matchingShowClose(src: string, openAt: number): number {
  const token = /<Show\b|<\/Show>/g;
  token.lastIndex = openAt;
  let depth = 0;
  for (let m = token.exec(src); m; m = token.exec(src)) {
    if (m[0] === '</Show>') {
      depth -= 1;
      if (depth === 0) return m.index + m[0].length;
    } else depth += 1;
  }
  return -1;
}

describe('scope_add_form_is_gated (C7 tripwire, AC22, AC39)', () => {
  it('CaptureControls.tsx renders the add form only inside <Show when={supportsOperatorScopeAdd(…)}>', async () => {
    const src = await readL4Source('CaptureControls.tsx');
    const gateAt = src.indexOf('<Show when={supportsOperatorScopeAdd(');
    expect(gateAt, 'no <Show when={supportsOperatorScopeAdd( gate in CaptureControls.tsx').toBeGreaterThanOrEqual(0);
    const gateEnd = matchingShowClose(src, gateAt);
    expect(gateEnd, 'the supportsOperatorScopeAdd gate has no matching </Show>').toBeGreaterThan(gateAt);
    const formAt = src.indexOf('data-testid="l4-scope-add-form"');
    expect(formAt, 'no data-testid="l4-scope-add-form" in CaptureControls.tsx').toBeGreaterThanOrEqual(0);
    expect(formAt, 'the add form must come after the supportsOperatorScopeAdd( gate').toBeGreaterThan(gateAt);
    expect(formAt, 'the add form must sit inside the supportsOperatorScopeAdd gate span').toBeLessThan(gateEnd);
    // Exactly one form, and only one occurrence of its testid (no second, ungated copy).
    expect(src.indexOf('data-testid="l4-scope-add-form"', formAt + 1)).toBe(-1);
    // What the live browser script (cua-l4.mjs) locates, and the confirm dialog it drives.
    expect(src).toContain('aria-label="Add L4 scope"');
    expect(src).toContain('data-testid="l4-scope-add"');
    expect(src).toContain('aria-label="Scope CIDR"');
    expect(src).toContain('aria-label="Scope ports"');
    expect(src).toContain('aria-label="Scope interface"');
    expect(src).toContain('aria-label="Scope direction"');
    expect(src).toContain('aria-label="Scope capability"');
    expect(src).toContain('title="Confirm L4 scope add"');
    expect(src).toContain('props.onAddScope(');
    expect(src).toContain('props.onConfirmAddScope(');
    // Provenance from the core's `source` (config / runtime).
    expect(src).toContain('e.source');
  });

  it('store.ts sends l4.scope.add only from addScope / confirmAddScope through beginGuarded / confirmGuarded with scopeAddArgs', async () => {
    const src = await readL4Source('store.ts');
    const lines = src.split('\n');
    const hits = lines.map((text, i) => ({ n: i + 1, text })).filter((l) => l.text.includes("'l4.scope.add'"));
    expect(hits.map((l) => l.n), 'store.ts must name l4.scope.add on exactly two lines (addScope, confirmAddScope)').toHaveLength(2);
    const problems: string[] = [];
    for (const l of hits) {
      const guarded = l.text.includes('beginGuarded(') || l.text.includes('confirmGuarded(');
      if (!guarded) problems.push(`line ${l.n}: l4.scope.add not sent through beginGuarded( / confirmGuarded(`);
      if (!l.text.includes('scopeAddArgs(')) problems.push(`line ${l.n}: l4.scope.add argument is not scopeAddArgs(`);
    }
    expect(problems).toEqual([]);
    // The two lines sit inside the two named functions (arrow or function form), in that order.
    const addAt = src.search(/(?:async function addScope\(|function addScope\(|const addScope = (?:async )?\()/);
    const confirmAt = src.search(/(?:async function confirmAddScope\(|function confirmAddScope\(|const confirmAddScope = (?:async )?\()/);
    expect(addAt, 'store.ts has no addScope definition').toBeGreaterThanOrEqual(0);
    expect(confirmAt, 'store.ts has no confirmAddScope definition').toBeGreaterThanOrEqual(0);
    const offsetOfLine = (n: number) => lines.slice(0, n - 1).join('\n').length + (n > 1 ? 1 : 0);
    const [first, second] = hits.map((l) => offsetOfLine(l.n)) as [number, number];
    const [lo, hi] = addAt < confirmAt ? [addAt, confirmAt] : [confirmAt, addAt];
    expect(first).toBeGreaterThan(lo);
    expect(first).toBeLessThan(hi);
    expect(second).toBeGreaterThan(hi);
    // Both are exported on the store object (the capture bar wires them through).
    expect(src).toMatch(/\n\s+addScope,\n/);
    expect(src).toMatch(/\n\s+confirmAddScope,\n/);
    // No direct call site for the verb anywhere in the store.
    expect(src).not.toMatch(/\bcall(?:<[^>]*>)?\(\s*'l4\.scope\.add'/);
  });
});

// ---- live schema block (AC18 live; run in C10 against the rig, skipped in the gate) ---------------
//
// Reads the real core's `tools/list` over the loopback-TCP bus (the wire of
// `tests/e2e/aitm_e2e/bus.py`): one `{"token": …}` line, then newline-delimited JSON-RPC. The token
// comes from the environment and is never printed. No `@types/node` here, so the node modules are
// loaded through a non-literal dynamic import and `process` is declared locally.

declare const process: { env: Record<string, string | undefined> };

interface LiveTool {
  name: string;
  inputSchema?: { properties?: Record<string, unknown> };
}

async function liveToolsList(addr: string, token: string): Promise<LiveTool[]> {
  const netModule = 'node:net';
  const net = (await import(/* @vite-ignore */ netModule)) as {
    createConnection(opts: { host: string; port: number }, onConnect: () => void): LiveSocket;
  };
  const sep = addr.lastIndexOf(':');
  const host = addr.slice(0, sep);
  const port = Number(addr.slice(sep + 1));
  return new Promise<LiveTool[]>((resolve, reject) => {
    const sock = net.createConnection({ host, port }, () => {
      sock.write(JSON.stringify({ token }) + '\n');
      sock.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'args-test', version: '0' } },
        }) + '\n',
      );
    });
    let buf = '';
    const fail = (why: string) => {
      sock.destroy();
      reject(new Error(why));
    };
    sock.setEncoding('utf8');
    sock.setTimeout(10_000, () => fail('bus read timed out'));
    sock.on('error', (e) => fail(`bus socket error: ${e.message}`));
    sock.on('data', (chunk) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg: { id?: unknown; error?: unknown; result?: { tools?: LiveTool[] } };
        try {
          msg = JSON.parse(line) as typeof msg;
        } catch {
          return fail('bus sent a non-JSON line');
        }
        if (msg.error) return fail(`bus rpc error: ${JSON.stringify(msg.error)}`);
        if (msg.id === 1) {
          sock.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
          sock.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) + '\n');
        } else if (msg.id === 2) {
          sock.end();
          resolve(msg.result?.tools ?? []);
        }
        // Anything else (no id) is a server push; ignored.
      }
    });
  });
}

interface LiveSocket {
  write(data: string): void;
  end(): void;
  destroy(): void;
  setEncoding(enc: string): void;
  setTimeout(ms: number, cb: () => void): void;
  on(ev: 'data', cb: (chunk: string) => void): void;
  on(ev: 'error', cb: (e: Error) => void): void;
}

describe.skipIf(!process.env.AITM_BUS_ADDR)('live schema (AC18): every builder key is in the rig tool inputSchema', () => {
  it('tools/list from the rig declares every L4_ARG_BUILDERS key', async () => {
    const addr = process.env.AITM_BUS_ADDR!;
    const token = process.env.AITM_BUS_OPERATOR_TOKEN;
    expect(token, 'AITM_BUS_OPERATOR_TOKEN must be set alongside AITM_BUS_ADDR').toBeTruthy();
    const tools = await liveToolsList(addr, token!);
    const byName = new Map(tools.map((t) => [t.name, t]));
    const missing: string[] = [];
    for (const b of L4_ARG_BUILDERS) {
      const tool = byName.get(b.tool);
      if (!tool) {
        missing.push(`${b.tool}: tool absent from tools/list`);
        continue;
      }
      const props = tool.inputSchema?.properties ?? {};
      for (const k of b.keys) if (!(k in props)) missing.push(`${b.tool}.${k}`);
    }
    expect(missing).toEqual([]);
  }, 20_000);
});
