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
