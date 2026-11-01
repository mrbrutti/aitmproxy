// The shared test double for the v2 Scan surface (T8 Task 8; used by the live model, the store and
// every view test after it). It is the `Scan.test.tsx:46` stub generalised: a `createStore` proxy
// for `app.proxy`/`app.ui`, a `bus` with a state signal, a role and a notification set, a `call`
// that records every tool and answers from a table, and `vi.fn()` actions the tests assert on.
//
// The file name is not `*.test.ts`, so vitest does not collect it; `tsc` still checks it and the
// app bundle never imports it. Nothing here is a fixture *of the core*: the default replies are the
// contract shapes under `crates/aitm-scan-model/fixtures/`, which prove nothing about a real scan
// (fixtures/README.md) — they only keep every test honest about the wire shape it consumes.

import { createSignal } from 'solid-js';
import { createStore } from 'solid-js/store';
import { vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AppStore } from '~/state/app';
import type { PocRun } from '~/bus/mock';
import type { BusRole, BusState, NotificationHandler, ToolDef } from '~/bus/types';

/** A canned answer: a value, or a function of the call's arguments (paging, echoes). */
export type StubReply = unknown | ((args: Record<string, unknown>) => unknown);

/**
 * `unknown | fn` collapses to `unknown`, which leaves a `(args) => …` reply's parameter implicitly
 * `any` at the call site. The overload puts the function arm first, so a test can write
 * `reply('scan.issues', (args) => …)` and get `args` typed without annotating it.
 */
interface ReplyFn {
  (name: string, value: (args: Record<string, unknown>) => unknown): void;
  (name: string, value: unknown): void;
}

export interface StubOptions {
  /** Tool names in `tools/list`; defaults to the fifteen `scan.*` verbs plus the three below. */
  tools?: string[] | undefined;
  scope?: { host: string }[] | undefined;
  findings?: PocRun[] | undefined;
  /** The resolved bus role; defaults to `operator`. */
  role?: BusRole | null | undefined;
  /** Replies by tool name, overriding the fixture defaults. */
  replies?: Record<string, StubReply> | undefined;
}

/** The fifteen D3 scan verbs, in the spec's order. Each has a same-named fixture. */
const SCAN_VERBS = [
  'scan.start',
  'scan.map',
  'scan.status',
  'scan.list',
  'scan.cancel',
  'scan.issues',
  'scan.issue',
  'scan.issue.update',
  'scan.sitemap',
  'scan.checks',
  'scan.profile.list',
  'scan.profile.get',
  'scan.profile.save',
  'scan.profile.delete',
  'scan.session.preview',
] as const;

const DEFAULT_TOOLS: string[] = [...SCAN_VERBS, 'l4.scope.list', 'scope.list', 'flow.list'];

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = resolve(here, '../../../../../crates/aitm-scan-model/fixtures');

/** A fresh parse per call: a test that mutates a reply cannot leak into the next one. */
function fixture(name: string): unknown {
  return JSON.parse(readFileSync(resolve(FIXTURES, `${name}.json`), 'utf8'));
}

const tool = (name: string): ToolDef => ({ name, description: `${name} (stub)`, inputSchema: { type: 'object' } });

export function stubApp(opts: StubOptions = {}) {
  const [proxy, setProxy] = createStore({
    tools: (opts.tools ?? DEFAULT_TOOLS).map(tool),
    scope: opts.scope ?? ([] as { host: string }[]),
    findings: opts.findings ?? ([] as PocRun[]),
    agentActionsLastMinute: 0,
    version: '0.5.8',
    address: '127.0.0.1:8080',
    listening: true,
    armed: false,
  });
  const [ui, setUi] = createStore({
    sidebar: { kind: 'all' } as { kind: string },
    pinned: [] as string[],
    quickFilter: '',
    panel: 'scan',
  });
  const [busState, setBusState] = createSignal<BusState>('open');
  const [role] = createSignal<BusRole | null>(opts.role !== undefined ? opts.role : 'operator');

  const handlers = new Set<NotificationHandler>();
  const replies = new Map<string, StubReply>(Object.entries(opts.replies ?? {}));
  const failures = new Map<string, string>();
  const calls: { tool: string; args: Record<string, unknown> }[] = [];

  /** The fixture a verb answers with when no test said otherwise. */
  function defaultReply(name: string): unknown {
    if ((SCAN_VERBS as readonly string[]).includes(name)) return fixture(name);
    if (name === 'scope.list') return proxy.scope.map((s) => ({ host: s.host }));
    if (name === 'l4.scope.list' || name === 'flow.list') return [];
    return null;
  }

  const call = vi.fn((name: string, args?: Record<string, unknown>): Promise<unknown> => {
    calls.push({ tool: name, args: args ?? {} });
    const failure = failures.get(name);
    if (failure !== undefined) return Promise.reject(new Error(failure));
    const canned = replies.has(name) ? replies.get(name) : defaultReply(name);
    const value = typeof canned === 'function' ? (canned as (a: Record<string, unknown>) => unknown)(args ?? {}) : canned;
    return Promise.resolve(value);
  });

  const setSidebar = vi.fn((s: { kind: string }) => setUi('sidebar', s));
  const select = vi.fn((_id: string) => {});
  const notice = vi.fn((_text: string, _kind?: string) => {});
  const loadDetail = vi.fn(async (_id: string): Promise<unknown> => null);
  const refreshSide = vi.fn(async (): Promise<void> => {});
  const addScope = vi.fn(async (host: string): Promise<void> => {
    setProxy('scope', (s) => [...s, { host }]);
  });

  const reply: ReplyFn = (name: string, value: unknown): void => {
    failures.delete(name);
    replies.set(name, value);
  };

  const app = {
    proxy,
    ui,
    bus: {
      address: 'bus 127.0.0.1:0 (stub)',
      state: busState,
      lastError: () => null,
      role,
      expectRole: null,
      roleMismatch: () => false,
      connect: () => {},
      close: () => {},
      tools: async () => proxy.tools,
      call,
      onNotification(handler: NotificationHandler) {
        handlers.add(handler);
        return () => {
          handlers.delete(handler);
        };
      },
    },
    groups: () => ({ apps: [], domains: [], inScope: 0 }),
    call,
    setSidebar,
    select,
    notice,
    loadDetail,
    refreshSide,
    addScope,
    setQuickFilter: vi.fn(),
    setL4Ids: vi.fn(),
    scanDiscover: vi.fn(async () => null),
  };

  return {
    app: app as unknown as AppStore,
    /** Every call through `app.call`, in order. */
    calls,
    count: (name: string): number => calls.filter((c) => c.tool === name).length,
    argsOf: (name: string): Record<string, unknown>[] => calls.filter((c) => c.tool === name).map((c) => c.args),
    /** Answer `name` with `value` (or with `value(args)`) from now on; clears a `fail`. */
    reply,
    /** Reject every further call to `name` with `message`, as a BusError would. */
    fail: (name: string, message: string): void => {
      failures.set(name, message);
    },
    /** Deliver a server notification, as the streaming bus does. */
    emit: (method: string, params: unknown): void => {
      for (const handler of [...handlers]) handler(method, params);
    },
    setBusState,
    setTools: (names: string[]): void => setProxy('tools', names.map(tool)),
    setScope: (hosts: string[]): void => setProxy('scope', hosts.map((host) => ({ host }))),
    setSidebar,
    select,
    notice,
    loadDetail,
    refreshSide,
    addScope,
  };
}
