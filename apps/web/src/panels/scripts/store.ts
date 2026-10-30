// Scripts panel state that outlives the component: the loaded scripts, the console, and the editor's
// draft. The panel unmounts whenever the inspector takes the lower region, and a half-written script
// must not vanish with it, so this lives per app store instead of per mount (and a fresh store — a
// test, a reconnect — starts clean). Every call goes through `app.call`; a failure is surfaced, never
// swallowed: row actions as a toast, the editor's validate/save as the result region's own text.

import { createMemo, createRoot, createSignal, type Accessor } from 'solid-js';
import { createStore, reconcile } from 'solid-js/store';
import type { AppStore } from '~/state/app';
import {
  FINDINGS_LIMIT,
  activeCount,
  isScriptName,
  parseFindings,
  parseReport,
  parseScriptList,
  type ScriptFindings,
  type ScriptReport,
  type ScriptRow,
} from './model';

/** What the editor's result region shows: a validate summary, a save result, or the core's error text verbatim. */
export type Outcome = { kind: 'valid'; report: ScriptReport } | { kind: 'saved'; report: ScriptReport } | { kind: 'error'; text: string };

export interface ScriptsStore {
  /** `script.list` is advertised: without it the panel says the core has no scripts tier. */
  offered: Accessor<boolean>;
  /** The session is an agent: the core refuses authoring unless `rhai.allow_agent_authoring` is set. */
  agent: Accessor<boolean>;
  canToggle: Accessor<boolean>;
  canReload: Accessor<boolean>;
  canValidate: Accessor<boolean>;
  canSave: Accessor<boolean>;
  hasFindings: Accessor<boolean>;
  rows: Accessor<ScriptRow[]>;
  /** The first `script.list` answered (or failed): until then "no scripts" would be a guess. */
  loaded: Accessor<boolean>;
  /**
   * How many scripts are enabled, or null while that is unknown: `script.list` is not offered, has not
   * answered yet, or has only failed. Never a made-up zero.
   */
  active: Accessor<number | null>;
  findings: Accessor<ScriptFindings>;
  /** A call is in flight; every control waits for it. */
  busy: Accessor<boolean>;
  name: Accessor<string>;
  setName: (v: string) => void;
  source: Accessor<string>;
  setSource: (v: string) => void;
  nameError: Accessor<string | null>;
  outcome: Accessor<Outcome | null>;
  /** Re-read `script.list` alone: all the sidebar's count needs. */
  refreshList: () => Promise<void>;
  /** Re-read the scripts and their findings. */
  refresh: () => Promise<void>;
  toggle: (row: ScriptRow) => Promise<void>;
  reload: (row: ScriptRow) => Promise<void>;
  validate: () => Promise<void>;
  save: () => Promise<void>;
}

/** Why authoring is off for an agent session; the core enforces it, the panel only explains it. */
export const AGENT_REASON = 'Agent session — the core refuses script authoring unless rhai.allow_agent_authoring is set. Connect as the operator to author.';

export const NAME_RULE = 'A name may contain only letters, digits, "_" and "-".';

const states = new WeakMap<AppStore, ScriptsStore>();

const messageOf = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export function scriptsStore(app: AppStore): ScriptsStore {
  let s = states.get(app);
  if (!s) {
    s = createRoot(() => build(app));
    states.set(app, s);
  }
  return s;
}

function build(app: AppStore): ScriptsStore {
  const has = (tool: string) => app.proxy.tools.some((t) => t.name === tool);
  const offered = createMemo(() => has('script.list'));
  // The role is read live (`null` = the server echoed none): only a known agent session is switched off,
  // so an unknown one still reaches the core and shows its answer. These are plain accessors, not memos,
  // so building the store (the sidebar does it for the count) reads neither the role nor the tool list
  // until a control actually asks.
  const agent = () => app.bus.role() === 'agent';
  const canToggle = () => !agent() && has('script.enable') && has('script.disable');
  const canReload = () => !agent() && has('script.reload');
  const canValidate = () => has('script.validate');
  const canSave = () => !agent() && has('script.save');
  const hasFindings = () => has('script.findings');

  // A keyed store, not a signal: a refresh after a click updates the rows in place, so the control
  // you just used keeps its DOM node (and its keyboard focus).
  const [rows, setRows] = createStore<ScriptRow[]>([]);
  const [loaded, setLoaded] = createSignal(false);
  const [listed, setListed] = createSignal(false);
  const [findings, setFindings] = createSignal<ScriptFindings>({ findings: [], dropped: 0 });
  const [busy, setBusy] = createSignal(false);
  const [name, setName] = createSignal('');
  const [source, setSource] = createSignal('');
  const [outcome, setOutcome] = createSignal<Outcome | null>(null);
  const nameError = createMemo(() => (name() !== '' && !isScriptName(name()) ? NAME_RULE : null));

  const active = createMemo(() => (offered() && listed() ? activeCount(rows) : null));

  async function refreshList(): Promise<void> {
    if (!offered()) return;
    await app.call('script.list').then(
      (raw) => {
        setRows(reconcile(parseScriptList(raw), { key: 'name' }));
        setListed(true);
      },
      (e) => app.notice(`script.list: ${messageOf(e)}`, 'error'),
    );
    setLoaded(true);
  }

  async function refresh(): Promise<void> {
    if (!offered()) return;
    const jobs: Promise<void>[] = [refreshList()];
    if (hasFindings()) {
      jobs.push(
        app.call('script.findings', { limit: FINDINGS_LIMIT }).then(
          (raw) => {
            setFindings(parseFindings(raw));
          },
          (e) => app.notice(`script.findings: ${messageOf(e)}`, 'error'),
        ),
      );
    }
    await Promise.all(jobs);
  }

  /** One row action: run it, surface a failure as a toast with the core's text, refresh after a success. */
  async function act(tool: string, args: Record<string, unknown>, done?: () => void): Promise<void> {
    if (busy()) return;
    setBusy(true);
    try {
      try {
        await app.call(tool, args);
      } catch (e) {
        app.notice(`${tool}: ${messageOf(e)}`, 'error');
        return;
      }
      done?.();
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  return {
    offered,
    agent,
    canToggle,
    canReload,
    canValidate,
    canSave,
    hasFindings,
    rows: () => rows,
    loaded,
    active,
    findings,
    busy,
    name,
    setName,
    source,
    setSource,
    nameError,
    outcome,
    refreshList,
    refresh,
    toggle: (row) => act(row.enabled ? 'script.disable' : 'script.enable', { name: row.name }),
    reload: (row) => act('script.reload', { name: row.name }, () => app.notice(`Reloaded ${row.name}`)),
    async validate() {
      const text = source();
      if (busy() || !canValidate() || text.trim() === '') return;
      setBusy(true);
      try {
        setOutcome({ kind: 'valid', report: parseReport(await app.call('script.validate', { source: text })) });
      } catch (e) {
        setOutcome({ kind: 'error', text: messageOf(e) });
      } finally {
        setBusy(false);
      }
    },
    async save() {
      const text = source();
      const n = name();
      // The name is re-checked here, not only on the button: Enter or a stale click must not reach the core.
      if (busy() || !canSave() || !isScriptName(n) || text.trim() === '') return;
      setBusy(true);
      try {
        setOutcome({ kind: 'saved', report: parseReport(await app.call('script.save', { name: n, source: text, enable: true })) });
      } catch (e) {
        setOutcome({ kind: 'error', text: messageOf(e) });
        return;
      } finally {
        setBusy(false);
      }
      await refresh();
    },
  };
}
