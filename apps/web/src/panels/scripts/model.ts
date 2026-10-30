// The wire shapes of the `script.*` commands (crates/aitm-plugin-rhai/src/commands.rs) and the pure
// helpers around them. Parsing is defensive: a partial or garbage payload degrades to empty rather
// than throwing in the panel, and nothing here invents a field the core does not send.

/** `script.list` → one row per loaded script, in chain order. */
export interface ScriptRow {
  name: string;
  path: string;
  /** The script API version it declares (`const API`). */
  api: string;
  /** The hook functions it defines, e.g. `on_request`. */
  hooks: string[];
  /** The live flag: a disabled script stays loaded but its hooks are skipped. */
  enabled: boolean;
  /** The most recent hook error, or null when the last runs were clean. */
  lastError: string | null;
}

export interface Registers {
  commands: string[];
  options: string[];
}

/**
 * What `script.validate` (no `path`, no `restart_required`) and `script.save` (both) report about a
 * script's text. `restartRequired` is null when the command does not carry the flag.
 */
export interface ScriptReport {
  name: string;
  api: string;
  hooks: string[];
  registers: Registers;
  path: string | null;
  restartRequired: boolean | null;
}

/** One finding a script emitted with `finding(...)`, from `script.findings`. */
export interface ScriptFinding {
  name: string;
  severity: string;
  flowId: string | null;
  detail: string | null;
  tags: string[];
  /** The script that emitted it. */
  source: string;
  /** Unix milliseconds. */
  at: number;
}

export interface ScriptFindings {
  /** Newest first. */
  findings: ScriptFinding[];
  /** How many the core's bounded sink dropped. */
  dropped: number;
}

/** How many findings the console shows (and asks the core for). */
export const FINDINGS_LIMIT = 50;

const SCRIPT_NAME = /^[A-Za-z0-9_-]+$/;

/**
 * Whether `name` is one `[A-Za-z0-9_-]+` path segment — the core's rule for `script.save`, checked
 * here first so a bad name is explained in place instead of after a round trip.
 */
export const isScriptName = (name: string): boolean => SCRIPT_NAME.test(name);

const obj = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {});
const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

/**
 * The rows of a `script.list` answer, or null when the answer is not a list at all: a malformed reply
 * is a failure to read, not "no scripts", and the caller must be able to tell the two apart.
 */
export function parseScriptList(raw: unknown): ScriptRow[] | null {
  if (!Array.isArray(raw)) return null;
  const rows: ScriptRow[] = [];
  for (const item of raw) {
    const o = obj(item);
    const name = str(o.name);
    // Every action addresses a script by name, so an entry without one cannot be shown usefully.
    if (!name) continue;
    rows.push({
      name,
      path: str(o.path),
      api: str(o.api),
      hooks: strings(o.hooks),
      enabled: o.enabled === true,
      lastError: typeof o.last_error === 'string' ? o.last_error : null,
    });
  }
  return rows;
}

export const activeCount = (rows: readonly ScriptRow[]): number => rows.filter((r) => r.enabled).length;

export function parseReport(raw: unknown): ScriptReport {
  const o = obj(raw);
  const registers = obj(o.registers);
  return {
    name: str(o.name),
    api: str(o.api),
    hooks: strings(o.hooks),
    registers: { commands: strings(registers.commands), options: strings(registers.options) },
    path: typeof o.path === 'string' ? o.path : null,
    restartRequired: typeof o.restart_required === 'boolean' ? o.restart_required : null,
  };
}

/** The core answers oldest first; the console wants the newest `limit` first. */
export function parseFindings(raw: unknown, limit = FINDINGS_LIMIT): ScriptFindings {
  const o = obj(raw);
  const list = Array.isArray(o.findings) ? o.findings : [];
  const findings: ScriptFinding[] = [];
  for (const item of list) {
    const f = obj(item);
    if (!f.name || typeof f.name !== 'string') continue;
    findings.push({
      name: f.name,
      severity: str(f.severity),
      flowId: typeof f.flow_id === 'string' && f.flow_id !== '' ? f.flow_id : null,
      detail: typeof f.detail === 'string' ? f.detail : null,
      tags: strings(f.tags),
      source: str(f.source),
      at: typeof f.at === 'number' ? f.at : 0,
    });
  }
  return {
    findings: findings.reverse().slice(0, limit),
    dropped: typeof o.dropped === 'number' && Number.isFinite(o.dropped) ? o.dropped : 0,
  };
}
