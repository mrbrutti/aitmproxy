import { describe, expect, it } from 'vitest';
import { FINDINGS_LIMIT, activeCount, isScriptName, parseFindings, parseReport, parseScriptList } from './model';

describe('isScriptName', () => {
  // The core's rule (crates/aitm-plugin-rhai/src/commands.rs `is_script_name`): one [A-Za-z0-9_-]+ segment.
  it('accepts letters, digits, underscore and hyphen', () => {
    expect(isScriptName('redact-auth')).toBe(true);
    expect(isScriptName('Tag_Admin9')).toBe(true);
    expect(isScriptName('-')).toBe(true);
  });

  it('rejects empty, spaces, dots, separators and non-ASCII', () => {
    for (const bad of ['', ' ', 'my script', 'a.rhai', '../etc', 'a/b', 'a\\b', 'café', 'a\nb', 'a\0b']) {
      expect(isScriptName(bad), JSON.stringify(bad)).toBe(false);
    }
  });
});

describe('parseScriptList', () => {
  it('reads one row per script in chain order', () => {
    const rows = parseScriptList([
      { name: 'a', path: '/s/a.rhai', api: '1', hooks: ['on_request', 'on_response'], enabled: true, last_error: null },
      { name: 'b', path: '/s/b.rhai', api: '1', hooks: [], enabled: false, last_error: 'on_response: boom (line 3)' },
    ]);
    expect(rows).toEqual([
      { name: 'a', path: '/s/a.rhai', api: '1', hooks: ['on_request', 'on_response'], enabled: true, lastError: null },
      { name: 'b', path: '/s/b.rhai', api: '1', hooks: [], enabled: false, lastError: 'on_response: boom (line 3)' },
    ]);
  });

  it('answers null, not an empty list, for anything that is not a list, so the caller can tell a malformed reply from "no scripts"', () => {
    expect(parseScriptList(null)).toBeNull();
    expect(parseScriptList(undefined)).toBeNull();
    expect(parseScriptList({})).toBeNull();
    expect(parseScriptList('nope')).toBeNull();
    expect(parseScriptList([])).toEqual([]); // a real, empty list
  });

  it('drops an entry it cannot act on and keeps the rest', () => {
    // An entry without a usable name cannot be acted on, so it is dropped; the rest survive.
    expect(parseScriptList([42, { name: '' }, { name: 'ok', enabled: 'yes', hooks: [1, 'on_request'], last_error: 7 }])).toEqual([
      { name: 'ok', path: '', api: '', hooks: ['on_request'], enabled: false, lastError: null },
    ]);
  });
});

describe('activeCount', () => {
  it('counts the enabled scripts', () => {
    const row = (enabled: boolean) => ({ name: 'x', path: '', api: '1', hooks: [], enabled, lastError: null });
    expect(activeCount([row(true), row(false), row(true)])).toBe(2);
    expect(activeCount([])).toBe(0);
  });
});

describe('parseReport', () => {
  it('reads a script.validate answer (no path for source, no restart flag)', () => {
    expect(parseReport({ name: 'probe', api: '1', hooks: ['on_request'], registers: { commands: ['probe.run'], options: ['probe.depth'] } })).toEqual({
      name: 'probe',
      api: '1',
      hooks: ['on_request'],
      registers: { commands: ['probe.run'], options: ['probe.depth'] },
      path: null,
      restartRequired: null,
    });
  });

  it('reads a script.save answer including restart_required', () => {
    expect(
      parseReport({ name: 'probe', path: '/s/probe.rhai', api: '1', hooks: [], registers: { commands: [], options: [] }, restart_required: true }),
    ).toEqual({ name: 'probe', api: '1', hooks: [], registers: { commands: [], options: [] }, path: '/s/probe.rhai', restartRequired: true });
  });

  it('tolerates missing registers', () => {
    expect(parseReport({ name: 'x', api: '1', hooks: ['on_request'] }).registers).toEqual({ commands: [], options: [] });
    expect(parseReport(null).name).toBe('');
  });
});

describe('parseFindings', () => {
  const finding = (n: number) => ({ name: `f${n}`, severity: 'low', flow_id: null, detail: null, tags: [], source: 's', at: n });

  it('lists newest first and carries the dropped count', () => {
    const r = parseFindings({ findings: [finding(1), finding(2), finding(3)], dropped: 4 });
    expect(r.findings.map((f) => f.name)).toEqual(['f3', 'f2', 'f1']);
    expect(r.dropped).toBe(4);
  });

  it('bounds the list to the newest 50', () => {
    const many = Array.from({ length: 60 }, (_, i) => finding(i));
    const r = parseFindings({ findings: many, dropped: 0 });
    expect(FINDINGS_LIMIT).toBe(50);
    expect(r.findings).toHaveLength(50);
    expect(r.findings[0]!.name).toBe('f59');
    expect(r.findings[49]!.name).toBe('f10');
  });

  it('reads every finding field and survives garbage', () => {
    const r = parseFindings({
      findings: [{ name: 'Open redirect', severity: 'high', flow_id: 'flow_9', detail: 'Location echoes ?next', tags: ['redirect'], source: 'probe', at: 1700000000000 }, 'junk'],
      dropped: 'x',
    });
    expect(r.findings[0]).toEqual({
      name: 'Open redirect',
      severity: 'high',
      flowId: 'flow_9',
      detail: 'Location echoes ?next',
      tags: ['redirect'],
      source: 'probe',
      at: 1700000000000,
    });
    expect(r.dropped).toBe(0);
    expect(parseFindings(null)).toEqual({ findings: [], dropped: 0 });
  });
});
