import { describe, expect, it } from 'vitest';
import type { ActivityEntry } from '~/state/app';
import { atMs, filterActivity, fullArgs, originLabel, summarizeArgs } from './activity';

const entry = (seq: number, p: Partial<ActivityEntry> = {}): ActivityEntry => ({
  seq,
  at: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
  origin: 'web',
  command: 'flow.list',
  result: 'ok',
  ...p,
});

const LOG: ActivityEntry[] = [
  entry(1, { origin: 'mcp', command: 'flow.replay', args: { id: 'f_1k' } }),
  entry(2, { origin: 'web', command: 'flow.kill', args: { id: 'f_2', mode: '429' } }),
  entry(3, { origin: 'cli', command: 'scope.add', args: { host: 'x.test' }, result: 'error', detail: 'refused' }),
  entry(4, { origin: 'mcp', command: 'ca.install', result: 'error', detail: 'agent paused by operator' }),
  entry(5, { origin: 'tui', command: 'flow.list' }),
];

const ids = (l: ActivityEntry[]) => l.map((e) => e.seq);

describe('filterActivity', () => {
  it('returns newest first with no filter', () => {
    expect(ids(filterActivity(LOG, { kind: 'all', query: '', clearedThrough: 0 }))).toEqual([5, 4, 3, 2, 1]);
  });
  it('Agent keeps mcp rows; Human keeps every other frontend', () => {
    expect(ids(filterActivity(LOG, { kind: 'agent', query: '', clearedThrough: 0 }))).toEqual([4, 1]);
    expect(ids(filterActivity(LOG, { kind: 'human', query: '', clearedThrough: 0 }))).toEqual([5, 3, 2]);
  });
  it('Errors keeps failed calls from any origin', () => {
    expect(ids(filterActivity(LOG, { kind: 'errors', query: '', clearedThrough: 0 }))).toEqual([4, 3]);
  });
  it('search matches command, origin label, args and detail, case-insensitively', () => {
    expect(ids(filterActivity(LOG, { kind: 'all', query: 'KILL', clearedThrough: 0 }))).toEqual([2]);
    expect(ids(filterActivity(LOG, { kind: 'all', query: 'agent', clearedThrough: 0 }))).toEqual([4, 1]);
    expect(ids(filterActivity(LOG, { kind: 'all', query: 'x.test', clearedThrough: 0 }))).toEqual([3]);
    expect(ids(filterActivity(LOG, { kind: 'all', query: 'refused', clearedThrough: 0 }))).toEqual([3]);
  });
  it('Clear view hides everything up to the cleared seq but keeps later entries', () => {
    expect(ids(filterActivity(LOG, { kind: 'all', query: '', clearedThrough: 3 }))).toEqual([5, 4]);
  });
});

describe('summarizeArgs / fullArgs / labels', () => {
  it('compacts arguments to one JSON line and blanks empties', () => {
    expect(summarizeArgs({ id: 'f_2', mode: '429' })).toBe('{"id":"f_2","mode":"429"}');
    expect(summarizeArgs(['a', 1])).toBe('["a",1]');
    expect(summarizeArgs(undefined)).toBe('');
    expect(summarizeArgs(null)).toBe('');
    expect(summarizeArgs({})).toBe('');
    expect(summarizeArgs([])).toBe('');
    expect(summarizeArgs('plain')).toBe('"plain"');
  });
  it('indents the hover form', () => {
    expect(fullArgs({ id: 'f_2' })).toBe('{\n  "id": "f_2"\n}');
    expect(fullArgs(undefined)).toBe('');
  });
  it('labels mcp as agent and parses timestamps safely', () => {
    expect(originLabel('mcp')).toBe('agent');
    expect(originLabel('web')).toBe('web');
    expect(atMs({ at: '2026-10-27T10:00:00.000Z' })).toBe(Date.parse('2026-10-27T10:00:00.000Z'));
    expect(atMs({ at: 'garbage' })).toBeNull();
  });
});
