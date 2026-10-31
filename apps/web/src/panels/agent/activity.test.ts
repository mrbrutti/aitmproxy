import { describe, expect, it } from 'vitest';
import type { ActivityEntry } from '~/state/app';
import { UI_BACKGROUND_READS, atMs, filterActivity, fullArgs, isUiPollNoise, originLabel, ownOriginOf, summarizeArgs } from './activity';

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

// The flood rule (push spec D7): a line is this UI's own background read, and dropped, only when
// it succeeded, names one of the reads the UI issues on timers, and came from us — labelled
// `aitm-web`, or unlabelled (the bridge does not label its connections) from our own origin.
describe('isUiPollNoise / ownOriginOf', () => {
  const own = { origin: 'operator' } as const;
  const ownRead = { origin: 'operator', clientLabel: null, command: 'flow.list', result: 'ok' } as const;

  it('isUiPollNoise matrix', () => {
    // (1) our origin, unlabelled, a successful background read: noise.
    expect(isUiPollNoise(ownRead, own)).toBe(true);
    // (2) the label absent rather than null is the same thing.
    expect(isUiPollNoise({ origin: 'operator', command: 'flow.list', result: 'ok' }, own)).toBe(true);
    // (3) a labelled bridge would say `aitm-web`: ours from any origin.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: 'aitm-web', command: 'flow.detail', result: 'ok' }, own)).toBe(true);
    // (4) an action from our origin is what the panel exists to show.
    expect(isUiPollNoise({ ...ownRead, command: 'flow.kill' }, own)).toBe(false);
    // (5) a failing poll is signal.
    expect(isUiPollNoise({ ...ownRead, result: 'error' }, own)).toBe(false);
    // (6) a real agent labels itself; never ours.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: 'claude-code', command: 'flow.list', result: 'ok' }, own)).toBe(false);
    // (7) an unlabelled read from another origin is somebody else's.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: null, command: 'flow.list', result: 'ok' }, own)).toBe(false);
    // (8) an unknown own origin matches nothing by origin.
    expect(isUiPollNoise(ownRead, { origin: null })).toBe(false);
    // (9) …but when we run on the agent token, our origin is `mcp`.
    expect(isUiPollNoise({ origin: 'mcp', clientLabel: null, command: 'flow.list', result: 'ok' }, { origin: 'mcp' })).toBe(true);
    // (10) another frontend's polling is that frontend's activity.
    expect(isUiPollNoise({ ...ownRead, clientLabel: 'aitm-mac' }, own)).toBe(false);
    // Every background read is covered; a navigation is an action.
    for (const command of UI_BACKGROUND_READS) expect(isUiPollNoise({ ...ownRead, command }, own), command).toBe(true);
    expect(isUiPollNoise({ ...ownRead, command: 'browser.navigate' }, own)).toBe(false);
    expect([...UI_BACKGROUND_READS].sort()).toEqual(
      [
        'flow.list',
        'flow.get',
        'flow.detail',
        'proxy.status',
        'agent.status',
        'agent.activity',
        'scope.list',
        'poc.list',
        'l4.flow.list',
        'l4.flow.get',
        'l4.scope.list',
        'l4.capture.status',
        'l4.agent.status',
        'l4.intercept.status',
        'l4.intercept.list',
        'browser.tabs',
        'browser.screenshot',
      ].sort(),
    );
  });

  it('ownOriginOf maps roles', () => {
    expect(ownOriginOf('operator')).toBe('operator');
    expect(ownOriginOf('agent')).toBe('mcp');
    expect(ownOriginOf(null)).toBeNull();
  });
});
