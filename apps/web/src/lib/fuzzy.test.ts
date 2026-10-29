import { describe, expect, it } from 'vitest';
import { fuzzyMatch, fuzzyRank, segments } from './fuzzy';

describe('fuzzyMatch', () => {
  it('returns null when the query is not a subsequence', () => {
    expect(fuzzyMatch('xyz', 'flow.replay')).toBeNull();
    expect(fuzzyMatch('replayy', 'flow.replay')).toBeNull();
  });

  it('matches an empty query with score 0', () => {
    expect(fuzzyMatch('', 'anything')).toEqual({ score: 0, indices: [] });
  });

  it('returns ascending indices into the original text, case-insensitively', () => {
    const m = fuzzyMatch('FR', 'flow.replay');
    expect(m).not.toBeNull();
    expect(m!.indices).toEqual([0, 5]);
  });

  it('prefers word starts over mid-word letters', () => {
    // "fr" could match f(0) + r(5, word start) or f(0) + r(8, mid-word).
    expect(fuzzyMatch('fr', 'flow.replay')!.indices).toEqual([0, 5]);
    // "ca" in "scope.add" vs "ca.install": the word-start match wins.
    expect(fuzzyMatch('ca', 'ca.install')!.score).toBeGreaterThan(fuzzyMatch('ca', 'scope.add')!.score);
  });

  it('rewards contiguous runs over scattered letters', () => {
    const contiguous = fuzzyMatch('play', 'flow.replay')!;
    const scattered = fuzzyMatch('play', 'proxy.pause.delay')!;
    expect(contiguous.score).toBeGreaterThan(scattered.score);
    expect(contiguous.indices).toEqual([7, 8, 9, 10]);
  });

  it('boosts an exact prefix', () => {
    expect(fuzzyMatch('flow', 'flow.kill')!.score).toBeGreaterThan(fuzzyMatch('flow', 'reflow.kill')!.score);
  });
});

describe('fuzzyRank', () => {
  const tools = [
    { name: 'flow.replay', description: 'Send a captured request again.' },
    { name: 'request.send', description: 'Send a crafted request through the proxy.' },
    { name: 'flow.resume', description: 'Release a paused flow to upstream.' },
    { name: 'ca.install', description: 'Install the root CA into a trust store.' },
  ];
  const fields = (t: (typeof tools)[number]) => [t.name, t.description];

  it('keeps original order and matches nothing for an empty query', () => {
    const r = fuzzyRank(tools, '', fields);
    expect(r.map((x) => x.item.name)).toEqual(tools.map((t) => t.name));
    expect(r[0]!.matches).toEqual([null, null]);
  });

  it('ranks a name match above a description-only match', () => {
    const r = fuzzyRank(tools, 'send', fields);
    expect(r[0]!.item.name).toBe('request.send');
    expect(r.map((x) => x.item.name)).toContain('flow.replay'); // "Send a captured…"
    expect(r[0]!.matches[0]).toEqual([8, 9, 10, 11]);
  });

  it('drops items that match no field', () => {
    const r = fuzzyRank(tools, 'zzz', fields);
    expect(r).toEqual([]);
  });

  it('puts the best fuzzy candidate first', () => {
    const r = fuzzyRank(tools, 'frp', fields);
    expect(r[0]!.item.name).toBe('flow.replay');
  });
});

describe('segments', () => {
  it('splits text into alternating plain and hit runs', () => {
    expect(segments('flow.replay', [0, 5, 6])).toEqual([
      { text: 'f', hit: true },
      { text: 'low.', hit: false },
      { text: 're', hit: true },
      { text: 'play', hit: false },
    ]);
  });
  it('returns the whole text when there are no indices', () => {
    expect(segments('abc', null)).toEqual([{ text: 'abc', hit: false }]);
  });
});
