import { describe, expect, it } from 'vitest';
import { exportFilename, fileStamp, slugify } from './export';
import { fmtWhen, filterRuns, matchedCount, parseVars, sortNewest, varsFromYaml } from './model';
import type { PocRun } from '~/bus/types';

const at = new Date(2026, 9, 27, 11, 5).getTime();

describe('exportFilename', () => {
  it('slugs the title and stamps the run time', () => {
    expect(exportFilename({ title: 'Reflected XSS in search', at, poc_path: '/x/y.yaml' }, 'yaml')).toBe('reflected-xss-in-search-20261027-1105.yaml');
    expect(exportFilename({ title: 'Reflected XSS in search', at, poc_path: '/x/y.yaml' }, 'png')).toBe('reflected-xss-in-search-20261027-1105.png');
  });
  it('falls back to the PoC file name, then to "finding"', () => {
    expect(exportFilename({ title: '', at, poc_path: '/Users/matt/aitm/poc/login-rate-limit.yaml' }, 'yaml')).toBe('login-rate-limit-20261027-1105.yaml');
    expect(exportFilename({ title: '   ', at, poc_path: '' }, 'png')).toBe('finding-20261027-1105.png');
  });
  it('strips accents and punctuation', () => {
    expect(slugify('Überlange Überschrift — mit: Zeichen!')).toBe('uberlange-uberschrift-mit-zeichen');
    expect(fileStamp(at)).toBe('20261027-1105');
  });
});

const run = (over: Partial<PocRun>): PocRun => ({
  id: 'p',
  title: 't',
  severity: 'low',
  target: 'https://a.test',
  passed: true,
  at: 0,
  origin: 'human',
  poc_path: '/p.yaml',
  yaml: '',
  finding_capture: '',
  screenshot_path: null,
  evaluated: [],
  ...over,
});

describe('model', () => {
  it('sorts newest first and filters by severity and text', () => {
    const runs = [run({ id: 'a', at: 1, severity: 'low' }), run({ id: 'b', at: 3, severity: 'high', title: 'XSS' }), run({ id: 'c', at: 2, severity: 'high', target: 'https://auth.test' })];
    expect(sortNewest(runs).map((r) => r.id)).toEqual(['b', 'c', 'a']);
    expect(filterRuns(runs, '', new Set(['high'])).map((r) => r.id)).toEqual(['b', 'c']);
    expect(filterRuns(runs, 'auth', new Set()).map((r) => r.id)).toEqual(['c']);
    expect(filterRuns(runs, 'xss', new Set(['low'])).map((r) => r.id)).toEqual([]);
  });
  it('counts matched assertions', () => {
    expect(matchedCount([{ assertion: 'a', matched: true }, { assertion: 'b', matched: false }])).toEqual({ matched: 1, total: 2 });
    expect(matchedCount(undefined)).toEqual({ matched: 0, total: 0 });
  });
  it('formats "when" relative within a day, then as a date', () => {
    const now = at;
    expect(fmtWhen(now - 10_000, now)).toBe('just now');
    expect(fmtWhen(now - 4 * 60_000, now)).toBe('4 min ago');
    expect(fmtWhen(now - 3 * 3_600_000, now)).toBe('3 h ago');
    expect(fmtWhen(now - 2 * 86_400_000, now)).toBe('25 Oct 11:05');
    expect(fmtWhen(null, now)).toBeNull();
  });
  it('round-trips vars as key=value lines', () => {
    expect(parseVars('a=1\n\n# c\nb = two words\nbad')).toEqual({ a: '1', b: 'two words' });
    expect(varsFromYaml('name: x\nvars:\n  host: a.test\n  token: "abc"\nsteps:\n  - x: 1')).toEqual({ host: 'a.test', token: 'abc' });
  });
});
