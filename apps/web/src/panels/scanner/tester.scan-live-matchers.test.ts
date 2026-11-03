// Stage-5 Tester (Jobs view Task 3.12 C): the pure matchers of `scripts/scan-live.mjs`, which the
// live proof cannot test where it runs (it needs ports and a core), pinned here with the 48 literals
// the script's `--selfcheck` used to hold, plus the Task 3.12 C additions (the token redaction, the
// dead-port guard's config ports) and a sweep proving the `.mjs` copies of `grouped` / `fmtElapsed`
// equal `helpers.ts`'s value for value. The module is loaded by URL at run time, the way
// `tester.live-env.test.ts` loads `live-env.mjs`, so the app's type-check never sees it.
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { fmtElapsed, grouped } from './helpers';

const here = dirname(fileURLToPath(import.meta.url));
const MATCHERS = `file://${resolve(here, '../../../scripts/scan-live-matchers.mjs')}`;

interface Matchers {
  TERMINAL: Set<string>;
  parseProbesText(text: unknown): { sent: number; budget: number } | null;
  phaseWord(words: unknown): string | null;
  terminalWord(words: unknown): string | null;
  CANCEL_WORDS: RegExp;
  CANCELLED_WORD: RegExp;
  ROW_PROGRESS_AUDITING: RegExp;
  PERCENT_TEXT: RegExp;
  CANCELLED_SENTENCE: RegExp;
  ATTENTION_ERRORS: RegExp;
  STOPPED_ERRORS_SENTENCE: string;
  RAW_ERRORS_LINE: string;
  grouped(n: number): string;
  ungroup(text: unknown): number;
  fmtElapsed(ms: number): string;
  elapsedSeconds(text: unknown): number;
  cancelLinesFor(text: unknown, job: string): string[];
  auditLogLines(configText: unknown): { mcp: string | null; ca: string | null };
  auditLogPath(line: unknown): string | null;
  insideDir(path: unknown, dir: string): boolean;
  strayErrorsTokens(cardText: unknown): number;
  sameDigests(a: Record<string, { size: unknown; sha256: unknown }>, b: Record<string, { size: unknown; sha256: unknown }>): boolean;
  shellQuote(text: unknown): string;
  redactOperatorUrl(url: unknown): string;
  listenPortsIn(configText: unknown): number[];
  portClashes(port: unknown, named: Record<string, unknown>): string[];
}

const matchers = async (): Promise<Matchers> => (await import(/* @vite-ignore */ MATCHERS)) as Matchers;

const AUDIT_FIXTURE = [
  '{"at":1,"origin":"operator","client_label":null,"connection_id":"c1","command":"scan.cancel","args":"{\\"job\\":\\"scan-1a2b3c4d\\"}","result":"ok"}',
  '{"at":2,"origin":"operator","client_label":null,"connection_id":"c1","command":"scan.status","args":"{\\"job\\":\\"scan-1a2b3c4d\\"}","result":"ok"}',
  '{"at":3,"origin":"operator","client_label":null,"connection_id":"c1","command":"scan.cancel","args":"{\\"job\\":\\"scan-ffffffff\\"}","result":"ok"}',
  'not json at all scan.cancel scan-1a2b3c4d',
  '',
].join('\n');
const CONFIG_FIXTURE = [
  'listen: 127.0.0.1:1',
  'ca:',
  '  audit_log: "/tmp/run/ca-audit.jsonl"',
  'mcp:',
  '  operator_token: x',
  '  audit_log: "/tmp/run/audit.jsonl"',
  '  transport:',
  '    loopback_tcp:',
  '      port: 0',
  '',
].join('\n');
const CARD_FIXTURE =
  'Done Stopped early: too many errors from the target. 7 checks could not run The crawl fetched 0 pages and hit 2 errors stopped_reason: errors crawl.last_error: connect_refused';

describe('tester: scan-live matchers, the 48 selfcheck literals (gap 56, Task 3.12 C)', () => {
  it('parseProbesText reads the W2 `287 of 2,000` and the legacy `418/2000`, null otherwise', async () => {
    const m = await matchers();
    expect(m.parseProbesText('287 of 2,000')).toEqual({ sent: 287, budget: 2000 });
    expect(m.parseProbesText('418/2000')).toEqual({ sent: 418, budget: 2000 });
    expect(m.parseProbesText('287 probes')).toBeNull();
    expect(m.parseProbesText(null)).toBeNull();
  });

  it('phaseWord and terminalWord lowercase the glossary words and keep the legacy `running · crawling` tail', async () => {
    const m = await matchers();
    expect(m.phaseWord('Auditing')).toBe('auditing');
    expect(m.phaseWord('Done')).toBe('done');
    expect(m.phaseWord('running · crawling')).toBe('crawling');
    expect(m.phaseWord('')).toBeNull();
    expect(m.terminalWord('Done')).toBe('done');
    expect(m.terminalWord('Cancelled')).toBe('cancelled');
    expect(m.terminalWord('Auditing')).toBeNull();
    expect([...m.TERMINAL].sort()).toEqual(['cancelled', 'done', 'failed']);
  });

  it('the cancel words match case-insensitively; CANCELLED_WORD rejects Cancelling', async () => {
    const m = await matchers();
    expect(m.CANCEL_WORDS.test('Cancelling')).toBe(true);
    expect(m.CANCEL_WORDS.test('Cancelled')).toBe(true);
    expect(m.CANCELLED_WORD.test('Cancelled')).toBe(true);
    expect(m.CANCELLED_WORD.test('Cancelling')).toBe(false);
  });

  it('the row progress and KPI percent require U+00A0 before %', async () => {
    const m = await matchers();
    expect(m.ROW_PROGRESS_AUDITING.exec('50\u00a0% · 3,236 of 6,468')?.slice(1)).toEqual(['50', '3,236', '6,468']);
    expect(m.ROW_PROGRESS_AUDITING.test('50 % · 3,236 of 6,468')).toBe(false);
    expect(m.PERCENT_TEXT.exec('50\u00a0%')?.[1]).toBe('50');
  });

  it('the D4 cancelled sentence and the D9 attention line, singular and plural, and their rejections', async () => {
    const m = await matchers();
    expect(m.CANCELLED_SENTENCE.exec('Cancelled after 1:55; 3,236 of 6,468 checks had run. What it found stays.')?.slice(1)).toEqual(['1:55', '3,236', '6,468']);
    expect(m.CANCELLED_SENTENCE.exec('Cancelled after 0:03; 0 of 1 check had run. What it found stays.')?.slice(1)).toEqual(['0:03', '0', '1']);
    expect(m.CANCELLED_SENTENCE.test('Done in 1:09 · 1,020 points · 6,468 checks.')).toBe(false);
    expect(m.ATTENTION_ERRORS.exec('7 checks could not run')?.[1]).toBe('7');
    expect(m.ATTENTION_ERRORS.exec('1 check could not run')?.[1]).toBe('1');
    expect(m.ATTENTION_ERRORS.test('3 checks were skipped')).toBe(false);
    expect(m.STOPPED_ERRORS_SENTENCE).toBe('Stopped early: too many errors from the target.');
    expect(m.RAW_ERRORS_LINE).toBe('stopped_reason: errors');
  });

  it('the number words: ungroup, grouped, fmtElapsed, elapsedSeconds', async () => {
    const m = await matchers();
    expect(m.ungroup('6,468')).toBe(6468);
    expect(m.grouped(6468)).toBe('6,468');
    expect(m.fmtElapsed(115000)).toBe('1:55');
    expect(m.fmtElapsed(3999)).toBe('0:03');
    expect(m.elapsedSeconds('1:55')).toBe(115);
  });

  it('cancelLinesFor counts the scan.cancel lines naming the job, JSON or not', async () => {
    const m = await matchers();
    expect(m.cancelLinesFor(AUDIT_FIXTURE, 'scan-1a2b3c4d')).toHaveLength(2);
    expect(m.cancelLinesFor(AUDIT_FIXTURE.split('\n').slice(0, 3).join('\n'), 'scan-1a2b3c4d')).toHaveLength(1);
    expect(m.cancelLinesFor(AUDIT_FIXTURE, 'scan-ffffffff')).toHaveLength(1);
    expect(m.cancelLinesFor(AUDIT_FIXTURE, 'scan-00000000')).toHaveLength(0);
  });

  it('auditLogLines, auditLogPath and insideDir judge the written config (gap 57)', async () => {
    const m = await matchers();
    expect(m.auditLogLines(CONFIG_FIXTURE).mcp).toBe('  audit_log: "/tmp/run/audit.jsonl"');
    expect(m.auditLogLines(CONFIG_FIXTURE).ca).toBe('  audit_log: "/tmp/run/ca-audit.jsonl"');
    expect(m.auditLogLines('mcp:\n  operator_token: x\n')).toEqual({ mcp: null, ca: null });
    expect(m.auditLogPath('  audit_log: "/tmp/run/audit.jsonl"')).toBe('/tmp/run/audit.jsonl');
    expect(m.auditLogPath('  audit_log: /tmp/run/audit.jsonl')).toBe('/tmp/run/audit.jsonl');
    expect(m.auditLogPath(null)).toBeNull();
    expect(m.insideDir('/tmp/run/audit.jsonl', '/tmp/run')).toBe(true);
    expect(m.insideDir('/tmp/run2/audit.jsonl', '/tmp/run')).toBe(false);
    expect(m.insideDir(null, '/tmp/run')).toBe(false);
  });

  it('strayErrorsTokens counts the `errors` tokens outside the D4 and crawl sentences (AC58 (c))', async () => {
    const m = await matchers();
    expect(m.strayErrorsTokens(CARD_FIXTURE)).toBe(1);
    expect(m.strayErrorsTokens(CARD_FIXTURE + ' errors')).toBe(2);
    expect(m.strayErrorsTokens('Stopped early: too many errors from the target. hit 1 error')).toBe(0);
  });

  it('sameDigests and shellQuote', async () => {
    const m = await matchers();
    expect(m.sameDigests({ a: { size: 1, sha256: 'x' } }, { a: { size: 1, sha256: 'x' } })).toBe(true);
    expect(m.sameDigests({ a: { size: 1, sha256: 'x' } }, { a: { size: 2, sha256: 'y' } })).toBe(false);
    expect(m.shellQuote("/a b/it's")).toBe("'/a b/it'\\''s'");
  });
});

describe('tester: scan-live matchers, Task 3.12 C additions', () => {
  it('redactOperatorUrl hides the bridge token and keeps the rest of the URL (the `aitm up` and `--keep` lines)', async () => {
    const m = await matchers();
    expect(m.redactOperatorUrl('http://127.0.0.1:8082/#t=op-bridge-token&expect=operator')).toBe('http://127.0.0.1:8082/#t=<redacted>&expect=operator');
    expect(m.redactOperatorUrl('http://127.0.0.1:8082/#t=legacy-token')).toBe('http://127.0.0.1:8082/#t=<redacted>');
    expect(m.redactOperatorUrl('http://127.0.0.1:8082/')).toBe('http://127.0.0.1:8082/');
    expect(m.redactOperatorUrl('http://127.0.0.1:8082/#t=op-bridge-token&expect=operator')).not.toContain('op-bridge-token');
  });

  it('listenPortsIn reads the `key: 127.0.0.1:<port>` lines of the written config (the browser proxy port is only there), never the scope entries', async () => {
    const m = await matchers();
    const cfg = ['listen: 127.0.0.1:50001', 'browser:', '  proxy_addr: 127.0.0.1:50002', 'scope:', '  entries:', '    - "127.0.0.1:50003"', '    - "127.0.0.1:50009"', 'mcp:', '  transport:', '    loopback_tcp:', '      port: 0', ''].join('\n');
    expect(m.listenPortsIn(cfg)).toEqual([50001, 50002]);
    expect(m.listenPortsIn('listen: 127.0.0.1:7\nbrowser:\n  proxy_addr: 127.0.0.1:7\n')).toEqual([7]);
    expect(m.listenPortsIn('')).toEqual([]);
    expect(m.listenPortsIn(null)).toEqual([]);
  });

  it('portClashes names every port that equals the dead port, none when it is distinct', async () => {
    const m = await matchers();
    expect(m.portClashes(50002, { proxy: 50001, 'browser proxy': 50002, web: 50003, target: 50002 })).toEqual(['browser proxy', 'target']);
    expect(m.portClashes(50009, { proxy: 50001, 'browser proxy': 50002, web: 50003, target: 50004 })).toEqual([]);
    expect(m.portClashes(null, { proxy: 50001 })).toEqual([]);
  });
});

describe('tester: the .mjs grouped / fmtElapsed equal helpers.ts (the sweep)', () => {
  it('grouped agrees over [0, 1, 999, 1000, 6468, 1234567]', async () => {
    const m = await matchers();
    for (const n of [0, 1, 999, 1000, 6468, 1234567]) expect(m.grouped(n), `grouped(${n})`).toBe(grouped(n));
    expect(grouped(1234567)).toBe('1,234,567');
  });

  it('fmtElapsed agrees over [0, 1000, 61000, 3599000, 3600000, 5124095576030000] ms', async () => {
    const m = await matchers();
    for (const ms of [0, 1000, 61000, 3599000, 3600000, 5124095576030000]) expect(m.fmtElapsed(ms), `fmtElapsed(${ms})`).toBe(fmtElapsed(ms));
    expect(fmtElapsed(3599000)).toBe('59:59');
    expect(fmtElapsed(3600000)).toBe('1:00:00');
  });
});
