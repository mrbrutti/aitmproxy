// Web live-harness audit-log isolation (spec 2026-11-02-web-harness-audit-log-isolation, AC1–AC5):
// `renderConfig` gains `auditLogDir`, which points the core's general audit log and CA audit log
// into the run's own dir, `assertAuditLogIsolated` refuses a written config that does not carry
// both lines, and `startAitm` wires both in and fails closed on an inherited `AITM_AUDIT_LOG`.
// The script is loaded by file URL exactly as `tester.live-env.test.ts` does.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

// `@types/node` is deliberately absent from apps/web (see `types-node-test.d.ts`); the AC5 tests
// set and restore the inherited variable, so `process` is declared locally as `args.test.ts` does.
declare const process: { env: Record<string, string | undefined> };

const here = dirname(fileURLToPath(import.meta.url));
const LIVE_ENV_PATH = resolve(here, '../../../scripts/live-env.mjs');
const LIVE_ENV = `file://${LIVE_ENV_PATH}`;

interface LiveEnv {
  renderConfig(opts: Record<string, unknown>): string;
  assertAuditLogIsolated(cfgPath: string, runDir: string): void;
  startAitm(opts: Record<string, unknown>): Promise<unknown>;
}

const liveEnv = async (): Promise<LiveEnv> => (await import(/* @vite-ignore */ LIVE_ENV)) as LiveEnv;

const BASE = { proxyPort: 1, browserProxyPort: 2, pocDir: '/p', pocOut: '/o', operatorSecret: 'opsecret-x', token: 'live-y' };

/** AC1: today's document, pinned byte for byte. */
const AC1_DOC =
  'listen: 127.0.0.1:1\nbrowser:\n  proxy_addr: 127.0.0.1:2\nscope:\n  allow_agent_widen: true\npoc:\n  dir: /p\n  out_dir: /o\nmcp:\n  operator_token: opsecret-x\n  transport:\n    loopback_tcp:\n      port: 0\n      token: live-y-mcp\n';

/** AC2: the isolated document for `auditLogDir: '/r/run'`. */
const AC2_DOC =
  'listen: 127.0.0.1:1\nbrowser:\n  proxy_addr: 127.0.0.1:2\nscope:\n  allow_agent_widen: true\npoc:\n  dir: /p\n  out_dir: /o\nca:\n  audit_log: "/r/run/ca-audit.jsonl"\nmcp:\n  operator_token: opsecret-x\n  audit_log: "/r/run/audit.jsonl"\n  transport:\n    loopback_tcp:\n      port: 0\n      token: live-y-mcp\n';

// One temp dir for the whole file, removed when it ends; each written document gets its own name.
let docDir = '';
let docCount = 0;
beforeAll(() => {
  docDir = mkdtempSync(join(tmpdir(), 'live-env-audit-'));
});
afterAll(() => {
  rmSync(docDir, { recursive: true, force: true });
});

/** Writes `doc` to a fresh file under the test's temp dir and returns its path. */
function writeDoc(doc: string): string {
  const path = join(docDir, `config-${++docCount}.yaml`);
  writeFileSync(path, doc);
  return path;
}

/** The source text of `startAitm` (from its `export` to the next top-level `export`), for the AC5 pins. */
function startAitmSource(): string {
  const src = readFileSync(LIVE_ENV_PATH, 'utf8');
  const start = src.indexOf('export async function startAitm(');
  const end = start < 0 ? -1 : src.indexOf('\nexport ', start + 1);
  if (start < 0 || end < 0) throw new Error(`startAitm not found in ${LIVE_ENV_PATH}`);
  return src.slice(start, end);
}

/** Runs `fn` with `AITM_AUDIT_LOG` set to `value` (deleted when `undefined`), restoring the inherited value after. */
async function withInheritedAuditLog(value: string | undefined, fn: () => Promise<void>): Promise<void> {
  const saved = process.env.AITM_AUDIT_LOG;
  try {
    if (value === undefined) delete process.env.AITM_AUDIT_LOG;
    else process.env.AITM_AUDIT_LOG = value;
    await fn();
  } finally {
    if (saved === undefined) delete process.env.AITM_AUDIT_LOG;
    else process.env.AITM_AUDIT_LOG = saved;
  }
}

/** Silences `console.error` for one test and hands back the spy; `afterEach` restores it. */
const spyConsoleError = () => vi.spyOn(console, 'error').mockImplementation(() => {});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('live-env renderConfig auditLogDir (AC1–AC3)', () => {
  it("without auditLogDir the document is byte-identical to today's", async () => {
    const { renderConfig } = await liveEnv();
    expect(renderConfig(BASE)).toBe(AC1_DOC);
    expect(renderConfig({ ...BASE, auditLogDir: null })).toBe(AC1_DOC);
  });

  it('auditLogDir adds ca.audit_log before mcp and mcp.audit_log after operator_token', async () => {
    const { renderConfig } = await liveEnv();
    expect(renderConfig({ ...BASE, auditLogDir: '/r/run' })).toBe(AC2_DOC);
    expect(renderConfig({ ...BASE, auditLogDir: '/r/run', scanner: { max_jobs: 2 } })).toContain(
      'scanner:\n  max_jobs: 2\nca:\n  audit_log: "/r/run/ca-audit.jsonl"\nmcp:\n',
    );
  });

  it('a relative auditLogDir is refused', async () => {
    const { renderConfig } = await liveEnv();
    expect(() => renderConfig({ ...BASE, auditLogDir: 'rel/run' })).toThrow(
      'live-env: auditLogDir must be an absolute path; got "rel/run"',
    );
  });

  it('a control or Unicode line-break character in auditLogDir is refused without echoing it', async () => {
    const { renderConfig } = await liveEnv();
    // `JSON.stringify` writes U+2028, U+2029 and U+0085 literally and libyaml folds them to a space
    // inside a double-quoted scalar, so the guard and the core would read two different paths.
    for (const dir of ['/r/a b', '/r/a\u0085b', '/r/a b', '/r/a\u0007b']) {
      let message = '';
      try {
        renderConfig({ ...BASE, auditLogDir: dir });
      } catch (err) {
        message = (err as Error).message;
      }
      expect(message).toBe('live-env: auditLogDir contains a control or Unicode line-break character; refusing to write it into YAML');
      expect(message).not.toContain('/r/a');
    }
  });
});

describe('live-env assertAuditLogIsolated (AC4)', () => {
  it('the guard accepts the isolated document and names what is missing otherwise', async () => {
    const { assertAuditLogIsolated } = await liveEnv();

    expect(assertAuditLogIsolated(writeDoc(AC2_DOC), '/r/run')).toBeUndefined();

    const ac1Path = writeDoc(AC1_DOC);
    expect(() => assertAuditLogIsolated(ac1Path, '/r/run')).toThrow(
      `live-env: refusing to start aitm: ${ac1Path} must carry mcp.audit_log "/r/run/audit.jsonl" and ca.audit_log "/r/run/ca-audit.jsonl" so the core's audit logs stay in the run dir; missing: mcp.audit_log, ca.audit_log`,
    );

    const noCa = AC2_DOC.replace('ca:\n  audit_log: "/r/run/ca-audit.jsonl"\n', '');
    expect(noCa).not.toContain('ca:');
    expect(() => assertAuditLogIsolated(writeDoc(noCa), '/r/run')).toThrow(/missing: ca\.audit_log$/);

    const wrongBlock = 'ca:\n  audit_log: "/r/run/audit.jsonl"\nmcp:\n  operator_token: x\n';
    expect(() => assertAuditLogIsolated(writeDoc(wrongBlock), '/r/run')).toThrow(
      /missing: mcp\.audit_log, ca\.audit_log$/,
    );
  });
});

describe('live-env startAitm wiring (AC5)', () => {
  const BOGUS = { aitmBin: '/nonexistent/aitm' };
  const NOT_FOUND = 'aitm binary not found at /nonexistent/aitm';

  it('startAitm passes its dir, no longer forces the audit log off, and carries both inherited-env messages', () => {
    // The ordering (env check, binary check, mkdtemp, write, guard, spawn) is pinned once, below.
    const body = startAitmSource();
    expect(body).toContain('auditLogDir: dir');
    expect(body).not.toContain("AITM_AUDIT_LOG: process.env.AITM_AUDIT_LOG ?? 'off'");
    expect(body).toContain(
      'live-env: AITM_AUDIT_LOG=off is set in this environment; this core writes no general audit log (mcp.audit_log in ',
    );
    expect(body).toContain(
      "live-env: AITM_AUDIT_LOG is set to a value other than off in this environment; it would override mcp.audit_log and send this core's general audit log outside ",
    );
  });

  it('startAitm refuses an inherited AITM_AUDIT_LOG other than off before writing anything', async () => {
    const { startAitm } = await liveEnv();
    const errorSpy = spyConsoleError();

    // Any value other than `off` aborts ahead of the binary check (so ahead of every port, dir
    // and file), with the fixed abort message and without echoing the value.
    await withInheritedAuditLog('on', async () => {
      await expect(startAitm(BOGUS)).rejects.toThrow(
        /^live-env: AITM_AUDIT_LOG is set to a value other than off in this environment; it would override mcp\.audit_log and send this core's general audit log outside .+\. Unset it \(env -u AITM_AUDIT_LOG\) and retry\.$/,
      );
    });
    await withInheritedAuditLog('/elsewhere/sneaky-audit.jsonl', async () => {
      await expect(startAitm(BOGUS)).rejects.toThrow(/^live-env: AITM_AUDIT_LOG is set to a value other than off/);
      await expect(startAitm(BOGUS)).rejects.not.toThrow(/sneaky/);
    });
    expect(errorSpy).not.toHaveBeenCalled();

    // `off` is tolerated: one warning on console.error, then the run goes on to the binary check.
    await withInheritedAuditLog('off', async () => {
      await expect(startAitm(BOGUS)).rejects.toThrow(NOT_FOUND);
    });
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(String(errorSpy.mock.calls[0]?.[0])).toMatch(
      /^live-env: AITM_AUDIT_LOG=off is set in this environment; this core writes no general audit log \(mcp\.audit_log in .+ is overridden\)$/,
    );

    // Unset is the normal case: silent, straight to the binary check.
    errorSpy.mockClear();
    await withInheritedAuditLog(undefined, async () => {
      await expect(startAitm(BOGUS)).rejects.toThrow(NOT_FOUND);
    });
    expect(errorSpy).not.toHaveBeenCalled();
  });
});

// Tester additions (Task 3): the guard must compare against the run dir rather than merely find the
// keys, the quoting claim in Design 1 must round-trip, malformed inputs must refuse rather than
// pass, and the AC5 ordering must hold statically for mkdtemp and the written file too.
describe('live-env audit-log isolation: tester edge cases', () => {
  it('the guard refuses the isolated document when it names a different run dir', async () => {
    const { assertAuditLogIsolated } = await liveEnv();
    // AC2's document carries both keys; only the dir is wrong. A presence-only check would accept it.
    const path = writeDoc(AC2_DOC);
    expect(() => assertAuditLogIsolated(path, '/r/other')).toThrow(
      `live-env: refusing to start aitm: ${path} must carry mcp.audit_log "/r/other/audit.jsonl" and ca.audit_log "/r/other/ca-audit.jsonl" so the core's audit logs stay in the run dir; missing: mcp.audit_log, ca.audit_log`,
    );
    // The same dir with a trailing slash normalises to the same two paths and is accepted.
    expect(assertAuditLogIsolated(path, '/r/run/')).toBeUndefined();
    // Design 2: a blank line inside a block does not end it (YAML reads it the same way); panel round 2.
    expect(assertAuditLogIsolated(writeDoc(AC2_DOC.replace('mcp:\n', 'mcp:\n\n')), '/r/run')).toBeUndefined();
  });

  it('a quote or backslash in auditLogDir is JSON-quoted and round-trips through the guard', async () => {
    const { renderConfig, assertAuditLogIsolated } = await liveEnv();
    const weird = '/r/we"ird\\dir';
    const doc = renderConfig({ ...BASE, auditLogDir: weird });
    expect(doc).toContain('ca:\n  audit_log: "/r/we\\"ird\\\\dir/ca-audit.jsonl"\nmcp:\n');
    expect(doc).toContain('  operator_token: opsecret-x\n  audit_log: "/r/we\\"ird\\\\dir/audit.jsonl"\n  transport:\n');
    expect(doc.split('\n').filter((l) => l.includes('audit_log'))).toHaveLength(2);
    expect(assertAuditLogIsolated(writeDoc(doc), weird)).toBeUndefined();
  });

  it('an empty-string auditLogDir is refused like any other relative path', async () => {
    const { renderConfig } = await liveEnv();
    expect(() => renderConfig({ ...BASE, auditLogDir: '' })).toThrow(
      /^live-env: auditLogDir must be an absolute path; got ""$/,
    );
    expect(() => renderConfig({ ...BASE, auditLogDir: './run' })).toThrow(
      /^live-env: auditLogDir must be an absolute path; got "\.\/run"$/,
    );
  });

  it('the guard refuses an empty file, a CRLF file, an indented-only file and a missing file', async () => {
    const { assertAuditLogIsolated } = await liveEnv();
    const both = /missing: mcp\.audit_log, ca\.audit_log$/;
    expect(() => assertAuditLogIsolated(writeDoc(''), '/r/run')).toThrow(both);
    expect(() => assertAuditLogIsolated(writeDoc(AC2_DOC.replace(/\n/g, '\r\n')), '/r/run')).toThrow(both);
    // Every line indented: no block header, so neither line can belong to `mcp:` or `ca:`.
    expect(() => assertAuditLogIsolated(writeDoc(AC2_DOC.replace(/^/gm, ' ')), '/r/run')).toThrow(both);
    // The audit_log lines under the right headers but with the key spelled differently or an extra
    // indent are not the exact line the core would read as `mcp.audit_log` / `ca.audit_log`.
    expect(() => assertAuditLogIsolated(writeDoc(AC2_DOC.replace(/  audit_log:/g, '   audit_log:')), '/r/run')).toThrow(both);
    expect(() => assertAuditLogIsolated(writeDoc(AC2_DOC.replace(/audit_log:/g, 'audit_log :')), '/r/run')).toThrow(both);
    // A path that does not exist must throw (the read fails), never return undefined.
    expect(() => assertAuditLogIsolated(join(docDir, 'absent.yaml'), '/r/run')).toThrow(/ENOENT/);
  });

  it('startAitm inspects AITM_AUDIT_LOG before the binary check and mkdtemp, and checks the written file before the spawn', () => {
    const body = startAitmSource();
    const envCheck = body.indexOf('process.env.AITM_AUDIT_LOG');
    const binCheck = body.indexOf('existsSync(aitmBin)');
    const mkdtemp = body.indexOf('mkdtempSync(');
    const write = body.indexOf('writeFileSync(cfg');
    const guard = body.indexOf('assertAuditLogIsolated(cfg, dir)');
    const spawnAt = body.indexOf('spawn(aitmBin');
    for (const at of [envCheck, binCheck, mkdtemp, write, guard, spawnAt]) expect(at).toBeGreaterThanOrEqual(0);
    expect(envCheck).toBeLessThan(binCheck);
    expect(binCheck).toBeLessThan(mkdtemp);
    expect(mkdtemp).toBeLessThan(write);
    expect(write).toBeLessThan(guard);
    expect(guard).toBeLessThan(spawnAt);

    // Nothing in the spawn env names AITM_AUDIT_LOG, so nothing defaults it to off; the exact-match
    // tolerance of `off` is a behaviour pin (the next test), not a source-text one.
    expect(body).not.toContain('AITM_AUDIT_LOG:');
  });

  it('startAitm treats OFF, off with whitespace and an empty string as values other than off', async () => {
    const { startAitm } = await liveEnv();
    const errorSpy = spyConsoleError();
    for (const v of ['OFF', 'off ', ' off', '', 'false', '0']) {
      await withInheritedAuditLog(v, async () => {
        await expect(startAitm({ aitmBin: '/nonexistent/aitm' })).rejects.toThrow(
          /^live-env: AITM_AUDIT_LOG is set to a value other than off/,
        );
      });
    }
    expect(errorSpy).not.toHaveBeenCalled();
  });
});
