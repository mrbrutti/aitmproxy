// Web live-harness audit-log isolation (spec 2026-11-02-web-harness-audit-log-isolation, AC1–AC4):
// `renderConfig` gains `auditLogDir`, which points the core's general audit log and CA audit log
// into the run's own dir, and `assertAuditLogIsolated` refuses a written config that does not
// carry both lines. The script is loaded by file URL exactly as `tester.live-env.test.ts` does.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const LIVE_ENV = `file://${resolve(here, '../../../scripts/live-env.mjs')}`;

interface LiveEnv {
  renderConfig(opts: Record<string, unknown>): string;
  assertAuditLogIsolated(cfgPath: string, runDir: string): void;
}

const liveEnv = async (): Promise<LiveEnv> => (await import(/* @vite-ignore */ LIVE_ENV)) as LiveEnv;

const BASE = { proxyPort: 1, browserProxyPort: 2, pocDir: '/p', pocOut: '/o', operatorSecret: 'opsecret-x', token: 'live-y' };

/** AC1: today's document, pinned byte for byte. */
const AC1_DOC =
  'listen: 127.0.0.1:1\nbrowser:\n  proxy_addr: 127.0.0.1:2\nscope:\n  allow_agent_widen: true\npoc:\n  dir: /p\n  out_dir: /o\nmcp:\n  operator_token: opsecret-x\n  transport:\n    loopback_tcp:\n      port: 0\n      token: live-y-mcp\n';

/** AC2: the isolated document for `auditLogDir: '/r/run'`. */
const AC2_DOC =
  'listen: 127.0.0.1:1\nbrowser:\n  proxy_addr: 127.0.0.1:2\nscope:\n  allow_agent_widen: true\npoc:\n  dir: /p\n  out_dir: /o\nca:\n  audit_log: "/r/run/ca-audit.jsonl"\nmcp:\n  operator_token: opsecret-x\n  audit_log: "/r/run/audit.jsonl"\n  transport:\n    loopback_tcp:\n      port: 0\n      token: live-y-mcp\n';

/** Writes `doc` to a fresh `config.yaml` and returns its path. */
function writeDoc(doc: string): string {
  const path = join(mkdtempSync(join(tmpdir(), 'live-env-audit-')), 'config.yaml');
  writeFileSync(path, doc);
  return path;
}

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
