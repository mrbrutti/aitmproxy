// Stage-5 Tester (T8 fix round): the two `scripts/live-env.mjs` changes of plan amendment PA12 /
// spec A11 that the plan records as tested but nothing under `src/` exercised: `parseOperatorUrl`
// over the core's current startup block (a miss is `null`, never the agent URL, so `scan-live.mjs`
// fails hard instead of running as the agent) and the quoted string values of the generated `l4:`
// block (a bare `*` is a YAML alias and made the core exit 1). The script is loaded by URL at run
// time, so the app's type-check never sees a `node:` import from a `.ts` file (A9).
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

// The script's path is derived the way `styles.test.ts` derives its own, and handed to the native
// loader as a file: URL (a relative `new URL(..., import.meta.url)` resolved against vite's
// http://localhost origin under jsdom).
const here = dirname(fileURLToPath(import.meta.url));
const LIVE_ENV = `file://${resolve(here, '../../../scripts/live-env.mjs')}`;

interface LiveEnv {
  parseOperatorUrl(stdout: unknown): string | null;
  renderConfig(opts: Record<string, unknown>): string;
}

const liveEnv = async (): Promise<LiveEnv> => (await import(/* @vite-ignore */ LIVE_ENV)) as LiveEnv;

/** The core's startup block as `crates/aitm/src/web/mod.rs` prints it with an operator token configured. */
const BLOCK = [
  '',
  '  aitm 0.5.9',
  '  Proxy      127.0.0.1:8080',
  '  Web UI     http://127.0.0.1:8082/#t=agent-bridge-token',
  '  Operator   http://127.0.0.1:8082/#t=op-bridge-token&expect=operator',
  '',
].join('\n');

describe('tester: live-env parseOperatorUrl (A11, PA12)', () => {
  it('reads the Operator line of the current startup block, never the Web UI (agent) line', async () => {
    const { parseOperatorUrl } = await liveEnv();
    expect(parseOperatorUrl(BLOCK)).toBe('http://127.0.0.1:8082/#t=op-bridge-token&expect=operator');
  });

  it('a block with only the agent Web UI line is a miss (null): the proof must fail hard, not fall back to the agent', async () => {
    const { parseOperatorUrl } = await liveEnv();
    const agentOnly = BLOCK.split('\n')
      .filter((l) => !l.includes('Operator'))
      .join('\n');
    expect(agentOnly).toContain('#t=agent-bridge-token');
    expect(parseOperatorUrl(agentOnly)).toBeNull();
    expect(parseOperatorUrl('')).toBeNull();
    expect(parseOperatorUrl(undefined)).toBeNull();
    expect(parseOperatorUrl(null)).toBeNull();
  });

  it('an Operator line without a #t= token is not an operator URL; the legacy line still parses', async () => {
    const { parseOperatorUrl } = await liveEnv();
    expect(parseOperatorUrl('  Operator   http://127.0.0.1:8082/\n')).toBeNull();
    expect(parseOperatorUrl('web UI (operator): http://127.0.0.1:8082/#t=legacy-token\n')).toBe(
      'http://127.0.0.1:8082/#t=legacy-token',
    );
  });
});

describe('tester: live-env renderConfig quotes every l4 string value (A11)', () => {
  const base = { proxyPort: 1, browserProxyPort: 2, pocDir: '/p', pocOut: '/o', operatorSecret: 'opsecret-x', token: 'live-y' };

  it('interface "*", direction and capability are quoted, and no bare `interface: *` alias remains', async () => {
    const { renderConfig } = await liveEnv();
    const yaml = renderConfig({
      ...base,
      scope: ['127.0.0.1'],
      l4: { enabled: true, scope: [{ addr: '127.0.0.0', prefix: 8, interface: '*', capability: 'inject' }] },
    });
    expect(yaml).toContain('      interface: "*"');
    expect(yaml).toContain('      direction: "outbound"');
    expect(yaml).toContain('      capability: "inject"');
    expect(yaml).not.toMatch(/interface:\s+\*\s*$/m);
    expect(yaml).toContain('        addr: 127.0.0.0');
    expect(yaml).toContain('        prefix: 8');
    expect(yaml).toContain('    - "127.0.0.1"');
    expect(yaml).toContain('  operator_token: opsecret-x');
    expect(yaml).toContain('l4:\n  enabled: true');
  });

  it('with no l4 and no scope the config has no empty keys', async () => {
    const { renderConfig } = await liveEnv();
    const yaml = renderConfig(base);
    expect(yaml).not.toContain('l4:');
    expect(yaml).not.toContain('entries:');
    expect(yaml).not.toContain('findings:');
    expect(yaml.endsWith('\n')).toBe(true);
  });
});
