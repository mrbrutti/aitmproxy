// Unit (c) fix 3: the layer tree + bytes pane rendered (spec §2, §2.3; AC40). Replaces the
// source-mirroring `hexRows(` / `base64ToBytes(` content check in args.test.ts with the behaviour:
// the bytes reach the DOM only as the text of one <pre>, equal to `hexRows(bytes)`, every byte
// outside 0x20–0x7e shown as `.`; without a `bytes` key the pane says so and shows nothing else.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@solidjs/testing-library';
import { LayerTree, NO_BYTES_NOTE } from './LayerTree';
import { hexRows, type L4PacketWire } from './model';

afterEach(cleanup);

/** The AC40 bytes: ESC [ A LF DEL ~ A — base64 `G1tBCn9+QQ==`. */
const AC40 = Uint8Array.of(0x1b, 0x5b, 0x41, 0x0a, 0x7f, 0x7e, 0x41);
const AC40_B64 = 'G1tBCn9+QQ==';

const pkt = (p: Partial<L4PacketWire> = {}): L4PacketWire => ({ dir: 'inbound', length: 7, injected: false, layers: ['Ether', 'IPv4', 'UDP'], ...p });

describe('LayerTree bytes pane (spec §2.3, AC40)', () => {
  it('renders the bytes as the text of one <pre>, exactly hexRows(bytes); the AC40 bytes read .[A..~A', () => {
    const r = render(() => <LayerTree packet={pkt({ bytes: AC40_B64 })} />);
    const pre = r.container.querySelector<HTMLPreElement>('pre[data-testid="l4-packet-hex"]');
    expect(pre).not.toBeNull();
    expect(pre!.textContent).toBe(hexRows(AC40).join('\n'));
    expect(pre!.textContent).toBe('00000000  1b 5b 41 0a 7f 7e 41                              |.[A..~A|');
    expect(pre!.textContent).toContain('.[A..~A');
    for (const ch of pre!.textContent!) if (ch !== '\n') expect(ch.charCodeAt(0)).toBeGreaterThanOrEqual(0x20);
    // Text only: the bytes create no element.
    expect(pre!.children).toHaveLength(0);
    expect(r.container.querySelector('[aria-label="Packet layers"]')).not.toBeNull();
    expect(r.container.textContent).not.toContain(NO_BYTES_NOTE);
  });

  it('bytes that spell markup stay text, never elements', () => {
    const r = render(() => <LayerTree packet={pkt({ bytes: btoa('<img src=x onerror=alert(1)>'), length: 28 })} />);
    expect(r.container.querySelector('img')).toBeNull();
    // 28 bytes span two 16-byte rows; each row's ASCII column is text.
    expect(r.container.querySelector('pre')!.textContent).toContain('|<img src=x onerr|');
    expect(r.container.querySelector('pre')!.textContent).toContain('|or=alert(1)>|');
  });

  it('without a bytes key the pane says "no bytes from this core" and renders no hex pane', () => {
    const r = render(() => <LayerTree packet={pkt()} />);
    expect(r.container.querySelector('[data-testid="l4-packet-hex"]')).toBeNull();
    expect(r.container.querySelector('pre')).toBeNull();
    expect(r.container.textContent).toContain('no bytes from this core');
    expect(NO_BYTES_NOTE).toBe('no bytes from this core');
  });
});

describe('LayerTree layer stack (spec §2)', () => {
  it('renders one treeitem per decoded layer, in order, under a "Layers · N bytes" head', () => {
    const r = render(() => <LayerTree packet={pkt({ layers: ['Ether', 'IPv4', 'UDP'], length: 42 })} />);
    expect(r.container.textContent).toContain('Layers · 42 bytes');
    const items = [...r.container.querySelectorAll('[role="treeitem"]')].map((el) => el.textContent?.trim());
    expect(items).toEqual(['Ether', '└ IPv4', '└ UDP']);
  });

  it('an empty layer stack says raw bytes (no decode) and fabricates no layer', () => {
    const r = render(() => <LayerTree packet={pkt({ layers: [] })} />);
    expect(r.container.querySelectorAll('[role="treeitem"]')).toHaveLength(0);
    expect(r.container.textContent).toContain('raw bytes (no decode)');
  });
});
