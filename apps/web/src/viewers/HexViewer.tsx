// Hex viewer: offset · 16 bytes · ASCII, 20px mono rows, windowed so a multi-megabyte body
// renders only what is on screen.

import { createMemo, createSignal, For, onCleanup, onMount, type Component } from 'solid-js';
import s from './viewers.module.css';

const ROW = 20;
const PER_ROW = 16;
const OVERSCAN = 10;
const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

export const HexViewer: Component<{ bytes: Uint8Array; class?: string }> = (props) => {
  let scroller!: HTMLDivElement;
  const [top, setTop] = createSignal(0);
  const [height, setHeight] = createSignal(400);
  const total = () => Math.ceil(props.bytes.length / PER_ROW);
  const offsetWidth = () => Math.max(8, props.bytes.length.toString(16).length);

  onMount(() => {
    const ro = new ResizeObserver(() => setHeight(scroller.clientHeight));
    ro.observe(scroller);
    setHeight(scroller.clientHeight);
    onCleanup(() => ro.disconnect());
  });

  const range = createMemo(() => {
    const start = Math.max(0, Math.floor(top() / ROW) - OVERSCAN);
    const end = Math.min(total(), Math.ceil((top() + height()) / ROW) + OVERSCAN);
    const out: number[] = [];
    for (let i = start; i < end; i++) out.push(i);
    return out;
  });

  const line = (row: number) => {
    const b = props.bytes;
    const from = row * PER_ROW;
    const to = Math.min(b.length, from + PER_ROW);
    let hex = '';
    let ascii = '';
    for (let i = from; i < to; i++) {
      const v = b[i]!;
      hex += HEX[v] + (i - from === 7 ? '  ' : ' ');
      ascii += v >= 32 && v < 127 ? String.fromCharCode(v) : '·';
    }
    return { offset: from.toString(16).padStart(offsetWidth(), '0'), hex: hex.padEnd(PER_ROW * 3 + 1, ' '), ascii };
  };

  return (
    <div ref={scroller} class={`${s.hex} ${props.class ?? ''}`} onScroll={() => setTop(scroller.scrollTop)} tabIndex={0} aria-label="Hex view">
      <div style={{ height: `${total() * ROW}px`, position: 'relative' }}>
        <For each={range()}>
          {(row) => {
            const l = line(row);
            return (
              <div class={s.hexRow} style={{ transform: `translateY(${row * ROW}px)` }}>
                <span class={s.hexOffset}>{l.offset}</span>
                <span class={s.hexBytes}>{l.hex}</span>
                <span class={s.hexAscii}>{l.ascii}</span>
              </div>
            );
          }}
        </For>
      </div>
    </div>
  );
};
