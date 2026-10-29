// Image bodies: data URL from base64, natural size, type and byte count, checkerboard behind
// transparency, fit / 100% zoom.

import { createMemo, createSignal, Show, type Component } from 'solid-js';
import { fmtBytes } from '~/lib/format';
import s from './viewers.module.css';

export const ImageViewer: Component<{ base64: string; mime: string; size: number; class?: string }> = (props) => {
  const [dims, setDims] = createSignal<{ w: number; h: number } | null>(null);
  const [fit, setFit] = createSignal(true);
  const [broken, setBroken] = createSignal(false);
  const src = createMemo(() => (props.base64 ? `data:${props.mime};base64,${props.base64}` : null));
  const type = () => props.mime.replace(/^image\//, '').toUpperCase();

  return (
    <div class={`${s.image} ${props.class ?? ''}`}>
      <div class={s.imageBar}>
        <span class={s.imageMeta}>
          <Show when={dims()} fallback={<span class={s.dash}>—</span>}>
            {(d) => (
              <>
                {d().w}×{d().h}
              </>
            )}
          </Show>
          <span class={s.imageSep}>·</span>
          {type()}
          <span class={s.imageSep}>·</span>
          {fmtBytes(props.size) ?? '—'}
        </span>
        <span class={s.treeSpacer} />
        <button type="button" class={`${s.treeBtn} ${fit() ? s.treeBtnOn : ''}`} onClick={() => setFit(true)} aria-pressed={fit()}>
          Fit
        </button>
        <button type="button" class={`${s.treeBtn} ${!fit() ? s.treeBtnOn : ''}`} onClick={() => setFit(false)} aria-pressed={!fit()}>
          100%
        </button>
      </div>
      <div class={s.imageStage}>
        <Show
          when={src() && !broken()}
          fallback={
            <div class={s.imageEmpty}>{broken() ? 'Image could not be decoded' : `No image bytes in this capture (${fmtBytes(props.size) ?? '—'} on the wire)`}</div>
          }
        >
          <img
            class={fit() ? s.imageFit : s.imageFull}
            src={src()!}
            alt=""
            onLoad={(e) => setDims({ w: e.currentTarget.naturalWidth, h: e.currentTarget.naturalHeight })}
            onError={() => setBroken(true)}
          />
        </Show>
      </div>
    </div>
  );
};
