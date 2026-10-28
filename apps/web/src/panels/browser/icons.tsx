// The Browser view's Lucide glyphs that the shared Icon map does not carry yet (arrow-left,
// arrow-right, rotate-cw, camera, terminal). Same rendering rules as ~/components/Icon: 1.5px
// stroke, grey, decorative unless labelled. Fold into Icon.tsx when that file is next touched.
import type { Component, JSX } from 'solid-js';
import { Dynamic } from 'solid-js/web';
import { ArrowLeft, ArrowRight, Camera, RotateCw, Terminal } from 'lucide-solid';

const ICONS = {
  'arrow-left': ArrowLeft,
  'arrow-right': ArrowRight,
  camera: Camera,
  'rotate-cw': RotateCw,
  terminal: Terminal,
} as const;

export type BrowserIconName = keyof typeof ICONS;

export const BrowserIcon: Component<{
  name: BrowserIconName;
  size?: 12 | 16 | 18 | undefined;
  class?: string | undefined;
  label?: string | undefined;
  style?: JSX.CSSProperties | undefined;
}> = (props) => {
  const px = () => `${props.size ?? 16}px`;
  return (
    <Dynamic
      component={ICONS[props.name]}
      size={props.size ?? 16}
      strokeWidth={1.5}
      aria-hidden={props.label ? undefined : true}
      aria-label={props.label}
      role={props.label ? 'img' : undefined}
      class={props.class ?? ''}
      style={{ width: px(), height: px(), ...props.style }}
    />
  );
};
