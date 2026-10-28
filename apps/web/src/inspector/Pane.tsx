// One inspector pane: `grid-template-rows: var(--size-tab-bar) minmax(0,1fr)` — the tab bar and a
// focusable content region. Also the shared format picker + find button for body tabs.

import { createSignal, Show, type Component, type JSX, type ParentComponent } from 'solid-js';
import { Icon, Menu } from '~/components';
import { FORMATS, type Format, type PrettyState } from './body';
import { Tabs, type TabDef } from './Tabs';
import { Control } from './ui';
import css from './inspector.module.css';

export interface PaneProps {
  title: string;
  tabs: TabDef[];
  active: string;
  onSelect: (id: string) => void;
  right?: JSX.Element;
  hidden?: boolean;
  label?: string;
  onPlus?: () => void;
  contentRef?: (el: HTMLDivElement) => void;
}

export const Pane: ParentComponent<PaneProps> = (props) => (
  <section class={css.pane} classList={{ [css.paneHidden!]: !!props.hidden }} aria-label={props.label ?? props.title} aria-hidden={props.hidden ? true : undefined}>
    <Tabs title={props.title} tabs={props.tabs} active={props.active} onSelect={props.onSelect} right={props.right} onPlus={props.onPlus} />
    <div class={css.content} tabIndex={-1} ref={(el) => props.contentRef?.(el)}>
      {props.children}
    </div>
  </section>
);

export interface BodyControlsProps {
  format: Format;
  onFormat: (f: Format) => void;
  /** The auto-detected label, shown when format is Auto. */
  label: string;
  prettyState: PrettyState;
  truncatedAt?: number | null;
  onFind: () => void;
  /** Hide the picker (Raw tab shows the exact text; the label stays). */
  pickerless?: boolean;
}

export const BodyControls: Component<BodyControlsProps> = (props) => {
  const [open, setOpen] = createSignal<{ left: number; top: number; right: number; bottom: number } | null>(null);
  let btn!: HTMLButtonElement;
  return (
    <>
      <Show when={props.truncatedAt != null}>
        <span class={css.chip} title="The capture kept only the first part of this body">
          Body truncated at {Math.round(props.truncatedAt! / 1024)} KB — export to see all
        </span>
      </Show>
      <Show when={props.prettyState === 'formatting'}>
        <span class={css.quietNote}>formatting…</span>
      </Show>
      <Show when={props.prettyState === 'capped'}>
        <span class={css.quietNote} title="Bodies over 20 MB are shown raw">
          raw only
        </span>
      </Show>
      <Show when={props.prettyState === 'invalid'}>
        <span class={css.quietNote} title="The body is not valid JSON; showing it as text">
          not JSON
        </span>
      </Show>
      <Show when={!props.pickerless} fallback={<span class={css.quietNote}>{props.label}</span>}>
        <Control
          ref={btn}
          aria-haspopup="menu"
          aria-expanded={!!open()}
          title="Body format"
          onClick={() => {
            const r = btn.getBoundingClientRect();
            setOpen({ left: r.left, top: r.top, right: r.right, bottom: r.bottom });
          }}
        >
          {props.format === 'auto' ? props.label : FORMATS.find((f) => f.id === props.format)!.label}
          <Icon name="chevron-down" size={12} />
        </Control>
        <Show when={open()}>
          {(anchor) => (
            <Menu
              anchor={anchor()}
              placement="bottom-end"
              label="Body format"
              onClose={() => setOpen(null)}
              items={FORMATS.map((f) => ({ label: f.id === 'auto' ? `Auto · ${props.label}` : f.label, checked: props.format === f.id, onSelect: () => props.onFormat(f.id) }))}
            />
          )}
        </Show>
      </Show>
      <Control icon title="Find in body (⌘F)" aria-label="Find in body" onClick={props.onFind}>
        <Icon name="search" size={12} />
      </Control>
    </>
  );
};
