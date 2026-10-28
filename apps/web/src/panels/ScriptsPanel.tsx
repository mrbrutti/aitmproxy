// The Scripts panel, as a placeholder (foundation §2.7 "Script editor", §3.8). The Rhai tier is an
// M3 deliverable (F8); until then this is the foundation's shape in grey bars, not a fake editor.
import type { Component } from 'solid-js';
import { Button, Icon } from '~/components';
import css from './scripts/ScriptsPanel.module.css';

const BARS = [72, 48, 88, 36, 64, 56, 80];

export const ScriptsPanel: Component = () => (
  <section class={css.panel} aria-label="Scripts">
    <header class={css.header}>
      <Icon name="code" class={css.icon} />
      <h2 class={css.title}>Scripts</h2>
      <span class={css.count}>0 active</span>
      <Button variant="outline" class={css.new} disabled title="Arrives with the M3 Rhai tier (F8)">
        <Icon name="plus" size={12} /> New script
      </Button>
    </header>
    <div class={css.body}>
      <div class={css.list}>
        <p class={css.empty}>Scripts arrive with the M3 Rhai tier (F8) — list, enable, edit and console will appear here.</p>
      </div>
      <div class={css.editor} aria-hidden="true">
        {BARS.map((w) => (
          <div class={css.bar} style={{ width: `${w}%` }} />
        ))}
      </div>
      <div class={css.console} aria-hidden="true">
        {BARS.slice(0, 4).map((w) => (
          <div class={css.bar} style={{ width: `${100 - w}%` }} />
        ))}
      </div>
    </div>
  </section>
);
