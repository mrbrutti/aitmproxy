// Slot: the Scripts panel (foundation §2.7). Filled in by its own builder; the shell mounts it
// in place of the inspector when app.ui.panel === 'scripts'.
import type { Component } from 'solid-js';

export const ScriptsPanel: Component = () => (
  <div style={{ padding: '12px', color: 'var(--color-text-tertiary)' }}>Scripts</div>
);
