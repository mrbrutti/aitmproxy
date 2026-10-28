// Slot: the Scope panel (foundation §2.7). Filled in by its own builder; the shell mounts it
// in place of the inspector when app.ui.panel === 'scope'.
import type { Component } from 'solid-js';

export const ScopePanel: Component = () => (
  <div style={{ padding: '12px', color: 'var(--color-text-tertiary)' }}>Scope</div>
);
