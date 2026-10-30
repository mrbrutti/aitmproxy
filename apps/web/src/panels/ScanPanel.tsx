// The Scan panel (spec §Design, AC3 web). The shell mounts it in place of the inspector when
// app.ui.panel === 'scan'; the implementation lives in ./scan, mirroring FindingsPanel.
import type { Component } from 'solid-js';
import { Scan } from './scan/Scan';

export const ScanPanel: Component = () => <Scan />;
