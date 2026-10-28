// The Findings panel (foundation §2.7 "PoC panel"). The shell mounts it in place of the inspector
// when app.ui.panel === 'findings'; the implementation lives in ./findings.
import type { Component } from 'solid-js';
import { Findings } from './findings/Findings';

export const FindingsPanel: Component = () => <Findings />;
