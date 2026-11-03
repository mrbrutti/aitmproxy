// W-18: the v2 Scan stylesheet uses design tokens only. These tests read the CSS file itself with
// `node:fs` (vitest blanks every `.css` import, `?raw` included, so the text is only reachable from
// disk) and fail the moment a hard-coded colour or a stray severity hue lands.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CSS_PATH = resolve(__dirname, 'scanner.module.css');

function css(): string {
  return readFileSync(CSS_PATH, 'utf8');
}

/** Strip comments, then split the sheet into `{ selector, body }` rule blocks. At-rule wrappers
 *  (`@container`, `@media`) are unwrapped so the rules inside them are still seen; `@keyframes`
 *  frames are kept as blocks whose selector is the frame name. */
function blocks(source: string): { selector: string; body: string }[] {
  const text = source.replace(/\/\*[\s\S]*?\*\//g, '');
  const out: { selector: string; body: string }[] = [];
  let i = 0;
  let selStart = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '{') {
      const selector = text.slice(selStart, i).trim();
      // Nested blocks (at-rules) hold rules, not declarations: look inside.
      const rest = text.slice(i + 1);
      const nextOpen = rest.indexOf('{');
      const nextClose = rest.indexOf('}');
      if (selector.startsWith('@') && nextOpen !== -1 && nextOpen < nextClose) {
        selStart = i + 1;
        i += 1;
        continue;
      }
      const end = i + 1 + nextClose;
      out.push({ selector, body: text.slice(i + 1, end) });
      i = end + 1;
      selStart = i;
      continue;
    }
    if (ch === '}') {
      i += 1;
      selStart = i;
      continue;
    }
    i += 1;
  }
  return out;
}

// Every class the T8 views use (plan Task 2). A missing class is a missing style, not a typo.
const REQUIRED = [
  'root',
  'header',
  'title',
  'tabs',
  'tab',
  'tabCount',
  'reconnectNote',
  'strip',
  'stateDot',
  'stripWords',
  'stripMetric',
  'bar',
  'barSeg',
  'layout',
  'list',
  'listHead',
  'listTitle',
  'rows',
  'row',
  'rowMain',
  'rowSecondary',
  'rowMeta',
  'tag',
  'chip',
  'chips',
  'detail',
  'body',
  'section',
  'sectionTitle',
  'facts',
  'mono',
  'dash',
  'empty',
  'errorBlock',
  'retry',
  'loading',
  'note',
  'reason',
  'notice',
  'editor',
  'field',
  'fieldLabel',
  'segmented',
  'segment',
  'originRow',
  'tree',
  'treeHost',
  'checkTree',
  'checkClass',
  'checkRow',
  'footer',
  'kv',
  'table',
  'jobRow',
  'detailHead',
  'fieldset',
  'idList',
];

describe('scanner.module.css (W-18 design tokens only)', () => {
  it('no_hardcoded_colours', () => {
    const source = css();
    expect(/#[0-9a-fA-F]{3,8}\b|rgb\(/.test(source)).toBe(false);
    // And the file is a real stylesheet, not an empty placeholder that trivially passes.
    expect(source.length).toBeGreaterThan(1000);
  });

  it('severity_hue_only_on_pill_bar_chip', () => {
    const all = blocks(css());
    expect(all.length).toBeGreaterThan(20);
    const offenders = all
      .filter((b) => b.body.includes('--color-severity-'))
      .filter(
        (b) =>
          !b.selector.startsWith('.barSeg[data-severity=') &&
          !b.selector.startsWith('.chip[data-severity='),
      )
      .map((b) => b.selector);
    expect(offenders).toEqual([]);
    // The rule is not vacuous: every severity level is painted on both the bar and the chips.
    for (const level of ['critical', 'high', 'medium', 'low', 'info']) {
      const bar = all.find((b) => b.selector === `.barSeg[data-severity='${level}']`);
      const chip = all.find((b) => b.selector === `.chip[data-severity='${level}']`);
      expect(bar?.body, `barSeg ${level}`).toContain(`--color-severity-${level}-fg`);
      expect(chip?.body, `chip ${level}`).toContain(`--color-severity-${level}-fg`);
    }
  });

  it('state_tone_uses_state_tokens', () => {
    const all = blocks(css());
    for (const tone of ['neutral', 'success', 'danger']) {
      const dot = all.find((b) => b.selector === `.stateDot[data-tone='${tone}']`);
      expect(dot?.body, `stateDot ${tone}`).toContain(`--color-state-${tone}-fg`);
    }
  });

  it('required_classes_present', () => {
    const source = css();
    const missing = REQUIRED.filter((name) => !new RegExp(`\\.${name}(?![\\w-])`).test(source));
    expect(missing).toEqual([]);
    // The states the plan names explicitly.
    expect(source).toContain(".tab[aria-selected='true']");
    expect(source).toContain(".row[aria-selected='true']");
    expect(source).toContain(".chip[aria-pressed='true']");
    expect(source).toContain(".segment[aria-checked='true']");
    expect(source).toContain(".bar[data-empty='true']");
    expect(source).toContain(".layout[data-empty='true']");
    expect(source).toContain('container-type: inline-size');
  });

  it('container_queries_present', () => {
    const source = css();
    expect(source).toContain('@container (max-width: 900px)');
    expect(source).toContain('@container (max-width: 600px)');
  });

  it('loading_bars_do_not_animate', () => {
    const loading = blocks(css()).filter((b) => b.selector.startsWith('.loading'));
    expect(loading.length).toBeGreaterThan(0);
    for (const b of loading) {
      expect(b.body, b.selector).not.toMatch(/animation|transition/);
    }
  });
});

/* ------------------------------------------------------------------ jobs.module.css (D18 W2) */

// Plan Task 3.7: the Jobs view's stylesheet reproduces the locked comp (`committed.html`) on the
// tokens. The metrics block on `.jobs` is the one place a number with a unit may live; colours are
// `var(--color-*)` only; severity ink sits only on `[data-severity=…]`; every duration and curve
// is a `var(--motion-*)`; the reduced-motion block beats `base.css`'s blanket rule.
const JOBS_CSS_PATH = resolve(__dirname, 'jobs.module.css');

function jobsCss(): string {
  return readFileSync(JOBS_CSS_PATH, 'utf8');
}

function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, '');
}

/** `name: value` declarations of one rule body, in order. */
function declarations(body: string): { name: string; value: string }[] {
  return body
    .split(';')
    .map((d) => d.trim())
    .filter((d) => d.length > 0)
    .map((d) => {
      const colon = d.indexOf(':');
      return { name: d.slice(0, colon).trim(), value: d.slice(colon + 1).trim() };
    });
}

/** The text inside `<prelude> { … }` up to its matching brace, or null when the prelude is absent. */
function atRuleBody(source: string, prelude: string): string | null {
  const start = source.indexOf(`${prelude} {`);
  if (start === -1) return null;
  let depth = 0;
  for (let i = start; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    if (source[i] === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(source.indexOf('{', start) + 1, i);
    }
  }
  return null;
}

const norm = (selector: string): string => selector.replace(/\s+/g, ' ').trim();

// The web's `CardMetrics` (plan Task 3.7), name → value, in the plan's order.
const JOBS_METRICS: Record<string, string> = {
  '--jobs-hairline': '1px',
  '--jobs-edge': '3px',
  '--jobs-chip-height': '22px',
  '--jobs-chip-pad': '9px',
  '--jobs-dot': '6px',
  '--jobs-dot-halo': '3px',
  '--jobs-now-mark': '2px',
  '--jobs-now-overshoot': '10px',
  '--jobs-now-dot': '10px',
  '--jobs-halo': '3px',
  '--jobs-halo-mix': '12%',
  '--jobs-track-highlight': '3%',
  '--jobs-crawl-cap': '80px',
  '--jobs-lane-label-top': '10px',
  '--jobs-lane-label-left': '12px',
  '--jobs-lane-sub-opacity': '0.75',
  '--jobs-tag-gap': '12px',
  '--jobs-scale-gap': '40px',
  '--jobs-mark-width': '8px',
  '--jobs-mark-height': '16px',
  '--jobs-mark-radius': '2px',
  '--jobs-mark-gap': '3px',
  '--jobs-gauge': '3px',
  '--jobs-ring-stroke': '2.5px',
  '--jobs-row': '44px',
  '--jobs-row-sub': '60px',
  '--jobs-header': '32px',
  '--jobs-col-state': '148fr',
  '--jobs-col-profile': '120px',
  '--jobs-col-target': '220fr',
  '--jobs-col-progress': '220fr',
  '--jobs-col-probes': '120px',
  '--jobs-col-points': '120px',
  '--jobs-col-issues': '124px',
  '--jobs-col-elapsed': '80px',
  '--jobs-col-action': '84px',
  '--jobs-entrance-rise': '8px',
  '--jobs-mark-travel': '3px',
  '--jobs-mark-scale': '0.6',
  '--jobs-swap-travel': '2px',
  '--jobs-tick-travel': '3px',
  '--jobs-tick-floor': '0.35',
  '--jobs-breath-floor': '0.4',
  '--jobs-heading-tracking': '-0.01em',
  '--jobs-kpi-pad-y': '14px',
};

// Every class the Jobs view's components use (plan Task 3.7).
const REQUIRED_JOBS = [
  'jobs',
  'banner',
  'card',
  'enter',
  'titleRow',
  'chip',
  'chipDot',
  'heading',
  'reason',
  'finding',
  'part',
  'verbs',
  'scanAgainError',
  'lane',
  'track',
  'crawl',
  'audit',
  'segLabel',
  'segSub',
  'toGo',
  'nowMark',
  'nowDot',
  'nowTag',
  'endSentence',
  'scale',
  'ledger',
  'group',
  'mark',
  'ledgerWord',
  'gauge',
  'gaugeFill',
  'kpis',
  'kpi',
  'kpiLabel',
  'kpiValue',
  'kpiUnit',
  'attention',
  'errorText',
  'rawLine',
  'notices',
  'head',
  'rows',
  'row',
  'cell',
  'ring',
  'ringTrack',
  'ringArc',
  'dot',
  'agentDot',
  'stateWord',
  'sub',
  'unit',
  'sev',
  'hoverCancel',
  'wells',
  'well',
  'wellTitle',
  'wellSub',
  'kv',
  'tick',
  'breathe',
  'endSwap',
  'visuallyHidden',
];

const TONE_PAIRS: Record<string, [fg: string, bg: string]> = {
  progress: ['--color-accent-base', '--color-accent-tint'],
  pending: ['--color-intercept-base', '--color-intercept-tint'],
  success: ['--color-state-success-fg', '--color-state-success-bg'],
  danger: ['--color-state-danger-fg', '--color-state-danger-bg'],
  neutral: ['--color-state-neutral-fg', '--color-state-neutral-bg'],
};

const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];

const ANIMATED_PROPERTIES = ['transform', 'opacity', 'width', 'stroke-dashoffset', 'color', 'background-color'];

const JOBS_GRID =
  'grid-template-columns: minmax(0, var(--jobs-col-state)) var(--jobs-col-profile) minmax(0, var(--jobs-col-target)) minmax(0, var(--jobs-col-progress)) var(--jobs-col-probes) var(--jobs-col-points) var(--jobs-col-issues) var(--jobs-col-elapsed) var(--jobs-col-action);';

describe('jobs.module.css (Jobs view D18 W2)', () => {
  it('no_colour_literals', () => {
    const source = jobsCss();
    expect(source.match(/#[0-9a-fA-F]{3,8}\b|rgba?\(|hsla?\(/g) ?? []).toEqual([]);
    // A real stylesheet, not a placeholder that trivially passes.
    expect(source.length).toBeGreaterThan(4000);
    expect(blocks(source).length).toBeGreaterThan(60);
  });

  it('metrics_block_is_the_web_card_metrics', () => {
    const metrics = blocks(jobsCss()).filter((b) => b.selector === '.jobs');
    expect(metrics).toHaveLength(1);
    const decls = declarations(metrics[0]?.body ?? '');
    // Exactly the 45 names, each once, in the plan's order, with the plan's values; nothing else.
    expect(Object.keys(JOBS_METRICS)).toHaveLength(45);
    expect(decls.map((d) => d.name)).toEqual(Object.keys(JOBS_METRICS));
    for (const d of decls) {
      expect(d.value, d.name).toBe(JOBS_METRICS[d.name]);
    }
  });

  it('no_geometry_or_duration_literals_outside_the_metrics', () => {
    const text = stripComments(jobsCss());
    const metrics = blocks(text).find((b) => b.selector === '.jobs');
    expect(metrics).toBeDefined();
    const outside = text.replace(metrics!.body, '');
    // The metrics block really was cut out (its values would otherwise fail the next line).
    expect(outside).not.toContain('--jobs-hairline:');
    expect(outside.match(/-?\d+(\.\d+)?(px|ms|s|fr|em)\b/g) ?? []).toEqual([]);
    const percents = outside.match(/-?\d+(\.\d+)?%/g) ?? [];
    expect(percents.length).toBeGreaterThan(0);
    expect(percents.filter((p) => !['100%', '50%', '-50%'].includes(p))).toEqual([]);
    const radii = blocks(text)
      .filter((b) => b.selector !== '.jobs')
      .flatMap((b) => declarations(b.body).filter((d) => d.name === 'border-radius').map((d) => [b.selector, d.value] as const));
    expect(radii.length).toBeGreaterThan(5);
    for (const [selector, value] of radii) {
      for (const part of value.split(/\s+/)) {
        expect(part, `${selector} border-radius`).toMatch(/^(var\(--radius-[a-z-]+\)|var\(--jobs-mark-radius\)|50%)$/);
      }
    }
  });

  it('severity_ink_only_on_data_severity', () => {
    const all = blocks(jobsCss());
    const offenders = all
      .filter((b) => b.body.includes('--color-severity-'))
      .filter((b) => !b.selector.includes('[data-severity='))
      .map((b) => b.selector);
    expect(offenders).toEqual([]);
    for (const level of SEVERITY_LEVELS) {
      const word = all.find((b) => b.selector === `.sev[data-severity='${level}']`);
      const mark = all.find((b) => b.selector === `.mark[data-severity='${level}']`);
      expect(word?.body, `sev ${level}`).toContain(`color: var(--color-severity-${level}-fg)`);
      expect(mark?.body, `mark ${level}`).toContain(`background: var(--color-severity-${level}-fg)`);
    }
  });

  it('tones_use_their_pairs', () => {
    const all = blocks(jobsCss());
    for (const [tone, [fg, bg]] of Object.entries(TONE_PAIRS)) {
      const edge = all.find((b) => b.selector === `.card[data-tone='${tone}']::before`);
      const chip = all.find((b) => b.selector === `.chip[data-tone='${tone}']`);
      const dot = all.find((b) => b.selector === `.dot[data-tone='${tone}']`);
      expect(edge?.body, `edge ${tone}`).toContain(`background: var(${fg})`);
      expect(chip?.body, `chip ${tone}`).toContain(`color: var(${fg})`);
      expect(chip?.body, `chip ${tone}`).toContain(`background: var(${bg})`);
      expect(dot?.body, `dot ${tone}`).toContain(`background: var(${fg})`);
    }
  });

  it('animated_properties_are_the_six', () => {
    const all = blocks(jobsCss());
    const transitions = all.flatMap((b) =>
      declarations(b.body)
        .filter((d) => d.name === 'transition' || d.name === 'transition-property')
        .map((d) => [b.selector, d.value] as const),
    );
    expect(transitions.length).toBeGreaterThan(6);
    for (const [selector, value] of transitions) {
      for (const item of value.split(',')) {
        expect(ANIMATED_PROPERTIES, `${selector}: ${item.trim()}`).toContain(item.trim().split(/\s+/)[0]);
      }
    }
    const frames = all.filter((b) => b.selector === 'from' || b.selector === 'to' || /^\d+%$/.test(b.selector));
    // The plan's six keyframes (jobsEnter, jobsEnterFade, jobsTick, jobsRise, jobsSwap, jobsBreathe), two frames each.
    expect(frames.length).toBe(12);
    for (const frame of frames) {
      for (const d of declarations(frame.body)) {
        expect(['opacity', 'transform'], `frame ${frame.selector}: ${d.name}`).toContain(d.name);
      }
    }
  });

  it('durations_and_curves_are_tokens', () => {
    const all = blocks(jobsCss());
    const motion = all.flatMap((b) =>
      declarations(b.body)
        .filter((d) => ['animation', 'transition', 'animation-duration', 'animation-delay', 'transition-duration'].includes(d.name))
        .map((d) => [b.selector, d.name, d.value] as const),
    );
    expect(motion.length).toBeGreaterThan(12);
    for (const [selector, name, value] of motion) {
      const stripped = value
        .replace(/!important/g, ' ')
        .replace(/calc\(var\(--motion-stagger\) \* var\(--jobs-i, 0\)\)/g, ' ')
        .replace(/var\(--motion-[a-z-]+\)/g, ' ');
      const leftovers = stripped
        .split(/[\s,]+/)
        .filter(Boolean)
        .filter((w) => !ANIMATED_PROPERTIES.includes(w) && !/^jobs[A-Z]\w+$/.test(w) && !['infinite', 'alternate', 'both', 'none'].includes(w));
      expect(leftovers, `${selector} ${name}: ${value}`).toEqual([]);
      if (value.replace(/!important/g, '').trim() !== 'none') {
        expect(value, `${selector} ${name}`).toContain('var(--motion-');
      }
    }
    // The plan's motion table, pinned literally.
    const body = (selector: string) => all.find((b) => norm(b.selector) === selector)?.body ?? '';
    const entrance = body(".card[data-entrance='play'] .enter, .enter[data-entrance='play']");
    expect(entrance).toContain('animation: jobsEnter var(--motion-sheet) var(--motion-ease-out) both;');
    expect(entrance).toContain('animation-delay: calc(var(--motion-stagger) * var(--jobs-i, 0));');
    expect(body('.tick')).toContain('animation: jobsTick var(--motion-counter) var(--motion-ease-out);');
    expect(body('.mark')).toContain('animation: jobsRise var(--motion-sheet) var(--motion-ease-out) both;');
    expect(body('.endSwap')).toContain('animation: jobsSwap var(--motion-sheet) var(--motion-ease-out) both;');
    expect(body('.breathe')).toContain('animation: jobsBreathe var(--motion-intercept-pulse) var(--motion-pulse) infinite alternate;');
    expect(body('.audit')).toContain('transition: width var(--motion-progress) var(--motion-ease-out);');
    expect(body('.crawl')).toContain('transition: width var(--motion-progress) var(--motion-ease-out);');
    expect(body('.ringArc')).toContain('transition: stroke-dashoffset var(--motion-progress) var(--motion-ease-out);');
    expect(body('.gaugeFill')).toContain('width var(--motion-progress) var(--motion-ease-out)');
    expect(body('.gaugeFill')).toContain('background-color var(--motion-popover) var(--motion-ease-out)');
    expect(body('.hoverCancel')).toContain('transition: opacity var(--motion-hover) var(--motion-ease-out);');
    expect(body('.kpi')).toContain('transition: background-color var(--motion-hover) var(--motion-ease-out);');
    for (const selector of ['.chip', '.card::before']) {
      expect(body(selector), selector).toContain('color var(--motion-popover) var(--motion-ease-out)');
      expect(body(selector), selector).toContain('background-color var(--motion-popover) var(--motion-ease-out)');
    }
  });

  it('reduced_motion_overrides_base_css', () => {
    const text = stripComments(jobsCss());
    expect(text.split('@media (prefers-reduced-motion: reduce)').length - 1).toBe(1);
    const reduced = atRuleBody(text, '@media (prefers-reduced-motion: reduce)');
    expect(reduced).not.toBeNull();
    const rules = blocks(reduced!);
    const body = (selector: string) => rules.find((b) => norm(b.selector) === selector)?.body ?? `MISSING ${selector}`;
    for (const selector of [".card[data-entrance='play'] .enter, .enter[data-entrance='play']", '.mark', '.endSwap']) {
      expect(body(selector), selector).toContain('animation-name: jobsEnterFade !important;');
      expect(body(selector), selector).toContain('animation-duration: var(--motion-sheet) !important;');
      // The stagger is kept: the reduced block does not touch the delay.
      expect(body(selector), selector).not.toContain('animation-delay');
    }
    expect(body('.hoverCancel')).toContain('transition-duration: var(--motion-hover) !important;');
    expect(body('.chip, .card::before')).toContain('transition-duration: var(--motion-popover) !important;');
    expect(body('.breathe')).toContain('animation: none !important;');
    expect(body('.tick')).toContain('animation-name: none !important;');
    // The opacity-only entrance: no travel in either frame.
    const fade = atRuleBody(text, '@keyframes jobsEnterFade');
    expect(fade).not.toBeNull();
    const frames = blocks(fade!);
    expect(frames.length).toBe(2);
    for (const frame of frames) {
      const names = declarations(frame.body).map((d) => d.name);
      expect(names, `jobsEnterFade ${frame.selector}`).toEqual(['opacity']);
    }
  });

  it('required_jobs_classes_present', () => {
    const source = jobsCss();
    const missing = REQUIRED_JOBS.filter((name) => !new RegExp(`\\.${name}(?![\\w-])`).test(source));
    expect(missing).toEqual([]);
    // The state selectors and the geometry the plan names explicitly.
    for (const literal of [
      ".row[aria-selected='true']",
      ".gauge[data-warn='true'] .gaugeFill",
      "[data-ink='muted']",
      ".card[data-entrance='play'] .enter",
      ".enter[data-entrance='play']",
      '.row:hover .hoverCancel',
      ".part[data-role='figure']",
      ".part[data-role='checkId']",
      ".part[data-role='agent']",
      JOBS_GRID,
      'width: calc((100% - var(--jobs-crawl-cap)) * var(--jobs-f, 0));',
      'stroke-dasharray: 1;',
      'stroke-dashoffset: calc(1 - var(--jobs-f, 0));',
      'color-mix(in srgb, var(--color-text-primary) var(--jobs-halo-mix), transparent)',
      'color-mix(in srgb, var(--color-text-primary) var(--jobs-track-highlight), transparent)',
    ]) {
      expect(source, literal).toContain(literal);
    }
    const all = blocks(source);
    const selected = all.find((b) => b.selector === ".row[aria-selected='true']");
    expect(selected?.body).toContain('background: var(--color-ground-active)');
    expect(selected?.body).toContain('inset var(--jobs-edge) 0 0 var(--color-accent-base)');
    expect(all.find((b) => b.selector === ".gauge[data-warn='true'] .gaugeFill")?.body).toContain('background: var(--color-intercept-base)');
    expect(all.find((b) => b.selector === "[data-ink='muted']")?.body).toContain('color: var(--color-text-tertiary)');
    expect(all.find((b) => b.selector === '.row:hover .hoverCancel')?.body).toContain('opacity: 1');
    // The table and its header share one grid.
    expect(source.split(JOBS_GRID).length - 1).toBe(1);
    expect(all.find((b) => b.body.includes(JOBS_GRID))?.selector.replace(/\s+/g, ' ')).toBe('.head, .row');
  });
});

/* ------------------------------------------------------------------ no `node:` in the app bundle */

const SRC_ROOT = resolve(__dirname, '../..');

/** Every `.ts`/`.tsx` under `src/` that is not a test file, a test kit or an ambient declaration. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...sourceFiles(path));
      continue;
    }
    const name = entry.name;
    if (!/\.tsx?$/.test(name)) continue;
    if (/\.test\.tsx?$/.test(name) || /\.d\.ts$/.test(name) || /\.testkit\.tsx?$/.test(name) || name === 'testkit.ts') continue;
    out.push(path);
  }
  return out;
}

describe('the app bundle never imports node: modules (plan PA1)', () => {
  it('no non-test file under src/ imports from node:, and none imports the test kit', () => {
    const files = sourceFiles(SRC_ROOT);
    // The walk is real: the scanner views are in it, the tests are not.
    expect(files.some((f) => f.endsWith('/panels/scanner/JobsView.tsx'))).toBe(true);
    expect(files.some((f) => /\.test\.tsx?$/.test(f))).toBe(false);
    const sources = files.map((f) => [f, readFileSync(f, 'utf8')] as const);
    // Static, CommonJS and dynamic forms alike.
    const offenders = sources.filter(([, src]) => /from\s+['"]node:|require\(\s*['"]node:|import\(\s*['"]node:/.test(src)).map(([f]) => f);
    expect(offenders).toEqual([]);
    // The test kit reads fixtures with node:fs, so it must stay out of the bundle too.
    const kitImporters = sources.filter(([, src]) => /from\s+['"][^'"]*\/testkit['"]/.test(src)).map(([f]) => f);
    expect(kitImporters).toEqual([]);
  });
});
