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

/* ------------------------------------------------------------------ no `node:` in the app bundle */

const SRC_ROOT = resolve(__dirname, '../..');

/** Every `.ts`/`.tsx` under `src/` that is not a test file, a test kit or an ambient declaration. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    let children: string[] | null = null;
    try {
      children = readdirSync(path);
    } catch {
      children = null; // ENOTDIR: a file
    }
    if (children !== null) {
      out.push(...sourceFiles(path));
      continue;
    }
    if (!/\.tsx?$/.test(name)) continue;
    if (/\.test\.tsx?$/.test(name) || /\.d\.ts$/.test(name) || /\.testkit\.tsx?$/.test(name) || name === 'testkit.ts') continue;
    out.push(path);
  }
  return out;
}

describe('the app bundle never imports node: modules (plan PA1)', () => {
  it('no non-test file under src/ imports from node:', () => {
    const files = sourceFiles(SRC_ROOT);
    // The walk is real: the scanner views are in it, the tests are not.
    expect(files.some((f) => f.endsWith('/panels/scanner/JobsView.tsx'))).toBe(true);
    expect(files.some((f) => /\.test\.tsx?$/.test(f))).toBe(false);
    const offenders = files.filter((f) => /from\s+['"]node:|require\(\s*['"]node:/.test(readFileSync(f, 'utf8')));
    expect(offenders).toEqual([]);
  });
});
