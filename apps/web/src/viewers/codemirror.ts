// Lazy CodeMirror 6 loader, theme and highlight style. Everything from @codemirror/* and @lezer/*
// is imported only through the dynamic `import()`s below, so vite keeps it in the lazy
// 'codemirror' chunk and the cold load stays small (§2.10(b)).

import type { Compartment, EditorState, Extension } from '@codemirror/state';
import type { EditorView } from '@codemirror/view';

export type StateMod = typeof import('@codemirror/state');
export type ViewMod = typeof import('@codemirror/view');
export type LanguageMod = typeof import('@codemirror/language');
export type CommandsMod = typeof import('@codemirror/commands');
export type SearchMod = typeof import('@codemirror/search');
export type JsonMod = typeof import('@codemirror/lang-json');
export type MergeMod = typeof import('@codemirror/merge');
export type AutocompleteMod = typeof import('@codemirror/autocomplete');

export interface CM {
  state: StateMod;
  view: ViewMod;
  language: LanguageMod;
  commands: CommandsMod;
  search: SearchMod;
  json: JsonMod;
  autocomplete: AutocompleteMod;
  /** Shared theme + highlight extensions (tokens only). */
  theme: Extension;
  /** Amber left edge on lines that differ from the original request (§2.7 `.l.edited`). */
  editedLines: (original: string) => Extension;
  /** StreamLanguage highlighters for the scripting surfaces, keyed by Lang. */
  langs: Record<'rhai' | 'yaml', Extension>;
  /** Schema/catalog-aware completion sources, keyed by Lang (added only to editable editors). */
  completions: Record<'rhai' | 'yaml', Extension>;
}

export type Lang = 'json' | 'text' | 'rhai' | 'yaml';

export interface StateOptions {
  lang: Lang;
  editable?: boolean;
  /** Original text; lines that differ from it get the amber edge. Only meaningful when editable. */
  original?: string | undefined;
  /** Holds the edited-lines extension so the original can be swapped without a new state. */
  editedCompartment?: Compartment | undefined;
  onChange?: ((text: string) => void) | undefined;
  extra?: Extension[];
}

let cmPromise: Promise<CM> | null = null;
let mergePromise: Promise<MergeMod> | null = null;

export function loadCodeMirror(): Promise<CM> {
  if (cmPromise) return cmPromise;
  cmPromise = (async () => {
    const [state, view, language, commands, search, json, autocomplete, highlight, rhai, yaml, completeRhai, completeYaml] =
      await Promise.all([
        import('@codemirror/state'),
        import('@codemirror/view'),
        import('@codemirror/language'),
        import('@codemirror/commands'),
        import('@codemirror/search'),
        import('@codemirror/lang-json'),
        import('@codemirror/autocomplete'),
        import('@lezer/highlight'),
        import('./lang/rhai'),
        import('./lang/yaml'),
        import('./lang/complete-rhai'),
        import('./lang/complete-yaml'),
      ]);
    const t = highlight.tags;
    const highlightStyle = language.HighlightStyle.define([
      { tag: t.propertyName, color: 'var(--color-syntax-key)' },
      { tag: t.string, color: 'var(--color-syntax-string)' },
      { tag: t.number, color: 'var(--color-syntax-number)' },
      { tag: [t.bool, t.null, t.keyword], color: 'var(--color-syntax-boolean)' },
      // Comments are additive (spec §2.2): the surface renders them in the muted text face, there
      // being no dedicated syntax.comment foundation token.
      { tag: t.comment, color: 'var(--color-text-tertiary)', fontStyle: 'italic' },
      { tag: [t.punctuation, t.separator], color: 'var(--color-syntax-punct)' },
      { tag: [t.brace, t.bracket, t.squareBracket, t.paren], color: 'var(--color-syntax-bracket)' },
    ]);

    // Map the generated colorizers' foundation faces (spec §1.1 map_token) onto @lezer/highlight tags.
    const synTokenTable = {
      keyword: t.keyword,
      boolean: t.bool,
      string: t.string,
      number: t.number,
      comment: t.comment,
      punct: t.punctuation,
      key: t.propertyName,
    };
    const langs = {
      rhai: language.StreamLanguage.define({ ...rhai.rhaiStreamParser, tokenTable: synTokenTable }),
      yaml: language.StreamLanguage.define({ ...yaml.yamlStreamParser, tokenTable: synTokenTable }),
    };
    const toOptions = (cands: { label: string; detail?: string; info?: string; type?: string }[]) =>
      cands.map((c) => ({
        label: c.label,
        ...(c.detail ? { detail: c.detail } : {}),
        ...(c.info ? { info: c.info } : {}),
        ...(c.type ? { type: c.type } : {}),
      }));
    const rhaiSource = (ctx: import('@codemirror/autocomplete').CompletionContext) => {
      const cands = completeRhai.rhaiCompletions(ctx.state.doc.toString(), ctx.pos);
      if (!cands.length) return null;
      const word = ctx.matchBefore(/[A-Za-z0-9_]*/);
      return { from: word ? word.from : ctx.pos, options: toOptions(cands), validFor: /^[A-Za-z0-9_]*$/ };
    };
    const yamlSource = (ctx: import('@codemirror/autocomplete').CompletionContext) => {
      const cands = completeYaml.pocYamlCompletions(ctx.state.doc.toString(), ctx.pos);
      if (!cands.length) return null;
      const word = ctx.matchBefore(/[\w-]*/);
      return { from: word ? word.from : ctx.pos, options: toOptions(cands), validFor: /^[\w-]*$/ };
    };
    const completions = {
      rhai: autocomplete.autocompletion({ override: [rhaiSource] }),
      yaml: autocomplete.autocompletion({ override: [yamlSource] }),
    };

    const theme = view.EditorView.theme({
      '&': {
        height: '100%',
        fontFamily: 'var(--font-data)',
        fontSize: 'var(--font-size-md)',
        color: 'var(--color-text-primary)',
        backgroundColor: 'var(--color-ground-surface)',
      },
      '&.cm-focused': { outline: 'none' },
      '.cm-scroller': { fontFamily: 'inherit', lineHeight: '20px', overflow: 'auto' },
      '.cm-content': { padding: '8px 0', caretColor: 'var(--color-text-primary)', minHeight: '100%' },
      '.cm-line': { padding: '0 16px 0 4px' },
      '.cm-gutters': {
        backgroundColor: 'var(--color-ground-surface)',
        color: 'var(--color-syntax-line-number)',
        border: 'none',
        fontSize: 'var(--font-size-xs)',
      },
      '.cm-lineNumbers .cm-gutterElement': { minWidth: '44px', padding: '0 14px 0 0', textAlign: 'right' },
      '.cm-foldGutter': { width: '12px', marginLeft: '-12px' },
      '.cm-foldGutter .cm-gutterElement': { padding: '0', color: 'var(--color-text-tertiary)', fontSize: 'var(--font-size-xs)', textAlign: 'center' },
      '.cm-foldGutter .cm-gutterElement:hover': { color: 'var(--color-text-primary)' },
      '.cm-activeLine': { backgroundColor: 'var(--color-syntax-current-line)' },
      '.cm-activeLineGutter': { backgroundColor: 'var(--color-syntax-current-line)', color: 'var(--color-text-secondary)' },
      '.cm-foldPlaceholder': {
        backgroundColor: 'var(--color-ground-raised)',
        border: '1px solid var(--color-line-control)',
        color: 'var(--color-text-secondary)',
        borderRadius: 'var(--radius-badge)',
        padding: '0 4px',
        margin: '0 2px',
      },
      '.cm-selectionBackground, &.cm-focused .cm-selectionBackground, .cm-content ::selection': {
        backgroundColor: 'var(--color-accent-tint) !important',
      },
      '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--color-text-primary)' },
      '.cm-matchingBracket, &.cm-focused .cm-matchingBracket': {
        backgroundColor: 'transparent',
        boxShadow: 'inset 0 -1px 0 var(--color-text-secondary)',
      },
      '.cm-nonmatchingBracket': { color: 'var(--color-status-server-error)' },
      '.cm-searchMatch': { backgroundColor: 'var(--color-syntax-match)', borderRadius: '2px' },
      '.cm-searchMatch.cm-searchMatch-selected': { outline: '1px solid var(--color-accent-base)' },
      '.cm-selectionMatch': { backgroundColor: 'color-mix(in srgb, var(--color-syntax-match) 55%, transparent)' },
      '.cm-line-edited': { boxShadow: 'inset 2px 0 0 var(--color-intercept-base)' },
      '.cm-placeholder': { color: 'var(--color-text-tertiary)' },
      // Completion popover: foundation floating surface (radius 10, floating shadow), data face (§2.8).
      '.cm-tooltip.cm-tooltip-autocomplete': {
        backgroundColor: 'var(--color-ground-raised)',
        border: '1px solid var(--color-line-border)',
        borderRadius: 'var(--radius-floating)',
        boxShadow: 'var(--shadow-floating)',
        overflow: 'hidden',
      },
      '.cm-tooltip-autocomplete > ul': { fontFamily: 'var(--font-data)', fontSize: 'var(--font-size-sm)', maxHeight: '16em' },
      '.cm-tooltip-autocomplete > ul > li': { padding: '2px 8px', color: 'var(--color-text-primary)' },
      '.cm-tooltip-autocomplete > ul > li[aria-selected]': {
        backgroundColor: 'var(--color-accent-tint)',
        color: 'var(--color-text-primary)',
      },
      '.cm-completionLabel': { color: 'var(--color-text-primary)' },
      '.cm-completionMatchedText': { textDecoration: 'none', color: 'var(--color-accent-base)', fontWeight: 'var(--font-weight-medium)' },
      '.cm-completionDetail': { color: 'var(--color-text-tertiary)', fontStyle: 'normal', marginLeft: '1em' },
      '.cm-tooltip.cm-completionInfo': {
        backgroundColor: 'var(--color-ground-raised)',
        border: '1px solid var(--color-line-border)',
        borderRadius: 'var(--radius-floating)',
        boxShadow: 'var(--shadow-floating)',
        color: 'var(--color-text-secondary)',
        fontFamily: 'var(--font-ui)',
        fontSize: 'var(--font-size-sm)',
        padding: '6px 10px',
      },
      // Search panel, restyled: 28px controls, radius 6, UI face 12px.
      '.cm-panels': {
        backgroundColor: 'var(--color-ground-raised)',
        color: 'var(--color-text-primary)',
        fontFamily: 'var(--font-ui)',
        fontSize: 'var(--font-size-sm)',
      },
      '.cm-panels.cm-panels-top': { borderBottom: '1px solid var(--color-line-border)' },
      '.cm-panel.cm-search': { padding: '4px 12px', display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '6px' },
      '.cm-panel.cm-search br': { display: 'none' },
      '.cm-panel.cm-search label': { display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' },
      '.cm-panel.cm-search input[type=checkbox]': { margin: '0', accentColor: 'var(--color-accent-base)' },
      '.cm-textfield': {
        height: 'var(--size-control)',
        borderRadius: 'var(--radius-control)',
        border: '1px solid var(--color-line-control)',
        backgroundColor: 'var(--color-ground-surface)',
        color: 'var(--color-text-primary)',
        fontFamily: 'var(--font-data)',
        fontSize: 'var(--font-size-sm)',
        padding: '0 8px',
        margin: '0',
      },
      '.cm-textfield:focus': { outline: '2px solid var(--color-line-focus)', outlineOffset: '1px' },
      '.cm-button': {
        height: 'var(--size-control)',
        borderRadius: 'var(--radius-control)',
        border: '1px solid var(--color-line-control)',
        backgroundColor: 'var(--color-ground-surface)',
        backgroundImage: 'none',
        color: 'var(--color-text-primary)',
        fontFamily: 'var(--font-ui)',
        fontSize: 'var(--font-size-sm)',
        padding: '0 10px',
        margin: '0',
        cursor: 'default',
      },
      '.cm-button:hover': { backgroundColor: 'var(--color-ground-hover)' },
      '.cm-button:active': { transform: 'scale(0.97)' },
      '.cm-panel.cm-search [name=close]': {
        position: 'static',
        marginLeft: 'auto',
        color: 'var(--color-text-secondary)',
        fontSize: 'var(--font-size-base)',
        padding: '0 4px',
      },
    });

    const originalLines = state.Facet.define<Set<string>, Set<string> | null>({ combine: (v) => (v.length ? v[0]! : null) });
    const editedDeco = view.Decoration.line({ class: 'cm-line-edited' });
    const build = (v: EditorView) => {
      const orig = v.state.facet(originalLines);
      if (!orig) return view.Decoration.none;
      const b = new state.RangeSetBuilder<import('@codemirror/view').Decoration>();
      for (const { from, to } of v.visibleRanges) {
        let pos = from;
        while (pos <= to) {
          const line = v.state.doc.lineAt(pos);
          if (!orig.has(line.text)) b.add(line.from, line.from, editedDeco);
          pos = line.to + 1;
        }
      }
      return b.finish();
    };
    const editedPlugin = view.ViewPlugin.fromClass(
      class {
        decorations: import('@codemirror/view').DecorationSet;
        constructor(v: EditorView) {
          this.decorations = build(v);
        }
        update(u: import('@codemirror/view').ViewUpdate) {
          if (u.docChanged || u.viewportChanged) this.decorations = build(u.view);
        }
      },
      { decorations: (p) => p.decorations },
    );
    const editedLines = (original: string): Extension => [originalLines.of(new Set(original.split('\n'))), editedPlugin];

    return {
      state,
      view,
      language,
      commands,
      search,
      json,
      autocomplete,
      theme: [theme, language.syntaxHighlighting(highlightStyle)],
      editedLines,
      langs,
      completions,
    };
  })();
  return cmPromise;
}

export function loadMerge(): Promise<MergeMod> {
  if (!mergePromise) mergePromise = import('@codemirror/merge');
  return mergePromise;
}

/** The fold-gutter chevrons from the mockup (▾ open, ▸ closed). */
function foldMarker(open: boolean): HTMLElement {
  const s = document.createElement('span');
  s.className = 'cm-fold-marker';
  s.textContent = open ? '▾' : '▸';
  s.setAttribute('aria-hidden', 'true');
  return s;
}

/** The common extension set for a body/raw viewer. */
export function baseExtensions(cm: CM, o: StateOptions): Extension[] {
  const { view, state, language, commands, search } = cm;
  const editable = !!o.editable;
  const ext: Extension[] = [
    view.lineNumbers(),
    language.foldGutter({ markerDOM: foldMarker }),
    view.highlightActiveLine(),
    view.highlightActiveLineGutter(),
    view.drawSelection(),
    view.rectangularSelection(),
    view.highlightSpecialChars(),
    language.bracketMatching(),
    language.indentOnInput(),
    search.search({ top: true }),
    search.highlightSelectionMatches(),
    view.keymap.of([...commands.defaultKeymap, ...search.searchKeymap, ...language.foldKeymap]),
    cm.theme,
    state.EditorState.tabSize.of(2),
  ];
  if (o.lang === 'json') ext.push(cm.json.json());
  else if (o.lang === 'rhai' || o.lang === 'yaml') ext.push(cm.langs[o.lang]);
  if (editable) {
    ext.push(commands.history(), view.keymap.of([...commands.historyKeymap, commands.indentWithTab]));
    // Schema/catalog-aware completion is an edit-path affordance only (spec §1.1, plan Task 4).
    if (o.lang === 'rhai' || o.lang === 'yaml') {
      ext.push(cm.completions[o.lang], view.keymap.of(cm.autocomplete.completionKeymap));
    }
    const edited = o.original != null ? cm.editedLines(o.original) : [];
    ext.push(o.editedCompartment ? o.editedCompartment.of(edited) : edited);
    if (o.onChange) {
      const cb = o.onChange;
      ext.push(view.EditorView.updateListener.of((u) => u.docChanged && cb(u.state.doc.toString())));
    }
  } else {
    ext.push(state.EditorState.readOnly.of(true), view.EditorView.editable.of(false));
  }
  if (o.extra) ext.push(...o.extra);
  return ext;
}

export function makeState(cm: CM, doc: string, o: StateOptions): EditorState {
  return cm.state.EditorState.create({ doc, extensions: baseExtensions(cm, o) });
}
