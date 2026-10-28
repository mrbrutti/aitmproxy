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

export interface CM {
  state: StateMod;
  view: ViewMod;
  language: LanguageMod;
  commands: CommandsMod;
  search: SearchMod;
  json: JsonMod;
  /** Shared theme + highlight extensions (tokens only). */
  theme: Extension;
  /** Amber left edge on lines that differ from the original request (§2.7 `.l.edited`). */
  editedLines: (original: string) => Extension;
}

export type Lang = 'json' | 'text';

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
    const [state, view, language, commands, search, json, highlight] = await Promise.all([
      import('@codemirror/state'),
      import('@codemirror/view'),
      import('@codemirror/language'),
      import('@codemirror/commands'),
      import('@codemirror/search'),
      import('@codemirror/lang-json'),
      import('@lezer/highlight'),
    ]);
    const t = highlight.tags;
    const highlightStyle = language.HighlightStyle.define([
      { tag: t.propertyName, color: 'var(--color-syntax-key)' },
      { tag: t.string, color: 'var(--color-syntax-string)' },
      { tag: t.number, color: 'var(--color-syntax-number)' },
      { tag: [t.bool, t.null, t.keyword], color: 'var(--color-syntax-boolean)' },
      { tag: [t.punctuation, t.separator], color: 'var(--color-syntax-punct)' },
      { tag: [t.brace, t.bracket, t.squareBracket, t.paren], color: 'var(--color-syntax-bracket)' },
    ]);

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
      theme: [theme, language.syntaxHighlighting(highlightStyle)],
      editedLines,
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
  if (editable) {
    ext.push(commands.history(), view.keymap.of([...commands.historyKeymap, commands.indentWithTab]));
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
