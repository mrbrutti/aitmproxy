// The ⌘K command palette (foundation §2.7). Rendered by the shell when app.ui.paletteOpen;
// closes via app.openPalette(false). Fuzzy search over every bus command (from tools/list),
// flows by URL, and setup actions; Recent and Pinned at the top. Selecting a command with
// parameters grows the panel into a schema-generated form; the result renders inline.
// Opened from ⌘K it does not animate; opened from the toolbar button it pops 160ms from .97.
import { createEffect, createMemo, createSignal, For, Match, on, onCleanup, onMount, Show, Switch, type Component } from 'solid-js';
import { Portal } from 'solid-js/web';
import { useApp } from '~/state/context';
import type { ToolDef } from '~/bus/types';
import { Button } from '~/components/Button';
import { Icon } from '~/components/Icon';
import { Kbd } from '~/components/Kbd';
import { FlowLine } from '~/lib/schema-form/FlowLine';
import { SchemaForm } from '~/lib/schema-form/SchemaForm';
import { createFormState, type FormState, type RawValues } from '~/lib/schema-form/infer';
import { isCACancelled, isCATrustTool } from '~/state/caTrust';
import { isMalformedConfirm, isNeedsConfirm, MALFORMED_CONFIRM_MESSAGE, STALE_CONFIRM_MESSAGE } from '~/bus/confirm';
import { segments } from '~/lib/fuzzy';
import { openedByPointer } from '~/lib/pointer';
import { buildGroups, commandKey, compactJson, flatten, flowIdsIn, parseQuery, pushRecent, readPinned, readRecent, setupKey, togglePinned, type PaletteItem } from './groups';
import { setupActions } from './setup';
import css from './palette.module.css';

type Stage =
  | { kind: 'list' }
  | { kind: 'form'; tool: ToolDef; form: FormState; confirming: boolean }
  | { kind: 'confirm'; tool: ToolDef; args: Record<string, unknown>; prompt: string; token: string }
  | { kind: 'running'; tool: ToolDef }
  | { kind: 'result'; tool: ToolDef; ok: boolean; value: unknown; ms: number; args: Record<string, unknown> };

/** Which call of the bus confirm handshake (bus spec D4) a run is: the first, or the re-send carrying `_confirm`. */
type Phase = { kind: 'begin' } | { kind: 'confirm'; token: string };

/** How one call ended; `ask` only ever comes from the `begin` phase, a second envelope is `stale`. */
type Outcome = { kind: 'done'; value: unknown } | { kind: 'ask'; prompt: string; token: string } | { kind: 'stale' } | { kind: 'failed'; message: string };

export const CommandPalette: Component = () => {
  const app = useApp();
  const animate = openedByPointer();
  const [query, setQuery] = createSignal('');
  const [active, setActive] = createSignal(0);
  const [recent, setRecent] = createSignal(readRecent());
  const [pinned, setPinned] = createSignal(readPinned());
  const [stage, setStage] = createSignal<Stage>({ kind: 'list' });
  let input: HTMLInputElement | undefined;
  let list: HTMLDivElement | undefined;
  const previous = document.activeElement as HTMLElement | null;

  let disposed = false;
  /** Bumped by every `run`; a reply whose run is no longer the latest ends that run without touching the stage. */
  let runSeq = 0;
  /** The `run` that holds the CA in-flight flag (§D17.12); only its ending releases it, so a superseded CA run cannot release what a newer one holds. */
  let caOwner = 0;
  const close = () => app.openPalette(false);
  onCleanup(() => {
    disposed = true;
    if (previous && document.contains(previous)) previous.focus({ preventScroll: true });
    const s = stage();
    if (s.kind === 'confirm' && isCATrustTool(s.tool.name)) void releaseCA();
  });
  onMount(() => queueMicrotask(() => input?.focus()));

  const setup = createMemo(() => setupActions(app, close));
  const groups = createMemo(() => {
    app.version();
    return buildGroups({ query: query(), tools: app.proxy.tools, flows: app.entries, recent: recent(), pinned: pinned(), setup: setup() });
  });
  const items = createMemo(() => flatten(groups()));
  /** Groups with each item's position in the flat list, for aria-activedescendant and scrolling. */
  const indexed = createMemo(() => {
    let i = 0;
    return groups().map((g) => ({ ...g, rows: g.items.map((item) => ({ item, index: i++ })) }));
  });
  const mode = createMemo(() => parseQuery(query()).mode);

  createEffect(on(items, () => setActive(0)));
  createEffect(
    on(active, (i) => {
      const el = list?.querySelector<HTMLElement>(`[data-index="${i}"]`);
      if (el && typeof el.scrollIntoView === 'function') el.scrollIntoView({ block: 'nearest' });
    }),
  );

  // ---- running commands ----
  const toolByName = (name: string) => app.proxy.tools.find((t) => t.name === name) ?? null;

  /** When a `ca.install` / `ca.uninstall` run ends, however it ends (§D17.12): the read-back the word comes from (D17.5), then the in-flight flag. */
  const releaseCA = async () => {
    if (!(await app.refreshCA())) app.notice('ca.status could not be re-read; the CA word may be stale', 'error');
    app.setCAInstalling(false);
  };

  const callFor = async (tool: ToolDef, args: Record<string, unknown>, phase: Phase): Promise<Outcome> => {
    try {
      const value = await app.call(tool.name, phase.kind === 'begin' ? args : { ...args, _confirm: phase.token });
      if (isMalformedConfirm(value)) return { kind: 'failed', message: MALFORMED_CONFIRM_MESSAGE };
      if (!isNeedsConfirm(value)) return { kind: 'done', value };
      if (phase.kind === 'confirm') return { kind: 'stale' };
      return { kind: 'ask', prompt: value.prompt, token: value.confirm_token };
    } catch (e) {
      return { kind: 'failed', message: (e as Error).message };
    }
  };

  /**
   * Where a call's outcome takes the palette. Only a palette still waiting for this very run is
   * written to: one that was closed, left, or moved on to a newer run meanwhile treats the reply
   * as the end of the run (a failure or a stale token becomes a notice, a result is dropped).
   * A CA run (§D17.12) is released on every ending while it owns the flag, never while the prompt is up.
   */
  const settle = async (tool: ToolDef, args: Record<string, unknown>, outcome: Outcome, t0: number, seq: number) => {
    const ca = isCATrustTool(tool.name);
    // A snapshot is exact here: every setStage in this function precedes its first await.
    const awaited = !disposed && seq === runSeq && stage().kind === 'running';
    const show = (s: Stage) => {
      if (awaited) setStage(s);
    };
    const result = (ok: boolean, value: unknown): Stage => ({ kind: 'result', tool, ok, value, ms: performance.now() - t0, args });
    const fail = (message: string) => (awaited ? setStage(result(false, message)) : app.notice(message, 'error'));
    switch (outcome.kind) {
      case 'ask':
        if (awaited) setStage({ kind: 'confirm', tool, args, prompt: outcome.prompt, token: outcome.token });
        else if (ca && caOwner === seq) await releaseCA();
        return;
      case 'done':
        show(result(true, outcome.value));
        if (tool.mutates !== false) void app.refreshSide();
        break;
      case 'stale':
        fail(STALE_CONFIRM_MESSAGE);
        break;
      case 'failed':
        if (ca && isCACancelled(outcome.message)) {
          // The operator dismissed the OS dialog: calm (D17.4), nothing to inspect.
          app.notice(outcome.message, 'info');
          show({ kind: 'list' });
        } else fail(outcome.message);
        break;
    }
    if (ca && caOwner === seq) await releaseCA();
    setRecent(pushRecent(commandKey(tool.name)));
  };

  /** One call of a command: the first by default, the confirming re-send when `phase` carries the token. */
  const run = async (tool: ToolDef, args: Record<string, unknown>, phase: Phase = { kind: 'begin' }) => {
    const seq = ++runSeq;
    setStage({ kind: 'running', tool });
    const t0 = performance.now();
    if (isCATrustTool(tool.name)) {
      caOwner = seq;
      if (phase.kind === 'begin') app.setCAInstalling(true);
    }
    await settle(tool, args, await callFor(tool, args, phase), t0, seq);
  };

  /** The operator declined the bus's prompt: nothing ran, nothing more is sent. */
  const cancelConfirm = async (tool: ToolDef) => {
    backToList();
    if (isCATrustTool(tool.name)) await releaseCA();
  };

  /** Initial form values from a setup action's arguments: strings and booleans as they are, the rest as JSON text. */
  const toRawValues = (args: Record<string, unknown>): RawValues =>
    Object.fromEntries(Object.entries(args).map(([k, v]) => [k, typeof v === 'string' || typeof v === 'boolean' ? v : JSON.stringify(v)]));

  const selectTool = (tool: ToolDef, initial: Record<string, unknown> = {}) => {
    const form = createFormState(tool, toRawValues(initial));
    if (form.fields.length === 0) {
      if (typeof tool.confirm === 'string') setStage({ kind: 'form', tool, form, confirming: true });
      else void run(tool, initial);
      return;
    }
    setStage({ kind: 'form', tool, form, confirming: false });
  };

  const submitForm = () => {
    const s = stage();
    if (s.kind !== 'form') return;
    s.form.touchAll();
    const r = s.form.result();
    if (!r.valid) return;
    if (typeof s.tool.confirm === 'string' && !s.confirming) {
      setStage({ ...s, confirming: true });
      return;
    }
    void run(s.tool, r.args);
  };

  const choose = (item: PaletteItem) => {
    switch (item.kind) {
      case 'command':
        selectTool(item.tool);
        break;
      case 'flow':
        app.select(item.entry.id);
        close();
        break;
      case 'setup': {
        setRecent(pushRecent(setupKey(item.action.id)));
        if (item.action.tool) {
          const t = toolByName(item.action.tool);
          if (t) selectTool(t, item.action.args ?? {});
          else app.notice(`${item.action.tool} is not available on this bus`, 'error');
        } else void item.action.run?.();
        break;
      }
    }
  };

  const backToList = () => {
    setStage({ kind: 'list' });
    queueMicrotask(() => input?.focus());
  };

  const onKeyDown = (e: KeyboardEvent) => {
    const s = stage();
    if (e.key === 'Escape') {
      e.preventDefault();
      if (s.kind === 'list') close();
      else if (s.kind === 'form' && s.confirming && s.form.fields.length) setStage({ ...s, confirming: false });
      else if (s.kind === 'confirm') void cancelConfirm(s.tool);
      else backToList();
      return;
    }
    if (s.kind !== 'list') {
      if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        if (s.kind === 'form') submitForm();
        else if (s.kind === 'confirm') void run(s.tool, s.args, { kind: 'confirm', token: s.token });
        else if (s.kind === 'result') void run(s.tool, s.args);
      }
      return;
    }
    const n = items().length;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        if (n) setActive((a) => (a + 1) % n);
        break;
      case 'ArrowUp':
        e.preventDefault();
        if (n) setActive((a) => (a - 1 + n) % n);
        break;
      case 'Home':
        if (!query()) {
          e.preventDefault();
          setActive(0);
        }
        break;
      case 'End':
        if (!query()) {
          e.preventDefault();
          setActive(Math.max(0, n - 1));
        }
        break;
      case 'Enter': {
        const it = items()[active()];
        if (it) {
          e.preventDefault();
          choose(it);
        }
        break;
      }
      case 'p':
      case 'P':
        if (e.metaKey || e.ctrlKey) {
          const it = items()[active()];
          if (it?.kind === 'command') {
            e.preventDefault();
            setPinned(togglePinned(it.tool.name));
          }
        }
        break;
    }
  };

  const copy = (text: string) => {
    void navigator.clipboard?.writeText(text).then(
      () => app.notice('Copied'),
      () => app.notice('Could not copy', 'error'),
    );
  };

  return (
    <Portal>
      <div class={css.scrim} onPointerDown={close} />
      <div class={css.panel} data-animate={animate ? 'true' : 'false'} role="dialog" aria-modal="true" aria-label="Command palette" onKeyDown={onKeyDown}>
        <div class={css.inputRow}>
          <Icon name="search" />
          <input
            ref={input}
            class={css.input}
            type="text"
            role="combobox"
            aria-expanded={stage().kind === 'list'}
            aria-controls="palette-list"
            aria-activedescendant={stage().kind === 'list' && items()[active()] ? `palette-item-${active()}` : undefined}
            aria-autocomplete="list"
            placeholder="Type a command, a URL, or a setup action…"
            value={query()}
            autocomplete="off"
            spellcheck={false}
            onInput={(e) => {
              setQuery(e.currentTarget.value);
              const s = stage();
              if (s.kind === 'confirm') void cancelConfirm(s.tool);
              else if (s.kind !== 'list') setStage({ kind: 'list' });
            }}
          />
          <Show when={mode() !== 'all'}>
            <span class={css.mode}>{mode() === 'commands' ? 'commands' : 'flows'}</span>
          </Show>
          <Kbd class={css.esc}>esc</Kbd>
        </div>
        <div class={css.rule} />

        <Switch>
          <Match when={stage().kind === 'list'}>
            <div ref={list} id="palette-list" class={css.list} role="listbox" aria-label="Results">
              <For
                each={indexed()}
                fallback={
                  <div class={css.empty}>
                    Nothing matches — try <code>&gt;</code> for commands or <code>/</code> for flows.
                  </div>
                }
              >
                {(group) => (
                  <>
                    <div class={css.groupLabel} role="presentation">
                      {group.label}
                    </div>
                    <For each={group.rows}>
                      {(row) => {
                        const item = row.item;
                        const i = row.index;
                        return (
                          <button
                            type="button"
                            id={`palette-item-${i}`}
                            role="option"
                            aria-selected={active() === i}
                            class={css.item}
                            data-index={i}
                            data-active={active() === i ? 'true' : undefined}
                            tabIndex={-1}
                            onPointerMove={() => active() !== i && setActive(i)}
                            onClick={() => choose(item)}
                          >
                            <Switch>
                              <Match when={item.kind === 'command' && item}>
                                {(it) => (
                                  <>
                                    <span class={css.name}>
                                      <For each={segments(it().tool.name, it().nameHits)}>{(s) => <span class={s.hit ? css.hit : undefined}>{s.text}</span>}</For>
                                    </span>
                                    <span class={css.desc}>
                                      <For each={segments(it().tool.description, it().descHits)}>{(s) => <span class={s.hit ? css.hit : undefined}>{s.text}</span>}</For>
                                    </span>
                                    <span class={css.meta}>
                                      <Show when={it().tool.mutates === false}>read-only</Show>
                                      <Show when={it().pinned}>
                                        <Icon name="pin" size={12} label="Pinned" />
                                      </Show>
                                    </span>
                                  </>
                                )}
                              </Match>
                              <Match when={item.kind === 'flow' && item}>{(it) => <FlowLine flow={it().entry.flow} hits={it().hits} />}</Match>
                              <Match when={item.kind === 'setup' && item}>
                                {(it) => (
                                  <>
                                    <Icon name={it().action.icon} />
                                    <span class={css.label}>
                                      <For each={segments(it().action.label, it().hits)}>{(s) => <span class={s.hit ? css.hit : undefined}>{s.text}</span>}</For>
                                    </span>
                                    <Show when={it().action.hint}>
                                      <span class={css.meta}>{it().action.hint}</span>
                                    </Show>
                                  </>
                                )}
                              </Match>
                            </Switch>
                          </button>
                        );
                      }}
                    </For>
                  </>
                )}
              </For>
            </div>
            <div class={css.foot}>
              <span>
                <Kbd>↑↓</Kbd> navigate
              </span>
              <span>
                <Kbd>↵</Kbd> run
              </span>
              <span>
                <Kbd>⌘P</Kbd> pin
              </span>
              <span class={css.spacer} />
              <span>
                <Kbd>&gt;</Kbd> commands
              </span>
              <span>
                <Kbd>/</Kbd> flows
              </span>
            </div>
          </Match>

          <Match when={stage().kind === 'form' && stage()}>
            {(s) => {
              const st = () => s() as Extract<Stage, { kind: 'form' }>;
              return (
                <div class={css.stage}>
                  <div class={css.stageHead}>
                    <span class={css.name}>{st().tool.name}</span>
                    <span class={css.desc}>{st().tool.description}</span>
                    <Show when={st().tool.mutates === false}>
                      <span class={css.readOnly}>read-only</span>
                    </Show>
                  </div>
                  <Show when={st().form.fields.length} fallback={<span class={css.noParams}>No parameters.</span>}>
                    <SchemaForm form={st().form} idPrefix={`palette-${st().tool.name.replace(/\W/g, '-')}`} autofocus onSubmit={submitForm} />
                  </Show>
                  <Show when={st().confirming && typeof st().tool.confirm === 'string'}>
                    <div class={css.confirm} role="alert">
                      {st().tool.confirm}
                    </div>
                  </Show>
                  <div class={css.stageFoot}>
                    <button type="button" class={css.ghostBtn} onClick={backToList}>
                      <Icon name="chevron-right" size={12} style={{ transform: 'rotate(180deg)' }} />
                      Back
                      <Kbd>esc</Kbd>
                    </button>
                    <span class={css.spacer} />
                    <Button variant="primary" kbd="⌘⏎" onClick={submitForm} disabled={!st().form.result().valid && st().form.touched().size > 0} ref={(n) => st().form.fields.length === 0 && queueMicrotask(() => n.focus())}>
                      {st().confirming ? 'Confirm' : 'Run'}
                    </Button>
                  </div>
                </div>
              );
            }}
          </Match>

          <Match when={stage().kind === 'confirm' && stage()}>
            {(s) => {
              const st = () => s() as Extract<Stage, { kind: 'confirm' }>;
              return (
                <div class={css.stage}>
                  <div class={css.stageHead}>
                    <span class={css.name}>{st().tool.name}</span>
                    <span class={css.desc}>{st().tool.description}</span>
                  </div>
                  <div class={css.confirm} role="alert">
                    {st().prompt}
                  </div>
                  <div class={css.stageFoot}>
                    <button type="button" class={css.ghostBtn} onClick={() => void cancelConfirm(st().tool)}>
                      <Icon name="chevron-right" size={12} style={{ transform: 'rotate(180deg)' }} />
                      Cancel
                      <Kbd>esc</Kbd>
                    </button>
                    <span class={css.spacer} />
                    <Button variant="primary" kbd="⌘⏎" onClick={() => void run(st().tool, st().args, { kind: 'confirm', token: st().token })} ref={(n) => queueMicrotask(() => n.focus())}>
                      Confirm
                    </Button>
                  </div>
                </div>
              );
            }}
          </Match>

          <Match when={stage().kind === 'running' && stage()}>
            {(s) => (
              <div class={css.stage}>
                <div class={css.stageHead}>
                  <span class={css.name}>{(s() as Extract<Stage, { kind: 'running' }>).tool.name}</span>
                  <span class={css.running}>Running…</span>
                </div>
              </div>
            )}
          </Match>

          <Match when={stage().kind === 'result' && stage()}>
            {(s) => {
              const st = () => s() as Extract<Stage, { kind: 'result' }>;
              const json = createMemo(() => compactJson(st().value));
              const full = () => (typeof st().value === 'string' ? (st().value as string) : (JSON.stringify(st().value, null, 2) ?? ''));
              const flows = createMemo(() => {
                app.version();
                return flowIdsIn(st().value, (id) => app.byId.has(id));
              });
              return (
                <div class={css.stage}>
                  <div class={css.stageHead}>
                    <span class={css.name}>{st().tool.name}</span>
                    <span class={css.desc}>{st().tool.description}</span>
                  </div>
                  <div class={css.result} data-state={st().ok ? 'ok' : 'error'} role="status">
                    <div class={css.resultHead}>
                      <span class={css.dot} aria-hidden="true" />
                      <b>{st().ok ? 'ok' : 'error'}</b>
                      <span class={css.ms}>{Math.round(st().ms)} ms</span>
                      <span class={css.spacer} />
                      <button type="button" class={css.ghostBtn} onClick={() => copy(full())}>
                        <Icon name="copy" size={12} />
                        Copy
                      </button>
                    </div>
                    <pre class={css.json} data-truncated={json().truncated ? 'true' : undefined} tabIndex={0}>
                      {json().text}
                    </pre>
                    <Show when={flows().length}>
                      <div class={css.links}>
                        <For each={flows()}>
                          {(f) => (
                            <button
                              type="button"
                              onClick={() => {
                                app.select(f.id);
                                close();
                              }}
                            >
                              Open{f.label ? <code> {f.label}</code> : ''} →
                            </button>
                          )}
                        </For>
                      </div>
                    </Show>
                  </div>
                  <div class={css.stageFoot}>
                    <button type="button" class={css.ghostBtn} onClick={backToList} ref={(n) => queueMicrotask(() => n.focus())}>
                      <Icon name="chevron-right" size={12} style={{ transform: 'rotate(180deg)' }} />
                      Back
                      <Kbd>esc</Kbd>
                    </button>
                    <span class={css.spacer} />
                    <Button variant="outline" kbd="⌘⏎" onClick={() => void run(st().tool, st().args)}>
                      Run again
                    </Button>
                  </div>
                </div>
              );
            }}
          </Match>
        </Switch>
      </div>
    </Portal>
  );
};
