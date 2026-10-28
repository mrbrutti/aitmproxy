// One PoC run: title, meta line, Assertions, Finding capture, Screenshot, YAML, and the actions
// bar (Run again · Export · Open capture). Data is null-safe; missing values print a grey dash.

import { createEffect, createMemo, createResource, createSignal, For, Match, on, onCleanup, Show, Switch, type Component } from 'solid-js';
import { Portal } from 'solid-js/web';
import type { PocRun } from '~/bus/mock';
import { Badge, Button, Icon, Menu, Popover, type AnchorRect } from '~/components';
import { methodHue, statusHue, type FlowSummary } from '~/model/flow';
import { useApp } from '~/state/context';
import { artifactDataUrl, downloadBlob, exportFilename, pngBlob, toArtifact, yamlBlob, type Artifact } from './export';
import { fmtWhen, fmtWhenFull, matchedCount, parseVars, varsFromYaml, varsText, verdictOf, whenOf } from './model';
import { SeverityPill } from './SeverityPill';
import { findingsState } from './state';
import { tokenizeYaml } from './yaml';
import css from './findings.module.css';

const anchorOf = (el: HTMLElement): AnchorRect => {
  const r = el.getBoundingClientRect();
  return { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
};

export interface FindingDetailProps {
  run: PocRun;
  ref?: ((el: HTMLDivElement) => void) | undefined;
  /** Select another run (the result of Run again). */
  onSelect: (id: string) => void;
}

export const FindingDetail: Component<FindingDetailProps> = (props) => {
  const app = useApp();
  /** Local YAML edits per run id; there is no `poc.save` yet (core follow-up). */
  const { localYaml, setLocalYaml, yamlRequested } = findingsState(app);
  const run = () => props.run;
  const verdict = createMemo(() => verdictOf(run()));

  // ---- source (lazy): poc.list carries no YAML, so the first look at an entry asks poc.get ----
  const [loadingPath, setLoadingPath] = createSignal<string | null>(null);
  const yamlLoading = () => !!run().poc_path && loadingPath() === run().poc_path;
  createEffect(
    on(
      () => [run().poc_path, run().yaml] as const,
      ([path, text]) => {
        if (!path || text || yamlRequested.has(path)) return;
        yamlRequested.add(path);
        setLoadingPath(path);
        void app.ensurePocSource(path).finally(() => loadingPath() === path && setLoadingPath(null));
      },
    ),
  );

  // ---- finding capture ----
  const flow = createMemo<FlowSummary | null>(() => {
    app.version();
    const id = run().finding_capture;
    return id ? (app.byId.get(id)?.flow ?? null) : null;
  });
  const openCapture = () => {
    const f = flow();
    if (f) app.select(f.id);
    else app.notice('The captured flow is no longer in the store', 'error');
  };

  // ---- screenshot (lazy, keyed by path) ----
  const [shot, { refetch: refetchShot }] = createResource(
    () => run().screenshot_path,
    async (path) => toArtifact(await app.call<unknown>('poc.artifact', { path }), path),
  );
  const shotUrl = createMemo(() => {
    const a = shot.latest;
    return a && !shot.error ? artifactDataUrl(a) : null;
  });
  const [zoom, setZoom] = createSignal(false);
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape' && zoom()) {
      e.stopPropagation();
      setZoom(false);
    }
  };
  document.addEventListener('keydown', onKey, true);
  onCleanup(() => document.removeEventListener('keydown', onKey, true));

  // ---- YAML ----
  const yaml = () => localYaml().get(run().id) ?? run().yaml ?? '';
  const edited = () => localYaml().has(run().id) && localYaml().get(run().id) !== run().yaml;
  const [editing, setEditing] = createSignal(false);
  const [draft, setDraft] = createSignal('');
  // A trailing newline is the file's terminator, not an extra numbered line.
  const lines = createMemo(() => {
    const l = tokenizeYaml(yaml());
    if (l.length > 1 && l[l.length - 1]!.length === 0) l.pop();
    return l;
  });
  const startEdit = () => {
    setDraft(yaml());
    setEditing(true);
  };
  const save = () => {
    const next = new Map(localYaml());
    if (draft() === run().yaml) next.delete(run().id);
    else next.set(run().id, draft());
    setLocalYaml(next);
    setEditing(false);
    app.notice('Saved locally — poc.save is a core follow-up');
  };
  const revert = () => {
    const next = new Map(localYaml());
    next.delete(run().id);
    setLocalYaml(next);
  };

  // ---- run again ----
  const [runAnchor, setRunAnchor] = createSignal<AnchorRect | null>(null);
  const [target, setTarget] = createSignal('');
  const [vars, setVars] = createSignal('');
  const [running, setRunning] = createSignal(false);
  const openRun = (el: HTMLElement) => {
    setTarget(run().target ?? '');
    setVars(varsText(varsFromYaml(yaml())));
    setRunAnchor(anchorOf(el));
  };
  const doRun = async () => {
    const path = run().poc_path;
    setRunAnchor(null);
    if (!path) {
      app.notice('This run has no PoC path to run', 'error');
      return;
    }
    const v = parseVars(vars());
    setRunning(true);
    try {
      const r = await app.runPoc(path, target().trim() || undefined, Object.keys(v).length ? v : undefined);
      if (r?.id) props.onSelect(r.id);
    } finally {
      setRunning(false);
    }
  };

  // ---- export ----
  const [exportAnchor, setExportAnchor] = createSignal<AnchorRect | null>(null);
  const exportYaml = () => downloadBlob(exportFilename(run(), 'yaml'), yamlBlob(yaml()));
  const exportPng = async () => {
    const path = run().screenshot_path;
    if (!path) return;
    try {
      const a: Artifact = shot.latest && !shot.error ? shot.latest : toArtifact(await app.call<unknown>('poc.artifact', { path }), path);
      if (!a.base64) throw new Error('empty artifact');
      downloadBlob(exportFilename(run(), 'png'), pngBlob(a.base64, a.mime));
    } catch (e) {
      app.notice(`Screenshot export failed: ${(e as Error).message}`, 'error');
    }
  };
  const exportAll = async () => {
    exportYaml();
    if (run().screenshot_path) await exportPng();
    app.notice(run().screenshot_path ? 'Downloaded the YAML and the screenshot — zip is a follow-up' : 'Downloaded the YAML — this run has no screenshot');
  };

  const counts = createMemo(() => matchedCount(run().evaluated));
  const copyPath = async () => {
    const p = run().poc_path;
    if (!p) return;
    try {
      await navigator.clipboard.writeText(p);
      app.notice('Path copied');
    } catch {
      app.notice('Clipboard unavailable', 'error');
    }
  };

  return (
    <div class={css.detail} ref={props.ref} tabIndex={-1} aria-label={`Finding: ${run().title ?? ''}`}>
      <div class={css.bar} role="toolbar" aria-label="Finding actions">
        <Show when={!running()} fallback={<span class={`${css.running} ${css.note}`}>Running…</span>}>
          <Button
            variant="toolbar"
            onClick={(e) => openRun(e.currentTarget)}
            disabled={!run().poc_path || !!run().local}
            title={run().local ? 'Not saved on the server — export the YAML into poc.dir first' : run().poc_path ? (verdict() === 'not-run' ? 'Run this PoC' : 'Run this PoC again') : 'No PoC path'}
          >
            <Icon name="play" />
            Run again
          </Button>
        </Show>
        <Button variant="toolbar" onClick={(e) => setExportAnchor(anchorOf(e.currentTarget))} aria-haspopup="menu" aria-expanded={!!exportAnchor()}>
          <Icon name="download" />
          Export
          <Icon name="chevron-down" size={12} />
        </Button>
        <Button variant="toolbar" onClick={openCapture} disabled={!flow()} title={flow() ? 'Open the captured flow in the inspector' : 'The captured flow is not in the store'}>
          <Icon name="circle-arrow-right" />
          Open capture
        </Button>
      </div>

      <div class={css.body}>
        <h2 class={css.title}>{run().title || <span class={css.dash}>Untitled finding</span>}</h2>
        <div class={css.metaLine}>
          <SeverityPill severity={run().severity} />
          <span class={css.sep}>·</span>
          <span class={`${css.mono} ${css.target}`}>{run().target || <span class={css.dash}>—</span>}</span>
          <span class={css.sep}>·</span>
          <Show when={verdict() !== 'not-run'} fallback={<span class={css.dash}>Not run yet</span>}>
            <span class={css.verdictText} data-ok={run().passed ? 'true' : 'false'}>
              <Icon name={run().passed ? 'check' : 'x'} size={12} />
              {run().passed ? 'Passed' : 'Failed'}
            </span>
          </Show>
          <span class={css.sep}>·</span>
          <span class={css.mono} title={fmtWhenFull(whenOf(run())) ?? undefined}>
            {fmtWhen(whenOf(run())) ?? <span class={css.dash}>—</span>}
          </span>
          <span class={css.sep}>·</span>
          <Show when={run().origin === 'agent'} fallback={<span>{run().origin || <span class={css.dash}>—</span>}</span>}>
            <span class={css.tag}>agent</span>
          </Show>
        </div>
        <Show when={run().local}>
          <p class={css.localNote}>Built in this session — not saved on the server. Export the YAML into poc.dir to run it.</p>
        </Show>
        <Show when={run().poc_path}>
          <div class={css.pathLine}>
            <span class={css.path} title={run().poc_path}>
              {run().poc_path}
            </span>
            <button type="button" class={css.iconBtn} onClick={copyPath} aria-label="Copy PoC path" title="Copy path">
              <Icon name="copy" size={12} />
            </button>
          </div>
        </Show>

        {/* Assertions */}
        <section class={css.section} aria-labelledby="f-assertions">
          <div class={css.sectionHead}>
            <h3 id="f-assertions">Assertions</h3>
            <Show when={counts().total > 0}>
              <span class={css.count}>
                {counts().matched} of {counts().total} matched
              </span>
            </Show>
          </div>
          <Show when={verdict() !== 'not-run'} fallback={<p class={css.muted}>Run the PoC to evaluate its assertions.</p>}>
            <Show when={counts().total > 0} fallback={<p class={css.muted}>No assertions were evaluated.</p>}>
              <div class={css.assertions} role="table" aria-label="Assertions">
                <For each={run().evaluated}>
                  {(a) => (
                    <div class={css.arow} role="row">
                      <span class={css.verdict} data-ok={a.matched ? 'true' : 'false'} role="cell">
                        <Icon name={a.matched ? 'check' : 'x'} size={12} label={a.matched ? 'Matched' : 'Not matched'} />
                      </span>
                      <span class={css.assertion} role="cell">
                        {a.assertion || <span class={css.dash}>—</span>}
                      </span>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </Show>
        </section>

        {/* Finding capture */}
        <section class={css.section} aria-labelledby="f-capture">
          <div class={css.sectionHead}>
            <h3 id="f-capture">Finding capture</h3>
          </div>
          <Show
            when={flow()}
            fallback={
              <p class={css.muted}>
                {run().finding_capture ? (
                  <>
                    The captured flow is no longer in the store <span class={css.mono}>({run().finding_capture})</span>.
                  </>
                ) : (
                  'No capture for this run.'
                )}
              </p>
            }
          >
            {(f) => (
              <div class={css.capture}>
                <Badge hue={methodHue(f())}>{f().kind === 'websocket' ? 'WS' : f().method}</Badge>
                <span class={css.status} data-hue={statusHue(f())}>
                  {f().intercept === 'paused' ? 'Paused' : f().intercept === 'killed' ? 'Killed' : (f().status ?? '—')}
                </span>
                <span class={css.url} title={`${f().scheme}://${f().authority}${f().path}${f().query ? `?${f().query}` : ''}`}>
                  <span class={css.host}>
                    {f().scheme}://{f().authority}
                  </span>
                  <span class={css.p}>{f().path}</span>
                  <Show when={f().query}>
                    <span class={css.q}>?{f().query}</span>
                  </Show>
                </span>
                <Button variant="small" class={css.open} onClick={openCapture}>
                  Open in inspector
                </Button>
              </div>
            )}
          </Show>
        </section>

        {/* Screenshot */}
        <section class={css.section} aria-labelledby="f-shot">
          <div class={css.sectionHead}>
            <h3 id="f-shot">Screenshot</h3>
          </div>
          <Show when={run().screenshot_path} fallback={<p class={css.muted}>No screenshot for this run.</p>}>
            <Switch>
              <Match when={shot.error}>
                <div class={css.shotError}>
                  <span>Could not load the screenshot — {(shot.error as Error)?.message ?? 'unknown error'}</span>
                  <Button variant="small" onClick={() => void refetchShot()}>
                    Retry
                  </Button>
                </div>
              </Match>
              <Match when={shot.loading}>
                <div class={css.shotLoading} aria-busy="true" aria-label="Loading screenshot" />
              </Match>
              <Match when={shotUrl()}>
                {(url) => (
                  <button type="button" class={css.shotWrap} onClick={() => setZoom(true)} aria-label="Open screenshot full size">
                    <img class={css.shot} src={url()} alt={`Screenshot for ${run().title ?? 'finding'}`} />
                  </button>
                )}
              </Match>
              <Match when={true}>
                <p class={css.muted}>
                  <Icon name="image" size={12} style={{ 'vertical-align': '-1px', 'margin-right': '4px' }} />
                  Screenshot unavailable.
                </p>
              </Match>
            </Switch>
          </Show>
        </section>

        {/* YAML */}
        <section class={css.section} aria-labelledby="f-yaml">
          <div class={css.sectionHead}>
            <h3 id="f-yaml">YAML</h3>
            <div class={css.tools}>
              <Show when={edited() && !editing()}>
                <span class={css.note}>Edited locally · poc.save is a core follow-up</span>
                <Button variant="small" onClick={revert}>
                  Revert
                </Button>
              </Show>
              <Show
                when={editing()}
                fallback={
                  <Button variant="small" onClick={startEdit}>
                    <Icon name="pencil" size={12} />
                    Edit
                  </Button>
                }
              >
                <Button variant="small" onClick={() => setEditing(false)}>
                  Cancel
                </Button>
                <Button variant="small" active onClick={save}>
                  Save
                </Button>
              </Show>
            </div>
          </div>
          <Show
            when={editing()}
            fallback={
              <Show
                when={yaml()}
                fallback={
                  <Show when={yamlLoading()} fallback={<p class={css.muted}>No YAML for this run.</p>}>
                    <div class={css.yamlLoading} role="progressbar" aria-label="Loading PoC YAML">
                      <i />
                      <i />
                      <i />
                      <i />
                    </div>
                  </Show>
                }
              >
                <pre class={css.code} aria-label="PoC YAML">
                  <For each={lines()}>
                    {(toks) => (
                      <div class={css.l}>
                        <For each={toks}>{(t) => <span class={t.type === 'text' ? undefined : css[t.type]}>{t.text}</span>}</For>
                      </div>
                    )}
                  </For>
                </pre>
              </Show>
            }
          >
            <textarea
              class={css.editor}
              aria-label="Edit PoC YAML"
              value={draft()}
              rows={Math.min(40, Math.max(8, draft().split('\n').length + 1))}
              spellcheck={false}
              onInput={(e) => setDraft(e.currentTarget.value)}
              onKeyDown={(e) => {
                if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
                  e.preventDefault();
                  save();
                } else if (e.key === 'Escape') {
                  e.preventDefault();
                  setEditing(false);
                }
              }}
            />
          </Show>
        </section>
      </div>

      <Show when={runAnchor()}>
        {(a) => (
          <Popover anchor={a()} onClose={() => setRunAnchor(null)} placement="bottom-end" label="Run again">
            <form
              class={css.form}
              onSubmit={(e) => {
                e.preventDefault();
                void doRun();
              }}
            >
              <label>
                Target
                <input class={css.input} value={target()} onInput={(e) => setTarget(e.currentTarget.value)} placeholder={run().target || 'https://host'} spellcheck={false} />
              </label>
              <label>
                Vars
                <textarea class={css.vars} value={vars()} onInput={(e) => setVars(e.currentTarget.value)} placeholder={'key=value\none per line'} spellcheck={false} />
              </label>
              <div class={css.formActions}>
                <Button variant="outline" onClick={() => setRunAnchor(null)}>
                  Cancel
                </Button>
                <Button variant="primary" type="submit" kbd="⏎">
                  Run
                </Button>
              </div>
            </form>
          </Popover>
        )}
      </Show>

      <Show when={exportAnchor()}>
        {(a) => (
          <Menu
            anchor={a()}
            placement="bottom-end"
            label="Export"
            onClose={() => setExportAnchor(null)}
            items={[
              { label: 'YAML', onSelect: exportYaml },
              { label: 'Screenshot PNG', onSelect: () => void exportPng(), disabled: !run().screenshot_path, title: run().screenshot_path ? undefined : 'No screenshot for this run' },
              { type: 'separator' },
              { label: 'Everything', onSelect: () => void exportAll(), title: 'Downloads the YAML and the PNG as two files — zip is not available yet' },
            ]}
          />
        )}
      </Show>

      <Show when={zoom() && shotUrl()}>
        {(url) => (
          <Portal>
            <div class={css.lightbox} role="dialog" aria-label="Screenshot" onClick={() => setZoom(false)}>
              <img src={url()} alt={`Screenshot for ${run().title ?? 'finding'}`} />
            </div>
          </Portal>
        )}
      </Show>
    </div>
  );
};
