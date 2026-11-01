// The profile editor (D-T8.5, D-T8.6): every field of `ScanProfile` (D2), in the spec's order, and
// the only place in the web UI a scan is launched from.
//
// Four rules it exists to keep:
//
//   1. **What you see is what runs** (W-12). Every edit goes through `setDraft(name, next)` and the
//      launch sends that draft *whole* (`store.launch` -> `{ profile }`). Nothing is merged by name
//      on the core, so an unsaved tweak runs exactly as it reads here.
//   2. **The core is the guard** (D-T8.6). `preflight` only explains a dimmed button — it never
//      widens anything, an unknown L4 coverage answer never disables, and an agent session is not
//      pre-refused here: the note says what the core may do, and the core decides.
//   3. **Names, never values** (D7, W-13). The session preview prints the cookie and header *names*
//      the core reported and the canary line. This component holds no session material of any kind.
//   4. **A built-in is never overwritten.** Its name is read-only until the operator asks for
//      `Save as`, which is the only way a new profile name is authored.

import { batch, createEffect, createMemo, createSignal, For, on, Show, type Component, type ParentComponent } from 'solid-js';
import { Button, Icon } from '~/components';
import { ConfirmInject } from '~/panels/l4/ConfirmInject';
import { AddHost } from '~/panels/scope/AddHost';
import { useApp } from '~/state/context';
import { CheckTree } from './CheckTree';
import { AGENT_NOTE, L4_HINT, PROFILE_NAME_HINT, hostInScope, isValidProfileName, originHost, unknownSelectors } from './helpers';
import { preflight, type LaunchMode } from './launch';
import {
  ACCURACIES,
  CRAWL_STRATEGIES,
  HTTP_VERSION_POLICIES,
  INSERTION_KINDS,
  INTENSITIES,
  L4_TRANSPORTS,
  LANES,
  ON_LOST,
  POINT_TRAITS,
  RECORD_PROBES,
  SESSION_MODES,
  SPEEDS,
  USE_BROWSER,
  type AuditOptions,
  type Budget,
  type CrawlOptions,
  type HttpOptions,
  type IgnoreRule,
  type InsertionKind,
  type L4Options,
  type L4Seed,
  type L4Transport,
  type Lane,
  type PointTrait,
  type ScanProfile,
  type SessionOptions,
  type SessionProfile,
  type WsOptions,
} from './model';
import { scanStore } from './store';
import css from './scanner.module.css';

/* ------------------------------------------------------------------ small shared controls */

const Section: ParentComponent<{ title: string }> = (props) => (
  <section class={css.section}>
    <h3 class={css.sectionTitle}>{props.title}</h3>
    {props.children}
  </section>
);

const TextField: Component<{
  label: string;
  value: string;
  placeholder?: string | undefined;
  readOnly?: boolean | undefined;
  onValue: (v: string) => void;
}> = (props) => (
  <label class={css.field}>
    <span class={css.fieldLabel}>{props.label}</span>
    <input
      type="text"
      aria-label={props.label}
      value={props.value}
      placeholder={props.placeholder}
      readOnly={props.readOnly}
      autocomplete="off"
      spellcheck={false}
      onInput={(e) => props.onValue(e.currentTarget.value)}
    />
  </label>
);

/** A number field that only reports a finite value — a half-typed `-` never clears the profile. */
const NumField: Component<{ label: string; value: number; step?: string | undefined; onValue: (v: number) => void }> = (
  props,
) => (
  <label class={css.field}>
    <span class={css.fieldLabel}>{props.label}</span>
    <input
      type="number"
      aria-label={props.label}
      value={String(props.value)}
      step={props.step}
      onInput={(e) => {
        const n = Number(e.currentTarget.value);
        if (e.currentTarget.value !== '' && Number.isFinite(n)) props.onValue(n);
      }}
    />
  </label>
);

const BoolField: Component<{ label: string; checked: boolean; onValue: (v: boolean) => void }> = (props) => (
  <label class={css.checkRow}>
    <input
      type="checkbox"
      aria-label={props.label}
      checked={props.checked}
      onChange={(e) => props.onValue(e.currentTarget.checked)}
    />
    <span>{props.label}</span>
  </label>
);

function Segmented<T extends string>(props: {
  label: string;
  options: readonly T[];
  value: T;
  onValue: (v: T) => void;
}) {
  return (
    <div class={css.field}>
      <span class={css.fieldLabel}>{props.label}</span>
      <div class={css.segmented} role="radiogroup" aria-label={props.label}>
        <For each={props.options}>
          {(option) => (
            <button
              type="button"
              class={css.segment}
              role="radio"
              aria-checked={props.value === option}
              onClick={() => props.onValue(option)}
            >
              {option}
            </button>
          )}
        </For>
      </div>
    </div>
  );
}

function Picker<T extends string>(props: {
  label: string;
  options: readonly T[];
  value: T;
  onValue: (v: T) => void;
}) {
  return (
    <label class={css.field}>
      <span class={css.fieldLabel}>{props.label}</span>
      <select aria-label={props.label} value={props.value} onChange={(e) => props.onValue(e.currentTarget.value as T)}>
        <For each={props.options}>
          {(option) => (
            <option value={option} selected={option === props.value}>
              {option}
            </option>
          )}
        </For>
      </select>
    </label>
  );
}

/* ------------------------------------------------------------------ text <-> list plumbing */

const lines = (text: string): string[] =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');

const sameList = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

const seedText = (seeds: readonly L4Seed[]): string =>
  seeds.map((s) => ('flow' in s ? `flow:${s.flow}` : 'hex' in s ? `hex:${s.hex}` : `base64:${s.base64}`)).join('\n');

/** Only the three documented forms are accepted; anything else is not a seed and is left out. */
function parseSeeds(text: string): L4Seed[] {
  const out: L4Seed[] = [];
  for (const line of lines(text)) {
    const at = line.indexOf(':');
    if (at <= 0) continue;
    const value = line.slice(at + 1).trim();
    if (value === '') continue;
    const kind = line.slice(0, at).trim();
    if (kind === 'flow') out.push({ flow: value });
    else if (kind === 'hex') out.push({ hex: value });
    else if (kind === 'base64') out.push({ base64: value });
  }
  return out;
}

const DASH = '—';

/** The reconnecting note (D-T8.10), the same sentence the Jobs view prints. */
const RECONNECT_NOTE = 'reconnecting: controls are disabled until the bus is back';

/** The session preview, as **names** (D7): no reply field here carries a value to print. */
function previewLines(session: SessionProfile): [string, string] {
  const names = `cookies: ${session.cookies.length ? session.cookies.join(', ') : DASH} · headers: ${
    session.headers.length ? session.headers.join(', ') : DASH
  }`;
  const canary =
    session.canary.kind === 'none'
      ? 'Canary: none; auth-lost detection off'
      : `Canary: ${session.canary.method} ${session.canary.path}${
          session.canary.expected_status === null ? '' : ` (expects ${session.canary.expected_status})`
        }`;
  return [names, canary];
}

const ignoreWords = (rule: IgnoreRule): string =>
  `kind: ${rule.kind ?? DASH} · name_regex: ${rule.name_regex ?? DASH} · trait: ${rule.trait ?? DASH}`;

/* ------------------------------------------------------------------ the editor */

export const ProfileEditor: Component<{ name: string }> = (props) => {
  const app = useApp();
  const s = scanStore(app);
  const draft = () => s.draft(props.name);
  return (
    <Show
      when={draft()}
      fallback={
        <Show
          when={s.lastError()}
          fallback={
            <div class={css.loading} aria-label="Loading profile">
              <i />
              <i />
              <i />
              <i />
            </div>
          }
        >
          {(error) => (
            <div class={css.errorBlock} role="alert">
              <p>{error()}</p>
              <Button class={css.retry} variant="outline" disabled={!s.busOpen()} onClick={() => void s.loadProfile(props.name)}>
                Retry
              </Button>
            </div>
          )}
        </Show>
      }
    >
      {(d) => <EditorForm name={props.name} profile={d().profile} dirty={d().dirty} />}
    </Show>
  );
};

const EditorForm: Component<{ name: string; profile: ScanProfile; dirty: boolean }> = (props) => {
  const app = useApp();
  const s = scanStore(app);

  const p = (): ScanProfile => props.profile;
  const write = (next: ScanProfile): void => s.setDraft(props.name, next);
  const setField = <K extends keyof ScanProfile>(key: K, value: ScanProfile[K]): void =>
    write({ ...p(), [key]: value });
  const setCrawl = <K extends keyof CrawlOptions>(key: K, value: CrawlOptions[K]): void =>
    setField('crawl', { ...p().crawl, [key]: value });
  const setAudit = <K extends keyof AuditOptions>(key: K, value: AuditOptions[K]): void =>
    setField('audit', { ...p().audit, [key]: value });
  const setSession = <K extends keyof SessionOptions>(key: K, value: SessionOptions[K]): void =>
    setField('session', { ...p().session, [key]: value });
  const setBudget = <K extends keyof Budget>(key: K, value: Budget[K]): void =>
    setField('budget', { ...p().budget, [key]: value });
  const setHttp = <K extends keyof HttpOptions>(key: K, value: HttpOptions[K]): void =>
    setField('http', { ...p().http, [key]: value });
  const setWs = <K extends keyof WsOptions>(key: K, value: WsOptions[K]): void =>
    setField('ws', { ...p().ws, [key]: value });
  const setL4 = <K extends keyof L4Options>(key: K, value: L4Options[K]): void =>
    setField('l4', { ...p().l4, [key]: value });

  /* -------------------------------------------------------------- name, save, delete */

  const entry = () => s.profiles().find((e) => e.name === props.name) ?? null;
  const isBuiltin = () => entry()?.builtin ?? false;
  const isSaved = () => entry() !== null && !isBuiltin();
  const [renaming, setRenaming] = createSignal(false);
  const [confirmDelete, setConfirmDelete] = createSignal(false);
  // Switching profiles ends any half-finished rename or delete on the one we left.
  createEffect(
    on(
      () => props.name,
      () => {
        setRenaming(false);
        setConfirmDelete(false);
      },
      { defer: true },
    ),
  );

  /** Whether the typed name is one the engine would save: the name rule, and not a built-in's name. */
  const nameIsBuiltin = () => s.profiles().some((e) => e.builtin && e.name === p().name);
  const nameOk = () => isValidProfileName(p().name) && !nameIsBuiltin();
  /** The hint shows only while the name is being authored (after `Save as`, or on a saved profile). */
  const nameEditable = () => !isBuiltin() || renaming();
  const showNameHint = () => nameEditable() && !nameOk();

  /** A built-in is never overwritten: saving it needs `Save as` and a name the engine accepts. */
  const canSave = () => nameOk() && props.dirty && !(isBuiltin() && p().name === props.name) && !s.busy();

  /* -------------------------------------------------------------- targets */

  const [scheme, setScheme] = createSignal<'https' | 'http'>('https');
  const [host, setHost] = createSignal('');
  const [port, setPort] = createSignal('');
  /** Concrete in-scope hosts only: a `*.` wildcard is not a host one can connect to. */
  const hosts = createMemo(() => app.proxy.scope.map((e) => e.host).filter((h) => !h.startsWith('*.')));
  createEffect(() => {
    const list = hosts();
    if (!list.includes(host())) setHost(list[0] ?? '');
  });
  /** A scope entry may already be `host:port`; then the port field is ignored, never appended. */
  const hostHasPort = () => host().includes(':');
  const composed = (): string | null => {
    const h = host();
    if (h === '') return null;
    if (hostHasPort()) return `${scheme()}://${h}`;
    const typed = port().trim();
    return typed === '' ? `${scheme()}://${h}` : `${scheme()}://${h}:${typed}`;
  };
  const addOrigin = (): void => {
    const origin = composed();
    if (origin === null || p().target.origins.includes(origin)) return;
    setField('target', { ...p().target, origins: [...p().target.origins, origin] });
  };
  const removeOrigin = (origin: string): void =>
    setField('target', { ...p().target, origins: p().target.origins.filter((o) => o !== origin) });

  const [l4Ip, setL4Ip] = createSignal('');
  const [l4Port, setL4Port] = createSignal('');
  const [l4Proto, setL4Proto] = createSignal<L4Transport>('tcp');
  const [l4Grammar, setL4Grammar] = createSignal('');
  const addL4Target = (): void => {
    const ip = l4Ip().trim();
    const portNumber = Number(l4Port().trim());
    if (ip === '' || !Number.isInteger(portNumber) || portNumber < 0 || portNumber > 65535) return;
    const grammar = l4Grammar().trim();
    setField('target', {
      ...p().target,
      l4: [...p().target.l4, { ip, port: portNumber, proto: l4Proto(), grammar: grammar === '' ? null : grammar }],
    });
  };
  const removeL4Target = (index: number): void =>
    setField('target', { ...p().target, l4: p().target.l4.filter((_, i) => i !== index) });

  const outOfScope = (origin: string) => !hostInScope(origin, app.proxy.scope);
  const hostOf = (origin: string) => originHost(origin)?.host ?? origin;

  /* -------------------------------------------------------------- lanes and checks */

  /** A lane no check lists is not on this build; it stays toggleable (D1: skipped and reported). */
  const laneAvailable = (lane: Lane) => s.checks().length === 0 || s.checks().some((c) => c.lanes.includes(lane));
  const setLane = (lane: Lane, on: boolean): void =>
    setField(
      'lanes',
      on ? LANES.filter((l) => l === lane || p().lanes.includes(l)) : p().lanes.filter((l) => l !== lane),
    );

  // The two selector fields keep their own text so a half-typed line is not rewritten under the
  // cursor; they re-sync whenever the tree (or a reload) changes what the selection actually is.
  const [includeText, setIncludeText] = createSignal(p().checks.include.join('\n'));
  const [excludeText, setExcludeText] = createSignal(p().checks.exclude.join('\n'));
  createEffect(() => {
    if (!sameList(lines(includeText()), p().checks.include)) setIncludeText(p().checks.include.join('\n'));
  });
  createEffect(() => {
    if (!sameList(lines(excludeText()), p().checks.exclude)) setExcludeText(p().checks.exclude.join('\n'));
  });
  /**
   * One batched write per keystroke: the text and the parsed selection must land together, or the
   * re-sync effects above run against half the edit and rewrite the field under the cursor.
   */
  const writeSelectors = (which: 'include' | 'exclude', text: string): void =>
    batch(() => {
      if (which === 'include') setIncludeText(text);
      else setExcludeText(text);
      setField('checks', {
        include: which === 'include' ? lines(text) : p().checks.include,
        exclude: which === 'exclude' ? lines(text) : p().checks.exclude,
      });
    });

  /* -------------------------------------------------------------- audit */

  const setKind = (kind: InsertionKind, on: boolean): void =>
    setAudit(
      'kinds',
      on ? INSERTION_KINDS.filter((k) => k === kind || p().audit.kinds.includes(k)) : p().audit.kinds.filter((k) => k !== kind),
    );
  const [ignoreKind, setIgnoreKind] = createSignal<InsertionKind | ''>('');
  const [ignoreRegex, setIgnoreRegex] = createSignal('');
  const [ignoreTrait, setIgnoreTrait] = createSignal<PointTrait | ''>('');
  const addIgnore = (): void => {
    const rule: IgnoreRule = {
      kind: ignoreKind() === '' ? null : (ignoreKind() as InsertionKind),
      name_regex: ignoreRegex().trim() === '' ? null : ignoreRegex().trim(),
      trait: ignoreTrait() === '' ? null : (ignoreTrait() as PointTrait),
    };
    if (rule.kind === null && rule.name_regex === null && rule.trait === null) return;
    setAudit('ignore', [...p().audit.ignore, rule]);
  };

  /* -------------------------------------------------------------- session preview */

  const [preview, setPreview] = createSignal<{ origin: string; session: SessionProfile } | null>(null);
  const runPreview = async (origin: string): Promise<void> => {
    const session = await s.previewSession(origin);
    if (session) setPreview({ origin, session });
  };

  /* -------------------------------------------------------------- l4 seeds */

  const [seeds, setSeeds] = createSignal(seedText(p().l4.seeds));
  createEffect(() => {
    if (seedText(parseSeeds(seeds())) !== seedText(p().l4.seeds)) setSeeds(seedText(p().l4.seeds));
  });

  /* -------------------------------------------------------------- pre-flight and launch */

  const pf = createMemo(() =>
    preflight(p(), {
      scope: app.proxy.scope,
      l4Offered: s.l4Offered(),
      l4Entries: s.l4Entries(),
      busOpen: s.busOpen(),
      // Only `agent` changes anything here (it adds the note); an unresolved role is not an agent.
      role: s.agent() ? 'agent' : 'operator',
    }),
  );
  const reason = createMemo(() => {
    const v = pf();
    return v.ok ? null : v.reason;
  });
  const note = createMemo(() => {
    const v = pf();
    return v.ok ? v.note : null;
  });
  const launch = (mode: LaunchMode): void => void s.launch(p(), mode);

  /** The Add-to-Scope affordance the core's `out_of_scope` refusal asks for (D-T8.6). */
  const refusedHost = createMemo(() => {
    const error = s.lastError();
    if (error === null || !error.startsWith('Out of scope:')) return null;
    const origin = p().target.origins.find(outOfScope);
    return origin === undefined ? null : hostOf(origin);
  });

  return (
    <>
      <form class={css.editor} aria-label="Profile editor" onSubmit={(e) => e.preventDefault()}>
        <Show when={!s.busOpen()}>
          <p class={css.note} role="status">
            {RECONNECT_NOTE}
          </p>
        </Show>
        {/* D-T8.10: every control is disabled while the bus is not open; the draft stays on screen. */}
        <fieldset class={css.fieldset} disabled={!s.busOpen()}>
          <Section title="Name">
            <TextField
              label="Profile name"
              value={p().name}
              readOnly={isBuiltin() && !renaming()}
              onValue={(v) => setField('name', v)}
            />
            <Show when={showNameHint()}>
              <p class={css.note} role="note" data-name-hint>
                {PROFILE_NAME_HINT}
              </p>
            </Show>
            <Show when={isBuiltin()}>
              <p class={css.note}>A built-in profile is never overwritten — `Save as` stores it under a new name.</p>
            </Show>
          </Section>

          <Section title="Targets">
            <div class={css.field}>
              <span class={css.fieldLabel}>Origins</span>
              <div role="list" aria-label="Origins">
                <Show when={p().target.origins.length === 0}>
                  <p class={css.note}>No origins yet.</p>
                </Show>
                <For each={p().target.origins}>
                  {(origin) => (
                    <div class={css.originRow} role="listitem" data-origin={origin}>
                      <span>{origin}</span>
                      <Show when={outOfScope(origin)}>
                        <span class={css.tag}>not in scope</span>
                        <Button variant="small" onClick={() => void app.addScope(hostOf(origin))}>
                          Add {hostOf(origin)} to Scope
                        </Button>
                      </Show>
                      <Button variant="ghost" aria-label={`Remove ${origin}`} onClick={() => removeOrigin(origin)}>
                        <Icon name="x" size={12} />
                      </Button>
                    </div>
                  )}
                </For>
              </div>
            </div>

            <div class={css.originRow}>
              <label class={css.field}>
                <span class={css.fieldLabel}>Origin scheme</span>
                <select
                  aria-label="Origin scheme"
                  value={scheme()}
                  onChange={(e) => setScheme(e.currentTarget.value === 'http' ? 'http' : 'https')}
                >
                  <option value="https" selected={scheme() === 'https'}>
                    https
                  </option>
                  <option value="http" selected={scheme() === 'http'}>
                    http
                  </option>
                </select>
              </label>
              <label class={css.field}>
                <span class={css.fieldLabel}>Origin host</span>
                <select aria-label="Origin host" value={host()} onChange={(e) => setHost(e.currentTarget.value)}>
                  <For each={hosts()}>
                    {(h) => (
                      <option value={h} selected={h === host()}>
                        {h}
                      </option>
                    )}
                  </For>
                </select>
              </label>
              <label class={css.field}>
                <span class={css.fieldLabel}>Origin port</span>
                <input
                  type="text"
                  aria-label="Origin port"
                  inputmode="numeric"
                  value={hostHasPort() ? '' : port()}
                  disabled={hostHasPort()}
                  placeholder={hostHasPort() ? 'in the host' : 'default'}
                  onInput={(e) => setPort(e.currentTarget.value)}
                />
              </label>
              <Button variant="outline" disabled={composed() === null} onClick={() => addOrigin()}>
                Add origin
              </Button>
            </div>
            <Show when={hosts().length === 0}>
              <p class={css.note}>No concrete host is in scope yet — add one below to pick it here.</p>
            </Show>
            <AddHost existing={app.proxy.scope.map((e) => e.host)} onAdd={(h) => app.addScope(h)} />

            <div class={css.field}>
              <span class={css.fieldLabel}>L4 targets</span>
              <div role="list" aria-label="L4 targets">
                <Show when={p().target.l4.length === 0}>
                  <p class={css.note}>No L4 targets yet.</p>
                </Show>
                <For each={p().target.l4}>
                  {(t, i) => (
                    <div class={css.originRow} role="listitem" data-l4={`${t.ip}:${t.port}`}>
                      <span>
                        {t.ip}:{t.port} {t.proto}
                        {t.grammar === null ? '' : ` · ${t.grammar}`}
                      </span>
                      <Button
                        variant="ghost"
                        aria-label={`Remove L4 target ${t.ip}:${t.port}`}
                        onClick={() => removeL4Target(i())}
                      >
                        <Icon name="x" size={12} />
                      </Button>
                    </div>
                  )}
                </For>
              </div>
              <p class={css.note}>{L4_HINT}</p>
            </div>
            <div class={css.originRow}>
              <TextField label="L4 target IP" value={l4Ip()} placeholder="127.0.0.1" onValue={setL4Ip} />
              <TextField label="L4 target port" value={l4Port()} placeholder="9" onValue={setL4Port} />
              <Picker label="L4 target proto" options={L4_TRANSPORTS} value={l4Proto()} onValue={setL4Proto} />
              <TextField label="L4 target grammar" value={l4Grammar()} placeholder="optional" onValue={setL4Grammar} />
              <Button variant="outline" onClick={() => addL4Target()}>
                Add L4 target
              </Button>
            </div>
          </Section>

          <Section title="Lanes">
            <div role="group" aria-label="Lanes">
              <For each={LANES}>
                {(lane) => (
                  <label class={css.checkRow} data-lane={lane}>
                    <input
                      type="checkbox"
                      aria-label={lane}
                      checked={p().lanes.includes(lane)}
                      onChange={(e) => setLane(lane, e.currentTarget.checked)}
                    />
                    <span>{lane}</span>
                    <Show when={!laneAvailable(lane)}>
                      <span class={css.tag}>not available on this build</span>
                    </Show>
                  </label>
                )}
              </For>
            </div>
          </Section>

          <Section title="Intensity, speed, accuracy">
            <Segmented
              label="Intensity"
              options={INTENSITIES}
              value={p().intensity}
              onValue={(v) => setField('intensity', v)}
            />
            <Show when={p().intensity === 'intrusive'}>
              <p class={css.note}>operator only; asks for confirmation</p>
            </Show>
            <Segmented label="Speed" options={SPEEDS} value={p().speed} onValue={(v) => setField('speed', v)} />
            <Segmented
              label="Accuracy"
              options={ACCURACIES}
              value={p().accuracy}
              onValue={(v) => setField('accuracy', v)}
            />
          </Section>

          <Section title="Checks">
            <CheckTree
              selection={p().checks}
              checks={s.checks()}
              unknown={unknownSelectors(p().checks, s.checks())}
              onChange={(next) => setField('checks', next)}
            />
            <label class={css.field}>
              <span class={css.fieldLabel}>Include selectors</span>
              <textarea
                aria-label="Include selectors"
                value={includeText()}
                placeholder="one of id | class | lane:* per line"
                onInput={(e) => writeSelectors('include', e.currentTarget.value)}
              />
            </label>
            <label class={css.field}>
              <span class={css.fieldLabel}>Exclude selectors</span>
              <textarea
                aria-label="Exclude selectors"
                value={excludeText()}
                placeholder="one of id | class | lane:* per line"
                onInput={(e) => writeSelectors('exclude', e.currentTarget.value)}
              />
            </label>
          </Section>

          <Section title="Crawl">
            <Segmented
              label="Crawl strategy"
              options={CRAWL_STRATEGIES}
              value={p().crawl.strategy}
              onValue={(v) => setCrawl('strategy', v)}
            />
            <NumField label="Max depth" value={p().crawl.max_depth} onValue={(v) => setCrawl('max_depth', v)} />
            <NumField label="Max pages" value={p().crawl.max_pages} onValue={(v) => setCrawl('max_pages', v)} />
            <BoolField
              label="Submit forms"
              checked={p().crawl.submit_forms}
              onValue={(v) => setCrawl('submit_forms', v)}
            />
            <BoolField
              label="Click handlers"
              checked={p().crawl.click_handlers}
              onValue={(v) => setCrawl('click_handlers', v)}
            />
            <BoolField label="Read robots.txt" checked={p().crawl.robots} onValue={(v) => setCrawl('robots', v)} />
            <BoolField label="Read sitemap.xml" checked={p().crawl.sitemap} onValue={(v) => setCrawl('sitemap', v)} />
            <Picker
              label="Use browser"
              options={USE_BROWSER}
              value={p().crawl.use_browser}
              onValue={(v) => setCrawl('use_browser', v)}
            />
          </Section>

          <Section title="Audit">
            <div class={css.field}>
              <span class={css.fieldLabel}>Insertion kinds</span>
              <div role="group" aria-label="Audit kinds">
                <For each={INSERTION_KINDS}>
                  {(kind) => (
                    <label class={css.checkRow}>
                      <input
                        type="checkbox"
                        aria-label={kind}
                        checked={p().audit.kinds.includes(kind)}
                        onChange={(e) => setKind(kind, e.currentTarget.checked)}
                      />
                      <span>{kind}</span>
                    </label>
                  )}
                </For>
              </div>
            </div>
            <div class={css.field}>
              <span class={css.fieldLabel}>Ignore rules</span>
              <div role="list" aria-label="Ignore rules">
                <Show when={p().audit.ignore.length === 0}>
                  <p class={css.note}>No ignore rules.</p>
                </Show>
                <For each={p().audit.ignore}>
                  {(rule, i) => (
                    <div class={css.originRow} role="listitem">
                      <span>{ignoreWords(rule)}</span>
                      <Button
                        variant="ghost"
                        aria-label={`Remove ignore rule ${i() + 1}`}
                        onClick={() => setAudit('ignore', p().audit.ignore.filter((_, at) => at !== i()))}
                      >
                        <Icon name="x" size={12} />
                      </Button>
                    </div>
                  )}
                </For>
              </div>
            </div>
            <div class={css.originRow}>
              <Picker
                label="Ignore kind"
                options={['', ...INSERTION_KINDS] as const}
                value={ignoreKind()}
                onValue={(v) => setIgnoreKind(v as InsertionKind | '')}
              />
              <TextField label="Ignore name regex" value={ignoreRegex()} onValue={setIgnoreRegex} />
              <Picker
                label="Ignore trait"
                options={['', ...POINT_TRAITS] as const}
                value={ignoreTrait()}
                onValue={(v) => setIgnoreTrait(v as PointTrait | '')}
              />
              <Button variant="outline" onClick={() => addIgnore()}>
                Add ignore rule
              </Button>
            </div>
            <NumField
              label="Max points per request"
              value={p().audit.max_points_per_request}
              onValue={(v) => setAudit('max_points_per_request', v)}
            />
            <NumField
              label="Frequent point threshold"
              value={p().audit.frequent_point_threshold}
              onValue={(v) => setAudit('frequent_point_threshold', v)}
            />
          </Section>

          <Section title="Session">
            <Segmented
              label="Session mode"
              options={SESSION_MODES}
              value={p().session.mode}
              onValue={(v) => setSession('mode', v)}
            />
            <Segmented
              label="On session lost"
              options={ON_LOST}
              value={p().session.on_lost}
              onValue={(v) => setSession('on_lost', v)}
            />
            <TextField
              label="Session from flow"
              value={p().session.from_flow ?? ''}
              placeholder="flow id (optional)"
              onValue={(v) => setSession('from_flow', v.trim() === '' ? null : v.trim())}
            />
            <For each={p().target.origins}>
              {(origin) => (
                <Button variant="outline" disabled={!s.busOpen() || s.busy()} onClick={() => void runPreview(origin)}>
                  Preview session for {origin}
                </Button>
              )}
            </For>
            <Show when={preview()}>
              {(pv) => (
                <div data-preview={pv().origin}>
                  <For each={previewLines(pv().session)}>{(line) => <p class={css.note}>{line}</p>}</For>
                </div>
              )}
            </Show>
          </Section>

          <Section title="Budget">
            <NumField label="Probe budget" value={p().budget.probes} onValue={(v) => setBudget('probes', v)} />
            <NumField label="Time budget (s)" value={p().budget.time_s} onValue={(v) => setBudget('time_s', v)} />
            <NumField label="Max issues" value={p().budget.max_issues} onValue={(v) => setBudget('max_issues', v)} />
            <NumField
              label="Check timeout (s)"
              value={p().budget.check_timeout_s}
              onValue={(v) => setBudget('check_timeout_s', v)}
            />
            <NumField
              label="Consecutive errors per host"
              value={p().budget.per_host_errors.consecutive}
              onValue={(v) => setBudget('per_host_errors', { ...p().budget.per_host_errors, consecutive: v })}
            />
            <NumField
              label="Error ratio per host"
              step="0.1"
              value={p().budget.per_host_errors.ratio}
              onValue={(v) => setBudget('per_host_errors', { ...p().budget.per_host_errors, ratio: v })}
            />
          </Section>

          <Section title="HTTP">
            <Segmented
              label="HTTP version"
              options={HTTP_VERSION_POLICIES}
              value={p().http.version}
              onValue={(v) => setHttp('version', v)}
            />
            <Segmented
              label="Record probes"
              options={RECORD_PROBES}
              value={p().http.record_probes}
              onValue={(v) => setHttp('record_probes', v)}
            />
          </Section>

          <Section title="WS">
            <NumField
              label="Reply window (ms)"
              value={p().ws.reply_window_ms}
              onValue={(v) => setWs('reply_window_ms', v)}
            />
            <NumField
              label="Max frame bytes"
              value={p().ws.max_frame_bytes}
              onValue={(v) => setWs('max_frame_bytes', v)}
            />
          </Section>

          <Section title="L4">
            <NumField label="Cases" value={p().l4.cases} onValue={(v) => setL4('cases', v)} />
            <NumField
              label="Reproduce count"
              value={p().l4.reproduce_count}
              onValue={(v) => setL4('reproduce_count', v)}
            />
            <NumField label="Liveness every" value={p().l4.liveness_every} onValue={(v) => setL4('liveness_every', v)} />
            <NumField
              label="Consecutive timeouts"
              value={p().l4.consecutive_timeouts}
              onValue={(v) => setL4('consecutive_timeouts', v)}
            />
            <NumField
              label="Max bytes per second"
              value={p().l4.max_bytes_per_s}
              onValue={(v) => setL4('max_bytes_per_s', v)}
            />
            <BoolField label="Dry run" checked={p().l4.dry_run} onValue={(v) => setL4('dry_run', v)} />
            <label class={css.field}>
              <span class={css.fieldLabel}>L4 seeds</span>
              <textarea
                aria-label="L4 seeds"
                value={seeds()}
                placeholder="flow:<id>, hex:<bytes> or base64:<bytes>, one per line"
                onInput={(e) => {
                  const text = e.currentTarget.value;
                  batch(() => {
                    setSeeds(text);
                    setL4('seeds', parseSeeds(text));
                  });
                }}
              />
            </label>
          </Section>

          <Show when={s.lastError() ?? s.startNotice()}>
            <div class={css.notice} role="status" aria-label="Launch result">
              <Show
                when={s.lastError()}
                fallback={
                  <Show when={s.startNotice()}>{(started) => <p class={css.note}>{started().job} started</p>}</Show>
                }
              >
                {(error) => (
                  <>
                    <p>{error()}</p>
                    <Show when={refusedHost()}>
                      {(h) => (
                        <Button variant="outline" onClick={() => void app.addScope(h())}>
                          Add {h()} to Scope
                        </Button>
                      )}
                    </Show>
                  </>
                )}
              </Show>
            </div>
          </Show>
        </fieldset>
      </form>

      <div class={css.footer}>
        <Show when={reason()}>
          {(text) => (
            <p class={css.reason} role="note" data-reason>
              {text()}
            </p>
          )}
        </Show>
        <Show when={note()}>
          {(text) => (
            <p class={css.note} data-note>
              {text()}
            </p>
          )}
        </Show>
        <Show when={s.agent() && note() === null}>
          <p class={css.note}>{AGENT_NOTE}</p>
        </Show>
        <Button variant="outline" disabled={!s.busOpen() || !canSave()} onClick={() => void s.saveProfile(p())}>
          Save
        </Button>
        <Show when={isBuiltin() && !renaming()}>
          <Button variant="ghost" disabled={!s.busOpen()} onClick={() => setRenaming(true)}>
            Save as
          </Button>
        </Show>
        <Show when={isSaved()}>
          <Show
            when={confirmDelete()}
            fallback={
              <Button variant="ghost" disabled={!s.busOpen()} onClick={() => setConfirmDelete(true)}>
                Delete
              </Button>
            }
          >
            <span>Delete {props.name}?</span>
            <Button variant="ghost" disabled={!s.busOpen()} onClick={() => setConfirmDelete(false)}>
              Keep
            </Button>
            <Button
              variant="outline"
              disabled={!s.busOpen() || s.busy()}
              onClick={() => {
                setConfirmDelete(false);
                void s.deleteProfile(props.name);
              }}
            >
              Confirm delete
            </Button>
          </Show>
        </Show>
        <Button variant="outline" disabled={!s.busOpen() || !pf().ok || s.busy()} onClick={() => launch('map')}>
          Map only
        </Button>
        <Button variant="primary" disabled={!s.busOpen() || !pf().ok || s.busy()} onClick={() => launch('start')}>
          Start
        </Button>
      </div>

      {/* No `busy`: cancelling the core's confirmation must always be possible, and the launch
          that opened the dialog is still unwinding when it first renders. */}
      <Show when={s.pendingConfirm()}>
        {(pending) => (
          <ConfirmInject
            title="Confirm scan"
            prompt={pending().prompt}
            confirmLabel="Start scan"
            onConfirm={() => void s.confirmLaunch()}
            onCancel={() => s.cancelConfirm()}
          />
        )}
      </Show>
    </>
  );
};
