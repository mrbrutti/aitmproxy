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
//
// Shape (PA9): the editor is keyed on the profile name, and each section is its own component that
// owns the half-typed state of its controls (a picker, a pending row, a preview, a confirm). Every
// section speaks one contract — `{ profile, set }` — so switching profiles recreates every section
// and no editor's half-typed row ever lands in another's.

import { batch, createEffect, createMemo, createSignal, For, Show, type Component } from 'solid-js';
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
  type CheckMeta,
  type IgnoreRule,
  type InsertionKind,
  type L4Seed,
  type L4Transport,
  type Lane,
  type PointTrait,
  type ScanProfile,
  type SessionProfile,
} from './model';
import { ErrorBlock, LoadingBars, ReconnectNote, Section } from './primitives';
import { scanStore } from './store';
import css from './scanner.module.css';

/* ------------------------------------------------------------------ small shared controls */

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

/** Origin scheme: a segmented control, not a native <select> (headless Chrome cannot drive one with real key events). */
type Scheme = 'https' | 'http';
const SCHEMES: readonly Scheme[] = ['https', 'http'];

/** The Audit ignore-rule pickers: an empty option (no constraint) before every kind and trait. */
const IGNORE_KINDS: readonly (InsertionKind | '')[] = ['', ...INSERTION_KINDS];
const IGNORE_TRAITS: readonly (PointTrait | '')[] = ['', ...POINT_TRAITS];

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

/** A native select over a closed set: a value outside `options` (a cleared select) is ignored, never cast. */
function Picker<T extends string>(props: {
  label: string;
  options: readonly T[];
  value: T;
  onValue: (v: T) => void;
}) {
  return (
    <label class={css.field}>
      <span class={css.fieldLabel}>{props.label}</span>
      <select
        aria-label={props.label}
        value={props.value}
        onChange={(e) => {
          const typed = e.currentTarget.value;
          const found = props.options.find((o) => o === typed);
          if (found !== undefined) props.onValue(found);
        }}
      >
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

const hostOf = (origin: string): string => originHost(origin)?.host ?? origin;

/* ------------------------------------------------------------------ the section contract */

/** What every section gets: the draft as it reads now, and the one way to replace it (W-12). */
interface SectionProps {
  profile: ScanProfile;
  set: (next: ScanProfile) => void;
}

/** A setter for one top-level field, over the draft as it reads at call time. */
function fieldSetter(props: SectionProps) {
  return <K extends keyof ScanProfile>(key: K, value: ScanProfile[K]): void =>
    props.set({ ...props.profile, [key]: value });
}

/** A setter for one key of a nested block (`crawl.max_depth`, `budget.probes`, ...). */
function blockSetter<B extends 'crawl' | 'audit' | 'session' | 'budget' | 'http' | 'ws' | 'l4'>(props: SectionProps, block: B) {
  return <K extends keyof ScanProfile[B]>(key: K, value: ScanProfile[B][K]): void =>
    props.set({ ...props.profile, [block]: { ...props.profile[block], [key]: value } });
}

/* ------------------------------------------------------------------ the editor */

export const ProfileEditor: Component<{ name: string }> = (props) => {
  const s = scanStore(useApp());
  return (
    // Keyed on the name (PA9): the whole editor, and every section's half-typed state with it, is
    // recreated when the operator switches profiles. The draft itself lives in the store.
    <Show keyed when={props.name}>
      {(name) => (
        <Show
          when={s.draft(name)}
          fallback={
            // The one error this block owns (PA5), keyed on *this* name: another profile's failed
            // read is never shown here while this one is still loading.
            <Show when={s.profileError(name)} fallback={<LoadingBars label="Loading profile" />}>
              {(error) => <ErrorBlock text={error()} onRetry={() => void s.loadProfile(name)} disabled={!s.busOpen()} />}
            </Show>
          }
        >
          {(d) => <EditorForm name={name} profile={d().profile} dirty={d().dirty} />}
        </Show>
      )}
    </Show>
  );
};

const EditorForm: Component<{ name: string; profile: ScanProfile; dirty: boolean }> = (props) => {
  const app = useApp();
  const s = scanStore(app);

  const p = (): ScanProfile => props.profile;
  const set = (next: ScanProfile): void => s.setDraft(props.name, next);

  const entry = () => s.profiles().find((e) => e.name === props.name) ?? null;
  const isBuiltin = () => entry()?.builtin ?? false;
  const isSaved = () => entry() !== null && !isBuiltin();
  /** `Save as` turns a built-in's read-only name into the new-name field; it ends with the editor. */
  const [renaming, setRenaming] = createSignal(false);

  /** Whether the typed name is one the engine would save: the name rule, and not a built-in's name. */
  const nameIsBuiltin = () => s.profiles().some((e) => e.builtin && e.name === p().name);
  const nameOk = () => isValidProfileName(p().name) && !nameIsBuiltin();
  /** The hint shows only while the name is being authored (after `Save as`, or on a saved profile). */
  const nameEditable = () => !isBuiltin() || renaming();

  return (
    <>
      <form class={css.editor} aria-label="Profile editor" onSubmit={(e) => e.preventDefault()}>
        <Show when={!s.busOpen()}>
          <ReconnectNote />
        </Show>
        {/* D-T8.10: every control is disabled while the bus is not open; the draft stays on screen. */}
        <fieldset class={css.fieldset} disabled={!s.busOpen()}>
          <NameSection profile={p()} set={set} readOnly={!nameEditable()} builtin={isBuiltin()} showHint={nameEditable() && !nameOk()} />
          <TargetsSection profile={p()} set={set} scope={app.proxy.scope} onAddScope={(h) => void app.addScope(h)} />
          <LanesSection profile={p()} set={set} checks={s.checks()} />
          <IntensitySection profile={p()} set={set} />
          <ChecksSection profile={p()} set={set} checks={s.checks()} />
          <CrawlSection profile={p()} set={set} />
          <AuditSection profile={p()} set={set} />
          <SessionSection profile={p()} set={set} preview={(origin) => s.previewSession(origin)} disabled={!s.busOpen() || s.busy()} />
          <BudgetSection profile={p()} set={set} />
          <HttpSection profile={p()} set={set} />
          <WsSection profile={p()} set={set} />
          <L4Section profile={p()} set={set} />
          <LaunchResult profile={p()} scope={app.proxy.scope} onAddScope={(h) => void app.addScope(h)} />
        </fieldset>
      </form>

      <LaunchFooter
        name={props.name}
        profile={p()}
        dirty={props.dirty}
        builtin={isBuiltin()}
        saved={isSaved()}
        nameOk={nameOk()}
        renaming={renaming()}
        onRename={() => setRenaming(true)}
      />

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

/* ------------------------------------------------------------------ sections */

const NameSection: Component<SectionProps & { readOnly: boolean; builtin: boolean; showHint: boolean }> = (props) => {
  const field = fieldSetter(props);
  return (
    <Section title="Name">
      <TextField label="Profile name" value={props.profile.name} readOnly={props.readOnly} onValue={(v) => field('name', v)} />
      <Show when={props.showHint}>
        <p class={css.note} role="note" data-name-hint>
          {PROFILE_NAME_HINT}
        </p>
      </Show>
      <Show when={props.builtin}>
        <p class={css.note}>A built-in profile is never overwritten — `Save as` stores it under a new name.</p>
      </Show>
    </Section>
  );
};

/** Origins and L4 targets. Owns the origin picker (scheme, host, port) and the pending L4 row. */
const TargetsSection: Component<SectionProps & { scope: readonly { host: string }[]; onAddScope: (host: string) => void }> = (props) => {
  const field = fieldSetter(props);
  const target = () => props.profile.target;

  const [scheme, setScheme] = createSignal<Scheme>('https');
  const [host, setHost] = createSignal('');
  const [port, setPort] = createSignal('');
  /** Concrete in-scope hosts only: a `*.` wildcard is not a host one can connect to. */
  const hosts = createMemo(() => props.scope.map((e) => e.host).filter((h) => !h.startsWith('*.')));
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
    if (origin === null || target().origins.includes(origin)) return;
    field('target', { ...target(), origins: [...target().origins, origin] });
  };
  const removeOrigin = (origin: string): void =>
    field('target', { ...target(), origins: target().origins.filter((o) => o !== origin) });

  const [l4Ip, setL4Ip] = createSignal('');
  const [l4Port, setL4Port] = createSignal('');
  const [l4Proto, setL4Proto] = createSignal<L4Transport>('tcp');
  const [l4Grammar, setL4Grammar] = createSignal('');
  const addL4Target = (): void => {
    const ip = l4Ip().trim();
    const portNumber = Number(l4Port().trim());
    if (ip === '' || !Number.isInteger(portNumber) || portNumber < 0 || portNumber > 65535) return;
    const grammar = l4Grammar().trim();
    field('target', {
      ...target(),
      l4: [...target().l4, { ip, port: portNumber, proto: l4Proto(), grammar: grammar === '' ? null : grammar }],
    });
  };
  const removeL4Target = (index: number): void => field('target', { ...target(), l4: target().l4.filter((_, i) => i !== index) });

  const outOfScope = (origin: string) => !hostInScope(origin, props.scope);

  return (
    <Section title="Targets">
      <div class={css.field}>
        <span class={css.fieldLabel}>Origins</span>
        <div role="list" aria-label="Origins">
          <Show when={target().origins.length === 0}>
            <p class={css.note}>No origins yet.</p>
          </Show>
          <For each={target().origins}>
            {(origin) => (
              <div class={css.originRow} role="listitem" data-origin={origin}>
                <span>{origin}</span>
                <Show when={outOfScope(origin)}>
                  <span class={css.tag}>not in scope</span>
                  <Button variant="small" onClick={() => props.onAddScope(hostOf(origin))}>
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
        <Segmented label="Origin scheme" options={SCHEMES} value={scheme()} onValue={setScheme} />
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
      <AddHost existing={props.scope.map((e) => e.host)} onAdd={(h) => props.onAddScope(h)} />

      <div class={css.field}>
        <span class={css.fieldLabel}>L4 targets</span>
        <div role="list" aria-label="L4 targets">
          <Show when={target().l4.length === 0}>
            <p class={css.note}>No L4 targets yet.</p>
          </Show>
          <For each={target().l4}>
            {(t, i) => (
              <div class={css.originRow} role="listitem" data-l4={`${t.ip}:${t.port}`}>
                <span>
                  {t.ip}:{t.port} {t.proto}
                  {t.grammar === null ? '' : ` · ${t.grammar}`}
                </span>
                <Button variant="ghost" aria-label={`Remove L4 target ${t.ip}:${t.port}`} onClick={() => removeL4Target(i())}>
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
  );
};

const LanesSection: Component<SectionProps & { checks: readonly CheckMeta[] }> = (props) => {
  const field = fieldSetter(props);
  /** A lane no check lists is not on this build; it stays toggleable (D1: skipped and reported). */
  const laneAvailable = (lane: Lane) => props.checks.length === 0 || props.checks.some((c) => c.lanes.includes(lane));
  const setLane = (lane: Lane, on: boolean): void =>
    field('lanes', on ? LANES.filter((l) => l === lane || props.profile.lanes.includes(l)) : props.profile.lanes.filter((l) => l !== lane));
  return (
    <Section title="Lanes">
      <div role="group" aria-label="Lanes">
        <For each={LANES}>
          {(lane) => (
            <label class={css.checkRow} data-lane={lane}>
              <input
                type="checkbox"
                aria-label={lane}
                checked={props.profile.lanes.includes(lane)}
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
  );
};

const IntensitySection: Component<SectionProps> = (props) => {
  const field = fieldSetter(props);
  return (
    <Section title="Intensity, speed, accuracy">
      <Segmented label="Intensity" options={INTENSITIES} value={props.profile.intensity} onValue={(v) => field('intensity', v)} />
      <Show when={props.profile.intensity === 'intrusive'}>
        <p class={css.note}>operator only; asks for confirmation</p>
      </Show>
      <Segmented label="Speed" options={SPEEDS} value={props.profile.speed} onValue={(v) => field('speed', v)} />
      <Segmented label="Accuracy" options={ACCURACIES} value={props.profile.accuracy} onValue={(v) => field('accuracy', v)} />
    </Section>
  );
};

/** The check tree and the two selector fields; owns the selector text so a half-typed line survives. */
const ChecksSection: Component<SectionProps & { checks: readonly CheckMeta[] }> = (props) => {
  const field = fieldSetter(props);
  const checks = () => props.profile.checks;
  // The two selector fields keep their own text so a half-typed line is not rewritten under the
  // cursor; they re-sync whenever the tree (or a reload) changes what the selection actually is.
  const [includeText, setIncludeText] = createSignal(checks().include.join('\n'));
  const [excludeText, setExcludeText] = createSignal(checks().exclude.join('\n'));
  createEffect(() => {
    if (!sameList(lines(includeText()), checks().include)) setIncludeText(checks().include.join('\n'));
  });
  createEffect(() => {
    if (!sameList(lines(excludeText()), checks().exclude)) setExcludeText(checks().exclude.join('\n'));
  });
  /**
   * One batched write per keystroke: the text and the parsed selection must land together, or the
   * re-sync effects above run against half the edit and rewrite the field under the cursor.
   */
  const writeSelectors = (which: 'include' | 'exclude', text: string): void =>
    batch(() => {
      if (which === 'include') setIncludeText(text);
      else setExcludeText(text);
      field('checks', {
        include: which === 'include' ? lines(text) : checks().include,
        exclude: which === 'exclude' ? lines(text) : checks().exclude,
      });
    });
  return (
    <Section title="Checks">
      <CheckTree selection={checks()} checks={props.checks} unknown={unknownSelectors(checks(), props.checks)} onChange={(next) => field('checks', next)} />
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
  );
};

const CrawlSection: Component<SectionProps> = (props) => {
  const setCrawl = blockSetter(props, 'crawl');
  const crawl = () => props.profile.crawl;
  return (
    <Section title="Crawl">
      <Segmented label="Crawl strategy" options={CRAWL_STRATEGIES} value={crawl().strategy} onValue={(v) => setCrawl('strategy', v)} />
      <NumField label="Max depth" value={crawl().max_depth} onValue={(v) => setCrawl('max_depth', v)} />
      <NumField label="Max pages" value={crawl().max_pages} onValue={(v) => setCrawl('max_pages', v)} />
      <BoolField label="Submit forms" checked={crawl().submit_forms} onValue={(v) => setCrawl('submit_forms', v)} />
      <BoolField label="Click handlers" checked={crawl().click_handlers} onValue={(v) => setCrawl('click_handlers', v)} />
      <BoolField label="Read robots.txt" checked={crawl().robots} onValue={(v) => setCrawl('robots', v)} />
      <BoolField label="Read sitemap.xml" checked={crawl().sitemap} onValue={(v) => setCrawl('sitemap', v)} />
      <Picker label="Use browser" options={USE_BROWSER} value={crawl().use_browser} onValue={(v) => setCrawl('use_browser', v)} />
    </Section>
  );
};

/** Insertion kinds, ignore rules and the two thresholds; owns the pending ignore rule. */
const AuditSection: Component<SectionProps> = (props) => {
  const setAudit = blockSetter(props, 'audit');
  const audit = () => props.profile.audit;
  const setKind = (kind: InsertionKind, on: boolean): void =>
    setAudit('kinds', on ? INSERTION_KINDS.filter((k) => k === kind || audit().kinds.includes(k)) : audit().kinds.filter((k) => k !== kind));
  const [ignoreKind, setIgnoreKind] = createSignal<InsertionKind | ''>('');
  const [ignoreRegex, setIgnoreRegex] = createSignal('');
  const [ignoreTrait, setIgnoreTrait] = createSignal<PointTrait | ''>('');
  const addIgnore = (): void => {
    const kind = ignoreKind();
    const trait = ignoreTrait();
    const regex = ignoreRegex().trim();
    const rule: IgnoreRule = {
      kind: kind === '' ? null : kind,
      name_regex: regex === '' ? null : regex,
      trait: trait === '' ? null : trait,
    };
    if (rule.kind === null && rule.name_regex === null && rule.trait === null) return;
    setAudit('ignore', [...audit().ignore, rule]);
  };
  return (
    <Section title="Audit">
      <div class={css.field}>
        <span class={css.fieldLabel}>Insertion kinds</span>
        <div role="group" aria-label="Audit kinds">
          <For each={INSERTION_KINDS}>
            {(kind) => (
              <label class={css.checkRow}>
                <input type="checkbox" aria-label={kind} checked={audit().kinds.includes(kind)} onChange={(e) => setKind(kind, e.currentTarget.checked)} />
                <span>{kind}</span>
              </label>
            )}
          </For>
        </div>
      </div>
      <div class={css.field}>
        <span class={css.fieldLabel}>Ignore rules</span>
        <div role="list" aria-label="Ignore rules">
          <Show when={audit().ignore.length === 0}>
            <p class={css.note}>No ignore rules.</p>
          </Show>
          <For each={audit().ignore}>
            {(rule, i) => (
              <div class={css.originRow} role="listitem">
                <span>{ignoreWords(rule)}</span>
                <Button
                  variant="ghost"
                  aria-label={`Remove ignore rule ${i() + 1}`}
                  onClick={() => setAudit('ignore', audit().ignore.filter((_, at) => at !== i()))}
                >
                  <Icon name="x" size={12} />
                </Button>
              </div>
            )}
          </For>
        </div>
      </div>
      <div class={css.originRow}>
        <Picker label="Ignore kind" options={IGNORE_KINDS} value={ignoreKind()} onValue={setIgnoreKind} />
        <TextField label="Ignore name regex" value={ignoreRegex()} onValue={setIgnoreRegex} />
        <Picker label="Ignore trait" options={IGNORE_TRAITS} value={ignoreTrait()} onValue={setIgnoreTrait} />
        <Button variant="outline" onClick={() => addIgnore()}>
          Add ignore rule
        </Button>
      </div>
      <NumField label="Max points per request" value={audit().max_points_per_request} onValue={(v) => setAudit('max_points_per_request', v)} />
      <NumField label="Frequent point threshold" value={audit().frequent_point_threshold} onValue={(v) => setAudit('frequent_point_threshold', v)} />
    </Section>
  );
};

/** Session mode, loss policy, the source flow and the names-only preview (D7); owns the preview. */
const SessionSection: Component<SectionProps & { preview: (origin: string) => Promise<SessionProfile | null>; disabled: boolean }> = (props) => {
  const setSession = blockSetter(props, 'session');
  const session = () => props.profile.session;
  const [preview, setPreview] = createSignal<{ origin: string; session: SessionProfile } | null>(null);
  const runPreview = async (origin: string): Promise<void> => {
    const result = await props.preview(origin);
    if (result) setPreview({ origin, session: result });
  };
  return (
    <Section title="Session">
      <Segmented label="Session mode" options={SESSION_MODES} value={session().mode} onValue={(v) => setSession('mode', v)} />
      <Segmented label="On session lost" options={ON_LOST} value={session().on_lost} onValue={(v) => setSession('on_lost', v)} />
      <TextField
        label="Session from flow"
        value={session().from_flow ?? ''}
        placeholder="flow id (optional)"
        onValue={(v) => setSession('from_flow', v.trim() === '' ? null : v.trim())}
      />
      <For each={props.profile.target.origins}>
        {(origin) => (
          <Button variant="outline" disabled={props.disabled} onClick={() => void runPreview(origin)}>
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
  );
};

const BudgetSection: Component<SectionProps> = (props) => {
  const setBudget = blockSetter(props, 'budget');
  const budget = () => props.profile.budget;
  return (
    <Section title="Budget">
      <NumField label="Probe budget" value={budget().probes} onValue={(v) => setBudget('probes', v)} />
      <NumField label="Time budget (s)" value={budget().time_s} onValue={(v) => setBudget('time_s', v)} />
      <NumField label="Max issues" value={budget().max_issues} onValue={(v) => setBudget('max_issues', v)} />
      <NumField label="Check timeout (s)" value={budget().check_timeout_s} onValue={(v) => setBudget('check_timeout_s', v)} />
      <NumField
        label="Consecutive errors per host"
        value={budget().per_host_errors.consecutive}
        onValue={(v) => setBudget('per_host_errors', { ...budget().per_host_errors, consecutive: v })}
      />
      <NumField
        label="Error ratio per host"
        step="0.1"
        value={budget().per_host_errors.ratio}
        onValue={(v) => setBudget('per_host_errors', { ...budget().per_host_errors, ratio: v })}
      />
    </Section>
  );
};

const HttpSection: Component<SectionProps> = (props) => {
  const setHttp = blockSetter(props, 'http');
  return (
    <Section title="HTTP">
      <Segmented label="HTTP version" options={HTTP_VERSION_POLICIES} value={props.profile.http.version} onValue={(v) => setHttp('version', v)} />
      <Segmented label="Record probes" options={RECORD_PROBES} value={props.profile.http.record_probes} onValue={(v) => setHttp('record_probes', v)} />
    </Section>
  );
};

const WsSection: Component<SectionProps> = (props) => {
  const setWs = blockSetter(props, 'ws');
  return (
    <Section title="WS">
      <NumField label="Reply window (ms)" value={props.profile.ws.reply_window_ms} onValue={(v) => setWs('reply_window_ms', v)} />
      <NumField label="Max frame bytes" value={props.profile.ws.max_frame_bytes} onValue={(v) => setWs('max_frame_bytes', v)} />
    </Section>
  );
};

/** The L4 lane's options and seeds; owns the seeds text so a half-typed line survives. */
const L4Section: Component<SectionProps> = (props) => {
  const setL4 = blockSetter(props, 'l4');
  const l4 = () => props.profile.l4;
  const [seeds, setSeeds] = createSignal(seedText(l4().seeds));
  createEffect(() => {
    if (seedText(parseSeeds(seeds())) !== seedText(l4().seeds)) setSeeds(seedText(l4().seeds));
  });
  return (
    <Section title="L4">
      <NumField label="Cases" value={l4().cases} onValue={(v) => setL4('cases', v)} />
      <NumField label="Reproduce count" value={l4().reproduce_count} onValue={(v) => setL4('reproduce_count', v)} />
      <NumField label="Liveness every" value={l4().liveness_every} onValue={(v) => setL4('liveness_every', v)} />
      <NumField label="Consecutive timeouts" value={l4().consecutive_timeouts} onValue={(v) => setL4('consecutive_timeouts', v)} />
      <NumField label="Max bytes per second" value={l4().max_bytes_per_s} onValue={(v) => setL4('max_bytes_per_s', v)} />
      <BoolField label="Dry run" checked={l4().dry_run} onValue={(v) => setL4('dry_run', v)} />
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
  );
};

/* ------------------------------------------------------------------ result and footer */

/**
 * The launch result (D-T8.6): the last error of the operations this editor owns — a launch, a save,
 * a delete, a preview (PA5) — with the Add-to-Scope affordance an `out_of_scope` refusal asks for,
 * or the started toast text. A `profile` error renders in the load block, an `issue` or `cancel`
 * error elsewhere; neither reaches here.
 */
const LaunchResult: Component<{ profile: ScanProfile; scope: readonly { host: string }[]; onAddScope: (host: string) => void }> = (props) => {
  const s = scanStore(useApp());
  const error = s.errorFor(['launch', 'save', 'delete', 'preview']);
  const refusedHost = createMemo(() => {
    const e = error();
    if (e === null || e.code !== 'out_of_scope') return null;
    const origin = props.profile.target.origins.find((o) => !hostInScope(o, props.scope));
    return origin === undefined ? null : hostOf(origin);
  });
  return (
    <Show when={error() ?? s.startNotice()}>
      <div class={css.notice} role="status" aria-label="Launch result">
        <Show
          when={error()}
          fallback={<Show when={s.startNotice()}>{(started) => <p class={css.note}>{started().job} started</p>}</Show>}
        >
          {(e) => (
            <>
              <p>{e().text}</p>
              <Show when={refusedHost()}>
                {(h) => (
                  <Button variant="outline" onClick={() => props.onAddScope(h())}>
                    Add {h()} to Scope
                  </Button>
                )}
              </Show>
            </>
          )}
        </Show>
      </div>
    </Show>
  );
};

/** Pre-flight, the agent note, Save / Save as / Delete (with its inline confirm), Map only and Start. */
const LaunchFooter: Component<{
  name: string;
  profile: ScanProfile;
  dirty: boolean;
  builtin: boolean;
  saved: boolean;
  nameOk: boolean;
  renaming: boolean;
  onRename: () => void;
}> = (props) => {
  const app = useApp();
  const s = scanStore(app);
  const [confirmDelete, setConfirmDelete] = createSignal(false);

  /** A built-in is never overwritten: saving it needs `Save as` and a name the engine accepts. */
  const canSave = () => props.nameOk && props.dirty && !(props.builtin && props.profile.name === props.name) && !s.busy();

  const pf = createMemo(() =>
    preflight(props.profile, {
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
  const launch = (mode: LaunchMode): void => void s.launch(props.profile, mode);
  const launchDisabled = () => !s.busOpen() || !pf().ok || s.busy();

  return (
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
      <Button variant="outline" disabled={!s.busOpen() || !canSave()} onClick={() => void s.saveProfile(props.profile)}>
        Save
      </Button>
      <Show when={props.builtin && !props.renaming}>
        <Button variant="ghost" disabled={!s.busOpen()} onClick={() => props.onRename()}>
          Save as
        </Button>
      </Show>
      <Show when={props.saved}>
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
      <Button variant="outline" disabled={launchDisabled()} onClick={() => launch('map')}>
        Map only
      </Button>
      <Button variant="primary" disabled={launchDisabled()} onClick={() => launch('start')}>
        Start
      </Button>
    </div>
  );
};
