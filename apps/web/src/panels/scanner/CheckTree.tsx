// The check tree (D-T8.5, W-11): every check the core offers, grouped lane -> class -> check, with
// the selection written back through `applyCheckToggle` so the `id | class | lane:*` grammar in
// `checks.include` / `checks.exclude` stays a faithful description of what will run.
//
// Two rules this component keeps:
//
//   1. **It renders the core's catalogue, never a guess.** A lane with no check on this build has no
//      group here (the Lanes toggles say so in words); a selector the catalogue cannot explain is
//      shown as unknown rather than dropped, because dropping it would silently change the scan.
//   2. **One write path.** Every checkbox calls `applyCheckToggle` — the tri-state class row and the
//      leaf row alike — so there is no second, divergent idea of what a selector means.

import { createEffect, createMemo, For, Show, type Component } from 'solid-js';
import { SeverityPill } from '~/panels/findings/SeverityPill';
import { applyCheckToggle, checkIsOn, type CheckTarget } from './helpers';
import { LANES, type CheckMeta, type CheckSelection, type Lane } from './model';
import css from './scanner.module.css';

export interface CheckTreeProps {
  selection: CheckSelection;
  checks: readonly CheckMeta[];
  onChange(next: CheckSelection): void;
  /** Selectors in the selection that match no known check (`unknownSelectors`). */
  unknown: readonly string[];
}

interface ClassGroup {
  class: string;
  checks: CheckMeta[];
}

interface LaneGroup {
  lane: Lane;
  classes: ClassGroup[];
  total: number;
}

/** `all` when every check under the row runs, `none` when none does, `mixed` otherwise. */
type Tri = 'all' | 'none' | 'mixed';

function tri(on: number, total: number): Tri {
  if (total === 0 || on === 0) return 'none';
  return on === total ? 'all' : 'mixed';
}

/** A checkbox that can also be `indeterminate` — a property, so it is set on the element. */
const TriBox: Component<{ label: string; state: Tri; onToggle: (on: boolean) => void }> = (props) => {
  let el: HTMLInputElement | undefined;
  createEffect(() => {
    if (el) el.indeterminate = props.state === 'mixed';
  });
  return (
    <input
      ref={el}
      type="checkbox"
      aria-label={props.label}
      checked={props.state === 'all'}
      // A mixed row turns everything on, a full row turns everything off (the usual tri-state).
      onChange={() => props.onToggle(props.state !== 'all')}
    />
  );
};

export const CheckTree: Component<CheckTreeProps> = (props) => {
  /** Lane -> class -> check, in `LANES` order and first-seen class order within a lane. */
  const groups = createMemo<LaneGroup[]>(() => {
    const out: LaneGroup[] = [];
    for (const lane of LANES) {
      const inLane = props.checks.filter((c) => c.lanes.includes(lane));
      if (inLane.length === 0) continue;
      const classes: ClassGroup[] = [];
      const index = new Map<string, ClassGroup>();
      for (const check of inLane) {
        let group = index.get(check.class);
        if (!group) {
          group = { class: check.class, checks: [] };
          index.set(check.class, group);
          classes.push(group);
        }
        group.checks.push(check);
      }
      out.push({ lane, classes, total: inLane.length });
    }
    return out;
  });

  const isOn = (c: CheckMeta): boolean => checkIsOn(props.selection, c);
  const onCount = (checks: readonly CheckMeta[]): number => checks.filter(isOn).length;
  const toggle = (target: CheckTarget, on: boolean): void =>
    props.onChange(applyCheckToggle(props.selection, target, on, props.checks));

  return (
    <div class={css.checkTree} role="tree" aria-label="Checks">
      <Show when={props.checks.length === 0}>
        <p class={css.note}>No checks — this build ships no check catalogue.</p>
      </Show>
      <For each={props.unknown}>
        {(selector) => (
          <div class={css.checkRow} role="treeitem">
            <span class={css.mono} data-unknown="true">
              {selector}
            </span>
            <span class={css.tag}>matches no check on this build</span>
          </div>
        )}
      </For>
      <For each={groups()}>
        {(lane) => (
          <>
            <div class={css.checkClass} role="treeitem" aria-expanded="true" data-lane={lane.lane}>
              <span>{lane.lane}</span>
              <span class={css.n}>
                {onCount(lane.classes.flatMap((g) => g.checks))}/{lane.total}
              </span>
            </div>
            <div role="group">
              <For each={lane.classes}>
                {(group) => (
                  <>
                    <div class={css.checkClass} role="treeitem" aria-expanded="true" data-class={group.class}>
                      <TriBox
                        label={group.class}
                        state={tri(onCount(group.checks), group.checks.length)}
                        onToggle={(on) => toggle({ class: group.class }, on)}
                      />
                      <span>{group.class}</span>
                      <span class={css.n}>
                        {onCount(group.checks)}/{group.checks.length}
                      </span>
                    </div>
                    <div role="group">
                      <For each={group.checks}>
                        {(check) => (
                          <div class={css.checkRow} role="treeitem" data-check={check.id}>
                            <label>
                              <input
                                type="checkbox"
                                checked={isOn(check)}
                                onChange={(e) => toggle({ id: check.id }, e.currentTarget.checked)}
                              />
                              {check.name}
                            </label>
                            <span class={css.mono}>{check.id}</span>
                            <span>{check.cost}</span>
                            <span>{check.technique}</span>
                            <SeverityPill severity={check.severity} />
                            <span class={css.tag}>{check.origin.kind}</span>
                          </div>
                        )}
                      </For>
                    </div>
                  </>
                )}
              </For>
            </div>
          </>
        )}
      </For>
    </div>
  );
};
