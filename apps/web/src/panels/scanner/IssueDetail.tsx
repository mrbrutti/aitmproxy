// One issue (D-T8.9 detail half): `scan.issue { id }` read into the store on mount and on every id
// change, rendered as facts and evidence **verbatim** — `payload` and `matched` are the core's
// bytes in mono, a timing series is a table with one column per sample, the L4 block prints the
// hex that was sent. The crossings leave through the store: a flow button is the app's own flow
// selection (`openFlow`), a PoC ref or finding id is matched against the Findings list (`openPoc`).
// The status control is a three-way radiogroup plus a note; "Update status" sends
// `scan.issue.update { id, status, note? }` and the reply replaces both the cached issue and the
// row (`store.updateIssue`). Missing values print a grey dash, never an empty cell (§2.8).

import { createEffect, createSignal, For, on, Show, type Component } from 'solid-js';
import { Button } from '~/components';
import { fmtClock } from '~/lib/format';
import { SeverityPill } from '~/panels/findings/SeverityPill';
import { useApp } from '~/state/context';
import { ISSUE_STATUSES, type Issue, type IssueStatus, type L4Oracle } from './model';
import { Dash, ErrorBlock, Fact, LoadingBars, yesNo } from './primitives';
import { scanStore } from './store';
import css from './scanner.module.css';

/** A fact's value: the text, or `null` (the dash) when the core gave nothing — an empty string too. */
const val = (v: string | number | null | undefined): string | null =>
  v === null || v === undefined || v === '' ? null : String(v);

function oracleText(o: L4Oracle): string {
  return o.kind === 'icmp' ? `icmp type ${o.type} code ${o.code}` : o.kind;
}

/** The jobs that found or re-found the issue (A5): the engine's list, else the one it belongs to. */
const foundBy = (i: Issue): readonly string[] => (i.jobs.length > 0 ? i.jobs : [i.job]);

/** A series row of the Timing table: one cell per sample, so two series line up column by column. */
const SeriesRow: Component<{ label: string; values: readonly number[] }> = (props) => (
  <tr>
    <th scope="row">{props.label}</th>
    <For each={props.values}>{(v) => <td>{String(v)}</td>}</For>
  </tr>
);

export const IssueDetail: Component<{ id: string }> = (props) => {
  const app = useApp();
  const s = scanStore(app);
  const issue = (): Issue | null => s.issueDetail(props.id);
  const error = (): string | null => s.issueDetailError(props.id);
  const offline = (): boolean => !s.busOpen();

  // The read is per id: a cached issue is shown at once and refreshed behind it.
  createEffect(on(() => props.id, (id) => void s.loadIssue(id)));

  // The status draft follows what the core last said; the operator's edit sits on top of it until
  // the update answers (and the reply then resets it to the new truth).
  const [draftStatus, setDraftStatus] = createSignal<IssueStatus>('open');
  const [draftNote, setDraftNote] = createSignal('');
  createEffect(
    on(issue, (i) => {
      if (!i) return;
      setDraftStatus(i.status);
      setDraftNote(i.note ?? '');
    }),
  );

  const update = (): void => {
    const note = draftNote().trim();
    void s.updateIssue(props.id, draftStatus(), note === '' ? undefined : note);
  };

  return (
    <div class={css.detail} role="region" aria-label="Issue detail" tabIndex={-1}>
      <div class={css.body}>
        <Show when={issue() === null && error()}>
          {(err) => <ErrorBlock text={err()} onRetry={() => void s.loadIssue(props.id)} disabled={offline()} />}
        </Show>
        <Show when={error() === null && issue() === null}>
          <LoadingBars label="Loading issue" />
        </Show>
        <Show when={issue()}>
          {(i) => (
            <>
              <section class={css.section}>
                <h2>{i().name}</h2>
                <div class={css.rowMeta}>
                  <span class={css.tag} data-field="class">
                    {i().class}
                  </span>
                  <SeverityPill severity={i().severity} />
                  <span class={css.sep}>×</span>
                  <span data-field="confidence">{i().confidence}</span>
                  <span class={css.tag} data-field="status">
                    {i().status}
                  </span>
                  <span class={css.mono} data-field="check">
                    {i().check_id}
                  </span>
                </div>
              </section>

              <section class={css.section} aria-label="Location">
                <h3 class={css.sectionTitle}>Location</h3>
                <dl class={css.facts}>
                  <Fact label="target" value={`${i().target.scheme}://${i().target.host}:${i().target.port}`} mono />
                  <Show
                    when={i().location.l4}
                    fallback={
                      <>
                        <Fact label="method" value={val(i().location.method)} mono />
                        <Fact label="path" value={val(i().location.path)} mono />
                        <Fact label="template" value={val(i().location.path_template)} mono />
                        <Fact label="kind" value={val(i().location.kind)} />
                        <Fact label="name" value={val(i().location.name)} mono />
                        <Fact label="field path" value={val(i().location.field_path)} mono />
                        <Fact label="ws path" value={val(i().location.ws_path)} mono />
                      </>
                    }
                  >
                    {(l4) => (
                      <>
                        <Fact label="endpoint" value={`${l4().ip}:${l4().port} ${l4().proto}`} mono />
                        <Fact label="grammar" value={val(l4().grammar)} />
                        <Fact label="field path" value={val(l4().field_path)} mono />
                        <Fact label="mutation" value={val(l4().mutation)} mono />
                        <Fact label="kind" value={val(i().location.kind)} />
                        <Fact label="name" value={val(i().location.name)} mono />
                      </>
                    )}
                  </Show>
                  <Fact label="lane" value={i().lane} />
                </dl>
              </section>

              <section class={css.section} aria-label="Description">
                <h3 class={css.sectionTitle}>Description</h3>
                <p class={css.note} data-field="description">
                  {i().description}
                </p>
                <h3 class={css.sectionTitle}>Remediation</h3>
                <p class={css.note} data-field="remediation">
                  {val(i().remediation)}
                </p>
              </section>

              <section class={css.section} aria-label="Evidence">
                <h3 class={css.sectionTitle}>Evidence</h3>
                <dl class={css.facts}>
                  <Fact
                    label="payload"
                    value={
                      <Show when={i().evidence.payload !== null} fallback={<Dash />}>
                        <pre class={css.mono} data-field="payload">
                          {i().evidence.payload}
                        </pre>
                      </Show>
                    }
                  />
                  <Fact
                    label="matched"
                    value={
                      <Show when={i().evidence.matched !== null} fallback={<Dash />}>
                        <pre class={css.mono} data-field="matched">
                          {i().evidence.matched}
                        </pre>
                      </Show>
                    }
                  />
                </dl>
                <Show when={i().evidence.timing}>
                  {(t) => (
                    <table class={css.table} aria-label="Timing">
                      <tbody>
                        <SeriesRow label="requested_s" values={t().requested_s} />
                        <SeriesRow label="observed_ms" values={t().observed_ms} />
                        <SeriesRow label="baseline_ms" values={t().baseline_ms} />
                        <tr>
                          <th scope="row">slope</th>
                          <td colSpan={Math.max(1, t().requested_s.length)}>{String(t().slope)}</td>
                        </tr>
                        <tr>
                          <th scope="row">r</th>
                          <td colSpan={Math.max(1, t().requested_s.length)}>{String(t().r)}</td>
                        </tr>
                      </tbody>
                    </table>
                  )}
                </Show>
                <Show when={i().evidence.diff}>
                  {(d) => (
                    <table class={css.table} aria-label="Diff">
                      <thead>
                        <tr>
                          <th scope="col">baseline length</th>
                          <th scope="col">true length</th>
                          <th scope="col">false length</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td>{String(d().baseline_len)}</td>
                          <td>{String(d().true_len)}</td>
                          <td>{String(d().false_len)}</td>
                        </tr>
                      </tbody>
                    </table>
                  )}
                </Show>
                <Show when={i().evidence.l4}>
                  {(l4) => (
                    <dl class={css.facts} aria-label="L4 evidence">
                      <Fact label="sent" value={l4().sent_hex} field="sent_hex" mono />
                      <Fact label="seed" value={l4().seed_id} mono />
                      <Fact label="rng seed" value={String(l4().rng_seed)} mono />
                      <Fact
                        label="mutation chain"
                        value={l4().mutation_chain.length > 0 ? l4().mutation_chain.join(' › ') : <Dash />}
                        mono
                      />
                      <Fact label="prior messages" value={String(l4().prior_messages)} />
                      <Fact label="oracle" value={oracleText(l4().oracle)} />
                      <Fact label="liveness before" value={yesNo(l4().liveness_before)} />
                      <Fact label="liveness after" value={yesNo(l4().liveness_after)} />
                      <Fact label="reproduced" value={`${l4().reproduced[0]}/${l4().reproduced[1]}`} />
                      <Fact label="scope entry" value={l4().scope_entry} mono />
                    </dl>
                  )}
                </Show>
                <div class={css.chips} role="group" aria-label="Flows">
                  <For each={i().evidence.probe_flows}>
                    {(id) => (
                      <Button variant="small" class={css.mono} aria-label={`Open flow ${id}`} disabled={offline()} onClick={() => void s.openFlow(id)}>
                        {id}
                      </Button>
                    )}
                  </For>
                  <Show when={i().evidence.baseline_flow}>
                    {(id) => (
                      <>
                        <span class={css.kv}>baseline</span>
                        <Button variant="small" class={css.mono} aria-label={`Open flow ${id()}`} disabled={offline()} onClick={() => void s.openFlow(id())}>
                          {id()}
                        </Button>
                      </>
                    )}
                  </Show>
                </div>
              </section>

              <section class={css.section} aria-label="Record">
                <h3 class={css.sectionTitle}>Record</h3>
                <dl class={css.facts}>
                  <Fact label="first seen" value={fmtClock(i().first_seen)} mono />
                  <Fact label="last seen" value={fmtClock(i().last_seen)} mono />
                  <Fact label="occurrences" value={String(i().occurrences)} mono />
                  <Fact
                    label="PoC"
                    value={
                      <Show when={i().poc_ref} fallback={<Dash />}>
                        {(ref) => (
                          <Button variant="small" aria-label={`Open PoC ${ref()}`} disabled={offline()} onClick={() => void s.openPoc(ref())}>
                            {ref()}
                          </Button>
                        )}
                      </Show>
                    }
                  />
                  <Fact
                    label="finding"
                    value={
                      <Show when={i().finding_id} fallback={<Dash />}>
                        {(fid) => (
                          <Button variant="small" aria-label={`Open finding ${fid()}`} disabled={offline()} onClick={() => void s.openPoc(fid())}>
                            {fid()}
                          </Button>
                        )}
                      </Show>
                    }
                  />
                  <Fact label="note" value={val(i().note)} />
                  <Fact
                    label="found by jobs"
                    value={
                      <ul class={css.idList} aria-label="Found by jobs">
                        <For each={foundBy(i())}>{(job) => <li class={css.mono}>{job}</li>}</For>
                      </ul>
                    }
                  />
                </dl>
              </section>

              <section class={css.section} aria-label="Status">
                <h3 class={css.sectionTitle}>Status</h3>
                <div class={css.field}>
                  <div class={css.segmented} role="radiogroup" aria-label="Issue status">
                    <For each={ISSUE_STATUSES}>
                      {(st) => (
                        <button
                          type="button"
                          role="radio"
                          class={css.segment}
                          aria-checked={draftStatus() === st}
                          disabled={offline()}
                          onClick={() => setDraftStatus(st)}
                        >
                          {st}
                        </button>
                      )}
                    </For>
                  </div>
                </div>
                <div class={css.field}>
                  <label class={css.fieldLabel} for={`issue-note-${props.id}`}>
                    Note
                  </label>
                  <textarea
                    id={`issue-note-${props.id}`}
                    aria-label="Note"
                    rows={3}
                    value={draftNote()}
                    disabled={offline()}
                    onInput={(e) => setDraftNote(e.currentTarget.value)}
                  />
                </div>
                <div class={css.footer}>
                  <Button variant="primary" disabled={offline() || s.busy()} onClick={update}>
                    Update status
                  </Button>
                </div>
              </section>
            </>
          )}
        </Show>
      </div>
    </div>
  );
};
