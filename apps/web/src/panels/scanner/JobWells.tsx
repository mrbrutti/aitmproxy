// The two wells under the table (spec D18 W2, D11, D21; plan Task 3.8c): `Crawl and points` and
// `Issues`, one `<section aria-label>` each, their rows from the Kit's `wellRows` — every key, every
// grouped number, the `—` before the status lands and each cell's ink come from `helpers.ts`; this
// file only draws them. A row is `.kv[data-key]`: the key span, then `[data-field=value]` holding
// one span per cell (`data-ink="value"` / `data-ink="muted"`, or `.sev[data-severity]`) with
// `WELL_CELL_SEPARATOR` as bare text between them, so the row's text reads `0 · 1 · 0` and the
// stylesheet paints each cell by its hook. The block is the entrance's fourth (`--jobs-i: 3`) and
// follows the card's `data-entrance`. No timer, no store read, no literal word.

import { Index, Show, type Component } from 'solid-js';
import {
  WELL_CELL_SEPARATOR,
  WELL_CRAWL_SUBTITLE,
  WELL_CRAWL_TITLE,
  WELL_ISSUES_SUBTITLE,
  WELL_ISSUES_TITLE,
  wellRows,
  type JobFacts,
  type WellCell,
  type WellRow,
} from './helpers';
import css from './jobs.module.css';

export interface JobWellsProps {
  facts: JobFacts;
  generation: number;
  play: boolean;
}

/** One cell in its ink (D21): a severity count above zero in the severity's ink, zero muted, else the value ink. */
const Cell: Component<{ cell: WellCell }> = (props) => {
  const severity = () => (typeof props.cell.ink === 'object' ? props.cell.ink.severity : null);
  return (
    <Show when={severity()} fallback={<span data-ink={props.cell.ink === 'muted' ? 'muted' : 'value'}>{props.cell.text}</span>}>
      {(level) => (
        <span class={css.sev} data-severity={level()}>
          {props.cell.text}
        </span>
      )}
    </Show>
  );
};

const Row: Component<{ row: WellRow }> = (props) => (
  <div class={css.kv} data-key={props.row.key}>
    <span>{props.row.key}</span>
    <span class={css.unit} data-field="value">
      <Index each={props.row.cells}>
        {(cell, i) => (
          <>
            <Show when={i > 0}>{WELL_CELL_SEPARATOR}</Show>
            <Cell cell={cell()} />
          </>
        )}
      </Index>
    </span>
  </div>
);

const Well: Component<{ title: string; subtitle: string; rows: WellRow[] }> = (props) => (
  <section class={css.well} aria-label={props.title}>
    <h3 class={css.wellTitle}>
      {props.title}
      <span class={css.wellSub}>{props.subtitle}</span>
    </h3>
    <Index each={props.rows}>{(row) => <Row row={row()} />}</Index>
  </section>
);

export const JobWells: Component<JobWellsProps> = (props) => {
  const rows = () => wellRows(props.facts);
  return (
    <div class={`${css.wells} ${css.enter}`} style={{ '--jobs-i': 3 }} data-entrance={props.play ? 'play' : 'none'}>
      <Well title={WELL_CRAWL_TITLE} subtitle={WELL_CRAWL_SUBTITLE} rows={rows().crawl} />
      <Well title={WELL_ISSUES_TITLE} subtitle={WELL_ISSUES_SUBTITLE} rows={rows().issues} />
    </div>
  );
};
