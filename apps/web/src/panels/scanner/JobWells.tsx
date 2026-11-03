// The two wells under the table (spec D18 W2, D11; plan Task 3.8 skeleton, Task 3.8c fills it):
// `Crawl and points` and `Issues`, one `<section aria-label>` each, their rows from the Kit's
// `wellRows` (D21) — every key, every grouped number and the `—` before the status lands come from
// `helpers.ts`. The block is the entrance's fourth (`--jobs-i: 3`) and follows the card's
// `data-entrance`. The skeleton renders each row's key and joined text; Task 3.8c inks the cells.

import { For, type Component } from 'solid-js';
import { WELL_CRAWL_SUBTITLE, WELL_CRAWL_TITLE, WELL_ISSUES_SUBTITLE, WELL_ISSUES_TITLE, wellRows, type JobFacts, type WellRow } from './helpers';
import css from './jobs.module.css';

export interface JobWellsProps {
  facts: JobFacts;
  generation: number;
  play: boolean;
}

const Well: Component<{ title: string; subtitle: string; rows: WellRow[] }> = (props) => (
  <section class={css.well} aria-label={props.title}>
    <h3 class={css.wellTitle}>
      {props.title}
      <span class={css.wellSub}>{props.subtitle}</span>
    </h3>
    <For each={props.rows}>
      {(row) => (
        <div class={css.kv} data-key={row.key}>
          <span>{row.key}</span>
          <span class={css.unit} data-field="value">
            {row.text}
          </span>
        </div>
      )}
    </For>
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
