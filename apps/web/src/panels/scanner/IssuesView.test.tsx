// T8 Task 13 (D-T8.9 Issues view, D-T8.10 states; W-8 vitest half, W-16, W-17): the Issues view
// groups the loaded page under severity headers with counts, filters client-side without a
// refetch, toggles "All jobs" into a job-less `scan.issues`, and the detail renders the evidence
// verbatim, crosses into a flow / a PoC, and round-trips `false_positive` through
// `scan.issue.update`.
//
// The fixtures under `crates/aitm-scan-model/fixtures/` are wire *shapes*, never evidence: a green
// run here says the view consumes the contract, not that any scan ever ran (fixtures/README.md).
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@solidjs/testing-library';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PocRun } from '~/bus/mock';
import { AppProvider } from '~/state/context';
import { IssuesView } from './IssuesView';
import { scanStore, type ScanStore } from './store';
import { stubApp } from './testkit';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(resolve(here, '../../../../../crates/aitm-scan-model/fixtures', name), 'utf8'));

type Raw = Record<string, unknown>;
const raw = (name: string): Raw => fixture(name) as Raw;

const JOB = 'scan-1a2b3c4d';
const XSS = 'issue-9f8e7d6c';
const REDIRECT = 'issue-4c3b2a19';
const PROBE_1 = '550e8400-e29b-41d4-a716-446655440000';
const PROBE_2 = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const BASELINE = '16fd2706-8baf-433b-82eb-8c7fada847da';

const pocRun = (id: string): PocRun => ({
  id,
  title: 'Reflected XSS on /search',
  severity: 'high',
  target: 'http://127.0.0.1:8080/search',
  passed: true,
  at: 1761900000000,
  origin: 'human',
  poc_path: `/pocs/${id}.yaml`,
  yaml: '',
  finding_capture: '',
  screenshot_path: null,
  evaluated: [],
});

const built: ScanStore[] = [];

/** A stub app, its store with the newest job selected, and the rendered view. */
async function mount(opts: Parameters<typeof stubApp>[0] = {}) {
  const stub = stubApp(opts);
  const s = scanStore(stub.app);
  built.push(s);
  await s.refreshJobs();
  expect(s.selectedJob()).toBe(JOB);
  const r = render(() => (
    <AppProvider store={stub.app}>
      <IssuesView />
    </AppProvider>
  ));
  const list = await screen.findByRole('listbox', { name: 'Issues' });
  return { ...stub, s, r, list };
}

const options = () => screen.getAllByRole('option');
const headers = (): [string | null, string | null][] =>
  Array.from(document.querySelectorAll('[data-severity][data-count]')).map((e) => [
    e.getAttribute('data-severity'),
    e.getAttribute('data-count'),
  ]);

async function openDetail(id: string) {
  fireEvent.click(document.querySelector(`[data-issue="${id}"]`)!);
  const region = await screen.findByRole('region', { name: 'Issue detail' });
  await waitFor(() => expect(region.querySelector('[data-field="payload"]')).not.toBeNull());
  return region;
}

afterEach(() => {
  cleanup();
  for (const s of built.splice(0)) s.dispose();
});

describe('IssuesView: the list', () => {
  it('grouped_with_counts (W-8): severity headers carry the group count; zero groups are absent', async () => {
    await mount();
    await waitFor(() => expect(options()).toHaveLength(2));
    expect(headers()).toEqual([
      ['high', '1'],
      ['medium', '1'],
    ]);
    for (const sev of ['critical', 'low', 'info']) {
      expect(document.querySelector(`[data-severity="${sev}"][data-count]`)).toBeNull();
    }
    const first = options()[0]!;
    expect(first.getAttribute('data-issue')).toBe(XSS);
    expect(first.textContent).toContain('GET /search');
    expect(first.textContent).toContain('query:q');
    expect(first.textContent).toContain('certain');
    expect(options()[1]!.getAttribute('data-issue')).toBe(REDIRECT);
  });

  it('filters_client_side: the text box and the chips narrow the loaded rows without a refetch', async () => {
    const h = await mount();
    await waitFor(() => expect(options()).toHaveLength(2));
    const box = screen.getByRole('searchbox', { name: 'Filter issues' });
    fireEvent.input(box, { target: { value: 'redirect' } });
    await waitFor(() => expect(options()).toHaveLength(1));
    expect(options()[0]!.getAttribute('data-issue')).toBe(REDIRECT);
    expect(h.count('scan.issues')).toBe(1);

    fireEvent.input(box, { target: { value: '' } });
    await waitFor(() => expect(options()).toHaveLength(2));
    const confidence = screen.getByRole('group', { name: 'Confidence' });
    fireEvent.click(within(confidence).getByRole('button', { name: 'certain' }));
    await waitFor(() => expect(options()).toHaveLength(1));
    expect(options()[0]!.getAttribute('data-issue')).toBe(XSS);
    expect(within(confidence).getByRole('button', { name: 'certain' }).getAttribute('aria-pressed')).toBe('true');
    expect(h.count('scan.issues')).toBe(1);

    // The class chips come from the loaded rows, and print the class token as the engine names it
    // (`data-raw` opts the chip out of the title-casing the other chip groups get).
    const classes = screen.getByRole('group', { name: 'Class' });
    expect(within(classes).getAllByRole('button').map((b) => b.textContent)).toEqual(['open-redirect', 'reflected-xss']);
    const xssChip = within(classes).getByRole('button', { name: 'reflected-xss' });
    expect(xssChip.textContent).toBe('reflected-xss');
    expect(xssChip.getAttribute('data-raw')).toBe('true');
    // The confidence chips keep the default (capitalised) presentation.
    expect(within(confidence).getByRole('button', { name: 'certain' }).getAttribute('data-raw')).toBeNull();
  });

  it('all_jobs_toggle: "All jobs" reads the page without a job', async () => {
    const h = await mount();
    await waitFor(() => expect(options()).toHaveLength(2));
    expect(h.argsOf('scan.issues')[0]).toEqual({ job: JOB, limit: 1024 });
    const all = screen.getByRole('button', { name: 'All jobs' });
    expect(all.getAttribute('aria-pressed')).toBe('false');
    fireEvent.click(all);
    await waitFor(() => expect(h.count('scan.issues')).toBe(2));
    expect(h.argsOf('scan.issues').at(-1)).toEqual({ limit: 1024 });
    expect(screen.getByRole('button', { name: 'All jobs' }).getAttribute('aria-pressed')).toBe('true');
  });

  it('load_more_iff_cursor: "Load more" appears only with a cursor and appends the next page', async () => {
    const h = await mount();
    await waitFor(() => expect(options()).toHaveLength(2));
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();

    const page = raw('scan.issues.json');
    const rows = page.issues as Raw[];
    const third = { ...rows[1]!, id: 'issue-00000003', name: 'Third issue', severity: 'low' };
    h.reply('scan.issues', (args) =>
      args.cursor ? { issues: [third], next_cursor: null, by_severity: page.by_severity } : { ...page, next_cursor: REDIRECT },
    );
    await h.s.refreshIssues(JOB);
    const more = await screen.findByRole('button', { name: 'Load more' });
    fireEvent.click(more);
    await waitFor(() => expect(options()).toHaveLength(3));
    expect(h.argsOf('scan.issues').at(-1)).toEqual({ job: JOB, limit: 1024, cursor: REDIRECT });
    expect(options()[2]!.getAttribute('data-issue')).toBe('issue-00000003');
    expect(headers()).toEqual([
      ['high', '1'],
      ['medium', '1'],
      ['low', '1'],
    ]);
    expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull();
  });

  it('states (W-16): empty, error with Retry, reconnecting', async () => {
    const h = await mount({
      replies: { 'scan.issues': { issues: [], next_cursor: null, by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } } },
    });
    await screen.findByText('No issues for this job');
    expect(screen.queryAllByRole('option')).toHaveLength(0);

    h.fail('scan.issues', 'x');
    await h.s.refreshIssues(JOB);
    const retry = await screen.findByRole('button', { name: 'Retry' });
    expect(retry.closest('[data-state="error"]')!.textContent).toContain('x');
    const before = h.count('scan.issues');
    fireEvent.click(retry);
    await waitFor(() => expect(h.count('scan.issues')).toBe(before + 1));

    h.setBusState('reconnecting');
    await waitFor(() => expect(screen.getByText(/reconnecting/)).toBeTruthy());
    for (const b of h.list.parentElement!.querySelectorAll('button')) expect(b.disabled).toBe(true);
    expect((screen.getByRole('searchbox', { name: 'Filter issues' }) as HTMLInputElement).disabled).toBe(true);
  });

  it('keyboard (W-17): ArrowDown/Up/Home/End move the selection, Enter focuses the detail', async () => {
    const h = await mount();
    await waitFor(() => expect(options()).toHaveLength(2));
    h.list.focus();
    fireEvent.keyDown(h.list, { key: 'ArrowDown' });
    expect(h.s.selectedIssue()).toBe(XSS);
    fireEvent.keyDown(h.list, { key: 'ArrowDown' });
    expect(h.s.selectedIssue()).toBe(REDIRECT);
    expect(options()[1]!.getAttribute('aria-selected')).toBe('true');
    expect(options()[0]!.getAttribute('aria-selected')).toBe('false');
    fireEvent.keyDown(h.list, { key: 'ArrowUp' });
    expect(h.s.selectedIssue()).toBe(XSS);
    fireEvent.keyDown(h.list, { key: 'End' });
    expect(h.s.selectedIssue()).toBe(REDIRECT);
    fireEvent.keyDown(h.list, { key: 'Home' });
    expect(h.s.selectedIssue()).toBe(XSS);
    expect(h.list.getAttribute('aria-activedescendant')).toBe(`issue-${XSS}`);
    const region = await screen.findByRole('region', { name: 'Issue detail' });
    fireEvent.keyDown(h.list, { key: 'Enter' });
    expect(document.activeElement).toBe(region);
  });
});

describe('IssueDetail', () => {
  it('detail_renders_evidence (W-8): payload and matched verbatim, flow/PoC/finding buttons, timing table', async () => {
    const h = await mount();
    await waitFor(() => expect(options()).toHaveLength(2));
    const region = await openDetail(XSS);
    expect(h.argsOf('scan.issue')[0]).toEqual({ id: XSS });
    expect(region.querySelector('[data-field="payload"]')!.textContent).toBe('<script>aitm-canary()</script>');
    expect(region.querySelector('[data-field="matched"]')!.textContent).toBe('reflected marker aitm-canary in an HTML text node');
    const flowButtons = within(region).getAllByRole('button', { name: /^Open flow / });
    expect(flowButtons.map((b) => b.getAttribute('aria-label'))).toEqual([
      `Open flow ${PROBE_1}`,
      `Open flow ${PROBE_2}`,
      `Open flow ${BASELINE}`,
    ]);
    expect(within(region).getByRole('button', { name: 'Open PoC poc-3b1c' })).toBeTruthy();
    expect(within(region).getByRole('button', { name: 'Open finding finding-7a21' })).toBeTruthy();
    expect(within(region).queryByRole('table', { name: 'Timing' })).toBeNull();
    expect(within(region).queryByRole('table', { name: 'Diff' })).toBeNull();
    expect(region.textContent).toContain('A request parameter is reflected into the response unescaped.');
    expect(region.textContent).toContain('Contextually encode output and set a strict CSP.');
    expect(region.textContent).toContain('reflected-xss');

    // A timing issue renders its series as a table, one column per sample.
    const issue = raw('scan.issue.json');
    h.reply('scan.issue', {
      ...issue,
      evidence: {
        ...(issue.evidence as Raw),
        timing: { requested_s: [1, 5], observed_ms: [1010, 5020], baseline_ms: [40, 42], slope: 1.0, r: 0.99 },
        diff: { baseline_len: 100, true_len: 100, false_len: 7 },
      },
    });
    await h.s.loadIssue(XSS);
    const timing = await within(region).findByRole('table', { name: 'Timing' });
    const cells = Array.from(timing.querySelectorAll('td')).map((td) => td.textContent);
    for (const v of ['1', '5', '1010', '5020', '40', '42', '0.99']) expect(cells).toContain(v);
    const diff = within(region).getByRole('table', { name: 'Diff' });
    expect(Array.from(diff.querySelectorAll('td')).map((td) => td.textContent)).toEqual(['100', '100', '7']);
  });

  it('open_flow_and_poc: a probe flow is the app selection; the PoC ref opens Findings', async () => {
    const h = await mount({ findings: [pocRun('poc-3b1c')] });
    await waitFor(() => expect(options()).toHaveLength(2));
    const region = await openDetail(XSS);
    fireEvent.click(within(region).getByRole('button', { name: `Open flow ${PROBE_1}` }));
    expect(h.select).toHaveBeenCalledWith(PROBE_1);
    fireEvent.click(within(region).getByRole('button', { name: 'Open PoC poc-3b1c' }));
    await waitFor(() => expect(h.setSidebar).toHaveBeenCalledWith({ kind: 'findings' }));
  });

  it('false_positive_round_trip: the status control sends scan.issue.update and the reply replaces the row', async () => {
    const h = await mount();
    await waitFor(() => expect(options()).toHaveLength(2));
    const region = await openDetail(XSS);
    expect(region.querySelector('[data-field="status"]')!.textContent).toBe('open');
    const group = within(region).getByRole('radiogroup', { name: 'Issue status' });
    expect(within(group).getAllByRole('radio').map((r) => r.textContent)).toEqual(['open', 'confirmed', 'false_positive']);
    const fp = within(group).getByRole('radio', { name: 'false_positive' });
    fireEvent.click(fp);
    expect(fp.getAttribute('aria-checked')).toBe('true');
    expect(within(group).getByRole('radio', { name: 'open' }).getAttribute('aria-checked')).toBe('false');
    fireEvent.input(within(region).getByRole('textbox', { name: 'Note' }), { target: { value: 'intended behaviour' } });
    fireEvent.click(within(region).getByRole('button', { name: 'Update status' }));
    await waitFor(() => expect(h.argsOf('scan.issue.update')).toHaveLength(1));
    expect(h.argsOf('scan.issue.update')[0]).toEqual({ id: XSS, status: 'false_positive', note: 'intended behaviour' });
    await waitFor(() => expect(region.querySelector('[data-field="status"]')!.textContent).toBe('false_positive'));
    const row = document.querySelector(`[data-issue="${XSS}"]`)!;
    expect(row.querySelector('[data-field="status"]')!.textContent).toBe('false_positive');
    expect(document.querySelector(`[data-issue="${REDIRECT}"] [data-field="status"]`)).toBeNull();
  });
});
