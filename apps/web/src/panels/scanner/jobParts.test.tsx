// The Jobs view's shared parts (spec D18 W2, plan Task 3.8): the counter that remounts on a new
// text so its keyframe plays once, the row ring, the tone and agent dots, the state chip, the
// severity words and the finding-line parts. Each test pins the attributes `jobs.module.css` and
// the live script select by; nothing here reads the store.
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { AGENT_DOT_HELP } from './helpers';
import { AgentDot, JobDot, Parts, Ring, SeverityWords, StateChip, Tick } from './jobParts';
import css from './jobs.module.css';

afterEach(() => cleanup());

describe('Tick', () => {
  it('tick_remounts_on_a_new_text_not_the_same_one: a new text is a new span, the same text keeps the node', () => {
    const [text, setText] = createSignal('3,236');
    const r = render(() => <Tick text={text()} />);
    const first = r.container.querySelector(`.${css.tick}`);
    expect(first).not.toBeNull();
    expect(first!.textContent).toBe('3,236');

    setText('3,236');
    expect(r.container.querySelector(`.${css.tick}`)).toBe(first);

    setText('3,284');
    const second = r.container.querySelector(`.${css.tick}`);
    expect(second).not.toBeNull();
    expect(second).not.toBe(first);
    expect(second!.textContent).toBe('3,284');
    expect(r.container.querySelectorAll(`.${css.tick}`)).toHaveLength(1);
  });

  it('tick_takes_an_extra_class', () => {
    const r = render(() => <Tick text="50 %" class="lead" />);
    const el = r.container.querySelector(`.${css.tick}`)!;
    expect(el.classList.contains('lead')).toBe(true);
    expect(el.textContent).toBe('50 %');
  });
});

describe('Ring', () => {
  it('determinate_ring: an svg hidden from readers, the arc with pathLength 1 and the fraction to 4 decimals', () => {
    const r = render(() => <Ring ring={{ determinate: 3236 / 6468 }} />);
    const svg = r.container.querySelector('svg')!;
    expect(svg.classList.contains(css.ring!)).toBe(true);
    expect(svg.getAttribute('viewBox')).toBe('0 0 18 18');
    expect(svg.getAttribute('aria-hidden')).toBe('true');
    expect(svg.getAttribute('data-fraction')).toBe('0.5003');
    expect(svg.getAttribute('data-indeterminate')).toBeNull();
    expect(svg.style.getPropertyValue('--jobs-f')).toBe(String(3236 / 6468));
    const circles = Array.from(svg.querySelectorAll('circle'));
    expect(circles).toHaveLength(2);
    const [track, arc] = circles as [SVGCircleElement, SVGCircleElement];
    expect(track.classList.contains(css.ringTrack!)).toBe(true);
    expect(arc.classList.contains(css.ringArc!)).toBe(true);
    for (const c of circles) {
      expect(c.getAttribute('cx')).toBe('9');
      expect(c.getAttribute('cy')).toBe('9');
      expect(c.getAttribute('r')).toBe('7');
    }
    expect(arc.getAttribute('pathLength')).toBe('1');
  });

  it('indeterminate_ring: marked, with no fraction', () => {
    const r = render(() => <Ring ring="indeterminate" />);
    const svg = r.container.querySelector('svg')!;
    expect(svg.getAttribute('data-indeterminate')).toBe('true');
    expect(svg.getAttribute('data-fraction')).toBeNull();
  });

  it('none_and_finished_draw_nothing', () => {
    const none = render(() => <Ring ring="none" />);
    expect(none.container.querySelector('svg')).toBeNull();
    cleanup();
    const finished = render(() => <Ring ring={{ finished: 1 }} />);
    expect(finished.container.querySelector('svg')).toBeNull();
  });
});

describe('JobDot, AgentDot, StateChip', () => {
  it('job_dot: the tone on a hidden dot, breathing only when asked', () => {
    const r = render(() => (
      <>
        <JobDot tone="pending" breathing />
        <JobDot tone="success" breathing={false} />
      </>
    ));
    const dots = Array.from(r.container.querySelectorAll(`.${css.dot}`));
    expect(dots).toHaveLength(2);
    expect(dots[0]!.getAttribute('data-tone')).toBe('pending');
    expect(dots[0]!.getAttribute('aria-hidden')).toBe('true');
    expect(dots[0]!.classList.contains(css.breathe!)).toBe(true);
    expect(dots[1]!.getAttribute('data-tone')).toBe('success');
    expect(dots[1]!.classList.contains(css.breathe!)).toBe(false);
  });

  it('agent_dot: hidden from readers, the Kit help as its title', () => {
    const r = render(() => <AgentDot />);
    const dot = r.container.querySelector(`.${css.agentDot}`)!;
    expect(dot.getAttribute('title')).toBe(AGENT_DOT_HELP);
    expect(AGENT_DOT_HELP).toBe('started by an agent');
    expect(dot.getAttribute('aria-hidden')).toBe('true');
  });

  it('state_chip: the state field, the tone, a dot and the word; the dot breathes only while cancelling', () => {
    const r = render(() => (
      <>
        <StateChip word="Auditing" tone="progress" breathing={false} />
        <StateChip word="Cancelling" tone="pending" breathing />
      </>
    ));
    const chips = Array.from(r.container.querySelectorAll(`.${css.chip}`));
    expect(chips).toHaveLength(2);
    const [auditing, cancelling] = chips as [HTMLElement, HTMLElement];
    expect(auditing.getAttribute('data-field')).toBe('state');
    expect(auditing.getAttribute('data-tone')).toBe('progress');
    expect(auditing.textContent).toBe('Auditing');
    expect(auditing.querySelector(`.${css.chipDot}`)).not.toBeNull();
    expect(auditing.querySelector(`.${css.chipDot}`)!.classList.contains(css.breathe!)).toBe(false);
    expect(cancelling.getAttribute('data-tone')).toBe('pending');
    expect(cancelling.textContent).toBe('Cancelling');
    expect(cancelling.querySelector(`.${css.chipDot}`)!.classList.contains(css.breathe!)).toBe(true);
  });
});

describe('SeverityWords, Parts', () => {
  it('severity_words: one inked span per part, a comma-space between, the text joined', () => {
    const r = render(() => (
      <SeverityWords
        parts={[
          { severity: 'high', word: '1 high' },
          { severity: 'low', word: '2 low' },
        ]}
        empty="no issues"
        class="x"
      />
    ));
    const root = r.container.firstElementChild!;
    expect(root.classList.contains('x')).toBe(true);
    expect(root.textContent).toBe('1 high, 2 low');
    const sev = Array.from(root.querySelectorAll(`.${css.sev}`));
    expect(sev.map((e) => e.getAttribute('data-severity'))).toEqual(['high', 'low']);
    expect(sev.map((e) => e.textContent)).toEqual(['1 high', '2 low']);
    expect(root.querySelector('[data-ink=muted]')).toBeNull();
    expect(root.querySelector('[data-count]')).toBeNull();
  });

  it('severity_words_empty: the empty words in the muted ink, no severity span', () => {
    const r = render(() => <SeverityWords parts={[]} empty="no issues yet" />);
    const root = r.container.firstElementChild!;
    expect(root.textContent).toBe('no issues yet');
    expect(root.getAttribute('data-ink')).toBe('muted');
    expect(root.querySelector(`.${css.sev}`)).toBeNull();
  });

  it('parts: one span per part with its role', () => {
    const r = render(() => (
      <Parts
        parts={[
          { text: 'now · ', role: 'plain' },
          { text: 'xss-reflected', role: 'checkId' },
          { text: ' and 3 more', role: 'plain' },
        ]}
      />
    ));
    const parts = Array.from(r.container.querySelectorAll(`.${css.part}`));
    expect(parts.map((p) => p.getAttribute('data-role'))).toEqual(['plain', 'checkId', 'plain']);
    expect(r.container.textContent).toBe('now · xss-reflected and 3 more');
  });
});
