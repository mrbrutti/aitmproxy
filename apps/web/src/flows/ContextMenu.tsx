// Row context menu (§2.7) and the two inline popovers it opens (Comment…, Build PoC…).
// Out-of-scope rows: mutating items disabled with the scope tooltip.
import { createSignal, type Component } from 'solid-js';
import type { AppStore, FlowEntry } from '~/state/app';
import { flowUrl, MARK_COLORS, type MarkColor } from '~/model/flow';
import { Button } from '~/components/Button';
import { Popover } from '~/components/Popover';
import type { MenuEntry } from '~/components/Menu';
import type { AnchorRect } from '~/components/floating';
import { toCurl } from '~/lib/curl';
import { EVENTS, OUT_OF_SCOPE } from '~/shell/shortcuts';
import ccss from '~/components/components.module.css';

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  }
}

const MARK_LABEL: Record<MarkColor, string> = {
  red: 'Red',
  orange: 'Orange',
  yellow: 'Yellow',
  green: 'Green',
  mint: 'Mint',
  teal: 'Teal',
  cyan: 'Cyan',
  blue: 'Blue',
  indigo: 'Indigo',
  purple: 'Purple',
  pink: 'Pink',
};

export function markItems(app: AppStore, entry: FlowEntry): MenuEntry[] {
  const current = entry.flow.mark;
  return [
    ...MARK_COLORS.map((c) => ({
      label: MARK_LABEL[c],
      swatch: `var(--mark-${c})`,
      checked: current === c,
      onSelect: () => void app.mark(entry.id, c),
    })),
    { type: 'separator' as const },
    { label: 'None', checked: current == null, onSelect: () => void app.mark(entry.id, null) },
  ];
}

export interface MenuHooks {
  onComment(entry: FlowEntry): void;
  onBuildPoc(entry: FlowEntry): void;
}

export function flowMenu(app: AppStore, entry: FlowEntry, hooks: MenuHooks): MenuEntry[] {
  const f = entry.flow;
  const oos = !f.inScope;
  const scopeTitle = oos ? OUT_OF_SCOPE(f.authority) : undefined;
  const paused = f.intercept === 'paused';
  const copied = (what: string) => (ok: boolean) => app.notice(ok ? `${what} copied` : `Could not copy ${what.toLowerCase()}`, ok ? 'info' : 'error');

  const items: MenuEntry[] = [];
  if (paused) {
    items.push(
      { label: 'Resume', kbd: '⌘⏎', disabled: oos, title: scopeTitle, onSelect: () => void app.resume(entry.id) },
      { label: 'Kill', kbd: '⌘\\', disabled: oos, title: scopeTitle, onSelect: () => void app.kill(entry.id) },
      { type: 'separator' },
    );
  }
  items.push(
    { label: 'Replay', kbd: 'r', disabled: oos, title: scopeTitle, onSelect: () => void app.replay(entry.id) },
    {
      label: 'Edit & repeat…',
      disabled: oos,
      title: scopeTitle,
      onSelect: () => {
        window.dispatchEvent(new CustomEvent(EVENTS.composePrefill, { detail: { id: entry.id } }));
        app.openCompose(true);
      },
    },
    { type: 'separator' },
    { label: 'Copy URL', onSelect: () => void copyText(flowUrl(f)).then(copied('URL')) },
    { label: 'Copy as cURL', onSelect: () => void copyText(toCurl(app.details[entry.id] ?? entry.raw)).then(copied('cURL')) },
    { type: 'separator' },
    { label: 'Mark', kbd: 'm', children: markItems(app, entry) },
    { label: 'Comment…', kbd: 'c', onSelect: () => hooks.onComment(entry) },
    { label: app.ui.pinned.includes(f.authority) ? 'Unpin host' : 'Pin host', kbd: 'p', onSelect: () => app.togglePin(f.authority) },
    { label: 'Build PoC from flow…', disabled: oos, title: scopeTitle, onSelect: () => hooks.onBuildPoc(entry) },
  );
  if (oos) items.push({ label: `Add ${f.authority} to scope`, onSelect: () => void app.addScope(f.authority) });
  items.push({ type: 'separator' });
  if (paused) items.push({ label: 'Kill', kbd: 'd', danger: true, disabled: oos, title: scopeTitle, onSelect: () => void app.kill(entry.id) });
  else items.push({ label: 'Kill', kbd: 'd', disabled: true, title: 'Only a paused request can be killed' });
  return items;
}

export const CommentPopover: Component<{ app: AppStore; entry: FlowEntry; anchor: AnchorRect; onClose: () => void }> = (props) => {
  const [text, setText] = createSignal(props.entry.flow.comment ?? '');
  const save = () => {
    const next = text().trim();
    if (next !== (props.entry.flow.comment ?? '')) void props.app.comment(props.entry.id, next);
    props.onClose();
  };
  return (
    <Popover anchor={props.anchor} onClose={props.onClose} animate={false} label="Comment">
      <form
        class={ccss.popoverRow}
        onSubmit={(e) => {
          e.preventDefault();
          save();
        }}
      >
        <input class={ccss.input} type="text" placeholder="Comment" aria-label="Comment" value={text()} onInput={(e) => setText(e.currentTarget.value)} />
        <Button variant="primary" type="submit" kbd="⏎">
          Save
        </Button>
      </form>
    </Popover>
  );
};

export const PocPopover: Component<{ app: AppStore; entry: FlowEntry; anchor: AnchorRect; onClose: () => void }> = (props) => {
  const suggested = () => `${props.entry.flow.method.toLowerCase()}-${props.entry.flow.path.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'root'}`;
  const [name, setName] = createSignal(suggested());
  const [param, setParam] = createSignal('');
  const build = () => {
    if (!name().trim()) return;
    void props.app.buildPoc(props.entry.id, name().trim(), param().trim() || undefined);
    props.onClose();
  };
  return (
    <Popover anchor={props.anchor} onClose={props.onClose} animate={false} label="Build PoC from flow">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          build();
        }}
      >
        <div class={ccss.popoverTitle}>Build PoC from flow {props.entry.flow.seq}</div>
        <div class={ccss.popoverRow} style={{ 'margin-bottom': '8px' }}>
          <input class={`${ccss.input} ${ccss.mono}`} type="text" placeholder="name" aria-label="PoC name" value={name()} onInput={(e) => setName(e.currentTarget.value)} />
        </div>
        <div class={ccss.popoverRow}>
          <input class={`${ccss.input} ${ccss.mono}`} type="text" placeholder="parameter (optional)" aria-label="Parameter" value={param()} onInput={(e) => setParam(e.currentTarget.value)} />
          <Button variant="primary" type="submit" kbd="⏎" disabled={!name().trim()}>
            Build
          </Button>
        </div>
      </form>
    </Popover>
  );
};
