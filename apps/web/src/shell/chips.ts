// The chip bar's order (§2.7; L4 parity §7(c)): `All | HTTP HTTPS WebSocket | TCP UDP L4 | h1 h2 |
// JSON Form XML JS CSS GraphQL Document Media Other`. ⌘1…⌘9 select the first nine (⌘5 is TCP).
import type { Chip } from '~/state/app';

export interface ChipDef {
  id: Chip;
  label: string;
  /** A separator is drawn before this chip. */
  group?: boolean;
}

export const CHIPS: readonly ChipDef[] = [
  { id: 'all', label: 'All' },
  { id: 'http', label: 'HTTP', group: true },
  { id: 'https', label: 'HTTPS' },
  { id: 'ws', label: 'WebSocket' },
  { id: 'tcp', label: 'TCP', group: true },
  { id: 'udp', label: 'UDP' },
  { id: 'l4', label: 'L4' },
  { id: 'h1', label: 'h1', group: true },
  { id: 'h2', label: 'h2' },
  { id: 'json', label: 'JSON', group: true },
  { id: 'form', label: 'Form' },
  { id: 'xml', label: 'XML' },
  { id: 'js', label: 'JS' },
  { id: 'css', label: 'CSS' },
  { id: 'graphql', label: 'GraphQL' },
  { id: 'document', label: 'Document' },
  { id: 'media', label: 'Media' },
  { id: 'other', label: 'Other' },
];
