// The chip bar's order (§2.7): `All | HTTP HTTPS WebSocket | h1 h2 | JSON Form XML JS CSS GraphQL
// Document Media Other`. ⌘1…⌘9 select the first nine.
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
