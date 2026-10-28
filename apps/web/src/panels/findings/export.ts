// Export helpers for a finding (§2.7 "Export (YAML + PNG …)"). Files download through a Blob and
// an anchor; names are `<title-slug>-<yyyymmdd-HHMM>.<ext>` so repeated runs of one PoC sort by
// time and never overwrite each other. HAR of the capture waits on the core follow-up.

import type { PocRun } from '~/bus/mock';
import { base64ToBytes } from '~/lib/bytes';

export type ExportExt = 'yaml' | 'png';

export function slugify(s: string): string {
  return s
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
    .replace(/-+$/g, '');
}

const two = (n: number) => String(n).padStart(2, '0');

/** `20261027-1105` in local time; a sortable, filename-safe stamp. */
export function fileStamp(epochMs: number): string {
  const d = new Date(epochMs);
  return `${d.getFullYear()}${two(d.getMonth() + 1)}${two(d.getDate())}-${two(d.getHours())}${two(d.getMinutes())}`;
}

/** Base name of a path without its extension, for runs with no title. */
function pathStem(path: string | null | undefined): string {
  if (!path) return '';
  const base = path.split(/[\\/]/).pop() ?? '';
  return base.replace(/\.[^.]+$/, '');
}

export function exportFilename(run: Pick<PocRun, 'title' | 'at' | 'poc_path'>, ext: ExportExt): string {
  const slug = slugify(run.title ?? '') || slugify(pathStem(run.poc_path)) || 'finding';
  const at = Number.isFinite(run.at) ? run.at : Date.now();
  return `${slug}-${fileStamp(at)}.${ext}`;
}

export function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Give the browser a tick to start the download before revoking.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function yamlBlob(text: string): Blob {
  return new Blob([text], { type: 'text/yaml;charset=utf-8' });
}

export function pngBlob(base64: string, mime = 'image/png'): Blob {
  const bytes = base64ToBytes(base64);
  return new Blob([bytes as BlobPart], { type: mime });
}

/** What `poc.artifact` returns (§4.7 / F13): bytes for images, text for YAML. */
export interface Artifact {
  mime: string;
  base64?: string;
  text?: string;
}

export function artifactDataUrl(a: Artifact): string | null {
  if (a.base64) return `data:${a.mime || 'image/png'};base64,${a.base64}`;
  return null;
}
