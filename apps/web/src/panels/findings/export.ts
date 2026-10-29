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

/** A `poc.artifact` result once normalised: the bytes (base64) plus a mime inferred from the path. */
export interface Artifact {
  mime: string;
  base64?: string;
  text?: string;
}

const MIME_BY_EXT: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  yaml: 'text/yaml',
  yml: 'text/yaml',
  har: 'application/json',
  json: 'application/json',
  txt: 'text/plain',
};

export function mimeForPath(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase() ?? '';
  return MIME_BY_EXT[ext] ?? 'application/octet-stream';
}

/**
 * The bus returns `poc.artifact` as bare base64 of the file's bytes (F13); an older fixture shape
 * was `{mime, base64|text}`. Both become an Artifact; textual types also get `text`.
 */
export function toArtifact(raw: unknown, path: string): Artifact {
  const mime = mimeForPath(path);
  if (typeof raw === 'string') {
    const a: Artifact = { mime, base64: raw };
    if (mime.startsWith('text/') || mime === 'application/json') {
      try {
        a.text = new TextDecoder().decode(base64ToBytes(raw));
      } catch {
        /* leave undecoded */
      }
    }
    return a;
  }
  const r = (raw ?? {}) as Partial<Artifact>;
  return { mime: r.mime || mime, ...(r.base64 ? { base64: r.base64 } : {}), ...(r.text ? { text: r.text } : {}) };
}

export function artifactDataUrl(a: Artifact): string | null {
  if (a.base64) return `data:${a.mime || 'image/png'};base64,${a.base64}`;
  return null;
}
