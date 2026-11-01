// Minimal Node typings for TEST files that read repo fixtures and stylesheets from disk
// (`crates/aitm-scan-model/fixtures/*.json`, `scanner.module.css`). The app bundle never imports
// `node:*`; `@types/node` is deliberately not added because it would retype the DOM timer and
// `URL` APIs the app relies on. Only the members the tests use are declared.
declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf8' | 'utf-8'): string;
  export function readdirSync(path: string, opts: { withFileTypes: true }): { name: string; isDirectory(): boolean; isFile(): boolean }[];
  export function readdirSync(path: string): string[];
  export function existsSync(path: string): boolean;
}
declare module 'node:path' {
  export function resolve(...parts: string[]): string;
  export function dirname(path: string): string;
  export function join(...parts: string[]): string;
}
declare module 'node:url' {
  export function fileURLToPath(url: string | URL): string;
}
