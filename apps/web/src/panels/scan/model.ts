// The shape of a `scan.discover` result (crates/aitm-plugin-scanner/src/commands.rs): an array of
// reached endpoint URLs, an array of injection points (each carrying the `flow` it was found in, its
// `location`, `name`, and a redacted `example`), an endpoint-URL -> flow-id map, plus crawl meta.
// Parsing is pure and defensive so a partial or garbage payload degrades to empty rather than
// throwing in the panel.

export interface InjectionPointRow {
  /** The flow this point was discovered in — the row opens it via `app.loadDetail`. */
  flow: string;
  /** query | body_param | header | cookie | path_segment | redirect. */
  location: string;
  /** The parameter / header / segment name. */
  name: string;
  /** The observed value, already redacted by the engine for secrets/cookies. Rendered verbatim. */
  example: string;
}

export interface ScanResult {
  endpoints: string[];
  injectionPoints: InjectionPointRow[];
  /**
   * Endpoint URL -> the flow that served it, keyed by the same scrubbed string that appears in
   * `endpoints`, so an endpoint row can open its flow via `app.loadDetail`. An endpoint the engine
   * captured no flow for is absent from the map and stays a plain row. A `Map` rather than an object
   * literal: lookups can't collide with `Object.prototype` keys from an untrusted payload.
   */
  endpointFlows: Map<string, string>;
  pagesCrawled: number | null;
  stoppedReason: string | null;
}

const asString = (v: unknown): string => (typeof v === 'string' ? v : '');

// Match the engine's MAX_RESULT_ITEMS (crates/aitm-plugin-scanner): bound the rows we
// allocate/render so a drifted backend contract can't jank the tab with a huge payload.
const MAX_RESULT_ROWS = 1024;

export function parseScanResult(raw: unknown): ScanResult {
  const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  const endpoints = Array.isArray(r.endpoints)
    ? r.endpoints.slice(0, MAX_RESULT_ROWS).filter((e): e is string => typeof e === 'string')
    : [];
  const injectionPoints = Array.isArray(r.injection_points)
    ? r.injection_points.slice(0, MAX_RESULT_ROWS).map((p): InjectionPointRow => {
        const o = (p && typeof p === 'object' ? p : {}) as Record<string, unknown>;
        return { flow: asString(o.flow), location: asString(o.location), name: asString(o.name), example: asString(o.example) };
      })
    : [];
  // A plain object only — an array or a scalar here means a drifted contract, not a map. Entries with
  // a non-string or empty flow id are dropped: an id that can't be opened must not make a row look
  // clickable.
  const endpointFlows = new Map<string, string>();
  const rawFlows = r.endpoint_flows;
  if (rawFlows && typeof rawFlows === 'object' && !Array.isArray(rawFlows)) {
    for (const [url, flow] of Object.entries(rawFlows as Record<string, unknown>)) {
      if (endpointFlows.size >= MAX_RESULT_ROWS) break;
      if (typeof flow === 'string' && flow !== '') endpointFlows.set(url, flow);
    }
  }
  const pagesCrawled = typeof r.pages_crawled === 'number' ? r.pages_crawled : null;
  const stoppedReason = typeof r.stopped_reason === 'string' ? r.stopped_reason : null;
  return { endpoints, injectionPoints, endpointFlows, pagesCrawled, stoppedReason };
}
