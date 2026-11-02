/** A plain JSON object — not null, not an array. The shape guard for a reply the bus typed as `unknown`. */
export const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
