// The command-bus client contract (foundation §4.10): JSON-RPC 2.0 / MCP 2025-06-18 lines over a
// WebSocket to `aitm web`'s /bus bridge. Every surface makes identical calls; the UI never
// hard-codes a command's parameters — forms and the palette are built from `tools/list`.

import type { Accessor } from 'solid-js';

export type JsonValue = string | number | boolean | null | JsonValue[] | { [k: string]: JsonValue };

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: number;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: number;
  result?: unknown;
  error?: JsonRpcError;
}

/** One entry of `tools/list`. `mutates`/`confirm` arrive with F1; absent today. */
export interface ToolDef {
  name: string;
  description: string;
  inputSchema: JsonSchema;
  mutates?: boolean;
  confirm?: string | null;
}

export interface JsonSchema {
  type?: string | string[];
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: JsonValue[];
  format?: string;
  additionalProperties?: boolean | JsonSchema;
  /** aitm TypeDesc hint (FlowId, Bytes, …) when the server emits it. */
  'x-aitm'?: string;
}

/** `tools/call` result envelope (§4.1). */
export interface ToolCallResult {
  content: { type: 'text'; text: string }[];
  structuredContent?: unknown;
  isError?: boolean;
}

export type BusState = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'closed' | 'unauthorized';

/**
 * The connection role the server/bridge resolves from the presented token (Decision A/C). The
 * client never declares it; it is read back from the `initialize` result's `role` echo.
 */
export type BusRole = 'operator' | 'agent';

/**
 * The `initialize` result (§4.1). `role` is the additive Decision C echo describing *this*
 * connection; it is absent on servers predating the echo, in which case the role is unknown.
 */
export interface ServerInfo {
  protocolVersion?: string;
  capabilities?: unknown;
  serverInfo?: { name?: string; version?: string };
  role?: BusRole;
}

/** Push events (§4.4, F4). The bridge relays them verbatim. */
export type FlowEventKind =
  | 'created'
  | 'request'
  | 'response'
  | 'ws_message'
  | 'intercepted'
  | 'released'
  | 'killed'
  | 'mutated'
  | 'meta'
  | 'cleared';

export interface FlowNotification {
  event: FlowEventKind;
  id: string;
  /**
   * The full `flow.get` object for the flow, same keys and spelling (`kind:"http"` with method,
   * scheme, authority, path, status, request_bytes, response_bytes, started_at, duration_ms;
   * `kind:"websocket"` with handshake, messages, started_at, duration_ms). On a real bus the store
   * still treats the push as a trigger and refetches the row by id; that is a deliberate choice
   * (one fetch path for push and poll), not a workaround for a sparse summary.
   */
  summary?: unknown;
}

/**
 * One audit line, in the model the Activity log renders. The server's wire shape differs
 * (`crates/aitm-core/src/audit.rs`): `at` is epoch ms, the label is `client_label`, `args` is a
 * redacted JSON string and `result` is `"ok"` or `{error}`; `toAgentEntry` in `bus/normalize.ts`
 * converts it; a line already in this model shape is accepted as it is.
 */
export interface AgentNotification {
  /** `operator`, `mcp` and `cli` are what the server records; `mac`, `web` and `tui` are frontend labels the model shape may carry, shown by name (only `mcp` renders as the agent). */
  origin: 'mcp' | 'cli' | 'operator' | 'mac' | 'web' | 'tui';
  /** The caller's `initialize.clientInfo.name`; `null` for an unlabelled connection (the bridge today). */
  clientLabel?: string | null;
  command: string;
  args?: unknown;
  result: 'ok' | 'error';
  /** ISO 8601. */
  at: string;
  /** The error reason when `result` is `error`. */
  detail?: string;
}

export interface StateNotification {
  listening: boolean;
  address?: string;
  protocol?: string;
  intercept_armed: boolean;
  paused: number;
  agent: 'all' | 'readonly' | 'paused';
  agent_actions_last_minute?: number;
  throughput?: { up: number; down: number };
  memory_bytes?: number;
}

/**
 * `proxy.status.system_proxy` (spec D6): the OS-level system proxy as the core reads it. The
 * compact sub-object carries the first seven fields; the full `proxy.system.*` results add
 * `guidance` (the env line when `unsupported`) and `remedy` (the privilege sentence when
 * `needs_privilege`). A state string the client does not know parses to `unknown`.
 */
export type SystemProxyState = 'off' | 'points_at_us' | 'other' | 'unsupported' | 'needs_privilege' | 'unknown';

export interface SystemProxyStatus {
  state: SystemProxyState;
  /** The effective endpoint; present only for `other` (D6). */
  host: string | null;
  port: number | null;
  /** The state file exists and every service it lists still reads back as what we wrote. */
  managed_by_us: boolean;
  /** A set/unset is in flight in the core (another client's call). */
  setting: boolean;
  /** `mechanism != none`. */
  supported: boolean;
  detail: string;
  guidance?: string | null;
  remedy?: string | null;
}

export class BusError extends Error {
  constructor(
    message: string,
    readonly code: number | null = null,
    readonly tool: string | null = null,
  ) {
    super(message);
    this.name = 'BusError';
  }
}

export type NotificationHandler = (method: string, params: unknown) => void;

export interface BusClient {
  /** Human-readable endpoint for the status bar: the bridge's host (`127.0.0.1:8082`). */
  readonly address: string;
  readonly state: Accessor<BusState>;
  /** Last connection error text, for the status bar tooltip. */
  readonly lastError: Accessor<string | null>;
  /**
   * The role this connection resolved to, from the `initialize` result `role` echo (Decision C).
   * `null` until `initialize` succeeds, after a disconnect, or when the server echoed no role.
   */
  readonly role: Accessor<BusRole | null>;
  /**
   * The client-side role *expectation* carried in the launch URL's `#expect=` fragment (Decision
   * B). Never sent to the server; it only drives the mismatch warning. `null` when none was set.
   */
  readonly expectRole: BusRole | null;
  /**
   * `true` when an expectation was set and the resolved role differs from it — including when the
   * server echoed no role, so the expectation cannot be confirmed (AC8). `false` when no
   * expectation was set.
   */
  readonly roleMismatch: Accessor<boolean>;
  connect(): void;
  close(): void;
  /** `tools/list`, cached after the first success. */
  tools(): Promise<ToolDef[]>;
  /** `tools/call`. Resolves `structuredContent` (or parsed text); rejects with BusError on `isError`. */
  call<T = unknown>(tool: string, args?: Record<string, unknown>): Promise<T>;
  /** Server-pushed `notifications/*`. Returns an unsubscribe. */
  onNotification(handler: NotificationHandler): () => void;
}

export const CLIENT_INFO = { name: 'aitm-web', version: '0.1.0' } as const;
export const PROTOCOL_VERSION = '2025-06-18';

/**
 * Narrow an untrusted role value — a URL/sessionStorage `#expect=` fragment or the `initialize`
 * result's `role` echo — to a known {@link BusRole}, returning `null` for anything else (absent,
 * unknown, or a role we do not model). The single source of truth for this check (Decision B/C).
 */
export function asRole(v: string | null | undefined): BusRole | null {
  return v === 'operator' || v === 'agent' ? v : null;
}

/**
 * One PoC as the Findings panel models it: a `poc.list` library entry, with its `poc.get` source
 * and the latest `poc.run` result of this session folded in by the store.
 */
export interface PocRun {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target: string;
  passed: boolean;
  at: number;
  origin: 'human' | 'agent';
  poc_path: string;
  yaml: string;
  finding_capture: string;
  screenshot_path: string | null;
  evaluated: { assertion: string; matched: boolean }[];
  /** Built in this session but not yet saved under poc.dir (the core returns YAML text only). */
  local?: boolean;
  /** The PoC's description text, when its `poc.list` entry carries one (`poc.get` answers it too, but only its YAML is kept); absent when none exists. */
  description?: string;
  /** Set when this entry has a run result in this session (poc.run keeps no history). */
  ran?: boolean;
}
