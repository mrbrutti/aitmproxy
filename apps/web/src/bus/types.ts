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

export type BusState = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'closed';

/** Push events (§4.4, F4). The bridge relays them verbatim; the mock bus emits the same shapes. */
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
  summary?: unknown;
}

export interface AgentNotification {
  origin: 'mcp' | 'cli' | 'mac' | 'web' | 'tui';
  command: string;
  args?: unknown;
  result: 'ok' | 'error';
  at: string;
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
  /** Human-readable endpoint for the status bar (`bus 127.0.0.1:9090` or `fixtures`). */
  readonly address: string;
  readonly state: Accessor<BusState>;
  /** Last connection error text, for the status bar tooltip. */
  readonly lastError: Accessor<string | null>;
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
