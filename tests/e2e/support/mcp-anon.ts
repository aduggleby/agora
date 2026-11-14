import type { APIRequestContext } from '@playwright/test';

export interface McpToolResult {
  isError: boolean;
  /** All text blocks joined. */
  text: string;
  structured: Record<string, unknown> | null;
}

/**
 * Calls one tool of the anonymous upload-link MCP (`/mcp?upload={code}`) over Streamable HTTP in stateless mode:
 * one JSON-RPC request, answered either as JSON or as a single server-sent event.
 */
export async function callAnonymousTool(
  request: APIRequestContext,
  code: string,
  name: string,
  args: Record<string, unknown>,
): Promise<McpToolResult> {
  const response = await request.post(`/mcp?upload=${encodeURIComponent(code)}`, {
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    data: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
  });
  if (!response.ok()) {
    throw new Error(`MCP call ${name} failed: ${response.status()} ${await response.text()}`);
  }

  const message = parseRpcResponse(await response.text());
  if (message.error) {
    throw new Error(`MCP call ${name} returned a protocol error: ${JSON.stringify(message.error)}`);
  }

  const result = message.result as { isError?: boolean; content?: Array<{ type: string; text?: string }>; structuredContent?: Record<string, unknown> };
  return {
    isError: result.isError === true,
    text: (result.content ?? []).filter((block) => block.type === 'text').map((block) => block.text ?? '').join('\n'),
    structured: result.structuredContent ?? null,
  };
}

function parseRpcResponse(body: string): { result?: unknown; error?: unknown } {
  const trimmed = body.trim();
  if (trimmed.startsWith('{')) {
    return JSON.parse(trimmed);
  }

  const data = trimmed
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice(5).trim())
    .filter((line) => line.startsWith('{'));
  if (data.length === 0) {
    throw new Error(`Unrecognized MCP response: ${trimmed.slice(0, 200)}`);
  }

  return JSON.parse(data[data.length - 1]);
}
