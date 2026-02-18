const ENDPOINT_ENV = {
  "eu-regulations": "FOUNDATION_MCP_EU_URL",
  "us-regulations": "FOUNDATION_MCP_US_URL",
  "security-controls": "FOUNDATION_MCP_CONTROLS_URL",
  "swedish-law": "FOUNDATION_MCP_SWEDISH_LAW_URL",
  "law-mcp": "FOUNDATION_MCP_LAW_URL"
};

function endpointForMcp(mcp) {
  const envName = ENDPOINT_ENV[mcp];
  const value = envName ? process.env[envName] : null;
  if (!value) {
    return null;
  }
  if (value.endsWith("/mcp")) {
    return value;
  }
  return `${value.replace(/\/+$/, "")}/mcp`;
}

async function callFoundation(endpoint, tool, params, timeoutMs) {
  const body = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: tool,
      arguments: params ?? {}
    }
  };
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs)
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const payload = await response.json();
  if (payload?.error) {
    throw new Error(payload.error?.message ?? "Foundation MCP error");
  }
  return payload?.result?.structuredContent ?? payload?.result ?? null;
}

export class FoundationResolver {
  constructor(options = {}) {
    this.timeoutMs = Number(options.timeoutMs ?? process.env.FOUNDATION_MCP_TIMEOUT_MS ?? 4000);
  }

  async resolve(calls = [], maxCalls = 5) {
    const selected = calls.slice(0, Math.max(0, maxCalls));
    const resolved = [];
    const unresolved = [];

    await Promise.all(
      selected.map(async (call) => {
        const endpoint = endpointForMcp(call.mcp);
        if (!endpoint) {
          unresolved.push({
            call,
            reason: `No endpoint configured for ${call.mcp}. Set ${ENDPOINT_ENV[call.mcp] ?? "FOUNDATION_MCP_*_URL"}.`
          });
          return;
        }
        try {
          const data = await callFoundation(endpoint, call.tool, call.params, this.timeoutMs);
          resolved.push({
            call,
            endpoint,
            data
          });
        } catch (error) {
          unresolved.push({
            call,
            endpoint,
            reason: error instanceof Error ? error.message : String(error)
          });
        }
      })
    );

    return {
      attempted: selected.length,
      truncated: calls.length > selected.length ? calls.length - selected.length : 0,
      resolved_count: resolved.length,
      unresolved_count: unresolved.length,
      resolved,
      unresolved
    };
  }
}
