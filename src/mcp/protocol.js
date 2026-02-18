import { SERVER_NAME, SERVER_TITLE, SERVER_VERSION } from "../config.js";
import { ToolInputError, dispatchTool, toolDefinitions } from "./tools.js";

function success(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function error(id, code, message, data) {
  return { jsonrpc: "2.0", id, error: { code, message, data } };
}

function toolResultEnvelope(toolName, payload) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({ tool: toolName, ...payload }, null, 2)
      }
    ],
    structuredContent: payload
  };
}

export function createRequestHandler(repo, options = {}) {
  return async function handleRequest(message) {
    if (!message || typeof message !== "object") {
      return error(null, -32600, "Invalid JSON-RPC request");
    }
    const { id, method, params } = message;

    if (!method || typeof method !== "string") {
      return id === undefined ? null : error(id, -32600, "Missing method");
    }

    try {
      switch (method) {
        case "initialize":
          return success(id, {
            protocolVersion: "2025-06-18",
            capabilities: {
              tools: {}
            },
            serverInfo: {
              name: SERVER_NAME,
              title: SERVER_TITLE,
              version: SERVER_VERSION
            }
          });
        case "notifications/initialized":
          return null;
        case "ping":
          return success(id, { ok: true, timestamp: new Date().toISOString() });
        case "tools/list":
          return success(id, { tools: toolDefinitions });
        case "tools/call": {
          const toolName = params?.name;
          const toolArgs = params?.arguments ?? {};
          if (!toolName || typeof toolName !== "string") {
            return error(id, -32602, "tools/call requires params.name");
          }
          const payload = await dispatchTool(repo, toolName, toolArgs, {
            foundationResolver: options.foundationResolver
          });
          return success(id, toolResultEnvelope(toolName, payload));
        }
        default:
          return id === undefined ? null : error(id, -32601, `Method not found: ${method}`);
      }
    } catch (err) {
      if (err instanceof ToolInputError) {
        return id === undefined ? null : error(id, -32602, err.message);
      }
      const messageText = err instanceof Error ? err.message : String(err);
      return id === undefined ? null : error(id, -32000, messageText);
    }
  };
}
