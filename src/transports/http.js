import http from "node:http";

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        if (!raw.trim()) {
          resolve({});
          return;
        }
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body)
  });
  res.end(body);
}

async function handleJsonRpcPayload(handler, payload) {
  if (Array.isArray(payload)) {
    const responses = [];
    for (const message of payload) {
      const response = await handler(message);
      if (response) {
        responses.push(response);
      }
    }
    return responses;
  }
  return await handler(payload);
}

export function startHttpTransport(handler, options = {}) {
  const host = options.host ?? process.env.MCP_HTTP_HOST ?? "127.0.0.1";
  const port = Number(options.port ?? process.env.MCP_HTTP_PORT ?? 3000);

  const server = http.createServer(async (req, res) => {
    if (req.url === "/health" && req.method === "GET") {
      sendJson(res, 200, { status: "ok", service: "financial-services-mcp", timestamp: new Date().toISOString() });
      return;
    }

    if (req.url === "/mcp" && req.method === "POST") {
      try {
        const payload = await readJsonBody(req);
        const response = await handleJsonRpcPayload(handler, payload);
        if (response == null || (Array.isArray(response) && response.length === 0)) {
          res.writeHead(204);
          res.end();
          return;
        }
        sendJson(res, 200, response);
      } catch (error) {
        sendJson(res, 400, {
          jsonrpc: "2.0",
          id: null,
          error: {
            code: -32700,
            message: "Invalid JSON payload",
            data: error instanceof Error ? error.message : String(error)
          }
        });
      }
      return;
    }

    if (req.url === "/" && req.method === "GET") {
      sendJson(res, 200, {
        name: "financial-services-mcp",
        transports: ["stdio", "http"],
        endpoint: "/mcp",
        health: "/health"
      });
      return;
    }

    sendJson(res, 404, { error: "Not found" });
  });

  server.listen(port, host, () => {
    process.stderr.write(`[financial-services-mcp] HTTP transport listening on http://${host}:${port}/mcp\n`);
  });

  return server;
}
