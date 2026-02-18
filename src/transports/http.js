import http from "node:http";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SOURCE_HEALTH_PATH = path.join(ROOT, "data", "source-health.json");

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

function setWorseStatus(current, candidate) {
  const rank = { ok: 0, degraded: 1, stale: 2 };
  return rank[candidate] > rank[current] ? candidate : current;
}

function ageDays(isoDate) {
  const parsed = new Date(String(isoDate ?? ""));
  if (Number.isNaN(parsed.valueOf())) {
    return null;
  }
  return (Date.now() - parsed.valueOf()) / (1000 * 60 * 60 * 24);
}

export async function buildHealthPayload(handler) {
  let status = "ok";
  const reasons = [];
  const now = new Date().toISOString();

  let datasetLastUpdated = null;
  let jurisdictionCoverage = null;
  try {
    const aboutResponse = await handler({
      jsonrpc: "2.0",
      id: "health-about",
      method: "tools/call",
      params: { name: "about", arguments: {} }
    });
    const content = aboutResponse?.result?.structuredContent;
    datasetLastUpdated = content?.data?.last_updated ?? null;
    jurisdictionCoverage = content?.data?.jurisdiction_coverage ?? null;
  } catch (error) {
    status = setWorseStatus(status, "degraded");
    reasons.push(`about_probe_failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  const datasetAge = ageDays(datasetLastUpdated);
  if (datasetLastUpdated == null) {
    status = setWorseStatus(status, "degraded");
    reasons.push("dataset_last_updated_missing");
  } else if (datasetAge == null) {
    status = setWorseStatus(status, "degraded");
    reasons.push("dataset_last_updated_invalid");
  } else if (datasetAge > 45) {
    status = setWorseStatus(status, "stale");
    reasons.push(`dataset_stale_${Math.floor(datasetAge)}d`);
  }

  let sourceHealth = null;
  if (existsSync(SOURCE_HEALTH_PATH)) {
    try {
      sourceHealth = JSON.parse(readFileSync(SOURCE_HEALTH_PATH, "utf8"));
      const healthAge = ageDays(sourceHealth.checked_at);
      if (healthAge == null) {
        status = setWorseStatus(status, "degraded");
        reasons.push("source_health_checked_at_invalid");
      } else if (healthAge > 30) {
        status = setWorseStatus(status, "stale");
        reasons.push(`source_health_stale_${Math.floor(healthAge)}d`);
      }

      const failed = Number(sourceHealth.failed ?? 0);
      const ok = Number(sourceHealth.ok ?? 0);
      if (failed > ok) {
        status = setWorseStatus(status, "degraded");
        reasons.push(`source_health_fail_ratio_${failed}:${ok}`);
      }
    } catch (error) {
      status = setWorseStatus(status, "degraded");
      reasons.push(`source_health_parse_failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  } else {
    status = setWorseStatus(status, "degraded");
    reasons.push("source_health_missing");
  }

  return {
    status,
    service: "financial-services-mcp",
    timestamp: now,
    checks: {
      dataset_last_updated: datasetLastUpdated,
      dataset_age_days: datasetAge == null ? null : Number(datasetAge.toFixed(2)),
      jurisdiction_coverage: jurisdictionCoverage,
      source_health: sourceHealth
        ? {
            checked_at: sourceHealth.checked_at ?? null,
            sources_checked: sourceHealth.sources_checked ?? null,
            ok: sourceHealth.ok ?? null,
            failed: sourceHealth.failed ?? null
          }
        : null
    },
    reasons
  };
}

export function startHttpTransport(handler, options = {}) {
  const host = options.host ?? process.env.MCP_HTTP_HOST ?? "127.0.0.1";
  const port = Number(options.port ?? process.env.MCP_HTTP_PORT ?? 3000);

  const server = http.createServer(async (req, res) => {
    if (req.url === "/health" && req.method === "GET") {
      const payload = await buildHealthPayload(handler);
      sendJson(res, 200, payload);
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
