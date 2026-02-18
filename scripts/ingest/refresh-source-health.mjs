import path from "node:path";

import { compiledDir, readJson, writeJson } from "./lib/dataset-files.mjs";

const datasetPath = path.join(compiledDir, "domain-dataset.json");
const outputPath = path.join(compiledDir, "source-health.json");

async function main() {
  const dataset = await readJson(datasetPath);
  const sources = Array.isArray(dataset.authoritativeSources) ? dataset.authoritativeSources : [];
  const checks = await Promise.all(sources.map((source) => checkSource(source)));

  await writeJson(outputPath, {
    checked_at: new Date().toISOString(),
    sources_checked: checks.length,
    ok: checks.filter((item) => item.status === "ok").length,
    failed: checks.filter((item) => item.status !== "ok").length,
    checks
  });
  process.stdout.write(`Wrote ${outputPath}\n`);
}

async function checkSource(source) {
  const result = {
    id: source.id,
    name: source.name,
    source_url: source.source_url,
    status: "unknown",
    http_status: null,
    title: null,
    error: null
  };

  try {
    const response = await fetch(source.source_url, {
      method: "GET",
      signal: AbortSignal.timeout(5000)
    });
    result.http_status = response.status;
    const text = await response.text();
    result.title = extractTitle(text);
    result.status = response.ok ? "ok" : "http_error";
    if (!response.ok) {
      result.error = `HTTP ${response.status}`;
    }
  } catch (error) {
    result.status = "network_error";
    result.error = error instanceof Error ? error.message : String(error);
  }

  return result;
}

function extractTitle(html) {
  const match = String(html).match(/<title[^>]*>([^<]+)<\/title>/i);
  return match ? match[1].trim().slice(0, 160) : null;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
