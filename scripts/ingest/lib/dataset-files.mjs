import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const projectRoot = path.resolve(__dirname, "../../..");
export const rawDir = path.join(projectRoot, "ingestion", "raw");
export const compiledDir = path.join(projectRoot, "data");

export const sectionMap = [
  { key: "authoritativeSources", file: "authoritative_sources.json" },
  { key: "dataCategories", file: "data_categories.json" },
  { key: "architecturePatterns", file: "architecture_patterns.json" },
  { key: "threatScenarios", file: "threat_scenarios.json" },
  { key: "technicalStandards", file: "technical_standards.json" },
  { key: "applicabilityRules", file: "applicability_rules.json" },
  { key: "evidenceArtifacts", file: "evidence_artifacts.json" },
  { key: "breachObligationsByJurisdiction", file: "breach_obligations_by_jurisdiction.json" },
  { key: "jurisdictionComparisonTopics", file: "jurisdiction_comparison_topics.json" },
  { key: "controlCatalog", file: "control_catalog.json" },
  { key: "knownLimitations", file: "known_limitations.json" }
];

function stableSort(value) {
  if (Array.isArray(value)) {
    return value.map((item) => stableSort(item));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const output = {};
  for (const key of Object.keys(value).sort()) {
    output[key] = stableSort(value[key]);
  }
  return output;
}

export function stableStringify(value) {
  return JSON.stringify(stableSort(value));
}

export function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export async function ensureIngestionDirs() {
  await mkdir(rawDir, { recursive: true });
  await mkdir(compiledDir, { recursive: true });
}

export async function readJson(filePath) {
  const text = await readFile(filePath, "utf8");
  return JSON.parse(text);
}

export async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

export async function loadRawSections() {
  const dataset = {};
  for (const section of sectionMap) {
    const filePath = path.join(rawDir, section.file);
    dataset[section.key] = await readJson(filePath);
  }
  return dataset;
}

export async function writeSourcesYml(authoritativeSources) {
  const lines = [];
  lines.push("sources:");
  for (const source of authoritativeSources) {
    lines.push(`  - id: "${source.id}"`);
    lines.push(`    source_type: "${source.source_type}"`);
    lines.push(`    name: "${escapeYamlString(source.name)}"`);
    lines.push(`    content: "${escapeYamlString(source.content)}"`);
    lines.push(`    provenance: "${escapeYamlString(source.provenance)}"`);
    lines.push(`    license: "${escapeYamlString(source.license)}"`);
    lines.push(`    refresh_cadence: "${escapeYamlString(source.refresh_cadence)}"`);
    lines.push(`    source_url: "${escapeYamlString(source.source_url)}"`);
  }
  const outputPath = path.join(projectRoot, "sources.yml");
  await writeFile(outputPath, `${lines.join("\n")}\n`, "utf8");
}

function escapeYamlString(value) {
  return String(value ?? "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}
