import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { toolDefinitions } from "../src/mcp/tools.js";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(testDir, "..");

test("compiled dataset metadata aligns with hash manifest", () => {
  const dataset = JSON.parse(readFileSync(new URL("../data/domain-dataset.json", import.meta.url), "utf8"));
  const hashes = JSON.parse(readFileSync(new URL("../data/dataset-hashes.json", import.meta.url), "utf8"));
  assert.equal(dataset._meta.fingerprint, hashes.dataset_fingerprint);
  assert.equal(dataset._meta.dataset_version, hashes.dataset_version);
  assert.equal(dataset._meta.coverage.eu.total, 27);
  assert.equal(dataset._meta.coverage.us.total, 51);
});

test("ingestion raw inputs are in sync with compiled hashes", () => {
  const run = spawnSync("node", ["scripts/ingest/check-drift.mjs"], {
    cwd: projectRoot,
    encoding: "utf8"
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
});

test("ingestion data integrity quality gate passes", () => {
  const run = spawnSync("node", ["scripts/qa/data-integrity.mjs"], {
    cwd: projectRoot,
    encoding: "utf8"
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
});

test("coverage report confirms complete EU and US jurisdiction coverage", () => {
  const report = JSON.parse(readFileSync(new URL("../data/coverage-report.json", import.meta.url), "utf8"));
  assert.equal(report.eu.total, 27);
  assert.equal(report.us.total, 51);
  assert.equal(report.eu.missing.length, 0);
  assert.equal(report.us.missing.length, 0);
  assert.equal(report.eu.covered, 27);
  assert.equal(report.us.covered, 51);
  assert.ok(report.us_state_breach_profile_quality);
  assert.equal(report.us_state_breach_profile_quality.total, 51);
  assert.ok(report.us_state_breach_profile_quality.source_tier.primary >= 10);
  assert.equal(report.us_state_breach_profile_quality.confidence.unknown, 0);
});

test("compiled dataset includes obligation graph and US state breach profiles", () => {
  const dataset = JSON.parse(readFileSync(new URL("../data/domain-dataset.json", import.meta.url), "utf8"));
  assert.ok(dataset.obligationGraph);
  assert.ok(Array.isArray(dataset.obligationGraph.nodes));
  assert.ok(Array.isArray(dataset.obligationGraph.edges));
  assert.ok(dataset.obligationGraph.nodes.length >= 150);
  assert.ok(dataset.obligationGraph.edges.length >= 100);
  assert.ok(dataset.usStateBreachProfiles);
  assert.equal(Object.keys(dataset.usStateBreachProfiles).length, 51);
  assert.ok(dataset.usStateBreachProfiles["US-CA"].law_mcp.document_id);
  assert.equal(dataset.usStateBreachProfiles["US-CA"].source_tier, "primary");
  assert.equal(dataset.usStateBreachProfiles["US-CA"].confidence, "authoritative");
  assert.equal(dataset.usStateBreachProfiles["US-AK"].source_tier, "secondary");
  assert.equal(dataset.usStateBreachProfiles["US-AK"].confidence, "estimated");
});

test("expert knowledge pack is present in compiled dataset", () => {
  const dataset = JSON.parse(readFileSync(new URL("../data/domain-dataset.json", import.meta.url), "utf8"));
  const standardIds = new Set((dataset.technicalStandards ?? []).map((item) => item.id));
  const threatIds = new Set((dataset.threatScenarios ?? []).map((item) => item.id));
  const ruleIds = new Set((dataset.applicabilityRules ?? []).map((item) => item.id));
  const evidenceIds = new Set((dataset.evidenceArtifacts ?? []).map((item) => item.id));
  const controlIds = new Set(Object.keys(dataset.controlCatalog ?? {}));

  assert.ok(standardIds.has("std-fapi-2-0"));
  assert.ok(standardIds.has("std-nist-csf-2-0"));
  assert.ok(threatIds.has("th-instant-payment-app-fraud"));
  assert.ok(threatIds.has("th-sanctions-screening-evasion"));
  assert.ok(ruleIds.has("app-eu-open-banking-fapi"));
  assert.ok(ruleIds.has("app-us-ofac-screening"));
  assert.ok(evidenceIds.has("ev-ofac-screening-governance"));
  assert.ok(evidenceIds.has("ev-model-risk-fair-lending"));
  assert.ok(controlIds.has("SCF.SC-04"));
  assert.ok(controlIds.has("SCF.FD-01"));
});

test("regulatory catalog covers all regulation IDs used in dataset", () => {
  const dataset = JSON.parse(readFileSync(new URL("../data/domain-dataset.json", import.meta.url), "utf8"));
  const catalog = JSON.parse(
    readFileSync(new URL("../ingestion/reference/regulatory_catalog.eu-us.json", import.meta.url), "utf8")
  );
  const used = new Set();
  const add = (value) => {
    const id = String(value ?? "").toUpperCase();
    if (id) {
      used.add(id);
    }
  };
  for (const item of dataset.applicabilityRules ?? []) {
    add(item?.obligation?.regulation_id);
  }
  for (const item of dataset.threatScenarios ?? []) {
    for (const ref of item.regulation_refs ?? []) {
      add(ref.regulation_id);
    }
  }
  for (const item of dataset.dataCategories ?? []) {
    for (const ref of item.regulation_refs ?? []) {
      add(ref.regulation_id);
    }
  }
  for (const item of dataset.technicalStandards ?? []) {
    for (const ref of item.regulation_mappings ?? []) {
      add(ref.regulation_id);
    }
  }
  for (const item of dataset.evidenceArtifacts ?? []) {
    for (const ref of item.regulation_basis ?? []) {
      add(ref.regulation_id);
    }
  }

  const catalogIds = new Set([...(catalog.eu ?? []), ...(catalog.us ?? [])].map((item) => String(item.id).toUpperCase()));
  const missing = [...used].filter((id) => !catalogIds.has(id));
  assert.deepEqual(missing, []);
});

test("registry metadata aligns between package.json and server.json", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const server = JSON.parse(readFileSync(new URL("../server.json", import.meta.url), "utf8"));
  assert.equal(pkg.mcpName, server.name);
  assert.equal(pkg.version, server.version);
});

test("tool schemas include parameter descriptions for agent usability", () => {
  const missing = [];
  for (const tool of toolDefinitions) {
    const properties = tool.inputSchema?.properties ?? {};
    for (const [name, schema] of Object.entries(properties)) {
      if (!schema?.description) {
        missing.push(`${tool.name}.${name}`);
      }
    }
  }
  assert.deepEqual(missing, []);
});
