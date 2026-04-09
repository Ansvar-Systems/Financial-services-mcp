import path from "node:path";
import { readFile } from "node:fs/promises";

import {
  compiledDir,
  ensureIngestionDirs,
  loadRawSections,
  projectRoot,
  sectionMap,
  sha256,
  stableStringify,
  writeJson,
  writeSourcesYml
} from "./lib/dataset-files.mjs";
import {
  augmentDatasetForCoverage,
  loadCoverageReferences,
  normalizeDataset
} from "./lib/coverage-augment.mjs";

const datasetFile = path.join(compiledDir, "domain-dataset.json");
const hashesFile = path.join(compiledDir, "dataset-hashes.json");
const coverageFile = path.join(compiledDir, "coverage-report.json");
const coverageAliasFile = path.join(compiledDir, "coverage.json");

async function main() {
  await ensureIngestionDirs();
  const rawDataset = await loadRawSections();
  const references = await loadCoverageReferences();
  validateDataset(rawDataset);
  const { dataset: augmentedDataset, coverageReport } = augmentDatasetForCoverage(rawDataset, references, {
    generatedAt: process.env.INGEST_GENERATED_AT
  });
  const normalizedDataset = normalizeDataset(augmentedDataset);
  const packageJson = JSON.parse(await readFile(path.join(projectRoot, "package.json"), "utf8"));

  const sectionHashes = {};
  for (const section of sectionMap) {
    sectionHashes[section.key] = sha256(stableStringify(normalizedDataset[section.key]));
  }

  const datasetFingerprint = sha256(
    stableStringify(
      sectionMap.reduce((acc, section) => {
        acc[section.key] = sectionHashes[section.key];
        return acc;
      }, {})
    )
  );

  const outputDataset = {
    _meta: {
      domain: "financial-services",
      dataset_version: packageJson.version,
      generated_at: new Date().toISOString(),
      fingerprint: datasetFingerprint,
      coverage: coverageReport
    },
    ...normalizedDataset
  };

  const outputHashes = {
    generated_at: outputDataset._meta.generated_at,
    dataset_version: outputDataset._meta.dataset_version,
    dataset_fingerprint: datasetFingerprint,
    section_hashes: sectionHashes
  };

  await writeJson(datasetFile, outputDataset);
  await writeJson(hashesFile, outputHashes);
  await writeJson(coverageFile, coverageReport);
  await writeJson(coverageAliasFile, coverageReport);
  await writeSourcesYml(normalizedDataset.authoritativeSources);

  process.stdout.write(`Wrote ${datasetFile}\n`);
  process.stdout.write(`Wrote ${hashesFile}\n`);
  process.stdout.write(`Wrote ${coverageFile}\n`);
  process.stdout.write(`Wrote ${coverageAliasFile}\n`);
  process.stdout.write(`Wrote ${path.join(projectRoot, "sources.yml")}\n`);
  process.stdout.write(`Dataset fingerprint: ${datasetFingerprint}\n`);
}

function validateDataset(dataset) {
  requireArray(dataset, "authoritativeSources");
  requireArray(dataset, "dataCategories");
  requireArray(dataset, "architecturePatterns");
  requireArray(dataset, "threatScenarios");
  requireArray(dataset, "technicalStandards");
  requireArray(dataset, "applicabilityRules");
  requireArray(dataset, "evidenceArtifacts");
  requireObject(dataset, "breachObligationsByJurisdiction");
  requireObject(dataset, "jurisdictionComparisonTopics");
  requireObject(dataset, "controlCatalog");
  requireArray(dataset, "knownLimitations");

  requireUniqueId(dataset.authoritativeSources, "authoritativeSources");
  requireUniqueId(dataset.dataCategories, "dataCategories");
  requireUniqueId(dataset.architecturePatterns, "architecturePatterns");
  requireUniqueId(dataset.threatScenarios, "threatScenarios");
  requireUniqueId(dataset.technicalStandards, "technicalStandards");
  requireUniqueId(dataset.applicabilityRules, "applicabilityRules");
  requireUniqueId(dataset.evidenceArtifacts, "evidenceArtifacts");

  for (const source of dataset.authoritativeSources) {
    for (const key of ["id", "source_type", "name", "content", "provenance", "license", "refresh_cadence", "source_url"]) {
      if (!source?.[key]) {
        throw new Error(`authoritativeSources.${source?.id ?? "<missing id>"} missing required field '${key}'.`);
      }
    }
  }
}

function requireArray(dataset, key) {
  if (!Array.isArray(dataset[key])) {
    throw new Error(`Expected '${key}' to be an array.`);
  }
}

function requireObject(dataset, key) {
  if (!dataset[key] || typeof dataset[key] !== "object" || Array.isArray(dataset[key])) {
    throw new Error(`Expected '${key}' to be an object.`);
  }
}

function requireUniqueId(items, sectionName) {
  const seen = new Set();
  for (const item of items) {
    if (!item || typeof item !== "object") {
      throw new Error(`Invalid entry in '${sectionName}'.`);
    }
    if (!item.id || typeof item.id !== "string") {
      throw new Error(`Entry in '${sectionName}' missing string id.`);
    }
    if (seen.has(item.id)) {
      throw new Error(`Duplicate id '${item.id}' in '${sectionName}'.`);
    }
    seen.add(item.id);
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
