import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { datasetForFingerprint } from "./domainData.js";

const compiledDatasetPath = fileURLToPath(new URL("../../data/domain-dataset.json", import.meta.url));

function validateShape(value) {
  const requiredKeys = [
    "authoritativeSources",
    "dataCategories",
    "architecturePatterns",
    "threatScenarios",
    "technicalStandards",
    "applicabilityRules",
    "evidenceArtifacts",
    "breachObligationsByJurisdiction",
    "usStateBreachProfiles",
    "obligationGraph",
    "jurisdictionComparisonTopics",
    "controlCatalog",
    "knownLimitations"
  ];
  for (const key of requiredKeys) {
    if (!(key in value)) {
      throw new Error(`Compiled dataset missing required key '${key}'.`);
    }
  }
  if (!value._meta || typeof value._meta !== "object") {
    throw new Error("Compiled dataset missing _meta section.");
  }
  if (!value._meta.fingerprint || !value._meta.dataset_version) {
    throw new Error("Compiled dataset _meta is missing fingerprint or dataset_version.");
  }
  if (!value._meta.coverage || typeof value._meta.coverage !== "object") {
    throw new Error("Compiled dataset _meta is missing coverage report.");
  }
}

export function loadDomainDataset() {
  if (!existsSync(compiledDatasetPath)) {
    return { dataset: datasetForFingerprint(), source: "embedded" };
  }

  try {
    const parsed = JSON.parse(readFileSync(compiledDatasetPath, "utf8"));
    validateShape(parsed);
    const { _meta, ...dataset } = parsed;
    return { dataset, source: "compiled", meta: _meta ?? null };
  } catch {
    return { dataset: datasetForFingerprint(), source: "embedded" };
  }
}
