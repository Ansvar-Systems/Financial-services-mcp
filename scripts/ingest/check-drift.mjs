import path from "node:path";

import {
  compiledDir,
  loadRawSections,
  readJson,
  sectionMap,
  sha256,
  stableStringify
} from "./lib/dataset-files.mjs";
import {
  augmentDatasetForCoverage,
  loadCoverageReferences,
  normalizeDataset
} from "./lib/coverage-augment.mjs";

const hashesPath = path.join(compiledDir, "dataset-hashes.json");

async function main() {
  const rawDataset = await loadRawSections();
  const references = await loadCoverageReferences();
  const { dataset: augmentedDataset } = augmentDatasetForCoverage(rawDataset, references, {
    generatedAt: process.env.INGEST_GENERATED_AT
  });
  const normalizedDataset = normalizeDataset(augmentedDataset);
  const expectedHashes = {};
  for (const section of sectionMap) {
    expectedHashes[section.key] = sha256(stableStringify(normalizedDataset[section.key]));
  }

  const existing = await readJson(hashesPath);
  const diffs = [];
  for (const section of sectionMap) {
    const actual = existing.section_hashes?.[section.key];
    const expected = expectedHashes[section.key];
    if (actual !== expected) {
      diffs.push({ section: section.key, expected, actual: actual ?? "<missing>" });
    }
  }

  if (diffs.length === 0) {
    process.stdout.write("No dataset drift detected.\n");
    return;
  }

  process.stderr.write("Dataset drift detected between ingestion/raw and compiled hashes:\n");
  for (const diff of diffs) {
    process.stderr.write(
      `- ${diff.section}\n  expected: ${diff.expected}\n  actual:   ${diff.actual}\n`
    );
  }
  process.stderr.write("Run `npm run ingest` to rebuild compiled artifacts.\n");
  process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
