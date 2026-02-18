import path from "node:path";

import { datasetForFingerprint } from "../../src/data/domainData.js";
import { ensureIngestionDirs, sectionMap, writeJson, rawDir } from "./lib/dataset-files.mjs";

async function main() {
  await ensureIngestionDirs();
  const dataset = datasetForFingerprint();
  for (const section of sectionMap) {
    if (!(section.key in dataset)) {
      throw new Error(`Missing section '${section.key}' in embedded dataset.`);
    }
    await writeJson(path.join(rawDir, section.file), dataset[section.key]);
  }
  process.stdout.write(`Bootstrapped raw ingestion files in ${rawDir}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
