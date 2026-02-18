import { createHash } from "node:crypto";

export const SERVER_NAME = "financial-services-mcp";
export const SERVER_TITLE = "Ansvar Financial Services MCP";
export const SERVER_VERSION = "1.0.0";
export const DOMAIN = "financial-services";
export const DATASET_VERSION = "1.0.0";
export const EFFECTIVE_DATE = "2026-02-18";
export const LAST_VERIFIED = "2026-02-18";
export const DB_FILE = new URL("../data/financial-services.db", import.meta.url);

export function computeFingerprint(payload) {
  const hash = createHash("sha256");
  hash.update(JSON.stringify(payload));
  return `sha256:${hash.digest("hex")}`;
}
