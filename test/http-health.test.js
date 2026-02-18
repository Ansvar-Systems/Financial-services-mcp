import test from "node:test";
import assert from "node:assert/strict";

import { createDomainDatabase } from "../src/db/database.js";
import { FoundationResolver } from "../src/foundation/resolver.js";
import { createRequestHandler } from "../src/mcp/protocol.js";
import { buildHealthPayload } from "../src/transports/http.js";

test("health payload includes structured status and checks", async () => {
  const repo = createDomainDatabase();
  const handler = createRequestHandler(repo, { foundationResolver: new FoundationResolver() });
  const payload = await buildHealthPayload(handler);

  assert.ok(["ok", "degraded", "stale"].includes(payload.status));
  assert.equal(payload.service, "financial-services-mcp");
  assert.equal(typeof payload.timestamp, "string");
  assert.ok(payload.checks);
  assert.ok("dataset_last_updated" in payload.checks);
  assert.ok("source_health" in payload.checks);
  assert.ok(Array.isArray(payload.reasons));
});
