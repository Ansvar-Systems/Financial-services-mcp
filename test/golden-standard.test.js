import test from "node:test";
import assert from "node:assert/strict";

import { createDomainDatabase } from "../src/db/database.js";
import { FoundationResolver } from "../src/foundation/resolver.js";
import { createRequestHandler } from "../src/mcp/protocol.js";

const repo = createDomainDatabase();

test("about exposes EU and US coverage baselines", () => {
  const result = repo.about();
  assert.equal(result.data.jurisdiction_coverage.eu.total, 27);
  assert.equal(result.data.jurisdiction_coverage.us.total, 51);
  assert.equal(result.data.jurisdiction_coverage.eu.missing.length, 0);
  assert.equal(result.data.jurisdiction_coverage.us.missing.length, 0);
});

test("assess applicability returns generated EU baseline for France", () => {
  const result = repo.assessApplicability("FR", "bank", ["payments"], ["dc-account-data"], {});
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("GDPR"));
  assert.ok(regs.includes("DORA"));
});

test("assess applicability returns generated US baseline for Texas", () => {
  const result = repo.assessApplicability("US-TX", "bank", ["payments"], ["dc-npi"], {});
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("GLBA"));
  assert.ok(regs.includes("STATE_BREACH_NOTIFICATION"));
});

test("breach obligations include generated state baseline for US-TX", () => {
  const result = repo.assessBreachObligations("customer data exposure event", ["US-TX"], ["dc-npi"]);
  assert.ok(result.data.notifications.length > 0);
  assert.ok(result.data.notifications.some((item) => item.jurisdiction === "US-TX"));
});

test("compare jurisdictions uses breach map fallback for generated states", () => {
  const result = repo.compareJurisdictions("breach notification", ["US-TX", "FR"]);
  assert.ok(result.data.comparison_matrix["US-TX"]);
  assert.ok(result.data.comparison_matrix.FR);
  assert.notEqual(result.data.comparison_matrix["US-TX"].timeline, "unknown");
});

test("source listing supports pagination", () => {
  const pageOne = repo.listSources("", 3, 0);
  const pageTwo = repo.listSources("", 3, 3);
  assert.equal(pageOne.data.pagination.limit, 3);
  assert.equal(pageOne.data.sources.length, 3);
  assert.equal(pageTwo.data.pagination.offset, 3);
});

test("architecture listing supports pagination", () => {
  const pageOne = repo.listArchitecturePatterns("", 2, 0);
  const pageTwo = repo.listArchitecturePatterns("", 2, 2);
  assert.equal(pageOne.data.patterns.length, 2);
  assert.equal(pageTwo.data.pagination.offset, 2);
});

test("search supports offset pagination", () => {
  const pageOne = repo.searchDomainKnowledge("payment", [], 2, 0);
  const pageTwo = repo.searchDomainKnowledge("payment", [], 2, 2);
  assert.equal(pageOne.data.pagination.limit, 2);
  assert.equal(pageTwo.data.pagination.offset, 2);
});

test("protocol rejects unexpected tool arguments with actionable error", async () => {
  const handler = createRequestHandler(repo, { foundationResolver: new FoundationResolver() });
  const response = await handler({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "about",
      arguments: {
        unsupported: true
      }
    }
  });
  assert.equal(response.error.code, -32602);
  assert.match(response.error.message, /Unknown argument/i);
});

test("protocol can attempt foundation resolution on demand", async () => {
  const handler = createRequestHandler(repo, { foundationResolver: new FoundationResolver() });
  const response = await handler({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: {
      name: "classify_data",
      arguments: {
        data_description: "PAN and CVV for payment processing",
        jurisdictions: ["DE"],
        resolve_foundation: true,
        resolve_foundation_max_calls: 3
      }
    }
  });
  const resolution = response.result.structuredContent.metadata.foundation_resolution;
  assert.equal(resolution.attempted > 0, true);
  assert.equal(resolution.resolved_count + resolution.unresolved_count, resolution.attempted);
});

test("protocol rejects calendar-invalid as_of_date", async () => {
  const handler = createRequestHandler(repo, { foundationResolver: new FoundationResolver() });
  const response = await handler({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "assess_applicability",
      arguments: {
        country: "DE",
        role: "bank",
        system_types: ["payments"],
        data_types: ["dc-account-data"],
        as_of_date: "2026-02-30"
      }
    }
  });
  assert.equal(response.error.code, -32602);
  assert.match(response.error.message, /not a valid date/i);
});

test("protocol handles notifications/cancelled as no-op", async () => {
  const handler = createRequestHandler(repo, { foundationResolver: new FoundationResolver() });
  const response = await handler({
    jsonrpc: "2.0",
    method: "notifications/cancelled",
    params: { requestId: "demo" }
  });
  assert.equal(response, null);
});

test("temporal applicability excludes DORA before effective date and includes after", () => {
  const before = repo.assessApplicability(
    "DE",
    "bank",
    ["payments"],
    ["dc-account-data"],
    {},
    "2024-12-31"
  );
  const after = repo.assessApplicability(
    "DE",
    "bank",
    ["payments"],
    ["dc-account-data"],
    {},
    "2025-01-17"
  );

  const regsBefore = before.data.obligations.map((item) => item.regulation_id);
  const regsAfter = after.data.obligations.map((item) => item.regulation_id);
  assert.ok(!regsBefore.includes("DORA"));
  assert.ok(regsAfter.includes("DORA"));
});

test("get_obligation_graph returns jurisdiction-scoped temporal nodes", () => {
  const graph = repo.getObligationGraph("US-TX", "2026-02-18", 50, 0);
  assert.equal(graph.data.jurisdiction, "US-TX");
  assert.ok(graph.data.nodes.length > 0);
  assert.ok(graph.data.nodes.some((item) => item.regulation_id === "STATE_BREACH_NOTIFICATION"));
});

test("assess breach obligations returns state-specific statute reference", () => {
  const result = repo.assessBreachObligations(
    "incident affecting consumer personal data",
    ["US-TX"],
    ["dc-npi"],
    "2026-02-18"
  );
  assert.ok(result.data.notifications.some((item) => item.statute_ref));
  assert.ok(
    result.metadata.citations.some((item) => String(item.ref).includes("Tex. Bus. & Com. Code"))
  );
});

test("expert EU open banking rule includes PSD2_RTS_SCA with EU foundation routing", () => {
  const result = repo.assessApplicability(
    "SE",
    "payment-institution",
    ["fs-open-banking"],
    ["dc-open-banking", "dc-account-data"],
    {},
    "2026-02-18"
  );
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("PSD2_RTS_SCA"));
  const scaCall = result.metadata.foundation_mcp_calls.find(
    (item) => item.params?.regulation === "PSD2_RTS_SCA"
  );
  assert.ok(scaCall);
  assert.equal(scaCall.mcp, "eu-regulations");
});

test("expert US AML context includes OFAC sanctions screening obligation", () => {
  const result = repo.assessApplicability(
    "US-NY",
    "bank",
    ["fs-aml", "fs-swift"],
    ["dc-kyc-aml", "dc-swift"],
    {},
    "2026-02-18"
  );
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("OFAC"));
  const ofacCall = result.metadata.foundation_mcp_calls.find(
    (item) => item.params?.regulation === "OFAC"
  );
  assert.ok(ofacCall);
  assert.equal(ofacCall.mcp, "us-regulations");
});

test("expert instant payment fraud scenario is retrievable by pattern and data type", () => {
  const result = repo.getDomainThreats(["fs-instant-pay"], ["dc-account-data"], {});
  assert.ok(result.data.threats.some((item) => item.threat_id === "th-instant-payment-app-fraud"));
});

test("composite AMLD6_BSA obligations expand to EU and US foundation calls", () => {
  const result = repo.assessApplicability(
    "US",
    "bank",
    ["fs-aml"],
    ["dc-kyc-aml"],
    {},
    "2026-02-18"
  );
  const euCall = result.metadata.foundation_mcp_calls.find(
    (item) => item.mcp === "eu-regulations" && item.params?.regulation === "AMLD6"
  );
  const usCall = result.metadata.foundation_mcp_calls.find(
    (item) => item.mcp === "us-regulations" && item.params?.regulation === "BSA"
  );
  assert.ok(euCall);
  assert.ok(usCall);
});
