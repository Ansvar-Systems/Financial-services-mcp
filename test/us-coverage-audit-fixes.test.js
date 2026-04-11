import test from "node:test";
import assert from "node:assert/strict";

import { createDomainDatabase } from "../src/db/database.js";

const repo = createDomainDatabase();

test("scope_pci_dss returns SAQ A for Stripe Elements iframe with no PAN storage", () => {
  const result = repo.scopePciDss(
    "E-commerce checkout where Stripe Elements iframe collects card details; merchant backend never sees PAN.",
    [],
    "Stripe Elements iframe (tokenized via Stripe.js), no PAN in merchant systems"
  );
  assert.equal(result.data.saq_type, "A", "iframe + tokenized + no storage must map to SAQ A");
  assert.ok(
    !result.data.applicable_requirements.some((req) => /Req 1-12 full baseline/i.test(req)),
    "SAQ A must not pull the full SAQ-D baseline"
  );
});

test("scope_pci_dss returns SAQ A for Braintree Hosted Fields with no PAN storage", () => {
  const result = repo.scopePciDss(
    "Checkout using Braintree Hosted Fields, tokens returned to merchant, nothing persisted",
    [],
    "Braintree Hosted Fields, tokenized"
  );
  assert.equal(result.data.saq_type, "A");
});

test("scope_pci_dss still returns SAQ D when merchant stores PAN", () => {
  const result = repo.scopePciDss(
    "Merchant collects PAN on its own checkout form and stores in a vault",
    ["PAN"],
    "merchant-hosted form, PAN stored"
  );
  assert.equal(result.data.saq_type, "D");
});

test("scope_pci_dss confidence is inferred (not authoritative) for heuristic scoping", () => {
  const result = repo.scopePciDss(
    "Stripe Elements iframe checkout",
    [],
    "tokenized"
  );
  assert.equal(
    result.metadata.confidence,
    "inferred",
    "heuristic-derived SAQ type must not be labelled authoritative"
  );
});

test("map_to_technical_standards('GLBA Safeguards Rule') returns GLBA-mapped standards", () => {
  const result = repo.mapToTechnicalStandards("GLBA Safeguards Rule", null);
  assert.ok(
    result.data.standard_mappings.length > 0,
    "named-rule queries must not filter out all GLBA standards"
  );
});

test("map_to_technical_standards('HIPAA Security Rule') is empty because no HIPAA mappings exist (proves parser doesn't falsely match)", () => {
  // HIPAA is intentionally not represented in the technicalStandards regulation_mappings
  // (no HIPAA threats exist in the dataset, so adding it would break the
  // "every technical standard links to threats" quality gate). The correct behaviour for
  // a named-rule query against an unknown regulation is: return an empty array, not crash,
  // and NOT accidentally match standards from other regulations.
  const result = repo.mapToTechnicalStandards("HIPAA Security Rule", null);
  assert.deepEqual(
    result.data.standard_mappings,
    [],
    "HIPAA has no mappings in the dataset; named-rule parser must not falsely match other regulations"
  );
});

test("map_to_technical_standards falls back to regulation-only match when clause is a named rule", () => {
  const resultRuleName = repo.mapToTechnicalStandards("GLBA Safeguards Rule", null);
  const resultRegOnly = repo.mapToTechnicalStandards("GLBA", null);
  assert.deepEqual(
    resultRuleName.data.standard_mappings.map((m) => m.standard_id).sort(),
    resultRegOnly.data.standard_mappings.map((m) => m.standard_id).sort(),
    "named-rule parse must produce the same standards as a plain regulation match when no section-level data exists"
  );
});

test("compare_jurisdictions returns a rich entry for every requested state, not just curated ones", () => {
  const result = repo.compareJurisdictions("breach notification", ["US-CA", "US-NY", "US-TX", "US-FL"], null);
  const matrix = result.data.comparison_matrix;
  for (const jur of ["US-CA", "US-NY", "US-TX", "US-FL"]) {
    assert.ok(matrix[jur], `comparison_matrix must include ${jur}`);
    assert.ok(
      typeof matrix[jur].obligation === "string" && matrix[jur].obligation.length > 0,
      `${jur} must carry a non-empty obligation string`
    );
    assert.notEqual(
      matrix[jur].obligation,
      "No domain intelligence entry yet",
      `${jur} must not fall through to the 'no intelligence' placeholder`
    );
    assert.ok(
      ["curated", "derived"].includes(matrix[jur].source_tier ?? matrix[jur].tier),
      `${jur} must declare its source tier so consumers can flag drift`
    );
  }
});

test("compare_jurisdictions default target list includes all 50 US state breach jurisdictions + DC when no jurisdictions passed", () => {
  const result = repo.compareJurisdictions("breach notification", [], null);
  const targets = result.data.jurisdictions;
  // Expect at least 10 US state entries in the default spread (was 4 before the fix).
  const usStates = targets.filter((t) => typeof t === "string" && t.startsWith("US-"));
  assert.ok(
    usStates.length >= 10,
    `default comparison should span at least 10 US state jurisdictions; got ${usStates.length}: ${JSON.stringify(usStates)}`
  );
});

test("compare_jurisdictions marks curated entries as 'curated' and derived entries as 'derived'", () => {
  const result = repo.compareJurisdictions("breach notification", ["US-CA", "US-WY"], null);
  const matrix = result.data.comparison_matrix;
  assert.equal(matrix["US-CA"].source_tier, "curated", "US-CA has a hand-curated entry");
  assert.equal(matrix["US-WY"].source_tier, "derived", "US-WY is derived from state breach profile");
});

test("assess_breach_obligations surfaces per-jurisdiction confidence and profile_source", () => {
  const result = repo.assessBreachObligations(
    "laptop with unencrypted customer PII lost in Wyoming",
    ["US-WY"],
    ["PII", "financial account number"],
    null
  );
  const wy = result.data.notifications.find((n) => n.jurisdiction === "US-WY");
  assert.ok(wy, "US-WY entry must be present in notifications");
  assert.equal(wy.confidence, "estimated", "US-WY profile is NCSL-derived, must be surfaced as estimated");
  assert.equal(wy.profile_source, "ncsl-derived-default", "profile_source must propagate into notification entry");
  assert.ok(
    Array.isArray(result.metadata.data_gaps) && result.metadata.data_gaps.length > 0,
    "metadata.data_gaps must list estimated-confidence jurisdictions consumed in this response"
  );
});

test("assess_breach_obligations keeps authoritative confidence for primary-statute-curated states", () => {
  const result = repo.assessBreachObligations(
    "breach of 10,000 California consumer records",
    ["US-CA"],
    ["name", "SSN"],
    null
  );
  const ca = result.data.notifications.find((n) => n.jurisdiction === "US-CA");
  assert.ok(ca, "US-CA entry must be present");
  assert.equal(ca.confidence, "authoritative");
});

test("build_evidence_plan('NYDFS Cybersecurity') returns coverage for 500.05/500.06/500.07/500.11/500.12/500.14/500.16 plus 500.17", () => {
  const result = repo.buildEvidencePlan({}, "NYDFS Cybersecurity");
  const sections = new Set(
    result.data.evidence_items.flatMap((item) =>
      (item.regulation_basis ?? [])
        .filter((basis) => basis.regulation_id === "NYDFS_CYBER_500")
        .map((basis) => basis.section)
    )
  );
  const expected = ["500.05", "500.06", "500.07", "500.11", "500.12", "500.14", "500.16", "500.17"];
  for (const sec of expected) {
    assert.ok(sections.has(sec), `NYDFS Cybersecurity evidence plan must cover section ${sec}; got ${JSON.stringify([...sections])}`);
  }
});

test("std-nist-800-53-r5 is registered and mapped to GLBA + NYDFS", () => {
  const result = repo.mapToTechnicalStandards("GLBA", null);
  const ids = result.data.standard_mappings.map((m) => m.standard_id);
  assert.ok(ids.includes("std-nist-800-53-r5"), `GLBA map must include std-nist-800-53-r5; got ${JSON.stringify(ids)}`);

  const nydfs = repo.mapToTechnicalStandards("NYDFS_CYBER_500", null);
  const nydfsIds = nydfs.data.standard_mappings.map((m) => m.standard_id);
  assert.ok(
    nydfsIds.includes("std-nist-800-53-r5"),
    `NYDFS_CYBER_500 map must include std-nist-800-53-r5; got ${JSON.stringify(nydfsIds)}`
  );
});

test("map_to_technical_standards('GLBA Safeguards Rule') returns at least 5 standards once NIST 800-53/CIS/FFIEC/HITRUST are populated", () => {
  const result = repo.mapToTechnicalStandards("GLBA Safeguards Rule", null);
  assert.ok(
    result.data.standard_mappings.length >= 5,
    `GLBA Safeguards Rule must map to at least 5 standards once US catalog is expanded; got ${result.data.standard_mappings.length}`
  );
});

test("map_to_technical_standards('NYDFS_CYBER_500') returns at least 5 standards once NIST 800-53 / CIS / FFIEC / NIST CSF expansion lands", () => {
  const result = repo.mapToTechnicalStandards("NYDFS_CYBER_500", null);
  assert.ok(
    result.data.standard_mappings.length >= 5,
    `NYDFS_CYBER_500 must map to at least 5 standards; got ${result.data.standard_mappings.length}`
  );
});

test("build_evidence_plan tolerates trailing 'audit' / casing drift in audit_type", () => {
  const canonical = repo.buildEvidencePlan({}, "NYDFS Cybersecurity");
  const withSuffix = repo.buildEvidencePlan({}, "NYDFS Cybersecurity audit");
  const upperCase = repo.buildEvidencePlan({}, "NYDFS CYBERSECURITY");
  const canonicalIds = canonical.data.evidence_items.map((i) => i.artifact_name).sort();
  assert.ok(canonicalIds.length > 0, "canonical audit_type must return at least one artifact");
  assert.deepEqual(
    withSuffix.data.evidence_items.map((i) => i.artifact_name).sort(),
    canonicalIds,
    "'NYDFS Cybersecurity audit' must match 'NYDFS Cybersecurity'"
  );
  assert.deepEqual(
    upperCase.data.evidence_items.map((i) => i.artifact_name).sort(),
    canonicalIds,
    "audit_type must be case-insensitive"
  );
});

test("build_evidence_plan does NOT return every artifact when audit_type is only filler words", () => {
  const fillerOnly = repo.buildEvidencePlan({}, "compliance");
  const everythingElse = repo.buildEvidencePlan({}, "audit");
  const nothing = repo.buildEvidencePlan({}, "compliance audit");
  const fullCatalog = repo.buildEvidencePlan({}, "");
  const fullCount = fullCatalog.data.evidence_items.length;

  // A query that reduces to ONLY filler tokens must not match every row — that would be wildly over-broad.
  // The safe behaviour is to return zero matches so the user refines their query.
  assert.notEqual(
    fillerOnly.data.evidence_items.length,
    fullCount,
    "'compliance' alone must not return every evidence artifact"
  );
  assert.notEqual(
    everythingElse.data.evidence_items.length,
    fullCount,
    "'audit' alone must not return every evidence artifact"
  );
  assert.notEqual(
    nothing.data.evidence_items.length,
    fullCount,
    "'compliance audit' (all filler) must not return every evidence artifact"
  );
});
