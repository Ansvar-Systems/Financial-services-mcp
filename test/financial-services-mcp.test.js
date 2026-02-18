import test from "node:test";
import assert from "node:assert/strict";

import { createDomainDatabase } from "../src/db/database.js";

const repo = createDomainDatabase();

test("classify PAN/CVV in Germany maps to PCI DSS + GDPR + BDSG context", () => {
  const result = repo.classifyData("PAN + CVV stored for recurring payments in Germany", ["DE"]);
  assert.ok(result.data.categories.some((item) => item.id === "dc-card-data"));
  assert.ok(result.data.applicable_regimes.includes("PCI_DSS"));
  assert.ok(result.data.applicable_regimes.includes("GDPR"));
  assert.equal(result.data.protection_tier, "critical");
});

test("classify SWIFT MT103 maps to SWIFT messaging category", () => {
  const result = repo.classifyData("SWIFT MT103 messages for correspondent banking", ["EU"]);
  assert.ok(result.data.categories.some((item) => item.id === "dc-swift"));
  assert.ok(result.data.applicable_regimes.includes("SWIFT_CSP"));
});

test("classify credit scoring in California maps to FCRA/ECOA/CCPA", () => {
  const result = repo.classifyData("customer credit scores used for automated lending decisions in California", ["US-CA"]);
  const categoryIds = result.data.categories.map((item) => item.id);
  assert.ok(categoryIds.includes("dc-credit"));
  assert.ok(result.data.applicable_regimes.includes("FCRA"));
  assert.ok(result.data.applicable_regimes.includes("ECOA"));
  assert.ok(result.data.applicable_regimes.includes("CCPA"));
});

test("classify crypto wallet data in EU maps to MiCA + AMLD", () => {
  const result = repo.classifyData("cryptocurrency wallet addresses and transaction history for EU exchange", ["EU"]);
  assert.ok(result.data.categories.some((item) => item.id === "dc-digital-asset"));
  assert.ok(result.data.applicable_regimes.includes("MiCA"));
  assert.ok(result.data.applicable_regimes.includes("AMLD5"));
});

test("SWIFT threat scenarios include Bangladesh Bank pattern reference", () => {
  const result = repo.getDomainThreats("fs-swift", ["dc-swift"], {});
  assert.ok(result.data.threats.some((item) => item.threat_id === "th-swift-credential-theft"));
  const swiftThreat = result.data.threats.find((item) => item.threat_id === "th-swift-credential-theft");
  assert.ok(swiftThreat.description.toLowerCase().includes("swift"));
});

test("DORA/PSD2 obligations for Swedish bank lending + payments", () => {
  const result = repo.assessApplicability("SE", "bank", ["payments", "lending"], ["dc-account-data", "dc-npi"], {});
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("DORA"));
});

test("US-NY fintech obligations include GLBA and NYDFS", () => {
  const result = repo.assessApplicability("US-NY", "fintech", ["payments", "lending"], ["dc-credit", "dc-card-data"], {});
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("GLBA"));
  assert.ok(regs.includes("NYDFS_CYBER_500"));
});

test("German insurance obligations include Solvency II", () => {
  const result = repo.assessApplicability("DE", "insurance", ["insurance"], ["dc-insurance"], {});
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("Solvency_II"));
});

test("US wealth management obligations include GLBA coverage", () => {
  const result = repo.assessApplicability("US-NY", "investment-firm", ["fs-wealth"], ["dc-account-data", "dc-trading"], {});
  const regs = result.data.obligations.map((item) => item.regulation_id);
  assert.ok(regs.includes("GLBA"));
});

test("map standards by PCI requirement returns PCI DSS standard", () => {
  const result = repo.mapToTechnicalStandards("PCI_DSS_4_0 Req 3", "");
  assert.ok(result.data.standard_mappings.some((item) => item.standard_id === "std-pci-dss-4-0"));
  assert.ok(
    result.metadata.citations.some((item) =>
      String(item.source_url).includes("pcisecuritystandards.org")
    )
  );
});

test("map standards by eIDAS reference returns ETSI trust-services standard", () => {
  const result = repo.mapToTechnicalStandards("eIDAS Art 24", "");
  assert.ok(
    result.data.standard_mappings.some((item) => item.standard_id === "std-etsi-eidas-trust-services")
  );
});

test("compare breach notification across SE and US-CA returns both jurisdictions", () => {
  const result = repo.compareJurisdictions("breach notification", ["SE", "US-CA"]);
  assert.ok(result.data.comparison_matrix.SE);
  assert.ok(result.data.comparison_matrix["US-CA"]);
});

test("compare breach notification uses jurisdiction-specific statute source URLs when available", () => {
  const result = repo.compareJurisdictions("breach notification", ["US-TX"]);
  const citation = result.metadata.citations.find((item) => String(item.ref).startsWith("US-TX:"));
  assert.ok(citation);
  assert.ok(String(citation.source_url).includes("statutes.capitol.texas.gov"));
});

test("compare breach notification uses NYDFS source URL for US-NY", () => {
  const result = repo.compareJurisdictions("breach notification", ["US-NY"]);
  const citation = result.metadata.citations.find((item) => String(item.ref).startsWith("US-NY:"));
  assert.ok(citation);
  assert.ok(String(citation.source_url).includes("dfs.ny.gov"));
});

test("assess applicability citations use source registry URL for NYDFS_CYBER_500", () => {
  const result = repo.assessApplicability("US-NY", "fintech", ["payments"], ["dc-account-data"], {}, "2026-02-18");
  const citation = result.metadata.citations.find((item) => String(item.ref).startsWith("NYDFS_CYBER_500"));
  assert.ok(citation);
  assert.equal(citation.type, "LAW_MCP");
  assert.ok(String(citation.source_url).includes("dfs.ny.gov"));
});

test("negative domain request redirects out of scope", () => {
  const result = repo.classifyData("medical device classification", ["EU"]);
  assert.ok(result.data.redirect);
  assert.equal(result.data.redirect.redirect_to, "healthcare-mcp");
});

test("edge case overlapping jurisdictions returns mixed obligations", () => {
  const result = repo.assessApplicability(
    "SE",
    "bank",
    ["payments", "fs-insurance-core", "fs-trading"],
    ["dc-account-data", "dc-insurance", "dc-open-banking"],
    { operating_jurisdictions: ["SE", "NL", "US-NY", "UK"] }
  );
  assert.ok(result.data.obligations.length >= 2);
});

test("control baseline includes expert risk scenarios for instant payments", () => {
  const result = repo.buildControlBaseline({
    system_types: ["fs-instant-pay"],
    data_types: ["dc-account-data", "dc-open-banking"]
  });
  assert.ok(Array.isArray(result.data.risk_scenarios));
  assert.ok(result.data.risk_scenarios.some((item) => item.threat_id === "th-instant-payment-app-fraud"));
  assert.ok(result.data.controls.some((item) => item.control_id === "SCF.FD-01"));
});

test("evidence plan marks direct relevance for AML/sanctions baseline", () => {
  const baseline = repo.buildControlBaseline({
    system_types: ["fs-aml", "fs-swift"],
    data_types: ["dc-kyc-aml", "dc-swift"]
  });
  const plan = repo.buildEvidencePlan(baseline.data, "");
  const ofacEvidence = plan.data.evidence_items.find(
    (item) => item.artifact_name === "Sanctions screening governance and tuning evidence"
  );
  assert.ok(ofacEvidence);
  assert.equal(ofacEvidence.baseline_relevance, "direct");
  assert.ok(ofacEvidence.matched_regulations.includes("OFAC") || ofacEvidence.matched_regulations.includes("BSA"));
});

test("evidence plan marks BIPA artifact as direct when baseline includes BIPA regulation basis", () => {
  const plan = repo.buildEvidencePlan(
    {
      controls: [{ control_id: "SCF.AC-01", regulation_basis: ["BIPA"] }]
    },
    ""
  );
  const bipaEvidence = plan.data.evidence_items.find(
    (item) => item.artifact_name === "BIPA biometric consent and retention control evidence"
  );
  assert.ok(bipaEvidence);
  assert.equal(bipaEvidence.baseline_relevance, "direct");
  assert.ok(bipaEvidence.matched_regulations.includes("BIPA"));
});
