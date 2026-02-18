import path from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, readFileSync } from "node:fs";

import { readJson } from "../ingest/lib/dataset-files.mjs";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));
const datasetPath = path.join(root, "data", "domain-dataset.json");
const coveragePath = path.join(root, "data", "coverage-report.json");
const euStatesPath = path.join(root, "ingestion", "reference", "eu_member_states.json");
const usStatesPath = path.join(root, "ingestion", "reference", "us_states.json");
const regulatoryCatalogPath = path.join(root, "ingestion", "reference", "regulatory_catalog.eu-us.json");

async function main() {
  const [dataset, coverage, euStates, usStates, regulatoryCatalog] = await Promise.all([
    readJson(datasetPath),
    readJson(coveragePath),
    readJson(euStatesPath),
    readJson(usStatesPath),
    readJson(regulatoryCatalogPath)
  ]);

  const failures = [];

  verifyMinimumCounts(dataset, failures);
  verifyCrossReferences(dataset, failures);
  verifyCoverage(dataset, coverage, euStates, usStates, failures);
  verifyRegulationReferenceQuality(dataset, failures);
  verifyModelReferenceIntegrity(dataset, euStates, usStates, failures);
  verifyRegulatoryCatalogCoverage(dataset, regulatoryCatalog, failures);
  verifyThreatCoverageDepth(dataset, regulatoryCatalog, failures);
  verifyRegulationCoverageDepth(dataset, regulatoryCatalog, failures);
  verifyStandardAdoptionCoverage(dataset, failures);
  verifyArchitectureThreatCoverage(dataset, failures);
  verifyArchitectureApplicabilityCoverage(dataset, failures);
  verifyThreatEvidenceLinkage(dataset, failures);
  verifyStandardsThreatEvidenceLinkage(dataset, failures);
  verifyEvidenceApplicabilityLinkage(dataset, failures);
  verifyEvidenceTemplateReferences(dataset, failures);
  verifyEvidenceTemplateQuality(dataset, failures);
  verifyUsStateBreachProfiles(dataset, usStates, failures);
  verifyObligationGraph(dataset, failures);

  const report = {
    checked_at: new Date().toISOString(),
    status: failures.length === 0 ? "pass" : "fail",
    failures
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (failures.length > 0) {
    process.exitCode = 1;
  }
}

function verifyMinimumCounts(dataset, failures) {
  const min = {
    dataCategories: 11,
    architecturePatterns: 12,
    threatScenarios: 11,
    technicalStandards: 12,
    applicabilityRules: 100,
    "obligationGraph.nodes": 150,
    "obligationGraph.edges": 100
  };

  for (const [key, expectedMin] of Object.entries(min)) {
    const actual = key.includes(".")
      ? Array.isArray(getValueByPath(dataset, key)) ? getValueByPath(dataset, key).length : 0
      : Array.isArray(dataset[key]) ? dataset[key].length : 0;
    if (actual < expectedMin) {
      failures.push(`Dataset '${key}' has ${actual}; expected at least ${expectedMin}.`);
    }
  }
}

function verifyCrossReferences(dataset, failures) {
  const patternIds = new Set((dataset.architecturePatterns ?? []).map((item) => item.id));
  const categoryIds = new Set((dataset.dataCategories ?? []).map((item) => item.id));
  const controlIds = new Set(Object.keys(dataset.controlCatalog ?? {}));

  for (const threat of dataset.threatScenarios ?? []) {
    for (const id of threat.affected_patterns ?? []) {
      if (!patternIds.has(id)) {
        failures.push(`Threat '${threat.id}' references missing architecture pattern '${id}'.`);
      }
    }
    for (const id of threat.affected_data_categories ?? []) {
      if (!categoryIds.has(id)) {
        failures.push(`Threat '${threat.id}' references missing data category '${id}'.`);
      }
    }
    for (const id of threat.control_refs ?? []) {
      if (!controlIds.has(id)) {
        failures.push(`Threat '${threat.id}' references missing control '${id}'.`);
      }
    }
  }
}

function verifyCoverage(dataset, coverage, euStates, usStates, failures) {
  if (coverage.eu.total !== euStates.length) {
    failures.push(`EU coverage total mismatch (${coverage.eu.total} vs ${euStates.length}).`);
  }
  if (coverage.us.total !== usStates.length) {
    failures.push(`US coverage total mismatch (${coverage.us.total} vs ${usStates.length}).`);
  }
  if ((coverage.eu.missing ?? []).length > 0) {
    failures.push(`EU coverage has missing jurisdictions: ${coverage.eu.missing.join(", ")}.`);
  }
  if ((coverage.us.missing ?? []).length > 0) {
    failures.push(`US coverage has missing jurisdictions: ${coverage.us.missing.join(", ")}.`);
  }
  if ((coverage.eu.baseline_missing ?? []).length > 0) {
    failures.push(`EU baseline obligations missing: ${coverage.eu.baseline_missing.join(", ")}.`);
  }
  if ((coverage.us.baseline_missing ?? []).length > 0) {
    failures.push(`US baseline obligations missing: ${coverage.us.baseline_missing.join(", ")}.`);
  }

  const obligations = dataset.applicabilityRules ?? [];
  for (const state of euStates) {
    if (!hasObligation(obligations, state, "GDPR")) {
      failures.push(`Missing GDPR baseline obligation for ${state}.`);
    }
    if (!hasObligation(obligations, state, "DORA")) {
      failures.push(`Missing DORA baseline obligation for ${state}.`);
    }
  }
  for (const state of usStates) {
    if (!hasObligation(obligations, state, "GLBA")) {
      failures.push(`Missing GLBA baseline obligation for ${state}.`);
    }
    if (!hasObligation(obligations, state, "STATE_BREACH_NOTIFICATION")) {
      failures.push(`Missing STATE_BREACH_NOTIFICATION baseline obligation for ${state}.`);
    }
  }
}

function verifyRegulationReferenceQuality(dataset, failures) {
  const knownPrefixes = new Set([
    "GDPR",
    "DORA",
    "PSD2",
    "PSD2_RTS_SCA",
    "EIDAS",
    "MICA",
    "NIS2",
    "MIFID_II",
    "SOLVENCY_II",
    "AMLD5",
    "AMLD6",
    "AMLD6_BSA",
    "GLBA",
    "SOX",
    "BSA",
    "OFAC",
    "FCRA",
    "ECOA",
    "BIPA",
    "CCPA",
    "BAFIN_VAIT",
    "MAR",
    "PSR",
    "NYDFS_CYBER_500",
    "STATE_BREACH_NOTIFICATION",
    "SWIFT_CSP",
    "PCI_DSS_4_0"
  ]);

  for (const threat of dataset.threatScenarios ?? []) {
    for (const ref of threat.regulation_refs ?? []) {
      const id = String(ref.regulation_id ?? "").toUpperCase();
      if (!id) {
        failures.push(`Threat '${threat.id}' has empty regulation_id.`);
        continue;
      }
      if (!knownPrefixes.has(id)) {
        failures.push(`Threat '${threat.id}' has unknown regulation_id '${id}'.`);
      }
    }
  }
}

function verifyModelReferenceIntegrity(dataset, euStates, usStates, failures) {
  const standardIds = new Set((dataset.technicalStandards ?? []).map((item) => item.id));
  const controlIds = new Set(Object.keys(dataset.controlCatalog ?? {}));
  const knownCountries = new Set(["EU", "US", ...euStates.map(String), ...usStates.map(String)].map((x) => x.toUpperCase()));
  const allowedFoundationMcps = new Set(["eu-regulations", "us-regulations", "security-controls"]);

  for (const rule of dataset.applicabilityRules ?? []) {
    const standardId = rule?.obligation?.standard_id;
    if (standardId && !standardIds.has(standardId)) {
      failures.push(`Applicability rule '${rule.id}' references missing standard '${standardId}'.`);
    }
    for (const country of rule?.condition?.country ?? []) {
      const normalized = String(country).toUpperCase();
      if (!knownCountries.has(normalized)) {
        failures.push(`Applicability rule '${rule.id}' uses unknown country code '${country}'.`);
      }
    }
  }

  for (const standard of dataset.technicalStandards ?? []) {
    for (const mapping of standard.control_mappings ?? []) {
      if (!controlIds.has(mapping.control_id)) {
        failures.push(
          `Technical standard '${standard.id}' references missing control '${mapping.control_id}'.`
        );
      }
    }
  }

  for (const threat of dataset.threatScenarios ?? []) {
    for (const ref of threat.regulation_refs ?? []) {
      const mcp = String(ref.foundation_mcp ?? "").trim();
      if (mcp && !allowedFoundationMcps.has(mcp)) {
        failures.push(`Threat '${threat.id}' uses unknown foundation_mcp '${mcp}'.`);
      }
    }
  }
}

function verifyRegulatoryCatalogCoverage(dataset, catalog, failures) {
  const catalogIds = new Set(
    [...(catalog.eu ?? []), ...(catalog.us ?? [])].map((item) => String(item.id ?? "").toUpperCase()).filter(Boolean)
  );
  const usedIds = collectDatasetRegulationIds(dataset);
  const missing = [...usedIds].filter((id) => !catalogIds.has(id)).sort();

  if (missing.length > 0) {
    failures.push(`Regulatory catalog missing entries for regulation IDs: ${missing.join(", ")}.`);
  }

  for (const entry of [...(catalog.eu ?? []), ...(catalog.us ?? [])]) {
    if (!entry?.id || !entry?.type || !entry?.url || !entry?.publisher) {
      failures.push(`Regulatory catalog entry '${entry?.id ?? "<missing id>"}' is missing required fields.`);
    }
    if (!String(entry.url ?? "").startsWith("https://")) {
      failures.push(`Regulatory catalog entry '${entry.id}' must use an https URL.`);
    }
  }
}

function verifyThreatCoverageDepth(dataset, catalog, failures) {
  const catalogIds = new Set(
    [...(catalog.eu ?? []), ...(catalog.us ?? [])].map((item) => String(item.id ?? "").toUpperCase()).filter(Boolean)
  );
  const threatMapped = new Set(
    (dataset.threatScenarios ?? [])
      .flatMap((item) => item.regulation_refs ?? [])
      .map((item) => String(item?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );
  const missingThreatCoverage = [...catalogIds].filter((id) => !threatMapped.has(id)).sort();
  if (missingThreatCoverage.length > 0) {
    failures.push(
      `Threat scenario regulation_refs missing for regulation IDs: ${missingThreatCoverage.join(", ")}.`
    );
  }
}

function verifyRegulationCoverageDepth(dataset, catalog, failures) {
  const catalogIds = new Set(
    [...(catalog.eu ?? []), ...(catalog.us ?? [])].map((item) => String(item.id ?? "").toUpperCase()).filter(Boolean)
  );

  const ruleMapped = new Set(
    (dataset.applicabilityRules ?? [])
      .filter((item) => String(item?.obligation?.standard_id ?? "").trim())
      .map((item) => String(item?.obligation?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );
  const standardMapped = new Set(
    (dataset.technicalStandards ?? [])
      .flatMap((item) => item.regulation_mappings ?? [])
      .map((item) => String(item?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );
  const evidenceMapped = new Set(
    (dataset.evidenceArtifacts ?? [])
      .flatMap((item) => item.regulation_basis ?? [])
      .map((item) => String(item?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );

  const missingRuleCoverage = [...catalogIds].filter((id) => !ruleMapped.has(id)).sort();
  const missingStandardCoverage = [...catalogIds].filter((id) => !standardMapped.has(id)).sort();
  const missingEvidenceCoverage = [...catalogIds].filter((id) => !evidenceMapped.has(id)).sort();

  if (missingRuleCoverage.length > 0) {
    failures.push(
      `Applicability rule standard mapping missing for regulation IDs: ${missingRuleCoverage.join(", ")}.`
    );
  }
  if (missingStandardCoverage.length > 0) {
    failures.push(
      `Technical standards regulation_mappings missing for regulation IDs: ${missingStandardCoverage.join(", ")}.`
    );
  }
  if (missingEvidenceCoverage.length > 0) {
    failures.push(
      `Evidence artifact regulation_basis missing for regulation IDs: ${missingEvidenceCoverage.join(", ")}.`
    );
  }
}

function verifyStandardAdoptionCoverage(dataset, failures) {
  const standardIds = new Set((dataset.technicalStandards ?? []).map((item) => item.id).filter(Boolean));
  const adopted = new Set(
    (dataset.applicabilityRules ?? [])
      .map((item) => String(item?.obligation?.standard_id ?? "").trim())
      .filter(Boolean)
  );
  const orphanStandards = [...standardIds].filter((id) => !adopted.has(id)).sort();
  if (orphanStandards.length > 0) {
    failures.push(`Technical standards not referenced by applicability rules: ${orphanStandards.join(", ")}.`);
  }
}

function verifyArchitectureThreatCoverage(dataset, failures) {
  const patternIds = new Set((dataset.architecturePatterns ?? []).map((item) => item.id).filter(Boolean));
  const coveredByThreats = new Set(
    (dataset.threatScenarios ?? []).flatMap((item) => item.affected_patterns ?? []).filter(Boolean)
  );
  const uncoveredPatterns = [...patternIds].filter((id) => !coveredByThreats.has(id)).sort();
  if (uncoveredPatterns.length > 0) {
    failures.push(`Architecture patterns missing threat coverage: ${uncoveredPatterns.join(", ")}.`);
  }
}

function verifyArchitectureApplicabilityCoverage(dataset, failures) {
  const patternIds = new Set((dataset.architecturePatterns ?? []).map((item) => item.id).filter(Boolean));
  const coveredByRules = new Set(
    (dataset.applicabilityRules ?? []).flatMap((item) => item?.condition?.system_types ?? []).filter(Boolean)
  );
  const uncoveredPatterns = [...patternIds].filter((id) => !coveredByRules.has(id)).sort();
  if (uncoveredPatterns.length > 0) {
    failures.push(`Architecture patterns missing applicability rule coverage: ${uncoveredPatterns.join(", ")}.`);
  }
}

function verifyThreatEvidenceLinkage(dataset, failures) {
  const evidenceByReg = new Set(
    (dataset.evidenceArtifacts ?? [])
      .flatMap((item) => item.regulation_basis ?? [])
      .map((ref) => String(ref?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );
  for (const threat of dataset.threatScenarios ?? []) {
    const refs = (threat.regulation_refs ?? [])
      .map((ref) => String(ref?.regulation_id ?? "").toUpperCase())
      .filter(Boolean);
    if (refs.length === 0) {
      failures.push(`Threat '${threat.id}' must include at least one regulation_ref.`);
      continue;
    }
    const hasEvidenceLink = refs.some((regId) => evidenceByReg.has(regId));
    if (!hasEvidenceLink) {
      failures.push(`Threat '${threat.id}' has no evidence artifact linkage via regulation_refs.`);
    }
  }
}

function verifyEvidenceTemplateReferences(dataset, failures) {
  for (const artifact of dataset.evidenceArtifacts ?? []) {
    const templateRef = String(artifact?.template_ref ?? "").trim();
    if (!templateRef) {
      failures.push(`Evidence artifact '${artifact?.id ?? "<missing id>"}' is missing template_ref.`);
      continue;
    }
    const resolved = path.join(root, templateRef);
    if (!existsSync(resolved)) {
      failures.push(`Evidence artifact '${artifact.id}' template_ref does not exist: ${templateRef}.`);
    }
  }
}

function verifyEvidenceTemplateQuality(dataset, failures) {
  const requiredMdHeadings = [
    "## Document Control",
    "## Control Objective",
    "## Regulatory Basis",
    "## Evidence Collection Checklist",
    "## Review and Approval"
  ];

  for (const artifact of dataset.evidenceArtifacts ?? []) {
    const templateRef = String(artifact?.template_ref ?? "").trim();
    if (!templateRef) {
      continue;
    }
    const resolved = path.join(root, templateRef);
    if (!existsSync(resolved)) {
      continue;
    }
    const content = readFileSync(resolved, "utf8");
    const lowered = content.toLowerCase();
    if (lowered.includes("placeholder")) {
      failures.push(`Evidence template '${templateRef}' contains placeholder text.`);
      continue;
    }

    if (templateRef.endsWith(".md")) {
      if (content.length < 1200) {
        failures.push(`Evidence template '${templateRef}' is too short for production use.`);
      }
      for (const heading of requiredMdHeadings) {
        if (!content.includes(heading)) {
          failures.push(`Evidence template '${templateRef}' missing required section '${heading}'.`);
        }
      }
    } else if (templateRef.endsWith(".csv")) {
      const firstLine = content.split(/\r?\n/, 1)[0] ?? "";
      const columns = firstLine.split(",").map((part) => part.trim()).filter(Boolean);
      if (columns.length < 8) {
        failures.push(`Evidence template '${templateRef}' must define at least 8 CSV columns.`);
      }
    } else if (templateRef.endsWith(".drawio")) {
      if (!content.includes("<mxfile") || !content.includes("<mxGraphModel")) {
        failures.push(`Evidence template '${templateRef}' is not a valid draw.io XML scaffold.`);
      }
    }
  }
}

function verifyStandardsThreatEvidenceLinkage(dataset, failures) {
  const threatRegs = new Set(
    (dataset.threatScenarios ?? [])
      .flatMap((item) => item.regulation_refs ?? [])
      .map((ref) => String(ref?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );
  const evidenceRegs = new Set(
    (dataset.evidenceArtifacts ?? [])
      .flatMap((item) => item.regulation_basis ?? [])
      .map((ref) => String(ref?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );

  for (const standard of dataset.technicalStandards ?? []) {
    const regs = (standard.regulation_mappings ?? [])
      .map((ref) => String(ref?.regulation_id ?? "").toUpperCase())
      .filter(Boolean);
    if (regs.length === 0) {
      failures.push(`Technical standard '${standard.id}' has no regulation_mappings.`);
      continue;
    }
    if (!regs.some((reg) => threatRegs.has(reg))) {
      failures.push(`Technical standard '${standard.id}' has no threat linkage via regulation_mappings.`);
    }
    if (!regs.some((reg) => evidenceRegs.has(reg))) {
      failures.push(`Technical standard '${standard.id}' has no evidence linkage via regulation_mappings.`);
    }
  }
}

function verifyEvidenceApplicabilityLinkage(dataset, failures) {
  const applicabilityRegs = new Set(
    (dataset.applicabilityRules ?? [])
      .map((item) => String(item?.obligation?.regulation_id ?? "").toUpperCase())
      .filter(Boolean)
  );
  for (const artifact of dataset.evidenceArtifacts ?? []) {
    const regs = (artifact.regulation_basis ?? [])
      .map((ref) => String(ref?.regulation_id ?? "").toUpperCase())
      .filter(Boolean);
    if (regs.length === 0) {
      failures.push(`Evidence artifact '${artifact.id}' has no regulation_basis entries.`);
      continue;
    }
    if (!regs.some((reg) => applicabilityRegs.has(reg))) {
      failures.push(`Evidence artifact '${artifact.id}' has no applicability-rule linkage via regulation_basis.`);
    }
  }
}

function verifyUsStateBreachProfiles(dataset, usStates, failures) {
  const profiles = dataset.usStateBreachProfiles ?? {};
  const allowedSourceTiers = new Set(["primary", "secondary"]);
  const allowedConfidence = new Set(["authoritative", "estimated"]);
  let primaryCount = 0;

  for (const state of usStates) {
    const profile = profiles[state];
    if (!profile) {
      failures.push(`Missing usStateBreachProfiles entry for ${state}.`);
      continue;
    }
    if (!profile.law_mcp?.document_id || !profile.law_mcp?.provision_ref) {
      failures.push(`State profile ${state} missing law_mcp document/provision.`);
    }
    if (!profile.statute_ref) {
      failures.push(`State profile ${state} missing statute_ref.`);
    }
    if (!profile.deadline) {
      failures.push(`State profile ${state} missing deadline.`);
    }
    if (!profile.source_url) {
      failures.push(`State profile ${state} missing source_url.`);
    }
    if (!profile.profile_source) {
      failures.push(`State profile ${state} missing profile_source.`);
    }

    const sourceTier = String(profile.source_tier ?? "").toLowerCase();
    if (!allowedSourceTiers.has(sourceTier)) {
      failures.push(`State profile ${state} has invalid source_tier '${profile.source_tier ?? ""}'.`);
    }
    const confidence = String(profile.confidence ?? "").toLowerCase();
    if (!allowedConfidence.has(confidence)) {
      failures.push(`State profile ${state} has invalid confidence '${profile.confidence ?? ""}'.`);
    }

    if (sourceTier === "primary") {
      primaryCount += 1;
      if (confidence !== "authoritative") {
        failures.push(`State profile ${state} source_tier primary must use authoritative confidence.`);
      }
      if (String(profile.source_url ?? "").includes("ncsl.org")) {
        failures.push(`State profile ${state} source_tier primary must reference a primary statute URL.`);
      }
    }
  }

  if (primaryCount < 10) {
    failures.push(`US state breach profile primary-source coverage is ${primaryCount}; expected at least 10 states.`);
  }
}

function verifyObligationGraph(dataset, failures) {
  const graph = dataset.obligationGraph ?? {};
  const nodes = graph.nodes ?? [];
  const edges = graph.edges ?? [];
  const nodeIds = new Set(nodes.map((item) => item.id));
  for (const edge of edges) {
    if (!nodeIds.has(edge.from_node_id) || !nodeIds.has(edge.to_node_id)) {
      failures.push(`Obligation graph edge '${edge.id}' references unknown node(s).`);
    }
  }
  for (const node of nodes) {
    if (!node.jurisdiction || !node.regulation_id || !node.obligation_type) {
      failures.push(`Obligation graph node '${node.id}' missing required fields.`);
    }
  }
}

function collectDatasetRegulationIds(dataset) {
  const ids = new Set();
  const add = (value) => {
    const text = String(value ?? "").toUpperCase();
    if (text) {
      ids.add(text);
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
  return ids;
}

function getValueByPath(obj, keyPath) {
  return keyPath.split(".").reduce((acc, key) => (acc && key in acc ? acc[key] : undefined), obj);
}

function hasObligation(obligations, country, regulationId) {
  const targetCountry = String(country).toUpperCase();
  const targetReg = String(regulationId).toUpperCase();
  return obligations.some((rule) => {
    const countries = Array.isArray(rule?.condition?.country) ? rule.condition.country.map((item) => String(item).toUpperCase()) : [];
    const reg = String(rule?.obligation?.regulation_id ?? "").toUpperCase();
    return countries.includes(targetCountry) && reg === targetReg;
  });
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
