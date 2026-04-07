import { sanitizeFtsInput, buildFtsMatchExpr } from "../utils/fts-sanitize.js";
import { buildCitation } from "../utils/citation.js";
import { mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

import {
  DATASET_VERSION,
  DB_FILE,
  DOMAIN,
  EFFECTIVE_DATE,
  LAST_VERIFIED,
  computeFingerprint
} from "../config.js";
import { schemaSql } from "./schema.js";
import { loadDomainDataset } from "../data/loadDataset.js";
import { isStrictIsoDate } from "../utils/date.js";

const SCHEMA_VERSION = "1.0.0";
const { dataset: activeDataset, source: datasetSource, meta: datasetMeta } = loadDomainDataset();
const {
  applicabilityRules,
  architecturePatterns,
  authoritativeSources,
  breachObligationsByJurisdiction,
  controlCatalog,
  dataCategories,
  evidenceArtifacts,
  jurisdictionComparisonTopics,
  knownLimitations,
  obligationGraph,
  technicalStandards,
  threatScenarios,
  usStateBreachProfiles
} = activeDataset;
const BASE_CITATIONS = [
  { type: "CELEX", ref: "DORA", source_url: "https://eur-lex.europa.eu/" },
  { type: "CFR", ref: "GLBA", source_url: "https://www.ecfr.gov/" },
  { type: "ISO", ref: "ISO 20022", source_url: "https://www.iso.org/standard/73677.html" }
];

function toJson(value) {
  return JSON.stringify(value ?? null);
}

function fromJson(value, fallback = null) {
  if (value == null || value === "") {
    return fallback;
  }
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeText(value) {
  return String(value ?? "").toLowerCase().trim();
}

function uniqueStrings(values) {
  return [...new Set((values ?? []).filter(Boolean))];
}

function maxProtectionTier(tiers) {
  const order = ["low", "medium", "high", "critical"];
  let best = "low";
  for (const tier of tiers) {
    if (order.indexOf(tier) > order.indexOf(best)) {
      best = tier;
    }
  }
  return best;
}

function matchesCondition(values, candidates) {
  if (!candidates || candidates.length === 0) {
    return true;
  }
  if (candidates.includes("any")) {
    return true;
  }
  const source = new Set((values ?? []).map((item) => normalizeText(item)));
  for (const candidate of candidates) {
    if (source.has(normalizeText(candidate))) {
      return true;
    }
  }
  return false;
}

function normalizeCountry(country) {
  const text = normalizeText(country);
  if (!text) {
    return "EU";
  }
  if (text.startsWith("us-")) {
    return `US-${text.slice(3).toUpperCase()}`;
  }
  if (text === "us") {
    return "US";
  }
  return text.toUpperCase();
}

function normalizeRole(role) {
  return normalizeText(role || "financial-entity").replace(/\s+/g, "-");
}

function parseArrayInput(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (!value) {
    return [];
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeAsOfDate(input) {
  if (!input) {
    return new Date().toISOString().slice(0, 10);
  }
  const text = String(input).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    throw new Error("as_of_date must use YYYY-MM-DD format.");
  }
  if (!isStrictIsoDate(text)) {
    throw new Error("as_of_date is not a valid date.");
  }
  return text;
}

function isWithinEffectiveWindow(asOfDate, effectiveFrom, effectiveTo) {
  if (effectiveFrom && asOfDate < effectiveFrom) {
    return false;
  }
  if (effectiveTo && asOfDate > effectiveTo) {
    return false;
  }
  return true;
}

function words(value) {
  return normalizeText(value)
    .split(/[^a-z0-9-]+/g)
    .filter(Boolean);
}

function buildMetadata(datasetFingerprint, extra = {}) {
  return {
    citations: extra.citations ?? BASE_CITATIONS,
    effective_date: EFFECTIVE_DATE,
    confidence: extra.confidence ?? "authoritative",
    inference_rationale:
      extra.inference_rationale ??
      "Result derived from Financial Services MCP domain dataset and rule logic.",
    last_verified: LAST_VERIFIED,
    dataset_version: DATASET_VERSION,
    dataset_fingerprint: datasetFingerprint,
    out_of_scope: extra.out_of_scope ?? [],
    foundation_mcp_calls: extra.foundation_mcp_calls ?? []
  };
}

function mapDataCategoryKeywords() {
  return {
    "dc-card-data": ["pan", "cvv", "card", "cardholder", "payment card", "track", "pin"],
    "dc-swift": ["swift", "mt103", "mt", "mx", "correspondent"],
    "dc-credit": ["credit", "score", "underwriting", "lending decision", "fico", "loan application"],
    "dc-digital-asset": ["wallet", "crypto", "digital asset", "blockchain", "token", "exchange"],
    "dc-insurance": ["claims", "policy", "underwriting", "actuarial", "insurance"],
    "dc-open-banking": ["open banking", "psd2", "consent", "ais", "pis", "fdx"],
    "dc-biometric": ["biometric", "voice print", "facial", "behavioral biometrics"],
    "dc-kyc-aml": ["kyc", "aml", "pep", "sanctions", "beneficial owner", "customer onboarding"],
    "dc-trading": ["order flow", "trading", "position", "market data", "execution"],
    "dc-account-data": ["account", "balance", "transaction", "statement"],
    "dc-npi": ["npi", "nonpublic personal", "personal financial", "customer information"]
  };
}

function maybeRedirectOutOfScope(text) {
  const lowered = normalizeText(text);
  if (!lowered) {
    return null;
  }
  const tokenSet = new Set(words(lowered));
  if (lowered.includes("medical device") || tokenSet.has("hospital")) {
    return {
      reason: "Healthcare scope is outside this MCP domain",
      redirect_to: "healthcare-mcp"
    };
  }
  if (tokenSet.has("automotive") || tokenSet.has("ecu")) {
    return {
      reason: "Automotive domain is outside this MCP domain",
      redirect_to: "automotive-cybersecurity-mcp"
    };
  }
  return null;
}

export function createDomainDatabase() {
  const dbPath = fileURLToPath(DB_FILE);
  mkdirSync(dbPath.replace(/\/[^/]+$/, ""), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA busy_timeout = 5000");
  db.exec(schemaSql);
  ensureSchemaCompatibility(db);

  const datasetFingerprint = datasetMeta?.fingerprint ?? computeFingerprint(activeDataset);
  const seeded = db.prepare("SELECT value FROM db_metadata WHERE key = 'dataset_fingerprint'").get();
  if (!seeded || seeded.value !== datasetFingerprint) {
    reseedDatabase(db, datasetFingerprint);
  }

  return new FinancialServicesRepository(db, datasetFingerprint);
}

function ensureSchemaCompatibility(db) {
  const columns = db.prepare("PRAGMA table_info(applicability_rules)").all();
  const names = new Set(columns.map((column) => column.name));
  const additions = [
    ["obligation_type", "TEXT"],
    ["priority", "INTEGER"],
    ["conflict_group", "TEXT"],
    ["effective_from", "TEXT"],
    ["effective_to", "TEXT"]
  ];
  for (const [name, type] of additions) {
    if (!names.has(name)) {
      db.exec(`ALTER TABLE applicability_rules ADD COLUMN ${name} ${type}`);
    }
  }
}

function reseedDatabase(db, datasetFingerprint) {
  db.exec("BEGIN");
  try {
    for (const table of [
      "architecture_patterns",
      "data_categories",
      "threat_scenarios",
      "technical_standards",
      "applicability_rules",
      "evidence_artifacts",
      "source_registry",
      "us_state_breach_profiles",
      "obligation_nodes",
      "obligation_edges",
      "db_metadata"
    ]) {
      db.exec(`DELETE FROM ${table}`);
    }
    db.exec("INSERT INTO architecture_patterns_fts(architecture_patterns_fts) VALUES('delete-all')");
    db.exec("INSERT INTO data_categories_fts(data_categories_fts) VALUES('delete-all')");
    db.exec("INSERT INTO threat_scenarios_fts(threat_scenarios_fts) VALUES('delete-all')");
    db.exec("INSERT INTO technical_standards_fts(technical_standards_fts) VALUES('delete-all')");

    const insertArchitecture = db.prepare(`
      INSERT INTO architecture_patterns (
        id, name, category, description, components, trust_boundaries, data_flows,
        integration_points, known_weaknesses, applicable_standards, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertArchitectureFts = db.prepare(
      "INSERT INTO architecture_patterns_fts (id, name, description, components) VALUES (?, ?, ?, ?)"
    );
    for (const pattern of architecturePatterns) {
      insertArchitecture.run(
        pattern.id,
        pattern.name,
        pattern.category,
        pattern.description,
        toJson(pattern.components),
        toJson(pattern.trust_boundaries),
        toJson(pattern.data_flows),
        toJson(pattern.integration_points),
        toJson(pattern.known_weaknesses),
        toJson(pattern.applicable_standards),
        pattern.last_updated
      );
      insertArchitectureFts.run(pattern.id, pattern.name, pattern.description, pattern.components.join(" "));
    }

    const insertCategory = db.prepare(`
      INSERT INTO data_categories (
        id, name, description, boundary_conditions, jurisdiction_protections,
        deidentification_requirements, cross_border_constraints, regulation_refs, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertCategoryFts = db.prepare(
      "INSERT INTO data_categories_fts (id, name, description, boundary_conditions) VALUES (?, ?, ?, ?)"
    );
    for (const category of dataCategories) {
      insertCategory.run(
        category.id,
        category.name,
        category.description,
        category.boundary_conditions ?? "",
        toJson(category.jurisdiction_protections),
        toJson(category.deidentification_requirements),
        toJson(category.cross_border_constraints),
        toJson(category.regulation_refs),
        category.last_updated
      );
      insertCategoryFts.run(category.id, category.name, category.description, category.boundary_conditions ?? "");
    }

    const insertThreat = db.prepare(`
      INSERT INTO threat_scenarios (
        id, name, category, description, attack_narrative, mitre_mapping, affected_patterns,
        affected_data_categories, likelihood_factors, impact_dimensions, regulation_refs,
        control_refs, detection_indicators, historical_incidents, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertThreatFts = db.prepare(
      "INSERT INTO threat_scenarios_fts (id, name, description, attack_narrative) VALUES (?, ?, ?, ?)"
    );
    for (const threat of threatScenarios) {
      insertThreat.run(
        threat.id,
        threat.name,
        threat.category,
        threat.description,
        threat.attack_narrative ?? "",
        toJson(threat.mitre_mapping),
        toJson(threat.affected_patterns),
        toJson(threat.affected_data_categories),
        toJson(threat.likelihood_factors),
        toJson(threat.impact_dimensions),
        toJson(threat.regulation_refs),
        toJson(threat.control_refs),
        toJson(threat.detection_indicators),
        toJson(threat.historical_incidents),
        threat.last_updated
      );
      insertThreatFts.run(threat.id, threat.name, threat.description, threat.attack_narrative ?? "");
    }

    const insertStandard = db.prepare(`
      INSERT INTO technical_standards (
        id, name, version, publisher, scope, key_clauses, control_mappings,
        regulation_mappings, implementation_guidance, licensing_restrictions, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const insertStandardFts = db.prepare(
      "INSERT INTO technical_standards_fts (id, name, scope, key_clauses) VALUES (?, ?, ?, ?)"
    );
    for (const standard of technicalStandards) {
      insertStandard.run(
        standard.id,
        standard.name,
        standard.version ?? "",
        standard.publisher,
        standard.scope,
        toJson(standard.key_clauses),
        toJson(standard.control_mappings),
        toJson(standard.regulation_mappings),
        standard.implementation_guidance ?? "",
        standard.licensing_restrictions ?? "",
        standard.last_updated
      );
      insertStandardFts.run(
        standard.id,
        standard.name,
        standard.scope,
        (standard.key_clauses ?? []).join(" ")
      );
    }

    const insertRule = db.prepare(`
      INSERT INTO applicability_rules (
        id, condition_json, obligation_json, obligation_type, priority,
        conflict_group, effective_from, effective_to, rationale, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const rule of applicabilityRules) {
      const obligation = rule.obligation ?? {};
      insertRule.run(
        rule.id,
        toJson(rule.condition),
        toJson(obligation),
        obligation.obligation_type ?? null,
        Number.isFinite(Number(obligation.priority)) ? Number(obligation.priority) : null,
        obligation.conflict_group ?? null,
        obligation.effective_from ?? null,
        obligation.effective_to ?? null,
        rule.rationale,
        rule.last_updated
      );
    }

    const insertEvidence = db.prepare(`
      INSERT INTO evidence_artifacts (
        id, audit_type, artifact_name, description, mandatory, retention_period,
        template_ref, regulation_basis, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const item of evidenceArtifacts) {
      insertEvidence.run(
        item.id,
        item.audit_type,
        item.artifact_name,
        item.description,
        item.mandatory ? 1 : 0,
        item.retention_period ?? "",
        item.template_ref ?? "",
        toJson(item.regulation_basis),
        item.last_updated
      );
    }

    const insertSource = db.prepare(`
      INSERT INTO source_registry (
        id, source_type, name, content, provenance, license, refresh_cadence, source_url
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const source of authoritativeSources) {
      insertSource.run(
        source.id,
        source.source_type,
        source.name,
        source.content,
        source.provenance,
        source.license,
        source.refresh_cadence,
        source.source_url
      );
    }

    const insertUsStateProfile = db.prepare(`
      INSERT INTO us_state_breach_profiles (
        jurisdiction, profile_json, last_updated
      ) VALUES (?, ?, ?)
    `);
    for (const [jurisdiction, profile] of Object.entries(usStateBreachProfiles ?? {})) {
      insertUsStateProfile.run(jurisdiction, toJson(profile), profile.last_updated ?? new Date().toISOString());
    }

    const insertObligationNode = db.prepare(`
      INSERT INTO obligation_nodes (
        id, jurisdiction, obligation_type, regulation_id, standard_id,
        trigger_json, exceptions_json, deadline_json, penalties_json, evidence_refs_json,
        priority, confidence, effective_from, effective_to, source_rule_id, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const node of obligationGraph?.nodes ?? []) {
      insertObligationNode.run(
        node.id,
        node.jurisdiction,
        node.obligation_type,
        node.regulation_id,
        node.standard_id ?? null,
        toJson(node.trigger_json ?? {}),
        toJson(node.exceptions_json ?? []),
        toJson(node.deadline_json ?? null),
        toJson(node.penalties_json ?? null),
        toJson(node.evidence_refs_json ?? []),
        Number.isFinite(Number(node.priority)) ? Number(node.priority) : null,
        node.confidence ?? null,
        node.effective_from ?? null,
        node.effective_to ?? null,
        node.source_rule_id ?? null,
        node.last_updated
      );
    }

    const insertObligationEdge = db.prepare(`
      INSERT INTO obligation_edges (
        id, from_node_id, to_node_id, relation_type, rationale, last_updated
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);
    for (const edge of obligationGraph?.edges ?? []) {
      insertObligationEdge.run(
        edge.id,
        edge.from_node_id,
        edge.to_node_id,
        edge.relation_type,
        edge.rationale ?? null,
        edge.last_updated
      );
    }

    const metadataRows = [
      ["schema_version", SCHEMA_VERSION],
      ["domain", DOMAIN],
      ["dataset_version", datasetMeta?.dataset_version ?? DATASET_VERSION],
      ["dataset_fingerprint", datasetFingerprint],
      ["dataset_source", datasetSource],
      ["coverage_report", JSON.stringify(datasetMeta?.coverage ?? null)],
      ["obligation_graph_version", obligationGraph?.version ?? "1.0.0"],
      ["last_updated", new Date().toISOString()],
      ["coverage_notes", knownLimitations.join("; ")]
    ];
    const insertMeta = db.prepare("INSERT INTO db_metadata (key, value) VALUES (?, ?)");
    for (const row of metadataRows) {
      insertMeta.run(...row);
    }

    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function rowToArchitecture(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    name: row.name,
    category: row.category,
    description: row.description,
    components: fromJson(row.components, []),
    trust_boundaries: fromJson(row.trust_boundaries, []),
    data_flows: fromJson(row.data_flows, []),
    integration_points: fromJson(row.integration_points, []),
    known_weaknesses: fromJson(row.known_weaknesses, []),
    applicable_standards: fromJson(row.applicable_standards, []),
    last_updated: row.last_updated
  };
}

function rowToCategory(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    boundary_conditions: row.boundary_conditions,
    jurisdiction_protections: fromJson(row.jurisdiction_protections, {}),
    deidentification_requirements: fromJson(row.deidentification_requirements, []),
    cross_border_constraints: fromJson(row.cross_border_constraints, []),
    regulation_refs: fromJson(row.regulation_refs, []),
    last_updated: row.last_updated
  };
}

function rowToThreat(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    name: row.name,
    category: row.category,
    description: row.description,
    attack_narrative: row.attack_narrative,
    mitre_mapping: fromJson(row.mitre_mapping, []),
    affected_patterns: fromJson(row.affected_patterns, []),
    affected_data_categories: fromJson(row.affected_data_categories, []),
    likelihood_factors: fromJson(row.likelihood_factors, []),
    impact_dimensions: fromJson(row.impact_dimensions, {}),
    regulation_refs: fromJson(row.regulation_refs, []),
    control_refs: fromJson(row.control_refs, []),
    detection_indicators: fromJson(row.detection_indicators, []),
    historical_incidents: fromJson(row.historical_incidents, []),
    last_updated: row.last_updated
  };
}

function rowToStandard(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    name: row.name,
    version: row.version || null,
    publisher: row.publisher,
    scope: row.scope,
    key_clauses: fromJson(row.key_clauses, []),
    control_mappings: fromJson(row.control_mappings, []),
    regulation_mappings: fromJson(row.regulation_mappings, []),
    implementation_guidance: row.implementation_guidance,
    licensing_restrictions: row.licensing_restrictions,
    last_updated: row.last_updated
  };
}

function rowToEvidence(row) {
  if (!row) {
    return null;
  }
  return {
    id: row.id,
    audit_type: row.audit_type,
    artifact_name: row.artifact_name,
    description: row.description,
    mandatory: Boolean(row.mandatory),
    retention_period: row.retention_period || null,
    template_ref: row.template_ref || null,
    regulation_basis: fromJson(row.regulation_basis, []),
    last_updated: row.last_updated
  };
}

function mapInputDataTypesToCategoryIds(dataTypes) {
  const lookups = new Map(dataCategories.map((item) => [normalizeText(item.id), item.id]));
  for (const item of dataCategories) {
    lookups.set(normalizeText(item.name), item.id);
  }
  const output = [];
  for (const item of dataTypes ?? []) {
    const key = normalizeText(item);
    if (lookups.has(key)) {
      output.push(lookups.get(key));
    }
  }
  return uniqueStrings(output);
}

function mapInputSystemTypesToPatternIds(systemTypes) {
  const lookups = new Map(architecturePatterns.map((item) => [normalizeText(item.id), item.id]));
  for (const item of architecturePatterns) {
    lookups.set(normalizeText(item.name), item.id);
  }
  const output = [];
  for (const item of systemTypes ?? []) {
    const key = normalizeText(item);
    if (lookups.has(key)) {
      output.push(lookups.get(key));
    }
  }
  return uniqueStrings(output);
}

function severityFromImpact(impactDimensions = {}) {
  const values = Object.values(impactDimensions).map((value) => normalizeText(value));
  if (values.includes("severe")) {
    return "critical";
  }
  if (values.includes("high")) {
    return "high";
  }
  if (values.includes("medium")) {
    return "medium";
  }
  return "low";
}

function relevanceFromScore(score) {
  if (Number.isNaN(score) || !Number.isFinite(score)) {
    return 0.5;
  }
  return Number((1 / (1 + Math.abs(score))).toFixed(4));
}

function parseRequirementRef(value) {
  const input = normalizeText(value);
  if (!input) {
    return { regulation: "", clauseOrArticle: "" };
  }
  const parts = input.split(/[:\s]+/g).filter(Boolean);
  if (parts.length === 1) {
    return { regulation: parts[0].toUpperCase(), clauseOrArticle: "" };
  }
  return { regulation: parts[0].toUpperCase(), clauseOrArticle: parts.slice(1).join(" ") };
}

function assignEffortByPriority(priorityScore) {
  if (priorityScore >= 90) {
    return "high";
  }
  if (priorityScore >= 75) {
    return "medium";
  }
  return "low";
}

const EU_REGULATION_IDS = new Set([
  "DORA",
  "PSD2",
  "PSD2_RTS_SCA",
  "GDPR",
  "MICA",
  "NIS2",
  "SOLVENCY_II",
  "MIFID_II",
  "AMLD5",
  "AMLD6",
  "EIDAS",
  "BAFIN_VAIT",
  "MAR",
  "PSR"
]);

function sourceUrlByFoundationMcp(foundationMcp) {
  const value = normalizeText(foundationMcp);
  if (value === "eu-regulations") {
    return "https://eur-lex.europa.eu/";
  }
  if (value === "security-controls") {
    return "https://www.pcisecuritystandards.org/";
  }
  return "https://www.ecfr.gov/";
}

function isEuRegulationId(regulationId) {
  return EU_REGULATION_IDS.has(regulationId);
}

function expandCompositeRegulationIds(regulationIdInput) {
  const regulationId = String(regulationIdInput ?? "").toUpperCase();
  if (!regulationId) {
    return [];
  }
  if (regulationId === "AMLD6_BSA") {
    return ["AMLD6", "BSA"];
  }
  return [regulationId];
}

function regulationReferenceToCitationType(obligation, regulationId) {
  const reg = String(regulationId ?? "").toUpperCase();
  if (obligation.article || isEuRegulationId(regulationId)) {
    return "CELEX";
  }
  if (["NYDFS_CYBER_500", "STATE_BREACH_NOTIFICATION", "BIPA", "CCPA"].includes(reg)) {
    return "LAW_MCP";
  }
  if (["PCI_DSS_4_0", "SWIFT_CSP"].includes(reg)) {
    return "STD";
  }
  return "CFR";
}

function standardSourceUrl(standard) {
  const id = normalizeText(standard?.id ?? standard?.standard_id);
  const publisher = normalizeText(standard?.publisher ?? standard?.standard_publisher);
  if (id.includes("pci") || publisher.includes("pci")) {
    return "https://www.pcisecuritystandards.org/";
  }
  if (id.includes("swift") || publisher.includes("swift")) {
    return "https://www.swift.com/";
  }
  if (publisher.includes("nist")) {
    return "https://www.nist.gov/";
  }
  if (publisher.includes("nacha")) {
    return "https://www.nacha.org/";
  }
  if (publisher.includes("european payments council")) {
    return "https://www.europeanpaymentscouncil.eu/";
  }
  if (id.includes("fapi") || publisher.includes("openid")) {
    return "https://openid.net/specs/";
  }
  if (id.includes("cpmi") || publisher.includes("iosco") || publisher.includes("bis")) {
    return "https://www.bis.org/cpmi/publ/";
  }
  if (publisher.includes("fatf")) {
    return "https://www.fatf-gafi.org/";
  }
  if (publisher.includes("esma")) {
    return "https://www.esma.europa.eu/";
  }
  if (publisher.includes("etsi")) {
    return "https://www.etsi.org/";
  }
  if (publisher.includes("eiopa")) {
    return "https://www.eiopa.europa.eu/";
  }
  if (publisher.includes("cdia")) {
    return "https://www.cdiaonline.org/";
  }
  if (publisher.includes("gleif")) {
    return "https://www.gleif.org/";
  }
  if (publisher.includes("emv")) {
    return "https://www.emvco.com/";
  }
  if (publisher.includes("oasis")) {
    return "https://www.oasis-open.org/";
  }
  if (publisher.includes("xbrl")) {
    return "https://www.xbrl.org/";
  }
  if (publisher.includes("fix")) {
    return "https://www.fixtrading.org/";
  }
  if (publisher.includes("berlin group")) {
    return "https://www.berlin-group.org/";
  }
  if (publisher.includes("obie")) {
    return "https://www.openbanking.org.uk/";
  }
  return "https://www.iso.org/";
}

function looksLikeEuReference(text) {
  const value = normalizeText(text);
  return ["gdpr", "dora", "psd2", "mica", "nis2", "mifid", "solvency", "amld", "eidas", "eur-lex"].some((token) =>
    value.includes(token)
  );
}

function sourceUrlForComparisonSource(source, fallbackUrl) {
  if (fallbackUrl) {
    return fallbackUrl;
  }
  const value = normalizeText(source);
  if (value.includes("23 nycrr") || value.includes("nydfs")) {
    return "https://www.dfs.ny.gov/industry_guidance/cybersecurity";
  }
  if (value.includes("cal. civ. code") || value.includes("1798.82")) {
    return "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.82.&lawCode=CIV";
  }
  if (value.includes("fla. stat") || value.includes("501.171")) {
    return "https://www.flsenate.gov/Laws/Statutes/2024/501.171";
  }
  if (value.includes("tex. bus.") || value.includes("tex bus")) {
    return "https://statutes.capitol.texas.gov/Docs/BC/htm/BC.521.htm";
  }
  if (looksLikeEuReference(source)) {
    return "https://eur-lex.europa.eu/";
  }
  if (value.includes("not available")) {
    return "https://www.ecfr.gov/";
  }
  return "https://www.ecfr.gov/";
}

function inferFoundationCallsFromObligations(obligations) {
  const calls = [];
  for (const obligation of obligations) {
    if (obligation.regulation_id) {
      const regulationIds = expandCompositeRegulationIds(obligation.regulation_id);
      for (const regulationId of regulationIds) {
        if (isEuRegulationId(regulationId)) {
          calls.push({
            mcp: "eu-regulations",
            tool: "get_article",
            params: {
              regulation: regulationId,
              article: obligation.article ?? obligation.section ?? obligation.clause ?? ""
            }
          });
        } else {
          calls.push({
            mcp: "us-regulations",
            tool: "get_section",
            params: {
              regulation: regulationId,
              section: obligation.section ?? obligation.article ?? obligation.clause ?? ""
            }
          });
        }
      }
    }
    if (obligation.standard_id) {
      calls.push({
        mcp: "security-controls",
        tool: "map_frameworks",
        params: { framework: obligation.standard_id }
      });
    }
  }
  return uniqueFoundationCalls(calls);
}

function uniqueFoundationCalls(calls) {
  const seen = new Set();
  const output = [];
  for (const call of calls) {
    const key = JSON.stringify(call);
    if (!seen.has(key)) {
      seen.add(key);
      output.push(call);
    }
  }
  return output;
}

export class FinancialServicesRepository {
  constructor(db, datasetFingerprint) {
    this.db = db;
    this.datasetFingerprint = datasetFingerprint;
    this.keywordMap = mapDataCategoryKeywords();
    this.regulationSourceUrlById = this.buildRegulationSourceUrlIndex();
  }

  buildRegulationSourceUrlIndex() {
    const index = new Map();
    const rows = this.db.prepare("SELECT id, name, source_url FROM source_registry").all();
    for (const row of rows) {
      const sourceUrl = String(row.source_url ?? "").trim();
      if (!sourceUrl) {
        continue;
      }
      const nameKey = normalizeText(row.name);
      if (nameKey) {
        index.set(nameKey, sourceUrl);
      }
      const idKey = normalizeText(row.id);
      if (idKey) {
        index.set(idKey, sourceUrl);
      }
      const normalizedFromSourceId = idKey.startsWith("src-reg-")
        ? idKey.slice("src-reg-".length).replace(/-/g, "_")
        : "";
      if (normalizedFromSourceId) {
        index.set(normalizedFromSourceId, sourceUrl);
      }
    }
    return index;
  }

  sourceUrlForRegulation(regulationId) {
    const key = normalizeText(regulationId);
    if (key && this.regulationSourceUrlById.has(key)) {
      return this.regulationSourceUrlById.get(key);
    }
    return isEuRegulationId(regulationId) ? "https://eur-lex.europa.eu/" : "https://www.ecfr.gov/";
  }

  about() {
    const coverageSummary = {
      architecture_patterns: this.db.prepare("SELECT COUNT(*) as c FROM architecture_patterns").get().c,
      data_categories: this.db.prepare("SELECT COUNT(*) as c FROM data_categories").get().c,
      threat_scenarios: this.db.prepare("SELECT COUNT(*) as c FROM threat_scenarios").get().c,
      technical_standards: this.db.prepare("SELECT COUNT(*) as c FROM technical_standards").get().c,
      applicability_rules: this.db.prepare("SELECT COUNT(*) as c FROM applicability_rules").get().c,
      evidence_artifacts: this.db.prepare("SELECT COUNT(*) as c FROM evidence_artifacts").get().c,
      us_state_breach_profiles: this.db.prepare("SELECT COUNT(*) as c FROM us_state_breach_profiles").get().c,
      obligation_nodes: this.db.prepare("SELECT COUNT(*) as c FROM obligation_nodes").get().c,
      obligation_edges: this.db.prepare("SELECT COUNT(*) as c FROM obligation_edges").get().c
    };
    const coverageReportRaw = this.db.prepare("SELECT value FROM db_metadata WHERE key = 'coverage_report'").get()?.value;
    const jurisdictionCoverage = fromJson(coverageReportRaw, null) ?? this.deriveRuntimeCoverage();
    const sources = this.db
      .prepare("SELECT source_type, name, source_url, refresh_cadence FROM source_registry ORDER BY name")
      .all();
    return {
      data: {
        server_name: "Ansvar Financial Services MCP",
        version: "1.0.0",
        domain: DOMAIN,
        dataset_source: this.db.prepare("SELECT value FROM db_metadata WHERE key = 'dataset_source'").get()?.value ?? "unknown",
        coverage_summary: coverageSummary,
        jurisdiction_coverage: jurisdictionCoverage,
        last_updated: this.db.prepare("SELECT value FROM db_metadata WHERE key = 'last_updated'").get()?.value,
        sources,
        known_limitations: knownLimitations
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: sources.slice(0, 4).map((item) => ({
          type: "URL",
          ref: item.name,
          source_url: item.source_url
        })),
        confidence: "authoritative"
      })
    };
  }

  deriveRuntimeCoverage() {
    const rows = this.db.prepare("SELECT condition_json FROM applicability_rules").all();
    const countries = new Set();
    for (const row of rows) {
      const condition = fromJson(row.condition_json, {});
      for (const country of parseArrayInput(condition.country)) {
        countries.add(String(country).toUpperCase());
      }
    }
    const euCovered = [...countries].filter((country) => /^[A-Z]{2}$/.test(country) && country !== "EU").length;
    const usCovered = [...countries].filter((country) => /^US-[A-Z]{2}$/.test(country)).length;
    return {
      generated_at: new Date().toISOString(),
      eu: { total: euCovered, covered: euCovered, missing: [], breach_covered: euCovered },
      us: { total: usCovered, covered: usCovered, missing: [], breach_covered: usCovered },
      regulatory_catalog: { eu: 0, us: 0 }
    };
  }

  listSources(sourceType, limitInput, offsetInput) {
    const normalized = normalizeText(sourceType);
    const limit = Math.max(1, Math.min(Number(limitInput ?? 50), 100));
    const offset = Math.max(0, Number(offsetInput ?? 0));
    const countQuery = normalized
      ? "SELECT COUNT(*) as c FROM source_registry WHERE lower(source_type)=?"
      : "SELECT COUNT(*) as c FROM source_registry";
    const total = normalized ? this.db.prepare(countQuery).get(normalized).c : this.db.prepare(countQuery).get().c;
    const query = normalized
      ? "SELECT * FROM source_registry WHERE lower(source_type)=? ORDER BY name LIMIT ? OFFSET ?"
      : "SELECT * FROM source_registry ORDER BY name LIMIT ? OFFSET ?";
    const rows = normalized ? this.db.prepare(query).all(normalized, limit, offset) : this.db.prepare(query).all(limit, offset);
    const data = rows.map((row) => ({
      source_id: row.id,
      source_type: row.source_type,
      name: row.name,
      content: row.content,
      provenance: row.provenance,
      license: row.license,
      refresh_cadence: row.refresh_cadence,
      source_url: row.source_url
    }));
    return {
      data: {
        sources: data,
        pagination: {
          limit,
          offset,
          total,
          next_offset: offset + data.length < total ? offset + data.length : null
        }
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: data.map((item) => ({ type: "URL", ref: item.name, source_url: item.source_url })),
        confidence: "authoritative"
      })
    };
  }

  listArchitecturePatterns(category, limitInput, offsetInput) {
    const normalized = normalizeText(category);
    const limit = Math.max(1, Math.min(Number(limitInput ?? 50), 100));
    const offset = Math.max(0, Number(offsetInput ?? 0));
    const countQuery = normalized
      ? "SELECT COUNT(*) as c FROM architecture_patterns WHERE lower(category)=?"
      : "SELECT COUNT(*) as c FROM architecture_patterns";
    const total = normalized ? this.db.prepare(countQuery).get(normalized).c : this.db.prepare(countQuery).get().c;
    const query = normalized
      ? "SELECT id, name, category, description FROM architecture_patterns WHERE lower(category)=? ORDER BY id LIMIT ? OFFSET ?"
      : "SELECT id, name, category, description FROM architecture_patterns ORDER BY id LIMIT ? OFFSET ?";
    const rows = normalized ? this.db.prepare(query).all(normalized, limit, offset) : this.db.prepare(query).all(limit, offset);
    return {
      data: {
        patterns: rows.map((row) => ({
          pattern_id: row.id,
          name: row.name,
          category: row.category,
          description: row.description
        })),
        pagination: {
          limit,
          offset,
          total,
          next_offset: offset + rows.length < total ? offset + rows.length : null
        }
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [{ type: "URL", ref: "BIAN Reference Architecture", source_url: "https://bian.org/" }]
      })
    };
  }

  getArchitecturePattern(patternId) {
    const row = this.db.prepare("SELECT * FROM architecture_patterns WHERE id=?").get(patternId);
    const pattern = rowToArchitecture(row);
    if (!pattern) {
      return {
        data: {
          error: `Unknown pattern_id: ${patternId}`,
          available_pattern_ids: architecturePatterns.map((item) => item.id)
        },
        metadata: buildMetadata(this.datasetFingerprint, {
          confidence: "estimated",
          inference_rationale: "Requested pattern does not exist in current dataset.",
          out_of_scope: [`Unknown pattern_id: ${patternId}`]
        })
      };
    }
    return {
      data: {
        pattern_id: pattern.id,
        name: pattern.name,
        category: pattern.category,
        description: pattern.description,
        topology: pattern.components,
        components: pattern.components,
        trust_boundaries: pattern.trust_boundaries,
        data_flows: pattern.data_flows,
        integration_points: pattern.integration_points,
        known_weaknesses: pattern.known_weaknesses,
        applicable_standards: pattern.applicable_standards
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [
          { type: "URL", ref: "PCI DSS", source_url: "https://www.pcisecuritystandards.org/" },
          { type: "URL", ref: "EBA DORA", source_url: "https://www.eba.europa.eu/" }
        ],
        confidence: "authoritative"
      }),
      _citation: buildCitation(
        pattern.id,
        `${pattern.name} (${pattern.category})`,
        "get_architecture_pattern",
        { pattern_id: patternId }
      )
    };
  }

  classifyData(dataDescription, jurisdictionsInput) {
    const description = normalizeText(dataDescription);
    const jurisdictions = parseArrayInput(jurisdictionsInput).map(normalizeCountry);
    const outOfScope = maybeRedirectOutOfScope(description);
    if (outOfScope) {
      return {
        data: {
          categories: [],
          applicable_regimes: [],
          protection_tier: "unknown",
          handling_requirements: [],
          redirect: outOfScope
        },
        metadata: buildMetadata(this.datasetFingerprint, {
          confidence: "estimated",
          inference_rationale: "Input content is outside the financial services domain.",
          out_of_scope: [outOfScope.reason]
        })
      };
    }

    const matchedCategoryIds = [];
    for (const [categoryId, keywords] of Object.entries(this.keywordMap)) {
      if (keywords.some((keyword) => description.includes(keyword))) {
        matchedCategoryIds.push(categoryId);
      }
    }
    if (matchedCategoryIds.length === 0) {
      matchedCategoryIds.push("dc-npi");
    }

    const categories = matchedCategoryIds
      .map((id) => this.db.prepare("SELECT * FROM data_categories WHERE id=?").get(id))
      .filter(Boolean)
      .map(rowToCategory);

    const regimes = [];
    const tiers = [];
    const handlingRequirements = [];
    for (const category of categories) {
      const protectionByJurisdiction = category.jurisdiction_protections ?? {};
      const selectedJurisdictions = jurisdictions.length > 0 ? jurisdictions : Object.keys(protectionByJurisdiction);
      for (const jurisdiction of selectedJurisdictions) {
        const match =
          protectionByJurisdiction[jurisdiction] ??
          protectionByJurisdiction.US ??
          protectionByJurisdiction.EU ??
          null;
        if (match) {
          regimes.push(...(match.regime ?? []));
          if (match.tier) {
            tiers.push(match.tier);
          }
          handlingRequirements.push(...(match.controls ?? []));
        }
      }
      handlingRequirements.push(...(category.deidentification_requirements ?? []));
      handlingRequirements.push(...(category.cross_border_constraints ?? []));
    }

    const categoryOutput = categories.map((category) => ({
      id: category.id,
      name: category.name,
      description: category.description
    }));

    const foundationCalls = [];
    for (const category of categories) {
      for (const ref of category.regulation_refs ?? []) {
        foundationCalls.push({
          mcp: ref.foundation_mcp ?? "unknown",
          tool: "lookup",
          params: ref
        });
      }
    }

    return {
      data: {
        categories: categoryOutput,
        applicable_regimes: uniqueStrings(regimes),
        protection_tier: maxProtectionTier(tiers),
        handling_requirements: uniqueStrings(handlingRequirements)
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: categories.flatMap((category) =>
          (category.regulation_refs ?? []).map((ref) => ({
            type: ref.article ? "CELEX" : "CFR",
            ref: `${ref.regulation_id}${ref.article ? ` Art. ${ref.article}` : ""}${ref.section ? ` Sec. ${ref.section}` : ""}`,
            source_url: sourceUrlByFoundationMcp(ref.foundation_mcp)
          }))
        ),
        foundation_mcp_calls: uniqueFoundationCalls(foundationCalls)
      })
    };
  }

  getDomainThreats(architecturePatternInput, dataTypesInput, deploymentContext) {
    const architecturePattern = normalizeText(architecturePatternInput);
    const dataTypeIds = mapInputDataTypesToCategoryIds(parseArrayInput(dataTypesInput));
    const systemPatternIds = mapInputSystemTypesToPatternIds(parseArrayInput(architecturePatternInput || []));
    const requestedPatternIds = uniqueStrings([
      ...(systemPatternIds ?? []),
      ...(architecturePattern ? [architecturePatternInput] : [])
    ]).map((value) => normalizeText(value));

    const threatRows = this.db.prepare("SELECT * FROM threat_scenarios ORDER BY id").all();
    const threats = threatRows
      .map(rowToThreat)
      .filter((threat) => {
        const patternMatch =
          requestedPatternIds.length === 0 ||
          threat.affected_patterns.some((patternId) =>
            requestedPatternIds.includes(normalizeText(patternId)) ||
            requestedPatternIds.includes(normalizeText(architecturePattern))
          );
        const dataMatch =
          dataTypeIds.length === 0 || threat.affected_data_categories.some((categoryId) => dataTypeIds.includes(categoryId));
        return patternMatch && dataMatch;
      })
      .map((threat) => ({
        threat_id: threat.id,
        name: threat.name,
        description: threat.description,
        attack_narrative: threat.attack_narrative,
        mitre_mapping: threat.mitre_mapping,
        regulation_refs: threat.regulation_refs,
        severity: severityFromImpact(threat.impact_dimensions),
        likelihood_factors: threat.likelihood_factors,
        impact_dimensions: threat.impact_dimensions,
        control_refs: threat.control_refs,
        detection_indicators: threat.detection_indicators
      }));

    const citations = threats.flatMap((threat) =>
      (threat.regulation_refs ?? []).map((ref) => ({
        type: ref.article ? "CELEX" : "CFR",
        ref: `${ref.regulation_id}${ref.article ? ` Art. ${ref.article}` : ""}${ref.section ? ` Sec. ${ref.section}` : ""}`,
        source_url: sourceUrlByFoundationMcp(ref.foundation_mcp)
      }))
    );

    const foundationCalls = threats.flatMap((threat) =>
      (threat.regulation_refs ?? []).map((ref) => ({
        mcp: ref.foundation_mcp ?? "unknown",
        tool: "lookup",
        params: ref
      }))
    );

    return {
      data: {
        context: {
          architecture_pattern: architecturePatternInput ?? null,
          data_types: dataTypesInput ?? [],
          deployment_context: deploymentContext ?? {}
        },
        threats
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: uniqueCitationList(citations),
        foundation_mcp_calls: uniqueFoundationCalls(foundationCalls)
      }),
      _citation: buildCitation(
        architecturePatternInput ? `FS threats: ${architecturePatternInput}` : "Financial services threats",
        `Financial services threat scenarios${architecturePatternInput ? ` for ${architecturePatternInput}` : ""}`,
        "get_domain_threats",
        {
          ...(architecturePatternInput ? { architecture_pattern: architecturePatternInput } : {}),
          ...(dataTypesInput && dataTypesInput.length > 0 ? { data_types: String(dataTypesInput) } : {})
        }
      )
    };
  }

  assessApplicability(countryInput, roleInput, systemTypesInput, dataTypesInput, additionalContext = {}, asOfDateInput) {
    const country = normalizeCountry(countryInput);
    const role = normalizeRole(roleInput || "financial-entity");
    const asOfDate = normalizeAsOfDate(asOfDateInput);
    const systemTypes = parseArrayInput(systemTypesInput);
    const dataTypes = parseArrayInput(dataTypesInput);
    const normalizedSystemTypes = systemTypes.map(normalizeText);
    const normalizedDataTypes = mapInputDataTypesToCategoryIds(dataTypes);

    const rows = this.db.prepare("SELECT * FROM applicability_rules ORDER BY id").all();
    const obligations = [];
    for (const row of rows) {
      const condition = fromJson(row.condition_json, {});
      const conditionCountries = parseArrayInput(condition.country);
      const conditionRoles = parseArrayInput(condition.role);
      const conditionSystems = parseArrayInput(condition.system_types);
      const conditionData = parseArrayInput(condition.data_types);

      if (!matchesCondition([country], conditionCountries.map(normalizeCountry))) {
        continue;
      }
      if (!matchesCondition([role], conditionRoles.map(normalizeRole))) {
        continue;
      }
      if (!matchesCondition(normalizedSystemTypes, conditionSystems.map(normalizeText))) {
        continue;
      }
      if (!matchesCondition(normalizedDataTypes, conditionData.map((item) => normalizeText(item)))) {
        continue;
      }
      if (!isWithinEffectiveWindow(asOfDate, row.effective_from, row.effective_to)) {
        continue;
      }

      const obligation = fromJson(row.obligation_json, {});
      obligations.push({
        ...obligation,
        obligation_type: row.obligation_type ?? obligation.obligation_type ?? "compliance",
        priority: Number.isFinite(Number(row.priority)) ? Number(row.priority) : Number(obligation.priority ?? 50),
        effective_from: row.effective_from ?? obligation.effective_from ?? null,
        effective_to: row.effective_to ?? obligation.effective_to ?? null,
        conflict_group: row.conflict_group ?? obligation.conflict_group ?? null,
        basis: row.rationale,
        rule_id: row.id
      });
    }
    obligations.sort((a, b) => (Number(b.priority ?? 0) - Number(a.priority ?? 0)) || String(a.regulation_id).localeCompare(String(b.regulation_id)));

    const deduped = [];
    const seen = new Set();
    for (const obligation of obligations) {
      const key = `${obligation.regulation_id}::${obligation.article ?? ""}::${obligation.section ?? ""}::${obligation.clause ?? ""}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      deduped.push(obligation);
    }

    const graphNodes = this.db
      .prepare(
        "SELECT * FROM obligation_nodes WHERE jurisdiction = ? AND (? IS NULL OR effective_from IS NULL OR effective_from <= ?) AND (? IS NULL OR effective_to IS NULL OR effective_to >= ?) ORDER BY priority DESC, id"
      )
      .all(country, asOfDate, asOfDate, asOfDate, asOfDate)
      .map((row) => ({
        id: row.id,
        obligation_type: row.obligation_type,
        regulation_id: row.regulation_id,
        standard_id: row.standard_id,
        priority: row.priority,
        confidence: row.confidence,
        effective_from: row.effective_from,
        effective_to: row.effective_to,
        source_rule_id: row.source_rule_id,
        trigger: fromJson(row.trigger_json, {}),
        deadline: fromJson(row.deadline_json, null),
        penalties: fromJson(row.penalties_json, null),
        evidence_refs: fromJson(row.evidence_refs_json, [])
      }));
    const graphNodeIds = new Set(graphNodes.map((item) => item.id));
    const graphEdges = this.db
      .prepare("SELECT * FROM obligation_edges WHERE from_node_id IN (SELECT id FROM obligation_nodes WHERE jurisdiction = ?) ORDER BY id")
      .all(country)
      .filter((row) => graphNodeIds.has(row.from_node_id) && graphNodeIds.has(row.to_node_id))
      .map((row) => ({
        id: row.id,
        from_node_id: row.from_node_id,
        to_node_id: row.to_node_id,
        relation_type: row.relation_type,
        rationale: row.rationale
      }));

    const foundationCalls = inferFoundationCallsFromObligations(deduped);
    return {
      data: {
        profile: {
          country,
          role,
          as_of_date: asOfDate,
          system_types: systemTypes,
          data_types: dataTypes,
          additional_context: additionalContext
        },
        obligations: deduped,
        obligation_graph: {
          nodes: graphNodes,
          edges: graphEdges
        }
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: deduped.flatMap((obligation) =>
          expandCompositeRegulationIds(obligation.regulation_id).map((regulationId) => ({
            type: regulationReferenceToCitationType(obligation, regulationId),
            ref: `${regulationId}${obligation.article ? ` Art. ${obligation.article}` : ""}${
              obligation.section ? ` Sec. ${obligation.section}` : ""
            }${obligation.clause ? ` ${obligation.clause}` : ""}`,
            source_url: this.sourceUrlForRegulation(regulationId)
          }))
        ),
        foundation_mcp_calls: foundationCalls
      })
    };
  }

  getObligationGraph(countryInput, asOfDateInput, limitInput, offsetInput) {
    const asOfDate = normalizeAsOfDate(asOfDateInput);
    const country = countryInput ? normalizeCountry(countryInput) : null;
    const limit = Math.max(1, Math.min(Number(limitInput ?? 100), 500));
    const offset = Math.max(0, Number(offsetInput ?? 0));
    const countParams = [asOfDate, asOfDate, asOfDate, asOfDate];
    const countQuery = country
      ? "SELECT COUNT(*) as c FROM obligation_nodes WHERE jurisdiction = ? AND (? IS NULL OR effective_from IS NULL OR effective_from <= ?) AND (? IS NULL OR effective_to IS NULL OR effective_to >= ?)"
      : "SELECT COUNT(*) as c FROM obligation_nodes WHERE (? IS NULL OR effective_from IS NULL OR effective_from <= ?) AND (? IS NULL OR effective_to IS NULL OR effective_to >= ?)";
    const total = country
      ? this.db.prepare(countQuery).get(country, ...countParams).c
      : this.db.prepare(countQuery).get(...countParams).c;
    const params = [asOfDate, asOfDate, asOfDate, asOfDate, limit, offset];
    const whereCountry = country ? "jurisdiction = ? AND " : "";
    if (country) {
      params.unshift(country);
    }
    const query = `
      SELECT * FROM obligation_nodes
      WHERE ${whereCountry}
        (? IS NULL OR effective_from IS NULL OR effective_from <= ?)
        AND (? IS NULL OR effective_to IS NULL OR effective_to >= ?)
      ORDER BY priority DESC, id
      LIMIT ? OFFSET ?
    `;
    const nodes = this.db.prepare(query).all(...params).map((row) => ({
      id: row.id,
      jurisdiction: row.jurisdiction,
      obligation_type: row.obligation_type,
      regulation_id: row.regulation_id,
      standard_id: row.standard_id,
      priority: row.priority,
      confidence: row.confidence,
      effective_from: row.effective_from,
      effective_to: row.effective_to,
      source_rule_id: row.source_rule_id,
      trigger: fromJson(row.trigger_json, {}),
      exceptions: fromJson(row.exceptions_json, []),
      deadline: fromJson(row.deadline_json, null),
      penalties: fromJson(row.penalties_json, null),
      evidence_refs: fromJson(row.evidence_refs_json, [])
    }));
    const nodeIds = new Set(nodes.map((node) => node.id));
    const edgesQuery = country
      ? "SELECT * FROM obligation_edges WHERE from_node_id IN (SELECT id FROM obligation_nodes WHERE jurisdiction = ?) ORDER BY id"
      : "SELECT * FROM obligation_edges ORDER BY id";
    const edges = (country ? this.db.prepare(edgesQuery).all(country) : this.db.prepare(edgesQuery).all())
      .filter((row) => nodeIds.has(row.from_node_id) && nodeIds.has(row.to_node_id))
      .map((row) => ({
        id: row.id,
        from_node_id: row.from_node_id,
        to_node_id: row.to_node_id,
        relation_type: row.relation_type,
        rationale: row.rationale
      }));

    return {
      data: {
        as_of_date: asOfDate,
        jurisdiction: country,
        nodes,
        edges,
        pagination: {
          limit,
          offset,
          total,
          next_offset: offset + nodes.length < total ? offset + nodes.length : null
        }
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [
          { type: "CELEX", ref: "GDPR", source_url: "https://eur-lex.europa.eu/" },
          { type: "CFR", ref: "GLBA", source_url: "https://www.ecfr.gov/" }
        ],
        confidence: "inferred",
        inference_rationale: "Obligation graph derived from applicability rules and breach profile mappings."
      }),
      _citation: buildCitation(
        country ? `FS obligation graph: ${country}` : "Financial services obligation graph",
        `Financial services obligation graph${country ? ` for ${country}` : ""}`,
        "get_obligation_graph",
        {
          ...(country ? { country } : {}),
          ...(asOfDate ? { as_of_date: asOfDate } : {})
        }
      )
    };
  }

  mapToTechnicalStandards(requirementRefInput, controlIdInput) {
    const requirementRef = normalizeText(requirementRefInput);
    const controlId = normalizeText(controlIdInput);
    const parsedRequirement = parseRequirementRef(requirementRef);
    const clauseQuery = normalizeText(parsedRequirement.clauseOrArticle);
    const normalizedClauseQuery = clauseQuery
      .replace(/\b(article|art|section|sec|clause|requirement)\b/g, "")
      .replace(/\s+/g, " ")
      .trim();
    const standards = this.db.prepare("SELECT * FROM technical_standards ORDER BY name").all().map(rowToStandard);
    const mappings = [];
    for (const standard of standards) {
      const regulationMappings = standard.regulation_mappings ?? [];
      const controlMappings = standard.control_mappings ?? [];
      const requirementMatch =
        !requirementRef ||
        regulationMappings.some((mapping) => {
          const regulationMatch = normalizeText(mapping.regulation_id) === normalizeText(parsedRequirement.regulation);
          if (!parsedRequirement.clauseOrArticle) {
            return regulationMatch;
          }
          const text = normalizeText(`${mapping.article ?? ""} ${mapping.section ?? ""} ${mapping.clause ?? ""}`);
          const textWithoutLabels = text
            .replace(/\b(article|art|section|sec|clause|requirement|req)\b/g, "")
            .replace(/\s+/g, " ")
            .trim();
          return (
            regulationMatch &&
            (text.includes(clauseQuery) ||
              (normalizedClauseQuery &&
                (text.includes(normalizedClauseQuery) || textWithoutLabels.includes(normalizedClauseQuery))))
          );
        });
      const controlMatch =
        !controlId || controlMappings.some((mapping) => normalizeText(mapping.control_id) === normalizeText(controlId));
      if (!(requirementMatch && controlMatch)) {
        continue;
      }
      mappings.push({
        standard_id: standard.id,
        standard_name: standard.name,
        standard_publisher: standard.publisher,
        clause: standard.key_clauses[0] ?? null,
        relevance: requirementRef || controlId ? "direct" : "contextual",
        implementation_guidance: standard.implementation_guidance
      });
    }

    const foundationCalls = mappings.map((mapping) => ({
      mcp: "security-controls",
      tool: "get_control_mapping",
      params: { standard_id: mapping.standard_id, control_id: controlIdInput ?? null }
    }));

    return {
      data: { standard_mappings: mappings },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: mappings.map((mapping) => ({
          type: "STD",
          ref: mapping.standard_name,
          source_url: standardSourceUrl(mapping)
        })),
        foundation_mcp_calls: uniqueFoundationCalls(foundationCalls)
      })
    };
  }

  searchDomainKnowledge(queryInput, contentTypeInput, limitInput, offsetInput) {
    const query = normalizeText(queryInput);
    if (!query) {
      return {
        data: {
          results: [],
          pagination: { limit: 0, offset: 0, total: 0, next_offset: null }
        },
        metadata: buildMetadata(this.datasetFingerprint, {
          confidence: "estimated",
          inference_rationale: "Empty query produced no results."
        })
      };
    }
    const contentTypes = parseArrayInput(contentTypeInput).map(normalizeText);
    const limit = Math.max(1, Math.min(Number(limitInput ?? 10), 25));
    const offset = Math.max(0, Number(offsetInput ?? 0));
    const matchTokens = words(query);
    const matchExpr = matchTokens.length > 1 ? matchTokens.join(" OR ") : sanitizeFtsInput(query);
    const searchTargets = [
      { type: "architecture_patterns", table: "architecture_patterns_fts", idField: "id", textField: "description" },
      { type: "threat_scenarios", table: "threat_scenarios_fts", idField: "id", textField: "description" },
      { type: "technical_standards", table: "technical_standards_fts", idField: "id", textField: "scope" },
      { type: "data_categories", table: "data_categories_fts", idField: "id", textField: "description" }
    ].filter((target) => contentTypes.length === 0 || contentTypes.includes(target.type));

    const results = [];
    for (const target of searchTargets) {
      const sql = `SELECT id, name, ${target.textField} as snippet, bm25(${target.table}) as score
        FROM ${target.table}
        WHERE ${target.table} MATCH ?
        ORDER BY score
        LIMIT ?`;
      const rows = this.db.prepare(sql).all(matchExpr, Math.max(limit + offset, limit));
      for (const row of rows) {
        results.push({
          content_type: target.type,
          id: row.id,
          title: row.name,
          snippet: String(row.snippet ?? "").slice(0, 280),
          relevance_score: relevanceFromScore(row.score),
          source_ref: "financial-services-domain-dataset"
        });
      }
    }

    results.sort((a, b) => b.relevance_score - a.relevance_score);
    const paged = results.slice(offset, offset + limit);
    return {
      data: {
        results: paged,
        pagination: {
          limit,
          offset,
          total: results.length,
          next_offset: offset + paged.length < results.length ? offset + paged.length : null
        }
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [{ type: "URL", ref: "Domain dataset", source_url: "https://financial-services-mcp.vercel.app" }],
        confidence: "inferred",
        inference_rationale: "Full-text matching over curated domain dataset using SQLite FTS5."
      })
    };
  }

  compareJurisdictions(topicInput, jurisdictionsInput, asOfDateInput) {
    const topic = normalizeText(topicInput);
    const asOfDate = normalizeAsOfDate(asOfDateInput);
    const jurisdictions = parseArrayInput(jurisdictionsInput).map(normalizeCountry);
    const availableTopicKey = Object.keys(jurisdictionComparisonTopics).find(
      (key) => topic === key || topic.includes(key) || key.includes(topic)
    );
    const selectedTopic = availableTopicKey ?? "breach notification";
    const matrixSource = jurisdictionComparisonTopics[selectedTopic];
    const targets = jurisdictions.length > 0 ? jurisdictions : Object.keys(matrixSource);
    const comparisonMatrix = {};
    for (const jurisdiction of targets) {
      const direct = matrixSource[jurisdiction];
      if (direct) {
        comparisonMatrix[jurisdiction] = direct;
        continue;
      }
      if (selectedTopic === "breach notification") {
        const breachEntry =
          breachObligationsByJurisdiction[jurisdiction] ??
          breachObligationsByJurisdiction[(jurisdiction || "").startsWith("US-") ? "US" : "EU"];
        if (breachEntry?.notifications?.length) {
          const first = breachEntry.notifications[0];
          const primaryCitation = (breachEntry.citations ?? [])[0] ?? null;
          comparisonMatrix[jurisdiction] = {
            obligation: first.recipient,
            timeline: first.deadline,
            trigger: breachEntry.topic ?? "breach notification",
            source: primaryCitation?.ref ?? "generated baseline",
            source_url: primaryCitation?.source_url ?? null
          };
          continue;
        }
      }
      comparisonMatrix[jurisdiction] = {
        obligation: "No domain intelligence entry yet",
        timeline: "unknown",
        trigger: "unknown",
        source: "not available",
        source_url: null
      };
    }
    const citations = targets.map((jurisdiction) => {
      const entry = comparisonMatrix[jurisdiction] ?? {};
      const source = entry.source ?? "n/a";
      const sourceUrl = sourceUrlForComparisonSource(source, entry.source_url);
      return {
        type: "REG",
        ref: `${jurisdiction}: ${source}`,
        source_url: sourceUrl
      };
    });
    return {
      data: {
        topic: selectedTopic,
        as_of_date: asOfDate,
        jurisdictions: targets,
        comparison_matrix: comparisonMatrix
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations,
        confidence: "inferred",
        inference_rationale: "Jurisdiction comparison assembled from obligation comparison dataset and normalized topic matching."
      })
    };
  }

  buildControlBaseline(orgProfileInput = {}) {
    const profile = typeof orgProfileInput === "object" && orgProfileInput ? orgProfileInput : {};
    const systemTypes = parseArrayInput(profile.system_types ?? profile.services ?? []);
    const dataTypes = parseArrayInput(profile.data_types ?? []);
    const targetPatternIds = mapInputSystemTypesToPatternIds(systemTypes);
    const targetDataIds = mapInputDataTypesToCategoryIds(dataTypes);

    const matchedThreats = this.db
      .prepare("SELECT * FROM threat_scenarios")
      .all()
      .map(rowToThreat)
      .filter((threat) => {
        const patternMatch =
          targetPatternIds.length === 0 || threat.affected_patterns.some((patternId) => targetPatternIds.includes(patternId));
        const dataMatch =
          targetDataIds.length === 0 || threat.affected_data_categories.some((categoryId) => targetDataIds.includes(categoryId));
        return patternMatch || dataMatch;
      });

    const scores = new Map();
    for (const threat of matchedThreats) {
      for (const controlId of threat.control_refs ?? []) {
        const baseline = scores.get(controlId) ?? { score: 0, regulation_basis: new Set(), rationale_parts: [] };
        const weight = controlCatalog[controlId]?.priority_weight ?? 50;
        baseline.score += weight;
        for (const ref of threat.regulation_refs ?? []) {
          baseline.regulation_basis.add(ref.regulation_id);
        }
        baseline.rationale_parts.push(`Mitigates ${threat.name}`);
        scores.set(controlId, baseline);
      }
    }

    const controls = [...scores.entries()]
      .map(([controlId, info]) => ({
        control_id: controlId,
        title: controlCatalog[controlId]?.title ?? "Control",
        priority: info.score >= 250 ? "critical" : info.score >= 160 ? "high" : "medium",
        rationale: uniqueStrings(info.rationale_parts).slice(0, 3).join("; "),
        regulation_basis: [...info.regulation_basis],
        standard_basis: deriveStandardBasisByControl(controlId)
      }))
      .sort((a, b) => {
        const rank = { critical: 3, high: 2, medium: 1, low: 0 };
        return rank[b.priority] - rank[a.priority];
      });

    const riskScenarios = matchedThreats
      .map((threat) => ({
        threat_id: threat.id,
        name: threat.name,
        severity: severityFromImpact(threat.impact_dimensions),
        primary_controls: (threat.control_refs ?? []).slice(0, 4)
      }))
      .sort((a, b) => {
        const rank = { critical: 3, high: 2, medium: 1, low: 0 };
        return rank[b.severity] - rank[a.severity];
      })
      .slice(0, 10);

    return {
      data: {
        profile,
        controls,
        risk_scenarios: riskScenarios
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [
          { type: "CELEX", ref: "DORA Art. 9", source_url: "https://eur-lex.europa.eu/" },
          { type: "CFR", ref: "GLBA Safeguards", source_url: "https://www.ecfr.gov/" }
        ],
        confidence: "inferred",
        inference_rationale:
          "Control baseline prioritized using threat-to-control mapping weights and matched high-severity risk scenarios."
      })
    };
  }

  buildEvidencePlan(baselineInput, auditTypeInput) {
    const baselineControls = Array.isArray(baselineInput?.controls)
      ? baselineInput.controls.map((item) => item.control_id ?? item)
      : parseArrayInput(baselineInput);
    const baselineRegulations = new Set(
      Array.isArray(baselineInput?.controls)
        ? baselineInput.controls.flatMap((item) => parseArrayInput(item?.regulation_basis))
        : []
    );
    const auditType = String(auditTypeInput ?? "").trim();
    let rows;
    if (auditType) {
      rows = this.db.prepare("SELECT * FROM evidence_artifacts WHERE audit_type=? ORDER BY artifact_name").all(auditType);
    } else {
      rows = this.db.prepare("SELECT * FROM evidence_artifacts ORDER BY audit_type, artifact_name").all();
    }
    const evidenceItems = rows.map(rowToEvidence).map((item) => ({
      matched_regulations: uniqueStrings(
        (item.regulation_basis ?? [])
          .map((basis) => basis.regulation_id)
          .filter((regId) => baselineRegulations.has(regId))
      ),
      artifact_name: item.artifact_name,
      audit_type: item.audit_type,
      description: item.description,
      template_ref: item.template_ref,
      mandatory: item.mandatory,
      retention_period: item.retention_period,
      regulation_basis: item.regulation_basis,
      baseline_relevance:
        baselineControls.length === 0
          ? "standard"
          : (item.regulation_basis ?? []).some((basis) => baselineRegulations.has(basis.regulation_id))
            ? "direct"
            : "contextual"
    }));
    return {
      data: {
        evidence_items: evidenceItems
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: uniqueCitationList(
          evidenceItems.flatMap((item) =>
            (item.regulation_basis ?? []).map((basis) => ({
              type: regulationReferenceToCitationType(basis, basis.regulation_id),
              ref: `${basis.regulation_id}${basis.article ? ` Art. ${basis.article}` : ""}${
                basis.section ? ` Sec. ${basis.section}` : ""
              }${basis.clause ? ` ${basis.clause}` : ""}`,
              source_url: this.sourceUrlForRegulation(basis.regulation_id)
            }))
          )
        ),
        confidence: "authoritative"
      })
    };
  }

  assessBreachObligations(incidentDescription, jurisdictionsInput, dataTypesInput, asOfDateInput) {
    const jurisdictions = parseArrayInput(jurisdictionsInput).map(normalizeCountry);
    const dataTypes = parseArrayInput(dataTypesInput);
    const asOfDate = normalizeAsOfDate(asOfDateInput);
    const outOfScope = maybeRedirectOutOfScope(incidentDescription);
    if (outOfScope) {
      return {
        data: {
          notifications: [],
          redirect: outOfScope
        },
        metadata: buildMetadata(this.datasetFingerprint, {
          confidence: "estimated",
          out_of_scope: [outOfScope.reason],
          inference_rationale: "Incident appears outside the financial services domain."
        })
      };
    }
    const targets = jurisdictions.length ? jurisdictions : ["EU"];
    const notifications = [];
    const citations = [];
    for (const jurisdiction of targets) {
      const stateProfileRow = this.db
        .prepare("SELECT profile_json FROM us_state_breach_profiles WHERE jurisdiction=?")
        .get(jurisdiction);
      const stateProfile = fromJson(stateProfileRow?.profile_json, null);
      const item =
        breachObligationsByJurisdiction[jurisdiction] ??
        breachObligationsByJurisdiction[(jurisdiction || "").startsWith("US-") ? "US" : "EU"];
      const profileInRange = isWithinEffectiveWindow(
        asOfDate,
        stateProfile?.effective_from ?? null,
        stateProfile?.effective_to ?? null
      );
      if (!profileInRange) {
        continue;
      }
      for (const notification of item.notifications ?? []) {
        notifications.push({
          jurisdiction,
          recipient: notification.recipient,
          deadline: notification.deadline,
          content_requirements: notification.content_requirements,
          penalties: notification.penalties,
          statute_ref: stateProfile?.statute_ref ?? null
        });
      }
      citations.push(...(item.citations ?? []));
      if (stateProfile?.source_url) {
        citations.push({
          type: "LAW_MCP",
          ref: `${jurisdiction} ${stateProfile.statute_ref ?? "state breach law"}`,
          source_url: stateProfile.source_url
        });
      }
    }
    if (dataTypes.some((item) => normalizeText(item).includes("card"))) {
      notifications.push({
        jurisdiction: "global-card-program",
        recipient: "Card brands / acquiring bank",
        deadline: "as required by contractual incident terms",
        content_requirements: ["forensic status", "scope of card impact", "containment plan"],
        penalties: "fines, increased assessments, or program restrictions"
      });
    }
    return {
      data: {
        incident_summary: incidentDescription,
        as_of_date: asOfDate,
        jurisdictions: targets,
        data_types: dataTypes,
        notifications
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: uniqueCitationList(citations),
        confidence: "inferred",
        inference_rationale: "Notification obligations selected by jurisdiction map and incident context."
      })
    };
  }

  createRemediationBacklog(currentStateInput = {}, targetBaselineInput = {}) {
    const currentState = typeof currentStateInput === "object" && currentStateInput ? currentStateInput : {};
    const targetBaseline = typeof targetBaselineInput === "object" && targetBaselineInput ? targetBaselineInput : {};
    const implemented = new Set(
      parseArrayInput(currentState.implemented_controls ?? currentState.controls ?? []).map((value) => normalizeText(value))
    );

    const targetControls = Array.isArray(targetBaseline.controls)
      ? targetBaseline.controls
      : parseArrayInput(targetBaseline).map((controlId) => ({ control_id: controlId, priority: "medium" }));

    const backlogItems = [];
    for (const control of targetControls) {
      const controlId = String(control.control_id ?? control.id ?? control).trim();
      if (!controlId || implemented.has(normalizeText(controlId))) {
        continue;
      }
      const catalog = controlCatalog[controlId] ?? { title: "Control implementation", priority_weight: 65 };
      const priority = control.priority ?? (catalog.priority_weight >= 90 ? "critical" : "high");
      backlogItems.push({
        control_id: controlId,
        title: catalog.title,
        priority,
        effort_estimate: assignEffortByPriority(catalog.priority_weight),
        regulation_basis: control.regulation_basis ?? [],
        risk_reduction: catalog.priority_weight,
        action: `Implement and validate ${controlId} (${catalog.title})`
      });
    }

    backlogItems.sort((a, b) => b.risk_reduction - a.risk_reduction);

    return {
      data: {
        backlog_items: backlogItems
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        confidence: "inferred",
        inference_rationale: "Backlog generated from target controls minus current implemented controls."
      })
    };
  }

  classifyFinancialEntity(entityDescriptionInput, servicesInput, jurisdictionInput) {
    const description = normalizeText(entityDescriptionInput);
    const services = parseArrayInput(servicesInput).map(normalizeText);
    const jurisdiction = normalizeCountry(jurisdictionInput || "EU");

    let doraCategory = "ICT third-party service provider";
    if (services.includes("payments")) {
      doraCategory = "payment institution";
    }
    if (services.includes("lending") || description.includes("credit institution")) {
      doraCategory = "credit institution";
    }
    if (services.includes("investment") || services.includes("trading")) {
      doraCategory = "investment firm";
    }
    if (services.includes("insurance")) {
      doraCategory = "insurance undertaking";
    }

    const proportionalityTier =
      description.includes("small") || description.includes("non-complex")
        ? "simplified (DORA Art. 16)"
        : "full ICT risk management (DORA Art. 6-15)";

    const supervisorMap = {
      SE: "Finansinspektionen",
      DE: "BaFin",
      NL: "DNB",
      "US-NY": "NYDFS",
      US: "Federal Reserve/OCC/FDIC"
    };

    const supervisor = supervisorMap[jurisdiction] ?? (jurisdiction.startsWith("US-") ? "State regulator + federal agencies" : "National competent authority");

    const applicableRtsIts = [
      "RTS on ICT risk management framework",
      "RTS on incident classification",
      "ITS on incident reporting",
      "RTS on third-party risk register"
    ];
    if (!services.includes("payments") && !services.includes("lending")) {
      applicableRtsIts.push("RTS on threat-led penetration testing applicability assessment");
    }

    return {
      data: {
        dora_category: doraCategory,
        proportionality_tier: proportionalityTier,
        supervisor,
        applicable_rts_its: applicableRtsIts
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [
          { type: "CELEX", ref: "DORA Art. 6", source_url: "https://eur-lex.europa.eu/" },
          { type: "CELEX", ref: "DORA Art. 16", source_url: "https://eur-lex.europa.eu/" }
        ],
        foundation_mcp_calls: [
          {
            mcp: "eu-regulations",
            tool: "get_article",
            params: { regulation: "DORA", article: "6" }
          }
        ]
      })
    };
  }

  scopePciDss(paymentFlowInput, dataStoredInput, architectureInput) {
    const paymentFlow = normalizeText(paymentFlowInput);
    const dataStored = parseArrayInput(dataStoredInput).map(normalizeText);
    const architecture = normalizeText(architectureInput);

    const storesPan = dataStored.some((item) => item.includes("pan") || item.includes("card"));
    const storesCvv = dataStored.some((item) => item.includes("cvv"));
    const hostedRedirect = paymentFlow.includes("hosted payment page") || paymentFlow.includes("redirect");
    const ecommerceTouchesCard = paymentFlow.includes("browser") || paymentFlow.includes("client-side") || paymentFlow.includes("javascript");

    let saqType = "D";
    if (hostedRedirect && !storesPan) {
      saqType = "A";
    } else if (ecommerceTouchesCard && !storesPan) {
      saqType = "A-EP";
    } else if (!ecommerceTouchesCard && !storesPan && architecture.includes("terminal")) {
      saqType = "B-IP";
    }

    const cdeBoundaries = [
      "Payment gateway and tokenization service",
      "Card authorization and settlement path",
      "Any connected-to systems with security impact on CDE"
    ];
    if (storesPan) {
      cdeBoundaries.push("Persistent card data store");
    }
    if (storesCvv) {
      cdeBoundaries.push("Critical finding: CVV storage must be eliminated post-authorization");
    }

    const requirementsBySaq = {
      A: ["Req 8 (access)", "Req 11 (testing for scoped systems)", "Req 12 (policies)"],
      "A-EP": ["Req 1", "Req 6", "Req 8", "Req 10", "Req 11", "Req 12"],
      "B-IP": ["Req 2", "Req 8", "Req 9", "Req 11", "Req 12"],
      D: ["Req 1-12 full baseline"]
    };

    return {
      data: {
        cde_boundaries: cdeBoundaries,
        saq_type: saqType,
        applicable_requirements: requirementsBySaq[saqType] ?? requirementsBySaq.D
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [{ type: "PCI", ref: "PCI DSS 4.0", source_url: "https://www.pcisecuritystandards.org/" }],
        foundation_mcp_calls: [
          {
            mcp: "security-controls",
            tool: "map_frameworks",
            params: { framework: "pci_dss_4_0" }
          }
        ]
      })
    };
  }

  assessSwiftCsp(architectureTypeInput, operatorRoleInput) {
    const architectureType = normalizeText(architectureTypeInput);
    const operatorRole = normalizeText(operatorRoleInput);
    const mandatoryControls = [
      "Restrict and secure internet access in SWIFT environment",
      "Enforce multi-factor authentication for operators",
      "Segregate operator and approver responsibilities",
      "Log and monitor all message creation and release actions",
      "Protect critical systems with EDR and allow-listing"
    ];
    const advisoryControls = [
      "Out-of-band transaction verification",
      "Behavioral analytics for operator anomalies",
      "Enhanced secure software supply chain checks"
    ];
    const attestationScope =
      architectureType.includes("alliance lite")
        ? "Alliance Lite2 footprint and connected operator endpoints"
        : "SWIFT Alliance infrastructure, operator endpoints, and integration gateways";

    if (operatorRole.includes("outsourced")) {
      advisoryControls.push("Third-party operator assurance and contractual control attestation");
    }

    return {
      data: {
        mandatory_controls: mandatoryControls,
        advisory_controls: advisoryControls,
        attestation_scope: attestationScope
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [{ type: "SWIFT", ref: "CSP Mandatory Controls", source_url: "https://www.swift.com/" }],
        foundation_mcp_calls: [
          {
            mcp: "security-controls",
            tool: "get_control",
            params: { framework: "swift_csp", control: "mandatory" }
          }
        ]
      })
    };
  }

  classifyDigitalAssetService(serviceDescriptionInput, assetTypesInput, jurisdictionsInput) {
    const description = normalizeText(serviceDescriptionInput);
    const assetTypes = parseArrayInput(assetTypesInput).map(normalizeText);
    const jurisdictions = parseArrayInput(jurisdictionsInput).map(normalizeCountry);

    let micaCategory = "crypto-asset service provider";
    if (description.includes("custody") || description.includes("wallet")) {
      micaCategory = "custody and administration of crypto-assets";
    } else if (description.includes("exchange")) {
      micaCategory = "operation of a trading platform for crypto-assets";
    } else if (description.includes("advice")) {
      micaCategory = "providing advice on crypto-assets";
    }

    const stateLicenses = [];
    for (const jurisdiction of jurisdictions) {
      if (jurisdiction === "US-NY") {
        stateLicenses.push("NY BitLicense");
      } else if (jurisdiction.startsWith("US-")) {
        stateLicenses.push(`${jurisdiction.replace("US-", "")} money transmitter license`);
      }
    }

    const applicableRequirements = [
      "AML/KYC program with sanctions screening",
      "Travel rule implementation for qualifying transfers",
      "Key management and custody controls",
      "Incident reporting and consumer disclosure controls"
    ];
    if (assetTypes.some((item) => item.includes("stablecoin"))) {
      applicableRequirements.push("Asset reserve and redemption transparency controls");
    }

    return {
      data: {
        mica_category: micaCategory,
        state_licenses: uniqueStrings(stateLicenses),
        applicable_requirements: applicableRequirements
      },
      metadata: buildMetadata(this.datasetFingerprint, {
        citations: [
          { type: "CELEX", ref: "MiCA", source_url: "https://eur-lex.europa.eu/" },
          { type: "CFR", ref: "BSA/AML", source_url: "https://www.ecfr.gov/" }
        ],
        foundation_mcp_calls: [
          {
            mcp: "eu-regulations",
            tool: "search_regulations",
            params: { regulation: "MiCA", query: micaCategory }
          }
        ]
      })
    };
  }
}

function deriveStandardBasisByControl(controlId) {
  const standards = technicalStandards.filter((item) =>
    (item.control_mappings ?? []).some((mapping) => mapping.control_id === controlId)
  );
  return standards.map((item) => item.id);
}

function uniqueCitationList(citations) {
  const seen = new Set();
  const output = [];
  for (const citation of citations) {
    const key = JSON.stringify(citation);
    if (!seen.has(key)) {
      seen.add(key);
      output.push(citation);
    }
  }
  return output;
}
