import path from "node:path";
import { readFile } from "node:fs/promises";

import { projectRoot } from "./dataset-files.mjs";

const referenceDir = path.join(projectRoot, "ingestion", "reference");
const DEFAULT_GENERATED_AT = "2026-02-18T00:00:00Z";
const OBLIGATION_NODE_VERSION = "1.0.0";

export async function loadCoverageReferences() {
  const [euMemberStates, usStates, regulatoryCatalog, usStateBreachOverrides] = await Promise.all([
    readJson(path.join(referenceDir, "eu_member_states.json")),
    readJson(path.join(referenceDir, "us_states.json")),
    readJson(path.join(referenceDir, "regulatory_catalog.eu-us.json")),
    readJson(path.join(referenceDir, "us_state_breach_overrides.json"))
  ]);

  return {
    euMemberStates,
    usStates,
    regulatoryCatalog,
    usStateBreachOverrides
  };
}

export function augmentDatasetForCoverage(rawDataset, references, options = {}) {
  const generatedAt = options.generatedAt ?? DEFAULT_GENERATED_AT;
  const dataset = structuredClone(rawDataset);
  const usStateBreachProfiles = buildUsStateBreachProfiles(
    references.usStates,
    references.usStateBreachOverrides ?? {},
    generatedAt
  );

  dataset.applicabilityRules = ensureCoverageApplicabilityRules(
    dataset.applicabilityRules ?? [],
    references,
    generatedAt,
    usStateBreachProfiles
  );
  dataset.breachObligationsByJurisdiction = ensureCoverageBreachMap(
    dataset.breachObligationsByJurisdiction ?? {},
    references,
    generatedAt,
    usStateBreachProfiles
  );
  dataset.usStateBreachProfiles = usStateBreachProfiles;
  dataset.authoritativeSources = ensureCoverageSources(dataset.authoritativeSources ?? [], references);
  dataset.knownLimitations = ensureCoverageLimitations(dataset.knownLimitations ?? []);
  dataset.obligationGraph = buildObligationGraph(dataset, generatedAt);

  const coverageReport = computeCoverageReport(dataset, references);

  if (
    coverageReport.eu.missing.length > 0 ||
    coverageReport.us.missing.length > 0 ||
    coverageReport.eu.baseline_missing.length > 0 ||
    coverageReport.us.baseline_missing.length > 0
  ) {
    throw new Error(
      `Coverage augmentation failed. Missing EU: [${coverageReport.eu.missing.join(", ")}], Missing US: [${coverageReport.us.missing.join(", ")}], EU baseline gaps: [${coverageReport.eu.baseline_missing.join(", ")}], US baseline gaps: [${coverageReport.us.baseline_missing.join(", ")}]`
    );
  }

  return { dataset, coverageReport };
}

export function normalizeDataset(dataset) {
  return {
    authoritativeSources: sortById(dataset.authoritativeSources),
    dataCategories: sortById(dataset.dataCategories),
    architecturePatterns: sortById(dataset.architecturePatterns),
    threatScenarios: sortById(dataset.threatScenarios),
    technicalStandards: sortById(dataset.technicalStandards),
    applicabilityRules: sortById(dataset.applicabilityRules),
    evidenceArtifacts: sortById(dataset.evidenceArtifacts),
    breachObligationsByJurisdiction: sortObject(dataset.breachObligationsByJurisdiction),
    usStateBreachProfiles: sortObject(dataset.usStateBreachProfiles ?? {}),
    obligationGraph: {
      version: dataset.obligationGraph?.version ?? OBLIGATION_NODE_VERSION,
      nodes: sortById(dataset.obligationGraph?.nodes ?? []),
      edges: sortById(dataset.obligationGraph?.edges ?? []),
      generated_at: dataset.obligationGraph?.generated_at ?? DEFAULT_GENERATED_AT
    },
    jurisdictionComparisonTopics: sortObject(dataset.jurisdictionComparisonTopics),
    controlCatalog: sortObject(dataset.controlCatalog),
    knownLimitations: [...dataset.knownLimitations]
  };
}

export function computeCoverageReport(dataset, references) {
  const applicabilityCountries = collectApplicabilityCountries(dataset.applicabilityRules ?? []);
  const euCovered = references.euMemberStates.filter((state) => applicabilityCountries.has(state));
  const usCovered = references.usStates.filter((state) => applicabilityCountries.has(state));
  const euMissing = references.euMemberStates.filter((state) => !applicabilityCountries.has(state));
  const usMissing = references.usStates.filter((state) => !applicabilityCountries.has(state));
  const obligationCoverage = collectObligationCoverage(dataset.applicabilityRules ?? []);
  const euBaselineMissing = references.euMemberStates.filter(
    (state) =>
      !obligationCoverage.has(`${state}::GDPR`) || !obligationCoverage.has(`${state}::DORA`)
  );
  const usBaselineMissing = references.usStates.filter(
    (state) =>
      !obligationCoverage.has(`${state}::GLBA`) ||
      !obligationCoverage.has(`${state}::STATE_BREACH_NOTIFICATION`)
  );

  const breachKeys = new Set(Object.keys(dataset.breachObligationsByJurisdiction ?? {}));
  const euBreachCovered = references.euMemberStates.filter((state) => breachKeys.has(state));
  const usBreachCovered = references.usStates.filter((state) => breachKeys.has(state));
  const usStateProfileCount = Object.keys(dataset.usStateBreachProfiles ?? {}).length;
  const usStateProfileQuality = summarizeUsStateProfileQuality(dataset.usStateBreachProfiles ?? {});
  const obligationGraphNodes = dataset.obligationGraph?.nodes?.length ?? 0;
  const obligationGraphEdges = dataset.obligationGraph?.edges?.length ?? 0;

  return {
    generated_at: new Date().toISOString(),
    eu: {
      total: references.euMemberStates.length,
      covered: euCovered.length,
      missing: euMissing,
      breach_covered: euBreachCovered.length,
      baseline_missing: euBaselineMissing
    },
    us: {
      total: references.usStates.length,
      covered: usCovered.length,
      missing: usMissing,
      breach_covered: usBreachCovered.length,
      baseline_missing: usBaselineMissing
    },
    regulatory_catalog: {
      eu: references.regulatoryCatalog?.eu?.length ?? 0,
      us: references.regulatoryCatalog?.us?.length ?? 0
    },
    us_state_breach_profiles: usStateProfileCount,
    us_state_breach_profile_quality: usStateProfileQuality,
    obligation_graph: {
      version: dataset.obligationGraph?.version ?? OBLIGATION_NODE_VERSION,
      nodes: obligationGraphNodes,
      edges: obligationGraphEdges
    }
  };
}

function ensureCoverageApplicabilityRules(existingRules, references, generatedAt, usStateBreachProfiles) {
  const rules = [...existingRules];
  const seenIds = new Set(rules.map((rule) => rule.id));

  for (const state of references.euMemberStates) {
    for (const template of euRuleTemplates(state, generatedAt)) {
      if (!seenIds.has(template.id)) {
        rules.push(template);
        seenIds.add(template.id);
      }
    }
  }

  for (const state of references.usStates) {
    for (const template of usRuleTemplates(state, generatedAt, usStateBreachProfiles[state])) {
      if (!seenIds.has(template.id)) {
        rules.push(template);
        seenIds.add(template.id);
      }
    }
  }

  return rules;
}

function ensureCoverageBreachMap(existingMap, references, generatedAt, usStateBreachProfiles) {
  const output = { ...existingMap };

  for (const state of references.euMemberStates) {
    if (!output[state]) {
      output[state] = euBreachTemplate(state, generatedAt);
    }
  }

  for (const state of references.usStates) {
    output[state] = usBreachTemplate(state, generatedAt, usStateBreachProfiles[state]);
  }

  return output;
}

function ensureCoverageSources(existingSources, references) {
  const output = [...existingSources];
  const seen = new Set(output.map((source) => source.id));
  for (const entry of [...(references.regulatoryCatalog.eu ?? []), ...(references.regulatoryCatalog.us ?? [])]) {
    const id = `src-reg-${String(entry.id).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    if (seen.has(id)) {
      continue;
    }
    output.push({
      id,
      source_type: "regulation-catalog",
      name: entry.id,
      content: `Foundation regulatory reference (${entry.type})`,
      provenance: "Ingestion regulatory catalog",
      license: "Public legal text reference",
      refresh_cadence: "quarterly",
      source_url: entry.url
    });
    seen.add(id);
  }
  return output;
}

function ensureCoverageLimitations(limitations) {
  const note =
    "EU and US jurisdiction coverage is baseline-generated for routing; authoritative legal text must be retrieved from foundation MCPs.";
  if (limitations.includes(note)) {
    return limitations;
  }
  return [...limitations, note];
}

function euRuleTemplates(state, generatedAt) {
  const countryLabel = state.toLowerCase();
  return [
    {
      id: `app-eu-gdpr-${countryLabel}`,
      condition: {
        country: [state, "EU"],
        role: ["bank", "insurance", "fintech", "payment-institution", "financial-entity"],
        system_types: ["any"],
        data_types: [
          "dc-npi",
          "dc-account-data",
          "dc-card-data",
          "dc-credit",
          "dc-insurance",
          "dc-open-banking",
          "dc-kyc-aml",
          "dc-trading",
          "dc-digital-asset"
        ]
      },
      obligation: {
        regulation_id: "GDPR",
        article: "32",
        standard_id: "std-iso-27017-27018",
        confidence: "authoritative",
        obligation_type: "security_of_processing",
        priority: 65,
        effective_from: "2018-05-25"
      },
      rationale: `EU baseline generated rule for ${state}: GDPR security of processing applies for financial personal data.`,
      last_updated: generatedAt
    },
    {
      id: `app-eu-dora-${countryLabel}`,
      condition: {
        country: [state, "EU"],
        role: ["bank", "insurance", "payment-institution", "investment-firm", "fintech", "financial-entity"],
        system_types: ["any"],
        data_types: ["dc-account-data", "dc-open-banking", "dc-trading", "dc-insurance", "dc-kyc-aml"]
      },
      obligation: {
        regulation_id: "DORA",
        article: "6",
        standard_id: "std-iso-27017-27018",
        confidence: "authoritative",
        obligation_type: "ict_risk_management",
        priority: 70,
        effective_from: "2025-01-17"
      },
      rationale: `EU baseline generated rule for ${state}: DORA ICT risk framework applies to in-scope financial entities.`,
      last_updated: generatedAt
    }
  ];
}

function usRuleTemplates(state, generatedAt, breachProfile) {
  const countryLabel = state.toLowerCase().replace(/^us-/, "");
  const profile = breachProfile ?? {};
  return [
    {
      id: `app-us-glba-${countryLabel}`,
      condition: {
        country: [state, "US"],
        role: ["bank", "fintech", "insurance", "payment-institution", "financial-entity"],
        system_types: ["any"],
        data_types: ["dc-npi", "dc-account-data", "dc-credit", "dc-card-data", "dc-open-banking"]
      },
      obligation: {
        regulation_id: "GLBA",
        section: "501(b)",
        standard_id: "std-nist-800-86",
        confidence: "authoritative",
        obligation_type: "information_security_program",
        priority: 68,
        effective_from: "2003-07-01"
      },
      rationale: `US baseline generated rule for ${state}: GLBA safeguards apply to covered financial institutions handling NPI.`,
      last_updated: generatedAt
    },
    {
      id: `app-us-state-breach-${countryLabel}`,
      condition: {
        country: [state],
        role: ["bank", "fintech", "insurance", "payment-institution", "financial-entity"],
        system_types: ["any"],
        data_types: ["dc-npi", "dc-account-data", "dc-credit", "dc-card-data", "dc-biometric"]
      },
      obligation: {
        regulation_id: "STATE_BREACH_NOTIFICATION",
        section: profile.statute_ref ?? state,
        standard_id: "std-nist-800-86",
        confidence: "authoritative",
        obligation_type: "breach_notification",
        priority: 88,
        effective_from: profile.effective_from ?? "2003-01-01",
        deadline: profile.deadline ?? "without unreasonable delay"
      },
      rationale: `US baseline generated rule for ${state}: state breach notification law must be resolved via law MCP.`,
      last_updated: generatedAt
    }
  ];
}

function euBreachTemplate(state, generatedAt) {
  return {
    topic: "breach notification",
    generated: true,
    generated_at: generatedAt,
    notifications: [
      {
        recipient: "National Data Protection Authority",
        deadline: "72 hours",
        content_requirements: [
          "nature of breach",
          "categories and approximate number of data subjects/records",
          "likely consequences",
          "mitigation and containment measures"
        ],
        penalties: "GDPR administrative sanctions"
      }
    ],
    citations: [{ type: "CELEX", ref: "GDPR Art. 33", source_url: "https://eur-lex.europa.eu/" }]
  };
}

function usBreachTemplate(state, generatedAt, profile) {
  const resolvedProfile = profile ?? buildDefaultUsStateProfile(state, generatedAt, {});
  return {
    topic: "breach notification",
    generated: true,
    profile_source: resolvedProfile.profile_source,
    generated_at: generatedAt,
    notifications: [
      {
        recipient: "Affected individuals",
        deadline: resolvedProfile.deadline,
        content_requirements: [
          "incident summary",
          "types of personal information affected",
          "consumer remediation guidance",
          "regulator notification details where required"
        ],
        penalties: resolvedProfile.penalties
      },
      {
        recipient: resolvedProfile.regulator_notice,
        deadline: resolvedProfile.deadline,
        content_requirements: [
          "incident scope and jurisdictional impact",
          `threshold analysis (${resolvedProfile.ag_notice_threshold})`,
          "remediation and notification plan"
        ],
        penalties: resolvedProfile.penalties
      }
    ],
    citations: [
      {
        type: "LAW_MCP",
        ref: `${state} ${resolvedProfile.statute_ref}`,
        source_url: resolvedProfile.source_url
      },
      {
        type: "LAW_MCP",
        ref: `${state} law-mcp:${resolvedProfile.law_mcp.document_id}#${resolvedProfile.law_mcp.provision_ref}`,
        source_url: resolvedProfile.source_url
      }
    ],
    state_profile: resolvedProfile
  };
}

function collectApplicabilityCountries(rules) {
  const output = new Set();
  for (const rule of rules) {
    const countries = Array.isArray(rule?.condition?.country) ? rule.condition.country : [];
    for (const country of countries) {
      output.add(String(country).toUpperCase());
    }
  }
  return output;
}

function collectObligationCoverage(rules) {
  const output = new Set();
  for (const rule of rules) {
    const countries = Array.isArray(rule?.condition?.country) ? rule.condition.country : [];
    const regulationId = String(rule?.obligation?.regulation_id ?? "").toUpperCase();
    if (!regulationId) {
      continue;
    }
    for (const country of countries) {
      const normalizedCountry = String(country).toUpperCase();
      if (!normalizedCountry || normalizedCountry === "EU" || normalizedCountry === "US") {
        continue;
      }
      output.add(`${normalizedCountry}::${regulationId}`);
    }
  }
  return output;
}

function summarizeUsStateProfileQuality(profiles) {
  const summary = {
    total: 0,
    source_tier: { primary: 0, secondary: 0, unknown: 0 },
    confidence: { authoritative: 0, estimated: 0, unknown: 0 }
  };

  for (const profile of Object.values(profiles)) {
    summary.total += 1;
    const tier = String(profile?.source_tier ?? "").toLowerCase();
    if (tier === "primary" || tier === "secondary") {
      summary.source_tier[tier] += 1;
    } else {
      summary.source_tier.unknown += 1;
    }

    const confidence = String(profile?.confidence ?? "").toLowerCase();
    if (confidence === "authoritative" || confidence === "estimated") {
      summary.confidence[confidence] += 1;
    } else {
      summary.confidence.unknown += 1;
    }
  }

  return summary;
}

function sortById(items) {
  return [...items].sort((a, b) => String(a.id).localeCompare(String(b.id)));
}

function sortObject(value) {
  if (Array.isArray(value)) {
    return value.map((item) => sortObject(item));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const output = {};
  for (const key of Object.keys(value).sort()) {
    output[key] = sortObject(value[key]);
  }
  return output;
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, "utf8"));
}

function buildUsStateBreachProfiles(usStates, overrides, generatedAt) {
  const output = {};
  for (const state of usStates) {
    const override = overrides?.[state] ?? {};
    output[state] = buildDefaultUsStateProfile(state, generatedAt, override);
  }
  return output;
}

function buildDefaultUsStateProfile(state, generatedAt, override = {}) {
  const stateCode = String(state).replace(/^US-/, "").toLowerCase();
  const statuteRef = override.statute_ref ?? `${state} breach notification statute`;
  const lawMcp = {
    document_id: override.law_mcp_document_id ?? `us-${stateCode}-breach-notification`,
    provision_ref: override.law_mcp_provision_ref ?? "main"
  };
  const sourceTier = override.source_tier ?? (Object.keys(override).length > 0 ? "primary" : "secondary");
  const confidence = override.confidence ?? (sourceTier === "primary" ? "authoritative" : "estimated");
  return {
    jurisdiction: state,
    statute_ref: statuteRef,
    deadline: override.deadline ?? "without unreasonable delay",
    ag_notice_threshold: override.ag_notice_threshold ?? "state-specific threshold",
    regulator_notice: override.regulator_notice ?? "State attorney general or designated regulator",
    consumer_notice: true,
    penalties: override.penalties ?? "state enforcement and private action exposure",
    source_url:
      override.source_url ??
      "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws",
    law_mcp: lawMcp,
    source_tier: sourceTier,
    confidence,
    effective_from: override.effective_from ?? "2003-01-01",
    effective_to: override.effective_to ?? null,
    profile_source: override.profile_source ?? (Object.keys(override).length > 0 ? "override" : "generated-default"),
    last_updated: generatedAt
  };
}

function buildObligationGraph(dataset, generatedAt) {
  const nodes = [];
  const edges = [];
  const evidenceByReg = buildEvidenceByRegulation(dataset.evidenceArtifacts ?? []);

  for (const rule of dataset.applicabilityRules ?? []) {
    const countries = Array.isArray(rule?.condition?.country) ? rule.condition.country : [];
    const obligation = rule?.obligation ?? {};
    const regulationId = obligation.regulation_id;
    if (!regulationId) {
      continue;
    }
    for (const country of countries) {
      const normalizedCountry = String(country).toUpperCase();
      if (normalizedCountry === "EU" || normalizedCountry === "US") {
        continue;
      }
      const nodeId = `ob-node-${rule.id}-${normalizedCountry.toLowerCase()}`;
      nodes.push({
        id: nodeId,
        jurisdiction: normalizedCountry,
        obligation_type: obligation.obligation_type ?? "compliance",
        regulation_id: regulationId,
        standard_id: obligation.standard_id ?? null,
        trigger_json: {
          role: rule.condition?.role ?? [],
          system_types: rule.condition?.system_types ?? [],
          data_types: rule.condition?.data_types ?? []
        },
        exceptions_json: obligation.exceptions ?? [],
        deadline_json: obligation.deadline ?? null,
        penalties_json: obligation.penalties ?? null,
        evidence_refs_json: evidenceByReg[regulationId] ?? [],
        priority: Number(obligation.priority ?? 50),
        confidence: obligation.confidence ?? "inferred",
        effective_from: obligation.effective_from ?? null,
        effective_to: obligation.effective_to ?? null,
        source_rule_id: rule.id,
        last_updated: rule.last_updated ?? generatedAt
      });
    }
  }

  for (const [jurisdiction, breachInfo] of Object.entries(dataset.breachObligationsByJurisdiction ?? {})) {
    if (!/^US-[A-Z]{2}$/.test(jurisdiction) && !/^[A-Z]{2}$/.test(jurisdiction)) {
      continue;
    }
    const first = Array.isArray(breachInfo.notifications) ? breachInfo.notifications[0] : null;
    nodes.push({
      id: `ob-breach-${jurisdiction.toLowerCase()}`,
      jurisdiction,
      obligation_type: "breach_notification",
      regulation_id: jurisdiction.startsWith("US-") ? "STATE_BREACH_NOTIFICATION" : "GDPR",
      standard_id: null,
      trigger_json: { event: "security incident with personal data impact" },
      exceptions_json: [],
      deadline_json: first?.deadline ?? null,
      penalties_json: first?.penalties ?? null,
      evidence_refs_json: [],
      priority: 90,
      confidence: "authoritative",
      effective_from: breachInfo.state_profile?.effective_from ?? null,
      effective_to: breachInfo.state_profile?.effective_to ?? null,
      source_rule_id: `breach-${jurisdiction.toLowerCase()}`,
      last_updated: breachInfo.generated_at ?? generatedAt
    });
  }

  const byJurisdiction = nodes.reduce((acc, node) => {
    const key = node.jurisdiction;
    if (!acc[key]) {
      acc[key] = [];
    }
    acc[key].push(node);
    return acc;
  }, {});

  for (const [jurisdiction, jurisdictionNodes] of Object.entries(byJurisdiction)) {
    const sorted = [...jurisdictionNodes].sort((a, b) => b.priority - a.priority);
    for (let i = 0; i < sorted.length - 1; i += 1) {
      const from = sorted[i];
      const to = sorted[i + 1];
      const relationType =
        from.obligation_type === "breach_notification" ? "precedes_incident_obligations" : "precedes";
      edges.push({
        id: `ob-edge-priority-${jurisdiction.toLowerCase()}-${i + 1}`,
        from_node_id: from.id,
        to_node_id: to.id,
        relation_type: relationType,
        rationale: "Higher-priority obligation should be evaluated first for this jurisdiction.",
        last_updated: generatedAt
      });
    }

    const glbaNode = jurisdictionNodes.find((item) => item.regulation_id === "GLBA");
    const stateBreachNode = jurisdictionNodes.find((item) => item.regulation_id === "STATE_BREACH_NOTIFICATION");
    if (glbaNode && stateBreachNode) {
      edges.push({
        id: `ob-edge-supplement-${jurisdiction.toLowerCase()}`,
        from_node_id: stateBreachNode.id,
        to_node_id: glbaNode.id,
        relation_type: "supplements",
        rationale: "State breach obligations supplement GLBA safeguard duties in incidents.",
        last_updated: generatedAt
      });
    }

    const gdprNode = jurisdictionNodes.find((item) => item.regulation_id === "GDPR");
    const doraNode = jurisdictionNodes.find((item) => item.regulation_id === "DORA");
    if (gdprNode && doraNode) {
      edges.push({
        id: `ob-edge-coapplies-${jurisdiction.toLowerCase()}`,
        from_node_id: gdprNode.id,
        to_node_id: doraNode.id,
        relation_type: "co_applies",
        rationale: "GDPR data protection and DORA operational resilience obligations can co-apply.",
        last_updated: generatedAt
      });
    }
  }

  return {
    version: OBLIGATION_NODE_VERSION,
    generated_at: generatedAt,
    nodes: sortById(nodes),
    edges: sortById(edges)
  };
}

function buildEvidenceByRegulation(evidenceArtifacts) {
  const output = {};
  for (const artifact of evidenceArtifacts) {
    for (const basis of artifact.regulation_basis ?? []) {
      const regId = basis.regulation_id;
      if (!regId) {
        continue;
      }
      if (!output[regId]) {
        output[regId] = [];
      }
      output[regId].push({
        artifact_id: artifact.id,
        artifact_name: artifact.artifact_name,
        audit_type: artifact.audit_type
      });
    }
  }
  return output;
}
