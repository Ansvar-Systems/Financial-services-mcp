import { isStrictIsoDate } from "../utils/date.js";

function obj(properties, required = []) {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      ...properties,
      resolve_foundation: {
        type: "boolean",
        description: "When true, resolve foundation_mcp_calls against configured foundation MCP endpoints."
      },
      resolve_foundation_max_calls: {
        type: "number",
        minimum: 1,
        maximum: 20,
        description: "Max foundation calls to resolve when resolve_foundation=true (default 5)."
      }
    },
    required
  };
}

export class ToolInputError extends Error {
  constructor(message) {
    super(message);
    this.name = "ToolInputError";
  }
}

export const toolDefinitions = [
  {
    name: "about",
    description: "Server metadata, coverage summary, data freshness, and known gaps for Financial Services MCP.",
    inputSchema: obj({})
  },
  {
    name: "list_sources",
    description: "List authoritative sources and provenance used by this domain MCP.",
    inputSchema: obj({
      source_type: { type: "string", description: "Optional source type filter (regulation, standard, supervisory, threat-intel)." },
      limit: { type: "number", minimum: 1, maximum: 100, description: "Max rows (default 50)." },
      offset: { type: "number", minimum: 0, description: "Result offset for pagination (default 0)." }
    })
  },
  {
    name: "list_architecture_patterns",
    description: "List available financial services architecture patterns with optional category filtering.",
    inputSchema: obj({
      category: { type: "string", description: "Optional pattern category filter (banking, payments, trading, insurance, etc.)." },
      limit: { type: "number", minimum: 1, maximum: 100, description: "Max rows (default 50)." },
      offset: { type: "number", minimum: 0, description: "Result offset for pagination (default 0)." }
    })
  },
  {
    name: "get_architecture_pattern",
    description: "Get full architecture pattern details including trust boundaries and data flows.",
    inputSchema: obj(
      {
        pattern_id: { type: "string", description: "Architecture pattern id such as fs-core-banking or fs-payments." }
      },
      ["pattern_id"]
    )
  },
  {
    name: "classify_data",
    description: "Classify financial data categories, regulatory regimes, and handling requirements.",
    inputSchema: obj(
      {
        data_description: { type: "string", description: "Natural-language data description." },
        jurisdictions: {
          type: "array",
          items: { type: "string" },
          description: "Jurisdiction codes (e.g., EU, DE, US-NY, US-CA)."
        }
      },
      ["data_description"]
    )
  },
  {
    name: "get_domain_threats",
    description: "Retrieve financial threat scenarios for architecture and data context.",
    inputSchema: obj({
      architecture_pattern: { type: "string", description: "Architecture pattern id or name." },
      data_types: {
        type: "array",
        items: { type: "string" },
        description: "Data types or data category IDs."
      },
      deployment_context: {
        type: "object",
        description: "Optional deployment context map.",
        additionalProperties: true
      }
    })
  },
  {
    name: "assess_applicability",
    description: "Assess regulatory and standards obligations for organization profile context.",
    inputSchema: obj(
      {
        country: { type: "string", description: "Country or sub-jurisdiction code (SE, DE, US-NY)." },
        role: { type: "string", description: "Entity role (bank, fintech, insurance, payment-institution)." },
        system_types: { type: "array", items: { type: "string" } },
        data_types: { type: "array", items: { type: "string" } },
        additional_context: { type: "object", additionalProperties: true },
        as_of_date: {
          type: "string",
          description: "Optional temporal evaluation date in YYYY-MM-DD format."
        }
      },
      ["country", "role", "system_types", "data_types"]
    )
  },
  {
    name: "get_obligation_graph",
    description: "Retrieve obligation graph nodes/edges with temporal filtering and optional jurisdiction scoping.",
    inputSchema: obj({
      country: { type: "string", description: "Optional jurisdiction code (e.g., DE, US-TX)." },
      as_of_date: { type: "string", description: "Optional evaluation date in YYYY-MM-DD format." },
      limit: { type: "number", minimum: 1, maximum: 500 },
      offset: { type: "number", minimum: 0 }
    })
  },
  {
    name: "map_to_technical_standards",
    description: "Map a requirement reference or control id to financial technical standards.",
    inputSchema: obj({
      requirement_ref: { type: "string", description: "Requirement reference like DORA:6 or PCI_DSS_4_0 Req 3." },
      control_id: { type: "string", description: "Control id such as SCF.AC-01." }
    })
  },
  {
    name: "search_domain_knowledge",
    description: "Full-text search across architecture, threat, data taxonomy, and standards knowledge.",
    inputSchema: obj(
      {
        query: { type: "string" },
        content_type: {
          type: "array",
          items: { type: "string" },
          description: "Optional content filters: architecture_patterns, threat_scenarios, technical_standards, data_categories."
        },
        limit: { type: "number", minimum: 1, maximum: 25 },
        offset: { type: "number", minimum: 0 }
      },
      ["query"]
    )
  },
  {
    name: "compare_jurisdictions",
    description: "Compare obligations across jurisdictions for a specific topic.",
    inputSchema: obj(
      {
        topic: { type: "string" },
        jurisdictions: { type: "array", items: { type: "string" } },
        as_of_date: { type: "string", description: "Optional evaluation date in YYYY-MM-DD format." }
      },
      ["topic", "jurisdictions"]
    )
  },
  {
    name: "build_control_baseline",
    description: "Create prioritized baseline controls from organization profile context.",
    inputSchema: obj(
      {
        org_profile: {
          type: "object",
          additionalProperties: true
        }
      },
      ["org_profile"]
    )
  },
  {
    name: "build_evidence_plan",
    description: "Build required audit evidence plan from baseline and audit type.",
    inputSchema: obj({
      baseline: { type: "object", additionalProperties: true },
      audit_type: { type: "string" }
    })
  },
  {
    name: "assess_breach_obligations",
    description: "Assess breach notification requirements by jurisdiction and data type.",
    inputSchema: obj(
      {
        incident_description: { type: "string" },
        jurisdictions: { type: "array", items: { type: "string" } },
        data_types: { type: "array", items: { type: "string" } },
        as_of_date: { type: "string", description: "Optional evaluation date in YYYY-MM-DD format." }
      },
      ["incident_description", "jurisdictions", "data_types"]
    )
  },
  {
    name: "create_remediation_backlog",
    description: "Create prioritized remediation backlog from current and target control state.",
    inputSchema: obj(
      {
        current_state: { type: "object", additionalProperties: true },
        target_baseline: { type: "object", additionalProperties: true }
      },
      ["current_state", "target_baseline"]
    )
  },
  {
    name: "classify_financial_entity",
    description: "Classify financial entity under DORA and national supervisory context.",
    inputSchema: obj(
      {
        entity_description: { type: "string" },
        services: { type: "array", items: { type: "string" } },
        jurisdiction: { type: "string" }
      },
      ["entity_description", "services", "jurisdiction"]
    )
  },
  {
    name: "scope_pci_dss",
    description: "Scope PCI DSS boundaries and determine probable SAQ type.",
    inputSchema: obj(
      {
        payment_flow: { type: "string" },
        data_stored: { type: "array", items: { type: "string" } },
        architecture: { type: "string" }
      },
      ["payment_flow", "data_stored", "architecture"]
    )
  },
  {
    name: "assess_swift_csp",
    description: "Assess SWIFT CSP mandatory and advisory controls based on architecture and role.",
    inputSchema: obj(
      {
        architecture_type: { type: "string" },
        operator_role: { type: "string" }
      },
      ["architecture_type", "operator_role"]
    )
  },
  {
    name: "classify_digital_asset_service",
    description: "Classify digital asset services for MiCA and US state licensing context.",
    inputSchema: obj(
      {
        service_description: { type: "string" },
        asset_types: { type: "array", items: { type: "string" } },
        jurisdictions: { type: "array", items: { type: "string" } }
      },
      ["service_description", "asset_types", "jurisdictions"]
    )
  }
];

function assertType(value, schema, path) {
  if (value === undefined) {
    return;
  }
  if (!schema?.type) {
    return;
  }
  switch (schema.type) {
    case "string":
      if (typeof value !== "string") {
        throw new ToolInputError(`${path} must be a string.`);
      }
      if (path.endsWith("as_of_date")) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
          throw new ToolInputError(`${path} must use YYYY-MM-DD format.`);
        }
        if (!isStrictIsoDate(value)) {
          throw new ToolInputError(`${path} is not a valid date.`);
        }
      }
      break;
    case "number":
      if (typeof value !== "number" || Number.isNaN(value)) {
        throw new ToolInputError(`${path} must be a number.`);
      }
      if (schema.minimum != null && value < schema.minimum) {
        throw new ToolInputError(`${path} must be >= ${schema.minimum}.`);
      }
      if (schema.maximum != null && value > schema.maximum) {
        throw new ToolInputError(`${path} must be <= ${schema.maximum}.`);
      }
      break;
    case "boolean":
      if (typeof value !== "boolean") {
        throw new ToolInputError(`${path} must be a boolean.`);
      }
      break;
    case "array":
      if (!Array.isArray(value)) {
        throw new ToolInputError(`${path} must be an array.`);
      }
      if (schema.items) {
        for (let i = 0; i < value.length; i += 1) {
          assertType(value[i], schema.items, `${path}[${i}]`);
        }
      }
      break;
    case "object":
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new ToolInputError(`${path} must be an object.`);
      }
      break;
    default:
      break;
  }
}

function validateArguments(tool, args) {
  const schema = tool.inputSchema ?? {};
  const safeArgs = args && typeof args === "object" ? args : {};
  const properties = schema.properties ?? {};
  const required = schema.required ?? [];

  for (const key of required) {
    if (!(key in safeArgs)) {
      throw new ToolInputError(`Missing required argument '${key}' for tool '${tool.name}'.`);
    }
  }

  if (schema.additionalProperties === false) {
    for (const key of Object.keys(safeArgs)) {
      if (!(key in properties)) {
        throw new ToolInputError(`Unknown argument '${key}' for tool '${tool.name}'.`);
      }
    }
  }

  for (const [key, propSchema] of Object.entries(properties)) {
    if (!(key in safeArgs)) {
      continue;
    }
    assertType(safeArgs[key], propSchema, key);
  }
}

export async function dispatchTool(repo, name, args = {}, context = {}) {
  const tool = toolDefinitions.find((item) => item.name === name);
  if (!tool) {
    throw new ToolInputError(`Unknown tool: ${name}`);
  }
  validateArguments(tool, args);

  const resolveFoundation = args.resolve_foundation === true;
  const resolveFoundationMaxCalls = Number(args.resolve_foundation_max_calls ?? 5);
  const toolArgs = { ...args };
  delete toolArgs.resolve_foundation;
  delete toolArgs.resolve_foundation_max_calls;

  let payload;
  switch (name) {
    case "about":
      payload = repo.about();
      break;
    case "list_sources":
      payload = repo.listSources(toolArgs.source_type, toolArgs.limit, toolArgs.offset);
      break;
    case "list_architecture_patterns":
      payload = repo.listArchitecturePatterns(toolArgs.category, toolArgs.limit, toolArgs.offset);
      break;
    case "get_architecture_pattern":
      payload = repo.getArchitecturePattern(toolArgs.pattern_id);
      break;
    case "classify_data":
      payload = repo.classifyData(toolArgs.data_description, toolArgs.jurisdictions);
      break;
    case "get_domain_threats":
      payload = repo.getDomainThreats(toolArgs.architecture_pattern, toolArgs.data_types, toolArgs.deployment_context);
      break;
    case "assess_applicability":
      payload = repo.assessApplicability(
        toolArgs.country,
        toolArgs.role,
        toolArgs.system_types,
        toolArgs.data_types,
        toolArgs.additional_context,
        toolArgs.as_of_date
      );
      break;
    case "get_obligation_graph":
      payload = repo.getObligationGraph(toolArgs.country, toolArgs.as_of_date, toolArgs.limit, toolArgs.offset);
      break;
    case "map_to_technical_standards":
      payload = repo.mapToTechnicalStandards(toolArgs.requirement_ref, toolArgs.control_id);
      break;
    case "search_domain_knowledge":
      payload = repo.searchDomainKnowledge(toolArgs.query, toolArgs.content_type, toolArgs.limit, toolArgs.offset);
      break;
    case "compare_jurisdictions":
      payload = repo.compareJurisdictions(toolArgs.topic, toolArgs.jurisdictions, toolArgs.as_of_date);
      break;
    case "build_control_baseline":
      payload = repo.buildControlBaseline(toolArgs.org_profile);
      break;
    case "build_evidence_plan":
      payload = repo.buildEvidencePlan(toolArgs.baseline, toolArgs.audit_type);
      break;
    case "assess_breach_obligations":
      payload = repo.assessBreachObligations(
        toolArgs.incident_description,
        toolArgs.jurisdictions,
        toolArgs.data_types,
        toolArgs.as_of_date
      );
      break;
    case "create_remediation_backlog":
      payload = repo.createRemediationBacklog(toolArgs.current_state, toolArgs.target_baseline);
      break;
    case "classify_financial_entity":
      payload = repo.classifyFinancialEntity(toolArgs.entity_description, toolArgs.services, toolArgs.jurisdiction);
      break;
    case "scope_pci_dss":
      payload = repo.scopePciDss(toolArgs.payment_flow, toolArgs.data_stored, toolArgs.architecture);
      break;
    case "assess_swift_csp":
      payload = repo.assessSwiftCsp(toolArgs.architecture_type, toolArgs.operator_role);
      break;
    case "classify_digital_asset_service":
      payload = repo.classifyDigitalAssetService(toolArgs.service_description, toolArgs.asset_types, toolArgs.jurisdictions);
      break;
    default:
      throw new ToolInputError(`Unknown tool: ${name}`);
  }

  if (
    resolveFoundation &&
    context.foundationResolver &&
    payload?.metadata?.foundation_mcp_calls &&
    payload.metadata.foundation_mcp_calls.length > 0
  ) {
    const foundationResolution = await context.foundationResolver.resolve(
      payload.metadata.foundation_mcp_calls,
      resolveFoundationMaxCalls
    );
    payload = {
      ...payload,
      metadata: {
        ...payload.metadata,
        foundation_resolution: foundationResolution
      }
    };
  }

  return payload;
}
