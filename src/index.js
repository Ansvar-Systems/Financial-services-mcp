import { createDomainDatabase } from "./db/database.js";
import { FoundationResolver } from "./foundation/resolver.js";
import { createRequestHandler } from "./mcp/protocol.js";
import { toolDefinitions } from "./mcp/tools.js";
import { startHttpTransport } from "./transports/http.js";
import { startStdioTransport } from "./transports/stdio.js";

function runCheck(repo) {
  const requiredTools = [
    "about",
    "list_sources",
    "list_architecture_patterns",
    "get_architecture_pattern",
    "classify_data",
    "get_domain_threats",
    "assess_applicability",
    "get_obligation_graph",
    "map_to_technical_standards",
    "search_domain_knowledge",
    "compare_jurisdictions",
    "build_control_baseline",
    "build_evidence_plan",
    "assess_breach_obligations",
    "create_remediation_backlog",
    "classify_financial_entity",
    "scope_pci_dss",
    "assess_swift_csp",
    "classify_digital_asset_service"
  ];
  const available = new Set(toolDefinitions.map((tool) => tool.name));
  for (const tool of requiredTools) {
    if (!available.has(tool)) {
      throw new Error(`Missing required tool definition: ${tool}`);
    }
  }

  const about = repo.about();
  if (!about?.data?.coverage_summary) {
    throw new Error("Health check failed: about tool did not return coverage summary.");
  }
  if (!about?.data?.jurisdiction_coverage?.eu?.total || !about?.data?.jurisdiction_coverage?.us?.total) {
    throw new Error("Health check failed: jurisdiction coverage metadata missing.");
  }

  const pattern = repo.getArchitecturePattern("fs-payments");
  if (!pattern?.data?.pattern_id) {
    throw new Error("Health check failed: fs-payments architecture lookup failed.");
  }

  const classification = repo.classifyData("PAN + CVV stored for recurring payments in Germany", ["DE"]);
  if (!classification?.data?.categories?.length) {
    throw new Error("Health check failed: classify_data did not detect financial data categories.");
  }

  const obligationGraph = repo.getObligationGraph("DE", "2026-02-18", 10, 0);
  if (!obligationGraph?.data?.nodes?.length) {
    throw new Error("Health check failed: get_obligation_graph returned no nodes for DE.");
  }
}

function main() {
  const repo = createDomainDatabase();
  if (process.argv.includes("--check")) {
    runCheck(repo);
    process.stdout.write("Financial Services MCP check passed.\n");
    return;
  }

  const foundationResolver = new FoundationResolver();
  const handler = createRequestHandler(repo, { foundationResolver });
  const enableStdio = process.env.MCP_ENABLE_STDIO !== "false";
  const enableHttp = process.env.MCP_ENABLE_HTTP !== "false";

  if (enableStdio) {
    startStdioTransport(handler);
  }
  if (enableHttp) {
    startHttpTransport(handler);
  }
}

main();
