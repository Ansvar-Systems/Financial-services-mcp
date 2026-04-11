import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createDomainDatabase } from "../../src/db/database.js";
import { FoundationResolver, resolveFoundationEndpoint } from "../../src/foundation/resolver.js";
import { createRequestHandler } from "../../src/mcp/protocol.js";
import { toolDefinitions } from "../../src/mcp/tools.js";

const root = path.resolve(fileURLToPath(new URL("../../", import.meta.url)));

async function main() {
  const report = {
    generated_at: new Date().toISOString(),
    phases: {},
    verdict: "A"
  };

  report.phases.structural = await checkStructural();
  report.phases.data_accuracy = await checkDataAccuracy();
  report.phases.agent_optimization = checkAgentOptimization();
  report.phases.deployment = await checkDeployment();
  report.phases.integration = checkIntegration();

  const failed = Object.values(report.phases).flatMap((phase) =>
    phase.status === "fail" ? phase.failures ?? [] : []
  );
  if (failed.length > 0) {
    report.verdict = "B";
  }

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.verdict !== "A") {
    process.exitCode = 1;
  }
}

async function checkStructural() {
  const failures = [];
  const repo = createDomainDatabase();
  const handler = createRequestHandler(repo, { foundationResolver: new FoundationResolver() });
  const initResponse = await handler({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  if (!initResponse?.result?.serverInfo?.name) {
    failures.push("MCP initialize did not return serverInfo.");
  }
  const listResponse = await handler({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  if (!Array.isArray(listResponse?.result?.tools) || listResponse.result.tools.length < 10) {
    failures.push("Tool registry appears incomplete.");
  }
  const requiredToolNames = [
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
  for (const required of requiredToolNames) {
    if (!available.has(required)) {
      failures.push(`Missing required tool '${required}'.`);
    }
  }
  const runtimeFailures = await runRuntimeSmokeChecks(handler);
  failures.push(...runtimeFailures);
  return {
    status: failures.length === 0 ? "pass" : "fail",
    failures
  };
}

async function checkDataAccuracy() {
  const failures = [];
  const expected = [
    path.join(root, "sources.yml"),
    path.join(root, "data", "domain-dataset.json"),
    path.join(root, "data", "dataset-hashes.json"),
    path.join(root, "data", "coverage-report.json")
  ];
  for (const file of expected) {
    if (!existsSync(file)) {
      failures.push(`Missing data artifact: ${file}`);
    }
  }

  if (failures.length === 0) {
    const dataset = JSON.parse(await readFile(path.join(root, "data", "domain-dataset.json"), "utf8"));
    const hashes = JSON.parse(await readFile(path.join(root, "data", "dataset-hashes.json"), "utf8"));
    const coverage = JSON.parse(await readFile(path.join(root, "data", "coverage-report.json"), "utf8"));

    if (dataset?._meta?.fingerprint !== hashes?.dataset_fingerprint) {
      failures.push("Dataset fingerprint does not match dataset-hashes manifest.");
    }
    if (dataset?._meta?.coverage?.eu?.total !== coverage?.eu?.total || dataset?._meta?.coverage?.us?.total !== coverage?.us?.total) {
      failures.push("Dataset embedded coverage totals do not match coverage-report totals.");
    }
    if ((coverage?.eu?.missing ?? []).length > 0 || (coverage?.us?.missing ?? []).length > 0) {
      failures.push("Coverage report contains missing jurisdictions.");
    }

    const generatedAt = String(dataset?._meta?.generated_at ?? "");
    const generatedDate = generatedAt ? new Date(generatedAt) : null;
    if (!generatedDate || Number.isNaN(generatedDate.valueOf())) {
      failures.push("Dataset generated_at is missing or invalid.");
    } else {
      const maxAgeDays = 45;
      const ageMs = Date.now() - generatedDate.valueOf();
      const ageDays = ageMs / (1000 * 60 * 60 * 24);
      if (ageDays > maxAgeDays) {
        failures.push(`Dataset is stale (${Math.floor(ageDays)} days old; max ${maxAgeDays}).`);
      }
    }
  }

  return {
    status: failures.length === 0 ? "pass" : "fail",
    failures
  };
}

function checkAgentOptimization() {
  const failures = [];
  const pagedTools = ["list_sources", "list_architecture_patterns", "search_domain_knowledge"];
  for (const toolName of pagedTools) {
    const tool = toolDefinitions.find((item) => item.name === toolName);
    const props = tool?.inputSchema?.properties ?? {};
    if (!("limit" in props) || !("offset" in props)) {
      failures.push(`Tool '${toolName}' missing limit/offset pagination fields.`);
    }
  }
  return {
    status: failures.length === 0 ? "pass" : "fail",
    failures
  };
}

async function checkDeployment() {
  const failures = [];
  const expectedFiles = [
    "src/transports/http.js",
    "src/transports/stdio.js",
    "server.json",
    "CHANGELOG.md",
    ".github/workflows/ci.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/check-source-updates.yml"
  ];
  for (const file of expectedFiles) {
    if (!existsSync(path.join(root, file))) {
      failures.push(`Missing deployment artifact '${file}'.`);
    }
  }

  // codeql.yml and gitleaks.yml intentionally removed per ADR-011 (GitHub Advanced
  // Security adoption). CodeQL default setup and GHAS Secret Protection now replace
  // the per-repo workflow files, so the audit must not flag their absence.
  const securityWorkflows = [
    ".github/workflows/semgrep.yml",
    ".github/workflows/trivy.yml",
    ".github/workflows/socket-security.yml",
    ".github/workflows/scorecard.yml"
  ];
  for (const file of securityWorkflows) {
    if (!existsSync(path.join(root, file))) {
      failures.push(`Missing required security workflow '${file}'.`);
    }
  }

  if (existsSync(path.join(root, "package.json")) && existsSync(path.join(root, "server.json"))) {
    try {
      const pkg = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
      const server = JSON.parse(await readFile(path.join(root, "server.json"), "utf8"));
      if (pkg.mcpName !== server.name) {
        failures.push("package.json mcpName does not match server.json name.");
      }
      if (pkg.version !== server.version) {
        failures.push("package.json version does not match server.json version.");
      }
      if (!pkg.bin || typeof pkg.bin !== "object" || Object.keys(pkg.bin).length === 0) {
        failures.push("package.json is missing a stdio bin entry.");
      }
    } catch (error) {
      failures.push(`Failed to parse package/server metadata: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return {
    status: failures.length === 0 ? "pass" : "fail",
    failures
  };
}

function checkIntegration() {
  const failures = [];
  const requiredFoundations = [
    { mcp: "eu-regulations", label: "FOUNDATION_MCP_EU_URL" },
    { mcp: "us-regulations", label: "FOUNDATION_MCP_US_URL" },
    { mcp: "security-controls", label: "FOUNDATION_MCP_CONTROLS_URL" }
  ];
  for (const entry of requiredFoundations) {
    const resolved = resolveFoundationEndpoint(entry.mcp);
    if (!resolved.endpoint) {
      failures.push(`Integration endpoint '${entry.label}' is not configured and no default endpoint is available.`);
    }
  }
  return {
    status: failures.length === 0 ? "pass" : "fail",
    failures
  };
}

async function runRuntimeSmokeChecks(handler) {
  const failures = [];
  const checks = [
    { name: "about", args: {} },
    {
      name: "assess_applicability",
      args: {
        country: "DE",
        role: "bank",
        system_types: ["payments"],
        data_types: ["dc-account-data"],
        as_of_date: "2026-02-18"
      }
    },
    { name: "get_obligation_graph", args: { country: "US-TX", as_of_date: "2026-02-18", limit: 10, offset: 0 } },
    { name: "build_control_baseline", args: { org_profile: { system_types: ["fs-payments"], data_types: ["dc-account-data"] } } },
    { name: "build_evidence_plan", args: { baseline: {}, audit_type: "DORA Compliance" } },
    { name: "compare_jurisdictions", args: { topic: "breach notification", jurisdictions: ["DE", "US-TX"], as_of_date: "2026-02-18" } }
  ];

  for (const check of checks) {
    const response = await handler({
      jsonrpc: "2.0",
      id: `smoke-${check.name}`,
      method: "tools/call",
      params: { name: check.name, arguments: check.args }
    });
    if (response?.error) {
      failures.push(`Runtime smoke failed for tool '${check.name}': ${response.error.message}`);
      continue;
    }
    const content = response?.result?.structuredContent;
    if (!content || typeof content !== "object") {
      failures.push(`Runtime smoke for tool '${check.name}' returned no structured content.`);
    }
  }

  return failures;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
