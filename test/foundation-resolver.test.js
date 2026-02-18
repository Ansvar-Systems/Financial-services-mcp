import test from "node:test";
import assert from "node:assert/strict";

import { resolveFoundationEndpoint } from "../src/foundation/resolver.js";

test("foundation resolver provides default production endpoints when env is unset", () => {
  const priorEu = process.env.FOUNDATION_MCP_EU_URL;
  const priorUs = process.env.FOUNDATION_MCP_US_URL;
  const priorControls = process.env.FOUNDATION_MCP_CONTROLS_URL;
  delete process.env.FOUNDATION_MCP_EU_URL;
  delete process.env.FOUNDATION_MCP_US_URL;
  delete process.env.FOUNDATION_MCP_CONTROLS_URL;

  try {
    const eu = resolveFoundationEndpoint("eu-regulations");
    const us = resolveFoundationEndpoint("us-regulations");
    const controls = resolveFoundationEndpoint("security-controls");
    assert.equal(eu.source, "default");
    assert.equal(us.source, "default");
    assert.equal(controls.source, "default");
    assert.ok(String(eu.endpoint).startsWith("https://"));
    assert.ok(String(us.endpoint).startsWith("https://"));
    assert.ok(String(controls.endpoint).startsWith("https://"));
  } finally {
    if (priorEu == null) {
      delete process.env.FOUNDATION_MCP_EU_URL;
    } else {
      process.env.FOUNDATION_MCP_EU_URL = priorEu;
    }
    if (priorUs == null) {
      delete process.env.FOUNDATION_MCP_US_URL;
    } else {
      process.env.FOUNDATION_MCP_US_URL = priorUs;
    }
    if (priorControls == null) {
      delete process.env.FOUNDATION_MCP_CONTROLS_URL;
    } else {
      process.env.FOUNDATION_MCP_CONTROLS_URL = priorControls;
    }
  }
});

test("foundation resolver prefers env-configured endpoint over defaults", () => {
  const prior = process.env.FOUNDATION_MCP_US_URL;
  process.env.FOUNDATION_MCP_US_URL = "https://example.org/custom-us-regs";
  try {
    const resolved = resolveFoundationEndpoint("us-regulations");
    assert.equal(resolved.source, "env");
    assert.equal(resolved.endpoint, "https://example.org/custom-us-regs/mcp");
  } finally {
    if (prior == null) {
      delete process.env.FOUNDATION_MCP_US_URL;
    } else {
      process.env.FOUNDATION_MCP_US_URL = prior;
    }
  }
});
