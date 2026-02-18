# Changelog

## 1.0.0 - 2026-02-18

- Initial production baseline for Financial Services MCP.
- Added full EU (27) and US (51) jurisdiction coverage generation.
- Added US state breach profile model with provenance tiers and confidence metadata.
- Added temporal applicability via `as_of_date`.
- Added obligation graph data model and `get_obligation_graph` tool.
- Added expert knowledge packs for payments fraud, cloud control-plane risk, AML/sanctions, and model-risk use cases.
- Added stricter integrity and production audit gates (runtime smoke checks, catalog coverage checks, freshness checks).
