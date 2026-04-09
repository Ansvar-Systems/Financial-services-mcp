# Tools — Financial Services MCP

This MCP exposes 20 tools across three categories: meta, universal domain, and financial-specific.

All tools accept two optional cross-cutting parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `resolve_foundation` | boolean | When `true`, resolve `foundation_mcp_calls` against configured foundation MCP endpoints. |
| `resolve_foundation_max_calls` | number (1–20) | Max foundation calls to resolve when `resolve_foundation=true`. Default: 5. |

---

## Meta Tools

### `about`

Server metadata, coverage summary, data freshness, and known gaps.

No parameters.

---

### `check_data_freshness`

Check dataset freshness, source health, and staleness indicators for this MCP server.

No parameters.

Returns: `status` (fresh/stale/unknown), `dataset_age_days`, `last_updated`, `jurisdiction_coverage`, and `source_health` summary.

---

### `list_sources`

List authoritative sources and provenance used by this domain MCP.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `source_type` | string | No | Filter by type: `regulation`, `standard`, `supervisory`, `threat-intel`. |
| `limit` | number (1–100) | No | Max rows. Default: 50. |
| `offset` | number | No | Pagination offset. Default: 0. |

---

## Universal Domain Tools

### `list_architecture_patterns`

List available financial services architecture patterns with optional category filtering.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `category` | string | No | Pattern category: `banking`, `payments`, `trading`, `insurance`, etc. |
| `limit` | number (1–100) | No | Max rows. Default: 50. |
| `offset` | number | No | Pagination offset. Default: 0. |

---

### `get_architecture_pattern`

Get full architecture pattern details including trust boundaries and data flows.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern_id` | string | **Yes** | Architecture pattern id, e.g. `fs-core-banking`, `fs-payments`. |

---

### `classify_data`

Classify financial data categories, regulatory regimes, and handling requirements.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `data_description` | string | **Yes** | Natural-language description of the data. |
| `jurisdictions` | string[] | No | Jurisdiction codes, e.g. `EU`, `DE`, `US-NY`, `US-CA`. |

---

### `get_domain_threats`

Retrieve financial threat scenarios for architecture and data context.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `architecture_pattern` | string | No | Architecture pattern id or name. |
| `data_types` | string[] | No | Data types or data category IDs. |
| `deployment_context` | object | No | Optional deployment context map. |

---

### `assess_applicability`

Assess regulatory and standards obligations for an organization profile.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `country` | string | **Yes** | Country or sub-jurisdiction code, e.g. `SE`, `DE`, `US-NY`. |
| `role` | string | **Yes** | Entity role: `bank`, `fintech`, `insurance`, `payment-institution`. |
| `system_types` | string[] | **Yes** | System/service types in scope, e.g. `payments`, `lending`, `fs-open-banking`. |
| `data_types` | string[] | **Yes** | Financial data categories in scope, e.g. `dc-account-data`, `dc-card-data`. |
| `additional_context` | object | No | Optional qualifiers such as `operating_jurisdictions` or delivery model. |
| `as_of_date` | string | No | Temporal evaluation date in `YYYY-MM-DD` format. |

---

### `get_obligation_graph`

Retrieve obligation graph nodes/edges with temporal filtering and optional jurisdiction scoping.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `country` | string | No | Jurisdiction code, e.g. `DE`, `US-TX`. |
| `as_of_date` | string | No | Evaluation date in `YYYY-MM-DD` format. |
| `limit` | number (1–500) | No | Max nodes returned. Default: 100. |
| `offset` | number | No | Pagination offset. Default: 0. |

---

### `map_to_technical_standards`

Map a requirement reference or control id to financial technical standards.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requirement_ref` | string | No | Requirement reference, e.g. `DORA:6` or `PCI_DSS_4_0 Req 3`. |
| `control_id` | string | No | Control id, e.g. `SCF.AC-01`. |

---

### `search_domain_knowledge`

Full-text search across architecture, threat, data taxonomy, and standards knowledge.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | **Yes** | Search phrase for full-text lookup. |
| `content_type` | string[] | No | Content filters: `architecture_patterns`, `threat_scenarios`, `technical_standards`, `data_categories`. |
| `limit` | number (1–25) | No | Max results per page. Default: 10. |
| `offset` | number | No | Pagination offset. Default: 0. |

---

### `compare_jurisdictions`

Compare obligations across jurisdictions for a specific topic.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `topic` | string | **Yes** | Comparison topic, e.g. `breach notification`, `incident reporting`. |
| `jurisdictions` | string[] | **Yes** | Jurisdictions to compare, e.g. `EU`, `SE`, `US-NY`, `US-CA`. |
| `as_of_date` | string | No | Evaluation date in `YYYY-MM-DD` format. |

---

### `build_control_baseline`

Create prioritized baseline controls from organization profile context.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `org_profile` | object | **Yes** | Organization profile including `system_types`, `data_types`, and optional operating context. |

---

### `build_evidence_plan`

Build required audit evidence plan from baseline and audit type.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `baseline` | object | No | Baseline output or control set from `build_control_baseline`. |
| `audit_type` | string | No | Audit scope filter, e.g. `DORA Compliance`, `PCI DSS 4.0 Assessment`. |

---

### `assess_breach_obligations`

Assess breach notification requirements by jurisdiction and data type.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `incident_description` | string | **Yes** | Short incident summary for breach notification routing. |
| `jurisdictions` | string[] | **Yes** | Impacted jurisdictions, e.g. `EU`, `US-FL`, `US-TX`. |
| `data_types` | string[] | **Yes** | Impacted data category IDs or plain-language labels. |
| `as_of_date` | string | No | Evaluation date in `YYYY-MM-DD` format. |

---

### `create_remediation_backlog`

Create prioritized remediation backlog from current and target control state.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `current_state` | object | **Yes** | Current control posture or assessment findings. |
| `target_baseline` | object | **Yes** | Target control baseline from `build_control_baseline`. |

---

## Financial-Specific Tools

### `classify_financial_entity`

Classify a financial entity under DORA and national supervisory context.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity_description` | string | **Yes** | Narrative of legal entity, licenses, and activity profile. |
| `services` | string[] | **Yes** | Primary services: `payments`, `lending`, `custody`, `brokerage`, etc. |
| `jurisdiction` | string | **Yes** | Primary jurisdiction code for supervisory classification. |

---

### `scope_pci_dss`

Scope PCI DSS boundaries and determine probable SAQ type.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `payment_flow` | string | **Yes** | Payment flow narrative including channel and processor handoff. |
| `data_stored` | string[] | **Yes** | Cardholder data elements stored, processed, or transmitted. |
| `architecture` | string | **Yes** | Architecture context: `hosted page`, `redirect`, `direct post`, `tokenized`, etc. |

---

### `assess_swift_csp`

Assess SWIFT CSP mandatory and advisory controls based on architecture and role.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `architecture_type` | string | **Yes** | SWIFT connectivity pattern: `service bureau`, `Alliance Access`, etc. |
| `operator_role` | string | **Yes** | Operational role interacting with SWIFT infrastructure. |

---

### `classify_digital_asset_service`

Classify digital asset services for MiCA and US state licensing context.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service_description` | string | **Yes** | Digital asset business model and offered functions. |
| `asset_types` | string[] | **Yes** | Supported asset categories: `stablecoins`, `utility tokens`, `securities tokens`, etc. |
| `jurisdictions` | string[] | **Yes** | Target jurisdictions for licensing and regulatory classification. |
