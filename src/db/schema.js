export const schemaSql = `
CREATE TABLE IF NOT EXISTS architecture_patterns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  components TEXT NOT NULL,
  trust_boundaries TEXT NOT NULL,
  data_flows TEXT NOT NULL,
  integration_points TEXT NOT NULL,
  known_weaknesses TEXT,
  applicable_standards TEXT,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS data_categories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  boundary_conditions TEXT,
  jurisdiction_protections TEXT NOT NULL,
  deidentification_requirements TEXT,
  cross_border_constraints TEXT,
  regulation_refs TEXT,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_scenarios (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  attack_narrative TEXT,
  mitre_mapping TEXT,
  affected_patterns TEXT,
  affected_data_categories TEXT,
  likelihood_factors TEXT,
  impact_dimensions TEXT,
  regulation_refs TEXT,
  control_refs TEXT,
  detection_indicators TEXT,
  historical_incidents TEXT,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS technical_standards (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT,
  publisher TEXT NOT NULL,
  scope TEXT NOT NULL,
  key_clauses TEXT,
  control_mappings TEXT,
  regulation_mappings TEXT,
  implementation_guidance TEXT,
  licensing_restrictions TEXT,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applicability_rules (
  id TEXT PRIMARY KEY,
  condition_json TEXT NOT NULL,
  obligation_json TEXT NOT NULL,
  obligation_type TEXT,
  priority INTEGER,
  conflict_group TEXT,
  effective_from TEXT,
  effective_to TEXT,
  rationale TEXT NOT NULL,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_artifacts (
  id TEXT PRIMARY KEY,
  audit_type TEXT NOT NULL,
  artifact_name TEXT NOT NULL,
  description TEXT NOT NULL,
  mandatory INTEGER NOT NULL,
  retention_period TEXT,
  template_ref TEXT,
  regulation_basis TEXT,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_registry (
  id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL,
  name TEXT NOT NULL,
  content TEXT NOT NULL,
  provenance TEXT NOT NULL,
  license TEXT NOT NULL,
  refresh_cadence TEXT NOT NULL,
  source_url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS us_state_breach_profiles (
  jurisdiction TEXT PRIMARY KEY,
  profile_json TEXT NOT NULL,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS obligation_nodes (
  id TEXT PRIMARY KEY,
  jurisdiction TEXT NOT NULL,
  obligation_type TEXT NOT NULL,
  regulation_id TEXT NOT NULL,
  standard_id TEXT,
  trigger_json TEXT,
  exceptions_json TEXT,
  deadline_json TEXT,
  penalties_json TEXT,
  evidence_refs_json TEXT,
  priority INTEGER,
  confidence TEXT,
  effective_from TEXT,
  effective_to TEXT,
  source_rule_id TEXT,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS obligation_edges (
  id TEXT PRIMARY KEY,
  from_node_id TEXT NOT NULL,
  to_node_id TEXT NOT NULL,
  relation_type TEXT NOT NULL,
  rationale TEXT,
  last_updated TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS db_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS architecture_patterns_fts USING fts5(
  id UNINDEXED,
  name,
  description,
  components,
  content=''
);

CREATE VIRTUAL TABLE IF NOT EXISTS threat_scenarios_fts USING fts5(
  id UNINDEXED,
  name,
  description,
  attack_narrative,
  content=''
);

CREATE VIRTUAL TABLE IF NOT EXISTS technical_standards_fts USING fts5(
  id UNINDEXED,
  name,
  scope,
  key_clauses,
  content=''
);

CREATE VIRTUAL TABLE IF NOT EXISTS data_categories_fts USING fts5(
  id UNINDEXED,
  name,
  description,
  boundary_conditions,
  content=''
);
`;
