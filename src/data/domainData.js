const isoDate = "2026-02-18T00:00:00Z";

export const authoritativeSources = [
  {
    id: "src-pci-ssc",
    source_type: "standard",
    name: "PCI Security Standards Council",
    content: "PCI DSS 4.0, SAQ guidance, PCI program documentation",
    provenance: "PCI SSC official publications",
    license: "PCI SSC license (free access)",
    refresh_cadence: "per version",
    source_url: "https://www.pcisecuritystandards.org/"
  },
  {
    id: "src-swift",
    source_type: "standard",
    name: "SWIFT",
    content: "Customer Security Programme control framework",
    provenance: "SWIFT official documentation and attestation guidance",
    license: "SWIFT membership (public summary)",
    refresh_cadence: "annual",
    source_url: "https://www.swift.com/your-needs/cyber-security/customer-security-programme-csp"
  },
  {
    id: "src-eba",
    source_type: "regulation",
    name: "European Banking Authority",
    content: "DORA RTS/ITS, PSD2 RTS on SCA",
    provenance: "EBA regulatory technical standards",
    license: "Free access (EU)",
    refresh_cadence: "per publication",
    source_url: "https://www.eba.europa.eu/"
  },
  {
    id: "src-esma",
    source_type: "regulation",
    name: "European Securities and Markets Authority",
    content: "MiFID II and MiCA technical standards",
    provenance: "ESMA public regulations and guidance",
    license: "Free access (EU)",
    refresh_cadence: "per publication",
    source_url: "https://www.esma.europa.eu/"
  },
  {
    id: "src-eiopa",
    source_type: "regulation",
    name: "European Insurance and Occupational Pensions Authority",
    content: "Solvency II and insurance ITS guidance",
    provenance: "EIOPA regulations and consultation papers",
    license: "Free access (EU)",
    refresh_cadence: "per publication",
    source_url: "https://www.eiopa.europa.eu/"
  },
  {
    id: "src-bafin",
    source_type: "supervisory",
    name: "BaFin",
    content: "BAIT/VAIT/KAIT supervisory guidance",
    provenance: "BaFin ICT security circulars",
    license: "Free access (DE)",
    refresh_cadence: "per update",
    source_url: "https://www.bafin.de/"
  },
  {
    id: "src-us-bank-regulators",
    source_type: "regulation",
    name: "Federal Reserve / OCC / FDIC",
    content: "US banking cybersecurity examination guidance",
    provenance: "US federal regulator publications",
    license: "Public domain (US government)",
    refresh_cadence: "per publication",
    source_url: "https://www.federalreserve.gov/"
  },
  {
    id: "src-fs-isac",
    source_type: "threat-intel",
    name: "FS-ISAC",
    content: "Financial sector threat intelligence and controls guidance",
    provenance: "Member bulletins and public summaries",
    license: "Membership (public summaries)",
    refresh_cadence: "continuous",
    source_url: "https://www.fsisac.com/"
  },
  {
    id: "src-nist",
    source_type: "standard",
    name: "NIST",
    content: "Financial sector cybersecurity profiles",
    provenance: "NIST special publications",
    license: "Public domain (US government)",
    refresh_cadence: "per revision",
    source_url: "https://www.nist.gov/"
  }
];

export const dataCategories = [
  {
    id: "dc-npi",
    name: "NPI",
    description: "Nonpublic personal information under GLBA.",
    boundary_conditions: "Includes personally identifiable customer financial information and inferences.",
    jurisdiction_protections: {
      US: { regime: ["GLBA"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.DP-03"] },
      "US-CA": { regime: ["GLBA", "CCPA"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.DP-03"] },
      EU: { regime: ["GDPR"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02"] }
    },
    deidentification_requirements: ["Tokenization for analytics", "Mask direct identifiers before sharing"],
    cross_border_constraints: ["SCCs for EU to third-country transfers", "Vendor contractual privacy controls"],
    regulation_refs: [
      { regulation_id: "GLBA", section: "501(b)", foundation_mcp: "us-regulations" },
      { regulation_id: "GDPR", article: "6", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-card-data",
    name: "Payment card data",
    description: "PAN, CVV, track data, and PIN-related elements.",
    boundary_conditions: "Any system storing, processing, or transmitting PAN is in scope.",
    jurisdiction_protections: {
      US: { regime: ["PCI_DSS"], tier: "critical", controls: ["SCF.CR-03", "SCF.EN-01", "SCF.NW-06"] },
      DE: { regime: ["PCI_DSS", "GDPR", "BDSG"], tier: "critical", controls: ["SCF.CR-03", "SCF.EN-01", "SCF.NW-06"] },
      EU: { regime: ["PCI_DSS", "GDPR"], tier: "critical", controls: ["SCF.CR-03", "SCF.EN-01", "SCF.NW-06"] }
    },
    deidentification_requirements: ["PAN truncation", "Tokenization", "Do not store CVV after authorization"],
    cross_border_constraints: ["Card network localization rules", "GDPR transfer mechanisms"],
    regulation_refs: [
      { regulation_id: "PCI_DSS_4_0", clause: "Req 3", foundation_mcp: "security-controls" },
      { regulation_id: "GDPR", article: "32", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-account-data",
    name: "Account data",
    description: "Account numbers, balances, statements, and transaction histories.",
    boundary_conditions: "Includes current account, card account, and custody account records.",
    jurisdiction_protections: {
      US: { regime: ["GLBA"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02"] },
      EU: { regime: ["GDPR", "PSD2"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.AU-02"] }
    },
    deidentification_requirements: ["Aggregate or hash account identifiers for analytics"],
    cross_border_constraints: ["Bank secrecy overlays may restrict transfers"],
    regulation_refs: [
      { regulation_id: "GLBA", section: "501", foundation_mcp: "us-regulations" },
      { regulation_id: "PSD2", article: "66", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-trading",
    name: "Trading data",
    description: "Order flow, positions, execution and market data records.",
    boundary_conditions: "Includes algo parameters where they influence client execution.",
    jurisdiction_protections: {
      US: { regime: ["REG_NMS"], tier: "high", controls: ["SCF.AU-02", "SCF.CM-05"] },
      EU: { regime: ["MiFID_II", "MAR"], tier: "high", controls: ["SCF.AU-02", "SCF.CM-05"] }
    },
    deidentification_requirements: ["Mask counterparties in non-regulatory analytics"],
    cross_border_constraints: ["Local market abuse reporting obligations persist"],
    regulation_refs: [
      { regulation_id: "MiFID_II", article: "16", foundation_mcp: "eu-regulations" },
      { regulation_id: "MAR", article: "12", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-kyc-aml",
    name: "KYC/AML data",
    description: "Identity evidence, beneficial ownership, sanctions and PEP screening information.",
    boundary_conditions: "Includes verification artifacts and monitoring outcomes.",
    jurisdiction_protections: {
      US: { regime: ["BSA_AML", "OFAC"], tier: "critical", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.IR-03"] },
      EU: { regime: ["AMLD5", "AMLD6"], tier: "critical", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.IR-03"] }
    },
    deidentification_requirements: ["Data minimization for model training", "Retention per AML mandates"],
    cross_border_constraints: ["Travel rule obligations for virtual asset service providers"],
    regulation_refs: [
      { regulation_id: "AMLD5", article: "13", foundation_mcp: "eu-regulations" },
      { regulation_id: "BSA", section: "5318", foundation_mcp: "us-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-credit",
    name: "Credit data",
    description: "Credit history, bureau scores, and underwriting data.",
    boundary_conditions: "Includes AI-driven decision features and adverse action rationale.",
    jurisdiction_protections: {
      US: { regime: ["FCRA", "ECOA"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.GV-04"] },
      "US-CA": { regime: ["FCRA", "ECOA", "CCPA"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.GV-04"] },
      EU: { regime: ["GDPR"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02", "SCF.GV-04"] }
    },
    deidentification_requirements: ["Bias testing data should be pseudonymized where possible"],
    cross_border_constraints: ["Automated decision transparency duties vary by jurisdiction"],
    regulation_refs: [
      { regulation_id: "FCRA", section: "604", foundation_mcp: "us-regulations" },
      { regulation_id: "GDPR", article: "22", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-insurance",
    name: "Insurance data",
    description: "Policy, underwriting, claims, and actuarial datasets.",
    boundary_conditions: "May include special-category personal data in health lines.",
    jurisdiction_protections: {
      US: { regime: ["STATE_INSURANCE"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02"] },
      EU: { regime: ["Solvency_II", "GDPR"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02"] },
      NL: { regime: ["Solvency_II", "GDPR"], tier: "high", controls: ["SCF.AC-01", "SCF.DS-02"] }
    },
    deidentification_requirements: ["Claims analytics should de-identify beneficiaries when feasible"],
    cross_border_constraints: ["Reinsurance transfer requires contract and privacy controls"],
    regulation_refs: [
      { regulation_id: "Solvency_II", article: "41", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-digital-asset",
    name: "Digital asset data",
    description: "Wallet addresses, custody keys metadata, and ledger transactions.",
    boundary_conditions: "Private keys are treated as critical secrets, not personal data alone.",
    jurisdiction_protections: {
      EU: { regime: ["MiCA", "AMLD5"], tier: "critical", controls: ["SCF.CR-03", "SCF.KM-01", "SCF.IR-03"] },
      US: { regime: ["STATE_MTL", "BSA_AML"], tier: "critical", controls: ["SCF.CR-03", "SCF.KM-01", "SCF.IR-03"] }
    },
    deidentification_requirements: ["On-chain analytics should limit direct identity linkage"],
    cross_border_constraints: ["Travel Rule applies for qualifying transfers"],
    regulation_refs: [
      { regulation_id: "MiCA", article: "63", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-swift",
    name: "SWIFT messaging",
    description: "MT/MX payment and correspondent banking messages.",
    boundary_conditions: "Includes FIN, FileAct, and message metadata retained for screening.",
    jurisdiction_protections: {
      US: { regime: ["SWIFT_CSP", "OFAC"], tier: "critical", controls: ["SCF.AC-01", "SCF.AU-02", "SCF.NW-06"] },
      EU: { regime: ["SWIFT_CSP", "AMLD"], tier: "critical", controls: ["SCF.AC-01", "SCF.AU-02", "SCF.NW-06"] }
    },
    deidentification_requirements: ["Sanctions and AML records must preserve forensic traceability"],
    cross_border_constraints: ["Cross-border correspondent chains require sanctions and AML checks"],
    regulation_refs: [
      { regulation_id: "SWIFT_CSP", clause: "Mandatory Controls", foundation_mcp: "security-controls" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-open-banking",
    name: "Open banking data",
    description: "API account/transaction data and consent records for AIS/PIS.",
    boundary_conditions: "Includes customer consents, token scopes, and TPP registration details.",
    jurisdiction_protections: {
      EU: { regime: ["PSD2", "GDPR"], tier: "high", controls: ["SCF.AC-01", "SCF.NW-06", "SCF.DS-02"] },
      US: { regime: ["FDX"], tier: "medium", controls: ["SCF.AC-01", "SCF.NW-06"] }
    },
    deidentification_requirements: ["Remove customer identifiers for product analytics"],
    cross_border_constraints: ["Cross-border TPP calls require contractual and consent safeguards"],
    regulation_refs: [
      { regulation_id: "PSD2", article: "97", foundation_mcp: "eu-regulations" }
    ],
    last_updated: isoDate
  },
  {
    id: "dc-biometric",
    name: "Biometric auth data",
    description: "Facial, voice, and behavioral biometrics for authentication.",
    boundary_conditions: "Template storage and replay risks require enhanced safeguards.",
    jurisdiction_protections: {
      EU: { regime: ["GDPR_ART_9"], tier: "critical", controls: ["SCF.EN-01", "SCF.AC-01", "SCF.DS-02"] },
      "US-IL": { regime: ["BIPA"], tier: "critical", controls: ["SCF.EN-01", "SCF.AC-01", "SCF.DS-02"] },
      "US-CA": { regime: ["CCPA"], tier: "high", controls: ["SCF.EN-01", "SCF.AC-01"] }
    },
    deidentification_requirements: ["Store only encrypted templates", "No raw biometric export"],
    cross_border_constraints: ["Explicit consent and local labor law constraints may apply"],
    regulation_refs: [
      { regulation_id: "GDPR", article: "9", foundation_mcp: "eu-regulations" },
      { regulation_id: "BIPA", section: "15", foundation_mcp: "us-regulations" }
    ],
    last_updated: isoDate
  }
];

export const architecturePatterns = [
  {
    id: "fs-core-banking",
    name: "Core Banking System",
    category: "banking",
    description: "Core ledger and product servicing architecture for retail and corporate banking.",
    components: [
      "core ledger",
      "account management",
      "product engine",
      "transaction processing",
      "general ledger interface",
      "regulatory reporting"
    ],
    trust_boundaries: [
      { boundary: "customer channels to API layer", rationale: "internet-originated risk and identity trust transition" },
      { boundary: "API layer to core ledger", rationale: "high-integrity posting boundary" },
      { boundary: "core systems to reporting zone", rationale: "separate data handling and disclosure controls" }
    ],
    data_flows: [
      { source: "channels", destination: "transaction processing", data_type: "account data", protocol: "HTTPS", encryption: "TLS 1.2+" },
      { source: "transaction processing", destination: "core ledger", data_type: "account data", protocol: "internal RPC", encryption: "mTLS" },
      { source: "core ledger", destination: "regulatory reporting", data_type: "account/trading data", protocol: "batch", encryption: "at-rest + in-transit" }
    ],
    integration_points: ["card processors", "payment rails", "credit bureaus", "regulatory gateways"],
    known_weaknesses: ["batch window privilege escalation", "insufficient segregation of duties"],
    applicable_standards: ["ISO_20022", "SOX_ITGC", "DORA"],
    last_updated: isoDate
  },
  {
    id: "fs-payments",
    name: "Payment Processing",
    category: "payments",
    description: "Card and account-based payment processing including authorization, fraud, and settlement.",
    components: [
      "payment gateway",
      "acquiring processor",
      "card network interface",
      "settlement engine",
      "fraud detection",
      "3DS server"
    ],
    trust_boundaries: [
      { boundary: "merchant integration boundary", rationale: "external input and replay/fraud risk" },
      { boundary: "cardholder data environment boundary", rationale: "PCI DSS scope control" },
      { boundary: "settlement boundary", rationale: "high-value irreversible financial postings" }
    ],
    data_flows: [
      { source: "merchant", destination: "gateway", data_type: "payment card data", protocol: "HTTPS", encryption: "TLS 1.2+" },
      { source: "gateway", destination: "network interface", data_type: "PAN/token", protocol: "ISO8583/API", encryption: "mTLS" },
      { source: "network interface", destination: "settlement engine", data_type: "clearing data", protocol: "batch/API", encryption: "TLS + encryption at rest" }
    ],
    integration_points: ["card schemes", "acquirers", "issuer processors", "fraud intelligence feeds"],
    known_weaknesses: ["scope creep into CDE", "insufficient 3DS telemetry checks"],
    applicable_standards: ["PCI_DSS_4_0", "EMV_3DS", "ISO_20022"],
    last_updated: isoDate
  },
  {
    id: "fs-trading",
    name: "Trading Platform",
    category: "markets",
    description: "Order management, execution and post-trade stack for electronic trading.",
    components: [
      "order management system",
      "execution management system",
      "market data feed",
      "risk engine",
      "post-trade processing",
      "regulatory reporting"
    ],
    trust_boundaries: [
      { boundary: "market connectivity boundary", rationale: "exchange and broker trust controls" },
      { boundary: "algo model boundary", rationale: "high-impact automated decision controls" }
    ],
    data_flows: [
      { source: "client order channels", destination: "OMS", data_type: "trading data", protocol: "FIX", encryption: "TLS/leased line controls" },
      { source: "OMS", destination: "EMS", data_type: "order flow", protocol: "FIX", encryption: "mTLS" }
    ],
    integration_points: ["venues", "market data vendors", "surveillance tooling"],
    known_weaknesses: ["parameter tampering", "latency manipulation"],
    applicable_standards: ["FIX", "MiFID_II", "STIX_TAXII"],
    last_updated: isoDate
  },
  {
    id: "fs-open-banking",
    name: "Open Banking / PSD2",
    category: "open-banking",
    description: "TPP onboarding and AIS/PIS API ecosystem with consent and SCA controls.",
    components: [
      "TPP registration",
      "consent management",
      "API gateway",
      "AIS service",
      "PIS service",
      "SCA engine"
    ],
    trust_boundaries: [
      { boundary: "TPP boundary", rationale: "third-party trust with delegated consent" },
      { boundary: "consent decision boundary", rationale: "legal basis and scope enforcement" }
    ],
    data_flows: [
      { source: "TPP", destination: "API gateway", data_type: "open banking data", protocol: "REST", encryption: "TLS + cert pinning" },
      { source: "gateway", destination: "consent management", data_type: "consent scope", protocol: "internal API", encryption: "mTLS" }
    ],
    integration_points: ["eIDAS/QWAC services", "customer identity providers"],
    known_weaknesses: ["scope escalation", "consent replay", "SCA downgrade"],
    applicable_standards: ["Berlin_Group_NextGenPSD2", "PSD2_RTS_SCA", "FDX_API"],
    last_updated: isoDate
  },
  {
    id: "fs-digital-lending",
    name: "Digital Lending Platform",
    category: "lending",
    description: "Loan origination and servicing with automated credit decisioning.",
    components: [
      "application intake",
      "credit decisioning",
      "underwriting engine",
      "loan origination",
      "servicing",
      "collections"
    ],
    trust_boundaries: [
      { boundary: "applicant data boundary", rationale: "sensitive PII and credit data protection" },
      { boundary: "model governance boundary", rationale: "fair lending and explainability controls" }
    ],
    data_flows: [
      { source: "applicant", destination: "intake", data_type: "credit data", protocol: "HTTPS", encryption: "TLS 1.2+" },
      { source: "intake", destination: "decisioning", data_type: "credit score + features", protocol: "internal API", encryption: "mTLS" }
    ],
    integration_points: ["credit bureaus", "identity verification providers", "collections agencies"],
    known_weaknesses: ["feature tampering", "adverse-action traceability gaps"],
    applicable_standards: ["FCRA", "ECOA", "ISO_27018"],
    last_updated: isoDate
  },
  {
    id: "fs-wealth",
    name: "Wealth Management",
    category: "wealth",
    description: "Portfolio and advisory systems with custody and reporting integrations.",
    components: ["portfolio management", "client reporting", "advisory tools", "custody integration", "compliance checks"],
    trust_boundaries: [
      { boundary: "advisor-client portal boundary", rationale: "personalized investment data access control" }
    ],
    data_flows: [
      { source: "advisor tools", destination: "portfolio core", data_type: "trading/account data", protocol: "API", encryption: "TLS" }
    ],
    integration_points: ["custodians", "market data", "KYC services"],
    known_weaknesses: ["excessive advisor privilege"],
    applicable_standards: ["MiFID_II", "ISO_27017"],
    last_updated: isoDate
  },
  {
    id: "fs-insurance-core",
    name: "Insurance Core System",
    category: "insurance",
    description: "Policy admin, claims, underwriting and actuarial processing stack.",
    components: ["policy administration", "claims management", "underwriting", "actuarial", "reinsurance", "distribution"],
    trust_boundaries: [
      { boundary: "claims intake boundary", rationale: "high volume personal data and fraud input channel" }
    ],
    data_flows: [
      { source: "brokers/agents", destination: "policy admin", data_type: "insurance data", protocol: "API/SFTP", encryption: "TLS + at-rest encryption" }
    ],
    integration_points: ["reinsurers", "medical assessment providers", "fraud bureaus"],
    known_weaknesses: ["claims fraud model poisoning"],
    applicable_standards: ["Solvency_II", "DORA"],
    last_updated: isoDate
  },
  {
    id: "fs-swift",
    name: "SWIFT Messaging",
    category: "payments",
    description: "SWIFT Alliance and sanctions screening flows for correspondent banking.",
    components: [
      "alliance access/lite",
      "message validation",
      "sanctions screening",
      "correspondent banking gateway",
      "reconciliation"
    ],
    trust_boundaries: [
      { boundary: "operator workstation boundary", rationale: "credential theft and privileged misuse risk" },
      { boundary: "message release boundary", rationale: "tamper-proof authorization requirements" }
    ],
    data_flows: [
      { source: "payment operations", destination: "alliance", data_type: "SWIFT messaging", protocol: "SWIFTNet", encryption: "SWIFT controls" },
      { source: "alliance", destination: "sanctions screening", data_type: "SWIFT message content", protocol: "internal API", encryption: "mTLS" }
    ],
    integration_points: ["SWIFT network", "sanctions engines", "core payments"],
    known_weaknesses: ["shared operator credentials", "weak segregation in release chain"],
    applicable_standards: ["SWIFT_CSP", "ISO_20022"],
    last_updated: isoDate
  },
  {
    id: "fs-aml",
    name: "AML/KYC Platform",
    category: "compliance",
    description: "Onboarding, sanctions, monitoring, and SAR case management platform.",
    components: [
      "customer onboarding",
      "identity verification",
      "transaction monitoring",
      "sanctions screening",
      "case management",
      "SAR filing"
    ],
    trust_boundaries: [
      { boundary: "external data provider boundary", rationale: "third-party identity and watchlist integrity" }
    ],
    data_flows: [
      { source: "core banking", destination: "transaction monitoring", data_type: "KYC/AML data", protocol: "stream/batch", encryption: "TLS + signed feeds" }
    ],
    integration_points: ["OFAC lists", "EU sanctions feeds", "law enforcement reporting gateways"],
    known_weaknesses: ["rule bypass via threshold fragmentation"],
    applicable_standards: ["AMLD6", "BSA_AML"],
    last_updated: isoDate
  },
  {
    id: "fs-digital-assets",
    name: "Digital Asset / Crypto",
    category: "digital-assets",
    description: "Wallet and custody architecture for digital asset service providers.",
    components: [
      "wallet infrastructure",
      "custody (hot/cold)",
      "exchange integration",
      "defi interface",
      "compliance monitoring"
    ],
    trust_boundaries: [
      { boundary: "key management boundary", rationale: "critical cryptographic secret lifecycle boundary" },
      { boundary: "smart contract boundary", rationale: "immutable code risk" }
    ],
    data_flows: [
      { source: "customers", destination: "wallet service", data_type: "digital asset data", protocol: "API", encryption: "TLS + HSM-backed keys" }
    ],
    integration_points: ["blockchain nodes", "liquidity venues", "travel rule providers"],
    known_weaknesses: ["hot wallet exposure", "bridge protocol dependency risk"],
    applicable_standards: ["MiCA", "FATF_TRAVEL_RULE"],
    last_updated: isoDate
  },
  {
    id: "fs-instant-pay",
    name: "Instant/Real-Time Payments",
    category: "payments",
    description: "SEPA Instant/FedNow/RTP payment stack with liquidity and fraud controls.",
    components: [
      "instant payment gateway",
      "iso 20022 messaging",
      "fraud scoring",
      "liquidity management",
      "settlement interface"
    ],
    trust_boundaries: [
      { boundary: "real-time authorization boundary", rationale: "irreversible payment risk under short decision window" }
    ],
    data_flows: [
      { source: "customer channel", destination: "instant gateway", data_type: "payment data", protocol: "API", encryption: "TLS" }
    ],
    integration_points: ["FedNow", "RTP", "SEPA Instant CSMs"],
    known_weaknesses: ["real-time mule account fraud"],
    applicable_standards: ["ISO_20022", "DORA"],
    last_updated: isoDate
  },
  {
    id: "fs-regtech",
    name: "Regulatory Reporting",
    category: "regtech",
    description: "Data aggregation and report production architecture for financial supervisory reporting.",
    components: ["data aggregation", "report generation", "submission gateway", "reconciliation", "audit trail"],
    trust_boundaries: [
      { boundary: "regulatory submission boundary", rationale: "integrity and non-repudiation controls for filed data" }
    ],
    data_flows: [
      { source: "source systems", destination: "reporting engine", data_type: "trading/account/insurance data", protocol: "batch/API", encryption: "TLS + signing" }
    ],
    integration_points: ["xbrl gateways", "supervisory portals"],
    known_weaknesses: ["manual data transformations without traceability"],
    applicable_standards: ["XBRL", "SOX_ITGC"],
    last_updated: isoDate
  }
];

export const threatScenarios = [
  {
    id: "th-core-ledger-manipulation",
    name: "Core ledger manipulation",
    category: "core-banking",
    description: "Unauthorized balance or posting changes in core banking systems.",
    attack_narrative: "Attacker gains privileged access to posting APIs, submits fraudulent reversal and adjustment entries, then suppresses reconciliation alerts.",
    mitre_mapping: ["T1078", "T1565.001", "T1119"],
    affected_patterns: ["fs-core-banking"],
    affected_data_categories: ["dc-account-data", "dc-npi"],
    likelihood_factors: ["high-value target", "legacy privileged workflows"],
    impact_dimensions: { patient_safety: "none", financial: "severe", regulatory: "high", reputational: "high" },
    regulation_refs: [
      { regulation_id: "SOX", section: "404", foundation_mcp: "us-regulations" },
      { regulation_id: "DORA", article: "9", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF.AC-01", "SCF.CM-05", "SCF.AU-02"],
    detection_indicators: ["anomalous privileged posting patterns", "reconciliation drift spikes"],
    historical_incidents: ["Financial statement control failures involving privileged posting abuse"],
    last_updated: isoDate
  },
  {
    id: "th-account-takeover-scale",
    name: "Account takeover at scale",
    category: "core-banking",
    description: "Credential stuffing and session hijack campaigns on digital banking portals.",
    attack_narrative: "Adversaries automate login attempts, bypass weak MFA enrollment, and trigger payout fraud before anti-fraud controls activate.",
    mitre_mapping: ["T1110.004", "T1539"],
    affected_patterns: ["fs-core-banking", "fs-open-banking"],
    affected_data_categories: ["dc-account-data", "dc-open-banking", "dc-biometric"],
    likelihood_factors: ["high credential reuse rates", "bot-enabled campaigns"],
    impact_dimensions: { financial: "high", regulatory: "high", reputational: "high" },
    regulation_refs: [
      { regulation_id: "PSD2", article: "97", foundation_mcp: "eu-regulations" },
      { regulation_id: "GLBA", section: "501(b)", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF.AC-01", "SCF.NW-06", "SCF.IR-03"],
    detection_indicators: ["credential stuffing spike", "session token anomalies"],
    historical_incidents: ["Mass online banking ATO campaigns"],
    last_updated: isoDate
  },
  {
    id: "th-cnp-fraud",
    name: "Card-not-present fraud",
    category: "payments",
    description: "Fraudulent remote card transactions exploiting weak controls in ecommerce payment flows.",
    attack_narrative: "Attackers test card lists and abuse poor challenge rules to authorize stolen cards.",
    mitre_mapping: ["T1656", "T1078"],
    affected_patterns: ["fs-payments", "fs-instant-pay"],
    affected_data_categories: ["dc-card-data"],
    likelihood_factors: ["high automation", "stolen data market availability"],
    impact_dimensions: { financial: "high", regulatory: "medium", reputational: "medium" },
    regulation_refs: [
      { regulation_id: "PCI_DSS_4_0", clause: "Req 6", foundation_mcp: "security-controls" },
      { regulation_id: "PCI_DSS_4_0", clause: "Req 11", foundation_mcp: "security-controls" }
    ],
    control_refs: ["SCF.SD-03", "SCF.TV-01", "SCF.AU-02"],
    detection_indicators: ["velocity anomalies", "BIN attack signatures"],
    historical_incidents: ["Large-scale CNP fraud incidents in ecommerce"],
    last_updated: isoDate
  },
  {
    id: "th-swift-credential-theft",
    name: "SWIFT operator credential theft",
    category: "swift",
    description: "Compromise of SWIFT Alliance operator credentials leading to fraudulent payment instruction.",
    attack_narrative: "Adversary compromises operator endpoint and message workflows to submit unauthorized MT messages with delayed detection.",
    mitre_mapping: ["T1078", "T1552", "T1565.001"],
    affected_patterns: ["fs-swift"],
    affected_data_categories: ["dc-swift", "dc-account-data"],
    likelihood_factors: ["targeted organized crime", "legacy workstation hardening gaps"],
    impact_dimensions: { financial: "severe", regulatory: "high", reputational: "high" },
    regulation_refs: [
      { regulation_id: "SWIFT_CSP", clause: "Mandatory Controls", foundation_mcp: "security-controls" },
      { regulation_id: "DORA", article: "9", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF.AC-01", "SCF.AU-02", "SCF.NW-06"],
    detection_indicators: ["out-of-hours release actions", "message pattern anomalies"],
    historical_incidents: ["Bangladesh Bank-style SWIFT fraud pattern"],
    last_updated: isoDate
  },
  {
    id: "th-openbanking-tpp-impersonation",
    name: "TPP impersonation",
    category: "open-banking",
    description: "Fraudulent third-party provider credentials used to access AIS/PIS APIs.",
    attack_narrative: "Attacker forges or steals TPP credentials and manipulates consent scope for unauthorized access.",
    mitre_mapping: ["T1586", "T1550", "T1190"],
    affected_patterns: ["fs-open-banking"],
    affected_data_categories: ["dc-open-banking", "dc-account-data"],
    likelihood_factors: ["certificate lifecycle gaps", "API trust boundary complexity"],
    impact_dimensions: { financial: "high", regulatory: "high", reputational: "high" },
    regulation_refs: [
      { regulation_id: "PSD2", article: "97", foundation_mcp: "eu-regulations" },
      { regulation_id: "eIDAS", article: "24", foundation_mcp: "eu-regulations" }
    ],
    control_refs: ["SCF.AC-01", "SCF.CM-05", "SCF.NW-06"],
    detection_indicators: ["unexpected TPP certificate fingerprints", "scope escalation anomalies"],
    historical_incidents: ["API ecosystem impersonation incidents in fintech integrations"],
    last_updated: isoDate
  },
  {
    id: "th-sca-bypass-downgrade",
    name: "SCA bypass and downgrade attack",
    category: "open-banking",
    description: "Manipulation of payment auth flow to bypass strong customer authentication.",
    attack_narrative: "Attacker forces fallback methods and exploits weak challenge routing to execute unauthorized payments.",
    mitre_mapping: ["T1111", "T1556"],
    affected_patterns: ["fs-open-banking", "fs-payments"],
    affected_data_categories: ["dc-account-data", "dc-open-banking"],
    likelihood_factors: ["complex fallback logic", "legacy auth interoperability"],
    impact_dimensions: { financial: "high", regulatory: "high", reputational: "medium" },
    regulation_refs: [{ regulation_id: "PSD2_RTS_SCA", article: "4", foundation_mcp: "eu-regulations" }],
    control_refs: ["SCF.AC-01", "SCF.TV-01"],
    detection_indicators: ["unexpected low-assurance auth completions"],
    historical_incidents: ["Payment auth downgrade abuse"],
    last_updated: isoDate
  },
  {
    id: "th-trading-algo-tampering",
    name: "Trading algorithm parameter tampering",
    category: "trading",
    description: "Unauthorized changes to strategy parameters resulting in market abuse or losses.",
    attack_narrative: "Insider or attacker modifies order limits/latency controls to trigger manipulative behavior.",
    mitre_mapping: ["T1565.001", "T1078"],
    affected_patterns: ["fs-trading"],
    affected_data_categories: ["dc-trading"],
    likelihood_factors: ["high privileged concentration", "change management bypass"],
    impact_dimensions: { financial: "high", regulatory: "high", reputational: "high" },
    regulation_refs: [
      { regulation_id: "MiFID_II", article: "17", foundation_mcp: "eu-regulations" },
      { regulation_id: "SOX", section: "404", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF.CM-05", "SCF.AU-02", "SCF.GV-04"],
    detection_indicators: ["unauthorized parameter diffs", "anomalous order burst patterns"],
    historical_incidents: ["Algorithmic trading control failures"],
    last_updated: isoDate
  },
  {
    id: "th-market-data-poisoning",
    name: "Market data feed poisoning",
    category: "trading",
    description: "Tampering with market data inputs used by trading engines.",
    attack_narrative: "Compromised feed handlers inject manipulated pricing signals to influence automated execution.",
    mitre_mapping: ["T1565.001", "T1195"],
    affected_patterns: ["fs-trading"],
    affected_data_categories: ["dc-trading"],
    likelihood_factors: ["third-party dependencies", "high velocity automation"],
    impact_dimensions: { financial: "high", regulatory: "medium", reputational: "high" },
    regulation_refs: [{ regulation_id: "MiFID_II", article: "16", foundation_mcp: "eu-regulations" }],
    control_refs: ["SCF.CM-05", "SCF.NW-06"],
    detection_indicators: ["feed checksum mismatches", "venue divergence alerts"],
    historical_incidents: ["Feed anomalies impacting algo execution"],
    last_updated: isoDate
  },
  {
    id: "th-hot-wallet-key-extraction",
    name: "Hot wallet key extraction",
    category: "digital-assets",
    description: "Compromise of online custody keys enabling unauthorized transfer of digital assets.",
    attack_narrative: "Attackers exploit wallet infrastructure to access signing material and drain custodial accounts.",
    mitre_mapping: ["T1552", "T1027", "T1078"],
    affected_patterns: ["fs-digital-assets"],
    affected_data_categories: ["dc-digital-asset"],
    likelihood_factors: ["high attacker incentive", "operational key management complexity"],
    impact_dimensions: { financial: "severe", regulatory: "high", reputational: "high" },
    regulation_refs: [
      { regulation_id: "MiCA", article: "63", foundation_mcp: "eu-regulations" },
      { regulation_id: "BSA", section: "5318(h)", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF.KM-01", "SCF.AC-01", "SCF.IR-03"],
    detection_indicators: ["abnormal signing velocity", "unexpected key export attempts"],
    historical_incidents: ["Exchange wallet compromise events"],
    last_updated: isoDate
  },
  {
    id: "th-aml-rule-evasion",
    name: "Transaction monitoring rule evasion",
    category: "aml",
    description: "Structuring and synthetic identity tactics to avoid AML controls.",
    attack_narrative: "Bad actors split transfers and manipulate onboarding information to remain below alert thresholds.",
    mitre_mapping: ["T1036", "T1078"],
    affected_patterns: ["fs-aml", "fs-core-banking"],
    affected_data_categories: ["dc-kyc-aml", "dc-account-data"],
    likelihood_factors: ["high transaction volume", "static threshold rules"],
    impact_dimensions: { financial: "high", regulatory: "high", reputational: "high" },
    regulation_refs: [
      { regulation_id: "AMLD5", article: "33", foundation_mcp: "eu-regulations" },
      { regulation_id: "BSA", section: "5318", foundation_mcp: "us-regulations" }
    ],
    control_refs: ["SCF.GV-04", "SCF.AU-02", "SCF.IR-03"],
    detection_indicators: ["rapidly repeated low-value transfer chains", "identity mismatch patterns"],
    historical_incidents: ["Regulatory enforcement for ineffective AML monitoring"],
    last_updated: isoDate
  },
  {
    id: "th-reg-report-manipulation",
    name: "Regulatory reporting manipulation",
    category: "regtech",
    description: "Intentional or accidental tampering of supervisory submissions.",
    attack_narrative: "Adversary modifies XBRL pipeline transformations or suppresses reconciliation errors before filing.",
    mitre_mapping: ["T1565.001", "T1119"],
    affected_patterns: ["fs-regtech"],
    affected_data_categories: ["dc-account-data", "dc-trading", "dc-insurance"],
    likelihood_factors: ["manual intervention points", "tight filing deadlines"],
    impact_dimensions: { financial: "medium", regulatory: "high", reputational: "high" },
    regulation_refs: [{ regulation_id: "SOX", section: "302", foundation_mcp: "us-regulations" }],
    control_refs: ["SCF.AU-02", "SCF.CM-05"],
    detection_indicators: ["late-stage adjustment spikes", "broken lineage records"],
    historical_incidents: ["Regulatory fines for inaccurate reporting"],
    last_updated: isoDate
  }
];

export const technicalStandards = [
  {
    id: "std-pci-dss-4-0",
    name: "PCI DSS 4.0",
    version: "4.0",
    publisher: "PCI SSC",
    scope: "Payment card data protection",
    key_clauses: ["Req 3", "Req 6", "Req 8", "Req 10", "Req 11"],
    control_mappings: [
      { framework: "scf", control_id: "SCF.CR-03" },
      { framework: "scf", control_id: "SCF.AC-01" },
      { framework: "scf", control_id: "SCF.AU-02" }
    ],
    regulation_mappings: [{ regulation_id: "PCI_DSS_4_0", clause: "Req 3" }],
    implementation_guidance: "Constrain CDE scope, tokenize PAN, and enforce strong IAM with quarterly testing.",
    licensing_restrictions: "Public summary and requirements references only.",
    last_updated: isoDate
  },
  {
    id: "std-swift-csp",
    name: "SWIFT CSP",
    version: "2026",
    publisher: "SWIFT",
    scope: "SWIFT messaging security controls and attestation",
    key_clauses: ["Mandatory controls", "Architecture A1-A4", "Operator security"],
    control_mappings: [
      { framework: "scf", control_id: "SCF.AC-01" },
      { framework: "scf", control_id: "SCF.NW-06" },
      { framework: "scf", control_id: "SCF.AU-02" }
    ],
    regulation_mappings: [{ regulation_id: "DORA", article: "9" }],
    implementation_guidance: "Segregate operator roles, harden endpoints, and verify release workflow integrity.",
    licensing_restrictions: "Detailed control text is membership-restricted.",
    last_updated: isoDate
  },
  {
    id: "std-iso-20022",
    name: "ISO 20022",
    version: "2019+",
    publisher: "ISO",
    scope: "Financial messaging data model and message definitions",
    key_clauses: ["Message definitions", "Business components", "Validation constraints"],
    control_mappings: [
      { framework: "scf", control_id: "SCF.DS-02" },
      { framework: "scf", control_id: "SCF.NW-06" }
    ],
    regulation_mappings: [{ regulation_id: "PSD2", article: "95" }],
    implementation_guidance: "Apply schema validation and message signing controls at ingress and egress.",
    licensing_restrictions: "Standard text subject to ISO licensing.",
    last_updated: isoDate
  },
  {
    id: "std-fdx-api",
    name: "FDX API",
    version: "6.x",
    publisher: "Financial Data Exchange",
    scope: "US open banking API interoperability",
    key_clauses: ["Consent model", "Token scope", "Security profile"],
    control_mappings: [{ framework: "scf", control_id: "SCF.AC-01" }],
    regulation_mappings: [{ regulation_id: "GLBA", section: "501(b)" }],
    implementation_guidance: "Enforce least-privilege scopes and consent lifecycle tracking.",
    licensing_restrictions: "Specification access per FDX terms.",
    last_updated: isoDate
  },
  {
    id: "std-berlin-group",
    name: "Berlin Group NextGenPSD2",
    version: "1.3+",
    publisher: "Berlin Group",
    scope: "EU PSD2 API profile for AIS/PIS",
    key_clauses: ["AIS endpoints", "PIS endpoints", "consent resources"],
    control_mappings: [
      { framework: "scf", control_id: "SCF.AC-01" },
      { framework: "scf", control_id: "SCF.NW-06" }
    ],
    regulation_mappings: [{ regulation_id: "PSD2", article: "97" }],
    implementation_guidance: "Bind consent to customer auth and certificate identity, and monitor TPP scope usage.",
    licensing_restrictions: "Use profile summaries and references only.",
    last_updated: isoDate
  },
  {
    id: "std-uk-open-banking",
    name: "UK Open Banking Standard",
    version: "3.1+",
    publisher: "OBIE",
    scope: "UK open banking API and security profile",
    key_clauses: ["Read/Write APIs", "Security profile", "customer journey"],
    control_mappings: [{ framework: "scf", control_id: "SCF.AC-01" }],
    regulation_mappings: [{ regulation_id: "PSR", article: "SCA" }],
    implementation_guidance: "Maintain detached signatures and robust consent revocation handling.",
    licensing_restrictions: "Refer to OBIE publication terms.",
    last_updated: isoDate
  },
  {
    id: "std-emv-3ds",
    name: "3DS 2.x / EMV 3DS",
    version: "2.3",
    publisher: "EMVCo",
    scope: "Strong customer authentication for card-not-present flows",
    key_clauses: ["Challenge flows", "Frictionless scoring", "Authentication value"],
    control_mappings: [{ framework: "scf", control_id: "SCF.AC-01" }],
    regulation_mappings: [{ regulation_id: "PSD2_RTS_SCA", article: "2" }],
    implementation_guidance: "Use risk-based authentication with strict fallback controls.",
    licensing_restrictions: "Specification content under EMVCo terms.",
    last_updated: isoDate
  },
  {
    id: "std-iso-27017-27018",
    name: "ISO 27017/27018",
    version: "2015/2019",
    publisher: "ISO",
    scope: "Cloud security and PII protection",
    key_clauses: ["Cloud shared responsibility", "PII processor controls"],
    control_mappings: [{ framework: "scf", control_id: "SCF.DS-02" }],
    regulation_mappings: [{ regulation_id: "DORA", article: "28" }],
    implementation_guidance: "Apply cloud-native access boundaries and processor assurance evidence.",
    licensing_restrictions: "Clause-level references only.",
    last_updated: isoDate
  },
  {
    id: "std-nist-800-86",
    name: "NIST SP 800-86",
    version: "1.0",
    publisher: "NIST",
    scope: "Forensic techniques integration",
    key_clauses: ["Collection", "Examination", "Analysis", "Reporting"],
    control_mappings: [{ framework: "scf", control_id: "SCF.IR-03" }],
    regulation_mappings: [{ regulation_id: "GLBA", section: "501(b)" }],
    implementation_guidance: "Align fraud and breach investigations with forensic chain-of-custody.",
    licensing_restrictions: "Public domain.",
    last_updated: isoDate
  },
  {
    id: "std-fix-protocol",
    name: "FIX Protocol",
    version: "5.0 SP2",
    publisher: "FIX Trading Community",
    scope: "Trading message exchange",
    key_clauses: ["Session layer", "application message types", "recovery handling"],
    control_mappings: [{ framework: "scf", control_id: "SCF.NW-06" }],
    regulation_mappings: [{ regulation_id: "MiFID_II", article: "17" }],
    implementation_guidance: "Enforce signed sessions and strict sequence/duplication handling.",
    licensing_restrictions: "Use publicly available reference material.",
    last_updated: isoDate
  },
  {
    id: "std-xbrl",
    name: "XBRL",
    version: "2.1",
    publisher: "XBRL International",
    scope: "Regulatory reporting data format",
    key_clauses: ["taxonomy validation", "instance integrity"],
    control_mappings: [{ framework: "scf", control_id: "SCF.AU-02" }],
    regulation_mappings: [{ regulation_id: "SOX", section: "302" }],
    implementation_guidance: "Use deterministic transformation pipelines and lineage checks.",
    licensing_restrictions: "Public specification.",
    last_updated: isoDate
  },
  {
    id: "std-stix-taxii",
    name: "STIX/TAXII",
    version: "2.1",
    publisher: "OASIS",
    scope: "Threat intelligence sharing",
    key_clauses: ["indicator model", "collection APIs"],
    control_mappings: [{ framework: "scf", control_id: "SCF.IR-03" }],
    regulation_mappings: [{ regulation_id: "DORA", article: "13" }],
    implementation_guidance: "Integrate FS-ISAC feeds with detection engineering pipelines.",
    licensing_restrictions: "Open standard.",
    last_updated: isoDate
  }
];

export const applicabilityRules = [
  {
    id: "app-se-bank-payments",
    condition: {
      country: ["SE", "EU"],
      role: ["bank", "financial-entity"],
      system_types: ["fs-core-banking", "fs-payments", "payments"],
      data_types: ["dc-account-data", "dc-npi"]
    },
    obligation: {
      regulation_id: "DORA",
      article: "6",
      standard_id: "std-iso-27017-27018",
      confidence: "authoritative"
    },
    rationale: "Swedish and EU banks providing payments/lending are in-scope for DORA ICT risk management.",
    last_updated: isoDate
  },
  {
    id: "app-se-psd2",
    condition: {
      country: ["SE", "EU"],
      role: ["bank", "payment-institution", "fintech"],
      system_types: ["fs-open-banking", "payments", "open-banking"],
      data_types: ["dc-open-banking", "dc-account-data"]
    },
    obligation: {
      regulation_id: "PSD2",
      article: "97",
      standard_id: "std-berlin-group",
      confidence: "authoritative"
    },
    rationale: "PSD2 SCA obligations apply to payment and open banking services in Sweden/EU.",
    last_updated: isoDate
  },
  {
    id: "app-eu-gdpr-financial",
    condition: {
      country: ["SE", "DE", "NL", "EU"],
      role: ["bank", "insurance", "fintech", "payment-institution"],
      system_types: ["any"],
      data_types: ["dc-npi", "dc-account-data", "dc-credit", "dc-insurance", "dc-open-banking"]
    },
    obligation: {
      regulation_id: "GDPR",
      article: "32",
      standard_id: "std-iso-27017-27018",
      confidence: "authoritative"
    },
    rationale: "Financial processing of personal data in EU jurisdictions requires GDPR security of processing obligations.",
    last_updated: isoDate
  },
  {
    id: "app-us-ny-fintech",
    condition: {
      country: ["US-NY", "US"],
      role: ["fintech", "bank", "payment-institution"],
      system_types: ["fs-payments", "fs-digital-lending", "payments", "lending"],
      data_types: ["dc-npi", "dc-credit", "dc-card-data"]
    },
    obligation: {
      regulation_id: "GLBA",
      section: "501(b)",
      standard_id: "std-nist-800-86",
      confidence: "authoritative"
    },
    rationale: "US fintech lending/payments processing NPI are under GLBA safeguards expectations.",
    last_updated: isoDate
  },
  {
    id: "app-us-nydfs",
    condition: {
      country: ["US-NY"],
      role: ["fintech", "bank", "insurance"],
      system_types: ["any"],
      data_types: ["dc-npi", "dc-account-data", "dc-credit"]
    },
    obligation: {
      regulation_id: "NYDFS_CYBER_500",
      section: "500.17",
      standard_id: "std-stix-taxii",
      confidence: "authoritative"
    },
    rationale: "NYDFS cybersecurity regulation imposes incident reporting and cybersecurity program obligations.",
    last_updated: isoDate
  },
  {
    id: "app-us-ca-privacy",
    condition: {
      country: ["US-CA"],
      role: ["fintech", "bank", "insurance"],
      system_types: ["any"],
      data_types: ["dc-npi", "dc-credit", "dc-biometric"]
    },
    obligation: {
      regulation_id: "CCPA",
      section: "1798.100",
      standard_id: "std-iso-27017-27018",
      confidence: "authoritative"
    },
    rationale: "California privacy requirements overlay GLBA exceptions with consumer rights and incident obligations.",
    last_updated: isoDate
  },
  {
    id: "app-de-insurance",
    condition: {
      country: ["DE", "EU"],
      role: ["insurance", "financial-entity"],
      system_types: ["fs-insurance-core", "insurance"],
      data_types: ["dc-insurance", "dc-npi"]
    },
    obligation: {
      regulation_id: "Solvency_II",
      article: "41",
      standard_id: "std-iso-27017-27018",
      confidence: "authoritative"
    },
    rationale: "German insurers are subject to Solvency II governance with ICT controls under DORA and BaFin guidance.",
    last_updated: isoDate
  },
  {
    id: "app-de-bafin-vait",
    condition: {
      country: ["DE"],
      role: ["insurance", "bank"],
      system_types: ["any"],
      data_types: ["dc-insurance", "dc-account-data"]
    },
    obligation: {
      regulation_id: "BaFin_VAIT",
      section: "ICT",
      standard_id: "std-iso-27017-27018",
      confidence: "inferred"
    },
    rationale: "BaFin VAIT/BAIT supervisory expectations apply by sector and institution type.",
    last_updated: isoDate
  },
  {
    id: "app-digital-assets-eu",
    condition: {
      country: ["EU", "DE", "NL", "SE"],
      role: ["crypto-asset-service-provider", "fintech"],
      system_types: ["fs-digital-assets", "digital-assets"],
      data_types: ["dc-digital-asset", "dc-kyc-aml"]
    },
    obligation: {
      regulation_id: "MiCA",
      article: "63",
      standard_id: "std-stix-taxii",
      confidence: "authoritative"
    },
    rationale: "MiCA and AMLD obligations apply to crypto-asset service providers in the EU.",
    last_updated: isoDate
  },
  {
    id: "app-pci-any",
    condition: {
      country: ["US", "US-NY", "US-CA", "DE", "SE", "NL", "EU"],
      role: ["merchant", "payment-institution", "fintech", "bank"],
      system_types: ["fs-payments", "payments", "fs-instant-pay"],
      data_types: ["dc-card-data"]
    },
    obligation: {
      regulation_id: "PCI_DSS_4_0",
      clause: "Req 1-12",
      standard_id: "std-pci-dss-4-0",
      confidence: "authoritative"
    },
    rationale: "Any handling of cardholder data brings PCI DSS obligations regardless of jurisdiction.",
    last_updated: isoDate
  },
  {
    id: "app-swift-any",
    condition: {
      country: ["US", "US-NY", "DE", "SE", "NL", "EU"],
      role: ["bank"],
      system_types: ["fs-swift", "swift"],
      data_types: ["dc-swift"]
    },
    obligation: {
      regulation_id: "SWIFT_CSP",
      clause: "mandatory controls",
      standard_id: "std-swift-csp",
      confidence: "authoritative"
    },
    rationale: "SWIFT-connected entities are expected to implement and attest to CSP control baselines.",
    last_updated: isoDate
  },
  {
    id: "app-aml-any",
    condition: {
      country: ["US", "US-NY", "US-CA", "DE", "SE", "NL", "EU"],
      role: ["bank", "fintech", "payment-institution", "crypto-asset-service-provider"],
      system_types: ["fs-aml", "payments", "digital-assets", "lending"],
      data_types: ["dc-kyc-aml", "dc-digital-asset"]
    },
    obligation: {
      regulation_id: "AMLD6_BSA",
      section: "monitoring",
      standard_id: "std-stix-taxii",
      confidence: "authoritative"
    },
    rationale: "AML obligations apply broadly across monitored financial services activities.",
    last_updated: isoDate
  },
  {
    id: "app-nis2-financial",
    condition: {
      country: ["SE", "DE", "NL", "EU"],
      role: ["bank", "insurance", "payment-institution", "fintech"],
      system_types: ["any"],
      data_types: ["dc-account-data", "dc-npi", "dc-open-banking", "dc-swift"]
    },
    obligation: {
      regulation_id: "NIS2",
      article: "21",
      standard_id: "std-stix-taxii",
      confidence: "inferred"
    },
    rationale: "NIS2 and financial sector resilience obligations overlap for essential/important entities.",
    last_updated: isoDate
  }
];

export const evidenceArtifacts = [
  {
    id: "ev-dora-ict-framework",
    audit_type: "DORA Compliance",
    artifact_name: "ICT risk management framework",
    description: "Documented framework covering ICT governance, risk controls, and resilience metrics.",
    mandatory: true,
    retention_period: "7 years",
    template_ref: "tmpl/dora-ict-framework.md",
    regulation_basis: [{ regulation_id: "DORA", article: "6" }],
    last_updated: isoDate
  },
  {
    id: "ev-dora-third-party-register",
    audit_type: "DORA Compliance",
    artifact_name: "ICT third-party register of information",
    description: "Contractual, criticality, and service dependency registry for ICT providers.",
    mandatory: true,
    retention_period: "7 years",
    template_ref: "tmpl/dora-third-party-register.csv",
    regulation_basis: [{ regulation_id: "DORA", article: "28" }],
    last_updated: isoDate
  },
  {
    id: "ev-pci-network-diagrams",
    audit_type: "PCI DSS 4.0 Assessment",
    artifact_name: "CDE network and data flow diagrams",
    description: "Current diagrams showing card data environment boundaries and connected systems.",
    mandatory: true,
    retention_period: "1 year",
    template_ref: "tmpl/pci-network-diagram.drawio",
    regulation_basis: [{ regulation_id: "PCI_DSS_4_0", clause: "Req 1" }],
    last_updated: isoDate
  },
  {
    id: "ev-pci-testing",
    audit_type: "PCI DSS 4.0 Assessment",
    artifact_name: "Quarterly ASV and penetration test evidence",
    description: "External/internal vulnerability scans and penetration testing outcomes.",
    mandatory: true,
    retention_period: "1 year",
    template_ref: "tmpl/pci-testing-evidence.md",
    regulation_basis: [{ regulation_id: "PCI_DSS_4_0", clause: "Req 11" }],
    last_updated: isoDate
  },
  {
    id: "ev-swift-attestation",
    audit_type: "SWIFT CSP Attestation",
    artifact_name: "SWIFT CSP attestation package",
    description: "Evidence for mandatory/advisory controls and annual attestation.",
    mandatory: true,
    retention_period: "3 years",
    template_ref: "tmpl/swift-csp-attestation.md",
    regulation_basis: [{ regulation_id: "SWIFT_CSP", clause: "attestation" }],
    last_updated: isoDate
  },
  {
    id: "ev-sox-itgc",
    audit_type: "SOX IT Controls",
    artifact_name: "ITGC control operation evidence",
    description: "Access, change, and operations control evidence supporting SOX reporting controls.",
    mandatory: true,
    retention_period: "7 years",
    template_ref: "tmpl/sox-itgc-control-log.xlsx",
    regulation_basis: [{ regulation_id: "SOX", section: "404" }],
    last_updated: isoDate
  },
  {
    id: "ev-glba-wisp",
    audit_type: "GLBA Safeguards",
    artifact_name: "Written information security program",
    description: "GLBA safeguards-aligned security program and risk assessment evidence.",
    mandatory: true,
    retention_period: "5 years",
    template_ref: "tmpl/glba-wisp.md",
    regulation_basis: [{ regulation_id: "GLBA", section: "501(b)" }],
    last_updated: isoDate
  },
  {
    id: "ev-aml-monitoring",
    audit_type: "AML/BSA Program",
    artifact_name: "Transaction monitoring and SAR evidence",
    description: "Rule logic, alert handling, and SAR filing evidence.",
    mandatory: true,
    retention_period: "5 years",
    template_ref: "tmpl/aml-monitoring.md",
    regulation_basis: [{ regulation_id: "BSA", section: "5318" }],
    last_updated: isoDate
  },
  {
    id: "ev-mifid-order-handling",
    audit_type: "MiFID II",
    artifact_name: "Order handling and best execution evidence",
    description: "Procedures and records proving compliant order handling and transaction reporting.",
    mandatory: true,
    retention_period: "5 years",
    template_ref: "tmpl/mifid-order-handling.md",
    regulation_basis: [{ regulation_id: "MiFID_II", article: "27" }],
    last_updated: isoDate
  }
];

export const breachObligationsByJurisdiction = {
  EU: {
    topic: "breach notification",
    notifications: [
      {
        recipient: "Supervisory Authority",
        deadline: "72 hours",
        content_requirements: ["nature of breach", "data categories", "likely consequences", "mitigation measures"],
        penalties: "GDPR administrative fines"
      }
    ],
    citations: [{ type: "CELEX", ref: "GDPR Art. 33", source_url: "https://eur-lex.europa.eu/" }]
  },
  SE: {
    topic: "breach notification",
    notifications: [
      {
        recipient: "IMY (Swedish DPA)",
        deadline: "72 hours",
        content_requirements: ["GDPR breach details", "affected data subjects", "actions taken"],
        penalties: "GDPR sanctioning powers"
      },
      {
        recipient: "Financial Supervisory Authority (if operational incident)",
        deadline: "as soon as feasible / DORA incident timelines",
        content_requirements: ["incident classification", "service impact", "containment status"],
        penalties: "supervisory measures and administrative sanctions"
      }
    ],
    citations: [{ type: "CELEX", ref: "DORA Art. 17", source_url: "https://eur-lex.europa.eu/" }]
  },
  DE: {
    topic: "breach notification",
    notifications: [
      {
        recipient: "BfDI or relevant Lander DPA",
        deadline: "72 hours",
        content_requirements: ["GDPR breach notification baseline", "BDSG-specific notes"],
        penalties: "GDPR/BDSG sanctions"
      }
    ],
    citations: [{ type: "CELEX", ref: "GDPR Art. 33", source_url: "https://eur-lex.europa.eu/" }]
  },
  "US-NY": {
    topic: "breach notification",
    notifications: [
      {
        recipient: "NYDFS",
        deadline: "72 hours",
        content_requirements: ["event type", "affected systems", "regulatory impact"],
        penalties: "NYDFS enforcement actions"
      },
      {
        recipient: "Affected individuals + state AG (threshold dependent)",
        deadline: "without unreasonable delay",
        content_requirements: ["breach details", "consumer guidance", "remediation actions"],
        penalties: "state enforcement penalties"
      }
    ],
    citations: [{ type: "CFR", ref: "23 NYCRR 500.17", source_url: "https://www.dfs.ny.gov/" }]
  },
  "US-CA": {
    topic: "breach notification",
    notifications: [
      {
        recipient: "Affected California residents",
        deadline: "without unreasonable delay",
        content_requirements: ["breach summary", "types of information", "support contacts"],
        penalties: "civil penalties and private litigation risk"
      }
    ],
    citations: [{ type: "USC", ref: "Cal. Civ. Code 1798.82", source_url: "https://leginfo.legislature.ca.gov/" }]
  },
  US: {
    topic: "breach notification",
    notifications: [
      {
        recipient: "Primary federal regulator",
        deadline: "36 hours (banking computer-security incident rules where applicable)",
        content_requirements: ["incident impact", "services affected", "status"],
        penalties: "supervisory actions"
      }
    ],
    citations: [{ type: "CFR", ref: "12 CFR 225/304/53 Incident Rule", source_url: "https://www.ecfr.gov/" }]
  }
};

export const jurisdictionComparisonTopics = {
  "breach notification": {
    EU: {
      obligation: "Notify supervisory authority within 72 hours for personal data breaches.",
      timeline: "72h",
      trigger: "Likely risk to rights and freedoms",
      source: "GDPR Art. 33",
      source_url: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"
    },
    SE: {
      obligation: "GDPR breach reporting plus financial resilience incident reporting under DORA when applicable.",
      timeline: "72h + DORA staged reporting",
      trigger: "Data breach and significant ICT incident",
      source: "GDPR Art. 33 + DORA Art. 17",
      source_url: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"
    },
    "US-NY": {
      obligation: "Report qualifying cybersecurity events to NYDFS and satisfy state notice requirements.",
      timeline: "72h (NYDFS) + consumer notice without unreasonable delay",
      trigger: "material cybersecurity event / breach of private information",
      source: "23 NYCRR 500.17",
      source_url: "https://www.dfs.ny.gov/industry_guidance/cybersecurity"
    },
    "US-CA": {
      obligation: "Notify affected residents for data breach incidents.",
      timeline: "without unreasonable delay",
      trigger: "breach of personal information",
      source: "Cal. Civ. Code 1798.82",
      source_url: "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.82.&lawCode=CIV"
    }
  },
  "dora vs nydfs incident reporting": {
    DORA: {
      obligation: "Classify ICT incidents and provide initial/intermediate/final reports to competent authority.",
      timeline: "staged timelines defined in RTS/ITS",
      trigger: "major ICT-related incident",
      source: "DORA Art. 17-19",
      source_url: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"
    },
    NYDFS: {
      obligation: "Notify NYDFS of qualifying cybersecurity event.",
      timeline: "72 hours",
      trigger: "event with notice obligations or material impact",
      source: "23 NYCRR 500.17",
      source_url: "https://www.dfs.ny.gov/industry_guidance/cybersecurity"
    }
  },
  "psd2 sca vs reg e disputes": {
    PSD2: {
      obligation: "Apply strong customer authentication and secure communication for electronic payments.",
      timeline: "pre-transaction",
      trigger: "electronic payment initiation/access",
      source: "PSD2 Art. 97",
      source_url: "https://eur-lex.europa.eu/eli/dir/2015/2366/oj"
    },
    REG_E: {
      obligation: "Investigate and resolve consumer EFT error claims within statutory windows.",
      timeline: "10 business days (provisional credit extension rules apply)",
      trigger: "consumer dispute of unauthorized EFT",
      source: "12 CFR 1005",
      source_url: "https://www.ecfr.gov/current/title-12/chapter-X/part-1005"
    }
  },
  "fda cybersecurity vs eu mdr cybersecurity": {
    FDA: {
      obligation: "Premarket and postmarket cybersecurity evidence with vulnerability lifecycle controls.",
      timeline: "premarket submission + ongoing postmarket",
      trigger: "medical device software lifecycle",
      source: "FDA Section 524B guidance",
      source_url: "https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity-medical-devices"
    },
    EU_MDR: {
      obligation: "Cybersecurity integrated in safety/risk management and technical documentation.",
      timeline: "conformity assessment + lifecycle monitoring",
      trigger: "MDR/IVDR device classification",
      source: "MDCG 2019-16",
      source_url: "https://eur-lex.europa.eu/eli/reg/2017/745/oj"
    }
  }
};

export const controlCatalog = {
  "SCF.AC-01": { title: "Access control and strong authentication", priority_weight: 100 },
  "SCF.AU-02": { title: "Audit logging and monitoring", priority_weight: 92 },
  "SCF.CR-03": { title: "Cryptographic protection and key handling", priority_weight: 95 },
  "SCF.NW-06": { title: "Network segmentation and secure communication", priority_weight: 90 },
  "SCF.DS-02": { title: "Data security and minimization", priority_weight: 89 },
  "SCF.CM-05": { title: "Secure change management", priority_weight: 80 },
  "SCF.IR-03": { title: "Incident response and reporting", priority_weight: 86 },
  "SCF.GV-04": { title: "Governance and model risk controls", priority_weight: 78 },
  "SCF.SD-03": { title: "Secure software development", priority_weight: 74 },
  "SCF.TV-01": { title: "Threat and vulnerability testing", priority_weight: 72 },
  "SCF.KM-01": { title: "Cryptographic key management", priority_weight: 94 },
  "SCF.EN-01": { title: "Encryption at rest and in transit", priority_weight: 88 }
};

export const knownLimitations = [
  "Foundation MCP calls are represented as routing metadata and stubs; live federation requires MCP endpoint configuration.",
  "State-by-state US licensing detail is modeled for key scenarios but not exhaustive.",
  "Jurisdictional edge-cases are rule-driven and may need legal review for production decisions."
];

export function datasetForFingerprint() {
  return {
    authoritativeSources,
    dataCategories,
    architecturePatterns,
    threatScenarios,
    technicalStandards,
    applicabilityRules,
    evidenceArtifacts,
    breachObligationsByJurisdiction,
    jurisdictionComparisonTopics,
    controlCatalog,
    knownLimitations
  };
}
