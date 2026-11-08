export interface EvidenceCheckItem {
  name: string;
  ok: boolean;
  status: 'pass' | 'review' | 'warning';
  detail: string;
}

export interface ScenarioDefinition {
  scenario_id: string; // e.g. "SC-001"
  package_id: string; // e.g. "FW-PKG-001-RTU"
  firmware_version: string;
  expected_version: string;
  asset_id: string;
  asset_name: string;
  device_type: string;
  process_unit: string;
  sector: 'oil_gas' | 'energy' | 'healthcare' | 'automotive';
  attack_description: string;
  mitre_tactic: string;
  mitre_technique: string;
  risk_score: number;
  risk_level: 'normal' | 'investigate' | 'high_risk';
  risk_factors: string[];
  reasons: string[];
  recommendation: 'allow_after_human_review' | 'investigate' | 'quarantine_review';
  deployment_allowed: boolean;
  human_approval_required: boolean;
  real_action_executed: boolean;
  sbom_present: boolean;
  sbom_status: 'complete' | 'incomplete' | 'missing';
  component_count: number;
  signature_status: 'valid' | 'invalid' | 'untrusted';
  trusted_root_status: 'trusted' | 'untrusted';
  vendor_id: string;
  vendor_trust: 'trusted' | 'untrusted';
  vulnerability_status: 'affected' | 'not_affected' | 'unknown';
  cve_id?: string;
  cve_severity?: string;
  unexpected_component_observed: boolean;
  evidence_age_days: number;
  freshness_threshold_days: number;
  hash_match: boolean;
  observed_hash: string;
  trusted_sha256: string;
}

export const SPECTRA_SCENARIOS: ScenarioDefinition[] = [
  {
    scenario_id: 'SC-001',
    package_id: 'FW-PKG-001-RELAY',
    firmware_version: 'v4.14.0',
    expected_version: 'v4.14.0',
    asset_id: 'ASSET-001-SEL710',
    asset_name: 'Substation SEL-710 Protective Relay',
    device_type: 'Protective Relay RTU',
    process_unit: 'Refinery Substation Feed 13.8kV',
    sector: 'energy',
    attack_description: 'Firmware hash mismatch tampering & invalid signature in binary delivery pipeline',
    mitre_tactic: 'Persistence',
    mitre_technique: 'T0857 - System Firmware Compromise',
    risk_score: 70,
    risk_level: 'high_risk',
    risk_factors: ['hash_integrity_failure', 'signature_failure'],
    reasons: [
      'Firmware package hash does not match the trusted vendor hash.',
      'Firmware package signature is invalid or not trusted.'
    ],
    recommendation: 'quarantine_review',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 18,
    signature_status: 'invalid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-NORTHGRID-01',
    vendor_trust: 'trusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 12,
    freshness_threshold_days: 30,
    hash_match: false,
    observed_hash: '9a31f8b1085c8821948756cbaef1904293847120398471209384712093847120',
    trusted_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  {
    scenario_id: 'SC-002',
    package_id: 'FW-PKG-002-FLOW',
    firmware_version: 'v2.7.4',
    expected_version: 'v2.7.4',
    asset_id: 'ASSET-002-ROC809',
    asset_name: 'HydroFlow ROC809 Flow Computer',
    device_type: 'Custody Transfer Flow Computer',
    process_unit: 'Crude Gathering & Metering Skids',
    sector: 'oil_gas',
    attack_description: 'Tampered package binary not anchored to vendor root with hash corruption',
    mitre_tactic: 'Impair Process Control',
    mitre_technique: 'T0833 - Control Logic Manipulation',
    risk_score: 90,
    risk_level: 'high_risk',
    risk_factors: ['hash_integrity_failure', 'signature_failure', 'trusted_root_failure'],
    reasons: [
      'Firmware package hash does not match the trusted vendor hash.',
      'Firmware package signature is invalid or not trusted.',
      'Firmware package is not anchored to a trusted vendor root.'
    ],
    recommendation: 'quarantine_review',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 32,
    signature_status: 'invalid',
    trusted_root_status: 'untrusted',
    vendor_id: 'VEND-HYDROFLOW-09',
    vendor_trust: 'trusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 8,
    freshness_threshold_days: 30,
    hash_match: false,
    observed_hash: '1b88301928475619283746192837461928374619283746192837461928374619',
    trusted_sha256: 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
  },
  {
    scenario_id: 'SC-003',
    package_id: 'FW-PKG-003-COMPRESSOR',
    firmware_version: 'v3.1.2',
    expected_version: 'v3.1.2',
    asset_id: 'ASSET-003-VFD-C1',
    asset_name: 'Centrifugal Gas Compressor VFD PLC',
    device_type: 'Compressor Station Controller',
    process_unit: 'Gas Compression & Vapor Recovery',
    sector: 'oil_gas',
    attack_description: 'Unapproved third-party vendor substitution during maintenance flash cycle',
    mitre_tactic: 'Discovery',
    mitre_technique: 'T0886 - Remote System Discovery',
    risk_score: 70,
    risk_level: 'high_risk',
    risk_factors: ['untrusted_vendor', 'signature_failure'],
    reasons: [
      'Firmware package is associated with an untrusted vendor.',
      'Firmware package signature is invalid or not trusted.'
    ],
    recommendation: 'quarantine_review',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 24,
    signature_status: 'untrusted',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-ROGUE-SHADOW-X',
    vendor_trust: 'untrusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 14,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
    trusted_sha256: '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d',
  },
  {
    scenario_id: 'SC-004',
    package_id: 'FW-PKG-004-COLUMN',
    firmware_version: 'v5.8.1',
    expected_version: 'v5.8.1',
    asset_id: 'ASSET-004-CDU-RTU',
    asset_name: 'Crude Distillation Column RTU-4',
    device_type: 'Atmospheric Distillation RTU',
    process_unit: 'Crude Distillation Unit (CDU-1)',
    sector: 'oil_gas',
    attack_description: 'Weaponized CVE-2023-38545 cURL heap buffer overflow embedded in diagnostic agent',
    mitre_tactic: 'Initial Access',
    mitre_technique: 'T0866 - Exploitation of Remote Services',
    risk_score: 20,
    risk_level: 'investigate',
    risk_factors: ['vulnerable_component'],
    reasons: [
      'A vulnerable component affects the firmware package (cURL v8.4.0 heap overflow).'
    ],
    recommendation: 'investigate',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 42,
    signature_status: 'valid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-EMERSON-APPROVED',
    vendor_trust: 'trusted',
    vulnerability_status: 'affected',
    cve_id: 'CVE-2023-38545',
    cve_severity: 'HIGH (CVSS 9.8)',
    unexpected_component_observed: false,
    evidence_age_days: 6,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    trusted_sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
  },
  {
    scenario_id: 'SC-005',
    package_id: 'FW-PKG-005-SIS',
    firmware_version: 'v1.2.0',
    expected_version: 'v2.4.1',
    asset_id: 'ASSET-005-SIS-TRICON',
    asset_name: 'TricoSafe SIS Safety Instrumented Controller',
    device_type: 'Safety Instrumented System (SIS)',
    process_unit: 'Refinery Alkylation Acid Safety Skid',
    sector: 'oil_gas',
    attack_description: 'Unauthorized firmware rollback to vulnerable legacy build (Triton/HatMan vector)',
    mitre_tactic: 'Inhibit Response Function',
    mitre_technique: 'T0857 - System Firmware Compromise',
    risk_score: 40,
    risk_level: 'high_risk',
    risk_factors: ['unauthorized_rollback'],
    reasons: [
      'Unauthorized rollback to an older firmware version (v1.2.0 < v2.4.1) was detected.'
    ],
    recommendation: 'quarantine_review',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 14,
    signature_status: 'valid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-TRICOSAFFE-04',
    vendor_trust: 'trusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 10,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    trusted_sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
  },
  {
    scenario_id: 'SC-006',
    package_id: 'FW-PKG-006-FLARE',
    firmware_version: 'v3.0.4',
    expected_version: 'v3.0.4',
    asset_id: 'ASSET-006-FLARE-ANLZ',
    asset_name: 'Flare Gas Continuous Emission Analyzer',
    device_type: 'Emission Telemetry Analyzer',
    process_unit: 'Off-Gas Treatment & Flare Stack',
    sector: 'oil_gas',
    attack_description: 'Missing or incomplete SBOM; opaque third-party C library binaries present',
    mitre_tactic: 'Collection',
    mitre_technique: 'T0888 - Software Inventory Gathering',
    risk_score: 15,
    risk_level: 'investigate',
    risk_factors: ['missing_sbom'],
    reasons: [
      'SBOM evidence is missing or incomplete (sub-component tree truncated).'
    ],
    recommendation: 'investigate',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'incomplete',
    component_count: 5,
    signature_status: 'valid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-SIEMENS-SENSORS',
    vendor_trust: 'trusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 4,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
    trusted_sha256: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
  },
  {
    scenario_id: 'SC-007',
    package_id: 'FW-PKG-007-RADAR',
    firmware_version: 'v1.9.0',
    expected_version: 'v1.9.0',
    asset_id: 'ASSET-007-TANK-RADAR',
    asset_name: 'Tank Farm Ultrasonic Radar Gauge',
    device_type: 'Hydrocarbon Level Radar',
    process_unit: 'Finished Products Tank Farm',
    sector: 'energy',
    attack_description: 'Unexpected diagnostic binary module observed in signed package manifest',
    mitre_tactic: 'Execution',
    mitre_technique: 'T0821 - Modify Controller Tasking',
    risk_score: 20,
    risk_level: 'investigate',
    risk_factors: ['unexpected_component'],
    reasons: [
      'An unexpected component change was detected in the firmware package manifest.'
    ],
    recommendation: 'investigate',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 19,
    signature_status: 'valid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-ROSEMOUNT-TANK',
    vendor_trust: 'trusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: true,
    evidence_age_days: 15,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: 'e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683',
    trusted_sha256: 'e7f6c011776e8db7cd330b54174fd76f7d0216b612387a5ffcfb81e6f0919683',
  },
  {
    scenario_id: 'SC-008',
    package_id: 'FW-PKG-008-HYDRO',
    firmware_version: 'v4.0.1',
    expected_version: 'v4.0.1',
    asset_id: 'ASSET-008-HCU-PUMP',
    asset_name: 'Hydrocracker High-Pressure Feed Pump',
    device_type: 'VFD Variable Speed Drive',
    process_unit: 'Hydrocracking Unit Reactor Loop',
    sector: 'oil_gas',
    attack_description: 'Vendor substitution in OTA supply chain (unauthorized vendor identifier)',
    mitre_tactic: 'Lateral Movement',
    mitre_technique: 'T0830 - Man-in-the-Middle',
    risk_score: 40,
    risk_level: 'high_risk',
    risk_factors: ['untrusted_vendor'],
    reasons: [
      'Firmware package is associated with an untrusted vendor (VEND-UNAPPROVED-PROXY).'
    ],
    recommendation: 'quarantine_review',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 22,
    signature_status: 'valid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-UNAPPROVED-PROXY',
    vendor_trust: 'untrusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 9,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: '7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451',
    trusted_sha256: '7902699be42c8a8e46fbbb4501726517e86b22c56a189f7625a6da49081b2451',
  },
  {
    scenario_id: 'SC-009',
    package_id: 'FW-PKG-009-VALVE',
    firmware_version: 'v1.0.8',
    expected_version: 'v2.2.0',
    asset_id: 'ASSET-009-FCC-SLIDE',
    asset_name: 'FCC Regenerator Catalyst Slide Valve',
    device_type: 'Electro-Hydraulic Actuator PLC',
    process_unit: 'Fluid Catalytic Cracking (FCC)',
    sector: 'oil_gas',
    attack_description: 'Unauthorized version downgrade accompanied by invalid digital signature',
    mitre_tactic: 'Impair Process Control',
    mitre_technique: 'T0833 - Control Logic Manipulation',
    risk_score: 70,
    risk_level: 'high_risk',
    risk_factors: ['unauthorized_rollback', 'signature_failure'],
    reasons: [
      'Unauthorized rollback to an older firmware version was detected.',
      'Firmware package signature is invalid or not trusted.'
    ],
    recommendation: 'quarantine_review',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 17,
    signature_status: 'invalid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-FLOWSERVE-ACTUATE',
    vendor_trust: 'trusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 18,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    trusted_sha256: '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
  },
  {
    scenario_id: 'SC-010',
    package_id: 'FW-PKG-010-BOILER',
    firmware_version: 'v4.2.0',
    expected_version: 'v4.2.0',
    asset_id: 'ASSET-010-BFW-CTRL',
    asset_name: 'Boiler Feedwater Deaerator RTU',
    device_type: 'Boiler Water Level Controller',
    process_unit: 'Steam Generation & Utilities',
    sector: 'energy',
    attack_description: 'Stale security evidence bundle exceeds maximum operational threshold (45 days > 30 days)',
    mitre_tactic: 'Evasion',
    mitre_technique: 'T0855 - Unauthorized Command Message',
    risk_score: 10,
    risk_level: 'investigate',
    risk_factors: ['stale_evidence'],
    reasons: [
      'Security evidence is stale (45 days old > 30 days threshold) and requires review before deployment.'
    ],
    recommendation: 'investigate',
    deployment_allowed: false,
    human_approval_required: true,
    real_action_executed: false,
    sbom_present: true,
    sbom_status: 'complete',
    component_count: 28,
    signature_status: 'valid',
    trusted_root_status: 'trusted',
    vendor_id: 'VEND-YOKOGAWA-STEAM',
    vendor_trust: 'trusted',
    vulnerability_status: 'not_affected',
    unexpected_component_observed: false,
    evidence_age_days: 45,
    freshness_threshold_days: 30,
    hash_match: true,
    observed_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    trusted_sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
  }
];

export const METRIC_READINESS_ITEMS = [
  {
    metric: 'Firmware Vulnerability Exposure Index (FVEI)',
    reason: 'Structured CVE severity, CVSS and EPSS records are not exposed by the current dashboard evidence schema.',
    document_target: 'Zero unmitigated Critical/High CVEs on safety-critical networks; zero-day remediation window to be defined.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'Firmware MTTD / MTTR',
    reason: 'Detection, incident, isolation and remediation timestamps are not collected.',
    document_target: 'Operational target requires agreed incident timing definitions.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'CI/CD artifact attestation',
    reason: 'No SLSA/build provenance attestation evidence is present in the current bundles.',
    document_target: '100% for safety-instrumented and station-automation software.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'Firmware binary parsing accuracy and coverage',
    reason: 'The current PoC does not parse arbitrary firmware binaries or produce parser ground-truth comparisons.',
    document_target: 'Parsing accuracy >=98%; coverage of target OEM firmware formats.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'Reachability accuracy / MTTC',
    reason: 'No binary call-graph, network/bus reachability, or CVE-to-function validation dataset is implemented.',
    document_target: 'Reachability precision >=95%; MTTC target requires measurement.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'Bootloader identification and tamper-detection accuracy',
    reason: 'No raw image bootloader extraction or controlled tamper test dataset is implemented.',
    document_target: 'Bootloader identification rate 99%; cryptographic provenance accuracy 100%.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'SBOM-to-binary consistency and license precision',
    reason: 'No binary-derived SBOM comparison or license scanner is implemented.',
    document_target: 'SBOM consistency >=99%; license compliance precision 100%.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'Safety-system exposure and patch-deferral risk',
    reason: 'No deployed SIS inventory, maintenance-window, or patch-deferral records are connected.',
    document_target: 'Operational safety and patch-deferral thresholds require plant-specific inventory.',
    status: 'NOT MEASURED'
  },
  {
    metric: 'Field provenance drift',
    reason: 'No live device firmware-state telemetry or central deployed-asset inventory is connected.',
    document_target: '100% accuracy target in supplied metrics document.',
    status: 'NOT MEASURED'
  }
];
