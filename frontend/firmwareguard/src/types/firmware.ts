export type SectorType = 'energy' | 'oil_gas' | 'healthcare' | 'automotive';

export type VexStatusType =
  | 'affected_reachable'
  | 'affected_not_reachable'
  | 'mitigated'
  | 'not_affected';

export type SeverityType = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Vulnerability {
  id: string; // e.g., CVE-2020-25111
  name: string;
  component: string;
  version: string;
  fixedVersion?: string;
  cvss: number;
  epss: number; // Exploit Prediction Scoring System e.g., 0.89
  cisaKev: boolean; // Known Exploited Vulnerability
  weaponizedPoc: boolean;
  vexStatus: VexStatusType;
  vexJustification: string;
  reachabilityPath?: string[]; // e.g., ['eth0 (DNP3:20000)', 'dnp3_listen()', 'dnp3_parse_pdu()', 'dnp3_process_object()']
  clinicalImpact?: string; // Healthcare specific (e.g. "Direct infusion delivery rate manipulation")
  gridImpact?: string; // Energy specific (e.g. "Substation breaker tripping / disconnect")
  safetyImpact?: string; // Oil & Gas / Automotive specific (e.g. "SIS bypass, CAN bus steering lock")
  mitigation?: string;
}

export interface SupplyChainComponent {
  id: string;
  name: string;
  version: string;
  layer: 'silicon_bsp' | 'rtos_kernel' | 'middleware' | 'app_logic';
  supplier: string;
  tier: 'Tier 1' | 'Tier 2' | 'Internal OEM';
  license: string;
  slsaLevel: 0 | 1 | 2 | 3;
  hashVerified: boolean;
  sha256: string;
  cveCount: number;
  reachableCveCount: number;
  sourceRepo?: string;
  dependencies?: string[]; // IDs of child components
}

export interface BinaryHardeningFlags {
  nxDep: boolean; // No-Execute / Data Execution Prevention
  aslrPie: boolean; // Address Space Layout Randomization / Position Independent Executable
  stackCanary: boolean; // Stack smashing protection
  relro: 'Full' | 'Partial' | 'None'; // Read-Only Relocations
  fortifySource: boolean; // Buffer overflow checking
  strippedSymbols: boolean; // Stripped debug symbols
}

export interface ExposedSecret {
  id: string;
  type: 'Private RSA Key' | 'Hardcoded Password' | 'AWS / Cloud Token' | 'Expired X.509 Cert' | 'Debug UART/JTAG Stub';
  severity: SeverityType;
  location: string; // File or binary offset, e.g., "/etc/ssl/certs/device_key.pem (offset 0x0041F0A)"
  snippet: string;
  riskDescription: string;
}

export interface FirmwareAsset {
  id: string;
  name: string;
  model: string;
  manufacturer: string;
  sector: SectorType;
  targetRole: string; // e.g., "Smart Substation RTU", "Infusion Pump", "Electronic Control Unit (ECU)"
  version: string;
  releaseDate: string;
  architecture: 'ARM Cortex-M4' | 'ARM Cortex-R5' | 'PowerPC e500' | 'TriCore TC397' | 'QNX x86_64' | 'Embedded Linux ARM64' | 'Renesas RX65N';
  osType: 'FreeRTOS' | 'VxWorks 7.0' | 'QNX Neutrino' | 'Embedded Linux (Yocto)' | 'AUTOSAR Classic' | 'Bare-metal';
  rawCveCount: number;
  reachableCveCount: number;
  cisaKevCount: number;
  signatureStatus: 'Signed & Valid' | 'Self-Signed' | 'Unsigned / Broken' | 'Deprecated MD5';
  mttrDays: number;
  sbomCompletenessPercent: number;
  hardening: BinaryHardeningFlags;
  secrets: ExposedSecret[];
  vulnerabilities: Vulnerability[];
  components: SupplyChainComponent[];
  complianceGaps: {
    standard: 'FDA 524B' | 'NERC CIP-013-1' | 'UNECE R155/R156' | 'TSA Pipeline Directives' | 'IEC 62443';
    status: 'Compliant' | 'Action Required' | 'Non-Compliant';
    details: string;
  }[];
}

export interface SectorMetrics {
  sector: SectorType;
  title: string;
  totalAssets: number;
  totalComponents: number;
  rawCves: number;
  reachableCves: number;
  activeKevCount: number;
  unsignedCount: number;
  secretsCount: number;
  avgSbomScore: number;
  primaryStandard: string;
  riskScore: number; // 0-100
}
