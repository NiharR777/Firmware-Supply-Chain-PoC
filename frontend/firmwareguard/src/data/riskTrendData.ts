export interface SectorTrendPoint {
  date: string; // ISO format e.g. "2026-10-08"
  displayDate: string; // e.g. "Oct 08"
  energy: number; // 0 - 100 risk score
  oil_gas: number; // 0 - 100 risk score
  healthcare: number; // 0 - 100 risk score
  automotive: number; // 0 - 100 risk score
  milestone?: {
    sector: 'energy' | 'oil_gas' | 'healthcare' | 'automotive';
    title: string;
    description: string;
    riskDelta: number;
    scenarioId?: string;
  };
}

export const SECTOR_30_DAY_TREND: SectorTrendPoint[] = [
  { date: '2026-10-08', displayDate: 'Oct 08', energy: 68, oil_gas: 74, healthcare: 82, automotive: 58 },
  { date: '2026-10-09', displayDate: 'Oct 09', energy: 69, oil_gas: 74, healthcare: 81, automotive: 58 },
  { date: '2026-10-10', displayDate: 'Oct 10', energy: 68, oil_gas: 76, healthcare: 80, automotive: 57 },
  {
    date: '2026-10-11',
    displayDate: 'Oct 11',
    energy: 67,
    oil_gas: 88,
    healthcare: 79,
    automotive: 56,
    milestone: {
      sector: 'oil_gas',
      title: 'SC-005 SIS Rollback Attempt Detected',
      description: 'Refinery Alkylation Safety Skid: firmware rollback to legacy v1.2.0 blocked by safety gate.',
      riskDelta: +12,
      scenarioId: 'SC-005'
    }
  },
  { date: '2026-10-12', displayDate: 'Oct 12', energy: 67, oil_gas: 89, healthcare: 79, automotive: 56 },
  { date: '2026-10-13', displayDate: 'Oct 13', energy: 66, oil_gas: 87, healthcare: 78, automotive: 55 },
  { date: '2026-10-14', displayDate: 'Oct 14', energy: 66, oil_gas: 86, healthcare: 78, automotive: 55 },
  {
    date: '2026-10-15',
    displayDate: 'Oct 15',
    energy: 82,
    oil_gas: 85,
    healthcare: 77,
    automotive: 54,
    milestone: {
      sector: 'energy',
      title: 'SC-001 SEL-710 Hash Mismatch Quarantine',
      description: 'Substation protective relay firmware package failed SHA-256 integrity verification.',
      riskDelta: +16,
      scenarioId: 'SC-001'
    }
  },
  { date: '2026-10-16', displayDate: 'Oct 16', energy: 83, oil_gas: 84, healthcare: 76, automotive: 54 },
  { date: '2026-10-17', displayDate: 'Oct 17', energy: 84, oil_gas: 83, healthcare: 75, automotive: 54 },
  { date: '2026-10-18', displayDate: 'Oct 18', energy: 83, oil_gas: 82, healthcare: 74, automotive: 53 },
  { date: '2026-10-19', displayDate: 'Oct 19', energy: 81, oil_gas: 82, healthcare: 73, automotive: 53 },
  {
    date: '2026-10-20',
    displayDate: 'Oct 20',
    energy: 80,
    oil_gas: 81,
    healthcare: 89,
    automotive: 52,
    milestone: {
      sector: 'healthcare',
      title: 'Ripple20 Treck TCP/IP Advisory Disclosure',
      description: 'FDA Section 524B safety advisory on unpatched Wi-Fi DHCP stack in bedside infusion pumps.',
      riskDelta: +16,
      scenarioId: 'med-pump-rev4'
    }
  },
  { date: '2026-10-21', displayDate: 'Oct 21', energy: 79, oil_gas: 80, healthcare: 88, automotive: 52 },
  { date: '2026-10-22', displayDate: 'Oct 22', energy: 78, oil_gas: 79, healthcare: 86, automotive: 51 },
  { date: '2026-10-23', displayDate: 'Oct 23', energy: 77, oil_gas: 78, healthcare: 85, automotive: 66,
    milestone: {
      sector: 'automotive',
      title: 'AUTOSAR UDS Stack Vulnerability (CVE-2021-35937)',
      description: 'Central Gateway ECU DoIP diagnostic service buffer overflow flagged in compliance review.',
      riskDelta: +15,
      scenarioId: 'auto-ecu-gateway'
    }
  },
  { date: '2026-10-24', displayDate: 'Oct 24', energy: 76, oil_gas: 78, healthcare: 84, automotive: 67 },
  { date: '2026-10-25', displayDate: 'Oct 25', energy: 75, oil_gas: 77, healthcare: 82, automotive: 66 },
  { date: '2026-10-26', displayDate: 'Oct 26', energy: 74, oil_gas: 76, healthcare: 81, automotive: 65 },
  { date: '2026-10-27', displayDate: 'Oct 27', energy: 73, oil_gas: 75, healthcare: 80, automotive: 64 },
  {
    date: '2026-10-28',
    displayDate: 'Oct 28',
    energy: 72,
    oil_gas: 89,
    healthcare: 79,
    automotive: 63,
    milestone: {
      sector: 'oil_gas',
      title: 'SC-008 Untrusted Vendor Substitution',
      description: 'Hydrocracker Feed Pump VFD: unauthorized vendor ID VEND-UNAPPROVED-PROXY intercepted.',
      riskDelta: +14,
      scenarioId: 'SC-008'
    }
  },
  { date: '2026-10-29', displayDate: 'Oct 29', energy: 72, oil_gas: 90, healthcare: 78, automotive: 62 },
  { date: '2026-10-30', displayDate: 'Oct 30', energy: 71, oil_gas: 91, healthcare: 78, automotive: 62 },
  { date: '2026-10-31', displayDate: 'Oct 31', energy: 70, oil_gas: 90, healthcare: 77, automotive: 61 },
  { date: '2026-11-01', displayDate: 'Nov 01', energy: 83, oil_gas: 91, healthcare: 77, automotive: 61,
    milestone: {
      sector: 'energy',
      title: 'NERC CIP-013 Tier-2 Microcode Audit Gap',
      description: 'Missing cryptographic root-of-trust attestation on P2020 hardware microcode.',
      riskDelta: +13,
      scenarioId: 'SC-001'
    }
  },
  { date: '2026-11-02', displayDate: 'Nov 02', energy: 84, oil_gas: 91, healthcare: 76, automotive: 62 },
  {
    date: '2026-11-03',
    displayDate: 'Nov 03',
    energy: 84,
    oil_gas: 92,
    healthcare: 75,
    automotive: 63,
    milestone: {
      sector: 'oil_gas',
      title: 'SC-004 cURL SOCKS5 VEX Reachability Suppression',
      description: 'Static call-graph disassembly confirms vulnerable proxy symbol is uncalled; risk stabilized.',
      riskDelta: -4,
      scenarioId: 'SC-004'
    }
  },
  { date: '2026-11-04', displayDate: 'Nov 04', energy: 85, oil_gas: 91, healthcare: 77, automotive: 64 },
  { date: '2026-11-05', displayDate: 'Nov 05', energy: 84, oil_gas: 91, healthcare: 78, automotive: 65 },
  { date: '2026-11-06', displayDate: 'Nov 06', energy: 84, oil_gas: 91, healthcare: 78, automotive: 65 },
];
