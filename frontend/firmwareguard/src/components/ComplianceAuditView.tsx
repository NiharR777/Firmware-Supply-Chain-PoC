import React, { useState } from 'react';
import { FirmwareAsset } from '../types/firmware';
import {
  FileCheck2,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Printer
} from 'lucide-react';

interface ComplianceAuditViewProps {
  assets: FirmwareAsset[];
}

export const ComplianceAuditView: React.FC<ComplianceAuditViewProps> = ({ assets }) => {
  const [selectedStandard, setSelectedStandard] = useState<'FDA 524B' | 'NERC CIP-013-1' | 'UNECE R155/R156' | 'TSA Pipeline Directives'>('FDA 524B');

  const standardsInfo = {
    'FDA 524B': {
      title: 'FDA Section 524B - Medical Device Cybersecurity',
      sector: 'Healthcare & MedTech',
      description: 'Federal statutory mandate requiring medical device manufacturers to submit machine-readable SBOMs, ensure verified component pedigree, and maintain active post-market vulnerability disclosure and patching programs.',
      articles: [
        {
          id: '524B(b)(1)',
          name: 'Machine-Readable Software Bill of Materials (SBOM)',
          status: 'Compliant',
          requirement: 'Submit a complete SBOM that includes commercial, open-source, and off-the-shelf software components with version and build hashes.',
          fleetStatus: '93% SBOM coverage across monitored infusion pumps and bedside monitors.'
        },
        {
          id: '524B(b)(2)',
          name: 'Coordinated Vulnerability Disclosure & Monitoring',
          status: 'Action Required',
          requirement: 'Demonstrate reasonable assurance that the device and related systems are cybersecure and monitor for post-market vulnerabilities.',
          fleetStatus: 'Action required on Treck TCP/IP stack (Ripple20 CVE-2020-25111); clinical impact assessment pending board sign-off.'
        },
        {
          id: '524B(b)(3)',
          name: 'Regular & Critical Security Update Delivery',
          status: 'Compliant',
          requirement: 'Provide processes and procedures to deliver authorized security patches to maintain device safety throughout total product life cycle (TPLC).',
          fleetStatus: 'Signed cryptographic delta OTA updates configured on MedCare pumps.'
        }
      ]
    },
    'NERC CIP-013-1': {
      title: 'NERC CIP-013-1 - Bulk Electric System Supply Chain',
      sector: 'Energy & Electric Grid',
      description: 'North American electric reliability standard establishing supply chain cyber security risk management plans for high- and medium-impact bulk electric system (BES) cyber assets.',
      articles: [
        {
          id: 'CIP-013 R1.1',
          name: 'Supplier Security Assessment & Notification',
          status: 'Compliant',
          requirement: 'Process for vendor notification of cybersecurity incidents and vendor disclosure of newly discovered vulnerabilities.',
          fleetStatus: '100% of grid relay vendors have executed active security advisories.'
        },
        {
          id: 'CIP-013 R1.2',
          name: 'Software Integrity & Authenticity Verification',
          status: 'Action Required',
          requirement: 'Verification of software and firmware integrity and authenticity before installation on BES cyber systems.',
          fleetStatus: 'NorthGrid RTU-710 has unverified Tier-2 silicon microcode hash.'
        },
        {
          id: 'CIP-013 R1.3',
          name: 'Interactive Remote Access & Default Credentials',
          status: 'Action Required',
          requirement: 'Eliminate vendor-owned default interactive remote access credentials and hardcoded backdoor keys.',
          fleetStatus: 'Shared default DNP3 key detected in ROM flash on SEL-710 generation batch.'
        }
      ]
    },
    'UNECE R155/R156': {
      title: 'UNECE WP.29 R155 / R156 - Vehicle Cybersecurity & Updates',
      sector: 'Automotive & Connected Fleets',
      description: 'Mandatory United Nations automotive regulations enforcing Cyber Security Management Systems (CSMS, R155) and Software Update Management Systems (SUMS, R156) for vehicle type approval.',
      articles: [
        {
          id: 'R155 Clause 7.2',
          name: 'Cybersecurity Across Tier-1/Tier-2 Supply Chain',
          status: 'Action Required',
          requirement: 'Vehicle manufacturers must identify and manage risks associated with dependencies across external component suppliers.',
          fleetStatus: 'Tier-1 OTA test private key found embedded in AeroDrive ECU production binary.'
        },
        {
          id: 'R155 Annex 5',
          name: 'Mitigation of Remote Vehicle Takeover Vectors',
          status: 'Compliant',
          requirement: 'Implement protection against unauthorized access to safety-critical CAN/Ethernet domains via diagnostic or wireless interfaces.',
          fleetStatus: 'Hardware Security Module (HSM) secure boot verified on Infineon AURIX.'
        },
        {
          id: 'R156 Clause 7.1',
          name: 'Cryptographic Software Update Validation',
          status: 'Compliant',
          requirement: 'All over-the-air firmware updates must be cryptographically authenticated and protected against tampering.',
          fleetStatus: 'ECDSA P-256 signature enforcement verified on central gateway.'
        }
      ]
    },
    'TSA Pipeline Directives': {
      title: 'TSA Security Directive Pipeline-2021-02C',
      sector: 'Oil & Gas Critical Infrastructure',
      description: 'Mandatory Transportation Security Administration cybersecurity performance requirements for designated critical natural gas and liquid petroleum pipelines.',
      articles: [
        {
          id: 'TSA SD 02C Sec III.A',
          name: 'Cybersecurity Incident Response & CISA KEV',
          status: 'Action Required',
          requirement: 'Mandatory 48-hour mitigation plan for known exploited vulnerabilities identified on OT systems.',
          fleetStatus: 'Log4j CVE-2021-44228 on ROC809 wellhead flow computer requires firewall quarantine.'
        },
        {
          id: 'TSA SD 02C Sec III.C',
          name: 'Safety Instrumented System (SIS) Isolation',
          status: 'Non-Compliant',
          requirement: 'Physical and logical segregation of safety shutdown controllers from operational networks.',
          fleetStatus: 'TricoSafe MP3008 SIS uses deprecated MD5 signature and unauthenticated maintenance port.'
        }
      ]
    }
  };

  const currentStandardInfo = standardsInfo[selectedStandard];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
            REGULATORY ASSURANCE
          </div>
          <h2 className="text-base font-bold text-slate-900 dark:text-white mt-0.5 flex items-center gap-2">
            <FileCheck2 className="w-5 h-5 text-emerald-600 dark:text-cyan-400" />
            <span>Sector Regulatory Compliance &amp; Audit Readiness Center</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Automated alignment with FDA Section 524B, NERC CIP-013-1, UNECE WP.29 R155/R156, and TSA Pipeline Directives.
          </p>
        </div>

        {/* Standard Picker */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {(Object.keys(standardsInfo) as (keyof typeof standardsInfo)[]).map((std) => (
            <button
              key={std}
              onClick={() => setSelectedStandard(std)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap cursor-pointer transition-colors border ${
                selectedStandard === std
                  ? 'bg-emerald-50 text-emerald-800 border-emerald-400 dark:bg-slate-800 dark:text-emerald-400 dark:border-emerald-500/50 shadow-xs'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-slate-900 dark:bg-slate-950 dark:text-slate-400 dark:border-slate-800'
              }`}
            >
              {std}
            </button>
          ))}
        </div>
      </div>

      {/* Standard Overview Banner */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
          <div>
            <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-600 dark:text-emerald-400 font-bold block">
              Regulatory Framework
            </span>
            <h3 className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
              {currentStandardInfo.title}
            </h3>
            <span className="text-xs text-slate-500 font-medium">
              Target Domain: {currentStandardInfo.sector}
            </span>
          </div>

          <button
            onClick={() => {
              const text = `REGULATORY AUDIT REPORT - ${currentStandardInfo.title}\nDomain: ${currentStandardInfo.sector}\nGenerated: ${new Date().toISOString()}\n\nArticles:\n${currentStandardInfo.articles.map(a => `[${a.status}] ${a.id}: ${a.name}\n${a.fleetStatus}`).join('\n\n')}`;
              navigator.clipboard.writeText(text);
              alert('Audit summary copied to clipboard!');
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors cursor-pointer shrink-0"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Copy Audit Dossier</span>
          </button>
        </div>

        <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed max-w-4xl">
          {currentStandardInfo.description}
        </p>
      </div>

      {/* Articles & Fleet Audit Checklist */}
      <div className="space-y-4">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
          Statutory Clause Evaluation &amp; Monitored Fleet Status
        </div>

        <div className="space-y-3">
          {currentStandardInfo.articles.map((art) => (
            <div
              key={art.id}
              className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-3"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-emerald-600 dark:text-emerald-400">
                      {art.id}
                    </span>
                    <span className="text-slate-300 dark:text-slate-600">·</span>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-200">
                      {art.name}
                    </h4>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 leading-relaxed">
                    {art.requirement}
                  </p>
                </div>

                <div className="shrink-0">
                  {art.status === 'Compliant' ? (
                    <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 px-2 py-0.5 rounded font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      COMPLIANT
                    </span>
                  ) : art.status === 'Action Required' ? (
                    <span className="flex items-center gap-1 text-[11px] font-mono text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800 px-2 py-0.5 rounded font-bold">
                      <AlertCircle className="w-3.5 h-3.5" />
                      ACTION REQUIRED
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[11px] font-mono text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 px-2 py-0.5 rounded font-bold">
                      <XCircle className="w-3.5 h-3.5" />
                      NON-COMPLIANT
                    </span>
                  )}
                </div>
              </div>

              {/* Monitored Fleet Observation */}
              <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-300">
                <span className="font-bold text-slate-500">Observed Fleet Evidence: </span>
                <span>{art.fleetStatus}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
