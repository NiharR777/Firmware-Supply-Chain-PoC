import React, { useState } from 'react';
import { FirmwareAsset } from '../types/firmware';
import {
  X,
  Cpu,
  Layers,
  ShieldAlert,
  ShieldCheck,
  KeyRound,
  FileCheck2,
  CheckCircle2,
  XCircle,
  Hash,
  AlertTriangle,
  ArrowRight
} from 'lucide-react';

interface AssetDetailModalProps {
  asset: FirmwareAsset | null;
  onClose: () => void;
  onOpenExportModal: () => void;
}

export const AssetDetailModal: React.FC<AssetDetailModalProps> = ({
  asset,
  onClose,
  onOpenExportModal,
}) => {
  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'components' | 'hardening' | 'secrets' | 'compliance'>('vulnerabilities');

  if (!asset) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 font-semibold">
                {asset.sector.replace('_', ' ')} SECTOR
              </span>
              <span className="text-slate-500">·</span>
              <span className="text-xs text-slate-400 font-mono">
                {asset.architecture} · {asset.osType}
              </span>
            </div>
            <h3 className="text-lg font-bold text-slate-100 mt-0.5">
              {asset.name}
            </h3>
            <div className="text-xs text-slate-400 mt-0.5">
              Model: <span className="text-slate-200 font-mono">{asset.model}</span> · Version: <span className="text-slate-200 font-mono">{asset.version}</span> · Manufacturer: {asset.manufacturer}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onOpenExportModal}
              className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors cursor-pointer"
            >
              Export VEX
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-5 border-b border-slate-800 bg-slate-950/60 overflow-x-auto">
          {[
            { id: 'vulnerabilities', label: `Reachable Vulnerabilities (${asset.vulnerabilities.length})` },
            { id: 'components', label: `Bill of Materials (${asset.components.length})` },
            { id: 'hardening', label: 'Binary Hardening' },
            { id: 'secrets', label: `Flash Secrets (${asset.secrets.length})` },
            { id: 'compliance', label: `Compliance Gaps (${asset.complianceGaps.length})` },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`py-3 px-3 text-xs font-medium border-b-2 cursor-pointer whitespace-nowrap transition-colors ${
                activeTab === tab.id
                  ? 'border-cyan-400 text-cyan-400 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {/* VULNERABILITIES TAB */}
          {activeTab === 'vulnerabilities' && (
            <div className="space-y-3">
              {asset.vulnerabilities.map((vuln) => (
                <div
                  key={vuln.id}
                  className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-rose-400">
                          {vuln.id}
                        </span>
                        <span className="text-slate-500">·</span>
                        <span className="text-xs font-semibold text-slate-200">
                          {vuln.component} {vuln.version}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-300 mt-1">
                        {vuln.name}
                      </h4>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-rose-300">
                        CVSS {vuln.cvss}
                      </span>
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          vuln.vexStatus === 'affected_reachable'
                            ? 'text-rose-400 bg-rose-950/60 border-rose-800'
                            : vuln.vexStatus === 'affected_not_reachable'
                            ? 'text-amber-400 bg-amber-950/60 border-amber-800'
                            : 'text-emerald-400 bg-emerald-950/60 border-emerald-800'
                        }`}
                      >
                        {vuln.vexStatus.toUpperCase()}
                      </span>
                    </div>
                  </div>

                  {/* Justification */}
                  <div className="text-xs text-slate-400 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/60">
                    <span className="font-semibold text-slate-300">VEX Justification: </span>
                    {vuln.vexJustification}
                  </div>

                  {/* Reachability Call Path */}
                  {vuln.reachabilityPath && (
                    <div className="p-2.5 rounded bg-slate-900/60 border border-slate-800/60 space-y-1">
                      <span className="text-[11px] font-semibold text-cyan-400 block">
                        Static Call Path Trace:
                      </span>
                      <div className="font-mono text-[11px] text-slate-300 flex items-center gap-1.5 flex-wrap">
                        {vuln.reachabilityPath.map((step, idx) => (
                          <React.Fragment key={idx}>
                            <span
                              className={
                                idx === (vuln.reachabilityPath?.length ?? 1) - 1
                                  ? 'text-rose-400 font-bold'
                                  : 'text-slate-300'
                              }
                            >
                              {step}
                            </span>
                            {idx < (vuln.reachabilityPath?.length ?? 1) - 1 && (
                              <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Sector specific risk statement */}
                  {(vuln.clinicalImpact || vuln.gridImpact || vuln.safetyImpact) && (
                    <div className="text-xs text-amber-300 bg-amber-950/30 p-2.5 rounded border border-amber-900/50">
                      <span className="font-semibold">Sector Safety Impact: </span>
                      {vuln.clinicalImpact || vuln.gridImpact || vuln.safetyImpact}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* COMPONENTS TAB */}
          {activeTab === 'components' && (
            <div className="space-y-3">
              {asset.components.map((comp) => (
                <div
                  key={comp.id}
                  className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <h4 className="text-xs font-bold text-slate-100">
                          {comp.name}
                        </h4>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                          {comp.version}
                        </span>
                        <span className="text-xs text-slate-500">· {comp.tier}</span>
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        Supplier: {comp.supplier} · License: {comp.license}
                      </div>
                    </div>

                    <div className="text-right">
                      <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2 py-0.5 rounded font-bold">
                        SLSA Level {comp.slsaLevel}
                      </span>
                    </div>
                  </div>

                  <div className="font-mono text-[11px] text-slate-500 break-all bg-slate-900/80 p-2 rounded">
                    SHA-256: {comp.sha256}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* HARDENING TAB */}
          {activeTab === 'hardening' && (
            <div className="grid grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-bold text-slate-200">NX / DEP</div>
                  <div className="text-[11px] text-slate-500">Stack Execution Prevention</div>
                </div>
                {asset.hardening.nxDep ? (
                  <span className="text-emerald-400 text-xs font-mono font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-4 h-4" /> ENABLED
                  </span>
                ) : (
                  <span className="text-rose-400 text-xs font-mono font-bold flex items-center gap-1">
                    <XCircle className="w-4 h-4" /> DISABLED
                  </span>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-bold text-slate-200">ASLR / PIE</div>
                  <div className="text-[11px] text-slate-500">Address Space Layout Randomization</div>
                </div>
                {asset.hardening.aslrPie ? (
                  <span className="text-emerald-400 text-xs font-mono font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-4 h-4" /> ENABLED
                  </span>
                ) : (
                  <span className="text-amber-400 text-xs font-mono font-bold flex items-center gap-1">
                    <AlertTriangle className="w-4 h-4" /> N/A (RTOS)
                  </span>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-bold text-slate-200">Stack Canaries</div>
                  <div className="text-[11px] text-slate-500">-fstack-protector-strong</div>
                </div>
                {asset.hardening.stackCanary ? (
                  <span className="text-emerald-400 text-xs font-mono font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-4 h-4" /> PRESENT
                  </span>
                ) : (
                  <span className="text-rose-400 text-xs font-mono font-bold flex items-center gap-1">
                    <XCircle className="w-4 h-4" /> ABSENT
                  </span>
                )}
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-xs font-bold text-slate-200">RELRO Protection</div>
                  <div className="text-[11px] text-slate-500">Read-Only Relocations</div>
                </div>
                <span className="text-slate-200 font-mono text-xs font-bold">
                  {asset.hardening.relro} RELRO
                </span>
              </div>
            </div>
          )}

          {/* SECRETS TAB */}
          {activeTab === 'secrets' && (
            <div className="space-y-3">
              {asset.secrets.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500 bg-slate-950 rounded-xl border border-slate-800">
                  No exposed cryptographic secrets or debug stubs found in this build.
                </div>
              ) : (
                asset.secrets.map((sec) => (
                  <div
                    key={sec.id}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-xs text-rose-400">
                        {sec.type}
                      </span>
                      <span className="text-[10px] font-mono text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-800">
                        {sec.severity}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-cyan-400">
                      {sec.location}
                    </div>
                    <pre className="p-2.5 rounded bg-slate-900 text-slate-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                      {sec.snippet}
                    </pre>
                    <p className="text-xs text-slate-400">{sec.riskDescription}</p>
                  </div>
                ))
              )}
            </div>
          )}

          {/* COMPLIANCE TAB */}
          {activeTab === 'compliance' && (
            <div className="space-y-3">
              {asset.complianceGaps.map((gap, idx) => (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-xs text-cyan-400">
                      {gap.standard}
                    </span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        gap.status === 'Compliant'
                          ? 'text-emerald-400 bg-emerald-950/60 border-emerald-800'
                          : 'text-amber-400 bg-amber-950/60 border-amber-800'
                      }`}
                    >
                      {gap.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{gap.details}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
