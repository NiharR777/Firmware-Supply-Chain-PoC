import React, { useState } from 'react';
import { FirmwareAsset, VexStatusType, Vulnerability } from '../types/firmware';
import {
  ShieldAlert,
  ShieldCheck,
  Filter,
  ArrowRight,
  CheckCircle2,
  Info,
  Copy,
  Check,
  Search
} from 'lucide-react';

interface VexMatrixProps {
  assets: FirmwareAsset[];
  onOpenExportModal: () => void;
}

export const VexMatrix: React.FC<VexMatrixProps> = ({ assets, onOpenExportModal }) => {
  const [selectedVexFilter, setSelectedVexFilter] = useState<VexStatusType | 'all'>('all');
  const [activeVulnDetail, setActiveVulnDetail] = useState<{ asset: FirmwareAsset; vuln: Vulnerability } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [matrixSearch, setMatrixSearch] = useState('');

  // Collect all vulnerabilities across assets with their parent asset reference
  const allVulns: { asset: FirmwareAsset; vuln: Vulnerability }[] = [];
  assets.forEach((asset) => {
    asset.vulnerabilities.forEach((vuln) => {
      allVulns.push({ asset, vuln });
    });
  });

  const filteredVulns = allVulns.filter(({ asset, vuln }) => {
    if (selectedVexFilter !== 'all' && vuln.vexStatus !== selectedVexFilter) {
      return false;
    }
    if (matrixSearch.trim()) {
      const q = matrixSearch.toLowerCase();
      const matchId = vuln.id.toLowerCase().includes(q);
      const matchComp = vuln.component.toLowerCase().includes(q);
      const matchAsset = asset.name.toLowerCase().includes(q);
      const matchJust = vuln.vexJustification.toLowerCase().includes(q);
      return matchId || matchComp || matchAsset || matchJust;
    }
    return true;
  });

  const counts: Record<VexStatusType | 'all', number> = {
    all: allVulns.length,
    affected_reachable: allVulns.filter((v) => v.vuln.vexStatus === 'affected_reachable').length,
    affected_not_reachable: allVulns.filter((v) => v.vuln.vexStatus === 'affected_not_reachable').length,
    mitigated: allVulns.filter((v) => v.vuln.vexStatus === 'mitigated').length,
    not_affected: allVulns.filter((v) => v.vuln.vexStatus === 'not_affected').length,
  };

  const copyVexStatement = (vuln: Vulnerability) => {
    const statement = `VEX STATEMENT [${vuln.id}]: Status: ${vuln.vexStatus.toUpperCase()} - Justification: ${vuln.vexJustification}`;
    navigator.clipboard.writeText(statement);
    setCopiedId(vuln.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getStatusBadge = (status: VexStatusType) => {
    switch (status) {
      case 'affected_reachable':
        return (
          <span className="text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/60 border border-rose-300 dark:border-rose-800/60 px-2 py-0.5 rounded text-[11px] font-mono font-semibold flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            Reachable &amp; Critical
          </span>
        );
      case 'affected_not_reachable':
        return (
          <span className="text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800/40 px-2 py-0.5 rounded text-[11px] font-mono font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
            Dead Code / Uncalled
          </span>
        );
      case 'mitigated':
        return (
          <span className="text-cyan-700 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/40 border border-cyan-300 dark:border-cyan-800/40 px-2 py-0.5 rounded text-[11px] font-mono font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
            Compensating Mitigations
          </span>
        );
      case 'not_affected':
        return (
          <span className="text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800/40 px-2 py-0.5 rounded text-[11px] font-mono font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            Config Disabled / Absent
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* VEX Filter & Methodology Banner */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
              VEX &amp; REACHABILITY
            </div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white mt-0.5 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-emerald-600 dark:text-cyan-400" />
              <span>VEX Exploitability &amp; Static Reachability Matrix</span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              FDA 524B and NERC CIP-013 compliant Vulnerability Exploitability eXchange classification engine.
            </p>
          </div>
          <button
            onClick={onOpenExportModal}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors whitespace-nowrap cursor-pointer shrink-0 shadow-xs"
          >
            <span>Generate Machine-Readable VEX (CycloneDX 1.5)</span>
          </button>
        </div>

        {/* Filter Tabs */}
        <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              onClick={() => setSelectedVexFilter('all')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors border ${
                selectedVexFilter === 'all'
                  ? 'bg-slate-900 text-white border-slate-900 dark:bg-slate-800 dark:text-slate-100 dark:border-slate-600'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100 dark:bg-slate-950 dark:text-slate-400 dark:border-slate-800'
              }`}
            >
              All Items ({counts.all})
            </button>
            <button
              onClick={() => setSelectedVexFilter('affected_reachable')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors border ${
                selectedVexFilter === 'affected_reachable'
                  ? 'bg-rose-100 text-rose-800 border-rose-400 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-700 font-bold'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-rose-700 dark:bg-slate-950 dark:text-slate-400 dark:border-slate-800'
              }`}
            >
              Reachable &amp; Actionable ({counts.affected_reachable})
            </button>
            <button
              onClick={() => setSelectedVexFilter('affected_not_reachable')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors border ${
                selectedVexFilter === 'affected_not_reachable'
                  ? 'bg-amber-100 text-amber-800 border-amber-400 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-700 font-bold'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-amber-700 dark:bg-slate-950 dark:text-slate-400 dark:border-slate-800'
              }`}
            >
              Dead Code ({counts.affected_not_reachable})
            </button>
            <button
              onClick={() => setSelectedVexFilter('mitigated')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors border ${
                selectedVexFilter === 'mitigated'
                  ? 'bg-cyan-100 text-cyan-800 border-cyan-400 dark:bg-cyan-950/80 dark:text-cyan-300 dark:border-cyan-700 font-bold'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-cyan-700 dark:bg-slate-950 dark:text-slate-400 dark:border-slate-800'
              }`}
            >
              Mitigated ({counts.mitigated})
            </button>
            <button
              onClick={() => setSelectedVexFilter('not_affected')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors border ${
                selectedVexFilter === 'not_affected'
                  ? 'bg-emerald-100 text-emerald-800 border-emerald-400 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-700 font-bold'
                  : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-emerald-700 dark:bg-slate-950 dark:text-slate-400 dark:border-slate-800'
              }`}
            >
              Disabled in Config ({counts.not_affected})
            </button>
          </div>

          <div className="relative w-full sm:w-56">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={matrixSearch}
              onChange={(e) => setMatrixSearch(e.target.value)}
              placeholder="Filter CVE or justification..."
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:border-emerald-500"
            />
          </div>
        </div>
      </div>

      {/* Main Table + Reachability Drawer Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Table View (8 Cols) */}
        <div className="lg:col-span-8 overflow-hidden rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-850 text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-semibold">
                <tr>
                  <th className="py-3 px-4">Vulnerability</th>
                  <th className="py-3 px-4">Component</th>
                  <th className="py-3 px-4">Host Device</th>
                  <th className="py-3 px-4 text-center">CVSS / EPSS</th>
                  <th className="py-3 px-4">VEX Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {filteredVulns.map(({ asset, vuln }) => {
                  const isSelected = activeVulnDetail?.vuln.id === vuln.id;
                  return (
                    <tr
                      key={`${asset.id}-${vuln.id}`}
                      onClick={() => setActiveVulnDetail({ asset, vuln })}
                      className={`hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer ${
                        isSelected ? 'bg-emerald-50/50 dark:bg-slate-800/60' : ''
                      }`}
                    >
                      <td className="py-3 px-4">
                        <div className="font-mono font-bold text-slate-900 dark:text-slate-200">
                          {vuln.id}
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-1 max-w-xs">
                          {vuln.name}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-700 dark:text-slate-300">
                        {vuln.component}
                        <span className="text-slate-400 block text-[10px]">{vuln.version}</span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="text-slate-900 dark:text-slate-200 font-semibold truncate max-w-[140px]">
                          {asset.name}
                        </div>
                        <div className="text-[10px] text-slate-500 uppercase">
                          {asset.sector.replace('_', ' ')}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-center">
                        <span
                          className={`font-mono font-bold tabular-nums ${
                            vuln.cvss >= 9.0
                              ? 'text-rose-600 dark:text-rose-400'
                              : vuln.cvss >= 7.0
                              ? 'text-amber-600 dark:text-amber-400'
                              : 'text-slate-700 dark:text-slate-300'
                          }`}
                        >
                          {vuln.cvss}
                        </span>
                        <div className="text-[10px] text-slate-400 font-mono">
                          EPSS {(vuln.epss * 100).toFixed(0)}%
                        </div>
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        {getStatusBadge(vuln.vexStatus)}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyVexStatement(vuln);
                          }}
                          title="Copy Machine VEX Statement"
                          className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-emerald-600 transition-colors cursor-pointer"
                        >
                          {copiedId === vuln.id ? (
                            <Check className="w-3.5 h-3.5 text-emerald-600" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Reachability Call Path Inspector Drawer (4 Cols) */}
        <div className="lg:col-span-4">
          {activeVulnDetail ? (
            <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-4 sticky top-20">
              <div className="border-b border-slate-100 dark:border-slate-800 pb-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-rose-600 dark:text-rose-400">
                    {activeVulnDetail.vuln.id}
                  </span>
                  {getStatusBadge(activeVulnDetail.vuln.vexStatus)}
                </div>
                <h4 className="text-sm font-bold text-slate-900 dark:text-white mt-1">
                  {activeVulnDetail.vuln.name}
                </h4>
                <div className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
                  Host: {activeVulnDetail.asset.name} ({activeVulnDetail.asset.model})
                </div>
              </div>

              {/* VEX Justification */}
              <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-1">
                <span className="text-[10px] font-bold text-emerald-600 dark:text-emerald-400 uppercase tracking-wider block">
                  Official VEX Justification
                </span>
                <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                  {activeVulnDetail.vuln.vexJustification}
                </p>
              </div>

              {/* Static Call Path Trace */}
              {activeVulnDetail.vuln.reachabilityPath && (
                <div className="space-y-2">
                  <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                    <ArrowRight className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                    <span>Binary Execution Call Path</span>
                  </span>
                  <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2 font-mono text-[11px]">
                    {activeVulnDetail.vuln.reachabilityPath.map((step, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <span className="text-slate-400 font-bold">{idx + 1}.</span>
                        <span
                          className={`${
                            idx === (activeVulnDetail.vuln.reachabilityPath?.length ?? 1) - 1
                              ? 'text-rose-600 dark:text-rose-400 font-bold bg-rose-50 dark:bg-rose-950/60 px-1.5 py-0.5 rounded border border-rose-200 dark:border-rose-900'
                              : 'text-slate-700 dark:text-slate-300'
                          }`}
                        >
                          {step}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sector Specific Risk Statement */}
              {(activeVulnDetail.vuln.clinicalImpact ||
                activeVulnDetail.vuln.gridImpact ||
                activeVulnDetail.vuln.safetyImpact) && (
                <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-900/50 space-y-1">
                  <span className="text-[10px] font-bold text-amber-800 dark:text-amber-300 uppercase tracking-wider block">
                    Domain Safety Risk
                  </span>
                  <p className="text-xs text-amber-900 dark:text-amber-200/90 leading-relaxed">
                    {activeVulnDetail.vuln.clinicalImpact ||
                      activeVulnDetail.vuln.gridImpact ||
                      activeVulnDetail.vuln.safetyImpact}
                  </p>
                </div>
              )}

              <button
                onClick={() => copyVexStatement(activeVulnDetail.vuln)}
                className="w-full py-2 px-3 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors flex items-center justify-center gap-1.5 cursor-pointer shadow-xs"
              >
                {copiedId === activeVulnDetail.vuln.id ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Copied VEX Statement</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy Machine VEX Statement</span>
                  </>
                )}
              </button>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center text-xs text-slate-500">
              Select any vulnerability row to view the static reachability trace and clinical/grid risk justification.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
