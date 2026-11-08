import React from 'react';
import { FirmwareAsset, SectorType, Vulnerability } from '../types/firmware';
import { SECTOR_METRICS_DATA } from '../data/firmwareData';
import {
  ShieldAlert,
  KeyRound,
  FileWarning,
  CheckCircle2,
  ExternalLink,
  Zap,
  Flame,
  HeartPulse,
  Car,
  ChevronRight,
  Filter
} from 'lucide-react';

interface ExecutiveOverviewProps {
  assets: FirmwareAsset[];
  selectedSector: SectorType | 'all';
  onSelectSector: (sector: SectorType | 'all') => void;
  onSelectAsset: (asset: FirmwareAsset) => void;
  onViewVexMatrix: () => void;
}

export const ExecutiveOverview: React.FC<ExecutiveOverviewProps> = ({
  assets,
  selectedSector,
  onSelectSector,
  onSelectAsset,
  onViewVexMatrix,
}) => {
  // Aggregate statistics
  const totalRawCves = assets.reduce((acc, a) => acc + a.rawCveCount, 0);
  const totalReachableCves = assets.reduce((acc, a) => acc + a.reachableCveCount, 0);
  const totalKevs = assets.reduce((acc, a) => acc + a.cisaKevCount, 0);
  const totalSecrets = assets.reduce((acc, a) => acc + a.secrets.length, 0);
  const totalUnsigned = assets.filter((a) => a.signatureStatus !== 'Signed & Valid').length;

  // Calculate noise reduction percentage
  const noiseReductionPercent = totalRawCves > 0
    ? Math.round(((totalRawCves - totalReachableCves) / totalRawCves) * 100)
    : 0;

  // Flatten critical weaponized vulnerabilities across current assets
  const criticalVulns: { asset: FirmwareAsset; vuln: Vulnerability }[] = [];
  assets.forEach((asset) => {
    asset.vulnerabilities.forEach((vuln) => {
      if (vuln.cisaKev || vuln.weaponizedPoc || vuln.vexStatus === 'affected_reachable') {
        criticalVulns.push({ asset, vuln });
      }
    });
  });

  const sectorIconMap: Record<SectorType, React.ReactNode> = {
    energy: <Zap className="w-4 h-4 text-amber-400" />,
    oil_gas: <Flame className="w-4 h-4 text-orange-400" />,
    healthcare: <HeartPulse className="w-4 h-4 text-rose-400" />,
    automotive: <Car className="w-4 h-4 text-cyan-400" />,
  };

  return (
    <div className="space-y-6">
      {/* Sector Strategic Posture Strip */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {(Object.keys(SECTOR_METRICS_DATA) as SectorType[]).map((secKey) => {
          const sec = SECTOR_METRICS_DATA[secKey];
          const isSelected = selectedSector === secKey;
          return (
            <div
              key={secKey}
              onClick={() => onSelectSector(isSelected ? 'all' : secKey)}
              className={`p-4 rounded-xl border transition-all cursor-pointer ${
                isSelected
                  ? 'bg-slate-900 border-cyan-500/60 shadow-lg shadow-cyan-950/30 ring-1 ring-cyan-500/30'
                  : 'bg-slate-900/50 border-slate-800 hover:border-slate-700 hover:bg-slate-900/80'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <div className="p-1.5 rounded-md bg-slate-800/80 border border-slate-700/50">
                    {sectorIconMap[secKey]}
                  </div>
                  <span className="text-xs font-semibold text-slate-200">{sec.title}</span>
                </div>
                <span className="font-mono text-xs font-bold tabular-nums text-slate-400">
                  {sec.riskScore}
                  <span className="text-[10px] text-slate-600 font-normal">/100 RISK</span>
                </span>
              </div>

              {/* Progress track */}
              <div className="w-full bg-slate-950 rounded-full h-1.5 mb-3 overflow-hidden">
                <div
                  className={`h-full rounded-full ${
                    sec.riskScore >= 85
                      ? 'bg-rose-500'
                      : sec.riskScore >= 75
                      ? 'bg-amber-500'
                      : 'bg-cyan-500'
                  }`}
                  style={{ width: `${sec.riskScore}%` }}
                />
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-slate-500 text-[11px] block">Reachable KEV</span>
                  <span className="font-mono font-semibold text-rose-400 tabular-nums">
                    {sec.activeKevCount} active
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 text-[11px] block">SBOM Health</span>
                  <span className="font-mono font-semibold text-slate-300 tabular-nums">
                    {sec.avgSbomScore}% complete
                  </span>
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
                <span>{sec.primaryStandard}</span>
                <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
              </div>
            </div>
          );
        })}
      </div>

      {/* Primary KPI Grid (High Density) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Raw CVEs */}
        <div className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800/90">
          <div className="text-[11px] text-slate-400 uppercase tracking-wider font-medium mb-1">
            Raw CVEs Found
          </div>
          <div className="font-mono text-2xl font-bold text-slate-200 tabular-nums">
            {totalRawCves}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Static binary scan count
          </div>
        </div>

        {/* Reachable & Actionable */}
        <div className="p-3.5 rounded-lg bg-rose-950/20 border border-rose-900/40">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] text-rose-400 uppercase tracking-wider font-semibold">
              Reachable (Action)
            </span>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="font-mono text-2xl font-bold text-rose-300 tabular-nums">
            {totalReachableCves}
          </div>
          <div className="text-[11px] text-rose-400/80 mt-1">
            Reachable call paths
          </div>
        </div>

        {/* CISA KEV Exploited */}
        <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-900/40">
          <div className="text-[11px] text-amber-400 uppercase tracking-wider font-semibold mb-1">
            Active CISA KEV
          </div>
          <div className="font-mono text-2xl font-bold text-amber-300 tabular-nums">
            {totalKevs}
          </div>
          <div className="text-[11px] text-amber-400/80 mt-1">
            Weaponized in the wild
          </div>
        </div>

        {/* VEX Noise Elimination */}
        <div className="p-3.5 rounded-lg bg-emerald-950/20 border border-emerald-900/40">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] text-emerald-400 uppercase tracking-wider font-semibold">
              VEX Noise Reduction
            </span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="font-mono text-2xl font-bold text-emerald-300 tabular-nums">
            {noiseReductionPercent}%
          </div>
          <div className="text-[11px] text-emerald-400/80 mt-1">
            Suppressed non-reachable
          </div>
        </div>

        {/* Exposed Firmware Secrets */}
        <div className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800/90">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-medium">
              Flash Secrets Found
            </span>
            <KeyRound className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="font-mono text-2xl font-bold text-cyan-300 tabular-nums">
            {totalSecrets}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            RSA keys, tokens, backdoors
          </div>
        </div>

        {/* Unsigned / Broken Signatures */}
        <div className="p-3.5 rounded-lg bg-slate-900/40 border border-slate-800/90">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider font-medium">
              Integrity Status
            </span>
            <FileWarning className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="font-mono text-2xl font-bold text-slate-200 tabular-nums">
            {totalUnsigned}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            Deprecated MD5 / Unsigned
          </div>
        </div>
      </div>

      {/* Alert-Fatigue Elimination Engine Banner */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
              Binary Composition & Static Reachability Filter
            </span>
            <span className="text-xs text-slate-500">·</span>
            <span className="text-xs text-slate-400">VEX Justification Architecture</span>
          </div>
          <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
            Raw CVE scanners generate severe alert fatigue across embedded Linux and RTOS images. FirmwareGuard traces binary symbol call-graphs from external network/CAN/bus interfaces: of <span className="font-mono text-white font-semibold tabular-nums">{totalRawCves}</span> detected CVEs, only <span className="font-mono text-rose-400 font-semibold tabular-nums">{totalReachableCves}</span> execute in active code paths. <span className="font-mono text-emerald-400 font-semibold tabular-nums">{totalRawCves - totalReachableCves}</span> CVEs are safely suppressed with machine-readable VEX statements.
          </p>
        </div>
        <button
          onClick={onViewVexMatrix}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 bg-cyan-950/40 border border-cyan-800/60 rounded-lg transition-colors whitespace-nowrap cursor-pointer shrink-0"
        >
          <Filter className="w-3.5 h-3.5" />
          <span>Explore Reachability Graph</span>
        </button>
      </div>

      {/* Main Two-Column Layout: Weaponized Attacks vs Target Fleet Inventory */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Top Weaponized Vulnerabilities (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>Priority Weaponized CVEs (Active Fleet Threat)</span>
            </h3>
            <span className="text-xs text-slate-500">
              {criticalVulns.length} actionable
            </span>
          </div>

          <div className="space-y-2.5">
            {criticalVulns.slice(0, 4).map(({ asset, vuln }) => (
              <div
                key={`${asset.id}-${vuln.id}`}
                className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-start justify-between gap-3 mb-1.5">
                  <div>
                    <span className="font-mono text-xs font-bold text-rose-400">
                      {vuln.id}
                    </span>
                    <span className="text-slate-500 mx-1.5 text-xs">·</span>
                    <span className="text-xs font-semibold text-slate-200">
                      {vuln.component} {vuln.version}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {vuln.cisaKev && (
                      <span className="text-[10px] font-mono text-rose-400 bg-rose-950/60 border border-rose-800/50 px-1.5 py-0.5 rounded">
                        CISA KEV
                      </span>
                    )}
                    <span className="font-mono text-xs font-bold text-rose-300 tabular-nums">
                      CVSS {vuln.cvss}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 line-clamp-2 mb-2">
                  {vuln.name}
                </p>

                {/* Specific sector impact */}
                {(vuln.clinicalImpact || vuln.gridImpact || vuln.safetyImpact) && (
                  <div className="p-2 rounded bg-slate-950/60 border border-slate-800/60 text-[11px] text-amber-300/90 mb-2 leading-tight">
                    <span className="font-semibold text-slate-400">Mission Impact: </span>
                    {vuln.clinicalImpact || vuln.gridImpact || vuln.safetyImpact}
                  </div>
                )}

                {/* Reachability Call Path preview */}
                {vuln.reachabilityPath && (
                  <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1 truncate">
                    <span className="text-slate-500">Path:</span>
                    <span className="text-cyan-400 truncate">
                      {vuln.reachabilityPath.join(' → ')}
                    </span>
                  </div>
                )}

                <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px]">
                  <span className="text-slate-500">Target: {asset.name}</span>
                  <button
                    onClick={() => onSelectAsset(asset)}
                    className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 cursor-pointer"
                  >
                    <span>Inspect Target</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Fleet Asset Inventory (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200">
              Monitored Firmware Deployments
            </h3>
            <span className="text-xs text-slate-500">
              Showing {assets.length} assets
            </span>
          </div>

          <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/40">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 font-medium">
                  <tr>
                    <th className="py-2.5 px-3">Device / Firmware</th>
                    <th className="py-2.5 px-3">Sector</th>
                    <th className="py-2.5 px-3">Arch & OS</th>
                    <th className="py-2.5 px-3 text-right">Raw CVE</th>
                    <th className="py-2.5 px-3 text-right">Reachable</th>
                    <th className="py-2.5 px-3 text-center">Integrity</th>
                    <th className="py-2.5 px-3 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {assets.map((asset) => (
                    <tr
                      key={asset.id}
                      className="hover:bg-slate-800/30 transition-colors group cursor-pointer"
                      onClick={() => onSelectAsset(asset)}
                    >
                      <td className="py-3 px-3">
                        <div className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors">
                          {asset.name}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono">
                          {asset.model} · {asset.version}
                        </div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="capitalize text-slate-300">
                          {asset.sector.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <div className="text-slate-300 font-mono text-[11px]">
                          {asset.architecture}
                        </div>
                        <div className="text-slate-500 text-[11px]">
                          {asset.osType}
                        </div>
                      </td>
                      <td className="py-3 px-3 text-right font-mono tabular-nums text-slate-400">
                        {asset.rawCveCount}
                      </td>
                      <td className="py-3 px-3 text-right">
                        <span
                          className={`font-mono font-bold tabular-nums ${
                            asset.reachableCveCount > 0
                              ? 'text-rose-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {asset.reachableCveCount}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            asset.signatureStatus === 'Signed & Valid'
                              ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800/40'
                              : 'text-rose-400 bg-rose-950/40 border-rose-800/40'
                          }`}
                        >
                          {asset.signatureStatus}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-center">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAsset(asset);
                          }}
                          className="px-2 py-1 text-[11px] text-cyan-400 hover:text-cyan-300 hover:bg-cyan-950/40 rounded transition-colors"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
