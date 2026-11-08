import React, { useState } from 'react';
import { FirmwareAsset, SupplyChainComponent } from '../types/firmware';
import {
  GitBranch,
  Cpu,
  Layers,
  Package,
  Code2,
  ShieldCheck,
  ShieldAlert,
  Hash,
  CheckCircle2,
  XCircle,
  ChevronRight
} from 'lucide-react';

interface PedigreeGraphProps {
  assets: FirmwareAsset[];
  onSelectAsset: (asset: FirmwareAsset) => void;
}

export const PedigreeGraph: React.FC<PedigreeGraphProps> = ({ assets, onSelectAsset }) => {
  const [selectedAssetId, setSelectedAssetId] = useState<string>(assets[0]?.id || '');
  const [selectedComponent, setSelectedComponent] = useState<SupplyChainComponent | null>(
    assets[0]?.components[0] || null
  );

  const currentAsset = assets.find((a) => a.id === selectedAssetId) || assets[0];

  const layerConfig = [
    { key: 'silicon_bsp', title: 'Tier-2 Silicon & BSP', icon: <Cpu className="w-4 h-4 text-amber-500" />, desc: 'Hardware abstraction, vendor HAL & SoC microcode' },
    { key: 'rtos_kernel', title: 'Tier-1 RTOS & Kernel', icon: <Layers className="w-4 h-4 text-cyan-500" />, desc: 'Real-time OS, memory management & task schedulers' },
    { key: 'middleware', title: 'Middleware & Protocol Stacks', icon: <Package className="w-4 h-4 text-indigo-500" />, desc: 'Network, cryptographic, TLS & industrial bus libraries' },
    { key: 'app_logic', title: 'OEM Application Logic', icon: <Code2 className="w-4 h-4 text-emerald-500" />, desc: 'Proprietary mission-critical controllers & telemetry engines' },
  ];

  return (
    <div className="space-y-6">
      {/* Asset Selector Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
            SUPPLY CHAIN PROVENANCE
          </div>
          <h2 className="text-base font-bold text-slate-900 dark:text-white mt-0.5 flex items-center gap-2">
            <GitBranch className="w-5 h-5 text-emerald-600 dark:text-cyan-400" />
            <span>Multi-Tier Supply Chain Pedigree &amp; Provenance Explorer</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Cryptographic verification and component lineage from silicon hardware vendor to proprietary OEM binary.
          </p>
        </div>

        {/* Device Switcher */}
        <div className="flex items-center gap-2">
          <label className="text-xs text-slate-600 dark:text-slate-400 font-medium">Target Device:</label>
          <select
            value={currentAsset?.id}
            onChange={(e) => {
              setSelectedAssetId(e.target.value);
              const found = assets.find((a) => a.id === e.target.value);
              if (found && found.components.length > 0) {
                setSelectedComponent(found.components[0]);
              }
            }}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-900 dark:text-slate-200 focus:outline-none focus:border-emerald-500"
          >
            {assets.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.model}) - {a.sector.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Pedigree Tree & Detail Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Visual Pedigree Flow Layers (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            Architectural Supply Chain Hierarchy
          </div>

          <div className="space-y-4 relative">
            {/* Vertical connector line */}
            <div className="absolute left-6 top-8 bottom-8 w-0.5 bg-slate-200 dark:bg-slate-800 pointer-events-none" />

            {layerConfig.map((layer, idx) => {
              const compsInLayer = currentAsset.components.filter((c) => c.layer === layer.key);

              return (
                <div key={layer.key} className="relative pl-12">
                  {/* Step indicator node */}
                  <div className="absolute left-4 top-3 -translate-x-1/2 w-5 h-5 rounded-full bg-white dark:bg-slate-950 border-2 border-slate-300 dark:border-slate-700 flex items-center justify-center text-[10px] font-mono text-slate-600 dark:text-slate-400 z-10">
                    {idx + 1}
                  </div>

                  <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {layer.icon}
                        <h4 className="text-xs font-bold text-slate-900 dark:text-slate-200">{layer.title}</h4>
                      </div>
                      <span className="text-[11px] text-slate-400">{layer.desc}</span>
                    </div>

                    {compsInLayer.length === 0 ? (
                      <div className="text-xs text-slate-400 italic py-2">
                        No components mapped at this tier in current SBOM view.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 mt-2">
                        {compsInLayer.map((comp) => {
                          const isSelected = selectedComponent?.id === comp.id;
                          return (
                            <div
                              key={comp.id}
                              onClick={() => setSelectedComponent(comp)}
                              className={`p-3 rounded-lg border transition-all cursor-pointer ${
                                isSelected
                                  ? 'bg-emerald-50 border-emerald-500 dark:bg-slate-800/90 dark:border-emerald-400 shadow-xs'
                                  : 'bg-slate-50 dark:bg-slate-950/60 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                              }`}
                            >
                              <div className="flex items-start justify-between gap-1 mb-1">
                                <span className="font-bold text-xs text-slate-900 dark:text-slate-200 truncate">
                                  {comp.name}
                                </span>
                                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 shrink-0">
                                  {comp.version}
                                </span>
                              </div>

                              <div className="flex items-center justify-between text-[11px] text-slate-500 mt-2">
                                <span className="truncate">{comp.supplier}</span>
                                <div className="flex items-center gap-1.5 shrink-0">
                                  {comp.hashVerified ? (
                                    <span title="SHA-256 Hash Verified">
                                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                                    </span>
                                  ) : (
                                    <span title="Unverified Hash">
                                      <XCircle className="w-3.5 h-3.5 text-rose-600" />
                                    </span>
                                  )}
                                  <span
                                    className={`font-mono text-[10px] px-1 rounded ${
                                      comp.reachableCveCount > 0
                                        ? 'text-rose-700 bg-rose-100 dark:text-rose-400 dark:bg-rose-950/60 font-bold'
                                        : 'text-slate-400'
                                    }`}
                                  >
                                    {comp.reachableCveCount > 0
                                      ? `${comp.reachableCveCount} Reachable`
                                      : `${comp.cveCount} CVEs`}
                                  </span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Component Provenance & Cryptographic Attestation (5 Cols) */}
        <div className="lg:col-span-5">
          {selectedComponent ? (
            <div className="sticky top-20 p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-4">
              <div className="flex items-start justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-emerald-600 dark:text-emerald-400 font-bold">
                    Component Provenance Record
                  </div>
                  <h3 className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
                    {selectedComponent.name}
                  </h3>
                  <div className="text-xs text-slate-500 font-mono mt-0.5">
                    Version: {selectedComponent.version} · {selectedComponent.tier}
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-[10px] block text-slate-400">License</span>
                  <span className="font-mono text-xs text-slate-800 dark:text-slate-200 font-semibold">
                    {selectedComponent.license}
                  </span>
                </div>
              </div>

              {/* SLSA Provenance Level */}
              <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                    <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                    <span>SLSA Build Provenance</span>
                  </span>
                  <span className="font-mono text-xs font-bold text-emerald-600 dark:text-emerald-400">
                    SLSA Level {selectedComponent.slsaLevel} / 3
                  </span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                  {selectedComponent.slsaLevel === 3
                    ? 'Hardened build platform with isolated hermetic environment & cryptographic non-falsifiable provenance.'
                    : selectedComponent.slsaLevel === 2
                    ? 'Version-controlled source with hosted build service and signed build service attestations.'
                    : selectedComponent.slsaLevel === 1
                    ? 'Basic script-driven build without tamper-proof logging; requires manual supply chain audit.'
                    : 'Unverified binary build artifact. High risk of upstream supply chain poisoning.'}
                </p>
              </div>

              {/* Cryptographic SHA-256 Hash Verification */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 dark:text-slate-400 flex items-center gap-1">
                    <Hash className="w-3.5 h-3.5 text-slate-400" />
                    <span>SHA-256 Hash Digest</span>
                  </span>
                  <span
                    className={`font-semibold text-[11px] ${
                      selectedComponent.hashVerified ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400'
                    }`}
                  >
                    {selectedComponent.hashVerified ? 'MATCHES VENDOR SBOM' : 'MISMATCH / UNATTESTED'}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all border border-slate-200 dark:border-slate-800">
                  {selectedComponent.sha256}
                </div>
              </div>

              {/* Supplier & Sourcing Info */}
              <div className="grid grid-cols-2 gap-3 text-xs pt-2 border-t border-slate-100 dark:border-slate-800">
                <div>
                  <span className="text-slate-400 block text-[10px]">Primary Supplier</span>
                  <span className="text-slate-800 dark:text-slate-200 font-semibold">{selectedComponent.supplier}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">Supply Chain Tier</span>
                  <span className="text-slate-800 dark:text-slate-200 font-semibold">{selectedComponent.tier}</span>
                </div>
              </div>

              {/* Jump to Asset Detail */}
              <button
                onClick={() => onSelectAsset(currentAsset)}
                className="w-full py-2 px-3 text-xs font-semibold text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
              >
                <span>Inspect Full {currentAsset.name} SBOM</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <div className="p-8 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center text-xs text-slate-500">
              Select any supply chain component on the left to inspect its cryptographic provenance and hash verification.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
