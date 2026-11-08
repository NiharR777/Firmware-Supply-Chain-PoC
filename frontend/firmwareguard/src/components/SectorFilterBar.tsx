import React from 'react';
import { SectorType } from '../types/firmware';
import { Zap, Flame, HeartPulse, Car, Globe, Search } from 'lucide-react';

interface SectorFilterBarProps {
  selectedSector: SectorType | 'all';
  onSelectSector: (sector: SectorType | 'all') => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  assetCount: number;
}

export const SectorFilterBar: React.FC<SectorFilterBarProps> = ({
  selectedSector,
  onSelectSector,
  searchQuery,
  onSearchChange,
  assetCount,
}) => {
  const sectors: { id: SectorType | 'all'; label: string; icon: React.ReactNode; standard: string }[] = [
    { id: 'all', label: 'All Critical Sectors', icon: <Globe className="w-4 h-4" />, standard: 'Cross-Sector Matrix' },
    { id: 'energy', label: 'Energy & Electric Grid', icon: <Zap className="w-4 h-4" />, standard: 'NERC CIP-013 / IEC 61850' },
    { id: 'oil_gas', label: 'Oil & Gas Pipelines', icon: <Flame className="w-4 h-4" />, standard: 'TSA Pipeline / TRITON Profile' },
    { id: 'healthcare', label: 'Healthcare & MedTech', icon: <HeartPulse className="w-4 h-4" />, standard: 'FDA 524B / ISO 14971' },
    { id: 'automotive', label: 'Automotive & Mobility', icon: <Car className="w-4 h-4" />, standard: 'UNECE WP.29 / ISO 21434' },
  ];

  return (
    <div className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-sm py-3 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Sector Tabs (Segmented control) */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 md:pb-0 scrollbar-none">
          {sectors.map((s) => {
            const isActive = selectedSector === s.id;
            return (
              <button
                key={s.id}
                onClick={() => onSelectSector(s.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap shrink-0 transition-colors cursor-pointer border ${
                  isActive
                    ? 'bg-slate-800 text-cyan-400 border-cyan-500/40 shadow-xs'
                    : 'bg-slate-900/40 text-slate-400 border-slate-800/80 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <span className={isActive ? 'text-cyan-400' : 'text-slate-500'}>{s.icon}</span>
                <span>{s.label}</span>
              </button>
            );
          })}
        </div>

        {/* Search & Counter */}
        <div className="flex items-center gap-3">
          <div className="relative w-full md:w-64">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Filter CVE, component, asset..."
              className="w-full bg-slate-950/80 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 transition-colors"
            />
          </div>
          <div className="text-xs text-slate-400 whitespace-nowrap shrink-0">
            <span className="font-mono text-slate-200 font-semibold tabular-nums">{assetCount}</span> targets monitored
          </div>
        </div>
      </div>
    </div>
  );
};
