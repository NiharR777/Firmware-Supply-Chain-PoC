import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  BarChart3,
  GitBranch,
  Lock,
  FileCheck2,
  CheckSquare2,
  History,
  Layers,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Zap,
  HeartPulse,
  Car
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  selectedSector: string;
  onSelectSector: (sector: string) => void;
  highRiskCount: number;
  investigateCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  selectedSector,
  onSelectSector,
  highRiskCount,
  investigateCount,
}) => {
  const menuItems = [
    { id: 'overview', label: 'Executive Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'assessment', label: 'Package Assessment', icon: <ShieldAlert className="w-4 h-4" />, badge: '10 bundles', badgeColor: 'bg-emerald-500/20 text-emerald-400' },
    { id: 'kpis', label: 'Supply-Chain KPIs', icon: <BarChart3 className="w-4 h-4" />, badge: '4 KPIs' },
    { id: 'readiness', label: 'Metric Readiness', icon: <Layers className="w-4 h-4" />, badge: '9 gaps', badgeColor: 'bg-amber-500/20 text-amber-400' },
    { id: 'reachability', label: 'VEX & Reachability', icon: <CheckSquare2 className="w-4 h-4" />, badge: 'VEX Matrix' },
    { id: 'hardening', label: 'Hardening & Secrets', icon: <Lock className="w-4 h-4" /> },
    { id: 'pedigree', label: 'Pedigree Tree', icon: <GitBranch className="w-4 h-4" /> },
    { id: 'compliance', label: 'Sector Compliance', icon: <FileCheck2 className="w-4 h-4" /> },
    { id: 'review', label: 'Human Review & Gate', icon: <ShieldCheck className="w-4 h-4" />, badge: 'Safety Gate', badgeColor: 'bg-emerald-500/20 text-emerald-400' },
    { id: 'audit', label: 'Audit History', icon: <History className="w-4 h-4" /> },
  ];

  const sectorFilters = [
    { id: 'all', label: 'All Sectors' },
    { id: 'oil_gas', label: 'Oil & Gas', icon: <Flame className="w-3.5 h-3.5 text-orange-400" /> },
    { id: 'energy', label: 'Energy & Grid', icon: <Zap className="w-3.5 h-3.5 text-amber-400" /> },
    { id: 'healthcare', label: 'Healthcare MedTech', icon: <HeartPulse className="w-3.5 h-3.5 text-rose-400" /> },
    { id: 'automotive', label: 'Automotive', icon: <Car className="w-3.5 h-3.5 text-cyan-400" /> },
  ];

  return (
    <aside className="w-64 bg-slate-900 text-slate-300 flex flex-col shrink-0 border-r border-slate-800 select-none">
      {/* Facility / Site Profile Lockup */}
      <div className="p-4 border-b border-slate-800">
        <div className="flex items-center gap-2 mb-1.5">
          <div className="w-7 h-7 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center font-bold text-xs">
            OP
          </div>
          <div className="truncate">
            <h2 className="text-xs font-bold text-white tracking-wide truncate">
              Industrial OT / ICS Fleet
            </h2>
            <div className="text-[10px] text-slate-400 truncate">
              Refinery &amp; Substation Automation
            </div>
          </div>
        </div>

        {/* Live Threat Ticker in Sidebar */}
        <div className="mt-3 p-2 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-1.5 text-rose-400 font-semibold font-mono">
            <span className="w-2 h-2 rounded-full bg-rose-500" />
            <span>{highRiskCount} High Risk</span>
          </div>
          <div className="flex items-center gap-1.5 text-amber-400 font-semibold font-mono">
            <span className="w-2 h-2 rounded-full bg-amber-500" />
            <span>{investigateCount} Review</span>
          </div>
        </div>
      </div>

      {/* Sector Quick Filter in Sidebar */}
      <div className="px-3 pt-3 pb-2 border-b border-slate-800">
        <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-1.5 px-2">
          Target Domain Filter
        </div>
        <div className="flex flex-wrap gap-1">
          {sectorFilters.map((sec) => (
            <button
              key={sec.id}
              onClick={() => onSelectSector(sec.id)}
              className={`flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors cursor-pointer ${
                selectedSector === sec.id
                  ? 'bg-emerald-600 text-white font-semibold'
                  : 'bg-slate-950/50 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {sec.icon}
              <span>{sec.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Navigation List */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-1">
        <div className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mb-1.5 px-2">
          Assurance Modules
        </div>
        {menuItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer text-left ${
                isActive
                  ? 'bg-emerald-600/20 text-emerald-300 font-semibold border-l-2 border-emerald-500 bg-slate-800'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <span className={isActive ? 'text-emerald-400' : 'text-slate-500'}>
                  {item.icon}
                </span>
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    item.badgeColor || 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Bottom Hard Safety Boundary Notice */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/80">
        <div className="flex items-center gap-2 text-[11px] text-emerald-400 font-semibold mb-1">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>SAFETY INVARIANT</span>
        </div>
        <p className="text-[10px] text-slate-400 leading-tight">
          Read-only evidence intake. Zero physical firmware flashing or device execution allowed.
        </p>
      </div>
    </aside>
  );
};
