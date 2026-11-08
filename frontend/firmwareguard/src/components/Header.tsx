import React from 'react';
import { ShieldCheck, Sun, Moon, Download, Bot } from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onOpenExportModal: () => void;
  onOpenAdvisorModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  theme,
  onToggleTheme,
  onOpenExportModal,
  onOpenAdvisorModal,
}) => {
  const navItems = [
    { id: 'overview', label: 'Executive Overview' },
    { id: 'assessment', label: 'Package Assessment' },
    { id: 'kpis', label: 'Supply-Chain KPIs' },
    { id: 'reachability', label: 'VEX & Reachability' },
    { id: 'hardening', label: 'Hardening & Secrets' },
    { id: 'readiness', label: 'Metric Readiness' },
    { id: 'audit', label: 'Audit History' },
  ];

  return (
    <header className="sticky top-0 z-40 bg-white/95 dark:bg-slate-950/95 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 transition-colors">
      <div className="w-full px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-6">
        {/* Left Zone: Brand Mark & Breadcrumb */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-9 h-9 rounded-xl bg-linear-to-br from-emerald-600 to-teal-500 text-white flex items-center justify-center font-bold text-lg shadow-sm">
            S
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-extrabold tracking-wider text-slate-900 dark:text-white uppercase">
                SPECTRA
              </span>
              <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/60">
                OT / ICS ASSURANCE
              </span>
            </div>
            <div className="text-[11px] text-slate-500 dark:text-slate-400 hidden sm:block">
              Energy · Oil &amp; Gas · Healthcare · Automotive
            </div>
          </div>
        </div>

        {/* Center Zone: Clean Single-line Navigation Links */}
        <nav className="hidden xl:flex items-center gap-5 text-xs font-semibold">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`whitespace-nowrap shrink-0 transition-colors py-1 cursor-pointer ${
                activeTab === item.id
                  ? 'text-emerald-600 dark:text-emerald-400 font-bold border-b-2 border-emerald-600 dark:border-emerald-400'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        {/* Right Zone: Controls & Actions */}
        <div className="flex items-center gap-2.5 shrink-0">
          {/* API Status Badge */}
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>API Online</span>
          </div>

          {/* Theme Switcher Toggle (Light by default, Dark optional) */}
          <button
            onClick={onToggleTheme}
            title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
            className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            {theme === 'light' ? (
              <Moon className="w-4 h-4 text-slate-700" />
            ) : (
              <Sun className="w-4 h-4 text-amber-400" />
            )}
          </button>

          {/* Advisor Button */}
          <button
            onClick={onOpenAdvisorModal}
            className="hidden md:flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <Bot className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
            <span>SpectraIQ Advisor</span>
          </button>

          {/* Primary Action Button */}
          <button
            onClick={onOpenExportModal}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors whitespace-nowrap cursor-pointer shadow-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export VEX</span>
          </button>
        </div>
      </div>
    </header>
  );
};
