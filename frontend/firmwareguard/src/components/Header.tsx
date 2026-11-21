
import React from 'react';
import { Sun, Moon, Download } from 'lucide-react';

type ApiStatus = 'checking' | 'online' | 'offline';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  theme: 'light' | 'dark';
  apiStatus: ApiStatus;
  onToggleTheme: () => void;
  onOpenExportModal: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  theme,
  apiStatus,
  onToggleTheme,
  onOpenExportModal,
}) => {
  const navItems = [
    { id: 'overview', label: 'Executive Overview' },
    { id: 'customer-assessment', label: 'Customer SBOM Assessment' },
    { id: 'assessment', label: 'Package Assessment' },
    { id: 'kpis', label: 'Supply-Chain KPIs' },
    { id: 'reachability', label: 'VEX & Reachability' },
    { id: 'hardening', label: 'Hardening & Secrets' },
    { id: 'readiness', label: 'Metric Readiness' },
    { id: 'audit', label: 'Audit History' },
  ];

  const apiStatusConfig = {
    checking: {
      label: 'Checking API',
      dot: 'bg-amber-500 animate-pulse',
      text: 'text-amber-700 dark:text-amber-400',
    },
    online: {
      label: 'API Online',
      dot: 'bg-emerald-500',
      text: 'text-emerald-700 dark:text-emerald-400',
    },
    offline: {
      label: 'API Offline',
      dot: 'bg-rose-500',
      text: 'text-rose-700 dark:text-rose-400',
    },
  };

  const currentApiStatus = apiStatusConfig[apiStatus];

  return (
    <header className="sticky top-0 z-40 bg-white/95 dark:bg-slate-950/95 backdrop-blur-md border-b border-slate-200 dark:border-slate-800 transition-colors">
      <div className="w-full px-4 sm:px-6 h-16 flex items-center justify-between gap-3">

        {/* Brand */}
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
              Healthcare · Telecom & Data Centers · Manufacturing
            </div>
          </div>
        </div>

        {/* Horizontal Navigation */}
        <nav
          aria-label="Main navigation"
          className="hidden xl:flex flex-1 min-w-0 items-center justify-center gap-3 text-[11px] font-semibold overflow-x-auto"
        >
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              title={item.label}
              aria-current={
                activeTab === item.id ? 'page' : undefined
              }
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

        {/* Right Controls */}
        <div className="flex items-center gap-2 shrink-0">

          {/* Live API Status */}
          <div
            role="status"
            aria-live="polite"
            title="Backend health endpoint: /api/health"
            className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border bg-slate-100 dark:bg-slate-900 border-slate-200 dark:border-slate-800 ${currentApiStatus.text}`}
          >
            <span
              className={`w-2 h-2 rounded-full ${currentApiStatus.dot}`}
            />
            <span>{currentApiStatus.label}</span>
          </div>

          {/* Theme Toggle */}
          <button
            type="button"
            onClick={onToggleTheme}
            title={
              theme === 'light'
                ? 'Switch to Dark Mode'
                : 'Switch to Light Mode'
            }
            aria-label={
              theme === 'light'
                ? 'Switch to Dark Mode'
                : 'Switch to Light Mode'
            }
            className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            {theme === 'light' ? (
              <Moon className="w-4 h-4 text-slate-700" />
            ) : (
              <Sun className="w-4 h-4 text-amber-400" />
            )}
          </button>


          {/* Export */}
          <button
            type="button"
            onClick={onOpenExportModal}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors whitespace-nowrap cursor-pointer shadow-xs"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export VEX</span>
          </button>

        </div>
      </div>
    </header>
  );
};
