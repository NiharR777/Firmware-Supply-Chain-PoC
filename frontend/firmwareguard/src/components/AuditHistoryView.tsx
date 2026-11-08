import React, { useState } from 'react';
import { History, ShieldAlert, CheckCircle2, XCircle, Search, Filter } from 'lucide-react';

export interface AuditEventItem {
  id: string;
  timestamp: string;
  event: string;
  scenario_id: string;
  package_id?: string;
  details: string;
  outcome?: string;
}

interface AuditHistoryViewProps {
  auditEvents: AuditEventItem[];
}

export const AuditHistoryView: React.FC<AuditHistoryViewProps> = ({ auditEvents }) => {
  const [filterQuery, setFilterQuery] = useState('');

  const filteredEvents = auditEvents.filter((item) => {
    if (!filterQuery.trim()) return true;
    const q = filterQuery.toLowerCase();
    return (
      item.scenario_id.toLowerCase().includes(q) ||
      item.event.toLowerCase().includes(q) ||
      item.details.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
            Immutable Audit Trail
          </div>
          <h2 className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
            Security Event &amp; Release Gate History
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Append-only audit log recording assessments, human review dispositions, and simulated gate attempts.
          </p>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={filterQuery}
            onChange={(e) => setFilterQuery(e.target.value)}
            placeholder="Filter audit events..."
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:border-emerald-500"
          />
        </div>
      </div>

      {/* Events Table */}
      <div className="overflow-hidden rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-slate-850 text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-semibold">
              <tr>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Scenario &amp; Package</th>
                <th className="py-3 px-4">Audit Details &amp; Disposition</th>
                <th className="py-3 px-4 text-center">Physical Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500 text-xs">
                    No matching audit events found in current session.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-850/50 transition-colors">
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-500 whitespace-nowrap">
                      {item.timestamp}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                          item.event.includes('gate')
                            ? 'text-purple-700 dark:text-purple-400 bg-purple-50 dark:bg-purple-950/60 border-purple-200 dark:border-purple-800'
                            : item.event.includes('review')
                            ? 'text-cyan-700 dark:text-cyan-400 bg-cyan-50 dark:bg-cyan-950/60 border-cyan-200 dark:border-cyan-800'
                            : 'text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-800'
                        }`}
                      >
                        {item.event.replace(/_/g, ' ')}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono font-bold text-slate-900 dark:text-white">
                      {item.scenario_id}
                      {item.package_id && (
                        <span className="text-slate-400 font-normal block text-[10px]">
                          {item.package_id}
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-slate-700 dark:text-slate-300 font-mono text-[11px] leading-relaxed">
                      {item.details}
                    </td>

                    <td className="py-3 px-4 text-center whitespace-nowrap">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">
                        NONE (SAFE)
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
