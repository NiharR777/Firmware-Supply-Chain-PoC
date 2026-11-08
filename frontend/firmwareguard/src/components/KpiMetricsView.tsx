
import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  RefreshCw,
  Info,
  BarChart3,
} from 'lucide-react';
import { firmwareApi } from '../api/client';
import type { PerformanceDashboard } from '../api/client';

interface KpiMetricsViewProps {
  scenarios: unknown[];
}

interface KpiCardProps {
  title: string;
  value: number | null;
  numerator: number;
  denominator: number;
  target: string;
  color: 'emerald' | 'cyan' | 'slate';
}

const KpiCard: React.FC<KpiCardProps> = ({
  title,
  value,
  numerator,
  denominator,
  target,
  color,
}) => {
  const colors = {
    emerald: {
      text: 'text-emerald-600 dark:text-emerald-400',
      bar: 'bg-emerald-500',
    },
    cyan: {
      text: 'text-cyan-600 dark:text-cyan-400',
      bar: 'bg-cyan-500',
    },
    slate: {
      text: 'text-slate-800 dark:text-slate-200',
      bar: 'bg-slate-400 dark:bg-slate-600',
    },
  };

  const style = colors[color];
  const percentage = value ?? 0;

  return (
    <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-2">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
          {title}
        </span>

        <span
          className={`font-mono text-2xl font-black ${style.text} tabular-nums`}
        >
          {value === null ? 'N/A' : `${value.toFixed(1)}%`}
        </span>
      </div>

      <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-2 overflow-hidden">
        <div
          className={`${style.bar} h-full rounded-full transition-all`}
          style={{ width: `${Math.min(100, Math.max(0, percentage))}%` }}
        />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 pt-1">
        <span>
          {numerator} of {denominator} bundles
        </span>
        <span className="font-mono text-[11px] text-slate-400">
          Target: {target}
        </span>
      </div>
    </div>
  );
};

export const KpiMetricsView: React.FC<KpiMetricsViewProps> = () => {
  const [dashboard, setDashboard] =
    useState<PerformanceDashboard | null>(null);

  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');

  const loadDashboard = useCallback(async () => {
    setIsLoading(true);
    setError('');

    try {
      const result = await firmwareApi.performanceDashboard();
      setDashboard(result);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load backend KPI dashboard.'
      );
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  if (isLoading) {
    return (
      <div className="min-h-[300px] flex flex-col items-center justify-center gap-3 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800">
        <RefreshCw className="w-7 h-7 text-emerald-500 animate-spin" />
        <p className="text-sm text-slate-500">
          Loading live supply-chain KPIs from backend...
        </p>
      </div>
    );
  }

  if (error || !dashboard) {
    return (
      <div className="p-6 rounded-xl bg-white dark:bg-slate-900 border border-rose-200 dark:border-rose-900 space-y-3">
        <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-semibold">
          <AlertTriangle className="w-5 h-5" />
          KPI Dashboard Unavailable
        </div>

        <p className="text-sm text-slate-500">
          {error || 'No dashboard data was returned by the backend.'}
        </p>

        <button
          onClick={loadDashboard}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold"
        >
          <RefreshCw className="w-4 h-4" />
          Retry Backend Connection
        </button>
      </div>
    );
  }

  const kpis = dashboard.kpis;
  const vex = dashboard.vex_status_counts;

  const cards = [
    {
      key: 'sbom_coverage',
      title: 'Complete SBOM Evidence',
      color: 'emerald' as const,
    },
    {
      key: 'signature_compliance',
      title: 'Signature & Trusted Root Evidence',
      color: 'cyan' as const,
    },
    {
      key: 'vex_coverage',
      title: 'Explicit VEX Status Coverage',
      color: 'emerald' as const,
    },
    {
      key: 'vendor_trust',
      title: 'Trusted Vendor Evidence',
      color: 'slate' as const,
    },
  ];

  return (
    <div className="space-y-6">

      {/* Dashboard Header */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
              SUPPLY-CHAIN SECURITY KPIs
            </div>

            <h2 className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
              Executive Performance Indicators &amp; Measurement Basis
            </h2>

            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Live measurements retrieved from the Firmware Supply Chain PoC backend.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono font-bold px-2.5 py-1 rounded-full bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-800">
              TARGETS ≠ ACHIEVED RESULTS
            </span>

            <button
              onClick={loadDashboard}
              className="p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-500 hover:text-emerald-600"
              title="Refresh KPI data"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Backend Connection Information */}
      <div className="flex items-center gap-2 text-xs text-emerald-700 dark:text-emerald-400">
        <span className="w-2 h-2 rounded-full bg-emerald-500" />
        Connected to /api/performance-dashboard
        <span className="text-slate-400">
          · {dashboard.scenario_bundles_available} bundles available
        </span>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {cards.map((card) => {
          const metric = kpis[card.key];

          return (
            <KpiCard
              key={card.key}
              title={metric.label || card.title}
              value={metric.value_percent}
              numerator={metric.numerator}
              denominator={metric.denominator}
              target={metric.target}
              color={card.color}
            />
          );
        })}
      </div>

      {/* VEX Distribution and Measurement Basis */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            VEX Status Distribution in Scenarios
          </h3>

          {[
            {
              label: 'Affected (Actionable CVE)',
              value: vex.affected,
              color: 'text-rose-600 dark:text-rose-400',
            },
            {
              label: 'Not Affected (Suppressed)',
              value: vex.not_affected,
              color: 'text-emerald-600 dark:text-emerald-400',
            },
            {
              label: 'Unknown / Missing',
              value: vex.unknown_or_missing,
              color: 'text-slate-500',
            },
          ].map((item) => (
            <div
              key={item.label}
              className="flex items-center justify-between p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs"
            >
              <span className="font-medium text-slate-700 dark:text-slate-300">
                {item.label}
              </span>

              <span className={`font-mono font-bold tabular-nums ${item.color}`}>
                {item.value}
              </span>
            </div>
          ))}
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            Evidence Measurement Basis &amp; Boundaries
          </h3>

          <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
            {dashboard.data_basis}
          </p>

          <p className="text-xs text-slate-600 dark:text-slate-400">
            Available bundles:{' '}
            <strong className="text-slate-900 dark:text-white">
              {dashboard.scenario_bundles_available}
            </strong>
          </p>

          <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/60 text-amber-900 dark:text-amber-200 text-xs leading-relaxed">
            {dashboard.scope_note}
          </div>

          <p className="text-[11px] text-slate-500">
            {dashboard.targets_note}
          </p>
        </div>
      </div>

      {/* Scenario Evidence Summary */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-emerald-500" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-white">
            Scenario Evidence Summary
          </h3>
        </div>

        <p className="text-xs text-slate-500">
          Backend-reported evidence across the available synthetic scenario bundles.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-slate-850 text-slate-600 dark:text-slate-400">
              <tr>
                <th className="p-3">Scenario</th>
                <th className="p-3">Package</th>
                <th className="p-3">Asset</th>
                <th className="p-3">SBOM</th>
                <th className="p-3">Signature</th>
                <th className="p-3">Vendor</th>
                <th className="p-3">VEX</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {dashboard.scenario_evidence.map((item) => (
                <tr key={String(item.scenario_id)}>
                  <td className="p-3 font-mono font-bold">
                    {String(item.scenario_id)}
                  </td>
                  <td className="p-3 font-mono">
                    {String(item.package_id)}
                  </td>
                  <td className="p-3">
                    {String(item.asset_name)}
                  </td>
                  <td className="p-3">
                    {item.sbom_complete ? 'Complete' : 'Missing'}
                  </td>
                  <td className="p-3">
                    {item.signature_compliant ? 'Valid' : 'Review'}
                  </td>
                  <td className="p-3">
                    {item.vendor_trusted ? 'Trusted' : 'Untrusted'}
                  </td>
                  <td className="p-3 font-mono">
                    {String(item.vex_status)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Not Measured Metrics */}
      <div className="space-y-3">
        <div>
          <h3 className="text-base font-bold text-slate-900 dark:text-white">
            Metric Readiness &amp; Documented Data Gaps
          </h3>

          <p className="text-xs text-slate-500 mt-1">
            Backend-reported metrics that cannot yet be measured with the current evidence schema.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs text-amber-700 dark:text-amber-400">
          <Info className="w-4 h-4" />
          {dashboard.not_measured.length} metrics currently not measured
        </div>

        <div className="overflow-hidden rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-850 text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-semibold">
                <tr>
                  <th className="py-3 px-4 w-1/4">Metric Requested</th>
                  <th className="py-3 px-4 w-1/2">Current Status / Data Gap</th>
                  <th className="py-3 px-4 w-1/4">Reference Benchmark Target</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {dashboard.not_measured.map((item) => (
                  <tr key={item.metric}>
                    <td className="py-3 px-4">
                      <strong className="font-semibold text-slate-900 dark:text-white block">
                        {item.metric}
                      </strong>

                      <span className="text-[9px] font-mono uppercase tracking-wider text-amber-600 dark:text-amber-400 font-bold">
                        Not measured
                      </span>
                    </td>

                    <td className="py-3 px-4 text-slate-600 dark:text-slate-400 leading-relaxed">
                      {item.reason}
                    </td>

                    <td className="py-3 px-4 text-slate-500 dark:text-slate-400 font-mono text-[11px] leading-relaxed">
                      {item.document_target}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="p-3 rounded-lg bg-slate-100 dark:bg-slate-850 text-[11px] text-slate-600 dark:text-slate-400">
        <strong>Measurement boundary:</strong> All displayed KPI percentages
        are derived from predefined synthetic evidence bundles. They are not
        operational production metrics or claims about deployed OT assets.
      </div>
    </div>
  );
};
