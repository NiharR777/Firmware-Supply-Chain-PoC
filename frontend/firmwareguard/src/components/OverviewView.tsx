import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceLine,
  ReferenceDot
} from 'recharts';
import type { ScenarioRecord } from '../api/client';
import { SECTOR_30_DAY_TREND } from '../data/riskTrendData';
import {
  ShieldAlert,
  ShieldCheck,
  FileCheck,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Layers,
  Flame,
  Zap,
  HeartPulse,
  Car,
  Activity,
  Calendar,
  AlertTriangle,
  TrendingUp,
  TrendingDown
} from 'lucide-react';

interface OverviewViewProps {
  scenarios: ScenarioRecord[];
  /** Sidebar sector filter. Optional until App.tsx passes the shared selection. */
  selectedSector?: string;
  onSelectScenario: (scenarioId: string) => void;
  onOpenReviewModal: () => void;
  onViewVexMatrix: () => void;
}

type TimeRange = '7d' | '14d' | '30d';

interface SectorMeta {
  key: 'energy' | 'oil_gas' | 'healthcare' | 'automotive';
  name: string;
  color: string;
  darkColor: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

const SECTOR_METAS: SectorMeta[] = [
  {
    key: 'energy',
    name: 'Energy',
    color: '#d97706',
    darkColor: '#f59e0b',
    icon: Zap,
    description: 'SEL relays, RTUs, NERC CIP-013 microcode'
  },
  {
    key: 'oil_gas',
    name: 'Oil & Gas',
    color: '#ea580c',
    darkColor: '#f97316',
    icon: Flame,
    description: 'Refinery SIS logic skids, flow meters'
  },
  {
    key: 'healthcare',
    name: 'Healthcare',
    color: '#e11d48',
    darkColor: '#fb7185',
    icon: HeartPulse,
    description: 'Bedside infusion pumps, FDA Section 524B'
  },
  {
    key: 'automotive',
    name: 'Automotive',
    color: '#0284c7',
    darkColor: '#38bdf8',
    icon: Car,
    description: 'AUTOSAR ECUs, CAN gateways, WP.29'
  }
];

export const OverviewView: React.FC<OverviewViewProps> = ({
  scenarios,
  selectedSector = 'all',
  onSelectScenario,
  onOpenReviewModal,
  onViewVexMatrix,
}) => {
  // Live KPIs calculated from backend scenario evidence.
  const totalScenarios = scenarios.length;
  const sbomCompleteCount = scenarios.filter((scenario) => scenario.sbom_status === 'complete').length;
  const sbomCoveragePercent = totalScenarios > 0 ? ((sbomCompleteCount / totalScenarios) * 100).toFixed(1) : '0.0';
  const signatureCompliantCount = scenarios.filter((scenario) => scenario.signature_status === 'valid' && scenario.trusted_root_status === 'trusted').length;
  const signatureCompliancePercent = totalScenarios > 0 ? ((signatureCompliantCount / totalScenarios) * 100).toFixed(1) : '0.0';
  const highRiskCount = scenarios.filter((scenario) => scenario.risk_level === 'high_risk').length;
  const investigateCount = scenarios.filter((scenario) => scenario.risk_level === 'investigate').length;
  const realActionsExecuted = scenarios.filter((scenario) => scenario.real_action_executed === true).length;

  // Firmware Risk Trend state
  const [timeRange, setTimeRange] = useState<TimeRange>('30d');
  const [activeSectors, setActiveSectors] = useState<Record<string, boolean>>({
    energy: true,
    oil_gas: true,
    healthcare: true,
    automotive: true,
  });

  // Filter 30-day time series data based on chosen time range
  const filteredTrendData = useMemo(() => {
    if (timeRange === '7d') {
      return SECTOR_30_DAY_TREND.slice(-7);
    }
    if (timeRange === '14d') {
      return SECTOR_30_DAY_TREND.slice(-14);
    }
    return SECTOR_30_DAY_TREND;
  }, [timeRange]);

  // Significant security incident milestones in the filtered window
  const activeMilestones = useMemo(() => {
    return filteredTrendData
      .filter((pt) => pt.milestone !== undefined)
      .filter((pt) => selectedSector === 'all' || pt.milestone?.sector === selectedSector)
      .map((pt) => ({
        date: pt.date,
        displayDate: pt.displayDate,
        ...pt.milestone!,
      }));
  }, [filteredTrendData, selectedSector]);

  const latestDataPoint = filteredTrendData[filteredTrendData.length - 1];
  const firstDataPoint = filteredTrendData[0];

  const toggleSector = (sectorKey: string) => {
    setActiveSectors((prev) => {
      const next = { ...prev, [sectorKey]: !prev[sectorKey] };
      // Prevent unselecting all sectors
      if (!Object.values(next).some(Boolean)) {
        return prev;
      }
      return next;
    });
  };

  const resetAllSectors = () => {
    setActiveSectors({
      energy: true,
      oil_gas: true,
      healthcare: true,
      automotive: true,
    });
  };

  // Custom Tooltip for Recharts
  const renderTrendTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload || !payload.length) return null;

    const currentPoint = filteredTrendData.find((d) => d.displayDate === label || d.date === label);
    const milestone = currentPoint?.milestone;

    return (
      <div className="bg-white/95 dark:bg-slate-900/95 backdrop-blur-md p-4 rounded-xl shadow-xl border border-slate-200 dark:border-slate-800 text-xs min-w-[260px] max-w-sm z-50">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-100 dark:border-slate-800">
          <div className="font-semibold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
            <Calendar className="w-3.5 h-3.5 text-slate-400" />
            <span>{currentPoint?.displayDate} ({currentPoint?.date})</span>
          </div>
          <span className="font-mono text-[10px] text-slate-400 uppercase tracking-wider">
            Risk Scores
          </span>
        </div>

        {/* Sector risk values */}
        <div className="space-y-1.5">
          {payload.map((item: any) => {
            const sec = SECTOR_METAS.find((s) => s.key === item.dataKey);
            return (
              <div key={item.dataKey} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-slate-600 dark:text-slate-300 font-medium">
                    {sec?.name || item.name}
                  </span>
                </div>
                <div className="flex items-center gap-1 font-mono font-bold tabular-nums">
                  <span
                    className={
                      item.value >= 80
                        ? 'text-rose-600 dark:text-rose-400'
                        : item.value >= 60
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-emerald-600 dark:text-emerald-400'
                    }
                  >
                    {item.value}
                  </span>
                  <span className="text-[10px] text-slate-400 font-normal">/100</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Significant Incident Milestone callout inside tooltip */}
        {milestone && (
          <div className="mt-3 pt-2.5 border-t border-rose-100 dark:border-rose-950/80 bg-rose-50/60 dark:bg-rose-950/30 p-2.5 rounded-lg border">
            <div className="flex items-center justify-between text-rose-800 dark:text-rose-300 font-bold mb-1">
              <span className="flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                <span>Security Milestone</span>
              </span>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-rose-200/60 dark:bg-rose-900/60 text-rose-800 dark:text-rose-200">
                {milestone.riskDelta > 0 ? `+${milestone.riskDelta}` : milestone.riskDelta} pts
              </span>
            </div>
            <div className="font-semibold text-slate-900 dark:text-slate-100 text-[11px] leading-tight">
              {milestone.title}
            </div>
            <div className="text-[10px] text-slate-600 dark:text-slate-400 mt-1 leading-normal">
              {milestone.description}
            </div>
            {milestone.scenarioId && (
              <div className="mt-2 text-right">
                <button
                  onClick={() => onSelectScenario(milestone.scenarioId!)}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 hover:bg-rose-500 text-white transition-colors cursor-pointer"
                >
                  <span>Assess Scenario ({milestone.scenarioId})</span>
                  <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      {/* Hero Banner Card - matching Crop2Cup / Spectra reference screenshot */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-slate-900 border border-slate-800 text-white p-6sm:p-8 shadow-xl">
        <div className="relative z-10 max-w-4xl space-y-4">
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 uppercase">
              Deterministic Decision Engine
            </span>
            <span className="text-xs text-slate-400">Â·</span>
            <span className="text-xs text-slate-300">OT / ICS Firmware Assurance PoC</span>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white leading-tight">
            Firmware Supply-Chain Assurance &amp; Safety Gate
          </h1>

          <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-3xl">
            Evidence-driven evaluation of observed firmware bundles against cryptographic, signature, rollback, and SBOM policies. Designed for refinery, substation, medical device, and connected automotive platforms.
          </p>

          {/* Quick Actions generated from live backend scenarios */}
          <div className="pt-2 flex flex-wrap items-center gap-2">
            {scenarios.slice(0, 4).map((scenario) => {
              const isHighRisk = scenario.risk_level === 'high_risk';
              const reason = scenario.risk_factors?.[0]?.replace(/_/g, ' ') || scenario.reasons?.[0] || 'Evidence review required';
              return (
                <button
                  key={scenario.scenario_id}
                  onClick={() => onSelectScenario(scenario.scenario_id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-colors cursor-pointer flex items-center gap-1.5 ${
                    isHighRisk
                      ? 'bg-rose-950/80 hover:bg-rose-900 text-rose-200 border-rose-800/80'
                      : 'bg-amber-950/80 hover:bg-amber-900 text-amber-200 border-amber-800/80'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${isHighRisk ? 'bg-rose-400' : 'bg-amber-400'}`} />
                  <span>Assess {scenario.scenario_id} ({reason})</span>
                </button>
              );
            })}

          </div>
        </div>
      </div>

      {/* 4 Primary KPI Metric Cards - Clean Light / Dark theme */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Scenario Bundles */}
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold mb-1">
            <span>SCENARIO BUNDLES</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
              SYNTHETIC
            </span>
          </div>
          <div className="font-mono text-3xl font-extrabold text-slate-900 dark:text-white tabular-nums">
            {totalScenarios}
          </div>
          <div className="mt-2 text-xs text-slate-500 dark:text-slate-400 flex items-center justify-between">
            <span>Available evidence sets</span>
            <span className="font-mono font-semibold text-slate-500 dark:text-slate-400">Sample catalogue</span>
          </div>
        </div>

        {/* Card 2: Complete SBOM Evidence */}
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold mb-1">
            <span>COMPLETE SBOM EVIDENCE</span>
            <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400 font-bold">
              TARGET: 98%
            </span>
          </div>
          <div className="font-mono text-3xl font-extrabold text-emerald-600 dark:text-emerald-400 tabular-nums">
            {sbomCoveragePercent}%
          </div>
          <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
            <div className="bg-emerald-500 h-full rounded-full" style={{ width: `${sbomCoveragePercent}%` }} />
          </div>
          <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            {sbomCompleteCount} of {totalScenarios} bundles complete (CycloneDX 1.5)
          </div>
        </div>

        {/* Card 3: Signature & Root Compliance */}
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-semibold mb-1">
            <span>SIGNATURE &amp; ROOT COMPLIANCE</span>
            <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 font-bold">
              TARGET: 100%
            </span>
          </div>
          <div className="font-mono text-3xl font-extrabold text-cyan-600 dark:text-cyan-400 tabular-nums">
            {signatureCompliancePercent}%
          </div>
          <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
            <div className="bg-cyan-500 h-full rounded-full" style={{ width: `${signatureCompliancePercent}%` }} />
          </div>
          <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            {signatureCompliantCount} of {totalScenarios} valid signature &amp; trusted root
          </div>
        </div>

        {/* Card 4: Hard Safety Boundary */}
        <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-emerald-300 dark:border-emerald-800/80 shadow-xs transition-colors">
          <div className="flex items-center justify-between text-xs text-emerald-700 dark:text-emerald-400 font-bold mb-1">
            <span>REAL ACTIONS EXECUTED</span>
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
          </div>
          <div className="font-mono text-3xl font-extrabold text-slate-900 dark:text-white tabular-nums">
            {realActionsExecuted}
          </div>
          <div className="mt-2 text-xs text-emerald-700 dark:text-emerald-300 font-semibold flex items-center gap-1">
            <span>Hard safety invariant</span>
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
            Read-only evidence evaluation only
          </div>
        </div>
      </div>

      {/* Safety Notice Strip */}
      <div className="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/60 text-emerald-900 dark:text-emerald-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
          <span>
            <strong className="font-bold">Safety Boundary Enforced: </strong>
            Deterministic normal-risk result AND manual human approval are both mandatory to pass the simulated release gate. No binary is executed, installed, flashed, or sent to physical hardware.
          </span>
        </div>
        <button
          onClick={onOpenReviewModal}
          className="whitespace-nowrap font-semibold text-emerald-700 dark:text-emerald-300 hover:underline cursor-pointer text-xs shrink-0"
        >
          Open Review Workflow â†’
        </button>
      </div>

      {/* NEW: Firmware Risk Trend Section using Recharts */}
      <section
        id="firmware-risk-trend"
        aria-label="Firmware Risk Trend"
        className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs p-5 transition-colors space-y-4"
      >
        {/* Header with Title and Time Range Toggle (7d, 14d, 30d) */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center text-emerald-600 dark:text-emerald-400 shrink-0">
              <Activity className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <span>Firmware Risk Trend</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 font-normal">
                  Illustrative Sample Data
                </span>
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Illustrative daily risk scores for demonstration only. These values are not live backend telemetry or measured production data.
              </p>
            </div>
          </div>

          {/* Time Range Toggle Controls: 7d, 14d, 30d */}
          <div className="flex items-center gap-2 self-start lg:self-auto">
            <div className="inline-flex items-center bg-slate-100 dark:bg-slate-800 p-0.5 rounded-lg border border-slate-200 dark:border-slate-700">
              {(['7d', '14d', '30d'] as TimeRange[]).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                    timeRange === range
                      ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-xs font-bold'
                      : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
                  }`}
                  aria-pressed={timeRange === range}
                >
                  {range}
                </button>
              ))}
            </div>

            <button
              onClick={resetAllSectors}
              title="Reset sector selection"
              className="px-2.5 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
            >
              Reset
            </button>
          </div>
        </div>

        {/* Sector Interactive Legend & Status Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
          {SECTOR_METAS
            .filter((sec) => selectedSector === 'all' || sec.key === selectedSector)
            .map((sec) => {
            const isVisible = selectedSector === 'all' ? activeSectors[sec.key] : true;
            const latestVal = latestDataPoint ? (latestDataPoint as any)[sec.key] : 0;
            const firstVal = firstDataPoint ? (firstDataPoint as any)[sec.key] : 0;
            const delta = latestVal - firstVal;
            const Icon = sec.icon;

            return (
              <button
                key={sec.key}
                onClick={() => {
                  if (selectedSector === 'all') toggleSector(sec.key);
                }}
                aria-pressed={isVisible}
                className={`p-3 rounded-lg border text-left transition-all ${selectedSector === 'all' ? 'cursor-pointer' : 'cursor-default'} flex flex-col justify-between ${
                  isVisible
                    ? 'bg-slate-50/80 dark:bg-slate-850 border-slate-300 dark:border-slate-700 shadow-2xs'
                    : 'bg-white dark:bg-slate-900/50 border-slate-200 dark:border-slate-800/60 opacity-40 hover:opacity-75'
                }`}
                title={`Toggle ${sec.name} line`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <span
                      className="w-2.5 h-2.5 rounded-full shrink-0"
                      style={{ backgroundColor: sec.darkColor }}
                    />
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 truncate">
                      {sec.name}
                    </span>
                  </div>
                  <Icon className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                </div>

                <div className="flex items-baseline justify-between mt-1">
                  <div className="font-mono text-xl font-extrabold text-slate-900 dark:text-white tabular-nums">
                    {latestVal}
                    <span className="text-[10px] text-slate-400 font-normal"> /100</span>
                  </div>
                  <div
                    className={`text-[10px] font-mono font-semibold flex items-center gap-0.5 ${
                      delta > 0
                        ? 'text-rose-600 dark:text-rose-400'
                        : delta < 0
                        ? 'text-emerald-600 dark:text-emerald-400'
                        : 'text-slate-400'
                    }`}
                  >
                    {delta > 0 ? (
                      <TrendingUp className="w-3 h-3" />
                    ) : delta < 0 ? (
                      <TrendingDown className="w-3 h-3" />
                    ) : null}
                    <span>{delta > 0 ? `+${delta}` : delta === 0 ? '0' : delta}</span>
                  </div>
                </div>

                <div className="text-[10px] text-slate-400 dark:text-slate-500 truncate mt-1">
                  {sec.description}
                </div>
              </button>
            );
          })}
        </div>

        {/* Recharts LineChart tracking daily risk scores aggregated by sector */}
        <div className="h-72 sm:h-80 w-full pt-2">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={filteredTrendData}
              margin={{ top: 15, right: 20, left: -10, bottom: 5 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                className="stroke-slate-200 dark:stroke-slate-800"
                vertical={false}
              />
              <XAxis
                dataKey="displayDate"
                tick={{ fontSize: 11, fill: '#64748b' }}
                tickLine={false}
                axisLine={{ stroke: '#cbd5e1' }}
              />
              <YAxis
                domain={[40, 100]}
                tick={{ fontSize: 11, fill: '#64748b' }}
                tickLine={false}
                axisLine={false}
                ticks={[40, 60, 80, 100]}
              />
              <Tooltip content={renderTrendTooltip} />

              {/* Recharts Legend component for sectors */}
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{ paddingBottom: '10px', fontSize: '11px' }}
                formatter={(value: string) => {
                  const sec = SECTOR_METAS.find((s) => s.key === value || s.name === value);
                  return (
                    <span className="text-slate-700 dark:text-slate-300 font-medium">
                      {sec ? sec.name : value}
                    </span>
                  );
                }}
              />

              {/* Threshold Reference Lines for Risk Categories */}
              <ReferenceLine
                y={80}
                stroke="#f43f5e"
                strokeDasharray="4 4"
                strokeOpacity={0.4}
                label={{
                  value: 'High Risk (80)',
                  position: 'insideTopLeft',
                  fill: '#f43f5e',
                  fontSize: 10,
                  opacity: 0.7
                }}
              />
              <ReferenceLine
                y={60}
                stroke="#f59e0b"
                strokeDasharray="4 4"
                strokeOpacity={0.3}
                label={{
                  value: 'Review Threshold (60)',
                  position: 'insideTopLeft',
                  fill: '#f59e0b',
                  fontSize: 10,
                  opacity: 0.6
                }}
              />

              {/* Significant Security Incident Milestone Markers on Timeline */}
              {activeMilestones.map((ms, idx) => (
                <ReferenceLine
                  key={`marker-line-${ms.date}-${idx}`}
                  x={ms.displayDate}
                  stroke={
                    ms.sector === 'oil_gas'
                      ? '#ea580c'
                      : ms.sector === 'energy'
                      ? '#d97706'
                      : ms.sector === 'healthcare'
                      ? '#e11d48'
                      : '#0284c7'
                  }
                  strokeDasharray="2 2"
                  strokeWidth={1.5}
                  strokeOpacity={0.7}
                />
              ))}

              {/* Individual Sector Lines */}
              {SECTOR_METAS.map((sec) => {
                const isVisible = selectedSector === 'all'
                  ? activeSectors[sec.key]
                  : sec.key === selectedSector;
                if (!isVisible) return null;
                return (
                  <Line
                    key={sec.key}
                    type="monotone"
                    dataKey={sec.key}
                    name={sec.name}
                    stroke={sec.darkColor}
                    strokeWidth={2.5}
                    dot={{
                      r: 3,
                      fill: sec.darkColor,
                      strokeWidth: 1.5,
                      stroke: '#ffffff'
                    }}
                    activeDot={{
                      r: 6,
                      strokeWidth: 2,
                      stroke: '#ffffff'
                    }}
                  />
                );
              })}
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Significant Security Incident Milestones Timeline Strip */}
        <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-500" />
              <span>Significant Security Incident Milestones ({activeMilestones.length})</span>
            </div>
            <span className="text-[11px] text-slate-400">
              Click any milestone to inspect evidence bundle
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {activeMilestones.map((ms, idx) => {
              const sec = SECTOR_METAS.find((s) => s.key === ms.sector);
              const Icon = sec?.icon || AlertTriangle;

              return (
                <div
                  key={`ms-card-${ms.date}-${idx}`}
                  onClick={() => {
                    if (ms.scenarioId && onSelectScenario) {
                      onSelectScenario(ms.scenarioId);
                    }
                  }}
                  className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer group ${
                    ms.riskDelta > 0
                      ? 'bg-rose-50/50 hover:bg-rose-50 dark:bg-rose-950/20 dark:hover:bg-rose-950/40 border-rose-200/80 dark:border-rose-900/60'
                      : 'bg-emerald-50/50 hover:bg-emerald-50 dark:bg-emerald-950/20 dark:hover:bg-emerald-950/40 border-emerald-200/80 dark:border-emerald-900/60'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] mb-1">
                    <span className="font-mono font-bold text-slate-600 dark:text-slate-400 flex items-center gap-1">
                      <Calendar className="w-3 h-3 text-slate-400" />
                      <span>{ms.displayDate}</span>
                    </span>
                    <span
                      className={`font-mono font-bold px-1.5 py-0.2 rounded text-[10px] ${
                        ms.riskDelta > 0
                          ? 'bg-rose-200/70 dark:bg-rose-900/60 text-rose-800 dark:text-rose-200'
                          : 'bg-emerald-200/70 dark:bg-emerald-900/60 text-emerald-800 dark:text-emerald-200'
                      }`}
                    >
                      {ms.riskDelta > 0 ? `+${ms.riskDelta}` : ms.riskDelta} Risk
                    </span>
                  </div>

                  <div className="font-semibold text-xs text-slate-900 dark:text-slate-100 group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors line-clamp-1 flex items-center gap-1">
                    <Icon className="w-3 h-3 shrink-0" style={{ color: sec?.darkColor }} />
                    <span>{ms.title}</span>
                  </div>

                  <div className="text-[10px] text-slate-500 dark:text-slate-400 line-clamp-2 mt-1 leading-snug">
                    {ms.description}
                  </div>

                  {ms.scenarioId && (
                    <div className="mt-1.5 pt-1 border-t border-slate-200/60 dark:border-slate-800 flex items-center justify-between text-[10px]">
                      <span className="font-mono text-slate-400">Bundle: {ms.scenarioId}</span>
                      <span className="font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-0.5 group-hover:underline">
                        <span>Assess</span>
                        <ChevronRight className="w-3 h-3" />
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Live Backend Scenario Evaluation Table */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white">
              Live Backend Scenario Evaluation
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Scenario records, risk decisions and evidence findings returned by the backend service.
              Sector filtering applies to the illustrative trend chart; backend scenarios are shown
              together because the current evidence records do not include sector tags.
            </p>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            {highRiskCount} High Risk · {investigateCount} Review Required
          </div>
        </div>

        <div className="overflow-hidden rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 dark:bg-slate-850 text-slate-600 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-semibold">
                <tr>
                  <th className="py-3 px-4">Scenario ID</th>
                  <th className="py-3 px-4">Device &amp; Unit</th>
                  <th className="py-3 px-4">Evidence Finding</th>
                  <th className="py-3 px-4 text-center">Risk Score</th>
                  <th className="py-3 px-4 text-center">Decision</th>
                  <th className="py-3 px-4 text-center">Safety Gate</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/80">
                {scenarios.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-10 px-4 text-center text-sm text-slate-500 dark:text-slate-400">
                      No backend scenario records are currently available. Check the API connection.
                    </td>
                  </tr>
                ) : (
                  scenarios.map((scenario) => {
                    const riskLevel = scenario.risk_level || 'unknown';
                    const riskScore = scenario.risk_score;
                    const finding = scenario.reasons?.[0] || scenario.risk_factors?.[0]?.replace(/_/g, ' ') || 'No risk explanation provided by backend.';
                    const safetyUnavailable = scenario.human_approval_required === undefined || scenario.deployment_allowed === undefined || scenario.real_action_executed === undefined;
                    const unsafeFlag = scenario.deployment_allowed === true || scenario.real_action_executed === true;

                    return (
                      <tr
                        key={scenario.scenario_id}
                        onClick={() => onSelectScenario(scenario.scenario_id)}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer group"
                      >
                        <td className="py-3 px-4">
                          <span className="font-mono font-bold text-slate-900 dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors">
                            {scenario.scenario_id}
                          </span>
                          <div className="text-[11px] text-slate-500 font-mono">{scenario.package_id || 'Package unavailable'}</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-semibold text-slate-800 dark:text-slate-200">
                            {scenario.asset_name || scenario.device_type || 'Device not specified'}
                          </div>
                          <div className="text-[11px] text-slate-500 truncate max-w-[220px]">
                            {scenario.process_unit || scenario.location || 'Unit not specified'}
                          </div>
                        </td>
                        <td className="py-3 px-4 max-w-sm">
                          <div className="text-slate-700 dark:text-slate-300 font-medium line-clamp-2">{finding}</div>
                          <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
                            {scenario.risk_factors?.join(', ') || 'No risk factors reported'}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-center font-mono font-bold text-sm tabular-nums">
                          <span className={riskScore === undefined ? 'text-slate-500' : riskScore >= 40 ? 'text-rose-600 dark:text-rose-400' : riskScore > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400'}>
                            {riskScore ?? 'N/A'}
                          </span>
                          <span className="text-[10px] text-slate-400 block font-normal">{riskScore === undefined ? 'score unavailable' : '/ 100'}</span>
                        </td>
                        <td className="py-3 px-4 text-center whitespace-nowrap">
                          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                            riskLevel === 'high_risk'
                              ? 'text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/60 border-rose-200 dark:border-rose-800'
                              : riskLevel === 'investigate'
                              ? 'text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 border-amber-200 dark:border-amber-800'
                              : riskLevel === 'normal'
                              ? 'text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-800'
                              : 'text-slate-600 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700'
                          }`}>
                            {riskLevel.replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-center whitespace-nowrap">
                          <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                            unsafeFlag
                              ? 'text-rose-700 bg-rose-50 border-rose-200 dark:text-rose-400 dark:bg-rose-950/60 dark:border-rose-800'
                              : safetyUnavailable
                              ? 'text-slate-600 bg-slate-100 border-slate-200 dark:text-slate-400 dark:bg-slate-800 dark:border-slate-700'
                              : scenario.human_approval_required === true
                              ? 'text-amber-700 bg-amber-50 border-amber-200 dark:text-amber-400 dark:bg-amber-950/60 dark:border-amber-800'
                              : 'text-emerald-700 bg-emerald-50 border-emerald-200 dark:text-emerald-400 dark:bg-emerald-950/60 dark:border-emerald-800'
                          }`}>
                            {unsafeFlag ? 'SAFETY REVIEW' : safetyUnavailable ? 'NOT PROVIDED' : scenario.human_approval_required ? 'HUMAN REVIEW' : 'REVIEW NOT REQUIRED'}
                          </span>
                          <div className="text-[10px] text-slate-400 mt-1">
                            {scenario.deployment_allowed === false ? 'No deployment' : scenario.deployment_allowed === true ? 'Deployment flag true' : 'Deployment unknown'}
                          </div>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={(event) => {
                              event.stopPropagation();
                              onSelectScenario(scenario.scenario_id);
                            }}
                            className="px-2.5 py-1 text-xs font-semibold text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/50 hover:bg-emerald-100 dark:hover:bg-emerald-900/60 rounded border border-emerald-200 dark:border-emerald-800 transition-colors"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};