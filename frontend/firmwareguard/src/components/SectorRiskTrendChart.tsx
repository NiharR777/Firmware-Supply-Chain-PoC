import React, { useState, useMemo } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ReferenceDot,
} from 'recharts';
import {
  SECTOR_30_DAY_TREND,
  SectorTrendPoint
} from '../data/riskTrendData';
import {
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Calendar,
  Filter,
  ExternalLink,
  Zap,
  Flame,
  HeartPulse,
  Car,
  Activity,
  Layers,
  ChevronRight
} from 'lucide-react';

interface SectorRiskTrendChartProps {
  onSelectScenario?: (scenarioId: string) => void;
}

type TimeWindow = '7d' | '14d' | '30d';

interface SectorConfig {
  key: 'energy' | 'oil_gas' | 'healthcare' | 'automotive';
  name: string;
  color: string;
  darkColor: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

const SECTOR_CONFIGS: SectorConfig[] = [
  {
    key: 'energy',
    name: 'Energy & Grid',
    color: '#d97706', // amber-600
    darkColor: '#f59e0b', // amber-500
    icon: Zap,
    description: 'SEL relays, RTUs, NERC CIP-013 microcode'
  },
  {
    key: 'oil_gas',
    name: 'Oil & Gas',
    color: '#ea580c', // orange-600
    darkColor: '#f97316', // orange-500
    icon: Flame,
    description: 'Refinery SIS logic skids, flow meters'
  },
  {
    key: 'healthcare',
    name: 'Healthcare / Medical',
    color: '#e11d48', // rose-600
    darkColor: '#fb7185', // rose-400
    icon: HeartPulse,
    description: 'Bedside infusion pumps, FDA Section 524B'
  },
  {
    key: 'automotive',
    name: 'Automotive',
    color: '#0284c7', // sky-600
    darkColor: '#38bdf8', // sky-400
    icon: Car,
    description: 'AUTOSAR ECUs, CAN gateways, WP.29'
  }
];

export const SectorRiskTrendChart: React.FC<SectorRiskTrendChartProps> = ({
  onSelectScenario
}) => {
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('30d');
  const [activeSectors, setActiveSectors] = useState<Record<string, boolean>>({
    energy: true,
    oil_gas: true,
    healthcare: true,
    automotive: true,
  });
  const [hoveredMilestone, setHoveredMilestone] = useState<string | null>(null);

  // Filter dataset by selected time window
  const filteredData = useMemo(() => {
    if (timeWindow === '7d') {
      return SECTOR_30_DAY_TREND.slice(-7);
    }
    if (timeWindow === '14d') {
      return SECTOR_30_DAY_TREND.slice(-14);
    }
    return SECTOR_30_DAY_TREND;
  }, [timeWindow]);

  // Extract milestones within current window
  const activeMilestones = useMemo(() => {
    return filteredData
      .filter((pt) => pt.milestone !== undefined)
      .map((pt) => ({
        date: pt.date,
        displayDate: pt.displayDate,
        ...pt.milestone!,
      }));
  }, [filteredData]);

  // Latest scores and calculations
  const latestPoint = filteredData[filteredData.length - 1];
  const firstPoint = filteredData[0];

  const overallLatestAvg = useMemo(() => {
    if (!latestPoint) return 0;
    const scores = [latestPoint.energy, latestPoint.oil_gas, latestPoint.healthcare, latestPoint.automotive];
    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  }, [latestPoint]);

  const overallInitialAvg = useMemo(() => {
    if (!firstPoint) return 0;
    const scores = [firstPoint.energy, firstPoint.oil_gas, firstPoint.healthcare, firstPoint.automotive];
    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  }, [firstPoint]);

  const avgDelta = overallLatestAvg - overallInitialAvg;

  // Sector toggle handler
  const toggleSector = (sectorKey: string) => {
    setActiveSectors((prev) => {
      const next = { ...prev, [sectorKey]: !prev[sectorKey] };
      // Prevent disabling all sectors
      if (!Object.values(next).some(Boolean)) {
        return prev;
      }
      return next;
    });
  };

  const selectAllSectors = () => {
    setActiveSectors({
      energy: true,
      oil_gas: true,
      healthcare: true,
      automotive: true,
    });
  };

  // Custom Recharts Tooltip
  const renderCustomTooltip = ({ active, payload, label }: any) => {
    if (!active || !payload || !payload.length) return null;

    const currentPoint = filteredData.find((d) => d.displayDate === label || d.date === label);
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

        {/* Sector values */}
        <div className="space-y-1.5">
          {payload.map((item: any) => {
            const sec = SECTOR_CONFIGS.find((s) => s.key === item.dataKey);
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

        {/* Milestone Callout inside tooltip */}
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
            {milestone.scenarioId && onSelectScenario && (
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
    <div id="firmware-risk-trend" aria-label="Firmware Risk Trend" className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs p-5 transition-colors space-y-4">
      {/* Top Header Row with Title, Controls, & Time Window */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center text-emerald-600 dark:text-emerald-400">
              <Activity className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <span>Firmware Risk Trend</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 font-normal">
                  30-Day Evolution · 4 Target Sectors
                </span>
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Multi-sector telemetry tracking firmware risk scores across Energy, Oil &amp; Gas, Healthcare, and Automotive platforms.
              </p>
            </div>
          </div>
        </div>

        {/* Time Window Buttons */}
        <div className="flex items-center gap-2 self-start lg:self-auto">
          <div className="flex items-center bg-slate-100 dark:bg-slate-800/80 p-0.5 rounded-lg border border-slate-200 dark:border-slate-700">
            {(['7d', '14d', '30d'] as TimeWindow[]).map((window) => (
              <button
                key={window}
                onClick={() => setTimeWindow(window)}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                  timeWindow === window
                    ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white'
                }`}
              >
                {window === '7d' ? 'Last 7 Days' : window === '14d' ? 'Last 14 Days' : 'Full 30 Days'}
              </button>
            ))}
          </div>

          <button
            onClick={selectAllSectors}
            title="Reset all sector toggles"
            className="px-2.5 py-1 text-xs font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700 transition-colors cursor-pointer"
          >
            Reset
          </button>
        </div>
      </div>

      {/* Sector Toggle Badges with Live Current Value */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
        {SECTOR_CONFIGS.map((sec) => {
          const isVisible = activeSectors[sec.key];
          const latestVal = latestPoint ? (latestPoint as any)[sec.key] : 0;
          const initialVal = firstPoint ? (firstPoint as any)[sec.key] : 0;
          const delta = latestVal - initialVal;
          const Icon = sec.icon;

          return (
            <button
              key={sec.key}
              onClick={() => toggleSector(sec.key)}
              className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between ${
                isVisible
                  ? 'bg-slate-50/80 dark:bg-slate-850 border-slate-300 dark:border-slate-700 shadow-2xs'
                  : 'bg-white dark:bg-slate-900/50 border-slate-200 dark:border-slate-800/60 opacity-40 hover:opacity-75'
              }`}
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

      {/* Main Recharts Line Chart Container */}
      <div className="relative pt-2">
        <div className="h-72 sm:h-80 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart
              data={filteredData}
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
              <Tooltip content={renderCustomTooltip} />

              {/* Threshold Reference Lines for Risk Categories */}
              <ReferenceLine
                y={80}
                stroke="#f43f5e"
                strokeDasharray="4 4"
                strokeOpacity={0.4}
                label={{
                  value: 'High Risk Threshold (80)',
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

              {/* Incident Milestone Vertical Reference Lines & Dots */}
              {activeMilestones.map((ms, idx) => (
                <ReferenceLine
                  key={`line-${ms.date}-${idx}`}
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

              {/* Render Lines for each active sector */}
              {SECTOR_CONFIGS.map((sec) => {
                if (!activeSectors[sec.key]) return null;
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
      </div>

      {/* Incident Milestone Timeline Markers / Clickable Strip */}
      <div className="pt-2 border-t border-slate-100 dark:border-slate-800">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
            <AlertTriangle className="w-3.5 h-3.5 text-rose-500" />
            <span>Supply Chain Security Milestones on Timeline ({activeMilestones.length})</span>
          </div>
          <span className="text-[11px] text-slate-400">
            Click any milestone to inspect evidence bundle
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {activeMilestones.map((ms, idx) => {
            const sec = SECTOR_CONFIGS.find((s) => s.key === ms.sector);
            const Icon = sec?.icon || AlertTriangle;

            return (
              <div
                key={`badge-${ms.date}-${idx}`}
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
    </div>
  );
};
