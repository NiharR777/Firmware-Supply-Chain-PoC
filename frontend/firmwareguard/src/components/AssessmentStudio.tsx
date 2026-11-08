
import React, { useEffect, useMemo, useState } from 'react';
import { ScenarioDefinition } from '../data/spectraScenarios';
import { firmwareApi, AssessmentResult, ScenarioRecord } from '../api/client';
import {
  ShieldCheck,
  Play,
  RotateCw,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Clock,
  Server,
} from 'lucide-react';

interface AssessmentStudioProps {
  scenarios: ScenarioDefinition[];
  selectedScenarioId: string;
  onSelectScenarioId: (id: string) => void;
  onOpenReviewModal: (scenarioId: string) => void;
}

const isPassingStatus = (status: string): boolean => {
  const value = status.toLowerCase().replace(/[\s-]+/g, '_');

  return [
    'pass',
    'passed',
    'valid',
    'trusted',
    'complete',
    'not_affected',
    'approved',
    'fresh',
    'compliant',
    'success',
  ].some((item) => value.includes(item));
};

const formatLabel = (value: string): string =>
  value.replace(/_/g, ' ');

export const AssessmentStudio: React.FC<AssessmentStudioProps> = ({
  scenarios,
  selectedScenarioId,
  onSelectScenarioId,
  onOpenReviewModal,
}) => {
  const [backendScenarios, setBackendScenarios] = useState<ScenarioRecord[]>([]);
  const [assessment, setAssessment] = useState<AssessmentResult | null>(null);
  const [isLoadingScenarios, setIsLoadingScenarios] = useState(true);
  const [isAssessing, setIsAssessing] = useState(false);
  const [error, setError] = useState('');

  const current = useMemo(
    () =>
      scenarios.find((scenario) => scenario.scenario_id === selectedScenarioId) ||
      scenarios[0],
    [scenarios, selectedScenarioId]
  );

  useEffect(() => {
    let active = true;

    const loadScenarios = async () => {
      try {
        setIsLoadingScenarios(true);
        const response = await firmwareApi.scenarios();

        if (active) {
          setBackendScenarios(response.scenarios || []);
          setError('');
        }
      } catch (err) {
        if (active) {
          setError(
            err instanceof Error
              ? err.message
              : 'Unable to load scenarios from the backend.'
          );
        }
      } finally {
        if (active) setIsLoadingScenarios(false);
      }
    };

    loadScenarios();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    setAssessment(null);
    setError('');
  }, [selectedScenarioId]);

  const handleRunAssessment = async () => {
    if (!current) return;

    setIsAssessing(true);
    setError('');
    setAssessment(null);

    try {
      const backendScenario = backendScenarios.find(
        (item) => item.scenario_id === selectedScenarioId
      );

      if (!backendScenario || !backendScenario.package_id) {
        throw new Error(
          `Scenario ${selectedScenarioId} is unavailable in the backend or has no package ID.`
        );
      }

      const result = await firmwareApi.assess(
        selectedScenarioId,
        backendScenario.package_id
      );

      if (result.scenario_id !== selectedScenarioId) {
        throw new Error('The backend returned a result for a different scenario.');
      }

      if (result.deployment_allowed !== false) {
        throw new Error(
          'Safety validation failed: backend did not confirm deployment_allowed=false.'
        );
      }

      if (result.real_action_executed !== false) {
        throw new Error(
          'Safety validation failed: backend did not confirm real_action_executed=false.'
        );
      }

      if (result.human_approval_required !== true) {
        throw new Error(
          'Safety validation failed: human approval is not marked as required.'
        );
      }

      setAssessment(result);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Assessment failed. Check that the backend is running.'
      );
    } finally {
      setIsAssessing(false);
    }
  };

  const evidenceRows = assessment?.evidence_layers || [];

  const riskBreakdown = (assessment?.risk_breakdown || []).map(
    (item: unknown) => {
      const entry = item as Record<string, unknown>;

      return {
        factor: String(entry.factor ?? entry.name ?? 'Risk factor'),
        weight: Number(entry.weight ?? entry.score ?? 0),
      };
    }
  );

  const decisionColor =
    assessment?.decision === 'high_risk'
      ? 'rose'
      : assessment?.decision === 'investigate'
      ? 'amber'
      : 'emerald';

  return (
    <div className="space-y-6">
      {/* Scenario selection */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 dark:border-slate-800 pb-3">
          <div>
            <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
              Deterministic Evidence Intake
            </div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
              Select Firmware Scenario Package (10 Predefined Bundles)
            </h2>
            <p className="text-[11px] text-slate-500 mt-1">
              Assessment results are retrieved from the live PoC backend.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleRunAssessment}
              disabled={isAssessing || isLoadingScenarios || !current}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors cursor-pointer shadow-xs disabled:opacity-60"
            >
              {isAssessing ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Evaluating Evidence...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Run Deterministic Assessment</span>
                </>
              )}
            </button>

            <button
              onClick={() => onOpenReviewModal(current.scenario_id)}
              disabled={!current}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-800 dark:text-slate-200 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
              <span>Simulate Review Gate</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-1.5">
          {scenarios.map((scenario) => {
            const isSelected = scenario.scenario_id === selectedScenarioId;

            return (
              <button
                key={scenario.scenario_id}
                onClick={() => onSelectScenarioId(scenario.scenario_id)}
                className={`p-2 rounded-lg text-left border transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-emerald-50 dark:bg-emerald-950/80 border-emerald-500 text-emerald-900 dark:text-emerald-200 ring-1 ring-emerald-500 font-bold'
                    : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="font-mono text-xs">{scenario.scenario_id}</div>
                <div className="text-[9px] font-mono uppercase mt-0.5 font-semibold text-slate-500">
                  {scenario.risk_level === 'high_risk'
                    ? 'HIGH*'
                    : scenario.risk_level === 'investigate'
                    ? 'REV*'
                    : 'NORM*'}
                </div>
              </button>
            );
          })}
        </div>

        {current && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-xs">
            <div>
              <span className="text-[11px] text-slate-500 block">Backend Package ID</span>
              <span className="font-mono font-bold text-slate-800 dark:text-slate-200">
                {backendScenarios.find(
                  (item) => item.scenario_id === selectedScenarioId
                )?.package_id || (isLoadingScenarios ? 'Loading...' : 'Unavailable')}
              </span>
            </div>

            <div>
              <span className="text-[11px] text-slate-500 block">Target Asset</span>
              <span className="font-semibold text-slate-800 dark:text-slate-200 truncate block">
                {current.asset_name}
              </span>
            </div>

            <div>
              <span className="text-[11px] text-slate-500 block">Process Unit</span>
              <span className="text-slate-700 dark:text-slate-300 truncate block">
                {current.process_unit}
              </span>
            </div>

            <div>
              <span className="text-[11px] text-slate-500 block">Backend Status</span>
              <span className="font-mono text-emerald-600 dark:text-emerald-400 font-semibold">
                {isLoadingScenarios ? 'CONNECTING' : backendScenarios.length > 0 ? 'CONNECTED' : 'UNAVAILABLE'}
              </span>
            </div>
          </div>
        )}

        {error && (
          <div className="p-3 rounded-lg border border-rose-300 dark:border-rose-900 bg-rose-50 dark:bg-rose-950/30 text-rose-700 dark:text-rose-300 text-xs flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Assessment results */}
      <div className="p-5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-6">
        {!assessment && !isAssessing && (
          <div className="py-12 text-center space-y-3">
            <Server className="w-9 h-9 mx-auto text-slate-400" />
            <h3 className="font-bold text-sm text-slate-800 dark:text-white">
              No backend assessment loaded
            </h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Select a scenario and run the deterministic assessment to retrieve
              actual evidence checks, risk factors and recommendations from the backend.
              Scenario preview labels are not assessment results.
            </p>
          </div>
        )}

        {isAssessing && (
          <div className="py-12 text-center">
            <RotateCw className="w-8 h-8 mx-auto text-emerald-600 animate-spin" />
            <p className="text-sm font-semibold mt-3 text-slate-700 dark:text-slate-200">
              Backend is evaluating the synthetic evidence bundle...
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Waiting for the deterministic assessment response.
            </p>
          </div>
        )}

        {assessment && (
          <>
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                    BACKEND ASSESSMENT RESULT
                  </span>
                  <span className="font-mono text-sm font-bold text-slate-900 dark:text-white">
                    {assessment.scenario_id} · {assessment.package_id}
                  </span>
                </div>

                <div className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                  Asset: {assessment.affected_assets?.[0]?.asset_name || current.asset_name}
                  {' '}({assessment.affected_assets?.[0]?.device_type || current.device_type})
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="px-4 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-center">
                  <span
                    className={`font-mono text-2xl font-black tabular-nums ${
                      assessment.risk_score >= 40
                        ? 'text-rose-600 dark:text-rose-400'
                        : assessment.risk_score > 0
                        ? 'text-amber-600 dark:text-amber-400'
                        : 'text-emerald-600 dark:text-emerald-400'
                    }`}
                  >
                    {assessment.risk_score}
                  </span>
                  <span className="text-[9px] uppercase tracking-wider text-slate-400 block font-semibold">
                    RISK SCORE / 100
                  </span>
                </div>

                <div
                  className={`px-3 py-2 rounded-lg text-xs font-mono font-bold uppercase border ${
                    decisionColor === 'rose'
                      ? 'bg-rose-50 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300 border-rose-300 dark:border-rose-800'
                      : decisionColor === 'amber'
                      ? 'bg-amber-50 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                      : 'bg-emerald-50 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                  }`}
                >
                  {formatLabel(assessment.decision)}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-7 space-y-3">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300 flex items-center justify-between">
                  <span>Backend Evidence Layers</span>
                  <span className="text-slate-500 font-mono font-normal">
                    {evidenceRows.length} controls
                  </span>
                </div>

                <div className="space-y-2">
                  {evidenceRows.map((item, index) => {
                    const passed = isPassingStatus(item.status);

                    return (
                      <div
                        key={`${item.name}-${index}`}
                        className={`p-3 rounded-lg border flex items-start justify-between gap-3 ${
                          passed
                            ? 'bg-white dark:bg-slate-950/60 border-slate-200 dark:border-slate-800/80'
                            : 'bg-rose-50/50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/50'
                        }`}
                      >
                        <div className="space-y-0.5">
                          <div className="font-semibold text-xs text-slate-900 dark:text-slate-100">
                            {item.name}
                          </div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono leading-relaxed">
                            {item.detail}
                          </div>
                        </div>

                        <span
                          className={`text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded border shrink-0 ${
                            passed
                              ? 'text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 border-emerald-200 dark:border-emerald-800'
                              : 'text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/60 border-rose-200 dark:border-rose-800'
                          }`}
                        >
                          {item.status}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="lg:col-span-5 space-y-4">
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                    Backend Risk Factor Weights
                  </div>

                  {riskBreakdown.length === 0 ? (
                    <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-300 text-xs">
                      No weighted risk factors were returned by the backend.
                    </div>
                  ) : (
                    <div className="space-y-1.5 font-mono text-xs">
                      {riskBreakdown.map((item, index) => (
                        <div
                          key={`${item.factor}-${index}`}
                          className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between"
                        >
                          <span className="text-slate-800 dark:text-slate-200">
                            {item.factor}
                          </span>
                          <span className="text-rose-600 dark:text-rose-400 font-bold tabular-nums">
                            +{item.weight}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="text-xs text-slate-500">
                    Risk factors returned: {assessment.risk_factors.length}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2">
                  <span className="text-[10px] font-mono font-bold text-cyan-600 dark:text-cyan-400 uppercase tracking-wider block">
                    MITRE ATT&CK for ICS Mapping
                  </span>
                  <div className="font-bold text-xs text-slate-900 dark:text-white">
                    {current.mitre_technique}
                  </div>
                  <div className="text-xs text-slate-500">
                    Tactic:{' '}
                    <span className="font-semibold text-slate-700 dark:text-slate-300">
                      {current.mitre_tactic}
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed pt-1 border-t border-slate-200 dark:border-slate-800">
                    {current.attack_description}
                  </p>
                  <p className="text-[10px] text-slate-400">
                    Scenario reference metadata; not generated by the assessment API.
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2">
                  <div className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                    Backend Decision Explanations
                  </div>
                  {assessment.explanations.length > 0 ? (
                    <ul className="text-xs text-slate-600 dark:text-slate-400 space-y-1.5 list-disc pl-4">
                      {assessment.explanations.map((reason, index) => (
                        <li key={index}>{reason}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-500">
                      No explanations returned.
                    </p>
                  )}
                </div>

                <div className="p-3.5 rounded-xl bg-slate-100 dark:bg-slate-850 border border-slate-200 dark:border-slate-800">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 block">
                    Backend Recommendations
                  </span>
                  {assessment.recommended_actions.length > 0 ? (
                    <ul className="font-bold text-xs text-slate-900 dark:text-white uppercase mt-1 space-y-1">
                      {assessment.recommended_actions.map((action, index) => (
                        <li key={index}>{formatLabel(action)}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-500 mt-1">
                      No recommendations returned.
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-wrap gap-3 items-center text-xs text-slate-600 dark:text-slate-300">
              <Clock className="w-4 h-4" />
              <span>
                Backend execution: {assessment.assessment_duration_ms.toFixed(3)} ms
              </span>
              <span>
                Assessed: {new Date(assessment.assessed_at).toLocaleString()}
              </span>
              <span>
                Provenance: {assessment.data_provenance}
              </span>
            </div>

            {assessment.warnings.length > 0 && (
              <div className="p-3 rounded-lg border border-amber-300 dark:border-amber-900 bg-amber-50 dark:bg-amber-950/30 text-amber-800 dark:text-amber-300 text-xs space-y-1">
                <strong>Backend warnings</strong>
                {assessment.warnings.map((warning, index) => (
                  <p key={index}>• {warning}</p>
                ))}
              </div>
            )}

            <div className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-xs text-emerald-900 dark:text-emerald-200 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                <strong className="font-bold">
                  HUMAN APPROVAL REQUIRED: {assessment.human_approval_required ? 'YES' : 'NO'}
                </strong>
              </div>
              <span>
                Deployment Allowed: <strong>NO</strong>
              </span>
              <span>
                Real Action Executed: <strong>NO</strong>
              </span>
              <span className="font-mono text-[11px] text-emerald-700 dark:text-emerald-300">
                SYNTHETIC OBSERVED EVIDENCE
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
