
import React, { useEffect, useState } from 'react';
import { ScenarioDefinition } from '../data/spectraScenarios';
import { firmwareApi } from '../api/client';
import type { AssessmentResult } from '../api/client';
import {
  X,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Loader2,
  AlertTriangle,
  ClipboardCheck,
  UserCheck,
  FileText,
} from 'lucide-react';

interface GateResult {
  outcome: string;
  message: string;
}

interface HumanReviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  scenario: ScenarioDefinition | null;
  onRecordReview: (
    scenarioId: string,
    reviewer: string,
    disposition: string,
    note: string
  ) => Promise<void>;
  onSimulateGate: (scenarioId: string) => Promise<GateResult>;
  existingReview?: {
    reviewer: string;
    disposition: string;
    note: string;
    recorded_at: string;
    workflow_status?: string;
  };
}

const getRecommendedDisposition = (decision?: string): string => {
  if (decision === 'high_risk') return 'rejected';
  if (decision === 'investigate') return 'hold_for_review';
  if (decision === 'normal') return 'approved_for_simulated_test';

  return 'hold_for_review';
};

const getRecommendedAction = (decision?: string): string => {
  if (decision === 'high_risk') return 'QUARANTINE';
  if (decision === 'investigate') return 'INVESTIGATE';
  if (decision === 'normal') return 'ALLOW — SIMULATED TEST ONLY';

  return 'HOLD FOR REVIEW';
};

const generateReviewNote = (
  scenarioId: string,
  assessment: AssessmentResult
): string => {
  const decision = assessment.decision || 'unknown';
  const score =
    typeof assessment.risk_score === 'number'
      ? `${assessment.risk_score}/100`
      : 'Not available';

  const reasons = Array.isArray(assessment.explanations)
    ? assessment.explanations.filter(
        (item): item is string => typeof item === 'string'
      )
    : [];

  const riskFactors = Array.isArray(assessment.risk_factors)
    ? assessment.risk_factors.filter(
        (item): item is string => typeof item === 'string'
      )
    : [];

  const evidenceSummary =
    reasons.length > 0
      ? reasons.slice(0, 3).join(' ')
      : riskFactors.length > 0
      ? `Risk factors detected: ${riskFactors.join(', ')}.`
      : 'Review the backend assessment evidence before making a decision.';

  return [
    `Automated review summary — ${scenarioId}`,
    `Package: ${assessment.package_id || 'Not available'}`,
    `Risk classification: ${decision.toUpperCase()}`,
    `Risk score: ${score}`,
    `System recommendation: ${getRecommendedAction(decision)}`,
    `Assessment findings: ${evidenceSummary}`,
    'Human reviewer must verify the evidence and confirm the disposition.',
    'Simulation only. No deployment or physical device action is authorized.',
  ].join('\n');
};

export const HumanReviewModal: React.FC<HumanReviewModalProps> = ({
  isOpen,
  onClose,
  scenario,
  onRecordReview,
  onSimulateGate,
  existingReview,
}) => {
  const [reviewer, setReviewer] = useState(
    'Demo Reviewer (authentication pending)'
  );
  const [disposition, setDisposition] = useState('hold_for_review');
  const [note, setNote] = useState('');
  const [gateResult, setGateResult] = useState<GateResult | null>(null);
  const [assessment, setAssessment] = useState<AssessmentResult | null>(null);
  const [isLoadingAssessment, setIsLoadingAssessment] = useState(false);
  const [assessmentError, setAssessmentError] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [error, setError] = useState('');

  // Reset the review state when the selected scenario changes.
  useEffect(() => {
    if (!isOpen) return;

    setReviewer(
      existingReview?.reviewer ||
        'Demo Reviewer (authentication pending)'
    );

    setDisposition(
      existingReview?.disposition || 'hold_for_review'
    );

    setNote(existingReview?.note || '');
    setGateResult(null);
    setError('');
  }, [isOpen, scenario?.scenario_id, existingReview]);

  // Retrieve the current deterministic assessment from the backend.
  useEffect(() => {
    if (!isOpen || !scenario) {
      setAssessment(null);
      setAssessmentError('');
      setIsLoadingAssessment(false);
      return;
    }

    let cancelled = false;

    const loadLiveAssessment = async () => {
      setIsLoadingAssessment(true);
      setAssessment(null);
      setAssessmentError('');

      try {
        const scenariosResponse = await firmwareApi.scenarios();

        const backendScenario = scenariosResponse.scenarios.find(
          (item) => item.scenario_id === scenario.scenario_id
        );

        if (!backendScenario || !backendScenario.package_id) {
          throw new Error(
            `Backend scenario or package ID for ${scenario.scenario_id} was not found.`
          );
        }

        const result = await firmwareApi.assess(
          backendScenario.scenario_id,
          backendScenario.package_id
        );

        if (
          result.deployment_allowed !== false ||
          result.real_action_executed !== false
        ) {
          throw new Error(
            'Backend safety invariant validation failed.'
          );
        }

        if (!cancelled) {
          setAssessment(result);
        }
      } catch (err) {
        if (!cancelled) {
          setAssessmentError(
            err instanceof Error
              ? err.message
              : 'Unable to retrieve live backend assessment.'
          );
        }
      } finally {
        if (!cancelled) {
          setIsLoadingAssessment(false);
        }
      }
    };

    loadLiveAssessment();

    return () => {
      cancelled = true;
    };
  }, [isOpen, scenario?.scenario_id]);

  // Generate the review explanation and safe default disposition.
  useEffect(() => {
    if (!assessment || existingReview) return;

    setNote(generateReviewNote(scenario?.scenario_id || 'UNKNOWN', assessment));
    setDisposition(getRecommendedDisposition(assessment.decision));
  }, [assessment, existingReview, scenario?.scenario_id]);

  if (!isOpen || !scenario) return null;

  const handleSaveReview = async () => {
    if (!assessment) {
      setError('A valid backend assessment is required before recording review.');
      return;
    }

    if (!reviewer.trim()) {
      setError('Reviewer identity is unavailable.');
      return;
    }

    setIsSaving(true);
    setError('');
    setGateResult(null);

    try {
      await onRecordReview(
        scenario.scenario_id,
        reviewer.trim(),
        disposition,
        note.trim()
      );
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to record human review.'
      );
    } finally {
      setIsSaving(false);
    }
  };

  const handleSimulate = async () => {
    setIsEvaluating(true);
    setError('');
    setGateResult(null);

    try {
      const result = await onSimulateGate(scenario.scenario_id);

      if (
        result.outcome !== 'blocked' &&
        result.outcome !== 'passed_for_simulated_test_only'
      ) {
        throw new Error('Unexpected gate response from backend.');
      }

      setGateResult(result);
    } catch (err) {
      setGateResult({
        outcome: 'blocked',
        message:
          err instanceof Error
            ? err.message
            : 'Backend gate evaluation failed.',
      });
    } finally {
      setIsEvaluating(false);
    }
  };

  const isBusy = isSaving || isEvaluating;
  const riskLevel = assessment?.decision || '';
  const riskScore = assessment?.risk_score;

  const riskColor =
    riskLevel === 'high_risk'
      ? 'text-rose-600 dark:text-rose-400'
      : riskLevel === 'investigate'
      ? 'text-amber-600 dark:text-amber-400'
      : riskLevel === 'normal'
      ? 'text-emerald-600 dark:text-emerald-400'
      : 'text-slate-500';

  const recommendedAction = getRecommendedAction(riskLevel);

  const existingDispositionLabel =
    existingReview?.disposition?.replace(/_/g, ' ') || '';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
      <div className="relative w-full max-w-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-900 dark:text-slate-100 transition-colors">

        {/* Header */}
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                  Automated Human Review
                </span>
                <span className="text-slate-400">·</span>
                <span className="font-mono text-xs text-slate-500">
                  {scenario.scenario_id}
                </span>
              </div>

              <h3 className="text-base font-bold text-slate-900 dark:text-white mt-0.5">
                Assessment Review &amp; Safety Gate
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            disabled={isBusy}
            aria-label="Close review modal"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto">

          {/* Package and risk summary */}
          <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <span className="text-slate-500 text-[11px] block">
                Backend Package ID
              </span>
              <span className="font-mono font-bold text-slate-800 dark:text-slate-200">
                {assessment?.package_id || 'Loading...'}
              </span>
            </div>

            <div>
              <span className="text-slate-500 text-[11px] block">
                Live Deterministic Risk
              </span>

              {isLoadingAssessment ? (
                <span className="font-mono text-slate-500 flex items-center gap-1">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  Loading...
                </span>
              ) : assessment ? (
                <span className={`font-mono font-bold uppercase ${riskColor}`}>
                  {riskLevel} ({riskScore}/100)
                </span>
              ) : (
                <span className="font-mono font-bold text-rose-600 dark:text-rose-400">
                  Unavailable
                </span>
              )}
            </div>

            <div className="col-span-2 sm:col-span-1">
              <span className="text-slate-500 text-[11px] block">
                Deployment Mode
              </span>
              <span className="font-mono text-slate-700 dark:text-slate-300">
                Simulation Only
              </span>
            </div>
          </div>

          {assessmentError && (
            <div className="p-3 rounded-lg border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 text-xs text-rose-700 dark:text-rose-300">
              Backend assessment unavailable: {assessmentError}
            </div>
          )}

          {/* Automated recommendation */}
          {assessment && (
            <div className="p-4 rounded-xl border border-emerald-200 dark:border-emerald-900 bg-emerald-50 dark:bg-emerald-950/30">
              <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-400">
                <ClipboardCheck className="w-4 h-4" />
                <span className="text-xs font-bold uppercase tracking-wide">
                  System-generated recommendation
                </span>
              </div>

              <div className={`text-lg font-extrabold mt-2 ${riskColor}`}>
                {recommendedAction}
              </div>

              <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                This recommendation is generated from the current deterministic backend assessment. The authorized reviewer remains responsible for the final human disposition.
              </p>
            </div>
          )}

          {/* Assessment provenance */}
          {assessment && (
            <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-xs">
              <div className="font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                <FileText className="w-3.5 h-3.5" />
                Backend assessment evidence
              </div>

              <div className="mt-1 text-slate-500">
                Risk factors: {assessment.risk_factors?.join(', ') || 'None reported'}
              </div>

              <div className="text-slate-500">
                Evidence source: {assessment.data_provenance}
              </div>

              <div className="text-slate-500">
                Assessed at: {assessment.assessed_at}
              </div>
            </div>
          )}

          {/* Existing backend review */}
          {existingReview && (
            <div className="p-3 rounded-lg border border-blue-200 dark:border-blue-900 bg-blue-50 dark:bg-blue-950/30 text-xs">
              <div className="font-semibold text-blue-700 dark:text-blue-400">
                Existing backend review record
              </div>
              <div className="mt-1 text-slate-600 dark:text-slate-300">
                Reviewer: {existingReview.reviewer}
              </div>
              <div className="text-slate-600 dark:text-slate-300">
                Disposition: {existingDispositionLabel}
              </div>
              <div className="text-slate-500 mt-1">
                Status: {existingReview.workflow_status || 'Recorded'}
              </div>
            </div>
          )}

          {/* Reviewer identity */}
          <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300">
              <UserCheck className="w-4 h-4" />
              Reviewer identity
            </div>

            <div className="mt-1 text-xs font-mono text-slate-600 dark:text-slate-300">
              {reviewer}
            </div>

            <p className="mt-1 text-[10px] text-amber-700 dark:text-amber-400">
              Prototype identity only. Authentication is not yet connected; production reviewer identity must come from a verified login.
            </p>
          </div>

          {/* Human decision */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
              Confirm Human Review Disposition
            </label>

            <select
              value={disposition}
              disabled={isBusy || !assessment}
              onChange={(e) => setDisposition(e.target.value)}
              className="w-full bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-3 py-2.5 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-emerald-500 transition-colors disabled:opacity-50"
            >
              <option value="approved_for_simulated_test">
                Approve for simulated test
              </option>
              <option value="hold_for_review">
                Hold for review
              </option>
              <option value="rejected">
                Reject / Quarantine
              </option>
            </select>

            <p className="text-[10px] text-slate-500 mt-1">
              The system preselects a recommendation. An authorized reviewer must confirm or change it.
            </p>
          </div>

          {/* Automatically generated justification */}
          <div>
            <div className="flex items-center justify-between gap-2 mb-1">
              <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                System-generated Review Summary
              </label>
              <span className="text-[10px] font-mono text-emerald-600 dark:text-emerald-400">
                AUTO-GENERATED
              </span>
            </div>

            <textarea
              rows={6}
              value={note}
              readOnly
              placeholder="The system will generate the review summary after the backend assessment loads."
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg p-3 text-xs font-mono leading-relaxed text-slate-700 dark:text-slate-300 focus:outline-none resize-y"
            />

            <p className="text-[10px] text-slate-500 mt-1">
              Generated from backend assessment fields. No manual technical justification is required.
            </p>
          </div>

          {/* API errors */}
          {error && (
            <div className="p-3 rounded-lg border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-rose-950/30 text-xs text-rose-700 dark:text-rose-300">
              {error}
            </div>
          )}

          {/* Gate evaluation result */}
          {gateResult && (
            <div
              className={`p-3.5 rounded-xl border text-xs leading-relaxed ${
                gateResult.outcome === 'passed_for_simulated_test_only'
                  ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 text-emerald-900 dark:text-emerald-200'
                  : 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800 text-rose-900 dark:text-rose-200'
              }`}
            >
              <div className="font-bold flex items-center gap-1.5 mb-1 uppercase tracking-wider font-mono">
                {gateResult.outcome === 'passed_for_simulated_test_only' ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    <span>Simulated Test Gate Passed</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 text-rose-600" />
                    <span>Simulated Test Gate Blocked</span>
                  </>
                )}
              </div>

              <p>{gateResult.message}</p>
            </div>
          )}

          {/* Safety invariant */}
          <div className="p-3 rounded-lg bg-slate-100 dark:bg-slate-850 text-[11px] text-slate-600 dark:text-slate-400">
            <strong className="flex items-center gap-1.5 mb-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              Safety Invariant
            </strong>
            The backend requires both manual human approval and deterministic normal-risk status before the simulated test gate can pass. Deployment is never authorized and no real device action is executed.
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 bg-slate-50 dark:bg-slate-950 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
          <button
            onClick={onClose}
            disabled={isBusy}
            className="px-3.5 py-1.5 text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white cursor-pointer disabled:opacity-50"
          >
            Cancel
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={handleSaveReview}
              disabled={isBusy || !assessment || !!assessmentError}
              className="px-3.5 py-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200 bg-white dark:bg-slate-850 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg transition-colors cursor-pointer disabled:opacity-50 flex items-center gap-2"
            >
              {isSaving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              {isSaving ? 'Saving Review...' : 'Record Human Review'}
            </button>

            <button
              onClick={handleSimulate}
              disabled={isBusy || !assessment || !!assessmentError}
              className="px-4 py-1.5 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors cursor-pointer shadow-xs disabled:opacity-50 flex items-center gap-2"
            >
              {isEvaluating && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              {isEvaluating ? 'Evaluating...' : 'Evaluate Simulated Gate'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
