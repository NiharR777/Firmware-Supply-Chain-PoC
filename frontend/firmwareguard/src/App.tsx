
import React, { useState, useEffect, useMemo } from 'react';
import { SPECTRA_SCENARIOS } from './data/spectraScenarios';
import { INITIAL_FIRMWARE_ASSETS } from './data/firmwareData';
import { FirmwareAsset } from './types/firmware';

import { firmwareApi, ApiError } from './api/client';
import type {
  WorkflowRecord,
  AuditEvent,
} from './api/client';

import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { OverviewView } from './components/OverviewView';
import { AssessmentStudio } from './components/AssessmentStudio';
import { KpiMetricsView } from './components/KpiMetricsView';
import { VexMatrix } from './components/VexMatrix';
import { BinaryHardeningView } from './components/BinaryHardeningView';
import { PedigreeGraph } from './components/PedigreeGraph';
import { ComplianceAuditView } from './components/ComplianceAuditView';
import { HumanReviewModal } from './components/HumanReviewModal';
import { SpectraAdvisorModal } from './components/SpectraAdvisorModal';
import { AuditHistoryView, AuditEventItem } from './components/AuditHistoryView';
import { VexExporterModal } from './components/VexExporterModal';
import { AssetDetailModal } from './components/AssetDetailModal';

type ReviewRecord = {
  reviewer: string;
  disposition: string;
  note: string;
  recorded_at: string;
  workflow_status?: string;
};

function mapWorkflowRecord(
  record: WorkflowRecord
): ReviewRecord {
  return {
    reviewer: record.reviewer || '',
    disposition: record.disposition || 'hold_for_review',
    note: record.note || '',
    recorded_at: record.recorded_at || '',
    workflow_status: record.workflow_status,
  };
}

function mapAuditEvent(
  event: AuditEvent,
  index: number
): AuditEventItem {
  const timestamp =
    event.timestamp || event.recorded_at || new Date().toISOString();

  const details =
    typeof event.reason === 'string'
      ? event.reason
      : [
          event.decision ? `Decision: ${event.decision}` : '',
          typeof event.risk_score === 'number'
            ? `Score: ${event.risk_score}/100`
            : '',
          event.disposition
            ? `Disposition: ${event.disposition}`
            : '',
          event.reviewer ? `Reviewer: ${event.reviewer}` : '',
          event.message ? String(event.message) : '',
          event.real_action_executed === false
            ? 'Real action executed: NO'
            : '',
        ]
          .filter(Boolean)
          .join(' · ') || 'Backend audit event';

  return {
    id: `backend-audit-${timestamp}-${index}`,
    timestamp,
    event: event.event,
    scenario_id: event.scenario_id || 'N/A',
    package_id: event.package_id || 'N/A',
    details,
    outcome: event.outcome,
  };
}

export default function App() {
  // Theme
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    return (
      (localStorage.getItem('spectra_theme') as 'light' | 'dark') ||
      'light'
    );
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    localStorage.setItem('spectra_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  // Navigation
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [selectedSector, setSelectedSector] = useState<string>('all');
  const [selectedScenarioId, setSelectedScenarioId] =
    useState<string>('SC-001');

  // Modals
  const [isAdvisorModalOpen, setIsAdvisorModalOpen] = useState(false);
  const [isReviewModalOpen, setIsReviewModalOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [selectedAssetForModal, setSelectedAssetForModal] =
    useState<FirmwareAsset | null>(null);

  // Backend workflow and audit state
  const [reviews, setReviews] = useState<
    Record<string, ReviewRecord>
  >({});
  const [auditEvents, setAuditEvents] = useState<AuditEventItem[]>([]);
  const [workflowLoading, setWorkflowLoading] = useState(true);
  const [workflowError, setWorkflowError] = useState('');

  // Refresh workflow records from backend
  const refreshWorkflow = async () => {
    const response = await firmwareApi.workflow();

    const mapped: Record<string, ReviewRecord> = {};

    Object.entries(response.workflow || {}).forEach(
      ([scenarioId, record]) => {
        mapped[scenarioId] = mapWorkflowRecord(record);
      }
    );

    setReviews(mapped);
  };

  // Refresh audit events from backend
  const refreshAudit = async () => {
    const response = await firmwareApi.audit();

    setAuditEvents(
      (response.events || []).map(mapAuditEvent)
    );
  };

  // Load persistent backend state when app opens
  useEffect(() => {
    let cancelled = false;

    const loadBackendState = async () => {
      setWorkflowLoading(true);
      setWorkflowError('');

      try {
        const [workflowResponse, auditResponse] = await Promise.all([
          firmwareApi.workflow(),
          firmwareApi.audit(),
        ]);

        if (cancelled) return;

        const mapped: Record<string, ReviewRecord> = {};

        Object.entries(workflowResponse.workflow || {}).forEach(
          ([scenarioId, record]) => {
            mapped[scenarioId] = mapWorkflowRecord(record);
          }
        );

        setReviews(mapped);
        setAuditEvents(
          (auditResponse.events || []).map(mapAuditEvent)
        );
      } catch (error) {
        if (!cancelled) {
          setWorkflowError(
            error instanceof Error
              ? error.message
              : 'Unable to load backend workflow.'
          );
        }
      } finally {
        if (!cancelled) {
          setWorkflowLoading(false);
        }
      }
    };

    loadBackendState();

    return () => {
      cancelled = true;
    };
  }, []);

  // Filter scenarios
  const filteredScenarios = useMemo(() => {
    if (selectedSector === 'all') return SPECTRA_SCENARIOS;

    return SPECTRA_SCENARIOS.filter(
      (scenario) => scenario.sector === selectedSector
    );
  }, [selectedSector]);

  const highRiskCount = SPECTRA_SCENARIOS.filter(
    (scenario) => scenario.risk_level === 'high_risk'
  ).length;

  const investigateCount = SPECTRA_SCENARIOS.filter(
    (scenario) => scenario.risk_level === 'investigate'
  ).length;

  const currentScenario =
    SPECTRA_SCENARIOS.find(
      (scenario) => scenario.scenario_id === selectedScenarioId
    ) || SPECTRA_SCENARIOS[0];

  // Record review using the real backend API
  const handleRecordReview = async (
    scenarioId: string,
    reviewer: string,
    disposition: string,
    note: string
  ) => {
    const approval = {
      reviewer: reviewer.trim(),
      disposition: disposition as
        | 'approved_for_simulated_test'
        | 'hold_for_review'
        | 'rejected',
      note: note.trim(),
    };

    const savedRecord = await firmwareApi.recordApproval(
      scenarioId,
      approval
    );

    setReviews((previous) => ({
      ...previous,
      [scenarioId]: mapWorkflowRecord(savedRecord),
    }));

    await refreshAudit();

    alert(
      `Backend confirmation: Human review recorded for ${scenarioId}. No physical device deployment is authorized.`
    );
  };

  // Evaluate the simulated gate using the real backend API
  const handleSimulateGate = async (scenarioId: string) => {
    try {
      const result = await firmwareApi.simulateRelease(scenarioId);

      if (
        result.deployment_allowed !== false ||
        result.real_action_executed !== false
      ) {
        throw new Error(
          'Safety verification failed: backend returned unexpected action flags.'
        );
      }

      await refreshWorkflow();
      await refreshAudit();

      return {
        outcome:
          result.workflow_status === 'simulated_test_gate_passed'
            ? 'passed_for_simulated_test_only'
            : 'blocked',
        message: result.message,
      };
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        return {
          outcome: 'blocked',
          message: error.message,
        };
      }

      throw error;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors">

      {/* Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        theme={theme}
        onToggleTheme={toggleTheme}
        onOpenExportModal={() => setIsExportModalOpen(true)}
        onOpenAdvisorModal={() => setIsAdvisorModalOpen(true)}
      />

      {/* Workspace */}
      <div className="flex-1 flex flex-col md:flex-row w-full">

        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          selectedSector={selectedSector}
          onSelectSector={setSelectedSector}
          highRiskCount={highRiskCount}
          investigateCount={investigateCount}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full space-y-6">

          {/* Backend loading/error status */}
          {workflowLoading && (
            <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900 text-xs text-blue-700 dark:text-blue-300">
              Loading workflow and audit records from backend...
            </div>
          )}

          {workflowError && (
            <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900 text-xs text-rose-700 dark:text-rose-300">
              Backend workflow loading failed: {workflowError}
              <button
                onClick={() => {
                  refreshWorkflow()
                    .then(refreshAudit)
                    .catch((error) =>
                      setWorkflowError(
                        error instanceof Error
                          ? error.message
                          : 'Refresh failed.'
                      )
                    );
                }}
                className="ml-2 underline font-semibold"
              >
                Retry
              </button>
            </div>
          )}

          {activeTab === 'overview' && (
            <OverviewView
              scenarios={filteredScenarios}
              onSelectScenario={(id) => {
                setSelectedScenarioId(id);
                setActiveTab('assessment');
              }}
              onOpenAdvisorModal={() =>
                setIsAdvisorModalOpen(true)
              }
              onOpenReviewModal={() =>
                setIsReviewModalOpen(true)
              }
              onViewVexMatrix={() =>
                setActiveTab('reachability')
              }
            />
          )}

          {activeTab === 'assessment' && (
            <AssessmentStudio
              scenarios={SPECTRA_SCENARIOS}
              selectedScenarioId={selectedScenarioId}
              onSelectScenarioId={setSelectedScenarioId}
              onOpenReviewModal={(id) => {
                setSelectedScenarioId(id);
                setIsReviewModalOpen(true);
              }}
            />
          )}

          {activeTab === 'kpis' && (
            <KpiMetricsView scenarios={SPECTRA_SCENARIOS} />
          )}

          {activeTab === 'readiness' && (
            <KpiMetricsView scenarios={SPECTRA_SCENARIOS} />
          )}

          {activeTab === 'reachability' && (
            <VexMatrix
              assets={INITIAL_FIRMWARE_ASSETS}
              onOpenExportModal={() =>
                setIsExportModalOpen(true)
              }
            />
          )}

          {activeTab === 'hardening' && (
            <BinaryHardeningView
              assets={INITIAL_FIRMWARE_ASSETS}
            />
          )}

          {activeTab === 'pedigree' && (
            <PedigreeGraph
              assets={INITIAL_FIRMWARE_ASSETS}
              onSelectAsset={(asset) =>
                setSelectedAssetForModal(asset)
              }
            />
          )}

          {activeTab === 'compliance' && (
            <ComplianceAuditView
              assets={INITIAL_FIRMWARE_ASSETS}
            />
          )}

          {activeTab === 'review' && (
            <div className="p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs space-y-4">
              <h2 className="text-base font-bold text-slate-900 dark:text-white">
                Human-in-the-Loop Review &amp; Safety Gate Console
              </h2>

              <p className="text-xs text-slate-500 leading-relaxed max-w-3xl">
                Manual human approval is a mandatory prerequisite
                for simulated release testing. Review evidence,
                record the engineer disposition, and evaluate the
                backend simulated release gate.
              </p>

              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-2">
                {SPECTRA_SCENARIOS.map((scenario) => (
                  <button
                    key={scenario.scenario_id}
                    onClick={() => {
                      setSelectedScenarioId(
                        scenario.scenario_id
                      );
                      setIsReviewModalOpen(true);
                    }}
                    className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 hover:border-emerald-500 bg-slate-50 dark:bg-slate-950 text-left transition-colors cursor-pointer"
                  >
                    <div className="font-mono font-bold text-xs">
                      {scenario.scenario_id}
                    </div>

                    <div className="text-[11px] text-slate-500 truncate mt-0.5">
                      {scenario.asset_name}
                    </div>

                    <div className="text-[10px] text-emerald-600 dark:text-emerald-400 font-semibold mt-1">
                      Review Gate →
                    </div>

                    {reviews[scenario.scenario_id] && (
                      <div className="text-[10px] text-blue-600 dark:text-blue-400 mt-1">
                        Backend review saved
                      </div>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'audit' && (
            <AuditHistoryView auditEvents={auditEvents} />
          )}
        </main>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-900 bg-white/80 dark:bg-slate-950/80 py-4 px-4 sm:px-6 lg:px-8 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            SPECTRA · OT Firmware Supply-Chain Assurance &amp; Safety Gate PoC
          </div>

          <div className="text-slate-400 font-mono text-[11px]">
            Synthetic Observed Evidence · Zero Physical Flashing
          </div>
        </div>
      </footer>

      {/* Human Review Modal */}
      <HumanReviewModal
        isOpen={isReviewModalOpen}
        onClose={() => setIsReviewModalOpen(false)}
        scenario={currentScenario}
        onRecordReview={handleRecordReview}
        onSimulateGate={handleSimulateGate}
        existingReview={reviews[currentScenario.scenario_id]}
      />

      {/* Other Modals */}
      <SpectraAdvisorModal
        isOpen={isAdvisorModalOpen}
        onClose={() => setIsAdvisorModalOpen(false)}
      />

      <VexExporterModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        assets={INITIAL_FIRMWARE_ASSETS}
      />

      <AssetDetailModal
        asset={selectedAssetForModal}
        onClose={() => setSelectedAssetForModal(null)}
        onOpenExportModal={() => {
          setSelectedAssetForModal(null);
          setIsExportModalOpen(true);
        }}
      />
    </div>
  );
}
