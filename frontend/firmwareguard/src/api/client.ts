export interface ScenarioRecord {
  scenario_id: string;
  package_id?: string;
  firmware_version?: string;
  asset_name?: string;
  device_type?: string;
  available?: boolean;
}

export interface EvidenceLayer {
  name: string;
  status: string;
  detail: string;
}

export interface AssessmentResult {
  use_case: string;
  scenario_id: string;
  package_id: string;
  decision: 'normal' | 'investigate' | 'high_risk';
  risk_score: number;
  severity: string;
  risk_factors: string[];
  risk_breakdown: unknown[];
  evidence_layers: EvidenceLayer[];
  explanations: string[];
  recommended_actions: string[];
  affected_assets: Array<{
    asset_id: string;
    asset_name: string;
    device_type: string;
    process_unit: string;
  }>;
  human_approval_required: boolean;
  deployment_allowed: boolean;
  real_action_executed: boolean;
  data_provenance: string;
  assessment_duration_ms: number;
  assessed_at: string;
  warnings: string[];
}

export interface WorkflowRecord {
  scenario_id: string;
  package_id?: string;
  reviewer?: string;
  disposition?: string;
  note?: string;
  recorded_at?: string;
  workflow_status?: string;
  deployment_allowed?: boolean;
  real_action_executed?: boolean;
  latest_gate_evaluation?: Record<string, unknown>;
}

export interface AuditEvent {
  event: string;
  scenario_id?: string;
  package_id?: string;
  timestamp?: string;
  recorded_at?: string;
  decision?: string;
  risk_score?: number;
  outcome?: string;
  reason?: string;
  reviewer?: string;
  disposition?: string;
  duration_ms?: number;
  real_action_executed?: boolean;
  [key: string]: unknown;
}

export interface ApiMetrics {
  dashboard_assessments_recorded: number;
  latency_samples_ms: number[];
  mean_latency_ms: number | null;
  median_latency_ms: number | null;
  min_latency_ms: number | null;
  max_latency_ms: number | null;
  note: string;
}

export interface PerformanceDashboard {
  data_basis: string;
  scope_note: string;
  scenario_bundles_available: number;
  scenario_bundles_unavailable: string[];
  kpis: Record<string, {
    label: string;
    numerator: number;
    denominator: number;
    value_percent: number | null;
    target: string;
    basis: string;
    status: string;
  }>;
  vex_status_counts: {
    affected: number;
    not_affected: number;
    unknown_or_missing: number;
  };
  scenario_evidence: Array<Record<string, unknown>>;
  not_measured: Array<{
    metric: string;
    reason: string;
    document_target: string;
  }>;
  targets_note: string;
}

export interface ApprovalRequest {
  reviewer: string;
  disposition:
    | 'approved_for_simulated_test'
    | 'hold_for_review'
    | 'rejected';
  note: string;
}

export interface GateResult {
  scenario_id: string;
  package_id: string;
  workflow_status: string;
  message: string;
  deployment_allowed: false;
  real_action_executed: false;
}

class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...options.headers,
    },
  });

  if (!response.ok) {
    let message = `API request failed (${response.status})`;

    try {
      const body = await response.json();
      if (typeof body.detail === 'string') {
        message = body.detail;
      }
    } catch {
      // Keep the HTTP status message if the response is not JSON.
    }

    throw new ApiError(message, response.status);
  }

  return response.json() as Promise<T>;
}

export const firmwareApi = {
  health: () =>
    apiRequest<{
      status: string;
      service: string;
      assessment_mode: string;
      real_action_executed: boolean;
    }>('/api/health'),

  scenarios: () =>
    apiRequest<{
      count: number;
      scenarios: ScenarioRecord[];
    }>('/api/scenarios'),

  assess: (scenarioId: string, packageId: string) =>
    apiRequest<AssessmentResult>('/api/supply-chain/assess', {
      method: 'POST',
      body: JSON.stringify({
        scenario_id: scenarioId,
        package_id: packageId,
      }),
    }),

  metrics: () =>
    apiRequest<ApiMetrics>('/api/metrics'),

  performanceDashboard: () =>
    apiRequest<PerformanceDashboard>('/api/performance-dashboard'),

  workflow: () =>
    apiRequest<{ workflow: Record<string, WorkflowRecord> }>(
      '/api/workflow'
    ),

  recordApproval: (scenarioId: string, approval: ApprovalRequest) =>
    apiRequest<WorkflowRecord & { duplicate_submission: boolean }>(
      `/api/workflow/${encodeURIComponent(scenarioId)}/approval`,
      {
        method: 'POST',
        body: JSON.stringify(approval),
      }
    ),

  simulateRelease: (scenarioId: string) =>
    apiRequest<GateResult>(
      `/api/workflow/${encodeURIComponent(scenarioId)}/simulate-release`,
      { method: 'POST' }
    ),

  audit: () =>
    apiRequest<{ events: AuditEvent[] }>('/api/audit'),
};

export { ApiError };
