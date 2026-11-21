
export interface ScenarioRecord {
  scenario_id: string;
  package_id?: string;
  firmware_version?: string;
  asset_name?: string;
  device_type?: string;
  asset_id?: string;
  product_id?: string;
  vendor_id?: string;
  process_unit?: string;
  location?: string;

  risk_score?: number;
  risk_level?: 'normal' | 'investigate' | 'high_risk' | string;
  risk_factors?: string[];
  risk_breakdown?: unknown[];
  reasons?: string[];
  recommendation?: string;

  hash_match?: boolean;
  observed_hash?: string;
  trusted_sha256?: string;

  signature_status?: string;
  trusted_root_status?: string;

  vendor_trust?: string;
  observed_vendor_id?: string;
  approved_vendor_id?: string;

  expected_version?: string;
  observed_version?: string;
  rollback_authorized?: boolean;

  sbom_present?: boolean;
  sbom_status?: string;
  component_count?: number;

  vulnerability_status?: string;
  vulnerabilities?: unknown[];

  unexpected_component_observed?: boolean;

  evidence_age_days?: number;
  freshness_threshold_days?: number;

  evidence_layers?: EvidenceLayer[];

  human_approval_required?: boolean;
  deployment_allowed?: boolean;
  real_action_executed?: boolean;
  data_provenance?: string;

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

export interface CustomerAssessmentResult {
  assessment_id: string;
  industry: string;
  customer_name: string;
  product_name: string;
  firmware_version: string;
  sbom_format: string;
  component_count: number;
  completeness: string;
  product_mapping: {
    customer_product: string;
    sbom_root_component: string | null;
    mapped: boolean;
    note: string;
  };
  baseline_comparison: {
    status: string;
    submitted_version: string;
    approved_version: string | null;
    approved_sha256: string | null;
    submitted_sha256: string;
  };
  vulnerability_matching: {
    catalog: string;
    catalog_is_live: boolean;
    findings_count: number;
    findings: Array<{
      demo_id: string;
      component: string;
      version: string;
      severity: string;
      description: string;
      recommendation: string;
    }>;
    live_nvd: {
      provider: string;
      is_live_source: boolean;
      components_checked: number;
      components_skipped: number;
      findings_count: number;
      findings: Array<{
        cve_id: string;
        component: string;
        version: string;
        severity: string;
        cvss_score: number | null;
        cvss_version: string | null;
        description: string;
        published: string | null;
        last_modified: string | null;
        references: string[];
        cpe_criteria: string[];
        match_status: string;
        applicability_verified: boolean;
        evidence_source: string;
        recommendation: string;
      }>;
      component_results: Array<{
        component: string;
        version: string;
        status: string;
        candidate_count: number;
      }>;
      errors: string[];
      applicability_note: string;
    };
  };
  risk: {
    score: number;
    level: string;
  };
  recommendation: string;
  warnings: string[];
  human_review_required: boolean;
  deployment_allowed: false;
  real_action_executed: false;
}

export interface CustomerAssessmentRequest {
  industry: 'industrial' | 'telecom' | 'healthcare';
  customer_name: string;
  product_name: string;
  firmware_version: string;
  firmware_sha256: string;
  approved_baseline_sha256?: string | null;
  approved_baseline_version?: string | null;
  sbom: Record<string, unknown>;
  provenance_source?: string;
  supplier_name?: string;
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
  customerAnalyze: (payload: CustomerAssessmentRequest) =>
    apiRequest<CustomerAssessmentResult>('/api/customer-assessment/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

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
