import { Program, Hunt, Finding, Report, HistorySession, CapabilityDefinition, CapabilityEvaluationResult, ResearchCase, ResearchActivity, DisclosurePackage, ExecutionResult } from '../types.ts';

const API_BASE = '/api/v1';

async function apiFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const defaultAuthHeader = 'Bearer mock-token:user-ayush-001:RESEARCHER:Ayush';
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: defaultAuthHeader,
    ...(options?.headers as Record<string, string>),
  };

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const errorBody = await res.json().catch(() => ({}));
    const reqId = errorBody.error?.requestId || res.headers.get('X-Request-ID');
    const msg = errorBody.error?.message || `API Error (${res.status}): ${res.statusText}`;
    const fullMsg = reqId ? `${msg} (Request ID: ${reqId})` : msg;
    throw new Error(fullMsg);
  }

  return res.json();
}

export const api = {
  // Programs
  getPrograms: () => apiFetch<Program[]>('/programs'),
  getProgramById: (id: string) => apiFetch<Program>(`/programs/${id}`),

  // Hunts
  getHunts: () => apiFetch<Hunt[]>('/hunts'),
  getHuntById: (id: string) => apiFetch<Hunt>(`/hunts/${id}`),
  createHunt: (programId: string, targetDomain: string) =>
    apiFetch<{ hunt: Hunt; isExisting: boolean }>('/hunts', {
      method: 'POST',
      body: JSON.stringify({ programId, targetDomain }),
    }),
  startHunt: (id: string) => apiFetch<Hunt>(`/hunts/${id}/start`, { method: 'POST' }),
  pauseHunt: (id: string) => apiFetch<Hunt>(`/hunts/${id}/pause`, { method: 'POST' }),
  resumeHunt: (id: string) => apiFetch<Hunt>(`/hunts/${id}/resume`, { method: 'POST' }),
  stopHunt: (id: string) => apiFetch<Hunt>(`/hunts/${id}/stop`, { method: 'POST' }),
  completeHunt: (id: string) => apiFetch<Hunt>(`/hunts/${id}/complete`, { method: 'POST' }),

  // Findings
  getFindings: () => apiFetch<Finding[]>('/findings'),
  getFindingById: (id: string) => apiFetch<Finding>(`/findings/${id}`),
  reviewFinding: (id: string) => apiFetch<Finding>(`/findings/${id}/review`, { method: 'POST' }),
  transitionFinding: (id: string, status: string) =>
    apiFetch<Finding>(`/findings/${id}/transition`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    }),
  validateFinding: (id: string) => apiFetch<Finding>(`/findings/${id}/validate`, { method: 'POST' }),
  verifyFinding: (id: string) => apiFetch<Finding>(`/findings/${id}/verify`, { method: 'POST' }),
  getFindingTimeline: (id: string) => apiFetch<any[]>(`/findings/${id}/timeline`),
  getFindingEvidence: (id: string) => apiFetch<any>(`/findings/${id}/evidence`),

  // Reports
  getReports: () => apiFetch<Report[]>('/reports'),
  getReportById: (id: string) => apiFetch<Report>(`/reports/${id}`),
  createReport: (findingId: string, title?: string, summary?: string) =>
    apiFetch<{ report: Report; isExisting: boolean }>(`/findings/${findingId}/report`, {
      method: 'POST',
      body: JSON.stringify({ title, summary }),
    }),
  markReportReady: (id: string) => apiFetch<Report>(`/reports/${id}/ready`, { method: 'POST' }),
  submitReport: (id: string) => apiFetch<Report>(`/reports/${id}/submit`, { method: 'POST' }),
  acceptReport: (id: string) => apiFetch<Report>(`/reports/${id}/accept`, { method: 'POST' }),
  rejectReport: (id: string) => apiFetch<Report>(`/reports/${id}/reject`, { method: 'POST' }),
  resolveReport: (id: string) => apiFetch<Report>(`/reports/${id}/resolve`, { method: 'POST' }),

  // History & Audit
  getHistory: () => apiFetch<HistorySession[]>('/history'),

  // Capabilities Framework
  getCapabilities: (filter?: { category?: string; status?: string }) => {
    const params = new URLSearchParams(filter || {}).toString();
    const query = params ? `?${params}` : '';
    return apiFetch<CapabilityDefinition[]>(`/capabilities${query}`);
  },
  getCapabilityById: (id: string) => apiFetch<CapabilityDefinition>(`/capabilities/${id}`),
  evaluateCapability: (programId: string, target: string, capabilityId: string, assetId?: string) =>
    apiFetch<CapabilityEvaluationResult>('/capabilities/evaluate', {
      method: 'POST',
      body: JSON.stringify({ programId, target, capabilityId, assetId }),
    }),
  analyzeCapability: (programId: string, target: string, capabilityId: string, observationData?: Record<string, any>, assetId?: string) =>
    apiFetch<any>('/research/analyze', {
      method: 'POST',
      body: JSON.stringify({ programId, target, capabilityId, observationData, assetId }),
    }),
  validateResearchFinding: (findingId: string, validationId?: string, observationOverride?: Record<string, any>) =>
    apiFetch<any>('/research/validate', {
      method: 'POST',
      body: JSON.stringify({ findingId, validationId, observationOverride }),
    }),

  getAuditEvents: (filters?: Record<string, string>) => {
    const params = new URLSearchParams(filters || {}).toString();
    const query = params ? `?${params}` : '';
    return apiFetch<any[]>(`/audit-events${query}`);
  },
  getRewardMetrics: () => apiFetch<{ paid: number; pending: number; potential: number; formattedPaid: string; formattedPending: string; formattedPotential: string }>('/metrics/rewards'),

  // Research Cases & Campaign Management
  getCases: (programId?: string) => {
    const query = programId ? `?programId=${encodeURIComponent(programId)}` : '';
    return apiFetch<ResearchCase[]>(`/cases${query}`);
  },
  getCaseById: (id: string) => apiFetch<ResearchCase & { lineage: any }>(`/cases/${id}`),
  createCase: (programId: string, title: string, objective: string, scopeSummary?: string) =>
    apiFetch<ResearchCase>('/cases', {
      method: 'POST',
      body: JSON.stringify({ programId, title, objective, scopeSummary }),
    }),
  transitionCase: (id: string, status: string) =>
    apiFetch<ResearchCase>(`/cases/${id}/transition`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    }),
  getCaseActivities: (id: string) => apiFetch<ResearchActivity[]>(`/cases/${id}/activities`),
  createCaseActivity: (caseId: string, capabilityId: string, assetId: string, target: string, action: string) =>
    apiFetch<ResearchActivity>(`/cases/${caseId}/activities`, {
      method: 'POST',
      body: JSON.stringify({ capabilityId, assetId, target, action }),
    }),

  // Disclosure & Submission Intelligence
  getDisclosures: (filters?: { findingId?: string; caseId?: string; programId?: string }) => {
    const params = new URLSearchParams(filters || {}).toString();
    const query = params ? `?${params}` : '';
    return apiFetch<DisclosurePackage[]>(`/disclosures${query}`);
  },
  getDisclosureById: (id: string) => apiFetch<DisclosurePackage>(`/disclosures/${id}`),
  createDisclosurePackage: (findingId: string) =>
    apiFetch<DisclosurePackage>(`/findings/${findingId}/disclosure`, {
      method: 'POST',
    }),
  transitionDisclosureStatus: (id: string, status: string) =>
    apiFetch<DisclosurePackage>(`/disclosures/${id}/transition`, {
      method: 'POST',
      body: JSON.stringify({ status }),
    }),
  approveDisclosurePackage: (id: string) =>
    apiFetch<DisclosurePackage>(`/disclosures/${id}/approve`, {
      method: 'POST',
      body: JSON.stringify({ confirmApproval: true }),
    }),
  recordManualSubmission: (id: string) =>
    apiFetch<DisclosurePackage>(`/disclosures/${id}/submit`, {
      method: 'POST',
    }),
  getDisclosureExportUrl: (id: string, format: 'markdown' | 'html' | 'text' | 'json' = 'markdown') =>
    `/api/v1/disclosures/${id}/package?format=${format}`,

  // Research Capability Execution Engine
  getExecutions: (filters?: { caseId?: string; programId?: string; status?: string }) => {
    const params = new URLSearchParams(filters || {}).toString();
    const query = params ? `?${params}` : '';
    return apiFetch<ExecutionResult[]>(`/executions${query}`);
  },
  getExecutionById: (id: string) => apiFetch<ExecutionResult>(`/executions/${id}`),
  executeCapability: (data: {
    caseId: string;
    capabilityId: string;
    assetId: string;
    target?: string;
    parameters?: Record<string, string | number | boolean>;
    confirmApproval?: boolean;
  }) =>
    apiFetch<ExecutionResult>('/executions', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  cancelExecution: (id: string, reason?: string) =>
    apiFetch<ExecutionResult>(`/executions/${id}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),

  // Governed Active Security Testing Framework
  getActiveCapabilities: () => apiFetch<any[]>('/active-testing/capabilities'),
  requestActiveApproval: (data: { programId: string; assetId: string; capabilityId: string; target?: string }) =>
    apiFetch<any>('/active-testing/approvals/request', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  confirmActiveApproval: (approvalId: string) =>
    apiFetch<any>('/active-testing/approvals/confirm', {
      method: 'POST',
      body: JSON.stringify({ approvalId }),
    }),
  executeActiveCapability: (data: {
    caseId: string;
    capabilityId: string;
    assetId: string;
    target?: string;
    approvalId?: string;
    confirmApproval?: boolean;
    parameters?: Record<string, string | number | boolean>;
  }) =>
    apiFetch<any>('/active-testing/execute', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  getActiveExecutions: (filters?: { caseId?: string; programId?: string; status?: string }) => {
    const params = new URLSearchParams(filters || {}).toString();
    const query = params ? `?${params}` : '';
    return apiFetch<any[]>(`/active-testing/executions${query}`);
  },
  getActiveExecutionById: (id: string) => apiFetch<any>(`/active-testing/executions/${id}`),
  cancelActiveExecution: (id: string, reason?: string) =>
    apiFetch<any>(`/active-testing/executions/${id}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),

  // Internal Security Program Ops (authenticated via same client)
  securityProgram: {
    getStatus: () => apiFetch<any>('/security-program/status'),
    getDashboard: () => apiFetch<any>('/security-program/dashboard'),
    listReports: (params?: Record<string, string | number | undefined>) => {
      const q = new URLSearchParams();
      if (params) {
        for (const [k, v] of Object.entries(params)) {
          if (v !== undefined && v !== null && String(v) !== '') q.set(k, String(v));
        }
      }
      const qs = q.toString();
      return apiFetch<any>(`/security-program/reports${qs ? `?${qs}` : ''}`);
    },
    listAudits: (params?: Record<string, string | number | undefined>) => {
      const q = new URLSearchParams();
      if (params) {
        for (const [k, v] of Object.entries(params)) {
          if (v !== undefined && v !== null && String(v) !== '') q.set(k, String(v));
        }
      }
      const qs = q.toString();
      return apiFetch<any>(`/security-program/audits${qs ? `?${qs}` : ''}`);
    },
    getReport: (id: string) => apiFetch<any>(`/security-program/reports/${id}`),
    scopeCheck: (asset: string) =>
      apiFetch<any>('/security-program/scope-check', {
        method: 'POST',
        body: JSON.stringify({ asset }),
      }),
    processReport: (body: Record<string, unknown>) =>
      apiFetch<any>('/security-program/reports/process', {
        method: 'POST',
        body: JSON.stringify(body),
      }),
    /** ADMIN-only on server; helper does not elevate privileges */
    disclosureTransition: (id: string, targetState: string) =>
      apiFetch<any>(`/security-program/reports/${encodeURIComponent(id)}/disclosure-transition`, {
        method: 'POST',
        body: JSON.stringify({ targetState }),
      }),
    getDisclosureTransitions: (id: string) =>
      apiFetch<any>(`/security-program/reports/${encodeURIComponent(id)}/disclosure-transitions`),
  },
};

