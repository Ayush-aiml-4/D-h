/**
 * In-memory durable repository for security-program ops.
 * Aligns with passiveResearch/persistenceStore pattern when SQL is unavailable.
 * Does not store raw secrets; evidence refs expected pre-redacted.
 */

import { createDefaultProgramConfig, type ProgramConfig } from './configModel.js';
import type { SecurityReport, AuditEvent } from './reportIntake.js';
import type { ChangeAuditEntry } from './livingUpdate.js';
import type { ScopeDecision } from './scopeEngine.js';
import { applyMeeshoHackerOneEvidence } from './meeshoHackerOneEvidence.js';
import { applyFullMeeshoScopeExport } from './meeshoFullScopeExport.js';

export interface StoredScopeDecision {
  id: string;
  reportId?: string;
  decision: ScopeDecision;
  createdAt: string;
}

export interface SecurityProgramStore {
  config: ProgramConfig;
  reports: Map<string, SecurityReport>;
  scopeDecisions: StoredScopeDecision[];
  configChanges: ChangeAuditEntry[];
  globalAudits: AuditEvent[];
}

function createStore(): SecurityProgramStore {
  return {
    config: createDefaultProgramConfig(),
    reports: new Map(),
    scopeDecisions: [],
    configChanges: [],
    globalAudits: [],
  };
}

let store: SecurityProgramStore = createStore();

export function getSecurityProgramStore(): SecurityProgramStore {
  return store;
}

export function resetSecurityProgramStoreForTests(): void {
  store = createStore();
}

export function getProgramConfig(): ProgramConfig {
  return store.config;
}

export function setProgramConfig(cfg: ProgramConfig): void {
  store.config = cfg;
}

export function saveReport(report: SecurityReport): SecurityReport {
  store.reports.set(report.report_id, report);
  return report;
}

export function getReport(id: string): SecurityReport | undefined {
  return store.reports.get(id);
}

export function listReports(): SecurityReport[] {
  return Array.from(store.reports.values());
}

export function saveScopeDecision(d: StoredScopeDecision): void {
  store.scopeDecisions.push(d);
}

export function listScopeDecisions(): StoredScopeDecision[] {
  return [...store.scopeDecisions];
}

export function appendConfigChange(entry: ChangeAuditEntry): void {
  store.configChanges.push(entry);
}

export function listConfigChanges(): ChangeAuditEntry[] {
  return [...store.configChanges];
}

export function appendGlobalAudit(event: AuditEvent): void {
  store.globalAudits.push(event);
}

export function listGlobalAudits(): AuditEvent[] {
  return [...store.globalAudits];
}


export interface ReportQuery {
  page?: number;
  pageSize?: number;
  validity?: string;
  severity?: string;
  scopeResult?: string;
  disclosureStatus?: string;
  remediationStatus?: string;
}

export interface AuditQuery {
  page?: number;
  pageSize?: number;
  action?: string;
  reportId?: string;
}

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 100;

function normalizePage(page?: number): number {
  const p = Number(page);
  if (!Number.isFinite(p) || p < 1) return 1;
  return Math.floor(p);
}

function normalizePageSize(size?: number): number {
  const s = Number(size);
  if (!Number.isFinite(s) || s < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(MAX_PAGE_SIZE, Math.floor(s));
}

export function queryReports(q: ReportQuery = {}): {
  items: SecurityReport[];
  total: number;
  page: number;
  pageSize: number;
} {
  let items = listReports();
  if (q.validity) items = items.filter((r) => r.validity === q.validity);
  if (q.severity) items = items.filter((r) => (r.severity || '') === q.severity);
  if (q.scopeResult) items = items.filter((r) => r.scope_result === q.scopeResult);
  if (q.disclosureStatus) items = items.filter((r) => r.disclosure_status === q.disclosureStatus);
  if (q.remediationStatus) items = items.filter((r) => r.remediation_status === q.remediationStatus);
  const total = items.length;
  const pageSize = normalizePageSize(q.pageSize);
  const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
  let page = normalizePage(q.page);
  if (page > maxPage) page = maxPage;
  const start = (page - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), total, page, pageSize };
}

export function queryAudits(q: AuditQuery = {}): {
  items: AuditEvent[];
  total: number;
  page: number;
  pageSize: number;
} {
  let items = listGlobalAudits();
  if (q.action) items = items.filter((e) => e.action === q.action);
  if (q.reportId) {
    items = items.filter((e) => (e.detail || '').includes(q.reportId!));
  }
  const total = items.length;
  const pageSize = normalizePageSize(q.pageSize);
  const maxPage = Math.max(1, Math.ceil(total / pageSize) || 1);
  let page = normalizePage(q.page);
  if (page > maxPage) page = maxPage;
  const start = (page - 1) * pageSize;
  // newest-first for audits: reverse then page
  const ordered = [...items].reverse();
  return { items: ordered.slice(start, start + pageSize), total, page, pageSize };
}


/** Apply HackerOne page evidence into living config (does not invent assets). */
export function applyProgramEvidenceFromHackerOne(): { applied: boolean; changeCount: number } {
  const { config, changes } = applyMeeshoHackerOneEvidence(getProgramConfig());
  setProgramConfig(config);
  for (const c of changes) {
    appendConfigChange({
      change_id: `ev-${Date.now()}-${c.field}`,
      timestamp: new Date().toISOString(),
      changed_field: c.field,
      previous_value: c.previous,
      new_value: c.next,
      source: String(c.source),
      reason: String(c.classification),
      affected_rules: ['living_config'],
      launch_impact: c.field.startsWith('Q') ? 'recalculate' : 'none',
      review_status: 'recorded',
    });
  }
  return { applied: true, changeCount: changes.length };
}

/** Apply full operator-supplied HackerOne In-Scope export (replaces Q4 with exact list). */
export function applyFullScopeExportFromOperator(): { applied: boolean; assetCount: number } {
  const config = applyFullMeeshoScopeExport(getProgramConfig());
  setProgramConfig(config);
  appendConfigChange({
    change_id: `ev-scope-export-${Date.now()}`,
    timestamp: new Date().toISOString(),
    changed_field: 'Q4_authorizedAssets',
    previous_value: 'partial_or_prior',
    new_value: config.Q4_authorizedAssets.map((a) => a.value),
    source: 'Operator HackerOne scope export',
    reason: 'CONFIRMED_FULL_REGISTER',
    affected_rules: ['scope_allowlist'],
    launch_impact: 'recalculate',
    review_status: 'recorded',
  });
  return { applied: true, assetCount: config.Q4_authorizedAssets.length };
}
