/**
 * Safe backend selection for security-program persistence.
 * Default: IN_MEMORY. DRIZZLE only when explicitly enabled AND health check passes.
 * Never silently falls back from DRIZZLE to memory.
 */

import type { SecurityProgramRepositoryPort } from './drizzleAdapter.js';
import { tryCreateDrizzleSecurityProgramRepository, createDrizzleSecurityProgramRepository, DRIZZLE_ADAPTER_STATUS } from './drizzleAdapter.js';
import {
  getProgramConfig,
  setProgramConfig,
  saveReport,
  getReport,
  listReports,
  saveScopeDecision,
  listScopeDecisions,
  appendConfigChange,
  listConfigChanges,
  appendGlobalAudit,
  listGlobalAudits,
} from './repository.js';
import type { ProgramConfig } from './configModel.js';
import type { SecurityReport, AuditEvent } from './reportIntake.js';
import type { ChangeAuditEntry } from './livingUpdate.js';
import type { ScopeDecision } from './scopeEngine.js';

export type PersistenceBackendMode = 'IN_MEMORY' | 'DRIZZLE';

export interface BackendSelectionResult {
  mode: PersistenceBackendMode;
  repository: SecurityProgramRepositoryPort;
  error?: string;
}

const memoryPort: SecurityProgramRepositoryPort = {
  getConfig: () => getProgramConfig(),
  setConfig: (cfg: ProgramConfig) => setProgramConfig(cfg),
  saveReport: (r: SecurityReport) => saveReport(r),
  getReport: (id: string) => getReport(id),
  listReports: () => listReports(),
  saveScopeDecision: (input) => saveScopeDecision(input),
  listScopeDecisions: () => listScopeDecisions(),
  appendConfigChange: (e: ChangeAuditEntry) => appendConfigChange(e),
  listConfigChanges: () => listConfigChanges(),
  appendGlobalAudit: (e: AuditEvent) => appendGlobalAudit(e),
  listGlobalAudits: () => listGlobalAudits(),
};

/**
 * Resolve active repository.
 * Env:
 *   SECURITY_PROGRAM_PERSISTENCE=IN_MEMORY|DRIZZLE (default IN_MEMORY)
 * If DRIZZLE requested but unhealthy → throw / return error (no silent memory fallback).
 */
export function resolveSecurityProgramBackend(options?: {
  mode?: PersistenceBackendMode;
  db?: unknown;
  sqlHealthy?: boolean;
}): BackendSelectionResult {
  const envMode = (process.env.SECURITY_PROGRAM_PERSISTENCE || 'IN_MEMORY').toUpperCase();
  const mode: PersistenceBackendMode =
    options?.mode || (envMode === 'DRIZZLE' ? 'DRIZZLE' : 'IN_MEMORY');

  if (mode === 'IN_MEMORY') {
    return { mode: 'IN_MEMORY', repository: memoryPort };
  }

  // DRIZZLE path
  const healthy = options?.sqlHealthy === true;
  if (!healthy) {
    return {
      mode: 'DRIZZLE',
      repository: memoryPort, // not used when error set
      error:
        'SECURITY_PROGRAM_PERSISTENCE=DRIZZLE but SQL backend is not healthy/migrated. Refusing silent fallback to memory.',
    };
  }

  const adapter = tryCreateDrizzleSecurityProgramRepository(options?.db);
  if (!adapter) {
    return {
      mode: 'DRIZZLE',
      repository: memoryPort,
      error:
        'DRIZZLE mode requested but adapter could not be constructed. Refusing silent fallback to memory.',
    };
  }

  return { mode: 'DRIZZLE', repository: adapter };
}

export function getAdapterStatus() {
  return { ...DRIZZLE_ADAPTER_STATUS, defaultMode: 'IN_MEMORY' as const };
}
