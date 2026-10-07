/**
 * Drizzle-backed adapter port for Security Program repository.
 * NOT activated by default. Requires explicit backend selection + SQL health.
 * Does not auto-migrate. Does not silently fall back to memory.
 */

import type { ProgramConfig } from './configModel.js';
import type { SecurityReport, AuditEvent } from './reportIntake.js';
import type { ChangeAuditEntry } from './livingUpdate.js';
import type { ScopeDecision } from './scopeEngine.js';

export interface SecurityProgramRepositoryPort {
  getConfig(): Promise<ProgramConfig> | ProgramConfig;
  setConfig(cfg: ProgramConfig): Promise<void> | void;
  saveReport(report: SecurityReport): Promise<SecurityReport> | SecurityReport;
  getReport(id: string): Promise<SecurityReport | undefined> | SecurityReport | undefined;
  listReports(): Promise<SecurityReport[]> | SecurityReport[];
  saveScopeDecision(input: {
    id: string;
    reportId?: string;
    decision: ScopeDecision;
    createdAt: string;
  }): Promise<void> | void;
  listScopeDecisions(): Promise<unknown[]> | unknown[];
  appendConfigChange(entry: ChangeAuditEntry): Promise<void> | void;
  listConfigChanges(): Promise<ChangeAuditEntry[]> | ChangeAuditEntry[];
  appendGlobalAudit(event: AuditEvent): Promise<void> | void;
  listGlobalAudits(): Promise<AuditEvent[]> | AuditEvent[];
}

export class DrizzleUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DrizzleUnavailableError';
  }
}

/**
 * Structural Drizzle repository: methods defined for interface parity.
 * Throws until SQL is healthy and schema migrated (no silent memory use).
 */
export function createDrizzleSecurityProgramRepository(db: unknown): SecurityProgramRepositoryPort {
  if (!db) {
    throw new DrizzleUnavailableError('Drizzle repository requires a database handle');
  }

  const notLive = (): never => {
    throw new DrizzleUnavailableError(
      'Drizzle repository methods are not live: schema not migrated or SQL unverified in this environment'
    );
  };

  return {
    getConfig: async () => notLive(),
    setConfig: async () => notLive(),
    saveReport: async () => notLive(),
    getReport: async () => notLive(),
    listReports: async () => notLive(),
    saveScopeDecision: async () => notLive(),
    listScopeDecisions: async () => notLive(),
    appendConfigChange: async () => notLive(),
    listConfigChanges: async () => notLive(),
    appendGlobalAudit: async () => notLive(),
    listGlobalAudits: async () => notLive(),
  };
}

export function tryCreateDrizzleSecurityProgramRepository(db: unknown): SecurityProgramRepositoryPort | null {
  if (!db) return null;
  try {
    return createDrizzleSecurityProgramRepository(db);
  } catch {
    return null;
  }
}

export const DRIZZLE_ADAPTER_STATUS = {
  implemented: true,
  activated: false,
  migrated: false,
  methodsDefined: true,
  liveQueries: false,
  reason:
    'Repository methods exist for contract parity; live SQL queries disabled until migration + health verification',
};

export const REPOSITORY_PORT_METHODS = [
  'getConfig',
  'setConfig',
  'saveReport',
  'getReport',
  'listReports',
  'saveScopeDecision',
  'listScopeDecisions',
  'appendConfigChange',
  'listConfigChanges',
  'appendGlobalAudit',
  'listGlobalAudits',
] as const;
