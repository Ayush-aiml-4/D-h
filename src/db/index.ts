import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import * as schema from './schema.ts';
import { logger } from '../utils/logger.ts';

const { Pool } = pg;

declare global {
  var _postgresPool: pg.Pool | undefined;
  var _inMemoryTables: Map<string, any[]> | undefined;
  var _inMemoryUserSeq: number | undefined;
}

export const isPostgresConfigured = (): boolean => {
  const required = ['SQL_HOST', 'SQL_USER', 'SQL_PASSWORD', 'SQL_DB_NAME'];
  return required.every((key) => Boolean(process.env[key] && process.env[key]?.trim()));
};

export const validateDbConfig = () => {
  const required = ['SQL_HOST', 'SQL_USER', 'SQL_PASSWORD', 'SQL_DB_NAME'];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    logger.warn('DB_CONFIG_MISSING', {
      missingVars: missing,
      message: 'Missing PostgreSQL configuration variables; using in-memory database fallback',
    });
  }
};

export const createPool = (): pg.Pool => {
  if (!global._postgresPool) {
    validateDbConfig();
    global._postgresPool = new Pool({
      host: process.env.SQL_HOST || '127.0.0.1',
      user: process.env.SQL_USER || 'postgres',
      password: process.env.SQL_PASSWORD || '',
      database: process.env.SQL_DB_NAME || 'postgres',
      max: 10,
      connectionTimeoutMillis: 2000,
      idleTimeoutMillis: 30000,
      statement_timeout: 10000,
    });

    global._postgresPool.on('error', (err) => {
      logger.error('DB_POOL_IDLE_ERROR', {
        error: err instanceof Error ? err.message : String(err),
      });
    });
  }
  return global._postgresPool;
};

let postgresHealthy = false;

export const verifyDatabaseConnection = async (): Promise<boolean> => {
  if (!isPostgresConfigured()) {
    postgresHealthy = false;
    return false;
  }
  try {
    const currentPool = createPool();
    const client = await currentPool.connect();
    try {
      await client.query('SELECT 1 as health_check;');
      postgresHealthy = true;
      return true;
    } finally {
      client.release();
    }
  } catch (err) {
    postgresHealthy = false;
    logger.error('DB_CONNECTIVITY_FAILED', {
      error: err instanceof Error ? err.message : String(err),
    });
    return false;
  }
};

export const getPoolStats = () => {
  if (!isPostgresConfigured() || !global._postgresPool) {
    return { total: 1, idle: 1, waiting: 0 };
  }
  const poolInstance = global._postgresPool;
  return {
    total: poolInstance.totalCount,
    idle: poolInstance.idleCount,
    waiting: poolInstance.waitingCount,
  };
};

export const closeDatabasePool = async (): Promise<void> => {
  if (global._postgresPool) {
    logger.info('DB_POOL_CLOSING', { message: 'Closing database connection pool gracefully...' });
    await global._postgresPool.end();
    global._postgresPool = undefined;
  }
};

// ============================================================================
// In-Memory Drizzle-Compatible Fallback Store (used when Cloud SQL is offline)
// ============================================================================

function getInMemoryStore(): Map<string, any[]> {
  if (!global._inMemoryTables) {
    global._inMemoryTables = new Map<string, any[]>();
  }
  return global._inMemoryTables;
}

function getTableName(table: any): string {
  if (!table || typeof table !== 'object') return 'unknown';
  const symName = table[Symbol.for('drizzle:Name')] || table[Symbol.for('drizzle:BaseName')];
  if (typeof symName === 'string') return symName;
  return table._?.name || 'unknown';
}

function getTableRows(table: any): any[] {
  const store = getInMemoryStore();
  const name = getTableName(table);
  if (!store.has(name)) {
    store.set(name, []);
  }
  return store.get(name)!;
}

function getColumnKeyMap(table: any): Map<string, string> {
  const map = new Map<string, string>();
  if (!table || typeof table !== 'object') return map;
  for (const [propKey, col] of Object.entries(table)) {
    if (col && typeof col === 'object' && 'name' in col && typeof (col as any).name === 'string') {
      map.set((col as any).name, propKey);
      map.set(propKey, propKey);
    }
  }
  return map;
}

function isStringChunk(chunk: any): boolean {
  return Boolean(chunk && typeof chunk === 'object' && Array.isArray(chunk.value) && !('queryChunks' in chunk) && !('name' in chunk));
}

function isColumnChunk(chunk: any): boolean {
  return Boolean(chunk && typeof chunk === 'object' && typeof chunk.name === 'string' && ('table' in chunk || 'columnType' in chunk));
}

function isParamChunk(chunk: any): boolean {
  return Boolean(chunk && typeof chunk === 'object' && 'value' in chunk && 'encoder' in chunk);
}

function isSqlChunk(chunk: any): boolean {
  return Boolean(chunk && typeof chunk === 'object' && Array.isArray(chunk.queryChunks));
}

function extractParamValues(chunk: any): any[] {
  if (isParamChunk(chunk)) {
    return Array.isArray(chunk.value) ? chunk.value : [chunk.value];
  }
  if (Array.isArray(chunk)) {
    return chunk.flatMap(extractParamValues);
  }
  if (isSqlChunk(chunk)) {
    return chunk.queryChunks.flatMap(extractParamValues);
  }
  if (isStringChunk(chunk) || isColumnChunk(chunk)) {
    return [];
  }
  return [chunk];
}

function evaluateSqlCondition(row: Record<string, any>, colMap: Map<string, string>, sqlObj: any): boolean {
  if (!sqlObj || typeof sqlObj !== 'object') return true;
  if (!Array.isArray(sqlObj.queryChunks)) return true;

  const chunks = sqlObj.queryChunks;
  const subSqls = chunks.filter(isSqlChunk);
  const stringParts = chunks
    .filter(isStringChunk)
    .map((c: any) => c.value.join(''))
    .join('');
  const trimmedStrings = stringParts.replace(/[()\s]/g, '');

  // Unwrap single parenthesized SQL expression
  if (subSqls.length === 1 && trimmedStrings === '') {
    return evaluateSqlCondition(row, colMap, subSqls[0]);
  }

  // Handle AND / OR combinators
  const lowerStrings = stringParts.toLowerCase();
  if (subSqls.length > 1 && lowerStrings.includes(' and ')) {
    return subSqls.every((sub: any) => evaluateSqlCondition(row, colMap, sub));
  }
  if (subSqls.length > 1 && lowerStrings.includes(' or ')) {
    return subSqls.some((sub: any) => evaluateSqlCondition(row, colMap, sub));
  }

  // Leaf comparison
  const colChunk = chunks.find(isColumnChunk);
  if (!colChunk) {
    if (subSqls.length > 0) {
      return subSqls.every((sub: any) => evaluateSqlCondition(row, colMap, sub));
    }
    return true;
  }

  const propKey = colMap.get(colChunk.name) || colChunk.name;
  const rowVal = row[propKey];
  const nonColChunks = chunks.filter((c: any) => c !== colChunk && !isStringChunk(c));
  const paramVals = nonColChunks.flatMap(extractParamValues);

  if (lowerStrings.includes(' in ')) {
    return paramVals.includes(rowVal);
  }
  if (lowerStrings.includes('>=')) {
    return rowVal >= paramVals[0];
  }
  if (lowerStrings.includes('<=')) {
    return rowVal <= paramVals[0];
  }
  if (lowerStrings.includes('!=') || lowerStrings.includes('<>')) {
    return rowVal !== paramVals[0];
  }
  if (lowerStrings.includes('=')) {
    return rowVal === paramVals[0];
  }

  return true;
}

function applyRowDefaults(tableName: string, raw: Record<string, any>): Record<string, any> {
  const now = new Date();
  const row: Record<string, any> = { ...raw };

  if (tableName === 'users') {
    if (row.id === undefined) {
      global._inMemoryUserSeq = (global._inMemoryUserSeq || 0) + 1;
      row.id = global._inMemoryUserSeq;
    }
    if (row.role === undefined) row.role = 'RESEARCHER';
    if (row.avatar === undefined) row.avatar = null;
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'programs') {
    if (row.status === undefined) row.status = 'ACTIVE';
    if (row.rulesLoaded === undefined) row.rulesLoaded = true;
    if (row.policyEnforced === undefined) row.policyEnforced = true;
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'assets') {
    if (row.status === undefined) row.status = 'IN_SCOPE';
    if (row.scopeStatus === undefined) row.scopeStatus = 'In Scope';
    if (row.endpointCount === undefined) row.endpointCount = 1;
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'program_scopes') {
    if (row.scopeType === undefined) row.scopeType = 'EXACT_DOMAIN';
    if (row.scopeStatus === undefined) row.scopeStatus = 'IN_SCOPE';
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'discovery_sessions') {
    if (row.operation === undefined) row.operation = 'ASSET_ENUMERATION';
    if (row.status === undefined) row.status = 'READY';
    if (row.startedAt === undefined) row.startedAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'policy_rules') {
    if (row.allowed === undefined) row.allowed = true;
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'hunts') {
    if (row.status === undefined) row.status = 'Ready';
    if (row.progress === undefined) row.progress = 0;
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'findings') {
    if (row.confidence === undefined) row.confidence = 90;
    if (row.status === undefined) row.status = 'Potential';
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'reports') {
    if (row.status === undefined) row.status = 'Draft';
    if (row.createdAt === undefined) row.createdAt = now;
    if (row.updatedAt === undefined) row.updatedAt = now;
  } else if (tableName === 'rewards') {
    if (row.amount === undefined) row.amount = '₹0';
    if (row.numericAmount === undefined) row.numericAmount = 0;
    if (row.currency === undefined) row.currency = 'INR';
    if (row.status === undefined) row.status = 'NONE';
    if (row.createdAt === undefined) row.createdAt = now;
  } else if (tableName === 'history_sessions') {
    if (row.verifiedFindingCount === undefined) row.verifiedFindingCount = 0;
    if (row.rewardAmount === undefined) row.rewardAmount = '₹0';
    if (row.status === undefined) row.status = 'Completed';
    if (row.createdAt === undefined) row.createdAt = now;
  } else if (tableName === 'audit_events') {
    if (row.success === undefined) row.success = true;
    if (row.createdAt === undefined) row.createdAt = now;
  }

  return row;
}

function createInMemoryDb() {
  const memDb: any = {
    select: () => ({
      from: (table: any) => {
        const colMap = getColumnKeyMap(table);
        let whereCond: any = null;
        let orderArg: any = null;
        let limitCount: number | null = null;

        const execute = async () => {
          const rows = getTableRows(table);
          let results = whereCond
            ? rows.filter((r) => evaluateSqlCondition(r, colMap, whereCond))
            : [...rows];

          if (orderArg) {
            let colChunk: any = null;
            let isDesc = false;
            if (isColumnChunk(orderArg)) {
              colChunk = orderArg;
            } else if (isSqlChunk(orderArg)) {
              colChunk = orderArg.queryChunks.find(isColumnChunk);
              const str = orderArg.queryChunks
                .filter(isStringChunk)
                .map((c: any) => c.value.join(''))
                .join('')
                .toLowerCase();
              isDesc = str.includes('desc');
            }
            if (colChunk) {
              const propKey = colMap.get(colChunk.name) || colChunk.name;
              results.sort((a, b) => {
                const va = a[propKey];
                const vb = b[propKey];
                const ta = va instanceof Date ? va.getTime() : va;
                const tb = vb instanceof Date ? vb.getTime() : vb;
                if (ta < tb) return isDesc ? 1 : -1;
                if (ta > tb) return isDesc ? -1 : 1;
                return 0;
              });
            }
          }

          if (limitCount !== null) {
            results = results.slice(0, limitCount);
          }

          return results.map((r) => ({ ...r }));
        };

        const builder: any = {
          where: (cond: any) => {
            whereCond = cond;
            return builder;
          },
          orderBy: (ord: any) => {
            orderArg = ord;
            return builder;
          },
          limit: (n: number) => {
            limitCount = n;
            return builder;
          },
          for: () => builder,
          then: (onfulfilled?: any, onrejected?: any) => execute().then(onfulfilled, onrejected),
          catch: (onrejected?: any) => execute().catch(onrejected),
        };

        return builder;
      },
    }),

    insert: (table: any) => ({
      values: (valOrArray: any) => {
        let executedPromise: Promise<any[]> | null = null;
        const execute = async () => {
          const tableName = getTableName(table);
          const rows = getTableRows(table);
          const items = Array.isArray(valOrArray) ? valOrArray : [valOrArray];
          const inserted: any[] = [];

          for (const item of items) {
            const row = applyRowDefaults(tableName, item);
            const existingIdx = row.id !== undefined ? rows.findIndex((r) => r.id === row.id) : -1;
            if (existingIdx >= 0) {
              rows[existingIdx] = { ...rows[existingIdx], ...row };
              inserted.push({ ...rows[existingIdx] });
            } else {
              rows.push(row);
              inserted.push({ ...row });
            }
          }
          return inserted;
        };

        const getPromise = () => {
          if (!executedPromise) executedPromise = execute();
          return executedPromise;
        };

        const builder: any = {
          returning: () => builder,
          then: (onfulfilled?: any, onrejected?: any) => getPromise().then(onfulfilled, onrejected),
          catch: (onrejected?: any) => getPromise().catch(onrejected),
        };
        return builder;
      },
    }),

    update: (table: any) => ({
      set: (updates: Record<string, any>) => {
        const colMap = getColumnKeyMap(table);
        let whereCond: any = null;
        let executedPromise: Promise<any[]> | null = null;

        const execute = async () => {
          const rows = getTableRows(table);
          const updated: any[] = [];
          for (let i = 0; i < rows.length; i++) {
            if (!whereCond || evaluateSqlCondition(rows[i], colMap, whereCond)) {
              rows[i] = { ...rows[i], ...updates };
              updated.push({ ...rows[i] });
            }
          }
          return updated;
        };

        const getPromise = () => {
          if (!executedPromise) executedPromise = execute();
          return executedPromise;
        };

        const builder: any = {
          where: (cond: any) => {
            whereCond = cond;
            return builder;
          },
          returning: () => builder,
          then: (onfulfilled?: any, onrejected?: any) => getPromise().then(onfulfilled, onrejected),
          catch: (onrejected?: any) => getPromise().catch(onrejected),
        };
        return builder;
      },
    }),

    delete: (table: any) => {
      const colMap = getColumnKeyMap(table);
      let whereCond: any = null;
      let executedPromise: Promise<any[]> | null = null;

      const execute = async () => {
        const store = getInMemoryStore();
        const name = getTableName(table);
        const rows = getTableRows(table);
        if (!whereCond) {
          store.set(name, []);
          return [];
        }
        const remaining = rows.filter((r) => !evaluateSqlCondition(r, colMap, whereCond));
        store.set(name, remaining);
        return [];
      };

      const getPromise = () => {
        if (!executedPromise) executedPromise = execute();
        return executedPromise;
      };

      const builder: any = {
        where: (cond: any) => {
          whereCond = cond;
          return builder;
        },
        returning: () => builder,
        then: (onfulfilled?: any, onrejected?: any) => getPromise().then(onfulfilled, onrejected),
        catch: (onrejected?: any) => getPromise().catch(onrejected),
      };
      return builder;
    },

    transaction: async (fn: (tx: any) => Promise<any>) => {
      return await fn(memDb);
    },
  };

  return memDb;
}

const inMemoryDb = createInMemoryDb();
let pgDrizzleInstance: ReturnType<typeof drizzle> | null = null;

function getActiveDb(): any {
  if (isPostgresConfigured() && postgresHealthy) {
    if (!pgDrizzleInstance) {
      pgDrizzleInstance = drizzle(createPool(), { schema });
    }
    return pgDrizzleInstance;
  }
  return inMemoryDb;
}

export const db: ReturnType<typeof drizzle> = new Proxy({} as ReturnType<typeof drizzle>, {
  get(_target, prop) {
    const active = getActiveDb();
    const val = active[prop];
    return typeof val === 'function' ? val.bind(active) : val;
  },
});

