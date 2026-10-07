import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import * as schema from './schema.ts';
import { logger } from '../utils/logger.ts';

const { Pool } = pg;

declare global {
  var _postgresPool: pg.Pool | undefined;
}

/**
 * Connection Pool Safety Configuration:
 * - max: 10 (Sized safely for Cloud Run container execution avoiding DB connection exhaustion)
 * - connectionTimeoutMillis: 10000 (10s max wait time for an available client)
 * - idleTimeoutMillis: 30000 (30s before reaping idle connections)
 * - statement_timeout: 10000 (10s max query execution time to prevent hanging database locks)
 */
export const validateDbConfig = () => {
  const required = ['SQL_HOST', 'SQL_USER', 'SQL_PASSWORD', 'SQL_DB_NAME'];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    logger.warn('DB_CONFIG_MISSING', {
      missingVars: missing,
      message: 'Missing PostgreSQL configuration variables',
    });
  }
};

export const createPool = (): pg.Pool => {
  if (!global._postgresPool) {
    validateDbConfig();
    global._postgresPool = new Pool({
      host: process.env.SQL_HOST,
      user: process.env.SQL_USER,
      password: process.env.SQL_PASSWORD,
      database: process.env.SQL_DB_NAME,
      max: 10,
      connectionTimeoutMillis: 10000,
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

export const verifyDatabaseConnection = async (): Promise<boolean> => {
  try {
    const currentPool = createPool();
    const client = await currentPool.connect();
    try {
      await client.query('SELECT 1 as health_check;');
      return true;
    } finally {
      client.release();
    }
  } catch (err) {
    logger.error('DB_CONNECTIVITY_FAILED', {
      error: err instanceof Error ? err.message : String(err),
    });
    return false;
  }
};

export const getPoolStats = () => {
  const poolInstance = global._postgresPool || createPool();
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

const pool = createPool();
export const db = drizzle(pool, { schema });
