import { logger } from '../utils/logger.ts';

export interface AppConfig {
  env: string;
  isProduction: boolean;
  port: number;
  db: {
    host?: string;
    user?: string;
    password?: string;
    database?: string;
  };
  allowedOrigins: string[];
  firebaseProjectId?: string;
}

export function validateStartupConfig(): AppConfig {
  const env = process.env.NODE_ENV || 'development';
  const isProduction = env === 'production';
  const port = 3000;

  const sqlHost = process.env.SQL_HOST;
  const sqlUser = process.env.SQL_USER;
  const sqlPassword = process.env.SQL_PASSWORD;
  const sqlDbName = process.env.SQL_DB_NAME;

  const missingDbVars: string[] = [];
  if (!sqlHost) missingDbVars.push('SQL_HOST');
  if (!sqlUser) missingDbVars.push('SQL_USER');
  if (!sqlPassword) missingDbVars.push('SQL_PASSWORD');
  if (!sqlDbName) missingDbVars.push('SQL_DB_NAME');

  if (missingDbVars.length > 0) {
    logger.warn('STARTUP_CONFIG_WARNING', {
      message: 'Missing database configuration variables; falling back to local/mock defaults',
      missingVars: missingDbVars,
    });
  }

  const rawOrigins = process.env.ALLOWED_ORIGINS || '';
  const allowedOrigins = rawOrigins
    ? rawOrigins.split(',').map((o) => o.trim()).filter(Boolean)
    : [];

  return {
    env,
    isProduction,
    port,
    db: {
      host: sqlHost,
      user: sqlUser,
      password: sqlPassword,
      database: sqlDbName,
    },
    allowedOrigins,
    firebaseProjectId: process.env.FIREBASE_PROJECT_ID,
  };
}
