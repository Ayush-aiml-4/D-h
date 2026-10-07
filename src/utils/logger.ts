export interface LogPayload {
  requestId?: string;
  event?: string;
  route?: string;
  method?: string;
  status?: number;
  durationMs?: number;
  actorId?: string;
  reason?: string;
  resourceType?: string;
  resourceId?: string;
  programId?: string;
  actionCategory?: string;
  error?: string;
  [key: string]: any;
}

const SECRET_PATTERNS = [
  /bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*/gi,
  /eyJ[a-zA-Z0-9\-_=]+\.eyJ[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+/g, // JWT pattern
  /postgres:\/\/[^@]+@/gi, // DB URL credentials
  /password=["']?[^"'\s]+["']?/gi,
  /apiKey=["']?[^"'\s]+["']?/gi,
];

const SENSITIVE_KEYS = new Set([
  'authorization',
  'token',
  'password',
  'sql_password',
  'sql_user',
  'database_url',
  'gemini_api_key',
  'api_key',
  'apikey',
  'secret',
  'firebase_token',
  'cookie',
  'set-cookie',
]);

export function redactSecrets(data: any): any {
  if (data === null || data === undefined) return data;

  if (typeof data === 'string') {
    let sanitized = data;
    for (const pattern of SECRET_PATTERNS) {
      sanitized = sanitized.replace(pattern, '[REDACTED_SECRET]');
    }
    return sanitized;
  }

  if (typeof data === 'number' || typeof data === 'boolean') {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => redactSecrets(item));
  }

  if (typeof data === 'object') {
    const redacted: Record<string, any> = {};
    for (const [key, value] of Object.entries(data)) {
      if (SENSITIVE_KEYS.has(key.toLowerCase())) {
        redacted[key] = '[REDACTED]';
      } else {
        redacted[key] = redactSecrets(value);
      }
    }
    return redacted;
  }

  return '[REDACTED]';
}

export const logger = {
  log: (level: 'INFO' | 'WARN' | 'ERROR' | 'SECURITY', event: string, payload: LogPayload = {}) => {
    const sanitizedPayload = redactSecrets(payload);
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      event,
      requestId: sanitizedPayload.requestId || 'no-request-id',
      ...sanitizedPayload,
    };
    const jsonOutput = JSON.stringify(entry);

    if (level === 'ERROR') {
      console.error(jsonOutput);
    } else if (level === 'WARN' || level === 'SECURITY') {
      console.warn(jsonOutput);
    } else {
      console.log(jsonOutput);
    }
  },

  info: (event: string, payload?: LogPayload) => logger.log('INFO', event, payload),
  warn: (event: string, payload?: LogPayload) => logger.log('WARN', event, payload),
  error: (event: string, payload?: LogPayload) => logger.log('ERROR', event, payload),
  security: (event: string, payload?: LogPayload) => logger.log('SECURITY', event, payload),
};
