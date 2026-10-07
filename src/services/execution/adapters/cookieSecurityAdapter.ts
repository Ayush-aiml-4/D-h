import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const cookieSecurityAdapter: ExecutionAdapter = {
  capabilityId: 'cap-cookie-security-audit',
  aliases: [
    'COOKIE_SECURITY_ANALYSIS',
    'capability.cookie-security-audit',
    'cookie-security',
    'cookie-flags',
  ],
  name: 'Cookie Security Flags Analysis Adapter',
  description: 'Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite protection flags with automatic secret value redaction',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-cookie-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const targetPath = (context.parameters?.path as string) || '/';
    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const rawHeaders = response.headers || {};
    let setCookieHeaders: string[] = [];

    for (const [k, v] of Object.entries(rawHeaders)) {
      if (k.toLowerCase() === 'set-cookie') {
        setCookieHeaders = Array.isArray(v) ? v : [String(v)];
        break;
      }
    }

    const cookieAnalysis: Record<string, any>[] = [];
    const missingFlagsSummary: { cookieName: string; missing: string[] }[] = [];

    for (const rawCookie of setCookieHeaders) {
      const parts = rawCookie.split(';').map((p) => p.trim());
      const firstPart = parts[0] || '';
      const equalsIdx = firstPart.indexOf('=');
      const cookieName = equalsIdx > -1 ? firstPart.substring(0, equalsIdx) : firstPart;

      const isSecure = parts.some((p) => p.toLowerCase() === 'secure');
      const isHttpOnly = parts.some((p) => p.toLowerCase() === 'httponly');
      const sameSitePart = parts.find((p) => p.toLowerCase().startsWith('samesite='));
      const sameSiteVal = sameSitePart ? sameSitePart.split('=')[1] : null;

      const pathPart = parts.find((p) => p.toLowerCase().startsWith('path='));
      const pathVal = pathPart ? pathPart.split('=')[1] : '/';

      const domainPart = parts.find((p) => p.toLowerCase().startsWith('domain='));
      const domainVal = domainPart ? domainPart.split('=')[1] : null;

      const missing: string[] = [];
      if (!isSecure) missing.push('Secure');
      if (!isHttpOnly) missing.push('HttpOnly');
      if (!sameSiteVal) missing.push('SameSite');

      if (missing.length > 0) {
        missingFlagsSummary.push({ cookieName, missing });
      }

      cookieAnalysis.push({
        cookieName,
        redactedValue: '[REDACTED]',
        isSecure,
        isHttpOnly,
        sameSite: sameSiteVal || 'Not Set',
        path: pathVal,
        domain: domainVal,
        missingFlags: missing,
      });
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      statusCode: response.statusCode,
      cookiesAnalyzedCount: setCookieHeaders.length,
      cookieDetails: cookieAnalysis,
      insecureCookiesCount: missingFlagsSummary.length,
      allCookiesSecure: setCookieHeaders.length > 0 && missingFlagsSummary.length === 0,
      hasSetCookieHeader: setCookieHeaders.length > 0,
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${setCookieHeaders.length}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'COOKIE_SECURITY_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
