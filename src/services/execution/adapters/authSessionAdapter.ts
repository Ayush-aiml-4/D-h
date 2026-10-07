import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const authSessionAdapter: ExecutionAdapter = {
  capabilityId: 'cap-jwt-structure-inspection',
  aliases: [
    'JWT_STRUCTURE_INSPECTION',
    'cap-oauth-flow-mapping',
    'cap-session-timeout-indicator',
    'jwt-structure',
    'oauth-flow-mapping',
    'session-timeout-indicator',
  ],
  name: 'Authentication & Session Architecture Adapter',
  description: 'Inspects token structures, OAuth redirect endpoints, and session lifetime attributes without authentication bypass',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-auth-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const targetPath = (context.parameters?.path as string) || '/';

    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const rawHeaders = response.headers || {};
    const normalizedHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(rawHeaders)) {
      normalizedHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }

    const setCookie = normalizedHeaders['set-cookie'] || null;
    const authHeader = normalizedHeaders['www-authenticate'] || null;

    // Check token claims if token provided in parameters
    let tokenDetails: any = null;
    const inputToken = (context.parameters?.token as string) || null;
    if (inputToken && typeof inputToken === 'string' && inputToken.includes('.')) {
      try {
        const parts = inputToken.split('.');
        if (parts.length === 3) {
          const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
          tokenDetails = {
            algorithm: header.alg || 'unknown',
            type: header.typ || 'JWT',
            hasExpiration: Boolean(payload.exp),
            issuer: payload.iss || null,
            subject: payload.sub ? 'REDACTED_USER_ID' : null,
            isNoneAlgorithm: header.alg?.toLowerCase() === 'none',
          };
        }
      } catch {
        // Invalid JWT format
      }
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      hasSetCookie: Boolean(setCookie),
      authChallenge: authHeader,
      tokenDetails,
      sessionSecurity: {
        hasExplicitSameSite: setCookie ? setCookie.toLowerCase().includes('samesite') : false,
        hasHttpOnly: setCookie ? setCookie.toLowerCase().includes('httponly') : false,
        hasSecure: setCookie ? setCookie.toLowerCase().includes('secure') : false,
      },
      assessment: tokenDetails?.isNoneAlgorithm ? 'CRITICAL_NONE_ALGORITHM' : 'STANDARD_AUTH_CONFIG',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${response.statusCode}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'AUTH_SESSION_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
