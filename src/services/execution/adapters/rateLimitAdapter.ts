import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const rateLimitAdapter: ExecutionAdapter = {
  capabilityId: 'cap-rate-limit-inspection',
  aliases: [
    'RATE_LIMIT_INSPECTION',
    'rate-limit-inspection',
    'rate-limiting-audit',
  ],
  name: 'Rate Limiting Policy Header Inspection Adapter',
  description: 'Audits rate limit quota response headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After) without load testing',
  authorizationLevel: 'REQUIRES_APPROVAL',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-ratelimit-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
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

    const rateLimit = normalizedHeaders['x-ratelimit-limit'] || normalizedHeaders['ratelimit-limit'] || null;
    const rateRemaining = normalizedHeaders['x-ratelimit-remaining'] || normalizedHeaders['ratelimit-remaining'] || null;
    const rateReset = normalizedHeaders['x-ratelimit-reset'] || normalizedHeaders['ratelimit-reset'] || null;
    const retryAfter = normalizedHeaders['retry-after'] || null;

    const hasRateLimitingHeaders = Boolean(rateLimit || rateRemaining || retryAfter);

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      hasRateLimitingHeaders,
      rateLimitQuota: rateLimit,
      rateLimitRemaining: rateRemaining,
      rateLimitReset: rateReset,
      retryAfterHeader: retryAfter,
      assessment: hasRateLimitingHeaders ? 'RATE_LIMITING_ENFORCED' : 'NO_EXPLICIT_RATE_LIMIT_HEADERS',
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
      observationType: 'RATE_LIMIT_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
