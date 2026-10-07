import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const cacheControlAdapter: ExecutionAdapter = {
  capabilityId: 'cap-cache-control-analysis',
  aliases: [
    'CACHE_CONTROL_ANALYSIS',
    'cache-control-analysis',
    'caching-policy-audit',
  ],
  name: 'Cache-Control & Caching Policy Adapter',
  description: 'Audits Cache-Control, Pragma, and Expires headers to evaluate client and intermediary cache privacy',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-cache-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
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

    const cacheControl = normalizedHeaders['cache-control'] || null;
    const pragma = normalizedHeaders['pragma'] || null;
    const expires = normalizedHeaders['expires'] || null;
    const etag = normalizedHeaders['etag'] || null;

    const directives = cacheControl ? cacheControl.split(',').map((s) => s.trim().toLowerCase()) : [];
    const hasNoStore = directives.includes('no-store');
    const hasNoCache = directives.includes('no-cache');
    const hasPrivate = directives.includes('private');
    const hasPublic = directives.includes('public');
    const hasMustRevalidate = directives.includes('must-revalidate');

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      cacheControl,
      pragma,
      expires,
      etag: etag ? 'PRESENT' : null,
      directives,
      hasNoStore,
      hasNoCache,
      hasPrivate,
      hasPublic,
      hasMustRevalidate,
      assessment: hasNoStore ? 'NO_CACHE_PROTECTED' : hasPublic ? 'PUBLICLY_CACHEABLE' : 'STANDARD',
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
      observationType: 'CACHE_CONTROL_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
