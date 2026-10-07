import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const crossOriginPoliciesAdapter: ExecutionAdapter = {
  capabilityId: 'cap-cross-origin-policies',
  aliases: [
    'CROSS_ORIGIN_POLICIES',
    'cross-origin-isolation',
    'coop-coep-corp-audit',
  ],
  name: 'Cross-Origin Isolation Policies Adapter',
  description: 'Audits COOP, COEP, and CORP response headers for process isolation and Spectre mitigation',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-coop-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
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

    const coop = normalizedHeaders['cross-origin-opener-policy'] || null;
    const coep = normalizedHeaders['cross-origin-embedder-policy'] || null;
    const corp = normalizedHeaders['cross-origin-resource-policy'] || null;

    const isCrossoriginIsolated = coop === 'same-origin' && (coep === 'require-corp' || coep === 'credentialless');

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      coop,
      coep,
      corp,
      isCrossoriginIsolated,
      assessment: isCrossoriginIsolated ? 'ISOLATED' : 'STANDARD_OPEN',
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
      observationType: 'CROSS_ORIGIN_POLICIES_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
