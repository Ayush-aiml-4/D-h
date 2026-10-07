import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const mimeSniffingAdapter: ExecutionAdapter = {
  capabilityId: 'cap-mime-sniffing-analysis',
  aliases: [
    'MIME_SNIFFING_ANALYSIS',
    'mime-sniffing-analysis',
    'content-type-protection',
  ],
  name: 'MIME Sniffing & Content-Type Protection Adapter',
  description: 'Audits X-Content-Type-Options nosniff enforcement and verifies Content-Type declaration integrity',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-mime-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
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

    const contentType = normalizedHeaders['content-type'] || null;
    const xContentTypeOptions = normalizedHeaders['x-content-type-options'] || null;
    const hasNosniff = xContentTypeOptions?.toLowerCase().includes('nosniff') || false;

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      contentType,
      xContentTypeOptions,
      hasNosniff,
      assessment: hasNosniff ? 'PROTECTED' : 'MISSING_NOSNIFF',
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
      observationType: 'MIME_SNIFFING_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
