import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const webSecurityHeadersAdapter: ExecutionAdapter = {
  capabilityId: 'cap-http-header-analysis',
  aliases: [
    'SECURITY_HEADER_ANALYSIS',
    'capability.http-header-analysis',
    'security-headers',
    'cap-security-headers',
    'http-security-headers',
  ],
  name: 'HTTP Security Header Analysis Adapter',
  description: 'Performs controlled live HTTP response header analysis to verify defense-in-depth security headers',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-hdr-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

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

    const recommendedHeaders = [
      'content-security-policy',
      'strict-transport-security',
      'x-content-type-options',
      'x-frame-options',
      'referrer-policy',
      'permissions-policy',
      'cross-origin-opener-policy',
      'cross-origin-resource-policy',
    ];

    const missingHeaders: string[] = [];
    const presentSecurityHeaders: string[] = [];

    for (const headerName of recommendedHeaders) {
      if (!normalizedHeaders[headerName]) {
        missingHeaders.push(headerName);
      } else {
        presentSecurityHeaders.push(headerName);
      }
    }

    // Header security assessment
    let assessment: 'STRONG' | 'MODERATE' | 'WEAK' = 'STRONG';
    if (missingHeaders.length >= 4) {
      assessment = 'WEAK';
    } else if (missingHeaders.length > 0) {
      assessment = 'MODERATE';
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      statusCode: response.statusCode,
      analyzedHeadersCount: Object.keys(normalizedHeaders).length,
      missingSecurityHeadersCount: missingHeaders.length,
      missingHeaders,
      presentSecurityHeaders,
      assessment,
      serverHeader: normalizedHeaders['server'] || null,
      xPoweredBy: normalizedHeaders['x-powered-by'] || null,
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${response.statusCode}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'SECURITY_HEADER_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
