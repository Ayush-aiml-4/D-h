import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const hstsAuditAdapter: ExecutionAdapter = {
  capabilityId: 'cap-hsts-audit',
  aliases: [
    'HSTS_ANALYSIS',
    'capability.hsts-audit',
    'hsts-audit',
    'cap-tls-ssl-audit',
    'strict-transport-security',
  ],
  name: 'HSTS & Transport Security Audit Adapter',
  description: 'Audits Strict-Transport-Security implementation to ensure HTTPS enforcement and downgrade mitigation',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-hsts-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const targetPath = (context.parameters?.path as string) || '/';
    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const rawHeaders = response.headers || {};
    let hstsHeader = '';

    for (const [k, v] of Object.entries(rawHeaders)) {
      if (k.toLowerCase() === 'strict-transport-security') {
        hstsHeader = Array.isArray(v) ? v.join('; ') : String(v);
        break;
      }
    }

    let maxAge = 0;
    let includeSubDomains = false;
    let preload = false;

    if (hstsHeader) {
      const matchAge = hstsHeader.match(/max-age=(\d+)/i);
      if (matchAge) maxAge = parseInt(matchAge[1], 10);
      includeSubDomains = /includeSubDomains/i.test(hstsHeader);
      preload = /preload/i.test(hstsHeader);
    }

    const ONE_YEAR_SECONDS = 31536000;
    const SIX_MONTHS_SECONDS = 15768000;

    const isOneYearPlus = maxAge >= ONE_YEAR_SECONDS;
    const isAdequate = Boolean(hstsHeader) && maxAge >= SIX_MONTHS_SECONDS;

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      statusCode: response.statusCode,
      hasHsts: Boolean(hstsHeader),
      rawHsts: hstsHeader || null,
      maxAgeSeconds: maxAge,
      includeSubDomains,
      preload,
      isOneYearPlus,
      isAdequate,
      status: !hstsHeader ? 'MISSING' : !isAdequate ? 'INADEQUATE_DURATION' : 'STRONG',
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${maxAge}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'HSTS_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
