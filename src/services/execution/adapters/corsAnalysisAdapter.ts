import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const corsAnalysisAdapter: ExecutionAdapter = {
  capabilityId: 'cap-cors-policy-audit',
  aliases: [
    'CORS_MISCONFIGURATION',
    'capability.cors-policy-audit',
    'cors-audit',
    'cors-analysis',
  ],
  name: 'CORS Policy Misconfiguration Adapter',
  description: 'Analyzes Cross-Origin Resource Sharing policy by sending controlled origin probes',
  authorizationLevel: 'LOW_RISK',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-cors-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const probeOrigin = 'https://evil-untrusted-test.com';
    const targetPath = (context.parameters?.path as string) || '/';

    const response = await client.request({
      method: 'GET',
      path: targetPath,
      headers: {
        'Origin': probeOrigin,
      },
    });

    const rawHeaders = response.headers || {};
    const getHeader = (name: string): string => {
      for (const [k, v] of Object.entries(rawHeaders)) {
        if (k.toLowerCase() === name.toLowerCase()) {
          return Array.isArray(v) ? v[0] : String(v);
        }
      }
      return '';
    };

    const allowOrigin = getHeader('access-control-allow-origin');
    const allowCredentials = getHeader('access-control-allow-credentials').toLowerCase() === 'true';
    const allowMethods = getHeader('access-control-allow-methods');
    const allowHeaders = getHeader('access-control-allow-headers');
    const exposeHeaders = getHeader('access-control-expose-headers');

    let isMisconfigured = false;
    let issueType = '';

    if (allowOrigin === '*' && allowCredentials) {
      isMisconfigured = true;
      issueType = 'wildcard-origin-with-credentials';
    } else if (allowOrigin === probeOrigin && allowCredentials) {
      isMisconfigured = true;
      issueType = 'arbitrary-reflected-origin-with-credentials';
    } else if (allowOrigin === 'null' && allowCredentials) {
      isMisconfigured = true;
      issueType = 'null-origin-with-credentials';
    } else if (allowOrigin === '*' && !allowCredentials) {
      issueType = 'permissive-wildcard-no-credentials';
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      statusCode: response.statusCode,
      probeOrigin,
      allowOrigin: allowOrigin || null,
      allowCredentials,
      allowMethods: allowMethods || null,
      allowHeaders: allowHeaders || null,
      exposeHeaders: exposeHeaders || null,
      isMisconfigured,
      issueType: issueType || 'none',
      hasCorsHeaders: Boolean(allowOrigin),
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${allowOrigin}:${allowCredentials}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'CORS_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
