import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const redirectChainAdapter: ExecutionAdapter = {
  capabilityId: 'cap-redirect-chain-analysis',
  aliases: [
    'REDIRECT_CHAIN_ANALYSIS',
    'http-redirect-chain',
    'cap-open-redirect-eval',
  ],
  name: 'HTTP Redirect Chain Analysis Adapter',
  description: 'Observes HTTP redirect status codes, hop sequence, protocol upgrades/downgrades, and target location headers',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-redir-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const targetPath = (context.parameters?.path as string) || '/';

    const response = await client.request({
      method: 'GET',
      path: targetPath,
      followRedirects: false,
    });

    const rawHeaders = response.headers || {};
    const normalizedHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(rawHeaders)) {
      normalizedHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }

    const locationHeader = normalizedHeaders['location'] || null;
    const isRedirect = [301, 302, 303, 307, 308].includes(response.statusCode);

    let isProtocolDowngrade = false;
    let isExternalDomain = false;
    let redirectHost: string | null = null;

    if (locationHeader) {
      try {
        if (locationHeader.startsWith('http://') || locationHeader.startsWith('https://')) {
          const parsed = new URL(locationHeader);
          redirectHost = parsed.hostname;
          if (parsed.protocol === 'http:' && response.url.startsWith('https:')) {
            isProtocolDowngrade = true;
          }
          if (parsed.hostname.toLowerCase() !== client.getHostname().toLowerCase()) {
            isExternalDomain = true;
          }
        }
      } catch {
        // Relative location or custom protocol
      }
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      isRedirect,
      locationHeader,
      redirectHost,
      isProtocolDowngrade,
      isExternalDomain,
      assessment: isProtocolDowngrade ? 'SECURITY_RISK' : isExternalDomain ? 'CROSS_DOMAIN_REDIRECT' : 'NORMAL',
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
      observationType: 'REDIRECT_CHAIN_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
