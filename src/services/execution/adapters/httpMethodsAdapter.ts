import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const httpMethodsAdapter: ExecutionAdapter = {
  capabilityId: 'cap-http-methods-analysis',
  aliases: [
    'HTTP_METHODS_ANALYSIS',
    'http-methods-analysis',
    'http-verb-tampering',
    'http-verbs-analysis',
  ],
  name: 'HTTP Method & Verb Analysis Adapter',
  description: 'Observes server support for OPTIONS, HEAD, and standard HTTP methods to assess allowed verbs and method configuration',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-methods-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const targetPath = (context.parameters?.path as string) || '/';

    // 1. Send OPTIONS probe to observe Allow / Access-Control-Allow-Methods headers
    const optionsRes = await client.request({
      method: 'OPTIONS',
      path: targetPath,
    });

    const optionsHeaders = optionsRes.headers || {};
    const normalizedOptionsHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(optionsHeaders)) {
      normalizedOptionsHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }

    const allowHeader = normalizedOptionsHeaders['allow'] || null;
    const corsAllowMethods = normalizedOptionsHeaders['access-control-allow-methods'] || null;

    // 2. Send HEAD probe to test header responsiveness
    const headRes = await client.request({
      method: 'HEAD',
      path: targetPath,
    });

    const rawAllowedMethods = allowHeader ? allowHeader.split(',').map((s) => s.trim().toUpperCase()) : [];
    const corsMethods = corsAllowMethods ? corsAllowMethods.split(',').map((s) => s.trim().toUpperCase()) : [];
    const detectedMethods = Array.from(new Set([...rawAllowedMethods, ...corsMethods]));

    const potentiallyRiskyMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT'];
    const observedRiskyMethods = detectedMethods.filter((m) => potentiallyRiskyMethods.includes(m));

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      path: targetPath,
      optionsStatusCode: optionsRes.statusCode,
      headStatusCode: headRes.statusCode,
      allowHeader,
      corsAllowMethods,
      detectedMethods: detectedMethods.length > 0 ? detectedMethods : ['GET', 'HEAD'],
      observedRiskyMethods,
      hasTraceMethod: detectedMethods.includes('TRACE'),
      assessment: observedRiskyMethods.length > 0 ? 'NEEDS_REVIEW' : 'NORMAL',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${optionsRes.statusCode}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'HTTP_METHODS_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
