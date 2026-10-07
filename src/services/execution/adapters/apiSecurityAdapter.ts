import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const apiSecurityAdapter: ExecutionAdapter = {
  capabilityId: 'cap-api-schema-mapping',
  aliases: [
    'API_SCHEMA_MAPPING',
    'cap-api-error-disclosure',
    'cap-openapi-doc-exposure',
    'cap-parameter-discovery',
    'api-schema-mapping',
    'openapi-exposure',
    'api-error-disclosure',
  ],
  name: 'API Security & Schema Intelligence Adapter',
  description: 'Probes authorized API endpoints to map schema structures, detect error stack trace leakages, and check OpenAPI documentation exposure',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-api-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const targetPath = (context.parameters?.path as string) || '/api/health';

    // 1. Probe API endpoint
    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const rawHeaders = response.headers || {};
    const normalizedHeaders: Record<string, string> = {};
    for (const [k, v] of Object.entries(rawHeaders)) {
      normalizedHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
    }

    const contentType = normalizedHeaders['content-type'] || '';
    const isJson = contentType.includes('application/json');

    // 2. Probe standard OpenAPI path
    let openApiExposed = false;
    let openApiFormat: string | null = null;
    try {
      const openApiRes = await client.request({
        method: 'GET',
        path: '/openapi.json',
      });
      if (openApiRes.statusCode === 200) {
        openApiExposed = true;
        openApiFormat = 'JSON_OPENAPI_SPEC';
      }
    } catch {
      // Governed probe completed
    }

    let parsedBody: any = null;
    let hasStackTrace = false;
    if (response.body) {
      try {
        parsedBody = JSON.parse(response.body);
        if (typeof response.body === 'string' && (response.body.includes('at ') || response.body.includes('Traceback'))) {
          hasStackTrace = true;
        }
      } catch {
        if (typeof response.body === 'string' && (response.body.includes('at ') || response.body.includes('Traceback'))) {
          hasStackTrace = true;
        }
      }
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      contentType,
      isJson,
      openApiExposed,
      openApiFormat,
      hasStackTrace,
      sampleKeys: parsedBody && typeof parsedBody === 'object' ? Object.keys(parsedBody).slice(0, 10) : [],
      assessment: openApiExposed ? 'OPENAPI_EXPOSED' : hasStackTrace ? 'STACK_TRACE_DISCLOSED' : 'CLEAN_API_RESPONSE',
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
      observationType: 'API_SECURITY_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
