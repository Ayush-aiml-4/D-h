import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const techFingerprintAdapter: ExecutionAdapter = {
  capabilityId: 'cap-tech-stack-fingerprint',
  aliases: [
    'TECH_STACK_FINGERPRINT',
    'cap-waf-detection',
    'cap-framework-header-detection',
    'tech-fingerprint',
    'waf-detection',
    'framework-headers',
  ],
  name: 'Technology Stack & Edge Infrastructure Fingerprinting Adapter',
  description: 'Identifies web server software, application frameworks, caching tiers, and CDN/WAF edge defenses from HTTP signatures',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-tech-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
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

    const server = normalizedHeaders['server'] || null;
    const xPoweredBy = normalizedHeaders['x-powered-by'] || null;
    const cfRay = normalizedHeaders['cf-ray'] || null;
    const xAmzCfId = normalizedHeaders['x-amz-cf-id'] || null;
    const xFastly = normalizedHeaders['x-fastly-request-id'] || null;
    const akamai = normalizedHeaders['x-akamai-request-id'] || null;

    let detectedWaf: string | null = null;
    if (cfRay) detectedWaf = 'Cloudflare';
    else if (xAmzCfId) detectedWaf = 'AWS CloudFront';
    else if (xFastly) detectedWaf = 'Fastly';
    else if (akamai) detectedWaf = 'Akamai';

    const detectedTech: string[] = [];
    if (server) detectedTech.push(`Server: ${server}`);
    if (xPoweredBy) detectedTech.push(`Framework: ${xPoweredBy}`);
    if (detectedWaf) detectedTech.push(`CDN/WAF: ${detectedWaf}`);

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      server,
      xPoweredBy,
      detectedWaf,
      detectedTechnologies: detectedTech,
      hasExplicitVersionExposure: Boolean(server?.match(/\d+\.\d+/) || xPoweredBy?.match(/\d+\.\d+/)),
      assessment: detectedTech.length > 0 ? 'FINGERPRINT_IDENTIFIED' : 'MINIMAL_EXPOSURE',
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
      observationType: 'TECH_FINGERPRINT_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
