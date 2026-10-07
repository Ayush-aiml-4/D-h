import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const cloudInfrastructureAdapter: ExecutionAdapter = {
  capabilityId: 'cap-cloud-provider-indicator',
  aliases: [
    'CLOUD_PROVIDER_INDICATOR',
    'cap-load-balancer-indicator',
    'cloud-infrastructure-indicator',
    'load-balancer-indicator',
  ],
  name: 'Cloud Provider & Edge Infrastructure Indicator Adapter',
  description: 'Audits public response headers and links to identify cloud provider topology and load balancer routing headers without probing internal metadata',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-cld-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
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

    const via = normalizedHeaders['via'] || null;
    const xForwardedFor = normalizedHeaders['x-forwarded-for'] || null;
    const xCloudTrace = normalizedHeaders['x-cloud-trace-context'] || null;
    const xAmznTrace = normalizedHeaders['x-amzn-trace-id'] || null;

    let cloudHost: string | null = null;
    if (xCloudTrace) cloudHost = 'Google Cloud Platform (GCP)';
    else if (xAmznTrace) cloudHost = 'Amazon Web Services (AWS)';
    else if (via?.toLowerCase().includes('azure')) cloudHost = 'Microsoft Azure';

    const body = typeof response.body === 'string' ? response.body : '';
    const hasS3Links = body.includes('.s3.amazonaws.com') || body.includes('.s3.');
    const hasGcsLinks = body.includes('storage.googleapis.com');
    const hasAzureBlobLinks = body.includes('.blob.core.windows.net');

    const detectedBuckets: string[] = [];
    if (hasS3Links) detectedBuckets.push('AWS_S3');
    if (hasGcsLinks) detectedBuckets.push('GOOGLE_CLOUD_STORAGE');
    if (hasAzureBlobLinks) detectedBuckets.push('AZURE_BLOB_STORAGE');

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      statusCode: response.statusCode,
      detectedCloudHost: cloudHost,
      routingHeaders: {
        via,
        xForwardedFor,
        hasAmznTrace: Boolean(xAmznTrace),
        hasGcpTrace: Boolean(xCloudTrace),
      },
      detectedObjectStorageTiers: detectedBuckets,
      metadataProbingAttempted: false, // Explicit: NEVER probe cloud metadata 169.254.169.254
      assessment: cloudHost ? 'CLOUD_INFRASTRUCTURE_IDENTIFIED' : 'ON_PREM_OR_GENERIC_HOST',
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
      observationType: 'CLOUD_INFRASTRUCTURE_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
