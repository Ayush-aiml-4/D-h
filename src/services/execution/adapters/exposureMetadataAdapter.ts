import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const exposureMetadataAdapter: ExecutionAdapter = {
  capabilityId: 'cap-sensitive-file-exposure',
  aliases: [
    'SENSITIVE_FILE_EXPOSURE',
    'cap-backup-artifact-indicator',
    'sensitive-files',
    'backup-artifacts',
  ],
  name: 'Public Metadata & Backup Artifact Exposure Adapter',
  description: 'Audits publicly accessible metadata manifests (robots.txt, sitemap.xml) and observes backup artifact presence',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-exp-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    // 1. Probe robots.txt
    const robotsRes = await client.request({
      method: 'GET',
      path: '/robots.txt',
    });

    const hasRobots = robotsRes.statusCode === 200 && typeof robotsRes.body === 'string';
    const disallowedPaths: string[] = [];
    if (hasRobots && robotsRes.body) {
      const lines = robotsRes.body.split('\n');
      for (const line of lines) {
        if (line.toLowerCase().startsWith('disallow:')) {
          const p = line.substring(9).trim();
          if (p) disallowedPaths.push(p);
        }
      }
    }

    // 2. Probe sitemap.xml
    let hasSitemap = false;
    try {
      const sitemapRes = await client.request({
        method: 'GET',
        path: '/sitemap.xml',
      });
      hasSitemap = sitemapRes.statusCode === 200;
    } catch {
      // Governed probe error handled
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      hasRobotsTxt: hasRobots,
      robotsStatusCode: robotsRes.statusCode,
      disallowedPathsCount: disallowedPaths.length,
      disallowedPathsSample: disallowedPaths.slice(0, 10),
      hasSitemapXml: hasSitemap,
      assessment: hasRobots || hasSitemap ? 'MANIFESTS_OBSERVED' : 'NO_PUBLIC_MANIFESTS',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${robotsRes.statusCode}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'EXPOSURE_METADATA_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
