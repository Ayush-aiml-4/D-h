import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const sourceMapExposureAdapter: ExecutionAdapter = {
  capabilityId: 'cap-source-map-exposure',
  aliases: [
    'SOURCE_MAP_EXPOSURE',
    'capability.source-map-exposure',
    'source-map-exposure',
    'js-source-maps',
  ],
  name: 'JavaScript Source Map Exposure Adapter',
  description: 'Detects exposed JavaScript source map files revealing uncompiled source code',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-srcmap-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const targetPath = (context.parameters?.path as string) || '/';
    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const body = response.body || '';
    const pathLower = targetPath.toLowerCase();
    const statusCode = response.statusCode;

    const hasMapExtension = pathLower.endsWith('.js.map') || pathLower.endsWith('.ts.map');
    const isMapContent = /"version"\s*:\s*3,[\s\S]*?"sources"\s*:\s*\[/i.test(body);
    const hasSourceMappingComment = /\/\/#\s*sourceMappingURL=[\w\.-]+\.map/i.test(body);

    const isExposed = statusCode === 200 && (hasMapExtension || isMapContent);

    // Extract map filename if present in comment
    let referencedMapFile: string | null = null;
    const mapMatch = body.match(/\/\/#\s*sourceMappingURL=([\w\.-]+\.map)/i);
    if (mapMatch && mapMatch[1]) {
      referencedMapFile = mapMatch[1];
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      path: targetPath,
      statusCode,
      hasSourceMapExposure: isExposed,
      hasSourceMappingComment,
      referencedMapFile,
      isMapContent,
      isClean: !isExposed,
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${isExposed}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'SOURCE_MAP_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
