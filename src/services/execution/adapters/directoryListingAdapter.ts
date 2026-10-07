import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const directoryListingAdapter: ExecutionAdapter = {
  capabilityId: 'cap-directory-listing',
  aliases: [
    'DIRECTORY_LISTING_DETECTION',
    'cap-directory-listing-detection',
    'capability.directory-listing',
    'directory-listing',
    'directory-indexing',
  ],
  name: 'Directory Listing & Indexing Detection Adapter',
  description: 'Detects exposed directory indexes and server file listings',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-dir-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const targetPath = (context.parameters?.path as string) || '/';
    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const body = response.body || '';

    const dirListingSignatures = [
      /<title>Index of \/[^<]*<\/title>/i,
      /<h1>Index of \/[^<]*<\/h1>/i,
      /<a href="[^"]*">Parent Directory<\/a>/i,
      /\[To Parent Directory\]/i,
      /<table[^>]*>[\s\S]*?Name[\s\S]*?Last modified[\s\S]*?Size/i,
      /<pre><a href="\.\.\/">\.\.\/<\/a>/i,
    ];

    const matchesListing = dirListingSignatures.some((sig) => sig.test(body));

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      path: targetPath,
      statusCode: response.statusCode,
      hasDirectoryListing: matchesListing,
      bodySnippetMatched: matchesListing,
      bodyLength: body.length,
      isClean: !matchesListing,
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${matchesListing}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'DIRECTORY_LISTING_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
