import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const directoryListingAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-directory-listing-detection',
  aliases: ['DIRECTORY_LISTING_DETECTION', 'Directory Indexing & Listing Detection'],
  name: 'Directory Indexing & Listing Detection',
  description: 'Identifies exposed directory indexes and directory listing pages',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const body = observationData.body || '';

    const dirListingSignatures = [
      /<title>Index of \/[^<]*<\/title>/i,
      /<h1>Index of \/[^<]*<\/h1>/i,
      /<a href="[^"]*">Parent Directory<\/a>/i,
      /\[To Parent Directory\]/i,
      /<table[^>]*>[\s\S]*?Name[\s\S]*?Last modified[\s\S]*?Size/i,
    ];

    const matchesListing = dirListingSignatures.some((sig) => sig.test(body));

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      path: observationData.path || '/',
      hasDirectoryListing: matchesListing,
      bodySnippetMatched: matchesListing,
    };

    const evidence = createSanitizedEvidence(
      'cap-directory-listing-detection',
      asset.id,
      'DIRECTORY_LISTING_DETECTION',
      observation,
      95
    );

    const findingCandidates = [];

    if (matchesListing) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-directory-listing-detection',
          issueIdentifier: 'exposed-directory-index',
          title: 'Exposed Directory Listing Enabled',
          category: 'Information Disclosure',
          severity: 'Medium',
          confidence: 95,
          whatWeFound: `Exposed directory index detected at path '${observationData.path || '/'}'.`,
          whyItMatters: 'Directory indexing allows attackers to enumerate unlinked files, backup scripts, temporary assets, and configuration files.',
          affectedTarget: `${asset.hostname || 'target'}${observationData.path || '/'}`,
          recommendedFix: "Disable directory indexing in web server configuration (e.g. 'Options -Indexes' in Apache or 'autoindex off;' in NGINX).",
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-directory-listing-detection',
      capabilityName: 'Directory Indexing & Listing Detection',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'Directory listing detection completed successfully',
    };
  },
};
