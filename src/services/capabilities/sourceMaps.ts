import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const sourceMapAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-source-map-exposure',
  aliases: ['SOURCE_MAP_EXPOSURE', 'JavaScript Source Map Exposure Detection'],
  name: 'JavaScript Source Map Exposure Detection',
  description: 'Detects accessible JavaScript source maps (.js.map) revealing original source code',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const body = observationData.body || '';
    const path = (observationData.path || '').toLowerCase();
    const statusCode = observationData.status || observationData.statusCode || 200;

    const hasMapExtension = path.endsWith('.js.map') || path.endsWith('.ts.map');
    const isMapContent = /"version"\s*:\s*3,[\s\S]*?"sources"\s*:\s*\[/i.test(body);
    const hasSourceMappingComment = /\/\/#\s*sourceMappingURL=[\w\.-]+\.map/i.test(body);

    const isExposed = statusCode === 200 && (hasMapExtension || isMapContent);

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      path: observationData.path || '/',
      statusCode,
      hasSourceMapExposure: isExposed,
      hasSourceMappingComment,
    };

    const evidence = createSanitizedEvidence(
      'cap-source-map-exposure',
      asset.id,
      'SOURCE_MAP_EXPOSURE',
      observation,
      95
    );

    const findingCandidates = [];

    if (isExposed) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-source-map-exposure',
          issueIdentifier: 'exposed-javascript-source-map',
          title: 'Exposed JavaScript Source Map File',
          category: 'Information Disclosure',
          severity: 'Low',
          confidence: 95,
          whatWeFound: `Publicly readable JavaScript source map file detected at path '${observationData.path}'.`,
          whyItMatters: 'Source maps allow reverse-engineering of uncompiled frontend source code, developer comments, and hidden endpoint logic.',
          affectedTarget: `${asset.hostname || 'target'}${observationData.path}`,
          recommendedFix: 'Restrict access to .map files in production or omit source map generation in build outputs.',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-source-map-exposure',
      capabilityName: 'JavaScript Source Map Exposure Detection',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'Source map exposure analysis completed successfully',
    };
  },
};
