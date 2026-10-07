import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const debugDisclosureAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-debug-error-disclosure',
  aliases: ['DEBUG_ERROR_DISCLOSURE', 'Debug & Verbose Error Disclosure Analysis'],
  name: 'Debug & Verbose Error Disclosure Analysis',
  description: 'Detects stack traces, framework debug dashboards, and verbose exception disclosures',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const body = observationData.body || '';
    const headers = JSON.stringify(observationData.headers || {});

    const debugIndicators = [
      { pattern: /Traceback \(most recent call last\):/i, type: 'Python Stack Trace' },
      { pattern: /at\s+[\w\$.]+\((?:[a-zA-Z]:\\|\/).*:\d+:\d+\)/i, type: 'Node.js / V8 Stack Trace' },
      { pattern: /Fatal error:.*in\s+[\/\w\.-]+\.php\s+on\s+line\s+\d+/i, type: 'PHP Fatal Error' },
      { pattern: /org\.springframework\.|java\.lang\.[a-zA-Z]+Exception/i, type: 'Java Exception Trace' },
      { pattern: /Django\s+[\d\.]+\s+DEBUG\s+page/i, type: 'Django Debug Page' },
      { pattern: /Laravel\s+Ignition\s+Error|Whoops!\s+There\s+was\s+an\s+error/i, type: 'Laravel Ignition Page' },
      { pattern: /PG::Error|SQLite3::Exception|SQLSTATE\[\d+\]/i, type: 'Database Exception' },
    ];

    const detectedTypes: string[] = [];
    for (const ind of debugIndicators) {
      if (ind.pattern.test(body) || ind.pattern.test(headers)) {
        detectedTypes.push(ind.type);
      }
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      path: observationData.path || '/',
      statusCode: observationData.status || observationData.statusCode || 200,
      hasDebugDisclosure: detectedTypes.length > 0,
      detectedDisclosureTypes: detectedTypes,
    };

    const evidence = createSanitizedEvidence(
      'cap-debug-error-disclosure',
      asset.id,
      'DEBUG_ERROR_DISCLOSURE',
      observation,
      95
    );

    const findingCandidates = [];

    if (detectedTypes.length > 0) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-debug-error-disclosure',
          issueIdentifier: 'verbose-debug-disclosure',
          title: 'Verbose Debug Information & Stack Trace Disclosure',
          category: 'Information Disclosure',
          severity: 'Medium',
          confidence: 90,
          whatWeFound: `Response contains verbose debug traces: ${detectedTypes.join(', ')}.`,
          whyItMatters: 'Stack traces and framework debug pages expose internal filesystem paths, code logic, dependencies, and environment variables.',
          affectedTarget: `${asset.hostname || 'target'}${observationData.path || '/'}`,
          recommendedFix: 'Disable framework debug modes in production and configure generic error handling pages.',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-debug-error-disclosure',
      capabilityName: 'Debug & Verbose Error Disclosure Analysis',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'Debug disclosure analysis completed successfully',
    };
  },
};
