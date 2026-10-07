import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const sourcemapValidator: ControlledValidator = {
  validationId: 'val-sourcemap-exposure',
  supportedCapability: 'cap-sourcemap-exposure',
  aliases: ['SOURCE_MAP_VALIDATION', 'SOURCE_MAP_EXPOSURE'],
  validationType: 'SOURCE_MAP_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'SOURCEMAP_VALIDATION_EVIDENCE',
  description: 'Validates JavaScript source map accessibility by parsing source map JSON structures (version, sources, mappings)',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || {};
    const status = rawObs.status || rawObs.statusCode || 200;
    const body = rawObs.body || finding.evidence?.responseBodySnippet || '';

    let isSourceMapJson = false;
    let sourcesCount = 0;

    if (status === 200) {
      try {
        const parsed = typeof body === 'string' ? JSON.parse(body) : body;
        if (parsed && typeof parsed === 'object' && (parsed.version === 3 || parsed.mappings) && Array.isArray(parsed.sources)) {
          isSourceMapJson = true;
          sourcesCount = parsed.sources.length;
        }
      } catch {
        if (body.includes('"version":3') && body.includes('"sources":[')) {
          isSourceMapJson = true;
        }
      }
    }

    const isValidated = isSourceMapJson;
    const confidence = isValidated ? 95 : 10;
    const resultStatus: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: resultStatus,
      confidence,
      summary: isValidated
        ? `Confirmed valid v3 JavaScript source map file exposing ${sourcesCount || 'multiple'} original source paths`
        : 'Source map file is inaccessible (404) or contains invalid JSON structure.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        path: rawObs.path || '/main.js.map',
        statusCode: status,
        isSourceMapJson,
        sourcesCount,
        validationMethod: 'CONTROLLED_SOURCEMAP_VERIFICATION',
      },
    };
  },
};
