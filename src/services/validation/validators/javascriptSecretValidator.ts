import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const javascriptSecretValidator: ControlledValidator = {
  validationId: 'val-js-secret-exposure',
  supportedCapability: 'cap-js-secret-exposure',
  aliases: ['JAVASCRIPT_SECRET_VALIDATION', 'JAVASCRIPT_SECRET_EXPOSURE'],
  validationType: 'JAVASCRIPT_SECRET_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'JS_SECRET_VALIDATION_EVIDENCE',
  description: 'Validates hardcoded secret key signatures in client-side JavaScript assets',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || {};
    const body = rawObs.body || finding.evidence?.responseBodySnippet || '';

    const secretPatterns = [
      /(?:AIzaSy|AKIA|ASIA|sq0atp-|sq0csp-|ghp_|gho_|glpat-)[a-zA-Z0-9_\-]{16,}/g,
      /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
      /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    ];

    let matchCount = 0;
    for (const pat of secretPatterns) {
      const matches = body.match(pat);
      if (matches) matchCount += matches.length;
    }

    const isValidated = matchCount > 0;
    const confidence = isValidated ? 95 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed ${matchCount} hardcoded secret signature(s) in client JavaScript asset`
        : 'No unredacted hardcoded secret signatures identified in evaluated JavaScript code.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        matchCount,
        validationMethod: 'CONTROLLED_JS_SECRET_VERIFICATION',
      },
    };
  },
};
