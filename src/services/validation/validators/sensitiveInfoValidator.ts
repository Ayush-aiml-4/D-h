import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const sensitiveInfoValidator: ControlledValidator = {
  validationId: 'val-sensitive-info-disclosure',
  supportedCapability: 'cap-sensitive-info-disclosure',
  aliases: ['SENSITIVE_INFORMATION_VALIDATION', 'SENSITIVE_INFORMATION_EXPOSURE'],
  validationType: 'SENSITIVE_INFORMATION_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'SENSITIVE_INFO_VALIDATION_EVIDENCE',
  description: 'Validates unencrypted PII, internal IP addresses, or sensitive credentials in API JSON responses',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || {};
    const body = rawObs.body || finding.evidence?.responseBodySnippet || '';

    const piiPatterns = [
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, // Email
      /\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b/g, // SSN
      /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g, // Internal IP
    ];

    let matchCount = 0;
    for (const pat of piiPatterns) {
      const matches = body.match(pat);
      if (matches) matchCount += matches.length;
    }

    const isValidated = matchCount > 0;
    const confidence = isValidated ? 90 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed ${matchCount} sensitive PII or internal IP pattern disclosure(s) in API response`
        : 'API response contains clean sanitized data without exposed internal metadata or PII.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        matchCount,
        validationMethod: 'CONTROLLED_SENSITIVE_INFO_VERIFICATION',
      },
    };
  },
};
