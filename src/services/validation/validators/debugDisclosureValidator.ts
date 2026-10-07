import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const debugDisclosureValidator: ControlledValidator = {
  validationId: 'val-debug-disclosure',
  supportedCapability: 'cap-debug-disclosure',
  aliases: ['DEBUG_DISCLOSURE_VALIDATION', 'DEBUG_ERROR_DISCLOSURE'],
  validationType: 'DEBUG_DISCLOSURE_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'DEBUG_DISCLOSURE_VALIDATION_EVIDENCE',
  description: 'Validates presence of stack traces, internal paths, or framework debug signatures in error outputs',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || {};
    const body = rawObs.body || finding.evidence?.responseBodySnippet || '';

    const debugSignatures = [
      'Traceback (most recent call last)',
      'at Module._compile',
      'Exception in thread "main"',
      'Fatal error:',
      'Stack trace:',
      'SyntaxError:',
      'Uncaught Error:',
      '/node_modules/',
      '/usr/local/app/',
      'C:\\Users\\',
    ];

    const matchedSignatures = debugSignatures.filter((sig) => body.includes(sig));
    const isValidated = matchedSignatures.length > 0;
    const confidence = isValidated ? 95 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed stack trace/debug disclosure signatures in response output: ${matchedSignatures.join(', ')}`
        : 'Response output contains standard production error handling without stack trace disclosures.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        matchedSignaturesCount: matchedSignatures.length,
        matchedSignatures,
        validationMethod: 'CONTROLLED_DEBUG_DISCLOSURE_VERIFICATION',
      },
    };
  },
};
