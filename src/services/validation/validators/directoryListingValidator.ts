import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const directoryListingValidator: ControlledValidator = {
  validationId: 'val-directory-listing',
  supportedCapability: 'cap-directory-listing',
  aliases: ['DIRECTORY_LISTING_VALIDATION', 'DIRECTORY_LISTING_DETECTION'],
  validationType: 'DIRECTORY_LISTING_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'DIRECTORY_LISTING_VALIDATION_EVIDENCE',
  description: 'Validates presence of directory indexing indicators (Index of /) in directory responses',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || {};
    const body = rawObs.body || finding.evidence?.responseBodySnippet || '';

    const indexingIndicators = [
      'Index of /',
      'Directory Listing for',
      'Parent Directory',
      '[To Parent Directory]',
      '<h1>Directory: /',
    ];

    const matched = indexingIndicators.filter((ind) => body.includes(ind));
    const isValidated = matched.length > 0;
    const confidence = isValidated ? 95 : 10;
    const status: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: status,
      confidence,
      summary: isValidated
        ? `Confirmed web server directory indexing is active: matched "${matched[0]}"`
        : 'Directory indexing is disabled or returns 403 Forbidden.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        matchedIndicators: matched,
        validationMethod: 'CONTROLLED_DIRECTORY_LISTING_VERIFICATION',
      },
    };
  },
};
