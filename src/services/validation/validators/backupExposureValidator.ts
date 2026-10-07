import { ControlledValidator, ValidationContext, ValidationResultStatus } from '../types.ts';

export const backupExposureValidator: ControlledValidator = {
  validationId: 'val-backup-exposure',
  supportedCapability: 'cap-backup-exposure',
  aliases: ['BACKUP_EXPOSURE_VALIDATION', 'BACKUP_CONFIGURATION_FILE_EXPOSURE'],
  validationType: 'BACKUP_EXPOSURE_VALIDATION',
  safetyLevel: 'NON_DESTRUCTIVE',
  requiredPolicy: 'POLICY_CHECK_REQUIRED',
  evidenceType: 'BACKUP_EXPOSURE_VALIDATION_EVIDENCE',
  description: 'Validates exposed backup/configuration files (.env, .bak, config.json) based on HTTP status and content patterns',

  async validate(context: ValidationContext) {
    const { finding, observationData } = context;
    const rawObs = observationData || {};
    const status = rawObs.status || rawObs.statusCode || 200;
    const body = rawObs.body || finding.evidence?.responseBodySnippet || '';

    const backupSignatures = ['DB_PASSWORD=', 'DATABASE_URL=', 'AWS_SECRET_ACCESS_KEY=', '["config"]', '<?php', 'MIME-Version:'];

    const matched = backupSignatures.filter((sig) => body.includes(sig));
    const isValidated = status === 200 && (matched.length > 0 || rawObs.path === '/.env');
    const confidence = isValidated ? 95 : 10;
    const resultStatus: ValidationResultStatus = isValidated ? 'VALIDATED' : 'UNVALIDATED';

    return {
      result: resultStatus,
      confidence,
      summary: isValidated
        ? `Confirmed accessible sensitive backup file (HTTP ${status}): matched signatures ${matched.join(', ') || 'environment variables'}`
        : 'Backup/configuration file path returned 404/403 or non-sensitive content.',
      sanitizedObservation: {
        evaluatedTarget: context.asset.hostname || context.asset.domain || context.finding.target,
        path: rawObs.path || '/.env',
        statusCode: status,
        matchedSignatures: matched,
        validationMethod: 'CONTROLLED_BACKUP_FILE_VERIFICATION',
      },
    };
  },
};
