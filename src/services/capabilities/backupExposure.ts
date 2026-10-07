import { CapabilityAnalyzer, CapabilityAnalyzerInput, PassiveAnalysisResult } from './types.ts';
import { createSanitizedEvidence, createFindingCandidate } from './utils.ts';

export const backupExposureAnalyzer: CapabilityAnalyzer = {
  capabilityId: 'cap-backup-file-exposure',
  aliases: ['BACKUP_CONFIGURATION_FILE_EXPOSURE', 'Backup & Config File Exposure Analysis'],
  name: 'Backup & Config File Exposure Analysis',
  description: 'Identifies publicly accessible backup, configuration, or environment files',

  async analyze(input: CapabilityAnalyzerInput): Promise<PassiveAnalysisResult> {
    const { asset, observationData, programId } = input;
    const path = (observationData.path || '').toLowerCase();
    const body = observationData.body || '';
    const statusCode = observationData.status || observationData.statusCode || 200;

    const sensitiveFilePaths = [
      { name: '.env File', ext: '.env', pattern: /DB_PASSWORD|SECRET_KEY|API_KEY|REDIS_URL/i },
      { name: 'Git Config File', ext: '.git/config', pattern: /\[repositoryformatversion\]|\[core\]/i },
      { name: 'Database Configuration', ext: 'config/database.yml', pattern: /adapter:|database:|username:|password:/i },
      { name: 'Backup Archive', ext: '.zip', pattern: /PK\x03\x04|zip archive/i },
      { name: 'Old/Bak File', ext: '.bak', pattern: /<\?php|module\.exports|import /i },
    ];

    let foundFile: { name: string; ext: string } | null = null;

    if (statusCode === 200) {
      for (const item of sensitiveFilePaths) {
        if (path.includes(item.ext) && item.pattern.test(body)) {
          foundFile = item;
          break;
        }
      }
    }

    const observation = {
      target: asset.hostname || asset.domain || 'target',
      path: observationData.path || '/',
      statusCode,
      hasBackupExposure: Boolean(foundFile),
      exposedFileDetails: foundFile,
    };

    const evidence = createSanitizedEvidence(
      'cap-backup-file-exposure',
      asset.id,
      'BACKUP_CONFIGURATION_FILE_EXPOSURE',
      observation,
      95
    );

    const findingCandidates = [];

    if (foundFile) {
      findingCandidates.push(
        createFindingCandidate({
          programId,
          assetId: asset.id,
          capabilityId: 'cap-backup-file-exposure',
          issueIdentifier: `exposed-file-${foundFile.ext}`,
          title: `Exposed ${foundFile.name} File`,
          category: 'Sensitive Data Exposure',
          severity: 'High',
          confidence: 90,
          whatWeFound: `Publicly accessible ${foundFile.name} detected at path '${observationData.path}'.`,
          whyItMatters: 'Exposed configuration and backup files leak passwords, API tokens, source code, or internal architecture details.',
          affectedTarget: `${asset.hostname || 'target'}${observationData.path}`,
          recommendedFix: 'Remove backup/config files from the web root and restrict access via web server rule.',
          evidence,
        })
      );
    }

    return {
      capabilityId: 'cap-backup-file-exposure',
      capabilityName: 'Backup & Config File Exposure Analysis',
      assetId: asset.id,
      observedAt: new Date().toISOString(),
      observations: [observation],
      findingCandidates,
      evidence: [evidence],
      executed: true,
      policyDecision: 'ALLOW',
      reason: 'Backup exposure analysis completed successfully',
    };
  },
};
