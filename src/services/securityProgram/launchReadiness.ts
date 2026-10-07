import type { ProgramConfig } from './configModel.js';

export type LaunchStatus = 'READY' | 'BLOCKED';

export interface LaunchReport {
  status: LaunchStatus;
  blockers: string[];
  checks: Record<string, boolean>;
}

export function calculateLaunchReadiness(config: ProgramConfig): LaunchReport {
  const checks: Record<string, boolean> = {
    Q1: !!config.Q1_programName?.trim(),
    Q2: !!config.Q2_legalEntity?.trim(),
    Q3: !!config.Q3_publicDescription?.trim(),
    Q4: config.Q4_authorizedAssets.length >= 1,
    Q4_register_complete: config.Q4_registerStatus === 'COMPLETE',
    Q5: config.Q5_allowlistOnly === true,
    Q6: config.Q6_intentionalThirdPartyInScope !== null,
    Q30:
      config.Q30_rewardModel === 'A_PAID' ||
      config.Q30_rewardModel === 'B_VDP' ||
      config.Q30_rewardModel === 'C_SELECTED',
  };

  const blockers: string[] = [];
  if (!checks.Q1) blockers.push('Q1_programName');
  if (!checks.Q2) blockers.push('Q2_legalEntity');
  if (!checks.Q3) blockers.push('Q3_publicDescription');
  if (!checks.Q4) blockers.push('Q4_authorizedAssets_empty');
  if (config.Q4_authorizedAssets.length > 0 && config.Q4_registerStatus !== 'COMPLETE') {
    blockers.push('Q4_register_incomplete_PARTIAL');
  }
  if (!checks.Q5) blockers.push('Q5_allowlist');
  if (!checks.Q6) blockers.push('Q6_third_party_unresolved');
  if (!checks.Q30) blockers.push('Q30_reward_model');

  // Hard rule
  if (config.Q4_authorizedAssets.length === 0) {
    if (!blockers.includes('Q4_authorizedAssets_empty')) blockers.push('Q4_authorizedAssets_empty');
  }

  return {
    status: blockers.length === 0 ? 'READY' : 'BLOCKED',
    blockers,
    checks,
  };
}
