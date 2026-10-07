import { BOUNTY_STATUS_DEFERRED, BOUNTY_STATUS_CONFIGURED_PAID } from './configModel.js';
import { calculateLaunchReadiness } from './launchReadiness.js';
import {
  getProgramConfig,
  listReports,
  listScopeDecisions,
  listConfigChanges,
  listGlobalAudits,
} from './repository.js';

export function buildDashboardSnapshot() {
  const config = getProgramConfig();
  const launch = calculateLaunchReadiness(config);
  const reports = listReports();

  const validityDist: Record<string, number> = {};
  const severityDist: Record<string, number> = {};
  const scopeDist: Record<string, number> = {};
  let duplicates = 0;
  let systemic = 0;
  let pendingSpecial = 0;
  let remediation: Record<string, number> = {};
  let disclosure: Record<string, number> = {};

  for (const r of reports) {
    validityDist[r.validity] = (validityDist[r.validity] || 0) + 1;
    severityDist[r.severity || 'unset'] = (severityDist[r.severity || 'unset'] || 0) + 1;
    scopeDist[r.scope_result] = (scopeDist[r.scope_result] || 0) + 1;
    if (r.duplicate_status === 'EXACT_DUPLICATE') duplicates += 1;
    if (r.systemic_status !== 'none') systemic += 1;
    if (r.scope_result === 'PENDING_SPECIAL_AUTH') pendingSpecial += 1;
    remediation[r.remediation_status] = (remediation[r.remediation_status] || 0) + 1;
    disclosure[r.disclosure_status] = (disclosure[r.disclosure_status] || 0) + 1;
  }

  return {
    programStatus: launch.status === 'READY' ? 'launch_ready' : 'draft',
    launchReadiness: launch.status,
    blockers: launch.blockers,
    reports: {
      open: reports.filter((r) => r.disclosure_status !== 'closed').length,
      total: reports.length,
      validityDistribution: validityDist,
      severityDistribution: severityDist,
    },
    scope: {
      decisions: listScopeDecisions().length,
      distribution: scopeDist,
      pendingSpecialAuthorization: pendingSpecial,
    },
    triage: {
      duplicates,
      systemicFindings: systemic,
    },
    remediation,
    disclosure,
    bounty: {
      status:
        config.Q30_rewardModel === 'A_PAID'
          ? BOUNTY_STATUS_CONFIGURED_PAID
          : config.Q30_rewardModel === 'B_VDP'
            ? 'VDP — RECOGNITION_ONLY'
            : config.Q30_rewardModel === 'C_SELECTED'
              ? 'ELIGIBILITY_REVIEW — AMOUNTS NOT CONFIGURED'
              : BOUNTY_STATUS_DEFERRED,
      model: config.Q30_rewardModel,
    },
    configurationChanges: listConfigChanges().slice(-20),
    auditEvents: listGlobalAudits().slice(-50),
    q4AssetCount: config.Q4_authorizedAssets.length,
  };
}
