import type { AllowlistEntry, ProgramConfig, RewardModel } from './configModel.js';
import { calculateLaunchReadiness } from './launchReadiness.js';

export interface ChangeAuditEntry {
  change_id: string;
  timestamp: string;
  changed_field: string;
  previous_value: unknown;
  new_value: unknown;
  source: string;
  reason: string;
  affected_rules: string[];
  launch_impact: string;
  review_status: 'recorded' | 'reviewed';
}

export interface UpdateResult {
  config: ProgramConfig;
  audit: ChangeAuditEntry | null;
  launch: ReturnType<typeof calculateLaunchReadiness>;
  message: string;
  needsClarification?: string;
}

let changeSeq = 0;

function audit(
  field: string,
  prev: unknown,
  next: unknown,
  source: string,
  reason: string,
  affected: string[],
  before: string,
  after: string
): ChangeAuditEntry {
  changeSeq += 1;
  return {
    change_id: `chg_${changeSeq}`,
    timestamp: new Date().toISOString(),
    changed_field: field,
    previous_value: prev,
    new_value: next,
    source,
    reason,
    affected_rules: affected,
    launch_impact: `${before}→${after}`,
    review_status: 'recorded',
  };
}

/**
 * Partial owner input handler — maps natural phrases to Q fields without full questionnaire.
 */
export function on_owner_input(
  config: ProgramConfig,
  message: string,
  source = 'owner'
): UpdateResult {
  const before = calculateLaunchReadiness(config).status;
  const text = message.trim();
  const lower = text.toLowerCase();

  // Q1
  let m = text.match(/^program name is\s+(.+)$/i);
  if (m) {
    const prev = config.Q1_programName;
    config.Q1_programName = m[1].trim();
    const after = calculateLaunchReadiness(config).status;
    return {
      config,
      audit: audit('Q1', prev, config.Q1_programName, source, 'owner_name', ['identity'], before, after),
      launch: calculateLaunchReadiness(config),
      message: 'Updated Q1',
    };
  }

  // Q2
  m = text.match(/^(?:legal )?entity is\s+(.+)$/i);
  if (m) {
    const prev = config.Q2_legalEntity;
    config.Q2_legalEntity = m[1].trim();
    const after = calculateLaunchReadiness(config).status;
    return {
      config,
      audit: audit('Q2', prev, config.Q2_legalEntity, source, 'owner_entity', ['identity'], before, after),
      launch: calculateLaunchReadiness(config),
      message: 'Updated Q2',
    };
  }

  // Q3
  m = text.match(/^description:\s*(.+)$/is);
  if (m) {
    const prev = config.Q3_publicDescription;
    config.Q3_publicDescription = m[1].trim();
    const after = calculateLaunchReadiness(config).status;
    return {
      config,
      audit: audit('Q3', prev, config.Q3_publicDescription, source, 'owner_description', ['identity'], before, after),
      launch: calculateLaunchReadiness(config),
      message: 'Updated Q3',
    };
  }

  // Q30
  if (/\bvdp only\b/i.test(text) || lower === 'q30: b' || /recognition-only/i.test(text)) {
    const prev = config.Q30_rewardModel;
    config.Q30_rewardModel = 'B_VDP';
    const after = calculateLaunchReadiness(config).status;
    return {
      config,
      audit: audit('Q30', prev, config.Q30_rewardModel, source, 'reward_model', ['bounty'], before, after),
      launch: calculateLaunchReadiness(config),
      message: 'Updated Q30 to VDP',
    };
  }
  if (/\bpaid bug bounty\b/i.test(text) || lower === 'q30: a') {
    const prev = config.Q30_rewardModel;
    config.Q30_rewardModel = 'A_PAID' as RewardModel;
    const after = calculateLaunchReadiness(config).status;
    return {
      config,
      audit: audit('Q30', prev, config.Q30_rewardModel, source, 'reward_model', ['bounty'], before, after),
      launch: calculateLaunchReadiness(config),
      message: 'Updated Q30 to paid (amounts still not set)',
    };
  }

  // Q6 none
  if (/no intentional third-party in scope|q6:\s*no\b/i.test(text)) {
    const prev = config.Q6_intentionalThirdPartyInScope;
    config.Q6_intentionalThirdPartyInScope = [];
    const after = calculateLaunchReadiness(config).status;
    return {
      config,
      audit: audit('Q6', prev, [], source, 'third_party_none', ['scope'], before, after),
      launch: calculateLaunchReadiness(config),
      message: 'Q6 resolved: no intentional third-party in scope',
    };
  }

  // Q4 authorized asset — require explicit authorization language
  m = text.match(
    /(?:authorized(?:\s+in-scope)?(?:\s+asset)?|in-scope asset|add allowlist)\s*:\s*(\S+)/i
  );
  if (m) {
    const raw = m[1].replace(/[.,;]+$/, '');
    const prev = [...config.Q4_authorizedAssets];
    const entry: AllowlistEntry = {
      id: `asset_${config.Q4_authorizedAssets.length + 1}`,
      type: raw.includes('*') ? 'wildcard' : raw.includes('/') && /^\d/.test(raw) ? 'cidr' : 'domain',
      value: raw.replace(/^https?:\/\//, '').split('/')[0].toLowerCase(),
    };
    if (raw.startsWith('*.')) {
      entry.type = 'wildcard';
      entry.value = raw.toLowerCase();
    }
    config.Q4_authorizedAssets.push(entry);
    const after = calculateLaunchReadiness(config).status;
    return {
      config,
      audit: audit('Q4', prev, config.Q4_authorizedAssets, source, 'authorized_asset', ['scope', 'launch'], before, after),
      launch: calculateLaunchReadiness(config),
      message: `Added Q4 asset ${entry.value}`,
    };
  }

  // Ambiguous URL without authorization verb
  if (/^https?:\/\/\S+$/i.test(text)) {
    return {
      config,
      audit: null,
      launch: calculateLaunchReadiness(config),
      message: 'URL seen without explicit authorization',
      needsClarification:
        'State explicitly: "Authorized in-scope asset: <url>" if this should enter Q4.',
    };
  }

  return {
    config,
    audit: null,
    launch: calculateLaunchReadiness(config),
    message: 'No mapped Q field',
    needsClarification: 'Could not map input to a known configuration field.',
  };
}
