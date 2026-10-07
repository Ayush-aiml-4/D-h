/**
 * Apply source-backed Meesho HackerOne program evidence to living ProgramConfig.
 * Does NOT invent hosts, packages, APIs, or third-party authorization.
 * Does NOT store real credentials/OTP values.
 */

import type { ProgramConfig, AllowlistEntry } from './configModel.js';
import { createDefaultProgramConfig } from './configModel.js';

export interface EvidenceChange {
  field: string;
  previous: unknown;
  next: unknown;
  classification: 'CONFIRMED' | 'PARTIALLY_CONFIRMED' | 'INFORMATIONAL';
  source: string;
}

/** Explicit domain from HackerOne screenshots — only this host is added to Q4 allowlist. */
const SUPPLIER_PANEL: AllowlistEntry = {
  id: 'meesho-supplier-panel',
  type: 'domain',
  value: 'supplier.meesho.com',
};

/**
 * Categories shown on program page without exact hosts/package IDs in the provided evidence.
 * Recorded as notes only — NOT allowlist entries.
 */
const Q4_CATEGORY_NOTES = [
  'Supplier Panel: supplier.meesho.com (exact host CONFIRMED)',
  'Consumer & Mobile Apps category shown: Meesho Web (host/URL not fully enumerated in provided evidence)',
  'Consumer & Mobile Apps category shown: Meesho Android App (package ID not provided in evidence)',
  'Consumer & Mobile Apps category shown: Meesho iOS App (bundle ID not provided in evidence)',
  'Consumer & Mobile Apps category shown: Valmo Mobile App (package/bundle ID not provided in evidence)',
];

export function applyMeeshoHackerOneEvidence(base?: ProgramConfig): {
  config: ProgramConfig;
  changes: EvidenceChange[];
} {
  const config = base ? structuredClone(base) : createDefaultProgramConfig();
  const changes: EvidenceChange[] = [];

  const set = (
    field: string,
    previous: unknown,
    next: unknown,
    classification: EvidenceChange['classification']
  ) => {
    changes.push({
      field,
      previous,
      next,
      classification,
      source: 'Meesho HackerOne program page / screenshots',
    });
  };

  // Q1
  set('Q1_programName', config.Q1_programName, 'Meesho Bug Bounty Program', 'CONFIRMED');
  config.Q1_programName = 'Meesho Bug Bounty Program';

  // Q5 already true — confirm closed scope posture
  set('Q5_allowlistOnly', config.Q5_allowlistOnly, true, 'CONFIRMED');
  config.Q5_allowlistOnly = true;

  // Q4 — only explicit host; register remains PARTIAL
  const prevQ4 = config.Q4_authorizedAssets.map((a) => a.value);
  const hasSupplier = config.Q4_authorizedAssets.some(
    (a) => a.type === 'domain' && a.value.toLowerCase() === 'supplier.meesho.com'
  );
  if (!hasSupplier) {
    config.Q4_authorizedAssets = [...config.Q4_authorizedAssets, { ...SUPPLIER_PANEL }];
  }
  set(
    'Q4_authorizedAssets',
    prevQ4,
    config.Q4_authorizedAssets.map((a) => a.value),
    'PARTIALLY_CONFIRMED'
  );
  set('Q4_registerStatus', config.Q4_registerStatus, 'PARTIAL', 'PARTIALLY_CONFIRMED');
  config.Q4_registerStatus = 'PARTIAL';

  // Q16 test accounts available (refs only)
  set('Q16_programTestAccounts', config.Q16_programTestAccounts, 'YES', 'CONFIRMED');
  config.Q16_programTestAccounts = 'YES';

  // Q27 researcher header
  set('Q27_customHeaderRequired', config.Q27_customHeaderRequired, true, 'CONFIRMED');
  config.Q27_customHeaderRequired = true;
  set('Q27_headerName', config.Q27_headerName, 'X-Hackerone', 'CONFIRMED');
  config.Q27_headerName = 'X-Hackerone';
  set('Q27_headerValueTemplate', config.Q27_headerValueTemplate, '<h1-username>', 'CONFIRMED');
  config.Q27_headerValueTemplate = '<h1-username>';

  // Q30 paid bounty
  set('Q30_rewardModel', config.Q30_rewardModel, 'A_PAID', 'CONFIRMED');
  config.Q30_rewardModel = 'A_PAID';

  // Q31 informational ranges only
  const ranges = {
    note: 'Displayed program reward ranges — not guaranteed payouts; final bounty at Meesho Security Team discretion; CVSS finalized by Meesho Security Team',
    webAndPlatform: {
      Low: '$100–$500',
      Medium: '$500–$1,000',
      High: '$1,000–$2,000',
      Critical: '$2,500–$3,000',
    },
    mobileApps: {
      eligibility: 'Only static analysis findings are eligible (as displayed)',
      Low: '$100–$500',
      Medium: '$500–$1,000',
      High: '$1,000–$2,500',
      Critical: '$2,500–$3,500',
    },
  };
  set('Q31_bountyStructure', config.Q31_bountyStructure, ranges, 'INFORMATIONAL');
  config.Q31_bountyStructure = ranges;

  // Special auth: mobile_dynamic remains PENDING / not assumed authorized
  // Do not change Q7–Q14 from PENDING except we could note OUT for inventing dynamic — keep PENDING

  // Notes
  const prevNotes = { ...config.programNotes };
  config.programNotes = {
    ...config.programNotes,
    platform: 'HackerOne',
    websiteShown: 'meesho.com',
    programLaunchShown: 'February 2026',
    closedScope: true,
    features: ['Closed Scope', 'Fast Payment', 'Collaboration Enabled', 'Includes Retesting'],
    mobileTestingNote:
      'Mobile apps table states only static analysis findings are eligible. Dynamic mobile / root / jailbreak testing is NOT assumed authorized.',
    accountRegistrationGuidance:
      'Use HackerOne email alias when registering free accounts: <h1-username>@wearehackerone.com',
    displayedMetrics: {
      responseEfficiency: '66%',
      avgFirstResponse: '2 days, 18 hours',
      avgTriage: '6 days, 6 hours',
      avgBounty: '1 month, 4 days',
      avgSubmissionToBounty: '1 month, 1 week',
      avgResolution: '1 month, 3 weeks',
      note: 'Informational HackerOne metrics only — not contractual SLAs',
    },
    q4CategoryNotes: Q4_CATEGORY_NOTES,
    testAccountsAvailable: true,
    testAccountStorage:
      'Program-provided Supplier Panel test accounts and consumer test mobile numbers/OTP exist on HackerOne. Store only SECRET_REF / REDACTED in systems; never log raw credentials.',
  };
  set('programNotes', prevNotes, config.programNotes, 'INFORMATIONAL');

  return { config, changes };
}
