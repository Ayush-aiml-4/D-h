/**
 * Authoritative in-scope register from operator-supplied HackerOne scope export.
 * Closed scope — only these entries are authorized. Wildcards are exclusions, not grants.
 * Do not invent additional hosts/packages.
 */

import type { AllowlistEntry, ProgramConfig } from './configModel.js';
import { applyMeeshoHackerOneEvidence } from './meeshoHackerOneEvidence.js';

export const MEESHO_IN_SCOPE_EXPORT: AllowlistEntry[] = [
  { id: 'www-meesho-com', type: 'domain', value: 'www.meesho.com' },
  { id: 'com-meesho-supply', type: 'mobile', value: 'com.meesho.supply' },
  { id: 'ios-1457958492', type: 'mobile', value: '1457958492' },
  { id: 'admin-meeshosupply-com', type: 'domain', value: 'admin.meeshosupply.com' },
  { id: 'supplier-meesho-com', type: 'domain', value: 'supplier.meesho.com' },
  { id: 'affiliate-meesho-com', type: 'domain', value: 'affiliate.meesho.com' },
  { id: 'prod-meeshoapi-com', type: 'api', value: 'prod.meeshoapi.com' },
  { id: 'www-valmo-in', type: 'domain', value: 'www.valmo.in' },
  { id: 'com-valmo-valmo', type: 'mobile', value: 'com.valmo.valmo' },
  { id: 'superstoreapp-meesho-com', type: 'domain', value: 'superstoreapp.meesho.com' },
  { id: 'investor-meesho-com', type: 'domain', value: 'investor.meesho.com' },
  { id: 'meesho-io', type: 'domain', value: 'meesho.io' },
];

export const MEESHO_EXPLICIT_OUT_OF_SCOPE = [
  'grocery-supplier.meesho.com',
  'farmiso.meeshosupply.com',
  'atlas.valmo.in',
  'affiliate-c.meesho.com',
  'warehouse.meesho.com',
  'agency.meesho.com',
  'di-prd-superset.meesho.com',
  'console.valmo.in',
  'log10-web-staging.valmo.in',
  'com.valmo.ops',
  'admin.meesho.io',
];

export const MEESHO_WILDCARD_EXCLUSIONS = [
  '*.meeshogcp.in',
  '*.meeshoaiservices.ai',
  '*.meesho.com',
  '*.meeshosupply.com',
  '*.valmo.in',
  '*.meeshoapi.com',
];

export function applyFullMeeshoScopeExport(base?: ProgramConfig): ProgramConfig {
  const { config } = applyMeeshoHackerOneEvidence(base);
  config.Q4_authorizedAssets = MEESHO_IN_SCOPE_EXPORT.map((e) => ({ ...e }));
  config.Q4_registerStatus = 'COMPLETE';
  config.programNotes = {
    ...config.programNotes,
    q4CategoryNotes: [
      ...(config.programNotes.q4CategoryNotes || []),
      'Full In-Scope register applied from operator HackerOne scope export.',
      'Wildcard patterns listed by program are EXCLUSIONS, not authorization.',
      'Explicit out-of-scope hosts recorded separately — do not test.',
      'superstoreapp.meesho.com: max severity High; grocery PIN/cancel rules apply.',
      'investor.meesho.com / meesho.io: max severity Low.',
      'Mobile packages: static-analysis eligibility preferred per program table.',
    ],
  };
  return config;
}
