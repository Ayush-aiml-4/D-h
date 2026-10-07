/**
 * Fictional fixture packs only — never production assets.
 */

export const FIXTURE_PACK_A_SCOPE = {
  exact: 'https://app.contoso-example.test/login',
  outOfScope: 'https://random-unlisted.example.test',
  wildcardChild: 'https://api.contoso-example.test',
  thirdParty: 'https://cdn.edge-example.test/x',
  specialAuth: 'https://app.contoso-example.test/admin',
};

export const FIXTURE_PACK_B_VALIDITY = {
  valid: {
    steps: ['Open page', 'Submit form'],
    actual: 'Unexpected admin action allowed',
    impact: 'Privilege escalation within test account',
    poc: 'synthetic steps only',
  },
  informative: { steps: ['curl -I'], actual: 'Server header present', impact: 'none' },
  insufficient: { steps: [], actual: '', impact: '' },
  spam: { steps: ['x'], actual: 'asdf', impact: 'qwerty' },
};

export const FIXTURE_PACK_C_DUPLICATES = {
  primary: {
    asset: 'https://app.contoso-example.test',
    root_cause: 'missing authz check on order id',
    vulnerability_class: 'idor',
    security_impact: 'read other orders',
  },
  exactDup: {
    asset: 'https://app.contoso-example.test',
    root_cause: 'missing authz check on order id',
    vulnerability_class: 'idor',
    security_impact: 'read other orders',
  },
  sameRoot: {
    asset: 'https://api.contoso-example.test',
    root_cause: 'missing authz check on order id',
    vulnerability_class: 'idor',
    security_impact: 'read other orders',
  },
  independent: {
    asset: 'https://app.contoso-example.test',
    root_cause: 'sqli in search q param',
    vulnerability_class: 'injection',
    security_impact: 'db read',
  },
};

export const FIXTURE_PACK_D_CHAINS = {
  validTwoLink: [
    { finding: 'open redirect', verified: true, required: true, reproducible: true, linkImpact: 'redirect' },
    { finding: 'token leak', verified: true, required: true, reproducible: true, linkImpact: 'session' },
  ],
  withOptional: [
    { finding: 'banner', verified: true, required: false, reproducible: true, linkImpact: 'info' },
    { finding: 'idor', verified: true, required: true, reproducible: true, linkImpact: 'data' },
  ],
  incomplete: [
    { finding: 'step1', verified: false, required: true, reproducible: false, linkImpact: '' },
  ],
};

export const FIXTURE_PACK_E_SENSITIVE = {
  syntheticPii: 'synthetic user email test-user@contoso-example.test',
  excessive: 'password=supersecret123',
};

export const FIXTURE_PACK_F_CONFIG = {
  q1: 'Program name is Example Contoso Security Program',
  q4Explicit: 'Authorized in-scope asset: app.contoso-example.test',
  q4Ambiguous: 'https://app.contoso-example.test',
  q30Vdp: 'VDP only',
};
