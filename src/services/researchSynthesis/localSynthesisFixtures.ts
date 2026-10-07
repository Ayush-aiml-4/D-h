import { ResearchObservation } from '../../types/researchSynthesis.ts';
import { createObservation } from './observationModelService.ts';

// Fixture A: Independent observations
export function createFixtureA_IndependentObservations(): ResearchObservation[] {
  const obs1 = createObservation({
    researchCaseId: 'case-indep-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Logistics Portal',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'acc-tenant-a',
      accountRole: 'LOGISTICS_PARTNER',
    },
    observationType: 'CROSS_ACCOUNT_ACCESS',
    expectedBehavior: 'Partner portal enforces strict tenant isolation on shipment tracking',
    observedBehavior: 'Partner A can view shipment metadata belonging to Partner B via shipment-id parameter',
    impactIndicators: ['RESOURCE_OWNERSHIP', 'CONFIDENTIALITY'],
    evidenceReferences: ['ev-shipment-bola-001', 'ev-shipment-bola-002'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHORIZATION_0004',
      fixtureId: 'fix-authz-valmo-01',
      stepNumber: 1,
    },
    resourceIdentifier: '/api/v1/shipments/SHP-99281',
  });

  const obs2 = createObservation({
    researchCaseId: 'case-indep-02',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Meesho Supplier Hub',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'acc-supplier-c',
      accountRole: 'SUPPLIER',
    },
    observationType: 'PATH_TRAVERSAL_READ',
    expectedBehavior: 'Catalog export download restricts path to supplier directory',
    observedBehavior: 'Path traversal ../../etc/passwd returns root file contents',
    impactIndicators: ['CONFIDENTIALITY', 'SENSITIVE_DATA'],
    evidenceReferences: ['ev-path-traversal-001'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHENTICATION_0005',
      fixtureId: 'fix-traversal-sup-01',
      stepNumber: 1,
    },
    resourceIdentifier: '/api/v1/catalog/export',
  });

  return [obs1, obs2];
}

// Fixture B: Duplicate observations
export function createFixtureB_DuplicateObservations(): ResearchObservation[] {
  const obs1 = createObservation({
    researchCaseId: 'case-dup-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Tracking API',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'acc-tenant-a',
      accountRole: 'USER',
    },
    observationType: 'CROSS_ACCOUNT_ACCESS',
    expectedBehavior: 'HTTP 403 on cross-tenant shipment query',
    observedBehavior: 'Cross-tenant shipment query returns HTTP 200 with full PII',
    impactIndicators: ['CONFIDENTIALITY', 'AUTHORIZATION'],
    evidenceReferences: ['ev-dup-01'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHORIZATION_0004',
      stepNumber: 1,
    },
    resourceIdentifier: '/api/v1/shipments/SHP-100',
  });

  const obs2 = createObservation({
    researchCaseId: 'case-dup-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Tracking API',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'acc-tenant-a',
      accountRole: 'USER',
    },
    observationType: 'CROSS_ACCOUNT_ACCESS',
    expectedBehavior: 'HTTP 403 on cross-tenant shipment query',
    observedBehavior: 'Cross-tenant shipment query returns HTTP 200 with full PII',
    impactIndicators: ['CONFIDENTIALITY', 'AUTHORIZATION'],
    evidenceReferences: ['ev-dup-02'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHORIZATION_0004',
      stepNumber: 2,
    },
    resourceIdentifier: '/api/v1/shipments/SHP-100',
  });

  return [obs1, obs2];
}

// Fixture C: Authorization + workflow chain
export function createFixtureC_AuthzWorkflowChain(): ResearchObservation[] {
  const obs1 = createObservation({
    researchCaseId: 'case-chain-authz-wf-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Order Dispatcher',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'driver-01',
      accountRole: 'DELIVERY_PARTNER',
    },
    observationType: 'CROSS_ACCOUNT_ACCESS',
    expectedBehavior: 'Delivery partner cannot access unassigned warehouse orders',
    observedBehavior: 'Delivery partner reads order manifest for warehouse WH-CENTRAL',
    impactIndicators: ['RESOURCE_OWNERSHIP'],
    evidenceReferences: ['ev-chain-01-authz'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHORIZATION_0004',
      stepNumber: 1,
    },
    resourceIdentifier: 'WH-ORDER-991',
    workflowId: 'order-lifecycle-v1',
  });

  const obs2 = createObservation({
    researchCaseId: 'case-chain-authz-wf-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Order Dispatcher',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'driver-01',
      accountRole: 'DELIVERY_PARTNER',
    },
    observationType: 'FORBIDDEN_WORKFLOW_TRANSITION',
    expectedBehavior: 'Order cannot transition to DELIVERED without verified OTP',
    observedBehavior: 'Direct transition from CREATED to DELIVERED accepted without OTP payment',
    impactIndicators: ['WORKFLOW_CONTROL', 'INTEGRITY'],
    evidenceReferences: ['ev-chain-02-workflow'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'WORKFLOW_0006',
      stepNumber: 2,
    },
    resourceIdentifier: 'WH-ORDER-991',
    workflowId: 'order-lifecycle-v1',
  });

  return [obs1, obs2];
}

// Fixture D: Authentication + authorization chain
export function createFixtureD_AuthnAuthzChain(): ResearchObservation[] {
  const obs1 = createObservation({
    researchCaseId: 'case-chain-authn-authz-01',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Meesho Supplier Portal',
    actorContext: {
      researcherId: 'researcher-001',
      accountRole: 'UNAUTHENTICATED',
    },
    observationType: 'AUTHN_BYPASS',
    expectedBehavior: 'Unauthenticated requests to /api/v1/supplier/profile return HTTP 401',
    observedBehavior: 'Header X-Original-User-Id bypasses authentication middleware completely',
    impactIndicators: ['AUTHORIZATION', 'ACCOUNT_BOUNDARY'],
    evidenceReferences: ['ev-authn-bypass-01'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHENTICATION_0005',
      stepNumber: 1,
    },
    resourceIdentifier: '/api/v1/supplier/profile',
  });

  const obs2 = createObservation({
    researchCaseId: 'case-chain-authn-authz-01',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Meesho Supplier Portal',
    actorContext: {
      researcherId: 'researcher-001',
      accountRole: 'UNAUTHENTICATED',
    },
    observationType: 'CROSS_ACCOUNT_ACCESS',
    expectedBehavior: 'Cross-supplier bank account records require explicit ownership authorization',
    observedBehavior: 'Arbitrary supplier bank account and payout details disclosed',
    impactIndicators: ['CONFIDENTIALITY', 'SENSITIVE_DATA', 'FINANCIAL'],
    evidenceReferences: ['ev-authz-bola-02'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHORIZATION_0004',
      stepNumber: 2,
    },
    resourceIdentifier: '/api/v1/supplier/profile',
  });

  return [obs1, obs2];
}

// Fixture E: Input + authorization chain
export function createFixtureE_InputAuthzChain(): ResearchObservation[] {
  const obs1 = createObservation({
    researchCaseId: 'case-chain-input-authz-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Partner DB',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'partner-x',
      accountRole: 'STANDARD_USER',
    },
    observationType: 'SQL_INJECTION_DIFFERENTIAL',
    expectedBehavior: 'Partner search parameter parameterized safely',
    observedBehavior: 'Boolean SQL injection differential in query filter',
    impactIndicators: ['CONFIDENTIALITY', 'INTEGRITY'],
    evidenceReferences: ['ev-sqli-01'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHENTICATION_0005',
      stepNumber: 1,
    },
    resourceIdentifier: '/api/v1/partners/search',
  });

  const obs2 = createObservation({
    researchCaseId: 'case-chain-input-authz-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Partner DB',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'partner-x',
      accountRole: 'STANDARD_USER',
    },
    observationType: 'CROSS_ACCOUNT_ACCESS',
    expectedBehavior: 'SQL injection cannot cross tenant database partition',
    observedBehavior: 'Cross-tenant authentication tokens extracted via SQL differential',
    impactIndicators: ['CONFIDENTIALITY', 'ACCOUNT_BOUNDARY', 'SENSITIVE_DATA'],
    evidenceReferences: ['ev-cross-tenant-token-02'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHORIZATION_0004',
      stepNumber: 2,
    },
    resourceIdentifier: '/api/v1/partners/search',
  });

  return [obs1, obs2];
}

// Fixture F: SSRF + input chain
export function createFixtureF_SSRFInputChain(): ResearchObservation[] {
  const obs1 = createObservation({
    researchCaseId: 'case-chain-ssrf-input-01',
    programId: 'meesho-hackerone',
    target: 'supplier.meesho.com',
    asset: 'Meesho Image Ingestion API',
    actorContext: {
      researcherId: 'researcher-001',
      accountIdentifier: 'supplier-01',
      accountRole: 'SUPPLIER',
    },
    observationType: 'OUTBOUND_SSRF_INTERACTION',
    expectedBehavior: 'Outbound image downloader rejects private RFC1918 and loopback IPs',
    observedBehavior: 'Downloader performs HTTP GET to internal backend service 10.0.4.15:8080',
    impactIndicators: ['SERVER_SIDE_INTERACTION', 'CONFIDENTIALITY'],
    evidenceReferences: ['ev-ssrf-internal-01'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'SERVER_INTERACTION_0007',
      stepNumber: 1,
    },
    resourceIdentifier: '/api/v1/products/upload-by-url',
  });

  return [obs1];
}

// Fixture G: False-positive multi-observation cluster (reflection + 200)
export function createFixtureG_FalsePositiveCluster(): ResearchObservation[] {
  const obs1 = createObservation({
    researchCaseId: 'case-fp-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Public FAQ',
    actorContext: {
      researcherId: 'researcher-001',
      accountRole: 'ANONYMOUS',
    },
    observationType: 'PARAMETER_REFLECTION',
    expectedBehavior: 'Search term reflected in HTML',
    observedBehavior: 'Search term string reflected safely inside text node without DOM script execution',
    impactIndicators: [],
    evidenceReferences: [],
    confidence: 'LOW_CONFIDENCE',
    provenance: {
      engine: 'AUTHENTICATION_0005',
      stepNumber: 1,
    },
    resourceIdentifier: '/faq?q=test',
  });

  return [obs1];
}

// Fixture H: One valid high-confidence finding
export function createFixtureH_ValidHighConfidenceFinding(): ResearchObservation[] {
  return createFixtureA_IndependentObservations().slice(0, 1);
}

// Fixture I: One technically interesting but ineligible finding (e.g. out of scope or ineligible class)
export function createFixtureI_TechnicallyInterestingIneligibleFinding(): ResearchObservation[] {
  const obs = createObservation({
    researchCaseId: 'case-ineligible-01',
    programId: 'meesho-hackerone',
    target: 'internal.meesho.com', // Out of scope asset
    asset: 'Internal Admin',
    actorContext: {
      researcherId: 'researcher-001',
      accountRole: 'ANONYMOUS',
    },
    observationType: 'CROSS_ACCOUNT_ACCESS',
    expectedBehavior: 'Strict 403 on internal admin',
    observedBehavior: 'Internal admin page accessible without auth',
    impactIndicators: ['AUTHORIZATION'],
    evidenceReferences: ['ev-ineligible-01'],
    confidence: 'HIGH_CONFIDENCE',
    provenance: {
      engine: 'AUTHORIZATION_0004',
      stepNumber: 1,
    },
    resourceIdentifier: '/admin/status',
  });

  return [obs];
}

// Fixture J: One incomplete finding (missing evidence, no impact)
export function createFixtureJ_IncompleteFinding(): ResearchObservation[] {
  const obs = createObservation({
    researchCaseId: 'case-incomplete-01',
    programId: 'meesho-hackerone',
    target: 'www.valmo.in',
    asset: 'Valmo Web',
    actorContext: {
      researcherId: 'researcher-001',
      accountRole: 'STANDARD_USER',
    },
    observationType: 'CUSTOM_OBSERVATION',
    expectedBehavior: 'Expected standard response',
    observedBehavior: 'Server returned HTTP 500 error on unusual input',
    impactIndicators: [],
    evidenceReferences: [], // No evidence attached
    confidence: 'NO_FINDING',
    provenance: {
      engine: 'SYNTHESIS_0008',
      stepNumber: 1,
    },
    resourceIdentifier: '/api/v1/unknown',
  });

  return [obs];
}

// Fixture K: Raw secret containing string for blocking test
export const FIXTURE_K_RAW_SECRET = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

// Fixture L: One duplicate finding group
export function createFixtureL_DuplicateFindingGroup(): ResearchObservation[] {
  return createFixtureB_DuplicateObservations();
}
