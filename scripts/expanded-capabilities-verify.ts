import { db } from '../src/db/index.ts';
import { programs, assets, users, findings } from '../src/db/schema.ts';
import { eq } from 'drizzle-orm';
import { AuthUser } from '../src/middleware/auth.ts';
import { CAPABILITIES } from '../src/constants/capabilities.ts';
import {
  executeCapability,
  clearExecutionsStore,
} from '../src/services/researchExecutionService.ts';
import {
  createResearchCase,
  getResearchCases,
  transitionCaseStatus,
} from '../src/services/caseService.ts';
import { adapterRegistry } from '../src/services/execution/adapterRegistry.ts';
import {
  SafeControlledHttpClient,
  isRestrictedHost,
} from '../src/services/execution/httpClient.ts';
import {
  resolveExecutionPolicy,
  evaluateExecutionApproval,
  CAPABILITY_EXECUTION_POLICIES,
} from '../src/services/execution/executionPolicy.ts';
import { computeEvidenceHash } from '../src/services/evidenceService.ts';

const adminUser: AuthUser = {
  uid: 'user-ayush-001',
  role: 'ADMIN',
  name: 'Ayush Singh',
  email: 'ayush@example.com',
};

const researcherUser: AuthUser = {
  uid: 'user-ayush-001',
  role: 'RESEARCHER',
  name: 'Ayush Singh',
  email: 'ayush@example.com',
};

async function runExpandedCapabilitiesVerification() {
  console.log('====================================================');
  console.log('DEVILHUNT #0003.5-C EXPANDED CAPABILITIES VERIFICATION');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function test(name: string, assertion: boolean, detail?: string) {
    if (assertion) {
      console.log(`[PASS] ${name}`);
      passed++;
    } else {
      console.error(`[FAIL] ${name} ${detail ? `(${detail})` : ''}`);
      failed++;
    }
  }

  // 1. Verify capability catalog count and categories
  test('01. Capability catalog contains exactly 40 defined capabilities', CAPABILITIES.length === 40, `Found ${CAPABILITIES.length}`);

  const distinctCategories = Array.from(new Set(CAPABILITIES.map((c) => c.category)));
  test('02. All 11 capability categories are represented', distinctCategories.length >= 11, `Found ${distinctCategories.length} categories: ${distinctCategories.join(', ')}`);

  // 2. Verify all 40 capabilities have valid policy definitions
  let allPoliciesValid = true;
  for (const cap of CAPABILITIES) {
    const policy = resolveExecutionPolicy(cap.id);
    if (!policy || !policy.authorizationLevel || typeof policy.maxTimeoutMs !== 'number') {
      allPoliciesValid = false;
      console.error(`Missing or invalid policy for capability: ${cap.id}`);
    }
  }
  test('03. All 40 capabilities resolve explicit execution policies', allPoliciesValid);

  // 3. Verify adapter registry has all primary and expanded adapters
  const registeredAdapters = adapterRegistry.listAdapters();
  test('04. Adapter registry contains registered execution adapters', registeredAdapters.length >= 17, `Found ${registeredAdapters.length} adapters`);

  // 4. Verify DB program and case setup
  const dbPrograms = await db.select().from(programs);
  const activeProgram = dbPrograms.find((p) => p.id === 'prog-acme-01') || dbPrograms.find((p) => p.status === 'Active')!;
  if (!activeProgram) throw new Error('No active program found in database');

  const dbAssets = await db.select().from(assets).where(eq(assets.programId, activeProgram.id));
  const validAsset = dbAssets.find((a) => a.status === 'IN_SCOPE') || dbAssets[0];
  if (!validAsset) throw new Error('No valid asset found for active program');

  const allCases = await getResearchCases(adminUser, activeProgram.id);
  let activeCase = allCases.find((c) => c.status === 'ACTIVE');
  if (!activeCase) {
    const draftCase = await createResearchCase(
      adminUser,
      {
        programId: activeProgram.id,
        title: 'Expanded Capabilities Verification Case',
        objective: 'Verify 40 capability executions with governed fixtures',
      },
      'req-init-case-c'
    );
    activeCase = await transitionCaseStatus(draftCase.id, 'ACTIVE', adminUser, 'req-init-act-c');
  }

  clearExecutionsStore();

  // Setup standard mock handler
  SafeControlledHttpClient.setMockHandler(async (options) => {
    const path = options.path || '/';
    if (path.includes('openapi') || path.includes('swagger')) {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: { 'content-type': 'application/json' },
        body: '{"openapi":"3.0.0","info":{"title":"Governed API","version":"1.0.0"},"paths":{}}',
        url: `https://security-test.example.com${path}`,
        durationMs: 5,
        redirectCount: 0,
      };
    }
    if (path.includes('robots.txt')) {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: { 'content-type': 'text/plain' },
        body: 'User-agent: *\nDisallow: /admin/\nDisallow: /private/\n',
        url: `https://security-test.example.com${path}`,
        durationMs: 5,
        redirectCount: 0,
      };
    }
    if (path.includes('security.txt')) {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: { 'content-type': 'text/plain' },
        body: 'Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59.000Z\nPolicy: https://example.com/security-policy\n',
        url: `https://security-test.example.com${path}`,
        durationMs: 5,
        redirectCount: 0,
      };
    }
    if (path.includes('graphql')) {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: { 'content-type': 'application/json' },
        body: '{"data":{"__schema":{"types":[{"name":"Query","kind":"OBJECT"},{"name":"User","kind":"OBJECT"}]}}}',
        url: `https://security-test.example.com${path}`,
        durationMs: 5,
        redirectCount: 0,
      };
    }
    return {
      statusCode: 200,
      statusText: 'OK',
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'server': 'nginx/1.24.0',
        'x-powered-by': 'Express',
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'SAMEORIGIN',
        'cross-origin-opener-policy': 'same-origin',
        'cross-origin-embedder-policy': 'require-corp',
        'cache-control': 'no-store, private',
        'cf-ray': '89a12bcde01-DFW',
        'allow': 'GET, HEAD, OPTIONS',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
      },
      body: '<!DOCTYPE html><html><head><title>Authorized Target</title><script src="/app.js" integrity="sha384-abc"></script></head><body><h1>Target Active</h1></body></html>',
      url: `https://security-test.example.com${path}`,
      durationMs: 5,
      redirectCount: 0,
    };
  });

  // 5. Test HTTP Methods Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-http-methods-analysis',
        assetId: validAsset.id,
      },
      'req-exp-01'
    );
    const obs = res.observations[0];
    test(
      '05. HTTP Methods Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'HTTP_METHODS_OBSERVATION' && obs.sanitizedData.detectedMethods.includes('GET')
    );
  } catch (err: any) {
    test('05. HTTP Methods Adapter executes safely', false, err.message);
  }

  // 6. Test Redirect Chain Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-redirect-chain-analysis',
        assetId: validAsset.id,
      },
      'req-exp-02'
    );
    const obs = res.observations[0];
    test(
      '06. Redirect Chain Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'REDIRECT_CHAIN_OBSERVATION'
    );
  } catch (err: any) {
    test('06. Redirect Chain Adapter executes safely', false, err.message);
  }

  // 7. Test Cache-Control Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-cache-control-analysis',
        assetId: validAsset.id,
      },
      'req-exp-03'
    );
    const obs = res.observations[0];
    test(
      '07. Cache-Control Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'CACHE_CONTROL_OBSERVATION' && obs.sanitizedData.hasNoStore === true
    );
  } catch (err: any) {
    test('07. Cache-Control Adapter executes safely', false, err.message);
  }

  // 8. Test MIME Sniffing Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-mime-sniffing-analysis',
        assetId: validAsset.id,
      },
      'req-exp-04'
    );
    const obs = res.observations[0];
    test(
      '08. MIME Sniffing Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'MIME_SNIFFING_OBSERVATION' && obs.sanitizedData.hasNosniff === true
    );
  } catch (err: any) {
    test('08. MIME Sniffing Adapter executes safely', false, err.message);
  }

  // 9. Test Cross-Origin Policies Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-cross-origin-policies',
        assetId: validAsset.id,
      },
      'req-exp-05'
    );
    const obs = res.observations[0];
    test(
      '09. Cross-Origin Policies Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'CROSS_ORIGIN_POLICIES_OBSERVATION' && obs.sanitizedData.isCrossoriginIsolated === true
    );
  } catch (err: any) {
    test('09. Cross-Origin Policies Adapter executes safely', false, err.message);
  }

  // 10. Test TLS Transport Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-tls-ssl-audit',
        assetId: validAsset.id,
      },
      'req-exp-06'
    );
    const obs = res.observations[0];
    test(
      '10. TLS Transport Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'TLS_TRANSPORT_OBSERVATION' && obs.sanitizedData.protocol === 'HTTPS'
    );
  } catch (err: any) {
    test('10. TLS Transport Adapter executes safely', false, err.message);
  }

  // 11. Test DNS Intelligence Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-dns-records-observation',
        assetId: validAsset.id,
      },
      'req-exp-07'
    );
    const obs = res.observations[0];
    test(
      '11. DNS Intelligence Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'DNS_INTELLIGENCE_OBSERVATION' && obs.sanitizedData.securityPolicies.hasDnssec === true
    );
  } catch (err: any) {
    test('11. DNS Intelligence Adapter executes safely', false, err.message);
  }

  // 12. Test API Security Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-api-schema-mapping',
        assetId: validAsset.id,
      },
      'req-exp-08'
    );
    const obs = res.observations[0];
    test(
      '12. API Security Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'API_SECURITY_OBSERVATION' && obs.sanitizedData.openApiExposed === true
    );
  } catch (err: any) {
    test('12. API Security Adapter executes safely', false, err.message);
  }

  // 13. Test GraphQL Introspection Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-graphql-introspection',
        assetId: validAsset.id,
      },
      'req-exp-09'
    );
    const obs = res.observations[0];
    test(
      '13. GraphQL Introspection Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'GRAPHQL_INTROSPECTION_OBSERVATION' && obs.sanitizedData.introspectionEnabled === true
    );
  } catch (err: any) {
    test('13. GraphQL Introspection Adapter executes safely', false, err.message);
  }

  // 14. Test Auth & Session Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-jwt-structure-inspection',
        assetId: validAsset.id,
        parameters: { token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkF5dXNoIiwiZXhwIjoxNzAwMDAwMDAwfQ.signature' },
      },
      'req-exp-10'
    );
    const obs = res.observations[0];
    test(
      '14. Auth & Session Adapter executes safely with redacted token output',
      res.status === 'COMPLETED' && obs?.observationType === 'AUTH_SESSION_OBSERVATION' && obs.sanitizedData.tokenDetails?.subject === 'REDACTED_USER_ID'
    );
  } catch (err: any) {
    test('14. Auth & Session Adapter executes safely', false, err.message);
  }

  // 15. Test Tech Fingerprint Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-tech-stack-fingerprint',
        assetId: validAsset.id,
      },
      'req-exp-11'
    );
    const obs = res.observations[0];
    test(
      '15. Tech Fingerprint Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'TECH_FINGERPRINT_OBSERVATION' && obs.sanitizedData.detectedWaf === 'Cloudflare'
    );
  } catch (err: any) {
    test('15. Tech Fingerprint Adapter executes safely', false, err.message);
  }

  // 16. Test Exposure Metadata Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-sensitive-file-exposure',
        assetId: validAsset.id,
      },
      'req-exp-12'
    );
    const obs = res.observations[0];
    test(
      '16. Exposure Metadata Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'EXPOSURE_METADATA_OBSERVATION' && obs.sanitizedData.hasRobotsTxt === true
    );
  } catch (err: any) {
    test('16. Exposure Metadata Adapter executes safely', false, err.message);
  }

  // 17. Test Client Security Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-client-secrets-detection',
        assetId: validAsset.id,
      },
      'req-exp-13'
    );
    const obs = res.observations[0];
    test(
      '17. Client Security Adapter executes safely with observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'CLIENT_SECURITY_OBSERVATION' && obs.sanitizedData.scriptTagCount >= 1
    );
  } catch (err: any) {
    test('17. Client Security Adapter executes safely', false, err.message);
  }

  // 18. Test Cloud Infrastructure Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-cloud-provider-indicator',
        assetId: validAsset.id,
      },
      'req-exp-14'
    );
    const obs = res.observations[0];
    test(
      '18. Cloud Infrastructure Adapter executes safely without metadata probing',
      res.status === 'COMPLETED' && obs?.observationType === 'CLOUD_INFRASTRUCTURE_OBSERVATION' && obs.sanitizedData.metadataProbingAttempted === false
    );
  } catch (err: any) {
    test('18. Cloud Infrastructure Adapter executes safely', false, err.message);
  }

  // 19. Test Security.txt Adapter
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-security-txt-observation',
        assetId: validAsset.id,
      },
      'req-exp-15'
    );
    const obs = res.observations[0];
    test(
      '19. Security.txt Adapter executes safely with RFC 9116 observation output',
      res.status === 'COMPLETED' && obs?.observationType === 'SECURITY_TXT_OBSERVATION' && obs.sanitizedData.hasSecurityTxt === true
    );
  } catch (err: any) {
    test('19. Security.txt Adapter executes safely', false, err.message);
  }

  // 20. Test Rate Limit Adapter (Requires Approval)
  try {
    const res = await executeCapability(
      adminUser,
      {
        caseId: activeCase.id,
        capabilityId: 'cap-rate-limit-inspection',
        assetId: validAsset.id,
        confirmApproval: true,
      },
      'req-exp-16'
    );
    const obs = res.observations[0];
    test(
      '20. Rate Limit Adapter executes with explicit confirmation',
      res.status === 'COMPLETED' && obs?.observationType === 'RATE_LIMIT_OBSERVATION'
    );
  } catch (err: any) {
    test('20. Rate Limit Adapter executes with explicit confirmation', false, err.message);
  }

  // Clean up mock handler
  SafeControlledHttpClient.clearMockHandler();

  console.log('\n====================================================');
  console.log(`EXPANDED CAPABILITIES VERIFICATION SUMMARY: ${passed} PASSED, ${failed} FAILED (TOTAL 20)`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

runExpandedCapabilitiesVerification().catch((err) => {
  console.error('Expanded capabilities verification failed:', err);
  process.exit(1);
});
