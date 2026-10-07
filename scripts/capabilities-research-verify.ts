import { getCapabilityAnalyzer, capabilityAnalyzers } from '../src/services/capabilities/index.ts';
import { sanitizeAndRedact, generateCorrelationKey } from '../src/services/capabilities/utils.ts';
import { CapabilityDefinition } from '../src/types.ts';
import { db } from '../src/db/index.ts';
import { users, programs, programScopes, assets } from '../src/db/schema.ts';

async function runResearchCapabilitiesVerification() {
  console.log('=== DEVILHUNT #0003.3-B — PASSIVE RESEARCH CAPABILITIES VERIFICATION ===\n');

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string, detail?: string) {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName}${detail ? `: ${detail}` : ''}`);
      failed++;
    }
  }

  try {
    // 1. Registry verification - 12 capability analyzers registered
    assert(
      capabilityAnalyzers.length === 12,
      'Registry Loading - 12 Capability Analyzers',
      `Expected 12, got ${capabilityAnalyzers.length}`
    );

    // 2. Lookup by ID and Alias
    const capSecurityHeader = getCapabilityAnalyzer('cap-http-header-analysis');
    const capSecurityHeaderAlias = getCapabilityAnalyzer('SECURITY_HEADER_ANALYSIS');
    assert(
      !!capSecurityHeader && capSecurityHeader === capSecurityHeaderAlias,
      'Capability Lookup by ID and Alias'
    );

    // 3. Secret Redaction Unit Test
    const secretInput = {
      apiKey: 'AIzaSyA1234567890BCDEFG1234567890BCDEF',
      authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
      normalText: 'Public information without credentials',
    };
    const { sanitized, redactedSecrets } = sanitizeAndRedact(secretInput);
    assert(
      redactedSecrets === true &&
        !JSON.stringify(sanitized).includes('AIzaSyA1234567890BCDEFG1234567890BCDEF') &&
        JSON.stringify(sanitized).includes('[REDACTED'),
      'Secret Redaction Engine (Credentials Stripped)'
    );

    // 4. Deterministic Correlation Key Generation
    const key1 = generateCorrelationKey('prog-1', 'asset-1', 'cap-cors', 'issue-1');
    const key2 = generateCorrelationKey('prog-1', 'asset-1', 'cap-cors', 'issue-1');
    assert(
      key1 === key2 && key1.length === 32,
      'Deterministic Correlation Key Generation'
    );

    // Mock fixtures
    const mockAsset = {
      id: 'asset-test-123',
      programId: 'prog-test-123',
      domain: 'target.sec',
      hostname: 'api.target.sec',
      type: 'SUBDOMAIN' as const,
      status: 'IN_SCOPE' as const,
      scopeStatus: 'In Scope',
    };

    const mockUser = {
      uid: 'user-test-123',
      email: 'tester@devilhunt.sec',
      name: 'Security Tester',
      role: 'RESEARCHER' as const,
    };

    const mockCapDef: CapabilityDefinition = {
      id: 'cap-http-header-analysis',
      name: 'HTTP Security Headers Analysis',
      category: 'CONFIGURATION_AUDIT',
      implementationStatus: 'SUPPORTED',
      automationLevel: 'AUTOMATED',
      description: 'Header analysis',
      authenticationRequirement: 'OPTIONAL',
      policyRequirement: 'POLICY_CHECK_REQUIRED',
      humanValidationRequirement: 'RECOMMENDED',
      evidenceSupport: 'JSON_EVIDENCE',
      reproductionSupport: 'CURL_COMMAND',
      reportingSupport: 'AUTOMATED_REPORT',
    };

    // 5. Test SECURITY_HEADER_ANALYSIS
    const headerAnalyzer = getCapabilityAnalyzer('SECURITY_HEADER_ANALYSIS')!;
    const headerRes = await headerAnalyzer.analyze({
      asset: mockAsset,
      capability: mockCapDef,
      observationData: {
        headers: { 'server': 'nginx' }, // Missing security headers
      },
      programId: 'prog-test-123',
      user: mockUser,
    });
    assert(
      headerRes.executed && headerRes.findingCandidates.length > 0 && headerRes.evidence.length > 0,
      'SECURITY_HEADER_ANALYSIS Passive Execution'
    );

    // 6. Test CSP_ANALYSIS
    const cspAnalyzer = getCapabilityAnalyzer('CSP_ANALYSIS')!;
    const cspRes = await cspAnalyzer.analyze({
      asset: mockAsset,
      capability: mockCapDef,
      observationData: {
        headers: { 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" },
      },
      programId: 'prog-test-123',
      user: mockUser,
    });
    assert(
      cspRes.executed && cspRes.findingCandidates.some((f) => f.title.includes('Unsafe Directives')),
      'CSP_ANALYSIS Weak Directive Identification'
    );

    // 7. Test CORS_MISCONFIGURATION
    const corsAnalyzer = getCapabilityAnalyzer('CORS_MISCONFIGURATION')!;
    const corsRes = await corsAnalyzer.analyze({
      asset: mockAsset,
      capability: mockCapDef,
      observationData: {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-credentials': 'true',
        },
      },
      programId: 'prog-test-123',
      user: mockUser,
    });
    assert(
      corsRes.executed && corsRes.findingCandidates.some((f) => f.severity === 'High'),
      'CORS_MISCONFIGURATION Detection'
    );

    // 8. Test JAVASCRIPT_SECRET_EXPOSURE with Redaction
    const jsSecretAnalyzer = getCapabilityAnalyzer('JAVASCRIPT_SECRET_EXPOSURE')!;
    const jsSecretRes = await jsSecretAnalyzer.analyze({
      asset: mockAsset,
      capability: mockCapDef,
      observationData: {
        path: '/static/js/app.js',
        body: 'const config = { apiKey: "AIzaSyA1234567890BCDEFG1234567890BCDEF" };',
      },
      programId: 'prog-test-123',
      user: mockUser,
    });
    assert(
      jsSecretRes.executed &&
        jsSecretRes.findingCandidates.some((f) => f.severity === 'Critical') &&
        jsSecretRes.evidence[0].redactedSecrets === true,
      'JAVASCRIPT_SECRET_EXPOSURE Detection & Redaction'
    );

    // 9. Test BACKUP_CONFIGURATION_FILE_EXPOSURE
    const backupAnalyzer = getCapabilityAnalyzer('BACKUP_CONFIGURATION_FILE_EXPOSURE')!;
    const backupRes = await backupAnalyzer.analyze({
      asset: mockAsset,
      capability: mockCapDef,
      observationData: {
        path: '/.env',
        status: 200,
        body: 'DB_PASSWORD=secret_pass_123',
      },
      programId: 'prog-test-123',
      user: mockUser,
    });
    assert(
      backupRes.executed && backupRes.findingCandidates.some((f) => f.title.includes('.env')),
      'BACKUP_CONFIGURATION_FILE_EXPOSURE Detection'
    );

    // 10. Test SOURCE_MAP_EXPOSURE
    const sourceMapAnalyzer = getCapabilityAnalyzer('SOURCE_MAP_EXPOSURE')!;
    const mapRes = await sourceMapAnalyzer.analyze({
      asset: mockAsset,
      capability: mockCapDef,
      observationData: {
        path: '/bundle.js.map',
        status: 200,
        body: '{"version":3,"sources":["app.ts"]}',
      },
      programId: 'prog-test-123',
      user: mockUser,
    });
    assert(
      mapRes.executed && mapRes.findingCandidates.some((f) => f.title.includes('Source Map')),
      'SOURCE_MAP_EXPOSURE Detection'
    );

    // 11. Test Secure Fixtures (False Positive Resistance across Analyzers)
    console.log('\n--- Testing False Positive Resistance with Secure Fixtures ---');
    let fpPassCount = 0;

    for (const analyzer of capabilityAnalyzers) {
      let safeObservation: Record<string, any> = {};

      switch (analyzer.capabilityId) {
        case 'cap-http-header-analysis':
          safeObservation = {
            headers: {
              'strict-transport-security': 'max-age=31536000; includeSubDomains',
              'x-content-type-options': 'nosniff',
              'x-frame-options': 'DENY',
              'content-security-policy': "default-src 'self'",
              'referrer-policy': 'strict-origin-when-cross-origin',
              'permissions-policy': 'camera=()',
              'cross-origin-opener-policy': 'same-origin',
              'cross-origin-resource-policy': 'same-origin',
            },
          };
          break;
        case 'cap-csp-audit':
          safeObservation = {
            headers: {
              'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'",
            },
          };
          break;
        case 'cap-hsts-audit':
          safeObservation = {
            headers: {
              'strict-transport-security': 'max-age=31536000; includeSubDomains',
            },
          };
          break;
        case 'cap-cors-misconfiguration':
          safeObservation = {
            headers: {
              'access-control-allow-origin': 'https://trusted.target.sec',
            },
          };
          break;
        case 'cap-cookie-security':
          safeObservation = {
            headers: {
              'set-cookie': 'session=xyz; Secure; HttpOnly; SameSite=Strict',
            },
          };
          break;
        case 'cap-tls-cipher-audit':
          safeObservation = {
            tlsVersion: 'TLSv1.3',
            cipher: 'TLS_AES_256_GCM_SHA384',
          };
          break;
        case 'cap-debug-disclosure':
          safeObservation = {
            path: '/api/v1/user',
            status: 200,
            body: '{"status":"ok"}',
          };
          break;
        case 'cap-directory-listing':
          safeObservation = {
            path: '/uploads/',
            status: 403,
            body: 'Forbidden',
          };
          break;
        case 'cap-backup-exposure':
          safeObservation = {
            path: '/.env',
            status: 404,
            body: 'Not Found',
          };
          break;
        case 'cap-sourcemap-exposure':
          safeObservation = {
            path: '/main.js.map',
            status: 404,
            body: '404 Not Found',
          };
          break;
        case 'cap-js-secret-exposure':
          safeObservation = {
            path: '/static/js/main.js',
            body: 'console.log("Hello World"); function calculate(a, b) { return a + b; }',
          };
          break;
        case 'cap-sensitive-info-disclosure':
          safeObservation = {
            path: '/api/data',
            status: 200,
            body: '{"username":"johndoe","publicProfile":true}',
          };
          break;
      }

      const res = await analyzer.analyze({
        asset: mockAsset,
        capability: mockCapDef,
        observationData: safeObservation,
        programId: 'prog-test-123',
        user: mockUser,
      });

      if (res.executed && res.findingCandidates.length === 0) {
        fpPassCount++;
      } else {
        console.warn(`[WARN] Analyzer ${analyzer.capabilityId} produced findings on clean fixture:`, res.findingCandidates);
      }
    }

    assert(
      fpPassCount === capabilityAnalyzers.length,
      `False Positive Resistance - ${fpPassCount}/${capabilityAnalyzers.length} Analyzers Clean on Secure Inputs`
    );

    console.log(`\n=== VERIFICATION SUMMARY ===`);
    console.log(`PASSED: ${passed}`);
    console.log(`FAILED: ${failed}`);

    if (failed > 0) {
      process.exit(1);
    } else {
      console.log('Research Capabilities Verification Complete: 100% PASS');
      process.exit(0);
    }
  } catch (err) {
    console.error('Fatal error during research capabilities verification:', err);
    process.exit(1);
  }
}

runResearchCapabilitiesVerification();
