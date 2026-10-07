import {
  AuthContext,
  HttpMethod,
} from '../../types/authorizationResearch.ts';
import {
  SessionModel,
  ExecutionSnapshot,
  ControlledParameter,
  AuthenticationHypothesis,
} from '../../types/authenticationResearch.ts';
import {
  createValidatedAuthContext,
  createSessionModel,
} from './authenticationContextAnalyzer.ts';
import { registerControlledParameter } from './inputResearchEngine.ts';

export interface LocalAuthFixtureEnvironment {
  contexts: {
    standardUser: AuthContext;
    privilegedUser: AuthContext;
    unauthenticated: AuthContext;
  };
  sessions: {
    activeSessionA: SessionModel;
    activeSessionB: SessionModel;
    invalidatedSessionA: SessionModel;
    expiredSessionA: SessionModel;
  };
  parameters: {
    xssSearchParam: ControlledParameter;
    safeXssSearchParam: ControlledParameter;
    sqliFilterParam: ControlledParameter;
    safeSqliFilterParam: ControlledParameter;
    traversalFileParam: ControlledParameter;
    safeTraversalFileParam: ControlledParameter;
  };
}

/**
 * Creates the local authentication & input research fixture environment.
 */
export function createLocalAuthFixtureEnvironment(params?: {
  researcherId?: string;
  programId?: string;
  caseId?: string;
}): LocalAuthFixtureEnvironment {
  const researcherId = params?.researcherId || 'user-ayush-001';
  const programId = params?.programId || 'meesho-hackerone';
  const caseId = params?.caseId || 'case-auth-research-01';

  // 1. Contexts
  const standardUser = createValidatedAuthContext({
    contextLabel: 'STANDARD_USER',
    researcherId,
    programId,
    caseId,
    accountIdentifier: 'acc-standard-user',
    accountRole: 'STANDARD_USER',
    credentialReference: 'cred-ref-std-01',
    sessionReference: 'sess-ref-std-01',
  });

  const privilegedUser = createValidatedAuthContext({
    contextLabel: 'PRIVILEGED_USER',
    researcherId,
    programId,
    caseId,
    accountIdentifier: 'acc-admin-user',
    accountRole: 'ADMIN_USER',
    credentialReference: 'cred-ref-admin-01',
    sessionReference: 'sess-ref-admin-01',
  });

  const unauthenticated = createValidatedAuthContext({
    contextLabel: 'UNAUTHENTICATED',
    researcherId,
    programId,
    caseId,
    accountIdentifier: 'anonymous',
    accountRole: 'UNAUTHENTICATED',
    credentialReference: 'none',
    sessionReference: 'none',
  });

  // 2. Sessions
  const activeSessionA = createSessionModel({
    sessionId: 'sess-act-a-01',
    sessionReference: 'sess-ref-user-a',
    accountIdentifier: 'acc-user-a',
    accountRole: 'STANDARD_USER',
    state: 'ACTIVE',
    credentialReference: 'cred-ref-user-a',
    ttlSeconds: 3600,
  });

  const activeSessionB = createSessionModel({
    sessionId: 'sess-act-b-02',
    sessionReference: 'sess-ref-user-b',
    accountIdentifier: 'acc-user-b',
    accountRole: 'STANDARD_USER',
    state: 'ACTIVE',
    credentialReference: 'cred-ref-user-b',
    ttlSeconds: 3600,
  });

  const invalidatedSessionA = createSessionModel({
    sessionId: 'sess-inval-a-03',
    sessionReference: 'sess-ref-user-a-invalidated',
    accountIdentifier: 'acc-user-a',
    accountRole: 'STANDARD_USER',
    state: 'INVALIDATED',
    credentialReference: 'cred-ref-user-a',
    ttlSeconds: 3600,
  });

  const expiredSessionA = createSessionModel({
    sessionId: 'sess-exp-a-04',
    sessionReference: 'sess-ref-user-a-expired',
    accountIdentifier: 'acc-user-a',
    accountRole: 'STANDARD_USER',
    state: 'EXPIRED',
    credentialReference: 'cred-ref-user-a',
    ttlSeconds: -100, // Expired in the past
  });

  // 3. Controlled Parameters
  const xssSearchParam = registerControlledParameter({
    parameterName: 'q',
    parameterType: 'QUERY',
    baseValue: 'kurti',
    securityContext: 'HTML_BODY',
  });

  const safeXssSearchParam = registerControlledParameter({
    parameterName: 'search',
    parameterType: 'QUERY',
    baseValue: 'saree',
    securityContext: 'HTML_BODY',
  });

  const sqliFilterParam = registerControlledParameter({
    parameterName: 'category_id',
    parameterType: 'QUERY',
    baseValue: '10',
    securityContext: 'SQL_CLAUSE',
  });

  const safeSqliFilterParam = registerControlledParameter({
    parameterName: 'cat_id',
    parameterType: 'QUERY',
    baseValue: '10',
    securityContext: 'SQL_CLAUSE',
  });

  const traversalFileParam = registerControlledParameter({
    parameterName: 'doc',
    parameterType: 'QUERY',
    baseValue: 'terms.txt',
    securityContext: 'FILE_PATH',
  });

  const safeTraversalFileParam = registerControlledParameter({
    parameterName: 'filename',
    parameterType: 'QUERY',
    baseValue: 'policy.txt',
    securityContext: 'FILE_PATH',
  });

  return {
    contexts: {
      standardUser,
      privilegedUser,
      unauthenticated,
    },
    sessions: {
      activeSessionA,
      activeSessionB,
      invalidatedSessionA,
      expiredSessionA,
    },
    parameters: {
      xssSearchParam,
      safeXssSearchParam,
      sqliFilterParam,
      safeSqliFilterParam,
      traversalFileParam,
      safeTraversalFileParam,
    },
  };
}

/**
 * Deterministic Mock Response Dispatcher for Authentication & Input Fixtures
 * Executes in-memory simulation with zero external network traffic.
 */
export function dispatchLocalAuthFixtureRequest(params: {
  endpoint: string;
  method?: HttpMethod;
  context?: AuthContext;
  session?: SessionModel;
  parameterName?: string;
  payloadValue?: string;
}): ExecutionSnapshot {
  const start = Date.now();
  const { endpoint, method = 'GET', context, session, parameterName, payloadValue } = params;
  const path = endpoint.toLowerCase();

  // =========================================================================
  // A. AUTHENTICATION BOUNDARY FIXTURES
  // =========================================================================

  // 1. /api/fixtures/auth/vulnerable-profile (Vulnerable Unauthenticated Endpoint)
  if (path.includes('/api/fixtures/auth/vulnerable-profile')) {
    // Flaw: allows unauthenticated requests and serves protected profile PII
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        userId: 'usr-9921',
        email: 'ayush.research@example.com',
        phoneNumber: '+91-9876543210',
        shippingAddress: '123 Tech Park, Bangalore',
        accountStatus: 'ACTIVE',
      },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 2. /api/fixtures/auth/secure-profile (Secure Enforced Endpoint)
  if (path.includes('/api/fixtures/auth/secure-profile')) {
    if (!context || context.authState === 'UNAUTHENTICATED') {
      return {
        statusCode: 401,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Unauthorized: Authentication credentials required' },
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'DENY',
        errorDetected: true,
        errorMessage: 'Unauthorized',
      };
    }

    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        userId: context.accountIdentifier,
        email: 'secure.user@example.com',
      },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 3. /api/fixtures/auth/public-info (Intentionally Public Endpoint)
  if (path.includes('/api/fixtures/auth/public-info')) {
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        platformName: 'DevilHunt Research Sandbox',
        status: 'ONLINE',
      },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // =========================================================================
  // B. SESSION SECURITY & ISOLATION FIXTURES
  // =========================================================================

  // 4. /api/fixtures/session/vulnerable-logout-reuse (Vulnerable Session Invalidation)
  if (path.includes('/api/fixtures/session/vulnerable-logout-reuse')) {
    // Flaw: accepts invalidated or expired session tokens without server-side revocation check
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        sessionStatus: 'honored',
        message: 'Protected dashboard data served',
        account: session ? session.accountIdentifier : 'acc-user-a',
      },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 5. /api/fixtures/session/secure-logout (Secure Session Invalidation)
  if (path.includes('/api/fixtures/session/secure-logout')) {
    if (session && (session.state === 'INVALIDATED' || session.state === 'EXPIRED' || session.state === 'REVOKED')) {
      return {
        statusCode: 401,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: `Unauthorized: Session is ${session.state}` },
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'DENY',
        errorDetected: true,
        errorMessage: 'Unauthorized',
      };
    }

    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: { status: 'session_active', data: 'ok' },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 6. /api/fixtures/session/vulnerable-cross-leak (Vulnerable Session Isolation)
  if (path.includes('/api/fixtures/session/vulnerable-cross-leak')) {
    // Flaw: regardless of session B, leaks account A data
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        tenantData: 'CONFIDENTIAL_ACCOUNT_A_DATA',
        ownerAccount: 'acc-user-a',
      },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // =========================================================================
  // C. PRIVILEGE BOUNDARY TRANSITION FIXTURES
  // =========================================================================

  // 7. /api/fixtures/privilege/vulnerable-admin (Vulnerable Standard User -> Admin Action)
  if (path.includes('/api/fixtures/privilege/vulnerable-admin')) {
    // Flaw: standard user can execute admin config reset
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        adminOperation: 'SYSTEM_SETTINGS_UPDATED',
        privilegedConfig: { maintenanceMode: false, debugLevel: 'VERBOSE' },
      },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 8. /api/fixtures/privilege/secure-admin (Secure Admin Action)
  if (path.includes('/api/fixtures/privilege/secure-admin')) {
    if (!context || context.accountRole !== 'ADMIN_USER') {
      return {
        statusCode: 403,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Forbidden: Requires ADMIN_USER role' },
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'DENY',
        errorDetected: true,
        errorMessage: 'Forbidden',
      };
    }

    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: { adminOperation: 'SYSTEM_SETTINGS_UPDATED' },
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // =========================================================================
  // D. INPUT SECURITY FIXTURES (XSS, INJECTION, PATH TRAVERSAL)
  // =========================================================================

  // 9. /api/fixtures/input/vulnerable-xss (Vulnerable HTML Reflected XSS)
  if (path.includes('/api/fixtures/input/vulnerable-xss')) {
    const val = payloadValue || 'default';
    return {
      statusCode: 200,
      contentType: 'text/html',
      responseHeaders: { 'content-type': 'text/html' },
      // Unencoded reflection in HTML
      responseBody: `<html><body><h1>Search Results</h1><p>Query: ${val}</p></body></html>`,
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'REFLECTED',
      errorDetected: false,
    };
  }

  // 10. /api/fixtures/input/safe-xss (Secure HTML Encoded Output)
  if (path.includes('/api/fixtures/input/safe-xss')) {
    const val = (payloadValue || 'default')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');

    return {
      statusCode: 200,
      contentType: 'text/html',
      responseHeaders: { 'content-type': 'text/html' },
      responseBody: `<html><body><h1>Search Results</h1><p>Query: ${val}</p></body></html>`,
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ENCODED',
      errorDetected: false,
    };
  }

  // 11. /api/fixtures/input/vulnerable-sqli (Vulnerable Boolean SQLi)
  if (path.includes('/api/fixtures/input/vulnerable-sqli')) {
    const val = payloadValue || '';
    // If True condition injected (or base value): returns item
    if (val === '10' || val.includes("'DEVILHUNT_EQ'='DEVILHUNT_EQ") || val.includes("1=1")) {
      return {
        statusCode: 200,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: [{ id: 10, name: 'Silk Kurti', category: 'Apparel' }],
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'ALLOW',
        errorDetected: false,
      };
    }

    // If False condition injected: returns empty
    if (val.includes("'DEVILHUNT_NEQ'='DEVILHUNT_DIFFERENT") || val.includes("1=2")) {
      return {
        statusCode: 404,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'No items found matching filter criteria' },
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'DENY',
        errorDetected: false,
      };
    }

    // Syntax probe returns syntax error
    if (val === "'") {
      return {
        statusCode: 500,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'SyntaxError: SQL syntax near quote' },
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'ERROR',
        errorDetected: true,
        errorMessage: 'SQL syntax error',
      };
    }

    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: [],
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 12. /api/fixtures/input/safe-sqli (Secure Parameterized Query)
  if (path.includes('/api/fixtures/input/safe-sqli')) {
    const val = payloadValue || '';
    if (val === '10') {
      return {
        statusCode: 200,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: [{ id: 10, name: 'Silk Kurti', category: 'Apparel' }],
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'ALLOW',
        errorDetected: false,
      };
    }

    // Literal parameter match: returns empty without SQL interpretation
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: [],
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 13. /api/fixtures/input/vulnerable-traversal (Vulnerable Path Traversal)
  if (path.includes('/api/fixtures/input/vulnerable-traversal')) {
    const val = payloadValue || '';
    if (val.includes('../') || val.includes('%2e%2e')) {
      // Flaw: reads outside root
      return {
        statusCode: 200,
        contentType: 'text/plain',
        responseHeaders: { 'content-type': 'text/plain' },
        responseBody: 'DH_CANARY_FIXTURE: confidential_system_canary_key=test_canary_secret_123',
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'ALLOW',
        errorDetected: false,
      };
    }

    return {
      statusCode: 200,
      contentType: 'text/plain',
      responseHeaders: { 'content-type': 'text/plain' },
      responseBody: 'Terms and conditions document content.',
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // 14. /api/fixtures/input/safe-traversal (Secure Canonicalized Path)
  if (path.includes('/api/fixtures/input/safe-traversal')) {
    const val = payloadValue || '';
    if (val.includes('../') || val.includes('%2e%2e')) {
      return {
        statusCode: 400,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Bad Request: Invalid path traversal sequence in filename' },
        responseTimeMs: Date.now() - start + 2,
        observedBehavior: 'DENY',
        errorDetected: true,
        errorMessage: 'Invalid path',
      };
    }

    return {
      statusCode: 200,
      contentType: 'text/plain',
      responseHeaders: { 'content-type': 'text/plain' },
      responseBody: 'Policy document content.',
      responseTimeMs: Date.now() - start + 2,
      observedBehavior: 'ALLOW',
      errorDetected: false,
    };
  }

  // Fallback 404
  return {
    statusCode: 404,
    contentType: 'application/json',
    responseHeaders: { 'content-type': 'application/json' },
    responseBody: { error: 'Not Found' },
    responseTimeMs: Date.now() - start + 1,
    observedBehavior: 'DENY',
    errorDetected: true,
  };
}
