import {
  AuthContext,
  ResourceModel,
  AuthorizationHypothesis,
  DifferentialExecutionSnapshot,
} from '../../types/authorizationResearch.ts';
import {
  createAccountAContext,
  createAccountBContext,
  createPrivilegedUserContext,
  createStandardUserContext,
  createUnauthenticatedContext,
} from './authContextService.ts';
import { createTestResource } from './resourceModelService.ts';

export interface LocalFixtureEnvironment {
  contexts: {
    accountA: AuthContext;
    accountB: AuthContext;
    standardUser: AuthContext;
    privilegedUser: AuthContext;
    unauthenticated: AuthContext;
  };
  resources: {
    orderAccountA: ResourceModel;
    orderAccountB: ResourceModel;
    secureOrderAccountA: ResourceModel;
    adminSettings: ResourceModel;
    secureAdminSettings: ResourceModel;
    publicCatalog: ResourceModel;
    privateProfile: ResourceModel;
    securePrivateProfile: ResourceModel;
  };
}

export function createLocalFixtureEnvironment(params?: {
  researcherId?: string;
  programId?: string;
  caseId?: string;
}): LocalFixtureEnvironment {
  const researcherId = params?.researcherId || 'user-ayush-001';
  const programId = params?.programId || 'meesho-hackerone';
  const caseId = params?.caseId || 'case-auth-test-01';

  const accountA = createAccountAContext({
    researcherId,
    programId,
    caseId,
    accountIdentifier: 'acc-user-a',
  });

  const accountB = createAccountBContext({
    researcherId,
    programId,
    caseId,
    accountIdentifier: 'acc-user-b',
  });

  const standardUser = createStandardUserContext({
    researcherId,
    programId,
    caseId,
    accountIdentifier: 'acc-standard-user',
  });

  const privilegedUser = createPrivilegedUserContext({
    researcherId,
    programId,
    caseId,
    accountIdentifier: 'acc-admin-user',
  });

  const unauthenticated = createUnauthenticatedContext({
    researcherId,
    programId,
    caseId,
  });

  // Resources
  const orderAccountA = createTestResource({
    resourceType: 'order',
    resourceId: 'ord-1001-account-a',
    ownerAccount: 'acc-user-a',
    endpointPath: '/api/fixtures/orders/ord-1001-account-a',
    sensitivity: 'FINANCIAL',
    expectedAuth: {
      ACCOUNT_A: 'ALLOW',
      ACCOUNT_B: 'DENY',
      UNAUTHENTICATED: 'DENY',
    },
  });

  const orderAccountB = createTestResource({
    resourceType: 'order',
    resourceId: 'ord-2002-account-b',
    ownerAccount: 'acc-user-b',
    endpointPath: '/api/fixtures/orders/ord-2002-account-b',
    sensitivity: 'FINANCIAL',
    expectedAuth: {
      ACCOUNT_A: 'DENY',
      ACCOUNT_B: 'ALLOW',
      UNAUTHENTICATED: 'DENY',
    },
  });

  const secureOrderAccountA = createTestResource({
    resourceType: 'order',
    resourceId: 'ord-secure-3003',
    ownerAccount: 'acc-user-a',
    endpointPath: '/api/fixtures/secure-orders/ord-secure-3003',
    sensitivity: 'FINANCIAL',
    expectedAuth: {
      ACCOUNT_A: 'ALLOW',
      ACCOUNT_B: 'DENY',
      UNAUTHENTICATED: 'DENY',
    },
  });

  const adminSettings = createTestResource({
    resourceType: 'admin_settings',
    resourceId: 'admin-config-global',
    ownerAccount: 'acc-admin-user',
    roleRequired: 'ADMIN_USER',
    endpointPath: '/api/fixtures/admin/settings',
    sensitivity: 'RESTRICTED_PII',
    expectedAuth: {
      STANDARD_USER: 'DENY',
      PRIVILEGED_USER: 'ALLOW',
      ADMIN_USER: 'ALLOW',
      UNAUTHENTICATED: 'DENY',
    },
  });

  const secureAdminSettings = createTestResource({
    resourceType: 'admin_settings',
    resourceId: 'admin-config-secure',
    ownerAccount: 'acc-admin-user',
    roleRequired: 'ADMIN_USER',
    endpointPath: '/api/fixtures/admin/secure-settings',
    sensitivity: 'RESTRICTED_PII',
    expectedAuth: {
      STANDARD_USER: 'DENY',
      PRIVILEGED_USER: 'ALLOW',
      ADMIN_USER: 'ALLOW',
      UNAUTHENTICATED: 'DENY',
    },
  });

  const publicCatalog = createTestResource({
    resourceType: 'catalog',
    resourceId: 'cat-public-001',
    ownerAccount: 'system',
    endpointPath: '/api/fixtures/public/catalog',
    sensitivity: 'PUBLIC',
    expectedAuth: {
      ACCOUNT_A: 'ALLOW',
      ACCOUNT_B: 'ALLOW',
      UNAUTHENTICATED: 'ALLOW',
    },
  });

  const privateProfile = createTestResource({
    resourceType: 'profile',
    resourceId: 'prof-user-a-101',
    ownerAccount: 'acc-user-a',
    endpointPath: '/api/fixtures/private/profile',
    sensitivity: 'RESTRICTED_PII',
    expectedAuth: {
      ACCOUNT_A: 'ALLOW',
      ACCOUNT_B: 'DENY',
      UNAUTHENTICATED: 'DENY',
    },
  });

  const securePrivateProfile = createTestResource({
    resourceType: 'profile',
    resourceId: 'prof-secure-user-a-102',
    ownerAccount: 'acc-user-a',
    endpointPath: '/api/fixtures/private/secure-profile',
    sensitivity: 'RESTRICTED_PII',
    expectedAuth: {
      ACCOUNT_A: 'ALLOW',
      ACCOUNT_B: 'DENY',
      UNAUTHENTICATED: 'DENY',
    },
  });

  return {
    contexts: {
      accountA,
      accountB,
      standardUser,
      privilegedUser,
      unauthenticated,
    },
    resources: {
      orderAccountA,
      orderAccountB,
      secureOrderAccountA,
      adminSettings,
      secureAdminSettings,
      publicCatalog,
      privateProfile,
      securePrivateProfile,
    },
  };
}

/**
 * Deterministic Mock Response Dispatcher
 * Simulates real HTTP server behavior for authorization fixtures without external network I/O.
 */
export function dispatchLocalFixtureRequest(params: {
  endpoint: string;
  method: string;
  context: AuthContext;
  resource?: ResourceModel;
  parameters?: Record<string, any>;
}): DifferentialExecutionSnapshot {
  const start = Date.now();
  const { endpoint, method, context } = params;
  const path = endpoint.toLowerCase();

  // 1. /api/fixtures/orders/:orderId (VULNERABLE BOLA Endpoint)
  // Flaw: returns order data regardless of which user calls it (no owner check)
  if (path.includes('/api/fixtures/orders/')) {
    if (context.authState === 'UNAUTHENTICATED') {
      return {
        statusCode: 401,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Unauthorized: Authentication required' },
        responseTimeMs: Date.now() - start + 2,
        observedAuth: 'DENY',
        errorDetected: true,
        errorMessage: 'Unauthorized',
      };
    }

    // Vulnerable: Returns Account A order details even when called by Account B
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        orderId: 'ord-1001-account-a',
        ownerAccount: 'acc-user-a',
        customerName: 'Ayush Researcher',
        email: 'ayush.research@example.com',
        phoneNumber: '+91-9876543210',
        shippingAddress: '123 Test Boulevard, Bangalore, Karnataka, India',
        totalAmount: '₹4,599.00',
        paymentMethod: 'UPI / HDFC Bank Account',
        items: [{ sku: 'MEESHO-SKU-9921', name: 'Cotton Kurti Set', price: '₹4,599.00' }],
        privateNotes: 'Confidential customer order notes',
      },
      responseTimeMs: Date.now() - start + 4,
      observedAuth: 'ALLOW',
      errorDetected: false,
    };
  }

  // 2. /api/fixtures/secure-orders/:orderId (SECURE BOLA Endpoint)
  // Properly checks ownership: caller must match order.ownerAccount
  if (path.includes('/api/fixtures/secure-orders/')) {
    if (context.authState === 'UNAUTHENTICATED') {
      return {
        statusCode: 401,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Unauthorized' },
        responseTimeMs: Date.now() - start + 2,
        observedAuth: 'DENY',
        errorDetected: true,
      };
    }

    if (context.accountIdentifier !== 'acc-user-a') {
      // Secure: rejects Account B with 403 Forbidden
      return {
        statusCode: 403,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Forbidden: You do not have permission to view this order' },
        responseTimeMs: Date.now() - start + 3,
        observedAuth: 'DENY',
        errorDetected: true,
        errorMessage: 'Forbidden',
      };
    }

    // Authorized owner gets 200 OK
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        orderId: 'ord-secure-3003',
        ownerAccount: 'acc-user-a',
        totalAmount: '₹1,299.00',
      },
      responseTimeMs: Date.now() - start + 3,
      observedAuth: 'ALLOW',
      errorDetected: false,
    };
  }

  // 3. /api/fixtures/admin/settings (VULNERABLE VERTICAL ESCALATION Endpoint)
  // Flaw: Allows STANDARD_USER to access admin config
  if (path.includes('/api/fixtures/admin/settings')) {
    if (context.authState === 'UNAUTHENTICATED') {
      return {
        statusCode: 401,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Unauthorized' },
        responseTimeMs: Date.now() - start + 2,
        observedAuth: 'DENY',
        errorDetected: true,
      };
    }

    // Vulnerable: Standard user receives admin configuration
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        adminSettings: {
          systemConfig: 'active',
          allowRegistration: true,
          internalComments: 'Superuser debugging mode enabled',
          adminSecretKey: 'redacted-ref',
        },
      },
      responseTimeMs: Date.now() - start + 3,
      observedAuth: 'ALLOW',
      errorDetected: false,
    };
  }

  // 4. /api/fixtures/admin/secure-settings (SECURE VERTICAL ESCALATION Endpoint)
  if (path.includes('/api/fixtures/admin/secure-settings')) {
    if (context.accountRole !== 'ADMIN_USER') {
      return {
        statusCode: 403,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Forbidden: Requires ADMIN_USER role' },
        responseTimeMs: Date.now() - start + 2,
        observedAuth: 'DENY',
        errorDetected: true,
        errorMessage: 'Forbidden',
      };
    }

    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: { adminSettings: { status: 'secure_ok' } },
      responseTimeMs: Date.now() - start + 2,
      observedAuth: 'ALLOW',
      errorDetected: false,
    };
  }

  // 5. /api/fixtures/public/catalog (INTENTIONALLY PUBLIC Endpoint)
  if (path.includes('/api/fixtures/public/catalog')) {
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        catalog: [
          { id: 'cat-item-1', name: 'Printed Saree', price: '₹499.00' },
          { id: 'cat-item-2', name: 'Cotton Shirt', price: '₹349.00' },
        ],
      },
      responseTimeMs: Date.now() - start + 2,
      observedAuth: 'ALLOW',
      errorDetected: false,
    };
  }

  // 6. /api/fixtures/private/profile (VULNERABLE UNAUTHENTICATED Endpoint)
  if (path.includes('/api/fixtures/private/profile')) {
    // Flaw: Returns PII even to unauthenticated requests
    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: {
        userId: 'prof-user-a-101',
        email: 'victim.user@example.com',
        phoneNumber: '+91-9988776655',
        shippingAddress: '456 MG Road, Bangalore',
      },
      responseTimeMs: Date.now() - start + 2,
      observedAuth: 'ALLOW',
      errorDetected: false,
    };
  }

  // 7. /api/fixtures/private/secure-profile (SECURE UNAUTHENTICATED Endpoint)
  if (path.includes('/api/fixtures/private/secure-profile')) {
    if (context.authState === 'UNAUTHENTICATED') {
      return {
        statusCode: 401,
        contentType: 'application/json',
        responseHeaders: { 'content-type': 'application/json' },
        responseBody: { error: 'Authentication required' },
        responseTimeMs: Date.now() - start + 2,
        observedAuth: 'DENY',
        errorDetected: true,
      };
    }

    return {
      statusCode: 200,
      contentType: 'application/json',
      responseHeaders: { 'content-type': 'application/json' },
      responseBody: { profileId: 'prof-secure-user-a-102', status: 'active' },
      responseTimeMs: Date.now() - start + 2,
      observedAuth: 'ALLOW',
      errorDetected: false,
    };
  }

  // Default fallback
  return {
    statusCode: 404,
    contentType: 'application/json',
    responseHeaders: { 'content-type': 'application/json' },
    responseBody: { error: 'Not Found' },
    responseTimeMs: Date.now() - start + 1,
    observedAuth: 'DENY',
    errorDetected: true,
  };
}
