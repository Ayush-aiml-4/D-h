import {
  ResourceModel,
  ResourceSensitivity,
  AuthContext,
  HttpMethod,
} from '../../types/authorizationResearch.ts';
import { BadRequestError } from '../../utils/errors.ts';

export function validateResourceModel(resource: ResourceModel): void {
  if (!resource.resourceType) {
    throw new BadRequestError('INVALID_RESOURCE_MODEL: resourceType is required');
  }
  if (!resource.resourceId) {
    throw new BadRequestError('INVALID_RESOURCE_MODEL: resourceId is required');
  }
  if (!resource.ownerAccount) {
    throw new BadRequestError('INVALID_RESOURCE_MODEL: ownerAccount is required');
  }
  if (!resource.endpointPath) {
    throw new BadRequestError('INVALID_RESOURCE_MODEL: endpointPath is required');
  }
  if (!resource.httpMethod) {
    throw new BadRequestError('INVALID_RESOURCE_MODEL: httpMethod is required');
  }
  if (!resource.sensitivity) {
    throw new BadRequestError('INVALID_RESOURCE_MODEL: sensitivity is required');
  }
  if (!resource.expectedAuthorization || typeof resource.expectedAuthorization !== 'object') {
    throw new BadRequestError('INVALID_RESOURCE_MODEL: expectedAuthorization matrix is required');
  }
}

/**
 * Resolves the expected authorization decision ('ALLOW' | 'DENY') for a given context and resource.
 */
export function getExpectedAuthorization(
  resource: ResourceModel,
  context: AuthContext
): 'ALLOW' | 'DENY' {
  // 1. Direct match on context label (e.g. 'ACCOUNT_A', 'ACCOUNT_B', 'UNAUTHENTICATED')
  if (resource.expectedAuthorization[context.contextLabel]) {
    return resource.expectedAuthorization[context.contextLabel];
  }

  // 2. Direct match on role (e.g. 'STANDARD_USER', 'ADMIN_USER')
  if (resource.expectedAuthorization[context.accountRole]) {
    return resource.expectedAuthorization[context.accountRole];
  }

  // 3. Direct match on account identifier
  if (resource.expectedAuthorization[context.accountIdentifier]) {
    return resource.expectedAuthorization[context.accountIdentifier];
  }

  // 4. Default logic based on ownership: If context owns resource and is authenticated -> ALLOW, else -> DENY
  if (context.authState === 'AUTHENTICATED' && context.accountIdentifier === resource.ownerAccount) {
    return 'ALLOW';
  }

  // 5. Default: fail-closed to DENY
  return 'DENY';
}

/**
 * Helper to construct standard resource definitions
 */
export function createTestResource(params: {
  resourceType: string;
  resourceId: string;
  ownerAccount: string;
  endpointPath: string;
  httpMethod?: HttpMethod;
  sensitivity?: ResourceSensitivity;
  roleRequired?: string;
  expectedAuth?: Record<string, 'ALLOW' | 'DENY'>;
  parameters?: Record<string, any>;
}): ResourceModel {
  const sensitivity = params.sensitivity || 'CONFIDENTIAL';
  const expectedAuth = params.expectedAuth || {
    ACCOUNT_A: 'ALLOW',
    ACCOUNT_B: 'DENY',
    UNAUTHENTICATED: 'DENY',
    STANDARD_USER: params.ownerAccount === 'acc-standard-user-01' ? 'ALLOW' : 'DENY',
    ADMIN_USER: 'ALLOW',
  };

  const resource: ResourceModel = {
    resourceType: params.resourceType,
    resourceId: params.resourceId,
    ownerAccount: params.ownerAccount,
    roleRequired: params.roleRequired as any,
    endpointPath: params.endpointPath,
    httpMethod: params.httpMethod || 'GET',
    expectedAuthorization: expectedAuth,
    sensitivity,
    parameters: params.parameters,
  };

  validateResourceModel(resource);
  return resource;
}
