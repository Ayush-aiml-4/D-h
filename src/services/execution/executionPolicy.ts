import { AuthUser } from '../../middleware/auth.ts';
import { ExecutionPolicy, AuthorizationLevel, ExecutionApproval } from './types.ts';
import { ForbiddenError } from '../../utils/errors.ts';

export const CAPABILITY_EXECUTION_POLICIES: Record<string, ExecutionPolicy> = {
  // 1. HTTP / Web Security
  'cap-http-header-analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'HTTP response header inspection for security controls',
  },
  'cap-csp-audit': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Content Security Policy analysis',
  },
  'cap-cors-policy-audit': {
    authorizationLevel: 'LOW_RISK',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 30,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Cross-Origin Resource Sharing policy check',
  },
  'cap-http-methods-analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'HTTP method and verb analysis',
  },
  'cap-redirect-chain-analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'HTTP redirect chain and upgrade analysis',
  },
  'cap-cache-control-analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Cache-Control and caching preconditions analysis',
  },
  'cap-mime-sniffing-analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'MIME sniffing and nosniff protection audit',
  },
  'cap-cross-origin-policies': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Cross-Origin isolation policies (COOP, COEP, CORP) audit',
  },

  // 2. TLS / Transport Security
  'cap-tls-ssl-audit': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['https:'],
    allowNetworkAccess: true,
    description: 'TLS configuration and cipher audit',
  },
  'cap-hsts-audit': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'HSTS & Transport Security Audit',
  },
  'cap-cert-expiration-analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['https:'],
    allowNetworkAccess: true,
    description: 'TLS certificate validity and SAN hostname coverage audit',
  },
  'cap-http-to-https-redirect': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'HTTP to HTTPS upgrade transition audit',
  },

  // 3. DNS / Domain Intelligence
  'cap-dns-records-observation': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: false,
    description: 'DNS Authoritative records observation',
  },
  'cap-subdomain-enum': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: false,
    description: 'In-scope subdomain relationship mapping',
  },
  'cap-caa-dnssec-observation': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: false,
    description: 'CAA and DNSSEC presence observation',
  },
  'cap-dangling-cname-indicator': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: false,
    description: 'Dangling CNAME and cloud pointer indicator',
  },

  // 4. API Security Assessment
  'cap-api-schema-mapping': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'API schema and endpoint mapping',
  },
  'cap-graphql-introspection': {
    authorizationLevel: 'LOW_RISK',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 30,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'GraphQL introspection query check',
  },
  'cap-api-error-disclosure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'API error response and stack trace disclosure analysis',
  },
  'cap-openapi-doc-exposure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'OpenAPI and Swagger specification file exposure',
  },

  // 5. Authentication & Session Configuration
  'cap-cookie-security-audit': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Cookie attribute analysis for session flags',
  },
  'cap-jwt-structure-inspection': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: false,
    description: 'JWT structure and claims analysis',
  },
  'cap-oauth-flow-mapping': {
    authorizationLevel: 'REQUIRES_APPROVAL',
    requiresExplicitApproval: true,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 20,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'OAuth grant flow and redirect mapping',
  },
  'cap-session-timeout-indicator': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Session expiration and cache invalidation indicator',
  },

  // 6. Technology Fingerprinting
  'cap-tech-stack-fingerprint': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Technology stack and server header fingerprinting',
  },
  'cap-waf-detection': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'WAF and CDN edge infrastructure detection',
  },
  'cap-framework-header-detection': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Framework and runtime header detection',
  },

  // 7. Exposure / Metadata Analysis
  'cap-sensitive-file-exposure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Public metadata manifests (robots.txt, sitemap.xml) inspection',
  },
  'cap-debug-disclosure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Debug & Verbose Error Disclosure Detection',
  },
  'cap-directory-listing': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Directory Listing & Indexing Detection',
  },
  'cap-backup-artifact-indicator': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Backup artifact and temporary file indicator',
  },

  // 8. Client-Side Security
  'cap-source-map-exposure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'JavaScript Source Map Exposure Detection',
  },
  'cap-client-secrets-detection': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Client-side high entropy secret pattern detection',
  },
  'cap-subresource-integrity': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Subresource Integrity (SRI) tag observation',
  },

  // 9. Cloud / Infrastructure Metadata
  'cap-cloud-provider-indicator': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Cloud provider and storage domain indicator',
  },
  'cap-load-balancer-indicator': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Reverse proxy and load balancer routing headers analysis',
  },

  // 10. Content & Endpoint Analysis
  'cap-security-txt-observation': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'RFC 9116 security.txt policy observation',
  },
  'cap-rate-limit-inspection': {
    authorizationLevel: 'REQUIRES_APPROVAL',
    requiresExplicitApproval: true,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 10,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Rate limiting policy and quota inspection',
  },

  // 11. Evidence & Research Intelligence
  'cap-execution-reference': {
    authorizationLevel: 'LOW_RISK',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: false,
    description: 'Controlled execution pipeline reference capability',
  },
  'cap-asset-discovery': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: false,
    description: 'Passive asset boundary discovery from authoritative program scope',
  },

  // Aliases and Legacy Identifiers
  'security_header_analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'HTTP Security Header Analysis',
  },
  'csp_analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Content Security Policy analysis',
  },
  'hsts_analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Strict Transport Security analysis',
  },
  'cookie_security_analysis': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Cookie Security Attributes Audit',
  },
  'cors_misconfiguration': {
    authorizationLevel: 'LOW_RISK',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 30,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'CORS Policy Misconfiguration Inspection',
  },
  'debug_error_disclosure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Debug and error disclosure analysis',
  },
  'directory_listing_detection': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Directory listing detection',
  },
  'source_map_exposure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Source map exposure detection',
  },
  'cap-debug-error-disclosure': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Debug & Verbose Error Disclosure Detection',
  },
  'cap-directory-listing-detection': {
    authorizationLevel: 'PASSIVE',
    requiresExplicitApproval: false,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 60,
    allowedProtocols: ['http:', 'https:'],
    allowNetworkAccess: true,
    description: 'Directory Listing & Indexing Detection',
  },
};

export function resolveExecutionPolicy(capabilityId: string): ExecutionPolicy {
  const normId = capabilityId.trim().toLowerCase();
  if (CAPABILITY_EXECUTION_POLICIES[normId]) {
    return CAPABILITY_EXECUTION_POLICIES[normId];
  }
  // Default fallback for any other capability: require explicit approval
  return {
    authorizationLevel: 'REQUIRES_APPROVAL',
    requiresExplicitApproval: true,
    maxTimeoutMs: 5000,
    maxRequestsPerMinute: 10,
    allowedProtocols: ['https:'],
    allowNetworkAccess: false,
    description: 'Standard security research capability',
  };
}

export function evaluateExecutionApproval(
  user: AuthUser,
  policy: ExecutionPolicy,
  confirmApproval?: boolean
): ExecutionApproval {
  const nowStr = new Date().toISOString();

  if (policy.authorizationLevel === 'RESTRICTED') {
    if (user.role !== 'ADMIN') {
      throw new ForbiddenError(
        'ADMIN_APPROVAL_REQUIRED: Restricted capability execution requires administrator authorization'
      );
    }
    return {
      approved: true,
      approvedBy: user.uid,
      approvedAt: nowStr,
      approvalType: 'ADMIN_AUTHORIZATION',
      reason: 'Administrator approval granted for restricted research capability',
    };
  }

  if (policy.requiresExplicitApproval) {
    if (!confirmApproval) {
      throw new ForbiddenError(
        'EXPLICIT_APPROVAL_REQUIRED: Capability requires explicit researcher confirmation before execution'
      );
    }
    return {
      approved: true,
      approvedBy: user.uid,
      approvedAt: nowStr,
      approvalType: 'EXPLICIT_RESEARCHER_CONFIRMATION',
      reason: 'Explicit researcher execution confirmation confirmed',
    };
  }

  // Automatic low risk / passive approval
  return {
    approved: true,
    approvedBy: user.uid,
    approvedAt: nowStr,
    approvalType: 'AUTOMATIC_LOW_RISK',
    reason: 'Automatic authorization granted for passive/low-risk capability',
  };
}
