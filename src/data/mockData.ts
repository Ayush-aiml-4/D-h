import { Program, Hunt, Finding, Report, AssetNode, HistorySession, UserProfile } from '../types';

export const initialProfile: UserProfile = {
  name: 'AYUSH',
  role: 'Lead Security Researcher',
  bountyTotal: '₹42,500',
  paidBounty: '₹25,000',
  pendingBounty: '₹17,500',
  potentialBounty: '₹42,500',
  activeHunts: 3,
  verifiedBugs: 7,
  submittedReports: 9,
  isDemoMode: true,
};

export const initialPrograms: Program[] = [
  {
    id: 'prog-acme-01',
    name: 'Acme Security Program',
    organization: 'Acme Corp Security',
    targetCount: 12,
    scopeStatus: 'In Scope (12 Assets)',
    rulesLoaded: true,
    rewardMax: '$10,000',
    lastHunt: '2 hours ago',
    status: 'Active',
    description: 'Core web applications, public REST APIs, and authentication microservices under authorized bug bounty.',
    targets: ['acme-security.test', 'api.acme-security.test', 'auth.acme-security.test', 'admin.acme-security.test'],
    rulesAllowed: [
      'Web application security testing',
      'API endpoint testing & authorization verification',
      'Authentication state and JWT validation',
      'Row-level access control & IDOR verification'
    ],
    rulesBlocked: [
      'Denial of Service (DoS / DDoS) testing',
      'Social engineering or phishing against staff',
      'Physical office security or facility testing',
      'Third-party cloud infrastructure modifications'
    ]
  },
  {
    id: 'prog-nexus-02',
    name: 'Nexus Payment Infrastructure',
    organization: 'Nexus Financial Systems',
    targetCount: 8,
    scopeStatus: 'In Scope (8 Assets)',
    rulesLoaded: true,
    rewardMax: '$15,000',
    lastHunt: '1 day ago',
    status: 'Active',
    description: 'High-assurance payment gateways, webhook ingestion engines, and merchant portal API suites.',
    targets: ['nexus-pay.dev', 'checkout.nexus-pay.dev', 'api.nexus-pay.dev'],
    rulesAllowed: [
      'Payment API payload validation',
      'Webhook signature integrity checks',
      'OAuth token delegation testing'
    ],
    rulesBlocked: [
      'Automated brute forcing over 100 req/min',
      'Transaction settlement manipulation on live testnets',
      'Customer support social engineering'
    ]
  },
  {
    id: 'prog-starlight-03',
    name: 'Starlight Cloud Vault',
    organization: 'Starlight Storage Labs',
    targetCount: 18,
    scopeStatus: 'In Scope (18 Assets)',
    rulesLoaded: true,
    rewardMax: '$8,500',
    lastHunt: '3 days ago',
    status: 'Active',
    description: 'Encrypted object store, presigned URL generators, and tenant segregation controls.',
    targets: ['starlight-cloud.test', 'vault-api.starlight-cloud.test'],
    rulesAllowed: [
      'Presigned URL signature expiry checks',
      'Access control policy verification',
      'Cross-origin resource sharing (CORS) validation'
    ],
    rulesBlocked: [
      'Exfiltration of test bucket data exceeding 1MB',
      'Storage cluster resource exhaustion'
    ]
  }
];

export const initialHunts: Hunt[] = [
  {
    id: 'hunt-101',
    programId: 'prog-acme-01',
    programName: 'Acme Security Program',
    targetDomain: 'api.acme-security.test',
    scopeCount: 12,
    status: 'Hunting',
    startedAt: '18 minutes ago',
    progressPercent: 72,
    currentTask: 'Validating tenant boundary header checks on /v2/transact',
    potentialFindingsCount: 0,
    verifiedFindingsCount: 2,
    policyViolationsCount: 0,
    steps: [
      { id: 'step-1', name: 'Reconnaissance', status: 'done' },
      { id: 'step-2', name: 'Target Mapping', status: 'done' },
      { id: 'step-3', name: 'API Discovery', status: 'done' },
      { id: 'step-4', name: 'Page Analysis', status: 'done' },
      { id: 'step-5', name: 'Security Checks', status: 'active', progress: 72 },
      { id: 'step-6', name: 'Evidence Validation', status: 'active', progress: 31 }
    ],
    liveLogs: [
      'Initialized policy enforcer with 4 allowed testing vectors and 4 restrictions',
      'Mapped 34 endpoint signatures on api.acme-security.test',
      'Checking authorization state on tenant headers...',
      'Mapping API endpoints across /v1 and /v2 namespaces...',
      'Reviewing application behavior during role escalation attempts...',
      'Validating potential finding: Broken Access Control on /v2/transact...'
    ]
  },
  {
    id: 'hunt-102',
    programId: 'prog-nexus-02',
    programName: 'Nexus Payment Infrastructure',
    targetDomain: 'checkout.nexus-pay.dev',
    scopeCount: 8,
    status: 'Analyzing',
    startedAt: '1 hour ago',
    progressPercent: 91,
    currentTask: 'Analyzing GraphQL query depth limits & schema reflection',
    potentialFindingsCount: 1,
    verifiedFindingsCount: 1,
    policyViolationsCount: 0,
    steps: [
      { id: 'step-1', name: 'Reconnaissance', status: 'done' },
      { id: 'step-2', name: 'Target Mapping', status: 'done' },
      { id: 'step-3', name: 'API Discovery', status: 'done' },
      { id: 'step-4', name: 'Page Analysis', status: 'done' },
      { id: 'step-5', name: 'Security Checks', status: 'done' },
      { id: 'step-6', name: 'Evidence Validation', status: 'active', progress: 85 }
    ],
    liveLogs: [
      'Scope verified: checkout.nexus-pay.dev is within authorized program rules',
      'Discovered GraphQL endpoint /graphql with Introspection enabled',
      'Testing object depth limit rules (Policy limit: <= 5 levels)',
      'Verified finding: GraphQL Introspection & Schema Exposure',
      'Identified potential finding: Unrestricted Password Reset Rate Limit'
    ]
  },
  {
    id: 'hunt-103',
    programId: 'prog-starlight-03',
    programName: 'Starlight Cloud Vault',
    targetDomain: 'vault-auth.starlight-cloud.test',
    scopeCount: 18,
    status: 'Ready',
    startedAt: 'Not started',
    progressPercent: 0,
    currentTask: 'Standing by for researcher initiation command',
    potentialFindingsCount: 0,
    verifiedFindingsCount: 0,
    policyViolationsCount: 0,
    steps: [
      { id: 'step-1', name: 'Reconnaissance', status: 'pending' },
      { id: 'step-2', name: 'Target Mapping', status: 'pending' },
      { id: 'step-3', name: 'API Discovery', status: 'pending' },
      { id: 'step-4', name: 'Page Analysis', status: 'pending' },
      { id: 'step-5', name: 'Security Checks', status: 'pending' },
      { id: 'step-6', name: 'Evidence Validation', status: 'pending' }
    ],
    liveLogs: [
      'Hunt configured and locked to starlight-cloud.test scope rules',
      'Awaiting manual launch trigger'
    ]
  },
  {
    id: 'hunt-104',
    programId: 'prog-starlight-03',
    programName: 'Starlight Cloud Vault',
    targetDomain: 'starlight-cloud.test',
    scopeCount: 18,
    status: 'Completed',
    startedAt: '3 days ago',
    progressPercent: 100,
    currentTask: 'Research session completed & archived',
    potentialFindingsCount: 0,
    verifiedFindingsCount: 1,
    policyViolationsCount: 0,
    steps: [
      { id: 'step-1', name: 'Reconnaissance', status: 'done' },
      { id: 'step-2', name: 'Target Mapping', status: 'done' },
      { id: 'step-3', name: 'API Discovery', status: 'done' },
      { id: 'step-4', name: 'Page Analysis', status: 'done' },
      { id: 'step-5', name: 'Security Checks', status: 'done' },
      { id: 'step-6', name: 'Evidence Validation', status: 'done' }
    ],
    liveLogs: [
      'Scope verified: starlight-cloud.test',
      'Checked CORS policies across endpoints',
      'Identified Insecure CORS Wildcard Policy',
      'Session completed successfully'
    ]
  }
];

export const initialFindings: Finding[] = [
  {
    id: 'find-801',
    huntId: 'hunt-101',
    programName: 'Acme Security Program',
    title: 'Broken Access Control',
    category: 'Authorization',
    severity: 'High',
    confidence: 94,
    target: 'api.acme-security.test',
    status: 'Verified',
    whatWeFound: 'A user may be able to access data belonging to another account by modifying tenant identification headers.',
    whyItMatters: 'Cross-tenant authorization check failure permits authenticated users to read transactions of arbitrary organizations.',
    affectedTarget: 'api.acme-security.test/v2/transact',
    evidence: {
      requestMethod: 'GET',
      requestUrl: 'https://api.acme-security.test/v2/transact?org_id=99421',
      requestHeaders: {
        'Host': 'api.acme-security.test',
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.user_token_A',
        'X-Tenant-Override': 'ORG_99421',
        'User-Agent': 'DevilHunt-Security-Auditor/1.0'
      },
      responseStatus: 200,
      responseHeaders: {
        'Content-Type': 'application/json',
        'X-Tenant-Verified': 'ORG_99421'
      },
      responseBodySnippet: JSON.stringify({
        status: "success",
        data: {
          transaction_id: "tx_99881122",
          amount: 45000,
          currency: "USD",
          owner_organization: "ORG_99421",
          sensitive_notes: "Wire transfer reference #9011"
        }
      }, null, 2),
      timestamp: '2026-08-11T07:45:12Z',
      validationStatus: 'Automated reproduction verified with 0 policy breaches',
      proofHash: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    },
    policyCheck: {
      inScope: true,
      testPermitted: true,
      validationCompleted: true,
      noRestrictedAction: true
    },
    recommendedFix: 'Validate that the tenant identifier in `X-Tenant-Override` strictly matches the token claims extracted from the verified `Authorization` JWT server-side before executing SQL queries.',
    createdAt: '2026-08-11 07:45'
  },
  {
    id: 'find-802',
    huntId: 'hunt-102',
    programName: 'Nexus Payment Infrastructure',
    title: 'Unrestricted Password Reset Rate Limit',
    category: 'Rate Limiting & Authentication',
    severity: 'Medium',
    confidence: 88,
    target: 'checkout.nexus-pay.dev',
    status: 'Needs review',
    whatWeFound: 'Password reset request endpoint accepts multiple consecutive requests without enforcing rate limits or exponential delay.',
    whyItMatters: 'Allows potential automated request flooding or email verification code enumeration.',
    affectedTarget: 'checkout.nexus-pay.dev/api/v1/reset-password',
    evidence: {
      requestMethod: 'POST',
      requestUrl: 'https://checkout.nexus-pay.dev/api/v1/reset-password',
      requestHeaders: {
        'Host': 'checkout.nexus-pay.dev',
        'Content-Type': 'application/json'
      },
      requestBody: '{"email":"target_user@example.test"}',
      responseStatus: 200,
      responseHeaders: {
        'Content-Type': 'application/json'
      },
      responseBodySnippet: JSON.stringify({
        message: "Reset email dispatched",
        attempt: 15
      }, null, 2),
      timestamp: '2026-08-11T06:20:00Z',
      validationStatus: 'Passive rate observation confirmed',
      proofHash: 'sha256:8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4'
    },
    policyCheck: {
      inScope: true,
      testPermitted: true,
      validationCompleted: true,
      noRestrictedAction: true
    },
    recommendedFix: 'Implement Redis token-bucket rate limiting based on IP address and target email key (e.g. max 3 attempts per 15 minutes).',
    createdAt: '2026-08-11 06:20'
  },
  {
    id: 'find-803',
    huntId: 'hunt-101',
    programName: 'Acme Security Program',
    title: 'IDOR in User Profile Metadata Export',
    category: 'Insecure Direct Object Reference',
    severity: 'High',
    confidence: 96,
    target: 'api.acme-security.test',
    status: 'Verified',
    whatWeFound: 'Submitting a data export request with an arbitrary target UUID returns private metadata payload without authorization checking.',
    whyItMatters: 'Enables unauthorized exfiltration of customer metadata records across the user directory.',
    affectedTarget: 'api.acme-security.test/v1/export-data',
    evidence: {
      requestMethod: 'POST',
      requestUrl: 'https://api.acme-security.test/v1/export-data',
      requestHeaders: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.standard_user'
      },
      requestBody: '{"target_user_uuid": "usr_7720911-diff"}',
      responseStatus: 200,
      responseHeaders: {
        'Content-Type': 'application/json'
      },
      responseBodySnippet: JSON.stringify({
        status: "complete",
        export_url: "https://static.acme-security.test/exports/usr_7720911-diff.json",
        user_email: "victim@acme-security.test"
      }, null, 2),
      timestamp: '2026-08-10T19:30:00Z',
      validationStatus: 'Single request validation executed cleanly',
      proofHash: 'sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531caacdabf8a'
    },
    policyCheck: {
      inScope: true,
      testPermitted: true,
      validationCompleted: true,
      noRestrictedAction: true
    },
    recommendedFix: 'Enforce strict session identity check matching `target_user_uuid` against `request.user.id` in server-side authorization middleware.',
    createdAt: '2026-08-10 19:30'
  },
  {
    id: 'find-804',
    huntId: 'hunt-102',
    programName: 'Nexus Payment Infrastructure',
    title: 'GraphQL Introspection & Schema Exposure',
    category: 'Information Disclosure',
    severity: 'Low',
    confidence: 92,
    target: 'checkout.nexus-pay.dev',
    status: 'Verified',
    whatWeFound: 'GraphQL endpoint exposes full schema introspection query responses to unauthenticated callers.',
    whyItMatters: 'Reveals internal query structures, field definitions, and hidden mutations to potential adversaries.',
    affectedTarget: 'checkout.nexus-pay.dev/graphql',
    evidence: {
      requestMethod: 'POST',
      requestUrl: 'https://checkout.nexus-pay.dev/graphql',
      requestHeaders: {
        'Content-Type': 'application/json'
      },
      requestBody: '{"query": "{ __schema { queryType { name } } }"}',
      responseStatus: 200,
      responseHeaders: {
        'Content-Type': 'application/json'
      },
      responseBodySnippet: JSON.stringify({
        data: {
          __schema: {
            queryType: { name: "RootQueryType" }
          }
        }
      }, null, 2),
      timestamp: '2026-08-10T14:10:00Z',
      validationStatus: 'Schema response confirmed',
      proofHash: 'sha256:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b'
    },
    policyCheck: {
      inScope: true,
      testPermitted: true,
      validationCompleted: true,
      noRestrictedAction: true
    },
    recommendedFix: 'Disable GraphQL introspection in production builds (`introspection: false` in server configuration).',
    createdAt: '2026-08-10 14:10'
  },
  {
    id: 'find-805',
    huntId: 'hunt-104',
    programName: 'Starlight Cloud Vault',
    title: 'Insecure CORS Wildcard Policy',
    category: 'Security Misconfiguration',
    severity: 'Medium',
    confidence: 95,
    target: 'starlight-cloud.test',
    status: 'Resolved',
    whatWeFound: 'Cloud Vault API returns `Access-Control-Allow-Origin: *` with credentials enabled on storage endpoints.',
    whyItMatters: 'Allows arbitrary external websites to read private bucket responses if users visit malicious domains.',
    affectedTarget: 'starlight-cloud.test/vault-api',
    evidence: {
      requestMethod: 'OPTIONS',
      requestUrl: 'https://vault-api.starlight-cloud.test/v1/buckets',
      requestHeaders: {
        'Origin': 'https://evil-attacker.test'
      },
      responseStatus: 200,
      responseHeaders: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true'
      },
      responseBodySnippet: 'OK',
      timestamp: '2026-08-08T11:00:00Z',
      validationStatus: 'Header configuration verified',
      proofHash: 'sha256:9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e'
    },
    policyCheck: {
      inScope: true,
      testPermitted: true,
      validationCompleted: true,
      noRestrictedAction: true
    },
    recommendedFix: 'Replace wildcard CORS header with strict whitelist validation against authorized Starlight origins.',
    createdAt: '2026-08-08 11:00'
  }
];

export const initialReports: Report[] = [
  {
    id: 'rep-901',
    findingId: 'find-801',
    programName: 'Acme Security Program',
    title: 'Broken Access Control on Tenant Header in /v2/transact',
    severity: 'High',
    researcher: 'Ayush (DevilHunt Security)',
    target: 'api.acme-security.test',
    status: 'Ready',
    summary: 'An authorized security review of api.acme-security.test identified a high-severity Broken Access Control vulnerability. The /v2/transact endpoint accepts caller-controlled tenant headers without checking token claim boundaries.',
    impact: 'An authenticated attacker holding a valid account can specify arbitrary organization IDs in headers and retrieve sensitive financial transaction records across tenants.',
    technicalDetails: 'During API endpoint testing, GET requests sent to /v2/transact were augmented with X-Tenant-Override headers. The server backend responded with HTTP 200 OK and populated tenant payload data belonging to the requested organization ID, bypassing standard tenancy boundaries.',
    evidenceSnippet: 'GET /v2/transact?org_id=99421 HTTP/1.1\nHost: api.acme-security.test\nX-Tenant-Override: ORG_99421\nAuthorization: Bearer <valid_token_A>\n\nHTTP/1.1 200 OK\n{"status":"success", "data":{"owner_organization":"ORG_99421", "amount": 45000}}',
    reproductionSteps: [
      'Authenticate as standard User A belonging to Org 1001.',
      'Construct GET request to https://api.acme-security.test/v2/transact?org_id=99421',
      'Add header X-Tenant-Override: ORG_99421',
      'Observe server returning transaction records belonging to ORG_99421.'
    ],
    recommendedFix: 'Ensure server middleware extracts tenant claim from the signature-verified JWT token and discards untrusted client headers.',
    testingPolicy: 'Testing was performed strictly within program guidelines. No DoS, destructive queries, or data exfiltration beyond proof of concept occurred.',
    timeline: [
      { date: '2026-08-11 07:15', action: 'Hunt started on api.acme-security.test' },
      { date: '2026-08-11 07:45', action: 'Finding identified & automatically verified by DevilHunt' },
      { date: '2026-08-11 08:00', action: 'Report prepared for responsible disclosure' }
    ],
    createdAt: '2026-08-11',
    recipientContact: 'security@acme-security.test'
  },
  {
    id: 'rep-902',
    findingId: 'find-803',
    programName: 'Acme Security Program',
    title: 'IDOR in Profile Export API Endpoint',
    severity: 'High',
    researcher: 'Ayush (DevilHunt Security)',
    target: 'api.acme-security.test',
    status: 'Submitted',
    summary: 'Submitting a data export request with an arbitrary target UUID returns unredacted metadata payload.',
    impact: 'Cross-user data leakage.',
    technicalDetails: 'The /v1/export-data endpoint fails to authorize target_user_uuid parameter.',
    evidenceSnippet: 'POST /v1/export-data\n{"target_user_uuid": "usr_7720911-diff"}',
    reproductionSteps: [
      'Log into standard account',
      'Send POST request to /v1/export-data with secondary UUID',
      'Observe export link generated for target user'
    ],
    recommendedFix: 'Restrict target UUID parameter to match authenticated session context.',
    testingPolicy: 'Scope policy strictly enforced.',
    timeline: [
      { date: '2026-08-10 19:30', action: 'Finding confirmed' },
      { date: '2026-08-10 20:10', action: 'Submitted to security team' }
    ],
    createdAt: '2026-08-10',
    recipientContact: 'security@acme-security.test'
  },
  {
    id: 'rep-903',
    findingId: 'find-804',
    programName: 'Nexus Payment Infrastructure',
    title: 'GraphQL Schema Exposure & Introspection Enabled',
    severity: 'Low',
    researcher: 'Ayush (DevilHunt Security)',
    target: 'checkout.nexus-pay.dev',
    status: 'Submitted',
    summary: 'GraphQL endpoint checkout.nexus-pay.dev/graphql exposes full schema introspection query responses to unauthenticated callers.',
    impact: 'Enables schema discovery and internal endpoint mapping for potential attackers.',
    technicalDetails: 'POST request to /graphql with __schema query returns full object hierarchy.',
    evidenceSnippet: 'POST /graphql\n{"query": "{ __schema { queryType { name } } }"}',
    reproductionSteps: [
      'Send POST request to https://checkout.nexus-pay.dev/graphql',
      'Include GraphQL introspection query body',
      'Observe server returning full schema metadata'
    ],
    recommendedFix: 'Disable introspection query execution in production API gateway.',
    testingPolicy: 'Scope policy strictly enforced.',
    timeline: [
      { date: '2026-08-10 14:10', action: 'Finding verified' },
      { date: '2026-08-10 15:00', action: 'Report submitted to Nexus security portal' }
    ],
    createdAt: '2026-08-10',
    recipientContact: 'security@nexus-pay.dev'
  },
  {
    id: 'rep-904',
    findingId: 'find-805',
    programName: 'Starlight Cloud Vault',
    title: 'Wildcard CORS Origin Policy on Cloud Vault API',
    severity: 'Medium',
    researcher: 'Ayush (DevilHunt Security)',
    target: 'starlight-cloud.test',
    status: 'Resolved',
    summary: 'Cloud Vault storage API returns Access-Control-Allow-Origin: * alongside credentials support.',
    impact: 'Cross-origin data access risk.',
    technicalDetails: 'Preflight OPTIONS request returns wildcard origin headers.',
    evidenceSnippet: 'OPTIONS /v1/buckets\nAccess-Control-Allow-Origin: *',
    reproductionSteps: [
      'Send OPTIONS preflight request with Origin header set to arbitrary test domain',
      'Observe server reflecting wildcard origin permit'
    ],
    recommendedFix: 'Restrict CORS allowed origins to authorized domain origins.',
    testingPolicy: 'Scope policy strictly enforced.',
    timeline: [
      { date: '2026-08-08 11:00', action: 'Finding verified' },
      { date: '2026-08-08 12:30', action: 'Report submitted' },
      { date: '2026-08-09 16:00', action: 'Vendor validated fix and awarded bounty' }
    ],
    createdAt: '2026-08-08',
    recipientContact: 'security@starlight-cloud.test'
  }
];

export const initialAttackSurface: AssetNode = {
  id: 'node-root',
  name: 'acme-security.test',
  domain: 'acme-security.test',
  type: 'root',
  status: 'In Scope',
  endpointsCount: 42,
  techStack: ['Cloudflare', 'Nginx', 'Node.js', 'PostgreSQL'],
  children: [
    {
      id: 'node-www',
      name: 'www',
      domain: 'www.acme-security.test',
      type: 'subdomain',
      status: 'In Scope',
      endpointsCount: 14,
      techStack: ['React', 'Next.js', 'Tailwind CSS'],
      endpoints: ['/', '/about', '/pricing', '/contact', '/login']
    },
    {
      id: 'node-api',
      name: 'api',
      domain: 'api.acme-security.test',
      type: 'api',
      status: 'Flagged',
      endpointsCount: 18,
      techStack: ['Express', 'TypeScript', 'Redis', 'JWT Auth'],
      endpoints: ['/v1/health', '/v1/export-data', '/v2/transact', '/v2/users', '/v2/webhook']
    },
    {
      id: 'node-auth',
      name: 'auth',
      domain: 'auth.acme-security.test',
      type: 'auth',
      status: 'Analyzed',
      endpointsCount: 6,
      techStack: ['OAuth 2.0', 'OIDC', 'Golang'],
      endpoints: ['/oauth/token', '/oauth/authorize', '/reset-password', '/verify-mfa']
    },
    {
      id: 'node-admin',
      name: 'admin',
      domain: 'admin.acme-security.test',
      type: 'admin',
      status: 'In Scope',
      endpointsCount: 3,
      techStack: ['Internal Portal', 'IP Restricted'],
      endpoints: ['/admin/login', '/admin/metrics']
    },
    {
      id: 'node-static',
      name: 'static',
      domain: 'static.acme-security.test',
      type: 'static',
      status: 'In Scope',
      endpointsCount: 1,
      techStack: ['AWS S3', 'CloudFront CDN'],
      endpoints: ['/assets/', '/exports/']
    }
  ]
};

export const initialHistory: HistorySession[] = [
  {
    id: 'hist-001',
    huntId: 'hunt-101',
    programName: 'Acme Security Program',
    target: 'api.acme-security.test',
    date: '2026-08-11',
    duration: '42 mins',
    potentialFindings: 0,
    verifiedFindings: 2,
    reportStatus: 'Ready',
    bountyEarned: '₹0'
  },
  {
    id: 'hist-002',
    huntId: 'hunt-102',
    programName: 'Nexus Payment Infrastructure',
    target: 'checkout.nexus-pay.dev',
    date: '2026-08-10',
    duration: '1 hr 15 mins',
    potentialFindings: 1,
    verifiedFindings: 1,
    reportStatus: 'Submitted',
    bountyEarned: '₹17,500'
  },
  {
    id: 'hist-003',
    huntId: 'hunt-104',
    programName: 'Starlight Cloud Vault',
    target: 'starlight-cloud.test',
    date: '2026-08-08',
    duration: '35 mins',
    potentialFindings: 0,
    verifiedFindings: 1,
    reportStatus: 'Resolved',
    bountyEarned: '₹25,000'
  },
  {
    id: 'hist-004',
    huntId: 'hunt-103',
    programName: 'Starlight Cloud Vault',
    target: 'vault-auth.starlight-cloud.test',
    date: '2026-08-05',
    duration: '15 mins',
    potentialFindings: 0,
    verifiedFindings: 0,
    reportStatus: 'Draft',
    bountyEarned: '₹0'
  }
];
