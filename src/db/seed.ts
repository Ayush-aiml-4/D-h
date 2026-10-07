import { db } from './index.ts';
import {
  users,
  programs,
  assets,
  policyRules,
  programScopes,
  discoverySessions,
  hunts,
  findings,
  reports,
  rewards,
  historySessions,
  auditEvents,
} from './schema.ts';
import { eq } from 'drizzle-orm';

export async function seedDatabase() {
  try {
    // 1. Seed Users (Ayush & Admin)
    const existingUser = await db.select().from(users).where(eq(users.uid, 'user-ayush-001'));
    if (existingUser.length === 0) {
      await db.insert(users).values({
        uid: 'user-ayush-001',
        name: 'Ayush Singh',
        email: 'ayushsingh556860@gmail.com',
        role: 'RESEARCHER',
        avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&q=80&w=150',
      });
    }

    const existingAdmin = await db.select().from(users).where(eq(users.uid, 'user-admin-001'));
    if (existingAdmin.length === 0) {
      await db.insert(users).values({
        uid: 'user-admin-001',
        name: 'DevilHunt Admin',
        email: 'admin@devilhunt.local',
        role: 'ADMIN',
      });
    }

    // 2. Seed Programs
    const existingProgs = await db.select().from(programs);
    if (existingProgs.length === 0) {
      await db.insert(programs).values([
        {
          id: 'prog-acme-01',
          name: 'Acme Security Program',
          description: 'Core web applications, public REST APIs, and authentication microservices under authorized bug bounty.',
          status: 'ACTIVE',
          rewardCeiling: '$10,000',
          rulesLoaded: true,
          policyEnforced: true,
        },
        {
          id: 'prog-nexus-02',
          name: 'Nexus Payment Infrastructure',
          description: 'High-assurance payment gateways, webhook ingestion engines, and merchant portal API suites.',
          status: 'ACTIVE',
          rewardCeiling: '$15,000',
          rulesLoaded: true,
          policyEnforced: true,
        },
        {
          id: 'prog-starlight-03',
          name: 'Starlight Cloud Vault',
          description: 'Encrypted object store, presigned URL generators, and tenant segregation controls.',
          status: 'ACTIVE',
          rewardCeiling: '$8,500',
          rulesLoaded: true,
          policyEnforced: true,
        },
      ]);
    }

    // 3. Seed Assets (Targets)
    const seedAssetList = [
      // Acme Security Program Root & Subdomains
      {
        id: 'asset-acme-root',
        programId: 'prog-acme-01',
        scopeId: 'scope-acme-108',
        domain: 'acme-security.test',
        type: 'DOMAIN',
        hostname: 'acme-security.test',
        url: 'https://acme-security.test',
        path: '/',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'Nginx / Cloudflare DNS',
        endpointCount: 1,
        discoverySource: 'SEED_POLICY_SCOPE',
        confidence: 100,
      },
      {
        id: 'asset-101',
        programId: 'prog-acme-01',
        scopeId: 'scope-acme-101',
        parentAssetId: 'asset-acme-root',
        domain: 'api.acme-security.test',
        type: 'SUBDOMAIN',
        hostname: 'api.acme-security.test',
        url: 'https://api.acme-security.test',
        path: '/',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'Node.js Express / GraphQL',
        endpointCount: 34,
        discoverySource: 'AUTHORIZED_DISCOVERY',
        confidence: 100,
      },
      {
        id: 'asset-101-endpoint',
        programId: 'prog-acme-01',
        scopeId: 'scope-acme-101',
        parentAssetId: 'asset-101',
        domain: 'api.acme-security.test',
        type: 'API_ENDPOINT',
        hostname: 'api.acme-security.test',
        url: 'https://api.acme-security.test/v1/auth/token',
        path: '/v1/auth/token',
        httpMethod: 'POST',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'JWT Authentication Endpoint',
        endpointCount: 1,
        discoverySource: 'ENDPOINT_MAPPING',
        confidence: 100,
      },
      {
        id: 'asset-102',
        programId: 'prog-acme-01',
        scopeId: 'scope-acme-102',
        parentAssetId: 'asset-acme-root',
        domain: 'auth.acme-security.test',
        type: 'SUBDOMAIN',
        hostname: 'auth.acme-security.test',
        url: 'https://auth.acme-security.test',
        path: '/',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'React / OAuth 2.0',
        endpointCount: 12,
        discoverySource: 'AUTHORIZED_DISCOVERY',
        confidence: 100,
      },
      // Nexus Payment Infrastructure
      {
        id: 'asset-nexus-root',
        programId: 'prog-nexus-02',
        scopeId: 'scope-nexus-201',
        domain: 'nexus-pay.dev',
        type: 'DOMAIN',
        hostname: 'nexus-pay.dev',
        url: 'https://nexus-pay.dev',
        path: '/',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'Anycast Gateway / Envoy Proxy',
        endpointCount: 1,
        discoverySource: 'SEED_POLICY_SCOPE',
        confidence: 100,
      },
      {
        id: 'asset-103',
        programId: 'prog-nexus-02',
        scopeId: 'scope-nexus-201',
        parentAssetId: 'asset-nexus-root',
        domain: 'checkout.nexus-pay.dev',
        type: 'SUBDOMAIN',
        hostname: 'checkout.nexus-pay.dev',
        url: 'https://checkout.nexus-pay.dev',
        path: '/',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'Next.js / Stripe Gateway',
        endpointCount: 18,
        discoverySource: 'AUTHORIZED_DISCOVERY',
        confidence: 100,
      },
      // Starlight Cloud Vault
      {
        id: 'asset-starlight-root',
        programId: 'prog-starlight-03',
        scopeId: 'scope-starlight-301',
        domain: 'starlight-cloud.test',
        type: 'DOMAIN',
        hostname: 'starlight-cloud.test',
        url: 'https://starlight-cloud.test',
        path: '/',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'Cloud Infrastructure Root',
        endpointCount: 1,
        discoverySource: 'SEED_POLICY_SCOPE',
        confidence: 100,
      },
      {
        id: 'asset-104',
        programId: 'prog-starlight-03',
        scopeId: 'scope-starlight-301',
        parentAssetId: 'asset-starlight-root',
        domain: 'vault-auth.starlight-cloud.test',
        type: 'SUBDOMAIN',
        hostname: 'vault-auth.starlight-cloud.test',
        url: 'https://vault-auth.starlight-cloud.test',
        path: '/',
        status: 'AUTHORIZED',
        scopeStatus: 'In Scope',
        technology: 'Golang / AWS S3 Presigned API',
        endpointCount: 22,
        discoverySource: 'AUTHORIZED_DISCOVERY',
        confidence: 100,
      },
      // Controlled Test Candidate Assets (Out-Of-Scope Lookalike & Discovered)
      {
        id: 'asset-lookalike-test',
        programId: 'prog-nexus-02',
        domain: 'evil-nexus-pay.dev',
        type: 'SUBDOMAIN',
        hostname: 'evil-nexus-pay.dev',
        url: 'https://evil-nexus-pay.dev',
        path: '/',
        status: 'OUT_OF_SCOPE',
        scopeStatus: 'Out of Scope',
        technology: 'Unknown External Server',
        endpointCount: 1,
        discoverySource: 'LOOKALIKE_BOUNDARY_TEST',
        confidence: 0,
      },
    ];

    for (const item of seedAssetList) {
      const existing = await db.select().from(assets).where(eq(assets.id, item.id));
      if (existing.length === 0) {
        try {
          await db.insert(assets).values(item);
        } catch (err: any) {
          if (err.code === '23505' || err.cause?.code === '23505') {
            await db
              .update(assets)
              .set({
                scopeId: item.scopeId,
                parentAssetId: item.parentAssetId,
                domain: item.domain,
                type: item.type,
                hostname: item.hostname,
                url: item.url,
                path: item.path,
                httpMethod: item.httpMethod,
                status: item.status,
                discoverySource: item.discoverySource,
                confidence: item.confidence,
              })
              .where(eq(assets.id, item.id));
          } else {
            throw err;
          }
        }
      } else {
        await db
          .update(assets)
          .set({
            scopeId: item.scopeId,
            parentAssetId: item.parentAssetId,
            domain: item.domain,
            type: item.type,
            hostname: item.hostname,
            url: item.url,
            path: item.path,
            httpMethod: item.httpMethod,
            status: item.status,
            discoverySource: item.discoverySource,
            confidence: item.confidence,
          })
          .where(eq(assets.id, item.id));
      }
    }

    // 4. Seed Policy Rules
    const existingPolicy = await db.select().from(policyRules);
    if (existingPolicy.length === 0) {
      await db.insert(policyRules).values([
        { id: 'pol-101', programId: 'prog-acme-01', name: 'Web application security testing', category: 'Testing Vector', allowed: true },
        { id: 'pol-102', programId: 'prog-acme-01', name: 'API endpoint testing & authorization verification', category: 'Testing Vector', allowed: true },
        { id: 'pol-103', programId: 'prog-acme-01', name: 'Denial of Service (DoS / DDoS) testing', category: 'Constraint', allowed: false },
        { id: 'pol-104', programId: 'prog-nexus-02', name: 'Payment API payload validation', category: 'Testing Vector', allowed: true },
        { id: 'pol-105', programId: 'prog-nexus-02', name: 'Automated brute forcing over 100 req/min', category: 'Constraint', allowed: false },
      ]);
    }

    // 4.5 Seed Program Scopes
    const existingScopes = await db.select().from(programScopes);
    if (existingScopes.length === 0) {
      await db.insert(programScopes).values([
        // prog-acme-01
        {
          id: 'scope-acme-101',
          programId: 'prog-acme-01',
          targetPattern: 'api.acme-security.test',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Acme core REST API domain',
        },
        {
          id: 'scope-acme-102',
          programId: 'prog-acme-01',
          targetPattern: 'auth.acme-security.test',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Acme OAuth authentication portal',
        },
        {
          id: 'scope-acme-105',
          programId: 'prog-acme-01',
          targetPattern: 'api.target.test',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Acme target test endpoint',
        },
        {
          id: 'scope-acme-106',
          programId: 'prog-acme-01',
          targetPattern: 'target.test',
          scopeType: 'SUBDOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Acme synthetic target test domain',
        },
        {
          id: 'scope-acme-107',
          programId: 'prog-acme-01',
          targetPattern: 'acme-security.test',
          scopeType: 'SUBDOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Acme security wildcard subdomain wildcard',
        },
        {
          id: 'scope-acme-108',
          programId: 'prog-acme-01',
          targetPattern: 'acme.test',
          scopeType: 'SUBDOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Acme general test domain wildcard',
        },
        {
          id: 'scope-acme-103',
          programId: 'prog-acme-01',
          targetPattern: 'out-of-scope.acme-security.test',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'OUT_OF_SCOPE',
          description: 'Third-party hosted customer portal',
        },
        {
          id: 'scope-acme-104',
          programId: 'prog-acme-01',
          targetPattern: 'legacy.acme-security.test',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'DISABLED',
          description: 'Deprecated legacy cluster',
        },
        // prog-nexus-02
        {
          id: 'scope-nexus-201',
          programId: 'prog-nexus-02',
          targetPattern: 'nexus-pay.dev',
          scopeType: 'SUBDOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Nexus payment infrastructure subdomains',
        },
        {
          id: 'scope-nexus-202',
          programId: 'prog-nexus-02',
          targetPattern: 'checkout.nexus-pay.dev',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Nexus merchant checkout portal',
        },
        {
          id: 'scope-nexus-203',
          programId: 'prog-nexus-02',
          targetPattern: 'sensitive.nexus-pay.dev',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'REVIEW_REQUIRED',
          description: 'Core banking ledger API - manual authorization required',
        },
        // prog-starlight-03
        {
          id: 'scope-starlight-301',
          programId: 'prog-starlight-03',
          targetPattern: 'vault-auth.starlight-cloud.test',
          scopeType: 'EXACT_DOMAIN',
          scopeStatus: 'IN_SCOPE',
          description: 'Starlight vault auth portal',
        },
        {
          id: 'scope-starlight-302',
          programId: 'prog-starlight-03',
          targetPattern: 'https://vault-auth.starlight-cloud.test/api/v1/storage',
          scopeType: 'URL',
          scopeStatus: 'IN_SCOPE',
          description: 'Starlight S3 storage endpoint',
        },
      ]);
    }

    // 4.6 Seed Discovery Sessions
    const existingDiscoverySessions = await db.select().from(discoverySessions);
    if (existingDiscoverySessions.length === 0) {
      await db.insert(discoverySessions).values([
        {
          id: 'disc-sess-101',
          programId: 'prog-acme-01',
          initiatedBy: 'user-ayush-001',
          targetScopeId: 'scope-acme-101',
          target: 'api.acme-security.test',
          operation: 'AUTHORIZED_DISCOVERY',
          status: 'COMPLETED',
          startedAt: new Date(Date.now() - 3600000),
          completedAt: new Date(Date.now() - 3300000),
          requestId: 'req-disc-seed-001',
        },
        {
          id: 'disc-sess-102',
          programId: 'prog-nexus-02',
          initiatedBy: 'user-ayush-001',
          targetScopeId: 'scope-nexus-201',
          target: 'checkout.nexus-pay.dev',
          operation: 'AUTHORIZED_DISCOVERY',
          status: 'READY',
          requestId: 'req-disc-seed-002',
        },
      ]);
    }

    // 5. Seed Hunts
    const existingHunts = await db.select().from(hunts);
    if (existingHunts.length === 0) {
      await db.insert(hunts).values([
        {
          id: 'hunt-101',
          programId: 'prog-acme-01',
          assetId: 'asset-101',
          researcherId: 'user-ayush-001',
          status: 'Hunting',
          progress: 72,
          scope: 'api.acme-security.test',
          currentTask: 'Validating tenant boundary header checks on /v2/transact',
          startedAt: '18 minutes ago',
        },
        {
          id: 'hunt-102',
          programId: 'prog-nexus-02',
          assetId: 'asset-103',
          researcherId: 'user-ayush-001',
          status: 'Analyzing',
          progress: 91,
          scope: 'checkout.nexus-pay.dev',
          currentTask: 'Analyzing GraphQL query depth limits & schema reflection',
          startedAt: '1 hour ago',
        },
        {
          id: 'hunt-103',
          programId: 'prog-starlight-03',
          assetId: 'asset-104',
          researcherId: 'user-ayush-001',
          status: 'Ready',
          progress: 0,
          scope: 'vault-auth.starlight-cloud.test',
          currentTask: 'Standing by for researcher initiation command',
          startedAt: 'Not started',
        },
        {
          id: 'hunt-100',
          programId: 'prog-acme-01',
          assetId: 'asset-102',
          researcherId: 'user-ayush-001',
          status: 'Completed',
          progress: 100,
          scope: 'auth.acme-security.test',
          currentTask: 'Completed full security review cycle',
          startedAt: 'Yesterday',
          completedAt: '2 hours ago',
        },
      ]);
    }

    // 6. Seed Findings
    const existingFindings = await db.select().from(findings);
    if (existingFindings.length === 0) {
      await db.insert(findings).values([
        {
          id: 'finding-101',
          huntId: 'hunt-101',
          programId: 'prog-acme-01',
          assetId: 'asset-101',
          title: 'Broken Object Level Authorization (BOLA) on /api/v2/tenants/{id}/keys',
          description: 'An authenticated user can query sensitive tenant configuration keys belonging to arbitrary organizations by replacing the path parameter with any numeric identifier.',
          severity: 'Critical',
          confidence: 98,
          category: 'Authorization Flaw (CWE-639)',
          status: 'Verified',
          evidence: 'GET /api/v2/tenants/1042/keys HTTP/1.1\nHost: api.acme-security.test\nAuthorization: Bearer <valid_tenant_1001_jwt>\n\nHTTP/1.1 200 OK\n{"tenant_id": 1042, "api_secret_key": "sec_live_9481a8..."}',
          discoveredAt: '14 minutes ago',
          verifiedAt: '10 minutes ago',
        },
        {
          id: 'finding-102',
          huntId: 'hunt-101',
          programId: 'prog-acme-01',
          assetId: 'asset-101',
          title: 'JWT Algorithm Confusion (RS256 to HS256) on Auth Ingestion',
          description: 'The authentication middleware accepts asymmetric tokens re-signed with the public key using HMAC HS256, bypassing token cryptographic validation.',
          severity: 'High',
          confidence: 94,
          category: 'Cryptographic Failure (CWE-347)',
          status: 'Verified',
          evidence: 'Header: {"alg":"HS256","typ":"JWT"}\nSigned with: Public Certificate RSA Key String\nAccepted by: auth.acme-security.test/v1/verify',
          discoveredAt: '28 minutes ago',
          verifiedAt: '20 minutes ago',
        },
        {
          id: 'finding-103',
          huntId: 'hunt-102',
          programId: 'prog-nexus-02',
          assetId: 'asset-103',
          title: 'GraphQL Introspection Enabled & Unrestricted Query Depth',
          description: 'Introspection queries are permitted in public environment, exposing full schema definitions and allowing nested queries capable of CPU starvation.',
          severity: 'Medium',
          confidence: 90,
          category: 'Information Disclosure (CWE-200)',
          status: 'Verified',
          evidence: 'POST /graphql HTTP/1.1\nHost: checkout.nexus-pay.dev\nContent-Type: application/json\n\n{"query":"{ __schema { types { name fields { name } } } }"}',
          discoveredAt: '45 minutes ago',
          verifiedAt: '30 minutes ago',
        },
        {
          id: 'finding-104',
          huntId: 'hunt-102',
          programId: 'prog-nexus-02',
          assetId: 'asset-103',
          title: 'Unrestricted Password Reset Token Generation Rate Limit',
          description: 'The password reset request endpoint lacks IP or email rate limits, allowing automated request flooding.',
          severity: 'Low',
          confidence: 85,
          category: 'Improper Rate Limiting (CWE-799)',
          status: 'Potential',
          evidence: '100 requests generated in 4.2 seconds yielded 100 HTTP 200 OK responses with unique reset tokens.',
          discoveredAt: '52 minutes ago',
        },
        {
          id: 'finding-100',
          huntId: 'hunt-100',
          programId: 'prog-acme-01',
          assetId: 'asset-102',
          title: 'Cross-Site Scripting (XSS) in Callback Redirect Parameter',
          description: 'Reflected payload in redirect_uri parameter executes arbitrary JS in victim session.',
          severity: 'Medium',
          confidence: 95,
          category: 'Cross-Site Scripting (CWE-79)',
          status: 'Verified',
          evidence: 'GET /oauth/callback?redirect_uri=javascript:alert(document.domain)',
          discoveredAt: 'Yesterday',
          verifiedAt: 'Yesterday',
        },
      ]);
    }

    // 7. Seed Reports
    const existingReports = await db.select().from(reports);
    if (existingReports.length === 0) {
      await db.insert(reports).values([
        {
          id: 'report-101',
          findingId: 'finding-101',
          programId: 'prog-acme-01',
          researcherId: 'user-ayush-001',
          title: 'Confidential Disclosure: BOLA Vulnerability on Tenant Keys Endpoint',
          summary: 'Critical BOLA vulnerability allowing unauthorized access to tenant secret keys across isolated organization accounts.',
          severity: 'Critical',
          status: 'Submitted',
          submittedAt: '8 minutes ago',
        },
        {
          id: 'report-102',
          findingId: 'finding-102',
          programId: 'prog-acme-01',
          researcherId: 'user-ayush-001',
          title: 'Confidential Disclosure: JWT RS256/HS256 Key Confusion',
          summary: 'Authentication bypass via JWT key confusion attack vector on auth ingestion proxy.',
          severity: 'High',
          status: 'Ready',
        },
        {
          id: 'report-103',
          findingId: 'finding-103',
          programId: 'prog-nexus-02',
          researcherId: 'user-ayush-001',
          title: 'Disclosure Package: GraphQL Introspection Exposure',
          summary: 'GraphQL schema inspection enabled in checkout endpoint allowing full query topology mapping.',
          severity: 'Medium',
          status: 'Submitted',
          submittedAt: '25 minutes ago',
        },
        {
          id: 'report-100',
          findingId: 'finding-100',
          programId: 'prog-acme-01',
          researcherId: 'user-ayush-001',
          title: 'Resolved Disclosure: Reflected XSS on OAuth Callback',
          summary: 'Reflected script injection flaw resolved by target vendor.',
          severity: 'Medium',
          status: 'Resolved',
          submittedAt: 'Yesterday',
          resolvedAt: 'Today',
        },
      ]);
    }

    // 8. Seed Rewards
    const existingRewards = await db.select().from(rewards);
    if (existingRewards.length === 0) {
      await db.insert(rewards).values([
        {
          id: 'reward-101',
          reportId: 'report-101',
          amount: '₹25,000',
          numericAmount: 25000,
          currency: 'INR',
          status: 'PENDING',
        },
        {
          id: 'reward-102',
          reportId: 'report-102',
          amount: '₹12,500',
          numericAmount: 12500,
          currency: 'INR',
          status: 'POTENTIAL',
        },
        {
          id: 'reward-103',
          reportId: 'report-103',
          amount: '₹5,000',
          numericAmount: 5000,
          currency: 'INR',
          status: 'PENDING',
        },
        {
          id: 'reward-100',
          reportId: 'report-100',
          amount: '₹25,000',
          numericAmount: 25000,
          currency: 'INR',
          status: 'PAID',
          paidAt: 'Today',
        },
      ]);
    }

    // 9. Seed History Sessions
    const existingHistory = await db.select().from(historySessions);
    if (existingHistory.length === 0) {
      await db.insert(historySessions).values([
        {
          id: 'hist-101',
          huntId: 'hunt-100',
          programId: 'prog-acme-01',
          researcherId: 'user-ayush-001',
          targetId: 'asset-102',
          duration: '42 mins',
          verifiedFindingCount: 1,
          rewardAmount: '₹25,000',
          status: 'Completed',
        },
      ]);
    }

    // 10. Seed Audit Events
    const existingAudit = await db.select().from(auditEvents);
    if (existingAudit.length === 0) {
      await db.insert(auditEvents).values([
        {
          id: 'audit-101',
          userId: 'user-ayush-001',
          entityType: 'HUNT',
          entityId: 'hunt-101',
          action: 'HUNT_STARTED',
          previousState: 'Ready',
          newState: 'Hunting',
          metadata: 'Policy-bounded security testing launched on api.acme-security.test',
        },
        {
          id: 'audit-102',
          userId: 'user-ayush-001',
          entityType: 'FINDING',
          entityId: 'finding-101',
          action: 'FINDING_VERIFIED',
          previousState: 'Under review',
          newState: 'Verified',
          metadata: 'BOLA on /api/v2/tenants/{id}/keys verified with PoC evidence',
        },
        {
          id: 'audit-103',
          userId: 'user-ayush-001',
          entityType: 'REPORT',
          entityId: 'report-101',
          action: 'REPORT_SUBMITTED',
          previousState: 'Ready',
          newState: 'Submitted',
          metadata: 'Disclosure report sent to vendor security team',
        },
      ]);
    }

    console.log('Database seeding completed successfully.');
  } catch (err) {
    console.error('Error seeding database:', err);
  }
}

if (process.argv[1] && process.argv[1].endsWith('seed.ts')) {
  seedDatabase().then(() => process.exit(0)).catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
