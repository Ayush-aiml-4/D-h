import { db } from '../db/index.ts';
import { assets, discoverySessions, programScopes, programs, users } from '../db/schema.ts';
import { eq, and, inArray } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';
import { parseTarget, evaluatePolicy } from './policyEngine.ts';
import { AttackSurfaceNode, ResearchPriorityLabel } from '../types.ts';
import { logger } from '../utils/logger.ts';

export interface DeterministicPriorityInput {
  type: string;
  confidence?: number;
  discoverySource?: string;
  scopeStatus?: string;
  endpointCount?: number;
  hasApiPattern?: boolean;
}

export interface DeterministicPriorityResult {
  priorityLabel: ResearchPriorityLabel;
  priorityReason: string;
}

/**
 * Deterministically calculates research priority using safe metadata only.
 * High Priority: Authorized API_ENDPOINT or SUBDOMAIN with endpoints and high confidence.
 * Medium Priority: Discovered/Authorized subdomains or URLs with moderate endpoint count.
 * Low Priority: Out of scope, root domain, or low confidence assets.
 * 
 * STRICT CONSTRAINTS:
 * - Labels allowed: 'HIGH PRIORITY', 'MEDIUM PRIORITY', 'LOW PRIORITY'
 * - NO vulnerability severity terms (e.g. CRITICAL, HIGH RISK, VULNERABLE, EXPLOITABLE)
 * - NO tech stack based risk scoring
 * - NO authorization depth based risk scoring
 */
export function calculateDeterministicResearchPriority(
  input: DeterministicPriorityInput
): DeterministicPriorityResult {
  const {
    type,
    confidence = 0.5,
    discoverySource = 'DISCOVERY',
    scopeStatus = 'UNKNOWN',
    endpointCount = 0,
    hasApiPattern = false,
  } = input;

  const normalizedScopeStatus = (scopeStatus || '').toUpperCase();

  // Rule 1: Out of scope or disabled assets are ALWAYS Low Priority
  if (normalizedScopeStatus === 'OUT_OF_SCOPE' || normalizedScopeStatus === 'DISABLED') {
    return {
      priorityLabel: 'LOW PRIORITY',
      priorityReason: 'Asset is out of scope or disabled for research operations',
    };
  }

  // Rule 2: In-Scope / Authorized API Endpoints or rich endpoints with high confidence
  if (
    (type === 'API_ENDPOINT' || type === 'api' || hasApiPattern) &&
    confidence >= 0.7 &&
    (normalizedScopeStatus === 'IN_SCOPE' || normalizedScopeStatus === 'AUTHORIZED' || normalizedScopeStatus === 'IN SCOPE')
  ) {
    return {
      priorityLabel: 'HIGH PRIORITY',
      priorityReason: 'Authorized API endpoint with high discovery confidence and active schema pattern',
    };
  }

  // Rule 3: Authorized Subdomains with multiple discovered endpoints
  if (
    (type === 'SUBDOMAIN' || type === 'subdomain') &&
    endpointCount > 3 &&
    confidence >= 0.8 &&
    (normalizedScopeStatus === 'IN_SCOPE' || normalizedScopeStatus === 'AUTHORIZED' || normalizedScopeStatus === 'IN SCOPE')
  ) {
    return {
      priorityLabel: 'HIGH PRIORITY',
      priorityReason: 'Authorized subdomain with high endpoint density and verified discovery confidence',
    };
  }

  // Rule 4: Discovered or Authorized subdomains / services / URLs
  if (
    type === 'SUBDOMAIN' ||
    type === 'subdomain' ||
    type === 'SERVICE' ||
    type === 'URL' ||
    type === 'auth' ||
    type === 'admin'
  ) {
    return {
      priorityLabel: 'MEDIUM PRIORITY',
      priorityReason: 'Discovered target asset within active program boundary requiring structured mapping',
    };
  }

  // Default Rule 5: Root domains, static assets, or low confidence items
  return {
    priorityLabel: 'LOW PRIORITY',
    priorityReason: 'Base target domain or low-density asset suitable for initial boundary inspection',
  };
}

export interface GetAttackSurfaceGraphOptions {
  programId?: string;
}

export async function buildAttackSurfaceGraph(
  user: AuthUser,
  options: GetAttackSurfaceGraphOptions = {}
): Promise<AttackSurfaceNode[]> {
  if (!user || !user.uid) {
    throw new Error('UNAUTHENTICATED: User authentication is required');
  }

  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new Error('UNAUTHORIZED_RESEARCHER: Researcher is not registered in authorization directory');
  }

  const targetProgramId = options.programId;

  // Fetch program scopes for reference
  let scopeConditions = [];
  if (targetProgramId) {
    scopeConditions.push(eq(programScopes.programId, targetProgramId));
  }
  const scopesList = scopeConditions.length > 0
    ? await db.select().from(programScopes).where(and(...scopeConditions))
    : await db.select().from(programScopes);

  // Fetch persisted assets
  let assetConditions = [];
  if (targetProgramId) {
    assetConditions.push(eq(assets.programId, targetProgramId));
  }
  const dbAssets = assetConditions.length > 0
    ? await db.select().from(assets).where(and(...assetConditions))
    : await db.select().from(assets);

  // Fetch active or completed discovery sessions for provenance mapping
  let sessionConditions = [];
  if (targetProgramId) {
    sessionConditions.push(eq(discoverySessions.programId, targetProgramId));
  }
  const sessionsList = sessionConditions.length > 0
    ? await db.select().from(discoverySessions).where(and(...sessionConditions))
    : await db.select().from(discoverySessions);

  const scopeOwnerMap = new Map<string, string>();
  for (const s of sessionsList) {
    if (s.targetScopeId) {
      scopeOwnerMap.set(s.targetScopeId, s.initiatedBy);
    }
  }

  // Build node graph dictionary by asset ID
  const nodesMap = new Map<string, AttackSurfaceNode>();

  // If no DB assets exist yet, synthesize root scope nodes from programScopes
  if (dbAssets.length === 0) {
    for (const scope of scopesList) {
      const parsed = parseTarget(scope.targetPattern);
      const host = parsed.hostname || scope.targetPattern.replace(/^\*\./, '');
      const nodeId = `node-scope-${scope.id}`;

      const priority = calculateDeterministicResearchPriority({
        type: scope.scopeType,
        confidence: 1.0,
        scopeStatus: scope.scopeStatus,
      });

      const node: AttackSurfaceNode = {
        id: nodeId,
        name: host,
        domain: host,
        type: scope.scopeType === 'SUBDOMAIN' ? 'subdomain' : 'root',
        assetStatus: scope.scopeStatus === 'IN_SCOPE' ? 'AUTHORIZED' : 'OUT_OF_SCOPE',
        scopeStatus: scope.scopeStatus,
        policyDecision: scope.scopeStatus === 'IN_SCOPE' ? 'ALLOW' : 'BLOCK',
        priorityLabel: priority.priorityLabel,
        priorityReason: priority.priorityReason,
        endpointsCount: 0,
        techStack: ['HTTP/HTTPS'],
        programId: scope.programId,
        scopeId: scope.id,
        researcherOwnership: 'SYSTEM',
        children: [],
        endpoints: [],
      };

      nodesMap.set(nodeId, node);
    }

    return Array.from(nodesMap.values());
  }

  // Group assets into parent domains and child subdomains / endpoints
  const childAssets = dbAssets.filter((a) => a.parentAssetId);

  // Map each DB asset
  for (const dbAsset of dbAssets) {
    const rawVal = dbAsset.url || dbAsset.hostname || dbAsset.domain || 'unknown-asset';
    const parsed = parseTarget(rawVal);
    const host = parsed.hostname || dbAsset.hostname || dbAsset.domain || 'unknown-asset';
    const nameStr = host.split('.')[0] || host;

    // Provenance Check: Internal complete provenance, but hide/redact another researcher's identity
    const sessionInitiatedBy = dbAsset.scopeId ? scopeOwnerMap.get(dbAsset.scopeId) : null;
    let ownershipStatus: 'OWNED' | 'OTHER' | 'SYSTEM' = 'SYSTEM';
    if (sessionInitiatedBy) {
      if (sessionInitiatedBy === user.uid) {
        ownershipStatus = 'OWNED';
      } else {
        ownershipStatus = 'OTHER';
      }
    }

    // Determine distinct statuses
    const isAuthorized = dbAsset.status === 'AUTHORIZED' || dbAsset.scopeStatus === 'IN_SCOPE' || dbAsset.scopeStatus === 'In Scope';
    const isOutOfScope = dbAsset.status === 'OUT_OF_SCOPE' || dbAsset.scopeStatus === 'OUT_OF_SCOPE';
    
    let scopeStatusStr: 'IN_SCOPE' | 'OUT_OF_SCOPE' | 'UNDER_REVIEW' | 'UNKNOWN' = 'UNKNOWN';
    if (isAuthorized) scopeStatusStr = 'IN_SCOPE';
    else if (isOutOfScope) scopeStatusStr = 'OUT_OF_SCOPE';
    else scopeStatusStr = 'UNDER_REVIEW';

    let policyDecision: 'ALLOW' | 'REVIEW_REQUIRED' | 'BLOCK' = 'BLOCK';
    if (isAuthorized) policyDecision = 'ALLOW';
    else if (dbAsset.status === 'DISCOVERED') policyDecision = 'REVIEW_REQUIRED';

    const techStackArray = dbAsset.technology
      ? dbAsset.technology.split(',').map((t) => t.trim())
      : ['HTTP/HTTPS'];

    const endpointsArray: string[] = [];
    if (dbAsset.path) {
      endpointsArray.push(dbAsset.path);
    }

    const priority = calculateDeterministicResearchPriority({
      type: dbAsset.type,
      confidence: dbAsset.confidence ? dbAsset.confidence / 100 : 0.9,
      discoverySource: dbAsset.discoverySource || 'ENUMERATION',
      scopeStatus: isAuthorized ? 'AUTHORIZED' : isOutOfScope ? 'OUT_OF_SCOPE' : 'DISCOVERED',
      endpointCount: dbAsset.endpointCount || 0,
      hasApiPattern: dbAsset.type === 'API_ENDPOINT' || (dbAsset.path || '').includes('/api/'),
    });

    const node: AttackSurfaceNode = {
      id: dbAsset.id,
      name: nameStr,
      domain: host,
      type: mapAssetTypeToGraphType(dbAsset.type),
      assetStatus: dbAsset.status,
      scopeStatus: scopeStatusStr,
      policyDecision,
      priorityLabel: priority.priorityLabel,
      priorityReason: priority.priorityReason,
      endpointsCount: dbAsset.endpointCount || 0,
      techStack: techStackArray,
      endpoints: endpointsArray,
      programId: dbAsset.programId,
      scopeId: dbAsset.scopeId,
      researcherOwnership: ownershipStatus,
      lastSeenAt: dbAsset.lastSeenAt ? dbAsset.lastSeenAt.toISOString() : undefined,
      children: [],
    };

    nodesMap.set(dbAsset.id, node);
  }

  // Link children to parent nodes
  for (const dbAsset of childAssets) {
    if (dbAsset.parentAssetId && nodesMap.has(dbAsset.parentAssetId) && nodesMap.has(dbAsset.id)) {
      const parentNode = nodesMap.get(dbAsset.parentAssetId)!;
      const childNode = nodesMap.get(dbAsset.id)!;
      if (!parentNode.children) parentNode.children = [];
      parentNode.children.push(childNode);
    }
  }

  // Return root-level nodes
  const resultNodes = Array.from(nodesMap.values()).filter((node) => {
    const asset = dbAssets.find((a) => a.id === node.id);
    return !asset || !asset.parentAssetId || !nodesMap.has(asset.parentAssetId);
  });

  return resultNodes;
}

export interface EvaluateCapabilityParams {
  programId: string;
  target: string;
  capability?: string;
  requestId?: string;
}

export interface EvaluateCapabilityResult {
  isAuthorizationEvaluationOnly: boolean;
  decision: 'ALLOW' | 'REVIEW_REQUIRED' | 'BLOCK';
  programId: string;
  target: string;
  capability: string;
  reason: string;
  evaluatedAt: string;
}

/**
 * AUTHORIZATION PREVIEW ONLY.
 * Authenticates user, verifies researcher registration, validates program context,
 * and executes existing server-side evaluatePolicy().
 * 
 * MUST NOT:
 * - execute discovery
 * - make network requests
 * - launch jobs
 * - execute attacks
 * - mutate target systems
 */
export async function evaluateResearchCapability(
  user: AuthUser,
  params: EvaluateCapabilityParams
): Promise<EvaluateCapabilityResult> {
  const { programId, target, requestId } = params;
  const capabilityToEvaluate = params.capability || 'RECONNAISSANCE';

  if (!user || !user.uid) {
    throw new Error('UNAUTHENTICATED: User authentication is required');
  }

  // Verify researcher in DB
  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    throw new Error('UNAUTHORIZED_RESEARCHER: Researcher is not registered in authorization directory');
  }

  // Verify Program
  if (!programId || typeof programId !== 'string') {
    throw new Error('PROGRAM_NOT_FOUND: Program ID is required');
  }

  const programRows = await db.select().from(programs).where(eq(programs.id, programId));
  if (programRows.length === 0) {
    throw new Error('PROGRAM_NOT_FOUND: Program does not exist');
  }

  const program = programRows[0];
  if (program.status !== 'ACTIVE' && program.status !== 'Active') {
    throw new Error(`INACTIVE_PROGRAM: Program '${program.name}' is inactive (Status: ${program.status})`);
  }

  // Call server-side evaluatePolicy
  const policyResult = await evaluatePolicy(
    user,
    { programId, target, operation: capabilityToEvaluate },
    requestId
  );

  return {
    isAuthorizationEvaluationOnly: true,
    decision: policyResult.decision,
    programId,
    target,
    capability: capabilityToEvaluate,
    reason: policyResult.reason || 'Policy evaluation complete',
    evaluatedAt: new Date().toISOString(),
  };
}

function mapAssetTypeToGraphType(type: string): AttackSurfaceNode['type'] {
  switch (type) {
    case 'DOMAIN':
      return 'root';
    case 'SUBDOMAIN':
      return 'subdomain';
    case 'API_ENDPOINT':
      return 'api';
    case 'SERVICE':
      return 'microservice';
    case 'URL':
      return 'static';
    default:
      return 'subdomain';
  }
}
