import { db } from '../db/index.ts';
import { programs, programScopes, policyRules, users } from '../db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';
import {
  SCOPE_TYPES,
  SCOPE_STATUSES,
  POLICY_DECISIONS,
  PROHIBITED_OPERATIONS,
  SENSITIVE_OPERATIONS,
  PolicyDecision,
} from '../constants/scope.ts';
import { PolicyEvaluationRequest, PolicyEvaluationResult, ProgramScope } from '../types.ts';
import { recordAuditEvent } from './auditService.ts';
import { logger } from '../utils/logger.ts';

export interface TargetParseResult {
  isValid: boolean;
  rawTarget: string;
  hostname: string;
  path: string;
  fullUrl?: string;
}

export function parseTarget(rawTarget: string): TargetParseResult {
  if (!rawTarget || typeof rawTarget !== 'string' || rawTarget.trim().length === 0) {
    return { isValid: false, rawTarget: '', hostname: '', path: '' };
  }

  const trimmed = rawTarget.trim();

  // Basic sanity check: reject invalid characters, control chars, spaces in domain
  if (/\s/.test(trimmed) || /[\<\>\"\'\`\\]/.test(trimmed)) {
    return { isValid: false, rawTarget: trimmed, hostname: '', path: '' };
  }

  try {
    let urlToParse = trimmed;
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      // If it looks like a path without a domain e.g. "/api/v1"
      if (trimmed.startsWith('/')) {
        return { isValid: true, rawTarget: trimmed, hostname: '', path: trimmed };
      }
      urlToParse = 'https://' + trimmed;
    }

    const parsed = new URL(urlToParse);
    const hostname = parsed.hostname.toLowerCase();

    // Check for invalid hostnames (empty, containing invalid characters or double dots)
    if (!hostname || hostname.includes('..') || hostname.startsWith('.') || hostname.endsWith('.')) {
      return { isValid: false, rawTarget: trimmed, hostname: '', path: '' };
    }

    return {
      isValid: true,
      rawTarget: trimmed,
      hostname,
      path: parsed.pathname || '/',
      fullUrl: parsed.href,
    };
  } catch (err) {
    return { isValid: false, rawTarget: trimmed, hostname: '', path: '' };
  }
}

export function matchScopeRule(parsedTarget: TargetParseResult, scope: ProgramScope): boolean {
  if (!parsedTarget.isValid) return false;

  const { hostname, path, fullUrl, rawTarget } = parsedTarget;
  const pattern = scope.targetPattern.trim().toLowerCase();

  switch (scope.scopeType) {
    case 'EXACT_DOMAIN': {
      // Exact domain match
      // Pattern could be "api.acme-security.test"
      const cleanPattern = pattern.startsWith('http://') || pattern.startsWith('https://')
        ? new URL(pattern).hostname.toLowerCase()
        : pattern.replace(/^\*\./, '');

      return hostname === cleanPattern;
    }

    case 'SUBDOMAIN': {
      // Subdomain wildcard match or base domain match
      // Pattern could be "nexus-pay.dev" or "*.nexus-pay.dev"
      const baseDomain = pattern.replace(/^\*\./, '');

      // Strict boundary check:
      // hostname must equal baseDomain OR end with '.' + baseDomain
      // Prevents "evil-nexus-pay.dev" or "nexus-pay.dev.attacker.com"
      if (hostname === baseDomain) return true;
      if (hostname.endsWith('.' + baseDomain)) return true;
      return false;
    }

    case 'URL': {
      // Target full URL prefix or match
      // Pattern: "https://vault-auth.starlight-cloud.test/api/v1/storage"
      if (fullUrl) {
        const cleanFullUrl = fullUrl.toLowerCase();
        if (cleanFullUrl === pattern) return true;
        if (cleanFullUrl.startsWith(pattern.endsWith('/') ? pattern : pattern + '/')) return true;
      }

      // If pattern is a domain+path e.g. "vault-auth.starlight-cloud.test/api/v1/storage"
      if (rawTarget.toLowerCase().startsWith(pattern)) return true;
      return false;
    }

    case 'API_ENDPOINT': {
      // Matches path or host+path
      // Pattern: "/api/v2/tenants" or "api.acme-security.test/api/v2/tenants"
      if (pattern.startsWith('/')) {
        return path === pattern || path.startsWith(pattern.endsWith('/') ? pattern : pattern + '/');
      }

      const rawLower = rawTarget.toLowerCase();
      if (rawLower.includes(pattern)) return true;
      return false;
    }

    default:
      return false;
  }
}

export async function evaluatePolicy(
  user: AuthUser,
  request: PolicyEvaluationRequest,
  requestId?: string
): Promise<PolicyEvaluationResult> {
  const { programId, target, operation } = request;

  // 1. Fail Closed on missing user or unauthenticated request
  if (!user || !user.uid) {
    logger.warn('POLICY_EVALUATION_UNAUTHENTICATED', { programId, target, requestId });
    return {
      decision: POLICY_DECISIONS.BLOCK,
      programId: programId || 'unknown',
      target: target || 'unknown',
      reason: 'Authentication required for policy evaluation',
    };
  }

  // 2. Validate input parameters
  if (!programId || typeof programId !== 'string' || !target || typeof target !== 'string') {
    return {
      decision: POLICY_DECISIONS.BLOCK,
      programId: programId || 'unknown',
      target: target || 'unknown',
      reason: 'Invalid or missing programId or target',
    };
  }

  // 3. Check Researcher Authorization (Check user active in DB)
  const userRows = await db.select().from(users).where(eq(users.uid, user.uid));
  if (userRows.length === 0) {
    logger.warn('POLICY_EVALUATION_UNREGISTERED_RESEARCHER', { uid: user.uid, programId, target });
    return {
      decision: POLICY_DECISIONS.BLOCK,
      programId,
      target,
      reason: 'Researcher identity not registered in authorization directory',
    };
  }

  // 3. Check for Prohibited Operations
  if (operation) {
    const normalizedOp = operation.toUpperCase().trim();
    if (PROHIBITED_OPERATIONS.includes(normalizedOp as any)) {
      const result: PolicyEvaluationResult = {
        decision: POLICY_DECISIONS.BLOCK,
        programId,
        target,
        reason: `Operation '${operation}' is explicitly prohibited by security policy`,
      };
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'POLICY',
        entityId: programId,
        action: 'POLICY_EVALUATE_BLOCK',
        success: false,
        requestId,
        metadata: { target, operation, reason: result.reason },
      });
      return result;
    }
  }

  // 4. Validate Target Format (Strict Parsing)
  const parsedTarget = parseTarget(target);
  if (!parsedTarget.isValid) {
    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.BLOCK,
      programId,
      target,
      reason: 'Malformed or invalid target format',
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, reason: result.reason },
    });
    return result;
  }

  // 5. Query Program Authorization & Active Status
  const programRows = await db.select().from(programs).where(eq(programs.id, programId));
  if (programRows.length === 0) {
    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.BLOCK,
      programId,
      target,
      reason: 'Program does not exist',
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, reason: result.reason },
    });
    return result;
  }

  const program = programRows[0];
  if (program.status !== 'ACTIVE' && program.status !== 'Active') {
    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.BLOCK,
      programId,
      target,
      reason: `Program '${program.name}' is inactive or archived (Status: ${program.status})`,
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, reason: result.reason },
    });
    return result;
  }

  // 7. Check Program Policy Rules (Disallowed Rules in DB)
  const dbPolicyRules = await db.select().from(policyRules).where(eq(policyRules.programId, programId));
  if (operation) {
    const opLower = operation.toLowerCase();
    const disallowedRule = dbPolicyRules.find(
      (r) => !r.allowed && (r.name.toLowerCase().includes(opLower) || opLower.includes(r.name.toLowerCase()))
    );
    if (disallowedRule) {
      const result: PolicyEvaluationResult = {
        decision: POLICY_DECISIONS.BLOCK,
        programId,
        target,
        reason: `Operation violates program policy rule: '${disallowedRule.name}'`,
      };
      await recordAuditEvent({
        userId: user.uid,
        entityType: 'POLICY',
        entityId: programId,
        action: 'POLICY_EVALUATE_BLOCK',
        success: false,
        requestId,
        metadata: { target, operation, reason: result.reason },
      });
      return result;
    }
  }

  // 8. Fetch Program Scopes & Match Target
  const dbScopes = await db.select().from(programScopes).where(eq(programScopes.programId, programId));

  const matchedScopes = dbScopes.filter((scope) =>
    matchScopeRule(parsedTarget, {
      id: scope.id,
      programId: scope.programId,
      targetPattern: scope.targetPattern,
      scopeType: scope.scopeType as any,
      scopeStatus: scope.scopeStatus as any,
    })
  );

  if (matchedScopes.length === 0) {
    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.BLOCK,
      programId,
      target,
      reason: 'Target is out of scope / no matching scope rule found for program',
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, reason: result.reason },
    });
    return result;
  }

  // Fail Closed Priority Resolution:
  // If ANY matching scope rule is DISABLED or OUT_OF_SCOPE, BLOCK takes precedence!
  const disabledScope = matchedScopes.find((s) => s.scopeStatus === SCOPE_STATUSES.DISABLED);
  if (disabledScope) {
    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.BLOCK,
      programId,
      target,
      matchedPattern: disabledScope.targetPattern,
      scopeType: disabledScope.scopeType,
      scopeStatus: disabledScope.scopeStatus,
      reason: `Target scope pattern '${disabledScope.targetPattern}' is currently DISABLED`,
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, matchedPattern: disabledScope.targetPattern, reason: result.reason },
    });
    return result;
  }

  const outOfScope = matchedScopes.find((s) => s.scopeStatus === SCOPE_STATUSES.OUT_OF_SCOPE);
  if (outOfScope) {
    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.BLOCK,
      programId,
      target,
      matchedPattern: outOfScope.targetPattern,
      scopeType: outOfScope.scopeType,
      scopeStatus: outOfScope.scopeStatus,
      reason: `Target '${target}' matches explicit OUT_OF_SCOPE rule '${outOfScope.targetPattern}'`,
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_BLOCK',
      success: false,
      requestId,
      metadata: { target, matchedPattern: outOfScope.targetPattern, reason: result.reason },
    });
    return result;
  }

  // Check for REVIEW_REQUIRED scope or Sensitive Operations
  const reviewScope = matchedScopes.find((s) => s.scopeStatus === SCOPE_STATUSES.REVIEW_REQUIRED);
  const isSensitiveOp = operation && SENSITIVE_OPERATIONS.includes(operation.toUpperCase().trim() as any);

  if (reviewScope || isSensitiveOp) {
    const matched = reviewScope || matchedScopes[0];
    const reason = reviewScope
      ? `Target matches scope rule '${reviewScope.targetPattern}' requiring manual review`
      : `Operation '${operation}' requires manual authorization review`;

    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.REVIEW_REQUIRED,
      programId,
      target,
      matchedPattern: matched.targetPattern,
      scopeType: matched.scopeType,
      scopeStatus: SCOPE_STATUSES.REVIEW_REQUIRED,
      reason,
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_REVIEW_REQUIRED',
      success: true,
      requestId,
      metadata: { target, operation, matchedPattern: matched.targetPattern, reason },
    });
    return result;
  }

  // Pick best IN_SCOPE match
  const inScopeMatch = matchedScopes.find((s) => s.scopeStatus === SCOPE_STATUSES.IN_SCOPE);
  if (inScopeMatch) {
    const result: PolicyEvaluationResult = {
      decision: POLICY_DECISIONS.ALLOW,
      programId,
      target,
      matchedPattern: inScopeMatch.targetPattern,
      scopeType: inScopeMatch.scopeType,
      scopeStatus: inScopeMatch.scopeStatus,
      reason: 'Target and operation are fully authorized within program scope',
    };
    await recordAuditEvent({
      userId: user.uid,
      entityType: 'POLICY',
      entityId: programId,
      action: 'POLICY_EVALUATE_ALLOW',
      success: true,
      requestId,
      metadata: { target, operation, matchedPattern: inScopeMatch.targetPattern, reason: result.reason },
    });
    return result;
  }

  // Default Fail Closed Fallback
  const fallbackResult: PolicyEvaluationResult = {
    decision: POLICY_DECISIONS.BLOCK,
    programId,
    target,
    reason: 'Fail-closed: No active authorized scope rule matched target',
  };
  await recordAuditEvent({
    userId: user.uid,
    entityType: 'POLICY',
    entityId: programId,
    action: 'POLICY_EVALUATE_BLOCK',
    success: false,
    requestId,
    metadata: { target, reason: fallbackResult.reason },
  });
  return fallbackResult;
}
