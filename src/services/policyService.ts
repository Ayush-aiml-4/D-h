import { db } from '../db/index.ts';
import { policyRules, programs, assets } from '../db/schema.ts';
import { eq, and } from 'drizzle-orm';
import { recordAuditEvent } from './auditService.ts';
import { AuthUser } from '../middleware/auth.ts';
import { logger } from '../utils/logger.ts';

export interface PolicyEvaluationResult {
  allowed: boolean;
  reason?: string;
  ruleName?: string;
}

export const evaluatePolicyAction = async (
  programId: string,
  targetDomain: string,
  actionCategory: string,
  user: AuthUser,
  requestId?: string
): Promise<PolicyEvaluationResult> => {
  try {
    const prog = await db.select().from(programs).where(eq(programs.id, programId));
    if (prog.length === 0) {
      return { allowed: false, reason: 'Program not found' };
    }

    // Query policy rules for program
    const rules = await db.select().from(policyRules).where(eq(policyRules.programId, programId));

    // Check if category is blocked
    const matchingRule = rules.find((r) => r.category.toLowerCase() === actionCategory.toLowerCase());

    if (matchingRule && !matchingRule.allowed) {
      logger.security('POLICY_BLOCKED_ACTION', {
        requestId,
        programId,
        targetDomain,
        actionCategory,
        actorId: user.uid,
        ruleName: matchingRule.name,
      });

      await recordAuditEvent({
        userId: user.uid,
        entityType: 'POLICY',
        entityId: programId,
        action: 'POLICY_BLOCKED_ACTION',
        success: false,
        requestId,
        metadata: JSON.stringify({
          programId,
          targetDomain,
          actionCategory,
          ruleName: matchingRule.name,
          reason: matchingRule.description || 'Action explicitly prohibited by program policy',
        }),
      });

      return {
        allowed: false,
        reason: matchingRule.description || `Action '${actionCategory}' is prohibited by program security policy`,
        ruleName: matchingRule.name,
      };
    }

    return { allowed: true };
  } catch (err) {
    logger.error('POLICY_EVALUATION_ERROR', {
      requestId,
      programId,
      error: err instanceof Error ? err.message : String(err),
    });
    return { allowed: false, reason: 'Failed to evaluate policy rules' };
  }
};
