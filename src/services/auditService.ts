import { db } from '../db/index.ts';
import { auditEvents } from '../db/schema.ts';
import { desc, eq, and, gte, lte } from 'drizzle-orm';
import { AuthUser } from '../middleware/auth.ts';
import { redactSecrets, logger } from '../utils/logger.ts';

export interface RecordAuditParams {
  userId: string;
  entityType: 'HUNT' | 'FINDING' | 'REPORT' | 'PROGRAM' | 'REWARD' | 'AUTH' | 'POLICY' | 'VALIDATION' | 'EVIDENCE' | 'DISCOVERY' | 'CASE' | 'ACTIVITY' | 'DISCLOSURE' | 'EXECUTION' | 'ACTIVE_EXECUTION';
  entityId: string;
  action: string;
  previousState?: string;
  newState?: string;
  success?: boolean;
  requestId?: string;
  metadata?: string | Record<string, any>;
}

export interface AuditFilterParams {
  entityType?: string;
  entityId?: string;
  action?: string;
  actor?: string;
  startDate?: string;
  endDate?: string;
}

export const recordAuditEvent = async (params: RecordAuditParams, tx?: any) => {
  const dbClient = tx || db;
  try {
    const id = `audit-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

    let cleanMetadata: string | null = null;
    if (params.metadata) {
      if (typeof params.metadata === 'string') {
        cleanMetadata = redactSecrets(params.metadata);
      } else {
        cleanMetadata = JSON.stringify(redactSecrets(params.metadata));
      }
    }

    const [event] = await dbClient
      .insert(auditEvents)
      .values({
        id,
        userId: params.userId,
        entityType: params.entityType,
        entityId: params.entityId,
        action: params.action,
        previousState: params.previousState || null,
        newState: params.newState || null,
        success: params.success !== undefined ? params.success : true,
        requestId: params.requestId || null,
        metadata: cleanMetadata,
      })
      .returning();

    logger.security(`AUDIT_EVENT_RECORDED`, {
      requestId: params.requestId,
      eventAction: params.action,
      actorId: params.userId,
      entityType: params.entityType,
      entityId: params.entityId,
      success: params.success !== undefined ? params.success : true,
    });

    return event;
  } catch (err) {
    logger.error('FAILED_RECORD_AUDIT_EVENT', {
      error: err instanceof Error ? err.message : String(err),
      actorId: params.userId,
      requestId: params.requestId,
    });
    if (tx) {
      throw err;
    }
    return null;
  }
};

export const getAuditEvents = async (user: AuthUser, filters?: AuditFilterParams) => {
  try {
    const conditions: any[] = [];

    // Researchers can strictly ONLY access audit events where userId === user.uid
    if (user.role !== 'ADMIN') {
      conditions.push(eq(auditEvents.userId, user.uid));
    } else if (filters?.actor) {
      conditions.push(eq(auditEvents.userId, filters.actor));
    }

    if (filters?.entityType) {
      conditions.push(eq(auditEvents.entityType, filters.entityType));
    }

    if (filters?.entityId) {
      conditions.push(eq(auditEvents.entityId, filters.entityId));
    }

    if (filters?.action) {
      conditions.push(eq(auditEvents.action, filters.action));
    }

    if (filters?.startDate) {
      const start = new Date(filters.startDate);
      if (!isNaN(start.getTime())) {
        conditions.push(gte(auditEvents.createdAt, start));
      }
    }

    if (filters?.endDate) {
      const end = new Date(filters.endDate);
      if (!isNaN(end.getTime())) {
        conditions.push(lte(auditEvents.createdAt, end));
      }
    }

    if (conditions.length > 0) {
      return await db
        .select()
        .from(auditEvents)
        .where(and(...conditions))
        .orderBy(desc(auditEvents.createdAt));
    }

    return await db.select().from(auditEvents).orderBy(desc(auditEvents.createdAt));
  } catch (err) {
    logger.error('FAILED_QUERY_AUDIT_EVENTS', {
      error: err instanceof Error ? err.message : String(err),
      actorId: user.uid,
    });
    throw new Error('Database query failed when loading audit events', { cause: err });
  }
};
