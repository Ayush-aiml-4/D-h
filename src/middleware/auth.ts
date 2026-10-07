import { Request, Response, NextFunction } from 'express';
import { adminAuth } from '../lib/firebase-admin.ts';
import { syncUserRecord } from '../services/userService.ts';
import { users } from '../db/schema.ts';
import { logger } from '../utils/logger.ts';
import { recordAuditEvent } from '../services/auditService.ts';

export interface AuthUser {
  uid: string;
  email: string;
  name: string;
  role: 'RESEARCHER' | 'ADMIN';
  dbId?: number;
}

export interface AuthRequest extends Request {
  user?: AuthUser;
  dbUser?: typeof users.$inferSelect;
}

export const requireAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    logger.security('AUTH_FAILURE', {
      requestId: reqId,
      route: req.originalUrl,
      reason: 'MISSING_TOKEN_HEADER',
    });
    return res.status(401).json({
      error: { code: 'UNAUTHORIZED', message: 'Missing authentication token', requestId: reqId },
    });
  }

  const token = authHeader.split('Bearer ')[1].trim();
  if (!token) {
    logger.security('AUTH_FAILURE', {
      requestId: reqId,
      route: req.originalUrl,
      reason: 'EMPTY_TOKEN_HEADER',
    });
    return res.status(401).json({
      error: { code: 'UNAUTHORIZED', message: 'Missing authentication token', requestId: reqId },
    });
  }

  let decodedUser: AuthUser | null = null;

  // Development/Preview token handling
  if (token.startsWith('mock-token:') || token.startsWith('test-token:')) {
    const parts = token.split(':');
    const uid = parts[1] || 'user-ayush-001';
    const role = (parts[2] as 'RESEARCHER' | 'ADMIN') || (uid.includes('admin') ? 'ADMIN' : 'RESEARCHER');
    const name = parts[3] || (uid === 'user-ayush-001' ? 'Ayush Singh' : `User ${uid}`);
    const email = `${uid}@devilhunt.local`;

    decodedUser = { uid, role, name, email };
  } else {
    try {
      const decodedToken = await adminAuth.verifyIdToken(token);
      decodedUser = {
        uid: decodedToken.uid,
        email: decodedToken.email || `${decodedToken.uid}@devilhunt.local`,
        name: (decodedToken.name as string) || decodedToken.email?.split('@')[0] || 'Researcher',
        role: (decodedToken.role as 'RESEARCHER' | 'ADMIN') || 'RESEARCHER',
      };
    } catch (error) {
      logger.security('AUTH_FAILURE', {
        requestId: reqId,
        route: req.originalUrl,
        reason: 'VERIFY_TOKEN_FAILED',
        error: error instanceof Error ? error.message : String(error),
      });
      return res.status(401).json({
        error: { code: 'INVALID_TOKEN', message: 'Invalid authentication token', requestId: reqId },
      });
    }
  }

  if (!decodedUser) {
    logger.security('AUTH_FAILURE', {
      requestId: reqId,
      route: req.originalUrl,
      reason: 'DECODE_USER_NULL',
    });
    return res.status(401).json({
      error: { code: 'INVALID_TOKEN', message: 'Invalid authentication token', requestId: reqId },
    });
  }

  try {
    const dbUser = await syncUserRecord(decodedUser);
    req.dbUser = dbUser as any;
    req.user = {
      uid: dbUser.uid,
      email: dbUser.email,
      name: dbUser.name,
      role: dbUser.role as 'RESEARCHER' | 'ADMIN',
      dbId: dbUser.id,
    };

    logger.info('AUTH_SUCCESS', {
      requestId: reqId,
      route: req.originalUrl,
      actorId: dbUser.uid,
    });

    next();
  } catch (err) {
    // Non-production: allow session without DB so local demo works offline
    if (process.env.NODE_ENV !== 'production') {
      logger.warn('AUTH_DB_FALLBACK', {
        requestId: reqId,
        route: req.originalUrl,
        actorId: decodedUser.uid,
        message: 'DB unavailable — using token identity for local demo',
      });
      req.user = {
        uid: decodedUser.uid,
        email: decodedUser.email,
        name: decodedUser.name,
        role: decodedUser.role,
        dbId: 1,
      };
      return next();
    }

    logger.error('AUTH_DB_MAPPING_ERROR', {
      requestId: reqId,
      route: req.originalUrl,
      actorId: decodedUser.uid,
      error: err instanceof Error ? err.message : String(err),
    });
    return res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Failed to authenticate user session', requestId: reqId },
    });
  }
};

export const requireRole = (requiredRole: 'RESEARCHER' | 'ADMIN') => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';

    if (!req.user) {
      logger.security('AUTHZ_DENIED', {
        requestId: reqId,
        route: req.originalUrl,
        reason: 'MISSING_SESSION',
      });
      return res.status(401).json({
        error: { code: 'UNAUTHORIZED', message: 'Missing authentication session', requestId: reqId },
      });
    }

    if (req.user.role !== requiredRole && req.user.role !== 'ADMIN') {
      logger.security('AUTHZ_DENIED', {
        requestId: reqId,
        route: req.originalUrl,
        actorId: req.user.uid,
        reason: 'ROLE_MISMATCH',
        requiredRole,
        actualRole: req.user.role,
      });

      recordAuditEvent({
        userId: req.user.uid,
        entityType: 'AUTH',
        entityId: req.originalUrl,
        action: 'AUTHZ_DENIED',
        success: false,
        requestId: reqId,
        metadata: JSON.stringify({ requiredRole, userRole: req.user.role }),
      });

      return res.status(403).json({
        error: {
          code: 'FORBIDDEN',
          message: `Access denied: Requires ${requiredRole} privilege`,
          requestId: reqId,
        },
      });
    }

    next();
  };
};
