import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';
import { logger } from '../utils/logger.ts';

declare global {
  namespace Express {
    interface Request {
      id?: string;
      requestId?: string;
      startTime?: number;
    }
  }
}

export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const incomingId = req.headers['x-request-id'];
  const requestId = typeof incomingId === 'string' && incomingId.trim() ? incomingId.trim() : randomUUID();

  req.id = requestId;
  req.requestId = requestId;
  req.startTime = Date.now();

  res.setHeader('X-Request-ID', requestId);

  res.on('finish', () => {
    // Skip excessive logging for static assets or health checks if needed, but log API requests cleanly
    const durationMs = req.startTime ? Date.now() - req.startTime : 0;
    
    // Only log API routes and standard endpoints to avoid noise
    if (req.originalUrl.startsWith('/api') || req.originalUrl.startsWith('/health')) {
      logger.info('HTTP_REQUEST', {
        requestId,
        route: req.originalUrl.split('?')[0],
        method: req.method,
        status: res.statusCode,
        durationMs,
      });
    }
  });

  next();
};
