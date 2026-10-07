import { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim())
  : [];

export const corsMiddleware = cors({
  origin: (origin, callback) => {
    // Allow non-browser requests (e.g. curl, server-side fetch, same-origin without origin header)
    if (!origin) {
      return callback(null, true);
    }

    const isAllowed =
      allowedOrigins.includes(origin) ||
      /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin) ||
      origin.endsWith('.run.app') ||
      origin.endsWith('.googleusercontent.com');

    if (isAllowed) {
      return callback(null, true);
    }

    return callback(new Error('CORS Policy: Origin not allowed'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  maxAge: 86400,
});

export const securityHeadersMiddleware = helmet({
  contentSecurityPolicy: false, // Retain support for preview environment rendering
  frameguard: false, // Retain support for iframe preview in AI Studio
  crossOriginResourcePolicy: { policy: 'cross-origin' },
});

export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // Reasonable limit for active security research workflows
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      error: {
        code: 'TOO_MANY_REQUESTS',
        message: 'Rate limit exceeded: Too many requests from this IP address',
      },
    });
  },
});

export const mutationRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Reasonable limit for mutation operations
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      error: {
        code: 'TOO_MANY_REQUESTS',
        message: 'Rate limit exceeded: Too many state mutation requests',
      },
    });
  },
});
