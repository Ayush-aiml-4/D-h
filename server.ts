import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import * as dotenv from 'dotenv';
import v1Router from './src/api/v1.ts';
import healthRouter from './src/api/health.ts';
import { seedDatabase } from './src/db/seed.ts';
import { verifyDatabaseConnection, closeDatabasePool } from './src/db/index.ts';
import { corsMiddleware, securityHeadersMiddleware, apiRateLimiter } from './src/middleware/security.ts';
import { requestIdMiddleware } from './src/middleware/requestId.ts';
import { logger } from './src/utils/logger.ts';
import { validateStartupConfig } from './src/config/env.ts';

dotenv.config();

async function startServer() {
  // Requirement 1: Validate startup environment configuration
  const config = validateStartupConfig();

  const app = express();
  const PORT = config.port;

  // Trust reverse proxy (Cloud Run / Nginx) for accurate client IP in rate limiting
  app.set('trust proxy', 1);

  // Request correlation ID middleware (must run first to assign req.id)
  app.use(requestIdMiddleware);

  // Security headers & CORS
  app.use(securityHeadersMiddleware);
  app.use(corsMiddleware);

  // Rate limiting for API requests
  app.use('/api', apiRateLimiter);

  // Requirement 11: Configure request body size limit (2MB)
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ limit: '2mb', extended: true }));

  // Handle payload too large error safely
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    if (err && (err.type === 'entity.too.large' || err.status === 413)) {
      const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
      logger.error('REQUEST_PAYLOAD_TOO_LARGE', {
        requestId: reqId,
        route: req.originalUrl,
      });
      return res.status(413).json({
        error: {
          code: 'PAYLOAD_TOO_LARGE',
          message: 'Request payload exceeds maximum allowed size limit of 2MB',
          requestId: reqId,
        },
      });
    }
    next(err);
  });

  // Verify database connectivity & seed relational or in-memory fallback database
  try {
    logger.info('DATABASE_VERIFICATION_INIT', { message: 'Starting PostgreSQL verification' });
    const isDbConnected = await verifyDatabaseConnection();
    if (isDbConnected) {
      await seedDatabase();
    } else {
      logger.warn('DATABASE_INIT_UNAVAILABLE', { message: 'PostgreSQL unavailable at startup; seeding in-memory fallback database' });
      await seedDatabase();
    }
  } catch (err) {
    logger.error('DATABASE_INIT_ERROR', { error: err instanceof Error ? err.message : String(err) });
  }

  // Health, Liveness, Readiness check endpoints
  app.use('/health', healthRouter);
  app.use('/api/health', healthRouter);

  // Mount API v1 router
  app.use('/api/v1', v1Router);

  // Requirement 15: Handle 404 for unknown API endpoints
  app.use('/api/*', (req: Request, res: Response) => {
    const reqId = req.id || (req.headers['x-request-id'] as string) || 'no-request-id';
    res.status(404).json({
      error: {
        code: 'NOT_FOUND',
        message: `API endpoint '${req.originalUrl}' not found`,
        requestId: reqId,
      },
    });
  });

  // Vite middleware for development vs static serve for production
  if (config.env !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    logger.info('SERVER_STARTED', { host: '0.0.0.0', port: PORT, env: config.env });
  });

  // Requirement 12: Configure HTTP server timeouts (30s request, 31s headers)
  server.requestTimeout = 30000;
  server.headersTimeout = 31000;

  // Requirement 17: Process level resilience & shutdown handling
  const gracefulShutdown = async (signal: string) => {
    logger.info('SERVER_SHUTDOWN_INIT', { signal });
    
    server.close(async () => {
      logger.info('SERVER_HTTP_CLOSED', { message: 'HTTP server closed successfully' });
      await closeDatabasePool();
      logger.info('SERVER_SHUTDOWN_COMPLETE', { message: 'Database pool closed cleanly' });
      process.exit(0);
    });

    setTimeout(async () => {
      logger.warn('SERVER_SHUTDOWN_TIMEOUT', { message: 'Forcing shutdown after 10s timeout' });
      await closeDatabasePool();
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  process.on('uncaughtException', (err) => {
    logger.error('UNCAUGHT_EXCEPTION', { error: err.message, stack: err.stack });
    gracefulShutdown('uncaughtException');
  });

  process.on('unhandledRejection', (reason) => {
    logger.error('UNHANDLED_REJECTION', {
      reason: reason instanceof Error ? reason.message : String(reason),
    });
  });
}

startServer();
