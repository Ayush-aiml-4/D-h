import { Router, Request, Response } from 'express';
import { verifyDatabaseConnection, getPoolStats, isPostgresConfigured } from '../db/index.ts';

const router = Router();

// Minimal app version
const APP_VERSION = process.env.APP_VERSION || '1.0.0';

// General health check: GET /health or GET /api/health
router.get('/', async (req: Request, res: Response) => {
  const isDbOk = await verifyDatabaseConnection();
  if (isDbOk || !isPostgresConfigured()) {
    return res.status(200).json({
      status: 'ok',
      database: isDbOk ? 'ok' : 'in-memory',
      version: APP_VERSION,
    });
  }
  return res.status(503).json({
    status: 'unhealthy',
    database: 'unhealthy',
    version: APP_VERSION,
  });
});

// Liveness probe: GET /health/live or GET /api/health/live
router.get('/live', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'live',
    timestamp: new Date().toISOString(),
  });
});

// Readiness probe: GET /health/ready or GET /api/health/ready
router.get('/ready', async (req: Request, res: Response) => {
  const isDbOk = await verifyDatabaseConnection();
  if (isDbOk || !isPostgresConfigured()) {
    const stats = getPoolStats();
    return res.status(200).json({
      status: 'ready',
      database: isDbOk ? 'connected' : 'in-memory',
      pool: {
        total: stats.total,
        idle: stats.idle,
        waiting: stats.waiting,
      },
    });
  }
  return res.status(503).json({
    status: 'unhealthy',
    database: 'disconnected',
  });
});

export default router;

