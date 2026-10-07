/**
 * Devil Hunt live console API — mounted under /api/v1/devil-hunt
 */
import { Router, Response } from 'express';
import { AuthRequest } from '../middleware/auth.ts';
import {
  getDevilHuntState,
  startHunt,
  pauseHunt,
  resumeHunt,
  stopHunt,
  clearView,
  ingestRequest,
  approveTest,
  rejectTest,
  exportJSON,
  exportCSV,
  exportMarkdown,
} from '../services/devilHunt/liveConsoleStore.ts';

const router = Router();

function reqId(req: AuthRequest) {
  return (req as any).requestId || 'no-request-id';
}

router.get('/state', (_req: AuthRequest, res: Response) => {
  res.json({ state: getDevilHuntState(), requestId: reqId(_req) });
});

router.post('/start', (req: AuthRequest, res: Response) => {
  const r = startHunt({
    huntId: typeof req.body?.huntId === 'string' ? req.body.huntId : undefined,
    target: typeof req.body?.target === 'string' ? req.body.target : undefined,
  });
  res.status(r.ok ? 200 : 400).json({ ...r, requestId: reqId(req) });
});

router.post('/pause', (req: AuthRequest, res: Response) => {
  res.json({ ...pauseHunt(), requestId: reqId(req) });
});

router.post('/resume', (req: AuthRequest, res: Response) => {
  const r = resumeHunt();
  res.status(r.ok ? 200 : 400).json({ ...r, requestId: reqId(req) });
});

router.post('/stop', (req: AuthRequest, res: Response) => {
  res.json({ ...stopHunt(), requestId: reqId(req) });
});

router.post('/clear-view', (req: AuthRequest, res: Response) => {
  res.json({ ...clearView(), requestId: reqId(req) });
});

router.post('/ingest', (req: AuthRequest, res: Response) => {
  const body = req.body || {};
  const r = ingestRequest({
    method: body.method,
    host: body.host,
    path: body.path,
    queryParamNames: Array.isArray(body.queryParamNames) ? body.queryParamNames : [],
    bodyKeys: Array.isArray(body.bodyKeys) ? body.bodyKeys : [],
    status: typeof body.status === 'number' ? body.status : null,
    responseHeaderNames: Array.isArray(body.responseHeaderNames) ? body.responseHeaderNames : [],
    responseStructure: typeof body.responseStructure === 'string' ? body.responseStructure : undefined,
    category: typeof body.category === 'string' ? body.category : undefined,
    authState: typeof body.authState === 'string' ? body.authState : undefined,
  });
  res.status(r.ok ? 200 : 400).json({ ...r, requestId: reqId(req) });
});

router.post('/approve', (req: AuthRequest, res: Response) => {
  const r = approveTest();
  res.status(r.ok ? 200 : 400).json({ ...r, requestId: reqId(req) });
});

router.post('/reject', (req: AuthRequest, res: Response) => {
  const r = rejectTest();
  res.status(r.ok ? 200 : 400).json({ ...r, requestId: reqId(req) });
});

router.get('/export/json', (_req: AuthRequest, res: Response) => {
  const data = exportJSON();
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="devil-hunt-export.json"');
  res.send(data);
});

router.get('/export/csv', (_req: AuthRequest, res: Response) => {
  const data = exportCSV();
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="devil-hunt-export.csv"');
  res.send(data);
});

router.get('/export/md', (_req: AuthRequest, res: Response) => {
  const data = exportMarkdown();
  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', 'attachment; filename="devil-hunt-report.md"');
  res.send(data);
});

export default router;
