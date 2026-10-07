import crypto from 'crypto';
import { TechnologyFingerprint } from './types.ts';

interface Rule {
  technology: string;
  category: TechnologyFingerprint['category'];
  confidence: TechnologyFingerprint['confidence'];
  test: (ctx: { headers: Record<string, string>; body: string; url: string }) => boolean;
  indicator: string;
}

const RULES: Rule[] = [
  {
    technology: 'React',
    category: 'frontend',
    confidence: 'MEDIUM',
    indicator: 'data-reactroot / __NEXT_DATA__ / react',
    test: ({ body }) => /data-reactroot|__NEXT_DATA__|react-dom/i.test(body),
  },
  {
    technology: 'Next.js',
    category: 'frontend',
    confidence: 'HIGH',
    indicator: '__NEXT_DATA__',
    test: ({ body }) => /__NEXT_DATA__/i.test(body),
  },
  {
    technology: 'Express',
    category: 'backend',
    confidence: 'MEDIUM',
    indicator: 'X-Powered-By: Express',
    test: ({ headers }) => /express/i.test(headers['x-powered-by'] || ''),
  },
  {
    technology: 'nginx',
    category: 'server',
    confidence: 'HIGH',
    indicator: 'Server: nginx',
    test: ({ headers }) => /nginx/i.test(headers['server'] || ''),
  },
  {
    technology: 'Apache',
    category: 'server',
    confidence: 'HIGH',
    indicator: 'Server: Apache',
    test: ({ headers }) => /apache/i.test(headers['server'] || ''),
  },
  {
    technology: 'Cloudflare',
    category: 'cdn',
    confidence: 'HIGH',
    indicator: 'cf-ray / server cloudflare',
    test: ({ headers }) =>
      !!(headers['cf-ray'] || /cloudflare/i.test(headers['server'] || '')),
  },
  {
    technology: 'Django',
    category: 'framework',
    confidence: 'MEDIUM',
    indicator: 'csrfmiddlewaretoken / Django',
    test: ({ body, headers }) =>
      /csrfmiddlewaretoken/i.test(body) || /django/i.test(headers['x-framework'] || ''),
  },
  {
    technology: 'JSON API',
    category: 'api',
    confidence: 'MEDIUM',
    indicator: 'application/json content-type',
    test: ({ headers }) => /application\/json/i.test(headers['content-type'] || ''),
  },
];

function normHeaders(h: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h || {})) out[k.toLowerCase()] = String(v);
  return out;
}

export function fingerprintTechnology(params: {
  url: string;
  headers: Record<string, string>;
  body: string;
  evidenceRef: string;
}): TechnologyFingerprint[] {
  const headers = normHeaders(params.headers);
  const results: TechnologyFingerprint[] = [];
  for (const rule of RULES) {
    if (rule.test({ headers, body: params.body || '', url: params.url })) {
      results.push({
        id: `tech-${crypto.randomBytes(4).toString('hex')}`,
        technology: rule.technology,
        category: rule.category,
        confidence: rule.confidence,
        evidenceRef: params.evidenceRef,
        sourceUrl: params.url,
        indicators: [rule.indicator],
      });
    }
  }
  return results;
}
