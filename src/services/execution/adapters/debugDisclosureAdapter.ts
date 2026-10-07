import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const debugDisclosureAdapter: ExecutionAdapter = {
  capabilityId: 'cap-debug-disclosure',
  aliases: [
    'DEBUG_ERROR_DISCLOSURE',
    'cap-debug-error-disclosure',
    'capability.debug-disclosure',
    'debug-disclosure',
    'stack-trace-disclosure',
  ],
  name: 'Debug & Verbose Error Disclosure Adapter',
  description: 'Checks for framework debug traces, stack traces, and verbose exception disclosure',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-debug-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;

    const targetPath = (context.parameters?.path as string) || '/';
    const response = await client.request({
      method: 'GET',
      path: targetPath,
    });

    const body = response.body || '';
    const headersStr = JSON.stringify(response.headers || {});

    const debugIndicators = [
      { pattern: /Traceback \(most recent call last\):/i, type: 'Python Stack Trace' },
      { pattern: /at\s+[\w\$.]+\((?:[a-zA-Z]:\\|\/).*:\d+:\d+\)/i, type: 'Node.js / V8 Stack Trace' },
      { pattern: /Fatal error:.*in\s+[\/\w\.-]+\.php\s+on\s+line\s+\d+/i, type: 'PHP Fatal Error' },
      { pattern: /org\.springframework\.|java\.lang\.[a-zA-Z]+Exception/i, type: 'Java Exception Trace' },
      { pattern: /Django\s+[\d\.]+\s+DEBUG\s+page/i, type: 'Django Debug Page' },
      { pattern: /Laravel\s+Ignition\s+Error|Whoops!\s+There\s+was\s+an\s+error/i, type: 'Laravel Ignition Page' },
      { pattern: /PG::Error|SQLite3::Exception|SQLSTATE\[\d+\]/i, type: 'Database Exception' },
      { pattern: /ASP\.NET\s+is\s+configured\s+to\s+show\s+verbose\s+errors/i, type: 'ASP.NET Debug Page' },
    ];

    const detectedTypes: string[] = [];
    for (const ind of debugIndicators) {
      if (ind.pattern.test(body) || ind.pattern.test(headersStr)) {
        detectedTypes.push(ind.type);
      }
    }

    const sanitizedData = {
      target: context.target,
      hostname: client.getHostname(),
      url: response.url,
      path: targetPath,
      statusCode: response.statusCode,
      hasDebugDisclosure: detectedTypes.length > 0,
      detectedDisclosureTypes: detectedTypes,
      bodyLength: body.length,
      isClean: detectedTypes.length === 0,
    };

    const rawCorrelation = `${context.capabilityId}:${context.assetId}:${context.executionId}:${detectedTypes.join(',')}`;
    const correlationHash = crypto.createHash('sha256').update(rawCorrelation).digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'DEBUG_DISCLOSURE_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
