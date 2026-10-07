import {
  ActiveExecutionContext,
  ActiveExecutionObservation,
  ActiveTestingAdapter,
  ControlledRequestBuilderInterface,
} from '../activeTestingTypes.ts';

export const httpMethodBehaviorAdapter: ActiveTestingAdapter = {
  capabilityId: 'active-http-method-validation',
  aliases: ['active-http-methods', 'http-verb-validation'],
  name: 'HTTP Method Behavior & Verb Tampering Validation',
  description: 'Tests server response to explicit HTTP verbs to detect method overrides, unsupported verbs, and unhandled behaviors safely.',
  authorizationTier: 'LOW_RISK_ACTIVE',
  enabled: true,

  async execute(
    context: ActiveExecutionContext,
    builder: ControlledRequestBuilderInterface
  ): Promise<ActiveExecutionObservation[]> {
    const observations: ActiveExecutionObservation[] = [];
    const testMethods = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'TRACE', 'PATCH'] as const;

    const methodResults: Record<string, { statusCode: number; allowHeader?: string; headers: Record<string, string> }> = {};

    for (const method of testMethods) {
      if (context.cancellationState.isCancelled) break;

      try {
        const res = await builder.send({
          method: method as any,
          mutationTag: `method_${method}`,
          mutationDescription: `Testing server response to HTTP ${method} verb`,
        });

        methodResults[method] = {
          statusCode: res.statusCode,
          allowHeader: res.headers['allow'],
          headers: res.headers,
        };
      } catch (err: any) {
        methodResults[method] = {
          statusCode: 0,
          headers: { error: err.message },
        };
      }
    }

    const optionsRes = methodResults['OPTIONS'];
    const traceRes = methodResults['TRACE'];
    const putRes = methodResults['PUT'];
    const deleteRes = methodResults['DELETE'];

    const allowsTrace = traceRes && traceRes.statusCode >= 200 && traceRes.statusCode < 300;
    const allowsPut = putRes && putRes.statusCode >= 200 && putRes.statusCode < 300;
    const allowsDelete = deleteRes && deleteRes.statusCode >= 200 && deleteRes.statusCode < 300;

    const allowedMethodsList = optionsRes?.allowHeader
      ? optionsRes.allowHeader.split(',').map((m) => m.trim().toUpperCase())
      : Object.keys(methodResults).filter((m) => methodResults[m]?.statusCode >= 200 && methodResults[m]?.statusCode < 400);

    observations.push({
      observationId: `obs-verb-${Date.now()}-1`,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      programId: context.programId,
      caseId: context.caseId,
      requestId: context.requestId,
      timestamp: new Date().toISOString(),
      observationType: 'HTTP_VERB_ANALYSIS',
      target: builder.getTarget(),
      sanitizedData: {
        target: builder.getTarget(),
        methodsTested: testMethods,
        methodResults,
        allowedMethodsList,
        allowsTrace,
        allowsPut,
        allowsDelete,
        hasVerbOverrideRisk: allowsTrace || allowsPut || allowsDelete,
        riskLevel: allowsTrace ? 'MEDIUM' : allowsPut || allowsDelete ? 'LOW' : 'INFO',
        recommendation: allowsTrace
          ? 'Disable TRACE method in web server configuration to prevent Cross-Site Tracing (XST)'
          : 'Enforce strict whitelist of permitted HTTP methods at API gateway',
      },
    });

    return observations;
  },
};
