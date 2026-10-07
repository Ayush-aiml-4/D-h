import {
  ActiveExecutionContext,
  ActiveExecutionObservation,
  ActiveTestingAdapter,
  ControlledRequestBuilderInterface,
} from '../activeTestingTypes.ts';

export const securityHeaderMutationAdapter: ActiveTestingAdapter = {
  capabilityId: 'active-header-mutation-validation',
  aliases: ['active-headers', 'header-mutation-validation'],
  name: 'Security Header Mutation & Reflection Validation',
  description: 'Probes response variations against controlled benign request headers (Origin, Host variations, custom accept types).',
  authorizationTier: 'LOW_RISK_ACTIVE',
  enabled: true,

  async execute(
    context: ActiveExecutionContext,
    builder: ControlledRequestBuilderInterface
  ): Promise<ActiveExecutionObservation[]> {
    const observations: ActiveExecutionObservation[] = [];

    // Probe 1: Baseline Request
    const baseline = await builder.send({
      method: 'GET',
      mutationTag: 'baseline_request',
      mutationDescription: 'Baseline GET request',
    });

    // Probe 2: Origin Header Variation (testing for arbitrary origin reflection)
    const testOrigin = 'https://research-origin.security.test';
    const originProbe = await builder.send({
      method: 'GET',
      headers: {
        'Origin': testOrigin,
      },
      mutationTag: 'origin_probe',
      mutationDescription: 'Controlled Origin header variation probe',
    });

    // Probe 3: X-Forwarded-Host Variation (benign test domain)
    const forwardedHostProbe = await builder.send({
      method: 'GET',
      headers: {
        'X-Forwarded-Host': 'internal-probe.devilhunt.test',
      },
      mutationTag: 'forwarded_host_probe',
      mutationDescription: 'Controlled X-Forwarded-Host variation probe',
    });

    // Probe 4: Custom Accept Header (testing content negotiation resilience)
    const acceptProbe = await builder.send({
      method: 'GET',
      headers: {
        'Accept': 'application/json, text/plain, */*',
      },
      mutationTag: 'accept_negotiation_probe',
      mutationDescription: 'Content negotiation accept header probe',
    });

    const acaoHeader = originProbe.headers['access-control-allow-origin'];
    const reflectsOrigin = acaoHeader === testOrigin;
    const reflectsWildcardWithCreds =
      acaoHeader === '*' && originProbe.headers['access-control-allow-credentials'] === 'true';

    const forwardedHostReflectedInLocation =
      Boolean(forwardedHostProbe.headers['location']?.includes('internal-probe.devilhunt.test'));

    observations.push({
      observationId: `obs-header-mut-${Date.now()}-1`,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      programId: context.programId,
      caseId: context.caseId,
      requestId: context.requestId,
      timestamp: new Date().toISOString(),
      observationType: 'HEADER_MUTATION_ANALYSIS',
      target: builder.getTarget(),
      sanitizedData: {
        target: builder.getTarget(),
        baselineStatus: baseline.statusCode,
        originProbe: {
          testOrigin,
          reflectedAcao: acaoHeader || 'NONE',
          reflectsOrigin,
          reflectsWildcardWithCreds,
        },
        forwardedHostProbe: {
          status: forwardedHostProbe.statusCode,
          reflectedInLocation: forwardedHostReflectedInLocation,
        },
        acceptProbe: {
          status: acceptProbe.statusCode,
          contentType: acceptProbe.headers['content-type'] || 'unknown',
        },
        hasAnomalousReflection: reflectsOrigin || reflectsWildcardWithCreds || forwardedHostReflectedInLocation,
        riskLevel: reflectsWildcardWithCreds ? 'HIGH' : reflectsOrigin ? 'MEDIUM' : 'LOW',
        recommendation: reflectsOrigin
          ? 'Enforce strict origin whitelist for Cross-Origin Resource Sharing'
          : 'Headers properly isolated against unhandled mutations',
      },
    });

    return observations;
  },
};
