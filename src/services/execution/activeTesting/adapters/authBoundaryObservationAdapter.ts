import {
  ActiveExecutionContext,
  ActiveExecutionObservation,
  ActiveTestingAdapter,
  ControlledRequestBuilderInterface,
} from '../activeTestingTypes.ts';

export const authBoundaryObservationAdapter: ActiveTestingAdapter = {
  capabilityId: 'active-auth-boundary-observation',
  aliases: ['active-auth-boundary', 'auth-boundary-observation'],
  name: 'Authorization Boundary & Access Differential Observation',
  description: 'Observes differential response behaviors between unauthenticated and controlled token states without credential theft or replay.',
  authorizationTier: 'APPROVAL_REQUIRED',
  enabled: true,

  async execute(
    context: ActiveExecutionContext,
    builder: ControlledRequestBuilderInterface
  ): Promise<ActiveExecutionObservation[]> {
    const observations: ActiveExecutionObservation[] = [];

    // Probe 1: Unauthenticated request baseline
    const unauthBaseline = await builder.send({
      method: 'GET',
      mutationTag: 'unauthenticated_baseline',
      mutationDescription: 'Baseline request without authorization credentials',
    });

    // Probe 2: Malformed synthetic token format (benign non-functional structure)
    const malformedAuthProbe = await builder.send({
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-synthetic-probe-token-null',
      },
      mutationTag: 'malformed_token_probe',
      mutationDescription: 'Controlled synthetic token probe',
    });

    // Probe 3: Custom mock role header probe (checking for insecure client-supplied role trust)
    const clientRoleHeaderProbe = await builder.send({
      method: 'GET',
      headers: {
        'X-User-Role': 'admin',
        'X-Role': 'admin',
      },
      mutationTag: 'client_role_header_probe',
      mutationDescription: 'Checking if backend trusts client-supplied role headers',
    });

    const isUnauthProtected = unauthBaseline.statusCode === 401 || unauthBaseline.statusCode === 403;
    const handlesMalformedGracefully =
      malformedAuthProbe.statusCode === 401 || malformedAuthProbe.statusCode === 403 || malformedAuthProbe.statusCode === 400;
    const serverErrorOnMalformed = malformedAuthProbe.statusCode >= 500;

    // Check if client role headers change status from 401/403 to 200 (insecure header trust)
    const improperRoleTrust =
      (unauthBaseline.statusCode === 401 || unauthBaseline.statusCode === 403) &&
      clientRoleHeaderProbe.statusCode === 200;

    observations.push({
      observationId: `obs-auth-boundary-${Date.now()}-1`,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      programId: context.programId,
      caseId: context.caseId,
      requestId: context.requestId,
      timestamp: new Date().toISOString(),
      observationType: 'AUTH_BOUNDARY_ANALYSIS',
      target: builder.getTarget(),
      sanitizedData: {
        target: builder.getTarget(),
        unauthenticatedStatus: unauthBaseline.statusCode,
        malformedAuthStatus: malformedAuthProbe.statusCode,
        roleHeaderProbeStatus: clientRoleHeaderProbe.statusCode,
        isUnauthProtected,
        handlesMalformedGracefully,
        serverErrorOnMalformed,
        improperRoleTrust,
        riskLevel: improperRoleTrust ? 'CRITICAL' : serverErrorOnMalformed ? 'MEDIUM' : 'INFO',
        recommendation: improperRoleTrust
          ? 'Never evaluate user authorization roles from client-supplied HTTP headers'
          : serverErrorOnMalformed
          ? 'Handle invalid authorization token formats gracefully without generating 500 internal server errors'
          : 'Authentication boundary responds deterministically across token variations',
      },
    });

    return observations;
  },
};
