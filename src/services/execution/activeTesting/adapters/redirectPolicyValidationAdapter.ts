import {
  ActiveExecutionContext,
  ActiveExecutionObservation,
  ActiveTestingAdapter,
  ControlledRequestBuilderInterface,
} from '../activeTestingTypes.ts';

export const redirectPolicyValidationAdapter: ActiveTestingAdapter = {
  capabilityId: 'active-redirect-policy-validation',
  aliases: ['active-redirect-policy', 'redirect-policy-adapter'],
  name: 'Redirect & Transport Security Policy Validation',
  description: 'Validates redirect handling, HTTPS upgrade enforcement, and location header isolation safely without external crawling.',
  authorizationTier: 'LOW_RISK_ACTIVE',
  enabled: true,

  async execute(
    context: ActiveExecutionContext,
    builder: ControlledRequestBuilderInterface
  ): Promise<ActiveExecutionObservation[]> {
    const observations: ActiveExecutionObservation[] = [];

    // Probe 1: Direct root path request
    const rootRes = await builder.send({
      method: 'GET',
      path: '/',
      mutationTag: 'root_request',
      mutationDescription: 'Inspect root path response and redirect headers',
    });

    // Probe 2: Trailing slash variation
    const slashRes = await builder.send({
      method: 'GET',
      path: '/api/',
      mutationTag: 'slash_redirect_probe',
      mutationDescription: 'Inspect trailing slash redirect handling',
    });

    // Probe 3: Host header upgrade check
    const hostHeader = builder.getHostname();
    const isRedirect = (res: any) => res.statusCode >= 300 && res.statusCode < 400;

    const rootLocation = rootRes.headers['location'] || '';
    const slashLocation = slashRes.headers['location'] || '';

    const rootIsRedirect = isRedirect(rootRes);
    const slashIsRedirect = isRedirect(slashRes);

    const enforcesHttps =
      (rootIsRedirect && rootLocation.startsWith('https://')) ||
      (slashIsRedirect && slashLocation.startsWith('https://')) ||
      rootRes.headers['strict-transport-security'] !== undefined;

    const hasOpenRedirectClue =
      (rootLocation.startsWith('//') && !rootLocation.startsWith(`//${hostHeader}`)) ||
      (slashLocation.startsWith('//') && !slashLocation.startsWith(`//${hostHeader}`));

    observations.push({
      observationId: `obs-redirect-policy-${Date.now()}-1`,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      programId: context.programId,
      caseId: context.caseId,
      requestId: context.requestId,
      timestamp: new Date().toISOString(),
      observationType: 'REDIRECT_POLICY_ANALYSIS',
      target: builder.getTarget(),
      sanitizedData: {
        target: builder.getTarget(),
        rootStatusCode: rootRes.statusCode,
        rootLocation,
        slashStatusCode: slashRes.statusCode,
        slashLocation,
        enforcesHttps,
        hasOpenRedirectClue,
        riskLevel: hasOpenRedirectClue ? 'HIGH' : enforcesHttps ? 'INFO' : 'LOW',
        recommendation: hasOpenRedirectClue
          ? 'Sanitize Location headers to prevent protocol-relative open redirection'
          : 'Redirect and transport policies configured correctly',
      },
    });

    return observations;
  },
};
