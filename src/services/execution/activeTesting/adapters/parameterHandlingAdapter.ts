import {
  ActiveExecutionContext,
  ActiveExecutionObservation,
  ActiveTestingAdapter,
  ControlledRequestBuilderInterface,
} from '../activeTestingTypes.ts';

export const parameterHandlingAdapter: ActiveTestingAdapter = {
  capabilityId: 'active-parameter-handling-validation',
  aliases: ['active-parameter-validation', 'parameter-handling-adapter'],
  name: 'Parameter Handling & Pollution Validation',
  description: 'Tests parameter parsing resilience against duplicate parameters (HTTP Parameter Pollution) and benign format variations.',
  authorizationTier: 'APPROVAL_REQUIRED',
  enabled: true,

  async execute(
    context: ActiveExecutionContext,
    builder: ControlledRequestBuilderInterface
  ): Promise<ActiveExecutionObservation[]> {
    const observations: ActiveExecutionObservation[] = [];

    // Probe 1: Standard single parameter request
    const singleParamProbe = await builder.send({
      method: 'GET',
      path: '/?test_param=alpha',
      mutationTag: 'single_param',
      mutationDescription: 'Baseline request with single query parameter',
    });

    // Probe 2: Duplicate parameter (HPP probe)
    const duplicateParamProbe = await builder.send({
      method: 'GET',
      path: '/?test_param=alpha&test_param=beta',
      mutationTag: 'duplicate_param_hpp',
      mutationDescription: 'Duplicate query parameter test (HPP)',
    });

    // Probe 3: Empty string parameter
    const emptyParamProbe = await builder.send({
      method: 'GET',
      path: '/?test_param=',
      mutationTag: 'empty_param',
      mutationDescription: 'Empty parameter value test',
    });

    // Probe 4: Array-formatted parameter
    const arrayParamProbe = await builder.send({
      method: 'GET',
      path: '/?test_param[]=alpha&test_param[]=beta',
      mutationTag: 'array_param_format',
      mutationDescription: 'Array formatted parameter test',
    });

    const isServerErrorOnHpp = duplicateParamProbe.statusCode >= 500;
    const isServerErrorOnEmpty = emptyParamProbe.statusCode >= 500;
    const isServerErrorOnArray = arrayParamProbe.statusCode >= 500;

    const hasUnhandledException = isServerErrorOnHpp || isServerErrorOnEmpty || isServerErrorOnArray;

    observations.push({
      observationId: `obs-param-handling-${Date.now()}-1`,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      programId: context.programId,
      caseId: context.caseId,
      requestId: context.requestId,
      timestamp: new Date().toISOString(),
      observationType: 'PARAMETER_HANDLING_ANALYSIS',
      target: builder.getTarget(),
      sanitizedData: {
        target: builder.getTarget(),
        singleParamStatus: singleParamProbe.statusCode,
        duplicateParamStatus: duplicateParamProbe.statusCode,
        emptyParamStatus: emptyParamProbe.statusCode,
        arrayParamStatus: arrayParamProbe.statusCode,
        isServerErrorOnHpp,
        isServerErrorOnEmpty,
        isServerErrorOnArray,
        hasUnhandledException,
        riskLevel: hasUnhandledException ? 'MEDIUM' : 'LOW',
        recommendation: hasUnhandledException
          ? 'Add input sanitization and exception handling for unconventional query parameter structures'
          : 'Query parameter parsing handles duplicates and empty values gracefully',
      },
    });

    return observations;
  },
};
