import { CapabilityAnalyzer } from './types.ts';
import { securityHeaderAnalyzer } from './securityHeaders.ts';
import { cspAnalyzer } from './csp.ts';
import { hstsAnalyzer } from './hsts.ts';
import { cookieSecurityAnalyzer } from './cookies.ts';
import { corsAnalyzer } from './cors.ts';
import { tlsAnalyzer } from './tls.ts';
import { debugDisclosureAnalyzer } from './debugDisclosure.ts';
import { directoryListingAnalyzer } from './directoryListing.ts';
import { backupExposureAnalyzer } from './backupExposure.ts';
import { sourceMapAnalyzer } from './sourceMaps.ts';
import { javascriptSecretAnalyzer } from './javascriptSecrets.ts';
import { sensitiveInformationAnalyzer } from './sensitiveInformation.ts';

export const capabilityAnalyzers: CapabilityAnalyzer[] = [
  securityHeaderAnalyzer,
  cspAnalyzer,
  hstsAnalyzer,
  cookieSecurityAnalyzer,
  corsAnalyzer,
  tlsAnalyzer,
  debugDisclosureAnalyzer,
  directoryListingAnalyzer,
  backupExposureAnalyzer,
  sourceMapAnalyzer,
  javascriptSecretAnalyzer,
  sensitiveInformationAnalyzer,
];

export function getCapabilityAnalyzer(idOrAlias: string): CapabilityAnalyzer | undefined {
  if (!idOrAlias) return undefined;
  const target = idOrAlias.trim().toLowerCase();

  return capabilityAnalyzers.find(
    (analyzer) =>
      analyzer.capabilityId.toLowerCase() === target ||
      analyzer.aliases.some((alias) => alias.toLowerCase() === target)
  );
}
