import { ControlledValidator } from './types.ts';
import { securityHeadersValidator } from './validators/securityHeadersValidator.ts';
import { cspValidator } from './validators/cspValidator.ts';
import { hstsValidator } from './validators/hstsValidator.ts';
import { cookieValidator } from './validators/cookieValidator.ts';
import { corsValidator } from './validators/corsValidator.ts';
import { tlsValidator } from './validators/tlsValidator.ts';
import { debugDisclosureValidator } from './validators/debugDisclosureValidator.ts';
import { directoryListingValidator } from './validators/directoryListingValidator.ts';
import { backupExposureValidator } from './validators/backupExposureValidator.ts';
import { sourcemapValidator } from './validators/sourcemapValidator.ts';
import { javascriptSecretValidator } from './validators/javascriptSecretValidator.ts';
import { sensitiveInfoValidator } from './validators/sensitiveInfoValidator.ts';

export const controlledValidators: ControlledValidator[] = [
  securityHeadersValidator,
  cspValidator,
  hstsValidator,
  cookieValidator,
  corsValidator,
  tlsValidator,
  debugDisclosureValidator,
  directoryListingValidator,
  backupExposureValidator,
  sourcemapValidator,
  javascriptSecretValidator,
  sensitiveInfoValidator,
];

export function getControlledValidator(idOrAlias: string): ControlledValidator | undefined {
  if (!idOrAlias) return undefined;
  const target = idOrAlias.trim().toLowerCase();

  return controlledValidators.find(
    (validator) =>
      validator.validationId.toLowerCase() === target ||
      validator.supportedCapability.toLowerCase() === target ||
      validator.aliases.some((alias) => alias.toLowerCase() === target)
  );
}
