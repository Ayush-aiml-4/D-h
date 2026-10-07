import {
  DestinationPolicyDecision,
  DestinationClass,
  ParsedUrl,
  ResolutionResult,
} from '../../types/serverInteractionResearch.ts';

// Known dangerous/sensitive internal infrastructure ports
const SENSITIVE_FORBIDDEN_PORTS = new Set([
  21, // FTP
  22, // SSH
  23, // Telnet
  25, // SMTP
  53, // DNS
  69, // TFTP
  110, // POP3
  135, // RPC
  139, // NetBIOS
  445, // SMB
  1433, // MSSQL
  1521, // Oracle
  3306, // MySQL
  5432, // PostgreSQL
  6379, // Redis
  9200, // Elasticsearch
  11211, // Memcached
  27017, // MongoDB
]);

const ALLOWED_STANDARD_PORTS = new Set([
  80, 443, 8000, 8080, 8443, 8888, 3000,
]);

/**
 * Evaluates whether a destination URL and its DNS resolution are permitted to be requested.
 */
export function evaluateDestinationPolicy(
  parsedUrl: ParsedUrl,
  resolution: ResolutionResult
): DestinationPolicyDecision {
  // 1. Scheme check
  if (!parsedUrl.isValidScheme || !parsedUrl.isValid) {
    return {
      decision: 'BLOCK',
      reason: parsedUrl.validationError || 'Invalid or prohibited URL scheme',
      destinationClass: 'INVALID',
      isRestricted: true,
      violatedRule: 'SCHEME_RESTRICTION',
    };
  }

  // 2. Port policy check
  if (SENSITIVE_FORBIDDEN_PORTS.has(parsedUrl.port)) {
    return {
      decision: 'BLOCK',
      reason: `Prohibited sensitive port: ${parsedUrl.port}`,
      destinationClass: resolution.destinationClass,
      isRestricted: true,
      violatedRule: 'SENSITIVE_PORT_RESTRICTION',
    };
  }

  // 3. Destination class evaluation on resolved address (precedence over original hostname)
  const effectiveClass: DestinationClass = resolution.destinationClass;

  switch (effectiveClass) {
    case 'METADATA':
      return {
        decision: 'BLOCK',
        reason: 'Cloud provider metadata and instance identity services are strictly blocked',
        destinationClass: 'METADATA',
        isRestricted: true,
        violatedRule: 'CLOUD_METADATA_BOUNDARY_DEFENSE',
      };

    case 'LOOPBACK':
      return {
        decision: 'DENY',
        reason: 'Loopback and local host destinations (127.0.0.0/8, ::1) are strictly prohibited',
        destinationClass: 'LOOPBACK',
        isRestricted: true,
        violatedRule: 'LOOPBACK_INTERACTION_DEFENSE',
      };

    case 'PRIVATE_RFC1918':
      return {
        decision: 'DENY',
        reason: 'Private RFC1918 internal subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are strictly prohibited',
        destinationClass: 'PRIVATE_RFC1918',
        isRestricted: true,
        violatedRule: 'RFC1918_PRIVATE_BOUNDARY_DEFENSE',
      };

    case 'LINK_LOCAL':
      return {
        decision: 'DENY',
        reason: 'Link-local addresses (169.254.0.0/16, fe80::/10) are strictly prohibited',
        destinationClass: 'LINK_LOCAL',
        isRestricted: true,
        violatedRule: 'LINK_LOCAL_BOUNDARY_DEFENSE',
      };

    case 'UNSPECIFIED':
      return {
        decision: 'DENY',
        reason: 'Unspecified and zero-network addresses (0.0.0.0/8, ::) are strictly prohibited',
        destinationClass: 'UNSPECIFIED',
        isRestricted: true,
        violatedRule: 'UNSPECIFIED_ADDRESS_DEFENSE',
      };

    case 'INVALID':
      return {
        decision: 'BLOCK',
        reason: 'Unresolvable or invalid destination address',
        destinationClass: 'INVALID',
        isRestricted: true,
        violatedRule: 'INVALID_DESTINATION_DEFENSE',
      };

    case 'CONTROLLED_FIXTURE':
      if (parsedUrl.canonicalHostname.includes('safe')) {
        return {
          decision: 'ALLOW',
          reason: 'Authorized controlled research fixture (safe test endpoint)',
          destinationClass: 'CONTROLLED_FIXTURE',
          isRestricted: false,
        };
      }
      return {
        decision: 'DENY',
        reason: 'Controlled fixture models an internal private destination',
        destinationClass: 'CONTROLLED_FIXTURE',
        isRestricted: true,
        violatedRule: 'CONTROLLED_FIXTURE_POLICY',
      };

    case 'PUBLIC_EXTERNAL':
    default:
      return {
        decision: 'ALLOW',
        reason: 'Routable public external destination',
        destinationClass: 'PUBLIC_EXTERNAL',
        isRestricted: false,
      };
  }
}
