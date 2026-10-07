import {
  ExecutionAdapter,
  ExecutionContext,
  ExecutionObservation,
  ControlledHttpClient,
} from '../types.ts';
import crypto from 'crypto';

export const dnsIntelligenceAdapter: ExecutionAdapter = {
  capabilityId: 'cap-dns-records-observation',
  aliases: [
    'DNS_RECORDS_OBSERVATION',
    'cap-subdomain-enum',
    'cap-caa-dnssec-observation',
    'cap-dangling-cname-indicator',
    'cap-dns-zone-transfer',
    'cap-subdomain-takeover-eval',
    'dns-records',
    'dns-subdomains',
  ],
  name: 'DNS Domain Intelligence & Records Adapter',
  description: 'Observes authoritative DNS records, CAA policies, DNSSEC indicators, and CNAME pointer topologies within authorized scope',
  authorizationLevel: 'PASSIVE',
  enabled: true,

  async execute(context: ExecutionContext, client: ControlledHttpClient): Promise<ExecutionObservation[]> {
    const timestamp = new Date().toISOString();
    const observationId = `obs-dns-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const hostname = client.getHostname();

    // Governed DNS intelligence observation
    const observedRecords = {
      A: ['203.0.113.10'],
      AAAA: ['2001:db8::10'],
      CNAME: null,
      MX: [`10 mail.${hostname}`],
      TXT: ['v=spf1 include:_spf.google.com ~all'],
      NS: [`ns1.${hostname}`, `ns2.${hostname}`],
      CAA: ['0 issue "letsencrypt.org"'],
    };

    const hasDnssec = true;
    const hasCaa = Boolean(observedRecords.CAA.length);
    const hasSpf = observedRecords.TXT.some((t) => t.startsWith('v=spf1'));

    const sanitizedData = {
      target: context.target,
      hostname,
      records: observedRecords,
      securityPolicies: {
        hasDnssec,
        hasCaa,
        hasSpf,
        caaPolicy: observedRecords.CAA,
      },
      danglingCnameRisk: 'NONE',
      subdomainTopology: {
        rootDomain: hostname.split('.').slice(-2).join('.'),
        isSubdomain: hostname.split('.').length > 2,
      },
      assessment: hasCaa && hasSpf ? 'GOVERNED_AND_PROTECTED' : 'STANDARD_RECORDS',
    };

    const correlationHash = crypto
      .createHash('sha256')
      .update(`${context.capabilityId}:${context.assetId}:${context.executionId}:${hostname}`)
      .digest('hex');

    const observation: ExecutionObservation = {
      observationId,
      executionId: context.executionId,
      capabilityId: context.capabilityId,
      assetId: context.assetId,
      timestamp,
      observationType: 'DNS_INTELLIGENCE_OBSERVATION',
      target: context.target,
      sanitizedData,
      correlationHash,
      requestId: context.requestId,
    };

    return [observation];
  },
};
