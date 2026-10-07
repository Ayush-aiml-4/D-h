import {
  AuthorizationHypothesis,
  DifferentialAnalysisResult,
  DifferentialExecutionSnapshot,
  DifferentialDifferences,
  ConfidenceRating,
  ImpactAssessment,
} from '../../types/authorizationResearch.ts';
import { sanitizeAndRedact } from '../capabilities/utils.ts';

const SENSITIVE_FIELD_NAMES = [
  'email',
  'phonenumber',
  'phone',
  'mobile',
  'ssn',
  'nationalid',
  'bankaccount',
  'accountnumber',
  'cardnumber',
  'creditcard',
  'cvv',
  'address',
  'shippingaddress',
  'billingaddress',
  'totalamount',
  'grandtotal',
  'orderamount',
  'price',
  'privatenotes',
  'internalcomments',
  'secret',
  'token',
  'apikey',
  'authkey',
  'password',
  'hash',
  'adminsettings',
  'systemconfig',
];

export function extractSensitiveFields(data: any): string[] {
  const exposed: string[] = [];
  if (!data || typeof data !== 'object') return exposed;

  function traverse(obj: any, prefix: string = '') {
    if (!obj || typeof obj !== 'object') return;
    for (const key of Object.keys(obj)) {
      const fullPath = prefix ? `${prefix}.${key}` : key;
      const cleanKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');

      if (SENSITIVE_FIELD_NAMES.some((s) => cleanKey.includes(s))) {
        const val = obj[key];
        if (val !== null && val !== undefined && val !== '') {
          exposed.push(fullPath);
        }
      }

      if (typeof obj[key] === 'object') {
        traverse(obj[key], fullPath);
      }
    }
  }

  traverse(data);
  return exposed;
}

export function containsOwnerData(responseBody: any, ownerAccount: string, resourceId: string): boolean {
  if (!responseBody) return false;
  const str = typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody);
  return (
    (Boolean(ownerAccount) && str.includes(ownerAccount)) ||
    (Boolean(resourceId) && str.includes(resourceId))
  );
}

export class ResponseDifferentialEngine {
  /**
   * Evaluates response differential between baseline and comparison executions for a hypothesis.
   */
  public analyzeDifferential(params: {
    hypothesis: AuthorizationHypothesis;
    baselineSnapshot: DifferentialExecutionSnapshot;
    comparisonSnapshot: DifferentialExecutionSnapshot;
  }): DifferentialAnalysisResult {
    const { hypothesis, baselineSnapshot, comparisonSnapshot } = params;
    const resource = hypothesis.targetResource;

    const baselineStatus = baselineSnapshot.statusCode;
    const comparisonStatus = comparisonSnapshot.statusCode;

    const baselineOk = baselineStatus >= 200 && baselineStatus < 300;
    const comparisonOk = comparisonStatus >= 200 && comparisonStatus < 300;

    // Detect sensitive fields in comparison response
    const sensitiveFields = extractSensitiveFields(comparisonSnapshot.responseBody);
    const hasOwnerData = containsOwnerData(
      comparisonSnapshot.responseBody,
      resource.ownerAccount,
      resource.resourceId
    );

    const isWriteOrStateChange = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(hypothesis.httpMethod);

    // Evaluate differences
    const statusDiffers = baselineStatus !== comparisonStatus;
    const bodyDiffers =
      JSON.stringify(baselineSnapshot.responseBody) !== JSON.stringify(comparisonSnapshot.responseBody);

    // Check if comparison was expected to be DENIED but was ALLOWED / returned success
    const expectedComp = hypothesis.expectedComparisonAuth; // 'ALLOW' | 'DENY'
    const isUnauthorizedSuccess = expectedComp === 'DENY' && comparisonOk;

    // Check if comparison context received sensitive/owner data without authorization
    const unauthorizedDataAccess = isUnauthorizedSuccess && (sensitiveFields.length > 0 || hasOwnerData);

    const privilegeBoundaryViolated =
      hypothesis.researchClass === 'VERTICAL_ESCALATION' && isUnauthorizedSuccess;

    const stateChanged = isWriteOrStateChange && isUnauthorizedSuccess;

    const differences: DifferentialDifferences = {
      statusDiffers,
      bodyDiffers,
      sensitiveFieldsExposed: sensitiveFields,
      resourceOwnershipExposed: hasOwnerData,
      privilegeBoundaryViolated,
      stateChanged,
      unauthorizedDataAccess,
    };

    // Determine vulnerability candidacy & confidence
    let isVulnerabilityCandidate = false;
    let confidence: ConfidenceRating = 'LOW_CONFIDENCE';
    let vulnerabilityType: string | undefined;
    let cwe: string | undefined;
    let owasp: string | undefined;
    let explanation = '';

    if (expectedComp === 'DENY' && comparisonOk) {
      // Comparison context should have been denied, but succeeded (2xx)
      if (hypothesis.researchClass === 'BOLA_IDOR' || hypothesis.researchClass === 'HORIZONTAL_AUTH') {
        if (hasOwnerData || sensitiveFields.length > 0) {
          isVulnerabilityCandidate = true;
          confidence = 'HIGH_CONFIDENCE';
          vulnerabilityType = 'Broken Object Level Authorization (BOLA / IDOR)';
          cwe = 'CWE-639';
          owasp = 'API1:2023 - Broken Object Level Authorization';
          explanation = `Cross-account access was granted: Account '${hypothesis.comparisonContext.accountIdentifier}' accessed resource '${resource.resourceId}' owned by '${resource.ownerAccount}' with HTTP ${comparisonStatus} and received ${sensitiveFields.length} sensitive fields.`;
        } else {
          isVulnerabilityCandidate = true;
          confidence = 'MEDIUM_CONFIDENCE';
          vulnerabilityType = 'Potential Insecure Direct Object Reference';
          cwe = 'CWE-639';
          owasp = 'API1:2023 - Broken Object Level Authorization';
          explanation = `Account '${hypothesis.comparisonContext.accountIdentifier}' successfully accessed resource '${resource.resourceId}' (HTTP ${comparisonStatus}), but sensitive field exposure was limited or masked.`;
        }
      } else if (hypothesis.researchClass === 'VERTICAL_ESCALATION') {
        isVulnerabilityCandidate = true;
        confidence = 'HIGH_CONFIDENCE';
        vulnerabilityType = 'Vertical Privilege Escalation (Broken Function Level Authorization)';
        cwe = 'CWE-280';
        owasp = 'API5:2023 - Broken Function Level Authorization';
        explanation = `Unprivileged user '${hypothesis.comparisonContext.accountRole}' successfully accessed privileged endpoint '${hypothesis.endpoint}' (HTTP ${comparisonStatus}) requiring '${resource.roleRequired || 'ADMIN_USER'}'.`;
      } else if (hypothesis.researchClass === 'UNAUTHENTICATED_ACCESS') {
        if (resource.sensitivity !== 'PUBLIC') {
          isVulnerabilityCandidate = true;
          confidence = 'HIGH_CONFIDENCE';
          vulnerabilityType = 'Unauthenticated Sensitive API Access (Missing Authentication Check)';
          cwe = 'CWE-306';
          owasp = 'API2:2023 - Broken Authentication';
          explanation = `Unauthenticated request successfully accessed non-public resource '${resource.resourceId}' (Sensitivity: ${resource.sensitivity}) with HTTP ${comparisonStatus}.`;
        } else {
          // Intentionally public resource
          isVulnerabilityCandidate = false;
          confidence = 'LOW_CONFIDENCE';
          explanation = `Endpoint '${hypothesis.endpoint}' is intentionally public (Sensitivity: PUBLIC); 200 OK without authentication is expected behavior.`;
        }
      }
    } else if (expectedComp === 'DENY' && !comparisonOk) {
      // Properly denied (e.g. 401 Unauthorized or 403 Forbidden)
      isVulnerabilityCandidate = false;
      confidence = 'HIGH_CONFIDENCE';
      explanation = `Authorization boundary properly enforced: request from '${hypothesis.comparisonContext.contextLabel}' was rejected with HTTP ${comparisonStatus}.`;
    } else {
      explanation = `Differential test completed with baseline HTTP ${baselineStatus} and comparison HTTP ${comparisonStatus}.`;
    }

    // Impact assessment
    const impactAssessment: ImpactAssessment = this.evaluateImpact(
      hypothesis,
      isVulnerabilityCandidate,
      differences,
      resource.sensitivity
    );

    return {
      hypothesisId: hypothesis.hypothesisId,
      researchClass: hypothesis.researchClass,
      targetAsset: hypothesis.targetAsset,
      endpoint: hypothesis.endpoint,
      httpMethod: hypothesis.httpMethod,
      resourceId: resource.resourceId,
      baselineContextLabel: hypothesis.baselineContext.contextLabel,
      comparisonContextLabel: hypothesis.comparisonContext.contextLabel,
      baselineResult: baselineSnapshot,
      comparisonResult: comparisonSnapshot,
      differences,
      confidence,
      isVulnerabilityCandidate,
      vulnerabilityType,
      cwe,
      owasp,
      explanation,
      impactAssessment,
    };
  }

  private evaluateImpact(
    hypothesis: AuthorizationHypothesis,
    isVuln: boolean,
    diffs: DifferentialDifferences,
    sensitivity: string
  ): ImpactAssessment {
    if (!isVuln) {
      return {
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        privilegeImpact: 'NONE',
        overallImpact: 'NONE',
        reasoning: 'No authorization boundary failure detected; target properly enforced access controls.',
      };
    }

    let conf: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' = 'NONE';
    let integ: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' = 'NONE';
    let priv: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' = 'NONE';
    let overall: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'MEDIUM';

    if (diffs.unauthorizedDataAccess || diffs.sensitiveFieldsExposed.length > 0) {
      conf = sensitivity === 'FINANCIAL' || sensitivity === 'RESTRICTED_PII' ? 'HIGH' : 'MEDIUM';
    }

    if (diffs.stateChanged) {
      integ = 'HIGH';
    }

    if (diffs.privilegeBoundaryViolated) {
      priv = 'HIGH';
    }

    if (conf === 'HIGH' && (integ === 'HIGH' || priv === 'HIGH')) {
      overall = 'CRITICAL';
    } else if (conf === 'HIGH' || integ === 'HIGH' || priv === 'HIGH') {
      overall = 'HIGH';
    } else {
      overall = 'MEDIUM';
    }

    return {
      confidentialityImpact: conf,
      integrityImpact: integ,
      privilegeImpact: priv,
      overallImpact: overall,
      reasoning: `Confidentiality: ${conf}, Integrity: ${integ}, Privilege: ${priv}. Evaluated on resource sensitivity '${sensitivity}'.`,
    };
  }
}

export const responseDifferentialEngine = new ResponseDifferentialEngine();
