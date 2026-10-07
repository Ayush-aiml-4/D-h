/** Researcher templates — no invented bounty/SLA/dates/program/assets/contacts */

export const templates = {
  acknowledgement: `Report received and queued for triage. Please do not expand testing if sensitive real-user data appears.`,

  clarification: (missing: string[]) =>
    `Additional information needed for triage: ${missing.join(', ')}. Please provide minimal reproducible detail only.`,

  outOfScope: `The reported asset or method is outside the program's explicit allowlist. Please stop testing that target.`,

  informative: `Thank you for the report. Under current program rules (including HackerOne Core Ineligible Findings where applicable), this does not present actionable security impact as submitted.`,

  duplicate: (primaryId: string) =>
    `This tracks an existing report (${primaryId}). Any additional security value has been noted where applicable.`,

  validated: `This report has been accepted as a valid security issue. Remediation is tracked internally.`,

  severityClarification: (notes: string) =>
    `Provisional severity notes: ${notes}. Factual corrections are welcome.`,

  additionalEvidence: `Please provide minimal redacted evidence only. Do not submit bulk personal data or live secrets.`,

  sensitiveDataStop: `Stop further testing on this issue. Purge unnecessary sensitive data and retain only the minimum evidence required for the report.`,

  remediationComplete: `A fix has been verified on our side. Limited retest only if explicitly requested.`,

  disclosurePending: `Coordinated disclosure is in progress. Do not publish details until a disclosure decision is recorded.`,

  finalClosure: (reason: string) => `This report is closed as: ${reason}. Thank you for your work.`,
};
