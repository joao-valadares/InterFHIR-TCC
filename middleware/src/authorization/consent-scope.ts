import {
  assertFhirReference,
  assertScopeShape,
  assertValidPeriod,
  canonicalizeAuthorizationDateTime,
  computeConsentProjectionHash,
  getConsentProjection,
  validateConsentScopePolicy,
  type PatientConsentGrant,
  type PatientConsentScope
} from "./authorization-model.js";

export function createPatientConsentScope(scope: PatientConsentScope): PatientConsentScope {
  assertScopeShape(scope);
  const purpose = normalizePurpose(scope.purposeOfUse);
  const normalizedScope = {
    ...scope,
    purposeOfUse: purpose,
    validFrom: canonicalizeAuthorizationDateTime(scope.validFrom),
    validUntil: canonicalizeAuthorizationDateTime(scope.validUntil)
  };
  assertValidPeriod(normalizedScope.validFrom, normalizedScope.validUntil);
  validateConsentScopePolicy(normalizedScope);
  return {
    ...normalizedScope
  };
}

export function validatePatientConsentScope(scope: PatientConsentScope): void {
  createPatientConsentScope(scope);
}

export function hashPatientConsentScope(scope: PatientConsentScope): string {
  const validated = createPatientConsentScope(scope);
  return computeConsentProjectionHash({
    consentReference: "Consent/scope",
    consentVersion: "1",
    scope: validated,
    status: "active"
  });
}

export function buildPatientConsentGrant(input: {
  consentReference: string;
  consentVersion: string;
  scope: PatientConsentScope;
  status?: PatientConsentGrant["status"];
}): PatientConsentGrant {
  assertFhirReference(input.consentReference, "INVALID_CONSENT_REFERENCE", "Consent");
  if (typeof input.consentVersion !== "string" || !/^\d+$/.test(input.consentVersion)) {
    throw new Error("INVALID_CONSENT_VERSION");
  }
  const scope = createPatientConsentScope(input.scope);
  const status = input.status ?? "active";
  if (status !== "active" && status !== "revoked" && status !== "superseded") {
    throw new Error("INVALID_CONSENT_STATUS");
  }
  return {
    consentReference: input.consentReference,
    consentVersion: input.consentVersion,
    consentProjectionHash: computeConsentProjectionHash({
      consentReference: input.consentReference,
      consentVersion: input.consentVersion,
      scope,
      status
    }),
    scope,
    status
  };
}

export function buildPatientConsentProjection(input: {
  consentReference: string;
  consentVersion: string;
  scope: PatientConsentScope;
  status?: PatientConsentGrant["status"];
}) {
  const grant = buildPatientConsentGrant(input);
  return getConsentProjection({
    consentReference: grant.consentReference,
    consentVersion: grant.consentVersion,
    scope: grant.scope,
    status: grant.status
  });
}

export const createPatientConsentGrant = buildPatientConsentGrant;

export { getConsentProjection } from "./authorization-model.js";

function normalizePurpose(value: string): string {
  const normalized = value.toUpperCase();
  if (normalized !== "TREAT" && normalized !== "HPAYMT") {
    throw new Error("INVALID_CONSENT_PURPOSE");
  }
  return normalized;
}
