import { ethers } from "ethers";

import {
  assertFhirReference,
  canonicalizeAuthorizationDateTime,
  computeConsentProjectionHash,
  hashIdentifier,
  hashReference,
  type PatientConsentGrant,
  type PatientConsentScope
} from "../authorization/authorization-model.js";
import {
  buildPatientConsentGrant,
  createPatientConsentScope
} from "../authorization/consent-scope.js";
import {
  getNetworkPolicyDefinition,
  parseNetworkPolicyReference
} from "../authorization/policy-definition.js";
import {
  ACTION_READ_CODE,
  PURPOSE_TREATMENT_CODE,
  REQUIRED_TREATMENT_OBSERVATION_MASK,
  RESOURCE_TYPE_ALLERGY_INTOLERANCE,
  RESOURCE_TYPE_CONDITION,
  RESOURCE_TYPE_DIAGNOSTIC_REPORT,
  RESOURCE_TYPE_DOCUMENT_REFERENCE,
  RESOURCE_TYPE_ENCOUNTER,
  RESOURCE_TYPE_IMMUNIZATION,
  RESOURCE_TYPE_MEDICATION_REQUEST,
  RESOURCE_TYPE_OBSERVATION,
  RESOURCE_TYPE_PROCEDURE,
  mapActionCode,
  mapPolicyMask,
  mapPurposeCode,
  mapResourceTypeCode
} from "../abac/policy-mask.js";

export {
  ACTION_READ_CODE,
  PURPOSE_TREATMENT_CODE,
  REQUIRED_TREATMENT_OBSERVATION_MASK,
  RESOURCE_TYPE_ALLERGY_INTOLERANCE,
  RESOURCE_TYPE_CONDITION,
  RESOURCE_TYPE_DIAGNOSTIC_REPORT,
  RESOURCE_TYPE_DOCUMENT_REFERENCE,
  RESOURCE_TYPE_ENCOUNTER,
  RESOURCE_TYPE_IMMUNIZATION,
  RESOURCE_TYPE_MEDICATION_REQUEST,
  RESOURCE_TYPE_OBSERVATION,
  RESOURCE_TYPE_PROCEDURE
};

export interface RegisterConsentInput {
  consentHash: string;
  consentIdHash: string;
  consentProjectionHash: string;
  consentVersion: string;
  patientHash: string;
  actorHash: string;
  actorConstraintHash: string;
  organizationHash: string;
  granteeOrganizationHash: string;
  resourceIdHash: string;
  policyIdHash: string;
  policyVersion: number;
  resourceTypeCode: number;
  actionCode: number;
  purposeCode: number;
  validFrom: number;
  validUntil: number;
  policyMask: number;
}

export interface LegacyRegisterConsentInput {
  consentHash: string;
  patientHash: string;
  actorHash: string;
  organizationHash: string;
  resourceIdHash: string;
  resourceTypeCode: number;
  actionCode: number;
  purposeCode: number;
  validFrom: number;
  validUntil: number;
  policyMask: number;
}

interface FhirCoding {
  code?: string;
}

interface FhirCodeableConcept {
  coding?: FhirCoding[];
  code?: string;
}

interface FhirReference {
  reference?: string;
}

interface FhirConsentActor {
  role?: FhirCodeableConcept;
  reference?: FhirReference;
}

interface FhirExtension {
  url?: string;
  valueIdentifier?: {
    system?: string;
    value?: string;
  };
}

interface FhirConsentProvision {
  type?: string;
  period?: {
    start?: string;
    end?: string;
  };
  actor?: FhirConsentActor[];
  action?: FhirCodeableConcept[];
  purpose?: FhirCoding[];
  class?: FhirCodeableConcept[];
  data?: Array<{ reference?: FhirReference }>;
  extension?: FhirExtension[];
}

export interface FhirConsent {
  resourceType?: string;
  id?: string;
  status?: string;
  meta?: { versionId?: string };
  patient?: FhirReference;
  organization?: FhirReference[];
  extension?: FhirExtension[];
  provision?: FhirConsentProvision;
}

interface ParsedConsent {
  grant: PatientConsentGrant;
  scope: PatientConsentScope;
  policyMask: number;
  resourceTypeCode: number;
  actionCode: number;
  purposeCode: number;
  validFrom: number;
  validUntil: number;
}

export function mapFhirConsentToRegisterConsentInput(consent: FhirConsent): RegisterConsentInput {
  const parsed = parseFhirConsent(consent);
  const patientHash = hashReference(parsed.scope.patientReference);
  const organizationHash = hashReference(parsed.scope.granteeOrganizationReference);
  const actorHash = parsed.scope.practitionerReference
    ? hashReference(parsed.scope.practitionerReference)
    : ethers.ZeroHash;
  const consentHash = hashReference(parsed.grant.consentReference);

  return {
    consentHash,
    consentIdHash: consentHash,
    consentProjectionHash: parsed.grant.consentProjectionHash,
    consentVersion: parsed.grant.consentVersion,
    patientHash,
    actorHash,
    actorConstraintHash: actorHash,
    organizationHash,
    granteeOrganizationHash: organizationHash,
    resourceIdHash: hashReference(parsed.scope.resourceReference),
    policyIdHash: hashIdentifier(parsed.scope.policyId),
    policyVersion: parsed.scope.policyVersion,
    resourceTypeCode: parsed.resourceTypeCode,
    actionCode: parsed.actionCode,
    purposeCode: parsed.purposeCode,
    validFrom: parsed.validFrom,
    validUntil: parsed.validUntil,
    policyMask: parsed.policyMask
  };
}

export function mapFhirConsentToPatientConsentGrant(consent: FhirConsent): PatientConsentGrant {
  return parseFhirConsent(consent).grant;
}

/**
 * Compatibility adapter for the pre-policy bootstrap/admin flow. Canonical
 * patient Consent registration must use mapFhirConsentToRegisterConsentInput.
 */
export function mapFhirConsentToLegacyRegisterConsentInput(
  consent: FhirConsent
): LegacyRegisterConsentInput {
  assertActivePermit(consent);
  const provision = requireValue(consent.provision, "FHIR_CONSENT_WITHOUT_PROVISION");
  const patientReference = requireReference(
    consent.patient?.reference,
    "FHIR_CONSENT_WITHOUT_PATIENT",
    "Patient"
  );
  const practitionerReference = requireReference(
    resolvePractitionerReference(provision),
    "FHIR_CONSENT_WITHOUT_PRACTITIONER",
    "Practitioner"
  );
  const organizationReference = resolveOrganizationReference(consent, provision);
  const resourceReference = resolveResourceReference(provision);
  const referencedResourceType = resourceReference.split("/", 1)[0];
  const declaredResourceType = provision.class?.length
    ? readSingleCode(
        provision.class,
        "FHIR_CONSENT_WITHOUT_RESOURCE_TYPE",
        "FHIR_CONSENT_AMBIGUOUS_CLASS"
      )
    : undefined;
  if (declaredResourceType && declaredResourceType !== referencedResourceType) {
    throw new Error("FHIR_CONSENT_RESOURCE_TYPE_MISMATCH");
  }
  const resourceTypeCode = mapResourceTypeCode(referencedResourceType);
  const actionCode = mapActionCode(
    readSingleCode(provision.action, "FHIR_CONSENT_WITHOUT_ACTION", "FHIR_CONSENT_AMBIGUOUS_ACTION")
  );
  const purposeCode = mapPurposeCode(
    readSingleCode(provision.purpose, "FHIR_CONSENT_WITHOUT_PURPOSE", "FHIR_CONSENT_AMBIGUOUS_PURPOSE")
  );
  const validFrom = parseFhirInstant(
    requireValue(provision.period?.start, "FHIR_CONSENT_WITHOUT_PERIOD_START")
  );
  const validUntil = parseFhirInstant(
    requireValue(provision.period?.end, "FHIR_CONSENT_WITHOUT_PERIOD_END")
  );
  if (validUntil <= validFrom) throw new Error("FHIR_CONSENT_INVALID_PERIOD");

  return {
    consentHash: hashReference(`Consent/${requireConsentId(consent.id)}`),
    patientHash: hashReference(patientReference),
    actorHash: hashReference(practitionerReference),
    organizationHash: hashReference(organizationReference),
    resourceIdHash: hashReference(resourceReference),
    resourceTypeCode,
    actionCode,
    purposeCode,
    validFrom,
    validUntil,
    policyMask: mapPolicyMask(resourceTypeCode, actionCode, purposeCode)
  };
}

function parseFhirConsent(consent: FhirConsent): ParsedConsent {
  assertActivePermit(consent);

  const provision = requireValue(consent.provision, "FHIR_CONSENT_WITHOUT_PROVISION");
  const patientReference = requireReference(
    consent.patient?.reference,
    "FHIR_CONSENT_WITHOUT_PATIENT",
    "Patient"
  );
  const practitionerReference = resolvePractitionerReference(provision);
  const organizationReference = resolveOrganizationReference(consent, provision);
  const resourceReference = resolveResourceReference(provision);
  const referencedResourceType = resourceReference.split("/", 1)[0];
  const declaredResourceType = provision.class?.length
    ? readSingleCode(
        provision.class,
        "FHIR_CONSENT_WITHOUT_RESOURCE_TYPE",
        "FHIR_CONSENT_AMBIGUOUS_CLASS"
      )
    : undefined;
  if (declaredResourceType && declaredResourceType !== referencedResourceType) {
    throw new Error("FHIR_CONSENT_RESOURCE_TYPE_MISMATCH");
  }

  const policyReference = readPolicyReference(consent, provision);
  const policy = getNetworkPolicyDefinition(policyReference.policyId, policyReference.policyVersion);
  if (!policy) {
    if (getNetworkPolicyDefinition(policyReference.policyId, 1)) {
      throw new Error("FHIR_CONSENT_POLICY_VERSION_NOT_FOUND");
    }
    throw new Error("FHIR_CONSENT_POLICY_NOT_FOUND");
  }
  if (policy.resourceType !== referencedResourceType) {
    throw new Error("FHIR_CONSENT_POLICY_RESOURCE_MISMATCH");
  }

  const resourceTypeCode = mapResourceTypeCode(referencedResourceType);
  const actionCode = mapActionCode(
    readSingleCode(provision.action, "FHIR_CONSENT_WITHOUT_ACTION", "FHIR_CONSENT_AMBIGUOUS_ACTION")
  );
  const purposeValue = readSingleCode(
    provision.purpose,
    "FHIR_CONSENT_WITHOUT_PURPOSE",
    "FHIR_CONSENT_AMBIGUOUS_PURPOSE"
  );
  const purposeCode = mapPurposeCode(purposeValue);
  if (policy.action !== "read" || actionCode !== ACTION_READ_CODE) {
    throw new Error("FHIR_CONSENT_POLICY_ACTION_MISMATCH");
  }
  if (policy.purpose !== purposeValue.toUpperCase()) {
    throw new Error("FHIR_CONSENT_POLICY_PURPOSE_MISMATCH");
  }
  const validFromValue = canonicalizeAuthorizationDateTime(
    requireValue(provision.period?.start, "FHIR_CONSENT_WITHOUT_PERIOD_START"),
    "INVALID_FHIR_DATETIME"
  );
  const validUntilValue = canonicalizeAuthorizationDateTime(
    requireValue(provision.period?.end, "FHIR_CONSENT_WITHOUT_PERIOD_END"),
    "INVALID_FHIR_DATETIME"
  );
  const validFrom = parseFhirInstant(validFromValue);
  const validUntil = parseFhirInstant(validUntilValue);
  if (validUntil <= validFrom) throw new Error("FHIR_CONSENT_INVALID_PERIOD");
  if (Date.parse(validFromValue) < Date.parse(policy.effectiveFrom)) {
    throw new Error("FHIR_CONSENT_POLICY_NOT_EFFECTIVE");
  }
  if (policy.effectiveUntil && Date.parse(validUntilValue) > Date.parse(policy.effectiveUntil)) {
    throw new Error("FHIR_CONSENT_POLICY_EXPIRED");
  }

  const policyMask = mapPolicyMask(resourceTypeCode, actionCode, purposeCode);
  if (policy.requiredAttributes !== policyMask) {
    throw new Error("FHIR_CONSENT_POLICY_ATTRIBUTES_MISMATCH");
  }
  const consentReference = `Consent/${requireConsentId(consent.id)}`;
  const consentVersion = readConsentVersion(consent);
  const scope = createPatientConsentScope({
    patientReference,
    granteeOrganizationReference: organizationReference,
    practitionerReference,
    resourceReference,
    purposeOfUse: purposeValue.toUpperCase(),
    policyId: policy.policyId,
    policyVersion: policy.version,
    validFrom: validFromValue,
    validUntil: validUntilValue
  });
  const grant = buildPatientConsentGrant({
    consentReference,
    consentVersion,
    scope
  });

  return {
    grant,
    scope,
    policyMask,
    resourceTypeCode,
    actionCode,
    purposeCode,
    validFrom,
    validUntil
  };
}

function assertActivePermit(consent: FhirConsent): void {
  if (consent.resourceType !== "Consent") {
    throw new Error("FHIR_RESOURCE_NOT_CONSENT");
  }
  if (consent.status !== "active") {
    throw new Error("FHIR_CONSENT_NOT_ACTIVE");
  }
  if (consent.provision?.type !== "permit") {
    throw new Error("FHIR_CONSENT_NOT_PERMIT");
  }
}

function readPolicyReference(
  consent: FhirConsent,
  provision: FhirConsentProvision
): { policyId: string; policyVersion: number } {
  const extensions = [...(consent.extension ?? []), ...(provision.extension ?? [])]
    .filter((candidate) => candidate.url === "https://interfhir.local/fhir/StructureDefinition/network-policy");
  if (extensions.length === 0) throw new Error("FHIR_CONSENT_WITHOUT_POLICY");
  if (extensions.length !== 1) throw new Error("FHIR_CONSENT_AMBIGUOUS_POLICY");
  const extension = extensions[0];
  const identifier = extension.valueIdentifier;
  if (identifier?.system !== "https://interfhir.local/policies") {
    throw new Error("FHIR_CONSENT_POLICY_SYSTEM_MISMATCH");
  }
  try {
    return parseNetworkPolicyReference(requireValue(identifier.value, "FHIR_CONSENT_WITHOUT_POLICY"));
  } catch (cause) {
    if (cause instanceof Error && cause.message === "INVALID_POLICY_VERSION") {
      throw new Error("FHIR_CONSENT_POLICY_VERSION_INVALID");
    }
    throw new Error("FHIR_CONSENT_POLICY_REFERENCE_INVALID");
  }
}

function resolvePractitionerReference(provision: FhirConsentProvision): string | undefined {
  const references = findActorReferences(provision, "Practitioner/");
  if (references.length > 1) throw new Error("FHIR_CONSENT_AMBIGUOUS_PRACTITIONER");
  return references[0];
}

function resolveOrganizationReference(
  consent: FhirConsent,
  provision: FhirConsentProvision
): string {
  if ((consent.organization?.length ?? 0) > 1) {
    throw new Error("FHIR_CONSENT_AMBIGUOUS_ORGANIZATION");
  }
  const topLevelReference = consent.organization?.length === 1
    ? requireReference(
        consent.organization[0]?.reference,
        "FHIR_CONSENT_WITHOUT_ORGANIZATION",
        "Organization"
      )
    : undefined;
  const actorReferences = findActorReferences(provision, "Organization/");
  if (actorReferences.length > 1) throw new Error("FHIR_CONSENT_AMBIGUOUS_ORGANIZATION");
  const actorReference = actorReferences[0];
  if (topLevelReference && actorReference && topLevelReference !== actorReference) {
    throw new Error("FHIR_CONSENT_ORGANIZATION_CONFLICT");
  }
  return requireReference(
    topLevelReference ?? actorReference,
    "FHIR_CONSENT_WITHOUT_ORGANIZATION",
    "Organization"
  );
}

function findActorReferences(provision: FhirConsentProvision, referencePrefix: string): string[] {
  return (provision.actor ?? [])
    .map((candidate) => candidate.reference?.reference)
    .filter((reference): reference is string => reference?.startsWith(referencePrefix) === true);
}

function resolveResourceReference(provision: FhirConsentProvision): string {
  if (provision.data?.length !== 1) {
    throw new Error("FHIR_CONSENT_RESOURCE_SCOPE_INVALID");
  }
  const resourceReference = requireValue(
    provision.data[0]?.reference?.reference,
    "FHIR_CONSENT_WITHOUT_RESOURCE"
  );
  assertFhirReference(resourceReference, "FHIR_CONSENT_WITHOUT_RESOURCE");
  return resourceReference;
}

function requireReference(
  value: string | undefined,
  errorCode: string,
  expectedResourceType: string
): string {
  assertFhirReference(value, errorCode, expectedResourceType);
  return value;
}

function readSingleCode(
  values: Array<FhirCoding | FhirCodeableConcept> | undefined,
  errorCode: string,
  ambiguityErrorCode: string
): string {
  if (!values || values.length === 0) throw new Error(errorCode);
  const value = values[0];
  const coding = "coding" in value ? value.coding : undefined;
  if (values.length !== 1 || (coding?.length ?? 0) > 1) {
    throw new Error(ambiguityErrorCode);
  }
  if (coding?.[0]?.code !== undefined && value.code !== undefined && coding[0].code !== value.code) {
    throw new Error(ambiguityErrorCode);
  }
  return requireValue(coding?.[0]?.code ?? value.code, errorCode);
}

function parseFhirInstant(value: string): number {
  const canonical = canonicalizeAuthorizationDateTime(value, "INVALID_FHIR_DATETIME");
  return Math.floor(Date.parse(canonical) / 1000);
}

function requireConsentId(value: string | undefined): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9.-]+$/.test(value)) {
    throw new Error("FHIR_CONSENT_WITHOUT_ID");
  }
  return value;
}

function readConsentVersion(consent: FhirConsent): string {
  const versionId = consent.meta?.versionId;
  if (versionId !== undefined && !/^\d+$/.test(versionId)) {
    throw new Error("FHIR_CONSENT_INVALID_VERSION");
  }
  return versionId ?? "1";
}

function requireValue<T>(value: T | null | undefined, errorCode: string): T {
  if (value === undefined || value === null || value === "") {
    throw new Error(errorCode);
  }
  return value;
}

// Kept as a named export for callers that need to derive the same projection
// without dereferencing the clinical Consent resource again.
export { computeConsentProjectionHash };
