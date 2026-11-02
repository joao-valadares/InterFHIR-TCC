import { ethers } from "ethers";
import {
  ACTION_READ_CODE,
  mapPolicyMask,
  mapPurposeCode,
  mapResourceTypeCode,
  SUPPORTED_RESOURCE_TYPE_CODES
} from "../abac/policy-mask.js";

export interface NetworkPolicyDefinition {
  policyId: string;
  version: number;
  resourceType: string;
  action: "read";
  purpose: string;
  requiredRoleCode?: number;
  requiredSpecialtyCode?: number;
  requiredAttributes: number;
  effectiveFrom: string;
  effectiveUntil?: string;
  definitionHash: string;
}

export interface PatientConsentScope {
  patientReference: string;
  granteeOrganizationReference: string;
  practitionerReference?: string;
  resourceReference: string;
  purposeOfUse: string;
  policyId: string;
  policyVersion: number;
  validFrom: string;
  validUntil: string;
}

export interface PatientConsentGrant {
  consentReference: string;
  consentVersion: string;
  consentProjectionHash: string;
  scope: PatientConsentScope;
  status: "active" | "revoked" | "superseded";
}

export interface ConsentProjectionInput {
  consentReference: string;
  consentVersion: string;
  scope: PatientConsentScope;
  status: PatientConsentGrant["status"];
}

export interface PatientConsentProjection {
  consentReferenceHash: string;
  consentVersion: string;
  status: PatientConsentGrant["status"];
  scope: {
    patientHash: string;
    granteeOrganizationHash: string;
    practitionerHash: string | null;
    resourceIdHash: string;
    purposeOfUse: string;
    policyIdHash: string;
    policyVersion: number;
    validFrom: string;
    validUntil: string;
  };
}

export const NETWORK_POLICY_EXTENSION_URL =
  "https://interfhir.local/fhir/StructureDefinition/network-policy";
export const NETWORK_POLICY_SYSTEM = "https://interfhir.local/policies";

const REGISTERED_NETWORK_POLICIES = new Map<string, NetworkPolicyDefinition>();
const STRICT_FHIR_DATETIME =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/;

export function hashReference(reference: string): string {
  assertFhirReference(reference, "INVALID_REFERENCE");
  return hashCanonicalText(reference);
}

export function hashIdentifier(identifier: string): string {
  assertNonEmptyText(identifier, "INVALID_IDENTIFIER");
  return hashCanonicalText(identifier);
}

export function hashCanonicalText(value: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

export function assertFhirReference(
  reference: string | undefined,
  errorCode: string,
  expectedResourceType?: string
): asserts reference is string {
  if (typeof reference !== "string" || !/^[A-Z][A-Za-z0-9]*\/[A-Za-z0-9.-]+$/.test(reference)) {
    throw new Error(errorCode);
  }
  if (expectedResourceType && reference.split("/", 1)[0] !== expectedResourceType) {
    throw new Error(errorCode);
  }
}

export function assertNonEmptyText(value: string | undefined, errorCode: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0 || value !== value.trim()) {
    throw new Error(errorCode);
  }
}

export function canonicalizeAuthorizationProjection(value: unknown): string {
  return JSON.stringify(sortJson(value));
}

export function registerNetworkPolicyDefinition(policy: NetworkPolicyDefinition): void {
  assertNetworkPolicyDefinitionIntegrity(policy);
  const key = policyKey(policy.policyId, policy.version);
  if (REGISTERED_NETWORK_POLICIES.has(key)) {
    throw new Error("NETWORK_POLICY_VERSION_ALREADY_REGISTERED");
  }
  const builtIn = getBuiltInNetworkPolicyDefinition(policy.policyId, policy.version);
  if (builtIn && canonicalizeAuthorizationProjection(policy) !== canonicalizeAuthorizationProjection(builtIn)) {
    throw new Error("NETWORK_POLICY_DEFINITION_CONFLICT");
  }
  REGISTERED_NETWORK_POLICIES.set(key, Object.freeze({ ...policy }));
}

export function getRegisteredNetworkPolicyDefinition(
  policyId: string,
  version: number
): NetworkPolicyDefinition | undefined {
  return REGISTERED_NETWORK_POLICIES.get(policyKey(policyId, version)) ??
    getBuiltInNetworkPolicyDefinition(policyId, version);
}

export function computeCanonicalNetworkPolicyDefinitionHash(
  policy: Omit<NetworkPolicyDefinition, "definitionHash">
): string {
  const canonicalDefinition = {
    policyId: policy.policyId,
    version: policy.version,
    resourceType: policy.resourceType,
    action: policy.action,
    purpose: policy.purpose,
    requiredRoleCode: policy.requiredRoleCode ?? null,
    requiredSpecialtyCode: policy.requiredSpecialtyCode ?? null,
    requiredAttributes: policy.requiredAttributes,
    effectiveFrom: policy.effectiveFrom,
    effectiveUntil: policy.effectiveUntil ?? null
  };
  return hashCanonicalText(canonicalizeAuthorizationProjection(canonicalDefinition));
}

export function assertNetworkPolicyDefinitionIntegrity(policy: NetworkPolicyDefinition): void {
  assertNonEmptyText(policy.policyId, "INVALID_POLICY_ID");
  if (!/^POLICY_[A-Z0-9_]+$/.test(policy.policyId)) throw new Error("INVALID_POLICY_ID");
  if (!Number.isSafeInteger(policy.version) || policy.version < 1) {
    throw new Error("INVALID_POLICY_VERSION");
  }
  if (typeof policy.resourceType !== "string" || !/^[A-Z][A-Za-z0-9]*$/.test(policy.resourceType)) {
    throw new Error("INVALID_POLICY_RESOURCE_TYPE");
  }
  if (policy.action !== "read") throw new Error("UNSUPPORTED_POLICY_ACTION");
  if (typeof policy.purpose !== "string" || !/^[A-Z0-9_]+$/.test(policy.purpose)) {
    throw new Error("INVALID_POLICY_PURPOSE");
  }
  if (!Number.isSafeInteger(policy.requiredAttributes) || policy.requiredAttributes < 1 || policy.requiredAttributes > 0xffff) {
    throw new Error("INVALID_POLICY_ATTRIBUTES");
  }
  if (policy.requiredRoleCode !== undefined && (!Number.isSafeInteger(policy.requiredRoleCode) || policy.requiredRoleCode < 1)) {
    throw new Error("INVALID_POLICY_ROLE");
  }
  if (policy.requiredSpecialtyCode !== undefined && (!Number.isSafeInteger(policy.requiredSpecialtyCode) || policy.requiredSpecialtyCode < 1)) {
    throw new Error("INVALID_POLICY_SPECIALTY");
  }
  const effectiveFrom = canonicalizeAuthorizationDateTime(policy.effectiveFrom, "INVALID_POLICY_EFFECTIVE_PERIOD");
  if (policy.effectiveFrom !== effectiveFrom) {
    throw new Error("INVALID_POLICY_EFFECTIVE_PERIOD");
  }
  if (policy.effectiveUntil !== undefined) {
    const effectiveUntil = canonicalizeAuthorizationDateTime(policy.effectiveUntil, "INVALID_POLICY_EFFECTIVE_PERIOD");
    if (policy.effectiveUntil !== effectiveUntil) {
      throw new Error("INVALID_POLICY_EFFECTIVE_PERIOD");
    }
    if (Date.parse(effectiveUntil) <= Date.parse(effectiveFrom)) {
      throw new Error("INVALID_POLICY_EFFECTIVE_PERIOD");
    }
  }
  if (typeof policy.definitionHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(policy.definitionHash)) {
    throw new Error("INVALID_NETWORK_POLICY_DEFINITION_HASH");
  }
  if (policy.definitionHash !== computeCanonicalNetworkPolicyDefinitionHash(policy)) {
    throw new Error("NETWORK_POLICY_DEFINITION_HASH_MISMATCH");
  }
}

export function validateConsentScopePolicy(scope: PatientConsentScope): void {
  const policy = getRegisteredNetworkPolicyDefinition(scope.policyId, scope.policyVersion);
  if (!policy) {
    if (isKnownNetworkPolicyId(scope.policyId) ||
      [...REGISTERED_NETWORK_POLICIES.values()].some((candidate) => candidate.policyId === scope.policyId)) {
      throw new Error("UNKNOWN_NETWORK_POLICY_VERSION");
    }
    throw new Error("UNKNOWN_NETWORK_POLICY");
  }
  const resourceType = scope.resourceReference.split("/", 1)[0];
  if (policy.resourceType !== resourceType) throw new Error("POLICY_RESOURCE_MISMATCH");
  if (policy.action !== "read") throw new Error("POLICY_ACTION_MISMATCH");
  if (policy.purpose !== scope.purposeOfUse.toUpperCase()) throw new Error("POLICY_PURPOSE_MISMATCH");

  const validFrom = canonicalizeAuthorizationDateTime(scope.validFrom);
  const validUntil = canonicalizeAuthorizationDateTime(scope.validUntil);
  const policyEffectiveFrom = canonicalizeAuthorizationDateTime(
    policy.effectiveFrom,
    "INVALID_POLICY_EFFECTIVE_PERIOD"
  );
  if (Date.parse(validFrom) < Date.parse(policyEffectiveFrom)) {
    throw new Error("CONSENT_BEFORE_POLICY_EFFECTIVE");
  }
  if (policy.effectiveUntil !== undefined) {
    const policyEffectiveUntil = canonicalizeAuthorizationDateTime(
      policy.effectiveUntil,
      "INVALID_POLICY_EFFECTIVE_PERIOD"
    );
    if (Date.parse(validUntil) > Date.parse(policyEffectiveUntil)) {
      throw new Error("CONSENT_AFTER_POLICY_EXPIRY");
    }
  }
}

export function canonicalizeAuthorizationDateTime(
  value: string,
  errorCode = "INVALID_CONSENT_PERIOD"
): string {
  const match = typeof value === "string" ? STRICT_FHIR_DATETIME.exec(value) : null;
  if (!match) {
    throw new Error(errorCode);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const fraction = match[7] ?? "";
  const zone = match[8];
  if (
    year < 1 ||
    month < 1 || month > 12 ||
    day < 1 || day > daysInMonth(year, month) ||
    hour > 23 || minute > 59 || second > 59
  ) {
    throw new Error(errorCode);
  }
  const offsetMinutes = parseTimezoneOffset(zone, errorCode);
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) throw new Error(errorCode);
  const expectedTimestamp = buildTimestamp(year, month, day, hour, minute, second, fraction, offsetMinutes);
  if (timestamp !== expectedTimestamp) throw new Error(errorCode);
  return new Date(timestamp).toISOString();
}

export function getConsentProjection(input: ConsentProjectionInput): PatientConsentProjection {
  assertFhirReference(input.consentReference, "INVALID_CONSENT_REFERENCE", "Consent");
  assertNonEmptyText(input.consentVersion, "INVALID_CONSENT_VERSION");
  assertConsentStatus(input.status);
  assertScopeShape(input.scope);
  validateConsentScopePolicy(input.scope);
  const validFrom = canonicalizeAuthorizationDateTime(input.scope.validFrom);
  const validUntil = canonicalizeAuthorizationDateTime(input.scope.validUntil);

  return {
    consentReferenceHash: hashReference(input.consentReference),
    consentVersion: input.consentVersion,
    status: input.status,
    scope: {
      patientHash: hashReference(input.scope.patientReference),
      granteeOrganizationHash: hashReference(input.scope.granteeOrganizationReference),
      practitionerHash: input.scope.practitionerReference
        ? hashReference(input.scope.practitionerReference)
        : null,
      resourceIdHash: hashReference(input.scope.resourceReference),
      purposeOfUse: input.scope.purposeOfUse,
      policyIdHash: hashIdentifier(input.scope.policyId),
      policyVersion: input.scope.policyVersion,
      validFrom,
      validUntil
    }
  };
}

export function computeConsentProjectionHash(input: ConsentProjectionInput): string {
  return hashCanonicalText(canonicalizeAuthorizationProjection(getConsentProjection(input)));
}

export function assertScopeShape(scope: PatientConsentScope): void {
  assertFhirReference(scope.patientReference, "INVALID_PATIENT_REFERENCE", "Patient");
  assertFhirReference(
    scope.granteeOrganizationReference,
    "INVALID_GRANTEE_ORGANIZATION_REFERENCE",
    "Organization"
  );
  if (scope.practitionerReference !== undefined) {
    assertFhirReference(scope.practitionerReference, "INVALID_PRACTITIONER_REFERENCE", "Practitioner");
  }
  assertFhirReference(scope.resourceReference, "INVALID_RESOURCE_REFERENCE");
  assertNonEmptyText(scope.purposeOfUse, "INVALID_CONSENT_PURPOSE");
  assertNonEmptyText(scope.policyId, "INVALID_POLICY_ID");
  if (!Number.isSafeInteger(scope.policyVersion) || scope.policyVersion < 1) {
    throw new Error("INVALID_POLICY_VERSION");
  }
  assertValidPeriod(scope.validFrom, scope.validUntil);
}

export function assertValidPeriod(validFrom: string, validUntil: string): void {
  const start = Date.parse(canonicalizeAuthorizationDateTime(validFrom));
  const end = Date.parse(canonicalizeAuthorizationDateTime(validUntil));
  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) {
    throw new Error("INVALID_CONSENT_PERIOD");
  }
}

function policyKey(policyId: string, version: number): string {
  return `${policyId}@${version}`;
}

function getBuiltInNetworkPolicyDefinition(
  policyId: string,
  version: number
): NetworkPolicyDefinition | undefined {
  if (version !== 1) return undefined;
  const match = /^POLICY_(TREATMENT|PAYMENT)_(.+)$/.exec(policyId);
  if (!match) return undefined;
  const purpose = match[1] === "TREATMENT" ? "TREAT" : "HPAYMT";
  const resourceType = Object.keys(SUPPORTED_RESOURCE_TYPE_CODES)
    .find((candidate) => toPolicyResourceSegment(candidate) === match[2]);
  if (!resourceType) return undefined;
  const definition = {
    policyId,
    version,
    resourceType,
    action: "read" as const,
    purpose,
    requiredRoleCode: 1,
    requiredSpecialtyCode: 1,
    requiredAttributes: mapPolicyMask(
      mapResourceTypeCode(resourceType),
      ACTION_READ_CODE,
      mapPurposeCode(purpose)
    ),
    effectiveFrom: "1970-01-01T00:00:00.000Z"
  };
  return Object.freeze({
    ...definition,
    definitionHash: computeCanonicalNetworkPolicyDefinitionHash(definition)
  });
}

function isKnownNetworkPolicyId(policyId: string): boolean {
  return getBuiltInNetworkPolicyDefinition(policyId, 1) !== undefined;
}

function toPolicyResourceSegment(resourceType: string): string {
  return resourceType.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase();
}

function daysInMonth(year: number, month: number): number {
  const date = new Date(0);
  date.setUTCFullYear(year, month, 0);
  date.setUTCHours(0, 0, 0, 0);
  return date.getUTCDate();
}

function parseTimezoneOffset(zone: string, errorCode: string): number {
  if (zone === "Z") return 0;
  const sign = zone[0] === "+" ? 1 : -1;
  const hours = Number(zone.slice(1, 3));
  const minutes = Number(zone.slice(4, 6));
  if (hours > 14 || minutes > 59 || (hours === 14 && minutes !== 0)) throw new Error(errorCode);
  return sign * (hours * 60 + minutes);
}

function buildTimestamp(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  fraction: string,
  offsetMinutes: number
): number {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(
    hour,
    minute,
    second,
    Number((fraction + "000").slice(0, 3) || 0)
  );
  return date.getTime() - offsetMinutes * 60_000;
}

function assertConsentStatus(status: string): asserts status is PatientConsentGrant["status"] {
  if (status !== "active" && status !== "revoked" && status !== "superseded") {
    throw new Error("INVALID_CONSENT_STATUS");
  }
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => sortJson(item));
  }
  if (value !== null && typeof value === "object") {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((result, key) => {
        const child = (value as Record<string, unknown>)[key];
        if (child !== undefined) result[key] = sortJson(child);
        return result;
      }, {});
  }
  return value;
}
