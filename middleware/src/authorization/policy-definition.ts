import {
  assertNetworkPolicyDefinitionIntegrity,
  assertNonEmptyText,
  canonicalizeAuthorizationDateTime,
  computeCanonicalNetworkPolicyDefinitionHash,
  getRegisteredNetworkPolicyDefinition,
  registerNetworkPolicyDefinition,
  type NetworkPolicyDefinition
} from "./authorization-model.js";
import {
  ACTION_READ_CODE,
  mapActionCode,
  mapPolicyMask,
  mapPurposeCode,
  mapResourceTypeCode,
  PURPOSE_PAYMENT_CODE,
  PURPOSE_TREATMENT_CODE,
  SUPPORTED_RESOURCE_TYPE_CODES
} from "../abac/policy-mask.js";

export type NetworkPolicyDefinitionInput = Omit<NetworkPolicyDefinition, "definitionHash">;

export const POLICY_TREATMENT_OBSERVATION_ID = "POLICY_TREATMENT_OBSERVATION";
export const POLICY_TREATMENT_OBSERVATION_VERSION = 1;
export const POLICY_TREATMENT_OBSERVATION_REFERENCE =
  `${POLICY_TREATMENT_OBSERVATION_ID}@${POLICY_TREATMENT_OBSERVATION_VERSION}`;

export function createNetworkPolicyDefinition(
  input: NetworkPolicyDefinitionInput
): NetworkPolicyDefinition {
  const definition = {
    ...input,
    effectiveFrom: canonicalizeAuthorizationDateTime(input.effectiveFrom, "INVALID_POLICY_EFFECTIVE_PERIOD"),
    effectiveUntil: input.effectiveUntil === undefined
      ? undefined
      : canonicalizeAuthorizationDateTime(input.effectiveUntil, "INVALID_POLICY_EFFECTIVE_PERIOD")
  } as NetworkPolicyDefinition;
  validatePolicyFields(definition);
  const created = {
    ...definition,
    definitionHash: computeNetworkPolicyDefinitionHash(definition)
  };
  registerNetworkPolicyDefinition(created);
  return created;
}

export function computeNetworkPolicyDefinitionHash(policy: NetworkPolicyDefinition): string {
  return computeCanonicalNetworkPolicyDefinitionHash(policy);
}

export function assertNetworkPolicyDefinition(policy: NetworkPolicyDefinition): void {
  assertNetworkPolicyDefinitionIntegrity(policy);
}

export function formatNetworkPolicyReference(policyId: string, version: number): string {
  assertPolicyIdentifier(policyId);
  if (!Number.isSafeInteger(version) || version < 1) throw new Error("INVALID_POLICY_VERSION");
  return `${policyId}@${version}`;
}

export function parseNetworkPolicyReference(value: string): { policyId: string; policyVersion: number } {
  if (typeof value !== "string") throw new Error("INVALID_POLICY_REFERENCE");
  const match = /^(POLICY_[A-Z0-9_]+)@(\d+)$/.exec(value);
  if (!match) throw new Error("INVALID_POLICY_REFERENCE");
  const policyVersion = Number(match[2]);
  if (!Number.isSafeInteger(policyVersion) || policyVersion < 1) {
    throw new Error("INVALID_POLICY_VERSION");
  }
  return { policyId: match[1], policyVersion };
}

export function getNetworkPolicyDefinition(policyId: string, version: number): NetworkPolicyDefinition | undefined {
  return getRegisteredNetworkPolicyDefinition(policyId, version);
}

export const POLICY_TREATMENT_OBSERVATION = createNetworkPolicyDefinition({
  policyId: POLICY_TREATMENT_OBSERVATION_ID,
  version: POLICY_TREATMENT_OBSERVATION_VERSION,
  resourceType: "Observation",
  action: "read",
  purpose: "TREAT",
  requiredRoleCode: 1,
  requiredSpecialtyCode: 1,
  requiredAttributes: mapPolicyMask(
    mapResourceTypeCode("Observation"),
    ACTION_READ_CODE,
    PURPOSE_TREATMENT_CODE
  ),
  effectiveFrom: "1970-01-01T00:00:00.000Z"
});

const NETWORK_POLICY_DEFINITIONS = buildKnownPolicies();

function buildKnownPolicies(): NetworkPolicyDefinition[] {
  const policies: NetworkPolicyDefinition[] = [POLICY_TREATMENT_OBSERVATION];
  for (const resourceType of Object.keys(SUPPORTED_RESOURCE_TYPE_CODES).sort()) {
    for (const purpose of ["TREAT", "HPAYMT"] as const) {
      const policyId = buildPolicyId(resourceType, purpose);
      if (policyId === POLICY_TREATMENT_OBSERVATION_ID) continue;
      const resourceTypeCode = mapResourceTypeCode(resourceType);
      const purposeCode = mapPurposeCode(purpose);
      policies.push(createNetworkPolicyDefinition({
        policyId,
        version: 1,
        resourceType,
        action: "read",
        purpose,
        requiredRoleCode: 1,
        requiredSpecialtyCode: 1,
        requiredAttributes: mapPolicyMask(resourceTypeCode, ACTION_READ_CODE, purposeCode),
        effectiveFrom: "1970-01-01T00:00:00.000Z"
      }));
    }
  }
  return policies;
}

function buildPolicyId(resourceType: string, purpose: string): string {
  const purposeSegment = purpose === "TREAT" ? "TREATMENT" : "PAYMENT";
  const resourceSegment = resourceType.replace(/([a-z])([A-Z])/g, "$1_$2").toUpperCase();
  return `POLICY_${purposeSegment}_${resourceSegment}`;
}

function validatePolicyFields(policy: NetworkPolicyDefinitionInput | NetworkPolicyDefinition): void {
  assertPolicyIdentifier(policy.policyId);
  if (!Number.isSafeInteger(policy.version) || policy.version < 1) {
    throw new Error("INVALID_POLICY_VERSION");
  }
  if (!/^[A-Z][A-Za-z0-9]*$/.test(policy.resourceType)) throw new Error("INVALID_POLICY_RESOURCE_TYPE");
  if (policy.action !== "read") throw new Error("UNSUPPORTED_POLICY_ACTION");
  if (!/^[A-Z0-9_]+$/.test(policy.purpose)) throw new Error("INVALID_POLICY_PURPOSE");
  if (!Number.isSafeInteger(policy.requiredAttributes) || policy.requiredAttributes < 1 || policy.requiredAttributes > 0xffff) {
    throw new Error("INVALID_POLICY_ATTRIBUTES");
  }
  if (policy.requiredRoleCode !== undefined && (!Number.isSafeInteger(policy.requiredRoleCode) || policy.requiredRoleCode < 1)) {
    throw new Error("INVALID_POLICY_ROLE");
  }
  if (policy.requiredSpecialtyCode !== undefined && (!Number.isSafeInteger(policy.requiredSpecialtyCode) || policy.requiredSpecialtyCode < 1)) {
    throw new Error("INVALID_POLICY_SPECIALTY");
  }
  canonicalizeAuthorizationDateTime(policy.effectiveFrom, "INVALID_POLICY_EFFECTIVE_PERIOD");
  if (policy.effectiveUntil !== undefined) {
    const effectiveFrom = Date.parse(canonicalizeAuthorizationDateTime(policy.effectiveFrom, "INVALID_POLICY_EFFECTIVE_PERIOD"));
    const effectiveUntil = Date.parse(canonicalizeAuthorizationDateTime(policy.effectiveUntil, "INVALID_POLICY_EFFECTIVE_PERIOD"));
    if (effectiveUntil <= effectiveFrom) {
      throw new Error("INVALID_POLICY_EFFECTIVE_PERIOD");
    }
  }
}

function assertPolicyIdentifier(policyId: string): void {
  assertNonEmptyText(policyId, "INVALID_POLICY_ID");
  if (!/^POLICY_[A-Z0-9_]+$/.test(policyId)) throw new Error("INVALID_POLICY_ID");
}

export const POLICY_PURPOSE_CODES = {
  TREAT: PURPOSE_TREATMENT_CODE,
  HPAYMT: PURPOSE_PAYMENT_CODE
} as const;
