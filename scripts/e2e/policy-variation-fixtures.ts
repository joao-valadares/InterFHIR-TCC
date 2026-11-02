/** Synthetic, test-only policy definitions. Production defaults stay intact. */
import { createNetworkPolicyDefinition } from "../../middleware/src/authorization/policy-definition.js";
import { ACTION_READ_CODE, mapPolicyMask, mapResourceTypeCode, PURPOSE_TREATMENT_CODE } from "../../middleware/src/abac/policy-mask.js";

const common = {
  version: 1, resourceType: "Observation", action: "read" as const, purpose: "TREAT",
  requiredAttributes: mapPolicyMask(mapResourceTypeCode("Observation"), ACTION_READ_CODE, PURPOSE_TREATMENT_CODE),
  effectiveFrom: "1970-01-01T00:00:00.000Z"
};

export const GENERAL_TREATMENT_POLICY = createNetworkPolicyDefinition({
  ...common, policyId: "POLICY_E2E_GENERAL_OBSERVATION", requiredRoleCode: 1
});
export const SPECIALIST_REVIEW_POLICY = createNetworkPolicyDefinition({
  ...common, policyId: "POLICY_E2E_SPECIALIST_OBSERVATION", requiredRoleCode: 2, requiredSpecialtyCode: 2
});
export const VARIATION_POLICIES = [GENERAL_TREATMENT_POLICY, SPECIALIST_REVIEW_POLICY];
export const VARIATION_PRACTITIONERS = [
  { reference: "Practitioner/daniel", account: "0x000000000000000000000000000000000000c001", roleCode: 1, specialtyCode: 3 },
  { reference: "Practitioner/carla", account: "0x000000000000000000000000000000000000c002", roleCode: 2, specialtyCode: 2 },
  { reference: "Practitioner/diana", account: "0x000000000000000000000000000000000000c003", roleCode: 2, specialtyCode: 3 }
] as const;
