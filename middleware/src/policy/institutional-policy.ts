export interface InstitutionalPolicyDecision {
  permitted: boolean;
  reasonCode:
    | "LOCAL_POLICY_PERMIT"
    | "LOCAL_ORGANIZATION_BLOCKED"
    | "LOCAL_PURPOSE_BLOCKED"
    | "LOCAL_POLICY_VERSION_MISMATCH"
    | "LOCAL_POLICY_INACTIVE"
    | "LOCAL_LICENSE_INACTIVE"
    | "LOCAL_TRUSTED_ATTRIBUTES_UNAVAILABLE";
}

export interface TrustedInstitutionalAttributes {
  roleCode: number;
  specialtyCode: number;
  licenseActive: boolean;
}

export type TrustedAttributeResolver = (input: {
  practitionerReference: string;
  organizationReference: string;
}) => Promise<TrustedInstitutionalAttributes>;

export interface InstitutionalPolicyEvaluator {
  evaluate(input: {
    requesterOrganizationReference: string;
    practitionerReference: string;
    /** Optional compatibility fields. They are never used as trusted data. */
    roleCode?: string | number;
    specialtyCode?: string | number;
    licenseActive?: boolean;
    resourceType: string;
    purposeOfUse: string;
    requestTime: string;
    policyId?: string;
    policyVersion?: number;
  }): Promise<InstitutionalPolicyDecision>;
}

export interface InstitutionalPolicyConfiguration {
  blockedOrganizationReferences?: readonly string[];
  blockedPurposesOfUse?: readonly string[];
  /** Map of the policy id to the only currently active local version. */
  activePolicyVersions?: ReadonlyMap<string, number> | Readonly<Record<string, number>>;
  /** Reads ABAC attributes from a trusted registry, never from an HTTP body. */
  trustedAttributeResolver?: TrustedAttributeResolver;
}

/**
 * Local policy is intentionally deny-only: a local permit only means that no
 * local restriction applies. It is never an authorization decision on its own.
 */
export function createInstitutionalPolicyEvaluator(
  configuration: InstitutionalPolicyConfiguration = {}
): InstitutionalPolicyEvaluator {
  const blockedOrganizations = new Set(
    configuration.blockedOrganizationReferences ?? []
  );
  const blockedPurposes = new Set(configuration.blockedPurposesOfUse ?? []);
  const activePolicyVersions = configuration.activePolicyVersions;

  function activeVersionFor(policyId: string): number | undefined {
    if (typeof (activePolicyVersions as ReadonlyMap<string, number>).get === "function") {
      return (activePolicyVersions as ReadonlyMap<string, number>).get(policyId);
    }
    return (activePolicyVersions as Readonly<Record<string, number>>)[policyId];
  }

  return {
    async evaluate(input) {
      if (blockedOrganizations.has(input.requesterOrganizationReference)) {
        return {
          permitted: false,
          reasonCode: "LOCAL_ORGANIZATION_BLOCKED"
        };
      }
      if (blockedPurposes.has(input.purposeOfUse)) {
        return {
          permitted: false,
          reasonCode: "LOCAL_PURPOSE_BLOCKED"
        };
      }
      if (activePolicyVersions !== undefined) {
        if (typeof input.policyId !== "string" || !Number.isSafeInteger(input.policyVersion)) {
          return {
            permitted: false,
            reasonCode: "LOCAL_POLICY_INACTIVE"
          };
        }
        const activeVersion = activeVersionFor(input.policyId);
        if (activeVersion === undefined) {
          return {
            permitted: false,
            reasonCode: "LOCAL_POLICY_INACTIVE"
          };
        }
        if (activeVersion !== input.policyVersion) {
          return {
            permitted: false,
            reasonCode: "LOCAL_POLICY_VERSION_MISMATCH"
          };
        }
      }
      if (configuration.trustedAttributeResolver) {
        let trustedAttributes: TrustedInstitutionalAttributes;
        try {
          trustedAttributes = await configuration.trustedAttributeResolver({
            practitionerReference: input.practitionerReference,
            organizationReference: input.requesterOrganizationReference
          });
        } catch {
          return {
            permitted: false,
            reasonCode: "LOCAL_TRUSTED_ATTRIBUTES_UNAVAILABLE"
          };
        }
        if (!trustedAttributes.licenseActive) {
          return {
            permitted: false,
            reasonCode: "LOCAL_LICENSE_INACTIVE"
          };
        }
      }
      return {
        permitted: true,
        reasonCode: "LOCAL_POLICY_PERMIT"
      };
    }
  };
}
