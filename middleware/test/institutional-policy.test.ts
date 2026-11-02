import { expect } from "chai";

import { createInstitutionalPolicyEvaluator } from "../src/policy/institutional-policy.js";

describe("deny-only institutional policy", function () {
  const baseInput = {
    requesterOrganizationReference: "Organization/clinic-b",
    practitionerReference: "Practitioner/bruno",
    roleCode: "practitioner",
    resourceType: "Observation",
    purposeOfUse: "TREAT",
    requestTime: "2026-08-01T10:00:00.000Z"
  };

  it("denies an organization blocked by the custodian", async function () {
    const policy = createInstitutionalPolicyEvaluator({
      blockedOrganizationReferences: ["Organization/clinic-b"]
    });

    expect(await policy.evaluate(baseInput)).to.deep.equal({
      permitted: false,
      reasonCode: "LOCAL_ORGANIZATION_BLOCKED"
    });
  });

  it("denies a purpose blocked by the custodian", async function () {
    const policy = createInstitutionalPolicyEvaluator({
      blockedPurposesOfUse: ["ETREAT"]
    });

    expect(
      await policy.evaluate({ ...baseInput, purposeOfUse: "ETREAT" })
    ).to.deep.equal({
      permitted: false,
      reasonCode: "LOCAL_PURPOSE_BLOCKED"
    });
  });

  it("returns only a local permit when no deny rule matches", async function () {
    const policy = createInstitutionalPolicyEvaluator({
      blockedOrganizationReferences: ["Organization/blocked"],
      blockedPurposesOfUse: ["RESEARCH"]
    });

    expect(await policy.evaluate(baseInput)).to.deep.equal({
      permitted: true,
      reasonCode: "LOCAL_POLICY_PERMIT"
    });
  });

  it("uses trusted registry attributes instead of caller-supplied ABAC claims", async function () {
    const policy = createInstitutionalPolicyEvaluator({
      trustedAttributeResolver: async () => ({
        roleCode: 1,
        specialtyCode: 1,
        licenseActive: false
      })
    });

    expect(await policy.evaluate({
      ...baseInput,
      roleCode: "administrator",
      specialtyCode: "cardiology",
      licenseActive: true
    })).to.deep.equal({
      permitted: false,
      reasonCode: "LOCAL_LICENSE_INACTIVE"
    });
  });

  it("denies a stale or inactive local policy version before the read boundary", async function () {
    const policy = createInstitutionalPolicyEvaluator({
      activePolicyVersions: new Map([["POLICY_TREATMENT_OBSERVATION", 2]])
    });

    expect(await policy.evaluate({
      ...baseInput,
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1
    })).to.deep.equal({
      permitted: false,
      reasonCode: "LOCAL_POLICY_VERSION_MISMATCH"
    });
  });
});
