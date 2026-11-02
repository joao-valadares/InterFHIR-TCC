import { expect } from "chai";

import {
  canonicalizeAuthorizationDateTime,
  computeConsentProjectionHash,
  registerNetworkPolicyDefinition
} from "../src/authorization/authorization-model.js";

import {
  buildPatientConsentGrant,
  createPatientConsentScope,
  getConsentProjection,
  hashPatientConsentScope
} from "../src/authorization/consent-scope.js";
import {
  createNetworkPolicyDefinition,
  computeNetworkPolicyDefinitionHash,
  POLICY_TREATMENT_OBSERVATION
} from "../src/authorization/policy-definition.js";

const scope = {
  patientReference: "Patient/maria",
  granteeOrganizationReference: "Organization/clinic-b",
  practitionerReference: "Practitioner/ana",
  resourceReference: "Observation/obs-1",
  purposeOfUse: "TREAT",
  policyId: "POLICY_TREATMENT_OBSERVATION",
  policyVersion: 1,
  validFrom: "2027-01-15T10:00:00.000Z",
  validUntil: "2027-01-15T11:00:00.000Z"
};

describe("consent-centered authorization model", function () {
  it("keeps a general network policy separate from a directed patient grant", function () {
    const policy = POLICY_TREATMENT_OBSERVATION;
    const consentScope = createPatientConsentScope(scope);
    const grant = buildPatientConsentGrant({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: consentScope
    });

    expect(policy).not.to.have.property("patientReference");
    expect(policy).not.to.have.property("granteeOrganizationReference");
    expect(consentScope.patientReference).to.equal("Patient/maria");
    expect(consentScope.granteeOrganizationReference).to.equal("Organization/clinic-b");
    expect(grant.scope).to.deep.equal(consentScope);
    expect(grant.status).to.equal("active");
    expect(grant.consentProjectionHash).to.match(/^0x[0-9a-f]{64}$/);
  });

  it("hashes only canonical authorization projection fields", function () {
    const consentScope = createPatientConsentScope(scope);
    const projection = getConsentProjection({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: consentScope,
      status: "active"
    });

    expect(hashPatientConsentScope(consentScope)).to.match(/^0x[0-9a-f]{64}$/);
    expect(JSON.stringify(projection)).not.to.include("resourceType");
    expect(JSON.stringify(projection)).not.to.include("clinical");
    expect(projection).to.have.all.keys("consentReferenceHash", "consentVersion", "status", "scope");
    expect(projection.scope).to.have.all.keys(
      "patientHash",
      "granteeOrganizationHash",
      "practitionerHash",
      "resourceIdHash",
      "purposeOfUse",
      "policyIdHash",
      "policyVersion",
      "validFrom",
      "validUntil"
    );
  });

  it("changes the policy definition hash when a policy rule changes", function () {
    const first = createNetworkPolicyDefinition({
      policyId: "POLICY_TEST",
      version: 1,
      resourceType: "Observation",
      action: "read",
      purpose: "TREAT",
      requiredAttributes: 1,
      effectiveFrom: "2027-01-01T00:00:00.000Z"
    });
    const second = {
      ...first,
      requiredAttributes: 2
    };

    expect(first.definitionHash).to.match(/^0x[0-9a-f]{64}$/);
    expect(computeNetworkPolicyDefinitionHash(second)).not.to.equal(first.definitionHash);
  });

  it("rejects duplicate policy versions and tampered policy definitions", function () {
    const input = {
      policyId: "POLICY_DUPLICATE_REGISTRATION",
      version: 1,
      resourceType: "Observation",
      action: "read" as const,
      purpose: "TREAT",
      requiredAttributes: 1,
      effectiveFrom: "2027-01-01T00:00:00.000Z"
    };

    createNetworkPolicyDefinition(input);
    expect(() => createNetworkPolicyDefinition(input)).to.throw(
      "NETWORK_POLICY_VERSION_ALREADY_REGISTERED"
    );
    expect(() => registerNetworkPolicyDefinition({
      ...POLICY_TREATMENT_OBSERVATION,
      requiredAttributes: POLICY_TREATMENT_OBSERVATION.requiredAttributes + 1
    })).to.throw("NETWORK_POLICY_DEFINITION_HASH_MISMATCH");
  });

  it("fails closed for invalid purpose, period, organization, resource, and policy", function () {
    expect(() => createPatientConsentScope({ ...scope, purposeOfUse: "DIAGNOSTIC" })).to.throw(
      "INVALID_CONSENT_PURPOSE"
    );
    expect(() => createPatientConsentScope({ ...scope, validUntil: scope.validFrom })).to.throw(
      "INVALID_CONSENT_PERIOD"
    );
    expect(() => createPatientConsentScope({
      ...scope,
      granteeOrganizationReference: "Practitioner/not-an-organization"
    })).to.throw("INVALID_GRANTEE_ORGANIZATION_REFERENCE");
    expect(() => createPatientConsentScope({
      ...scope,
      resourceReference: "not-a-resource"
    })).to.throw("INVALID_RESOURCE_REFERENCE");
    expect(() => createPatientConsentScope({
      ...scope,
      policyId: "POLICY_UNKNOWN"
    })).to.throw("UNKNOWN_NETWORK_POLICY");
    expect(() => createPatientConsentScope({
      ...scope,
      policyVersion: 2
    })).to.throw("UNKNOWN_NETWORK_POLICY_VERSION");
  });

  it("fails closed when a direct projection caller supplies an unknown or incompatible policy", function () {
    expect(() => getConsentProjection({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: { ...scope, policyId: "POLICY_UNKNOWN" },
      status: "active"
    })).to.throw("UNKNOWN_NETWORK_POLICY");
    expect(() => getConsentProjection({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: { ...scope, policyVersion: 2 },
      status: "active"
    })).to.throw("UNKNOWN_NETWORK_POLICY_VERSION");
    expect(() => getConsentProjection({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: { ...scope, resourceReference: "MedicationRequest/med-1" },
      status: "active"
    })).to.throw("POLICY_RESOURCE_MISMATCH");
    expect(() => getConsentProjection({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: { ...scope, purposeOfUse: "HPAYMT" },
      status: "active"
    })).to.throw("POLICY_PURPOSE_MISMATCH");
  });

  it("canonicalizes equivalent Consent timestamps and rejects non-zoned dateTime values", function () {
    const equivalentScope = {
      ...scope,
      validFrom: "2027-01-15T07:00:00.000-03:00",
      validUntil: "2027-01-15T08:00:00.000-03:00"
    };

    expect(computeConsentProjectionHash({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope,
      status: "active"
    })).to.equal(computeConsentProjectionHash({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: equivalentScope,
      status: "active"
    }));
    expect(() => getConsentProjection({
      consentReference: "Consent/cons-1",
      consentVersion: "1",
      scope: { ...scope, validFrom: "2027-01-15T10:00:00.000" },
      status: "active"
    })).to.throw("INVALID_CONSENT_PERIOD");
  });

  it("rejects semantically invalid FHIR dateTimes after syntax validation", function () {
    expect(() => canonicalizeAuthorizationDateTime(
      "2027-02-30T10:00:00.000Z",
      "INVALID_FHIR_DATETIME"
    )).to.throw("INVALID_FHIR_DATETIME");
    expect(() => canonicalizeAuthorizationDateTime(
      "2027-01-15T24:00:00.000Z",
      "INVALID_FHIR_DATETIME"
    )).to.throw("INVALID_FHIR_DATETIME");
    expect(canonicalizeAuthorizationDateTime("2027-02-28T23:59:59.999-03:00"))
      .to.equal("2027-03-01T02:59:59.999Z");
  });
});
