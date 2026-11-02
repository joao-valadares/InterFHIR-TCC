import { expect } from "chai";

import { buildPatientConsentResource } from "../src/fhir/consent-builder.js";
import type { PatientConsentScope } from "../src/authorization/authorization-model.js";

const scope: PatientConsentScope = {
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

describe("controlled FHIR Consent builder", function () {
  it("builds an active, permitted R4 Consent from domain scope only", function () {
    const consent = buildPatientConsentResource(scope);

    expect(consent).to.deep.include({
      resourceType: "Consent",
      status: "active",
      scope: {
        coding: [{
          system: "http://terminology.hl7.org/CodeSystem/consentscope",
          code: "patient-privacy"
        }]
      },
      patient: { reference: "Patient/maria" },
      organization: [{ reference: "Organization/clinic-b" }]
    });
    expect(consent.provision).to.deep.include({
      type: "permit",
      period: { start: scope.validFrom, end: scope.validUntil },
      action: [{ coding: [{ code: "read" }] }],
      purpose: [{
        system: "http://terminology.hl7.org/CodeSystem/v3-ActReason",
        code: "TREAT"
      }],
      data: [{ meaning: "instance", reference: { reference: "Observation/obs-1" } }]
    });
    expect(consent.provision.actor).to.deep.equal([
      {
        role: { coding: [{ code: "performer" }] },
        reference: { reference: "Practitioner/ana" }
      }
    ]);
    expect(consent.extension).to.deep.equal([
      {
        url: "https://interfhir.local/fhir/StructureDefinition/network-policy",
        valueIdentifier: {
          system: "https://interfhir.local/policies",
          value: "POLICY_TREATMENT_OBSERVATION@1"
        }
      }
    ]);
  });

  it("declares the FHIR purpose terminology so HAPI preserves the authorization purpose", function () {
    const consent = buildPatientConsentResource(scope);

    expect(consent.provision.purpose).to.deep.equal([{
      system: "http://terminology.hl7.org/CodeSystem/v3-ActReason",
      code: "TREAT"
    }]);
  });

  it("does not copy arbitrary patient-supplied FHIR properties", function () {
    const resource = buildPatientConsentResource({
      ...scope,
      resourceType: "Bundle",
      clinicalPayload: "must-not-be-copied"
    } as unknown as PatientConsentScope);

    expect(resource.resourceType).to.equal("Consent");
    expect(JSON.stringify(resource)).not.to.include("clinicalPayload");
    expect(JSON.stringify(resource)).not.to.include("must-not-be-copied");
  });

  it("supports a directed organization grant without a practitioner constraint", function () {
    const resource = buildPatientConsentResource({
      ...scope,
      practitionerReference: undefined
    });

    expect(resource.provision.actor).to.deep.equal([]);
    expect(resource.organization).to.deep.equal([{ reference: scope.granteeOrganizationReference }]);
  });
});
