import { expect } from "chai";
import { ethers } from "ethers";

import {
  ACTION_READ_CODE,
  PURPOSE_TREATMENT_CODE,
  REQUIRED_TREATMENT_OBSERVATION_MASK,
  RESOURCE_TYPE_DIAGNOSTIC_REPORT,
  RESOURCE_TYPE_OBSERVATION,
  mapFhirConsentToRegisterConsentInput
} from "../src/fhir/consent-mapper.js";

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function activeTreatmentObservationConsent() {
  return {
    resourceType: "Consent",
    id: "cons-1",
    meta: { versionId: "1" },
    status: "active",
    patient: { reference: "Patient/maria" },
    organization: [{ reference: "Organization/hospital-a" }],
    extension: [{
      url: "https://interfhir.local/fhir/StructureDefinition/network-policy",
      valueIdentifier: {
        system: "https://interfhir.local/policies",
        value: "POLICY_TREATMENT_OBSERVATION@1"
      }
    }],
    provision: {
      type: "permit",
      period: {
        start: "2027-01-15T10:00:00.000Z",
        end: "2027-01-15T11:00:00.000Z"
      },
      actor: [
        {
          role: { coding: [{ code: "performer" }] },
          reference: { reference: "Practitioner/ana" }
        },
        {
          role: { coding: [{ code: "custodian" }] },
          reference: { reference: "Organization/hospital-a" }
        }
      ],
      action: [{ coding: [{ code: "read" }] }],
      purpose: [{
        system: "http://terminology.hl7.org/CodeSystem/v3-ActReason",
        code: "TREAT"
      }],
      class: [{ code: "Observation" }],
      data: [{ reference: { reference: "Observation/obs-1" } }]
    }
  };
}

describe("FHIR Consent mapper", function () {
  it("maps an active FHIR Consent permit into the on-chain consent registration DTO", function () {
    const input = mapFhirConsentToRegisterConsentInput(activeTreatmentObservationConsent());

    expect(input).to.deep.equal({
      consentHash: id("Consent/cons-1"),
      consentIdHash: id("Consent/cons-1"),
      consentProjectionHash: "0x66c668e479609a78f4adfc4f6ad0f9155f307928450baf9f0852c9073bbb34cb",
      consentVersion: "1",
      patientHash: id("Patient/maria"),
      actorHash: id("Practitioner/ana"),
      actorConstraintHash: id("Practitioner/ana"),
      organizationHash: id("Organization/hospital-a"),
      granteeOrganizationHash: id("Organization/hospital-a"),
      resourceIdHash: id("Observation/obs-1"),
      policyIdHash: id("POLICY_TREATMENT_OBSERVATION"),
      policyVersion: 1,
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      validFrom: 1_800_007_200,
      validUntil: 1_800_010_800,
      policyMask: REQUIRED_TREATMENT_OBSERVATION_MASK
    });
  });

  it("infers the resource type from the referenced FHIR data when HAPI omits provision.class", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.class = [];

    const input = mapFhirConsentToRegisterConsentInput(consent);

    expect(input.resourceTypeCode).to.equal(RESOURCE_TYPE_OBSERVATION);
    expect(input.resourceIdHash).to.equal(id("Observation/obs-1"));
  });

  it("rejects a class that disagrees with the referenced FHIR resource type", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.class[0].code = "MedicationRequest";

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_RESOURCE_TYPE_MISMATCH"
    );
  });

  it("rejects inactive FHIR consent before creating on-chain input", function () {
    const consent = activeTreatmentObservationConsent();
    consent.status = "draft";

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw("FHIR_CONSENT_NOT_ACTIVE");
  });

  it("maps non-Observation FHIR consent scopes through the same generic policy path", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.class[0].code = "MedicationRequest";
    consent.provision.data[0].reference.reference = "MedicationRequest/med-1";
    consent.extension[0].valueIdentifier.value = "POLICY_TREATMENT_MEDICATION_REQUEST@1";

    const input = mapFhirConsentToRegisterConsentInput(consent);

    expect(input.resourceTypeCode).to.not.equal(RESOURCE_TYPE_OBSERVATION);
    expect(input.resourceIdHash).to.equal(id("MedicationRequest/med-1"));
    expect(input.policyMask).to.equal(REQUIRED_TREATMENT_OBSERVATION_MASK);
  });

  it("maps DiagnosticReport consent scopes to a stable resource type code", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.class[0].code = "DiagnosticReport";
    consent.provision.data[0].reference.reference = "DiagnosticReport/report-1";
    consent.extension[0].valueIdentifier.value = "POLICY_TREATMENT_DIAGNOSTIC_REPORT@1";

    const input = mapFhirConsentToRegisterConsentInput(consent);

    expect(input.resourceTypeCode).to.equal(RESOURCE_TYPE_DIAGNOSTIC_REPORT);
    expect(input.resourceIdHash).to.equal(id("DiagnosticReport/report-1"));
  });

  it("maps an explicit payment purpose so a divergent API purpose reaches the on-chain consent decision", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.purpose[0].code = "HPAYMT";
    consent.extension[0].valueIdentifier.value = "POLICY_PAYMENT_OBSERVATION@1";

    const input = mapFhirConsentToRegisterConsentInput(consent);

    expect(input.purposeCode).to.equal(2);
    expect(input.policyMask).to.equal(4063);
  });

  it("rejects a Consent without a network policy extension", function () {
    const consent = activeTreatmentObservationConsent();
    consent.extension = [];

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_WITHOUT_POLICY"
    );
  });

  it("rejects a policy that does not match the Consent resource or purpose", function () {
    const consent = activeTreatmentObservationConsent();
    consent.extension[0].valueIdentifier.value = "POLICY_PAYMENT_OBSERVATION@1";

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_POLICY_PURPOSE_MISMATCH"
    );
  });

  it("rejects a Consent with a divergent resource reference", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.class = [];
    consent.provision.data[0].reference.reference = "MedicationRequest/med-1";

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_POLICY_RESOURCE_MISMATCH"
    );
  });

  it("rejects a Consent that attempts to authorize multiple resources", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.data.push({ reference: { reference: "Observation/obs-2" } });

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_RESOURCE_SCOPE_INVALID"
    );
  });

  it("rejects conflicting organization declarations", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.actor[1].reference.reference = "Organization/other";

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_ORGANIZATION_CONFLICT"
    );
  });

  it("rejects multiple organization references", function () {
    const consent = activeTreatmentObservationConsent();
    consent.organization.push({ reference: "Organization/other" });

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_AMBIGUOUS_ORGANIZATION"
    );
  });

  it("rejects multiple practitioner actor references", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.actor.push({
      role: { coding: [{ code: "performer" }] },
      reference: { reference: "Practitioner/beatriz" }
    });

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_AMBIGUOUS_PRACTITIONER"
    );
  });

  it("rejects multiple policy extensions", function () {
    const consent = activeTreatmentObservationConsent();
    consent.extension.push({
      url: "https://interfhir.local/fhir/StructureDefinition/network-policy",
      valueIdentifier: {
        system: "https://interfhir.local/policies",
        value: "POLICY_TREATMENT_OBSERVATION@1"
      }
    });

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "FHIR_CONSENT_AMBIGUOUS_POLICY"
    );
  });

  it("rejects multiple class, action, and purpose values", function () {
    const classConsent = activeTreatmentObservationConsent();
    classConsent.provision.class.push({ code: "Observation" });
    expect(() => mapFhirConsentToRegisterConsentInput(classConsent)).to.throw(
      "FHIR_CONSENT_AMBIGUOUS_CLASS"
    );

    const actionConsent = activeTreatmentObservationConsent();
    actionConsent.provision.action.push({ coding: [{ code: "read" }] });
    expect(() => mapFhirConsentToRegisterConsentInput(actionConsent)).to.throw(
      "FHIR_CONSENT_AMBIGUOUS_ACTION"
    );

    const purposeConsent = activeTreatmentObservationConsent();
    purposeConsent.provision.purpose.push({
      system: "http://terminology.hl7.org/CodeSystem/v3-ActReason",
      code: "TREAT"
    });
    expect(() => mapFhirConsentToRegisterConsentInput(purposeConsent)).to.throw(
      "FHIR_CONSENT_AMBIGUOUS_PURPOSE"
    );
  });

  it("rejects a Consent period without a timezone", function () {
    const consent = activeTreatmentObservationConsent();
    consent.provision.period.start = "2027-01-15T10:00:00.000";

    expect(() => mapFhirConsentToRegisterConsentInput(consent)).to.throw(
      "INVALID_FHIR_DATETIME"
    );
  });
});
