import { expect } from "chai";
import { ethers } from "ethers";

import {
  ACTION_READ_CODE,
  PURPOSE_TREATMENT_CODE,
  REQUIRED_TREATMENT_OBSERVATION_MASK,
  RESOURCE_TYPE_DIAGNOSTIC_REPORT,
  RESOURCE_TYPE_IMMUNIZATION,
  RESOURCE_TYPE_OBSERVATION
} from "../src/abac/policy-mask.js";
import { mapFhirRequestToAccessRequest } from "../src/abac/attribute-mapper.js";
import { hashFhirResource } from "../src/fhir/resource-hasher.js";

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function observation() {
  return {
    resourceType: "Observation",
    id: "obs-1",
    status: "final",
    subject: { reference: "Patient/maria" },
    valueQuantity: { value: 80, unit: "mmHg" }
  };
}

describe("FHIR request attribute mapper", function () {
  it("maps a protected FHIR read request into the contract AccessRequest DTO", function () {
    const resource = observation();

    const accessRequest = mapFhirRequestToAccessRequest({
      resource,
      resourceReference: "Observation/obs-1",
      patientReference: "Patient/maria",
      practitionerReference: "Practitioner/ana",
      organizationReference: "Organization/hospital-a",
      action: "read",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000
    });

    expect(accessRequest).to.deep.equal({
      patientHash: id("Patient/maria"),
      actorHash: id("Practitioner/ana"),
      organizationHash: id("Organization/hospital-a"),
      resourceIdHash: id("Observation/obs-1"),
      resourceHash: hashFhirResource(resource),
      resourceTypeCode: RESOURCE_TYPE_OBSERVATION,
      actionCode: ACTION_READ_CODE,
      purposeCode: PURPOSE_TREATMENT_CODE,
      attributesMask: REQUIRED_TREATMENT_OBSERVATION_MASK,
      requestTime: 1_800_000_000
    });
  });

  it("maps HPAYMT as a distinct purpose instead of rejecting it before blockchain authorization", function () {
    const accessRequest = mapFhirRequestToAccessRequest({
      resource: observation(),
      resourceReference: "Observation/obs-1",
      patientReference: "Patient/maria",
      practitionerReference: "Practitioner/ana",
      organizationReference: "Organization/hospital-a",
      action: "read",
      purposeOfUse: "HPAYMT",
      requestTime: 1_800_000_000
    });

    expect(accessRequest.purposeCode).to.equal(2);
    expect(accessRequest.attributesMask).to.equal(4063);
  });

  it("maps subject-based non-Observation resources through the same generic request path", function () {
    const resource = {
      resourceType: "DiagnosticReport",
      id: "report-1",
      status: "final",
      subject: { reference: "Patient/maria" },
      result: [{ reference: "Observation/obs-1" }]
    };

    const accessRequest = mapFhirRequestToAccessRequest({
      resource,
      resourceReference: "DiagnosticReport/report-1",
      patientReference: "Patient/maria",
      practitionerReference: "Practitioner/ana",
      organizationReference: "Organization/hospital-a",
      action: "read",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000
    });

    expect(accessRequest.resourceTypeCode).to.equal(RESOURCE_TYPE_DIAGNOSTIC_REPORT);
    expect(accessRequest.resourceIdHash).to.equal(id("DiagnosticReport/report-1"));
    expect(accessRequest.resourceHash).to.equal(hashFhirResource(resource));
    expect(accessRequest.attributesMask).to.equal(REQUIRED_TREATMENT_OBSERVATION_MASK);
  });

  it("maps patient-based resources through the same generic request path", function () {
    const resource = {
      resourceType: "Immunization",
      id: "imm-1",
      status: "completed",
      patient: { reference: "Patient/maria" },
      vaccineCode: { text: "Synthetic vaccine record" }
    };

    const accessRequest = mapFhirRequestToAccessRequest({
      resource,
      resourceReference: "Immunization/imm-1",
      patientReference: "Patient/maria",
      practitionerReference: "Practitioner/ana",
      organizationReference: "Organization/hospital-a",
      action: "read",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000
    });

    expect(accessRequest.resourceTypeCode).to.equal(RESOURCE_TYPE_IMMUNIZATION);
    expect(accessRequest.patientHash).to.equal(id("Patient/maria"));
    expect(accessRequest.resourceIdHash).to.equal(id("Immunization/imm-1"));
  });

  it("rejects mismatched patient references before calling blockchain", function () {
    expect(() =>
      mapFhirRequestToAccessRequest({
        resource: observation(),
        resourceReference: "Observation/obs-1",
        patientReference: "Patient/other",
        practitionerReference: "Practitioner/ana",
        organizationReference: "Organization/hospital-a",
        action: "read",
        purposeOfUse: "TREAT",
        requestTime: 1_800_000_000
      })
    ).to.throw("FHIR_REQUEST_PATIENT_MISMATCH");
  });

  it("rejects unsupported scopes explicitly", function () {
    expect(() =>
      mapFhirRequestToAccessRequest({
        resource: observation(),
        resourceReference: "Observation/obs-1",
        patientReference: "Patient/maria",
        practitionerReference: "Practitioner/ana",
        organizationReference: "Organization/hospital-a",
        action: "write",
        purposeOfUse: "TREAT",
        requestTime: 1_800_000_000
      })
    ).to.throw("UNSUPPORTED_ACTION");
  });
});
