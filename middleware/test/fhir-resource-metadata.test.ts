import { expect } from "chai";

import { extractFhirResourceMetadata } from "../src/fhir/resource-metadata.js";

describe("generic FHIR resource metadata extraction", function () {
  it("extracts patient metadata from subject-based clinical resources", function () {
    const metadata = extractFhirResourceMetadata({
      resourceType: "DiagnosticReport",
      id: "report-1",
      status: "final",
      subject: { reference: "Patient/maria" }
    });

    expect(metadata).to.deep.equal({
      resourceReference: "DiagnosticReport/report-1",
      resourceType: "DiagnosticReport",
      patientReference: "Patient/maria"
    });
  });

  it("extracts patient metadata from patient-based clinical resources", function () {
    const metadata = extractFhirResourceMetadata({
      resourceType: "Immunization",
      id: "imm-1",
      status: "completed",
      patient: { reference: "Patient/maria" }
    });

    expect(metadata.patientReference).to.equal("Patient/maria");
    expect(metadata.resourceReference).to.equal("Immunization/imm-1");
  });

  it("fails with a stable error for supported resources missing patient linkage", function () {
    expect(() =>
      extractFhirResourceMetadata({
        resourceType: "DocumentReference",
        id: "doc-1",
        status: "current"
      })
    ).to.throw("FHIR_RESOURCE_WITHOUT_PATIENT_REFERENCE");
  });

  it("fails with a stable error for unsupported resource types", function () {
    expect(() =>
      extractFhirResourceMetadata({
        resourceType: "Coverage",
        id: "coverage-1",
        beneficiary: { reference: "Patient/maria" }
      })
    ).to.throw("UNSUPPORTED_RESOURCE_TYPE");
  });
});
