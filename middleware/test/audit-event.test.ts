import { expect } from "chai";

import { createAccessAuditEvent } from "../src/fhir/audit-event.js";

describe("FHIR AuditEvent mapper", function () {
  it("creates an AuditEvent with decision metadata and without embedding clinical payload", function () {
    const auditEvent = createAccessAuditEvent({
      requestId: "request-123",
      action: "read",
      granted: true,
      outcomeReason: "ACCESS_GRANTED",
      patientReference: "Patient/maria",
      practitionerReference: "Practitioner/ana",
      organizationReference: "Organization/hospital-a",
      resourceReference: "Observation/obs-1",
      requestHash: "0xabc",
      transactionHash: "0xdef",
      recordedAt: "2027-01-15T10:00:00.000Z"
    });

    expect(auditEvent.resourceType).to.equal("AuditEvent");
    expect(auditEvent.recorded).to.equal("2027-01-15T10:00:00.000Z");
    expect(auditEvent.outcome).to.equal("0");
    expect(auditEvent.extension.some((extension) => extension.url === "https://interfhir.local/fhir/StructureDefinition/access-request-id")).to.equal(true);
    expect(JSON.stringify(auditEvent)).to.contain("0xabc");
    expect(JSON.stringify(auditEvent)).to.not.contain("valueQuantity");
  });

  it("marks denied accesses with a major failure outcome", function () {
    const auditEvent = createAccessAuditEvent({
      action: "read",
      granted: false,
      outcomeReason: "ACCESS_DENIED",
      patientReference: "Patient/maria",
      practitionerReference: "Practitioner/ana",
      organizationReference: "Organization/hospital-a",
      resourceReference: "Observation/obs-1",
      requestHash: "0xabc",
      transactionHash: "0xdef",
      recordedAt: "2027-01-15T10:00:00.000Z"
    });

    expect(auditEvent.outcome).to.equal("4");
  });
});
