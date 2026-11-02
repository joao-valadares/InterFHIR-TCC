import { expect } from "chai";
import { createPatientShareService } from "../src/interfhir/patient-share-service.js";
import type { ShareGrant } from "../src/share/share-grant.js";

describe("patient share creation", function () {
  it("uses the trusted injected custodian instead of a hardcoded institution", async function () {
    let persisted: ShareGrant | undefined;
    const service = createPatientShareService({
      custodianOrganizationReference: "Organization/hospital-c-trusted",
      now: () => "2026-07-20T00:00:00.000Z",
      validate: async () => ({ resourceTypes: ["Observation"] }),
      shares: {
        savePending: async (share) => { persisted = share; return share; },
        activate: async (shareId) => ({ ...(persisted as ShareGrant), shareId, status: "active" as const }),
        issueHandoffCode: async () => undefined
      }
    });

    await service.create({ patientReference: "Patient/ana", granteeOrganizationReference: "Organization/clinic-b", consentReference: "Consent/cons", resourceReferences: ["Observation/obs-ana-1"], purposeOfUse: "TREAT", validUntil: "2026-08-30T23:59:59.000Z" });
    expect(persisted?.custodianOrganizationReference).to.equal("Organization/hospital-c-trusted");
  });

  it("derives a directed share from patient context and stores only a handoff hash", async function () {
    const events: unknown[] = [];
    const service = createPatientShareService({ custodianOrganizationReference: "Organization/hospital-a", now: () => "2026-07-20T00:00:00.000Z", validate: async (input) => { expect(input.patientReference).to.equal("Patient/ana"); return { resourceTypes: ["Observation"] }; }, shares: { savePending: async (share) => { events.push(share); return share; }, activate: async (shareId) => ({ ...(events[0] as ShareGrant), shareId, status: "active" as const }), issueHandoffCode: async (shareId, hash) => { events.push({ shareId, hash }); } } });
    const result = await service.create({ patientReference: "Patient/ana", granteeOrganizationReference: "Organization/clinic-b", consentReference: "Consent/cons-ana-clinic-b", resourceReferences: ["Observation/obs-ana-1"], purposeOfUse: "TREAT", validUntil: "2026-08-30T23:59:59.000Z" });
    expect(result.shareId).to.match(/^share_/);
    expect(result.manifestIds).to.deep.equal([]);
    expect(result.handoffCode).to.be.a("string").and.not.empty;
    expect(JSON.stringify(events)).not.to.include(result.handoffCode);
    expect(JSON.stringify(events)).to.include("sha256:");
  });

  it("does not persist a share when the custodian validation rejects the patient Consent or resource binding", async function () {
    let persisted = 0;
    const service = createPatientShareService({ custodianOrganizationReference: "Organization/hospital-a", now: () => "2026-07-20T00:00:00.000Z", validate: async () => { throw new Error("FHIR_CONSENT_PATIENT_MISMATCH"); }, shares: { savePending: async () => { persisted += 1; throw new Error("must not persist"); }, activate: async () => { throw new Error("must not activate"); }, issueHandoffCode: async () => { throw new Error("must not issue"); } } });
    await expectRejected(() => service.create({ patientReference: "Patient/ana", granteeOrganizationReference: "Organization/clinic-b", consentReference: "Consent/other-patient", resourceReferences: ["Observation/obs-other"], purposeOfUse: "TREAT", validUntil: "2026-08-30T23:59:59.000Z" }), "FHIR_CONSENT_PATIENT_MISMATCH");
    expect(persisted).to.equal(0);
  });

  it("publishes custodian-owned manifests only after activating the share", async function () {
    const events: string[] = [];
    const service = createPatientShareService({ custodianOrganizationReference: "Organization/hospital-a", now: () => "2026-07-20T00:00:00.000Z", validate: async () => ({ resourceTypes: ["Observation"] }), publish: async () => { events.push("publish"); return { manifestId: "manifest_opaque" }; }, shares: { savePending: async (share) => { events.push("pending"); return share; }, activate: async (shareId) => { events.push("active"); return { shareId, custodianOrganizationReference: "Organization/hospital-a", granteeOrganizationReference: "Organization/clinic-b", patientReference: "Patient/ana", consentReference: "Consent/cons", allowedResourceTypes: ["Observation"], allowedOperation: "read", allowedPurpose: "TREAT", validFrom: "2026-07-20T00:00:00.000Z", validUntil: "2026-08-30T23:59:59.000Z", status: "active" as const, createdAt: "2026-07-20T00:00:00.000Z" }; }, issueHandoffCode: async () => { events.push("code"); } } });
    const result = await service.create({ patientReference: "Patient/ana", granteeOrganizationReference: "Organization/clinic-b", consentReference: "Consent/cons", resourceReferences: ["Observation/obs"], purposeOfUse: "TREAT", validUntil: "2026-08-30T23:59:59.000Z" });
    expect(events).to.deep.equal(["pending", "active", "code", "publish"]);
    expect(result.manifestIds).to.deep.equal(["manifest_opaque"]);
  });

  it("registers the patient-directed consent before publishing the manifest", async function () {
    const events: string[] = [];
    const service = createPatientShareService({
      custodianOrganizationReference: "Organization/hospital-a",
      now: () => "2026-07-20T00:00:00.000Z",
      validate: async () => ({ resourceTypes: ["Observation"] }),
      registerDirectedConsent: async () => { events.push("directed-consent"); },
      publish: async () => { events.push("publish"); return { manifestId: "manifest_opaque" }; },
      shares: {
        savePending: async (share) => { events.push("pending"); return share; },
        activate: async (shareId) => {
          events.push("active");
          return { shareId, custodianOrganizationReference: "Organization/hospital-a", granteeOrganizationReference: "Organization/clinic-b", patientReference: "Patient/ana", consentReference: "Consent/cons", allowedResourceTypes: ["Observation"], allowedOperation: "read", allowedPurpose: "TREAT", validFrom: "2026-07-20T00:00:00.000Z", validUntil: "2026-08-30T23:59:59.000Z", status: "active" as const, createdAt: "2026-07-20T00:00:00.000Z" };
        },
        issueHandoffCode: async () => { events.push("code"); }
      }
    });

    await service.create({ patientReference: "Patient/ana", granteeOrganizationReference: "Organization/clinic-b", consentReference: "Consent/cons", resourceReferences: ["Observation/obs"], purposeOfUse: "TREAT", validUntil: "2026-08-30T23:59:59.000Z" });
    expect(events).to.deep.equal(["pending", "active", "code", "directed-consent", "publish"]);
  });
});

async function expectRejected(action: () => Promise<unknown>, reason: string) {
  try { await action(); expect.fail("expected rejection"); } catch (error) { expect((error as Error).message).to.equal(reason); }
}
