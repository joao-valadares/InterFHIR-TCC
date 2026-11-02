import { expect } from "chai";

import { createCustodianAccessService, hashHandoffCode } from "../src/interfhir/custodian-access-service.js";

describe("custodian directed-share service", function () {
  const share = { handoffRedeemedAt: "2026-07-19T00:00:00.000Z", shareId: "share_11111111-1111-4111-8111-111111111111", custodianOrganizationReference: "Organization/hospital-a", granteeOrganizationReference: "Organization/clinic-b", patientReference: "Patient/ana", consentReference: "Consent/cons-ana-clinic-b", allowedResourceTypes: ["Observation"], allowedOperation: "read" as const, allowedPurpose: "TREAT", validFrom: "2026-07-01T00:00:00.000Z", validUntil: "2026-08-30T23:59:59.000Z", status: "active" as const, createdAt: "2026-07-01T00:00:00.000Z" };
  const manifest = { manifestId: "manifest_opaque", shareId: share.shareId, version: 1, status: "active" as const, custodianOrganizationReference: "Organization/hospital-a", granteeOrganizationReference: "Organization/clinic-b", resourceReference: "Observation/obs-ana-1", resourceType: "Observation", fhirVersionId: "7", subjectReference: "Patient/ana", consentReferenceHash: "hash", consentProjectionHash: "hash", resourceHash: "hash", previousVersionCommitment: "0x00", commitment: "0x01", signingKeyId: "key", signature: "signature", createdAt: share.createdAt };

  it("redeems a directed handoff only once and returns opaque share metadata", async function () {
    let redeemed = false;
    const service = createCustodianAccessService({ shares: { requireActive: async () => share, redeemHandoffCode: async (hash, org) => { expect(hash).to.equal(hashHandoffCode("handoff-code-123456")); expect(org).to.equal("Organization/clinic-b"); if (redeemed) throw new Error("HANDOFF_CODE_ALREADY_REDEEMED"); redeemed = true; return share; } }, manifests: { listActiveForShare: async () => [manifest], requireActiveForShare: async () => manifest }, deliver: async () => undefined });
    const response = await service.redeemHandoff({ handoffCode: "handoff-code-123456", granteeOrganizationReference: "Organization/clinic-b", now: "2026-07-20T00:00:00.000Z" });
    expect(response).to.deep.equal({ shareId: share.shareId, manifests: [{ manifestId: "manifest_opaque", resourceType: "Observation" }], validUntil: share.validUntil });
    await expectRejected(() => service.redeemHandoff({ handoffCode: "handoff-code-123456", granteeOrganizationReference: "Organization/clinic-b", now: "2026-07-20T00:00:00.000Z" }), "HANDOFF_CODE_ALREADY_REDEEMED");
  });

  it("loads custodian metadata before delivery and rejects a wrong grantee without calling delivery", async function () {
    let delivered = 0;
    const service = createCustodianAccessService({ shares: { requireActive: async () => share, redeemHandoffCode: async () => share }, manifests: { listActiveForShare: async () => [manifest], requireActiveForShare: async () => manifest }, deliver: async () => { delivered += 1; return { ok: true }; } });
    await expectRejected(() => service.readShare({ shareId: share.shareId, manifestId: manifest.manifestId, requesterOrganizationReference: "Organization/other", practitionerReference: "Practitioner/bruno", operation: "read", purposeOfUse: "TREAT", requestTime: "2026-07-20T00:00:00.000Z", requestId: "req_11111111-1111-4111-8111-111111111111", assertionHash: "sha256:trusted" }), "SHARE_GRANTEE_MISMATCH");
    expect(delivered).to.equal(0);
  });

  it("denies an active unredeemed share before manifest lookup", async function () {
    const service = createCustodianAccessService({ shares: { requireActive: async () => ({...share, handoffRedeemedAt: undefined}), redeemHandoffCode: async () => share }, manifests: { listActiveForShare: async () => { throw new Error("MUST_NOT_READ"); }, requireActiveForShare: async () => manifest }, deliver: async () => undefined });
    await expectRejected(() => service.getShare({shareId: share.shareId,granteeOrganizationReference: "Organization/clinic-b",now:"2026-07-20T00:00:00.000Z"}), "HANDOFF_NOT_REDEEMED");
  });

  it("allows only the grantee to look up the opaque share metadata after redemption", async function () {
    const service = createCustodianAccessService({ shares: { requireActive: async () => share, redeemHandoffCode: async () => share }, manifests: { listActiveForShare: async () => [manifest], requireActiveForShare: async () => manifest }, deliver: async () => undefined });
    const response = await service.getShare({ shareId: share.shareId, granteeOrganizationReference: "Organization/clinic-b", now: "2026-07-20T00:00:00.000Z" });
    expect(response.manifests).to.deep.equal([{ manifestId: manifest.manifestId, resourceType: "Observation" }]);
    await expectRejected(() => service.getShare({ shareId: share.shareId, granteeOrganizationReference: "Organization/other", now: "2026-07-20T00:00:00.000Z" }), "SHARE_GRANTEE_MISMATCH");
  });
});
async function expectRejected(action: () => Promise<unknown>, reason: string) { try { await action(); expect.fail("expected rejection"); } catch (error) { expect((error as Error).message).to.equal(reason); } }
