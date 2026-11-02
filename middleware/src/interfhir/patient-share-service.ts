import { randomBytes } from "node:crypto";
import { buildShareGrant, type ShareGrant } from "../share/share-grant.js";
import { hashHandoffCode } from "./custodian-access-service.js";

export function createPatientShareService(options: {
  custodianOrganizationReference: string;
  shares: { savePending(share: ShareGrant): Promise<ShareGrant>; activate(shareId: string, updatedAt: string): Promise<ShareGrant>; issueHandoffCode(shareId: string, codeHash: string, expiresAt: string): Promise<void> };
  validate(input: { patientReference: string; consentReference: string; granteeOrganizationReference: string; resourceReferences: string[] }): Promise<{ resourceTypes: string[] }>;
  registerDirectedConsent?(input: { share: ShareGrant; resourceReferences: string[]; resourceTypes: string[] }): Promise<void>;
  publish?(input: { share: ShareGrant; resourceReference: string; now: string }): Promise<{ manifestId: string }>;
  now?: () => string;
}) {
  let publisher = options.publish;
  return { async create(input: { patientReference: string; granteeOrganizationReference: string; consentReference: string; resourceReferences: string[]; purposeOfUse: string; validUntil: string }) {
    const now = (options.now ?? (() => new Date().toISOString()))();
    const validated = await options.validate(input);
    const share = buildShareGrant({ custodianOrganizationReference: options.custodianOrganizationReference, granteeOrganizationReference: input.granteeOrganizationReference, patientReference: input.patientReference, consentReference: input.consentReference, allowedResourceTypes: validated.resourceTypes, allowedOperation: "read", allowedPurpose: input.purposeOfUse, validFrom: now, validUntil: input.validUntil, now });
    await options.shares.savePending({ ...share, status: "pending" });
    const active = await options.shares.activate(share.shareId, now);
    const handoffCode = randomBytes(24).toString("base64url");
    await options.shares.issueHandoffCode(active.shareId, hashHandoffCode(handoffCode), input.validUntil);
    if (options.registerDirectedConsent) {
      await options.registerDirectedConsent({ share: active, resourceReferences: input.resourceReferences, resourceTypes: validated.resourceTypes });
    }
    const manifestIds = publisher
      ? await Promise.all(input.resourceReferences.map(async (resourceReference) => (await publisher!({ share: active, resourceReference, now })).manifestId))
      : [];
    return { shareId: active.shareId, handoffCode, manifestIds };
  }, setPublisher(next: NonNullable<typeof publisher>) { publisher = next; } };
}
