import { createHash } from "node:crypto";

import type { ResourceManifestVersion } from "../manifest/resource-manifest.js";
import { assertShareUsable, type ShareGrant } from "../share/share-grant.js";

export interface CustodianAccessService {
  redeemHandoff(input: { handoffCode: string; granteeOrganizationReference: string; now: string }): Promise<{ shareId: string; manifests: Array<{ manifestId: string; resourceType: string }>; validUntil: string }>;
  getShare(input: { shareId: string; granteeOrganizationReference: string; now: string }): Promise<{ shareId: string; manifests: Array<{ manifestId: string; resourceType: string }>; validUntil: string }>;
  readShare(input: { shareId: string; manifestId: string; requesterOrganizationReference: string; practitionerReference: string; operation: "read"; purposeOfUse: string; requestTime: string; requestId: string; assertionHash: string }): Promise<unknown>;
}

/**
 * Custodian-side share boundary. It never accepts a FHIR pointer, patient id,
 * consent id or requester identity from the B2B body: these values are loaded
 * from custodian-owned share and manifest metadata.
 */
export function createCustodianAccessService(options: {
  shares: {
    redeemHandoffCode(codeHash: string, granteeOrganizationReference: string, now: string): Promise<ShareGrant>;
    requireActive(shareId: string): Promise<ShareGrant>;
  };
  manifests: {
    listActiveForShare(shareId: string): Promise<ResourceManifestVersion[]>;
    requireActiveForShare(shareId: string, manifestId: string): Promise<ResourceManifestVersion>;
  };
  deliver(input: { share: ShareGrant; manifest: ResourceManifestVersion; requestId: string; requesterOrganizationReference: string; practitionerReference: string; purposeOfUse: string; requestTime: string; assertionHash: string }): Promise<unknown>;
}): CustodianAccessService {
  return {
    async redeemHandoff(input) {
      const share = await options.shares.redeemHandoffCode(hashHandoffCode(input.handoffCode), input.granteeOrganizationReference, input.now);
      return shareSummary(options, share, input.granteeOrganizationReference, input.now);
    },
    async getShare(input) {
      const share = await options.shares.requireActive(input.shareId);
      assertShareUsable(share, input.granteeOrganizationReference, share.allowedPurpose, input.now);
      requireRedeemed(share);
      return shareSummary(options, share, input.granteeOrganizationReference, input.now);
    },
    async readShare(input) {
      if (input.operation !== "read") throw new Error("SHARE_OPERATION_READ_REQUIRED");
      if (!/^req_[0-9a-f-]{36}$/i.test(input.requestId)) throw new Error("REQUEST_ID_INVALID");
      const share = await options.shares.requireActive(input.shareId);
      assertShareUsable(share, input.requesterOrganizationReference, input.purposeOfUse, input.requestTime);
      requireRedeemed(share);
      const manifest = await options.manifests.requireActiveForShare(input.shareId, input.manifestId);
      if (!share.allowedResourceTypes.includes(manifest.resourceType)) throw new Error("SHARE_RESOURCE_TYPE_MISMATCH");
      return options.deliver({ share, manifest, requestId: input.requestId, requesterOrganizationReference: input.requesterOrganizationReference, practitionerReference: input.practitionerReference, purposeOfUse: input.purposeOfUse, requestTime: input.requestTime, assertionHash: input.assertionHash });
    }
  };
}

async function shareSummary(options: { manifests: { listActiveForShare(shareId: string): Promise<ResourceManifestVersion[]> } }, share: ShareGrant, granteeOrganizationReference: string, now: string) {
  assertShareUsable(share, granteeOrganizationReference, share.allowedPurpose, now);
  const manifests = await options.manifests.listActiveForShare(share.shareId);
  return { shareId: share.shareId, manifests: manifests.map((manifest) => ({ manifestId: manifest.manifestId, resourceType: manifest.resourceType })), validUntil: share.validUntil };
}

export function hashHandoffCode(code: string) {
  if (code.trim().length < 16) throw new Error("HANDOFF_CODE_INVALID");
  return `sha256:${createHash("sha256").update(code).digest("base64url")}`;
}

function requireRedeemed(share: ShareGrant) { if (!share.handoffRedeemedAt) throw new Error("HANDOFF_NOT_REDEEMED"); }
