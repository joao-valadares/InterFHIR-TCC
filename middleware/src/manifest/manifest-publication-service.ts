import { randomUUID } from "node:crypto";

import {
  buildFhirManifestVersion,
  computeManifestCommitment,
  type ResourceManifestVersion
} from "./resource-manifest.js";
import type { ManifestSigner } from "./manifest-signer.js";
import type { ManifestVersionRepository } from "./postgres-manifest-repository.js";
import type { FhirResource } from "../fhir/resource-hasher.js";
import { mapFhirConsentToPatientConsentGrant } from "../fhir/consent-mapper.js";
import type { ShareRepository } from "../share/postgres-share-repository.js";
import type { ShareGrant } from "../share/share-grant.js";

export interface VersionedFhirClient {
  readLatest(resourceReference: string): Promise<FhirResource>;
  readConsent(consentReference: string): Promise<FhirResource>;
}

export interface ManifestAnchor {
  anchorInitial(manifest: ResourceManifestVersion): Promise<void>;
  getManifestRecord?(manifestId: string, version: number): Promise<{ commitment?: string; status?: number | bigint; exists?: boolean }>;
  supersedeAndAnchor(
    current: ResourceManifestVersion,
    superseded: ResourceManifestVersion,
    active: ResourceManifestVersion
  ): Promise<void>;
  revoke?(current: ResourceManifestVersion, revoked: ResourceManifestVersion): Promise<void>;
}

export interface ManifestPublicationService {
  publishInitial(input: {
    share: ShareGrant;
    resourceReference: string;
    now: string;
    consentProjectionHash?: string;
    consentVersion?: string;
    manifestId?: string;
    beforeSideEffect?: () => Promise<unknown>;
  }): Promise<ResourceManifestVersion>;
  publishNext(input: {
    shareId: string;
    manifestId: string;
    now: string;
    beforeSideEffect?: () => Promise<unknown>;
  }): Promise<ResourceManifestVersion>;
  findActiveForShare(shareId: string): Promise<ResourceManifestVersion | undefined>;
  revokeForShare(input: { shareId: string; now: string; beforeSideEffect?: () => Promise<unknown> }): Promise<{ manifestIds: string[] }>;
}

export function createManifestPublicationService(options: {
  shareRepository: Pick<ShareRepository, "requireActive">;
  manifestRepository: Pick<
    ManifestVersionRepository,
    "savePending" | "activatePending" | "supersedeAndActivate" | "requireActiveForShare"
  > & Partial<Pick<ManifestVersionRepository, "findById" | "listActiveForShare" | "revokeActive">>;
  fhirClient: VersionedFhirClient;
  signer: Pick<ManifestSigner, "sign">;
  anchor: ManifestAnchor;
  signingKeyId: string;
}): ManifestPublicationService {
  return {
    async publishInitial(input) {
      const share = await options.shareRepository.requireActive(input.share.shareId);
      assertSameShare(input.share, share);
      await input.beforeSideEffect?.();
      const resource = await options.fhirClient.readLatest(input.resourceReference);
      await input.beforeSideEffect?.();
      const mappedConsentProjectionHash = await readConsentProjectionHash(
        options.fhirClient,
        share.consentReference,
        input.beforeSideEffect
      );
      if (
        input.consentProjectionHash !== undefined &&
        input.consentProjectionHash !== mappedConsentProjectionHash
      ) {
        throw new Error("CONSENT_PROJECTION_HASH_MISMATCH");
      }
      const consentProjectionHash = mappedConsentProjectionHash;
      const pending = await signVersion(
        {
          ...buildFhirManifestVersion({
            manifestId: input.manifestId ?? `manifest_${randomUUID()}`,
            share,
            resource,
            consentProjectionHash,
            signingKeyId: options.signingKeyId,
            status: "pending",
            now: input.now
          }),
          updatedAt: input.now
        },
        options.signer
      );
      await input.beforeSideEffect?.();
      const persistedPending = await persistPendingManifest(options.manifestRepository, pending);
      if (persistedPending.status === "active") {
        await reconcilePersistedActiveManifest(options.anchor, persistedPending);
        return persistedPending;
      }
      if (persistedPending.status !== "pending") throw new Error("MANIFEST_RECOVERY_PERSISTENCE_MISMATCH");
      const active = await signVersion(
        { ...withoutSignature(persistedPending), status: "active", updatedAt: persistedPending.updatedAt ?? persistedPending.createdAt },
        options.signer
      );
      const chainRecord = await options.anchor.getManifestRecord?.(active.manifestId, active.version);
      if (chainRecord?.exists) {
        if (chainRecord.commitment !== active.commitment) {
          throw new Error("MANIFEST_RECOVERY_CHAIN_MISMATCH");
        }
        if (Number(chainRecord.status) !== 1) {
          throw new Error("MANIFEST_RECOVERY_CHAIN_NOT_ACTIVE");
        }
      } else {
        await input.beforeSideEffect?.();
        await options.anchor.anchorInitial(active);
      }
      await input.beforeSideEffect?.();
      return options.manifestRepository.activatePending(active);
    },

    async publishNext(input) {
      const share = await options.shareRepository.requireActive(input.shareId);
      const current = await options.manifestRepository.requireActiveForShare(
        share.shareId,
        input.manifestId
      );
      await input.beforeSideEffect?.();
      const pendingExisting = await options.manifestRepository.findById?.(
        current.manifestId,
        current.version + 1
      );
      const transitionAt = pendingExisting?.createdAt ?? input.now;
      const superseded = await signVersion(
        { ...withoutSignature(current), status: "superseded", updatedAt: transitionAt },
        options.signer
      );
      let persistedPending = pendingExisting;
      if (!persistedPending) {
        await input.beforeSideEffect?.();
        const resource = await options.fhirClient.readLatest(current.resourceReference);
        const consentProjectionHash = await readConsentProjectionHash(
          options.fhirClient,
          share.consentReference,
          input.beforeSideEffect
        );
        const pending = await signVersion(
          {
            ...buildFhirManifestVersion({
              manifestId: current.manifestId,
              share,
              resource,
              consentProjectionHash,
              signingKeyId: options.signingKeyId,
              version: current.version + 1,
              status: "pending",
              previousVersionCommitment: superseded.commitment,
              now: transitionAt
            }),
            updatedAt: transitionAt
          },
          options.signer
        );
        await input.beforeSideEffect?.();
        persistedPending = await persistPendingManifest(options.manifestRepository, pending);
      }
      if (!persistedPending) throw new Error("MANIFEST_RECOVERY_PERSISTENCE_MISSING");
      if (persistedPending.status === "active") {
        await reconcilePersistedActiveManifest(options.anchor, persistedPending);
        return persistedPending;
      }
      if (persistedPending.status !== "pending") throw new Error("MANIFEST_RECOVERY_PERSISTENCE_MISMATCH");
      const active = await signVersion(
        { ...withoutSignature(persistedPending), status: "active", updatedAt: persistedPending.updatedAt ?? persistedPending.createdAt },
        options.signer
      );
      const chainRecord = await options.anchor.getManifestRecord?.(active.manifestId, active.version);
      if (chainRecord?.exists) {
        if (chainRecord.commitment !== active.commitment) {
          throw new Error("MANIFEST_RECOVERY_CHAIN_MISMATCH");
        }
        if (Number(chainRecord.status) !== 1) {
          throw new Error("MANIFEST_RECOVERY_CHAIN_NOT_ACTIVE");
        }
      } else {
        await input.beforeSideEffect?.();
        await options.anchor.supersedeAndAnchor(current, superseded, active);
      }
      await input.beforeSideEffect?.();
      return options.manifestRepository.supersedeAndActivate(superseded, active);
    },

    async findActiveForShare(shareId) {
      if (!options.manifestRepository.listActiveForShare) return undefined;
      const manifests = await options.manifestRepository.listActiveForShare(shareId);
      return manifests[0];
    },

    async revokeForShare(input) {
      if (!options.manifestRepository.listActiveForShare || !options.manifestRepository.revokeActive) {
        throw new Error("MANIFEST_REPOSITORY_NOT_CONFIGURED");
      }
      const activeManifests = await options.manifestRepository.listActiveForShare(input.shareId);
      const manifestIds: string[] = [];
      for (const current of activeManifests) {
        // Keep the revoked commitment deterministic across a crash between the
        // chain anchor and local activation. The current version is immutable,
        // so its last durable timestamp is a stable recovery checkpoint.
        const revocationUpdatedAt = current.updatedAt ?? current.createdAt;
        const revoked = await signVersion(
          { ...withoutSignature(current), status: "revoked", updatedAt: revocationUpdatedAt },
          options.signer
        );
        if (!options.anchor.revoke) throw new Error("MANIFEST_REVOCATION_ANCHOR_NOT_CONFIGURED");
        await input.beforeSideEffect?.();
        const chainRecord = await options.anchor.getManifestRecord?.(current.manifestId, current.version);
        if (chainRecord?.exists) {
          const expectedCommitment = Number(chainRecord.status) === 2 ? revoked.commitment : current.commitment;
          if (chainRecord.commitment !== expectedCommitment) {
            throw new Error("MANIFEST_RECOVERY_CHAIN_MISMATCH");
          }
          if (Number(chainRecord.status) !== 2) {
            await input.beforeSideEffect?.();
            await options.anchor.revoke(current, revoked);
          }
        } else {
          await input.beforeSideEffect?.();
          await options.anchor.revoke(current, revoked);
        }
        await input.beforeSideEffect?.();
        await options.manifestRepository.revokeActive(revoked);
        manifestIds.push(revoked.manifestId);
      }
      return { manifestIds };
    }
  };
}

async function persistPendingManifest(
  repository: Pick<ManifestVersionRepository, "savePending"> & Partial<Pick<ManifestVersionRepository, "findById">>,
  pending: ResourceManifestVersion
) {
  const existing = await repository.findById?.(pending.manifestId, pending.version);
  if (existing) {
    assertSameManifestVersion(existing, pending);
    return existing;
  }
  try {
    return await repository.savePending(pending);
  } catch (error) {
    if (!(error instanceof Error) || error.message !== "MANIFEST_VERSION_ALREADY_EXISTS") throw error;
    const recovered = await repository.findById?.(pending.manifestId, pending.version);
    if (!recovered) throw new Error("MANIFEST_RECOVERY_PERSISTENCE_MISSING");
    assertSameManifestVersion(recovered, pending);
    return recovered;
  }
}

function assertSameManifestVersion(left: ResourceManifestVersion, right: ResourceManifestVersion) {
  if (
    left.manifestId !== right.manifestId ||
    left.shareId !== right.shareId ||
    left.version !== right.version ||
    left.commitment !== right.commitment ||
    left.signature !== right.signature
  ) throw new Error("MANIFEST_RECOVERY_PERSISTENCE_MISMATCH");
}

async function readConsentProjectionHash(
  fhirClient: VersionedFhirClient,
  consentReference: string,
  beforeSideEffect?: () => Promise<unknown>
) {
  await beforeSideEffect?.();
  const consent = await fhirClient.readConsent(consentReference);
  return mapFhirConsentToPatientConsentGrant(
    consent as Parameters<typeof mapFhirConsentToPatientConsentGrant>[0]
  ).consentProjectionHash;
}

async function reconcilePersistedActiveManifest(
  anchor: ManifestAnchor,
  manifest: ResourceManifestVersion
) {
  const canonicalCommitment = computeManifestCommitment(manifest);
  if (canonicalCommitment !== manifest.commitment) {
    throw new Error("MANIFEST_RECOVERY_PERSISTENCE_MISMATCH");
  }
  if (!anchor.getManifestRecord) {
    throw new Error("MANIFEST_ANCHOR_VERIFIER_NOT_CONFIGURED");
  }
  const chainRecord = await anchor.getManifestRecord(manifest.manifestId, manifest.version);
  if (!chainRecord?.exists) {
    throw new Error("MANIFEST_RECOVERY_CHAIN_MISSING");
  }
  if (chainRecord.commitment !== canonicalCommitment) {
    throw new Error("MANIFEST_RECOVERY_CHAIN_MISMATCH");
  }
  if (Number(chainRecord.status) !== 1) {
    throw new Error("MANIFEST_RECOVERY_CHAIN_NOT_ACTIVE");
  }
}

async function signVersion(
  draft: Omit<ResourceManifestVersion, "commitment" | "signature">,
  signer: Pick<ManifestSigner, "sign">
) {
  const commitment = computeManifestCommitment(draft);
  const signed = await signer.sign(commitment);
  if (signed.signingKeyId !== draft.signingKeyId) {
    throw new Error("MANIFEST_SIGNING_KEY_ID_MISMATCH");
  }
  return { ...draft, commitment, signature: signed.signature };
}

function withoutSignature(manifest: ResourceManifestVersion) {
  const { commitment: _commitment, signature: _signature, ...draft } = manifest;
  return draft;
}

function assertSameShare(expected: ShareGrant, actual: ShareGrant) {
  if (
    expected.shareId !== actual.shareId ||
    expected.custodianOrganizationReference !== actual.custodianOrganizationReference ||
    expected.granteeOrganizationReference !== actual.granteeOrganizationReference
  ) {
    throw new Error("SHARE_REPOSITORY_MISMATCH");
  }
}
