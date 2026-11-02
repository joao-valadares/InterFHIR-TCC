import { expect } from "chai";
import {
  createManifestPublicationService
} from "../src/manifest/manifest-publication-service.js";
import { buildPatientConsentResource } from "../src/fhir/consent-builder.js";
import { computeManifestCommitment, type ResourceManifestVersion } from "../src/manifest/resource-manifest.js";
import type { ShareGrant } from "../src/share/share-grant.js";

describe("FHIR manifest publication service", function () {
  it("persists a signed pending version, anchors its signed active version, then activates it", async function () {
    const calls: string[] = [];
    const share = activeShare();
    const repository = inMemoryRepository(calls);
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: repository,
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async (manifest) => {
          calls.push(`anchor:${manifest.status}`);
        },
        supersedeAndAnchor: async () => undefined
      },
      signingKeyId: "hospital-a-key"
    });

    const published = await service.publishInitial({
      share,
      resourceReference: "Observation/obs-1",
      now: "2027-01-15T10:00:00.000Z"
    });

    expect(published.status).to.equal("active");
    expect(published.fhirVersionId).to.equal("7");
    expect(published.commitment).to.equal(
      computeManifestCommitment((( { commitment: _commitment, signature: _signature, ...draft }) => draft)(published))
    );
    expect(calls).to.deep.equal(["save:pending", "anchor:active", "activate:active"]);
  });

  it("keeps the pending version non-deliverable when anchoring fails", async function () {
    const calls: string[] = [];
    const share = activeShare();
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: inMemoryRepository(calls),
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async () => {
          throw new Error("ANCHOR_UNAVAILABLE");
        },
        supersedeAndAnchor: async () => undefined
      },
      signingKeyId: "hospital-a-key"
    });

    await expectRejection(
      service.publishInitial({
        share,
        resourceReference: "Observation/obs-1",
        now: "2027-01-15T10:00:00.000Z"
      }),
      "ANCHOR_UNAVAILABLE"
    );
    expect(calls).to.deep.equal(["save:pending"]);
  });

  it("reconciles an active chain anchor after a restart before database activation", async function () {
    const calls: string[] = [];
    const share = activeShare();
    const manifests = new Map<string, ResourceManifestVersion>();
    let anchored: ResourceManifestVersion | undefined;
    let crashAfterAnchor = true;
    const repository = {
      savePending: async (manifest: ResourceManifestVersion) => {
        calls.push("save:pending");
        const key = `${manifest.manifestId}:${manifest.version}`;
        if (manifests.has(key)) throw new Error("MANIFEST_VERSION_ALREADY_EXISTS");
        manifests.set(key, manifest);
        return manifest;
      },
      findById: async (manifestId: string, version: number) => manifests.get(`${manifestId}:${version}`),
      activatePending: async (manifest: ResourceManifestVersion) => {
        calls.push("activate:active");
        const active = { ...manifest, status: "active" as const };
        manifests.set(`${manifest.manifestId}:${manifest.version}`, active);
        return active;
      },
      requireActiveForShare: async () => { throw new Error("NOT_USED"); },
      supersedeAndActivate: async () => { throw new Error("NOT_USED"); }
    };
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: repository,
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async (manifest: ResourceManifestVersion) => {
          calls.push("anchor:active");
          anchored = manifest;
          if (crashAfterAnchor) {
            crashAfterAnchor = false;
            throw new Error("PROCESS_RESTART_AFTER_ANCHOR");
          }
        },
        getManifestRecord: async () => anchored ? { commitment: anchored.commitment, status: 1, exists: true } : undefined,
        supersedeAndAnchor: async () => undefined
      } as never,
      signingKeyId: "hospital-a-key"
    });

    await expectRejection(
      service.publishInitial({ share, resourceReference: "Observation/obs-1", manifestId: "manifest_recover", now: "2027-01-15T10:00:00.000Z" }),
      "PROCESS_RESTART_AFTER_ANCHOR"
    );
    const recovered = await service.publishInitial({ share, resourceReference: "Observation/obs-1", manifestId: "manifest_recover", now: "2027-01-15T10:00:00.000Z" });

    expect(recovered.status).to.equal("active");
    expect(calls.filter((call) => call === "anchor:active")).to.have.length(1);
    expect(calls).to.deep.equal(["save:pending", "anchor:active", "activate:active"]);
  });

  it("reconciles manifest revocation after a chain anchor before local activation", async function () {
    const share = activeShare();
    let current = signedVersion({ shareId: share.shareId, version: 1, status: "active" });
    let chainRecord: { commitment: string; status: number; exists: boolean } | undefined = { commitment: current.commitment, status: 1, exists: true };
    let failLocalActivation = true;
    let revokeAnchors = 0;
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: {
        savePending: async (manifest) => manifest,
        activatePending: async (manifest) => manifest,
        supersedeAndActivate: async (_superseded, active) => active,
        requireActiveForShare: async () => current,
        listActiveForShare: async () => current.status === "active" ? [current] : [],
        revokeActive: async (revoked) => {
          if (failLocalActivation) {
            failLocalActivation = false;
            throw new Error("LOCAL_REVOCATION_ACTIVATION_INTERRUPTED");
          }
          current = revoked;
          return current;
        }
      },
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async () => undefined,
        supersedeAndAnchor: async () => undefined,
        getManifestRecord: async () => chainRecord ?? { exists: false },
        revoke: async (_active, revoked) => {
          revokeAnchors += 1;
          chainRecord = { commitment: revoked.commitment, status: 2, exists: true };
        }
      },
      signingKeyId: "hospital-a-key"
    });

    await expectRejection(
      service.revokeForShare({ shareId: share.shareId, now: "2027-01-15T10:00:00.000Z" }),
      "LOCAL_REVOCATION_ACTIVATION_INTERRUPTED"
    );
    const recovered = await service.revokeForShare({ shareId: share.shareId, now: "2027-01-15T10:05:00.000Z" });

    expect(recovered.manifestIds).to.deep.equal([current.manifestId]);
    expect(current.status).to.equal("revoked");
    expect(revokeAnchors).to.equal(1);
  });

  it("anchors a legitimately updated FHIR resource as v2 and supersedes the signed v1", async function () {
    const calls: string[] = [];
    const share = activeShare();
    const current = signedVersion({ shareId: share.shareId, version: 1, status: "active" });
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: {
        ...inMemoryRepository(calls),
        requireActiveForShare: async () => current,
        supersedeAndActivate: async (superseded, active) => {
          calls.push(`supersede:${superseded.status}:${active.status}`);
          return active;
        }
      },
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async () => undefined,
        supersedeAndAnchor: async (_current, superseded, active) => {
          calls.push(`anchor-next:${superseded.status}:${active.status}`);
        }
      },
      signingKeyId: "hospital-a-key"
    });

    const next = await service.publishNext({
      shareId: share.shareId,
      manifestId: current.manifestId,
      now: "2027-01-15T10:10:00.000Z"
    });

    expect(next).to.include({ version: 2, status: "active" });
    expect(calls).to.deep.equal([
      "save:pending",
      "anchor-next:superseded:active",
      "supersede:superseded:active"
    ]);
  });

  it("reconciles an active manifest returned during initial publication before success", async function () {
    const share = activeShare();
    const active = signedVersion({ shareId: share.shareId, version: 1, status: "active" });
    let chainReads = 0;
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: {
        savePending: async () => active,
        activatePending: async () => { throw new Error("NOT_USED"); },
        supersedeAndActivate: async () => { throw new Error("NOT_USED"); },
        requireActiveForShare: async () => active
      },
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async () => { throw new Error("NOT_USED"); },
        supersedeAndAnchor: async () => undefined,
        getManifestRecord: async () => {
          chainReads += 1;
          return { exists: true, status: 1, commitment: `0x${"4".repeat(64)}` };
        }
      },
      signingKeyId: "hospital-a-key"
    });

    await expectRejection(
      service.publishInitial({
        share,
        resourceReference: "Observation/obs-1",
        manifestId: active.manifestId,
        now: "2027-01-15T10:00:00.000Z"
      }),
      "MANIFEST_RECOVERY_CHAIN_MISMATCH"
    );
    expect(chainReads).to.equal(1);
  });

  it("rejects persisted active metadata tampering even when its commitment field is unchanged", async function () {
    const share = activeShare();
    const active = signedVersion({ shareId: share.shareId, version: 1, status: "active" });
    const tampered = { ...active, resourceReference: "Observation/obs-tampered" };
    let chainReads = 0;
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: {
        savePending: async () => tampered,
        activatePending: async () => { throw new Error("NOT_USED"); },
        supersedeAndActivate: async () => { throw new Error("NOT_USED"); },
        requireActiveForShare: async () => tampered
      },
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async () => { throw new Error("NOT_USED"); },
        supersedeAndAnchor: async () => undefined,
        getManifestRecord: async () => {
          chainReads += 1;
          return { exists: true, status: 1, commitment: active.commitment };
        }
      },
      signingKeyId: "hospital-a-key"
    });

    await expectRejection(
      service.publishInitial({
        share,
        resourceReference: "Observation/obs-1",
        manifestId: active.manifestId,
        now: "2027-01-15T10:00:00.000Z"
      }),
      "MANIFEST_RECOVERY_PERSISTENCE_MISMATCH"
    );
    expect(chainReads).to.equal(0);
  });

  it("reconciles an active next version returned after a restart before success", async function () {
    const share = activeShare();
    const current = signedVersion({ shareId: share.shareId, version: 1, status: "active" });
    const activeNext = signedVersion({ shareId: share.shareId, version: 2, status: "active" });
    let chainReads = 0;
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: {
        savePending: async (manifest) => manifest,
        activatePending: async (manifest) => manifest,
        findById: async () => activeNext,
        requireActiveForShare: async () => current,
        supersedeAndActivate: async () => { throw new Error("NOT_USED"); }
      },
      fhirClient: fhirClient(),
      signer: signer(),
      anchor: {
        anchorInitial: async () => undefined,
        supersedeAndAnchor: async () => { throw new Error("NOT_USED"); },
        getManifestRecord: async () => {
          chainReads += 1;
          return { exists: true, status: 1, commitment: `0x${"5".repeat(64)}` };
        }
      },
      signingKeyId: "hospital-a-key"
    });

    await expectRejection(
      service.publishNext({
        shareId: share.shareId,
        manifestId: current.manifestId,
        now: "2027-01-15T10:10:00.000Z"
      }),
      "MANIFEST_RECOVERY_CHAIN_MISMATCH"
    );
    expect(chainReads).to.equal(1);
  });

  it("rejects a noncanonical Consent before publishing or anchoring a manifest", async function () {
    const calls: string[] = [];
    const share = activeShare();
    const service = createManifestPublicationService({
      shareRepository: { requireActive: async () => share },
      manifestRepository: inMemoryRepository(calls),
      fhirClient: {
        ...fhirClient(),
        readConsent: async () => ({ resourceType: "Consent", id: "cons-1", status: "active" })
      },
      signer: signer(),
      anchor: {
        anchorInitial: async () => { calls.push("anchor"); },
        supersedeAndAnchor: async () => undefined
      },
      signingKeyId: "hospital-a-key"
    });

    await expectRejection(
      service.publishInitial({
        share,
        resourceReference: "Observation/obs-1",
        consentProjectionHash: `0x${"9".repeat(64)}`,
        now: "2027-01-15T10:00:00.000Z"
      }),
      "FHIR_CONSENT_NOT_PERMIT"
    );
    expect(calls).to.deep.equal([]);
  });
});

function activeShare(): ShareGrant {
  return {
    shareId: "share_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    patientReference: "Patient/maria",
    consentReference: "Consent/cons-1",
    allowedResourceTypes: ["Observation"],
    allowedOperation: "read",
    allowedPurpose: "TREAT",
    validFrom: "2027-01-15T09:00:00.000Z",
    validUntil: "2027-01-15T18:00:00.000Z",
    status: "active",
    createdAt: "2027-01-15T09:00:00.000Z"
  };
}

function fhirClient() {
  return {
    readLatest: async () => ({
      resourceType: "Observation",
      id: "obs-1",
      meta: { versionId: "7" },
      subject: { reference: "Patient/maria" },
      status: "final",
      valueInteger: 120
    }),
    readConsent: async () => ({
      ...buildPatientConsentResource({
        patientReference: "Patient/maria",
        granteeOrganizationReference: "Organization/clinic-b",
        practitionerReference: "Practitioner/bruno",
        resourceReference: "Observation/obs-1",
        purposeOfUse: "TREAT",
        policyId: "POLICY_TREATMENT_OBSERVATION",
        policyVersion: 1,
        validFrom: "2027-01-15T09:00:00.000Z",
        validUntil: "2027-01-15T18:00:00.000Z"
      }),
      id: "cons-1",
      meta: { versionId: "1" }
    })
  };
}

function signer() {
  return {
    sign: async (commitment: string) => ({
      algorithm: "ES256" as const,
      signingKeyId: "hospital-a-key",
      signature: `sig:${commitment}`
    })
  };
}

function inMemoryRepository(calls: string[]) {
  const manifests = new Map<string, ResourceManifestVersion>();
  return {
    savePending: async (manifest: ResourceManifestVersion) => {
      calls.push(`save:${manifest.status}`);
      manifests.set(`${manifest.manifestId}:${manifest.version}`, manifest);
      return manifest;
    },
    activatePending: async (manifest: ResourceManifestVersion) => {
      calls.push(`activate:${manifest.status}`);
      manifests.set(`${manifest.manifestId}:${manifest.version}`, manifest);
      return manifest;
    },
    requireActiveForShare: async () => {
      throw new Error("NOT_USED");
    },
    supersedeAndActivate: async () => {
      throw new Error("NOT_USED");
    }
  };
}

function signedVersion(input: {
  shareId: string;
  version: number;
  status: ResourceManifestVersion["status"];
}): ResourceManifestVersion {
  const draft: Omit<ResourceManifestVersion, "commitment" | "signature"> = {
    manifestId: "manifest_existing",
    shareId: input.shareId,
    version: input.version,
    status: input.status,
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    resourceReference: "Observation/obs-1",
    resourceType: "Observation",
    fhirVersionId: "6",
    subjectReference: "Patient/maria",
    consentReferenceHash: `0x${"1".repeat(64)}`,
    consentProjectionHash: `0x${"2".repeat(64)}`,
    resourceHash: `0x${"3".repeat(64)}`,
    previousVersionCommitment: `0x${"0".repeat(64)}`,
    signingKeyId: "hospital-a-key",
    createdAt: "2027-01-15T10:00:00.000Z"
  };
  return { ...draft, commitment: computeManifestCommitment(draft), signature: "sig" };
}

async function expectRejection(promise: Promise<unknown>, message: string) {
  try {
    await promise;
    expect.fail(`Expected ${message}`);
  } catch (error) {
    expect((error as Error).message).to.equal(message);
  }
}
