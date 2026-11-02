import { randomUUID } from "node:crypto";

import { expect } from "chai";

import {
  computeManifestCommitment,
  type ResourceManifestVersion
} from "../src/manifest/resource-manifest.js";
import { createPostgresManifestVersionRepository } from "../src/manifest/postgres-manifest-repository.js";
import { createPostgresShareRepository } from "../src/share/postgres-share-repository.js";
import { buildShareGrant } from "../src/share/share-grant.js";

const connectionString =
  process.env.MANIFEST_TEST_DATABASE_URL ??
  process.env.MANIFEST_DATABASE_URL ??
  "postgresql://manifest:manifest@127.0.0.1:5433/interfhir_manifest";
const clinicConnectionString =
  process.env.CLINIC_B_METADATA_TEST_DATABASE_URL ??
  "postgresql://clinic_b_metadata:clinic_b_metadata@127.0.0.1:5435/interfhir_clinic_b_metadata";

describe("PostgreSQL versioned manifest repository", function (this: { timeout(milliseconds: number): void }) {
  this.timeout(20_000);

  it("reconciles the exact pending manifest row after a repository restart", async function () {
    const share = await prepareShare();
    const firstRepository = createPostgresManifestVersionRepository({ connectionString });
    await firstRepository.migrate();
    const pending = buildManifestVersion(share.shareId, "pending");
    await firstRepository.savePending(pending);
    await firstRepository.close();

    const restartedRepository = createPostgresManifestVersionRepository({ connectionString });
    const recovered = await restartedRepository.findById!(pending.manifestId, pending.version);
    await restartedRepository.close();

    expect(recovered).to.deep.equal(pending);
  });

  it("keeps a new FHIR-only manifest pending until the corresponding active version is signed", async function () {
    const share = await prepareShare();
    const repository = createPostgresManifestVersionRepository({ connectionString });
    await repository.migrate();
    const pending = buildManifestVersion(share.shareId, "pending");
    await repository.savePending(pending);

    await expectRejection(
      repository.requireActiveForShare(share.shareId, pending.manifestId),
      "MANIFEST_NOT_ACTIVE_FOR_SHARE"
    );
    const active = buildManifestVersion(share.shareId, "active", pending);
    await repository.activatePending(active);

    expect(await repository.requireActiveForShare(share.shareId, pending.manifestId)).to.deep.equal(active);
    await repository.close();
  });

  it("rejects an activation signature that changes immutable clinical metadata", async function () {
    const share = await prepareShare();
    const repository = createPostgresManifestVersionRepository({ connectionString });
    await repository.migrate();
    const pending = buildManifestVersion(share.shareId, "pending");
    await repository.savePending(pending);
    const active = buildManifestVersion(share.shareId, "active", pending);
    const alteredDraft = { ...active, resourceHash: `0x${"4".repeat(64)}` };
    const altered = {
      ...alteredDraft,
      commitment: computeManifestCommitment(
        (({ commitment: _commitment, signature: _signature, ...draft }) => draft)(alteredDraft)
      )
    };

    await expectRejection(
      repository.activatePending(altered),
      "MANIFEST_TRANSITION_IMMUTABLE_FIELDS_CHANGED"
    );
    await repository.close();
  });

  it("does not expose Hospital A active manifests through the separate Clínica B metadata database", async function () {
    const share = await prepareShare();
    const hospitalRepository = createPostgresManifestVersionRepository({ connectionString });
    await hospitalRepository.migrate();
    const pending = buildManifestVersion(share.shareId, "pending");
    await hospitalRepository.savePending(pending);
    await hospitalRepository.activatePending(buildManifestVersion(share.shareId, "active", pending));

    const clinicRepository = createPostgresManifestVersionRepository({ connectionString: clinicConnectionString });
    await clinicRepository.migrate();
    expect(await clinicRepository.listActiveForShare(share.shareId)).to.deep.equal([]);
    await expectRejection(
      clinicRepository.requireActiveForShare(share.shareId, pending.manifestId),
      "MANIFEST_NOT_ACTIVE_FOR_SHARE"
    );
    await hospitalRepository.close();
    await clinicRepository.close();
  });

  it("atomically supersedes a signed v1 while activating its signed v2", async function () {
    const share = await prepareShare();
    const repository = createPostgresManifestVersionRepository({ connectionString });
    await repository.migrate();
    const pendingV1 = buildManifestVersion(share.shareId, "pending");
    await repository.savePending(pendingV1);
    const activeV1 = buildManifestVersion(share.shareId, "active", pendingV1);
    await repository.activatePending(activeV1);
    const supersededV1 = buildManifestVersion(share.shareId, "superseded", activeV1);
    const pendingV2 = buildManifestVersion(
      share.shareId,
      "pending",
      { ...activeV1, version: 2 },
      supersededV1.commitment
    );
    await repository.savePending(pendingV2);
    const activeV2 = buildManifestVersion(share.shareId, "active", pendingV2);

    await repository.supersedeAndActivate(supersededV1, activeV2);

    expect(await repository.requireActiveForShare(share.shareId, activeV1.manifestId)).to.deep.equal(activeV2);
    await repository.close();
  });
});

async function prepareShare() {
  const shareRepository = createPostgresShareRepository({ connectionString });
  await shareRepository.migrate();
  const share = buildShareGrant({
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    patientReference: "Patient/maria",
    consentReference: "Consent/cons-1",
    allowedResourceTypes: ["Observation"],
    allowedOperation: "read",
    allowedPurpose: "TREAT",
    validFrom: "2027-01-15T09:00:00.000Z",
    validUntil: "2027-01-15T18:00:00.000Z",
    now: "2027-01-15T10:00:00.000Z"
  });
  await shareRepository.savePending({ ...share, status: "pending" });
  await shareRepository.activate(share.shareId, "2027-01-15T10:01:00.000Z");
  await shareRepository.close();
  return share;
}

function buildManifestVersion(
  shareId: string,
  status: ResourceManifestVersion["status"],
  previous?: ResourceManifestVersion,
  previousVersionCommitment?: string
): ResourceManifestVersion {
  const draft: Omit<ResourceManifestVersion, "commitment" | "signature"> = {
    manifestId: previous?.manifestId ?? `manifest-${randomUUID()}`,
    shareId,
    version: previous?.version ?? 1,
    status,
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    resourceReference: "Observation/obs-1",
    resourceType: "Observation",
    fhirVersionId: "7",
    subjectReference: "Patient/maria",
    consentReferenceHash: `0x${"1".repeat(64)}`,
    consentProjectionHash: `0x${"2".repeat(64)}`,
    resourceHash: `0x${"3".repeat(64)}`,
    previousVersionCommitment: previousVersionCommitment ?? previous?.previousVersionCommitment ?? `0x${"0".repeat(64)}`,
    signingKeyId: "hospital-a-manifest-key-1",
    createdAt: "2027-01-15T10:00:00.000Z",
    ...(previous ? { updatedAt: "2027-01-15T10:01:00.000Z" } : {})
  };
  return { ...draft, commitment: computeManifestCommitment(draft), signature: "test-signature" };
}

async function expectRejection(promise: Promise<unknown>, message: string) {
  try {
    await promise;
    expect.fail(`Expected rejection with ${message}`);
  } catch (error) {
    expect(error).to.be.instanceOf(Error);
    expect((error as Error).message).to.equal(message);
  }
}
