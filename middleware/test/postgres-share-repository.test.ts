import { randomUUID } from "node:crypto";

import { expect } from "chai";

import {
  createPostgresShareRepository
} from "../src/share/postgres-share-repository.js";
import { buildShareGrant } from "../src/share/share-grant.js";

const connectionString =
  process.env.HOSPITAL_A_METADATA_TEST_DATABASE_URL ??
  process.env.MANIFEST_TEST_DATABASE_URL ??
  "postgresql://manifest:manifest@127.0.0.1:5433/interfhir_manifest";

describe("PostgreSQL share repository", function (this: { timeout(milliseconds: number): void }) {
  this.timeout(20_000);

  it("keeps a pending share unavailable until it is activated", async function () {
    const repository = createPostgresShareRepository({ connectionString });
    await repository.migrate();
    const share = buildShare();
    await repository.savePending({ ...share, status: "pending" });

    await expectRejection(repository.requireActive(share.shareId), "SHARE_NOT_ACTIVE");
    const active = await repository.activate(share.shareId, "2027-01-15T10:01:00.000Z");
    await repository.close();

    expect(active).to.deep.include({
      shareId: share.shareId,
      status: "active",
      updatedAt: "2027-01-15T10:01:00.000Z"
    });
  });

  it("redeems a handoff code only once for its directed grantee before expiration", async function () {
    const repository = createPostgresShareRepository({ connectionString });
    await repository.migrate();
    const share = buildShare();
    await repository.savePending({ ...share, status: "pending" });
    await repository.activate(share.shareId, "2027-01-15T10:01:00.000Z");
    const codeHash = `0x${randomUUID().replaceAll("-", "").padEnd(64, "a")}`;
    await repository.issueHandoffCode(share.shareId, codeHash, "2027-01-15T10:10:00.000Z");

    const redeemed = await repository.redeemHandoffCode(
      codeHash,
      "Organization/clinic-b",
      "2027-01-15T10:05:00.000Z"
    );
    await expectRejection(
      repository.redeemHandoffCode(codeHash, "Organization/clinic-b", "2027-01-15T10:06:00.000Z"),
      "HANDOFF_CODE_ALREADY_REDEEMED"
    );
    await repository.close();

    expect(redeemed.shareId).to.equal(share.shareId);
  });

  it("does not redeem a code for a different institution or after expiration", async function () {
    const repository = createPostgresShareRepository({ connectionString });
    await repository.migrate();
    const share = buildShare();
    await repository.savePending({ ...share, status: "pending" });
    await repository.activate(share.shareId, "2027-01-15T10:01:00.000Z");
    const wrongGranteeCode = `0x${randomUUID().replaceAll("-", "").padEnd(64, "b")}`;
    await repository.issueHandoffCode(share.shareId, wrongGranteeCode, "2027-01-15T10:10:00.000Z");
    await expectRejection(
      repository.redeemHandoffCode(wrongGranteeCode, "Organization/attacker", "2027-01-15T10:05:00.000Z"),
      "HANDOFF_GRANTEE_MISMATCH"
    );
    const expiredShare = buildShare();
    await repository.savePending({ ...expiredShare, status: "pending" });
    await repository.activate(expiredShare.shareId, "2027-01-15T10:01:00.000Z");
    const expiredCode = `0x${randomUUID().replaceAll("-", "").padEnd(64, "c")}`;
    await repository.issueHandoffCode(expiredShare.shareId, expiredCode, "2027-01-15T10:02:00.000Z");
    await expectRejection(
      repository.redeemHandoffCode(expiredCode, "Organization/clinic-b", "2027-01-15T10:03:00.000Z"),
      "HANDOFF_CODE_EXPIRED"
    );
    await repository.close();
  });
});

function buildShare() {
  return buildShareGrant({
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
}

async function expectRejection(promise: Promise<unknown>, message: string) {
  try {
    await promise;
    expect.fail(`Expected rejection with ${message}`);
  } catch (error) {
    expect((error as Error).message).to.equal(message);
  }
}
