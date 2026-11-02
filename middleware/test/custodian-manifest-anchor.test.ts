import { expect } from "chai";
import { ethers } from "ethers";

import { createCustodianManifestAnchor } from "../src/manifest/custodian-manifest-anchor.js";

describe("Custodian manifest anchor", function () {
  it("uses the owner-bound contract when no institutional signer is supplied", async function () {
    const calls: string[] = [];
    const contract = fakeContract(calls);
    const anchor = createCustodianManifestAnchor({ accessControl: contract });

    await anchor.anchorInitial({
      manifestId: "manifest:e2e",
      version: 1,
      commitment: ethers.ZeroHash,
      previousVersionCommitment: ethers.ZeroHash
    } as never);

    expect(calls).to.deep.equal(["anchorManifestVersion", "wait"]);
  });

  it("forwards version transitions and normalizes manifest records", async function () {
    const calls: string[] = [];
    const contract = fakeContract(calls);
    const anchor = createCustodianManifestAnchor({ accessControl: contract });
    const current = manifest("current", 1);
    const superseded = { ...current, status: "superseded" as const };
    const active = manifest("current", 2);

    await anchor.supersedeAndAnchor(current, superseded, active);
    expect(await anchor.getManifestRecord!(current.manifestId, current.version)).to.deep.equal({
      commitment: ethers.ZeroHash,
      status: 1,
      exists: true
    });
    await anchor.revoke!(current, { ...current, status: "revoked" });

    expect(calls).to.deep.equal([
      "supersedeAndAnchorManifestVersion",
      "wait",
      "getManifestRecord",
      "revokeManifestVersion",
      "wait"
    ]);
  });
});

function manifest(manifestId: string, version: number) {
  return {
    manifestId,
    shareId: "share_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    version,
    status: "active" as const,
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    resourceReference: "Observation/obs-1",
    resourceType: "Observation",
    fhirVersionId: "7",
    subjectReference: "Patient/maria",
    consentReferenceHash: ethers.ZeroHash,
    consentProjectionHash: ethers.ZeroHash,
    resourceHash: ethers.ZeroHash,
    previousVersionCommitment: ethers.ZeroHash,
    commitment: ethers.ZeroHash,
    signingKeyId: "hospital-a-key",
    signature: "signature",
    createdAt: "2027-01-15T10:00:00.000Z"
  };
}

function fakeContract(calls: string[]) {
  return {
    anchorManifestVersion: async () => transaction(calls, "anchorManifestVersion"),
    supersedeAndAnchorManifestVersion: async () => transaction(calls, "supersedeAndAnchorManifestVersion"),
    revokeManifestVersion: async () => transaction(calls, "revokeManifestVersion"),
    getManifestRecord: async () => {
      calls.push("getManifestRecord");
      return { commitment: ethers.ZeroHash, status: 1n, exists: true };
    },
    connect: () => {
      throw new Error("INSTITUTIONAL_SIGNER_MUST_NOT_BE_USED");
    }
  };
}

function transaction(calls: string[], name: string) {
  calls.push(name);
  return { hash: ethers.ZeroHash, wait: async () => { calls.push("wait"); } };
}
