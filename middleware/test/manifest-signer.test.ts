import { expect } from "chai";
import { generateKeyPair } from "jose";

import { createManifestSigner } from "../src/manifest/manifest-signer.js";
import {
  computeManifestCommitment,
  type ResourceManifestVersion
} from "../src/manifest/resource-manifest.js";

describe("ES256 manifest signer", function () {
  it("signs a commitment and verifies the exact signed manifest version", async function () {
    const keys = await generateKeyPair("ES256");
    const signer = createManifestSigner({
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
      signingKeyId: "hospital-a-manifest-key-1"
    });
    const draft = manifestDraft();
    const commitment = computeManifestCommitment(draft);
    const signed = await signer.sign(commitment);
    const manifest = manifestVersion(draft, {
      commitment,
      signingKeyId: signed.signingKeyId,
      signature: signed.signature
    });

    expect(signed.algorithm).to.equal("ES256");
    expect(await signer.verify(manifest)).to.equal(true);
  });

  it("rejects a signature when the commitment or signing key id changes", async function () {
    const keys = await generateKeyPair("ES256");
    const signer = createManifestSigner({
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
      signingKeyId: "hospital-a-manifest-key-1"
    });
    const draft = manifestDraft();
    const commitment = computeManifestCommitment(draft);
    const signed = await signer.sign(commitment);
    const manifest = manifestVersion(draft, {
      commitment,
      signingKeyId: signed.signingKeyId,
      signature: signed.signature
    });

    expect(
      await signer.verify({
        ...manifest,
        commitment: `0x${"b".repeat(64)}`
      })
    ).to.equal(false);
    expect(
      await signer.verify({
        ...manifest,
        signingKeyId: "attacker-key"
      })
    ).to.equal(false);
    expect(
      await signer.verify({
        ...manifest,
        granteeOrganizationReference: "Organization/attacker"
      })
    ).to.equal(false);
  });
});

function manifestDraft(): Omit<ResourceManifestVersion, "commitment" | "signature"> {
  return {
    manifestId: "manifest:share_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:Observation/obs-1",
    shareId: "share_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    version: 1,
    status: "active",
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    resourceReference: "Observation/obs-1",
    resourceType: "Observation",
    fhirVersionId: "1",
    subjectReference: "Patient/maria",
    consentReferenceHash: `0x${"1".repeat(64)}`,
    consentProjectionHash: `0x${"2".repeat(64)}`,
    resourceHash: `0x${"3".repeat(64)}`,
    previousVersionCommitment: `0x${"0".repeat(64)}`,
    signingKeyId: "hospital-a-manifest-key-1",
    createdAt: "2027-01-15T10:00:00.000Z"
  };
}

function manifestVersion(
  draft: Omit<ResourceManifestVersion, "commitment" | "signature">,
  overrides: Pick<ResourceManifestVersion, "commitment" | "signingKeyId" | "signature">
): ResourceManifestVersion {
  return {
    ...draft,
    ...overrides
  };
}
