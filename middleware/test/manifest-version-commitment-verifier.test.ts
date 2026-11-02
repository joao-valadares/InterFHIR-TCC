import { expect } from "chai";
import { computeManifestCommitment } from "../src/manifest/resource-manifest.js";
import { createManifestVersionCommitmentVerifier } from "../src/blockchain/manifest-version-commitment-verifier.js";

describe("versioned manifest commitment verifier", function () {
  const manifest = { manifestId: "manifest_opaque", shareId: "share_opaque", version: 1, status: "active" as const, custodianOrganizationReference: "Organization/hospital-a", granteeOrganizationReference: "Organization/clinic-b", resourceReference: "Observation/obs", resourceType: "Observation", fhirVersionId: "1", subjectReference: "Patient/ana", consentReferenceHash: "0x01", consentProjectionHash: "0x02", resourceHash: "0x03", previousVersionCommitment: "0x00", signingKeyId: "kid", signature: "sig", createdAt: "2026-01-01T00:00:00.000Z", commitment: "" };
  manifest.commitment = computeManifestCommitment(manifest);
  it("accepts only the active matching on-chain version commitment", async function () {
    const verifier = createManifestVersionCommitmentVerifier({ getManifestRecord: async () => ({ exists: true, status: 1, commitment: manifest.commitment }) });
    expect(await verifier.verify(manifest)).to.equal(true);
    const wrong = createManifestVersionCommitmentVerifier({ getManifestRecord: async () => ({ exists: true, status: 1, commitment: "0xwrong" }) });
    expect(await wrong.verify(manifest)).to.equal(false);
  });
});
