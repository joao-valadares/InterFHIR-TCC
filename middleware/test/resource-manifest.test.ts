import { expect } from "chai";
import { ethers } from "ethers";

import {
  buildFhirManifestVersion,
  computeManifestCommitment,
  type ResourceManifestVersion
} from "../src/manifest/resource-manifest.js";
import { buildShareGrant, type ShareGrant } from "../src/share/share-grant.js";
import type { FhirResource } from "../src/fhir/resource-hasher.js";

describe("Versioned FHIR manifest model", function () {
  it("builds a manifest version from a directed share and FHIR resource", function () {
    const share = buildShare();
    const draft = buildFhirManifestVersion({
      manifestId: "manifest:share-1:v1",
      share,
      resource: observation(),
      consentProjectionHash: ethers.ZeroHash,
      signingKeyId: "hospital-a-key",
      now: "2027-01-15T10:00:00.000Z"
    });

    expect(draft).to.deep.include({
      manifestId: "manifest:share-1:v1",
      shareId: share.shareId,
      resourceReference: "Observation/obs-1",
      resourceType: "Observation",
      fhirVersionId: "7",
      subjectReference: "Patient/maria",
      previousVersionCommitment: ethers.ZeroHash,
      status: "active"
    });
    expect(draft.consentReferenceHash).to.equal(
      ethers.keccak256(ethers.toUtf8Bytes(share.consentReference))
    );
  });

  it("changes the commitment when versioned authorization state changes", function () {
    const draft: Omit<ResourceManifestVersion, "commitment" | "signature"> = {
      ...buildFhirManifestVersion({
        manifestId: "manifest:share-1:v1",
        share: buildShare(),
        resource: observation(),
        consentProjectionHash: ethers.ZeroHash,
        signingKeyId: "hospital-a-key",
        now: "2027-01-15T10:00:00.000Z"
      })
    };

    expect(computeManifestCommitment(draft)).to.match(/^0x[0-9a-f]{64}$/);
    expect(computeManifestCommitment({ ...draft, status: "revoked" })).not.to.equal(
      computeManifestCommitment(draft)
    );
  });

  it("rejects a share whose patient differs from the FHIR resource", function () {
    expect(() => buildFhirManifestVersion({
      manifestId: "manifest:share-1:v1",
      share: { ...buildShare(), patientReference: "Patient/attacker" },
      resource: observation(),
      consentProjectionHash: ethers.ZeroHash,
      signingKeyId: "hospital-a-key"
    })).to.throw("MANIFEST_SHARE_PATIENT_MISMATCH");
  });
});

function observation(): FhirResource {
  return {
    resourceType: "Observation",
    id: "obs-1",
    status: "final",
    subject: { reference: "Patient/maria" },
    meta: { versionId: "7" },
    valueQuantity: { value: 80, unit: "mmHg" }
  };
}

function buildShare(): ShareGrant {
  return buildShareGrant({
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
    now: "2027-01-15T10:00:00.000Z"
  });
}
