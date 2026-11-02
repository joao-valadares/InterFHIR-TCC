import { expect } from "chai";

import {
  assertShareUsable,
  buildShareGrant
} from "../src/share/share-grant.js";

const now = "2027-01-15T10:00:00.000Z";

describe("directed ShareGrant", function () {
  it("creates an opaque active share owned by a distinct custodian and grantee", function () {
    const share = buildShareGrant(baseInput());

    expect(share).to.include({
      custodianOrganizationReference: "Organization/hospital-a",
      granteeOrganizationReference: "Organization/clinic-b",
      patientReference: "Patient/maria",
      consentReference: "Consent/cons-1",
      allowedOperation: "read",
      allowedPurpose: "TREAT",
      status: "active",
      createdAt: now
    });
    expect(share.shareId).to.match(/^share_[0-9a-f-]{36}$/);
    expect(share.shareId).not.to.contain("maria");
    expect(share.allowedResourceTypes).to.deep.equal(["Observation"]);
  });

  it("rejects a share whose custodian and grantee are the same institution", function () {
    expect(() =>
      buildShareGrant({
        ...baseInput(),
        granteeOrganizationReference: "Organization/hospital-a"
      })
    ).to.throw("SHARE_CUSTODIAN_EQUALS_GRANTEE");
  });

  it("requires a read operation and a purpose", function () {
    expect(() =>
      buildShareGrant({ ...baseInput(), allowedPurpose: "" })
    ).to.throw("SHARE_PURPOSE_REQUIRED");

    expect(() =>
      buildShareGrant({
        ...baseInput(),
        allowedOperation: "write" as "read"
      })
    ).to.throw("SHARE_OPERATION_READ_REQUIRED");
  });

  it("rejects an invalid validity period", function () {
    expect(() =>
      buildShareGrant({
        ...baseInput(),
        validFrom: "2027-01-16T10:00:00.000Z",
        validUntil: "2027-01-15T10:00:00.000Z"
      })
    ).to.throw("SHARE_VALIDITY_PERIOD_INVALID");
  });

  it("allows only an active share for its exact grantee, purpose and period", function () {
    const share = buildShareGrant(baseInput());

    expect(() =>
      assertShareUsable(
        share,
        "Organization/clinic-b",
        "TREAT",
        "2027-01-15T12:00:00.000Z"
      )
    ).not.to.throw();
  });

  it("rejects a divergent requester organization without accepting requester-supplied patient data", function () {
    const share = buildShareGrant(baseInput());

    expect(() =>
      assertShareUsable(
        share,
        "Organization/attacker",
        "TREAT",
        "2027-01-15T12:00:00.000Z"
      )
    ).to.throw("SHARE_GRANTEE_MISMATCH");
    expect(share.patientReference).to.equal("Patient/maria");
  });

  it("rejects inactive, expired and purpose-divergent shares before resource lookup", function () {
    const share = buildShareGrant(baseInput());

    for (const status of ["pending", "revoked", "expired"] as const) {
      expect(() =>
        assertShareUsable(
          { ...share, status },
          "Organization/clinic-b",
          "TREAT",
          "2027-01-15T12:00:00.000Z"
        )
      ).to.throw("SHARE_NOT_ACTIVE");
    }

    expect(() =>
      assertShareUsable(
        share,
        "Organization/clinic-b",
        "HPAYMT",
        "2027-01-15T12:00:00.000Z"
      )
    ).to.throw("SHARE_PURPOSE_MISMATCH");

    expect(() =>
      assertShareUsable(
        share,
        "Organization/clinic-b",
        "TREAT",
        "2027-02-01T12:00:00.000Z"
      )
    ).to.throw("SHARE_OUTSIDE_VALIDITY_PERIOD");
  });
});

function baseInput() {
  return {
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    patientReference: "Patient/maria",
    consentReference: "Consent/cons-1",
    allowedResourceTypes: ["Observation"],
    allowedOperation: "read" as const,
    allowedPurpose: "TREAT",
    validFrom: "2027-01-15T09:00:00.000Z",
    validUntil: "2027-01-15T18:00:00.000Z",
    now
  };
}
