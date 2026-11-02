import { expect } from "chai";

import {
  assertCertificateIdentity,
  type CertificateIdentity
} from "../src/pki/certificate-identity.js";

const clinicB: CertificateIdentity = {
  fingerprint256: "AA:BB:CC",
  subjectOrganization: "Organization/clinic-b",
  serialNumber: "1234",
  validFrom: "2027-01-01T00:00:00.000Z",
  validTo: "2027-12-31T23:59:59.000Z"
};

describe("Institutional certificate identity", function () {
  it("accepts a current certificate for the registered institution", function () {
    expect(() => assertCertificateIdentity(clinicB, {
      expectedOrganization: "Organization/clinic-b",
      now: () => new Date("2027-06-01T00:00:00.000Z")
    })).not.to.throw();
  });

  it("rejects expired and organization-mismatched certificate identities", function () {
    expect(() => assertCertificateIdentity(clinicB, {
      expectedOrganization: "Organization/clinic-b",
      now: () => new Date("2028-01-01T00:00:00.000Z")
    })).to.throw("CERTIFICATE_EXPIRED");
    expect(() => assertCertificateIdentity(clinicB, {
      expectedOrganization: "Organization/hospital-a",
      now: () => new Date("2027-06-01T00:00:00.000Z")
    })).to.throw("CERTIFICATE_ORGANIZATION_MISMATCH");
  });
});
