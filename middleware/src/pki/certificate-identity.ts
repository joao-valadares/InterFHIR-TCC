import { X509Certificate } from "node:crypto";
import { createHash } from "node:crypto";

export interface CertificateIdentity {
  fingerprint256: string;
  subjectOrganization: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  x5tS256?: string;
}

export function certificateIdentityFromPem(certificatePem: string): CertificateIdentity {
  return certificateIdentityFromX509(new X509Certificate(certificatePem));
}

export function certificateIdentityFromX509(certificate: X509Certificate): CertificateIdentity {
  return {
    fingerprint256: certificate.fingerprint256,
    subjectOrganization: organizationFromSubject(certificate.subject),
    serialNumber: certificate.serialNumber,
    validFrom: new Date(certificate.validFrom).toISOString(),
    validTo: new Date(certificate.validTo).toISOString(),
    x5tS256: createHash("sha256").update(certificate.raw).digest("base64url")
  };
}

export function assertCertificateIdentity(
  identity: CertificateIdentity,
  options: { expectedOrganization: string; now?: () => Date }
): void {
  const now = (options.now ?? (() => new Date()))().getTime();
  if (now < Date.parse(identity.validFrom)) throw new Error("CERTIFICATE_NOT_YET_VALID");
  if (now > Date.parse(identity.validTo)) throw new Error("CERTIFICATE_EXPIRED");
  if (identity.subjectOrganization !== options.expectedOrganization) {
    throw new Error("CERTIFICATE_ORGANIZATION_MISMATCH");
  }
}

function organizationFromSubject(subject: string): string {
  const match = /(?:^|\n)O=([^\n]+)/.exec(subject);
  if (!match?.[1]) throw new Error("CERTIFICATE_ORGANIZATION_MISSING");
  return match[1].trim();
}
