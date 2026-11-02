import { randomUUID } from "node:crypto";

export type ShareStatus = "pending" | "active" | "revoked" | "expired";

export interface ShareGrant {
  shareId: string;
  handoffRedeemedAt?: string;
  custodianOrganizationReference: string;
  granteeOrganizationReference: string;
  patientReference: string;
  consentReference: string;
  allowedResourceTypes: string[];
  allowedOperation: "read";
  allowedPurpose: string;
  validFrom: string;
  validUntil: string;
  status: ShareStatus;
  createdAt: string;
  updatedAt?: string;
}

export function buildShareGrant(
  input: Omit<ShareGrant, "shareId" | "status" | "createdAt" | "updatedAt"> & {
    shareId?: string;
    now?: string;
  }
): ShareGrant {
  assertNonEmpty(input.custodianOrganizationReference, "SHARE_CUSTODIAN_REQUIRED");
  assertNonEmpty(input.granteeOrganizationReference, "SHARE_GRANTEE_REQUIRED");
  if (
    input.custodianOrganizationReference ===
    input.granteeOrganizationReference
  ) {
    throw new Error("SHARE_CUSTODIAN_EQUALS_GRANTEE");
  }
  assertNonEmpty(input.patientReference, "SHARE_PATIENT_REQUIRED");
  assertNonEmpty(input.consentReference, "SHARE_CONSENT_REQUIRED");
  if (input.allowedOperation !== "read") {
    throw new Error("SHARE_OPERATION_READ_REQUIRED");
  }
  assertNonEmpty(input.allowedPurpose, "SHARE_PURPOSE_REQUIRED");
  if (input.allowedResourceTypes.length === 0) {
    throw new Error("SHARE_RESOURCE_TYPES_REQUIRED");
  }
  if (input.allowedResourceTypes.some((resourceType) => resourceType.trim().length === 0)) {
    throw new Error("SHARE_RESOURCE_TYPE_REQUIRED");
  }
  const validFrom = parseTimestamp(input.validFrom, "SHARE_VALIDITY_PERIOD_INVALID");
  const validUntil = parseTimestamp(input.validUntil, "SHARE_VALIDITY_PERIOD_INVALID");
  if (validFrom >= validUntil) {
    throw new Error("SHARE_VALIDITY_PERIOD_INVALID");
  }
  const shareId = input.shareId ?? `share_${randomUUID()}`;
  if (!/^share_[0-9a-f-]{36}$/i.test(shareId)) {
    throw new Error("SHARE_ID_INVALID");
  }
  const createdAt = input.now ?? new Date().toISOString();
  parseTimestamp(createdAt, "SHARE_CREATED_AT_INVALID");

  return {
    shareId,
    custodianOrganizationReference: input.custodianOrganizationReference,
    granteeOrganizationReference: input.granteeOrganizationReference,
    patientReference: input.patientReference,
    consentReference: input.consentReference,
    allowedResourceTypes: [...new Set(input.allowedResourceTypes)],
    allowedOperation: "read",
    allowedPurpose: input.allowedPurpose,
    validFrom: input.validFrom,
    validUntil: input.validUntil,
    status: "active",
    createdAt
  };
}

export function assertShareUsable(
  share: ShareGrant,
  granteeOrganizationReference: string,
  purposeOfUse: string,
  requestTime: string
): void {
  if (share.status !== "active") {
    throw new Error("SHARE_NOT_ACTIVE");
  }
  if (share.granteeOrganizationReference !== granteeOrganizationReference) {
    throw new Error("SHARE_GRANTEE_MISMATCH");
  }
  if (share.allowedPurpose !== purposeOfUse) {
    throw new Error("SHARE_PURPOSE_MISMATCH");
  }
  const requestAt = parseTimestamp(requestTime, "SHARE_REQUEST_TIME_INVALID");
  const validFrom = parseTimestamp(share.validFrom, "SHARE_VALIDITY_PERIOD_INVALID");
  const validUntil = parseTimestamp(share.validUntil, "SHARE_VALIDITY_PERIOD_INVALID");
  if (requestAt < validFrom || requestAt > validUntil) {
    throw new Error("SHARE_OUTSIDE_VALIDITY_PERIOD");
  }
}

function assertNonEmpty(value: string, reason: string) {
  if (value.trim().length === 0) {
    throw new Error(reason);
  }
}

function parseTimestamp(value: string, reason: string) {
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    throw new Error(reason);
  }
  return timestamp;
}
