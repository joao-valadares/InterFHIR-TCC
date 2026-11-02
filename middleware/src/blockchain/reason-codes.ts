export const REASON_LABELS = {
  1: "PERMIT",
  2: "CONSENT_NOT_FOUND",
  3: "CONSENT_NOT_ACTIVE",
  4: "CONSENT_OUT_OF_PERIOD",
  5: "CONSENT_SCOPE_MISMATCH",
  6: "RESOURCE_HASH_MISMATCH",
  7: "REQUESTER_NOT_AUTHORIZED",
  8: "POLICY_NOT_ACTIVE",
  9: "ATTRIBUTES_NOT_COMPLIANT",
  10: "CONSENT_MASK_NOT_MET",
  11: "DECISION_NOT_FOUND",
  12: "DECISION_NOT_GRANTED",
  13: "DECISION_EXPIRED",
  14: "PATIENT_REVOKED",
  15: "INSTITUTION_NOT_ACTIVE",
  16: "CONSENT_PROJECTION_MISMATCH",
  17: "ENFORCEMENT_DELIVERY_FAILED"
} as const;

export type ReasonCode = keyof typeof REASON_LABELS;

export function reasonCodeToLabel(reasonCode: bigint | number | string): string {
  const numericReasonCode = Number(reasonCode);
  return REASON_LABELS[numericReasonCode as ReasonCode] ?? `UNKNOWN_REASON_${numericReasonCode}`;
}
