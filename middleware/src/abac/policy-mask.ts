export const ROLE_PRACTITIONER = 1 << 0;
export const ORG_AUTHORIZED = 1 << 1;
export const LICENSE_ACTIVE = 1 << 2;
export const RESOURCE_OBSERVATION = 1 << 3;
export const ACTION_READ = 1 << 4;
export const PURPOSE_TREATMENT = 1 << 5;
export const CONSENT_ACTIVE = 1 << 6;
export const CONSENT_PERIOD_VALID = 1 << 7;
export const PURPOSE_PAYMENT = 1 << 8;
export const INTEGRITY_VALID = 1 << 9;
export const DATA_SUBJECT_MATCH = 1 << 10;
export const REQUESTER_MATCHES_CONSENT = 1 << 11;

export const REQUIRED_TREATMENT_OBSERVATION_MASK =
  ROLE_PRACTITIONER |
  ORG_AUTHORIZED |
  LICENSE_ACTIVE |
  RESOURCE_OBSERVATION |
  ACTION_READ |
  PURPOSE_TREATMENT |
  CONSENT_ACTIVE |
  CONSENT_PERIOD_VALID |
  INTEGRITY_VALID |
  DATA_SUBJECT_MATCH |
  REQUESTER_MATCHES_CONSENT;

export const REQUIRED_PAYMENT_OBSERVATION_MASK =
  (REQUIRED_TREATMENT_OBSERVATION_MASK & ~PURPOSE_TREATMENT) |
  PURPOSE_PAYMENT;

export const RESOURCE_TYPE_OBSERVATION = 1;
export const RESOURCE_TYPE_DIAGNOSTIC_REPORT = 2;
export const RESOURCE_TYPE_DOCUMENT_REFERENCE = 3;
export const RESOURCE_TYPE_CONDITION = 4;
export const RESOURCE_TYPE_PROCEDURE = 5;
export const RESOURCE_TYPE_MEDICATION_REQUEST = 6;
export const RESOURCE_TYPE_ENCOUNTER = 7;
export const RESOURCE_TYPE_IMMUNIZATION = 8;
export const RESOURCE_TYPE_ALLERGY_INTOLERANCE = 9;
export const ACTION_READ_CODE = 1;
export const PURPOSE_TREATMENT_CODE = 1;
export const PURPOSE_PAYMENT_CODE = 2;
export const SUPPORTED_PURPOSE_CODES = {
  TREAT: PURPOSE_TREATMENT_CODE,
  HPAYMT: PURPOSE_PAYMENT_CODE
} as const;

export const SUPPORTED_RESOURCE_TYPE_CODES: Record<string, number> = {
  Observation: RESOURCE_TYPE_OBSERVATION,
  DiagnosticReport: RESOURCE_TYPE_DIAGNOSTIC_REPORT,
  DocumentReference: RESOURCE_TYPE_DOCUMENT_REFERENCE,
  Condition: RESOURCE_TYPE_CONDITION,
  Procedure: RESOURCE_TYPE_PROCEDURE,
  MedicationRequest: RESOURCE_TYPE_MEDICATION_REQUEST,
  Encounter: RESOURCE_TYPE_ENCOUNTER,
  Immunization: RESOURCE_TYPE_IMMUNIZATION,
  AllergyIntolerance: RESOURCE_TYPE_ALLERGY_INTOLERANCE
};

export function mapResourceTypeCode(code: string) {
  const resourceTypeCode = SUPPORTED_RESOURCE_TYPE_CODES[code];
  if (resourceTypeCode !== undefined) {
    return resourceTypeCode;
  }
  throw new Error("UNSUPPORTED_RESOURCE_TYPE");
}

export function mapActionCode(code: string) {
  if (code.toLowerCase() === "read") {
    return ACTION_READ_CODE;
  }
  throw new Error("UNSUPPORTED_ACTION");
}

export function mapPurposeCode(code: string) {
  const normalizedCode = code.toUpperCase();
  const purposeCode = SUPPORTED_PURPOSE_CODES[normalizedCode as keyof typeof SUPPORTED_PURPOSE_CODES];
  if (purposeCode !== undefined) {
    return purposeCode;
  }
  throw new Error("UNSUPPORTED_PURPOSE");
}

export function mapPolicyMask(resourceTypeCode: number, actionCode: number, purposeCode: number) {
  if (isSupportedTreatmentReadResource(resourceTypeCode) && actionCode === ACTION_READ_CODE) {
    if (purposeCode === PURPOSE_TREATMENT_CODE) {
      return REQUIRED_TREATMENT_OBSERVATION_MASK;
    }
    if (purposeCode === PURPOSE_PAYMENT_CODE) {
      return REQUIRED_PAYMENT_OBSERVATION_MASK;
    }
  }
  throw new Error("UNSUPPORTED_POLICY_SCOPE");
}

function isSupportedTreatmentReadResource(resourceTypeCode: number) {
  return Object.values(SUPPORTED_RESOURCE_TYPE_CODES).includes(resourceTypeCode);
}
