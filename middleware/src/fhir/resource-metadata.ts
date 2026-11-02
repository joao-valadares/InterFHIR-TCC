import type { FhirResource } from "./resource-hasher.js";

export const SUPPORTED_CLINICAL_RESOURCE_TYPES = [
  "Observation",
  "DiagnosticReport",
  "DocumentReference",
  "Condition",
  "Procedure",
  "MedicationRequest",
  "Encounter",
  "Immunization",
  "AllergyIntolerance"
] as const;

export type SupportedClinicalResourceType = (typeof SUPPORTED_CLINICAL_RESOURCE_TYPES)[number];

export interface FhirResourceMetadata {
  resourceReference: string;
  resourceType: SupportedClinicalResourceType;
  patientReference: string;
}

const PATIENT_REFERENCE_PATHS: Record<SupportedClinicalResourceType, string[]> = {
  Observation: ["subject.reference"],
  DiagnosticReport: ["subject.reference"],
  DocumentReference: ["subject.reference"],
  Condition: ["subject.reference"],
  Procedure: ["subject.reference"],
  MedicationRequest: ["subject.reference"],
  Encounter: ["subject.reference"],
  Immunization: ["patient.reference"],
  AllergyIntolerance: ["patient.reference"]
};

export function extractFhirResourceMetadata(resource: FhirResource): FhirResourceMetadata {
  const resourceType = requireSupportedResourceType(resource.resourceType);
  const id = requireString(resource.id, "FHIR_RESOURCE_WITHOUT_ID");
  const patientReference = extractFirstStringAtPath(resource, PATIENT_REFERENCE_PATHS[resourceType]);

  if (!patientReference) {
    throw new Error("FHIR_RESOURCE_WITHOUT_PATIENT_REFERENCE");
  }

  return {
    resourceReference: `${resourceType}/${id}`,
    resourceType,
    patientReference
  };
}

export function requireSupportedResourceType(resourceType: unknown): SupportedClinicalResourceType {
  if (typeof resourceType !== "string") {
    throw new Error("FHIR_RESOURCE_WITHOUT_RESOURCE_TYPE");
  }
  if (!isSupportedClinicalResourceType(resourceType)) {
    throw new Error("UNSUPPORTED_RESOURCE_TYPE");
  }
  return resourceType;
}

export function isSupportedClinicalResourceType(resourceType: string): resourceType is SupportedClinicalResourceType {
  return SUPPORTED_CLINICAL_RESOURCE_TYPES.includes(resourceType as SupportedClinicalResourceType);
}

function extractFirstStringAtPath(resource: FhirResource, paths: string[]) {
  for (const path of paths) {
    const value = readPath(resource, path);
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function readPath(value: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((current, key) => {
    if (typeof current !== "object" || current === null || Array.isArray(current)) {
      return undefined;
    }
    return (current as Record<string, unknown>)[key];
  }, value);
}

function requireString(value: unknown, errorCode: string) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(errorCode);
  }
  return value;
}
