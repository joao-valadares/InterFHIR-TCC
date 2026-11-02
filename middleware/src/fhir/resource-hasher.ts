import { ethers } from "ethers";

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue | undefined };

export interface FhirResource {
  resourceType?: string;
  id?: string;
  [key: string]: JsonValue | undefined;
}

export function canonicalizeFhirResource(resource: FhirResource) {
  assertFhirIdentity(resource);
  return canonicalizeJson(resource);
}

export function canonicalizeJson(value: JsonValue | undefined) {
  return JSON.stringify(sortJson(value));
}

export function hashFhirResource(resource: FhirResource) {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalizeFhirResource(resource)));
}

export function extractFhirVersionId(resource: FhirResource) {
  const versionId =
    resource.meta && typeof resource.meta === "object" && !Array.isArray(resource.meta)
      ? resource.meta.versionId
      : undefined;
  if (typeof versionId !== "string" || versionId.trim().length === 0) {
    throw new Error("FHIR_VERSION_ID_REQUIRED");
  }
  return versionId;
}

function assertFhirIdentity(resource: FhirResource) {
  if (!resource.resourceType) {
    throw new Error("FHIR_RESOURCE_WITHOUT_RESOURCE_TYPE");
  }
  if (!resource.id) {
    throw new Error("FHIR_RESOURCE_WITHOUT_ID");
  }
}

function sortJson(value: JsonValue | undefined): JsonValue | undefined {
  if (Array.isArray(value)) {
    return value.map((item) => sortJson(item) as JsonValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.keys(value)
      .filter((key) => value[key] !== undefined)
      .sort()
      .reduce<Record<string, JsonValue>>((result, key) => {
        result[key] = sortJson(value[key]) as JsonValue;
        return result;
      }, {});
  }
  return value;
}
