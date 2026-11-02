import { ethers } from "ethers";

import {
  mapActionCode,
  mapPolicyMask,
  mapPurposeCode,
  mapResourceTypeCode
} from "./policy-mask.js";
import { extractFhirResourceMetadata } from "../fhir/resource-metadata.js";
import { hashFhirResource } from "../fhir/resource-hasher.js";
import type { FhirResource } from "../fhir/resource-hasher.js";

export interface AccessRequestDto {
  patientHash: string;
  actorHash: string;
  organizationHash: string;
  resourceIdHash: string;
  resourceHash: string;
  resourceTypeCode: number;
  actionCode: number;
  purposeCode: number;
  attributesMask: number;
  requestTime: number;
}

export interface FhirReadRequestContext {
  resource: FhirResource;
  resourceReference: string;
  patientReference: string;
  practitionerReference: string;
  organizationReference: string;
  action: string;
  purposeOfUse: string;
  requestTime: number;
}

export function mapFhirRequestToAccessRequest(context: FhirReadRequestContext): AccessRequestDto {
  const metadata = extractFhirResourceMetadata(context.resource);
  assertResourceReference(metadata.resourceReference, context.resourceReference);
  assertPatientReference(metadata.patientReference, context.patientReference);

  const resourceTypeCode = mapResourceTypeCode(metadata.resourceType);
  const actionCode = mapActionCode(context.action);
  const purposeCode = mapPurposeCode(context.purposeOfUse);

  return {
    patientHash: hashReference(context.patientReference),
    actorHash: hashReference(context.practitionerReference),
    organizationHash: hashReference(context.organizationReference),
    resourceIdHash: hashReference(context.resourceReference),
    resourceHash: hashFhirResource(context.resource),
    resourceTypeCode,
    actionCode,
    purposeCode,
    attributesMask: mapPolicyMask(resourceTypeCode, actionCode, purposeCode),
    requestTime: context.requestTime
  };
}

function assertResourceReference(actualResourceReference: string, expectedResourceReference: string) {
  if (actualResourceReference !== expectedResourceReference) {
    throw new Error("FHIR_REQUEST_RESOURCE_MISMATCH");
  }
}

function assertPatientReference(actualPatientReference: string, expectedPatientReference: string) {
  if (actualPatientReference !== expectedPatientReference) {
    throw new Error("FHIR_REQUEST_PATIENT_MISMATCH");
  }
}

function hashReference(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}
