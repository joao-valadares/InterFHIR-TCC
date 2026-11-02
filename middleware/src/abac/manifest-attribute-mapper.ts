import { ethers } from "ethers";

import {
  mapActionCode,
  mapPolicyMask,
  mapPurposeCode,
  mapResourceTypeCode
} from "./policy-mask.js";
import type { AccessRequestDto } from "./attribute-mapper.js";
import { assertFhirReference } from "../authorization/authorization-model.js";
import type { ResourceManifestVersion } from "../manifest/resource-manifest.js";

export interface ManifestReadContext {
  practitionerReference: string;
  organizationReference: string;
  purposeOfUse: string;
  requestTime: number;
}

/**
 * Only stable identity references cross the HTTP-to-ABAC boundary. Role,
 * specialty and license attributes are deliberately absent: the blockchain
 * registry derives them from the hashed practitioner identity and gateway.
 */
export interface TrustedManifestIdentity {
  practitionerReference: string;
  organizationReference: string;
}

export function mapManifestToAccessRequest(
  manifest: ResourceManifestVersion,
  context: ManifestReadContext
): AccessRequestDto {
  assertFhirReference(context.practitionerReference, "INVALID_PRACTITIONER_REFERENCE", "Practitioner");
  assertFhirReference(context.organizationReference, "INVALID_ORGANIZATION_REFERENCE", "Organization");
  const resourceTypeCode = mapResourceTypeCode(manifest.resourceType);
  const actionCode = mapActionCode("read");
  const purposeCode = mapPurposeCode(context.purposeOfUse);

  return {
    patientHash: hashReference(manifest.subjectReference),
    actorHash: hashReference(context.practitionerReference),
    organizationHash: hashReference(context.organizationReference),
    resourceIdHash: hashReference(manifest.resourceReference),
    resourceHash: manifest.resourceHash,
    resourceTypeCode,
    actionCode,
    purposeCode,
    attributesMask: mapPolicyMask(
      resourceTypeCode,
      actionCode,
      purposeCode
    ),
    requestTime: context.requestTime
  };
}

/**
 * Produces a local, metadata-only correlation hash for denials that happen
 * before the blockchain can return its canonical request hash. It is not an
 * authorization decision and is never used as a substitute for the on-chain
 * request hash after evaluation.
 */
export function computeAccessRequestCorrelationHash(request: AccessRequestDto): string {
  return ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(request)));
}

function hashReference(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}
