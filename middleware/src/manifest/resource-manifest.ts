import { ethers } from "ethers";

import {
  extractFhirVersionId,
  hashFhirResource,
  type FhirResource
} from "../fhir/resource-hasher.js";
import {
  extractFhirResourceMetadata,
  isSupportedClinicalResourceType,
  type SupportedClinicalResourceType
} from "../fhir/resource-metadata.js";
import type { ShareGrant } from "../share/share-grant.js";

export type ManifestStatus = "pending" | "active" | "superseded" | "revoked";

export interface ResourceManifestVersion {
  manifestId: string;
  shareId: string;
  version: number;
  status: ManifestStatus;
  custodianOrganizationReference: string;
  granteeOrganizationReference: string;
  resourceReference: string;
  resourceType: string;
  fhirVersionId: string;
  subjectReference: string;
  consentReferenceHash: string;
  consentProjectionHash: string;
  resourceHash: string;
  previousVersionCommitment: string;
  commitment: string;
  signingKeyId: string;
  signature: string;
  createdAt: string;
  updatedAt?: string;
}

export interface BuildFhirManifestVersionInput {
  manifestId: string;
  share: ShareGrant;
  resource: FhirResource;
  consentProjectionHash: string;
  signingKeyId: string;
  version?: number;
  status?: ManifestStatus;
  previousVersionCommitment?: string;
  now?: string;
}

export interface ResourceManifestMetadata {
  resourceReference: string;
  resourceType: SupportedClinicalResourceType;
  subjectReference: string;
}

export function buildFhirManifestVersion(input: BuildFhirManifestVersionInput): Omit<ResourceManifestVersion, "commitment" | "signature"> {
  const metadata = extractResourceManifestMetadata(input.resource);
  if (metadata.subjectReference !== input.share.patientReference) {
    throw new Error("MANIFEST_SHARE_PATIENT_MISMATCH");
  }
  if (!input.share.allowedResourceTypes.includes(metadata.resourceType)) {
    throw new Error("MANIFEST_SHARE_RESOURCE_TYPE_MISMATCH");
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(input.consentProjectionHash)) {
    throw new Error("CONSENT_PROJECTION_HASH_INVALID");
  }
  const signingKeyId = requireString(input.signingKeyId, "MANIFEST_SIGNING_KEY_ID_REQUIRED");
  const createdAt = input.now ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(createdAt))) {
    throw new Error("MANIFEST_CREATED_AT_INVALID");
  }

  return {
    manifestId: requireString(input.manifestId, "MANIFEST_ID_REQUIRED"),
    shareId: input.share.shareId,
    version: input.version ?? 1,
    status: input.status ?? "active",
    custodianOrganizationReference: input.share.custodianOrganizationReference,
    granteeOrganizationReference: input.share.granteeOrganizationReference,
    resourceReference: metadata.resourceReference,
    resourceType: metadata.resourceType,
    fhirVersionId: extractFhirVersionId(input.resource),
    subjectReference: metadata.subjectReference,
    consentReferenceHash: hashText(input.share.consentReference),
    consentProjectionHash: input.consentProjectionHash,
    resourceHash: hashFhirResource(input.resource),
    previousVersionCommitment: input.previousVersionCommitment ?? ethers.ZeroHash,
    signingKeyId,
    createdAt
  };
}

export function extractResourceManifestMetadata(resource: FhirResource): ResourceManifestMetadata {
  const fields = extractResourceManifestFields(resource);
  return {
    resourceReference: fields.resourceReference,
    resourceType: fields.resourceType,
    subjectReference: fields.subjectReference
  };
}

export function computeManifestCommitment(
  manifest: ResourceManifestVersion | Omit<ResourceManifestVersion, "commitment" | "signature">
): string {
  const canonical = {
    manifestId: manifest.manifestId,
    shareId: manifest.shareId,
    version: manifest.version,
    status: manifest.status,
    custodianOrganizationReference: manifest.custodianOrganizationReference,
    granteeOrganizationReference: manifest.granteeOrganizationReference,
    resourceReference: manifest.resourceReference,
    resourceType: manifest.resourceType,
    fhirVersionId: manifest.fhirVersionId,
    subjectReference: manifest.subjectReference,
    consentReferenceHash: manifest.consentReferenceHash,
    consentProjectionHash: manifest.consentProjectionHash,
    resourceHash: manifest.resourceHash,
    previousVersionCommitment: manifest.previousVersionCommitment,
    signingKeyId: manifest.signingKeyId,
    createdAt: manifest.createdAt,
    updatedAt: manifest.updatedAt ?? null
  };
  return hashText(JSON.stringify(canonical));
}

function extractResourceManifestFields(resource: FhirResource): ResourceManifestMetadata {
  if (resource.resourceType === "Bundle") {
    return extractBundlePackageFields(resource);
  }
  const metadata = extractFhirResourceMetadata(resource);
  return {
    resourceReference: metadata.resourceReference,
    resourceType: metadata.resourceType,
    subjectReference: metadata.patientReference
  };
}

function extractBundlePackageFields(bundle: FhirResource): ResourceManifestMetadata {
  const clinicalResources = extractContainedClinicalResources(bundle);
  if (clinicalResources.length === 0) {
    throw new Error("FHIR_BUNDLE_WITHOUT_SUPPORTED_CLINICAL_RESOURCE");
  }
  const first = clinicalResources[0];
  const metadata = extractFhirResourceMetadata(first);
  return {
    resourceReference: requireResourceReference(bundle),
    resourceType: metadata.resourceType,
    subjectReference: metadata.patientReference
  };
}

function extractContainedClinicalResources(bundle: FhirResource): FhirResource[] {
  return readBundleEntries(bundle)
    .map((entry) => (isRecord(entry) ? entry.resource : undefined))
    .filter((resource): resource is FhirResource =>
      isRecord(resource) &&
      typeof resource.resourceType === "string" &&
      isSupportedClinicalResourceType(resource.resourceType)
    );
}

function readBundleEntries(bundle: FhirResource): unknown[] {
  const entries = bundle.entry;
  return Array.isArray(entries) ? entries : [];
}

function requireResourceReference(resource: FhirResource): string {
  if (typeof resource.resourceType !== "string" || typeof resource.id !== "string" || resource.id.length === 0) {
    throw new Error("FHIR_RESOURCE_WITHOUT_ID");
  }
  return `${resource.resourceType}/${resource.id}`;
}

function hashText(value: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function requireString(value: unknown, errorCode: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(errorCode);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
