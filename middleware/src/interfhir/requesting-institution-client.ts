import type { UdapClientTlsOptions } from "../udap/udap-client.js";

export type RequestingInstitutionTlsOptions = UdapClientTlsOptions;

export interface RequestingInstitutionFetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type RequestingInstitutionFetch = (
  url: string,
  init: {
    method: "POST";
    headers: Record<string, string>;
    body: string;
    tls: RequestingInstitutionTlsOptions;
  }
) => Promise<RequestingInstitutionFetchResponse>;

export interface RedeemHandoffResponse {
  shareId: string;
  manifests: Array<{ manifestId: string; resourceType: string }>;
  validUntil: string;
}

export interface ReadShareResponse {
  manifest: {
    manifestId: string;
    shareId: string;
    resourceReference: string;
    fhirVersionId: string;
    custodianOrganizationReference: string;
  };
  resource: {
    resourceType: string;
    id: string;
    meta: { versionId: string; [key: string]: unknown };
    [key: string]: unknown;
  };
}

export function createRequestingInstitutionClient(options: {
  custodianBaseUrl: string;
  tls: RequestingInstitutionTlsOptions;
  fetch: RequestingInstitutionFetch;
}) {
  const baseUrl = options.custodianBaseUrl.replace(/\/+$/, "");
  if (!baseUrl.startsWith("https://")) throw new Error("REQUESTING_INSTITUTION_HTTPS_REQUIRED");

  return {
    async redeemHandoff(input: { handoffCode: string; udapToken: string }): Promise<RedeemHandoffResponse> {
      const body = await postJson(options.fetch, `${baseUrl}/interfhir/v1/shares/redeem`, input.udapToken, options.tls, {
        handoffCode: input.handoffCode
      });
      return requireRedeemResponse(body);
    },

    async readShare(input: {
      shareId: string;
      manifestId: string;
      resourceType: string;
      purposeOfUse: string;
      requestId: string;
      udapToken: string;
    }): Promise<ReadShareResponse> {
      const body = await postJson(options.fetch, `${baseUrl}/interfhir/v1/access/read`, input.udapToken, options.tls, {
        shareId: input.shareId,
        manifestId: input.manifestId,
        operation: "read",
        purposeOfUse: input.purposeOfUse,
        requestId: input.requestId
      });
      return requireReadResponse(body, {
        shareId: input.shareId,
        manifestId: input.manifestId,
        resourceType: input.resourceType
      });
    }
  };
}

async function postJson(
  request: RequestingInstitutionFetch,
  url: string,
  udapToken: string,
  tls: RequestingInstitutionTlsOptions,
  body: Record<string, string>
): Promise<unknown> {
  const response = await request(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${udapToken}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(body),
    tls
  });
  const responseBody = await response.json();
  if (!response.ok) {
    if (containsClinicalPayload(responseBody)) {
      throw new Error("REQUESTING_INSTITUTION_DENIAL_CONTAINS_CLINICAL_PAYLOAD");
    }
    throw new Error(`REQUESTING_INSTITUTION_HTTP_${response.status}:${responseError(responseBody)}`);
  }
  return responseBody;
}

function requireRedeemResponse(value: unknown): RedeemHandoffResponse {
  if (!isRecord(value) || !nonEmpty(value.shareId) || !Array.isArray(value.manifests) || value.manifests.length === 0 || !nonEmpty(value.validUntil)) {
    throw new Error("REQUESTING_INSTITUTION_REDEEM_RESPONSE_INVALID");
  }
  const manifests = value.manifests.map((manifest) => {
    if (!isRecord(manifest) || !nonEmpty(manifest.manifestId) || !nonEmpty(manifest.resourceType)) {
      throw new Error("REQUESTING_INSTITUTION_REDEEM_RESPONSE_INVALID");
    }
    return { manifestId: manifest.manifestId, resourceType: manifest.resourceType };
  });
  return { shareId: value.shareId, manifests, validUntil: value.validUntil };
}

function requireReadResponse(
  value: unknown,
  expected: { shareId: string; manifestId: string; resourceType: string }
): ReadShareResponse {
  if (!isRecord(value) || !isRecord(value.manifest) || !isRecord(value.resource)) {
    throw new Error("REQUESTING_INSTITUTION_READ_RESPONSE_INVALID");
  }
  const manifest = value.manifest;
  const resource = value.resource;
  const manifestId = requiredReadString(manifest, "manifestId");
  const shareId = requiredReadString(manifest, "shareId");
  const resourceReference = requiredReadString(manifest, "resourceReference");
  const fhirVersionId = requiredReadString(manifest, "fhirVersionId");
  const custodianOrganizationReference = requiredReadString(manifest, "custodianOrganizationReference");
  const resourceType = requiredReadString(resource, "resourceType");
  const resourceId = requiredReadString(resource, "id");
  if (!isRecord(resource.meta)) {
    throw new Error("REQUESTING_INSTITUTION_READ_RESPONSE_INVALID");
  }
  const resourceVersionId = requiredReadString(resource.meta, "versionId");
  if (
    manifestId !== expected.manifestId ||
    shareId !== expected.shareId ||
    resourceType !== expected.resourceType ||
    resourceReference !== `${resourceType}/${resourceId}` ||
    fhirVersionId !== resourceVersionId
  ) {
    throw new Error("REQUESTING_INSTITUTION_READ_RESPONSE_INVALID");
  }
  return {
    manifest: {
      manifestId,
      shareId,
      resourceReference,
      fhirVersionId,
      custodianOrganizationReference
    },
    resource: resource as ReadShareResponse["resource"]
  };
}

function responseError(value: unknown): string {
  if (isRecord(value) && typeof value.error === "string" && value.error.length > 0) return value.error;
  return "REMOTE_ERROR";
}

function containsClinicalPayload(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsClinicalPayload);
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, child]) =>
    ["resource", "payload", "content", "pointer", "fhirLocator", "fhirBaseUrl", "patientReference", "resourceReference", "consentReference"].includes(key) || containsClinicalPayload(child)
  );
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function requiredReadString(value: Record<string, unknown>, field: string): string {
  if (!nonEmpty(value[field])) throw new Error("REQUESTING_INSTITUTION_READ_RESPONSE_INVALID");
  return value[field];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
