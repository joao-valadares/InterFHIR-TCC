import {
  extractFhirVersionId,
  type FhirResource
} from "./resource-hasher.js";

interface HapiFhirClientOptions {
  baseUrl: string;
  authorization?: string;
  fetch?: typeof fetch;
}

export interface HapiFhirClient {
  readResource(resourceReference: string): Promise<FhirResource>;
  readLatest?(resourceReference: string): Promise<FhirResource>;
  vread?(resourceReference: string, versionId: string): Promise<FhirResource>;
  readConsent?(consentReference: string): Promise<FhirResource>;
  createResource(resource: FhirResource): Promise<FhirResource>;
  upsertResource?(resourceReference: string, resource: FhirResource): Promise<FhirResource>;
  updateResource?(resourceReference: string, resource: FhirResource): Promise<FhirResource>;
  createAuditEvent(event: unknown): Promise<void>;
  health?(): Promise<boolean>;
}

export interface VersionedHapiFhirClient extends HapiFhirClient {
  readLatest(resourceReference: string): Promise<FhirResource>;
  vread(resourceReference: string, versionId: string): Promise<FhirResource>;
  readConsent(consentReference: string): Promise<FhirResource>;
  health(): Promise<boolean>;
}

export function createHapiFhirClient(options: HapiFhirClientOptions): VersionedHapiFhirClient {
  const fetchImpl = options.fetch ?? fetch;
  const baseUrl = options.baseUrl.replace(/\/+$/, "");

  return {
    async readResource(resourceReference: string): Promise<FhirResource> {
      const response = await fetchImpl(`${baseUrl}/${resourceReference}`, {
        method: "GET",
        headers: requestHeaders(
          { accept: "application/fhir+json" },
          options.authorization
        )
      });

      await assertOk(response);
      return (await response.json()) as FhirResource;
    },

    async health(): Promise<boolean> {
      const response = await fetchImpl(`${baseUrl}/metadata`, {
        method: "GET",
        headers: requestHeaders(
          { accept: "application/fhir+json" },
          options.authorization
        )
      });
      return response.ok;
    },

    async readLatest(resourceReference: string): Promise<FhirResource> {
      const response = await fetchImpl(`${baseUrl}/${resourceReference}`, {
        method: "GET",
        headers: requestHeaders(
          { accept: "application/fhir+json" },
          options.authorization
        )
      });

      await assertOk(response);
      return (await response.json()) as FhirResource;
    },

    async vread(
      resourceReference: string,
      versionId: string
    ): Promise<FhirResource> {
      if (!versionId.trim()) {
        throw new Error("FHIR_VERSION_ID_REQUIRED");
      }
      const response = await fetchImpl(
        `${baseUrl}/${resourceReference}/_history/${versionId}`,
        {
          method: "GET",
          headers: requestHeaders(
            { accept: "application/fhir+json" },
            options.authorization
          )
        }
      );

      await assertOk(response);
      const resource = (await response.json()) as FhirResource;
      if (extractFhirVersionId(resource) !== versionId) {
        throw new Error("FHIR_VERSION_ID_MISMATCH");
      }
      return resource;
    },

    async readConsent(consentReference: string): Promise<FhirResource> {
      const response = await fetchImpl(`${baseUrl}/${consentReference}`, {
        method: "GET",
        headers: requestHeaders(
          { accept: "application/fhir+json" },
          options.authorization
        )
      });

      await assertOk(response);
      return (await response.json()) as FhirResource;
    },

    async createResource(resource: FhirResource): Promise<FhirResource> {
      const resourceType = requireResourceType(resource);
      const response = await fetchImpl(`${baseUrl}/${resourceType}`, {
        method: "POST",
        headers: requestHeaders(
          {
            accept: "application/fhir+json",
            "content-type": "application/fhir+json"
          },
          options.authorization
        ),
        body: JSON.stringify(resource)
      });

      await assertOk(response);
      return (await response.json()) as FhirResource;
    },

    async upsertResource(resourceReference: string, resource: FhirResource): Promise<FhirResource> {
      if (!resourceReference.trim()) throw new Error("FHIR_RESOURCE_REFERENCE_REQUIRED");
      const response = await fetchImpl(`${baseUrl}/${resourceReference}`, {
        method: "PUT",
        headers: requestHeaders(
          {
            accept: "application/fhir+json",
            "content-type": "application/fhir+json"
          },
          options.authorization
        ),
        body: JSON.stringify(resource)
      });

      await assertOk(response);
      return (await response.json()) as FhirResource;
    },

    async updateResource(resourceReference: string, resource: FhirResource): Promise<FhirResource> {
      if (!resourceReference.trim()) throw new Error("FHIR_RESOURCE_REFERENCE_REQUIRED");
      const response = await fetchImpl(`${baseUrl}/${resourceReference}`, {
        method: "PUT",
        headers: requestHeaders(
          {
            accept: "application/fhir+json",
            "content-type": "application/fhir+json"
          },
          options.authorization
        ),
        body: JSON.stringify(resource)
      });

      await assertOk(response);
      return (await response.json()) as FhirResource;
    },

    async createAuditEvent(event: unknown): Promise<void> {
      const response = await fetchImpl(`${baseUrl}/AuditEvent`, {
        method: "POST",
        headers: requestHeaders(
          { "content-type": "application/fhir+json" },
          options.authorization
        ),
        body: JSON.stringify(event)
      });

      await assertOk(response);
    }
  };
}

function requestHeaders(
  headers: Record<string, string>,
  authorization: string | undefined
) {
  return authorization ? { ...headers, authorization } : headers;
}

function requireResourceType(resource: FhirResource) {
  if (typeof resource.resourceType !== "string" || resource.resourceType.length === 0) {
    throw new Error("FHIR_RESOURCE_WITHOUT_TYPE");
  }
  return resource.resourceType;
}

async function assertOk(response: Response) {
  if (!response.ok) {
    throw new Error(`FHIR_HTTP_${response.status}`);
  }
}
