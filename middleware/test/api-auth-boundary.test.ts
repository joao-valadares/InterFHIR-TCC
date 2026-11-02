import { expect } from "chai";
import { createHealthAccessApi } from "../src/api/api-handler.js";
import type {
  ApiAdminService,
  ApiFhirClient,
  ApiRequest
} from "../src/api/api-handler.js";

const authenticatedPractitioner = {
  kind: "practitioner" as const,
  sub: "local:practitioner-bruno",
  practitionerReference: "Practitioner/bruno",
  organizationReference: "Organization/clinic-b",
  roleCode: "legacy-local",
  specialtyCode: "legacy-local",
  issuer: "interfhir-local-test",
  audience: ["interfhir-api-test"],
  exp: 1_900_000_000,
  jti: "jwt-session-2"
};

const authenticatedAdministrator = {
  kind: "administrator" as const,
  sub: "local:administrator",
  organizationReference: "Organization/clinic-b",
  issuer: "interfhir-local-test",
  audience: ["interfhir-api-test"],
  exp: 1_900_000_000,
  jti: "jwt-session-2-admin"
};

const trustedRequestTime = 1_850_000_123;

function observation() {
  return {
    resourceType: "Observation",
    id: "obs-1",
    status: "final",
    subject: { reference: "Patient/maria" }
  };
}

function readBody() {
  return {
    resourceReference: "Observation/obs-1",
    patientReference: "Patient/maria",
    practitionerReference: "Practitioner/attacker",
    organizationReference: "Organization/attacker",
    purposeOfUse: "TREAT",
    requestTime: 1_800_000_000,
    recordedAt: "2027-01-15T10:00:00.000Z"
  };
}

describe("Health Access API authentication boundary", function () {
  it("rejects protected reads when no authenticated principal is present", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(),
      adminService: fakeAdminService()
    });

    const directRead = await api.handle({
      method: "POST",
      path: "/access/read",
      body: readBody()
    });
    const manifestRead = await api.handle({
      method: "POST",
      path: "/access/read-manifest",
      body: {
        manifestId: "manifest:vault:hospital-a:Observation/obs-1:v1",
        purposeOfUse: "TREAT",
        requestTime: 1_800_000_000,
        recordedAt: "2027-01-15T10:00:00.000Z"
      }
    });

    expect(directRead).to.deep.equal({
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    });
    expect(manifestRead).to.deep.equal({
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    });
  });

  it("retires the public manifest read route without invoking any read service", async function () {
    const manifestRequests: unknown[] = [];
    const api = createHealthAccessApi(
      {
        fhirClient: fakeFhirClient(),
        accessService: {
          handleRead: async () => {
            throw new Error("LEGACY_READ_FALLBACK_MUST_NOT_BE_USED");
          },
          handleReadByManifest: async (request) => {
            manifestRequests.push(request);
            return { status: 200, body: observation() };
          }
        },
        adminService: fakeAdminService()
      },
      trustedTimeOptions()
    );

    const response = await api.handle(
      withPrincipal({
        method: "POST",
        path: "/access/read-manifest",
        body: {
          manifestId: "manifest:vault:hospital-a:Observation/obs-1:v1",
          practitionerReference: "Practitioner/attacker",
          organizationReference: "Organization/attacker",
          purposeOfUse: "TREAT",
          recordedAt: "2027-01-15T10:00:00.000Z"
        }
      })
    );

    expect(response).to.deep.equal({
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    });
    expect(manifestRequests).to.deep.equal([]);
  });

  it("blocks direct public FHIR reads and writes without invoking the FHIR client", async function () {
    const fhirCalls: string[] = [];
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient({
        readResource: async () => {
          fhirCalls.push("read");
          return observation();
        },
        createResource: async (resource) => {
          fhirCalls.push("create");
          return resource;
        }
      }),
      accessService: fakeAccessService(),
      adminService: fakeAdminService()
    });

    const read = await api.handle({
      method: "GET",
      path: "/fhir/Observation/obs-1"
    });
    const write = await api.handle({
      method: "POST",
      path: "/fhir/Observation",
      body: observation()
    });

    expect(read).to.deep.equal({
      status: 403,
      body: { error: "FHIR_DIRECT_ACCESS_BLOCKED" }
    });
    expect(write).to.deep.equal({
      status: 403,
      body: { error: "FHIR_DIRECT_ACCESS_BLOCKED" }
    });
    expect(fhirCalls).to.deep.equal([]);
  });

  it("retires generic administrative routes regardless of authentication or bootstrap mode", async function () {
    const dependencies = {
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(),
      adminService: fakeAdminService()
    };
    const protectedApi = createHealthAccessApi(dependencies);
    const bootstrapApi = createHealthAccessApi(
      dependencies,
      bootstrapOptions()
    );

    const requests: ApiRequest[] = [
      { method: "POST", path: "/setup/demo/participants" },
      { method: "POST", path: "/setup/demo/policy" },
      { method: "POST", path: "/policies/register", body: { resourceType: "Observation", action: "read", purpose: "TREAT" } },
      { method: "POST", path: "/resources/register-hash", body: { resourceReference: "Observation/obs-1" } },
      { method: "POST", path: "/manifests/publish", body: { vaultId: "vault:hospital-a", custodianOrganizationReference: "Organization/hospital-a", resourceReference: "Observation/obs-1" } },
      { method: "GET", path: "/manifests/manifest:vault:hospital-a:Observation/obs-1:v1" },
      { method: "POST", path: "/manifests/revoke", body: { manifestId: "manifest:vault:hospital-a:Observation/obs-1:v1" } },
      { method: "POST", path: "/consents/register", body: { consentReference: "Consent/cons-1" } },
      { method: "POST", path: "/consents/revoke", body: { consentReference: "Consent/cons-1" } }
    ];

    for (const request of requests) {
      expect(await protectedApi.handle(request)).to.deep.equal({
        status: 410,
        body: { error: "LEGACY_ADMIN_ROUTE_DISABLED" }
      });
      expect(await bootstrapApi.handle(withPrincipal(request, authenticatedAdministrator))).to.deep.equal({
        status: 410,
        body: { error: "LEGACY_ADMIN_ROUTE_DISABLED" }
      });
    }
  });

  it("forbids a non-practitioner role from using protected read routes", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(),
      adminService: fakeAdminService()
    });

    const response = await api.handle(
      withPrincipal(
        {
          method: "POST",
          path: "/access/read-manifest",
          body: {
            manifestId:
              "manifest:vault:hospital-a:Observation/obs-1:v1",
            purposeOfUse: "TREAT",
            recordedAt: "2027-01-15T10:00:00.000Z"
          }
        },
        authenticatedAdministrator
      )
    );

    expect(response).to.deep.equal({
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    });
  });

});

function withPrincipal(
  request: ApiRequest,
  principal: typeof authenticatedPractitioner | typeof authenticatedAdministrator =
    authenticatedPractitioner
) {
  return {
    ...request,
    principal
  } as ApiRequest;
}

function trustedTimeOptions() {
  return {
    now: () => trustedRequestTime
  } as unknown as Parameters<typeof createHealthAccessApi>[1];
}

function bootstrapOptions() {
  return {
    bootstrapEnabled: true,
    now: () => trustedRequestTime
  } as unknown as Parameters<typeof createHealthAccessApi>[1];
}

function fakeFhirClient(overrides: Partial<ApiFhirClient> = {}): ApiFhirClient {
  return {
    readResource: async () => observation(),
    createResource: async (resource) => resource,
    createAuditEvent: async () => undefined,
    health: async () => true,
    ...overrides
  };
}

function fakeAccessService() {
  return {
    handleRead: async () => ({ status: 200, body: observation() }),
    handleReadByManifest: async () => ({ status: 200, body: observation() })
  };
}

function fakeAdminService(): ApiAdminService {
  return {
    institutionReference: "Organization/clinic-b",
    health: async () => true
  };
}
