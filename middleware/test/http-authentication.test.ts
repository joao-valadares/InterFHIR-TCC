import { expect } from "chai";
import { existsSync, readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";

import {
  createBearerAuthenticationMiddleware,
  createLocalJwtService
} from "../src/auth/authentication.js";
import { createHealthAccessApi } from "../src/api/api-handler.js";
import type { ApiAdminService, ApiFhirClient } from "../src/api/api-handler.js";
import { createHttpServer, createMutualTlsServer } from "../src/api/http-server.js";

describe("Bearer authentication over the local HTTP API", function () {
  it("accepts the Clinic B certificate and rejects a connection without a client certificate", async function (this: { skip(): never }) {
    const root = new URL("../../.local/pki/", import.meta.url);
    const caPath = new URL("ca/ca.crt", root);
    const hospitalKeyPath = new URL("hospital-a/tls.key", root);
    const hospitalCertPath = new URL("hospital-a/tls.crt", root);
    const clinicKeyPath = new URL("clinic-b/tls.key", root);
    const clinicCertPath = new URL("clinic-b/tls.crt", root);
    if (![caPath, hospitalKeyPath, hospitalCertPath, clinicKeyPath, clinicCertPath].every((path) => existsSync(path))) this.skip();
    const identities: unknown[] = [];
    const server = createMutualTlsServer({
      handle: async (request) => {
        if (request.certificateIdentity) identities.push(request.certificateIdentity);
        return { status: 200, body: { ok: true } };
      }
    }, {
      key: readFileSync(hospitalKeyPath),
      cert: readFileSync(hospitalCertPath),
      ca: readFileSync(caPath),
      expectedOrganization: "Organization/clinic-b"
    });
    await listenServer(server);
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("MTLS_TEST_SERVER_ADDRESS_UNAVAILABLE");
      const allowed = await requestTls(address.port, {
        path: "/protected",
        ca: readFileSync(caPath), key: readFileSync(clinicKeyPath), cert: readFileSync(clinicCertPath)
      });
      expect(allowed.statusCode).to.equal(200);
      const healthWithoutClient = await requestTls(address.port, { path: "/health", ca: readFileSync(caPath) });
      expect(healthWithoutClient.statusCode).to.equal(200);
      const protectedWithoutClient = await requestTls(address.port, { path: "/protected", ca: readFileSync(caPath) });
      expect(protectedWithoutClient.statusCode).to.equal(403);
      expect(identities).to.have.length(1);
      expect(identities[0]).to.have.property("subjectOrganization", "Organization/clinic-b");
    } finally {
      await closeServer(server);
    }
  });

  it("accepts a valid token, rejects a missing token and blocks direct FHIR access", async function () {
    const trustedRequestTime = 1_850_000_123;
    const manifestRequests: unknown[] = [];
    const jwt = createLocalJwtService({
      secret: "session-2-http-test-secret-with-32-characters",
      issuer: "interfhir-local-test",
      audience: "interfhir-api-test"
    });
    const token = await jwt.issueToken({
      sub: "local:practitioner-bruno",
      practitionerReference: "Practitioner/bruno",
      role: "practitioner",
      organizationReference: "Organization/clinic-b",
      jti: "session-2-http",
      expiresInSeconds: 300
    });
    const api = createBearerAuthenticationMiddleware(
      createHealthAccessApi(
        {
          fhirClient: fakeFhirClient(),
          accessService: {
            handleRead: async () => {
              throw new Error("LEGACY_READ_FALLBACK_MUST_NOT_BE_USED");
            },
            handleReadByManifest: async (request) => {
              manifestRequests.push(request);
              return { status: 200, body: { ok: true } };
            }
          },
          adminService: fakeAdminService()
        },
        {
          now: () => trustedRequestTime
        } as unknown as Parameters<typeof createHealthAccessApi>[1]
      ),
      jwt
    );
    const server = createHttpServer(api);

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("HTTP_TEST_SERVER_ADDRESS_UNAVAILABLE");
      }
      const baseUrl = `http://127.0.0.1:${address.port}`;
      const maliciousBody = {
        resourceReference: "Observation/obs-1",
        patientReference: "Patient/maria",
        practitionerReference: "Practitioner/attacker",
        organizationReference: "Organization/attacker",
        purposeOfUse: "TREAT",
        requestTime: 1,
        recordedAt: "2027-01-15T10:00:00.000Z"
      };

      const authenticated = await fetch(`${baseUrl}/access/read`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify(maliciousBody)
      });
      const missingToken = await fetch(`${baseUrl}/access/read-manifest`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          manifestId:
            "manifest:vault:hospital-a:Observation/obs-1:v1",
          purposeOfUse: "TREAT",
          recordedAt: "2027-01-15T10:00:00.000Z"
        })
      });
      const authenticatedManifest = await fetch(`${baseUrl}/access/read-manifest`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          manifestId: "manifest:vault:hospital-a:Observation/obs-1:v1",
          purposeOfUse: "TREAT",
          recordedAt: "2027-01-15T10:00:00.000Z"
        })
      });
      const directFhir = await fetch(`${baseUrl}/fhir/Observation/obs-1`);

      expect(authenticated.status).to.equal(410);
      expect(await authenticated.json()).to.deep.equal({
        error: "LEGACY_READ_ROUTE_DISABLED"
      });
      expect(authenticatedManifest.status).to.equal(410);
      expect(missingToken.status).to.equal(410);
      expect(await missingToken.json()).to.deep.equal({
        error: "LEGACY_READ_ROUTE_DISABLED"
      });
      expect(directFhir.status).to.equal(403);
      expect(await directFhir.json()).to.deep.equal({
        error: "FHIR_DIRECT_ACCESS_BLOCKED"
      });
      expect(manifestRequests).to.deep.equal([]);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});

function listenServer(server: ReturnType<typeof createMutualTlsServer>) {
  return new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
}

function closeServer(server: ReturnType<typeof createMutualTlsServer>) {
  return new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function requestTls(port: number, options: { path?: string; ca: Buffer; key?: Buffer; cert?: Buffer }) {
  return new Promise<{ statusCode?: number }>((resolve, reject) => {
    const request = httpsRequest({ hostname: "127.0.0.1", port, path: options.path ?? "/health", method: "GET", rejectUnauthorized: false, ...options }, (response) => {
      response.resume(); response.on("end", () => resolve({ statusCode: response.statusCode }));
    });
    request.once("error", reject); request.end();
  });
}

function fakeFhirClient(): ApiFhirClient {
  return {
    readResource: async () => ({ resourceType: "Observation", id: "obs-1" }),
    createResource: async (resource) => resource,
    createAuditEvent: async () => undefined,
    health: async () => true
  };
}

function fakeAdminService(): ApiAdminService {
  return {
    institutionReference: "Organization/hospital-a",
    health: async () => true
  };
}
