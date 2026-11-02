import { expect } from "chai";

import { createHapiFhirClient } from "../src/fhir/hapi-fhir-client.js";

describe("HAPI FHIR HTTP client", function () {
  it("reads a FHIR resource by reference through the configured base URL", async function () {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir",
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        return jsonResponse({ resourceType: "Observation", id: "obs-1" });
      }
    });

    const resource = await client.readResource("Observation/obs-1");

    expect(resource).to.deep.equal({ resourceType: "Observation", id: "obs-1" });
    expect(calls[0].url).to.equal("http://localhost:8080/fhir/Observation/obs-1");
    expect(calls[0].init?.method).to.equal("GET");
  });

  it("checks only HAPI metadata for local readiness", async function () {
    const calls: string[] = [];
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir",
      fetch: async (url) => {
        calls.push(String(url));
        return jsonResponse({ resourceType: "CapabilityStatement" });
      }
    });

    expect(await client.health()).to.equal(true);
    expect(calls).to.deep.equal(["http://localhost:8080/fhir/metadata"]);
  });

  it("reads exactly the requested immutable FHIR version through vread", async function () {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir",
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        return jsonResponse({
          resourceType: "Observation",
          id: "obs-1",
          meta: { versionId: "7" }
        });
      }
    });

    const resource = await client.vread("Observation/obs-1", "7");

    expect(resource.meta).to.deep.equal({ versionId: "7" });
    expect(calls[0].url).to.equal(
      "http://localhost:8080/fhir/Observation/obs-1/_history/7"
    );
    expect(calls[0].init?.headers).to.deep.equal({ accept: "application/fhir+json" });
  });

  it("rejects a vread response without the exact requested meta.versionId", async function () {
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir",
      fetch: async () => jsonResponse({ resourceType: "Observation", id: "obs-1" })
    });

    try {
      await client.vread("Observation/obs-1", "7");
      expect.fail("Expected FHIR_VERSION_ID_REQUIRED");
    } catch (error) {
      expect((error as Error).message).to.equal("FHIR_VERSION_ID_REQUIRED");
    }
  });

  it("creates an AuditEvent without requiring clinical payload in the request", async function () {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir/",
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        return jsonResponse({ resourceType: "AuditEvent", id: "audit-1" }, 201);
      }
    });

    await client.createAuditEvent({ resourceType: "AuditEvent", outcome: "0" });

    expect(calls[0].url).to.equal("http://localhost:8080/fhir/AuditEvent");
    expect(calls[0].init?.method).to.equal("POST");
    expect(calls[0].init?.headers).to.deep.equal({ "content-type": "application/fhir+json" });
    expect(calls[0].init?.body).to.equal(JSON.stringify({ resourceType: "AuditEvent", outcome: "0" }));
  });

  it("creates a FHIR resource using the resourceType route", async function () {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir",
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        return jsonResponse({ resourceType: "Observation", id: "created" }, 201);
      }
    });

    const resource = await client.createResource({ resourceType: "Observation", status: "final" });

    expect(resource).to.deep.equal({ resourceType: "Observation", id: "created" });
    expect(calls[0].url).to.equal("http://localhost:8080/fhir/Observation");
    expect(calls[0].init?.method).to.equal("POST");
    expect(calls[0].init?.body).to.equal(JSON.stringify({ resourceType: "Observation", status: "final" }));
  });

  it("upserts a Consent at the exact deterministic reference with PUT", async function () {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir",
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        return jsonResponse({ resourceType: "Consent", id: "consent-deterministic" }, 201);
      }
    });

    const resource = await (client as unknown as {
      upsertResource(reference: string, value: Record<string, unknown>): Promise<Record<string, unknown>>;
    }).upsertResource("Consent/consent-deterministic", { resourceType: "Consent", id: "consent-deterministic" });

    expect(resource).to.deep.equal({ resourceType: "Consent", id: "consent-deterministic" });
    expect(calls[0].url).to.equal("http://localhost:8080/fhir/Consent/consent-deterministic");
    expect(calls[0].init?.method).to.equal("PUT");
  });

  it("throws a stable error when HAPI FHIR rejects the request", async function () {
    const client = createHapiFhirClient({
      baseUrl: "http://localhost:8080/fhir",
      fetch: async () => jsonResponse({ issue: [] }, 404)
    });

    let error: unknown;
    try {
      await client.readResource("Observation/missing");
    } catch (caught) {
      error = caught;
    }

    expect(error).to.be.instanceOf(Error);
    expect((error as Error).message).to.equal("FHIR_HTTP_404");
  });

  it("forwards only the configured service authorization to HAPI", async function () {
    const calls: RequestInit[] = [];
    const client = createHapiFhirClient({
      baseUrl: "http://hospital-a-fhir:8080/fhir",
      authorization: "Bearer internal-service-token",
      fetch: async (_url, init) => {
        calls.push(init ?? {});
        return jsonResponse({
          resourceType: "Observation",
          id: "obs-1"
        });
      }
    });

    await client.readResource("Observation/obs-1");

    expect(calls[0].headers).to.deep.equal({
      accept: "application/fhir+json",
      authorization: "Bearer internal-service-token"
    });
  });
});

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body
  } as Response;
}
