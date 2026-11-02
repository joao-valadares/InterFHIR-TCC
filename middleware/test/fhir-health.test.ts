import { expect } from "chai";

import * as fhirHealth from "../src/fhir/fhir-health.js";

const { checkFhirRuntime } = fhirHealth;
const waitForFhirMetadata = (
  fhirHealth as typeof fhirHealth & {
    waitForFhirMetadata(
      options: WaitForFhirMetadataOptions
    ): Promise<{
      ready: boolean;
      checked: string[];
    }>;
  }
).waitForFhirMetadata;

interface WaitForFhirMetadataOptions {
  vaultId: string;
  baseUrl: string;
  timeoutMs: number;
  pollIntervalMs: number;
  fetch: typeof fetch;
  now: () => number;
  sleep: (milliseconds: number) => Promise<void>;
}

describe("FHIR runtime health checker", function () {
  it("checks only the resources required by the selected vault", async function () {
    const urls: string[] = [];

    const result = await checkFhirRuntime({
      baseUrl: "http://127.0.0.1:8082/fhir",
      requiredResources: [
        "Organization/clinic-b",
        "Practitioner/bruno"
      ],
      fetch: async (url) => {
        urls.push(String(url));
        return jsonResponse({ resourceType: String(url).endsWith("/metadata") ? "CapabilityStatement" : "Patient" });
      }
    });

    expect(result.ready).to.equal(true);
    expect(result.checked).to.deep.equal([
      "metadata",
      "Organization/clinic-b",
      "Practitioner/bruno"
    ]);
    expect(urls).to.deep.equal([
      "http://127.0.0.1:8082/fhir/metadata",
      "http://127.0.0.1:8082/fhir/Organization/clinic-b",
      "http://127.0.0.1:8082/fhir/Practitioner/bruno"
    ]);
  });

  it("reports the first failed endpoint without hiding the failing status", async function () {
    const result = await checkFhirRuntime({
      baseUrl: "http://127.0.0.1:8080/fhir/",
      requiredResources: ["Organization/hospital-a", "Observation/obs-ana-1"],
      fetch: async (url) => {
        if (String(url).endsWith("/Observation/obs-ana-1")) {
          return jsonResponse({ resourceType: "OperationOutcome" }, 404);
        }
        return jsonResponse({ resourceType: "Patient" });
      }
    });

    expect(result.ready).to.equal(false);
    expect(result.failed).to.deep.equal({
      endpoint: "Observation/obs-ana-1",
      status: 404
    });
  });

  it("reports network failures as an unavailable endpoint", async function () {
    const result = await checkFhirRuntime({
      baseUrl: "http://127.0.0.1:8080/fhir",
      fetch: async () => {
        throw new TypeError("fetch failed");
      }
    });

    expect(result.ready).to.equal(false);
    expect(result.failed).to.deep.equal({
      endpoint: "metadata",
      status: 0
    });
  });

  it("retries a vault metadata endpoint until HAPI is actually ready", async function () {
    expect(waitForFhirMetadata).to.be.a("function");
    let attempts = 0;
    let elapsed = 0;

    const result = await waitForFhirMetadata({
      vaultId: "vault:hospital-a",
      baseUrl: "http://127.0.0.1:8081/fhir",
      timeoutMs: 1_000,
      pollIntervalMs: 25,
      fetch: async () => {
        attempts += 1;
        return jsonResponse(
          attempts === 1
            ? { resourceType: "OperationOutcome" }
            : { resourceType: "CapabilityStatement" },
          attempts === 1 ? 503 : 200
        );
      },
      now: () => elapsed,
      sleep: async (milliseconds) => {
        elapsed += milliseconds;
      }
    });

    expect(result).to.deep.equal({
      ready: true,
      checked: ["metadata"]
    });
    expect(attempts).to.equal(2);
  });

  it("fails with the vault, endpoint, last status and timeout when HAPI never becomes ready", async function () {
    expect(waitForFhirMetadata).to.be.a("function");
    let elapsed = 0;

    await expectRejection(
      waitForFhirMetadata({
        vaultId: "vault:clinic-b",
        baseUrl: "http://127.0.0.1:8082/fhir",
        timeoutMs: 100,
        pollIntervalMs: 25,
        fetch: async () =>
          jsonResponse({ resourceType: "OperationOutcome" }, 503),
        now: () => elapsed,
        sleep: async (milliseconds) => {
          elapsed += milliseconds;
        }
      }),
      "FHIR_VAULT_NOT_READY: vault:clinic-b endpoint=metadata status=503 timeoutMs=100"
    );
  });
});

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body
  } as Response;
}

async function expectRejection(
  promise: Promise<unknown>,
  message: string
) {
  try {
    await promise;
    expect.fail(`Expected rejection with ${message}`);
  } catch (error) {
    expect(error).to.be.instanceOf(Error);
    expect((error as Error).message).to.equal(message);
  }
}
