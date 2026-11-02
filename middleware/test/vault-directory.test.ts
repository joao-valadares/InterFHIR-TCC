import { expect } from "chai";

import {
  createVaultDirectory,
  type VaultDescriptor
} from "../src/vault/vault-directory.js";
import { createVaultClientFactory } from "../src/vault/vault-client-factory.js";

const hospitalA: VaultDescriptor = {
  id: "hospital-a",
  vaultId: "vault:hospital-a",
  custodianOrganizationReference: "Organization/hospital-a",
  fhirBaseUrl: "http://hospital-a-fhir:8080/fhir",
  serviceCredentials: {
    bearerToken: "hospital-a-service-token"
  },
  seedBundlePath: "fixtures/fhir/hospital-a-bundle.json",
  requiredResources: ["Observation/obs-ana-1"]
};

describe("Vault directory and client factory", function () {
  it("resolves a trusted vault only when vault id and custodian agree", function () {
    const directory = createVaultDirectory([hospitalA]);

    expect(
      directory.require(
        "vault:hospital-a",
        "Organization/hospital-a"
      )
    ).to.equal(hospitalA);
  });

  it("rejects an unknown vault before any client can be selected", function () {
    const directory = createVaultDirectory([hospitalA]);

    expect(() =>
      directory.require(
        "vault:unknown",
        "Organization/hospital-a"
      )
    ).to.throw("UNKNOWN_VAULT: vault:unknown");
  });

  it("rejects a manifest custodian that diverges from the trusted descriptor", function () {
    const directory = createVaultDirectory([hospitalA]);

    expect(() =>
      directory.require(
        "vault:hospital-a",
        "Organization/clinic-b"
      )
    ).to.throw("VAULT_CUSTODIAN_MISMATCH");
  });

  it("builds the HAPI client from the trusted internal URL and service credentials", async function () {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const factory = createVaultClientFactory({
      directory: createVaultDirectory([hospitalA]),
      fetch: async (url, init) => {
        calls.push({ url: String(url), init });
        return jsonResponse({
          resourceType: "Observation",
          id: "obs-ana-1"
        });
      }
    });

    const context = factory.forVault(
      "vault:hospital-a",
      "Organization/hospital-a"
    );
    await context.client.readResource("Observation/obs-ana-1");

    expect(context.descriptor).to.equal(hospitalA);
    expect(calls).to.have.length(1);
    expect(calls[0].url).to.equal(
      "http://hospital-a-fhir:8080/fhir/Observation/obs-ana-1"
    );
    expect(calls[0].init?.headers).to.deep.equal({
      accept: "application/fhir+json",
      authorization: "Bearer hospital-a-service-token"
    });
  });
});

function jsonResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body
  } as Response;
}
