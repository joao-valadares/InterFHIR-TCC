import { expect } from "chai";

import {
  buildRuntimeTargets,
  checkRuntimeDependency,
  waitForRuntimeDependencies
} from "../../scripts/wait-for-services.js";

describe("institutional runtime diagnostics", function () {
  it("builds host/container-aware targets for both gateways and dependencies", function () {
    const targets = buildRuntimeTargets({
      FHIR_HOSPITAL_A_BASE_URL: "http://hospital-a-fhir:8080/fhir",
      FHIR_CLINIC_B_BASE_URL: "http://clinic-b-fhir:8080/fhir",
      HOSPITAL_A_METADATA_DATABASE_URL:
        "postgresql://hospital_a_metadata:hospital_a_metadata@hospital-a-metadata-postgres:5432/interfhir_hospital_a_metadata",
      CLINIC_B_METADATA_DATABASE_URL:
        "postgresql://clinic_b_metadata:clinic_b_metadata@clinic-b-metadata-postgres:5432/interfhir_clinic_b_metadata",
      BLOCKCHAIN_RPC_URL: "http://besu-hospital-a-validator:8545",
      HEALTH_ACCESS_PUBLIC_HOSPITAL_A_URL: "http://hospital-a-gateway:3000",
      HEALTH_ACCESS_PUBLIC_CLINIC_B_URL: "http://clinic-b-gateway:3000",
      OIDC_HOSPITAL_A_JWKS_URI: "http://keycloak:8080/realms/hospital-a/certs",
      OIDC_CLINIC_B_JWKS_URI: "http://keycloak:8080/realms/clinic-b/certs",
      UDAP_DISCOVERY_URL: "http://hospital-a-gateway:3000/fhir/.well-known/udap"
    });

    expect(targets.map((target) => [target.service, target.endpoint])).to.deep.equal([
      ["institutional-identity-network", "interfhir-institutional-identity"],
      ["institutional-blockchain-network", "interfhir-institutional-blockchain"],
      ["hospital-a-fhir", "http://hospital-a-fhir:8080/fhir/metadata"],
      ["clinic-b-fhir", "http://clinic-b-fhir:8080/fhir/metadata"],
      ["hospital-a-metadata-postgres", "hospital-a-metadata-postgres:5432"],
      ["clinic-b-metadata-postgres", "clinic-b-metadata-postgres:5432"],
      ["besu-hospital-a-validator", "http://besu-hospital-a-validator:8545"],
      ["hospital-a-jwks", "http://keycloak:8080/realms/hospital-a/certs"],
      ["clinic-b-jwks", "http://keycloak:8080/realms/clinic-b/certs"],
      ["hospital-a-udap", "http://hospital-a-gateway:3000/fhir/.well-known/udap"],
      ["hospital-a-gateway", "http://hospital-a-gateway:3000/health"],
      ["clinic-b-gateway", "http://clinic-b-gateway:3000/health"]
    ]);
  });

  it("omits optional UDAP discovery when UDAP is explicitly disabled", function () {
    const targets = buildRuntimeTargets({
      UDAP_ENABLED: "false",
      UDAP_DISCOVERY_URL: "http://hospital-a-gateway:3000/fhir/.well-known/udap"
    });

    expect(targets.some((target) => target.service.endsWith("-udap"))).to.equal(false);
  });

  it("treats Clinic B UDAP as a requester check against the remote Hospital A issuer", function () {
    const targets = buildRuntimeTargets({
      RUNTIME_HOSPITAL_A_GATEWAY_URL: "https://hospital-a-gateway:3000",
      RUNTIME_CLINIC_B_GATEWAY_URL: "https://clinic-b-gateway:3000",
      RUNTIME_HOSPITAL_A_TLS_CA_PATH: "/run/interfhir/pki/ca/ca.crt",
      RUNTIME_HOSPITAL_A_TLS_CERT_PATH: "/run/interfhir/pki/hospital-a/client.crt",
      RUNTIME_HOSPITAL_A_TLS_KEY_PATH: "/run/interfhir/pki/hospital-a/client.key",
      UDAP_ENABLED: "false",
      UDAP_CLINIC_B_ENABLED: "true",
      UDAP_CLINIC_B_DISCOVERY_URL: "https://hospital-a-gateway:3000/fhir/.well-known/udap"
    });

    const target = targets.find((candidate) => candidate.service === "clinic-b-udap-requester");
    expect(target).to.deep.include({
      service: "clinic-b-udap-requester",
      endpoint: "https://hospital-a-gateway:3000/fhir/.well-known/udap"
    });
    expect(target?.tls).to.deep.equal({
      caPath: "/run/interfhir/pki/ca/ca.crt",
      certPath: "/run/interfhir/pki/hospital-a/client.crt",
      keyPath: "/run/interfhir/pki/hospital-a/client.key"
    });
    expect(targets.some((candidate) => candidate.service === "clinic-b-udap")).to.equal(false);
  });

  it("includes configured CA and client material for HTTPS gateway diagnostics", function () {
    const targets = buildRuntimeTargets({
      RUNTIME_HOSPITAL_A_GATEWAY_URL: "https://hospital-a-gateway:3000",
      RUNTIME_HOSPITAL_A_TLS_CA_PATH: "/run/interfhir/pki/ca/ca.crt",
      RUNTIME_HOSPITAL_A_TLS_CERT_PATH: "/run/interfhir/pki/hospital-a/client.crt",
      RUNTIME_HOSPITAL_A_TLS_KEY_PATH: "/run/interfhir/pki/hospital-a/client.key",
      UDAP_ENABLED: "false"
    });

    const target = targets.find((candidate) => candidate.service === "hospital-a-gateway");
    expect(target?.tls).to.deep.equal({
      caPath: "/run/interfhir/pki/ca/ca.crt",
      certPath: "/run/interfhir/pki/hospital-a/client.crt",
      keyPath: "/run/interfhir/pki/hospital-a/client.key"
    });
  });

  it("reports the dependency error with remediation context", async function () {
    const result = await checkRuntimeDependency(
      {
        service: "hospital-a-fhir",
        endpoint: "http://hospital-a-fhir:8080/fhir/metadata",
        kind: "http",
        remediation: "Start hospital-a-fhir and wait for /fhir/metadata."
      },
      {
        fetch: async () => {
          throw new Error("ECONNREFUSED");
        }
      }
    );

    expect(result).to.deep.equal({
      service: "hospital-a-fhir",
      endpoint: "http://hospital-a-fhir:8080/fhir/metadata",
      status: "failed",
      lastStatus: 0,
      lastError: "ECONNREFUSED",
      remediation: "Start hospital-a-fhir and wait for /fhir/metadata."
    });
  });

  it("reports an unavailable external Docker network with exact remediation", async function () {
    const result = await checkRuntimeDependency(
      {
        service: "institutional-identity-network",
        endpoint: "interfhir-institutional-identity",
        kind: "docker-network",
        networkName: "interfhir-institutional-identity",
        remediation: "Run docker compose -f docker-compose.identity.yml up -d keycloak."
      },
      {
        inspectNetwork: async () => {
          throw new Error("docker daemon unavailable");
        }
      }
    );

    expect(result).to.deep.equal({
      service: "institutional-identity-network",
      endpoint: "interfhir-institutional-identity",
      status: "failed",
      lastStatus: 0,
      lastError: "docker daemon unavailable",
      remediation: "Run docker compose -f docker-compose.identity.yml up -d keycloak."
    });
  });

  it("stops waiting on the first failed dependency", async function () {
    const checked: string[] = [];
    const results = await waitForRuntimeDependencies(
      [
        {
          service: "hospital-a-fhir",
          endpoint: "http://hospital-a-fhir:8080/fhir/metadata",
          kind: "http",
          remediation: "Start hospital-a-fhir."
        },
        {
          service: "clinic-b-fhir",
          endpoint: "http://clinic-b-fhir:8080/fhir/metadata",
          kind: "http",
          remediation: "Start clinic-b-fhir."
        }
      ],
      {
        timeoutMs: 0,
        pollIntervalMs: 10,
        fetch: async (url) => {
          checked.push(String(url));
          return {
            ok: false,
            status: 503
          } as Response;
        },
        sleep: async () => undefined
      }
    );

    expect(checked).to.deep.equal([
      "http://hospital-a-fhir:8080/fhir/metadata"
    ]);
    expect(results).to.deep.equal([
      {
        service: "hospital-a-fhir",
        endpoint: "http://hospital-a-fhir:8080/fhir/metadata",
        status: "failed",
        lastStatus: 503,
        lastError: "HTTP 503",
        remediation: "Start hospital-a-fhir."
      }
    ]);
  });
});
