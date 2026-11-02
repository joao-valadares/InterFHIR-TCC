import { mkdtemp, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { expect } from "chai";
import { readFileSync } from "node:fs";
import { exportJWK, generateKeyPair } from "jose";
import * as configModule from "../src/config.js";

import {
  loadHostDevelopmentHealthAccessConfig,
  loadHealthAccessConfig,
  withLoopbackDevelopmentOverrides
} from "../src/config.js";

const fixtureDirectory = await mkdtemp(path.join(os.tmpdir(), "interfhir-config-"));
const trustedJwksPath = path.join(fixtureDirectory, "trusted-jwks.json");
after(async () => rm(fixtureDirectory, { recursive: true, force: true }));
const manifestKeys = await generateKeyPair("ES256", { extractable: true });
const manifestPrivateJwk = { ...(await exportJWK(manifestKeys.privateKey)), alg: "ES256", kid: "hospital-a-2026" };
const manifestPublicJwk = { ...(await exportJWK(manifestKeys.publicKey)), alg: "ES256", kid: "hospital-a-2026" };
const trustedJwksJson = JSON.stringify({ keys: [{
  kty: "RSA",
  n: "uuIdiyLJPeUTW18sXl64a877fwlLnCYTZ9Kz-o01LMkZzbVYlYv1N60oXXTzCwemQqywPPXGnONsb9n8B4I8uFowcs4r3usp6XUug9oPaaw_qs7ojmhepAaHMG-b-YEc39pd2QAmligxFq1RjazbLt2YFzGr52UWkKz277317xqHZSLLRFfWudBUnvGnfkeeIm5MI-iJH5NMtyzNGO_ovYRza9vZQFKgCs288qCIKmkSRShelakTS20kSQMCzpHi_IqR0VWnzAqZY_hj227n1wyxSbs_feDhaioSToRM8f_TAlhNvmpXXSYmPcLhj3gzJplPF6n8P2RXwhLGfXNrHQ",
  e: "AQAB",
  kid: "clinic-b-udap-client-2026",
  alg: "RS256",
  use: "sig"
}] });
await writeFile(trustedJwksPath, trustedJwksJson);


describe("Health Access Control middleware config", function () {
  it("describes both local FHIR vaults without collapsing them into one base URL", function () {
    const config = loadHealthAccessConfig({ FHIR_VAULT_ID: "hospital-a" });

    expect(config).to.have.nested.property(
      "fhirVaults.hospital-a.baseUrl",
      "http://hospital-a-fhir:8080/fhir"
    );
    expect(config).to.have.nested.property(
      "fhirVaults.hospital-a.vaultId",
      "vault:hospital-a"
    );
    expect(config).to.have.nested.property(
      "fhirVaults.hospital-a.seedBundlePath",
      "fixtures/fhir/hospital-a-bundle.json"
    );
    expect(config).to.have.nested.property(
      "fhirVaults.clinic-b.baseUrl",
      "http://clinic-b-fhir:8080/fhir"
    );
    expect(config).to.have.nested.property(
      "fhirVaults.clinic-b.vaultId",
      "vault:clinic-b"
    );
    expect(config.fhirVaults["hospital-a"].serviceCredentials).to.equal(
      undefined
    );
    expect(config).to.have.nested.property(
      "fhirVaults.clinic-b.seedBundlePath",
      "fixtures/fhir/clinic-b-bundle.json"
    );
    expect(config.blockchainRpcUrl).to.equal("http://127.0.0.1:8546");
    expect(config.manifestDatabaseUrl).to.equal(
      "postgresql://hospital_a_metadata:hospital_a_metadata@127.0.0.1:5433/interfhir_hospital_a_metadata"
    );
    expect(config.institutionMetadataDatabaseUrl).to.equal(
      "postgresql://hospital_a_metadata:hospital_a_metadata@127.0.0.1:5433/interfhir_hospital_a_metadata"
    );
    expect(config.authentication).to.deep.equal({
      secret: undefined,
      issuer: "interfhir-local",
      audience: "interfhir-api",
      oidcIssuers: []
    });
    expect(config.bootstrapEnabled).to.equal(false);
    expect(config.institutionReference).to.equal("Organization/hospital-a");
  });

  it("requires explicit vault selection instead of defaulting to Hospital A", function () {
    expect(() => loadHealthAccessConfig({})).to.throw("FHIR_VAULT_NOT_CONFIGURED");
  });

  it("requires both explicit gateway and vault selections without deriving either value", function () {
    const requireExplicitInstitutionGatewayBinding = (configModule as unknown as {
      requireExplicitInstitutionGatewayBinding?: (env: Record<string, string | undefined>) => string;
    }).requireExplicitInstitutionGatewayBinding;
    expect(requireExplicitInstitutionGatewayBinding).to.be.a("function");
    const requireBinding = requireExplicitInstitutionGatewayBinding as (env: Record<string, string | undefined>) => string;
    expect(() => requireBinding({
      INSTITUTION_GATEWAY: "hospital-a"
    })).to.throw("FHIR_VAULT_NOT_CONFIGURED");
    expect(() => requireBinding({
      FHIR_VAULT_ID: "hospital-a"
    })).to.throw("INSTITUTION_GATEWAY_REQUIRED");
    expect(() => requireBinding({
      INSTITUTION_GATEWAY: "hospital-a",
      FHIR_VAULT_ID: "clinic-b"
    })).to.throw("INSTITUTION_GATEWAY_MISMATCH");
    expect(requireBinding({
      INSTITUTION_GATEWAY: "clinic-b",
      FHIR_VAULT_ID: "clinic-b"
    })).to.equal("clinic-b");
  });

  it("ships an unbound environment example instead of an operational Hospital A selection", function () {
    const example = readFileSync(new URL("../../.env.example", import.meta.url), "utf8");
    expect(example).to.match(/^INSTITUTION_GATEWAY=\s*$/m);
    expect(example).to.match(/^FHIR_VAULT_ID=\s*$/m);
    expect(example).to.match(/^INSTITUTION_METADATA_DATABASE_URL=\s*$/m);
  });

  it("uses loopback vault endpoints only when the host development override is explicit", function () {
    const config = loadHealthAccessConfig(
      withLoopbackDevelopmentOverrides({ FHIR_VAULT_ID: "hospital-a" })
    );

    expect(config).to.have.nested.property(
      "fhirVaults.hospital-a.baseUrl",
      "http://127.0.0.1:8081/fhir"
    );
    expect(config).to.have.nested.property(
      "fhirVaults.clinic-b.baseUrl",
      "http://127.0.0.1:8082/fhir"
    );
  });

  it("derives local metadata database defaults from the explicitly selected vault", function () {
    const config = loadHealthAccessConfig({ FHIR_VAULT_ID: "clinic-b" });

    expect(config.institutionMetadataDatabaseUrl).to.equal(
      "postgresql://clinic_b_metadata:clinic_b_metadata@127.0.0.1:5435/interfhir_clinic_b_metadata"
    );
    expect(config.manifestDatabaseUrl).to.equal(
      "postgresql://clinic_b_metadata:clinic_b_metadata@127.0.0.1:5435/interfhir_clinic_b_metadata"
    );
  });

  it("creates an explicit host-development config without changing the Docker defaults", function () {
    const hostConfig = loadHostDevelopmentHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      JWT_SECRET: "local-test-secret-with-at-least-32-characters"
    });

    expect(hostConfig.fhirVaults["hospital-a"].baseUrl).to.equal(
      "http://127.0.0.1:8081/fhir"
    );
    expect(hostConfig.fhirVaults["clinic-b"].baseUrl).to.equal(
      "http://127.0.0.1:8082/fhir"
    );
    expect(loadHealthAccessConfig({ FHIR_VAULT_ID: "hospital-a" }).fhirVaults["hospital-a"].baseUrl).to.equal(
      "http://hospital-a-fhir:8080/fhir"
    );
  });

  it("selects one vault explicitly and applies per-vault URL overrides", function () {
    const config = loadHealthAccessConfig({
      FHIR_VAULT_ID: "clinic-b",
      FHIR_HOSPITAL_A_BASE_URL: "http://hospital-a-fhir:8080/fhir/",
      FHIR_CLINIC_B_BASE_URL: "http://clinic-b-fhir:8080/fhir/",
      FHIR_HOSPITAL_A_SERVICE_TOKEN: "hospital-a-token",
      FHIR_CLINIC_B_SERVICE_TOKEN: "clinic-b-token",
      BLOCKCHAIN_RPC_URL: "http://hardhat:8545",
      HEALTH_ACCESS_CONTROL_ADDRESS: "0x0000000000000000000000000000000000000001",
      MANIFEST_DATABASE_URL: "postgresql://middleware:test@metadata:5432/manifests",
      INSTITUTION_METADATA_DATABASE_URL:
        "postgresql://hospital:test@hospital-a-metadata:5432/metadata",
      JWT_SECRET: "local-test-secret-with-at-least-32-characters",
      JWT_ISSUER: "custom-issuer",
      JWT_AUDIENCE: "custom-audience",
      HEALTH_ACCESS_BOOTSTRAP_ENABLED: "true"
    });

    expect(config).to.have.nested.property("selectedFhirVault.id", "clinic-b");
    expect(config).to.have.nested.property(
      "selectedFhirVault.baseUrl",
      "http://clinic-b-fhir:8080/fhir"
    );
    expect(config.institutionReference).to.equal("Organization/clinic-b");
    expect(config).to.have.nested.property(
      "fhirVaults.hospital-a.baseUrl",
      "http://hospital-a-fhir:8080/fhir"
    );
    expect(config.fhirVaults["hospital-a"].serviceCredentials).to.deep.equal({
      bearerToken: "hospital-a-token"
    });
    expect(config.fhirVaults["clinic-b"].serviceCredentials).to.deep.equal({
      bearerToken: "clinic-b-token"
    });
    expect(config.blockchainRpcUrl).to.equal("http://hardhat:8545");
    expect(config.healthAccessControlAddress).to.equal("0x0000000000000000000000000000000000000001");
    expect(config.manifestDatabaseUrl).to.equal(
      "postgresql://middleware:test@metadata:5432/manifests"
    );
    expect(config.institutionMetadataDatabaseUrl).to.equal(
      "postgresql://hospital:test@hospital-a-metadata:5432/metadata"
    );
    expect(config.authentication).to.deep.equal({
      secret: "local-test-secret-with-at-least-32-characters",
      issuer: "custom-issuer",
      audience: "custom-audience",
      oidcIssuers: []
    });
    expect(config.bootstrapEnabled).to.equal(true);
  });

  it("rejects an unknown vault instead of silently routing to Hospital A", function () {
    expect(() =>
      loadHealthAccessConfig({
        FHIR_VAULT_ID: "unknown-vault"
      })
    ).to.throw("UNKNOWN_FHIR_VAULT: unknown-vault");
  });

  it("rejects an ambiguous bootstrap setting instead of enabling it", function () {
    expect(() =>
      loadHealthAccessConfig({
        FHIR_VAULT_ID: "hospital-a",
        HEALTH_ACCESS_BOOTSTRAP_ENABLED: "yes"
      })
    ).to.throw("INVALID_BOOLEAN_ENV: HEALTH_ACCESS_BOOTSTRAP_ENABLED");
  });

  it("requires the complete configured wallet set when a permissioned RPC deployment is selected", function () {
    expect(() => loadHealthAccessConfig({ FHIR_VAULT_ID: "hospital-a", BLOCKCHAIN_PEP_PRIVATE_KEY: "0x1234" })).to.throw("BLOCKCHAIN_WALLET_CONFIG_INCOMPLETE");
    const config = loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      BLOCKCHAIN_DEPLOYER_PRIVATE_KEY: "0x1111111111111111111111111111111111111111111111111111111111111111",
      BLOCKCHAIN_PATIENT_PRIVATE_KEY: "0x2222222222222222222222222222222222222222222222222222222222222222",
      BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY: "0x3333333333333333333333333333333333333333333333333333333333333333",
      BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY: "0x4444444444444444444444444444444444444444444444444444444444444444",
      BLOCKCHAIN_PEP_PRIVATE_KEY: "0x5555555555555555555555555555555555555555555555555555555555555555"
    });
    expect(config.blockchainWallets?.pepPrivateKey).to.match(/^0x55/);
  });

  it("treats blank Compose wallet placeholders as external optional secrets", function () {
    const config = loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_CONTROL_ADDRESS: "",
      BLOCKCHAIN_DEPLOYER_PRIVATE_KEY: "",
      BLOCKCHAIN_PATIENT_PRIVATE_KEY: "",
      BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY: "",
      BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY: "",
      BLOCKCHAIN_PEP_PRIVATE_KEY: ""
    });

    expect(config.healthAccessControlAddress).to.equal(undefined);
    expect(config.blockchainWallets).to.equal(undefined);
  });

  it("does not promote Clinic B requester settings into the local UDAP issuer", function () {
    const config = loadHealthAccessConfig({
      FHIR_VAULT_ID: "clinic-b",
      HEALTH_ACCESS_TLS_KEY_PATH: "/run/interfhir/pki/clinic-b/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: "/run/interfhir/pki/clinic-b/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: "/run/interfhir/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/hospital-a",
      UDAP_ENABLED: "false",
      UDAP_REQUESTER_ENABLED: "true",
      UDAP_REQUESTER_DISCOVERY_URL: "https://hospital-a.local/fhir/.well-known/udap",
      UDAP_REQUESTER_SIGNING_KEY_PATH: "/run/interfhir/udap/clinic-b-client-signing.key",
      UDAP_REQUESTER_PUBLIC_JWK_PATH: "/run/interfhir/udap/clinic-b-client-public-jwk.json",
      UDAP_REQUESTER_TRUSTED_JWKS_PATH: "/run/interfhir/udap/hospital-a-issuer-jwks.json"
    });

    expect(config.udap).to.equal(undefined);
  });

  it("loads separate OIDC issuer trust configuration for both institutions", function () {
    const config = loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      OIDC_HOSPITAL_A_ISSUER: "https://identity.local/realms/hospital-a",
      OIDC_HOSPITAL_A_JWKS_URI: "https://identity.local/realms/hospital-a/certs",
      OIDC_HOSPITAL_A_AUDIENCE: "interfhir-api",
      OIDC_CLINIC_B_ISSUER: "https://identity.local/realms/clinic-b",
      OIDC_CLINIC_B_JWKS_URI: "https://identity.local/realms/clinic-b/certs",
      OIDC_CLINIC_B_AUDIENCE: "interfhir-api"
    });

    expect(config.authentication.oidcIssuers).to.deep.equal([
      {
        issuer: "https://identity.local/realms/hospital-a",
        jwksUri: "https://identity.local/realms/hospital-a/certs",
        audience: "interfhir-api",
        organizationReference: "Organization/hospital-a"
      },
      {
        issuer: "https://identity.local/realms/clinic-b",
        jwksUri: "https://identity.local/realms/clinic-b/certs",
        audience: "interfhir-api",
        organizationReference: "Organization/clinic-b"
      }
    ]);
  });

  it("enables UDAP only with a complete trusted configuration", function () {
    const config = loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_TLS_KEY_PATH: ".local/pki/hospital-a/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: ".local/pki/hospital-a/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: ".local/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/clinic-b",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local/",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/udap/hospital-a-signing.key",
      UDAP_SIGNING_KEY_ID: "hospital-a-udap-2026",
      UDAP_TRUSTED_JWKS_JSON: trustedJwksJson,
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/.well-known/udap/jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata"
    });
    expect(config.udap).to.deep.equal({
      issuer: "https://hospital-a.local",
      baseUrl: "https://hospital-a.local",
      tokenAudience: "clinic-b-gateway",
      signingKeyPath: ".local/udap/hospital-a-signing.key",
      signingKeyId: "hospital-a-udap-2026",
      signingAlgorithm: "RS256",
      trustedJwks: JSON.parse(trustedJwksJson).keys,
      issuerJwksPath: ".local/udap/hospital-a-issuer-jwks.json",
      issuerJwksUri: "https://hospital-a.local/.well-known/udap/jwks.json",
      signedMetadata: "signed-metadata",
      signedMetadataPath: undefined
    });
    expect(() => loadHealthAccessConfig({ FHIR_VAULT_ID: "hospital-a", UDAP_ISSUER: "https://hospital-a.local" })).to.throw("UDAP_CONFIG_INCOMPLETE");
    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/udap/hospital-a-signing.key",
      UDAP_SIGNING_KEY_ID: "hospital-a-udap-2026",
      UDAP_TRUSTED_JWKS_JSON: trustedJwksJson,
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/.well-known/udap/jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata"
    })).to.throw("UDAP_MTLS_CONFIG_REQUIRED");
  });

  it("loads explicit gateway bind and public/peer port settings", function () {
    const config = loadHealthAccessConfig({
      INSTITUTION_GATEWAY: "clinic-b",
      FHIR_VAULT_ID: "clinic-b",
      HEALTH_ACCESS_API_HOST: "0.0.0.0",
      HEALTH_ACCESS_API_PORT: "3000",
      HEALTH_ACCESS_PUBLIC_PORT: "3002",
      HEALTH_ACCESS_PEER_PORT: "4002",
      BLOCKCHAIN_RPC_URL: "http://besu-hospital-a-validator:8545",
      INSTITUTION_METADATA_DATABASE_URL:
        "postgresql://clinic_b_metadata:clinic_b_metadata@clinic-b-metadata-postgres:5432/interfhir_clinic_b_metadata"
    });

    expect(config.gateway).to.deep.include({
      bindAddress: "0.0.0.0",
      apiPort: 3000,
      publicPort: 3002,
      peerPort: 4002
    });
    expect(config.blockchainRpcUrl).to.equal(
      "http://besu-hospital-a-validator:8545"
    );
  });

  it("defaults the peer listener to a distinct container port and rejects collisions", function () {
    const config = loadHealthAccessConfig({ FHIR_VAULT_ID: "hospital-a" });
    expect(config.gateway.publicPort).to.equal(3000);
    expect(config.gateway.peerPort).to.equal(4000);

    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_PUBLIC_PORT: "3000",
      HEALTH_ACCESS_PEER_PORT: "3000"
    })).to.throw("PUBLIC_PEER_PORT_COLLISION");
  });

  it("loads trusted UDAP JWKS from an explicitly mounted file path", function () {
    const config = loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_TLS_KEY_PATH: ".local/pki/hospital-a/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: ".local/pki/hospital-a/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: ".local/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/clinic-b",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/udap/hospital-a-signing.key",
      UDAP_SIGNING_KEY_ID: "hospital-a-udap-2026",
      UDAP_TRUSTED_JWKS_PATH: trustedJwksPath,
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/.well-known/udap/jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata"
    });

    expect(config.udap?.trustedJwks).to.deep.equal(JSON.parse(readFileSync(trustedJwksPath, "utf8")).keys);
  });

  it("rejects invalid gateway ports before the runtime starts", function () {
    expect(() =>
      loadHealthAccessConfig({
        FHIR_VAULT_ID: "hospital-a",
        HEALTH_ACCESS_API_PORT: "0"
      })
    ).to.throw("INVALID_PORT: HEALTH_ACCESS_API_PORT");
  });

  it("rejects duplicate OIDC issuer URLs during configuration", function () {
    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      OIDC_HOSPITAL_A_ISSUER: "https://identity.local/realms/shared",
      OIDC_HOSPITAL_A_JWKS_URI: "https://identity.local/realms/shared/certs-a",
      OIDC_HOSPITAL_A_AUDIENCE: "interfhir-api",
      OIDC_CLINIC_B_ISSUER: "https://identity.local/realms/shared",
      OIDC_CLINIC_B_JWKS_URI: "https://identity.local/realms/shared/certs-b",
      OIDC_CLINIC_B_AUDIENCE: "interfhir-api"
    })).to.throw("OIDC_ISSUER_DUPLICATE");
  });

  it("rejects a UDAP signing path reused as TLS key material", function () {
    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_TLS_KEY_PATH: ".local/pki/hospital-a/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: ".local/pki/hospital-a/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: ".local/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/clinic-b",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/pki/hospital-a/server.key",
      UDAP_SIGNING_KEY_ID: "hospital-a-udap-2026",
      UDAP_TRUSTED_JWKS_JSON: trustedJwksJson,
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/.well-known/udap/jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata"
    })).to.throw("UDAP_SIGNING_KEY_PURPOSE_CONFLICT");
  });

  it("keeps manifest signing independent from the UDAP signing identity", function () {
    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_TLS_KEY_PATH: ".local/pki/hospital-a/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: ".local/pki/hospital-a/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: ".local/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/clinic-b",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/udap/hospital-a-signing.key",
      UDAP_SIGNING_KEY_ID: "shared-key-id",
      UDAP_TRUSTED_JWKS_JSON: trustedJwksJson,
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/.well-known/udap/jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata",
      MANIFEST_SIGNING_PRIVATE_JWK: JSON.stringify({ ...manifestPrivateJwk, kid: "shared-key-id" }),
      MANIFEST_SIGNING_PUBLIC_JWK: JSON.stringify({ ...manifestPublicJwk, kid: "shared-key-id" }),
      MANIFEST_SIGNING_KEY_ID: "shared-key-id"
    })).to.throw("MANIFEST_UDAP_KEY_PURPOSE_CONFLICT");
  });

  it("requires an explicit complete JWK pair for persistent manifest signing", function () {
    const config = loadHealthAccessConfig({ FHIR_VAULT_ID: "hospital-a", MANIFEST_SIGNING_PRIVATE_JWK: JSON.stringify(manifestPrivateJwk), MANIFEST_SIGNING_PUBLIC_JWK: JSON.stringify(manifestPublicJwk), MANIFEST_SIGNING_KEY_ID: "hospital-a-2026" });
    expect(config.manifestSigning).to.deep.equal({ privateJwk: manifestPrivateJwk, publicJwk: manifestPublicJwk, keyId: "hospital-a-2026" });
    expect(() => loadHealthAccessConfig({ FHIR_VAULT_ID: "hospital-a", MANIFEST_SIGNING_KEY_ID: "partial" })).to.throw("MANIFEST_SIGNING_CONFIG_INCOMPLETE");
  });

  it("rejects malformed manifest and UDAP public JWK material during config load", function () {
    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      MANIFEST_SIGNING_PRIVATE_JWK: JSON.stringify(manifestPrivateJwk),
      MANIFEST_SIGNING_PUBLIC_JWK: JSON.stringify({ ...manifestPublicJwk, crv: "P-384" }),
      MANIFEST_SIGNING_KEY_ID: "hospital-a-2026"
    })).to.throw("MANIFEST_SIGNING_PUBLIC_JWK_INVALID");

    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_TLS_KEY_PATH: ".local/pki/hospital-a/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: ".local/pki/hospital-a/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: ".local/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/clinic-b",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/udap/hospital-a-signing.key",
      UDAP_SIGNING_KEY_ID: "hospital-a-udap-2026",
      UDAP_TRUSTED_JWKS_JSON: trustedJwksJson.replace(/"n":"[^"]+"/, '"n":"malformed"'),
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/.well-known/udap/jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata"
    })).to.throw("UDAP_TRUSTED_JWKS_INVALID");
  });

  it("binds the public JWKS URI to the gateway origin and allowed path", function () {
    const base = {
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_TLS_KEY_PATH: ".local/pki/hospital-a/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: ".local/pki/hospital-a/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: ".local/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/clinic-b",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/udap/hospital-a-signing.key",
      UDAP_SIGNING_KEY_ID: "hospital-a-udap-2026",
      UDAP_TRUSTED_JWKS_JSON: trustedJwksJson,
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata"
    };
    expect(() => loadHealthAccessConfig({
      ...base,
      UDAP_ISSUER_JWKS_URI: "https://other-gateway.local/.well-known/udap/jwks.json"
    })).to.throw("UDAP_ISSUER_JWKS_ORIGIN_MISMATCH");
    expect(() => loadHealthAccessConfig({
      ...base,
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/other-jwks.json"
    })).to.throw("UDAP_ISSUER_JWKS_PATH_INVALID");
    expect(() => loadHealthAccessConfig({
      ...base,
      UDAP_ISSUER_JWKS_URI: "ftp://hospital-a.local/.well-known/udap/jwks.json"
    })).to.throw("UDAP_ISSUER_JWKS_SCHEME_INVALID");
    expect(() => loadHealthAccessConfig({
      ...base,
      UDAP_ISSUER_JWKS_URI: "file://hospital-a.local/.well-known/udap/jwks.json"
    })).to.throw("UDAP_ISSUER_JWKS_SCHEME_INVALID");
  });

  it("rejects RSA oth private material in trusted JWKS during config loading", function () {
    expect(() => loadHealthAccessConfig({
      FHIR_VAULT_ID: "hospital-a",
      HEALTH_ACCESS_TLS_KEY_PATH: ".local/pki/hospital-a/server.key",
      HEALTH_ACCESS_TLS_CERT_PATH: ".local/pki/hospital-a/server.crt",
      HEALTH_ACCESS_TLS_CA_PATH: ".local/pki/ca/ca.crt",
      MTLS_EXPECTED_PEER_ORGANIZATION: "Organization/clinic-b",
      UDAP_ISSUER: "https://hospital-a.local",
      UDAP_BASE_URL: "https://hospital-a.local",
      UDAP_TOKEN_AUDIENCE: "clinic-b-gateway",
      UDAP_SIGNING_KEY_PATH: ".local/udap/hospital-a-signing.key",
      UDAP_SIGNING_KEY_ID: "hospital-a-udap-2026",
      UDAP_TRUSTED_JWKS_JSON: trustedJwksJson.replace(
        '"use":"sig"',
        '"use":"sig","oth":[{"r":"private"}]'
      ),
      UDAP_ISSUER_JWKS_PATH: ".local/udap/hospital-a-issuer-jwks.json",
      UDAP_ISSUER_JWKS_URI: "https://hospital-a.local/.well-known/udap/jwks.json",
      UDAP_SIGNED_METADATA: "signed-metadata"
    })).to.throw("UDAP_TRUSTED_JWKS_PRIVATE_MATERIAL");
  });
});
