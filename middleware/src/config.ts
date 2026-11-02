type EnvLike = Record<string, string | undefined> & {
  FHIR_VAULT_ID?: string;
  FHIR_HOSPITAL_A_BASE_URL?: string;
  FHIR_CLINIC_B_BASE_URL?: string;
  FHIR_HOSPITAL_A_SERVICE_TOKEN?: string;
  FHIR_CLINIC_B_SERVICE_TOKEN?: string;
  BLOCKCHAIN_RPC_URL?: string;
  HEALTH_ACCESS_CONTROL_ADDRESS?: string;
  BLOCKCHAIN_DEPLOYER_PRIVATE_KEY?: string;
  BLOCKCHAIN_PATIENT_PRIVATE_KEY?: string;
  BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY?: string;
  BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY?: string;
  BLOCKCHAIN_PEP_PRIVATE_KEY?: string;
  MANIFEST_DATABASE_URL?: string;
  INSTITUTION_METADATA_DATABASE_URL?: string;
  JWT_SECRET?: string;
  JWT_ISSUER?: string;
  JWT_AUDIENCE?: string;
  OIDC_HOSPITAL_A_ISSUER?: string;
  OIDC_HOSPITAL_A_JWKS_URI?: string;
  OIDC_HOSPITAL_A_AUDIENCE?: string;
  OIDC_CLINIC_B_ISSUER?: string;
  OIDC_CLINIC_B_JWKS_URI?: string;
  OIDC_CLINIC_B_AUDIENCE?: string;
  HEALTH_ACCESS_TLS_KEY_PATH?: string;
  HEALTH_ACCESS_TLS_CERT_PATH?: string;
  HEALTH_ACCESS_TLS_CA_PATH?: string;
  MTLS_EXPECTED_PEER_ORGANIZATION?: string;
  UDAP_ISSUER?: string;
  UDAP_BASE_URL?: string;
  UDAP_TOKEN_AUDIENCE?: string;
  UDAP_SIGNING_KEY_PATH?: string;
  UDAP_SIGNING_KEY_ID?: string;
  UDAP_SIGNING_ALGORITHM?: string;
  UDAP_TRUSTED_JWKS_JSON?: string;
  UDAP_TRUSTED_JWKS_PATH?: string;
  UDAP_ISSUER_JWKS_PATH?: string;
  UDAP_ISSUER_JWKS_URI?: string;
  UDAP_SIGNED_METADATA?: string;
  UDAP_SIGNED_METADATA_PATH?: string;
  UDAP_ENABLED?: string;
  MANIFEST_SIGNING_PRIVATE_JWK?: string;
  MANIFEST_SIGNING_PUBLIC_JWK?: string;
  MANIFEST_SIGNING_KEY_ID?: string;
  HEALTH_ACCESS_API_HOST?: string;
  HEALTH_ACCESS_API_PORT?: string;
  HEALTH_ACCESS_PUBLIC_PORT?: string;
  HEALTH_ACCESS_PEER_PORT?: string;
  HEALTH_ACCESS_BOOTSTRAP_ENABLED?: string;
};

import { readFileSync } from "node:fs";
import path from "node:path";

import {
  assertManifestJwkPair,
  assertUdapTrustedJwks
} from "./identity/key-material.js";
import type { VaultDescriptor } from "./vault/vault-directory.js";

export const FHIR_VAULT_IDS = ["hospital-a", "clinic-b"] as const;

export type FhirVaultId = (typeof FHIR_VAULT_IDS)[number];

export interface FhirVaultDescriptor extends VaultDescriptor {
  id: FhirVaultId;
  baseUrl: string;
}

export function loadHealthAccessConfig(env: EnvLike = process.env) {
  const fhirVaults: Record<FhirVaultId, FhirVaultDescriptor> = {
    "hospital-a": {
      id: "hospital-a",
      vaultId: "vault:hospital-a",
      baseUrl: normalizeBaseUrl(env.FHIR_HOSPITAL_A_BASE_URL ?? "http://hospital-a-fhir:8080/fhir"),
      fhirBaseUrl: normalizeBaseUrl(env.FHIR_HOSPITAL_A_BASE_URL ?? "http://hospital-a-fhir:8080/fhir"),
      custodianOrganizationReference: "Organization/hospital-a",
      ...serviceCredentials(env.FHIR_HOSPITAL_A_SERVICE_TOKEN),
      seedBundlePath: "fixtures/fhir/hospital-a-bundle.json",
      requiredResources: [
        "Organization/hospital-a",
        "Organization/clinic-b",
        "Patient/pat-ana",
        "Practitioner/ana",
        "Practitioner/bruno",
        "Observation/obs-ana-1",
        "DiagnosticReport/report-ana-1",
        "Consent/cons-ana-1",
        "Consent/cons-ana-clinic-b"
      ]
    },
    "clinic-b": {
      id: "clinic-b",
      vaultId: "vault:clinic-b",
      baseUrl: normalizeBaseUrl(env.FHIR_CLINIC_B_BASE_URL ?? "http://clinic-b-fhir:8080/fhir"),
      fhirBaseUrl: normalizeBaseUrl(env.FHIR_CLINIC_B_BASE_URL ?? "http://clinic-b-fhir:8080/fhir"),
      custodianOrganizationReference: "Organization/clinic-b",
      ...serviceCredentials(env.FHIR_CLINIC_B_SERVICE_TOKEN),
      seedBundlePath: "fixtures/fhir/clinic-b-bundle.json",
      requiredResources: [
        "Organization/clinic-b",
        "Practitioner/bruno"
      ]
    }
  };
  if (typeof env.FHIR_VAULT_ID !== "string" || env.FHIR_VAULT_ID.trim().length === 0) {
    throw new Error("FHIR_VAULT_NOT_CONFIGURED");
  }
  const selectedVaultId = requireVaultId(env.FHIR_VAULT_ID);
  const selectedFhirVault = fhirVaults[selectedVaultId];
  const institutionReference = requireInstitutionBinding(
    selectedFhirVault.custodianOrganizationReference
  );
  const localMetadataDatabaseUrl = defaultMetadataDatabaseUrl(selectedVaultId);

  const tls = tlsConfig(env);
  const manifestSigning = manifestSigningConfig(env);
  const udap = udapConfig(env, tls, manifestSigning);

  return {
    fhirVaults,
    selectedFhirVault,
    institutionReference,
    gateway: gatewayConfig(env),
    blockchainRpcUrl: env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546",
    healthAccessControlAddress: optionalEnv(env.HEALTH_ACCESS_CONTROL_ADDRESS),
    blockchainWallets: blockchainWalletConfig(env),
    institutionMetadataDatabaseUrl:
      env.INSTITUTION_METADATA_DATABASE_URL ??
      localMetadataDatabaseUrl,
    manifestDatabaseUrl:
      env.MANIFEST_DATABASE_URL ??
      env.INSTITUTION_METADATA_DATABASE_URL ??
      localMetadataDatabaseUrl,
    authentication: {
      secret: env.JWT_SECRET,
      issuer: env.JWT_ISSUER ?? "interfhir-local",
      audience: env.JWT_AUDIENCE ?? "interfhir-api",
      oidcIssuers: oidcIssuers(env)
    },
    tls,
    udap,
    manifestSigning,
    bootstrapEnabled: readBoolean(
      env.HEALTH_ACCESS_BOOTSTRAP_ENABLED,
      "HEALTH_ACCESS_BOOTSTRAP_ENABLED"
    )
  };
}

function blockchainWalletConfig(env: EnvLike) {
  const values = [
    optionalEnv(env.BLOCKCHAIN_DEPLOYER_PRIVATE_KEY),
    optionalEnv(env.BLOCKCHAIN_PATIENT_PRIVATE_KEY),
    optionalEnv(env.BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY),
    optionalEnv(env.BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY),
    optionalEnv(env.BLOCKCHAIN_PEP_PRIVATE_KEY)
  ];
  if (values.every((value) => value === undefined)) return undefined;
  if (values.some((value) => !isPrivateKey(value))) throw new Error("BLOCKCHAIN_WALLET_CONFIG_INCOMPLETE");
  return {
    deployerPrivateKey: values[0] as string,
    patientPrivateKey: values[1] as string,
    practitionerPrivateKey: values[2] as string,
    organizationPrivateKey: values[3] as string,
    pepPrivateKey: values[4] as string
  };
}

function isPrivateKey(value: string | undefined) {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function manifestSigningConfig(env: EnvLike) {
  const privateJwkText = optionalEnv(env.MANIFEST_SIGNING_PRIVATE_JWK);
  const publicJwkText = optionalEnv(env.MANIFEST_SIGNING_PUBLIC_JWK);
  const keyId = optionalEnv(env.MANIFEST_SIGNING_KEY_ID);
  const values = [privateJwkText, publicJwkText, keyId];
  if (values.every((value) => value === undefined)) return undefined;
  if (values.some((value) => !value)) throw new Error("MANIFEST_SIGNING_CONFIG_INCOMPLETE");
  const privateJwk = parseJsonObject(privateJwkText as string, "MANIFEST_SIGNING_JWK_INVALID");
  const publicJwk = parseJsonObject(publicJwkText as string, "MANIFEST_SIGNING_JWK_INVALID");
  assertManifestJwkPair(privateJwk, publicJwk, keyId as string);
  return { privateJwk, publicJwk, keyId: keyId as string };
}

function gatewayConfig(env: EnvLike) {
  const bindAddress = env.HEALTH_ACCESS_API_HOST ?? "127.0.0.1";
  if (bindAddress.trim().length === 0) {
    throw new Error("INVALID_HOST: HEALTH_ACCESS_API_HOST");
  }

  const apiPort = readPort(env.HEALTH_ACCESS_API_PORT, "HEALTH_ACCESS_API_PORT", 3000);
  const publicPort = readPort(env.HEALTH_ACCESS_PUBLIC_PORT, "HEALTH_ACCESS_PUBLIC_PORT", apiPort);
  const peerPort = readPort(env.HEALTH_ACCESS_PEER_PORT, "HEALTH_ACCESS_PEER_PORT", 4000);
  if (publicPort === peerPort) throw new Error("PUBLIC_PEER_PORT_COLLISION");
  return {
    bindAddress,
    apiPort,
    publicPort,
    peerPort
  };
}

function readPort(value: string | undefined, name: string, fallback: number) {
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(value)) throw new Error(`INVALID_PORT: ${name}`);
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`INVALID_PORT: ${name}`);
  }
  return port;
}

function udapConfig(
  env: EnvLike,
  tls: ReturnType<typeof tlsConfig>,
  manifestSigning: ReturnType<typeof manifestSigningConfig>
) {
  const issuer = optionalEnv(env.UDAP_ISSUER);
  const baseUrlValue = optionalEnv(env.UDAP_BASE_URL);
  const tokenAudience = optionalEnv(env.UDAP_TOKEN_AUDIENCE);
  const signingKeyPath = optionalEnv(env.UDAP_SIGNING_KEY_PATH);
  const signingKeyId = optionalEnv(env.UDAP_SIGNING_KEY_ID);
  const trustedJwksJson = optionalEnv(env.UDAP_TRUSTED_JWKS_JSON);
  const trustedJwksPath = optionalEnv(env.UDAP_TRUSTED_JWKS_PATH);
  const issuerJwksPath = optionalEnv(env.UDAP_ISSUER_JWKS_PATH);
  const issuerJwksUriValue = optionalEnv(env.UDAP_ISSUER_JWKS_URI);
  const signedMetadata = optionalEnv(env.UDAP_SIGNED_METADATA);
  const signedMetadataPath = optionalEnv(env.UDAP_SIGNED_METADATA_PATH);
  const explicitEnabled = optionalEnv(env.UDAP_ENABLED);
  if (explicitEnabled !== undefined && !readBoolean(explicitEnabled, "UDAP_ENABLED")) return undefined;
  const values = [
    issuer,
    baseUrlValue,
    tokenAudience,
    signingKeyPath,
    signingKeyId,
    trustedJwksJson ?? trustedJwksPath,
    issuerJwksPath,
    issuerJwksUriValue,
    signedMetadata ?? signedMetadataPath
  ];
  if (values.every((value) => value === undefined)) return undefined;
  if (values.some((value) => !value)) throw new Error("UDAP_CONFIG_INCOMPLETE");
  if (signedMetadata && signedMetadataPath) {
    throw new Error("UDAP_SIGNED_METADATA_SOURCE_CONFLICT");
  }
  if (trustedJwksJson && trustedJwksPath) {
    throw new Error("UDAP_TRUSTED_JWKS_SOURCE_CONFLICT");
  }
  if (!tls) throw new Error("UDAP_MTLS_CONFIG_REQUIRED");
  if (samePath(signingKeyPath as string, tls.keyPath) || samePath(signingKeyPath as string, tls.certPath) || samePath(signingKeyPath as string, tls.caPath)) {
    throw new Error("UDAP_SIGNING_KEY_PURPOSE_CONFLICT");
  }
  if (manifestSigning && signingKeyId === manifestSigning.keyId) {
    throw new Error("MANIFEST_UDAP_KEY_PURPOSE_CONFLICT");
  }
  let trustedJwks: { keys?: Record<string, unknown>[] };
  try {
    const trustedJwksText = trustedJwksPath
      ? readFileSync(trustedJwksPath, "utf8")
      : trustedJwksJson as string;
    trustedJwks = JSON.parse(trustedJwksText) as { keys?: Record<string, unknown>[] };
  } catch {
    throw new Error(trustedJwksPath ? "UDAP_TRUSTED_JWKS_READ_FAILED" : "UDAP_TRUSTED_JWKS_INVALID");
  }
  assertUdapTrustedJwks(trustedJwks.keys ?? []);
  const baseUrl = normalizeBaseUrl(baseUrlValue as string);
  const issuerJwksUri = requireUdapIssuerJwksUri(issuerJwksUriValue as string, baseUrl);
  return {
    issuer: issuer as string,
    baseUrl,
    tokenAudience: tokenAudience as string,
    signingKeyPath: signingKeyPath as string,
    signingKeyId: signingKeyId as string,
    signingAlgorithm: readSigningAlgorithm(env.UDAP_SIGNING_ALGORITHM),
    trustedJwks: trustedJwks.keys as Record<string, unknown>[],
    issuerJwksPath: issuerJwksPath as string,
    issuerJwksUri,
    signedMetadata,
    signedMetadataPath
  };
}

function tlsConfig(env: EnvLike) {
  const keyPath = optionalEnv(env.HEALTH_ACCESS_TLS_KEY_PATH);
  const certPath = optionalEnv(env.HEALTH_ACCESS_TLS_CERT_PATH);
  const caPath = optionalEnv(env.HEALTH_ACCESS_TLS_CA_PATH);
  const values = [keyPath, certPath, caPath];
  if (values.every((value) => value === undefined)) return undefined;
  if (values.some((value) => !value)) throw new Error("INSTITUTION_TLS_CONFIG_INCOMPLETE");
  if (!env.MTLS_EXPECTED_PEER_ORGANIZATION) throw new Error("MTLS_EXPECTED_PEER_ORGANIZATION_REQUIRED");
  return {
    keyPath: keyPath as string,
    certPath: certPath as string,
    caPath: caPath as string,
    expectedPeerOrganization: env.MTLS_EXPECTED_PEER_ORGANIZATION
  };
}

function parseJsonObject(value: string, errorCode: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(errorCode);
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error(errorCode);
  }
}

function readSigningAlgorithm(value: string | undefined): "RS256" | "ES256" {
  if (value === undefined || value === "RS256") return "RS256";
  if (value === "ES256") return value;
  throw new Error("UDAP_SIGNING_ALGORITHM_INVALID");
}

function samePath(left: string, right: string) {
  return path.resolve(left).toLowerCase() === path.resolve(right).toLowerCase();
}

function requireUdapIssuerJwksUri(value: string, baseUrl: string) {
  let gateway: URL;
  let uri: URL;
  try {
    gateway = new URL(baseUrl);
    uri = new URL(value);
  } catch {
    throw new Error("UDAP_ISSUER_JWKS_URI_INVALID");
  }
  if (uri.protocol !== "http:" && uri.protocol !== "https:") {
    throw new Error("UDAP_ISSUER_JWKS_SCHEME_INVALID");
  }
  if (gateway.origin !== uri.origin) throw new Error("UDAP_ISSUER_JWKS_ORIGIN_MISMATCH");
  if (
    uri.pathname !== "/.well-known/udap/jwks.json" ||
    uri.search.length > 0 ||
    uri.hash.length > 0
  ) throw new Error("UDAP_ISSUER_JWKS_PATH_INVALID");
  return value;
}

function oidcIssuers(env: EnvLike) {
  const issuers = [
    oidcIssuer(env.OIDC_HOSPITAL_A_ISSUER, env.OIDC_HOSPITAL_A_JWKS_URI, env.OIDC_HOSPITAL_A_AUDIENCE, "Organization/hospital-a"),
    oidcIssuer(env.OIDC_CLINIC_B_ISSUER, env.OIDC_CLINIC_B_JWKS_URI, env.OIDC_CLINIC_B_AUDIENCE, "Organization/clinic-b")
  ].filter((issuer): issuer is { issuer: string; jwksUri: string; audience: string; organizationReference: string } => issuer !== undefined);
  if (new Set(issuers.map((issuer) => issuer.issuer)).size !== issuers.length) {
    throw new Error("OIDC_ISSUER_DUPLICATE");
  }
  return issuers;
}

function oidcIssuer(issuer: string | undefined, jwksUri: string | undefined, audience: string | undefined, organizationReference: string) {
  if (!issuer && !jwksUri && !audience) return undefined;
  if (!issuer || !jwksUri || !audience) throw new Error("OIDC_ISSUER_CONFIG_INCOMPLETE");
  return { issuer, jwksUri, audience, organizationReference };
}

/**
 * Makes a host-run development process address the explicit loopback ports
 * declared by docker-compose.dev.yml. Runtime configuration remains private
 * by default and must not call this helper from inside a container.
 */
export function withLoopbackDevelopmentOverrides(
  env: EnvLike = process.env
): EnvLike {
  return {
    ...env,
    FHIR_HOSPITAL_A_BASE_URL:
      env.FHIR_HOSPITAL_A_BASE_URL ?? "http://127.0.0.1:8081/fhir",
    FHIR_CLINIC_B_BASE_URL:
      env.FHIR_CLINIC_B_BASE_URL ?? "http://127.0.0.1:8082/fhir"
  };
}

/**
 * Loads the explicit host-process configuration for the loopback-only
 * docker-compose.dev.yml overlay. The normal loader deliberately keeps the
 * private Docker DNS names, so a host process must opt in to this helper.
 */
export function loadHostDevelopmentHealthAccessConfig(env: EnvLike = process.env) {
  return loadHealthAccessConfig(withLoopbackDevelopmentOverrides(env));
}

function requireVaultId(value: string): FhirVaultId {
  if (FHIR_VAULT_IDS.includes(value as FhirVaultId)) {
    return value as FhirVaultId;
  }
  throw new Error(`UNKNOWN_FHIR_VAULT: ${value}`);
}

export function requireInstitutionBinding(reference: string | undefined): string {
  if (typeof reference !== "string" || reference.trim().length === 0) {
    throw new Error("ADMIN_INSTITUTION_NOT_CONFIGURED");
  }
  return reference;
}

export function assertInstitutionBinding(
  configuredReference: string | undefined,
  custodianReference: string
) {
  const configured = requireInstitutionBinding(configuredReference);
  if (configured !== custodianReference) {
    throw new Error("ADMIN_INSTITUTION_MISMATCH");
  }
  return configured;
}

export function requireExplicitInstitutionGatewayBinding(
  env: Record<string, string | undefined>
): FhirVaultId {
  const institution = env.INSTITUTION_GATEWAY;
  if (typeof institution !== "string" || institution.trim().length === 0) {
    throw new Error("INSTITUTION_GATEWAY_REQUIRED");
  }
  const vaultId = env.FHIR_VAULT_ID;
  if (typeof vaultId !== "string" || vaultId.trim().length === 0) {
    throw new Error("FHIR_VAULT_NOT_CONFIGURED");
  }
  if (!FHIR_VAULT_IDS.includes(institution as FhirVaultId)) {
    throw new Error("INSTITUTION_GATEWAY_INVALID");
  }
  const selectedVaultId = requireVaultId(vaultId);
  if (selectedVaultId !== institution) {
    throw new Error("INSTITUTION_GATEWAY_MISMATCH");
  }
  return selectedVaultId;
}

function defaultMetadataDatabaseUrl(vaultId: FhirVaultId) {
  const databaseUser = vaultId.replace("-", "_") + "_metadata";
  const databaseName = `interfhir_${databaseUser}`;
  const port = vaultId === "hospital-a" ? 5433 : 5435;
  return `postgresql://${databaseUser}:${databaseUser}@127.0.0.1:${port}/${databaseName}`;
}

function normalizeBaseUrl(value: string) {
  return value.replace(/\/+$/, "");
}

function optionalEnv(value: string | undefined) {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function serviceCredentials(bearerToken: string | undefined) {
  return bearerToken ? { serviceCredentials: { bearerToken } } : {};
}

function readBoolean(value: string | undefined, name: string) {
  if (value === undefined || value === "false") {
    return false;
  }
  if (value === "true") {
    return true;
  }
  throw new Error(`INVALID_BOOLEAN_ENV: ${name}`);
}
