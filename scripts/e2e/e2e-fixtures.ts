import { runtimeEnvironment, validateProjectRoot, composeArguments } from "../runtime-environment.js";
import { existsSync, lstatSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";

import {
  buildRuntimeTargets,
  type RuntimeTarget
} from "../wait-for-services.js";

export const E2E_PROJECT_NAME = runtimeEnvironment().projectName;

export const E2E_PROJECT_VOLUME_NAMES = [
  `${E2E_PROJECT_NAME}-hospital-a-metadata-postgres-data`,
  `${E2E_PROJECT_NAME}-clinic-b-metadata-postgres-data`,
  `${E2E_PROJECT_NAME}-hospital-a-postgres-data`,
  `${E2E_PROJECT_NAME}-clinic-b-postgres-data`,
  `${E2E_PROJECT_NAME}-besu-hospital-a-data`,
  `${E2E_PROJECT_NAME}-besu-clinic-b-data`,
  `${E2E_PROJECT_NAME}-besu-auditor-data`,
  `${E2E_PROJECT_NAME}-besu-consortium-data`
] as const;

export interface ProjectVolumeIdentity {
  name: string;
  labels: Record<string, string | undefined>;
}

export const E2E_SCENARIO_IDS = [
  "authorized-consent-read",
  "authorized-general-policy-bruno",
  "authorized-general-policy-daniel",
  "authorized-specialist-policy-carla",
  "tampered-historical-fhir-content",
  "authorized-restored-historical-version",
  "general-policy-role-denied",
  "specialist-policy-role-denied",
  "specialist-policy-specialty-denied",
  "wrong-organization",
  "wrong-practitioner",
  "purpose-mismatch",
  "revoked-consent",
  "expired-consent",
  "policy-version-mismatch",
  "tampered-manifest",
  "tampered-fhir-version", // historical id: version binding in the manifest
  "certificate-token-mismatch",
  "assertion-replay",
  "handoff-replay",
  "blockchain-unavailable",
  "metadata-postgres-unavailable"
] as const;

export type E2EScenarioId = (typeof E2E_SCENARIO_IDS)[number];

export type E2ERequestId = string & { readonly __e2eRequestId: unique symbol };

export function createE2ERequestId(value: string): E2ERequestId {
  if (!/^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new Error("E2E_REQUEST_ID_INVALID");
  }
  return value as E2ERequestId;
}

export const E2E_REQUEST_IDS = {
  authorizedConsentRead: createE2ERequestId("req_00000000-0000-4000-8000-000000000001"),
  wrongPractitioner: createE2ERequestId("req_00000000-0000-4000-8000-000000000002"),
  purposeMismatch: createE2ERequestId("req_00000000-0000-4000-8000-000000000003"),
  tamperedManifest: createE2ERequestId("req_00000000-0000-4000-8000-000000000004"),
  certificateTokenMismatch: createE2ERequestId("req_00000000-0000-4000-8000-000000000005"),
  blockchainUnavailable: createE2ERequestId("req_00000000-0000-4000-8000-000000000006"),
  metadataPostgresUnavailable: createE2ERequestId("req_00000000-0000-4000-8000-000000000007"),
  tamperedFhirVersion: createE2ERequestId("req_00000000-0000-4000-8000-000000000008"),
  expiredConsent: createE2ERequestId("req_00000000-0000-4000-8000-000000000009"),
  revokedConsent: createE2ERequestId("req_00000000-0000-4000-8000-000000000010")
} as const;

export const PROJECT_COMPOSE_FILES = [
  "docker-compose.yml",
  "docker-compose.dev.yml",
  "docker-compose.identity.yml",
  "docker-compose.blockchain.yml"
] as const;

export interface ProjectComposeCommand {
  root: string;
  composeFiles: string[];
  args: string[];
}

export interface E2ECheck {
  service: string;
  status: "ok" | "blocked" | "failed";
  reason?: string;
}

export interface E2EConfig {
  projectRoot: string;
  reportPath: string;
  hospitalAGatewayUrl: string;
  clinicBGatewayUrl: string;
  hospitalAFhirUrl: string;
  clinicBFhirUrl: string;
  keycloakUrl: string;
  hospitalAOidcIssuer: string;
  clinicBOidcIssuer: string;
  hospitalAJwksUrl: string;
  clinicBJwksUrl: string;
  hospitalAMetadataDatabaseUrl: string;
  clinicBMetadataDatabaseUrl: string;
  blockchainRpcUrl: string;
  udapDiscoveryUrl: string;
  clientId: string;
  patientUsername: string;
  patientPassword: string;
  patientClientSecret: string;
  clinicBClientSecret: string;
  hospitalAPractitionerUsername: string;
  hospitalAPractitionerPassword: string;
  clinicBPatientUsername: string;
  clinicBPatientPassword: string;
  clinicBAdministratorUsername: string;
  clinicBAdministratorPassword: string;
  practitionerUsername: string;
  practitionerPassword: string;
  administratorUsername: string;
  administratorPassword: string;
  hospitalATlsCaPath: string;
  clinicBTlsCaPath: string;
  clinicBClientKeyPath: string;
  clinicBClientCertPath: string;
  hospitalAClientKeyPath: string;
  hospitalAClientCertPath: string;
  clinicBSigningKeyPath: string;
  clinicBPublicJwkPath: string;
}

export function assertIsolatedProjectRoot(root = process.cwd()): string {
  const resolved = path.resolve(root);
  const requiredFiles = [
    "package.json",
    "docker-compose.yml",
    "docker-compose.dev.yml",
    "docker-compose.identity.yml",
    "docker-compose.blockchain.yml",
    "scripts",
    "middleware",
    ".git"
  ];
  for (const relativePath of requiredFiles) {
    if (!existsSync(path.join(resolved, relativePath))) {
      throw new Error(`E2E_PROJECT_ROOT_INVALID:${relativePath}`);
    }
  }
  validateProjectRoot(resolved);
  return resolved;
}

export function assertProjectVolumeIdentity(
  volumes: readonly ProjectVolumeIdentity[],
  root = process.cwd(),
  projectName = E2E_PROJECT_NAME
): void {
  const projectRoot = assertIsolatedProjectRoot(root);
  const allowed = new Set<string>(E2E_PROJECT_VOLUME_NAMES);
  for (const volume of volumes) {
    if (!allowed.has(volume.name)) {
      throw new Error(`E2E_PROJECT_VOLUME_UNEXPECTED:${volume.name}`);
    }
    if (volume.labels["com.docker.compose.project"] !== projectName) {
      throw new Error(`E2E_PROJECT_VOLUME_IDENTITY_MISMATCH:${volume.name}:project`);
    }
    const workingDirectory = volume.labels["com.docker.compose.project.working_dir"];
    if (workingDirectory !== undefined) {
      if (workingDirectory.trim().length === 0 || normalizePath(workingDirectory) !== normalizePath(projectRoot)) {
        throw new Error(`E2E_PROJECT_VOLUME_IDENTITY_MISMATCH:${volume.name}:working_dir`);
      }
    }
  }
}

export function buildProjectScopedResetPlan(root = process.cwd()): ProjectComposeCommand[] {
  const projectRoot = assertIsolatedProjectRoot(root);
  return [{ root: projectRoot, composeFiles: [...PROJECT_COMPOSE_FILES], args: [...composeArguments(projectRoot), "down", "--volumes"] }];
}

export function buildProjectScopedDownPlan(root = process.cwd()): ProjectComposeCommand[] {
  const projectRoot = assertIsolatedProjectRoot(root);
  return [{ root: projectRoot, composeFiles: [...PROJECT_COMPOSE_FILES], args: [...composeArguments(projectRoot), "stop"] }];
}

export function buildE2ERuntimeTargets(
  env: Record<string, string | undefined> = process.env
): RuntimeTarget[] {
  const runtimeEnv: Record<string, string | undefined> = {
    ...env,
    RUNTIME_HOSPITAL_A_FHIR_BASE_URL: env.RUNTIME_HOSPITAL_A_FHIR_BASE_URL ?? "http://127.0.0.1:8081/fhir",
    RUNTIME_CLINIC_B_FHIR_BASE_URL: env.RUNTIME_CLINIC_B_FHIR_BASE_URL ?? "http://127.0.0.1:8082/fhir",
    RUNTIME_HOSPITAL_A_METADATA_DATABASE_URL: env.RUNTIME_HOSPITAL_A_METADATA_DATABASE_URL ?? "postgresql://hospital_a_metadata:hospital_a_metadata@127.0.0.1:5433/interfhir_hospital_a_metadata",
    RUNTIME_CLINIC_B_METADATA_DATABASE_URL: env.RUNTIME_CLINIC_B_METADATA_DATABASE_URL ?? "postgresql://clinic_b_metadata:clinic_b_metadata@127.0.0.1:5435/interfhir_clinic_b_metadata",
    RUNTIME_BLOCKCHAIN_RPC_URL: env.RUNTIME_BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546",
    RUNTIME_HOSPITAL_A_GATEWAY_URL: env.RUNTIME_HOSPITAL_A_GATEWAY_URL ?? "https://localhost:3001",
    RUNTIME_CLINIC_B_GATEWAY_URL: env.RUNTIME_CLINIC_B_GATEWAY_URL ?? "https://localhost:3002",
    RUNTIME_HOSPITAL_A_TLS_CA_PATH: env.RUNTIME_HOSPITAL_A_TLS_CA_PATH ?? ".local/pki/ca/ca.crt",
    RUNTIME_HOSPITAL_A_TLS_CERT_PATH: env.RUNTIME_HOSPITAL_A_TLS_CERT_PATH ?? ".local/pki/clinic-b/client.crt",
    RUNTIME_HOSPITAL_A_TLS_KEY_PATH: env.RUNTIME_HOSPITAL_A_TLS_KEY_PATH ?? ".local/pki/clinic-b/client.key",
    RUNTIME_CLINIC_B_TLS_CA_PATH: env.RUNTIME_CLINIC_B_TLS_CA_PATH ?? ".local/pki/ca/ca.crt",
    RUNTIME_CLINIC_B_TLS_CERT_PATH: env.RUNTIME_CLINIC_B_TLS_CERT_PATH ?? ".local/pki/hospital-a/client.crt",
    RUNTIME_CLINIC_B_TLS_KEY_PATH: env.RUNTIME_CLINIC_B_TLS_KEY_PATH ?? ".local/pki/hospital-a/client.key",
    RUNTIME_HOSPITAL_A_JWKS_URI: env.RUNTIME_HOSPITAL_A_JWKS_URI ?? "http://127.0.0.1:8180/realms/hospital-a/protocol/openid-connect/certs",
    RUNTIME_CLINIC_B_JWKS_URI: env.RUNTIME_CLINIC_B_JWKS_URI ?? "http://127.0.0.1:8180/realms/clinic-b/protocol/openid-connect/certs",
    UDAP_ENABLED: "true",
    UDAP_CLINIC_B_ENABLED: "true",
    UDAP_BASE_URL: env.UDAP_BASE_URL ?? "https://localhost:3001",
    UDAP_DISCOVERY_URL: env.UDAP_DISCOVERY_URL ?? "https://localhost:3001/fhir/.well-known/udap",
    UDAP_CLINIC_B_DISCOVERY_URL: env.UDAP_CLINIC_B_DISCOVERY_URL ?? "https://localhost:3001/fhir/.well-known/udap"
  };

  const keycloakBase = env.KEYCLOAK_HOST_URL ?? "http://127.0.0.1:8180";
  const keycloakManagementBase = env.KEYCLOAK_MANAGEMENT_HOST_URL ?? "http://127.0.0.1:8190";
  return [
    {
      service: "keycloak",
      endpoint: `${keycloakManagementBase}/health/ready`,
      kind: "http",
      remediation: "Start Keycloak and wait for the management health endpoint."
    },
    {
      service: "hospital-a-oidc",
      endpoint: `${keycloakBase}/realms/hospital-a/.well-known/openid-configuration`,
      kind: "http",
      remediation: "Import the Hospital A realm and verify its OIDC discovery document."
    },
    {
      service: "clinic-b-oidc",
      endpoint: `${keycloakBase}/realms/clinic-b/.well-known/openid-configuration`,
      kind: "http",
      remediation: "Import the Clínica B realm and verify its OIDC discovery document."
    },
    ...buildRuntimeTargets(runtimeEnv)
  ];
}

export function loadE2EConfig(
  env: Record<string, string | undefined> = process.env,
  root = process.cwd()
): E2EConfig {
  const projectRoot = assertIsolatedProjectRoot(root);
  const keycloakUrl = env.KEYCLOAK_HOST_URL ?? "http://127.0.0.1:8180";
  return {
    projectRoot,
    reportPath: path.join(projectRoot, "reports", "e2e-latest.json"),
    hospitalAGatewayUrl: env.E2E_HOSPITAL_A_GATEWAY_URL ?? "https://localhost:3001",
    clinicBGatewayUrl: env.E2E_CLINIC_B_GATEWAY_URL ?? "https://localhost:3002",
    hospitalAFhirUrl: env.E2E_HOSPITAL_A_FHIR_URL ?? "http://127.0.0.1:8081/fhir",
    clinicBFhirUrl: env.E2E_CLINIC_B_FHIR_URL ?? "http://127.0.0.1:8082/fhir",
    keycloakUrl,
    hospitalAOidcIssuer: env.E2E_HOSPITAL_A_OIDC_ISSUER ?? "http://keycloak:8080/realms/hospital-a",
    clinicBOidcIssuer: env.E2E_CLINIC_B_OIDC_ISSUER ?? "http://keycloak:8080/realms/clinic-b",
    hospitalAJwksUrl: env.E2E_HOSPITAL_A_JWKS_URL ?? `${keycloakUrl}/realms/hospital-a/protocol/openid-connect/certs`,
    clinicBJwksUrl: env.E2E_CLINIC_B_JWKS_URL ?? `${keycloakUrl}/realms/clinic-b/protocol/openid-connect/certs`,
    hospitalAMetadataDatabaseUrl: env.E2E_HOSPITAL_A_METADATA_DATABASE_URL ?? "postgresql://hospital_a_metadata:hospital_a_metadata@127.0.0.1:5433/interfhir_hospital_a_metadata",
    clinicBMetadataDatabaseUrl: env.E2E_CLINIC_B_METADATA_DATABASE_URL ?? "postgresql://clinic_b_metadata:clinic_b_metadata@127.0.0.1:5435/interfhir_clinic_b_metadata",
    blockchainRpcUrl: env.E2E_BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546",
    udapDiscoveryUrl: env.E2E_UDAP_DISCOVERY_URL ?? "https://localhost:3001/fhir/.well-known/udap",
    clientId: env.E2E_UDAP_CLIENT_ID ?? "clinic-b-gateway",
    patientUsername: env.E2E_PATIENT_USERNAME ?? "paciente.ana",
    patientPassword: env.E2E_PATIENT_PASSWORD ?? "local-only-ana-password",
    patientClientSecret: env.E2E_PATIENT_CLIENT_SECRET ?? "local-only-hospital-a-api-secret",
    clinicBClientSecret: env.E2E_CLINIC_B_CLIENT_SECRET ?? "local-only-clinic-b-api-secret",
    hospitalAPractitionerUsername: env.E2E_HOSPITAL_A_PRACTITIONER_USERNAME ?? "profissional.ana",
    hospitalAPractitionerPassword: env.E2E_HOSPITAL_A_PRACTITIONER_PASSWORD ?? "local-only-professional-password",
    clinicBPatientUsername: env.E2E_CLINIC_B_PATIENT_USERNAME ?? "paciente.ana",
    clinicBPatientPassword: env.E2E_CLINIC_B_PATIENT_PASSWORD ?? "local-only-ana-password",
    clinicBAdministratorUsername: env.E2E_CLINIC_B_ADMINISTRATOR_USERNAME ?? "admin.clinica",
    clinicBAdministratorPassword: env.E2E_CLINIC_B_ADMINISTRATOR_PASSWORD ?? "local-only-admin-password",
    practitionerUsername: env.E2E_PRACTITIONER_USERNAME ?? "profissional.bruno",
    practitionerPassword: env.E2E_PRACTITIONER_PASSWORD ?? "local-only-bruno-password",
    administratorUsername: env.E2E_ADMINISTRATOR_USERNAME ?? "admin.hospital",
    administratorPassword: env.E2E_ADMINISTRATOR_PASSWORD ?? "local-only-admin-password",
    hospitalATlsCaPath: path.resolve(projectRoot, env.E2E_TLS_CA_PATH ?? ".local/pki/ca/ca.crt"),
    clinicBTlsCaPath: path.resolve(projectRoot, env.E2E_TLS_CA_PATH ?? ".local/pki/ca/ca.crt"),
    clinicBClientKeyPath: path.resolve(projectRoot, env.E2E_CLINIC_B_TLS_KEY_PATH ?? ".local/pki/clinic-b/client.key"),
    clinicBClientCertPath: path.resolve(projectRoot, env.E2E_CLINIC_B_TLS_CERT_PATH ?? ".local/pki/clinic-b/client.crt"),
    hospitalAClientKeyPath: path.resolve(projectRoot, env.E2E_HOSPITAL_A_TLS_CLIENT_KEY_PATH ?? ".local/pki/hospital-a/client.key"),
    hospitalAClientCertPath: path.resolve(projectRoot, env.E2E_HOSPITAL_A_TLS_CLIENT_CERT_PATH ?? ".local/pki/hospital-a/client.crt"),
    clinicBSigningKeyPath: path.resolve(projectRoot, env.E2E_UDAP_SIGNING_KEY_PATH ?? ".local/udap/clinic-b-client-signing.key"),
    clinicBPublicJwkPath: path.resolve(projectRoot, env.E2E_UDAP_PUBLIC_JWK_PATH ?? ".local/udap/clinic-b-client-public-jwk.json")
  };
}

export async function readJsonFile<T>(filePath: string): Promise<T> {
  return JSON.parse(await readFile(filePath, "utf8")) as T;
}

function composeCommand(root: string, composeFiles: string[], operation: string[]): ProjectComposeCommand {
  return {
    root,
    composeFiles,
    args: [
      "compose",
      "--project-name",
      E2E_PROJECT_NAME,
      "--project-directory",
      root,
      ...composeFiles.flatMap((file) => ["--file", path.join(root, file)]),
      ...operation
    ]
  };
}

function normalizePath(value: string): string {
  return path.resolve(value).replaceAll("\\", "/").replace(/\/$/, "").toLowerCase();
}
