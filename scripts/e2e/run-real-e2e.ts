import { observeDelivery, writeRunArtifact } from "../scientific/evidence.js";
import { applyRuntimeEnvironment, runtimePreflight, runtimeEnvironment, composeArguments, assertOwnedResources, COMPOSE_FILES } from "../runtime-environment.js";
import { spawn, execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, writeFile, mkdir, unlink } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import path from "node:path";

import { Contract, JsonRpcProvider, Interface } from "ethers";
import {
  createRemoteJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importPKCS8,
  jwtVerify,
  SignJWT,
  type JWK
} from "jose";
import pg from "pg";

import {
  assertNegativeResponse,
  assertReadinessGate,
  assertSanitizedE2EReport,
  assertConsentProjectionChain,
  createEnvironmentBlockedReport,
  createFailedE2EReport,
  pseudonymousHash,
  type E2EHttpResponse,
  type E2EReport,
  type E2EScenarioReport
} from "./e2e-assertions.js";
import {
  assertIsolatedProjectRoot,
  buildE2ERuntimeTargets,
  buildProjectScopedDownPlan,
  E2E_SCENARIO_IDS,
  E2E_REQUEST_IDS,
  E2E_PROJECT_NAME,
  loadE2EConfig,
  readJsonFile,
  type E2ECheck,
  type E2EConfig,
  type E2ERequestId,
  type E2EScenarioId,
  type ProjectComposeCommand
} from "./e2e-fixtures.js";
import {
  checkRuntimeDependency,
  waitForRuntimeDependencies,
  type RuntimeDependencyResult,
  type RuntimeTarget
} from "../wait-for-services.js";
import { certificateIdentityFromPem } from "../../middleware/src/pki/certificate-identity.js";
import { createUdapClient, type UdapClientTlsOptions, type UdapDiscoveryMetadata, type UdapHttpFetch } from "../../middleware/src/udap/udap-client.js";
import { createRequestingInstitutionClient, type ReadShareResponse } from "../../middleware/src/interfhir/requesting-institution-client.js";
import { hashFhirResource } from "../../middleware/src/fhir/resource-hasher.js";
import { mapFhirConsentToRegisterConsentInput } from "../../middleware/src/fhir/consent-mapper.js";
import { computeManifestCommitment, type ResourceManifestVersion } from "../../middleware/src/manifest/resource-manifest.js";
import { readPatientAnaAddress, readPersistentDeployment, readPublicNetwork, verifyPersistentDeployment } from "../read-deployment.js";
import { GENERAL_TREATMENT_POLICY, SPECIALIST_REVIEW_POLICY, VARIATION_PRACTITIONERS } from "./policy-variation-fixtures.js";
import { createHistoricalObservationStore, withHistoricalObservationMutation } from "./historical-fhir-mutation.js";

const { Client } = pg;

export const EXPECTED_DENIAL_STATUSES: Readonly<Record<E2EScenarioId, readonly number[]>> = {
  "authorized-consent-read": [],
  "authorized-general-policy-bruno": [],
  "authorized-general-policy-daniel": [],
  "authorized-specialist-policy-carla": [],
  "tampered-historical-fhir-content": [403],
  "authorized-restored-historical-version": [],
  "general-policy-role-denied": [403],
  "specialist-policy-role-denied": [403],
  "specialist-policy-specialty-denied": [403],
  "wrong-organization": [403],
  "wrong-practitioner": [403],
  "purpose-mismatch": [403],
  "revoked-consent": [403],
  "expired-consent": [403],
  "policy-version-mismatch": [400],
  "tampered-manifest": [409],
  "tampered-fhir-version": [409],
  "certificate-token-mismatch": [403],
  "assertion-replay": [409],
  "handoff-replay": [409],
  "blockchain-unavailable": [503],
  "metadata-postgres-unavailable": [503]
};

const EXPECTED_DENIAL_REASONS: Partial<Record<E2EScenarioId, string>> = {
  "general-policy-role-denied": "ACCESS_DENIED", "specialist-policy-role-denied": "ACCESS_DENIED", "specialist-policy-specialty-denied": "ACCESS_DENIED",
  "tampered-historical-fhir-content": "MANIFEST_RESOURCE_HASH_MISMATCH",
  "wrong-organization": "UDAP_ORGANIZATION_MISMATCH", "wrong-practitioner": "CONSENT_PRACTITIONER_MISMATCH",
  "purpose-mismatch": "UDAP_PURPOSE_NOT_ALLOWED", "revoked-consent": "SHARE_NOT_ACTIVE",
  "expired-consent": "SHARE_OUTSIDE_VALIDITY_PERIOD", "policy-version-mismatch": "UNKNOWN_NETWORK_POLICY_VERSION",
  "tampered-manifest": "MANIFEST_STORED_COMMITMENT_MISMATCH", "tampered-fhir-version": "MANIFEST_COMMITMENT_MISMATCH",
  "certificate-token-mismatch": "CERTIFICATE_ORGANIZATION_MISMATCH", "assertion-replay": "UDAP_ASSERTION_REPLAY",
  "handoff-replay": "HANDOFF_CODE_ALREADY_REDEEMED", "blockchain-unavailable": "BLOCKCHAIN_UNAVAILABLE",
  "metadata-postgres-unavailable": "METADATA_STORE_UNAVAILABLE"
};

const DEFAULT_SUBPROCESS_TIMEOUT_MS = 120_000;
export const DEFAULT_COMPOSE_TIMEOUT_MS = 600_000;
export const KEYCLOAK_CONTAINER_HOSTNAME = "http://keycloak:8080";
const MIN_COMPOSE_TIMEOUT_MS = 1_000;
const MAX_COMPOSE_TIMEOUT_MS = 1_800_000;
export const DEFAULT_NETWORK_TIMEOUT_MS = 60_000;

export function createE2EIdempotencyKey(operation: string, executionId: string = randomUUID()): string {
  return `e2e-${operation}-${executionId}`;
}

export interface E2ETemporaryFileScope {
  register(filePath: string): void;
  cleanup(): Promise<void>;
}

export function createE2ETemporaryFileScope(): E2ETemporaryFileScope {
  const files = new Set<string>();
  return {
    register(filePath) {
      files.add(path.resolve(filePath));
    },
    async cleanup() {
      const failures: string[] = [];
      for (const filePath of files) {
        try {
          await unlink(filePath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") failures.push(path.basename(filePath));
        }
      }
      if (failures.length > 0) throw new Error("E2E_TEMPORARY_FILE_CLEANUP_FAILED");
    }
  };
}

export async function withE2ETemporaryFiles<T>(operation: (scope: E2ETemporaryFileScope) => Promise<T>): Promise<T> {
  const scope = createE2ETemporaryFileScope();
  try {
    return await operation(scope);
  } finally {
    await scope.cleanup();
  }
}

const CONSENT_REQUEST = {
  granteeOrganizationReference: "Organization/clinic-b",
  practitionerReference: "Practitioner/bruno",
  resourceReference: "Observation/obs-ana-1",
  purposeOfUse: "TREAT",
  policyId: "POLICY_TREATMENT_OBSERVATION",
  policyVersion: 1
} as const;

const LIVE_LIMITATIONS = [
  "This local E2E is an integration proof, not a production capacity or throughput claim.",
  "The report contains only states, counts, pseudonymous hashes and sanitized reasons."
];

interface OidcToken {
  value: string;
  claims: Record<string, unknown>;
}

export interface KeycloakDemoUserProfile {
  id: string;
  realm: string;
  username: string;
  password: string;
  clientSecret: string;
  issuer: string;
  jwksUrl: string;
  expectedClaims: Record<string, string>;
}

export function buildKeycloakDemoUserProfiles(config: Record<string, string>): KeycloakDemoUserProfile[] {
  return [
    {
      id: "hospital-a-patient",
      realm: "hospital-a",
      username: config.patientUsername,
      password: config.patientPassword,
      clientSecret: config.patientClientSecret,
      issuer: config.hospitalAOidcIssuer,
      jwksUrl: config.hospitalAJwksUrl,
      expectedClaims: { role: "patient", patientReference: "Patient/pat-ana", organizationReference: "Organization/hospital-a" }
    },
    {
      id: "hospital-a-practitioner",
      realm: "hospital-a",
      username: config.hospitalAPractitionerUsername,
      password: config.hospitalAPractitionerPassword,
      clientSecret: config.patientClientSecret,
      issuer: config.hospitalAOidcIssuer,
      jwksUrl: config.hospitalAJwksUrl,
      expectedClaims: { role: "practitioner", practitionerReference: "Practitioner/ana", organizationReference: "Organization/hospital-a" }
    },
    {
      id: "hospital-a-administrator",
      realm: "hospital-a",
      username: config.administratorUsername,
      password: config.administratorPassword,
      clientSecret: config.patientClientSecret,
      issuer: config.hospitalAOidcIssuer,
      jwksUrl: config.hospitalAJwksUrl,
      expectedClaims: { role: "administrator", organizationReference: "Organization/hospital-a" }
    },
    {
      id: "clinic-b-patient",
      realm: "clinic-b",
      username: config.clinicBPatientUsername,
      password: config.clinicBPatientPassword,
      clientSecret: config.clinicBClientSecret,
      issuer: config.clinicBOidcIssuer,
      jwksUrl: config.clinicBJwksUrl,
      expectedClaims: { role: "patient", patientReference: "Patient/pat-ana", organizationReference: "Organization/clinic-b" }
    },
    {
      id: "clinic-b-practitioner",
      realm: "clinic-b",
      username: config.practitionerUsername,
      password: config.practitionerPassword,
      clientSecret: config.clinicBClientSecret,
      issuer: config.clinicBOidcIssuer,
      jwksUrl: config.clinicBJwksUrl,
      expectedClaims: { role: "practitioner", practitionerReference: "Practitioner/bruno", organizationReference: "Organization/clinic-b" }
    },
    {
      id: "clinic-b-administrator",
      realm: "clinic-b",
      username: config.clinicBAdministratorUsername,
      password: config.clinicBAdministratorPassword,
      clientSecret: config.clinicBClientSecret,
      issuer: config.clinicBOidcIssuer,
      jwksUrl: config.clinicBJwksUrl,
      expectedClaims: { role: "administrator", organizationReference: "Organization/clinic-b" }
    }
  ];
}

export function assertKeycloakDemoUserClaims(profile: Pick<KeycloakDemoUserProfile, "id" | "expectedClaims">, claims: Record<string, unknown>): void {
  for (const [claim, expected] of Object.entries(profile.expectedClaims)) {
    if (claims[claim] !== expected) throw new Error(`OIDC_CLAIM_INVALID:${profile.id}:${claim}`);
  }
}

interface RealUdapSession {
  client: ReturnType<typeof createUdapClient>;
  metadata: UdapDiscoveryMetadata;
  token: string;
  tls: UdapClientTlsOptions;
  fetch: UdapHttpFetch;
}

interface ManifestDatabaseRow {
  manifest_id: string;
  share_id: string;
  version: number;
  status: ResourceManifestVersion["status"];
  custodian_organization_reference: string;
  grantee_organization_reference: string;
  resource_reference: string;
  resource_type: string;
  fhir_version_id: string;
  subject_reference: string;
  consent_reference_hash: string;
  consent_projection_hash: string;
  resource_hash: string;
  previous_version_commitment: string;
  commitment: string;
  signing_key_id: string;
  signature: string;
  created_at: Date | string;
  updated_at: Date | string | null;
}

interface LiveContext {
  config: E2EConfig;
  patientToken: string;
  practitionerToken: string;
  administratorToken: string;
  consent: Record<string, unknown>;
  requester: RealUdapSession;
  handoffCode: string;
  shareId: string;
  manifestId: string;
  read: ReadShareResponse;
  originalManifestRow: ManifestDatabaseRow;
}

export async function main(argv: string[] = process.argv.slice(2)) {
  const lifecycleCommand = process.env.npm_lifecycle_event?.split(":").at(-1);
  const command = argv[0] ?? lifecycleCommand ?? "run";
  applyRuntimeEnvironment();
  const root = assertIsolatedProjectRoot(process.cwd());
  const config = loadE2EConfig(process.env, root);

  if (command === "refresh-gateways") {
    assertOwnedResources(config.projectRoot);
    await prepareLocalArtifacts(config);
    await withE2ETemporaryFiles(async scope => {
      await runCompose(config, COMPOSE_FILES, ["--profile", "gateways", "up", "-d", "--build", "--no-deps", "hospital-a-gateway", "clinic-b-gateway"], await writeComposeEnvironment(config, scope));
    });
    return;
  }
  if (command === "up") {
    await bringUpRuntime(config);
    return;
  }
  if (command === "wait") {
    const checks = await waitForE2ERuntime(config, true);
    printJson({ status: "ready", checks });
    return;
  }
  if (command === "down") {
    await runComposePlan(buildProjectScopedDownPlan(root), config);
    return;
  }
  if (command === "run") {
    await runE2E(config);
    return;
  }
  throw new Error(`E2E_COMMAND_INVALID:${command}`);
}

async function bringUpRuntime(config: E2EConfig) {
  const temporaryFiles = createE2ETemporaryFileScope();
  let startupSucceeded = false;
  try {
    await runtimePreflight(config.projectRoot);
    await prepareLocalArtifacts(config);
    const composeEnv = await writeComposeEnvironment(config, temporaryFiles);

    await runCompose(config, ["docker-compose.blockchain.yml"], ["up", "-d", "besu-hospital-a-validator", "besu-clinic-b-validator", "besu-auditor-validator", "besu-consortium-validator"], composeEnv);
    await runCompose(config, ["docker-compose.identity.yml"], ["up", "-d", "keycloak"], composeEnv);
    await runCompose(config, ["docker-compose.yml", "docker-compose.dev.yml"], ["up", "-d", "--build", "hospital-a-fhir", "clinic-b-fhir", "hospital-a-metadata-postgres", "clinic-b-metadata-postgres"], composeEnv);
    await waitForE2ERuntime(config, false);

    await runProjectNpm(config, "deploy:rpc", { E2E_ALLOW_STALE_DEPLOYMENT_REDEPLOY: "true" });
    await runProjectNpm(config, "network:bootstrap");
    await runProcess(process.execPath, ["scripts/run-hardhat.cjs", "run", "--no-compile", "scripts/e2e/prepare-policy-variations.ts"], config.projectRoot, { BLOCKCHAIN_RPC_URL: config.blockchainRpcUrl });
    const finalComposeEnv = await writeComposeEnvironment(config, temporaryFiles);
    await runCompose(config, [
      "docker-compose.yml",
      "docker-compose.dev.yml",
      "docker-compose.identity.yml",
      "docker-compose.blockchain.yml"
    ], ["--profile", "gateways", "up", "-d", "--build"], finalComposeEnv);
    await waitForE2ERuntime(config, true);
    const oidcGate = await runKeycloakOidcGate(config);
    startupSucceeded = true;
    printJson({ status: "ready", phase: "compose-and-persistent-bootstrap", oidc: oidcGate });
  } finally {
    try {
      await temporaryFiles.cleanup();
    } catch {
      console.error("E2E_TEMPORARY_FILE_CLEANUP_FAILED");
      process.exitCode = 1;
    }
    if (!startupSucceeded) console.error("E2E_STARTUP_FAILED_STATE_PRESERVED");
  }
}

async function runE2E(config: E2EConfig) {
  const temporaryFiles = createE2ETemporaryFileScope();
  let checks: RuntimeDependencyResult[] = [];
  const completed: E2EScenarioReport[] = [];
  try {
    checks = await waitForE2ERuntime(config, true, false);
    const failedCheck = checks.find((check) => check.status !== "ok");
    if (failedCheck) {
      await writeReport(config, createEnvironmentBlockedReport({
        generatedAt: new Date().toISOString(),
        reason: failedCheck.lastError ?? "DEPENDENCY_UNAVAILABLE",
        checks: checks.map(toE2ECheck)
      }));
      process.exitCode = 2;
      return;
    }

    await runKeycloakOidcGate(config);
    const context = await executeLiveFlow(config, completed, temporaryFiles);
    await writeReport(config, createLiveReport(checks, completed, context));
    if (completed.some((scenario) => scenario.status !== "passed")) process.exitCode = 1;
  } catch (error) {
    const reason = safeError(error);
    console.error(`E2E_RUN_FAILED:${reason}`);
    const blocked = isEnvironmentFailure(error) && completed.length === 0;
    const report = blocked
      ? createEnvironmentBlockedReport({ generatedAt: new Date().toISOString(), reason, checks: checks.map(toE2ECheck) })
      : createFailedE2EReport({ generatedAt: new Date().toISOString(), reason, checks: checks.map(toE2ECheck), completed });
    await writeReport(config, report);
    process.exitCode = blocked ? 2 : 1;
  } finally {
    try {
      await temporaryFiles.cleanup();
    } catch {
      console.error("E2E_TEMPORARY_FILE_CLEANUP_FAILED");
      process.exitCode = 1;
    }
  }
}

async function executeLiveFlow(config: E2EConfig, completed: E2EScenarioReport[], temporaryFiles: E2ETemporaryFileScope): Promise<LiveContext> {
  await verifyPersistentBesu(config);
  await seedAndValidateFixtures(config);
  const executionId = randomUUID();
  const profiles = buildKeycloakDemoUserProfiles(config as unknown as Record<string, string>);
  const patient = await issueOidcToken(config, requireKeycloakDemoUserProfile(profiles, "hospital-a-patient"));
  const practitioner = await issueOidcToken(config, requireKeycloakDemoUserProfile(profiles, "clinic-b-practitioner"));
  const administrator = await issueOidcToken(config, requireKeycloakDemoUserProfile(profiles, "hospital-a-administrator"));

  const consentResponse = await postGatewayJson(config, "/patient/consents", patient.value, {
    ...CONSENT_REQUEST,
    validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
  }, { "idempotency-key": createE2EIdempotencyKey("consent", executionId) });
  requireStatus(consentResponse, 201, "PATIENT_CONSENT_CREATE");
  const consent = requireRecord(consentResponse.body, "PATIENT_CONSENT_RESPONSE_INVALID");
  await validateConsentProjection(config, consent);

  const requester = await createRealUdapSession(config);
  const handoffCode = requireString(consent, "handoffCode");
  const shareId = requireString(consent, "shareId");
  const manifestId = requireString(consent, "manifestId");
  const requesterClient = createRequestingInstitutionClient({
    custodianBaseUrl: new URL(requester.metadata.registration_endpoint).origin,
    tls: requester.tls,
    fetch: requester.fetch
  });
  const redeemed = await requesterClient.redeemHandoff({ handoffCode, udapToken: requester.token });
  if (redeemed.shareId !== shareId || !redeemed.manifests.some((manifest) => manifest.manifestId === manifestId)) {
    throw new Error("E2E_GRANT_MANIFEST_SCOPE_INVALID");
  }
  const accessRequestId = `req_${randomUUID()}`;
  const read = await requesterClient.readShare({
    shareId,
    manifestId,
    resourceType: "Observation",
    purposeOfUse: "TREAT",
    requestId: accessRequestId,
    udapToken: requester.token
  });
  const observedReads = await validateAuthorizedRead(config, read, accessRequestId);
  const originalManifestRow = await readManifestRow(config, manifestId);
  completed.push({ ...passedScenario("authorized-consent-read", 200, "PERMIT", observedReads), responseHash: pseudonymousHash(read) });

  await executePolicyVariations(config, completed, patient.value, executionId);
  // A larger campaign must use fresh credentials rather than test token expiry
  // accidentally while exercising an unrelated control.
  Object.assign(requester, await createRealUdapSession(config));
  patient.value = (await issueOidcToken(config, requireKeycloakDemoUserProfile(profiles, "hospital-a-patient"))).value;

  await executeDenied(completed, "wrong-organization", async () => {
    const invalidClient = await createUdapClientSession(config, "Organization/hospital-a", "Practitioner/bruno", "TREAT", false);
    return requestUdapToken(invalidClient, invalidClient.metadata, invalidClient.assertion);
  });
  await executeDenied(completed, "wrong-practitioner", async () => {
    const session = await createUdapClientSession(config, "Organization/clinic-b", "Practitioner/ana", "TREAT");
    const token = requireTokenResponse(await requestUdapToken(session, session.metadata, session.assertion));
    return requesterReadRaw(session.fetch, session.metadata, token, requester.tls, shareId, manifestId, "TREAT", E2E_REQUEST_IDS.wrongPractitioner);
  });
  await executeDenied(completed, "purpose-mismatch", async () => {
    const session = await createUdapClientSession(config, "Organization/clinic-b", "Practitioner/bruno", "HPAYMT");
    return requestUdapToken(session, session.metadata, session.assertion);
  });
  await executeDenied(completed, "tampered-manifest", async () => {
    try {
      await tamperManifest(config, manifestId, originalManifestRow.resource_hash);
      return await requesterReadRaw(requester.fetch, requester.metadata, requester.token, requester.tls, shareId, manifestId, "TREAT", E2E_REQUEST_IDS.tamperedManifest);
    } finally {
      await restoreManifest(config, manifestId, originalManifestRow);
    }
  });
  await executeDenied(completed, "certificate-token-mismatch", async () => {
    const wrongTls = await readTls(config.hospitalAClientKeyPath, config.hospitalAClientCertPath, config.hospitalATlsCaPath);
    return requesterReadRaw(requester.fetch, requester.metadata, requester.token, wrongTls, shareId, manifestId, "TREAT", E2E_REQUEST_IDS.certificateTokenMismatch);
  });
  await executeDenied(completed, "assertion-replay", async () => {
    const session = await createUdapClientSession(config, "Organization/clinic-b", "Practitioner/bruno", "TREAT");
    const first = await requestUdapToken(session, session.metadata, session.assertion);
    if (first.status < 200 || first.status >= 300) throw new Error("E2E_ASSERTION_FIRST_REQUEST_FAILED");
    return requestUdapToken(session, session.metadata, session.assertion);
  });
  await executeDenied(completed, "handoff-replay", async () =>
    requesterRedeemRaw(requester.fetch, requester.metadata, requester.tls, requester.token, handoffCode));
  await executeDenied(completed, "blockchain-unavailable", async () => {
    await runCompose(config, ["docker-compose.blockchain.yml"], ["stop", "besu-hospital-a-validator"], await writeComposeEnvironment(config, temporaryFiles));
    try {
      return await requesterReadRaw(requester.fetch, requester.metadata, requester.token, requester.tls, shareId, manifestId, "TREAT", E2E_REQUEST_IDS.blockchainUnavailable);
    } finally {
      await runCompose(config, ["docker-compose.blockchain.yml"], ["start", "besu-hospital-a-validator"], await writeComposeEnvironment(config, temporaryFiles));
      await waitForTarget(config, buildE2ERuntimeTargets(process.env).find((target) => target.service === "besu-hospital-a-validator")!);
    }
  });
  await executeDenied(completed, "metadata-postgres-unavailable", async () => {
    await runCompose(config, ["docker-compose.yml", "docker-compose.dev.yml"], ["stop", "hospital-a-metadata-postgres"], await writeComposeEnvironment(config, temporaryFiles));
    try {
      return await requesterReadRaw(requester.fetch, requester.metadata, requester.token, requester.tls, shareId, manifestId, "TREAT", E2E_REQUEST_IDS.metadataPostgresUnavailable);
    } finally {
      await runCompose(config, ["docker-compose.yml", "docker-compose.dev.yml"], ["start", "hospital-a-metadata-postgres"], await writeComposeEnvironment(config, temporaryFiles));
      await waitForTarget(config, buildE2ERuntimeTargets(process.env).find((target) => target.service === "hospital-a-metadata-postgres")!);
    }
  });
  await executeDenied(completed, "tampered-fhir-version", async () => {
    try {
      // Legacy scenario id retained for comparison with immutable reports. This
      // mutates the manifest's version binding, not HAPI's historical JSON.
      const mutation = buildTamperedManifestVersionMutation(originalManifestRow);
      await tamperManifestVersion(config, manifestId, mutation);
      return await requesterReadRaw(requester.fetch, requester.metadata, requester.token, requester.tls, shareId, manifestId, "TREAT", E2E_REQUEST_IDS.tamperedFhirVersion);
    } finally {
      await restoreManifest(config, manifestId, originalManifestRow);
    }
  });
  await executeDenied(completed, "policy-version-mismatch", async () =>
    postGatewayJson(config, "/patient/consents", patient.value, {
      ...CONSENT_REQUEST,
      policyVersion: 999,
      validUntil: new Date(Date.now() + 60_000).toISOString()
    }, { "idempotency-key": createE2EIdempotencyKey("policy-version-mismatch", executionId) }));

  const expiring = await postGatewayJson(config, "/patient/consents", patient.value, {
    ...CONSENT_REQUEST,
    validUntil: new Date(Date.now() + 45_000).toISOString()
  }, { "idempotency-key": createE2EIdempotencyKey("expiring-consent", executionId) });
  requireStatus(expiring, 201, "EXPIRING_CONSENT_CREATE");
  const expiringBody = requireRecord(expiring.body, "EXPIRING_CONSENT_RESPONSE_INVALID");
  const expiringRedeemed = await requesterClient.redeemHandoff({
    handoffCode: requireString(expiringBody, "handoffCode"),
    udapToken: requester.token
  });
  await delay(46_000);
  await executeDenied(completed, "expired-consent", async () =>
    requesterReadRaw(requester.fetch, requester.metadata, requester.token, requester.tls, expiringRedeemed.shareId, requireString(expiringBody, "manifestId"), "TREAT", E2E_REQUEST_IDS.expiredConsent));

  const revoke = await postGatewayJson(config, `/patient/consents/${encodeURIComponent(requireString(consent, "consentReference"))}/revoke`, patient.value, undefined);
  requireStatus(revoke, 200, "CONSENT_REVOKE");
  await executeDenied(completed, "revoked-consent", async () =>
    requesterReadRaw(requester.fetch, requester.metadata, requester.token, requester.tls, shareId, manifestId, "TREAT", E2E_REQUEST_IDS.revokedConsent));

  return {
    config,
    patientToken: patient.value,
    practitionerToken: practitioner.value,
    administratorToken: administrator.value,
    consent,
    requester,
    handoffCode,
    shareId,
    manifestId,
    read,
    originalManifestRow
  };
}

async function executePolicyVariations(config: E2EConfig, completed: E2EScenarioReport[], patientToken: string, executionId: string) {
  for (const practitioner of VARIATION_PRACTITIONERS) {
    const result = await getJson(`${config.hospitalAFhirUrl}/${practitioner.reference}`, {
      method: "PUT", headers: { "content-type": "application/fhir+json" },
      body: JSON.stringify({ resourceType: "Practitioner", id: practitioner.reference.split("/")[1], active: true })
    });
    if (![200, 201].includes(result.status)) throw new Error("E2E_VARIATION_PRACTITIONER_SEED_FAILED");
  }
  const specialistId = "obs-ana-specialist";
  const writeObservation = async (value: number) => {
    const result = await getJson(`${config.hospitalAFhirUrl}/Observation/${specialistId}`, {
      method: "PUT", headers: { "content-type": "application/fhir+json" },
      body: JSON.stringify({ resourceType: "Observation", id: specialistId, status: "final", code: { text: "Synthetic specialist measurement" }, subject: { reference: "Patient/pat-ana" }, valueQuantity: { value, unit: "/min" } })
    });
    if (![200, 201].includes(result.status)) throw new Error("E2E_VARIATION_FHIR_WRITE_FAILED");
    return requireString(requireRecord(requireRecord(result.body, "E2E_VARIATION_FHIR_INVALID").meta, "E2E_VARIATION_VERSION_INVALID"), "versionId");
  };
  const firstVersion = await writeObservation(80);
  const pinnedVersion = await writeObservation(82);
  if (firstVersion === pinnedVersion) throw new Error("E2E_VARIATION_VERSION_NOT_ADVANCED");

  const prepareShare = async (policy: typeof GENERAL_TREATMENT_POLICY, resourceReference: string) => {
    const result = await postGatewayJson(config, "/patient/consents", patientToken, {
      granteeOrganizationReference: "Organization/clinic-b", resourceReference, purposeOfUse: "TREAT",
      policyId: policy.policyId, policyVersion: policy.version,
      validUntil: new Date(Date.now() + 3_600_000).toISOString()
    }, { "idempotency-key": createE2EIdempotencyKey(policy.policyId, executionId) });
    requireStatus(result, 201, "E2E_VARIATION_CONSENT_CREATE");
    const consent = requireRecord(result.body, "E2E_VARIATION_CONSENT_INVALID");
    const projection = await validateConsentProjection(config, consent);
    if (projection.actorConstraintHash !== "0x" + "0".repeat(64)) throw new Error("E2E_VARIATION_ACTOR_MUST_BE_UNCONSTRAINED");
    const session = await createRealUdapSession(config);
    const client = createRequestingInstitutionClient({ custodianBaseUrl: new URL(session.metadata.registration_endpoint).origin, tls: session.tls, fetch: session.fetch });
    const redeemed = await client.redeemHandoff({ handoffCode: requireString(consent, "handoffCode"), udapToken: session.token });
    const shareId = requireString(consent, "shareId"), manifestId = requireString(consent, "manifestId");
    if (redeemed.shareId !== shareId || !redeemed.manifests.some(m => m.manifestId === manifestId)) throw new Error("E2E_VARIATION_GRANT_MISMATCH");
    return { shareId, manifestId };
  };
  const generalShare = await prepareShare(GENERAL_TREATMENT_POLICY, "Observation/obs-ana-1");
  const specialistShare = await prepareShare(SPECIALIST_REVIEW_POLICY, `Observation/${specialistId}`);
  const currentSpecialistVersion = await writeObservation(84);
  if (currentSpecialistVersion === pinnedVersion) throw new Error("E2E_VARIATION_CURRENT_VERSION_NOT_ADVANCED");

  const authorize = async (scenarioId: E2EScenarioId, practitioner: string, role: number, specialty: number, policy: typeof GENERAL_TREATMENT_POLICY, share: { shareId: string; manifestId: string }, expectedId: string) => {
    const session = await createUdapClientSession(config, "Organization/clinic-b", practitioner, "TREAT");
    const tokenResponse = await requestUdapToken(session, session.metadata, session.assertion);
    requireStatus(tokenResponse, 200, "E2E_VARIATION_TOKEN");
    const token = requireTokenResponse(tokenResponse);
    const client = createRequestingInstitutionClient({ custodianBaseUrl: new URL(session.metadata.registration_endpoint).origin, tls: session.tls, fetch: session.fetch });
    const requestId = `req_${randomUUID()}`;
    let read: ReadShareResponse;
    try {
      read = await client.readShare({ ...share, resourceType: "Observation", purposeOfUse: "TREAT", requestId, udapToken: token });
    } catch (error) {
      completed.push({ id: scenarioId, status: "failed", outcome: "blocked", dataDelivery: "unknown", reason: safeError(error), observedReads: {} });
      throw error;
    }
    const observed = await validateAuthorizedRead(config, read, requestId, expectedId);
    if (expectedId === specialistId && (read.manifest.fhirVersionId !== pinnedVersion || requireRecord(read.resource.valueQuantity, "E2E_VARIATION_CONTENT_INVALID").value !== 82)) throw new Error("E2E_VARIATION_PINNED_VERSION_NOT_RETURNED");
    const result = passedScenario(scenarioId, 200, "PERMIT", observed);
    result.responseHash = pseudonymousHash(read);
    result.policyEvidence = {
      policyId: policy.policyId, policyVersion: policy.version,
      requiredRoleCode: policy.requiredRoleCode ?? 0, requiredSpecialtyCode: policy.requiredSpecialtyCode ?? 0,
      professionalRoleCode: role, professionalSpecialtyCode: specialty, individualConstraint: false,
      pinnedVersion: read.manifest.fhirVersionId,
      currentVersion: expectedId === specialistId ? currentSpecialistVersion : read.manifest.fhirVersionId
    };
    completed.push(result);
  };
  await authorize("authorized-general-policy-bruno", "Practitioner/bruno", 1, 1, GENERAL_TREATMENT_POLICY, generalShare, "obs-ana-1");
  await authorize("authorized-general-policy-daniel", "Practitioner/daniel", 1, 3, GENERAL_TREATMENT_POLICY, generalShare, "obs-ana-1");
  await authorize("authorized-specialist-policy-carla", "Practitioner/carla", 2, 2, SPECIALIST_REVIEW_POLICY, specialistShare, specialistId);
  for (const [scenarioId, practitioner, share] of [
    ["general-policy-role-denied", "Practitioner/carla", generalShare],
    ["specialist-policy-role-denied", "Practitioner/bruno", specialistShare],
    ["specialist-policy-specialty-denied", "Practitioner/diana", specialistShare]
  ] as const) {
    const session = await createUdapClientSession(config, "Organization/clinic-b", practitioner, "TREAT");
    const token = requireTokenResponse(await requestUdapToken(session, session.metadata, session.assertion));
    await executeDenied(completed, scenarioId, () => requesterReadRaw(session.fetch, session.metadata, token, session.tls, share.shareId, share.manifestId, "TREAT", `req_${randomUUID()}` as E2ERequestId));
  }

  const historicalUrl = `${config.hospitalAFhirUrl}/Observation/${specialistId}/_history/${pinnedVersion}`;
  const before = await getJson(historicalUrl);
  requireStatus(before, 200, "E2E_HISTORICAL_BEFORE");
  const originalHash = hashFhirResource(requireRecord(before.body, "E2E_HISTORICAL_BEFORE_INVALID") as never);
  const session = await createUdapClientSession(config, "Organization/clinic-b", "Practitioner/carla", "TREAT");
  const token = requireTokenResponse(await requestUdapToken(session, session.metadata, session.assertion));
  const requestId = `req_${randomUUID()}` as E2ERequestId;
  await withHistoricalObservationMutation(createHistoricalObservationStore(config.projectRoot), Number(pinnedVersion), async () => {
    const tampered = await getJson(historicalUrl);
    requireStatus(tampered, 200, "E2E_HISTORICAL_TAMPERED_READ");
    const resource = requireRecord(tampered.body, "E2E_HISTORICAL_TAMPERED_INVALID");
    if (requireRecord(resource.valueQuantity, "E2E_HISTORICAL_VALUE_INVALID").value !== 999 || hashFhirResource(resource as never) === originalHash) throw new Error("E2E_HISTORICAL_MUTATION_NOT_VISIBLE");
    await executeDenied(completed, "tampered-historical-fhir-content", () => requesterReadRaw(session.fetch, session.metadata, token, session.tls,
      specialistShare.shareId, specialistShare.manifestId, "TREAT", requestId));
    const result = completed.find(s => s.id === "tampered-historical-fhir-content")!;
    if (result.status !== "passed") throw new Error("E2E_HISTORICAL_DENIAL_FAILED");
    const observation = readAccessObservation(config, requestId);
    const count = (name: string) => observation.stages.filter(s => s.name === name && s.status === "confirmed").length;
    if (observation.status !== 403 || count("fhirVread") !== 1 || count("commitmentCheck") !== 1 || count("auditEvent") !== 1) throw new Error("E2E_HISTORICAL_DENIAL_STAGE_MISMATCH");
    const finalization = observation.stages.find(s => s.name === "blockchainFinalization" && s.status === "confirmed");
    const decision = observation.stages.find(s => s.name === "blockchainDecision");
    const provider = new JsonRpcProvider(config.blockchainRpcUrl);
    try {
      const receipt = finalization?.transactionHash ? await provider.getTransactionReceipt(finalization.transactionHash) : null;
      const eventInterface = new Interface(["event EnforcementFinalized(bytes32 indexed requestHash, bool delivered, uint8 reasonCode, address indexed finalizedBy)"]);
      const event = receipt?.logs.flatMap(log => { try { const parsed = eventInterface.parseLog(log); return parsed ? [parsed] : []; } catch { return []; } })
        .find(e => e.args.requestHash === decision?.requestHash && e.args.delivered === false && Number(e.args.reasonCode) === 6);
      if (!receipt || receipt.status !== 1 || !event) throw new Error("E2E_HISTORICAL_DENIAL_NOT_FINALIZED");
    } finally { provider.destroy(); }
    result.observedReads = { fhirVread: 1, commitmentCheck: 1, auditEvent: 1, integrityDenialFinalized: 1, evaluatorVread: 1 };
  });
  const restored = await getJson(historicalUrl);
  requireStatus(restored, 200, "E2E_HISTORICAL_RESTORED_READ");
  if (hashFhirResource(requireRecord(restored.body, "E2E_HISTORICAL_RESTORED_INVALID") as never) !== originalHash) throw new Error("E2E_HISTORICAL_PUBLIC_RESTORE_MISMATCH");
  completed.find(s => s.id === "tampered-historical-fhir-content")!.observedReads!.historicalVersionRestored = 1;
  await authorize("authorized-restored-historical-version", "Practitioner/carla", 2, 2, SPECIALIST_REVIEW_POLICY, specialistShare, specialistId);
}

function createLiveReport(
  checks: RuntimeDependencyResult[],
  scenarios: E2EScenarioReport[],
  _context: LiveContext
): E2EReport {
  const orderedScenarios = E2E_SCENARIO_IDS.map((id) => {
    const scenario = scenarios.find((candidate) => candidate.id === id);
    if (!scenario) throw new Error(`E2E_SCENARIO_RESULT_MISSING:${id}`);
    return scenario;
  });
  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    executionMode: "live",
    readiness: checks.map(toE2ECheck),
    summary: {
      total: E2E_SCENARIO_IDS.length,
      passed: orderedScenarios.filter((scenario) => scenario.status === "passed").length,
      failed: orderedScenarios.filter((scenario) => scenario.status === "failed").length,
      blocked: orderedScenarios.filter((scenario) => scenario.status === "blocked").length
    },
    scenarios: orderedScenarios,
    evidence: {
      liveServices: true,
      realOidc: true,
      realMtls: true,
      realUdap: true,
      persistentBesu: true,
      persistentPostgres: true,
      hapiFhir: true
    },
    limitations: LIVE_LIMITATIONS
  };
}

async function prepareLocalArtifacts(config: E2EConfig) {
  await runProjectNpm(config, "besu:generate");
  if (!(await fileExists(path.join(config.projectRoot, ".local", "pki", "ca", "ca.crt")))) {
    await runProcess("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path.join(config.projectRoot, "scripts", "generate-local-pki.ps1")], config.projectRoot);
  }
  if (!(await fileExists(config.clinicBSigningKeyPath))) {
    await runProjectNpm(config, "udap:keys");
  }
  await mkdir(path.join(config.projectRoot, ".local", "e2e"), { recursive: true });
  const hospitalPrivate = await readFile(path.join(config.projectRoot, ".local", "udap", "hospital-a-signing.key"), "utf8");
  const hospitalPublic = await readJsonFile<JWK>(path.join(config.projectRoot, ".local", "udap", "hospital-a-signing.jwk.json"));
  const signedMetadata = await new SignJWT({
    token_endpoint: `${config.hospitalAGatewayUrl}/udap/token`,
    registration_endpoint: `${config.hospitalAGatewayUrl}/udap/register`,
    jwks_uri: `${config.hospitalAGatewayUrl}/.well-known/udap/jwks.json`,
    jwks: { keys: [publicJwk(hospitalPublic)] }
  })
    .setProtectedHeader({ alg: "RS256", kid: String(hospitalPublic.kid), typ: "JWT" })
    .setIssuer(config.hospitalAGatewayUrl)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(await importPKCS8(hospitalPrivate, "RS256"));
  await writeFile(path.join(config.projectRoot, ".local", "e2e", "hospital-a-signed-metadata.jwt"), `${signedMetadata}\n`, "utf8");
  await writeFile(path.join(config.projectRoot, ".local", "e2e", "hospital-a-issuer-jwks.json"), `${JSON.stringify({ keys: [publicJwk(hospitalPublic)] }, null, 2)}\n`, "utf8");
}

async function writeComposeEnvironment(config: E2EConfig, temporaryFiles: E2ETemporaryFileScope): Promise<string> {
  const deploymentPath = path.join(config.projectRoot, ".local", "besu", "deployment.json");
  const deployment = await fileExists(deploymentPath) ? await readJsonFile<{ healthAccessControl: string }>(deploymentPath) : undefined;
  const network = await readJsonFile<{ wallets: Array<{ name: string }>; institutions: Record<string, { walletAddresses: Record<string, string> }> }>(path.join(config.projectRoot, ".local", "besu", "network.json"));
  const walletKey = async (institution: string, role: string) => (await readFile(path.join(config.projectRoot, ".local", "besu", "institutions", institution, `${role}.key`), "utf8")).trim();
  const root = path.join(config.projectRoot, ".local", "e2e");
  const hospitalPublic = await readJsonFile<JWK>(path.join(config.projectRoot, ".local", "udap", "hospital-a-signing.jwk.json"));
  const manifestKeys = await ensureManifestKeys(root);
  const values: Record<string, string> = {
    ...runtimeEnvironment(config.projectRoot).environment,
    KEYCLOAK_CONTAINER_HOSTNAME,
    HOSPITAL_A_HEALTH_ACCESS_CONTROL_ADDRESS: deployment?.healthAccessControl ?? "",
    CLINIC_B_HEALTH_ACCESS_CONTROL_ADDRESS: deployment?.healthAccessControl ?? "",
    HOSPITAL_A_BLOCKCHAIN_RPC_URL: "http://besu-hospital-a-validator:8545",
    CLINIC_B_BLOCKCHAIN_RPC_URL: "http://besu-hospital-a-validator:8545",
    HOSPITAL_A_BLOCKCHAIN_DEPLOYER_PRIVATE_KEY: await walletKey("hospital-a", "deployer"),
    HOSPITAL_A_BLOCKCHAIN_PATIENT_PRIVATE_KEY: await walletKey("hospital-a", "patient"),
    HOSPITAL_A_BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY: await walletKey("hospital-a", "practitioner"),
    HOSPITAL_A_BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY: await walletKey("hospital-a", "organization"),
    HOSPITAL_A_BLOCKCHAIN_PEP_PRIVATE_KEY: await walletKey("hospital-a", "pep"),
    CLINIC_B_BLOCKCHAIN_DEPLOYER_PRIVATE_KEY: await walletKey("clinic-b", "deployer"),
    CLINIC_B_BLOCKCHAIN_PATIENT_PRIVATE_KEY: await walletKey("clinic-b", "patient"),
    CLINIC_B_BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY: await walletKey("clinic-b", "practitioner"),
    CLINIC_B_BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY: await walletKey("clinic-b", "organization"),
    CLINIC_B_BLOCKCHAIN_PEP_PRIVATE_KEY: await walletKey("clinic-b", "pep"),
    MANIFEST_SIGNING_PRIVATE_JWK: JSON.stringify(manifestKeys.privateJwk),
    MANIFEST_SIGNING_PUBLIC_JWK: JSON.stringify(manifestKeys.publicJwk),
    MANIFEST_SIGNING_KEY_ID: String(manifestKeys.privateJwk.kid),
    UDAP_ENABLED: "true",
    UDAP_ISSUER: config.hospitalAGatewayUrl,
    UDAP_BASE_URL: config.hospitalAGatewayUrl,
    UDAP_TOKEN_AUDIENCE: `${config.hospitalAGatewayUrl}/udap/token`,
    UDAP_SIGNING_KEY_ID: String(hospitalPublic.kid),
    UDAP_ISSUER_JWKS_URI: `${config.hospitalAGatewayUrl}/.well-known/udap/jwks.json`,
    UDAP_ISSUER_JWKS_PATH: ".local/e2e/hospital-a-issuer-jwks.json",
    UDAP_SIGNED_METADATA_PATH: ".local/e2e/hospital-a-signed-metadata.jwt",
    UDAP_CLINIC_B_ENABLED: "true",
    UDAP_CLINIC_B_DISCOVERY_URL: `${config.hospitalAGatewayUrl}/fhir/.well-known/udap`
  };
  const envPath = path.join(root, `compose-${randomUUID()}.env`);
  temporaryFiles.register(envPath);
  await writeFile(envPath, `${Object.entries(values).map(([key, value]) => `${key}='${value.replaceAll("'", "'\\''")}'`).join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
  return envPath;
}

async function ensureManifestKeys(root: string) {
  const saved = path.join(root,"manifest-key-pair.json");
  if (await fileExists(saved)) return readJsonFile<{privateJwk: JWK; publicJwk: JWK}>(saved);
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = { ...(await exportJWK(privateKey)), alg: "ES256", kid: "hospital-a-manifest-2026" };
  const publicJwk = { ...(await exportJWK(publicKey)), alg: "ES256", kid: "hospital-a-manifest-2026" };
  await writeFile(saved, JSON.stringify({privateJwk, publicJwk}), {flag:"wx",mode:0o600});
  return { privateJwk, publicJwk };
}

async function verifyPersistentBesu(config: E2EConfig) {
  const deployment = readPersistentDeployment(path.join(config.projectRoot, ".local", "besu", "deployment.json"));
  const network = readPublicNetwork(path.join(config.projectRoot, ".local", "besu", "network.json"));
  const provider = new JsonRpcProvider(config.blockchainRpcUrl);
  try {
    await verifyPersistentDeployment(provider, deployment, readPatientAnaAddress(network));
    const chain = await provider.getNetwork();
    if (Number(chain.chainId) !== deployment.chainId) throw new Error("E2E_PERSISTENT_BESU_CHAIN_MISMATCH");
  } finally {
    provider.destroy();
  }
}

async function seedAndValidateFixtures(config: E2EConfig) {
  const fixtures = [
    [config.hospitalAFhirUrl, "fixtures/fhir/hospital-a-bundle.json"],
    [config.clinicBFhirUrl, "fixtures/fhir/clinic-b-bundle.json"]
  ] as const;
  for (const [baseUrl, fixturePath] of fixtures) {
    const bundle = await readJsonFile<Record<string, unknown>>(path.join(config.projectRoot, fixturePath));
    const response = await getJson(baseUrl, { method: "POST", headers: { "content-type": "application/fhir+json", accept: "application/fhir+json" }, body: JSON.stringify(bundle) });
    requireStatus(response, 200, "FHIR_FIXTURE_SEED");
  }
  for (const reference of ["Organization/hospital-a", "Patient/pat-ana", "Observation/obs-ana-1", "Consent/cons-ana-1"]) {
    requireStatus(await getJson(`${config.hospitalAFhirUrl}/${reference}`), 200, `FHIR_REQUIRED:${reference}`);
  }
  requireStatus(await getJson(`${config.clinicBFhirUrl}/Observation/obs-ana-1`), 404, "CLINIC_B_CLINICAL_COPY");

}

export async function runKeycloakOidcGate(config: E2EConfig): Promise<{ validatedUsers: number }> {
  const profiles = buildKeycloakDemoUserProfiles(config as unknown as Record<string, string>);
  for (const profile of profiles) await issueOidcToken(config, profile);
  return { validatedUsers: profiles.length };
}

function requireKeycloakDemoUserProfile(profiles: KeycloakDemoUserProfile[], id: string): KeycloakDemoUserProfile {
  const profile = profiles.find((candidate) => candidate.id === id);
  if (!profile) throw new Error(`OIDC_PROFILE_MISSING:${id}`);
  return profile;
}

async function issueOidcToken(config: E2EConfig, profile: KeycloakDemoUserProfile): Promise<OidcToken> {
  const response = await getJson(`${config.keycloakUrl}/realms/${profile.realm}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ grant_type: "password", client_id: "interfhir-api", client_secret: profile.clientSecret, username: profile.username, password: profile.password, scope: "openid" }).toString()
  });
  requireStatus(response, 200, `OIDC_TOKEN:${profile.id}`);
  const body = requireRecord(response.body, "OIDC_TOKEN_RESPONSE_INVALID");
  const token = requireString(body, "access_token");
  const decoded = decodeJwt(token);
  if (decoded.role !== profile.expectedClaims.role) throw new Error(`OIDC_ROLE_INVALID:${profile.id}`);
  const verified = await jwtVerify(token, createRemoteJWKSet(new URL(profile.jwksUrl)), { issuer: profile.issuer, audience: "interfhir-api", algorithms: ["RS256"] });
  const claims = verified.payload as Record<string, unknown>;
  if (typeof claims.sub !== "string" || claims.sub.length === 0) throw new Error(`OIDC_SUBJECT_INVALID:${profile.id}`);
  if (typeof claims.jti !== "string" || claims.jti.length === 0) throw new Error(`OIDC_JTI_INVALID:${profile.id}`);
  if (claims.preferred_username !== profile.username) throw new Error(`OIDC_USERNAME_INVALID:${profile.id}`);
  assertKeycloakDemoUserClaims(profile, claims);
  return { value: token, claims };
}

async function validateConsentProjection(config: E2EConfig, consent: Record<string, unknown>) {
  const reference = requireString(consent, "consentReference");
  const resource = await getJson(`${config.hospitalAFhirUrl}/${reference}`);
  requireStatus(resource, 200, "FHIR_CONSENT_READ");
  const fhirConsent = requireRecord(resource.body, "FHIR_CONSENT_INVALID");
  if (fhirConsent.resourceType !== "Consent" || fhirConsent.status !== "active") throw new Error("FHIR_CONSENT_NOT_ACTIVE");
  const mapped = mapFhirConsentToRegisterConsentInput(fhirConsent as never);
  const deployment = readPersistentDeployment(path.join(config.projectRoot, ".local", "besu", "deployment.json"));
  const provider = new JsonRpcProvider(config.blockchainRpcUrl);
  try {
    const registry = new Contract(deployment.consentRegistry, ["function getActivePatientConsentProjection(bytes32) view returns (tuple(bytes32 policyIdHash, uint32 policyVersion, uint32 consentVersion, bytes32 consentProjectionHash, bool active, uint8 status))"], provider);
    await assertConsentProjectionChain(
      consent,
      mapped,
      async (consentHash) => registry.getFunction("getActivePatientConsentProjection")(consentHash)
    );
    return mapped;
  } finally {
    provider.destroy();
  }
}

async function createRealUdapSession(config: E2EConfig): Promise<RealUdapSession> {
  const session = await createUdapClientSession(config, "Organization/clinic-b", "Practitioner/bruno", "TREAT");
  const tokenResponse = await requestUdapToken(session, session.metadata, session.assertion);
  requireStatus(tokenResponse, 200, "UDAP_TOKEN");
  return { client: session.client, metadata: session.metadata, token: requireString(requireRecord(tokenResponse.body, "UDAP_TOKEN_RESPONSE_INVALID"), "access_token"), tls: session.tls, fetch: session.fetch };
}

async function createUdapClientSession(config: E2EConfig, organizationReference: string, practitionerReference: string, purposeOfUse: string, register = true) {
  const [signingKeyPem, publicJwk, tls] = await Promise.all([
    readFile(config.clinicBSigningKeyPath, "utf8"),
    readJsonFile<Record<string, unknown>>(config.clinicBPublicJwkPath),
    readTls(config.clinicBClientKeyPath, config.clinicBClientCertPath, config.clinicBTlsCaPath)
  ]);
  const certificate = certificateIdentityFromPem(tls.cert.toString());
  if (!certificate.x5tS256) throw new Error("E2E_UDAP_CERTIFICATE_THUMBPRINT_MISSING");
  const fetch = createBoundedMtlsUdapFetch();
  const client = createUdapClient({
    discoveryTrust: { origin: new URL(config.udapDiscoveryUrl).origin, issuer: new URL(config.udapDiscoveryUrl).origin, jwks: await readJsonFile(path.join(config.projectRoot, ".local/e2e/hospital-a-issuer-jwks.json")) },
    clientId: config.clientId,
    organizationReference,
    certificateThumbprint: certificate.x5tS256,
    signingKey: await importPKCS8(signingKeyPem, "RS256"),
    signingKeyId: String(publicJwk.kid),
    signingAlgorithm: "RS256",
    publicJwk,
    fetch
  });
  const metadata = await client.discover(config.udapDiscoveryUrl, tls);
  if (register) try {
    const statement = await client.createSoftwareStatement({ registrationEndpoint: metadata.registration_endpoint });
    const registration = await client.registerClient({ metadata, softwareStatement: statement, tls });
    if (registration.organizationReference !== organizationReference) throw new Error("E2E_UDAP_REGISTRATION_ORGANIZATION_MISMATCH");
  } catch (error) {
    if (!String(error instanceof Error ? error.message : error).includes("HTTP_409")) throw error;
  }
  const assertion = await client.createAssertion({ tokenEndpoint: metadata.token_endpoint, practitionerReference, roleCode: "physician", purposeOfUse });
  return { client, metadata, tls, fetch, assertion };
}

async function requestUdapToken(session: { fetch: UdapHttpFetch; tls: UdapClientTlsOptions }, metadata: UdapDiscoveryMetadata, assertion: string): Promise<E2EHttpResponse> {
  const response = await session.fetch(metadata.token_endpoint, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }),
    tls: session.tls
  });
  return { status: response.status, body: await response.json() };
}

async function requesterReadRaw(fetch: UdapHttpFetch, metadata: UdapDiscoveryMetadata, token: string, tls: UdapClientTlsOptions, shareId: string, manifestId: string, purposeOfUse: string, requestId: E2ERequestId): Promise<E2EHttpResponse> {
  return postUdap(fetch, `${new URL(metadata.registration_endpoint).origin}/interfhir/v1/access/read`, tls, token, { shareId, manifestId, operation: "read", purposeOfUse, requestId });
}

async function requesterRedeemRaw(fetch: UdapHttpFetch, metadata: UdapDiscoveryMetadata, tls: UdapClientTlsOptions, token: string, handoffCode: string): Promise<E2EHttpResponse> {
  return postUdap(fetch, `${new URL(metadata.registration_endpoint).origin}/interfhir/v1/shares/redeem`, tls, token, { handoffCode });
}

async function postUdap(fetch: UdapHttpFetch, url: string, tls: UdapClientTlsOptions, token: string, body: Record<string, string>): Promise<E2EHttpResponse> {
  const response = await fetch(url, { method: "POST", headers: { authorization: `Bearer ${token}`, accept: "application/json", "content-type": "application/json" }, body: JSON.stringify(body), tls });
  return { status: response.status, body: await response.json() };
}

async function validateAuthorizedRead(config: E2EConfig, response: ReadShareResponse, requestId: string, expectedId = "obs-ana-1") {
  if (response.resource.resourceType !== "Observation" || response.resource.id !== expectedId || response.resource.meta.versionId !== response.manifest.fhirVersionId) {
    throw new Error("E2E_AUTHORIZED_READ_SCOPE_INVALID");
  }
  const vread = await getJson(`${config.hospitalAFhirUrl}/Observation/${expectedId}/_history/${response.manifest.fhirVersionId}`);
  requireStatus(vread, 200, "FHIR_VREAD");
  if (hashFhirResource(requireRecord(vread.body, "FHIR_VREAD_INVALID") as never) !== hashFhirResource(response.resource as never)) throw new Error("E2E_FHIR_HASH_MISMATCH");
  const audit = await getJson(`${config.hospitalAFhirUrl}/AuditEvent?_sort=-date&_count=100`);
  requireStatus(audit, 200, "FHIR_AUDIT_EVENT_READ");
  const auditBundle = requireRecord(audit.body, "FHIR_AUDIT_EVENT_INVALID");
  const matching = (Array.isArray(auditBundle.entry) ? auditBundle.entry : []).map((entry: any) => entry.resource).filter((event: any) => event?.extension?.some((extension: any) => extension.url === "https://interfhir.local/fhir/StructureDefinition/access-request-id" && extension.valueString === requestId));
  if (matching.length !== 1) throw new Error("E2E_REQUEST_AUDIT_EVENT_MISSING");
  const observation = readAccessObservation(config, requestId);
  if (observation.status !== 200) throw new Error("E2E_REQUEST_OBSERVATION_MISSING");
  const stages = observation.stages;
  const finalization = stages.find(stage => stage.name === "blockchainFinalization" && stage.status === "confirmed");
  if (!finalization?.transactionHash) throw new Error("E2E_FINALIZATION_RECEIPT_MISSING");
  const provider = new JsonRpcProvider(config.blockchainRpcUrl);
  try {
    const receipt = await provider.getTransactionReceipt(finalization.transactionHash);
    if (!receipt || receipt.status !== 1) throw new Error("E2E_FINALIZATION_NOT_CONFIRMED");
    const decision = stages.find(stage => stage.name === "blockchainDecision");
    const auditHash = matching[0].extension.find((extension: any) => extension.url === "https://interfhir.local/fhir/StructureDefinition/access-request-hash")?.valueString;
    if (!decision?.requestHash || auditHash !== decision.requestHash) throw new Error("E2E_AUDIT_REQUEST_HASH_MISMATCH");
    const eventInterface = new Interface(["event EnforcementFinalized(bytes32 indexed requestHash, bool delivered, uint8 reasonCode, address indexed finalizedBy)"]);
    const event = receipt.logs.flatMap(log => { try { const parsed = eventInterface.parseLog(log); return parsed ? [parsed] : []; } catch { return []; } }).find(event => event.args.requestHash === decision.requestHash && event.args.delivered === true);
    if (!event) throw new Error("E2E_FINALIZATION_EVENT_MISSING");
  } finally { provider.destroy(); }
  const counts = Object.fromEntries(["commitmentCheck", "fhirVread", "auditEvent"].map(name => [name, stages.filter(stage => stage.name === name && stage.status === "confirmed").length]));
  if (counts.fhirVread !== 1 || counts.auditEvent !== 1 || counts.commitmentCheck !== 1) throw new Error("E2E_OBSERVED_STAGE_COUNTS_INVALID");
  requireStatus(await getJson(`${config.clinicBFhirUrl}/Observation/${expectedId}`), 404, "CLINIC_B_CLINICAL_COPY");
  return { ...counts, evaluatorVread: 1, evaluatorAuditSearch: 1 };
}

function readAccessObservation(config: E2EConfig, requestId: string): { status: number; stages: Array<{ name: string; status: string; transactionHash?: string; requestHash?: string }> } {
  const logs = execFileSync("docker", [...composeArguments(config.projectRoot), "logs", "--no-log-prefix", "hospital-a-gateway"], { cwd: config.projectRoot, encoding: "utf8", windowsHide: true, maxBuffer: 16 * 1024 * 1024 });
  const observations = logs.split(/\r?\n/).flatMap(line => { try { const value = JSON.parse(line); return value.kind === "access-observation" && value.requestId === requestId ? [value] : []; } catch { return []; } });
  if (observations.length !== 1) throw new Error("E2E_REQUEST_OBSERVATION_MISSING");
  return observations[0];
}

async function readManifestRow(config: E2EConfig, manifestId: string) {
  const client = new Client({ connectionString: config.hospitalAMetadataDatabaseUrl });
  await client.connect();
  try {
    const result = await client.query<ManifestDatabaseRow>(`SELECT
      v.manifest_id, h.share_id, v.version, v.status,
      v.custodian_organization_reference, v.grantee_organization_reference,
      v.resource_reference, v.resource_type, v.fhir_version_id,
      v.subject_reference, v.consent_reference_hash, v.consent_projection_hash,
      v.resource_hash, v.previous_version_commitment, v.commitment,
      v.signing_key_id, v.signature, v.created_at, v.updated_at
      FROM manifest_versions v
      JOIN manifest_headers h ON h.manifest_id = v.manifest_id
      WHERE v.manifest_id = $1 AND v.status = 'active'`, [manifestId]);
    if (!result.rows[0]) throw new Error("E2E_MANIFEST_ROW_MISSING");
    return result.rows[0];
  } finally {
    await client.end();
  }
}

async function tamperManifest(config: E2EConfig, manifestId: string, originalResourceHash: string) {
  const client = new Client({ connectionString: config.hospitalAMetadataDatabaseUrl });
  await client.connect();
  try {
    await client.query("UPDATE manifest_versions SET resource_hash = $2 WHERE manifest_id = $1 AND status = 'active'", [manifestId, `sha256:${"0".repeat(64)}`]);
    if (originalResourceHash === `sha256:${"0".repeat(64)}`) throw new Error("E2E_MANIFEST_TAMPER_SENTINEL_COLLISION");
  } finally {
    await client.end();
  }
}

async function tamperManifestVersion(config: E2EConfig, manifestId: string, mutation: { fhir_version_id: string; commitment: string }) {
  const client = new Client({ connectionString: config.hospitalAMetadataDatabaseUrl });
  await client.connect();
  try {
    await client.query(
      "UPDATE manifest_versions SET fhir_version_id = $2, commitment = $3 WHERE manifest_id = $1 AND status = 'active'",
      [manifestId, mutation.fhir_version_id, mutation.commitment]
    );
  } finally {
    await client.end();
  }
}

// Recomputing the local commitment does not refresh the custodial signature or
// the on-chain anchor; verification must reject this binding before vread.
export function buildTamperedManifestVersionMutation(original: ManifestDatabaseRow): { fhir_version_id: string; commitment: string } {
  const manifest = databaseRowToManifest(original);
  const tampered = {
    ...manifest,
    fhirVersionId: `${manifest.fhirVersionId}-tampered`
  };
  return {
    fhir_version_id: tampered.fhirVersionId,
    commitment: computeManifestCommitment(tampered)
  };
}

async function restoreManifest(config: E2EConfig, manifestId: string, original: ManifestDatabaseRow) {
  const client = new Client({ connectionString: config.hospitalAMetadataDatabaseUrl });
  await client.connect();
  try {
    await client.query(
      "UPDATE manifest_versions SET resource_hash = $2, fhir_version_id = $3, commitment = $4 WHERE manifest_id = $1 AND status = 'active'",
      [manifestId, original.resource_hash, original.fhir_version_id, original.commitment]
    );
  } finally {
    await client.end();
  }
  const restored = await readManifestRow(config, manifestId);
  if (canonicalManifestRow(restored) !== canonicalManifestRow(original)) {
    throw new Error("E2E_MANIFEST_RESTORE_FAILED");
  }
}

function databaseRowToManifest(row: ManifestDatabaseRow): ResourceManifestVersion {
  return {
    manifestId: row.manifest_id,
    shareId: row.share_id,
    version: row.version,
    status: row.status,
    custodianOrganizationReference: row.custodian_organization_reference,
    granteeOrganizationReference: row.grantee_organization_reference,
    resourceReference: row.resource_reference,
    resourceType: row.resource_type,
    fhirVersionId: row.fhir_version_id,
    subjectReference: row.subject_reference,
    consentReferenceHash: row.consent_reference_hash,
    consentProjectionHash: row.consent_projection_hash,
    resourceHash: row.resource_hash,
    previousVersionCommitment: row.previous_version_commitment,
    commitment: row.commitment,
    signingKeyId: row.signing_key_id,
    signature: row.signature,
    createdAt: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    ...(row.updated_at ? { updatedAt: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at } : {})
  };
}

function canonicalManifestRow(row: ManifestDatabaseRow): string {
  return JSON.stringify({
    ...row,
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
    updated_at: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at
  });
}

export async function executeDenied(completed: E2EScenarioReport[], id: E2EScenarioId, operation: () => Promise<E2EHttpResponse>) {
  let response: E2EHttpResponse | undefined;
  try {
    response = await operation();
    assertNegativeResponse(response, EXPECTED_DENIAL_STATUSES[id]);
    if (responseError(response.body) !== EXPECTED_DENIAL_REASONS[id]) throw new Error("E2E_DENIAL_REASON_MISMATCH");
    completed.push(passedScenario(id, response.status, responseError(response.body), {}));
  } catch (error) {
    // Preserve the failed assertion, even when the API returned an error code.
    // Otherwise a clinical leak or the wrong rejection reason is concealed.
    const reason = safeError(error);
    completed.push({ id, status: "failed", outcome: "denied", dataDelivery: observeDelivery(response?.body, false), ...(response ? { httpStatus: response.status } : {}), reason, responseHash: pseudonymousHash(reason), observedReads: {} });
  }
}

function passedScenario(id: E2EScenarioId, httpStatus: number, reason: string, observedReads: Record<string, number>): E2EScenarioReport {
  const authorized = id.startsWith("authorized-");
  return { id, status: "passed", outcome: authorized ? "authorized" : "denied", dataDelivery: authorized ? "authorized" : "none", httpStatus, reason, responseHash: pseudonymousHash(`${id}:${httpStatus}:${reason}`), observedReads };
}

async function waitForE2ERuntime(config: E2EConfig, includeGateways: boolean, throwOnFailure = true): Promise<RuntimeDependencyResult[]> {
  const targets = buildE2ERuntimeTargets(process.env).filter((target) => includeGateways || !["hospital-a-gateway", "clinic-b-gateway", "hospital-a-udap", "clinic-b-udap-requester"].includes(target.service));
  const checks = await waitForRuntimeDependencies(targets, { timeoutMs: readNumberEnv("E2E_WAIT_TIMEOUT_MS", 120_000), pollIntervalMs: readNumberEnv("E2E_POLL_INTERVAL_MS", 2_000), requestTimeoutMs: readNumberEnv("E2E_REQUEST_TIMEOUT_MS", 5_000) });
  if (throwOnFailure) assertReadinessGate(checks.map(toE2ECheck));
  return checks;
}

async function waitForTarget(config: E2EConfig, target: RuntimeTarget) {
  if (!target) throw new Error("E2E_RUNTIME_TARGET_MISSING");
  const result = await waitForRuntimeDependencies([target], { timeoutMs: readNumberEnv("E2E_WAIT_TIMEOUT_MS", 120_000), pollIntervalMs: readNumberEnv("E2E_POLL_INTERVAL_MS", 2_000), requestTimeoutMs: readNumberEnv("E2E_REQUEST_TIMEOUT_MS", 5_000) });
  if (result[0]?.status !== "ok") throw new Error(`E2E_RUNTIME_TARGET_UNAVAILABLE:${result[0]?.service}`);
}

async function runProjectNpm(config: E2EConfig, script: string, extraEnv: Record<string, string> = {}) {
  await runProcess(process.platform === "win32" ? "npm.cmd" : "npm", ["run", script], config.projectRoot, {
    BLOCKCHAIN_RPC_URL: config.blockchainRpcUrl,
    ...extraEnv
  });
}

async function runCompose(config: E2EConfig, composeFiles: string[], operation: string[], envFile: string) {
  await runProcess("docker", [...composeArguments(config.projectRoot), "--file", path.join(config.projectRoot, "scripts/e2e/policy-variation.compose.yml"), "--env-file", envFile, ...operation], config.projectRoot, {}, readComposeTimeoutMs());
}

async function runComposePlan(plan: ProjectComposeCommand[], config: E2EConfig) {
  assertOwnedResources(config.projectRoot);
  for (const command of plan) await runProcess("docker", command.args, command.root, {}, readComposeTimeoutMs());
}

export function runProcess(command: string, args: string[], cwd: string, extraEnv: Record<string, string> = {}, timeoutMs = readNumberEnv("E2E_SUBPROCESS_TIMEOUT_MS", DEFAULT_SUBPROCESS_TIMEOUT_MS)) {
  return new Promise<void>((resolve, reject) => {
    const isWindowsCmd = process.platform === "win32" && command.toLowerCase().endsWith(".cmd");
    const executable = isWindowsCmd ? process.env.ComSpec ?? "cmd.exe" : command;
    const executableArgs = isWindowsCmd
      ? ["/d", "/s", "/c", ["call", quoteWindowsCmdToken(command), ...args.map(quoteWindowsCmdToken)].join(" ")]
      : args;
    const child = spawn(executable, executableArgs, {
      cwd,
      env: { ...process.env, ...extraEnv },
      stdio: "inherit",
      windowsHide: true,
      shell: false,
      ...(isWindowsCmd ? { windowsVerbatimArguments: true } : {})
    });
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      terminateChild(child);
      reject(new Error(`COMMAND_TIMEOUT:${command}`));
    }, timeoutMs);
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    child.once("error", (error) => finish(error));
    child.once("exit", (code) => code === 0 ? finish() : finish(new Error(`COMMAND_FAILED:${command}:${code ?? "signal"}`)));
  });
}

function quoteWindowsCmdToken(value: string): string {
  if (/^[A-Za-z0-9_./\\:=+,\-@]+$/.test(value)) return value;
  return `"${value.replace(/["^]/g, "^$&")}"`;
}

function terminateChild(child: ReturnType<typeof spawn>) {
  if (process.platform === "win32" && child.pid) {
    const killer = spawn("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
      shell: false
    });
    killer.once("error", () => undefined);
  }
  child.kill("SIGTERM");
}

async function postGatewayJson(config: E2EConfig, route: string, token: string, body: unknown, headers: Record<string, string> = {}): Promise<E2EHttpResponse> {
  const tls = await readTls(config.clinicBClientKeyPath, config.clinicBClientCertPath, config.clinicBTlsCaPath);
  const fetch = createBoundedMtlsUdapFetch();
  const response = await fetch(`${config.hospitalAGatewayUrl}${route}`, { method: "POST", headers: { authorization: `Bearer ${token}`, accept: "application/json", "content-type": "application/json", ...headers }, body: body === undefined ? "" : JSON.stringify(body), tls });
  return { status: response.status, body: await response.json() };
}

async function getJson(url: string, init: RequestInit = {}): Promise<E2EHttpResponse> {
  const response = await fetchWithTimeout(url, init, readNumberEnv("E2E_NETWORK_TIMEOUT_MS", DEFAULT_NETWORK_TIMEOUT_MS));
  const text = await response.text();
  let body: unknown;
  try { body = text ? JSON.parse(text) : undefined; } catch { body = { error: "NON_JSON_RESPONSE" }; }
  return { status: response.status, body };
}

export function withTimeout<T>(promise: Promise<T>, timeoutMs: number, errorCode: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(errorCode)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

export async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit = {},
  timeoutMs = DEFAULT_NETWORK_TIMEOUT_MS,
  fetchImplementation: typeof fetch = fetch
): Promise<Response> {
  const controller = new AbortController();
  let timer!: NodeJS.Timeout;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error("E2E_NETWORK_TIMEOUT"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      fetchImplementation(input, { ...init, signal: controller.signal }),
      timeout
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function createBoundedMtlsUdapFetch(timeoutMs = readNumberEnv("E2E_NETWORK_TIMEOUT_MS", DEFAULT_NETWORK_TIMEOUT_MS)): UdapHttpFetch {
  return (url, init) => new Promise((resolve, reject) => {
    let target: URL;
    try {
      target = new URL(url);
    } catch {
      reject(new Error("UDAP_URL_INVALID"));
      return;
    }
    if (target.protocol !== "https:") {
      reject(new Error("UDAP_HTTPS_REQUIRED"));
      return;
    }
    let settled = false;
    const request = httpsRequest({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      method: init.method,
      key: init.tls.key,
      cert: init.tls.cert,
      ca: init.tls.ca,
      ...(init.tls.servername ? { servername: init.tls.servername } : {}),
      rejectUnauthorized: true,
      headers: init.headers
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("error", (error) => finish(error));
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        finish(undefined, {
          status: response.statusCode ?? 0,
          ok: (response.statusCode ?? 0) >= 200 && (response.statusCode ?? 0) < 300,
          async json() {
            try {
              return JSON.parse(raw) as unknown;
            } catch {
              throw new Error("UDAP_HTTP_RESPONSE_INVALID");
            }
          }
        });
      });
    });
    const timer = setTimeout(() => {
      if (settled) return;
      request.destroy();
      finish(new Error("E2E_NETWORK_TIMEOUT"));
    }, timeoutMs);
    const finish = (error?: Error, value?: { status: number; ok: boolean; json(): Promise<unknown> }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value!);
    };
    request.once("error", (error) => finish(error));
    request.setTimeout(timeoutMs, () => {
      request.destroy();
      finish(new Error("E2E_NETWORK_TIMEOUT"));
    });
    if (init.body) request.write(init.body);
    request.end();
  });
}

async function readTls(keyPath: string, certPath: string, caPath: string): Promise<UdapClientTlsOptions> {
  const [key, cert, ca] = await Promise.all([readFile(keyPath), readFile(certPath), readFile(caPath)]);
  return { key, cert, ca };
}

function toE2ECheck(check: RuntimeDependencyResult): E2ECheck {
  return { service: check.service, status: check.status === "ok" ? "ok" : "blocked", ...(check.lastError ? { reason: check.lastError } : {}) };
}

export async function writeReport(config: Pick<E2EConfig, "projectRoot" | "reportPath">, report: E2EReport) {
  assertSanitizedE2EReport(report);
  const artifact = await writeRunArtifact("e2e", report, config.projectRoot);
  if (path.resolve(config.reportPath) !== path.resolve(config.projectRoot, "reports/e2e-latest.json")) {
    await mkdir(path.dirname(config.reportPath), { recursive: true });
    await writeFile(config.reportPath, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
  }
  printJson({ report: "reports/e2e-latest.json", executionMode: report.executionMode, summary: report.summary });
}

function responseError(body: unknown) {
  return isRecord(body) && typeof body.error === "string" ? body.error : "DENIED";
}

function requireTokenResponse(response: E2EHttpResponse): string {
  requireStatus(response, 200, "UDAP_TOKEN");
  return requireString(requireRecord(response.body, "UDAP_TOKEN_RESPONSE_INVALID"), "access_token");
}

function requireStatus(response: E2EHttpResponse, expected: number, operation: string) {
  if (response.status !== expected) throw new Error(`${operation}_HTTP_${response.status}:${responseError(response.body)}`);
}

function requireRecord(value: unknown, errorCode: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(errorCode);
  return value;
}

function requireString(value: Record<string, unknown>, field: string): string {
  if (typeof value[field] !== "string" || value[field].length === 0) throw new Error(`E2E_FIELD_INVALID:${field}`);
  return value[field] as string;
}

function safeError(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return /^[A-Z][A-Z0-9_:-]{1,127}$/.test(message) ? message : "E2E_INTERNAL_FAILURE";
}

function isEnvironmentFailure(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  return /ECONNREFUSED|ECONNRESET|ENOTFOUND|ETIMEDOUT|EAI_AGAIN|RPC_UNAVAILABLE|FHIR_HTTP_5|HTTP_503|COMMAND_FAILED:docker/i.test(message);
}

function publicJwk(value: JWK) {
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicValue } = value;
  return publicValue;
}

function printJson(value: unknown) {
  console.log(JSON.stringify(value, null, 2));
}

export function readComposeTimeoutMs(env: NodeJS.ProcessEnv = process.env) {
  const timeoutMs = readNumberEnv("E2E_COMPOSE_TIMEOUT_MS", DEFAULT_COMPOSE_TIMEOUT_MS, env);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < MIN_COMPOSE_TIMEOUT_MS || timeoutMs > MAX_COMPOSE_TIMEOUT_MS) {
    throw new Error("E2E_INVALID_NUMBER:E2E_COMPOSE_TIMEOUT_MS");
  }
  return timeoutMs;
}

function readNumberEnv(name: string, fallback: number, env: NodeJS.ProcessEnv = process.env) {
  const value = env[name];
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(value)) throw new Error(`E2E_INVALID_NUMBER:${name}`);
  return Number(value);
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

async function fileExists(filePath: string) {
  try { await readFile(filePath); return true; } catch { return false; }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

if (process.argv.some((argument) => path.basename(argument) === "run-real-e2e.ts")) {
  await main();
}
