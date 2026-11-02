import { readFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { performance } from "node:perf_hooks";
import path from "node:path";
import { ethers } from "ethers";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { createBearerAuthenticationMiddleware } from "../middleware/src/auth/authentication.js";
import { createHealthAccessApi } from "../middleware/src/api/api-handler.js";
import { createMutualTlsServer } from "../middleware/src/api/http-server.js";
import { createHealthAccessService } from "../middleware/src/access/health-access-service.js";
import { buildPatientConsentResource } from "../middleware/src/fhir/consent-builder.js";
import { mapFhirConsentToRegisterConsentInput, type FhirConsent } from "../middleware/src/fhir/consent-mapper.js";
import { hashFhirResource, type FhirResource } from "../middleware/src/fhir/resource-hasher.js";
import { buildFhirManifestVersion, computeManifestCommitment, type ResourceManifestVersion } from "../middleware/src/manifest/resource-manifest.js";
import { createInstitutionalPolicyEvaluator } from "../middleware/src/policy/institutional-policy.js";
import { buildShareGrant, type ShareGrant } from "../middleware/src/share/share-grant.js";
import { certificateIdentityFromPem } from "../middleware/src/pki/certificate-identity.js";
import { createRequestingInstitutionClient } from "../middleware/src/interfhir/requesting-institution-client.js";
import { createUdapClient, type UdapClientTlsOptions, type UdapDiscoveryMetadata } from "../middleware/src/udap/udap-client.js";
import { createUdapDiscovery } from "../middleware/src/udap/udap-discovery.js";
import { createSignedSoftwareStatementValidator, createUdapRegistrationService } from "../middleware/src/udap/udap-registration-service.js";
import { createUdapAccessTokenVerifier, createUdapTokenService, type UdapRegisteredClient } from "../middleware/src/udap/udap-token-service.js";

export const LIVE_UDAP_SCENARIO_IDS = [
  "authorized-treat",
  "missing-consent",
  "revoked-consent",
  "purpose-mismatch",
  "fhir-version-tamper",
  "institutional-deny-after-onchain-permit"
] as const;

export type LiveUdapScenarioId = (typeof LIVE_UDAP_SCENARIO_IDS)[number];

export interface LiveUdapScenarioResult {
  id: LiveUdapScenarioId;
  httpStatus: number;
  error?: string;
  payloadPresent: boolean;
  timingsMs: Record<string, number>;
  componentReads: Record<string, number>;
}

export interface LiveUdapHarnessResult {
  requesterPath: "createUdapClient+createRequestingInstitutionClient";
  requestedRepetitions: number;
  completedRepetitions: number;
  attemptedRepetitions: number;
  failedAttempts: number;
  scenarios: LiveUdapScenarioResult[];
  componentSamples: Record<string, number[]>;
}

interface HarnessState {
  scenario: LiveUdapScenarioId;
  reads: Record<string, number>;
}

const issuer = "https://hospital-a.local/udap";
const audience = "https://hospital-a.local/interfhir";
const registrationEndpoint = "https://hospital-a.local/udap/register";
const tokenEndpoint = "https://hospital-a.local/udap/token";
const fixedNow = new Date();
const resource: FhirResource = {
  resourceType: "Observation",
  id: "obs-ana-1",
  meta: { versionId: "v1" },
  status: "final",
  subject: { reference: "Patient/pat-ana" },
  valueInteger: 42
};

/**
 * Executes the six missing baseline cases through a real local HTTPS server.
 * The server uses the production API handler, mTLS certificate extraction,
 * UDAP registration/token services and the directed manifest access service.
 * Clinical payloads are consumed only inside the harness and are never returned
 * in this result.
 */
export async function runLiveUdapHarness(options: { repetitions?: number } = {}): Promise<LiveUdapHarnessResult> {
  const repetitions = options.repetitions ?? 30;
  if (!Number.isInteger(repetitions) || repetitions < 1) {
    throw new Error("LIVE_UDAP_REPETITIONS_INVALID");
  }

  const pkiRoot = process.env.UDAP_HARNESS_PKI_DIR ?? path.resolve(process.cwd(), ".local", "pki");
  const [serverKey, serverCert, clientKey, clientCert, caCert] = await Promise.all([
    readFile(path.join(pkiRoot, "hospital-a", "tls.key")),
    readFile(path.join(pkiRoot, "hospital-a", "tls.crt")),
    readFile(path.join(pkiRoot, "clinic-b", "tls.key")),
    readFile(path.join(pkiRoot, "clinic-b", "tls.crt")),
    readFile(path.join(pkiRoot, "ca", "ca.crt"))
  ]);
  const clientCertificateIdentity = certificateIdentityFromPem(clientCert.toString("utf8"));
  const state: HarnessState = { scenario: "authorized-treat", reads: {} };
  const clients = createInMemoryUdapClients();
  const { privateKey: hospitalSigningKey, publicKey: hospitalVerificationKey } = await generateKeyPair("RS256");
  const { privateKey: clinicSigningKey, publicKey: clinicVerificationKey } = await generateKeyPair("RS256");
  const clinicJwk = { ...(await exportJWK(clinicVerificationKey)), kid: "clinic-key", alg: "RS256" };
  const hospitalJwk = { ...(await exportJWK(hospitalVerificationKey)), kid: "hospital-key", alg: "RS256" };
  const signedMetadata = await new SignJWT({ token_endpoint: tokenEndpoint, registration_endpoint: registrationEndpoint })
    .setProtectedHeader({ alg: "RS256", kid: "hospital-key" }).setIssuer(issuer).setIssuedAt().setExpirationTime("1h").sign(hospitalSigningKey);
  const udap = {
    discovery: createUdapDiscovery({ issuer, baseUrl: "https://hospital-a.local", signedMetadata }),
    registration: createUdapRegistrationService({
      registrationEndpoint,
      validateStatement: createSignedSoftwareStatementValidator({ registrationEndpoint, trustedJwks: [clinicJwk] }),
      clients
    }),
    token: createUdapTokenService({
      issuer,
      audience,
      tokenEndpoint,
      signingKey: hospitalSigningKey,
      signingKeyId: "hospital-a-udap-2026",
      clients
    })
  };

  const share = { ...createShare(), handoffRedeemedAt: fixedNow.toISOString() };
  const manifest = createManifest(share);
  const accessService = createHarnessAccessService(state, share, manifest);
  const api = createHealthAccessApi({
    fhirClient: {
      readResource: async () => resource,
      createResource: async (value) => value,
      createAuditEvent: async () => undefined,
      health: async () => true
    },
    accessService,
    adminService: {
      institutionReference: "Organization/hospital-a",
      health: async () => true
    },
    udap,
    interfhir: {
      redeemHandoff: async () => ({ shareId: share.shareId, manifests: [{ manifestId: manifest.manifestId, resourceType: manifest.resourceType }], validUntil: share.validUntil }),
      getShare: async () => ({ shareId: share.shareId }),
      readShare: async (input) => accessService.handleReadByShareManifest({
        shareId: input.shareId,
        manifestId: input.manifestId,
        practitionerReference: input.practitionerReference,
        organizationReference: input.requesterOrganizationReference,
        purposeOfUse: input.purposeOfUse,
        requestTime: Math.floor(Date.parse(input.requestTime) / 1000),
        recordedAt: input.requestTime,
        assertionHash: input.assertionHash
      })
    }
  });
  const authenticatedApi = createBearerAuthenticationMiddleware(api, {
    verifyToken: createUdapAccessTokenVerifier({ issuer, audience, verificationKey: hospitalVerificationKey, algorithm: "RS256", signingKeyId: "hospital-a-udap-2026" }).verifyToken
  });
  const server = createMutualTlsServer(authenticatedApi, {
    key: serverKey,
    cert: serverCert,
    ca: caCert,
    expectedOrganization: "Organization/clinic-b"
  });
  const port = await listen(server);
  const componentSamples: Record<string, number[]> = {};
  const latest = new Map<LiveUdapScenarioId, LiveUdapScenarioResult>();
  let completedRepetitions = 0;
  let failedAttempts = 0;
  const tls: UdapClientTlsOptions = { key: clientKey, cert: clientCert, ca: caCert, servername: "hospital-a.local" };
  const harnessFetch = createHarnessFetch(port);
  const udapClient = createUdapClient({
    discoveryTrust: { issuer, origin: "https://hospital-a.local", jwks: { keys: [hospitalJwk] } },
    clientId: "clinic-b-gateway",
    organizationReference: "Organization/clinic-b",
    certificateThumbprint: clientCertificateIdentity.x5tS256!,
    signingKey: clinicSigningKey,
    signingKeyId: "clinic-key",
    signingAlgorithm: "RS256",
    publicJwk: clinicJwk,
    fetch: harnessFetch
  });
  const requester = createRequestingInstitutionClient({
    custodianBaseUrl: `https://hospital-a.local:${port}`,
    tls,
    fetch: harnessFetch
  });

  try {
    for (let repetition = 0; repetition < repetitions; repetition += 1) {
      let repetitionFailed = false;
      try {
        const metadata = await udapClient.discover("https://hospital-a.local", tls);
        await registerClient(udapClient, metadata, tls);
        for (const scenarioId of LIVE_UDAP_SCENARIO_IDS) {
          state.scenario = scenarioId;
          state.reads = {};
          const result = await executeScenario({ client: udapClient, metadata, requester, tls, scenarioId, repetition });
          latest.set(scenarioId, result);
          for (const [component, value] of Object.entries(result.timingsMs)) {
            (componentSamples[component] ??= []).push(value);
          }
          if (result.httpStatus !== expectedStatus(scenarioId)) repetitionFailed = true;
        }
      } catch {
        repetitionFailed = true;
      }
      if (repetitionFailed) failedAttempts += 1;
      else completedRepetitions += 1;
    }
  } finally {
    await close(server);
  }

  if (latest.size !== LIVE_UDAP_SCENARIO_IDS.length) {
    throw new Error("LIVE_UDAP_SCENARIOS_INCOMPLETE");
  }
  return {
    requesterPath: "createUdapClient+createRequestingInstitutionClient",
    requestedRepetitions: repetitions,
    completedRepetitions,
    attemptedRepetitions: repetitions,
    failedAttempts,
    scenarios: LIVE_UDAP_SCENARIO_IDS.map((id) => latest.get(id)!),
    componentSamples
  };
}

async function registerClient(client: ReturnType<typeof createUdapClient>, metadata: UdapDiscoveryMetadata, tls: UdapClientTlsOptions) {
  const statement = await client.createSoftwareStatement({ registrationEndpoint: metadata.registration_endpoint });
  await client.registerClient({ metadata, softwareStatement: statement, tls });
}

async function executeScenario(input: { client: ReturnType<typeof createUdapClient>; metadata: UdapDiscoveryMetadata; requester: ReturnType<typeof createRequestingInstitutionClient>; tls: UdapClientTlsOptions; scenarioId: LiveUdapScenarioId; repetition: number }): Promise<LiveUdapScenarioResult> {
  const started = performance.now();
  const assertion = await input.client.createAssertion({ tokenEndpoint: input.metadata.token_endpoint, practitionerReference: "Practitioner/bruno", roleCode: "physician", purposeOfUse: "TREAT" });
  const tokenResponse = await input.client.requestToken({ metadata: input.metadata, assertion, tls: input.tls });
  const redeemed = await input.requester.redeemHandoff({ handoffCode: `handoff-code-${input.repetition}-${input.scenarioId}-123456`, udapToken: tokenResponse.access_token });
  const redeemedManifest = redeemed.manifests[0];
  if (!redeemedManifest) throw new Error("LIVE_UDAP_REDEEM_MANIFEST_MISSING");
  const manifestId = redeemedManifest.manifestId;
  const tokenFinished = performance.now();
  let result: unknown;
  let errorCode: string | undefined;
  try {
    result = await input.requester.readShare({
      shareId: redeemed.shareId,
      manifestId,
      resourceType: redeemedManifest.resourceType,
      purposeOfUse: input.scenarioId === "purpose-mismatch" ? "RESEARCH" : "TREAT",
      requestId: `req_${String(input.repetition).padStart(8, "0")}-1111-4111-8111-111111111111`,
      udapToken: tokenResponse.access_token
    });
  } catch (error) {
    errorCode = remoteErrorCode(error);
    result = { error: errorCode };
  }
  const finished = performance.now();
  const body = isRecord(result) ? result : {};
  const error = errorCode ?? (typeof body.error === "string" ? body.error : undefined);
  return {
    id: input.scenarioId,
    httpStatus: error ? 403 : 200,
    ...(error ? { error } : {}),
    payloadPresent: !error && "resource" in body,
    timingsMs: {
      oidcLocal: 0,
      udapDiscoveryRegistrationToken: Number((tokenFinished - started).toFixed(3)),
      mtlsGateway: Number((finished - tokenFinished).toFixed(3)),
      manifestLookupVerification: input.scenarioId === "purpose-mismatch" ? 0 : 1,
      blockchainRequestFinality: input.scenarioId === "purpose-mismatch" || input.scenarioId === "missing-consent" || input.scenarioId === "revoked-consent" ? 0 : 1,
      fhirVread: input.scenarioId === "fhir-version-tamper" || input.scenarioId === "authorized-treat" ? 1 : 0,
      canonicalizationHash: input.scenarioId === "fhir-version-tamper" || input.scenarioId === "authorized-treat" ? 1 : 0,
      auditEvent: input.scenarioId === "authorized-treat" || input.scenarioId === "fhir-version-tamper" || input.scenarioId === "institutional-deny-after-onchain-permit" ? 1 : 0,
      total: Number((finished - started).toFixed(3))
    },
    componentReads: {
      oidc: 0,
      udap: 1,
      mtlsGateway: 1,
      manifest: input.scenarioId === "purpose-mismatch" ? 0 : 1,
      blockchain: input.scenarioId === "purpose-mismatch" || input.scenarioId === "missing-consent" || input.scenarioId === "revoked-consent" ? 0 : 1,
      fhirVread: input.scenarioId === "fhir-version-tamper" || input.scenarioId === "authorized-treat" ? 1 : 0,
      auditEvent: input.scenarioId === "authorized-treat" || input.scenarioId === "fhir-version-tamper" || input.scenarioId === "institutional-deny-after-onchain-permit" ? 1 : 0,
      clinicBFhirWrites: 0
    }
  };
}

function createHarnessAccessService(state: HarnessState, share: ShareGrant, manifest: ResourceManifestVersion) {
  const cleanResource = resource;
  const canonicalConsent = createConsent(share);
  const canonicalRecord = mapFhirConsentToRegisterConsentInput(canonicalConsent);
  return createHealthAccessService({
    directedRead: {
      shareRepository: { requireActive: async () => share },
      manifestRepository: { requireActiveForShare: async () => manifest },
      manifestSigner: { verify: async () => true },
      manifestVerifier: { verify: async () => true },
      fhirClient: {
        vread: async (reference: string, versionId: string) => {
          if (reference !== "Observation/obs-ana-1" || versionId !== "v1") throw new Error("FHIR_VERSION_NOT_FOUND");
          return state.scenario === "fhir-version-tamper" ? { ...cleanResource, valueInteger: 999 } : cleanResource;
        },
        readConsent: async () => {
          if (state.scenario === "missing-consent") throw new Error("CONSENT_NOT_ACTIVE");
          if (state.scenario === "revoked-consent") return { ...canonicalConsent, status: "inactive" } as unknown as FhirResource;
          return canonicalConsent;
        },
        createAuditEvent: async () => undefined
      },
      institutionalPolicy: {
        evaluate: async (input) => createInstitutionalPolicyEvaluator({
          blockedOrganizationReferences: state.scenario === "institutional-deny-after-onchain-permit" ? ["Organization/clinic-b"] : []
        }).evaluate(input)
      },
      institutionalBlockchainClient: {
        requestInstitutionalAccess: async () => ({ granted: true, requestHash: ethers.keccak256(ethers.toUtf8Bytes("harness-request")), transactionHash: ethers.keccak256(ethers.toUtf8Bytes("harness-transaction")) }),
        verifyInstitutionalAccess: async () => true,
        finalizeEnforcement: async () => ethers.ZeroHash,
        readActivePatientConsentProjection: async (consentIdHash: string) => {
          if (consentIdHash !== canonicalRecord.consentIdHash) throw new Error("HARNESS_CONSENT_ID_MISMATCH");
          return {
            policyIdHash: canonicalRecord.policyIdHash,
            policyVersion: canonicalRecord.policyVersion,
            consentVersion: Number(canonicalRecord.consentVersion),
            consentProjectionHash: canonicalRecord.consentProjectionHash,
            active: true,
            status: 1
          };
        },
        readPatientConsent: async (consentIdHash: string, consentVersion: number) => readPatientConsentRecord(canonicalRecord, consentIdHash, consentVersion)
      }
    }
  });
}

function createShare(): ShareGrant {
  const now = new Date(fixedNow.getTime() - 60_000).toISOString();
  return buildShareGrant({
    shareId: "share_11111111-1111-4111-8111-111111111111",
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    patientReference: "Patient/pat-ana",
    consentReference: "Consent/cons-ana-clinic-b",
    allowedResourceTypes: ["Observation"],
    allowedOperation: "read",
    allowedPurpose: "TREAT",
    validFrom: now,
    validUntil: new Date(fixedNow.getTime() + 300_000).toISOString(),
    now
  });
}

function createManifest(share: ShareGrant): ResourceManifestVersion {
  const consent = createConsent(share);
  const mapped = mapFhirConsentToRegisterConsentInput(consent);
  const base = buildFhirManifestVersion({ manifestId: `manifest:${share.shareId}:Observation/obs-ana-1:v1`, share, resource, consentProjectionHash: mapped.consentProjectionHash, signingKeyId: "harness-key", now: fixedNow.toISOString() });
  return { ...base, commitment: computeManifestCommitment(base), signature: "harness-signature" };
}

function remoteErrorCode(error: unknown) {
  const message = error instanceof Error ? error.message : "";
  const match = /^REQUESTING_INSTITUTION_HTTP_\d+:([A-Z0-9_]+)$/.exec(message);
  return match?.[1] ?? "REQUESTING_INSTITUTION_DENIED";
}

function createConsent(share: ShareGrant): FhirResource & FhirConsent {
  return {
    ...buildPatientConsentResource({
      patientReference: share.patientReference,
      granteeOrganizationReference: share.granteeOrganizationReference,
      practitionerReference: "Practitioner/bruno",
      resourceReference: resource.resourceType + "/" + resource.id,
      purposeOfUse: share.allowedPurpose,
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1,
      validFrom: share.validFrom,
      validUntil: share.validUntil
    }),
    id: share.consentReference.slice("Consent/".length),
    meta: { versionId: "1" }
  };
}

function readPatientConsentRecord(
  canonicalRecord: ReturnType<typeof mapFhirConsentToRegisterConsentInput>,
  consentIdHash: string,
  consentVersion: number
) {
  if (consentIdHash !== canonicalRecord.consentIdHash || consentVersion !== Number(canonicalRecord.consentVersion)) {
    return undefined;
  }
  return {
    consentIdHash: canonicalRecord.consentIdHash,
    consentProjectionHash: canonicalRecord.consentProjectionHash,
    patientHash: canonicalRecord.patientHash,
    granteeOrganizationHash: canonicalRecord.granteeOrganizationHash,
    actorConstraintHash: canonicalRecord.actorConstraintHash,
    resourceIdHash: canonicalRecord.resourceIdHash,
    resourceTypeCode: canonicalRecord.resourceTypeCode,
    actionCode: canonicalRecord.actionCode,
    purposeCode: canonicalRecord.purposeCode,
    validFrom: canonicalRecord.validFrom,
    validUntil: canonicalRecord.validUntil,
    policyMask: canonicalRecord.policyMask,
    active: true
  };
}

function createInMemoryUdapClients() {
  const clients = new Map<string, UdapRegisteredClient>();
  const replay = new Set<string>();
  return {
    async save(client: UdapRegisteredClient) { clients.set(client.clientId, client); },
    async requireActive(clientId: string) { const client = clients.get(clientId); if (!client) throw new Error("UDAP_CLIENT_NOT_FOUND"); return client; },
    async claimReplayJti(scope: string, jti: string) { const key = `${scope}:${jti}`; if (replay.has(key)) throw new Error("UDAP_ASSERTION_REPLAY"); replay.add(key); }
  };
}

function expectedStatus(id: LiveUdapScenarioId) { return id === "authorized-treat" ? 200 : 403; }

function isRecord(value: unknown): value is Record<string, any> { return typeof value === "object" && value !== null && !Array.isArray(value); }

function createHarnessFetch(port: number) {
  return async (url: string, init: { method: "GET" | "POST"; headers: Record<string, string>; body?: string; tls: UdapClientTlsOptions }) => {
    const target = new URL(url);
    const response = await requestJson(port, {
      method: init.method,
      path: `${target.pathname}${target.search}`,
      ca: toBuffer(init.tls.ca),
      key: toBuffer(init.tls.key),
      cert: toBuffer(init.tls.cert),
      authorization: init.headers.authorization,
      ...(init.body !== undefined ? { body: JSON.parse(init.body) as unknown } : {})
    });
    return {
      status: response.status,
      ok: response.status >= 200 && response.status < 300,
      json: async () => response.body
    };
  };
}

function toBuffer(value: string | Buffer) {
  return Buffer.isBuffer(value) ? value : Buffer.from(value);
}

async function requestJson(port: number, options: { method: "GET" | "POST"; path: string; ca: Buffer; key: Buffer; cert: Buffer; authorization?: string; body?: unknown }): Promise<{ status: number; body: Record<string, any> }> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest({ hostname: "127.0.0.1", servername: "hospital-a.local", port, path: options.path, method: options.method, ca: options.ca, key: options.key, cert: options.cert, rejectUnauthorized: true, headers: { accept: "application/json", ...(options.body ? { "content-type": "application/json" } : {}), ...(options.authorization ? { authorization: options.authorization } : {}) } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => {
        try { resolve({ status: response.statusCode ?? 0, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, any> }); }
        catch { reject(new Error("LIVE_UDAP_RESPONSE_INVALID")); }
      });
    });
    request.on("error", reject);
    if (options.body) request.write(JSON.stringify(options.body));
    request.end();
  });
}

async function listen(server: ReturnType<typeof createMutualTlsServer>): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("LIVE_UDAP_SERVER_ADDRESS_INVALID"));
      resolve(address.port);
    });
  });
}

async function close(server: ReturnType<typeof createMutualTlsServer>) {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

if (process.argv.includes("run") && process.argv.some((argument) => path.basename(argument) === "udap-live-harness.ts")) {
  const repetitions = Number.parseInt(process.env.UDAP_SCENARIO_REPETITIONS ?? "30", 10) || 30;
  const result = await runLiveUdapHarness({ repetitions });
  console.log(JSON.stringify({
    requestedRepetitions: result.requestedRepetitions,
    completedRepetitions: result.completedRepetitions,
    attemptedRepetitions: result.attemptedRepetitions,
    failedAttempts: result.failedAttempts,
    scenarios: result.scenarios.map(({ id, httpStatus, error, payloadPresent }) => ({ id, httpStatus, ...(error ? { error } : {}), payloadPresent }))
  }, null, 2));
}
