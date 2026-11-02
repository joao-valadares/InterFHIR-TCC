import { createHealthAccessApi } from "../middleware/src/api/api-handler.js";
import { createHttpServer } from "../middleware/src/api/http-server.js";
import { createMutualTlsServer } from "../middleware/src/api/http-server.js";
import { readFile } from "node:fs/promises";
import { createLocalJWKSet, decodeJwt, importPKCS8, jwtVerify } from "jose";
import {
  createBearerAuthenticationMiddleware,
  createLocalJwtService
} from "../middleware/src/auth/authentication.js";
import { createOidcVerifier } from "../middleware/src/auth/oidc-verifier.js";
import { createHealthAccessService } from "../middleware/src/access/health-access-service.js";
import { createEthersAccessClient } from "../middleware/src/blockchain/ethers-access-client.js";
import { createManifestVersionCommitmentVerifier } from "../middleware/src/blockchain/manifest-version-commitment-verifier.js";
import {
  assertInstitutionBinding,
  loadHealthAccessConfig,
  loadHostDevelopmentHealthAccessConfig,
  requireExplicitInstitutionGatewayBinding,
  requireInstitutionBinding
} from "../middleware/src/config.js";
import { createHapiFhirClient } from "../middleware/src/fhir/hapi-fhir-client.js";
import { hashFhirResource } from "../middleware/src/fhir/resource-hasher.js";
import { mapFhirConsentToRegisterConsentInput } from "../middleware/src/fhir/consent-mapper.js";
import { createPostgresManifestVersionRepository } from "../middleware/src/manifest/postgres-manifest-repository.js";
import { createManifestSigner } from "../middleware/src/manifest/manifest-signer.js";
import { createManifestPublicationService } from "../middleware/src/manifest/manifest-publication-service.js";
import { createCustodianManifestAnchor } from "../middleware/src/manifest/custodian-manifest-anchor.js";
import {
  assertCanonicalRuntimeDependencies,
  createConfiguredContractRuntime
} from "./runtime-contracts.js";
import { createUdapDiscovery } from "../middleware/src/udap/udap-discovery.js";
import { createPostgresUdapClientRepository } from "../middleware/src/udap/postgres-udap-client-repository.js";
import { createSignedSoftwareStatementValidator, createUdapRegistrationService } from "../middleware/src/udap/udap-registration-service.js";
import { createUdapAccessTokenVerifierFromIssuerJwks, createUdapTokenService } from "../middleware/src/udap/udap-token-service.js";
import { createPostgresShareRepository } from "../middleware/src/share/postgres-share-repository.js";
import { createPostgresConsentOperationRepository } from "../middleware/src/consent/postgres-consent-operation-repository.js";
import {
  createPatientConsentService,
  isEmptyPatientConsentRecord
} from "../middleware/src/consent/patient-consent-service.js";
import { createPatientShareService } from "../middleware/src/interfhir/patient-share-service.js";
import { createCustodianAccessService } from "../middleware/src/interfhir/custodian-access-service.js";
import { createInstitutionalPolicyEvaluator } from "../middleware/src/policy/institutional-policy.js";
import { extractFhirResourceMetadata } from "../middleware/src/fhir/resource-metadata.js";
import { hashIdentifier, hashReference } from "../middleware/src/authorization/authorization-model.js";
import { getNetworkPolicyDefinition } from "../middleware/src/authorization/policy-definition.js";
import { mapActionCode, mapPurposeCode, mapResourceTypeCode } from "../middleware/src/abac/policy-mask.js";
import {
  assertPublicJwkSetsEqual,
  assertUdapTrustedJwks,
  validateIdentityKeyMaterial
} from "../middleware/src/identity/key-material.js";
import type { ShareGrant } from "../middleware/src/share/share-grant.js";
import { ethers } from "ethers";

requireExplicitInstitutionGatewayBinding(process.env);

const config =
  process.env.HEALTH_ACCESS_HOST_DEV === "true"
    ? loadHostDevelopmentHealthAccessConfig()
    : loadHealthAccessConfig();
const publicPort = config.gateway.publicPort;
const peerPort = config.gateway.peerPort;
const bindAddress = config.gateway.bindAddress;
const institutionReference = requireInstitutionBinding(config.institutionReference);
assertInstitutionBinding(
  institutionReference,
  config.selectedFhirVault.custodianOrganizationReference
);
await validateIdentityKeyMaterial(config);
const fhirClient = createHapiFhirClient({ baseUrl: config.selectedFhirVault.baseUrl });
if (!fhirClient.updateResource) throw new Error("FHIR_UPDATE_NOT_CONFIGURED");
if (!fhirClient.upsertResource) throw new Error("FHIR_UPSERT_NOT_CONFIGURED");
const patientConsentFhirClient = {
  readResource: fhirClient.readResource.bind(fhirClient),
  createResource: fhirClient.createResource.bind(fhirClient),
  upsertResource: fhirClient.upsertResource.bind(fhirClient),
  updateResource: fhirClient.updateResource.bind(fhirClient)
};
const manifestVersionRepository = createPostgresManifestVersionRepository({ connectionString: config.institutionMetadataDatabaseUrl });
await manifestVersionRepository.migrate();
const manifestSigner = config.manifestSigning
  ? createManifestSigner({ privateKey: config.manifestSigning.privateJwk, publicKey: config.manifestSigning.publicJwk, signingKeyId: config.manifestSigning.keyId })
  : undefined;
const shareRepository = createPostgresShareRepository({ connectionString: config.institutionMetadataDatabaseUrl });
await shareRepository.migrate();
const consentOperationRepository = createPostgresConsentOperationRepository({ connectionString: config.institutionMetadataDatabaseUrl });
await consentOperationRepository.migrate();
let patientDirectedConsentRegistrar: ((input: { share: ShareGrant; resourceReferences: string[]; resourceTypes: string[] }) => Promise<void>) | undefined;
const patientShares = createPatientShareService({
  custodianOrganizationReference: config.selectedFhirVault.custodianOrganizationReference,
  shares: shareRepository,
  validate: async (input) => {
    const consent = await fhirClient.readResource(input.consentReference);
    if (consent.resourceType !== "Consent" || consent.status !== "active") throw new Error("FHIR_CONSENT_NOT_ACTIVE");
    const consentRecord = consent as { patient?: { reference?: string }; provision?: { actor?: Array<{ reference?: { reference?: string } }> } };
    if (consentRecord.patient?.reference !== input.patientReference) throw new Error("FHIR_CONSENT_PATIENT_MISMATCH");
    if (!consentRecord.provision?.actor?.some((actor) => actor.reference?.reference === input.granteeOrganizationReference)) throw new Error("FHIR_CONSENT_GRANTEE_MISMATCH");
    const resourceTypes = await Promise.all(input.resourceReferences.map(async (reference) => {
      const resource = await fhirClient.readResource(reference);
      const metadata = extractFhirResourceMetadata(resource);
      if (metadata.patientReference !== input.patientReference) throw new Error("SHARE_RESOURCE_PATIENT_MISMATCH");
      return metadata.resourceType;
    }));
    return { resourceTypes };
  },
  registerDirectedConsent: async (input) => {
    if (!patientDirectedConsentRegistrar) throw new Error("DIRECTED_CONSENT_REGISTRAR_NOT_CONFIGURED");
    await patientDirectedConsentRegistrar(input);
  }
});
const udapClients = config.udap
  ? createPostgresUdapClientRepository({ connectionString: config.institutionMetadataDatabaseUrl })
  : undefined;
if (udapClients) await udapClients.migrate();
const udap = config.udap && udapClients
  ? await createConfiguredUdap(config.udap, udapClients)
  : undefined;
const contractRuntime = await createConfiguredContractRuntime({
  blockchainRpcUrl: config.blockchainRpcUrl,
  healthAccessControlAddress: config.healthAccessControlAddress,
  blockchainWallets: config.blockchainWallets,
  allowEphemeralDeployment: config.bootstrapEnabled
});
const accessControl = contractRuntime.accessControl;
const patientAccessControl = accessControl.connect(contractRuntime.patientSigner) as unknown as {
  registerDirectedConsent(input: Record<string, unknown>): Promise<{ wait(): Promise<unknown> }>;
};
patientDirectedConsentRegistrar = async ({ share, resourceReferences }) => {
  if (resourceReferences.length !== 1) throw new Error("DIRECTED_CONSENT_RESOURCE_SCOPE_UNSUPPORTED");
  const consent = await fhirClient.readResource(share.consentReference);
  const mapped = mapFhirConsentToRegisterConsentInput(consent);
  if (mapped.organizationHash !== ethers.keccak256(ethers.toUtf8Bytes(share.granteeOrganizationReference))) throw new Error("DIRECTED_CONSENT_GRANTEE_MISMATCH");
  if (mapped.resourceIdHash !== ethers.keccak256(ethers.toUtf8Bytes(resourceReferences[0]))) throw new Error("DIRECTED_CONSENT_RESOURCE_MISMATCH");
  const transaction = await patientAccessControl.registerDirectedConsent({
    consentIdHash: mapped.consentHash,
    consentProjectionHash: hashFhirResource(consent),
    patientHash: mapped.patientHash,
    granteeOrganizationHash: mapped.organizationHash,
    actorConstraintHash: mapped.actorHash,
    resourceIdHash: mapped.resourceIdHash,
    resourceTypeCode: mapped.resourceTypeCode,
    actionCode: mapped.actionCode,
    purposeCode: mapped.purposeCode,
    validFrom: mapped.validFrom,
    validUntil: mapped.validUntil,
    policyMask: mapped.policyMask
  });
  await transaction.wait();
};
let publication: ReturnType<typeof createManifestPublicationService> | undefined;
if (manifestSigner) {
  const configuredPublication = createManifestPublicationService({
    shareRepository,
    manifestRepository: manifestVersionRepository,
    fhirClient: { readLatest: (reference) => fhirClient.readResource(reference), readConsent: (reference) => fhirClient.readResource(reference) },
    signer: manifestSigner,
    anchor: createCustodianManifestAnchor({ accessControl: accessControl as unknown as Parameters<typeof createCustodianManifestAnchor>[0]["accessControl"] }),
    signingKeyId: config.manifestSigning!.keyId
  });
  publication = configuredPublication;
  patientShares.setPublisher((input) => configuredPublication.publishInitial(input));
}
const patientAccessContract = accessControl.connect(contractRuntime.patientSigner) as unknown as Parameters<typeof createEthersAccessClient>[0]["contract"];
const basePatientBlockchainClient = createEthersAccessClient({
  requesterAddress: contractRuntime.patientSigner.address,
  contract: patientAccessContract
});
const patientConsentRegistry = new ethers.Contract(
  contractRuntime.deployment.consentRegistry,
  [
    "function getPatientConsent(bytes32, uint32) view returns (tuple(bytes32 consentIdHash, bytes32 consentProjectionHash, bytes32 patientHash, bytes32 granteeOrganizationHash, bytes32 actorConstraintHash, bytes32 resourceIdHash, uint16 resourceTypeCode, uint16 actionCode, uint16 purposeCode, uint64 validFrom, uint64 validUntil, bool active, uint16 policyMask, address dataSubject))",
    "function getActivePatientConsentProjection(bytes32) view returns (tuple(bytes32 policyIdHash, uint32 policyVersion, uint32 consentVersion, bytes32 consentProjectionHash, bool active, uint8 status))"
  ],
  accessControl.runner
);
const patientBlockchainClient = {
  ...basePatientBlockchainClient,
  syncResourceIntegrity: async (input: { resourceReference: string; resourceType: string; resourceHash: string }) => {
    const transaction = await accessControl.registerResourceHash(
      hashReference(input.resourceReference),
      mapResourceTypeCode(input.resourceType),
      input.resourceHash
    );
    await transaction.wait();
  },
  getPatientConsent: async (consentIdHash: string, consentVersion: number) => {
    const mapped = mapPatientConsentRecord(await patientConsentRegistry.getPatientConsent(consentIdHash, consentVersion));
    return isEmptyPatientConsentRecord(mapped) ? undefined : mapped;
  },
  isPatientConsentActive: async (consentIdHash: string, consentVersion: number) => {
    const record = await patientConsentRegistry.getPatientConsent(consentIdHash, consentVersion);
    return Boolean(tupleField(record, "active", 11));
  }
};
const institutionRegistry = new ethers.Contract(
  await accessControl.institutionRegistry(),
  ["function getInstitution(bytes32) view returns (tuple(address gatewayAccount, bytes32 metadataCommitment, bool active))"],
  accessControl.runner
);
const patientConsents = publication
  ? createPatientConsentService({
      fhirClient: patientConsentFhirClient,
      operations: consentOperationRepository,
      shares: shareRepository,
      publication,
      blockchain: patientBlockchainClient,
      custodianOrganizationReference: config.selectedFhirVault.custodianOrganizationReference,
      validatePolicy: async (scope) => {
        const definition = getNetworkPolicyDefinition(scope.policyId, scope.policyVersion);
        if (!definition) throw new Error("POLICY_NOT_FOUND");
        const onChain = await accessControl.getActivePolicy(hashIdentifier(scope.policyId), scope.policyVersion);
        if (!Boolean(tupleField(onChain, "active", 11))) throw new Error("POLICY_NOT_ACTIVE");
        if (
          Number(tupleField(onChain, "resourceTypeCode", 3)) !== mapResourceTypeCode(definition.resourceType) ||
          Number(tupleField(onChain, "actionCode", 4)) !== mapActionCode(definition.action) ||
          Number(tupleField(onChain, "purposeCode", 5)) !== mapPurposeCode(definition.purpose) ||
          Number(tupleField(onChain, "requiredMask", 6)) !== definition.requiredAttributes
        ) {
          throw new Error("POLICY_SCOPE_MISMATCH");
        }
      },
      validateInstitution: async (organizationReference) => {
        const record = await institutionRegistry.getInstitution(hashReference(organizationReference));
        const gateway = tupleField(record, "gatewayAccount", 0);
        if (!Boolean(tupleField(record, "active", 2)) || gateway === ethers.ZeroAddress) {
          throw new Error("INSTITUTION_NOT_REGISTERED");
        }
      },
      validatePractitioner: async (practitionerReference, organizationReference) => {
        const record = await accessControl.practitioners(hashReference(practitionerReference));
        if (
          !Boolean(tupleField(record, "active", 5)) ||
          !Boolean(tupleField(record, "licenseActive", 4)) ||
          String(tupleField(record, "organizationHash", 1)).toLowerCase() !== hashReference(organizationReference).toLowerCase()
        ) {
          throw new Error("PRACTITIONER_ORGANIZATION_MISMATCH");
        }
      },
      validateResource: async (resourceReference, patientReference) => {
        let resource;
        try {
          resource = await fhirClient.readResource(resourceReference);
        } catch (error) {
          if (error instanceof Error && error.message === "FHIR_HTTP_404") throw new Error("RESOURCE_NOT_FOUND");
          throw error;
        }
        const metadata = extractFhirResourceMetadata(resource);
        if (metadata.patientReference !== patientReference) throw new Error("FHIR_RESOURCE_PATIENT_MISMATCH");
        return { resourceReference: metadata.resourceReference, resourceType: metadata.resourceType };
      }
    })
  : undefined;
const institutionalAccessControl = accessControl.connect(contractRuntime.pepSigner) as unknown as Parameters<typeof createEthersAccessClient>[0]["contract"];
const institutionalClient = createEthersAccessClient({ requesterAddress: contractRuntime.pepSigner.address, contract: institutionalAccessControl });
const accessService = createHealthAccessService({
  ...(manifestSigner ? { directedRead: { observe: process.env.INTERFHIR_DIAGNOSTICS === "true" ? (observation) => console.log(JSON.stringify(observation)) : undefined, shareRepository, manifestRepository: manifestVersionRepository, manifestSigner, manifestVerifier: createManifestVersionCommitmentVerifier(accessControl as unknown as Parameters<typeof createManifestVersionCommitmentVerifier>[0]), fhirClient: { vread: fhirClient.vread.bind(fhirClient), readConsent: fhirClient.readResource.bind(fhirClient), createAuditEvent: fhirClient.createAuditEvent.bind(fhirClient) }, institutionalPolicy: createInstitutionalPolicyEvaluator(), institutionalBlockchainClient: { ...institutionalClient, readActivePatientConsentProjection: async (consentIdHash: string) => mapPatientConsentProjection(await patientConsentRegistry.getActivePatientConsentProjection(consentIdHash)), readPatientConsent: async (consentIdHash: string, consentVersion: number) => { const mapped = mapPatientConsentRecord(await patientConsentRegistry.getPatientConsent(consentIdHash, consentVersion)); return isEmptyPatientConsentRecord(mapped) ? undefined : mapped; } } } } : {})
});
const interfhir = manifestSigner ? createCustodianAccessService({ shares: shareRepository, manifests: manifestVersionRepository, deliver: async (input) => accessService.handleReadByShareManifest({ requestId: input.requestId, shareId: input.share.shareId, manifestId: input.manifest.manifestId, practitionerReference: input.practitionerReference, organizationReference: input.requesterOrganizationReference, purposeOfUse: input.purposeOfUse, requestTime: Math.floor(Date.parse(input.requestTime) / 1000), recordedAt: input.requestTime, assertionHash: input.assertionHash }) }) : undefined;

// This is the production entrypoint boundary. Unit-test factories may remain
// partial, but this process cannot expose a production-looking partial API.
assertCanonicalRuntimeDependencies({
  manifestSigningConfigured: manifestSigner !== undefined,
  patientConsentServiceConfigured: patientConsents !== undefined,
  directedAccessConfigured: manifestSigner !== undefined,
  interfhirConfigured: interfhir !== undefined
});

const api = createHealthAccessApi(
  {
    fhirClient,
    accessService,
    adminService: {
      institutionReference,
      health: async () => {
        const owner = await accessControl.owner();
        return typeof owner === "string" && owner.startsWith("0x");
      }
    },
    manifestRepository: manifestVersionRepository,
    ...(patientConsents ? { patientConsents } : {}),
    ...(manifestSigner ? { patientShares } : {}),
    ...(interfhir ? { interfhir } : {}),
    ...(udap ? { udap } : {})
  },
  {
    bootstrapEnabled: config.bootstrapEnabled,
    institutionReference
  }
);

if (config.authentication.oidcIssuers.length === 0 && !config.authentication.secret) {
  throw new Error("JWT_SECRET_REQUIRED");
}

const humanVerifier = config.authentication.oidcIssuers.length > 0
  ? { verifyToken: createOidcVerifier({ issuers: config.authentication.oidcIssuers }).verify }
  : createLocalJwtService({
        secret: config.authentication.secret as string,
        issuer: config.authentication.issuer,
        audience: config.authentication.audience
      });
const udapVerifier = config.udap && udap
  ? await createUdapAccessTokenVerifierFromIssuerJwks({
      issuer: config.udap.issuer,
      audience: config.udap.tokenAudience,
      issuerJwks: udap.issuerJwks,
      signingKeyId: config.udap.signingKeyId,
      signingAlgorithm: config.udap.signingAlgorithm
    })
  : undefined;
const authenticatedApi = createBearerAuthenticationMiddleware(api, {
  async verifyToken(token) {
    if (udapVerifier && decodeJwt(token).iss === config.udap?.issuer) return udapVerifier.verifyToken(token);
    return humanVerifier.verifyToken(token);
  }
});

const scheme = config.tls ? "https" : "http";
const createGatewayServer = async () => {
  if (!config.tls) return createHttpServer(authenticatedApi);
  return createMutualTlsServer(authenticatedApi, {
    key: await readFile(config.tls.keyPath),
    cert: await readFile(config.tls.certPath),
    ca: await readFile(config.tls.caPath),
    expectedOrganization: config.tls.expectedPeerOrganization
  });
};
const servers = [await createGatewayServer(), await createGatewayServer()];
let listeningServers = 0;
let cleanupStarted = false;

for (const server of servers) {
  server.once("listening", () => {
    listeningServers += 1;
    if (listeningServers !== servers.length) return;
    console.log(
      JSON.stringify(
        {
          status: "ready",
          transport: scheme,
          apiBaseUrl: `${scheme}://${bindAddress}:${publicPort}`,
          publicBaseUrl: `${scheme}://${bindAddress}:${publicPort}`,
          peerBaseUrl: `${scheme}://${bindAddress}:${peerPort}`,
          publicPort,
          peerPort,
          bindAddress,
          fhirVaultId: config.selectedFhirVault.id,
          fhirBaseUrl: config.selectedFhirVault.baseUrl,
          contractMode: contractRuntime.mode,
          deployment: contractRuntime.deployment,
          manifestSigningConfigured: manifestSigner !== undefined
        },
        null,
        2
      )
    );
  });
  server.on("error", (error) => {
    console.error(JSON.stringify({ status: "failed", error: error instanceof Error ? error.message : String(error) }));
    process.exitCode = 1;
    for (const other of servers) {
      if (other.listening) other.close();
    }
  });
  server.on("close", () => {
    if (!servers.every((candidate) => !candidate.listening)) return;
    if (cleanupStarted) return;
    cleanupStarted = true;
    void manifestVersionRepository.close();
    void udapClients?.close();
    void shareRepository.close();
    void consentOperationRepository.close();
    contractRuntime.close();
  });
}

servers[0].listen(publicPort, bindAddress);
servers[1].listen(peerPort, bindAddress);

function tupleField(record: unknown, name: string, index: number): unknown {
  if (record === null || typeof record !== "object") return undefined;
  const value = record as Record<string | number, unknown>;
  return value[name] ?? value[index];
}

function mapPatientConsentRecord(record: unknown) {
  return {
    consentIdHash: String(tupleField(record, "consentIdHash", 0)),
    consentProjectionHash: String(tupleField(record, "consentProjectionHash", 1)),
    patientHash: String(tupleField(record, "patientHash", 2)),
    granteeOrganizationHash: String(tupleField(record, "granteeOrganizationHash", 3)),
    actorConstraintHash: String(tupleField(record, "actorConstraintHash", 4)),
    resourceIdHash: String(tupleField(record, "resourceIdHash", 5)),
    resourceTypeCode: Number(tupleField(record, "resourceTypeCode", 6)),
    actionCode: Number(tupleField(record, "actionCode", 7)),
    purposeCode: Number(tupleField(record, "purposeCode", 8)),
    validFrom: Number(tupleField(record, "validFrom", 9)),
    validUntil: Number(tupleField(record, "validUntil", 10)),
    active: Boolean(tupleField(record, "active", 11)),
    policyMask: Number(tupleField(record, "policyMask", 12))
  };
}

function mapPatientConsentProjection(record: unknown) {
  return {
    policyIdHash: String(tupleField(record, "policyIdHash", 0)),
    policyVersion: Number(tupleField(record, "policyVersion", 1)),
    consentVersion: Number(tupleField(record, "consentVersion", 2)),
    consentProjectionHash: String(tupleField(record, "consentProjectionHash", 3)),
    active: Boolean(tupleField(record, "active", 4)),
    status: Number(tupleField(record, "status", 5))
  };
}

async function createConfiguredUdap(
  settings: NonNullable<typeof config.udap>,
  clients: ReturnType<typeof createPostgresUdapClientRepository>
) {
  const tokenEndpoint = `${settings.baseUrl}/udap/token`;
  const registrationEndpoint = `${settings.baseUrl}/udap/register`;
  const signingKey = await importPKCS8(await readFile(settings.signingKeyPath, "utf8"), settings.signingAlgorithm);
  const signedMetadata = settings.signedMetadataPath
    ? await readFile(settings.signedMetadataPath, "utf8")
    : settings.signedMetadata;
  if (!signedMetadata) throw new Error("UDAP_SIGNED_METADATA_UNAVAILABLE");
  const issuerJwks = JSON.parse(await readFile(settings.issuerJwksPath, "utf8")) as {
    keys?: Record<string, unknown>[];
  };
  const issuerKeys = issuerJwks.keys;
  if (!Array.isArray(issuerKeys)) throw new Error("UDAP_ISSUER_JWKS_INVALID");
  const { payload: signedMetadataPayload } = await jwtVerify(
    signedMetadata.trim(),
    createLocalJWKSet({ keys: issuerKeys }),
    { algorithms: [settings.signingAlgorithm], issuer: settings.issuer }
  );
  if (signedMetadataPayload.jwks_uri !== settings.issuerJwksUri) {
    throw new Error("UDAP_SIGNED_METADATA_JWKS_URI_MISMATCH");
  }
  const metadataJwks = signedMetadataPayload.jwks;
  if (
    !metadataJwks ||
    typeof metadataJwks !== "object" ||
    Array.isArray(metadataJwks) ||
    !Array.isArray((metadataJwks as { keys?: unknown }).keys)
  ) {
    throw new Error("UDAP_SIGNED_METADATA_JWKS_INVALID");
  }
  const metadataKeys = (metadataJwks as { keys: Record<string, unknown>[] }).keys;
  assertUdapTrustedJwks(metadataKeys);
  assertPublicJwkSetsEqual(issuerKeys, metadataKeys);
  return {
    issuerJwksUri: settings.issuerJwksUri,
    issuerJwks: { keys: issuerKeys },
    discovery: createUdapDiscovery({ issuer: settings.issuer, baseUrl: settings.baseUrl, signedMetadata: signedMetadata.trim(), issuerJwksUri: settings.issuerJwksUri }),
    registration: createUdapRegistrationService({
      registrationEndpoint,
      validateStatement: createSignedSoftwareStatementValidator({ registrationEndpoint, trustedJwks: settings.trustedJwks }),
      clients
    }),
    token: createUdapTokenService({
      issuer: settings.issuer,
      audience: settings.tokenAudience,
      tokenEndpoint,
      signingKey,
      signingKeyId: settings.signingKeyId,
      signingAlgorithm: settings.signingAlgorithm,
      clients
    })
  };
}
