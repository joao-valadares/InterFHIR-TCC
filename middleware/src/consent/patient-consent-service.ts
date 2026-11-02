import { randomBytes, randomUUID } from "node:crypto";

import type { PatientConsentInputDto } from "../blockchain/ethers-access-client.js";
import {
  canonicalizeAuthorizationDateTime,
  hashCanonicalText,
  hashReference,
  type PatientConsentScope
} from "../authorization/authorization-model.js";
import { createPatientConsentScope } from "../authorization/consent-scope.js";
import { buildPatientConsentResource } from "../fhir/consent-builder.js";
import {
  mapFhirConsentToPatientConsentGrant,
  mapFhirConsentToRegisterConsentInput,
  type FhirConsent
} from "../fhir/consent-mapper.js";
import type { FhirResource } from "../fhir/resource-hasher.js";
import type { ManifestPublicationService } from "../manifest/manifest-publication-service.js";
import type { ResourceManifestVersion } from "../manifest/resource-manifest.js";
import type { ShareGrant } from "../share/share-grant.js";
import { buildShareGrant } from "../share/share-grant.js";
import { hashHandoffCode } from "../interfhir/custodian-access-service.js";

export type ConsentOperationState =
  | "pending_fhir"
  | "pending_chain"
  | "pending_manifest"
  | "active"
  | "failed_recoverable"
  | "revoked"
  | "superseded";

export interface ConsentOperation {
  operationId: string;
  idempotencyKey: string;
  requestDigest: string;
  patientHash: string;
  consentReference?: string;
  consentVersion?: string;
  policyId: string;
  policyVersion: number;
  validFrom?: string;
  state: ConsentOperationState;
  resumeState?: Exclude<ConsentOperationState, "active" | "failed_recoverable" | "revoked" | "superseded">;
  shareId: string;
  manifestId?: string;
  handoffCodeHash?: string;
  fhirCreateAttempted?: boolean;
  chainTransactionHash?: string;
  revocationTransactionHash?: string;
  leaseOwner?: string;
  leaseToken?: string;
  leaseExpiresAt?: string;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ConsentOperationCreateInput {
  operationId: string;
  idempotencyKey: string;
  requestDigest: string;
  patientHash: string;
  policyId: string;
  policyVersion: number;
  validFrom: string;
  shareId: string;
  createdAt: string;
}

export interface ConsentOperationUpdate {
  consentReference?: string;
  consentVersion?: string;
  policyId?: string;
  policyVersion?: number;
  state?: ConsentOperationState;
  resumeState?: ConsentOperation["resumeState"] | null;
  shareId?: string;
  manifestId?: string;
  handoffCodeHash?: string;
  fhirCreateAttempted?: boolean;
  chainTransactionHash?: string;
  revocationTransactionHash?: string;
  error?: string | null;
  updatedAt?: string;
}

export interface ConsentOperationLease {
  owner: string;
  leaseToken: string;
  now: string;
  leaseExpiresAt: string;
}

export interface ConsentOperationRepository {
  createPending(input: ConsentOperationCreateInput): Promise<ConsentOperation>;
  findByIdempotencyKey(patientHash: string, idempotencyKey: string): Promise<ConsentOperation | undefined>;
  findById(operationId: string): Promise<ConsentOperation | undefined>;
  findByConsent(patientHash: string, consentReference: string): Promise<ConsentOperation | undefined>;
  update(operationId: string, patch: ConsentOperationUpdate, lease?: ConsentOperationLease): Promise<ConsentOperation>;
  claimOrCreatePending?(input: ConsentOperationCreateInput, claim: {
    owner: string;
    leaseToken: string;
    now: string;
    leaseExpiresAt: string;
  }): Promise<{ operation: ConsentOperation; claimed: boolean }>;
  claimExisting?(operationId: string, lease: ConsentOperationLease): Promise<{ operation: ConsentOperation; claimed: boolean }>;
  renewLease?(operationId: string, lease: ConsentOperationLease): Promise<ConsentOperation>;
  releaseClaim?(operationId: string, lease: Pick<ConsentOperationLease, "owner" | "leaseToken">): Promise<void>;
}

export interface PatientConsentCreateRequest {
  granteeOrganizationReference: string;
  practitionerReference?: string;
  resourceReference: string;
  purposeOfUse: string;
  policyId: string;
  policyVersion: number;
  validUntil: string;
}

export interface PatientConsentCreateInput {
  patientReference: string;
  idempotencyKey: string;
  request: PatientConsentCreateRequest;
}

export interface PatientConsentCreateResponse {
  operationId: string;
  consentReference: string;
  consentVersion: string;
  consentHash: string;
  policyId: string;
  policyVersion: number;
  shareId: string;
  manifestId: string;
  handoffCode: string;
  status: "active";
}

export interface PatientConsentRevokeInput {
  patientReference: string;
  consentReference: string;
}

export interface PatientConsentRevokeResponse {
  operationId: string;
  consentReference: string;
  consentVersion: string;
  shareId: string;
  manifestIds: string[];
  status: "revoked";
}

interface PatientConsentFhirClient {
  upsertResource(resourceReference: string, resource: FhirResource): Promise<FhirResource>;
  readResource(resourceReference: string): Promise<FhirResource>;
  updateResource(resourceReference: string, resource: FhirResource): Promise<FhirResource>;
}

interface PatientConsentShareRepository {
  savePending(share: ShareGrant): Promise<ShareGrant>;
  activate(shareId: string, updatedAt: string): Promise<ShareGrant>;
  findById(shareId: string): Promise<ShareGrant | undefined>;
  issueHandoffCode(shareId: string, codeHash: string, expiresAt: string): Promise<void>;
  revoke(shareId: string, updatedAt: string): Promise<ShareGrant>;
}

interface PatientConsentBlockchainClient {
  registerPatientConsent(input: PatientConsentInputDto): Promise<string>;
  syncResourceIntegrity?(input: {
    resourceReference: string;
    resourceType: string;
    resourceHash: string;
  }): Promise<void>;
  revokePatientConsent(consentIdHash: string, consentVersion: number): Promise<string>;
  isPatientConsentActive?(consentIdHash: string, consentVersion: number): Promise<boolean>;
  getPatientConsent?(consentIdHash: string, consentVersion: number): Promise<PatientConsentChainRecord | undefined>;
}

export interface PatientConsentChainRecord {
  consentIdHash: string;
  consentProjectionHash: string;
  patientHash: string;
  granteeOrganizationHash: string;
  actorConstraintHash: string;
  resourceIdHash: string;
  resourceTypeCode: number;
  actionCode: number;
  purposeCode: number;
  validFrom: number;
  validUntil: number;
  active: boolean;
  policyMask: number;
}

export function isEmptyPatientConsentRecord(
  record: Pick<PatientConsentChainRecord, "consentIdHash"> | null | undefined
) {
  return !record || /^0x0{64}$/i.test(record.consentIdHash);
}

interface PatientConsentValidation {
  validatePolicy(scope: PatientConsentScope): Promise<void>;
  validateInstitution(organizationReference: string): Promise<void>;
  validatePractitioner(practitionerReference: string, organizationReference: string): Promise<void>;
  validateResource(resourceReference: string, patientReference: string): Promise<{ resourceType: string; resourceReference: string }>;
}

export interface PatientConsentServiceOptions extends PatientConsentValidation {
  fhirClient: PatientConsentFhirClient;
  operations: ConsentOperationRepository;
  shares: PatientConsentShareRepository;
  publication: Pick<ManifestPublicationService, "publishInitial" | "revokeForShare"> & {
    findActiveForShare?(shareId: string): Promise<Pick<ResourceManifestVersion, "manifestId" | "resourceReference" | "resourceType" | "resourceHash"> | undefined>;
  };
  blockchain: PatientConsentBlockchainClient;
  custodianOrganizationReference: string;
  now?: () => string;
}

export interface PatientConsentService {
  create(input: PatientConsentCreateInput): Promise<PatientConsentCreateResponse>;
  revoke(input: PatientConsentRevokeInput): Promise<PatientConsentRevokeResponse>;
}

export function createPatientConsentService(options: PatientConsentServiceOptions): PatientConsentService {
  const responses = new Map<string, PatientConsentCreateResponse>();
  const handoffCodes = new Map<string, string>();
  const processLocks = new Map<string, Promise<void>>();
  assertValidationConfigured(options);

  return {
    async create(input) {
      const request = validateCreateInput(input);
      const patientHash = hashReference(input.patientReference);
      const requestDigest = computeConsentOperationRequestDigest({ patientHash, request });
      return withProcessLock(processLocks, `${patientHash}:${input.idempotencyKey}`, async () => {
        let operation = await options.operations.findByIdempotencyKey(patientHash, input.idempotencyKey);
        assertOperationDigest(operation, requestDigest);
        if (operation?.state === "active") {
          const response = responses.get(operation.operationId);
          if (!response) throw new Error("IDEMPOTENCY_RESULT_UNAVAILABLE");
          return response;
        }
        if (operation?.state === "revoked" || operation?.state === "superseded") {
          throw new Error("CONSENT_OPERATION_TERMINAL");
        }

        const owner = `consent-worker-${randomUUID()}`;
        let lease: ConsentOperationLease | undefined;
        let claimOperationId: string | undefined;
        try {
          if (options.operations.claimOrCreatePending) {
            const operationId = `op_${randomUUID()}`;
            lease = createLease(options, owner);
            const claimed = await options.operations.claimOrCreatePending({
              operationId,
              idempotencyKey: input.idempotencyKey,
              requestDigest,
              patientHash,
              policyId: request.policyId,
              policyVersion: request.policyVersion,
              validFrom: currentTime(options),
              shareId: `share_${operationId.slice(3)}`,
              createdAt: currentTime(options)
            }, {
              owner,
              leaseToken: lease.leaseToken,
              now: currentTime(options),
              leaseExpiresAt: lease.leaseExpiresAt
            });
            operation = claimed.operation;
            assertOperationDigest(operation, requestDigest);
            if (!claimed.claimed) {
              if (operation.state === "active") {
                const response = responses.get(operation.operationId);
                if (!response) throw new Error("IDEMPOTENCY_RESULT_UNAVAILABLE");
                return response;
              }
              if (operation.state === "revoked" || operation.state === "superseded") {
                throw new Error("CONSENT_OPERATION_TERMINAL");
              }
              throw new Error("IDEMPOTENCY_OPERATION_IN_PROGRESS");
            }
            assertLeaseToken(operation, lease);
          } else {
            if (!operation) {
              const operationId = `op_${randomUUID()}`;
              try {
                operation = await options.operations.createPending({
                  operationId,
                  idempotencyKey: input.idempotencyKey,
                  requestDigest,
                  patientHash,
                  policyId: request.policyId,
                  policyVersion: request.policyVersion,
                  validFrom: currentTime(options),
                  shareId: `share_${operationId.slice(3)}`,
                  createdAt: currentTime(options)
                });
              } catch (error) {
                if (!isErrorCode(error, "CONSENT_OPERATION_ALREADY_EXISTS")) throw new Error(safeErrorCode(error));
                operation = await options.operations.findByIdempotencyKey(patientHash, input.idempotencyKey);
                if (!operation) throw new Error("CONSENT_OPERATION_NOT_FOUND");
                assertOperationDigest(operation, requestDigest);
              }
            }
          }

          claimOperationId = operation.operationId;
          let stage = operation.resumeState ?? pendingStage(operation.state);
          const scope = createScope(input.patientReference, request, options, operation.validFrom);
          await options.validatePolicy(scope);
          await options.validateInstitution(request.granteeOrganizationReference);
          if (request.practitionerReference) {
            await options.validatePractitioner(
              request.practitionerReference,
              request.granteeOrganizationReference
            );
          }
          const resourceMetadata = await options.validateResource(request.resourceReference, input.patientReference);
          if (
            resourceMetadata.resourceReference !== request.resourceReference ||
            resourceMetadata.resourceType !== request.resourceReference.split("/", 1)[0]
          ) {
            throw new Error("RESOURCE_IDENTITY_MISMATCH");
          }

          let mapped = operation.consentReference
            ? await readAndMapConsent(options.fhirClient, operation.consentReference, scope)
            : undefined;

          if (stage === "pending_fhir") {
            const plannedConsentReference = operation.consentReference ?? deterministicConsentReference(operation.operationId, requestDigest);
            let created: FhirResource | undefined;
            if (operation.fhirCreateAttempted && !operation.consentReference) {
              await renewLease(options, operation, lease);
              try {
                created = await options.fhirClient.readResource(plannedConsentReference);
              } catch (error) {
                if (!isFhirNotFound(error)) throw error;
              }
            }
            if (!created && !operation.consentReference) {
              await renewLease(options, operation, lease);
              await updateOperation(options, operation.operationId, {
                fhirCreateAttempted: true,
                updatedAt: currentTime(options)
              }, lease);
              operation = (await options.operations.findById(operation.operationId))!;
              await renewLease(options, operation, lease);
              const consentResource = {
                ...buildPatientConsentResource(scope),
                id: plannedConsentReference.slice("Consent/".length)
              } as unknown as FhirResource;
              created = await options.fhirClient.upsertResource(plannedConsentReference, consentResource);
            }
            const consentReference = requireConsentReference(created ?? { resourceType: "Consent", id: plannedConsentReference.slice("Consent/".length) });
            if (consentReference !== plannedConsentReference) throw new Error("FHIR_RESOURCE_REFERENCE_MISMATCH");
            await updateOperation(options, operation.operationId, {
              consentReference,
              state: "pending_chain",
              resumeState: "pending_chain",
              error: null,
              updatedAt: currentTime(options)
            }, lease);
            operation = (await options.operations.findById(operation.operationId))!;
            stage = "pending_chain";
            mapped = await readAndMapConsent(options.fhirClient, consentReference, scope);
          }

          if (stage === "pending_chain") {
            if (!operation.consentReference || !mapped) throw new Error("CONSENT_OPERATION_REFERENCE_MISSING");
            const blockchainInput = toPatientConsentInput(mapped);
            let existingChain = await options.blockchain.getPatientConsent?.(
              blockchainInput.consentIdHash,
              blockchainInput.consentVersion
            );
            if (isEmptyPatientConsentRecord(existingChain)) existingChain = undefined;
            let chainTransactionHash = operation.chainTransactionHash;
            if (existingChain) {
              assertChainConsentMatches(existingChain, blockchainInput);
            } else if (operation.chainTransactionHash) {
              throw new Error("CONSENT_CHAIN_CONFIRMATION_UNAVAILABLE");
            } else if (!(await options.blockchain.isPatientConsentActive?.(blockchainInput.consentIdHash, blockchainInput.consentVersion))) {
              await renewLease(options, operation, lease);
              chainTransactionHash = await options.blockchain.registerPatientConsent(blockchainInput);
            }
            stage = "pending_manifest";
            await updateOperation(options, operation.operationId, {
              ...(chainTransactionHash ? { chainTransactionHash } : {}),
              consentVersion: mapped.grant.consentVersion,
              state: "pending_manifest",
              resumeState: "pending_manifest",
              error: null,
              updatedAt: currentTime(options)
            }, lease);
            operation = (await options.operations.findById(operation.operationId))!;
          }

          if (stage !== "pending_manifest") throw new Error("CONSENT_OPERATION_STATE_INVALID");
          if (!operation.consentReference || !mapped) throw new Error("CONSENT_OPERATION_REFERENCE_MISSING");
          const activeShare = await ensureActiveShare(options, operation, mapped.scope, () => renewLease(options, operation!, lease));
          const handoffCode = await ensureHandoffCode(options, operation, activeShare, handoffCodes, () => renewLease(options, operation!, lease), lease);
          let manifest = await options.publication.findActiveForShare?.(activeShare.shareId);
          if (!manifest) {
            await renewLease(options, operation, lease);
            manifest = await options.publication.publishInitial({
              share: activeShare,
              resourceReference: mapped.scope.resourceReference,
              consentProjectionHash: mapped.grant.consentProjectionHash,
              consentVersion: mapped.grant.consentVersion,
              manifestId: operation.manifestId ?? deterministicManifestId(operation.operationId),
              now: currentTime(options),
              beforeSideEffect: async () => { await renewLease(options, operation!, lease); }
            });
          }
          if (!manifest?.manifestId) throw new Error("MANIFEST_REFERENCE_MISSING");
          await options.blockchain.syncResourceIntegrity?.({
            resourceReference: manifest.resourceReference,
            resourceType: manifest.resourceType,
            resourceHash: manifest.resourceHash
          });
          const consentReference = operation.consentReference;
          if (!consentReference) throw new Error("CONSENT_OPERATION_REFERENCE_MISSING");
          operation = await updateOperation(options, operation.operationId, {
            manifestId: manifest.manifestId,
            state: "active",
            resumeState: null,
            error: null,
            updatedAt: currentTime(options)
          }, lease);
          const response: PatientConsentCreateResponse = {
            operationId: operation.operationId,
            consentReference,
            consentVersion: mapped.grant.consentVersion,
            consentHash: mapped.grant.consentProjectionHash,
            policyId: mapped.scope.policyId,
            policyVersion: mapped.scope.policyVersion,
            shareId: activeShare.shareId,
            manifestId: manifest.manifestId,
            handoffCode,
            status: "active"
          };
          responses.set(operation.operationId, response);
          return response;
        } catch (error) {
          const safe = safeErrorCode(error);
          try {
            if (claimOperationId) {
              const current = await options.operations.findById(claimOperationId);
              await updateOperation(options, claimOperationId, {
                state: "failed_recoverable",
                resumeState: current?.resumeState ?? "pending_fhir",
                error: safe,
                updatedAt: currentTime(options)
              }, lease);
            }
          } catch {
            // The original safe failure remains the public result.
          }
          throw new Error(safe);
        } finally {
          if (claimOperationId) {
            try {
              await options.operations.releaseClaim?.(claimOperationId, lease ?? { owner, leaseToken: "fallback" });
            } catch {
              // Lease cleanup must not replace the operation result or safe error.
            }
          }
        }
      });
    },

    async revoke(input) {
      const patientHash = hashReference(input.patientReference);
      const consentReference = requireConsentReferenceValue(input.consentReference);
      let operation = await options.operations.findByConsent(patientHash, consentReference);
      if (!operation || !operation.consentVersion || !operation.shareId) {
        throw new Error("CONSENT_NOT_FOUND");
      }
      const operationId = operation.operationId;
      const originalConsentVersion = operation.consentVersion;
      if (operation.state === "revoked") {
        return {
          operationId: operation.operationId,
          consentReference,
          consentVersion: operation.consentVersion,
          shareId: operation.shareId,
          manifestIds: operation.manifestId ? [operation.manifestId] : [],
          status: "revoked"
        };
      }

      let lease: ConsentOperationLease | undefined;
      const claimOperationId = operationId;
      let claimedForRevocation = false;
      try {
        if (options.operations.claimExisting) {
          lease = createLease(options, `consent-revoke-${randomUUID()}`);
          const claimed = await options.operations.claimExisting(operation.operationId, lease);
          if (!claimed.claimed) throw new Error("CONSENT_OPERATION_IN_PROGRESS");
          operation = claimed.operation;
          assertLeaseToken(operation, lease);
          claimedForRevocation = true;
        }
        await renewLease(options, operation, lease);
        const consent = await options.fhirClient.readResource(consentReference);
        assertConsentPatient(consent, input.patientReference);
        const isActive = consent.resourceType === "Consent" && consent.status === "active";
        if (isActive) {
          const revoked = { ...consent, status: "inactive" };
          await renewLease(options, operation, lease);
          await options.fhirClient.updateResource(consentReference, revoked);
        } else if (consent.resourceType !== "Consent" || consent.status !== "inactive") {
          throw new Error("FHIR_CONSENT_NOT_ACTIVE");
        }
        const consentIdHash = hashReference(consentReference);
        const consentVersion = Number(operation.consentVersion);
        const chainActive = await options.blockchain.isPatientConsentActive?.(consentIdHash, consentVersion) ?? true;
        if (chainActive) {
          await renewLease(options, operation, lease);
          const transactionHash = await options.blockchain.revokePatientConsent(consentIdHash, consentVersion);
          operation = await updateOperation(options, operation.operationId, {
            revocationTransactionHash: transactionHash,
            updatedAt: currentTime(options)
          }, lease);
        }
        const share = await options.shares.findById(operation.shareId);
        if (share?.status === "active") {
          await renewLease(options, operation, lease);
          await options.shares.revoke(share.shareId, currentTime(options));
        }
        await renewLease(options, operation, lease);
        const publication = await options.publication.revokeForShare({
          shareId: operation.shareId,
          now: currentTime(options),
          beforeSideEffect: async () => { await renewLease(options, operation!, lease); }
        });
        operation = await updateOperation(options, operation.operationId, {
          state: "revoked",
          resumeState: null,
          error: null,
          updatedAt: currentTime(options)
        }, lease);
        return {
          operationId: operation.operationId,
          consentReference,
          consentVersion: originalConsentVersion,
          shareId: operation.shareId,
          manifestIds: publication.manifestIds.length > 0
            ? publication.manifestIds
            : operation.manifestId ? [operation.manifestId] : [],
          status: "revoked"
        };
      } catch (error) {
        const safe = safeErrorCode(error);
        try {
          await updateOperation(options, operation.operationId, {
            state: "failed_recoverable",
            resumeState: "pending_chain",
            error: safe,
            updatedAt: currentTime(options)
          }, lease);
        } catch {
          // Preserve the sanitized revocation error.
        }
        throw new Error(safe);
      } finally {
        if (claimedForRevocation) {
          try {
            await options.operations.releaseClaim?.(claimOperationId, lease!);
          } catch {
            // Lease cleanup must not replace the sanitized revocation result.
          }
        }
      }
    }
  };
}

function validateCreateInput(input: PatientConsentCreateInput): PatientConsentCreateRequest {
  if (typeof input.patientReference !== "string" || input.patientReference.trim().length === 0) {
    throw new Error("PATIENT_REFERENCE_REQUIRED");
  }
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(input.idempotencyKey)) {
    throw new Error("INVALID_IDEMPOTENCY_KEY");
  }
  const request = input.request;
  if (!request || typeof request !== "object") throw new Error("CONSENT_REQUEST_REQUIRED");
  return request;
}

function createScope(
  patientReference: string,
  request: PatientConsentCreateRequest,
  options: PatientConsentServiceOptions,
  persistedValidFrom?: string
): PatientConsentScope {
  return createPatientConsentScope({
    patientReference,
    granteeOrganizationReference: request.granteeOrganizationReference,
    practitionerReference: request.practitionerReference,
    resourceReference: request.resourceReference,
    purposeOfUse: request.purposeOfUse,
    policyId: request.policyId,
    policyVersion: request.policyVersion,
    validFrom: persistedValidFrom ?? currentTime(options),
    validUntil: request.validUntil
  });
}

export function computeConsentOperationRequestDigest(input: {
  patientHash: string;
  request: PatientConsentCreateRequest;
}): string {
  const validUntil = typeof input.request.validUntil === "string"
    ? canonicalizeAuthorizationDateTime(input.request.validUntil)
    : input.request.validUntil;
  return hashCanonicalText(JSON.stringify({
    patientHash: input.patientHash,
    granteeOrganizationReference: input.request.granteeOrganizationReference,
    practitionerReference: input.request.practitionerReference ?? null,
    resourceReference: input.request.resourceReference,
    purposeOfUse: typeof input.request.purposeOfUse === "string"
      ? input.request.purposeOfUse.toUpperCase()
      : input.request.purposeOfUse,
    policyId: input.request.policyId,
    policyVersion: input.request.policyVersion,
    validUntil
  }));
}

async function readAndMapConsent(
  fhirClient: PatientConsentFhirClient,
  consentReference: string,
  expectedScope: PatientConsentScope
) {
  const consent = await fhirClient.readResource(consentReference);
  assertConsentPatient(consent, expectedScope.patientReference);
  const grant = mapFhirConsentToPatientConsentGrant(consent as FhirConsent);
  if (!sameScope(grant.scope, expectedScope)) throw new Error("FHIR_CONSENT_SCOPE_MISMATCH");
  return { grant, scope: grant.scope, mapped: mapFhirConsentToRegisterConsentInput(consent as FhirConsent) };
}

function toPatientConsentInput(value: Awaited<ReturnType<typeof readAndMapConsent>>): PatientConsentInputDto {
  return {
    consentIdHash: value.mapped.consentIdHash,
    consentProjectionHash: value.mapped.consentProjectionHash,
    patientHash: value.mapped.patientHash,
    actorConstraintHash: value.mapped.actorConstraintHash,
    granteeOrganizationHash: value.mapped.granteeOrganizationHash,
    resourceIdHash: value.mapped.resourceIdHash,
    policyIdHash: value.mapped.policyIdHash,
    policyVersion: value.mapped.policyVersion,
    consentVersion: Number(value.mapped.consentVersion),
    resourceTypeCode: value.mapped.resourceTypeCode,
    actionCode: value.mapped.actionCode,
    purposeCode: value.mapped.purposeCode,
    validFrom: value.mapped.validFrom,
    validUntil: value.mapped.validUntil,
    policyMask: value.mapped.policyMask
  };
}

async function ensureActiveShare(
  options: PatientConsentServiceOptions,
  operation: ConsentOperation,
  scope: PatientConsentScope,
  beforeSideEffect: () => Promise<unknown>
): Promise<ShareGrant> {
  const existing = await options.shares.findById(operation.shareId);
  if (existing?.status === "active") {
    assertShareMatchesScope(existing, options, operation, scope);
    return existing;
  }
  if (existing?.status === "revoked" || existing?.status === "expired") {
    throw new Error("SHARE_NOT_REACTIVATABLE");
  }
  const draft = buildShareGrant({
    shareId: operation.shareId,
    custodianOrganizationReference: options.custodianOrganizationReference,
    granteeOrganizationReference: scope.granteeOrganizationReference,
    patientReference: scope.patientReference,
    consentReference: operation.consentReference!,
    allowedResourceTypes: [scope.resourceReference.split("/", 1)[0]!],
    allowedOperation: "read",
    allowedPurpose: scope.purposeOfUse,
    validFrom: scope.validFrom,
    validUntil: scope.validUntil,
    now: currentTime(options)
  });
  if (!existing) {
    try {
      await beforeSideEffect();
      await options.shares.savePending({ ...draft, status: "pending" });
    } catch (error) {
      if (!isErrorCode(error, "SHARE_ALREADY_EXISTS")) throw error;
      const recovered = await options.shares.findById(operation.shareId);
      if (!recovered) throw new Error("SHARE_RECOVERY_NOT_FOUND");
      assertShareMatchesScope(recovered, options, operation, scope);
    }
  }
  await beforeSideEffect();
  return options.shares.activate(operation.shareId, currentTime(options));
}

async function ensureHandoffCode(
  options: PatientConsentServiceOptions,
  operation: ConsentOperation,
  share: ShareGrant,
  handoffCodes: Map<string, string>,
  beforeSideEffect: () => Promise<unknown>,
  lease?: ConsentOperationLease
) {
  const existing = handoffCodes.get(operation.operationId);
  if (existing) return existing;
  if (operation.handoffCodeHash) throw new Error("IDEMPOTENCY_RESULT_UNAVAILABLE");
  const code = randomBytes(24).toString("base64url");
  const codeHash = hashHandoffCode(code);
  await beforeSideEffect();
  await updateOperation(options, operation.operationId, {
    handoffCodeHash: codeHash,
    updatedAt: currentTime(options)
  }, lease);
  await beforeSideEffect();
  await options.shares.issueHandoffCode(share.shareId, codeHash, share.validUntil);
  handoffCodes.set(operation.operationId, code);
  return code;
}

function assertValidationConfigured(options: PatientConsentServiceOptions) {
  const validators: Array<[keyof PatientConsentValidation, string]> = [
    ["validatePolicy", "VALIDATE_POLICY_NOT_CONFIGURED"],
    ["validateInstitution", "VALIDATE_INSTITUTION_NOT_CONFIGURED"],
    ["validatePractitioner", "VALIDATE_PRACTITIONER_NOT_CONFIGURED"],
    ["validateResource", "VALIDATE_RESOURCE_NOT_CONFIGURED"]
  ];
  for (const [name, errorCode] of validators) {
    if (typeof options[name] !== "function") throw new Error(errorCode);
  }
}

function assertOperationDigest(operation: ConsentOperation | undefined, requestDigest: string) {
  if (!operation) return;
  if (!operation.requestDigest) throw new Error("IDEMPOTENCY_DIGEST_MISSING");
  if (operation.requestDigest !== requestDigest) throw new Error("IDEMPOTENCY_KEY_SCOPE_MISMATCH");
}

function assertChainConsentMatches(record: PatientConsentChainRecord, expected: PatientConsentInputDto) {
  if (
    !record.active ||
    record.consentIdHash !== expected.consentIdHash ||
    record.consentProjectionHash !== expected.consentProjectionHash ||
    record.patientHash !== expected.patientHash ||
    record.granteeOrganizationHash !== expected.granteeOrganizationHash ||
    record.actorConstraintHash !== expected.actorConstraintHash ||
    record.resourceIdHash !== expected.resourceIdHash ||
    record.resourceTypeCode !== expected.resourceTypeCode ||
    record.actionCode !== expected.actionCode ||
    record.purposeCode !== expected.purposeCode ||
    record.validFrom !== expected.validFrom ||
    record.validUntil !== expected.validUntil ||
    record.policyMask !== expected.policyMask
  ) {
    throw new Error("CONSENT_CHAIN_PROJECTION_MISMATCH");
  }
}

function assertShareMatchesScope(
  share: ShareGrant,
  options: PatientConsentServiceOptions,
  operation: ConsentOperation,
  scope: PatientConsentScope
) {
  if (
    share.custodianOrganizationReference !== options.custodianOrganizationReference ||
    share.granteeOrganizationReference !== scope.granteeOrganizationReference ||
    share.patientReference !== scope.patientReference ||
    share.consentReference !== operation.consentReference ||
    share.allowedPurpose !== scope.purposeOfUse ||
    share.validFrom !== scope.validFrom ||
    share.validUntil !== scope.validUntil ||
    !share.allowedResourceTypes.includes(scope.resourceReference.split("/", 1)[0]!)
  ) throw new Error("SHARE_OPERATION_SCOPE_MISMATCH");
}

function deterministicConsentReference(operationId: string, requestDigest: string) {
  return `Consent/${operationId.replace(/^op_/, "consent-")}-${requestDigest.replace(/^0x/, "").slice(0, 16)}`;
}

function deterministicManifestId(operationId: string) {
  return `manifest_${operationId.replace(/^op_/, "")}`;
}

function isFhirNotFound(error: unknown) {
  return error instanceof Error && ["FHIR_HTTP_404", "FHIR_CONSENT_NOT_FOUND"].includes(error.message);
}

async function withProcessLock<T>(locks: Map<string, Promise<void>>, key: string, action: () => Promise<T>): Promise<T> {
  const previous = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => { release = resolve; });
  locks.set(key, current);
  await previous;
  try {
    return await action();
  } finally {
    release();
    if (locks.get(key) === current) locks.delete(key);
  }
}

function assertConsentPatient(consent: FhirResource, patientReference: string) {
  if (consent.resourceType !== "Consent") throw new Error("FHIR_RESOURCE_NOT_CONSENT");
  const patient = consent.patient;
  const reference = isRecord(patient) && typeof patient.reference === "string" ? patient.reference : undefined;
  if (reference !== patientReference) throw new Error("FHIR_CONSENT_PATIENT_MISMATCH");
}

function requireConsentReference(resource: FhirResource) {
  return requireConsentReferenceValue(
    resource.resourceType === "Consent" && typeof resource.id === "string"
      ? `Consent/${resource.id}`
      : undefined
  );
}

function requireConsentReferenceValue(value: string | undefined) {
  if (typeof value !== "string" || !/^Consent\/[A-Za-z0-9.-]+$/.test(value)) {
    throw new Error("INVALID_CONSENT_REFERENCE");
  }
  return value;
}

function sameScope(left: PatientConsentScope, right: PatientConsentScope) {
  return left.patientReference === right.patientReference
    && left.granteeOrganizationReference === right.granteeOrganizationReference
    && left.practitionerReference === right.practitionerReference
    && left.resourceReference === right.resourceReference
    && left.purposeOfUse === right.purposeOfUse
    && left.policyId === right.policyId
    && left.policyVersion === right.policyVersion
    && left.validFrom === right.validFrom
    && left.validUntil === right.validUntil;
}

function pendingStage(state: ConsentOperationState): Exclude<ConsentOperationState, "active" | "failed_recoverable" | "revoked" | "superseded"> {
  if (state === "pending_fhir" || state === "pending_chain" || state === "pending_manifest") return state;
  throw new Error("CONSENT_OPERATION_STATE_INVALID");
}

function currentTime(options: { now?: () => string }) {
  return options.now?.() ?? new Date().toISOString();
}

function createLease(options: { now?: () => string }, owner: string): ConsentOperationLease {
  const now = currentTime(options);
  return {
    owner,
    leaseToken: randomUUID(),
    now,
    leaseExpiresAt: new Date(Date.parse(now) + 60_000).toISOString()
  };
}

async function renewLease(
  options: PatientConsentServiceOptions,
  operation: ConsentOperation,
  lease: ConsentOperationLease | undefined
) {
  if (!lease || !options.operations.renewLease) return operation;
  const now = currentTime(options);
  const leaseExpiresAt = new Date(Date.parse(now) + 60_000).toISOString();
  const renewed = await options.operations.renewLease(operation.operationId, {
    ...lease,
    now,
    leaseExpiresAt
  });
  if (renewed.leaseOwner !== lease.owner || renewed.leaseToken !== lease.leaseToken) {
    throw new Error("CONSENT_OPERATION_LEASE_LOST");
  }
  Object.assign(operation, renewed);
  lease.now = now;
  lease.leaseExpiresAt = leaseExpiresAt;
  return operation;
}

function assertLeaseToken(operation: ConsentOperation, lease: ConsentOperationLease) {
  if (operation.leaseOwner !== lease.owner || operation.leaseToken !== lease.leaseToken) {
    throw new Error("CONSENT_OPERATION_LEASE_LOST");
  }
}

function updateOperation(
  options: PatientConsentServiceOptions,
  operationId: string,
  patch: ConsentOperationUpdate,
  lease: ConsentOperationLease | undefined
) {
  return options.operations.update(operationId, patch, lease);
}

function safeErrorCode(error: unknown) {
  const message = error instanceof Error ? error.message : "INTERNAL_ERROR";
  return /^[A-Z][A-Z0-9_:-]{1,127}$/.test(message) ? message : "INTERNAL_ERROR";
}

function isErrorCode(error: unknown, expected: string) {
  return error instanceof Error && error.message === expected;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
