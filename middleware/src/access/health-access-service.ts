import {
  computeAccessRequestCorrelationHash,
  mapManifestToAccessRequest
} from "../abac/manifest-attribute-mapper.js";
import type { InstitutionalAccessRequestDto } from "../blockchain/ethers-access-client.js";
import { ethers } from "ethers";
import { hashIdentifier, hashReference as hashAuthorizationReference } from "../authorization/authorization-model.js";
import { createAccessAuditEvent } from "../fhir/audit-event.js";
import {
  mapFhirConsentToPatientConsentGrant,
  mapFhirConsentToRegisterConsentInput,
  type FhirConsent
} from "../fhir/consent-mapper.js";
import { hashFhirResource, type FhirResource } from "../fhir/resource-hasher.js";
import { extractResourceManifestMetadata } from "../manifest/resource-manifest.js";
import type { ManifestSigner } from "../manifest/manifest-signer.js";
import type { ManifestVersionRepository } from "../manifest/postgres-manifest-repository.js";
import type { ShareRepository } from "../share/postgres-share-repository.js";
import type { ResourceManifestVersion } from "../manifest/resource-manifest.js";

export interface AccessEvaluation {
  granted: boolean;
  reasonCode: string;
  policyId: string;
  policyVersion: number;
  consentReference: string;
  consentVersion: string;
  requestHash: string;
}

interface BlockchainAccessDecision {
  granted: boolean;
  requestHash: string;
  transactionHash: string;
}

interface InstitutionalBlockchainClient {
  requestInstitutionalAccess(request: InstitutionalAccessRequestDto): Promise<BlockchainAccessDecision>;
  verifyInstitutionalAccess(request: InstitutionalAccessRequestDto, verificationTime: number): Promise<boolean>;
  finalizeEnforcement(requestHash: string, delivered: boolean, reasonCode: number): Promise<string>;
  readActivePatientConsentProjection(consentIdHash: string): Promise<InstitutionalConsentProjection>;
  readPatientConsent(consentIdHash: string, consentVersion: number): Promise<InstitutionalConsentRecord | undefined>;
}

interface InstitutionalConsentProjection {
  policyIdHash: string;
  policyVersion: number;
  consentVersion: number;
  consentProjectionHash: string;
  active: boolean;
  status: number;
}

interface InstitutionalConsentRecord {
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
  policyMask: number;
  active: boolean;
}

interface ServiceDependencies {
  directedRead?: {
    now?: () => number;
    observe?: (observation: AccessObservation) => void;
    shareRepository: Pick<ShareRepository, "requireActive">;
    manifestRepository: Pick<ManifestVersionRepository, "requireActiveForShare">;
    manifestSigner: Pick<ManifestSigner, "verify">;
    manifestVerifier: { verify(manifest: ResourceManifestVersion): Promise<boolean> };
    fhirClient: {
      vread(resourceReference: string, versionId: string): Promise<FhirResource>;
      readConsent(consentReference: string): Promise<FhirResource>;
      createAuditEvent(event: unknown): Promise<void>;
    };
    institutionalPolicy?: {
      evaluate(input: {
        requesterOrganizationReference: string;
        practitionerReference: string;
        roleCode?: string | number;
        specialtyCode?: string | number;
        licenseActive?: boolean;
        resourceType: string;
        purposeOfUse: string;
        requestTime: string;
        policyId?: string;
        policyVersion?: number;
      }): Promise<{ permitted: boolean; reasonCode: string }>;
    };
    institutionalBlockchainClient: InstitutionalBlockchainClient;
  };
}

interface DirectedManifestReadRequest {
  requestId?: string;
  shareId: string;
  manifestId: string;
  practitionerReference: string;
  organizationReference: string;
  purposeOfUse: string;
  requestTime: number;
  recordedAt: string;
  /** Derived from a verified UDAP service principal, never from the HTTP body. */
  assertionHash: string;
}

interface DirectedConsentValidation {
  consentReference: string;
  consentVersion: string;
  policyId: string;
  policyVersion: number;
}

export interface AccessObservation {
  kind: "access-observation";
  requestId?: string;
  status: number;
  stages: Array<{ name: string; durationMs: number; status: "confirmed" | "failed"; transactionHash?: string; requestHash?: string }>;
  durationMs: number;
}
export function createHealthAccessService(dependencies: ServiceDependencies) {
  if (dependencies.directedRead) assertDirectedConsentReaders(dependencies.directedRead.institutionalBlockchainClient);
  return { async handleReadByShareManifest(request: DirectedManifestReadRequest) {
    const started = performance.now();
    const stages: AccessObservation["stages"] = [];
    const wrap = <T extends object>(target: T, names: Record<string,string>): T => new Proxy(target, { get(object, key) {
      const value = Reflect.get(object, key);
      if (typeof value !== "function" || !names[String(key)]) return typeof value === "function" ? value.bind(object) : value;
      return async (...args: unknown[]) => {
        const time = performance.now();
        try {
          const result = await value.apply(object, args);
          const tx = typeof result === "string" ? result : result?.transactionHash;
          const hash = result?.requestHash;
          stages.push({ name: names[String(key)], durationMs: performance.now() - time, status: "confirmed",
            ...(typeof tx === "string" && /^0x[0-9a-f]{64}$/i.test(tx) ? { transactionHash: tx } : {}),
            ...(typeof hash === "string" && /^0x[0-9a-f]{64}$/i.test(hash) ? { requestHash: hash } : {}) });
          return result;
        } catch (error) {
          stages.push({ name: names[String(key)], durationMs: performance.now() - time, status: "failed" });
          throw error;
        }
      };
    } });
    const directed = dependencies.directedRead;
    const core = createCoreHealthAccessService(directed ? { directedRead: { ...directed,
      fhirClient: wrap(directed.fhirClient, { vread: "fhirVread", readConsent: "consentRead", createAuditEvent: "auditEvent" }),
      manifestVerifier: wrap(directed.manifestVerifier, { verify: "commitmentCheck" }),
      institutionalBlockchainClient: wrap(directed.institutionalBlockchainClient, { requestInstitutionalAccess: "blockchainDecision", verifyInstitutionalAccess: "blockchainVerification", finalizeEnforcement: "blockchainFinalization" })
    } } : dependencies);
    let response;
    try { response = await core.handleReadByShareManifest(request); }
    catch { response = { status: 503, body: { error: stages.some(stage => stage.name === "auditEvent" && stage.status === "failed") ? "AUDIT_UNAVAILABLE" : "DEPENDENCY_UNAVAILABLE" } }; }
    try { directed?.observe?.({ kind: "access-observation", requestId: request.requestId, status: response.status, stages, durationMs: performance.now() - started }); } catch { /* Diagnostics cannot alter the clinical decision. */ }
    return response;
  } };
}

function createCoreHealthAccessService(dependencies: ServiceDependencies) {
  if (dependencies.directedRead) assertDirectedConsentReaders(dependencies.directedRead.institutionalBlockchainClient);
  return {
    async handleReadByShareManifest(request: DirectedManifestReadRequest) {
      const directed = dependencies.directedRead;
      if (!directed) {
        return { status: 500, body: { error: "DIRECTED_READ_NOT_CONFIGURED" } };
      }
      let share;
      try {
        share = await directed.shareRepository.requireActive(request.shareId);
      } catch (error) {
        await auditDirected(
          directed.fhirClient,
          request,
          undefined,
          createBoundaryEvaluation(request, "unknown", safeAccessErrorCode(error, "SHARE_NOT_ACTIVE"))
        );
        return { status: 403, body: { error: safeAccessErrorCode(error, "SHARE_NOT_ACTIVE") } };
      }
      if (!share.handoffRedeemedAt) return { status: 403, body: { error: "HANDOFF_NOT_REDEEMED" } };
      if (share.granteeOrganizationReference !== request.organizationReference) {
        await auditDirected(
          directed.fhirClient,
          request,
          undefined,
          createBoundaryEvaluation(request, share.consentReference, "SHARE_GRANTEE_MISMATCH")
        );
        return { status: 403, body: { error: "SHARE_GRANTEE_MISMATCH" } };
      }
      if (share.allowedPurpose !== request.purposeOfUse) {
        await auditDirected(
          directed.fhirClient,
          request,
          undefined,
          createBoundaryEvaluation(request, share.consentReference, "SHARE_PURPOSE_MISMATCH")
        );
        return { status: 403, body: { error: "SHARE_PURPOSE_MISMATCH" } };
      }
      let consent: FhirResource;
      try {
        consent = await directed.fhirClient.readConsent(share.consentReference);
      } catch (error) {
        await auditDirectedBestEffort(
          directed.fhirClient,
          request,
          undefined,
          createBoundaryEvaluation(request, share.consentReference, "FHIR_CONSENT_UNAVAILABLE")
        );
        if (isDependencyUnavailable(error)) {
          return { status: 503, body: { error: "FHIR_CONSENT_UNAVAILABLE" } };
        }
        return { status: 403, body: { error: safeAccessErrorCode(error, "FHIR_CONSENT_UNAVAILABLE") } };
      }
      let manifest: ResourceManifestVersion;
      try {
        manifest = await directed.manifestRepository.requireActiveForShare(
          share.shareId,
          request.manifestId
        );
      } catch (error) {
        await auditDirected(
          directed.fhirClient,
          request,
          undefined,
          createBoundaryEvaluation(request, share.consentReference, safeAccessErrorCode(error, "MANIFEST_NOT_ACTIVE"))
        );
        return { status: 403, body: { error: safeAccessErrorCode(error, "MANIFEST_NOT_ACTIVE") } };
      }
      let manifestValid = false;
      try {
        manifestValid = await directed.manifestSigner.verify(manifest);
      } catch {
        manifestValid = false;
      }
      if (!manifestValid) {
        await auditDirected(
          directed.fhirClient,
          request,
          manifest,
          createBoundaryEvaluation(request, share.consentReference, "MANIFEST_COMMITMENT_MISMATCH")
        );
        return { status: 409, body: { error: "MANIFEST_COMMITMENT_MISMATCH" } };
      }
      try {
        manifestValid = await directed.manifestVerifier.verify(manifest);
      } catch {
        await auditDirectedBestEffort(
          directed.fhirClient,
          request,
          manifest,
          createBoundaryEvaluation(request, share.consentReference, "BLOCKCHAIN_UNAVAILABLE")
        );
        return { status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } };
      }
      if (!manifestValid) {
        await auditDirected(
          directed.fhirClient,
          request,
          manifest,
          createBoundaryEvaluation(request, share.consentReference, "MANIFEST_COMMITMENT_MISMATCH")
        );
        return { status: 409, body: { error: "MANIFEST_COMMITMENT_MISMATCH" } };
      }
      if (consent.resourceType !== "Consent" || consent.status !== "active") {
        const evaluation = createDirectedEvaluation(
          request,
          manifest,
          bestEffortConsentValidation(consent, share.consentReference),
          "FHIR_CONSENT_NOT_ACTIVE",
          false
        );
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 403, body: { error: "FHIR_CONSENT_NOT_ACTIVE" } };
      }
      const consentValidation = await validateCurrentDirectedConsent(
        directed,
        consent,
        share,
        manifest,
        request.practitionerReference,
        request.organizationReference,
        request.requestTime
      );
      if (typeof consentValidation === "string") {
        const evaluation = createDirectedEvaluation(
          request,
          manifest,
          bestEffortConsentValidation(consent, share.consentReference),
          consentValidation,
          false
        );
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return {
          status: consentValidation === "CONSENT_PROJECTION_UNAVAILABLE" ? 503 : 403,
          body: { error: consentValidation }
        };
      }
      const accessRequest = mapDirectedManifestToInstitutionalRequest(manifest, {
        practitionerReference: request.practitionerReference,
        organizationReference: request.organizationReference,
        purposeOfUse: request.purposeOfUse,
        requestTime: request.requestTime,
        assertionHash: request.assertionHash
      });
      let decision: BlockchainAccessDecision;
      try {
        decision = await directed.institutionalBlockchainClient.requestInstitutionalAccess(accessRequest);
      } catch {
        const evaluation = createDirectedEvaluation(
          request,
          manifest,
          consentValidation,
          "BLOCKCHAIN_UNAVAILABLE",
          false
        );
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } };
      }
      if (!decision.granted) {
        const evaluation = createDirectedEvaluation(
          request,
          manifest,
          consentValidation,
          "ACCESS_DENIED",
          false,
          decision.requestHash,
          decision.transactionHash
        );
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 403, body: { error: "ACCESS_DENIED" } };
      }
      let verified: boolean;
      try {
        verified = await directed.institutionalBlockchainClient.verifyInstitutionalAccess(
          accessRequest,
          request.requestTime
        );
      } catch {
        const evaluation = createDirectedEvaluation(
          request,
          manifest,
          consentValidation,
          "BLOCKCHAIN_UNAVAILABLE",
          false,
          decision.requestHash,
          decision.transactionHash
        );
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } };
      }
      if (!verified) {
        const evaluation = createDirectedEvaluation(
          request,
          manifest,
          consentValidation,
          "ACCESS_VERIFICATION_FAILED",
          false,
          decision.requestHash,
          decision.transactionHash
        );
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 403, body: { error: "ACCESS_VERIFICATION_FAILED" } };
      }
      if (
        directed.institutionalPolicy
      ) {
        let localPolicy;
        try {
          localPolicy = await directed.institutionalPolicy.evaluate({
            requesterOrganizationReference: request.organizationReference,
            practitionerReference: request.practitionerReference,
            resourceType: manifest.resourceType,
            purposeOfUse: request.purposeOfUse,
            requestTime: new Date(request.requestTime * 1000).toISOString(),
            policyId: consentValidation.policyId,
            policyVersion: consentValidation.policyVersion
          });
        } catch {
          const evaluation = createDirectedEvaluation(
            request,
            manifest,
            consentValidation,
            "LOCAL_TRUSTED_ATTRIBUTES_UNAVAILABLE",
            false,
            decision.requestHash,
            decision.transactionHash
          );
          await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
          return { status: 503, body: { error: "LOCAL_POLICY_UNAVAILABLE" } };
        }
        if (!localPolicy.permitted) {
          const finalized = await finalizeDirected(
            directed.institutionalBlockchainClient,
            decision.requestHash,
            false,
            7
          );
          const evaluation = createDirectedEvaluation(
            request,
            manifest,
            consentValidation,
            localPolicy.reasonCode,
            false,
            decision.requestHash,
            decision.transactionHash
          );
          await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
          return finalized
            ? { status: 403, body: { error: "INSTITUTIONAL_POLICY_DENIED" } }
            : { status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } };
        }
      }
      let resource: FhirResource;
      try {
        resource = await directed.fhirClient.vread(
          manifest.resourceReference,
          manifest.fhirVersionId
        );
      } catch {
        await finalizeDirected(directed.institutionalBlockchainClient, decision.requestHash, false, 6);
        const evaluation = createDirectedEvaluation(
          request,
          manifest,
          consentValidation,
          "FHIR_READ_FAILED",
          false,
          decision.requestHash,
          decision.transactionHash
        );
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 503, body: { error: "FHIR_READ_FAILED" } };
      }
      if (!fhirResourceMatchesManifestVersion(resource, manifest)) {
        await finalizeDirected(directed.institutionalBlockchainClient, decision.requestHash, false, 6);
        const evaluation = createDirectedEvaluation(request, manifest, consentValidation, "MANIFEST_RESOURCE_METADATA_MISMATCH", false, decision.requestHash, decision.transactionHash);
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 403, body: { error: "MANIFEST_RESOURCE_METADATA_MISMATCH" } };
      }
      if (hashFhirResource(resource) !== manifest.resourceHash) {
        await finalizeDirected(directed.institutionalBlockchainClient, decision.requestHash, false, 6);
        const evaluation = createDirectedEvaluation(request, manifest, consentValidation, "MANIFEST_RESOURCE_HASH_MISMATCH", false, decision.requestHash, decision.transactionHash);
        await auditDirectedBestEffort(directed.fhirClient, request, manifest, evaluation);
        return { status: 403, body: { error: "MANIFEST_RESOURCE_HASH_MISMATCH" } };
      }
      const revalidateRelease = async () => {
        const currentTime = directed.now?.() ?? Math.floor(Date.now() / 1000);
        try {
          const currentShare = await directed.shareRepository.requireActive(request.shareId);
          if (!currentShare.handoffRedeemedAt) return "HANDOFF_NOT_REDEEMED";
          const currentConsent = await directed.fhirClient.readConsent(share.consentReference);
          if (currentConsent.status !== "active") return "FHIR_CONSENT_NOT_ACTIVE";
          const validation = await validateCurrentDirectedConsent(directed, currentConsent, currentShare,
            manifest, request.practitionerReference, request.organizationReference, currentTime);
          if (typeof validation === "string") return validation;
          if (!await directed.institutionalBlockchainClient.verifyInstitutionalAccess(accessRequest, currentTime)) return "ACCESS_VERIFICATION_FAILED";
          if (directed.institutionalPolicy) {
            const policy = await directed.institutionalPolicy.evaluate({ requesterOrganizationReference: request.organizationReference,
              practitionerReference: request.practitionerReference, resourceType: manifest.resourceType,
              purposeOfUse: request.purposeOfUse, requestTime: new Date(currentTime * 1000).toISOString(),
              policyId: validation.policyId, policyVersion: validation.policyVersion });
            if (!policy.permitted) return "INSTITUTIONAL_POLICY_DENIED";
          }
          return undefined;
        } catch { return "RELEASE_REVALIDATION_UNAVAILABLE"; }
      };
      const releaseError = await revalidateRelease();
      if (releaseError) return { status: releaseError.endsWith("UNAVAILABLE") ? 503 : 403, body: { error: releaseError } };
      // This event records the permitted decision, not receipt by the remote institution.
      const evaluation = createDirectedEvaluation(request, manifest, consentValidation,
        "ACCESS_DECISION_PERMITTED", true, decision.requestHash, decision.transactionHash);
      try {
        await auditDirected(directed.fhirClient, request, manifest, evaluation);
      } catch {
        return { status: 503, body: { error: "AUDIT_UNAVAILABLE" } };
      }
      const finalized = await finalizeDirected(directed.institutionalBlockchainClient,
        decision.requestHash, true, 1);
      if (!finalized) return { status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } };
      const finalReleaseError = await revalidateRelease();
      if (finalReleaseError) return { status: finalReleaseError.endsWith("UNAVAILABLE") ? 503 : 403, body: { error: finalReleaseError } };
      return {
        status: 200,
        body: {
          manifest: {
            manifestId: manifest.manifestId,
            shareId: manifest.shareId,
            resourceReference: manifest.resourceReference,
            fhirVersionId: manifest.fhirVersionId,
            custodianOrganizationReference: manifest.custodianOrganizationReference
          },
          resource
        }
      };
    }
  };
}

function mapDirectedManifestToInstitutionalRequest(
  manifest: ResourceManifestVersion,
  context: {
    practitionerReference: string;
    organizationReference: string;
    purposeOfUse: string;
    requestTime: number;
    assertionHash: string;
  }
): InstitutionalAccessRequestDto {
  const access = mapManifestToAccessRequest(manifest, context);
  return {
    ...access,
    shareIdHash: hashReference(manifest.shareId),
    manifestIdHash: hashReference(manifest.manifestId),
    consentIdHash: manifest.consentReferenceHash,
    consentProjectionHash: manifest.consentProjectionHash,
    assertionHash: normalizeBytes32(context.assertionHash)
  };
}

function hashReference(value: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

async function validateCurrentDirectedConsent(
  directed: NonNullable<ServiceDependencies["directedRead"]>,
  consent: FhirResource,
  share: { consentReference: string; granteeOrganizationReference: string; allowedPurpose: string },
  manifest: ResourceManifestVersion,
  practitionerReference: string,
  organizationReference: string,
  requestTime: number
): Promise<DirectedConsentValidation | string> {
  let grant;
  try {
    grant = mapFhirConsentToPatientConsentGrant(consent as FhirConsent);
  } catch (error) {
    return safeConsentErrorCode(error);
  }
  let mapped;
  try {
    mapped = mapFhirConsentToRegisterConsentInput(consent as FhirConsent);
  } catch (error) {
    return safeConsentErrorCode(error);
  }
  const validFrom = Math.floor(Date.parse(grant.scope.validFrom) / 1000);
  const validUntil = Math.floor(Date.parse(grant.scope.validUntil) / 1000);
  if (requestTime < validFrom || requestTime > validUntil) return "FHIR_CONSENT_EXPIRED";
  if (
    grant.scope.practitionerReference !== undefined &&
    grant.scope.practitionerReference !== practitionerReference
  ) {
    return "CONSENT_PRACTITIONER_MISMATCH";
  }
  if (grant.scope.granteeOrganizationReference !== organizationReference) {
    return "CONSENT_ORGANIZATION_MISMATCH";
  }
  if (
    grant.consentReference !== share.consentReference ||
    hashReference(grant.consentReference) !== manifest.consentReferenceHash ||
    grant.consentProjectionHash !== manifest.consentProjectionHash ||
    grant.scope.patientReference !== manifest.subjectReference ||
    grant.scope.granteeOrganizationReference !== share.granteeOrganizationReference ||
    grant.scope.resourceReference !== manifest.resourceReference ||
    grant.scope.resourceReference.split("/", 1)[0] !== manifest.resourceType ||
    grant.scope.purposeOfUse !== share.allowedPurpose
  ) return "CONSENT_MANIFEST_MISMATCH";

  const consentIdHash = hashAuthorizationReference(share.consentReference);
  let projection: InstitutionalConsentProjection;
  try {
    projection = await directed.institutionalBlockchainClient.readActivePatientConsentProjection(consentIdHash);
  } catch (error) {
    return isDependencyUnavailable(error)
      ? "CONSENT_PROJECTION_UNAVAILABLE"
      : "CONSENT_PROJECTION_MISMATCH";
  }
  if (
    !projection.active ||
    projection.status !== 1 ||
    projection.consentVersion !== Number(grant.consentVersion) ||
    projection.consentProjectionHash !== grant.consentProjectionHash ||
    projection.policyIdHash !== hashIdentifier(grant.scope.policyId) ||
    projection.policyVersion !== grant.scope.policyVersion
  ) return "CONSENT_PROJECTION_MISMATCH";
  let record: InstitutionalConsentRecord | undefined;
  try {
    record = await directed.institutionalBlockchainClient.readPatientConsent(
      consentIdHash,
      projection.consentVersion
    );
  } catch (error) {
    return isDependencyUnavailable(error)
      ? "CONSENT_PROJECTION_UNAVAILABLE"
      : "CONSENT_PROJECTION_MISMATCH";
  }
  if (
    !record ||
    !record.active ||
    record.consentIdHash !== consentIdHash ||
    record.consentProjectionHash !== grant.consentProjectionHash ||
    record.patientHash !== hashAuthorizationReference(grant.scope.patientReference) ||
    record.granteeOrganizationHash !== hashAuthorizationReference(grant.scope.granteeOrganizationReference) ||
    record.actorConstraintHash !== mapped.actorConstraintHash ||
    record.resourceIdHash !== hashAuthorizationReference(grant.scope.resourceReference) ||
    record.resourceTypeCode !== mapped.resourceTypeCode ||
    record.actionCode !== mapped.actionCode ||
    record.purposeCode !== mapped.purposeCode ||
    record.validFrom !== validFrom ||
    record.validUntil !== validUntil ||
    record.policyMask !== mapped.policyMask
  ) return "CONSENT_PROJECTION_MISMATCH";
  return {
    consentReference: grant.consentReference,
    consentVersion: grant.consentVersion,
    policyId: grant.scope.policyId,
    policyVersion: grant.scope.policyVersion
  };
}

function assertDirectedConsentReaders(client: InstitutionalBlockchainClient) {
  if (typeof client.readActivePatientConsentProjection !== "function") {
    throw new Error("DIRECTED_CONSENT_PROJECTION_READER_NOT_CONFIGURED");
  }
  if (typeof client.readPatientConsent !== "function") {
    throw new Error("DIRECTED_CONSENT_ON_CHAIN_READER_NOT_CONFIGURED");
  }
}

function safeConsentErrorCode(error: unknown) {
  const message = error instanceof Error ? error.message : "CONSENT_PROJECTION_UNAVAILABLE";
  return /^[A-Z][A-Z0-9_:-]{1,127}$/.test(message) ? message : "CONSENT_PROJECTION_UNAVAILABLE";
}

function safeAccessErrorCode(error: unknown, fallback: string) {
  const message = error instanceof Error ? error.message : fallback;
  return /^[A-Z][A-Z0-9_:-]{1,127}$/.test(message) ? message : fallback;
}

function isDependencyUnavailable(error: unknown) {
  const message = error instanceof Error ? error.message : String(error);
  const code = typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : "";
  return (
    /^FHIR_HTTP_5\d\d$/.test(message) ||
    /(?:ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|RPC_OFFLINE|NETWORK_ERROR|FETCH_FAILED|TIMEOUT|UNAVAILABLE)/i.test(`${code} ${message}`)
  );
}

function consentVersionFromResource(consent: FhirResource): string {
  const meta = consent.meta;
  if (meta && typeof meta === "object" && !Array.isArray(meta)) {
    const versionId = (meta as { versionId?: unknown }).versionId;
    if (typeof versionId === "string" && /^\d+$/.test(versionId)) return versionId;
  }
  return "unknown";
}

function bestEffortConsentValidation(
  consent: FhirResource,
  consentReference: string
): DirectedConsentValidation {
  const fallback = {
    consentReference,
    consentVersion: consentVersionFromResource(consent),
    policyId: "unknown",
    policyVersion: 0
  };
  try {
    const candidate = {
      ...(consent as FhirConsent),
      ...(consent.status !== "active" ? { status: "active" } : {})
    };
    const grant = mapFhirConsentToPatientConsentGrant(candidate);
    return {
      consentReference: grant.consentReference,
      consentVersion: grant.consentVersion,
      policyId: grant.scope.policyId,
      policyVersion: grant.scope.policyVersion
    };
  } catch {
    return fallback;
  }
}

function createBoundaryEvaluation(
  request: DirectedManifestReadRequest,
  consentReference: string,
  reasonCode: string
): AccessEvaluation {
  return {
    granted: false,
    reasonCode,
    policyId: "unknown",
    policyVersion: 0,
    consentReference,
    consentVersion: "unknown",
    requestHash: ethers.keccak256(
      ethers.toUtf8Bytes(
        JSON.stringify({
          shareId: request.shareId,
          manifestId: request.manifestId,
          practitionerReference: request.practitionerReference,
          organizationReference: request.organizationReference,
          purposeOfUse: request.purposeOfUse,
          requestTime: request.requestTime
        })
      )
    )
  };
}

function createDirectedEvaluation(
  request: DirectedManifestReadRequest,
  manifest: ResourceManifestVersion,
  consent: DirectedConsentValidation,
  reasonCode: string,
  granted: boolean,
  requestHash?: string,
  transactionHash?: string
): AccessEvaluation & { transactionHash?: string } {
  let correlationHash = requestHash;
  if (!correlationHash) {
    try {
      correlationHash = computeAccessRequestCorrelationHash(
        mapDirectedManifestToInstitutionalRequest(manifest, {
          practitionerReference: request.practitionerReference,
          organizationReference: request.organizationReference,
          purposeOfUse: request.purposeOfUse,
          requestTime: request.requestTime,
          assertionHash: request.assertionHash
        })
      );
    } catch {
      correlationHash = ethers.keccak256(
        ethers.toUtf8Bytes(
          JSON.stringify({
            shareId: request.shareId,
            manifestId: request.manifestId,
            practitionerReference: request.practitionerReference,
            organizationReference: request.organizationReference,
            purposeOfUse: request.purposeOfUse,
            requestTime: request.requestTime
          })
        )
      );
    }
  }
  return {
    granted,
    reasonCode,
    policyId: consent.policyId,
    policyVersion: consent.policyVersion,
    consentReference: consent.consentReference,
    consentVersion: consent.consentVersion,
    requestHash: correlationHash,
    ...(transactionHash ? { transactionHash } : {})
  };
}

async function auditDirected(
  fhirClient: NonNullable<ServiceDependencies["directedRead"]>["fhirClient"],
  request: DirectedManifestReadRequest,
  manifest: ResourceManifestVersion | undefined,
  evaluation: AccessEvaluation & { transactionHash?: string }
) {
  await fhirClient.createAuditEvent(
    createAccessAuditEvent({
      action: "read",
      granted: evaluation.granted,
      outcomeReason: evaluation.reasonCode,
      practitionerReference: request.practitionerReference,
      organizationReference: request.organizationReference,
      ...(manifest
        ? {
            resourceReference: manifest.resourceReference,
            patientReference: manifest.subjectReference
          }
        : {}),
      requestHash: evaluation.requestHash,
      ...(request.requestId ? { requestId: request.requestId } : {}),
      ...(evaluation.transactionHash
        ? { transactionHash: evaluation.transactionHash }
        : {}),
      recordedAt: request.recordedAt,
      policyId: evaluation.policyId,
      policyVersion: evaluation.policyVersion,
      consentReference: evaluation.consentReference,
      consentVersion: evaluation.consentVersion,
      ...(manifest
        ? {
            institutionReference: manifest.custodianOrganizationReference,
            custodianOrganizationReference: manifest.custodianOrganizationReference
          }
        : {})
    })
  );
}

async function auditDirectedBestEffort(
  fhirClient: NonNullable<ServiceDependencies["directedRead"]>["fhirClient"],
  request: DirectedManifestReadRequest,
  manifest: ResourceManifestVersion | undefined,
  evaluation: AccessEvaluation & { transactionHash?: string }
) {
  try {
    await auditDirected(fhirClient, request, manifest, evaluation);
  } catch {
    // Preserve the primary dependency failure and its fail-closed response.
  }
}

async function finalizeDirected(
  client: InstitutionalBlockchainClient,
  requestHash: string,
  delivered: boolean,
  reasonCode: number
) {
  try {
    await client.finalizeEnforcement(requestHash, delivered, reasonCode);
    return true;
  } catch {
    return false;
  }
}

function normalizeBytes32(value: string): string {
  return /^0x[0-9a-fA-F]{64}$/.test(value)
    ? value
    : ethers.keccak256(ethers.toUtf8Bytes(value));
}

function fhirResourceMatchesManifestVersion(
  resource: FhirResource,
  manifest: ResourceManifestVersion
) {
  try {
    const metadata = extractResourceManifestMetadata(resource);
    const versionId =
      resource.meta && typeof resource.meta === "object" && !Array.isArray(resource.meta)
        ? resource.meta.versionId
        : undefined;
    return (
      metadata.subjectReference === manifest.subjectReference &&
      metadata.resourceReference === manifest.resourceReference &&
      metadata.resourceType === manifest.resourceType &&
      versionId === manifest.fhirVersionId
    );
  } catch {
    return false;
  }
}
