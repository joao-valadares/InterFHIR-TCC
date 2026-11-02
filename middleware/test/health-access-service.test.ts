import { expect } from "chai";
import { ethers } from "ethers";

import { createHealthAccessService } from "../src/access/health-access-service.js";
import { buildPatientConsentResource } from "../src/fhir/consent-builder.js";
import { mapFhirConsentToPatientConsentGrant, mapFhirConsentToRegisterConsentInput } from "../src/fhir/consent-mapper.js";
import { hashFhirResource, type FhirResource } from "../src/fhir/resource-hasher.js";
import { computeManifestCommitment, type ResourceManifestVersion } from "../src/manifest/resource-manifest.js";
import type { InstitutionalAccessRequestDto } from "../src/blockchain/ethers-access-client.js";

function observation(): FhirResource {
  return {
    resourceType: "Observation",
    id: "obs-1",
    status: "final",
    subject: { reference: "Patient/maria" },
    meta: { versionId: "7" }
  };
}

function directedManifest(): ResourceManifestVersion {
  const consent = directedConsent();
  const grant = mapFhirConsentToPatientConsentGrant(consent as never);
  const draft: Omit<ResourceManifestVersion, "commitment" | "signature"> = {
    manifestId: "manifest_directed_obs_1",
    shareId: "share_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    version: 1,
    status: "active",
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: "Organization/clinic-b",
    resourceReference: "Observation/obs-1",
    resourceType: "Observation",
    fhirVersionId: "7",
    subjectReference: "Patient/maria",
    consentReferenceHash: ethers.keccak256(ethers.toUtf8Bytes("Consent/cons-1")),
    consentProjectionHash: grant.consentProjectionHash,
    resourceHash: hashFhirResource(observation()),
    previousVersionCommitment: ethers.ZeroHash,
    signingKeyId: "hospital-a-key",
    createdAt: "2027-01-15T10:00:00.000Z"
  };
  return { ...draft, commitment: computeManifestCommitment(draft), signature: "sig" };
}

function directedManifestWithConsent(consentProjectionHash: string): ResourceManifestVersion {
  const draft = {
    ...directedManifest(),
    consentReferenceHash: ethers.keccak256(ethers.toUtf8Bytes("Consent/cons-1")),
    consentProjectionHash
  };
  const { commitment: _commitment, signature: _signature, ...withoutSignature } = draft;
  return { ...draft, commitment: computeManifestCommitment(withoutSignature) };
}

function directedConsent(scope: Partial<Parameters<typeof buildPatientConsentResource>[0]> = {}): FhirResource {
  return {
    ...buildPatientConsentResource({
      patientReference: "Patient/maria",
      granteeOrganizationReference: "Organization/clinic-b",
      practitionerReference: "Practitioner/bruno",
      resourceReference: "Observation/obs-1",
      purposeOfUse: "TREAT",
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1,
      validFrom: "2027-01-15T08:00:00.000Z",
      validUntil: "2027-01-15T18:00:00.000Z",
      ...scope
    }),
    id: "cons-1",
    meta: { versionId: "1" }
  };
}

function directedDependencies(
  manifest: ResourceManifestVersion,
  overrides: Partial<{
    now: () => number;
    organizationReference: string;
    vread: () => Promise<FhirResource>;
    consent: () => Promise<FhirResource>;
    projection: () => Promise<{ policyIdHash: string; policyVersion: number; consentVersion: number; consentProjectionHash: string; active: boolean; status: number }>;
    record: () => Promise<ReturnType<typeof onChainConsentRecord>>;
    institutionalRequest: () => Promise<{ granted: boolean; requestHash: string; transactionHash: string }>;
    policy: (input: { requestTime: string }) => Promise<{ permitted: boolean; reasonCode: string }>;
    manifestSigner: () => Promise<boolean>;
    manifestVerifier: () => Promise<boolean>;
    finalization: () => Promise<string>;
    audit: () => Promise<void>;
  }> = {}
) {
  const institutionalRequests: InstitutionalAccessRequestDto[] = [];
  const finalized: Array<{ delivered: boolean; reasonCode: number }> = [];
  const auditEvents: unknown[] = [];
  const service = createHealthAccessService({
    directedRead: {
      now: overrides.now ?? (() => 1_800_000_000),
      shareRepository: {
        requireActive: async () => ({
          handoffRedeemedAt: "2027-01-15T09:00:00.000Z",
          shareId: manifest.shareId,
          consentReference: "Consent/cons-1",
          patientReference: "Patient/maria",
          granteeOrganizationReference: "Organization/clinic-b",
          allowedPurpose: "TREAT"
        })
      } as never,
      manifestRepository: { requireActiveForShare: async () => manifest },
      manifestSigner: { verify: overrides.manifestSigner ?? (async () => true) },
      manifestVerifier: { verify: overrides.manifestVerifier ?? (async () => true) },
      institutionalBlockchainClient: {
        requestInstitutionalAccess: async (request) => {
          institutionalRequests.push(request);
          return overrides.institutionalRequest?.() ?? { granted: true, requestHash: "0xabc", transactionHash: "0xdef" };
        },
        verifyInstitutionalAccess: async () => true,
        finalizeEnforcement: async (_hash, delivered, reasonCode) => {
          finalized.push({ delivered, reasonCode });
          return overrides.finalization?.() ?? "0xghi";
        },
        readActivePatientConsentProjection: overrides.projection ?? (async () => onChainConsentProjection()),
        readPatientConsent: overrides.record ?? (async () => onChainConsentRecord())
      },
      fhirClient: {
        vread: overrides.vread ?? (async () => observation()),
        readConsent: overrides.consent ?? (async () => directedConsent()),
        createAuditEvent: overrides.audit ?? (async (event) => { auditEvents.push(event); })
      },
      ...(overrides.policy ? {
        institutionalPolicy: {
          evaluate: async (input) => overrides.policy?.(input) ?? { permitted: true, reasonCode: "ACCESS_GRANTED" }
        }
      } : {})
    }
  });
  return { service, institutionalRequests, finalized, auditEvents };
}

function onChainConsentProjection() {
  const mapped = mapFhirConsentToRegisterConsentInput(directedConsent() as never);
  return {
    policyIdHash: mapped.policyIdHash,
    policyVersion: mapped.policyVersion,
    consentVersion: Number(mapped.consentVersion),
    consentProjectionHash: mapped.consentProjectionHash,
    active: true,
    status: 1
  };
}

function onChainConsentRecord() {
  const mapped = mapFhirConsentToRegisterConsentInput(directedConsent() as never);
  return {
    consentIdHash: mapped.consentIdHash,
    consentProjectionHash: mapped.consentProjectionHash,
    patientHash: mapped.patientHash,
    granteeOrganizationHash: mapped.granteeOrganizationHash,
    actorConstraintHash: mapped.actorConstraintHash,
    resourceIdHash: mapped.resourceIdHash,
    resourceTypeCode: mapped.resourceTypeCode,
    actionCode: mapped.actionCode,
    purposeCode: mapped.purposeCode,
    validFrom: mapped.validFrom,
    validUntil: mapped.validUntil,
    policyMask: mapped.policyMask,
    active: true
  };
}

describe("Health access middleware service", function () {
  for (const mutation of ["revocation", "version", "scope"] as const) {
    it(`withholds content when concurrent ${mutation} changes Consent while vread is pending`, async function () {
      let announceRead!: () => void;
      let releaseRead!: () => void;
      const readStarted = new Promise<void>(resolve => { announceRead = resolve; });
      const readGate = new Promise<void>(resolve => { releaseRead = resolve; });
      let currentConsent = directedConsent();
      let reads = 0;
      const manifest = directedManifest();
      const { service, institutionalRequests, finalized } = directedDependencies(manifest, {
        consent: async () => currentConsent,
        vread: async () => { reads++; announceRead(); await readGate; return observation(); }
      });
      const pending = service.handleReadByShareManifest({
        shareId: manifest.shareId, manifestId: manifest.manifestId,
        practitionerReference: "Practitioner/bruno", organizationReference: "Organization/clinic-b", purposeOfUse: "TREAT",
        requestTime: 1_800_000_000, recordedAt: "2027-01-15T10:00:00.000Z", assertionHash: "assertion"
      });
      try {
        await readStarted;
        expect(institutionalRequests).to.have.length(1);
        currentConsent = mutation === "revocation" ? { ...directedConsent(), status: "inactive" }
          : mutation === "version" ? { ...directedConsent(), meta: { versionId: "2" } }
          : directedConsent({ resourceReference: "Observation/another-resource" });
      } finally { releaseRead(); }
      const response = await pending;
      const expected = { revocation: "FHIR_CONSENT_NOT_ACTIVE", version: "CONSENT_MANIFEST_MISMATCH", scope: "CONSENT_MANIFEST_MISMATCH" }[mutation];
      expect(response).to.deep.equal({ status: 403, body: { error: expected } });
      expect(reads).to.equal(1);
      expect(finalized.some(event => event.delivered)).to.equal(false);
    });
  }
  for (const mismatch of ["content", "version"] as const) {
    it(`withholds a ${mismatch} mismatch after exactly one vread and finalizes a denial`, async function () {
      const manifest = directedManifest();
      let vreadCalls = 0;
      const { service, finalized, auditEvents } = directedDependencies(manifest, {
        vread: async () => {
          vreadCalls += 1;
          return mismatch === "content"
            ? { ...observation(), status: "amended" }
            : { ...observation(), meta: { versionId: "8" } };
        }
      });
      const response = await service.handleReadByShareManifest({
        shareId: manifest.shareId, manifestId: manifest.manifestId,
        practitionerReference: "Practitioner/bruno", organizationReference: "Organization/clinic-b",
        purposeOfUse: "TREAT", requestTime: 1_800_000_000,
        recordedAt: "2027-01-15T10:00:00.000Z", assertionHash: "0xassertion"
      });
      const reason = mismatch === "content"
        ? "MANIFEST_RESOURCE_HASH_MISMATCH" : "MANIFEST_RESOURCE_METADATA_MISMATCH";
      expect(response).to.deep.equal({ status: 403, body: { error: reason } });
      expect(vreadCalls).to.equal(1);
      expect(finalized).to.deep.equal([{ delivered: false, reasonCode: 6 }]);
      expect(auditEvents).to.have.length(1);
      expect(auditEvents[0]).to.have.property("outcomeDesc", reason);
    });
  }
  it("exposes only the directed institutional read operation", function () {
    const service = createHealthAccessService({
      directedRead: {
        shareRepository: { requireActive: async () => ({}) },
        manifestRepository: { requireActiveForShare: async () => directedManifest() },
        manifestSigner: { verify: async () => true },
        manifestVerifier: { verify: async () => true },
        fhirClient: {
          vread: async () => observation(),
          readConsent: async () => directedConsent(),
          createAuditEvent: async () => undefined
        },
        institutionalBlockchainClient: {
          requestInstitutionalAccess: async () => ({ granted: true, requestHash: "0xabc", transactionHash: "0xdef" }),
          verifyInstitutionalAccess: async () => true,
          finalizeEnforcement: async () => "0xghi",
          readActivePatientConsentProjection: async () => onChainConsentProjection(),
          readPatientConsent: async () => onChainConsentRecord()
        }
      }
    } as never);

    expect(service).not.to.have.property("handleRead");
    expect(service).not.to.have.property("handleReadByManifest");
    expect(service.handleReadByShareManifest).to.be.a("function");
  });

  it("authorizes a directed FHIR vread only after share, consent and blockchain checks", async function () {
    const manifest = directedManifest();
    const { service, institutionalRequests, finalized } = directedDependencies(manifest);
    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: ethers.keccak256(ethers.toUtf8Bytes("trusted-assertion"))
    });

    expect(response.status).to.equal(200);
    expect(institutionalRequests[0]).to.include({
      consentIdHash: manifest.consentReferenceHash,
      consentProjectionHash: manifest.consentProjectionHash
    });
    expect(finalized).to.deep.equal([{ delivered: true, reasonCode: 1 }]);
  });

  it("denies a non-grantee before retrieving the resource", async function () {
    let vreadCalls = 0;
    const manifest = directedManifest();
    const { service } = directedDependencies(manifest, {
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });
    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/attacker",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });
    expect(response).to.deep.equal({ status: 403, body: { error: "SHARE_GRANTEE_MISMATCH" } });
    expect(vreadCalls).to.equal(0);
  });

  it("normalizes an externally represented assertion hash before the EVM request", async function () {
    const manifest = directedManifest();
    const { service, institutionalRequests } = directedDependencies(manifest);
    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "sha256:external-representation"
    });

    expect(response.status).to.equal(200);
    expect(institutionalRequests[0].assertionHash).to.match(/^0x[0-9a-f]{64}$/i);
  });

  it("denies a mutated Consent before requestInstitutionalAccess and vread", async function () {
    const originalConsent = directedConsent();
    const originalGrant = mapFhirConsentToPatientConsentGrant(originalConsent as never);
    const manifest = directedManifestWithConsent(originalGrant.consentProjectionHash);
    let vreadCalls = 0;
    const { service, institutionalRequests } = directedDependencies(manifest, {
      consent: async () => ({
        ...originalConsent,
        provision: {
          ...(originalConsent.provision as Record<string, unknown>),
          data: [{ reference: { reference: "Observation/obs-other" } }]
        }
      }),
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "CONSENT_MANIFEST_MISMATCH" } });
    expect(institutionalRequests).to.deep.equal([]);
    expect(vreadCalls).to.equal(0);
  });

  it("denies when the active on-chain Consent projection has a different version", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    const { service, institutionalRequests } = directedDependencies(manifest, {
      projection: async () => ({
        policyIdHash: ethers.keccak256(ethers.toUtf8Bytes("POLICY_TREATMENT_OBSERVATION")),
        policyVersion: 1,
        consentVersion: 2,
        consentProjectionHash: manifest.consentProjectionHash,
        active: true,
        status: 1
      }),
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "CONSENT_PROJECTION_MISMATCH" } });
    expect(institutionalRequests).to.deep.equal([]);
    expect(vreadCalls).to.equal(0);
  });

  it("does not vread when the local policy is inactive or version-divergent", async function () {
    for (const reasonCode of ["LOCAL_POLICY_INACTIVE", "LOCAL_POLICY_VERSION_MISMATCH"]) {
      const manifest = directedManifest();
      let vreadCalls = 0;
      const { service } = directedDependencies(manifest, {
        policy: async () => ({ permitted: false, reasonCode }),
        vread: async () => {
          vreadCalls += 1;
          return observation();
        }
      });

      const response = await service.handleReadByShareManifest({
        shareId: manifest.shareId,
        manifestId: manifest.manifestId,
        practitionerReference: "Practitioner/bruno",
        organizationReference: "Organization/clinic-b",
        purposeOfUse: "TREAT",
        requestTime: 1_800_000_000,
        recordedAt: "1999-01-01T00:00:00.000Z",
        assertionHash: "0xassertion"
      });

      expect(response).to.deep.equal({ status: 403, body: { error: "INSTITUTIONAL_POLICY_DENIED" } });
      expect(vreadCalls).to.equal(0);
    }
  });

  it("does not vread an expired current Consent", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    const { service } = directedDependencies(manifest, {
      consent: async () => {
        const expired = directedConsent() as FhirResource & {
          provision: { period: { end: string } };
        };
        expired.provision.period.end = "2027-01-15T08:30:00.000Z";
        return expired;
      },
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_003_600,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "FHIR_CONSENT_EXPIRED" } });
    expect(vreadCalls).to.equal(0);
  });

  it("does not vread when the current Consent organization is mismatched", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    const { service } = directedDependencies(manifest, {
      consent: async () => {
        const mismatched = directedConsent() as FhirResource & {
          organization: Array<{ reference: string }>;
        };
        mismatched.organization = [{ reference: "Organization/attacker" }];
        return mismatched;
      },
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "CONSENT_ORGANIZATION_MISMATCH" } });
    expect(vreadCalls).to.equal(0);
  });

  it("does not vread when the manifest signature or commitment is tampered", async function () {
    for (const manifestCheck of ["signature", "commitment"] as const) {
      const manifest = directedManifest();
      let vreadCalls = 0;
      const { service } = directedDependencies(manifest, {
        ...(manifestCheck === "signature"
          ? { manifestSigner: async () => false }
          : { manifestVerifier: async () => false }),
        vread: async () => {
          vreadCalls += 1;
          return observation();
        }
      });

      const response = await service.handleReadByShareManifest({
        shareId: manifest.shareId,
        manifestId: manifest.manifestId,
        practitionerReference: "Practitioner/bruno",
        organizationReference: "Organization/clinic-b",
        purposeOfUse: "TREAT",
        requestTime: 1_800_000_000,
        recordedAt: "2027-01-15T10:00:00.000Z",
        assertionHash: "0xassertion"
      });

      expect(response).to.deep.equal({ status: 409, body: { error: "MANIFEST_COMMITMENT_MISMATCH" } });
      expect(vreadCalls).to.equal(0);
    }
  });

  it("returns 503 when manifest blockchain verification is unavailable", async function () {
    const manifest = directedManifest();
    const { service } = directedDependencies(manifest, {
      manifestVerifier: async () => { throw new Error("RPC_OFFLINE"); }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } });
  });

  it("preserves the FHIR dependency 503 when AuditEvent finalization also fails", async function () {
    const manifest = directedManifest();
    const { service } = directedDependencies(manifest, {
      consent: async () => { throw new Error("FHIR_HTTP_503"); },
      audit: async () => { throw new Error("AUDIT_EVENT_UNAVAILABLE"); }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 503, body: { error: "FHIR_CONSENT_UNAVAILABLE" } });
  });

  it("uses trusted requestTime for local policy evaluation and blocks delivery after post-read finalization failure", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    let policyRequestTime: string | undefined;
    const { service, auditEvents } = directedDependencies(manifest, {
      policy: async (input) => {
        policyRequestTime = input.requestTime;
        return { permitted: true, reasonCode: "ACCESS_GRANTED" };
      },
      finalization: async () => {
        throw new Error("FINALIZATION_UNAVAILABLE");
      },
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "1999-01-01T00:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(policyRequestTime).to.equal(new Date(1_800_000_000 * 1000).toISOString());
    expect(vreadCalls).to.equal(1);
    expect(response).to.deep.equal({ status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } });
    expect(auditEvents).to.have.length(1);
    expect(auditEvents[0]).to.have.nested.property(
      "outcomeDesc",
      "ACCESS_DECISION_PERMITTED"
    );
    expect(auditEvents[0]).to.have.nested.property("outcome", "0");
  });

  it("blocks clinical delivery when mandatory audit fails", async function () {
    const manifest = directedManifest();
    const { service, finalized } = directedDependencies(manifest, { audit: async () => { throw new Error("secret dependency details"); } });
    const response = await service.handleReadByShareManifest({ shareId: manifest.shareId, manifestId: manifest.manifestId, practitionerReference: "Practitioner/bruno", organizationReference: "Organization/clinic-b", purposeOfUse: "TREAT", requestTime: 1_800_000_000, recordedAt: "2027-01-15T10:00:00.000Z", assertionHash: "assertion" });
    expect(response).to.deep.equal({ status: 503, body: { error: "AUDIT_UNAVAILABLE" } });
    expect(finalized.some(item => item.delivered)).to.equal(false);
  });

  for (const mutation of ["revocation", "expiration"] as const) it("blocks " + mutation + " during a clinical read", async function () {
    const manifest = directedManifest();
    let readFinished = false;
    const { service, finalized } = directedDependencies(manifest, {
      now: () => mutation === "expiration" && readFinished ? 1_800_100_000 : 1_800_000_000,
      consent: async () => ({ ...directedConsent(), status: mutation === "revocation" && readFinished ? "inactive" : "active" }),
      vread: async () => { readFinished = true; return observation(); }
    });
    const response = await service.handleReadByShareManifest({ shareId: manifest.shareId, manifestId: manifest.manifestId, practitionerReference: "Practitioner/bruno", organizationReference: "Organization/clinic-b", purposeOfUse: "TREAT", requestTime: 1_800_000_000, recordedAt: "2027-01-15T10:00:00.000Z", assertionHash: "assertion" });
    expect(response).to.deep.equal({ status: 403, body: { error: mutation === "revocation" ? "FHIR_CONSENT_NOT_ACTIVE" : "FHIR_CONSENT_EXPIRED" } });
    expect(finalized.some(item => item.delivered)).to.equal(false);
  });

  it("revalidates the current Consent actor before any vread", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    const { service, institutionalRequests } = directedDependencies(manifest, {
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/attacker",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "CONSENT_PRACTITIONER_MISMATCH" } });
    expect(institutionalRequests).to.deep.equal([]);
    expect(vreadCalls).to.equal(0);
  });

  it("fails closed and audits an inactive Consent without clinical entities", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    const { service, auditEvents } = directedDependencies(manifest, {
      consent: async () => ({ ...directedConsent(), status: "inactive" }),
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "FHIR_CONSENT_NOT_ACTIVE" } });
    expect(vreadCalls).to.equal(0);
    expect(auditEvents).to.have.length(1);
    expect(auditEvents[0]).to.have.nested.property("outcomeDesc", "FHIR_CONSENT_NOT_ACTIVE");
    expect(auditEvents[0]).to.have.nested.property("extension[1].valueString").that.is.a("string");
    expect(JSON.stringify(auditEvents[0])).to.not.contain("Observation/obs-1");
    expect(JSON.stringify(auditEvents[0])).to.not.contain("Patient/maria");
  });

  it("does not vread when the versioned policy is denied by the trusted blockchain", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    const { service, auditEvents } = directedDependencies(manifest, {
      institutionalRequest: async () => ({ granted: false, requestHash: "0xabc", transactionHash: "0xdef" }),
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "ACCESS_DENIED" } });
    expect(vreadCalls).to.equal(0);
    expect(auditEvents).to.have.length(1);
    expect(auditEvents[0]).to.have.nested.property("outcomeDesc", "ACCESS_DENIED");
  });

  it("fails closed when the blockchain cannot evaluate the request", async function () {
    const manifest = directedManifest();
    let vreadCalls = 0;
    const { service } = directedDependencies(manifest, {
      institutionalRequest: async () => {
        throw new Error("RPC_OFFLINE");
      },
      vread: async () => {
        vreadCalls += 1;
        return observation();
      }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } });
    expect(vreadCalls).to.equal(0);
  });

  it("returns 503 when the FHIR Consent dependency is unavailable", async function () {
    const manifest = directedManifest();
    const { service } = directedDependencies(manifest, {
      consent: async () => { throw new Error("FHIR_HTTP_503"); }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 503, body: { error: "FHIR_CONSENT_UNAVAILABLE" } });
  });

  it("returns 503 when the on-chain Consent projection dependency is unavailable", async function () {
    const manifest = directedManifest();
    const { service } = directedDependencies(manifest, {
      projection: async () => { throw new Error("RPC_OFFLINE"); }
    });

    const response = await service.handleReadByShareManifest({
      shareId: manifest.shareId,
      manifestId: manifest.manifestId,
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b",
      purposeOfUse: "TREAT",
      requestTime: 1_800_000_000,
      recordedAt: "2027-01-15T10:00:00.000Z",
      assertionHash: "0xassertion"
    });

    expect(response).to.deep.equal({ status: 503, body: { error: "CONSENT_PROJECTION_UNAVAILABLE" } });
  });

  it("rejects directed-read construction without the mandatory current on-chain Consent readers", function () {
    expect(() => createHealthAccessService({
      directedRead: {
        shareRepository: { requireActive: async () => ({}) } as never,
        manifestRepository: { requireActiveForShare: async () => directedManifest() },
        manifestSigner: { verify: async () => true },
        manifestVerifier: { verify: async () => true },
        fhirClient: {
          vread: async () => observation(),
          readConsent: async () => directedConsent(),
          createAuditEvent: async () => undefined
        },
        institutionalBlockchainClient: {
          requestInstitutionalAccess: async () => ({ granted: true, requestHash: "0xabc", transactionHash: "0xdef" }),
          verifyInstitutionalAccess: async () => true,
          finalizeEnforcement: async () => "0xghi"
        }
      }
    } as never)).to.throw("DIRECTED_CONSENT_PROJECTION_READER_NOT_CONFIGURED");
  });
});
