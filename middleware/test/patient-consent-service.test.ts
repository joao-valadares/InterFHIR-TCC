import { expect } from "chai";

import { buildPatientConsentResource } from "../src/fhir/consent-builder.js";
import {
  createPatientConsentService,
  type ConsentOperation,
  type ConsentOperationRepository,
  type PatientConsentCreateRequest
} from "../src/consent/patient-consent-service.js";
import type { FhirResource } from "../src/fhir/resource-hasher.js";
import type { ShareGrant } from "../src/share/share-grant.js";

const now = "2026-08-01T10:00:00.000Z";
const patientReference = "Patient/ana";
const input: PatientConsentCreateRequest = {
  granteeOrganizationReference: "Organization/clinic-b",
  practitionerReference: "Practitioner/beatriz",
  resourceReference: "Observation/obs-ana-1",
  purposeOfUse: "TREAT",
  policyId: "POLICY_TREATMENT_OBSERVATION",
  policyVersion: 1,
  validUntil: "2026-08-30T23:59:59.000Z"
};

describe("patient Consent lifecycle service", function () {
  it("creates one constrained Consent, anchors it, derives one share, publishes one manifest, and returns no clinical payload", async function () {
    const harness = createHarness();

    const result = await harness.service.create({
      patientReference,
      idempotencyKey: "consent-demo-001",
      request: input
    });

    expect(result).to.include({
      consentVersion: "1",
      policyId: input.policyId,
      policyVersion: 1,
      manifestId: "manifest_opaque",
      status: "active"
    });
    expect(result.consentReference).to.equal(harness.upsertReference);
    expect(result.consentHash).to.match(/^0x[0-9a-f]{64}$/);
    expect(result.shareId).to.match(/^share_[0-9a-f-]{36}$/);
    expect(result.handoffCode).to.be.a("string").and.have.length.greaterThan(16);
    expect(JSON.stringify(harness.blockchainInputs)).not.to.include("obs-ana-1");
    expect(harness.resourceIntegrityInputs).to.deep.equal([{
      resourceReference: "Observation/obs-ana-1",
      resourceType: "Observation",
      resourceHash: `0x${"1".repeat(64)}`
    }]);
    expect(harness.events).to.deep.equal([
      "operation:pending_fhir",
      "fhir:upsert:Consent",
      "operation:pending_chain",
      "chain:register",
      "operation:pending_manifest",
      "share:pending",
      "share:active",
      "handoff:issued",
      "manifest:publish",
      "chain:resource-integrity",
      "operation:active"
    ]);
  });

  it("reuses an idempotent operation without creating a second Consent or share", async function () {
    const harness = createHarness();

    const first = await harness.service.create({
      patientReference,
      idempotencyKey: "consent-demo-idempotent",
      request: input
    });
    const second = await harness.service.create({
      patientReference,
      idempotencyKey: "consent-demo-idempotent",
      request: input
    });

    expect(second).to.deep.equal(first);
    expect(harness.events.filter((event) => event === "fhir:upsert:Consent")).to.have.length(1);
    expect(harness.events.filter((event) => event === "share:pending")).to.have.length(1);
  });

  it("serializes same-key requests so concurrent calls create one Consent and one share", async function () {
    let createEntered = 0;
    let releaseCreate!: () => void;
    const createGate = new Promise<void>((resolve) => { releaseCreate = resolve; });
    const harness = createHarness({
      beforeCreateResource: async () => {
        createEntered += 1;
        if (createEntered === 1) await createGate;
      }
    });

    const first = harness.service.create({ patientReference, idempotencyKey: "consent-demo-concurrent", request: input });
    await new Promise<void>((resolve) => {
      const wait = () => createEntered === 1 ? resolve() : setTimeout(wait, 0);
      wait();
    });
    const second = harness.service.create({ patientReference, idempotencyKey: "consent-demo-concurrent", request: input });
    releaseCreate();

    const [firstResult, secondResult] = await Promise.all([first, second]);
    expect(secondResult).to.deep.equal(firstResult);
    expect(harness.events.filter((event) => event === "fhir:upsert:Consent")).to.have.length(1);
    expect(harness.events.filter((event) => event === "share:pending")).to.have.length(1);
  });

  it("does not let a worker continue after another owner fences its expired lease", async function () {
    const harness = createHarness({ useLease: true, loseLeaseBeforeFhir: true });

    await expectRejected(
      () => harness.service.create({ patientReference, idempotencyKey: "consent-demo-lost-lease", request: input }),
      "CONSENT_OPERATION_LEASE_LOST"
    );
    expect(harness.events).not.to.include("fhir:create:Consent");
    expect(harness.events).not.to.include("fhir:upsert:Consent");
  });

  it("recovers a crashed FHIR upsert without issuing a second Consent write", async function () {
    const harness = createHarness({ failUpsertAfterWrite: true });

    await expectRejected(
      () => harness.service.create({ patientReference, idempotencyKey: "consent-demo-fhir-upsert", request: input }),
      "FHIR_UPSERT_INTERRUPTED"
    );
    const recovered = await harness.service.create({
      patientReference,
      idempotencyKey: "consent-demo-fhir-upsert",
      request: input
    });

    expect(recovered.consentReference).to.equal(harness.upsertReference);
    expect(harness.upsertCalls).to.equal(1);
  });

  it("rejects a same-key request whose scope or policy changes", async function () {
    const harness = createHarness();
    await harness.service.create({ patientReference, idempotencyKey: "consent-demo-scope", request: input });

    await expectRejected(
      () => harness.service.create({
        patientReference,
        idempotencyKey: "consent-demo-scope",
        request: { ...input, resourceReference: "Observation/obs-other" }
      }),
      "IDEMPOTENCY_KEY_SCOPE_MISMATCH"
    );
  });

  it("does not issue a second one-time handoff when its checkpoint is lost", async function () {
    const harness = createHarness({ failHandoffIssue: true });

    await expectRejected(
      () => harness.service.create({ patientReference, idempotencyKey: "consent-demo-handoff-recovery", request: input }),
      "HANDOFF_ISSUE_INTERRUPTED"
    );
    await expectRejected(
      () => harness.service.create({ patientReference, idempotencyKey: "consent-demo-handoff-recovery", request: input }),
      "IDEMPOTENCY_RESULT_UNAVAILABLE"
    );
    expect(harness.handoffIssueCount).to.equal(1);
  });

  it("fails closed when the authenticated patient does not match the created Consent", async function () {
    const harness = createHarness({
      consent: buildConsent("Patient/other")
    });

    await expectRejected(
      () => harness.service.create({ patientReference, idempotencyKey: "consent-demo-mismatch", request: input }),
      "FHIR_CONSENT_PATIENT_MISMATCH"
    );
    expect(harness.blockchainInputs).to.deep.equal([]);
    expect(harness.events.some((event) => event === "share:pending")).to.equal(false);
  });

  it("rejects missing or inactive policy before writing FHIR", async function () {
    for (const errorCode of ["POLICY_NOT_FOUND", "POLICY_NOT_ACTIVE"]) {
      const harness = createHarness({
        validatePolicy: async () => { throw new Error(errorCode); }
      });

      await expectRejected(
        () => harness.service.create({ patientReference, idempotencyKey: `consent-demo-${errorCode}`, request: input }),
        errorCode
      );
      expect(harness.events).not.to.include("fhir:create:Consent");
    }
  });

  it("rejects an invalid period, an unregistered institution, another organization's practitioner, or a missing resource", async function () {
    const cases: Array<{ errorCode: string; overrides: HarnessOverrides }> = [
      { errorCode: "INVALID_CONSENT_PERIOD", overrides: { now: "2026-08-30T23:59:59.000Z" } },
      { errorCode: "INSTITUTION_NOT_REGISTERED", overrides: { validateInstitution: async () => { throw new Error("INSTITUTION_NOT_REGISTERED"); } } },
      { errorCode: "PRACTITIONER_ORGANIZATION_MISMATCH", overrides: { validatePractitioner: async () => { throw new Error("PRACTITIONER_ORGANIZATION_MISMATCH"); } } },
      { errorCode: "RESOURCE_NOT_FOUND", overrides: { validateResource: async () => { throw new Error("RESOURCE_NOT_FOUND"); } } }
    ];

    for (const [index, testCase] of cases.entries()) {
      const harness = createHarness(testCase.overrides);
      await expectRejected(
        () => harness.service.create({ patientReference, idempotencyKey: `consent-demo-invalid-${index}`, request: input }),
        testCase.errorCode
      );
      expect(harness.events).not.to.include("fhir:create:Consent");
    }
  });

  it("rejects a resource validator result whose identity differs from the request", async function () {
    const harness = createHarness({
      validateResource: async () => ({ resourceType: "Observation", resourceReference: "Observation/obs-other" })
    });

    await expectRejected(
      () => harness.service.create({ patientReference, idempotencyKey: "consent-demo-resource-identity", request: input }),
      "RESOURCE_IDENTITY_MISMATCH"
    );
    expect(harness.events).not.to.include("fhir:create:Consent");
  });

  it("rejects construction when a security validator is missing", function () {
    expect(() => createHarness({ omitValidators: true })).to.throw("VALIDATE_POLICY_NOT_CONFIGURED");
  });

  it("treats an empty blockchain tuple as an absent Consent", async function () {
    const harness = createHarness({
      getPatientConsent: async () => emptyPatientConsentRecord()
    });

    const result = await harness.service.create({
      patientReference,
      idempotencyKey: "consent-demo-empty-chain-record",
      request: input
    });

    expect(result.status).to.equal("active");
    expect(harness.chainRegistrationCount).to.equal(1);
  });

  it("marks a chain outage recoverable and resumes from the durable chain stage", async function () {
    let failChain = true;
    const harness = createHarness({
      registerPatientConsent: async (value) => {
        harness.blockchainInputs.push(value);
        if (failChain) throw new Error("BLOCKCHAIN_UNAVAILABLE");
        harness.events.push("chain:register");
        return "0xtx";
      }
    });

    await expectRejected(
      () => harness.service.create({ patientReference, idempotencyKey: "consent-demo-recovery", request: input }),
      "BLOCKCHAIN_UNAVAILABLE"
    );
    expect(harness.operations.values()[0]?.state).to.equal("failed_recoverable");
    expect(harness.operations.values()[0]?.resumeState).to.equal("pending_chain");

    failChain = false;
    const result = await harness.service.create({
      patientReference,
      idempotencyKey: "consent-demo-recovery",
      request: input
    });
    expect(result.status).to.equal("active");
    expect(harness.events.filter((event) => event === "fhir:upsert:Consent")).to.have.length(1);
  });

  it("revokes FHIR, blockchain, share, and manifest access for the authenticated patient", async function () {
    const harness = createHarness();
    const created = await harness.service.create({
      patientReference,
      idempotencyKey: "consent-demo-revoke",
      request: input
    });

    const result = await harness.service.revoke({
      patientReference,
      consentReference: created.consentReference
    });

    expect(result).to.include({
      consentReference: created.consentReference,
      consentVersion: "1",
      shareId: created.shareId,
      status: "revoked"
    });
    expect(harness.updatedConsent?.status).to.equal("inactive");
    expect(harness.events).to.include.members(["chain:revoke", "share:revoked", "manifest:revoke", "operation:revoked"]);
  });
});

function createHarness(overrides: HarnessOverrides = {}) {
  const events: string[] = [];
  const blockchainInputs: unknown[] = [];
  const resourceIntegrityInputs: unknown[] = [];
  const operations = createOperationStore(events, overrides);
  const share: ShareGrant = {
    shareId: "share_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    custodianOrganizationReference: "Organization/hospital-a",
    granteeOrganizationReference: input.granteeOrganizationReference,
    patientReference,
    consentReference: "Consent/cons-generated",
    allowedResourceTypes: ["Observation"],
    allowedOperation: "read" as const,
    allowedPurpose: "TREAT",
    validFrom: now,
    validUntil: input.validUntil,
    status: "active" as const,
    createdAt: now
  };
  let storedShare: ShareGrant | undefined;
  let consent: FhirResource = overrides.consent ?? buildConsent(patientReference);
  let updatedConsent: FhirResource | undefined;
  let chainRegistrationCount = 0;
  let handoffIssueCount = 0;
  let upsertCalls = 0;
  let upsertReference: string | undefined;
  const fhir = {
    createResource: async (resource: FhirResource) => {
      events.push("fhir:create:Consent");
      await overrides.beforeCreateResource?.();
      consent = overrides.consent ?? { ...resource, id: "cons-generated", meta: { versionId: "1" } };
      return consent;
    },
    upsertResource: async (reference: string, resource: FhirResource) => {
      upsertCalls += 1;
      upsertReference = reference;
      events.push("fhir:upsert:Consent");
      await overrides.beforeCreateResource?.();
      consent = overrides.consent
        ? { ...overrides.consent, id: reference.slice("Consent/".length), meta: { versionId: "1" } }
        : { ...resource, id: reference.slice("Consent/".length), meta: { versionId: "1" } };
      if (overrides.failUpsertAfterWrite) throw new Error("FHIR_UPSERT_INTERRUPTED");
      return consent;
    },
    readResource: async (reference: string) => reference === "Observation/obs-ana-1" ? observation() : consent,
    updateResource: async (_reference: string, resource: FhirResource) => {
      updatedConsent = resource;
      consent = resource;
      return resource;
    }
  };
  const validation = overrides.omitValidators ? {} : {
    validatePolicy: overrides.validatePolicy ?? (async () => undefined),
    validateInstitution: overrides.validateInstitution ?? (async () => undefined),
    validatePractitioner: overrides.validatePractitioner ?? (async () => undefined),
    validateResource: overrides.validateResource ?? (async () => ({ resourceType: "Observation", resourceReference: "Observation/obs-ana-1" }))
  };
  const service = createPatientConsentService({
    fhirClient: fhir,
    operations,
    shares: {
      savePending: async (value: ShareGrant) => { events.push("share:pending"); storedShare = value; return value; },
      activate: async () => {
        events.push("share:active");
        const activated: ShareGrant = { ...(storedShare ?? share), status: "active" };
        storedShare = activated;
        return activated;
      },
      findById: async () => storedShare,
      issueHandoffCode: async () => {
        handoffIssueCount += 1;
        if (overrides.failHandoffIssue) throw new Error("HANDOFF_ISSUE_INTERRUPTED");
        events.push("handoff:issued");
      },
      revoke: async () => { events.push("share:revoked"); return { ...share, status: "revoked" as const }; }
    },
    publication: {
      publishInitial: async () => { events.push("manifest:publish"); return { manifestId: "manifest_opaque", resourceReference: "Observation/obs-ana-1", resourceType: "Observation", resourceHash: `0x${"1".repeat(64)}` } as never; },
      findActiveForShare: async () => undefined,
      revokeForShare: async () => { events.push("manifest:revoke"); return { manifestIds: ["manifest_opaque"] }; }
    },
    blockchain: {
      ...(overrides.getPatientConsent ? { getPatientConsent: overrides.getPatientConsent } : {}),
      registerPatientConsent: overrides.registerPatientConsent ?? (async (value: unknown) => {
        blockchainInputs.push(value);
        chainRegistrationCount += 1;
        events.push("chain:register");
        return "0xtx";
      }),
      syncResourceIntegrity: async (value: unknown) => {
        resourceIntegrityInputs.push(value);
        events.push("chain:resource-integrity");
      },
      revokePatientConsent: async () => { events.push("chain:revoke"); return "0xrevoke"; }
    },
    custodianOrganizationReference: "Organization/hospital-a",
    now: () => overrides.now ?? now,
    ...validation
  } as never);

  return {
    service,
    operations,
    events,
    blockchainInputs,
    resourceIntegrityInputs,
    get updatedConsent() { return updatedConsent; },
    get chainRegistrationCount() { return chainRegistrationCount; },
    get handoffIssueCount() { return handoffIssueCount; },
    get upsertCalls() { return upsertCalls; },
    get upsertReference() { return upsertReference; }
  };
}

type HarnessOverrides = {
  now?: string;
  consent?: FhirResource;
  validatePolicy?: (input: unknown) => Promise<void>;
  validateInstitution?: (input: string) => Promise<void>;
  validatePractitioner?: (practitioner: string, organization: string) => Promise<void>;
  validateResource?: (resource: string, patient: string) => Promise<{ resourceType: string; resourceReference?: string }>;
  registerPatientConsent?: (input: unknown) => Promise<string>;
  getPatientConsent?: () => Promise<unknown>;
  beforeCreateResource?: () => Promise<void>;
  failHandoffIssue?: boolean;
  failUpsertAfterWrite?: boolean;
  useLease?: boolean;
  loseLeaseBeforeFhir?: boolean;
  omitValidators?: boolean;
};

function buildConsent(patient: string) {
  return {
    ...buildPatientConsentResource({
      patientReference: patient,
      ...input,
      validFrom: now
    }),
    id: "cons-generated",
    meta: { versionId: "1" }
  };
}

function emptyPatientConsentRecord() {
  return {
    consentIdHash: `0x${"0".repeat(64)}`,
    consentProjectionHash: `0x${"0".repeat(64)}`,
    patientHash: `0x${"0".repeat(64)}`,
    granteeOrganizationHash: `0x${"0".repeat(64)}`,
    actorConstraintHash: `0x${"0".repeat(64)}`,
    resourceIdHash: `0x${"0".repeat(64)}`,
    resourceTypeCode: 0,
    actionCode: 0,
    purposeCode: 0,
    validFrom: 0,
    validUntil: 0,
    active: false,
    policyMask: 0
  };
}

function observation() {
  return {
    resourceType: "Observation",
    id: "obs-ana-1",
    subject: { reference: patientReference },
    status: "final"
  };
}

function createOperationStore(events: string[], options: HarnessOverrides = {}) {
  const values = new Map<string, ConsentOperation>();
  const repository: ConsentOperationRepository & {
    values(): ConsentOperation[];
    migrate(): Promise<void>;
    health(): Promise<boolean>;
    close(): Promise<void>;
  } = {
    async createPending(value) {
      const operation: ConsentOperation = {
        ...value,
        state: "pending_fhir",
        createdAt: now,
        updatedAt: now
      };
      values.set(`${operation.patientHash}:${operation.idempotencyKey}`, operation);
      values.set(operation.operationId, operation);
      events.push("operation:pending_fhir");
      return operation;
    },
    async findByIdempotencyKey(patientHash, idempotencyKey) {
      return values.get(`${patientHash}:${idempotencyKey}`);
    },
    async findById(operationId) {
      return values.get(operationId);
    },
    async findByConsent(patientHash, consentReference) {
      return [...values.values()].find((value) => value.patientHash === patientHash && value.consentReference === consentReference);
    },
    async update(operationId, patch) {
      const current = values.get(operationId);
      if (!current) throw new Error("CONSENT_OPERATION_NOT_FOUND");
      const updated = { ...current, ...patch, updatedAt: now } as ConsentOperation & { resumeState?: ConsentOperation["resumeState"]; error?: string };
      if (patch.resumeState === null) delete updated.resumeState;
      if (patch.error === null) delete updated.error;
      values.set(operationId, updated);
      values.set(`${updated.patientHash}:${updated.idempotencyKey}`, updated);
      if (patch.state) events.push(`operation:${patch.state}`);
      return updated;
    },
    values() {
      return [...new Set(values.values())];
    },
    migrate: async () => undefined,
    health: async () => true,
    close: async () => undefined
  };
  if (options.useLease) {
    Object.assign(repository, {
      async claimOrCreatePending(value: Parameters<NonNullable<ConsentOperationRepository["claimOrCreatePending"]>>[0], claim: Parameters<NonNullable<ConsentOperationRepository["claimOrCreatePending"]>>[1]) {
        let operation = values.get(`${value.patientHash}:${value.idempotencyKey}`);
        if (!operation) {
          operation = {
            ...value,
            state: "pending_fhir",
            createdAt: now,
            updatedAt: now
          };
          values.set(`${operation.patientHash}:${operation.idempotencyKey}`, operation);
          values.set(operation.operationId, operation);
          events.push("operation:pending_fhir");
        }
        const leased = { ...operation, leaseOwner: claim.owner, leaseToken: claim.leaseToken, leaseExpiresAt: claim.leaseExpiresAt } as ConsentOperation & { leaseToken?: string };
        values.set(operation.operationId, leased);
        values.set(`${operation.patientHash}:${operation.idempotencyKey}`, leased);
        return { operation: leased, claimed: true };
      },
      async renewLease(operationId: string) {
        if (options.loseLeaseBeforeFhir) throw new Error("CONSENT_OPERATION_LEASE_LOST");
        const operation = values.get(operationId);
        if (!operation) throw new Error("CONSENT_OPERATION_NOT_FOUND");
        return operation;
      },
      async releaseClaim(operationId: string) {
        const operation = values.get(operationId);
        if (operation) {
          const released = { ...operation, leaseOwner: undefined, leaseToken: undefined, leaseExpiresAt: undefined } as ConsentOperation;
          values.set(operationId, released);
          values.set(`${operation.patientHash}:${operation.idempotencyKey}`, released);
        }
      }
    });
  }
  return repository;
}

async function expectRejected(action: () => Promise<unknown>, message: string) {
  try {
    await action();
    expect.fail(`Expected rejection with ${message}`);
  } catch (error) {
    expect((error as Error).message).to.equal(message);
    expect((error as Error).message).not.to.include(input.resourceReference);
  }
}
