import { expect } from "chai";

import {
  createPostgresConsentOperationRepository,
  type ConsentOperation
} from "../src/consent/postgres-consent-operation-repository.js";

describe("PostgreSQL Consent operation repository", function () {
  it("persists idempotency, lifecycle state, recovery state, and patient-scoped lookup", async function () {
    const pool = new FakePool();
    const repository = createPostgresConsentOperationRepository({ pool: pool as never });
    await repository.migrate();

    const operation = await repository.createPending({
      operationId: "op_11111111-1111-4111-8111-111111111111",
      idempotencyKey: "consent-demo-001",
      patientHash: "0xpatient",
      requestDigest: "0xdigest-001",
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1,
      validFrom: "2026-08-01T10:00:00.000Z",
      shareId: "share_11111111-1111-4111-8111-111111111111",
      createdAt: "2026-08-01T10:00:00.000Z"
    });
    const updated = await repository.update(operation.operationId, {
      consentReference: "Consent/opaque",
      consentVersion: "1",
      state: "pending_chain",
      resumeState: "pending_chain"
    });
    const recovered = await repository.update(operation.operationId, {
      state: "failed_recoverable",
      resumeState: "pending_chain",
      error: "BLOCKCHAIN_UNAVAILABLE"
    });

    expect(updated).to.include({
      operationId: operation.operationId,
      requestDigest: "0xdigest-001",
      consentReference: "Consent/opaque",
      consentVersion: "1",
      state: "pending_chain"
    });
    expect(recovered).to.include({
      state: "failed_recoverable",
      resumeState: "pending_chain",
      error: "BLOCKCHAIN_UNAVAILABLE"
    });
    expect(await repository.findByIdempotencyKey("0xpatient", "consent-demo-001")).to.deep.equal(recovered);
    expect(await repository.findByConsent("0xpatient", "Consent/opaque")).to.deep.equal(recovered);
  });

  it("rejects a duplicate patient/idempotency pair without exposing the operation payload", async function () {
    const pool = new FakePool();
    const repository = createPostgresConsentOperationRepository({ pool: pool as never });
    await repository.migrate();
    const input = {
      operationId: "op_22222222-2222-4222-8222-222222222222",
      idempotencyKey: "consent-demo-duplicate",
      patientHash: "0xpatient",
      requestDigest: "0xdigest-duplicate",
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1,
      validFrom: "2026-08-01T10:00:00.000Z",
      shareId: "share_22222222-2222-4222-8222-222222222222",
      createdAt: "2026-08-01T10:00:00.000Z"
    };
    await repository.createPending(input);
    await expectRejected(repository.createPending({ ...input, operationId: "op_33333333-3333-4333-8333-333333333333" }), "CONSENT_OPERATION_ALREADY_EXISTS");
  });

  it("atomically claims the first worker and rejects a mismatched digest", async function () {
    const pool = new FakePool();
    const repository = createPostgresConsentOperationRepository({ pool: pool as never });
    await repository.migrate();
    const input = {
      operationId: "op_44444444-4444-4444-8444-444444444444",
      idempotencyKey: "consent-demo-claim",
      patientHash: "0xpatient",
      requestDigest: "0xdigest-claim",
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1,
      validFrom: "2026-08-01T10:00:00.000Z",
      shareId: "share_44444444-4444-4444-8444-444444444444",
      createdAt: "2026-08-01T10:00:00.000Z"
    };
    const claim = await repository.claimOrCreatePending!(input, {
      owner: "worker-a",
      leaseToken: "lease-claim-a",
      now: "2026-08-01T10:00:00.000Z",
      leaseExpiresAt: "2026-08-01T10:01:00.000Z"
    });
    expect(claim.claimed).to.equal(true);
    const concurrent = await repository.claimOrCreatePending!(
      { ...input, operationId: "op_55555555-5555-4555-8555-555555555555" },
      { owner: "worker-b", leaseToken: "lease-claim-b", now: "2026-08-01T10:00:01.000Z", leaseExpiresAt: "2026-08-01T10:01:01.000Z" }
    );
    expect(concurrent.claimed).to.equal(false);
    await expectRejected(
      repository.claimOrCreatePending!(
        { ...input, operationId: "op_66666666-6666-4666-8666-666666666666", requestDigest: "0xdigest-other" },
        { owner: "worker-c", leaseToken: "lease-claim-c", now: "2026-08-01T10:00:01.000Z", leaseExpiresAt: "2026-08-01T10:01:01.000Z" }
      ),
      "IDEMPOTENCY_KEY_SCOPE_MISMATCH"
    );
  });

  it("fences an expired worker so its stale checkpoint cannot overwrite the new owner", async function () {
    const pool = new FakePool();
    const repository = createPostgresConsentOperationRepository({ pool: pool as never });
    await repository.migrate();
    const input = {
      operationId: "op_77777777-7777-4777-8777-777777777777",
      idempotencyKey: "consent-demo-fence",
      patientHash: "0xpatient-fence",
      requestDigest: "0xdigest-fence",
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1,
      validFrom: "2026-08-01T10:00:00.000Z",
      shareId: "share_77777777-7777-4777-8777-777777777777",
      createdAt: "2026-08-01T10:00:00.000Z"
    };
    const first = await repository.claimOrCreatePending!(input, {
      owner: "worker-a",
      leaseToken: "lease-a",
      now: "2026-08-01T10:00:00.000Z",
      leaseExpiresAt: "2026-08-01T10:00:01.000Z"
    } as never);
    const second = await repository.claimOrCreatePending!({ ...input, operationId: "op_88888888-8888-4888-8888-888888888888" }, {
      owner: "worker-b",
      leaseToken: "lease-b",
      now: "2026-08-01T10:00:02.000Z",
      leaseExpiresAt: "2026-08-01T10:01:02.000Z"
    } as never);

    expect(first.operation.leaseOwner).to.equal("worker-a");
    expect(second.claimed).to.equal(true);
    const fencedUpdate = repository.update as unknown as (operationId: string, patch: Record<string, unknown>, lease: Record<string, unknown>) => Promise<unknown>;
    await expectRejected(
      fencedUpdate(first.operation.operationId, { chainTransactionHash: "0xstale" }, { owner: "worker-a", leaseToken: "lease-a", now: "2026-08-01T10:00:02.000Z" }),
      "CONSENT_OPERATION_LEASE_LOST"
    );
    const renewed = (repository as unknown as { renewLease(operationId: string, lease: Record<string, unknown>): Promise<ConsentOperation> }).renewLease(
      first.operation.operationId,
      { owner: "worker-b", leaseToken: "lease-b", now: "2026-08-01T10:00:02.000Z", leaseExpiresAt: "2026-08-01T10:01:02.000Z" }
    );
    expect((await renewed).leaseOwner).to.equal("worker-b");
  });
});

class FakePool {
  private readonly rows: Array<Record<string, unknown>> = [];

  async connect() {
    return {
      query: this.query.bind(this),
      release() { return undefined; }
    };
  }

  async query<T = Record<string, unknown>>(text: string, values: unknown[] = []) {
    const normalized = text.replace(/\s+/g, " ").trim().toUpperCase();
    if (normalized.startsWith("CREATE TABLE") || normalized.startsWith("CREATE UNIQUE")) {
      return { rows: [], rowCount: 0 } as { rows: T[]; rowCount: number };
    }
    if (normalized.startsWith("INSERT INTO CONSENT_OPERATIONS")) {
      const claimInsert = normalized.includes("ON CONFLICT");
      const [operationId, idempotencyKey, requestDigest, patientHash, policyId, policyVersion, validFrom, shareId] = values as [string, string, string, string, string, number, string, string];
      const owner = claimInsert ? values[8] : null;
      const leaseToken = claimInsert ? values[9] : null;
      const leaseExpiresAt = claimInsert ? values[10] : null;
      const createdAt = claimInsert ? values[11] : values[8];
      if (this.rows.some((row) => row.patient_hash === patientHash && row.idempotency_key === idempotencyKey)) {
        if (normalized.includes("ON CONFLICT")) return { rows: [], rowCount: 0 } as unknown as { rows: T[]; rowCount: number };
        const error = new Error("duplicate") as Error & { code: string };
        error.code = "23505";
        throw error;
      }
      const row = {
        operation_id: operationId,
        idempotency_key: idempotencyKey,
        request_digest: requestDigest,
        patient_hash: patientHash,
        consent_reference: null,
        consent_version: null,
        policy_id: policyId,
        policy_version: policyVersion,
        valid_from: validFrom,
        state: "pending_fhir",
        resume_state: null,
        share_id: shareId,
        manifest_id: null,
        handoff_code_hash: null,
        fhir_create_attempted: false,
        chain_transaction_hash: null,
        revocation_transaction_hash: null,
        lease_owner: owner,
        lease_token: leaseToken,
        lease_expires_at: leaseExpiresAt,
        error: null,
        created_at: createdAt,
        updated_at: createdAt
      };
      this.rows.push(row);
      return { rows: [row], rowCount: 1 } as unknown as { rows: T[]; rowCount: number };
    }
    if (normalized === "BEGIN" || normalized === "COMMIT" || normalized === "ROLLBACK") {
      return { rows: [], rowCount: 0 } as unknown as { rows: T[]; rowCount: number };
    }
    if (normalized.startsWith("SELECT") && normalized.includes("FROM CONSENT_OPERATIONS") && normalized.includes("IDEMPOTENCY_KEY = $2")) {
      const row = this.rows.find((candidate) => candidate.patient_hash === values[0] && candidate.idempotency_key === values[1]);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 } as unknown as { rows: T[]; rowCount: number };
    }
    if (normalized.startsWith("SELECT") && normalized.includes("FROM CONSENT_OPERATIONS") && normalized.includes("WHERE OPERATION_ID = $1")) {
      const row = this.rows.find((candidate) => candidate.operation_id === values[0]);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 } as unknown as { rows: T[]; rowCount: number };
    }
    if (normalized.startsWith("SELECT") && normalized.includes("FROM CONSENT_OPERATIONS") && normalized.includes("CONSENT_REFERENCE = $2")) {
      const row = this.rows.find((candidate) => candidate.patient_hash === values[0] && candidate.consent_reference === values[1]);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 } as unknown as { rows: T[]; rowCount: number };
    }
    if (normalized.startsWith("UPDATE CONSENT_OPERATIONS")) {
      const operationIdMatch = text.match(/WHERE\s+operation_id\s*=\s*\$(\d+)/i);
      const operationIdIndex = operationIdMatch ? Number(operationIdMatch[1]) - 1 : values.length - 1;
      const operationId = values[operationIdIndex];
      const row = this.rows.find((candidate) => candidate.operation_id === operationId);
      if (!row) return { rows: [], rowCount: 0 } as unknown as { rows: T[]; rowCount: number };
      const whereClause = text.split(/WHERE/i)[1] ?? "";
      const ownerMatch = whereClause.match(/lease_owner\s*=\s*\$(\d+)/i);
      const tokenMatch = whereClause.match(/lease_token\s*=\s*\$(\d+)/i);
      const expiryMatch = whereClause.match(/lease_expires_at\s*>\s*\$(\d+)/i);
      if (ownerMatch && row.lease_owner !== values[Number(ownerMatch[1]) - 1]) {
        return { rows: [], rowCount: 0 } as unknown as { rows: T[]; rowCount: number };
      }
      if (tokenMatch && row.lease_token !== values[Number(tokenMatch[1]) - 1]) {
        return { rows: [], rowCount: 0 } as unknown as { rows: T[]; rowCount: number };
      }
      if (expiryMatch && row.lease_expires_at && Date.parse(String(row.lease_expires_at)) <= Date.parse(String(values[Number(expiryMatch[1]) - 1]))) {
        return { rows: [], rowCount: 0 } as unknown as { rows: T[]; rowCount: number };
      }
      Object.assign(row, valuesToPatch(text, values));
      return { rows: [row], rowCount: 1 } as unknown as { rows: T[]; rowCount: number };
    }
    throw new Error(`UNSUPPORTED_FAKE_QUERY:${normalized}`);
  }

  async end() { return undefined; }
}

function valuesToPatch(text: string, values: unknown[]) {
  const match = text.match(/SET\s+(.+)\s+WHERE\s+operation_id/i);
  if (!match) throw new Error("FAKE_UPDATE_SHAPE_UNSUPPORTED");
  const patch: Record<string, unknown> = {};
  for (const assignment of match[1]!.split(",")) {
    const [column, placeholder] = assignment.split("=").map((value) => value.trim());
    if (placeholder?.toUpperCase() === "NULL") {
      patch[column!.toLowerCase().replace(/\s+/g, "")] = null;
      continue;
    }
    const index = Number(placeholder?.match(/\$(\d+)/)?.[1]) - 1;
    const value = values[index];
    const property = {
      consent_reference: "consent_reference",
      consent_version: "consent_version",
      policy_id: "policy_id",
      policy_version: "policy_version",
      state: "state",
      resume_state: "resume_state",
      share_id: "share_id",
      manifest_id: "manifest_id",
      handoff_code_hash: "handoff_code_hash",
      fhir_create_attempted: "fhir_create_attempted",
      chain_transaction_hash: "chain_transaction_hash",
      revocation_transaction_hash: "revocation_transaction_hash",
      lease_owner: "lease_owner",
      lease_token: "lease_token",
      lease_expires_at: "lease_expires_at",
      error: "error",
      updated_at: "updated_at"
    }[column!.toLowerCase().replace(/\s+/g, "")];
    if (property) patch[property] = value;
  }
  return patch;
}

async function expectRejected(promise: Promise<unknown>, message: string) {
  try {
    await promise;
    expect.fail(`Expected rejection with ${message}`);
  } catch (error) {
    expect((error as Error).message).to.equal(message);
  }
}
