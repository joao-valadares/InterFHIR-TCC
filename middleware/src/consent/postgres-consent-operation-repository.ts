import pg from "pg";
import { absorbIdlePostgresClientErrors } from "../persistence/postgres-pool.js";

import type {
  ConsentOperation,
  ConsentOperationLease,
  ConsentOperationRepository,
  ConsentOperationState,
  ConsentOperationUpdate
} from "./patient-consent-service.js";

export type { ConsentOperation } from "./patient-consent-service.js";

const { Pool } = pg;

export const CONSENT_OPERATION_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS consent_operations (
  operation_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT,
  patient_hash TEXT NOT NULL,
  consent_reference TEXT,
  consent_version TEXT,
  policy_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL CHECK (policy_version > 0),
  valid_from TIMESTAMPTZ,
  state TEXT NOT NULL CHECK (state IN (
    'pending_fhir', 'pending_chain', 'pending_manifest', 'active',
    'failed_recoverable', 'revoked', 'superseded'
  )),
  resume_state TEXT,
  share_id TEXT,
  manifest_id TEXT,
  handoff_code_hash TEXT,
  fhir_create_attempted BOOLEAN NOT NULL DEFAULT FALSE,
  chain_transaction_hash TEXT,
  revocation_transaction_hash TEXT,
  lease_owner TEXT,
  lease_token TEXT,
  lease_expires_at TIMESTAMPTZ,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS consent_operations_patient_idempotency
  ON consent_operations (patient_hash, idempotency_key);

ALTER TABLE consent_operations ADD COLUMN IF NOT EXISTS request_digest TEXT;
ALTER TABLE consent_operations ADD COLUMN IF NOT EXISTS fhir_create_attempted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE consent_operations ADD COLUMN IF NOT EXISTS chain_transaction_hash TEXT;
ALTER TABLE consent_operations ADD COLUMN IF NOT EXISTS revocation_transaction_hash TEXT;
ALTER TABLE consent_operations ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE consent_operations ADD COLUMN IF NOT EXISTS lease_token TEXT;
ALTER TABLE consent_operations ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
`;

interface QueryResultLike<Row = Record<string, unknown>> {
  rows: Row[];
  rowCount: number | null;
}

interface Queryable {
  query<Row = Record<string, unknown>>(text: string, values?: unknown[]): Promise<QueryResultLike<Row>>;
}

interface PoolClientLike extends Queryable {
  release(): void;
}

interface PoolLike extends Queryable {
  connect(): Promise<PoolClientLike>;
  end(): Promise<void>;
}

export interface PostgresConsentOperationRepositoryOptions {
  connectionString?: string;
  pool?: PoolLike;
}

export function createPostgresConsentOperationRepository(
  options: PostgresConsentOperationRepositoryOptions
): ConsentOperationRepository & { migrate(): Promise<void>; health(): Promise<boolean>; close(): Promise<void> } {
  const pool = options.pool ?? (new Pool({ connectionString: requireConnectionString(options.connectionString) }) as unknown as PoolLike);
  absorbIdlePostgresClientErrors(pool);

  return {
    async migrate() {
      await pool.query(CONSENT_OPERATION_SCHEMA_SQL);
    },

    async createPending(input) {
      const result = await pool.query<ConsentOperationRow>(
         `INSERT INTO consent_operations (
           operation_id, idempotency_key, request_digest, patient_hash, policy_id, policy_version, valid_from,
           state, share_id, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, 'pending_fhir', $8, $9::timestamptz, $9::timestamptz)
         RETURNING ${SELECT_FIELDS}`,
        [input.operationId, input.idempotencyKey, input.requestDigest, input.patientHash, input.policyId,
          input.policyVersion, input.validFrom, input.shareId, input.createdAt]
      ).catch((error) => {
        throw mapPostgresError(error);
      });
      if (!result.rows[0]) throw new Error("CONSENT_OPERATION_NOT_CREATED");
      return mapRow(result.rows[0]);
    },

    async claimOrCreatePending(input, claim) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const inserted = await client.query<ConsentOperationRow>(
          `INSERT INTO consent_operations (
             operation_id, idempotency_key, request_digest, patient_hash, policy_id, policy_version, valid_from,
             state, share_id, lease_owner, lease_token, lease_expires_at, created_at, updated_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, 'pending_fhir', $8, $9, $10, $11::timestamptz, $12::timestamptz, $12::timestamptz)
           ON CONFLICT (patient_hash, idempotency_key) DO NOTHING
           RETURNING ${SELECT_FIELDS}`,
          [input.operationId, input.idempotencyKey, input.requestDigest, input.patientHash,
            input.policyId, input.policyVersion, input.validFrom, input.shareId,
            claim.owner, claim.leaseToken, claim.leaseExpiresAt, input.createdAt]
        );
        if (inserted.rows[0]) {
          await client.query("COMMIT");
          return { operation: mapRow(inserted.rows[0]), claimed: true };
        }

        const existingResult = await client.query<ConsentOperationRow>(
          `SELECT ${SELECT_FIELDS}
           FROM consent_operations
           WHERE patient_hash = $1 AND idempotency_key = $2
           FOR UPDATE`,
          [input.patientHash, input.idempotencyKey]
        );
        const existing = existingResult.rows[0] ? mapRow(existingResult.rows[0]) : undefined;
        if (!existing) throw new Error("CONSENT_OPERATION_NOT_FOUND");
        if (!existing.requestDigest) throw new Error("IDEMPOTENCY_DIGEST_MISSING");
        if (existing.requestDigest !== input.requestDigest) throw new Error("IDEMPOTENCY_KEY_SCOPE_MISMATCH");
        const leaseExpired = !existing.leaseExpiresAt || Date.parse(existing.leaseExpiresAt) <= Date.parse(claim.now);
        const terminal = existing.state === "active" || existing.state === "revoked" || existing.state === "superseded";
        if (!terminal && leaseExpired) {
          const updated = await client.query<ConsentOperationRow>(
            `UPDATE consent_operations
             SET lease_owner = $2, lease_token = $3, lease_expires_at = $4::timestamptz, updated_at = $5::timestamptz
             WHERE operation_id = $1
             RETURNING ${SELECT_FIELDS}`,
            [existing.operationId, claim.owner, claim.leaseToken, claim.leaseExpiresAt, claim.now]
          );
          if (!updated.rows[0]) throw new Error("CONSENT_OPERATION_NOT_FOUND");
          await client.query("COMMIT");
          return { operation: mapRow(updated.rows[0]), claimed: true };
        }
        await client.query("COMMIT");
        return { operation: existing, claimed: false };
      } catch (error) {
        await rollback(client);
        throw mapPostgresError(error);
      } finally {
        client.release();
      }
    },

    async claimExisting(operationId: string, lease: ConsentOperationLease) {
      const result = await pool.query<ConsentOperationRow>(
        `UPDATE consent_operations
         SET lease_owner = $2, lease_token = $3, lease_expires_at = $4::timestamptz, updated_at = $5::timestamptz
         WHERE operation_id = $1
           AND state NOT IN ('revoked', 'superseded')
           AND (lease_expires_at IS NULL OR lease_expires_at <= $5::timestamptz)
         RETURNING ${SELECT_FIELDS}`,
        [operationId, lease.owner, lease.leaseToken, lease.leaseExpiresAt, lease.now]
      );
      if (result.rows[0]) return { operation: mapRow(result.rows[0]), claimed: true };
      const existing = await pool.query<{ operation_id: string }>(
        `SELECT operation_id FROM consent_operations WHERE operation_id = $1 LIMIT 1`,
        [operationId]
      );
      if (!existing.rows[0]) throw new Error("CONSENT_OPERATION_NOT_FOUND");
      throw new Error("CONSENT_OPERATION_IN_PROGRESS");
    },

    async renewLease(operationId, lease: ConsentOperationLease) {
      const result = await pool.query<ConsentOperationRow>(
        `UPDATE consent_operations
         SET lease_expires_at = $3::timestamptz, updated_at = $4::timestamptz
         WHERE operation_id = $1
           AND lease_owner = $2
           AND lease_token = $5
           AND lease_expires_at > $4::timestamptz
         RETURNING ${SELECT_FIELDS}`,
        [operationId, lease.owner, lease.leaseExpiresAt, lease.now, lease.leaseToken]
      );
      if (!result.rows[0]) throw new Error("CONSENT_OPERATION_LEASE_LOST");
      return mapRow(result.rows[0]);
    },

    async releaseClaim(operationId, lease) {
      await pool.query(
        `UPDATE consent_operations
         SET lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
         WHERE operation_id = $1 AND lease_owner = $2 AND lease_token = $3`,
        [operationId, lease.owner, lease.leaseToken]
      );
    },

    async findByIdempotencyKey(patientHash, idempotencyKey) {
      const result = await pool.query<ConsentOperationRow>(
        `SELECT ${SELECT_FIELDS}
         FROM consent_operations
         WHERE patient_hash = $1 AND idempotency_key = $2
         LIMIT 1`,
        [patientHash, idempotencyKey]
      );
      return result.rows[0] ? mapRow(result.rows[0]) : undefined;
    },

    async findById(operationId) {
      const result = await pool.query<ConsentOperationRow>(
        `SELECT ${SELECT_FIELDS}
         FROM consent_operations
         WHERE operation_id = $1
         LIMIT 1`,
        [operationId]
      );
      return result.rows[0] ? mapRow(result.rows[0]) : undefined;
    },

    async findByConsent(patientHash, consentReference) {
      const result = await pool.query<ConsentOperationRow>(
        `SELECT ${SELECT_FIELDS}
         FROM consent_operations
         WHERE patient_hash = $1 AND consent_reference = $2
         LIMIT 1`,
        [patientHash, consentReference]
      );
      return result.rows[0] ? mapRow(result.rows[0]) : undefined;
    },

    async update(operationId, patch, lease) {
      const assignments: string[] = [];
      const values: unknown[] = [];
      const columns: Array<[keyof ConsentOperationUpdate, string]> = [
        ["consentReference", "consent_reference"],
        ["consentVersion", "consent_version"],
        ["policyId", "policy_id"],
        ["policyVersion", "policy_version"],
        ["state", "state"],
        ["resumeState", "resume_state"],
        ["shareId", "share_id"],
        ["manifestId", "manifest_id"],
        ["handoffCodeHash", "handoff_code_hash"],
        ["fhirCreateAttempted", "fhir_create_attempted"],
        ["chainTransactionHash", "chain_transaction_hash"],
        ["revocationTransactionHash", "revocation_transaction_hash"],
        ["error", "error"]
      ];
      for (const [property, column] of columns) {
        if (patch[property] !== undefined) {
          assignments.push(`${column} = $${values.length + 1}`);
          values.push(patch[property]);
        }
      }
      assignments.push(`updated_at = $${values.length + 1}::timestamptz`);
      values.push(patch.updatedAt ?? new Date().toISOString());
      values.push(operationId);
      const operationIdParameter = values.length;
      if (lease) {
        values.push(lease.owner, lease.leaseToken, lease.now);
      }
      const result = await pool.query<ConsentOperationRow>(
        `UPDATE consent_operations
         SET ${assignments.join(", ")}
         WHERE operation_id = $${operationIdParameter}
         ${lease ? `AND lease_owner = $${operationIdParameter + 1}
           AND lease_token = $${operationIdParameter + 2}
           AND lease_expires_at > $${operationIdParameter + 3}::timestamptz` : ""}
         RETURNING ${SELECT_FIELDS}`,
        values
      );
      if (!result.rows[0]) {
        if (lease) throw new Error("CONSENT_OPERATION_LEASE_LOST");
        throw new Error("CONSENT_OPERATION_NOT_FOUND");
      }
      return mapRow(result.rows[0]);
    },

    async health() {
      const result = await pool.query<{ ok: number }>("SELECT 1 AS ok");
      return result.rows[0]?.ok === 1;
    },

    async close() {
      await pool.end();
    }
  };
}

interface ConsentOperationRow {
  operation_id: string;
  idempotency_key: string;
  request_digest: string | null;
  patient_hash: string;
  consent_reference: string | null;
  consent_version: string | null;
  policy_id: string;
  policy_version: number;
  valid_from: Date | string | null;
  state: ConsentOperationState;
  resume_state: ConsentOperationState | null;
  share_id: string | null;
  manifest_id: string | null;
  handoff_code_hash: string | null;
  fhir_create_attempted: boolean;
  chain_transaction_hash: string | null;
  revocation_transaction_hash: string | null;
  lease_owner: string | null;
  lease_token: string | null;
  lease_expires_at: Date | string | null;
  error: string | null;
  created_at: Date | string;
  updated_at: Date | string;
}

const SELECT_FIELDS = `
  operation_id, idempotency_key, request_digest, patient_hash, consent_reference, consent_version,
  policy_id, policy_version, valid_from, state, resume_state, share_id, manifest_id,
  handoff_code_hash, fhir_create_attempted, chain_transaction_hash, revocation_transaction_hash,
  lease_owner, lease_token, lease_expires_at, error, created_at, updated_at`;

function mapRow(row: ConsentOperationRow): ConsentOperation {
  if (!row.share_id) throw new Error("CONSENT_OPERATION_SHARE_MISSING");
  return {
    operationId: row.operation_id,
    idempotencyKey: row.idempotency_key,
    requestDigest: row.request_digest ?? "",
    patientHash: row.patient_hash,
    ...(row.consent_reference ? { consentReference: row.consent_reference } : {}),
    ...(row.consent_version ? { consentVersion: row.consent_version } : {}),
    policyId: row.policy_id,
    policyVersion: Number(row.policy_version),
    ...(row.valid_from ? { validFrom: toIsoString(row.valid_from) } : {}),
    state: row.state,
    ...(row.resume_state && isPendingState(row.resume_state) ? { resumeState: row.resume_state } : {}),
    shareId: row.share_id,
    ...(row.manifest_id ? { manifestId: row.manifest_id } : {}),
    ...(row.handoff_code_hash ? { handoffCodeHash: row.handoff_code_hash } : {}),
    ...(row.fhir_create_attempted ? { fhirCreateAttempted: true } : {}),
    ...(row.chain_transaction_hash ? { chainTransactionHash: row.chain_transaction_hash } : {}),
    ...(row.revocation_transaction_hash ? { revocationTransactionHash: row.revocation_transaction_hash } : {}),
    ...(row.lease_owner ? { leaseOwner: row.lease_owner } : {}),
    ...(row.lease_token ? { leaseToken: row.lease_token } : {}),
    ...(row.lease_expires_at ? { leaseExpiresAt: toIsoString(row.lease_expires_at) } : {}),
    ...(row.error ? { error: row.error } : {}),
    createdAt: toIsoString(row.created_at),
    updatedAt: toIsoString(row.updated_at)
  };
}

function requireConnectionString(value: string | undefined) {
  if (!value) throw new Error("INSTITUTION_METADATA_DATABASE_URL_REQUIRED");
  return value;
}

function mapPostgresError(error: unknown) {
  if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
    return new Error("CONSENT_OPERATION_ALREADY_EXISTS");
  }
  return error;
}

async function rollback(client: Queryable) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original transaction error.
  }
}

function toIsoString(value: Date | string) {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function isPendingState(value: ConsentOperationState): value is "pending_fhir" | "pending_chain" | "pending_manifest" {
  return value === "pending_fhir" || value === "pending_chain" || value === "pending_manifest";
}
