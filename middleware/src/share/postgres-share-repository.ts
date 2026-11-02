import pg from "pg";
import { absorbIdlePostgresClientErrors } from "../persistence/postgres-pool.js";

import type { ShareGrant } from "./share-grant.js";

const { Pool } = pg;

export const SHARE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS share_grants (
  share_id TEXT PRIMARY KEY,
  custodian_organization_reference TEXT NOT NULL,
  grantee_organization_reference TEXT NOT NULL,
  patient_reference TEXT NOT NULL,
  consent_reference TEXT NOT NULL,
  allowed_resource_types JSONB NOT NULL,
  allowed_operation TEXT NOT NULL CHECK (allowed_operation = 'read'),
  allowed_purpose TEXT NOT NULL,
  valid_from TIMESTAMPTZ NOT NULL,
  valid_until TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked', 'expired')),
  handoff_code_hash TEXT,
  handoff_expires_at TIMESTAMPTZ,
  handoff_redeemed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS share_grants_handoff_code_hash
  ON share_grants (handoff_code_hash)
  WHERE handoff_code_hash IS NOT NULL;
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

export interface ShareRepository {
  migrate(): Promise<void>;
  savePending(share: ShareGrant): Promise<ShareGrant>;
  activate(shareId: string, updatedAt: string): Promise<ShareGrant>;
  findById(shareId: string): Promise<ShareGrant | undefined>;
  requireActive(shareId: string): Promise<ShareGrant>;
  revoke(shareId: string, updatedAt: string): Promise<ShareGrant>;
  issueHandoffCode(shareId: string, codeHash: string, expiresAt: string): Promise<void>;
  redeemHandoffCode(codeHash: string, granteeOrganizationReference: string, now: string): Promise<ShareGrant>;
  health(): Promise<boolean>;
  close(): Promise<void>;
}

export interface PostgresShareRepositoryOptions {
  connectionString?: string;
  pool?: PoolLike;
}

export function createPostgresShareRepository(options: PostgresShareRepositoryOptions): ShareRepository {
  const pool = options.pool ?? (new Pool({ connectionString: requireConnectionString(options.connectionString) }) as unknown as PoolLike);
  absorbIdlePostgresClientErrors(pool);
  return {
    async migrate() {
      await pool.query(SHARE_SCHEMA_SQL);
    },
    async savePending(share) {
      if (share.status !== "pending") {
        throw new Error("SHARE_NOT_PENDING");
      }
      try {
        await pool.query(
          `INSERT INTO share_grants (
             share_id, custodian_organization_reference, grantee_organization_reference,
             patient_reference, consent_reference, allowed_resource_types, allowed_operation,
             allowed_purpose, valid_from, valid_until, status, created_at, updated_at
           ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9::timestamptz,
             $10::timestamptz, $11, $12::timestamptz, $13::timestamptz)`,
          [
            share.shareId, share.custodianOrganizationReference, share.granteeOrganizationReference,
            share.patientReference, share.consentReference, JSON.stringify(share.allowedResourceTypes),
            share.allowedOperation, share.allowedPurpose, share.validFrom, share.validUntil,
            share.status, share.createdAt, share.updatedAt ?? null
          ]
        );
      } catch (error) {
        throw mapPostgresError(error);
      }
      return share;
    },
    async activate(shareId, updatedAt) {
      return updateStatus(pool, shareId, "pending", "active", updatedAt);
    },
    async findById(shareId) {
      const result = await pool.query<ShareRow>(`${SELECT_SHARE} WHERE share_id = $1`, [shareId]);
      return result.rows[0] ? mapShare(result.rows[0]) : undefined;
    },
    async requireActive(shareId) {
      const result = await pool.query<ShareRow>(`${SELECT_SHARE} WHERE share_id = $1`, [shareId]);
      const share = result.rows[0] ? mapShare(result.rows[0]) : undefined;
      if (!share) {
        throw new Error("SHARE_NOT_FOUND");
      }
      if (share.status !== "active") {
        throw new Error("SHARE_NOT_ACTIVE");
      }
      return share;
    },
    async revoke(shareId, updatedAt) {
      return updateStatus(pool, shareId, "active", "revoked", updatedAt);
    },
    async issueHandoffCode(shareId, codeHash, expiresAt) {
      const result = await pool.query(
        `UPDATE share_grants
         SET handoff_code_hash = $2,
             handoff_expires_at = $3::timestamptz,
             handoff_redeemed_at = CASE
               WHEN handoff_code_hash = $2 THEN handoff_redeemed_at
               ELSE NULL
             END
         WHERE share_id = $1 AND status = 'active'
           AND (handoff_code_hash IS NULL OR handoff_code_hash = $2)`,
        [shareId, codeHash, expiresAt]
      );
      if (result.rowCount !== 1) {
        const existing = await pool.query<{ handoff_code_hash: string | null }>(
          `SELECT handoff_code_hash FROM share_grants WHERE share_id = $1`,
          [shareId]
        );
        if (existing.rows[0]?.handoff_code_hash) throw new Error("HANDOFF_CODE_ALREADY_ISSUED");
        throw new Error("SHARE_NOT_ACTIVE");
      }
    },
    async redeemHandoffCode(codeHash, granteeOrganizationReference, now) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await client.query<ShareRow>(
          `${SELECT_SHARE} WHERE handoff_code_hash = $1 FOR UPDATE`,
          [codeHash]
        );
        const share = result.rows[0] ? mapShare(result.rows[0]) : undefined;
        if (!share) {
          throw new Error("HANDOFF_CODE_NOT_FOUND");
        }
        if (share.status !== "active") {
          throw new Error("SHARE_NOT_ACTIVE");
        }
        if (share.granteeOrganizationReference !== granteeOrganizationReference) {
          throw new Error("HANDOFF_GRANTEE_MISMATCH");
        }
        if (share.handoffRedeemedAt) {
          throw new Error("HANDOFF_CODE_ALREADY_REDEEMED");
        }
        if (!share.handoffExpiresAt || Date.parse(now) > Date.parse(share.handoffExpiresAt)) {
          throw new Error("HANDOFF_CODE_EXPIRED");
        }
        await client.query(
          `UPDATE share_grants SET handoff_redeemed_at = $2::timestamptz WHERE share_id = $1`,
          [share.shareId, now]
        );
        await client.query("COMMIT");
        return { ...share, handoffRedeemedAt: now };
      } catch (error) {
        await rollback(client);
        throw error;
      } finally {
        client.release();
      }
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

interface ShareRow {
  share_id: string;
  custodian_organization_reference: string;
  grantee_organization_reference: string;
  patient_reference: string;
  consent_reference: string;
  allowed_resource_types: string[];
  allowed_operation: "read";
  allowed_purpose: string;
  valid_from: Date | string;
  valid_until: Date | string;
  status: ShareGrant["status"];
  handoff_code_hash: string | null;
  handoff_expires_at: Date | string | null;
  handoff_redeemed_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string | null;
}

type StoredShareGrant = ShareGrant & {
  handoffCodeHash?: string;
  handoffExpiresAt?: string;
  handoffRedeemedAt?: string;
};

const SELECT_SHARE = `SELECT
  share_id, custodian_organization_reference, grantee_organization_reference,
  patient_reference, consent_reference, allowed_resource_types, allowed_operation,
  allowed_purpose, valid_from, valid_until, status, handoff_code_hash,
  handoff_expires_at, handoff_redeemed_at, created_at, updated_at
  FROM share_grants`;

async function updateStatus(
  pool: PoolLike,
  shareId: string,
  expectedStatus: ShareGrant["status"],
  nextStatus: ShareGrant["status"],
  updatedAt: string
) {
  const result = await pool.query<ShareRow>(
    `UPDATE share_grants
     SET status = $3, updated_at = $4::timestamptz
     WHERE share_id = $1 AND status = $2
     RETURNING share_id, custodian_organization_reference, grantee_organization_reference,
       patient_reference, consent_reference, allowed_resource_types, allowed_operation,
       allowed_purpose, valid_from, valid_until, status, handoff_code_hash,
       handoff_expires_at, handoff_redeemed_at, created_at, updated_at`,
    [shareId, expectedStatus, nextStatus, updatedAt]
  );
  if (!result.rows[0]) {
    throw new Error(expectedStatus === "pending" ? "SHARE_NOT_PENDING" : "SHARE_NOT_ACTIVE");
  }
  return mapShare(result.rows[0]);
}

function mapShare(row: ShareRow): StoredShareGrant {
  return {
    shareId: row.share_id,
    custodianOrganizationReference: row.custodian_organization_reference,
    granteeOrganizationReference: row.grantee_organization_reference,
    patientReference: row.patient_reference,
    consentReference: row.consent_reference,
    allowedResourceTypes: row.allowed_resource_types,
    allowedOperation: row.allowed_operation,
    allowedPurpose: row.allowed_purpose,
    validFrom: toIsoString(row.valid_from),
    validUntil: toIsoString(row.valid_until),
    status: row.status,
    createdAt: toIsoString(row.created_at),
    ...(row.updated_at ? { updatedAt: toIsoString(row.updated_at) } : {}),
    ...(row.handoff_code_hash ? { handoffCodeHash: row.handoff_code_hash } : {}),
    ...(row.handoff_expires_at ? { handoffExpiresAt: toIsoString(row.handoff_expires_at) } : {}),
    ...(row.handoff_redeemed_at ? { handoffRedeemedAt: toIsoString(row.handoff_redeemed_at) } : {})
  };
}

function requireConnectionString(value: string | undefined) {
  if (!value) {
    throw new Error("INSTITUTION_METADATA_DATABASE_URL_REQUIRED");
  }
  return value;
}

function mapPostgresError(error: unknown) {
  if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
    return new Error("SHARE_ALREADY_EXISTS");
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
