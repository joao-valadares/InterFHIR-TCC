import pg from "pg";
import { absorbIdlePostgresClientErrors } from "../persistence/postgres-pool.js";

import { computeManifestCommitment, type ResourceManifestVersion } from "./resource-manifest.js";
import { SHARE_SCHEMA_SQL } from "../share/postgres-share-repository.js";

const { Pool } = pg;

interface QueryResultLike<Row = Record<string, unknown>> {
  rows: Row[];
  rowCount: number | null;
}

interface Queryable {
  query<Row = Record<string, unknown>>(
    text: string,
    values?: unknown[]
  ): Promise<QueryResultLike<Row>>;
}

interface PoolClientLike extends Queryable {
  release(): void;
}

interface PoolLike extends Queryable {
  connect(): Promise<PoolClientLike>;
  end(): Promise<void>;
}

export interface PostgresManifestRepositoryOptions {
  connectionString?: string;
  pool?: PoolLike;
}

export const MANIFEST_VERSION_SCHEMA_SQL = `
${SHARE_SCHEMA_SQL}

CREATE TABLE IF NOT EXISTS manifest_headers (
  manifest_id TEXT PRIMARY KEY,
  share_id TEXT NOT NULL REFERENCES share_grants(share_id),
  current_version INTEGER NOT NULL CHECK (current_version > 0),
  lifecycle_status TEXT NOT NULL CHECK (lifecycle_status IN ('pending', 'active', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_versions (
  manifest_id TEXT NOT NULL REFERENCES manifest_headers(manifest_id),
  version INTEGER NOT NULL CHECK (version > 0),
  status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'superseded', 'revoked')),
  custodian_organization_reference TEXT NOT NULL,
  grantee_organization_reference TEXT NOT NULL,
  resource_reference TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  fhir_version_id TEXT NOT NULL,
  subject_reference TEXT NOT NULL,
  consent_reference_hash TEXT NOT NULL,
  consent_projection_hash TEXT NOT NULL,
  resource_hash TEXT NOT NULL,
  previous_version_commitment TEXT NOT NULL,
  commitment TEXT NOT NULL,
  signing_key_id TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ,
  PRIMARY KEY (manifest_id, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS manifest_versions_one_active
  ON manifest_versions (manifest_id)
  WHERE status = 'active';
`;

export interface ManifestVersionRepository {
  migrate(): Promise<void>;
  findById?(manifestId: string, version: number): Promise<ResourceManifestVersion | undefined>;
  savePending(manifest: ResourceManifestVersion): Promise<ResourceManifestVersion>;
  activatePending(manifest: ResourceManifestVersion): Promise<ResourceManifestVersion>;
  supersedeAndActivate(
    superseded: ResourceManifestVersion,
    active: ResourceManifestVersion
  ): Promise<ResourceManifestVersion>;
  requireActiveForShare(shareId: string, manifestId: string): Promise<ResourceManifestVersion>;
  listActiveForShare(shareId: string): Promise<ResourceManifestVersion[]>;
  revokeActive(manifest: ResourceManifestVersion): Promise<ResourceManifestVersion>;
  health(): Promise<boolean>;
  close(): Promise<void>;
}

/** Persists the FHIR-only signed model and its fail-closed lifecycle transitions. */
export function createPostgresManifestVersionRepository(
  options: PostgresManifestRepositoryOptions
): ManifestVersionRepository {
  const pool =
    options.pool ??
    (new Pool({
      connectionString: requireConnectionString(options.connectionString)
    }) as unknown as PoolLike);
  absorbIdlePostgresClientErrors(pool);
  return {
    async migrate() {
      await pool.query(MANIFEST_VERSION_SCHEMA_SQL);
    },
    async findById(manifestId, version) {
      const result = await pool.query<ManifestVersionRow>(
        `${SELECT_MANIFEST_VERSION}
         WHERE v.manifest_id = $1 AND v.version = $2
         LIMIT 1`,
        [manifestId, version]
      );
      return result.rows[0] ? mapManifestVersion(result.rows[0]) : undefined;
    },
    async savePending(manifest) {
      if (manifest.status !== "pending") {
        throw new Error("MANIFEST_NOT_PENDING");
      }
      assertManifestVersionIntegrity(manifest);
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          `INSERT INTO manifest_headers (
             manifest_id, share_id, current_version, lifecycle_status, created_at
           ) VALUES ($1, $2, $3, 'pending', $4::timestamptz)
           ON CONFLICT (manifest_id) DO NOTHING`,
          [manifest.manifestId, manifest.shareId, manifest.version, manifest.createdAt]
        );
        const header = await client.query<ManifestHeaderRow>(
          `SELECT share_id, current_version FROM manifest_headers WHERE manifest_id = $1 FOR UPDATE`,
          [manifest.manifestId]
        );
        if (!header.rows[0] || header.rows[0].share_id !== manifest.shareId) {
          throw new Error("MANIFEST_SHARE_MISMATCH");
        }
        await insertManifestVersion(client, manifest);
        await client.query(
          `UPDATE manifest_headers SET current_version = GREATEST(current_version, $2)
           WHERE manifest_id = $1`,
          [manifest.manifestId, manifest.version]
        );
        await client.query("COMMIT");
        return manifest;
      } catch (error) {
        await rollback(client);
        throw mapManifestVersionPostgresError(error);
      } finally {
        client.release();
      }
    },
    async activatePending(manifest) {
      return transitionManifestVersion(pool, manifest, "pending", "active", "active");
    },
    async supersedeAndActivate(superseded, active) {
      if (superseded.status !== "superseded" || active.status !== "active") {
        throw new Error("MANIFEST_TRANSITION_STATUS_INVALID");
      }
      assertManifestVersionIntegrity(superseded);
      assertManifestVersionIntegrity(active);
      if (
        active.manifestId !== superseded.manifestId ||
        active.version !== superseded.version + 1 ||
        active.shareId !== superseded.shareId ||
        active.previousVersionCommitment !== superseded.commitment
      ) {
        throw new Error("MANIFEST_VERSION_CHAIN_INVALID");
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const current = await client.query<ManifestVersionRow>(
          `${SELECT_MANIFEST_VERSION}
           WHERE v.manifest_id = $1 AND v.version = $2 FOR UPDATE`,
          [superseded.manifestId, superseded.version]
        );
        const pending = await client.query<ManifestVersionRow>(
          `${SELECT_MANIFEST_VERSION}
           WHERE v.manifest_id = $1 AND v.version = $2 FOR UPDATE`,
          [active.manifestId, active.version]
        );
        const storedCurrent = current.rows[0] ? mapManifestVersion(current.rows[0]) : undefined;
        const storedPending = pending.rows[0] ? mapManifestVersion(pending.rows[0]) : undefined;
        if (!storedCurrent || !storedPending) {
          throw new Error("MANIFEST_NOT_FOUND");
        }
        if (storedCurrent.status !== "active" || storedPending.status !== "pending") {
          throw new Error("MANIFEST_NOT_PENDING");
        }
        if (
          !sameImmutableManifestFields(storedCurrent, superseded) ||
          !sameImmutableManifestFields(storedPending, active)
        ) {
          throw new Error("MANIFEST_TRANSITION_IMMUTABLE_FIELDS_CHANGED");
        }
        await updateManifestVersionTransition(client, superseded);
        await updateManifestVersionTransition(client, active);
        await client.query(
          `UPDATE manifest_headers SET current_version = $2, lifecycle_status = 'active'
           WHERE manifest_id = $1`,
          [active.manifestId, active.version]
        );
        await client.query("COMMIT");
        return active;
      } catch (error) {
        await rollback(client);
        throw mapManifestVersionPostgresError(error);
      } finally {
        client.release();
      }
    },
    async requireActiveForShare(shareId, manifestId) {
      const result = await pool.query<ManifestVersionRow>(
        `${SELECT_MANIFEST_VERSION}
         WHERE v.manifest_id = $1 AND h.share_id = $2 AND v.status = 'active'`,
        [manifestId, shareId]
      );
      if (!result.rows[0]) {
        throw new Error("MANIFEST_NOT_ACTIVE_FOR_SHARE");
      }
      return mapManifestVersion(result.rows[0]);
    },
    async listActiveForShare(shareId) {
      const result = await pool.query<ManifestVersionRow>(
        `${SELECT_MANIFEST_VERSION}
         WHERE h.share_id = $1 AND v.status = 'active'
         ORDER BY v.manifest_id, v.version`,
        [shareId]
      );
      return result.rows.map(mapManifestVersion);
    },
    async revokeActive(manifest) {
      return transitionManifestVersion(pool, manifest, "active", "revoked", "revoked");
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

interface ManifestHeaderRow {
  share_id: string;
  current_version: number;
}

interface ManifestVersionRow {
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

const SELECT_MANIFEST_VERSION = `SELECT
  v.manifest_id, h.share_id, v.version, v.status,
  v.custodian_organization_reference, v.grantee_organization_reference,
  v.resource_reference, v.resource_type, v.fhir_version_id,
  v.subject_reference, v.consent_reference_hash, v.consent_projection_hash,
  v.resource_hash, v.previous_version_commitment, v.commitment,
  v.signing_key_id, v.signature, v.created_at, v.updated_at
  FROM manifest_versions v
  JOIN manifest_headers h ON h.manifest_id = v.manifest_id`;

async function insertManifestVersion(queryable: Queryable, manifest: ResourceManifestVersion) {
  await queryable.query(
    `INSERT INTO manifest_versions (
       manifest_id, version, status, custodian_organization_reference,
       grantee_organization_reference, resource_reference, resource_type,
       fhir_version_id, subject_reference, consent_reference_hash,
       consent_projection_hash, resource_hash, previous_version_commitment,
       commitment, signing_key_id, signature, created_at, updated_at
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
       $13, $14, $15, $16, $17::timestamptz, $18::timestamptz)`,
    [
      manifest.manifestId, manifest.version, manifest.status,
      manifest.custodianOrganizationReference, manifest.granteeOrganizationReference,
      manifest.resourceReference, manifest.resourceType, manifest.fhirVersionId,
      manifest.subjectReference, manifest.consentReferenceHash, manifest.consentProjectionHash,
      manifest.resourceHash, manifest.previousVersionCommitment, manifest.commitment,
      manifest.signingKeyId, manifest.signature, manifest.createdAt, manifest.updatedAt ?? null
    ]
  );
}

async function transitionManifestVersion(
  pool: PoolLike,
  manifest: ResourceManifestVersion,
  expectedStatus: ResourceManifestVersion["status"],
  nextStatus: ResourceManifestVersion["status"],
  lifecycleStatus: "active" | "revoked"
) {
  if (manifest.status !== nextStatus) {
    throw new Error("MANIFEST_TRANSITION_STATUS_INVALID");
  }
  assertManifestVersionIntegrity(manifest);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const storedResult = await client.query<ManifestVersionRow>(
      `${SELECT_MANIFEST_VERSION}
       WHERE v.manifest_id = $1 AND v.version = $2 FOR UPDATE`,
      [manifest.manifestId, manifest.version]
    );
    const stored = storedResult.rows[0] ? mapManifestVersion(storedResult.rows[0]) : undefined;
    if (!stored) {
      throw new Error("MANIFEST_NOT_FOUND");
    }
    if (stored.status !== expectedStatus || stored.shareId !== manifest.shareId) {
      throw new Error(expectedStatus === "pending" ? "MANIFEST_NOT_PENDING" : "MANIFEST_NOT_ACTIVE");
    }
    if (!sameImmutableManifestFields(stored, manifest)) {
      throw new Error("MANIFEST_TRANSITION_IMMUTABLE_FIELDS_CHANGED");
    }
    await updateManifestVersionTransition(client, manifest);
    await client.query(
      `UPDATE manifest_headers SET lifecycle_status = $2 WHERE manifest_id = $1`,
      [manifest.manifestId, lifecycleStatus]
    );
    await client.query("COMMIT");
    return manifest;
  } catch (error) {
    await rollback(client);
    throw mapManifestVersionPostgresError(error);
  } finally {
    client.release();
  }
}

async function updateManifestVersionTransition(client: Queryable, manifest: ResourceManifestVersion) {
  await client.query(
    `UPDATE manifest_versions
     SET status = $3, commitment = $4, signing_key_id = $5, signature = $6,
         updated_at = $7::timestamptz
     WHERE manifest_id = $1 AND version = $2`,
    [manifest.manifestId, manifest.version, manifest.status, manifest.commitment,
      manifest.signingKeyId, manifest.signature, manifest.updatedAt ?? manifest.createdAt]
  );
}

function assertManifestVersionIntegrity(manifest: ResourceManifestVersion) {
  const { commitment, signature: _signature, ...draft } = manifest;
  if (computeManifestCommitment(draft) !== commitment) {
    throw new Error("MANIFEST_STORED_COMMITMENT_MISMATCH");
  }
}

function sameImmutableManifestFields(stored: ResourceManifestVersion, next: ResourceManifestVersion) {
  const immutable = (manifest: ResourceManifestVersion) => ({
    manifestId: manifest.manifestId,
    shareId: manifest.shareId,
    version: manifest.version,
    custodianOrganizationReference: manifest.custodianOrganizationReference,
    granteeOrganizationReference: manifest.granteeOrganizationReference,
    resourceReference: manifest.resourceReference,
    resourceType: manifest.resourceType,
    fhirVersionId: manifest.fhirVersionId,
    subjectReference: manifest.subjectReference,
    consentReferenceHash: manifest.consentReferenceHash,
    consentProjectionHash: manifest.consentProjectionHash,
    resourceHash: manifest.resourceHash,
    previousVersionCommitment: manifest.previousVersionCommitment,
    createdAt: manifest.createdAt
  });
  return JSON.stringify(immutable(stored)) === JSON.stringify(immutable(next));
}

function mapManifestVersion(row: ManifestVersionRow): ResourceManifestVersion {
  const manifest: ResourceManifestVersion = {
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
    createdAt: toIsoString(row.created_at),
    ...(row.updated_at ? { updatedAt: toIsoString(row.updated_at) } : {})
  };
  assertManifestVersionIntegrity(manifest);
  return manifest;
}

function mapManifestVersionPostgresError(error: unknown) {
  if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
    return new Error("MANIFEST_VERSION_ALREADY_EXISTS");
  }
  return error;
}

function requireConnectionString(value: string | undefined) {
  if (!value) {
    throw new Error("MANIFEST_DATABASE_URL_REQUIRED");
  }
  return value;
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
