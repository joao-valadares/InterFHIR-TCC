import pg from "pg";
import { absorbIdlePostgresClientErrors } from "../persistence/postgres-pool.js";

import type { UdapRegisteredClient } from "./udap-token-service.js";

const { Pool } = pg;

export const UDAP_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS udap_clients (
  client_id TEXT PRIMARY KEY,
  organization_reference TEXT NOT NULL,
  certificate_fingerprint TEXT NOT NULL,
  jwks JSONB NOT NULL,
  allowed_scopes JSONB NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS udap_replay_jtis (
  issuer TEXT NOT NULL,
  jti TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (issuer, jti)
);`;

export interface UdapClientRepository {
  migrate(): Promise<void>;
  save(client: UdapRegisteredClient): Promise<void>;
  requireActive(clientId: string): Promise<UdapRegisteredClient>;
  claimReplayJti(issuer: string, jti: string, expiresAt: Date): Promise<void>;
  pruneExpired(now: Date): Promise<void>;
  health(): Promise<boolean>;
  close(): Promise<void>;
}

export function createInMemoryUdapClientRepository(): UdapClientRepository {
  const clients = new Map<string, UdapRegisteredClient>();
  const replay = new Set<string>();
  return { async migrate() {}, async save(client) { clients.set(client.clientId, structuredClone(client)); }, async requireActive(clientId) { const client = clients.get(clientId); if (!client) throw new Error("UDAP_CLIENT_NOT_FOUND"); return structuredClone(client); }, async claimReplayJti(issuer, jti) { const key = `${issuer}:${jti}`; if (replay.has(key)) throw new Error("UDAP_ASSERTION_REPLAY"); replay.add(key); }, async pruneExpired() {}, async health() { return true; }, async close() {} };
}

export function createPostgresUdapClientRepository(options: { connectionString: string }): UdapClientRepository {
  const pool = new Pool({ connectionString: options.connectionString });
  absorbIdlePostgresClientErrors(pool);
  return {
    async migrate() { await pool.query(UDAP_SCHEMA_SQL); },
    async save(client) { await pool.query(`INSERT INTO udap_clients (client_id, organization_reference, certificate_fingerprint, jwks, allowed_scopes, active) VALUES ($1,$2,$3,$4::jsonb,$5::jsonb,TRUE) ON CONFLICT (client_id) DO UPDATE SET organization_reference=EXCLUDED.organization_reference, certificate_fingerprint=EXCLUDED.certificate_fingerprint, jwks=EXCLUDED.jwks, allowed_scopes=EXCLUDED.allowed_scopes, active=TRUE`, [client.clientId, client.organizationReference, client.certificateThumbprint, JSON.stringify(client.jwks), JSON.stringify(client.allowedScopes)]); },
    async requireActive(clientId) { const result = await pool.query<{ client_id: string; organization_reference: string; certificate_fingerprint: string; jwks: Record<string, unknown>[]; allowed_scopes: string[] }>(`SELECT client_id, organization_reference, certificate_fingerprint, jwks, allowed_scopes FROM udap_clients WHERE client_id=$1 AND active=TRUE`, [clientId]); const row = result.rows[0]; if (!row) throw new Error("UDAP_CLIENT_NOT_FOUND"); return { clientId: row.client_id, organizationReference: row.organization_reference, certificateThumbprint: row.certificate_fingerprint, jwks: row.jwks, allowedScopes: row.allowed_scopes }; },
    async claimReplayJti(issuer, jti, expiresAt) { try { await pool.query(`INSERT INTO udap_replay_jtis (issuer,jti,expires_at) VALUES ($1,$2,$3)`, [issuer, jti, expiresAt]); } catch (error) { if (isUniqueViolation(error)) throw new Error("UDAP_ASSERTION_REPLAY"); throw error; } },
    async pruneExpired(now) { await pool.query(`DELETE FROM udap_replay_jtis WHERE expires_at < $1`, [now]); },
    async health() { return (await pool.query<{ ok: number }>("SELECT 1 AS ok")).rows[0]?.ok === 1; },
    async close() { await pool.end(); }
  };
}

function isUniqueViolation(error: unknown) { return typeof error === "object" && error !== null && "code" in error && error.code === "23505"; }
