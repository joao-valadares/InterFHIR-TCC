import type { UdapRegisteredClient } from "./udap-token-service.js";
import { createLocalJWKSet, jwtVerify } from "jose";
import { assertUdapPublicJwk } from "../identity/key-material.js";

const MAXIMUM_CLOCK_SKEW_SECONDS = 5;

export interface ValidatedSoftwareStatement extends UdapRegisteredClient {
  statementIssuer: string;
  statementJti: string;
  statementExpiresAt: Date;
}

export function createSignedSoftwareStatementValidator(options: {
  registrationEndpoint: string;
  trustedJwks: Record<string, unknown>[];
  now?: () => number;
}) {
  return async (statement: string): Promise<ValidatedSoftwareStatement> => {
    for (const key of options.trustedJwks) assertUdapPublicJwk(key);
    const { payload } = await jwtVerify(statement, createLocalJWKSet({ keys: options.trustedJwks }), {
      algorithms: ["RS256", "ES256"],
      audience: options.registrationEndpoint,
      currentDate: new Date((options.now ?? (() => Math.floor(Date.now() / 1000)))() * 1000)
    });
    const clientId = requireString(payload.client_id);
    const statementIssuer = requireString(payload.iss);
    const statementSubject = requireString(payload.sub);
    if (statementIssuer !== clientId || statementSubject !== clientId) {
      throw new Error("UDAP_SOFTWARE_STATEMENT_IDENTITY_MISMATCH");
    }
    const statementJti = requireString(payload.jti);
    const statementIssuedAt = requireNumber(payload.iat);
    const statementExpiration = requireNumber(payload.exp);
    const currentTime = (options.now ?? (() => Math.floor(Date.now() / 1000)))();
    if (statementIssuedAt > currentTime + MAXIMUM_CLOCK_SKEW_SECONDS) throw new Error("UDAP_SOFTWARE_STATEMENT_IAT_INVALID");
    if (statementExpiration - statementIssuedAt > 300 || statementExpiration <= statementIssuedAt) throw new Error("UDAP_SOFTWARE_STATEMENT_LIFETIME_INVALID");
    return {
      clientId,
      organizationReference: requireString(payload.organization_reference),
      certificateThumbprint: requireString(payload.certificate_thumbprint),
      jwks: requirePublicJwkArray(payload.jwks),
      allowedScopes: requireStringArray(payload.allowed_scopes),
      statementIssuer,
      statementJti,
      statementExpiresAt: new Date(statementExpiration * 1000)
    };
  };
}

export function createUdapRegistrationService(options: {
  registrationEndpoint: string;
  validateStatement(statement: string): Promise<ValidatedSoftwareStatement>;
  clients: {
    save(client: UdapRegisteredClient): Promise<void>;
    claimReplayJti(issuer: string, jti: string, expiresAt: Date): Promise<void>;
  };
}) {
  return {
    async register(request: { software_statement: string }, certificate: { subjectOrganization: string; x5tS256: string }) {
      if (!request.software_statement) throw new Error("UDAP_SOFTWARE_STATEMENT_REQUIRED");
      const client = await options.validateStatement(request.software_statement);
      if (client.organizationReference !== certificate.subjectOrganization) throw new Error("UDAP_REGISTRATION_ORGANIZATION_MISMATCH");
      if (client.certificateThumbprint !== certificate.x5tS256) throw new Error("UDAP_REGISTRATION_CERTIFICATE_MISMATCH");
      await options.clients.claimReplayJti(client.statementIssuer, client.statementJti, client.statementExpiresAt);
      await options.clients.save(client);
      return { client_id: client.clientId, organizationReference: client.organizationReference };
    }
  };
}

function requireString(value: unknown): string { if (typeof value !== "string" || value.length === 0) throw new Error("UDAP_SOFTWARE_STATEMENT_INVALID"); return value; }
function requireNumber(value: unknown): number { if (typeof value !== "number" || !Number.isFinite(value)) throw new Error("UDAP_SOFTWARE_STATEMENT_INVALID"); return value; }
function requireStringArray(value: unknown): string[] { if (!Array.isArray(value) || !value.every((entry) => typeof entry === "string" && entry.length > 0)) throw new Error("UDAP_SOFTWARE_STATEMENT_INVALID"); return value; }
function requireRecordArray(value: unknown): Record<string, unknown>[] { if (!Array.isArray(value) || !value.every((entry) => typeof entry === "object" && entry !== null && !Array.isArray(entry))) throw new Error("UDAP_SOFTWARE_STATEMENT_INVALID"); return value as Record<string, unknown>[]; }

function requirePublicJwkArray(value: unknown): Record<string, unknown>[] {
  const keys = requireRecordArray(value);
  for (const key of keys) assertUdapPublicJwk(key, "UDAP_SOFTWARE_STATEMENT_INVALID");
  return keys;
}
