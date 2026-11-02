import { createHash } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import type { AuthenticatedPrincipal } from "../auth/principal.js";
import { assertUdapPublicJwk, type JsonWebKeyRecord } from "../identity/key-material.js";

const MAXIMUM_CLOCK_SKEW_SECONDS = 5;

export interface UdapRegisteredClient {
  clientId: string;
  organizationReference: string;
  certificateThumbprint: string;
  jwks: Record<string, unknown>[];
  allowedScopes: string[];
}

export function createUdapTokenService(options: {
  issuer: string;
  audience: string;
  tokenEndpoint: string;
  signingKey: CryptoKey | Uint8Array;
  signingKeyId?: string;
  signingAlgorithm?: "RS256" | "ES256";
  now?: () => number;
  clients: {
    requireActive(clientId: string): Promise<UdapRegisteredClient>;
    claimReplayJti(issuer: string, jti: string, expiresAt: Date): Promise<void>;
  };
}) {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  return {
    async issue(request: { grant_type: string; scope: string; client_assertion_type: string; client_assertion: string; udap: string }, certificate: { fingerprint256: string; x5tS256: string }) {
      if (request.grant_type !== "client_credentials" || request.udap !== "1" || request.client_assertion_type !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") throw new Error("UDAP_TOKEN_REQUEST_INVALID");
      const untrusted = decodeUntrustedPayload(request.client_assertion);
      const clientId = requireString(untrusted.iss, "UDAP_ASSERTION_INVALID");
      if (untrusted.sub !== clientId) throw new Error("UDAP_ASSERTION_SUBJECT_MISMATCH");
      const client = await options.clients.requireActive(clientId);
      if (certificate.x5tS256 !== client.certificateThumbprint) throw new Error("UDAP_CERTIFICATE_BINDING_MISMATCH");
      if (!client.allowedScopes.includes(request.scope)) throw new Error("UDAP_SCOPE_NOT_ALLOWED");
      const { payload } = await jwtVerify(request.client_assertion, createLocalJWKSet({ keys: client.jwks }), { algorithms: ["RS256", "ES256"], issuer: clientId, audience: options.tokenEndpoint, currentDate: new Date(now() * 1000) });
      const issuedAt = requireNumber(payload.iat, "UDAP_ASSERTION_INVALID");
      const expiresAt = requireNumber(payload.exp, "UDAP_ASSERTION_INVALID");
      if (issuedAt > now() + MAXIMUM_CLOCK_SKEW_SECONDS) throw new Error("UDAP_ASSERTION_IAT_INVALID");
      if (expiresAt - issuedAt > 300 || expiresAt <= now() || expiresAt <= issuedAt) throw new Error("UDAP_ASSERTION_LIFETIME_INVALID");
      const jti = requireString(payload.jti, "UDAP_ASSERTION_INVALID");
      const extension = readExtension(payload.extensions);
      if (extension.organization_id !== client.organizationReference) throw new Error("UDAP_ORGANIZATION_MISMATCH");
      if (!extension.purpose_of_use.includes("TREAT")) throw new Error("UDAP_PURPOSE_NOT_ALLOWED");
      await options.clients.claimReplayJti(clientId, jti, new Date(expiresAt * 1000));
      const assertionHash = `sha256:${createHash("sha256").update(request.client_assertion).digest("base64url")}`;
      const claims = { iss: options.issuer, aud: options.audience, client_id: clientId, organizationReference: client.organizationReference, practitionerReference: extension.subject_id, roleCode: extension.subject_role, purposeOfUse: extension.purpose_of_use, assertionHash, cnf: { "x5t#S256": certificate.x5tS256 } };
      const access_token = await new SignJWT(claims).setProtectedHeader({ alg: options.signingAlgorithm ?? "RS256", ...(options.signingKeyId ? { kid: options.signingKeyId } : {}) }).setIssuer(options.issuer).setAudience(options.audience).setJti(assertionHash).setIssuedAt(now()).setExpirationTime(now() + 300).sign(options.signingKey);
      return { access_token, token_type: "Bearer", expires_in: 300, assertionHash, claims };
    }
  };
}

/** Verifies the custodian-issued token before exposing a service principal. */
export function createUdapAccessTokenVerifier(options: {
  issuer: string;
  audience: string;
  verificationKey: CryptoKey | Uint8Array;
  algorithm: "RS256" | "ES256";
  signingKeyId: string;
  now?: () => number;
}) {
  return {
    async verifyToken(token: string): Promise<Extract<AuthenticatedPrincipal, { kind: "service" }>> {
      if (decodeProtectedHeader(token).kid !== options.signingKeyId) throw new Error("UDAP_TOKEN_KEY_ID_MISMATCH");
      const { payload } = await jwtVerify(token, options.verificationKey, { algorithms: [options.algorithm], issuer: options.issuer, audience: options.audience, currentDate: new Date((options.now ?? (() => Math.floor(Date.now() / 1000)))() * 1000) });
      const cnf = payload.cnf;
      if (!cnf || typeof cnf !== "object") throw new Error("UDAP_TOKEN_INVALID");
      const thumbprint = (cnf as Record<string, unknown>)["x5t#S256"];
      if (typeof thumbprint !== "string" || thumbprint.length === 0) throw new Error("UDAP_TOKEN_INVALID");
      const purposeOfUse = payload.purposeOfUse;
      if (!Array.isArray(purposeOfUse) || !purposeOfUse.every((value) => typeof value === "string")) throw new Error("UDAP_TOKEN_INVALID");
      return { kind: "service", clientId: requireString(payload.client_id, "UDAP_TOKEN_INVALID"), organizationReference: requireString(payload.organizationReference, "UDAP_TOKEN_INVALID"), practitionerReference: requireString(payload.practitionerReference, "UDAP_TOKEN_INVALID"), purposeOfUse, certificateThumbprint: thumbprint, assertionHash: requireString(payload.assertionHash, "UDAP_TOKEN_INVALID"), exp: requireNumber(payload.exp, "UDAP_TOKEN_INVALID"), jti: requireString(payload.jti, "UDAP_TOKEN_INVALID") };
    }
  };
}

export async function createUdapAccessTokenVerifierFromIssuerJwks(options: {
  issuer: string;
  audience: string;
  issuerJwks: { keys: Record<string, unknown>[] };
  signingKeyId: string;
  signingAlgorithm: "RS256" | "ES256";
  now?: () => number;
}) {
  for (const candidate of options.issuerJwks.keys) {
    assertUdapPublicJwk(candidate as JsonWebKeyRecord, "UDAP_ISSUER_VERIFICATION_KEY_INVALID");
  }
  const matchingKeys = options.issuerJwks.keys.filter((candidate) => candidate.kid === options.signingKeyId);
  if (matchingKeys.length === 0) throw new Error("UDAP_ISSUER_VERIFICATION_KEY_NOT_FOUND");
  if (matchingKeys.length > 1) throw new Error("UDAP_ISSUER_VERIFICATION_KEY_DUPLICATE");
  const jwk = matchingKeys[0];
  assertUdapPublicJwk(jwk as JsonWebKeyRecord, "UDAP_ISSUER_VERIFICATION_KEY_INVALID");
  if (jwk.alg !== options.signingAlgorithm) throw new Error("UDAP_ISSUER_VERIFICATION_KEY_ALGORITHM_MISMATCH");
  const verificationKey = await importJWK(jwk as JWK, options.signingAlgorithm);
  return createUdapAccessTokenVerifier({
    issuer: options.issuer,
    audience: options.audience,
    verificationKey,
    algorithm: options.signingAlgorithm,
    signingKeyId: options.signingKeyId,
    ...(options.now ? { now: options.now } : {})
  });
}

function decodeUntrustedPayload(token: string): Record<string, unknown> { const part = token.split(".")[1]; if (!part) throw new Error("UDAP_ASSERTION_INVALID"); try { return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>; } catch { throw new Error("UDAP_ASSERTION_INVALID"); } }
function requireString(value: unknown, error: string): string { if (typeof value !== "string" || value.length === 0) throw new Error(error); return value; }
function requireNumber(value: unknown, error: string): number { if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(error); return value; }
function readExtension(value: unknown) { if (!value || typeof value !== "object") throw new Error("UDAP_EXTENSION_REQUIRED"); const extension = (value as Record<string, unknown>)["hl7-b2b"]; if (!extension || typeof extension !== "object") throw new Error("UDAP_EXTENSION_REQUIRED"); const fields = extension as Record<string, unknown>; return { organization_id: requireString(fields.organization_id, "UDAP_EXTENSION_INVALID"), subject_id: requireString(fields.subject_id, "UDAP_EXTENSION_INVALID"), subject_role: requireString(fields.subject_role, "UDAP_EXTENSION_INVALID"), purpose_of_use: Array.isArray(fields.purpose_of_use) && fields.purpose_of_use.every((value) => typeof value === "string") ? fields.purpose_of_use : (() => { throw new Error("UDAP_EXTENSION_INVALID"); })() }; }
