import {
  createRemoteJWKSet,
  customFetch,
  decodeJwt,
  jwtVerify
} from "jose";

import type { AuthenticatedPrincipal } from "./principal.js";

export interface OidcIssuerConfig {
  issuer: string;
  jwksUri: string;
  audience: string;
  organizationReference: string;
}

/** These attributes are resolved by the trusted registry/chain, not OIDC. */
const TRUSTED_ATTRIBUTE_SOURCE = "trusted-registry";

export function createOidcVerifier(options: {
  issuers: OidcIssuerConfig[];
  fetch?: typeof globalThis.fetch;
  now?: () => number;
}) {
  if (new Set(options.issuers.map((issuer) => issuer.issuer)).size !== options.issuers.length) {
    throw new Error("OIDC_ISSUER_DUPLICATE");
  }
  const issuers = new Map(options.issuers.map((issuer) => [issuer.issuer, issuer]));
  const keySets = new Map(
    options.issuers.map((issuer) => [
      issuer.issuer,
      createRemoteJWKSet(new URL(issuer.jwksUri), options.fetch ? { [customFetch]: options.fetch } : undefined)
    ])
  );

  return {
    async verify(token: string): Promise<AuthenticatedPrincipal> {
      const unverified = decodeJwt(token);
      const issuer = typeof unverified.iss === "string" ? issuers.get(unverified.iss) : undefined;
      if (!issuer) {
        throw new Error("OIDC_ISSUER_NOT_CONFIGURED");
      }
      const keySet = keySets.get(issuer.issuer);
      if (!keySet) {
        throw new Error("OIDC_ISSUER_NOT_CONFIGURED");
      }
      const { payload, protectedHeader } = await jwtVerify(token, keySet, {
        algorithms: ["RS256", "ES256"],
        issuer: issuer.issuer,
        audience: issuer.audience,
        currentDate: new Date((options.now ?? (() => Math.floor(Date.now() / 1000)))() * 1000)
      });
      if (protectedHeader.typ !== undefined && protectedHeader.typ !== "JWT") {
        throw new Error("OIDC_TOKEN_TYPE_INVALID");
      }
      const common = {
        sub: requireString(payload.sub),
        issuer: issuer.issuer,
        audience: readExactAudience(payload.aud, issuer.audience),
        exp: requireNumber(payload.exp),
        jti: requireString(payload.jti)
      };
      const role = requireString(payload.role);
      if (role === "patient") {
        assertOptionalOrganization(payload.organizationReference, issuer.organizationReference);
        return { kind: "patient", ...common, patientReference: requireString(payload.patientReference) };
      }
      if (role === "practitioner") {
        assertOrganization(payload.organizationReference, issuer.organizationReference);
        return {
          kind: "practitioner",
          ...common,
          practitionerReference: requireString(payload.practitionerReference),
          organizationReference: issuer.organizationReference,
          roleCode: TRUSTED_ATTRIBUTE_SOURCE,
          specialtyCode: TRUSTED_ATTRIBUTE_SOURCE
        };
      }
      if (role === "administrator") {
        assertOrganization(payload.organizationReference, issuer.organizationReference);
        return { kind: "administrator", ...common, organizationReference: issuer.organizationReference };
      }
      throw new Error("OIDC_ROLE_INVALID");
    }
  };
}

function requireString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("OIDC_CLAIMS_INVALID");
  return value;
}

function requireNumber(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error("OIDC_CLAIMS_INVALID");
  return value;
}

function readAudience(value: unknown): string[] {
  if (typeof value === "string" && value.length > 0) return [value];
  if (Array.isArray(value) && value.every((item) => typeof item === "string" && item.length > 0)) return value;
  throw new Error("OIDC_CLAIMS_INVALID");
}

function readExactAudience(value: unknown, expected: string): string[] {
  const audience = readAudience(value);
  if (audience.length !== 1 || audience[0] !== expected) {
    throw new Error("OIDC_AUDIENCE_INVALID");
  }
  return audience;
}

function assertOptionalOrganization(value: unknown, expected: string) {
  if (value !== undefined && value !== expected) throw new Error("OIDC_ORGANIZATION_MISMATCH");
}

function assertOrganization(value: unknown, expected: string) {
  if (value === undefined) throw new Error("OIDC_ORGANIZATION_REQUIRED");
  assertOptionalOrganization(value, expected);
}
