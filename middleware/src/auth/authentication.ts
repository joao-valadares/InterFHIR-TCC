import { jwtVerify, SignJWT } from "jose";

import type { ApiRequest, ApiResponse } from "../api/api-handler.js";
import type { AuthenticatedPrincipal as Principal } from "./principal.js";

export type { AuthenticatedPrincipal } from "./principal.js";

export const AUTHENTICATED_ROLES = ["practitioner", "administrator"] as const;

export type AuthenticatedRole = (typeof AUTHENTICATED_ROLES)[number];

export interface LocalJwtServiceOptions {
  secret: string;
  issuer: string;
  audience: string;
  now?: () => number;
}

export interface LocalTokenClaims {
  sub: string;
  practitionerReference: string;
  role: AuthenticatedRole;
  organizationReference: string;
  jti: string;
  expiresInSeconds: number;
}

interface Api {
  handle(request: ApiRequest): Promise<ApiResponse>;
}

interface TokenVerifier {
  verifyToken(token: string): Promise<Principal>;
}

const DOCUMENTED_JWT_SECRET_PLACEHOLDERS = new Set([
  "replace-with-a-local-secret-of-at-least-32-characters",
  "change-this-local-development-secret-32-chars"
]);

export function createLocalJwtService(options: LocalJwtServiceOptions) {
  const secret = options.secret.trim();
  if (secret.length < 32) {
    throw new Error("JWT_SECRET_TOO_SHORT");
  }
  if (DOCUMENTED_JWT_SECRET_PLACEHOLDERS.has(secret.toLowerCase())) {
    throw new Error("JWT_SECRET_PLACEHOLDER");
  }

  const key = new TextEncoder().encode(secret);
  const currentTime = options.now ?? (() => Math.floor(Date.now() / 1000));

  return {
    async issueToken(claims: LocalTokenClaims) {
      const issuedAt = currentTime();
      return new SignJWT({
        practitionerReference: claims.practitionerReference,
        role: claims.role,
        organizationReference: claims.organizationReference
      })
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setSubject(claims.sub)
        .setIssuer(options.issuer)
        .setAudience(options.audience)
        .setJti(claims.jti)
        .setIssuedAt(issuedAt)
        .setExpirationTime(issuedAt + claims.expiresInSeconds)
        .sign(key);
    },

    async verifyToken(token: string): Promise<Principal> {
      const { payload } = await jwtVerify(token, key, {
        algorithms: ["HS256"],
        issuer: options.issuer,
        audience: options.audience,
        currentDate: new Date(currentTime() * 1000)
      });

      const common = {
        sub: requireNonEmptyString(payload.sub),
        organizationReference: requireNonEmptyString(payload.organizationReference),
        issuer: options.issuer,
        audience: [options.audience],
        exp: requireNumber(payload.exp),
        jti: requireNonEmptyString(payload.jti)
      };
      if (requireRole(payload.role) === "administrator") {
        return { kind: "administrator", ...common };
      }
      return {
        kind: "practitioner",
        ...common,
        practitionerReference: requireNonEmptyString(payload.practitionerReference),
        roleCode: "legacy-local",
        specialtyCode: "legacy-local"
      };
    }
  };
}

export function createBearerAuthenticationMiddleware(api: Api, verifier: TokenVerifier): Api {
  return {
    async handle(request: ApiRequest): Promise<ApiResponse> {
      if (request.authorization === undefined) {
        return api.handle(request);
      }

      const token = readBearerToken(request.authorization);
      if (!token) {
        return invalidTokenResponse();
      }

      try {
        const principal = await verifier.verifyToken(token);
        return api.handle({ ...request, principal });
      } catch {
        return invalidTokenResponse();
      }
    }
  };
}

function readBearerToken(authorization: string) {
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return match?.[1];
}

function invalidTokenResponse(): ApiResponse {
  return { status: 401, body: { error: "INVALID_TOKEN" } };
}

function requireNonEmptyString(value: unknown) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("INVALID_TOKEN_CLAIMS");
  }
  return value;
}

function requireNumber(value: unknown) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error("INVALID_TOKEN_CLAIMS");
  }
  return value;
}

function requireRole(value: unknown): AuthenticatedRole {
  if (AUTHENTICATED_ROLES.includes(value as AuthenticatedRole)) {
    return value as AuthenticatedRole;
  }
  throw new Error("INVALID_TOKEN_CLAIMS");
}
