import { expect } from "chai";
import { SignJWT } from "jose";

import {
  createBearerAuthenticationMiddleware,
  createLocalJwtService
} from "../src/auth/authentication.js";
import type { ApiRequest, ApiResponse } from "../src/api/api-handler.js";

const secret = "session-2-local-test-secret-with-32-characters";
const issuer = "interfhir-local-test";
const audience = "interfhir-api-test";
const now = 1_800_000_000;

const tokenClaims = {
  sub: "local:practitioner-bruno",
  practitionerReference: "Practitioner/bruno",
  role: "practitioner" as const,
  organizationReference: "Organization/clinic-b",
  jti: "jwt-session-2"
};

describe("Local JWT authentication", function () {
  it("rejects a secret shorter than 32 characters", function () {
    expect(() =>
      createLocalJwtService({
        secret: "short-local-secret",
        issuer,
        audience
      })
    ).to.throw("JWT_SECRET_TOO_SHORT");
  });

  for (const placeholder of [
    "replace-with-a-local-secret-of-at-least-32-characters",
    "change-this-local-development-secret-32-chars"
  ]) {
    it(`rejects the documented placeholder secret: ${placeholder}`, function () {
      expect(() =>
        createLocalJwtService({
          secret: placeholder,
          issuer,
          audience
        })
      ).to.throw("JWT_SECRET_PLACEHOLDER");
    });
  }

  it("authenticates a valid Bearer token and propagates the principal", async function () {
    const principals: unknown[] = [];
    const jwt = createLocalJwtService({
      secret,
      issuer,
      audience,
      now: () => now
    });
    const token = await jwt.issueToken({
      ...tokenClaims,
      expiresInSeconds: 300
    });
    const authenticatedApi = createBearerAuthenticationMiddleware(
      {
        handle: async (request: ApiRequest): Promise<ApiResponse> => {
          principals.push(request.principal);
          return { status: 200, body: { ok: true } };
        }
      },
      jwt
    );

    const response = await authenticatedApi.handle({
      method: "POST",
      path: "/access/read",
      authorization: `Bearer ${token}`
    });

    expect(response.status).to.equal(200);
    expect(principals).to.deep.equal([
      {
        kind: "practitioner",
        sub: tokenClaims.sub,
        practitionerReference: tokenClaims.practitionerReference,
        organizationReference: tokenClaims.organizationReference,
        roleCode: "legacy-local",
        specialtyCode: "legacy-local",
        issuer,
        audience: [audience],
        exp: now + 300,
        jti: tokenClaims.jti
      }
    ]);
  });

  it("rejects a token signed with a different secret", async function () {
    const verifier = createLocalJwtService({
      secret,
      issuer,
      audience,
      now: () => now
    });
    const attacker = createLocalJwtService({
      secret: "different-local-test-secret-with-32-characters",
      issuer,
      audience,
      now: () => now
    });
    const token = await attacker.issueToken({
      ...tokenClaims,
      expiresInSeconds: 300
    });

    const response = await authenticatedResponse(verifier, token);

    expect(response).to.deep.equal({
      status: 401,
      body: { error: "INVALID_TOKEN" }
    });
  });

  it("rejects an expired token", async function () {
    const signer = createLocalJwtService({
      secret,
      issuer,
      audience,
      now: () => now - 600
    });
    const verifier = createLocalJwtService({
      secret,
      issuer,
      audience,
      now: () => now
    });
    const token = await signer.issueToken({
      ...tokenClaims,
      expiresInSeconds: 60
    });

    const response = await authenticatedResponse(verifier, token);

    expect(response).to.deep.equal({
      status: 401,
      body: { error: "INVALID_TOKEN" }
    });
  });

  it("rejects a signed token when a required claim is missing", async function () {
    const verifier = createLocalJwtService({
      secret,
      issuer,
      audience,
      now: () => now
    });
    const { organizationReference: _missing, ...incompleteClaims } = tokenClaims;
    const token = await signRawToken(incompleteClaims);

    const response = await authenticatedResponse(verifier, token);

    expect(response).to.deep.equal({
      status: 401,
      body: { error: "INVALID_TOKEN" }
    });
  });

  it("rejects a signed token with an unsupported role", async function () {
    const verifier = createLocalJwtService({
      secret,
      issuer,
      audience,
      now: () => now
    });
    const token = await signRawToken({
      ...tokenClaims,
      role: "root"
    });

    const response = await authenticatedResponse(verifier, token);

    expect(response).to.deep.equal({
      status: 401,
      body: { error: "INVALID_TOKEN" }
    });
  });
});

async function authenticatedResponse(
  jwt: ReturnType<typeof createLocalJwtService>,
  token: string
) {
  const authenticatedApi = createBearerAuthenticationMiddleware(
    {
      handle: async (): Promise<ApiResponse> => ({
        status: 200,
        body: { ok: true }
      })
    },
    jwt
  );

  return authenticatedApi.handle({
    method: "POST",
    path: "/access/read",
    authorization: `Bearer ${token}`
  });
}

async function signRawToken(claims: Record<string, unknown>) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(new TextEncoder().encode(secret));
}
