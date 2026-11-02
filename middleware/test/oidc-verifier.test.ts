import { expect } from "chai";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { createOidcVerifier } from "../src/auth/oidc-verifier.js";

const now = 1_800_000_000;
const issuer = "https://identity.clinic-b.local/realms/clinic-b";
const audience = "interfhir-api";

describe("OIDC multi-issuer verifier", function () {
  it("rejects duplicate issuer URLs instead of silently overwriting trust", function () {
    expect(() => createOidcVerifier({
      issuers: [
        { issuer, audience, organizationReference: "Organization/clinic-b", jwksUri: `${issuer}/one` },
        { issuer, audience: "different-audience", organizationReference: "Organization/hospital-a", jwksUri: `${issuer}/two` }
      ]
    })).to.throw("OIDC_ISSUER_DUPLICATE");
  });

  it("accepts a signed practitioner identity from its configured issuer", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const verifier = createOidcVerifier({
      issuers: [{ issuer, audience, organizationReference: "Organization/clinic-b", jwksUri: `${issuer}/protocol/openid-connect/certs` }],
      now: () => now,
      fetch: async () => jsonResponse({ keys: [{ ...jwk, kid: "clinic-b-key", use: "sig", alg: "RS256" }] })
    });
    const token = await new SignJWT({
      role: "practitioner",
      practitionerReference: "Practitioner/beatriz",
      organizationReference: "Organization/clinic-b",
      roleCode: "attacker-controlled-role",
      specialtyCode: "attacker-controlled-specialty"
    })
      .setProtectedHeader({ alg: "RS256", kid: "clinic-b-key" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("clinic-b:practitioner-beatriz")
      .setJti("oidc-practitioner-1")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    expect(await verifier.verify(token)).to.deep.equal({
      kind: "practitioner",
      sub: "clinic-b:practitioner-beatriz",
      practitionerReference: "Practitioner/beatriz",
      organizationReference: "Organization/clinic-b",
      roleCode: "trusted-registry",
      specialtyCode: "trusted-registry",
      issuer,
      audience: [audience],
      exp: now + 300,
      jti: "oidc-practitioner-1"
    });
  });

  it("rejects a token from an issuer that is not configured", async function () {
    const { privateKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({
      role: "practitioner",
      practitionerReference: "Practitioner/attacker",
      organizationReference: "Organization/attacker",
      roleCode: "physician",
      specialtyCode: "general"
    })
      .setProtectedHeader({ alg: "RS256", kid: "attacker-key" })
      .setIssuer("https://attacker.invalid/realm")
      .setAudience(audience)
      .setSubject("attacker")
      .setJti("attacker-token")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);
    const verifier = createOidcVerifier({ issuers: [], now: () => now });

    await expectRejected(
      () => verifier.verify(token),
      "OIDC_ISSUER_NOT_CONFIGURED"
    );
  });

  it("does not require or trust OIDC role and specialty attributes", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const verifier = createOidcVerifier({
      issuers: [{ issuer, audience, organizationReference: "Organization/clinic-b", jwksUri: `${issuer}/protocol/openid-connect/certs` }],
      now: () => now,
      fetch: async () => jsonResponse({ keys: [{ ...jwk, kid: "clinic-b-key", use: "sig", alg: "RS256" }] })
    });
    const token = await new SignJWT({
      role: "practitioner",
      practitionerReference: "Practitioner/beatriz",
      organizationReference: "Organization/clinic-b"
    })
      .setProtectedHeader({ alg: "RS256", kid: "clinic-b-key" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("clinic-b:practitioner-beatriz")
      .setJti("oidc-practitioner-2")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    expect(await verifier.verify(token)).to.include({
      roleCode: "trusted-registry",
      specialtyCode: "trusted-registry"
    });
  });

  it("accepts a patient identity only when the verified patient reference and replay id are present", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const verifier = createOidcVerifier({
      issuers: [{ issuer, audience, organizationReference: "Organization/clinic-b", jwksUri: `${issuer}/protocol/openid-connect/certs` }],
      now: () => now,
      fetch: async () => jsonResponse({ keys: [{ ...jwk, kid: "clinic-b-key", use: "sig", alg: "RS256" }] })
    });
    const token = await new SignJWT({ role: "patient", patientReference: "Patient/pat-ana" })
      .setProtectedHeader({ alg: "RS256", kid: "clinic-b-key" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("clinic-b:patient-ana")
      .setJti("oidc-patient-1")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    expect(await verifier.verify(token)).to.include({ kind: "patient", patientReference: "Patient/pat-ana", jti: "oidc-patient-1" });
  });

  it("rejects a practitioner token whose verified organization claim is absent or divergent", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const verifier = createOidcVerifier({
      issuers: [{ issuer, audience, organizationReference: "Organization/clinic-b", jwksUri: `${issuer}/protocol/openid-connect/certs` }],
      now: () => now,
      fetch: async () => jsonResponse({ keys: [{ ...jwk, kid: "clinic-b-key", use: "sig", alg: "RS256" }] })
    });
    for (const organizationReference of [undefined, "Organization/attacker"]) {
      const token = await new SignJWT({ role: "practitioner", practitionerReference: "Practitioner/beatriz", ...(organizationReference ? { organizationReference } : {}) })
        .setProtectedHeader({ alg: "RS256", kid: "clinic-b-key" })
        .setIssuer(issuer)
        .setAudience(audience)
        .setSubject("clinic-b:practitioner-beatriz")
        .setJti(`oidc-practitioner-invalid-${organizationReference ?? "missing"}`)
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);

      await expectRejected(() => verifier.verify(token), organizationReference ? "OIDC_ORGANIZATION_MISMATCH" : "OIDC_ORGANIZATION_REQUIRED");
    }
  });

  it("rejects a human token without a replay identifier", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const verifier = createOidcVerifier({
      issuers: [{ issuer, audience, organizationReference: "Organization/clinic-b", jwksUri: `${issuer}/protocol/openid-connect/certs` }],
      now: () => now,
      fetch: async () => jsonResponse({ keys: [{ ...jwk, kid: "clinic-b-key", use: "sig", alg: "RS256" }] })
    });
    const token = await new SignJWT({ role: "administrator", organizationReference: "Organization/clinic-b" })
      .setProtectedHeader({ alg: "RS256", kid: "clinic-b-key" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("clinic-b:administrator")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    await expectRejected(() => verifier.verify(token), "OIDC_CLAIMS_INVALID");
  });
});

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}

async function expectRejected(action: () => Promise<unknown>, message: string) {
  try {
    await action();
    expect.fail("Expected promise rejection");
  } catch (error) {
    expect((error as Error).message).to.equal(message);
  }
}
