import { expect } from "chai";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { createUdapAccessTokenVerifier, createUdapAccessTokenVerifierFromIssuerJwks, createUdapTokenService } from "../src/udap/udap-token-service.js";

const now = 1_800_000_000;
const tokenEndpoint = "https://hospital-a.local/udap/token";
const fingerprint = "thumbprint-1";

describe("UDAP token service", function () {
  it("attests the software declaration for different professionals without independent human authentication", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const service = createUdapTokenService({ issuer: "https://hospital-a.local/udap", audience: "https://hospital-a.local/interfhir",
      tokenEndpoint, signingKey: privateKey, now: () => now,
      clients: { requireActive: async () => ({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint,
        jwks: [{ ...jwk, kid: "clinic-key", alg: "RS256" }], allowedScopes: ["system/Observation.r"] }), claimReplayJti: async () => undefined }
    });
    for (const practitioner of ["Practitioner/beatriz", "Practitioner/another-professional"]) {
      const assertion = await new SignJWT({ extensions: { "hl7-b2b": { version: "1", subject_id: practitioner, subject_role: "physician", organization_id: "Organization/clinic-b", purpose_of_use: ["TREAT"] } } })
        .setProtectedHeader({ alg: "RS256", kid: "clinic-key" }).setIssuer("clinic-b-gateway").setSubject("clinic-b-gateway")
        .setAudience(tokenEndpoint).setJti(practitioner).setIssuedAt(now).setExpirationTime(now + 300).sign(privateKey);
      const token = await service.issue(tokenRequest(assertion), { fingerprint256: "ignored", x5tS256: fingerprint });
      expect(token.claims).to.include({ client_id: "clinic-b-gateway", practitionerReference: practitioner });
      expect(token.claims.cnf).to.deep.equal({ "x5t#S256": fingerprint });
    }
  });
  it("issues a short certificate-bound token for a valid private_key_jwt assertion", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const { publicKey: otherPublicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const otherJwk = await exportJWK(otherPublicKey);
    const replayed: string[] = [];
    const service = createUdapTokenService({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      tokenEndpoint,
      signingKey: privateKey,
      signingKeyId: "hospital-a-udap-2026",
      now: () => now,
      clients: {
        requireActive: async () => ({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint, jwks: [{ ...jwk, kid: "clinic-key", alg: "RS256" }], allowedScopes: ["system/Observation.r"] }),
        claimReplayJti: async (_issuer, jti) => { if (replayed.includes(jti)) throw new Error("UDAP_ASSERTION_REPLAY"); replayed.push(jti); }
      }
    });
    const assertion = await createAssertion(privateKey, "assertion-1");

    const token = await service.issue({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }, { fingerprint256: "ignored", x5tS256: fingerprint });
    expect(token.expires_in).to.equal(300);
    expect(token.access_token.split(".")[0]).to.be.a("string");
    expect(token.claims).to.include({ client_id: "clinic-b-gateway", organizationReference: "Organization/clinic-b", practitionerReference: "Practitioner/beatriz", assertionHash: token.assertionHash });
    expect(token.claims.cnf).to.deep.equal({ "x5t#S256": fingerprint });
    const principal = await createUdapAccessTokenVerifierFromIssuerJwks({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      issuerJwks: { keys: [{ ...otherJwk, kid: "hospital-a-udap-previous", alg: "RS256" }, { ...jwk, kid: "hospital-a-udap-2026", alg: "RS256" }] },
      signingKeyId: "hospital-a-udap-2026",
      signingAlgorithm: "RS256",
      now: () => now
    }).then((verifier) => verifier.verifyToken(token.access_token));
    expect(principal).to.include({ kind: "service", clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint });
  });

  it("marks issued tokens with the dedicated UDAP key id", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const service = createUdapTokenService({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      tokenEndpoint,
      signingKey: privateKey,
      signingKeyId: "hospital-a-udap-2026",
      now: () => now,
      clients: {
        requireActive: async () => ({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint, jwks: [{ ...jwk, kid: "clinic-key", alg: "RS256" }], allowedScopes: ["system/Observation.r"] }),
        claimReplayJti: async () => undefined
      }
    });
    const assertion = await createAssertion(privateKey, "assertion-kid");
    const token = await service.issue({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }, { fingerprint256: "ignored", x5tS256: fingerprint });
    const header = JSON.parse(Buffer.from(token.access_token.split(".")[0], "base64url").toString("utf8")) as Record<string, unknown>;
    expect(header).to.include({ alg: "RS256", kid: "hospital-a-udap-2026" });
  });

  it("requires one public issuer key and rejects private JWKS material", async function () {
    const { publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const base = {
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      signingKeyId: "hospital-a-udap-2026",
      signingAlgorithm: "RS256" as const
    };

    await expectRejected(
      () => createUdapAccessTokenVerifierFromIssuerJwks({ ...base, issuerJwks: { keys: [] } }),
      "UDAP_ISSUER_VERIFICATION_KEY_NOT_FOUND"
    );
    await expectRejected(
      () => createUdapAccessTokenVerifierFromIssuerJwks({ ...base, issuerJwks: { keys: [{ ...jwk, kid: base.signingKeyId, alg: "RS256" }, { ...jwk, kid: base.signingKeyId, alg: "RS256" }] } }),
      "UDAP_ISSUER_VERIFICATION_KEY_DUPLICATE"
    );
    for (const field of ["d", "p", "q", "dp", "dq", "qi", "k", "oth"]) {
      await expectRejected(
        () => createUdapAccessTokenVerifierFromIssuerJwks({ ...base, issuerJwks: { keys: [{ ...jwk, kid: base.signingKeyId, alg: "RS256", [field]: "private-material" }] } }),
        "UDAP_TRUSTED_JWKS_PRIVATE_MATERIAL"
      );
    }
  });

  it("restricts access-token verification to the configured algorithm", async function () {
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const token = await new SignJWT({
      client_id: "clinic-b-gateway",
      organizationReference: "Organization/clinic-b",
      practitionerReference: "Practitioner/bruno",
      purposeOfUse: ["TREAT"],
      assertionHash: "sha256:assertion",
      cnf: { "x5t#S256": fingerprint }
    })
      .setProtectedHeader({ alg: "ES256", kid: "hospital-a-udap-2026" })
      .setIssuer("https://hospital-a.local/udap")
      .setAudience("https://hospital-a.local/interfhir")
      .setJti("es256-token")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    const verifier = createUdapAccessTokenVerifier({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      verificationKey: publicKey,
      algorithm: "RS256",
      signingKeyId: "hospital-a-udap-2026",
      now: () => now
    });
    await expectAnyRejected(() => verifier.verifyToken(token));
  });

  it("rejects an access token whose header kid differs from the trusted key", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({
      client_id: "clinic-b-gateway",
      organizationReference: "Organization/clinic-b",
      practitionerReference: "Practitioner/bruno",
      purposeOfUse: ["TREAT"],
      assertionHash: "sha256:assertion",
      cnf: { "x5t#S256": fingerprint }
    })
      .setProtectedHeader({ alg: "RS256", kid: "hospital-a-udap-previous" })
      .setIssuer("https://hospital-a.local/udap")
      .setAudience("https://hospital-a.local/interfhir")
      .setJti("wrong-kid-token")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(privateKey);

    const verifier = createUdapAccessTokenVerifier({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      verificationKey: publicKey,
      algorithm: "RS256",
      signingKeyId: "hospital-a-udap-2026",
      now: () => now
    });
    await expectRejected(() => verifier.verifyToken(token), "UDAP_TOKEN_KEY_ID_MISMATCH");
  });

  it("rejects assertion replay and a divergent mTLS certificate thumbprint", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const used = new Set<string>();
    const service = createUdapTokenService({ issuer: "https://hospital-a.local/udap", audience: "https://hospital-a.local/interfhir", tokenEndpoint, signingKey: privateKey, now: () => now, clients: { requireActive: async () => ({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint, jwks: [{ ...jwk, kid: "clinic-key", alg: "RS256" }], allowedScopes: ["system/Observation.r"] }), claimReplayJti: async (_issuer, jti) => { if (used.has(jti)) throw new Error("UDAP_ASSERTION_REPLAY"); used.add(jti); } } });
    const assertion = await createAssertion(privateKey, "assertion-2");
    await expectRejected(() => service.issue({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }, { fingerprint256: "ignored", x5tS256: "attacker-thumbprint" }), "UDAP_CERTIFICATE_BINDING_MISMATCH");
    await service.issue({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }, { fingerprint256: "ignored", x5tS256: fingerprint });
    await expectRejected(() => service.issue({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }, { fingerprint256: "ignored", x5tS256: fingerprint }), "UDAP_ASSERTION_REPLAY");
  });

  it("accepts an assertion issued up to five seconds ahead to tolerate gateway clock skew", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const service = createUdapTokenService({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      tokenEndpoint,
      signingKey: privateKey,
      now: () => now,
      clients: {
        requireActive: async () => ({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint, jwks: [{ ...jwk, kid: "clinic-key", alg: "RS256" }], allowedScopes: ["system/Observation.r"] }),
        claimReplayJti: async () => undefined
      }
    });
    const assertion = await new SignJWT({ extensions: { "hl7-b2b": { version: "1", subject_id: "Practitioner/beatriz", subject_role: "physician", organization_id: "Organization/clinic-b", purpose_of_use: ["TREAT"] } } })
      .setProtectedHeader({ alg: "RS256", kid: "clinic-key" })
      .setIssuer("clinic-b-gateway")
      .setSubject("clinic-b-gateway")
      .setAudience(tokenEndpoint)
      .setJti("tolerated-future-assertion")
      .setIssuedAt(now + 5)
      .setExpirationTime(now + 305)
      .sign(privateKey);

    await service.issue({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }, { fingerprint256: "ignored", x5tS256: fingerprint });
  });

  it("rejects an assertion issued more than five seconds in the future even when its lifetime is short", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const service = createUdapTokenService({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      tokenEndpoint,
      signingKey: privateKey,
      now: () => now,
      clients: {
        requireActive: async () => ({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint, jwks: [{ ...jwk, kid: "clinic-key", alg: "RS256" }], allowedScopes: ["system/Observation.r"] }),
        claimReplayJti: async () => undefined
      }
    });
    const assertion = await new SignJWT({ extensions: { "hl7-b2b": { version: "1", subject_id: "Practitioner/beatriz", subject_role: "physician", organization_id: "Organization/clinic-b", purpose_of_use: ["TREAT"] } } })
      .setProtectedHeader({ alg: "RS256", kid: "clinic-key" })
      .setIssuer("clinic-b-gateway")
      .setSubject("clinic-b-gateway")
      .setAudience(tokenEndpoint)
      .setJti("future-assertion")
      .setIssuedAt(now + 6)
      .setExpirationTime(now + 306)
      .sign(privateKey);

    await expectRejected(() => service.issue({ grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, udap: "1" }, { fingerprint256: "ignored", x5tS256: fingerprint }), "UDAP_ASSERTION_IAT_INVALID");
  });

  it("rejects assertions with a divergent audience or an expired lifetime", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const service = createUdapTokenService({
      issuer: "https://hospital-a.local/udap",
      audience: "https://hospital-a.local/interfhir",
      tokenEndpoint,
      signingKey: privateKey,
      now: () => now,
      clients: {
        requireActive: async () => ({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: fingerprint, jwks: [{ ...jwk, kid: "clinic-key", alg: "RS256" }], allowedScopes: ["system/Observation.r"] }),
        claimReplayJti: async () => undefined
      }
    });
    const wrongAudience = await createAssertion(privateKey, "wrong-audience", { audience: "https://other.example.test/udap/token" });
    const expired = await createAssertion(privateKey, "expired", { issuedAt: now - 301, expirationTime: now - 1 });

    await expectAnyRejected(() => service.issue(tokenRequest(wrongAudience), { fingerprint256: "ignored", x5tS256: fingerprint }));
    await expectAnyRejected(() => service.issue(tokenRequest(expired), { fingerprint256: "ignored", x5tS256: fingerprint }));
  });
});

function tokenRequest(client_assertion: string) {
  return { grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion, udap: "1" } as const;
}

async function createAssertion(privateKey: CryptoKey, jti: string, overrides: { audience?: string; issuedAt?: number; expirationTime?: number } = {}) {
  return new SignJWT({ extensions: { "hl7-b2b": { version: "1", subject_id: "Practitioner/beatriz", subject_role: "physician", organization_id: "Organization/clinic-b", purpose_of_use: ["TREAT"] } } })
    .setProtectedHeader({ alg: "RS256", kid: "clinic-key" }).setIssuer("clinic-b-gateway").setSubject("clinic-b-gateway").setAudience(overrides.audience ?? tokenEndpoint).setJti(jti).setIssuedAt(overrides.issuedAt ?? now).setExpirationTime(overrides.expirationTime ?? now + 300).sign(privateKey);
}
async function expectRejected(action: () => Promise<unknown>, message: string) { try { await action(); expect.fail("Expected rejection"); } catch (error) { expect((error as Error).message).to.equal(message); } }
async function expectAnyRejected(action: () => Promise<unknown>) { try { await action(); expect.fail("Expected rejection"); } catch (error) { expect(error).to.be.instanceOf(Error); } }
