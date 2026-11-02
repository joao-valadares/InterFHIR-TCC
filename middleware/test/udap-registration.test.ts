import { expect } from "chai";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

import { createSignedSoftwareStatementValidator, createUdapRegistrationService } from "../src/udap/udap-registration-service.js";

describe("UDAP registration", function () {
  it("persists only approved client metadata after validating the mTLS organization", async function () {
    const saved: unknown[] = [];
    const service = createUdapRegistrationService({ registrationEndpoint: "https://hospital-a.local/udap/register", validateStatement: async () => statement(), clients: { save: async (client) => { saved.push(client); }, claimReplayJti: async () => undefined } });
    await service.register({ software_statement: "signed" }, { subjectOrganization: "Organization/clinic-b", x5tS256: "thumbprint" });
    expect(saved).to.deep.equal([{ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: "thumbprint", jwks: [{ kty: "RSA" }], allowedScopes: ["system/Observation.r"], statementIssuer: "clinic-b-software", statementJti: "statement-1", statementExpiresAt: new Date("2027-01-15T08:05:00.000Z") }]);
  });

  it("rejects a registration whose certificate does not match the statement", async function () {
    const service = createUdapRegistrationService({ registrationEndpoint: "https://hospital-a.local/udap/register", validateStatement: async () => statement(), clients: { save: async () => undefined, claimReplayJti: async () => undefined } });
    await expectRejected(() => service.register({ software_statement: "signed" }, { subjectOrganization: "Organization/clinic-b", x5tS256: "different" }), "UDAP_REGISTRATION_CERTIFICATE_MISMATCH");
  });

  it("validates signed statement audience, expiry and jti before registration", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const validator = createSignedSoftwareStatementValidator({ registrationEndpoint: "https://hospital-a.local/udap/register", trustedJwks: [{ ...jwk, kid: "statement-key", alg: "RS256" }], now: () => 1_800_000_000 });
    const statement = await new SignJWT({ client_id: "clinic-b-gateway", organization_reference: "Organization/clinic-b", certificate_thumbprint: "thumbprint", jwks: [{ ...jwk, kid: "client-key", alg: "RS256" }], allowed_scopes: ["system/Observation.r"] }).setProtectedHeader({ alg: "RS256", kid: "statement-key" }).setIssuer("clinic-b-gateway").setSubject("clinic-b-gateway").setAudience("https://hospital-a.local/udap/register").setJti("statement-1").setIssuedAt(1_800_000_000).setExpirationTime(1_800_000_300).sign(privateKey);
    expect(await validator(statement)).to.include({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b" });
  });

  it("accepts a software statement issued up to five seconds ahead to tolerate gateway clock skew", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const validator = createSignedSoftwareStatementValidator({ registrationEndpoint: "https://hospital-a.local/udap/register", trustedJwks: [{ ...jwk, kid: "statement-key", alg: "RS256" }], now: () => 1_800_000_000 });
    const statement = await new SignJWT({ client_id: "clinic-b-gateway", organization_reference: "Organization/clinic-b", certificate_thumbprint: "thumbprint", jwks: [{ ...jwk, kid: "client-key", alg: "RS256" }], allowed_scopes: ["system/Observation.r"] }).setProtectedHeader({ alg: "RS256", kid: "statement-key" }).setIssuer("clinic-b-gateway").setSubject("clinic-b-gateway").setAudience("https://hospital-a.local/udap/register").setJti("statement-clock-skew").setIssuedAt(1_800_000_005).setExpirationTime(1_800_000_305).sign(privateKey);

    expect(await validator(statement)).to.include({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b" });
  });

  it("rejects a software statement issued more than five seconds ahead", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const validator = createSignedSoftwareStatementValidator({ registrationEndpoint: "https://hospital-a.local/udap/register", trustedJwks: [{ ...jwk, kid: "statement-key", alg: "RS256" }], now: () => 1_800_000_000 });
    const statement = await new SignJWT({ client_id: "clinic-b-gateway", organization_reference: "Organization/clinic-b", certificate_thumbprint: "thumbprint", jwks: [{ ...jwk, kid: "client-key", alg: "RS256" }], allowed_scopes: ["system/Observation.r"] }).setProtectedHeader({ alg: "RS256", kid: "statement-key" }).setIssuer("clinic-b-gateway").setSubject("clinic-b-gateway").setAudience("https://hospital-a.local/udap/register").setJti("statement-invalid-clock-skew").setIssuedAt(1_800_000_006).setExpirationTime(1_800_000_306).sign(privateKey);

    await expectRejected(() => validator(statement), "UDAP_SOFTWARE_STATEMENT_IAT_INVALID");
  });

  it("rejects a software statement whose subject does not equal the client id", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const validator = createSignedSoftwareStatementValidator({ registrationEndpoint: "https://hospital-a.local/udap/register", trustedJwks: [{ ...jwk, kid: "statement-key", alg: "RS256" }], now: () => 1_800_000_000 });
    const statement = await new SignJWT({ client_id: "clinic-b-gateway", organization_reference: "Organization/clinic-b", certificate_thumbprint: "thumbprint", jwks: [{ ...jwk, kid: "client-key", alg: "RS256" }], allowed_scopes: ["system/Observation.r"] }).setProtectedHeader({ alg: "RS256", kid: "statement-key" }).setIssuer("clinic-b-software").setSubject("different-client").setAudience("https://hospital-a.local/udap/register").setJti("statement-sub-mismatch").setIssuedAt(1_800_000_000).setExpirationTime(1_800_000_300).sign(privateKey);

    await expectRejected(() => validator(statement), "UDAP_SOFTWARE_STATEMENT_IDENTITY_MISMATCH");
  });

  it("rejects a software statement whose issuer does not equal the client id", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const validator = createSignedSoftwareStatementValidator({ registrationEndpoint: "https://hospital-a.local/udap/register", trustedJwks: [{ ...jwk, kid: "statement-key", alg: "RS256" }], now: () => 1_800_000_000 });
    const statement = await new SignJWT({ client_id: "clinic-b-gateway", organization_reference: "Organization/clinic-b", certificate_thumbprint: "thumbprint", jwks: [{ ...jwk, kid: "client-key", alg: "RS256" }], allowed_scopes: ["system/Observation.r"] }).setProtectedHeader({ alg: "RS256", kid: "statement-key" }).setIssuer("different-client").setSubject("clinic-b-gateway").setAudience("https://hospital-a.local/udap/register").setJti("statement-issuer-mismatch").setIssuedAt(1_800_000_000).setExpirationTime(1_800_000_300).sign(privateKey);

    await expectRejected(() => validator(statement), "UDAP_SOFTWARE_STATEMENT_IDENTITY_MISMATCH");
  });

  it("rejects a software statement missing sub", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const validator = createSignedSoftwareStatementValidator({ registrationEndpoint: "https://hospital-a.local/udap/register", trustedJwks: [{ ...jwk, kid: "statement-key", alg: "RS256" }], now: () => 1_800_000_000 });
    const statement = await new SignJWT({ client_id: "clinic-b-gateway", organization_reference: "Organization/clinic-b", certificate_thumbprint: "thumbprint", jwks: [{ ...jwk, kid: "client-key", alg: "RS256" }], allowed_scopes: ["system/Observation.r"] }).setProtectedHeader({ alg: "RS256", kid: "statement-key" }).setIssuer("clinic-b-gateway").setAudience("https://hospital-a.local/udap/register").setJti("statement-sub-missing").setIssuedAt(1_800_000_000).setExpirationTime(1_800_000_300).sign(privateKey);

    await expectRejected(() => validator(statement), "UDAP_SOFTWARE_STATEMENT_INVALID");
  });

  it("rejects a software statement whose lifetime exceeds five minutes", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    const validator = createSignedSoftwareStatementValidator({ registrationEndpoint: "https://hospital-a.local/udap/register", trustedJwks: [{ ...jwk, kid: "statement-key", alg: "RS256" }], now: () => 1_800_000_000 });
    const statement = await new SignJWT({ client_id: "clinic-b-gateway", organization_reference: "Organization/clinic-b", certificate_thumbprint: "thumbprint", jwks: [{ ...jwk, kid: "client-key", alg: "RS256" }], allowed_scopes: ["system/Observation.r"] }).setProtectedHeader({ alg: "RS256", kid: "statement-key" }).setIssuer("clinic-b-gateway").setSubject("clinic-b-gateway").setAudience("https://hospital-a.local/udap/register").setJti("statement-long").setIssuedAt(1_800_000_000).setExpirationTime(1_800_000_301).sign(privateKey);

    await expectRejected(() => validator(statement), "UDAP_SOFTWARE_STATEMENT_LIFETIME_INVALID");
  });

  it("records a statement jti before persisting the registered client", async function () {
    const events: string[] = [];
    const service = createUdapRegistrationService({ registrationEndpoint: "https://hospital-a.local/udap/register", validateStatement: async () => statement(), clients: { claimReplayJti: async () => { events.push("replay"); }, save: async () => { events.push("save"); } } });
    await service.register({ software_statement: "signed" }, { subjectOrganization: "Organization/clinic-b", x5tS256: "thumbprint" });
    expect(events).to.deep.equal(["replay", "save"]);
  });

  it("rejects private material in the trusted software-statement JWKS", async function () {
    const validator = createSignedSoftwareStatementValidator({
      registrationEndpoint: "https://hospital-a.local/udap/register",
      trustedJwks: [{ kty: "RSA", kid: "private", alg: "RS256", d: "private-material" }],
      now: () => 1_800_000_000
    });

    await expectRejected(() => validator("not-a-valid-statement"), "UDAP_TRUSTED_JWKS_PRIVATE_MATERIAL");
  });
});
function statement() { return { clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: "thumbprint", jwks: [{ kty: "RSA" }], allowedScopes: ["system/Observation.r"], statementIssuer: "clinic-b-software", statementJti: "statement-1", statementExpiresAt: new Date("2027-01-15T08:05:00.000Z") }; }
async function expectRejected(action: () => Promise<unknown>, message: string) { try { await action(); expect.fail("Expected rejection"); } catch (error) { expect((error as Error).message).to.equal(message); } }
