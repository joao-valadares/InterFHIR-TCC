import { expect } from "chai";
import { exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";

import {
  createUdapClient,
  type UdapClientTlsOptions,
  type UdapDiscoveryMetadata
} from "../src/udap/udap-client.js";

describe("UDAP institutional requester client", function () {
  it("executes discovery, signed software statement, DCR, assertion and token with the same mTLS material", async function () {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = { ...(await exportJWK(publicKey)), kid: "clinic-key", alg: "RS256", use: "sig" };
    const tls: UdapClientTlsOptions = { key: "clinic-key", cert: "clinic-cert", ca: "hospital-ca" };
    const calls: Array<{ url: string; init: { method: string; headers: Record<string, string>; body?: string; tls: UdapClientTlsOptions } }> = [];
    const metadata: UdapDiscoveryMetadata = {
      udap_versions_supported: ["1"],
      udap_profiles_supported: ["udap_dcr", "udap_authn", "udap_authz"],
      udap_authorization_extensions_supported: ["hl7-b2b"],
      udap_authorization_extensions_required: ["hl7-b2b"],
      grant_types_supported: ["client_credentials"],
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      token_endpoint: "https://hospital-a.example.test/udap/token",
      registration_endpoint: "https://hospital-a.example.test/udap/register",
      issuer: "https://hospital-a.example.test/udap",
      scopes_supported: ["system/Observation.r"],
      token_endpoint_auth_signing_alg_values_supported: ["RS256"],
      signed_metadata: "signed-metadata"
    };
    metadata.signed_metadata = await new SignJWT({ token_endpoint: metadata.token_endpoint, registration_endpoint: metadata.registration_endpoint })
      .setProtectedHeader({ alg: "RS256", kid: "clinic-key" }).setIssuer(metadata.issuer).setIssuedAt(1_800_000_000).setExpirationTime(1_800_000_300).sign(privateKey);
    const client = createUdapClient({
      discoveryTrust: { issuer: "https://hospital-a.example.test/udap", origin: "https://hospital-a.example.test", jwks: { keys: [publicJwk] } },
      clientId: "clinic-b-gateway",
      organizationReference: "Organization/clinic-b",
      certificateThumbprint: "clinic-thumbprint",
      signingKey: privateKey,
      signingKeyId: "clinic-key",
      signingAlgorithm: "RS256",
      publicJwk,
      fetch: async (url, init) => {
        calls.push({ url, init });
        if (init.method === "GET") return jsonResponse(200, metadata);
        if (url.endsWith("/udap/register")) return jsonResponse(201, { client_id: "clinic-b-gateway", organizationReference: "Organization/clinic-b" });
        return jsonResponse(200, { access_token: "token-1", token_type: "Bearer", expires_in: 300 });
      },
      now: () => 1_800_000_000
    });

    const validSignature = metadata.signed_metadata;
    metadata.signed_metadata = "invalid-signature";
    await expectRejected(() => client.discover("https://hospital-a.example.test", tls), "UDAP_SIGNED_METADATA_INVALID");
    metadata.signed_metadata = validSignature;
    const originalEndpoint = metadata.token_endpoint;
    metadata.token_endpoint = "https://attacker.example/udap/token";
    await expectRejected(() => client.discover("https://hospital-a.example.test", tls), "UDAP_SIGNED_METADATA_INVALID");
    metadata.token_endpoint = originalEndpoint;
    calls.length = 0;
    const discovered = await client.discover("https://hospital-a.example.test", tls);
    const statement = await client.createSoftwareStatement({ registrationEndpoint: discovered.registration_endpoint });
    await client.registerClient({ metadata: discovered, softwareStatement: statement, tls });
    const assertion = await client.createAssertion({
      tokenEndpoint: discovered.token_endpoint,
      practitionerReference: "Practitioner/beatriz",
      roleCode: "physician",
      purposeOfUse: "TREAT"
    });
    const token = await client.requestToken({ metadata: discovered, assertion, tls });

    const verifiedStatement = await jwtVerify(statement, publicKey, { audience: discovered.registration_endpoint, currentDate: new Date(1_800_000_000_000) });
    expect(verifiedStatement.payload).to.include({
      client_id: "clinic-b-gateway",
      organization_reference: "Organization/clinic-b",
      certificate_thumbprint: "clinic-thumbprint"
    });
    expect(verifiedStatement.payload.jwks).to.deep.equal([publicJwk]);
    const verifiedAssertion = await jwtVerify(assertion, publicKey, { audience: discovered.token_endpoint, currentDate: new Date(1_800_000_000_000) });
    expect(verifiedAssertion.payload).to.include({ iss: "clinic-b-gateway", sub: "clinic-b-gateway" });
    expect(verifiedAssertion.payload.exp! - verifiedAssertion.payload.iat!).to.be.at.most(300);
    expect(verifiedAssertion.payload.jti).to.be.a("string").and.not.empty;
    expect(verifiedAssertion.payload.extensions).to.deep.equal({
      "hl7-b2b": {
        version: "1",
        subject_id: "Practitioner/beatriz",
        subject_role: "physician",
        organization_id: "Organization/clinic-b",
        purpose_of_use: ["TREAT"]
      }
    });
    expect(token).to.deep.equal({ access_token: "token-1", token_type: "Bearer", expires_in: 300 });
    expect(calls.map((call) => call.init.tls)).to.deep.equal([tls, tls, tls]);
    expect(calls.map((call) => call.url)).to.deep.equal([
      "https://hospital-a.example.test/fhir/.well-known/udap",
      discovered.registration_endpoint,
      discovered.token_endpoint
    ]);
  });

  it("rejects discovery metadata without the protected UDAP endpoints", async function () {
    const { privateKey } = await generateKeyPair("RS256");
    const client = createUdapClient({
      discoveryTrust: { issuer: "https://hospital-a.example.test/udap", origin: "https://hospital-a.example.test", jwks: { keys: [] } },
      clientId: "clinic-b-gateway",
      organizationReference: "Organization/clinic-b",
      certificateThumbprint: "clinic-thumbprint",
      signingKey: privateKey,
      signingKeyId: "clinic-key",
      signingAlgorithm: "RS256",
      publicJwk: { kty: "RSA", n: "AQ", e: "AQAB", kid: "clinic-key", alg: "RS256" },
      fetch: async () => jsonResponse(200, { issuer: "https://hospital-a.example.test/udap" }),
      now: () => 1_800_000_000
    });

    await expectRejected(() => client.discover("https://hospital-a.example.test", { key: "k", cert: "c", ca: "ca" }), "UDAP_DISCOVERY_RESPONSE_INVALID");
  });
});

function jsonResponse(status: number, body: unknown) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

async function expectRejected(action: () => Promise<unknown>, message: string) {
  try {
    await action();
    expect.fail("Expected rejection");
  } catch (error) {
    expect((error as Error).message).to.equal(message);
  }
}
