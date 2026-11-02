import { expect } from "chai";

import { createHealthAccessApi } from "../src/api/api-handler.js";
import type {
  ApiAdminService,
  ApiFhirClient,
  ApiRequest
} from "../src/api/api-handler.js";

function observation() {
  return {
    resourceType: "Observation",
    id: "obs-1",
    subject: { reference: "Patient/maria" }
  };
}

describe("Health Access HTTP API handler", function () {
  it("exposes the patient Consent lifecycle as the canonical route and rejects body patient identity", async function () {
    const calls: unknown[] = [];
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      patientConsents: {
        create: async (input) => { calls.push({ method: "create", input }); return { status: "active" }; },
        revoke: async (input) => { calls.push({ method: "revoke", input }); return { status: "revoked" }; }
      }
    });
    const principal = { kind: "patient" as const, sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: "jti" };
    const body = {
      granteeOrganizationReference: "Organization/clinic-b",
      practitionerReference: "Practitioner/beatriz",
      resourceReference: "Observation/obs-ana-1",
      purposeOfUse: "TREAT",
      policyId: "POLICY_TREATMENT_OBSERVATION",
      policyVersion: 1,
      validUntil: "2026-08-30T23:59:59.000Z"
    };

    const created = await api.handle({ method: "POST", path: "/patient/consents", principal, body, idempotencyKey: "consent-demo-001" });
    const rejected = await api.handle({ method: "POST", path: "/patient/consents", principal, idempotencyKey: "consent-demo-002", body: { ...body, patientReference: "Patient/attacker" } });
    const revoked = await api.handle({ method: "POST", path: "/patient/consents/Consent%2Fcons-generated/revoke", principal });

    expect(created).to.deep.equal({ status: 201, body: { status: "active" } });
    expect(rejected).to.deep.equal({ status: 400, body: { error: "PATIENT_REFERENCE_NOT_ALLOWED" } });
    expect(revoked).to.deep.equal({ status: 200, body: { status: "revoked" } });
    expect(calls).to.deep.equal([
      { method: "create", input: { patientReference: "Patient/ana", idempotencyKey: "consent-demo-001", request: body } },
      { method: "revoke", input: { patientReference: "Patient/ana", consentReference: "Consent/cons-generated" } }
    ]);
  });

  it("requires an idempotency key for canonical patient Consent creation", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      patientConsents: { create: async () => ({ status: "active" }), revoke: async () => ({ status: "revoked" }) }
    });
    const response = await api.handle({
      method: "POST",
      path: "/patient/consents",
      principal: { kind: "patient", sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: "jti" },
      body: { granteeOrganizationReference: "Organization/clinic-b" }
    });
    expect(response).to.deep.equal({ status: 400, body: { error: "MISSING_IDEMPOTENCY_KEY" } });
  });

  it("rejects unrecognized patient Consent request fields before invoking the service", async function () {
    let calls = 0;
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      patientConsents: {
        create: async () => { calls += 1; return { status: "active" }; },
        revoke: async () => ({ status: "revoked" })
      }
    });

    const response = await api.handle({
      method: "POST",
      path: "/patient/consents",
      principal: { kind: "patient", sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: "jti-unknown-field" },
      idempotencyKey: "consent-unknown-field",
      body: {
        granteeOrganizationReference: "Organization/clinic-b",
        resourceReference: "Observation/obs-ana-1",
        purposeOfUse: "TREAT",
        policyId: "POLICY_TREATMENT_OBSERVATION",
        policyVersion: 1,
        validUntil: "2026-08-30T23:59:59.000Z",
        rawConsentHash: "attacker-controlled"
      }
    });

    expect(response).to.deep.equal({ status: 400, body: { error: "UNKNOWN_FIELD", field: "rawConsentHash" } });
    expect(calls).to.equal(0);
  });

  it("maps unknown and mismatched network policy errors to stable 4xx responses", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      patientConsents: {
        create: async () => { throw new Error("UNKNOWN_NETWORK_POLICY_VERSION"); },
        revoke: async () => ({ status: "revoked" })
      }
    });

    const response = await api.handle({
      method: "POST",
      path: "/patient/consents",
      principal: { kind: "patient", sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: "jti" },
      idempotencyKey: "consent-policy-error",
      body: { granteeOrganizationReference: "Organization/clinic-b", resourceReference: "Observation/obs-ana-1", purposeOfUse: "TREAT", policyId: "POLICY_UNKNOWN", policyVersion: 2, validUntil: "2026-08-30T23:59:59.000Z" }
    });

    expect(response).to.deep.equal({ status: 400, body: { error: "UNKNOWN_NETWORK_POLICY_VERSION" } });
  });

  it("disables the deprecated patient share route without invoking its side effects", async function () {
    let calls = 0;
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      patientShares: { create: async () => { calls += 1; return { shareId: "share_legacy" }; } }
    });
    const response = await api.handle({
      method: "POST",
      path: "/patient/shares",
      principal: { kind: "patient", sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: "jti" },
      body: { granteeOrganizationReference: "Organization/clinic-b", consentReference: "Consent/legacy", resourceReferences: ["Observation/obs-ana-1"], purposeOfUse: "TREAT", validUntil: "2026-08-30T23:59:59.000Z" }
    });

    expect(response).to.deep.equal({ status: 410, body: { error: "LEGACY_PATIENT_SHARE_ROUTE_DISABLED" } });
    expect(calls).to.equal(0);
  });

  it("does not derive or create a legacy patient share from the request body", async function () {
    const calls: unknown[] = [];
    const api = createHealthAccessApi({ fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService(), patientShares: { create: async (input) => { calls.push(input); return { shareId: "share_1" }; } } });
    const principal = { kind: "patient" as const, sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: "jti" };
    const response = await api.handle({ method: "POST", path: "/patient/shares", principal, body: { patientReference: "Patient/attacker", granteeOrganizationReference: "Organization/clinic-b", consentReference: "Consent/cons-ana-clinic-b", resourceReferences: ["Observation/obs-ana-1"], purposeOfUse: "TREAT", validUntil: "2026-08-30T23:59:59.000Z" } });
    expect(response).to.deep.equal({ status: 410, body: { error: "LEGACY_PATIENT_SHARE_ROUTE_DISABLED" } });
    expect(calls).to.deep.equal([]);
  });

  it("retires generic administrative routes before invoking legacy services", async function () {
    const calls: string[] = [];
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService()
    }, { bootstrapEnabled: true });

    const requests: ApiRequest[] = [
      { method: "POST", path: "/consents/register", body: { consentReference: "Consent/legacy" } },
      { method: "POST", path: "/consents/revoke", body: { consentReference: "Consent/legacy" } },
      { method: "POST", path: "/resources/register-hash", body: { resourceReference: "Observation/legacy" } },
      { method: "POST", path: "/manifests/publish", body: { vaultId: "vault:hospital-a", custodianOrganizationReference: "Organization/hospital-a", resourceReference: "Observation/legacy" } },
      { method: "GET", path: "/manifests/legacy" },
      { method: "POST", path: "/manifests/revoke", body: { manifestId: "manifest:legacy" } },
      { method: "POST", path: "/policies/register", body: { resourceType: "Observation", action: "read", purpose: "TREAT" } },
      { method: "POST", path: "/setup/demo/participants" },
      { method: "POST", path: "/setup/demo/policy" }
    ];

    for (const request of requests) {
      const response = await api.handle(withAdministrator(request));
      expect(response).to.deep.equal({
        status: 410,
        body: { error: "LEGACY_ADMIN_ROUTE_DISABLED" }
      });
    }
    expect(calls).to.deep.equal([]);
  });

  it("maps unsupported policy and registration conflict codes to stable 4xx responses", async function () {
    const errors = [
      "UNSUPPORTED_RESOURCE_TYPE",
      "UNSUPPORTED_ACTION",
      "UNSUPPORTED_POLICY_SCOPE",
      "UNSUPPORTED_PURPOSE",
      "NETWORK_POLICY_VERSION_ALREADY_REGISTERED",
      "NETWORK_POLICY_DEFINITION_CONFLICT",
      "POLICY_VERSION_ALREADY_EXISTS",
      "CONSENT_VERSION_ALREADY_EXISTS"
    ];
    for (const errorCode of errors) {
      const api = createHealthAccessApi({
        fhirClient: fakeFhirClient(),
        accessService: fakeAccessService(200),
        adminService: fakeAdminService(),
        patientConsents: {
          create: async () => { throw new Error(errorCode); },
          revoke: async () => ({ status: "revoked" })
        }
      });
      const response = await api.handle({
        method: "POST",
        path: "/patient/consents",
        principal: { kind: "patient", sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: `jti-${errorCode}` },
        idempotencyKey: `consent-${errorCode}`,
        body: { granteeOrganizationReference: "Organization/clinic-b", resourceReference: "Observation/obs-ana-1", purposeOfUse: "TREAT", policyId: "POLICY_TREATMENT_OBSERVATION", policyVersion: 1, validUntil: "2026-08-30T23:59:59.000Z" }
      });
      expect(response.status).to.be.oneOf([400, 409]);
      expect(response.body).to.deep.equal({ error: errorCode });
    }
  });

  it("maps lease loss and FHIR patient identity failures to stable client errors", async function () {
    const cases = [
      { errorCode: "CONSENT_OPERATION_LEASE_LOST", expectedStatus: 409 },
      { errorCode: "FHIR_RESOURCE_PATIENT_MISMATCH", expectedStatus: 400 }
    ];
    for (const testCase of cases) {
      const api = createHealthAccessApi({
        fhirClient: fakeFhirClient(),
        accessService: fakeAccessService(200),
        adminService: fakeAdminService(),
        patientConsents: {
          create: async () => { throw new Error(testCase.errorCode); },
          revoke: async () => ({ status: "revoked" })
        }
      });
      const response = await api.handle({
        method: "POST",
        path: "/patient/consents",
        principal: { kind: "patient", sub: "patient", patientReference: "Patient/ana", issuer: "issuer", audience: ["aud"], exp: 1_900_000_000, jti: `jti-${testCase.errorCode}` },
        idempotencyKey: `consent-${testCase.errorCode}`,
        body: { granteeOrganizationReference: "Organization/clinic-b", resourceReference: "Observation/obs-ana-1", purposeOfUse: "TREAT", policyId: "POLICY_TREATMENT_OBSERVATION", policyVersion: 1, validUntil: "2026-08-30T23:59:59.000Z" }
      });
      expect(response).to.deep.equal({ status: testCase.expectedStatus, body: { error: testCase.errorCode } });
    }
  });
  it("maps expired or revoked shares to a fail-closed authorization denial", async function () {
    for (const errorCode of ["SHARE_NOT_ACTIVE", "SHARE_OUTSIDE_VALIDITY_PERIOD"]) {
      const api = createHealthAccessApi({
        fhirClient: fakeFhirClient(),
        accessService: fakeAccessService(200),
        adminService: fakeAdminService(),
        interfhir: { redeemHandoff: async () => ({}), getShare: async () => ({}), readShare: async () => { throw new Error(errorCode); } }
      });
      const principal = { kind: "service" as const, clientId: "clinic-b", organizationReference: "Organization/clinic-b", practitionerReference: "Practitioner/bruno", purposeOfUse: ["TREAT"], certificateThumbprint: "cert", assertionHash: "hash", exp: 1_900_000_000, jti: `jti-${errorCode}` };
      const certificateIdentity = { fingerprint256: "fingerprint", x5tS256: "cert", subjectOrganization: "Organization/clinic-b", serialNumber: "1", validFrom: "2027-01-01T00:00:00.000Z", validTo: "2027-12-31T00:00:00.000Z" };
      const response = await api.handle({ method: "POST", path: "/interfhir/v1/access/read", body: { shareId: "share_1", manifestId: "manifest_1", operation: "read", purposeOfUse: "TREAT", requestId: "req_11111111-1111-4111-8111-111111111111" }, principal, certificateIdentity });
      expect(response).to.deep.equal({ status: 403, body: { error: errorCode } });
    }
  });
  it("uses only the verified institutional principal and matching mTLS certificate for B2B redemption", async function () {
    const calls: unknown[] = [];
    const api = createHealthAccessApi({ fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService(), interfhir: { redeemHandoff: async (input) => { calls.push(input); return { shareId: "share_1" }; }, getShare: async () => ({ shareId: "share_1" }), readShare: async () => ({}) } }, { now: () => 1_800_000_000 });
    const principal = { kind: "service" as const, clientId: "clinic-b", organizationReference: "Organization/clinic-b", practitionerReference: "Practitioner/bruno", purposeOfUse: ["TREAT"], certificateThumbprint: "cert", assertionHash: "hash", exp: 1_900_000_000, jti: "jti" };
    const certificateIdentity = { fingerprint256: "fingerprint", x5tS256: "cert", subjectOrganization: "Organization/clinic-b", serialNumber: "1", validFrom: "2027-01-01T00:00:00.000Z", validTo: "2027-12-31T00:00:00.000Z" };
    const response = await api.handle({ method: "POST", path: "/interfhir/v1/shares/redeem", body: { handoffCode: "handoff-code-123456", organizationReference: "Organization/attacker" }, principal, certificateIdentity });
    expect(response.status).to.equal(200);
    expect(calls).to.deep.equal([{ handoffCode: "handoff-code-123456", granteeOrganizationReference: "Organization/clinic-b", now: "2027-01-15T08:00:00.000Z" }]);
  });
  it("maps replay and temporary metadata-store failures to safe HTTP denials", async function () {
    const principal = { kind: "service" as const, clientId: "clinic-b", organizationReference: "Organization/clinic-b", practitionerReference: "Practitioner/bruno", purposeOfUse: ["TREAT"], certificateThumbprint: "cert", assertionHash: "hash", exp: 1_900_000_000, jti: "jti" };
    const certificateIdentity = { fingerprint256: "fingerprint", x5tS256: "cert", subjectOrganization: "Organization/clinic-b", serialNumber: "1", validFrom: "2027-01-01T00:00:00.000Z", validTo: "2027-12-31T00:00:00.000Z" };
    const request = { method: "POST" as const, path: "/interfhir/v1/access/read", body: { shareId: "share_1", manifestId: "manifest_1", operation: "read", purposeOfUse: "TREAT", requestId: "req_11111111-1111-4111-8111-111111111111" }, principal, certificateIdentity };
    const replayApi = createHealthAccessApi({ fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService(), interfhir: { redeemHandoff: async () => { throw new Error("HANDOFF_CODE_ALREADY_REDEEMED"); }, getShare: async () => ({}), readShare: async () => ({}) } });
    const unavailable = Object.assign(new Error("terminating connection due to administrator command"), { code: "57P01" });
    const unavailableApi = createHealthAccessApi({ fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService(), interfhir: { redeemHandoff: async () => ({}), getShare: async () => ({}), readShare: async () => { throw unavailable; } } });

    expect(await replayApi.handle({ ...request, path: "/interfhir/v1/shares/redeem", body: { handoffCode: "handoff-code-123456" } })).to.deep.equal({ status: 409, body: { error: "HANDOFF_CODE_ALREADY_REDEEMED" } });
    expect(await unavailableApi.handle(request)).to.deep.equal({ status: 503, body: { error: "METADATA_STORE_UNAVAILABLE" } });
  });
  it("rejects an interinstitutional purpose that was not granted in the UDAP access token", async function () {
    let reads = 0;
    const api = createHealthAccessApi({ fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService(), interfhir: { redeemHandoff: async () => ({}), getShare: async () => ({}), readShare: async () => { reads += 1; return {}; } } });
    const principal = { kind: "service" as const, clientId: "clinic-b", organizationReference: "Organization/clinic-b", practitionerReference: "Practitioner/bruno", purposeOfUse: ["TREAT"], certificateThumbprint: "cert", assertionHash: "hash", exp: 1_900_000_000, jti: "jti" };
    const certificateIdentity = { fingerprint256: "fingerprint", x5tS256: "cert", subjectOrganization: "Organization/clinic-b", serialNumber: "1", validFrom: "2027-01-01T00:00:00.000Z", validTo: "2027-12-31T00:00:00.000Z" };
    const response = await api.handle({ method: "POST", path: "/interfhir/v1/access/read", body: { shareId: "share_1", manifestId: "manifest_1", operation: "read", purposeOfUse: "RESEARCH", requestId: "req_11111111-1111-4111-8111-111111111111" }, principal, certificateIdentity });
    expect(response).to.deep.equal({ status: 403, body: { error: "UDAP_PURPOSE_NOT_ALLOWED" } });
    expect(reads).to.equal(0);
  });
  it("propagates the custodian access status instead of wrapping a denial in HTTP 200", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      interfhir: {
        redeemHandoff: async () => ({}),
        getShare: async () => ({}),
        readShare: async () => ({ status: 403, body: { error: "MANIFEST_RESOURCE_HASH_MISMATCH" } })
      }
    });
    const principal = { kind: "service" as const, clientId: "clinic-b", organizationReference: "Organization/clinic-b", practitionerReference: "Practitioner/bruno", purposeOfUse: ["TREAT"], certificateThumbprint: "cert", assertionHash: "hash", exp: 1_900_000_000, jti: "jti" };
    const certificateIdentity = { fingerprint256: "fingerprint", x5tS256: "cert", subjectOrganization: "Organization/clinic-b", serialNumber: "1", validFrom: "2027-01-01T00:00:00.000Z", validTo: "2027-12-31T00:00:00.000Z" };

    const response = await api.handle({
      method: "POST",
      path: "/interfhir/v1/access/read",
      body: { shareId: "share_1", manifestId: "manifest_1", operation: "read", purposeOfUse: "TREAT", requestId: "req_11111111-1111-4111-8111-111111111111" },
      principal,
      certificateIdentity
    });

    expect(response).to.deep.equal({ status: 403, body: { error: "MANIFEST_RESOURCE_HASH_MISMATCH" } });
  });
  it("looks up a share only through the verified grantee organization", async function () {
    const calls: unknown[] = [];
    const api = createHealthAccessApi({ fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService(), interfhir: { redeemHandoff: async () => ({}), getShare: async (input) => { calls.push(input); return { shareId: input.shareId }; }, readShare: async () => ({}) } }, { now: () => 1_800_000_000 });
    const principal = { kind: "service" as const, clientId: "clinic-b", organizationReference: "Organization/clinic-b", practitionerReference: "Practitioner/bruno", purposeOfUse: ["TREAT"], certificateThumbprint: "cert", assertionHash: "hash", exp: 1_900_000_000, jti: "jti" };
    const certificateIdentity = { fingerprint256: "fingerprint", x5tS256: "cert", subjectOrganization: "Organization/clinic-b", serialNumber: "1", validFrom: "2027-01-01T00:00:00.000Z", validTo: "2027-12-31T00:00:00.000Z" };
    const response = await api.handle({ method: "GET", path: "/interfhir/v1/shares/share_opaque", principal, certificateIdentity });
    expect(response.status).to.equal(200);
    expect(calls).to.deep.equal([{ shareId: "share_opaque", granteeOrganizationReference: "Organization/clinic-b", now: "2027-01-15T08:00:00.000Z" }]);
  });
  it("serves UDAP discovery and delegates registration and token requests", async function () {
    const calls: unknown[] = [];
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService(),
      udap: {
        discovery: { metadata: async () => ({ issuer: "https://hospital-a.local/udap" }) },
        registration: { register: async (body, certificate) => { calls.push({ body, certificate }); return { client_id: "clinic-b-gateway" }; } },
        token: { issue: async (body, certificate) => { calls.push({ body, certificate }); return { access_token: "token", token_type: "Bearer", expires_in: 300 }; } }
      }
    });
    expect(await api.handle({ method: "GET", path: "/fhir/.well-known/udap" })).to.deep.equal({ status: 200, body: { issuer: "https://hospital-a.local/udap" } });
    const certificateIdentity = { fingerprint256: "fingerprint", x5tS256: "thumbprint", subjectOrganization: "Organization/clinic-b", serialNumber: "1", validFrom: "2027-01-01T00:00:00.000Z", validTo: "2027-12-31T00:00:00.000Z" };
    expect((await api.handle({ method: "POST", path: "/udap/register", body: { software_statement: "signed" }, certificateIdentity })).status).to.equal(201);
    expect((await api.handle({ method: "POST", path: "/udap/token", body: { grant_type: "client_credentials", scope: "system/Observation.r", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: "assertion", udap: "1" }, certificateIdentity })).status).to.equal(200);
    expect(calls).to.have.length(2);
  });

  it("serves the configured public Hospital A issuer JWKS at the advertised URI", async function () {
    const publicJwk = {
      kty: "RSA",
      n: "uuIdiyLJPeUTW18sXl64a877fwlLnCYTZ9Kz-o01LMkZzbVYlYv1N60oXXTzCwemQqywPPXGnONsb9n8B4I8uFowcs4r3usp6XUug9oPaaw_qs7ojmhepAaHMG-b-YEc39pd2QAmligxFq1RjazbLt2YFzGr52UWkKz277317xqHZSLLRFfWudBUnvGnfkeeIm5MI-iJH5NMtyzNGO_ovYRza9vZQFKgCs288qCIKmkSRShelakTS20kSQMCzpHi_IqR0VWnzAqZY_hj227n1wyxSbs_feDhaioSToRM8f_TAlhNvmpXXSYmPcLhj3gzJplPF6n8P2RXwhLGfXNrHQ",
      e: "AQAB",
      kid: "hospital-a-udap-2026",
      alg: "RS256",
      use: "sig"
    };
    const issuerJwk = { ...publicJwk, privateLikeExtension: "must-not-be-served" };
    const issuerJwksUri = "https://hospital-a.local/.well-known/udap/jwks.json";
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      udap: {
        issuerJwksUri,
        issuerJwks: { keys: [issuerJwk] },
        discovery: { metadata: async () => ({ jwks_uri: issuerJwksUri }) },
        registration: { register: async () => ({ client_id: "clinic-b-gateway" }) },
        token: { issue: async () => ({ access_token: "token" }) }
      }
    });

    const response = await api.handle({ method: "GET", path: "/.well-known/udap/jwks.json" });

    expect(response).to.deep.equal({
      status: 200,
      headers: { "content-type": "application/json" },
      body: { keys: [publicJwk] }
    });
    expect(JSON.stringify(response.body)).not.to.match(/"(?:d|p|q|dp|dq|qi|k)"/);
  });

  it("fails closed when the issuer JWKS is absent, private or not configured", async function () {
    const base = { fhirClient: fakeFhirClient(), accessService: fakeAccessService(200), adminService: fakeAdminService() };
    const withoutUdap = createHealthAccessApi(base);
    expect(await withoutUdap.handle({ method: "GET", path: "/.well-known/udap/jwks.json" })).to.deep.equal({ status: 404, body: { error: "UDAP_NOT_CONFIGURED" } });

    const withoutJwks = createHealthAccessApi({
      ...base,
      udap: {
        issuerJwksUri: "https://hospital-a.local/.well-known/udap/jwks.json",
        discovery: { metadata: async () => ({}) },
        registration: { register: async () => ({}) },
        token: { issue: async () => ({}) }
      }
    });
    expect(await withoutJwks.handle({ method: "GET", path: "/.well-known/udap/jwks.json" })).to.deep.equal({ status: 503, body: { error: "UDAP_JWKS_UNAVAILABLE" } });

    const privateMaterial = createHealthAccessApi({
      ...base,
      udap: {
        issuerJwksUri: "https://hospital-a.local/.well-known/udap/jwks.json",
        issuerJwks: { keys: [{ kty: "RSA", n: "AQ", e: "AQAB", kid: "private", alg: "RS256", d: "private-material" }] },
        discovery: { metadata: async () => ({}) },
        registration: { register: async () => ({}) },
        token: { issue: async () => ({}) }
      }
    });
    expect(await privateMaterial.handle({ method: "GET", path: "/.well-known/udap/jwks.json" })).to.deep.equal({ status: 503, body: { error: "UDAP_JWKS_UNAVAILABLE" } });

    const rsaOthMaterial = createHealthAccessApi({
      ...base,
      udap: {
        issuerJwksUri: "https://hospital-a.local/.well-known/udap/jwks.json",
        issuerJwks: { keys: [{ kty: "RSA", n: "AQ", e: "AQAB", kid: "private", alg: "RS256", oth: [{ r: "private" }] }] },
        discovery: { metadata: async () => ({}) },
        registration: { register: async () => ({}) },
        token: { issue: async () => ({}) }
      }
    });
    expect(await rsaOthMaterial.handle({ method: "GET", path: "/.well-known/udap/jwks.json" })).to.deep.equal({ status: 503, body: { error: "UDAP_JWKS_UNAVAILABLE" } });
  });
  it("reports API and dependency health", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService()
    });

    const response = await api.handle({
      method: "GET",
      path: "/health"
    });

    expect(response.status).to.equal(200);
    expect(response.body).to.deep.equal({ status: "ok", fhir: "ok", blockchain: "ok" });
  });

  it("reports unavailable when the manifest metadata database is down", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      manifestRepository: {
        health: async () => false
      }
    } as unknown as Parameters<typeof createHealthAccessApi>[0]);

    const response = await api.handle({ method: "GET", path: "/health" });

    expect(response).to.deep.equal({
      status: 503,
      body: {
        status: "unavailable",
        fhir: "ok",
        blockchain: "ok",
        manifests: "unavailable"
      }
    });
  });

  it("maps a manifest database health exception to service unavailable", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService(),
      manifestRepository: {
        health: async () => {
          throw new Error("connect ECONNREFUSED");
        }
      }
    });

    const response = await api.handle({ method: "GET", path: "/health" });

    expect(response.status).to.equal(503);
    expect(response.body).to.deep.equal({
      status: "unavailable",
      fhir: "ok",
      blockchain: "ok",
      manifests: "unavailable"
    });
  });

  it("blocks direct FHIR resource routes", async function () {
    const createdResources: unknown[] = [];
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient({
        createResource: async (resource: Parameters<ApiFhirClient["createResource"]>[0]) => {
          createdResources.push(resource);
          return { ...resource, id: "obs-1" };
        }
      }),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService()
    });

    const created = await api.handle({
      method: "POST",
      path: "/fhir/Observation",
      body: observation()
    });
    const read = await api.handle({
      method: "GET",
      path: "/fhir/Observation/obs-1"
    });

    expect(created).to.deep.equal({
      status: 403,
      body: { error: "FHIR_DIRECT_ACCESS_BLOCKED" }
    });
    expect(read).to.deep.equal({
      status: 403,
      body: { error: "FHIR_DIRECT_ACCESS_BLOCKED" }
    });
    expect(createdResources).to.deep.equal([]);
  });

  it("disables the legacy direct read route without calling the access service", async function () {
    const requests: unknown[] = [];
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: {
        handleRead: async (request) => {
          requests.push(request);
          return { status: request.purposeOfUse === "TREAT" ? 200 : 403, body: { decision: request.purposeOfUse } };
        },
        handleReadByManifest: async () => ({ status: 200, body: { ok: true } })
      },
      adminService: fakeAdminService()
    });

    const response = await api.handle(
      withPractitioner({
        method: "POST",
        path: "/access/read",
        body: readBody("TREAT")
      })
    );

    expect(response).to.deep.equal({
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    });
    expect(requests).to.have.length(0);
  });

  it("retires the public manifest read route without invoking the access service", async function () {
    const calls: unknown[] = [];
    const api = createHealthAccessApi(
      {
        fhirClient: fakeFhirClient(),
        accessService: {
          handleRead: async () => ({ status: 200, body: observation() }),
          handleReadByManifest: async (request) => {
            calls.push(request);
            return { status: 200, body: { manifest: { manifestId: request.manifestId }, resource: observation() } };
          }
        },
        adminService: fakeAdminService()
      },
      {
        bootstrapEnabled: true,
        now: () => 1_800_000_000
      }
    );

    const read = await api.handle(
      withPractitioner({
        method: "POST",
        path: "/access/read-manifest",
        body: {
          manifestId: "manifest:vault:hospital-a:Observation/obs-1:v1",
          practitionerReference: "Practitioner/attacker",
          organizationReference: "Organization/attacker",
          purposeOfUse: "TREAT",
          requestTime: 1_800_000_000,
          recordedAt: "2027-01-15T10:00:00.000Z"
        }
      })
    );

    expect(read).to.deep.equal({
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    });
    expect(calls).to.deep.equal([]);
  });

  it("returns stable API errors for missing body fields and unknown routes", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService()
    });

    const invalid = await api.handle(
      withPractitioner({ method: "POST", path: "/access/read", body: {} })
    );
    const missing = await api.handle({ method: "GET", path: "/missing" });

    expect(invalid.status).to.equal(410);
    expect(invalid.body).to.deep.equal({ error: "LEGACY_READ_ROUTE_DISABLED" });
    expect(missing.status).to.equal(404);
    expect(missing.body).to.deep.equal({ error: "ROUTE_NOT_FOUND" });
  });

  it("retires manifest reads before validating an inactive manifest", async function () {
    const api = createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: {
        handleRead: async () => ({ status: 200, body: observation() }),
        handleReadByManifest: async () => {
          throw new Error("MANIFEST_NOT_ACTIVE");
        }
      },
      adminService: fakeAdminService()
    });

    const response = await api.handle(
      withPractitioner({
        method: "POST",
        path: "/access/read-manifest",
        body: {
          manifestId: "manifest:vault:hospital-a:Observation/obs-1:v1",
          purposeOfUse: "TREAT",
          recordedAt: "2027-01-15T10:00:00.000Z"
        }
      })
    );

    expect(response).to.deep.equal({
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    });
  });

  it("fails closed during API construction when the administrator institution is not configured", function () {
    expect(() => createHealthAccessApi({
      fhirClient: fakeFhirClient(),
      accessService: fakeAccessService(200),
      adminService: fakeAdminService({ institutionReference: undefined })
    })).to.throw("ADMIN_INSTITUTION_NOT_CONFIGURED");
  });

  it("rejects an API binding that differs from the admin service institution", function () {
    expect(() => createHealthAccessApi(
      {
        fhirClient: fakeFhirClient(),
        accessService: fakeAccessService(200),
        adminService: fakeAdminService()
      },
      { institutionReference: "Organization/clinic-b" }
    )).to.throw("ADMIN_INSTITUTION_MISMATCH");
  });

  it("rejects a blank admin-service binding even when API options provide an institution", function () {
    expect(() => createHealthAccessApi(
      {
        fhirClient: fakeFhirClient(),
        accessService: fakeAccessService(200),
        adminService: fakeAdminService({ institutionReference: " " })
      },
      { institutionReference: "Organization/hospital-a" }
    )).to.throw("ADMIN_INSTITUTION_NOT_CONFIGURED");
  });

});

function fakeFhirClient(overrides: Partial<ApiFhirClient> = {}): ApiFhirClient {
  return {
    readResource: async () => observation(),
    createResource: async (resource) => resource,
    createAuditEvent: async () => undefined,
    health: async () => true,
    ...overrides
  };
}

function fakeAccessService(status: number) {
  return {
    handleRead: async () => ({ status, body: status === 200 ? observation() : { error: "ACCESS_DENIED" } }),
    handleReadByManifest: async () => ({ status, body: status === 200 ? observation() : { error: "ACCESS_DENIED" } })
  };
}

function fakeAdminService(overrides: Partial<ApiAdminService> = {}): ApiAdminService {
  return {
    institutionReference: "Organization/hospital-a",
    health: async () => true,
    ...overrides
  };
}

function readBody(purposeOfUse: string) {
  return {
    resourceReference: "Observation/obs-1",
    patientReference: "Patient/maria",
    practitionerReference: "Practitioner/ana",
    organizationReference: "Organization/hospital-a",
    purposeOfUse,
    requestTime: 1_800_000_000,
    recordedAt: "2027-01-15T10:00:00.000Z"
  };
}

function withPractitioner(request: ApiRequest): ApiRequest {
  return {
    ...request,
    principal: {
      kind: "practitioner",
      sub: "local:practitioner-ana",
      practitionerReference: "Practitioner/ana",
      organizationReference: "Organization/hospital-a",
      roleCode: "legacy-local",
      specialtyCode: "legacy-local",
      issuer: "interfhir-local-test",
      audience: ["interfhir-api-test"],
      exp: 1_900_000_000,
      jti: "api-handler-test"
    }
  };
}

function withAdministrator(request: ApiRequest): ApiRequest {
  return {
    ...request,
    principal: {
      kind: "administrator",
      sub: "local:administrator",
      organizationReference: "Organization/hospital-a",
      issuer: "interfhir-local-test",
      audience: ["interfhir-api-test"],
      exp: 1_900_000_000,
      jti: "api-handler-admin-test"
    }
  };
}
