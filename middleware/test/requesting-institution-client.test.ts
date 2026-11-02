import { expect } from "chai";

import {
  createRequestingInstitutionClient,
  type RequestingInstitutionTlsOptions
} from "../src/interfhir/requesting-institution-client.js";

describe("Clinic B requesting institution client", function () {
  const tls: RequestingInstitutionTlsOptions = { key: "clinic-key", cert: "clinic-cert", ca: "hospital-ca" };

  it("redeems a handoff through the Hospital A HTTPS endpoint with the UDAP bearer token and mTLS certificate", async function () {
    const calls: Array<{ url: string; init: { method: string; headers: Record<string, string>; body: string; tls: RequestingInstitutionTlsOptions } }> = [];
    const client = createRequestingInstitutionClient({
      custodianBaseUrl: "https://hospital-a.example.test/",
      tls,
      fetch: async (url, init) => {
        calls.push({ url, init });
        return jsonResponse(200, {
          shareId: "share_7f0e64e1-07bb-4e94-bfd4-a1b30a96ffd3",
          manifests: [{ manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc", resourceType: "Observation" }],
          validUntil: "2027-01-15T11:00:00.000Z"
        });
      }
    });

    const redeemed = await client.redeemHandoff({ handoffCode: "handoff-secret-from-patient", udapToken: "udap-access-token" });

    expect(redeemed).to.deep.equal({
      shareId: "share_7f0e64e1-07bb-4e94-bfd4-a1b30a96ffd3",
      manifests: [{ manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc", resourceType: "Observation" }],
      validUntil: "2027-01-15T11:00:00.000Z"
    });
    expect(calls).to.deep.equal([{
      url: "https://hospital-a.example.test/interfhir/v1/shares/redeem",
      init: {
        method: "POST",
        headers: { authorization: "Bearer udap-access-token", "content-type": "application/json" },
        body: JSON.stringify({ handoffCode: "handoff-secret-from-patient" }),
        tls
      }
    }]);
    expect(JSON.stringify(calls)).not.to.include("Consent/");
    expect(JSON.stringify(calls)).not.to.include("Observation/");
  });

  it("reads a redeemed share with only custodian-owned identifiers and mTLS", async function () {
    const calls: Array<{ url: string; init: { method: string; headers: Record<string, string>; body: string; tls: RequestingInstitutionTlsOptions } }> = [];
    const client = createRequestingInstitutionClient({
      custodianBaseUrl: "https://hospital-a.example.test",
      tls,
      fetch: async (url, init) => {
        calls.push({ url, init });
        return jsonResponse(200, {
          manifest: {
            manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc",
            shareId: "share_7f0e64e1-07bb-4e94-bfd4-a1b30a96ffd3",
            resourceReference: "Observation/obs-ana-1",
            fhirVersionId: "7",
            custodianOrganizationReference: "Organization/hospital-a"
          },
          resource: { resourceType: "Observation", id: "obs-ana-1", meta: { versionId: "7" } }
        });
      }
    });

    const result = await client.readShare({
      shareId: "share_7f0e64e1-07bb-4e94-bfd4-a1b30a96ffd3",
      manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc",
      resourceType: "Observation",
      purposeOfUse: "TREAT",
      requestId: "req_8f2f2f53-2dd4-4604-9d71-9a795767e468",
      udapToken: "udap-read-token"
    });

    expect(result).to.deep.equal({
      manifest: {
        manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc",
        shareId: "share_7f0e64e1-07bb-4e94-bfd4-a1b30a96ffd3",
        resourceReference: "Observation/obs-ana-1",
        fhirVersionId: "7",
        custodianOrganizationReference: "Organization/hospital-a"
      },
      resource: { resourceType: "Observation", id: "obs-ana-1", meta: { versionId: "7" } }
    });
    expect(calls[0]).to.deep.equal({
      url: "https://hospital-a.example.test/interfhir/v1/access/read",
      init: {
        method: "POST",
        headers: { authorization: "Bearer udap-read-token", "content-type": "application/json" },
        body: JSON.stringify({
          shareId: "share_7f0e64e1-07bb-4e94-bfd4-a1b30a96ffd3",
          manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc",
          operation: "read",
          purposeOfUse: "TREAT",
          requestId: "req_8f2f2f53-2dd4-4604-9d71-9a795767e468"
        }),
        tls
      }
    });
    expect(JSON.stringify(calls)).not.to.include("practitionerReference");
    expect(JSON.stringify(calls)).not.to.include("organizationReference");
    expect(JSON.stringify(calls)).not.to.include("consentReference");
    expect(JSON.stringify(calls)).not.to.include("resourceReference");
    expect(JSON.stringify(calls)).not.to.include("patientReference");
  });

  it("rejects malformed HTTP 200 read envelopes and inconsistent share or resource identities", async function () {
    const malformedBodies = [
      { resourceType: "Observation", id: "obs-ana-1" },
      {
        manifest: {
          manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc",
          shareId: "share_attacker",
          resourceReference: "Observation/obs-ana-1",
          fhirVersionId: "7",
          custodianOrganizationReference: "Organization/hospital-a"
        },
        resource: { resourceType: "DiagnosticReport", id: "obs-ana-1", meta: { versionId: "7" } }
      }
    ];

    for (const body of malformedBodies) {
      const client = createRequestingInstitutionClient({
        custodianBaseUrl: "https://hospital-a.example.test",
        tls,
        fetch: async () => jsonResponse(200, body)
      });
      await expectRejected(() => client.readShare({
        shareId: "share_7f0e64e1-07bb-4e94-bfd4-a1b30a96ffd3",
        manifestId: "manifest_5c4f15c2-513e-435f-babb-c40777fd49dc",
        resourceType: "Observation",
        purposeOfUse: "TREAT",
        requestId: "req_8f2f2f53-2dd4-4604-9d71-9a795767e468",
        udapToken: "udap-read-token"
      }), "REQUESTING_INSTITUTION_READ_RESPONSE_INVALID");
    }
  });

  it("fails closed for malformed redemption and denial responses containing clinical payload", async function () {
    const malformed = createRequestingInstitutionClient({
      custodianBaseUrl: "https://hospital-a.example.test",
      tls,
      fetch: async () => jsonResponse(200, { shareId: "share_1", manifests: [{ manifestId: "manifest_1" }] })
    });
    await expectRejected(() => malformed.redeemHandoff({ handoffCode: "handoff", udapToken: "token" }), "REQUESTING_INSTITUTION_REDEEM_RESPONSE_INVALID");

    const denied = createRequestingInstitutionClient({
      custodianBaseUrl: "https://hospital-a.example.test",
      tls,
      fetch: async () => jsonResponse(403, { error: "MANIFEST_INVALID", resource: { resourceType: "Observation" } })
    });
    await expectRejected(() => denied.redeemHandoff({ handoffCode: "handoff", udapToken: "token" }), "REQUESTING_INSTITUTION_DENIAL_CONTAINS_CLINICAL_PAYLOAD");
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
