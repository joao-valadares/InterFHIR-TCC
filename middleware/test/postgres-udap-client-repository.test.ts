import { expect } from "chai";

import { createInMemoryUdapClientRepository } from "../src/udap/postgres-udap-client-repository.js";

describe("UDAP client repository", function () {
  it("stores only registered client metadata and atomically rejects a replayed assertion jti", async function () {
    const repository = createInMemoryUdapClientRepository();
    await repository.save({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b", certificateThumbprint: "thumbprint", jwks: [{ kty: "RSA", kid: "key-1" }], allowedScopes: ["system/Observation.r"] });
    expect(await repository.requireActive("clinic-b-gateway")).to.include({ clientId: "clinic-b-gateway", organizationReference: "Organization/clinic-b" });
    await repository.claimReplayJti("clinic-b-gateway", "assertion-1", new Date("2027-01-15T10:05:00.000Z"));
    await expectRejected(() => repository.claimReplayJti("clinic-b-gateway", "assertion-1", new Date("2027-01-15T10:05:00.000Z")), "UDAP_ASSERTION_REPLAY");
  });
});

async function expectRejected(action: () => Promise<unknown>, message: string) { try { await action(); expect.fail("Expected rejection"); } catch (error) { expect((error as Error).message).to.equal(message); } }
