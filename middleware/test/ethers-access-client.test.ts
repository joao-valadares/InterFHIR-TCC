import { Interface } from "ethers";
import { expect } from "chai";

import { createEthersAccessClient } from "../src/blockchain/ethers-access-client.js";
import type { AccessRequestDto } from "../src/abac/attribute-mapper.js";

const accessRequest: AccessRequestDto = {
  patientHash: "0x" + "01".repeat(32),
  actorHash: "0x" + "02".repeat(32),
  organizationHash: "0x" + "03".repeat(32),
  resourceIdHash: "0x" + "04".repeat(32),
  resourceHash: "0x" + "05".repeat(32),
  resourceTypeCode: 1,
  actionCode: 1,
  purposeCode: 1,
  attributesMask: 3839,
  requestTime: 1_800_000_000
};

describe("ethers access client", function () {
  it("simulates access before sending the transaction and returns request metadata", async function () {
    const calls: string[] = [];
    const client = createEthersAccessClient({
      requesterAddress: "0x0000000000000000000000000000000000000001",
      contract: {
        computeRequestHash: async () => "0xabc",
        requestAccess: Object.assign(
          async () => {
            calls.push("tx");
            return { hash: "0xdef", wait: async () => undefined };
          },
          {
            staticCall: async () => {
              calls.push("static");
              return true;
            }
          }
        ),
        verifyAccess: Object.assign(async () => ({ hash: "0xverify", wait: async () => undefined }), {
          staticCall: async () => true
        })
      }
    });

    const decision = await client.requestAccess(accessRequest);

    expect(calls).to.deep.equal(["static", "tx"]);
    expect(decision).to.deep.equal({ granted: true, requestHash: "0xabc", transactionHash: "0xdef" });
  });

  it("uses static verification before emitting the verification transaction", async function () {
    const calls: Array<{ kind: string; verificationTime?: number }> = [];
    const client = createEthersAccessClient({
      requesterAddress: "0x0000000000000000000000000000000000000001",
      contract: {
        computeRequestHash: async () => "0xabc",
        requestAccess: Object.assign(async () => ({ hash: "0xdef", wait: async () => undefined }), {
          staticCall: async () => true
        }),
        verifyAccess: Object.assign(
          async (_request: AccessRequestDto, verificationTime: number) => {
            calls.push({ kind: "tx", verificationTime });
            return { hash: "0xverify", wait: async () => undefined };
          },
          {
            staticCall: async (_request: AccessRequestDto, verificationTime: number) => {
              calls.push({ kind: "static", verificationTime });
              return true;
            }
          }
        )
      }
    });

    const verified = await client.verifyAccess(accessRequest, 1_800_000_120);

    expect(verified).to.equal(true);
    expect(calls).to.deep.equal([
      { kind: "static", verificationTime: 1_800_000_120 },
      { kind: "tx", verificationTime: 1_800_000_120 }
    ]);
  });

  it("submits an institutional PEP decision and finalizes its enforcement", async function () {
    const calls: string[] = [];
    const eventInterface = new Interface(["event AccessDecisionRecorded(uint256 indexed decisionId, address indexed requester, bytes32 indexed patientHash, bytes32 actorHash, bytes32 resourceIdHash, bytes32 resourceHash, bytes32 policyId, bool granted, uint8 reasonCode)"]);
    const log = eventInterface.encodeEventLog(eventInterface.getEvent("AccessDecisionRecorded")!, [7n, "0x0000000000000000000000000000000000000001", accessRequest.patientHash, accessRequest.actorHash, accessRequest.resourceIdHash, accessRequest.resourceHash, "0x" + "00".repeat(32), true, 1]);
    const client = createEthersAccessClient({
      requesterAddress: "0x0000000000000000000000000000000000000001",
      contract: {
        computeRequestHash: async () => "0xlegacy",
        requestAccess: Object.assign(async () => ({ hash: "0xlegacy", wait: async () => undefined }), { staticCall: async () => true }),
        verifyAccess: Object.assign(async () => ({ hash: "0xlegacy", wait: async () => undefined }), { staticCall: async () => true }),
        computeInstitutionalRequestHash: async () => "0xinstitutional",
        requestInstitutionalAccess: Object.assign(
          async () => { calls.push("tx"); return { hash: "0xtx", wait: async () => ({ status: 1, logs: [log] }) }; },
          { staticCall: async () => { calls.push("static"); return [true, 7n] as const; } }
        ),
        verifyInstitutionalAccess: Object.assign(async () => ({ hash: "0xverify", wait: async () => undefined }), { staticCall: async () => true }),
        finalizeEnforcement: async () => ({ hash: "0xfinal", wait: async () => ({ status: 1, logs: [] }) })
      }
    });
    const request = { ...accessRequest, shareIdHash: "0x" + "06".repeat(32), manifestIdHash: "0x" + "07".repeat(32), consentIdHash: "0x" + "08".repeat(32), consentProjectionHash: "0x" + "09".repeat(32), assertionHash: "0x" + "0a".repeat(32) };

    const decision = await client.requestInstitutionalAccess(request);
    const finalization = await client.finalizeEnforcement(decision.requestHash, true, 1);

    expect(calls).to.deep.equal(["static", "tx"]);
    expect(decision).to.deep.equal({ granted: true, requestHash: "0xinstitutional", transactionHash: "0xtx", decisionId: 7n });
    expect(finalization).to.equal("0xfinal");
  });

  it("anchors and versions patient Consent operations through the blockchain client", async function () {
    const calls: string[] = [];
    const consent = {
      consentIdHash: "0x" + "08".repeat(32),
      consentProjectionHash: "0x" + "09".repeat(32),
      patientHash: accessRequest.patientHash,
      actorConstraintHash: "0x" + "00".repeat(32),
      granteeOrganizationHash: accessRequest.organizationHash,
      resourceIdHash: accessRequest.resourceIdHash,
      policyIdHash: "0x" + "0a".repeat(32),
      policyVersion: 1,
      consentVersion: 1,
      resourceTypeCode: accessRequest.resourceTypeCode,
      actionCode: accessRequest.actionCode,
      purposeCode: accessRequest.purposeCode,
      validFrom: 1_800_000_000,
      validUntil: 1_800_003_600,
      policyMask: accessRequest.attributesMask
    };
    const client = createEthersAccessClient({
      requesterAddress: "0x0000000000000000000000000000000000000001",
      contract: {
        computeRequestHash: async () => "0xlegacy",
        requestAccess: Object.assign(async () => ({ hash: "0xlegacy", wait: async () => undefined }), { staticCall: async () => true }),
        verifyAccess: Object.assign(async () => ({ hash: "0xlegacy", wait: async () => undefined }), { staticCall: async () => true }),
        registerPatientConsent: async () => { calls.push("register"); return { hash: "0xregister", wait: async () => undefined }; },
        revokePatientConsent: async () => { calls.push("revoke"); return { hash: "0xrevoke", wait: async () => undefined }; },
        supersedePatientConsent: async () => { calls.push("supersede"); return { hash: "0xsupersede", wait: async () => undefined }; }
      }
    });

    expect(await client.registerPatientConsent(consent)).to.equal("0xregister");
    expect(await client.revokePatientConsent(consent.consentIdHash, 1)).to.equal("0xrevoke");
    expect(await client.supersedePatientConsent(consent, 1)).to.equal("0xsupersede");
    expect(calls).to.deep.equal(["register", "revoke", "supersede"]);
  });
});
