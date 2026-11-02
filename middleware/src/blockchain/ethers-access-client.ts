import { Interface } from "ethers";
import type { AccessRequestDto } from "../abac/attribute-mapper.js";

export interface InstitutionalAccessRequestDto extends AccessRequestDto {
  shareIdHash: string;
  manifestIdHash: string;
  consentIdHash: string;
  consentProjectionHash: string;
  assertionHash: string;
}

export interface PatientConsentInputDto {
  consentIdHash: string;
  consentProjectionHash: string;
  patientHash: string;
  actorConstraintHash: string;
  granteeOrganizationHash: string;
  resourceIdHash: string;
  policyIdHash: string;
  policyVersion: number;
  consentVersion: number;
  resourceTypeCode: number;
  actionCode: number;
  purposeCode: number;
  validFrom: number;
  validUntil: number;
  policyMask: number;
}

interface TransactionResponse {
  hash: string;
  wait(): Promise<unknown>;
}

type ContractMethod<TArgs extends readonly unknown[], TResult> = ((...args: TArgs) => Promise<TransactionResponse>) & {
  staticCall(...args: TArgs): Promise<TResult>;
};

type TransactionMethod<TArgs extends readonly unknown[]> = (...args: TArgs) => Promise<TransactionResponse>;

interface HealthAccessContract {
  computeRequestHash(request: AccessRequestDto, requesterAddress: string): Promise<string>;
  requestAccess: ContractMethod<[AccessRequestDto], boolean>;
  verifyAccess: ContractMethod<[AccessRequestDto, number], boolean>;
  computeInstitutionalRequestHash?: (request: InstitutionalAccessRequestDto, pepAddress: string) => Promise<string>;
  requestInstitutionalAccess?: ContractMethod<[InstitutionalAccessRequestDto], readonly [boolean, bigint]>;
  verifyInstitutionalAccess?: ContractMethod<[InstitutionalAccessRequestDto, number], boolean>;
  finalizeEnforcement?: TransactionMethod<[string, boolean, number]>;
  registerPatientConsent?: TransactionMethod<[PatientConsentInputDto]>;
  revokePatientConsent?: TransactionMethod<[string, number]>;
  supersedePatientConsent?: TransactionMethod<[PatientConsentInputDto, number]>;
}

interface EthersAccessClientOptions {
  requesterAddress: string;
  contract: HealthAccessContract;
}

export function createEthersAccessClient(options: EthersAccessClientOptions) {
  return {
    async requestAccess(request: AccessRequestDto) {
      const granted = await options.contract.requestAccess.staticCall(request);
      const transaction = await options.contract.requestAccess(request);
      await transaction.wait();
      const requestHash = await options.contract.computeRequestHash(request, options.requesterAddress);

      return {
        granted,
        requestHash,
        transactionHash: transaction.hash
      };
    },

    async verifyAccess(request: AccessRequestDto, verificationTime: number) {
      const verified = await options.contract.verifyAccess.staticCall(request, verificationTime);
      if (!verified) {
        return false;
      }

      const transaction = await options.contract.verifyAccess(request, verificationTime);
      await transaction.wait();
      return true;
    },

    async requestInstitutionalAccess(request: InstitutionalAccessRequestDto) {
      const method = requireInstitutionalMethod(options.contract.requestInstitutionalAccess);
      await method.staticCall(request);
      const transaction = await method(request);
      const receipt = requireSuccessfulReceipt(await transaction.wait());
      const event = receipt.logs.map(log => { try { return decisionInterface.parseLog(log); } catch { return null; } }).find(event => event?.name === "AccessDecisionRecorded" && String(event.args.requester).toLowerCase() === options.requesterAddress.toLowerCase() && event.args.patientHash === request.patientHash && event.args.resourceIdHash === request.resourceIdHash);
      const requestHash = await requireInstitutionalMethod(
        options.contract.computeInstitutionalRequestHash
      )(request, options.requesterAddress);
      return {
        granted: event?.args.granted === true,
        requestHash,
        transactionHash: transaction.hash,
        decisionId: event?.args.decisionId ?? 0n
      };
    },

    async verifyInstitutionalAccess(request: InstitutionalAccessRequestDto, verificationTime: number) {
      const method = requireInstitutionalMethod(options.contract.verifyInstitutionalAccess);
      if (!(await method.staticCall(request, verificationTime))) {
        return false;
      }
      const transaction = await method(request, verificationTime);
      requireSuccessfulReceipt(await transaction.wait());
      return method.staticCall(request, verificationTime);
    },

    async finalizeEnforcement(requestHash: string, delivered: boolean, reasonCode: number) {
      const method = requireTransactionMethod(options.contract.finalizeEnforcement);
      const transaction = await method(requestHash, delivered, reasonCode);
      requireSuccessfulReceipt(await transaction.wait());
      return transaction.hash;
    },

    async registerPatientConsent(input: PatientConsentInputDto) {
      const method = requireTransactionMethod(options.contract.registerPatientConsent);
      const transaction = await method(input);
      await transaction.wait();
      return transaction.hash;
    },

    async revokePatientConsent(consentIdHash: string, consentVersion: number) {
      const method = requireTransactionMethod(options.contract.revokePatientConsent);
      const transaction = await method(consentIdHash, consentVersion);
      await transaction.wait();
      return transaction.hash;
    },

    async supersedePatientConsent(input: PatientConsentInputDto, previousConsentVersion: number) {
      const method = requireTransactionMethod(options.contract.supersedePatientConsent);
      const transaction = await method(input, previousConsentVersion);
      await transaction.wait();
      return transaction.hash;
    }
  };
}

function requireInstitutionalMethod<T>(method: T | undefined): T {
  if (!method) {
    throw new Error("INSTITUTIONAL_PEP_CONTRACT_METHOD_NOT_CONFIGURED");
  }
  return method;
}

function requireTransactionMethod<T>(method: T | undefined): T {
  if (!method) {
    throw new Error("BLOCKCHAIN_CONTRACT_METHOD_NOT_CONFIGURED");
  }
  return method;
}

const decisionInterface = new Interface(["event AccessDecisionRecorded(uint256 indexed decisionId, address indexed requester, bytes32 indexed patientHash, bytes32 actorHash, bytes32 resourceIdHash, bytes32 resourceHash, bytes32 policyId, bool granted, uint8 reasonCode)"]);
function requireSuccessfulReceipt(value: unknown): { status: number; logs: Array<{ topics: readonly string[]; data: string }> } {
  if (!value || typeof value !== "object" || !("status" in value) || value.status !== 1 || !("logs" in value) || !Array.isArray(value.logs)) throw new Error("BLOCKCHAIN_RECEIPT_UNCONFIRMED");
  return value as { status: number; logs: Array<{ topics: readonly string[]; data: string }> };
}
