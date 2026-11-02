import { readFile } from "node:fs/promises";
import path from "node:path";
import { Contract, JsonRpcProvider, Wallet, id } from "ethers";
import { readPersistentDeployment } from "../read-deployment.js";
import { VARIATION_POLICIES, VARIATION_PRACTITIONERS } from "./policy-variation-fixtures.js";
import { mapActionCode, mapPurposeCode, mapResourceTypeCode } from "../../middleware/src/abac/policy-mask.js";

const provider = new JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546");
try {
  const deployment = readPersistentDeployment();
  const key = (await readFile(path.resolve(".local/besu/wallets/deployer.key"), "utf8")).trim();
  const owner = new Wallet(key, provider);
  const artifact = JSON.parse(await readFile("artifacts/contracts/HealthAccessControl.sol/HealthAccessControl.json", "utf8"));
  const contract = new Contract(deployment.healthAccessControl, artifact.abi, owner);
  if ((await contract.owner()).toLowerCase() !== owner.address.toLowerCase()) throw new Error("E2E_POLICY_FIXTURE_OWNER_MISMATCH");
  for (const practitioner of VARIATION_PRACTITIONERS) {
    await (await contract.registerPractitioner(practitioner.account, id(practitioner.reference), id("Organization/clinic-b"), practitioner.roleCode, practitioner.specialtyCode, true)).wait();
  }
  for (const policy of VARIATION_POLICIES) {
    const input = {
      policyId: id(policy.policyId), version: policy.version, definitionHash: policy.definitionHash,
      resourceTypeCode: mapResourceTypeCode(policy.resourceType), actionCode: mapActionCode(policy.action), purposeCode: mapPurposeCode(policy.purpose),
      requiredMask: policy.requiredAttributes, requiredRoleCode: policy.requiredRoleCode ?? 0, requiredSpecialtyCode: policy.requiredSpecialtyCode ?? 0,
      effectiveFrom: Math.floor(Date.parse(policy.effectiveFrom) / 1000), effectiveUntil: 0, active: true
    };
    const stored = await contract.getActivePolicy(input.policyId, input.version);
    if (stored.policyId === "0x" + "0".repeat(64)) await (await contract.createPolicyVersion(input)).wait();
    const actual = await contract.getActivePolicy(input.policyId, input.version);
    for (const [field, expected] of Object.entries(input)) {
      if (String(actual[field]).toLowerCase() !== String(expected).toLowerCase()) throw new Error(`E2E_POLICY_FIXTURE_DIVERGENCE:${field}`);
    }
  }
  console.log(JSON.stringify({ status: "e2e-policy-fixtures-ready", policyIds: VARIATION_POLICIES.map(p => p.policyId), practitioners: VARIATION_PRACTITIONERS.length }));
} finally {
  provider.destroy();
}
