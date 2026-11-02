import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { Contract, JsonRpcProvider, Wallet } from "ethers";

import {
  bootstrapInstitutionalState,
  type BootstrapPreflight
} from "./bootstrap-state.js";
import { POLICY_TREATMENT_OBSERVATION } from "../middleware/src/authorization/policy-definition.js";
import {
  readPatientAnaAddress,
  readPersistentDeployment,
  readPublicNetwork,
  verifyPersistentDeployment
} from "./read-deployment.js";

export { assertInstitutionRecordMatches, preflightInstitutionalBootstrap } from "./bootstrap-state.js";

if (process.argv.some((argument) => path.basename(argument) === "bootstrap-institutional-network.ts" || path.basename(argument) === "bootstrap-institutional-network.js")) {
  await main();
}

async function main(): Promise<void> {
  const deployment = readPersistentDeployment();
  const network = readPublicNetwork();

  const provider = new JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546");
  try {
    const patientAddress = readPatientAnaAddress(network);
    const verification = await verifyPersistentDeployment(provider, deployment, patientAddress);
    if (network.chainId !== deployment.chainId) throw new Error("BOOTSTRAP_NETWORK_DEPLOYMENT_MISMATCH");
    const deployer = new Wallet(await requiredDeployerKey(), provider);
    if ((await deployer.getAddress()).toLowerCase() !== verification.owner.toLowerCase()) {
      throw new Error("BOOTSTRAP_OWNER_MISMATCH");
    }

    const accessControl = new Contract(deployment.healthAccessControl, readArtifact("HealthAccessControl").abi, deployer);
    const institutionRegistry = new Contract(deployment.institutionRegistry, readArtifact("InstitutionRegistry").abi, deployer);
    const consentRegistry = new Contract(deployment.consentRegistry, readArtifact("ConsentRegistry").abi, deployer);
    const { preflight, writes } = await bootstrapInstitutionalState(
      accessControl,
      institutionRegistry,
      consentRegistry,
      network
    );

    console.log(JSON.stringify(bootstrapOutput(deployment.chainId, deployment.healthAccessControl, writes, preflight), null, 2));
  } finally {
    provider.destroy();
  }
}

function bootstrapOutput(
  chainId: number,
  contractAddress: string,
  writes: string[],
  preflight: BootstrapPreflight
) {
  return {
    status: writes.length === 0 ? "already_bootstrapped" : "bootstrapped",
    chainId,
    contractAddress,
    writes,
    participants: {
      patientAna: {
        reference: "Patient/pat-ana",
        address: preflight.patientAddress,
        controllerAuthorized: preflight.patientConsentController
      },
      institutions: preflight.institutions.map((institution) => ({
        organizationReference: institution.organizationReference,
        practitionerReference: institution.practitionerReference,
        organizationAccount: institution.configuration.organizationAccount,
        practitionerAccount: institution.configuration.practitionerAccount,
        gatewayAccount: institution.configuration.gatewayAccount,
        pepAuthorized: institution.pepAuthorized || institution.authorizePep
      }))
    },
    policy: {
      reference: "POLICY_TREATMENT_OBSERVATION@1",
      definitionHash: POLICY_TREATMENT_OBSERVATION.definitionHash
    }
  };
}

async function requiredDeployerKey(): Promise<string> {
  const configured = process.env.BLOCKCHAIN_DEPLOYER_PRIVATE_KEY;
  if (configured) return configured;
  return (await readFile(path.resolve(process.cwd(), ".local", "besu", "wallets", "deployer.key"), "utf8")).trim();
}

function readArtifact(name: string) {
  const artifactPath = path.resolve(process.cwd(), "artifacts", "contracts", `${name}.sol`, `${name}.json`);
  return JSON.parse(readFileSync(artifactPath, "utf8")) as { abi: ConstructorParameters<typeof Contract>[1] };
}
