import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { Contract, ContractFactory, JsonRpcProvider, Wallet } from "ethers";

import {
  deploymentFilePath,
  readPatientAnaAddress,
  readPersistentDeployment,
  readPublicNetwork,
  sanitizeDeployment,
  verifyPersistentDeployment,
  writePersistentDeployment,
  type PersistentDeployment
} from "./read-deployment.js";

if (process.argv.some((argument) => path.basename(argument) === "deploy-json-rpc.ts" || path.basename(argument) === "deploy-json-rpc.js")) {
  await main();
}

async function main(): Promise<void> {
  const provider = new JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546");
  const deploymentPath = deploymentFilePath();
  try {
    const patientAddress = readPatientAnaAddress(readPublicNetwork());
    if (await fileExists(deploymentPath)) {
      const deployment = readPersistentDeployment(deploymentPath);
      try {
        await verifyPersistentDeployment(provider, deployment, patientAddress);
        console.log(JSON.stringify({ status: "existing", ...sanitizeDeployment(deployment) }, null, 2));
        return;
      } catch (error) {
        if (!shouldRedeployStaleDeployment(error)) throw error;

        const deployerKey = await configuredOrLocalKey("BLOCKCHAIN_DEPLOYER_PRIVATE_KEY", path.join("wallets", "deployer.key"));
        const deployer = new Wallet(deployerKey, provider);
        const redeployed = await deployAll(deployer, patientAddress);
        await writePersistentDeployment(redeployed, deploymentPath);
        console.log(JSON.stringify({ status: "redeployed", ...sanitizeDeployment(redeployed) }, null, 2));
        return;
      }
    }

    const deployerKey = await configuredOrLocalKey("BLOCKCHAIN_DEPLOYER_PRIVATE_KEY", path.join("wallets", "deployer.key"));
    const deployer = new Wallet(deployerKey, provider);
    const deployment = await deployAll(deployer, patientAddress);
    await writePersistentDeployment(deployment, deploymentPath);
    console.log(JSON.stringify({ status: "deployed", ...sanitizeDeployment(deployment) }, null, 2));
  } finally {
    provider.destroy();
  }
}

export function shouldRedeployStaleDeployment(error: unknown, env: NodeJS.ProcessEnv = process.env): boolean {
  if (env.E2E_ALLOW_STALE_DEPLOYMENT_REDEPLOY !== "true") return false;
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  return /^DEPLOYMENT_CONTRACT_CODE_MISSING:[^:\s]+$/.test(message);
}

export async function deployAll(deployer: Wallet, patientAddress: string): Promise<PersistentDeployment> {
  const attributeRegistry = await deploy("AttributeRegistry", deployer);
  const consentRegistry = await deploy("ConsentRegistry", deployer);
  const auditRegistry = await deploy("AuditRegistry", deployer);
  const resourceRegistry = await deploy("ResourceRegistry", deployer);
  const healthAccessControl = await deploy("HealthAccessControl", deployer, [
    await attributeRegistry.getAddress(),
    await consentRegistry.getAddress(),
    await auditRegistry.getAddress(),
    await resourceRegistry.getAddress()
  ]);
  const healthAccessControlAddress = await healthAccessControl.getAddress();

  // ConsentRegistry is still owned by the deployer at this point. Register Ana
  // before handing registry writes to HealthAccessControl.
  await (await consentRegistry.getFunction("authorizePatientConsentController")(patientAddress, true)).wait();
  await (await attributeRegistry.getFunction("transferOwnership")(healthAccessControlAddress)).wait();
  await (await resourceRegistry.getFunction("transferOwnership")(healthAccessControlAddress)).wait();
  await (await consentRegistry.getFunction("authorizeWriter")(healthAccessControlAddress, true)).wait();
  await (await consentRegistry.getFunction("authorizePatientConsentController")(healthAccessControlAddress, true)).wait();
  await (await auditRegistry.getFunction("authorizeWriter")(healthAccessControlAddress, true)).wait();

  const institutionRegistry = String(await healthAccessControl.getFunction("institutionRegistry")());
  const network = await deployer.provider!.getNetwork();
  const deployment: PersistentDeployment = {
    schemaVersion: 1,
    chainId: Number(network.chainId),
    blockNumber: await deployer.provider!.getBlockNumber(),
    deployer: await deployer.getAddress(),
    attributeRegistry: await attributeRegistry.getAddress(),
    consentRegistry: await consentRegistry.getAddress(),
    auditRegistry: await auditRegistry.getAddress(),
    resourceRegistry: await resourceRegistry.getAddress(),
    institutionRegistry,
    healthAccessControl: healthAccessControlAddress
  };
  await verifyPersistentDeployment(deployer.provider as JsonRpcProvider, deployment, patientAddress);
  return deployment;
}

async function deploy(name: string, deployer: Wallet, args: unknown[] = []): Promise<Contract> {
  const artifact = readArtifact(name);
  const factory = new ContractFactory(artifact.abi, artifact.bytecode, deployer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract as unknown as Contract;
}

function readArtifact(name: string) {
  const artifactPath = path.resolve(
    process.cwd(),
    "artifacts",
    "contracts",
    `${name}.sol`,
    `${name}.json`
  );
  return JSON.parse(readFileSync(artifactPath, "utf8")) as {
    abi: ConstructorParameters<typeof ContractFactory>[0];
    bytecode: ConstructorParameters<typeof ContractFactory>[1];
  };
}

async function configuredOrLocalKey(environmentName: string, localRelativePath: string): Promise<string> {
  const configured = process.env[environmentName];
  if (configured) return configured;
  const localPath = path.resolve(process.cwd(), ".local", "besu", localRelativePath);
  return (await readFile(localPath, "utf8")).trim();
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await readFile(filePath);
    return true;
  } catch {
    return false;
  }
}
