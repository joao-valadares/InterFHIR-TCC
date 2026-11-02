import { readFileSync } from "node:fs";
import path from "node:path";

import {
  Contract,
  JsonRpcProvider,
  Wallet,
  type ContractRunner,
  type JsonRpcSigner
} from "ethers";
import {
  readPersistentDeployment,
  tryReadPersistentDeployment,
  verifyPersistentDeployment,
  type PersistentDeployment
} from "./read-deployment.js";

export { readPersistentDeployment } from "./read-deployment.js";

interface ConfiguredContractRuntimeOptions {
  blockchainRpcUrl: string;
  healthAccessControlAddress?: string;
  deploymentPath?: string;
  allowEphemeralDeployment: boolean;
  blockchainWallets?: {
    deployerPrivateKey: string;
    patientPrivateKey: string;
    practitionerPrivateKey: string;
    organizationPrivateKey: string;
    pepPrivateKey: string;
  };
}

interface AddressedSigner extends ContractRunner {
  address: string;
}

export interface ContractRuntime {
  mode: "configured-json-rpc" | "ephemeral-hardhat";
  deployment: {
    deployer: string;
    attributeRegistry: string;
    consentRegistry: string;
    auditRegistry: string;
    resourceRegistry: string;
    institutionRegistry: string;
    healthAccessControl: string;
  };
  accessControl: Contract;
  patientSigner: AddressedSigner;
  practitionerSigner: AddressedSigner;
  organizationSigner: AddressedSigner;
  pepSigner: AddressedSigner;
  close(): void;
}

export interface CanonicalRuntimeDependencies {
  manifestSigningConfigured: boolean;
  patientConsentServiceConfigured: boolean;
  directedAccessConfigured: boolean;
  interfhirConfigured: boolean;
}

/**
 * Production startup must never expose the API without every official
 * patient-consent and institutional-interoperability dependency.
 * Test factories intentionally do not call this entrypoint guard.
 */
export function assertCanonicalRuntimeDependencies(
  dependencies: CanonicalRuntimeDependencies
) {
  const missing = [
    ["manifestSigning", dependencies.manifestSigningConfigured],
    ["patientConsents", dependencies.patientConsentServiceConfigured],
    ["directedAccess", dependencies.directedAccessConfigured],
    ["interfhir", dependencies.interfhirConfigured]
  ]
    .filter(([, configured]) => !configured)
    .map(([name]) => name);
  if (missing.length > 0) {
    throw new Error(`CANONICAL_RUNTIME_INCOMPLETE:${missing.join(",")}`);
  }
}

export async function createConfiguredContractRuntime(
  options: ConfiguredContractRuntimeOptions
): Promise<ContractRuntime> {
  const persistedDeployment = tryReadPersistentDeployment(options.deploymentPath);
  const healthAccessControlAddress = options.healthAccessControlAddress ?? persistedDeployment?.healthAccessControl;
  if (persistedDeployment && healthAccessControlAddress && healthAccessControlAddress.toLowerCase() !== persistedDeployment.healthAccessControl.toLowerCase()) {
    throw new Error("DEPLOYMENT_ADDRESS_MISMATCH");
  }
  if (healthAccessControlAddress) {
    return createJsonRpcRuntime({
      ...options,
      healthAccessControlAddress,
      persistedDeployment
    });
  }
  if (!options.allowEphemeralDeployment) {
    throw new Error("HEALTH_ACCESS_CONTROL_ADDRESS_REQUIRED");
  }
  return createEphemeralRuntime();
}

async function createJsonRpcRuntime(
  options: ConfiguredContractRuntimeOptions & { persistedDeployment?: PersistentDeployment }
): Promise<ContractRuntime> {
  const wallets = options.blockchainWallets;
  if (!wallets?.pepPrivateKey) throw new Error("BLOCKCHAIN_PEP_PRIVATE_KEY_REQUIRED");
  if (!wallets.deployerPrivateKey) throw new Error("BLOCKCHAIN_DEPLOYER_PRIVATE_KEY_REQUIRED");
  if (!wallets.patientPrivateKey) throw new Error("BLOCKCHAIN_PATIENT_PRIVATE_KEY_REQUIRED");
  if (!wallets.practitionerPrivateKey) throw new Error("BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY_REQUIRED");
  if (!wallets.organizationPrivateKey) throw new Error("BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY_REQUIRED");
  const provider = new JsonRpcProvider(options.blockchainRpcUrl);
  const deploymentVerification = options.persistedDeployment
    ? await verifyPersistentDeployment(provider, options.persistedDeployment)
    : undefined;
  const deployer = new Wallet(wallets.deployerPrivateKey, provider);
  const patient = new Wallet(wallets.patientPrivateKey, provider);
  const practitioner = new Wallet(wallets.practitionerPrivateKey, provider);
  const organization = new Wallet(wallets.organizationPrivateKey, provider);
  const pep = new Wallet(wallets.pepPrivateKey, provider);
  const artifact = readHealthAccessControlArtifact();
  const accessControl = new Contract(
    options.healthAccessControlAddress!,
    artifact.abi,
    deployer
  );
  const attributeRegistry = deploymentVerification?.registries.attributeRegistry
    ?? await accessControl.attributeRegistry() as string;
  const consentRegistry = deploymentVerification?.registries.consentRegistry
    ?? await accessControl.consentRegistry() as string;
  const auditRegistry = deploymentVerification?.registries.auditRegistry
    ?? await accessControl.auditRegistry() as string;
  const resourceRegistry = deploymentVerification?.registries.resourceRegistry
    ?? await accessControl.resourceRegistry() as string;
  const institutionRegistry = deploymentVerification?.registries.institutionRegistry
    ?? await accessControl.institutionRegistry() as string;

  return {
    mode: "configured-json-rpc",
    deployment: {
      deployer: await deployer.getAddress(),
      attributeRegistry,
      consentRegistry,
      auditRegistry,
      resourceRegistry,
      institutionRegistry,
      healthAccessControl: options.healthAccessControlAddress!
    },
    accessControl,
    patientSigner: asAddressedSigner(patient),
    practitionerSigner: asAddressedSigner(practitioner),
    organizationSigner: asAddressedSigner(organization),
    pepSigner: asAddressedSigner(pep),
    close() {
      provider.destroy();
    }
  };
}

async function createEphemeralRuntime(): Promise<ContractRuntime> {
  const { deployHealthAccessContracts, ethers } = await import("./deploy.js");
  const deployment = await deployHealthAccessContracts();
  const [, patient, practitioner, organization, pep] = await ethers.getSigners();
  const accessControl = (await ethers.getContractAt(
    "HealthAccessControl",
    deployment.healthAccessControl
  )) as unknown as Contract;

  return {
    mode: "ephemeral-hardhat",
    deployment,
    accessControl,
    patientSigner: patient,
    practitionerSigner: practitioner,
    organizationSigner: organization,
    pepSigner: pep,
    close() {
      // The in-process Hardhat runtime is released with the API process.
    }
  };
}

function readHealthAccessControlArtifact() {
  const artifactPath = path.resolve(
    process.cwd(),
    "artifacts",
    "contracts",
    "HealthAccessControl.sol",
    "HealthAccessControl.json"
  );
  return JSON.parse(readFileSync(artifactPath, "utf8")) as {
    abi: ConstructorParameters<typeof Contract>[1];
  };
}

function asAddressedSigner(signer: Wallet | JsonRpcSigner) {
  return signer as Wallet & AddressedSigner & ContractRunner;
}
