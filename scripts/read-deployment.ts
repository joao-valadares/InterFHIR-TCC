import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, open, rename, rm } from "node:fs/promises";
import path from "node:path";

import { Contract, JsonRpcProvider, ZeroAddress, isAddress, keccak256, toUtf8Bytes, type InterfaceAbi } from "ethers";

import { INSTITUTION_NAMES, readPatientAnaAddress, type PublicNetworkConfiguration } from "./network-config.js";

export { INSTITUTION_NAMES, readPatientAnaAddress, type PublicNetworkConfiguration } from "./network-config.js";

export interface PersistentDeployment {
  schemaVersion: 1;
  chainId: number;
  blockNumber: number;
  deployer: string;
  attributeRegistry: string;
  consentRegistry: string;
  auditRegistry: string;
  resourceRegistry: string;
  institutionRegistry: string;
  healthAccessControl: string;
}

const DEPLOYMENT_FIELDS: Array<keyof PersistentDeployment> = [
  "schemaVersion",
  "chainId",
  "blockNumber",
  "deployer",
  "attributeRegistry",
  "consentRegistry",
  "auditRegistry",
  "resourceRegistry",
  "institutionRegistry",
  "healthAccessControl"
];

const DEPLOYMENT_CONTRACT_FIELDS: Array<keyof PersistentDeployment> = [
  "attributeRegistry",
  "consentRegistry",
  "auditRegistry",
  "resourceRegistry",
  "institutionRegistry",
  "healthAccessControl"
];

const DEPLOYMENT_BINDINGS: Array<{
  field: keyof Pick<PersistentDeployment, "attributeRegistry" | "consentRegistry" | "auditRegistry" | "resourceRegistry" | "institutionRegistry">;
  functionName: string;
}> = [
  { field: "attributeRegistry", functionName: "attributeRegistry" },
  { field: "consentRegistry", functionName: "consentRegistry" },
  { field: "auditRegistry", functionName: "auditRegistry" },
  { field: "resourceRegistry", functionName: "resourceRegistry" },
  { field: "institutionRegistry", functionName: "institutionRegistry" }
];

const NETWORK_FIELDS = ["schemaVersion", "chainId", "validators", "wallets", "institutions"] as const;
const VALIDATOR_FIELDS = ["name", "address"] as const;
const WALLET_FIELDS = ["name", "address", "reference"] as const;
const INSTITUTION_FIELDS = ["organizationReference", "practitionerReference", "walletAddresses"] as const;
const INSTITUTION_WALLET_FIELDS = ["deployer", "patient", "practitioner", "organization", "pep"] as const;
const VALIDATOR_NAMES = new Set(["hospital-a", "clinic-b", "auditor", "consortium"]);
const WALLET_NAMES = new Set(["deployer", "patient", "practitioner", "organization", "pep"]);
export interface DeploymentVerification {
  owner: string;
  registries: {
    attributeRegistry: string;
    consentRegistry: string;
    auditRegistry: string;
    resourceRegistry: string;
    institutionRegistry: string;
  };
  patientConsentController?: boolean;
}

export function deploymentFilePath(root = process.cwd()): string {
  return path.resolve(root, ".local", "besu", "deployment.json");
}

export function networkFilePath(root = process.cwd()): string {
  return path.resolve(root, ".local", "besu", "network.json");
}

export function readPersistentDeployment(filePath = deploymentFilePath()): PersistentDeployment {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
  } catch {
    throw new Error(`DEPLOYMENT_READ_FAILED:${filePath}`);
  }
  assertNoPrivateKeyMaterial(parsed);
  return assertDeploymentShape(parsed, filePath);
}

export function tryReadPersistentDeployment(filePath = deploymentFilePath()): PersistentDeployment | undefined {
  if (!existsSync(filePath)) return undefined;
  return readPersistentDeployment(filePath);
}

export async function writePersistentDeployment(
  deployment: PersistentDeployment,
  filePath = deploymentFilePath()
): Promise<void> {
  const validated = assertDeploymentShape(deployment, filePath);
  assertNoPrivateKeyMaterial(validated);
  await mkdir(path.dirname(filePath), { recursive: true });
  await replaceFileAtomically(filePath, `${JSON.stringify(validated, null, 2)}\n`);
}

export async function replaceFileAtomically(
  filePath: string,
  content: string,
  renameFile: (source: string, target: string) => Promise<void> = rename,
  removeFile: (source: string) => Promise<void> = (source) => rm(source, { force: true }),
  openFile: (
    source: string,
    flags: "wx"
  ) => Promise<Pick<Awaited<ReturnType<typeof open>>, "writeFile" | "sync" | "close">> = (source, flags) => open(source, flags)
): Promise<void> {
  const temporaryPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${randomUUID()}.tmp`
  );
  let temporaryFileOwned = false;
  let operationFailed = false;
  let operationError: unknown;
  try {
    const temporaryFile = await openFile(temporaryPath, "wx");
    temporaryFileOwned = true;
    let operationError: unknown;
    let operationFailed = false;
    try {
      await temporaryFile.writeFile(content, { encoding: "utf8" });
      await temporaryFile.sync();
    } catch (error) {
      operationFailed = true;
      operationError = error;
    }

    let closeError: unknown;
    let closeFailed = false;
    try {
      await temporaryFile.close();
    } catch (error) {
      closeFailed = true;
      closeError = error;
    }

    if (operationFailed && closeFailed) {
      throw new AggregateError(
        [operationError, closeError],
        "DEPLOYMENT_TEMPORARY_CLOSE_FAILED",
        { cause: operationError }
      );
    }
    if (operationFailed) {
      throw operationError;
    }
    if (closeFailed) {
      throw closeError;
    }
    await renameFile(temporaryPath, filePath);
  } catch (error) {
    operationFailed = true;
    operationError = error;
    throw error;
  } finally {
    if (temporaryFileOwned) {
      try {
        await removeFile(temporaryPath);
      } catch (cleanupError) {
        if (operationFailed) {
          throw new AggregateError(
            [operationError, cleanupError],
            "DEPLOYMENT_TEMPORARY_CLEANUP_FAILED",
            { cause: operationError }
          );
        }
        throw new Error("DEPLOYMENT_TEMPORARY_CLEANUP_FAILED", { cause: cleanupError });
      }
    }
  }
}

export function sanitizeDeployment(deployment: PersistentDeployment): PersistentDeployment {
  return {
    schemaVersion: deployment.schemaVersion,
    chainId: deployment.chainId,
    blockNumber: deployment.blockNumber,
    deployer: deployment.deployer,
    attributeRegistry: deployment.attributeRegistry,
    consentRegistry: deployment.consentRegistry,
    auditRegistry: deployment.auditRegistry,
    resourceRegistry: deployment.resourceRegistry,
    institutionRegistry: deployment.institutionRegistry,
    healthAccessControl: deployment.healthAccessControl
  };
}

export async function verifyPersistentDeployment(
  provider: JsonRpcProvider,
  deployment: PersistentDeployment,
  expectedPatientConsentController?: string
): Promise<DeploymentVerification> {
  const validated = assertDeploymentShape(deployment, "<memory>");
  const chain = await provider.getNetwork();
  if (Number(chain.chainId) !== validated.chainId) {
    throw new Error(`DEPLOYMENT_CHAIN_ID_MISMATCH:${validated.chainId}:${chain.chainId}`);
  }
  for (const field of DEPLOYMENT_CONTRACT_FIELDS) {
    const address = validated[field] as string;
    const code = await provider.getCode(address);
    if (code === "0x" || code === "0x0") throw new Error(`DEPLOYMENT_CONTRACT_CODE_MISSING:${field}`);
  }

  const accessControl = new Contract(
    validated.healthAccessControl,
    readArtifact("HealthAccessControl"),
    provider
  );
  const owner = requireContractAddress(
    await accessControl.getFunction("owner")(),
    "owner"
  );
  if (owner.toLowerCase() !== validated.deployer.toLowerCase()) {
    throw new Error("DEPLOYMENT_OWNER_MISMATCH");
  }

  const registries = {} as DeploymentVerification["registries"];
  for (const binding of DEPLOYMENT_BINDINGS) {
    const actual = requireContractAddress(
      await accessControl.getFunction(binding.functionName)(),
      binding.field
    );
    if (actual.toLowerCase() !== validated[binding.field].toLowerCase()) {
      throw new Error(`DEPLOYMENT_REGISTRY_MISMATCH:${binding.field}`);
    }
    registries[binding.field] = actual;
  }

  let patientConsentController: boolean | undefined;
  if (expectedPatientConsentController !== undefined) {
    const patientAddress = requireAddress(expectedPatientConsentController, "patientConsentController");
    const consentRegistry = new Contract(
      validated.consentRegistry,
      ["function patientConsentControllers(address) view returns (bool)"],
      provider
    );
    patientConsentController = Boolean(
      await consentRegistry.getFunction("patientConsentControllers")(patientAddress)
    );
    if (!patientConsentController) throw new Error("DEPLOYMENT_PATIENT_CONTROLLER_MISMATCH");
  }

  return { owner, registries, patientConsentController };
}

export function readPublicNetwork(filePath = networkFilePath()): PublicNetworkConfiguration {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8")) as unknown;
  } catch {
    throw new Error(`NETWORK_READ_FAILED:${filePath}`);
  }
  assertNoPrivateKeyMaterial(parsed);
  return assertPublicNetworkShape(parsed, filePath);
}

function assertDeploymentShape(value: unknown, filePath: string): PersistentDeployment {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`DEPLOYMENT_INVALID:${filePath}`);
  }
  const candidate = value as Record<string, unknown>;
  assertClosedFields(candidate, DEPLOYMENT_FIELDS, "DEPLOYMENT_FIELD_UNKNOWN");
  for (const field of DEPLOYMENT_FIELDS) {
    if (!(field in candidate)) throw new Error(`DEPLOYMENT_FIELD_MISSING:${field}`);
  }
  if (candidate.schemaVersion !== 1 || !Number.isInteger(candidate.chainId) || !Number.isInteger(candidate.blockNumber)) {
    throw new Error(`DEPLOYMENT_INVALID:${filePath}`);
  }
  for (const field of DEPLOYMENT_FIELDS.slice(3)) {
    if (typeof candidate[field] !== "string" || !isAddress(candidate[field]) || candidate[field] === ZeroAddress) {
      throw new Error(`DEPLOYMENT_ADDRESS_INVALID:${field}`);
    }
  }
  return candidate as unknown as PersistentDeployment;
}

function assertNoPrivateKeyMaterial(value: unknown): void {
  if (typeof value === "string") {
    if (/-----BEGIN [^-]*PRIVATE KEY-----/i.test(value)) throw new Error("DEPLOYMENT_PRIVATE_KEY_MATERIAL");
    return;
  }
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) assertNoPrivateKeyMaterial(item);
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (/(private.?key|mnemonic|seed|secret|password|token)/i.test(key)) {
      throw new Error("DEPLOYMENT_PRIVATE_KEY_MATERIAL");
    }
    assertNoPrivateKeyMaterial(nested);
  }
}

export function sanitizePublicNetwork(network: PublicNetworkConfiguration): PublicNetworkConfiguration {
  const institutions = {} as PublicNetworkConfiguration["institutions"];
  for (const name of INSTITUTION_NAMES) {
    const entry = network.institutions[name];
    institutions[name] = {
      organizationReference: entry.organizationReference,
      practitionerReference: entry.practitionerReference,
      walletAddresses: {
        deployer: entry.walletAddresses.deployer,
        patient: entry.walletAddresses.patient,
        practitioner: entry.walletAddresses.practitioner,
        organization: entry.walletAddresses.organization,
        pep: entry.walletAddresses.pep
      }
    };
  }
  return {
    schemaVersion: network.schemaVersion,
    chainId: network.chainId,
    validators: network.validators.map((validator) => ({ name: validator.name, address: validator.address })),
    wallets: network.wallets.map((wallet) => ({
      name: wallet.name,
      address: wallet.address,
      ...(wallet.reference === undefined ? {} : { reference: wallet.reference })
    })),
    institutions
  };
}

function assertPublicNetworkShape(value: unknown, filePath: string): PublicNetworkConfiguration {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`NETWORK_CONFIG_INVALID:${filePath}`);
  const candidate = value as Record<string, unknown>;
  assertClosedFields(candidate, NETWORK_FIELDS, "NETWORK_FIELD_UNKNOWN");
  if (candidate.schemaVersion !== 2 || !Number.isInteger(candidate.chainId)) {
    throw new Error(`NETWORK_CONFIG_INVALID:${filePath}`);
  }
  if (!Array.isArray(candidate.validators) || candidate.validators.length === 0) {
    throw new Error(`NETWORK_CONFIG_INVALID:${filePath}`);
  }
  const validators = candidate.validators.map((value, index) => {
    const validator = asRecord(value, `validators.${index}`);
    assertClosedFields(validator, VALIDATOR_FIELDS, "NETWORK_FIELD_UNKNOWN", `validators.${index}`);
    const name = requireString(validator.name, `validators.${index}.name`);
    if (!VALIDATOR_NAMES.has(name)) throw new Error(`NETWORK_VALIDATOR_INVALID:${name}`);
    return { name, address: requireAddress(validator.address, `validators.${index}.address`) };
  });
  if (new Set(validators.map((validator) => validator.name)).size !== validators.length) {
    throw new Error("NETWORK_VALIDATOR_DUPLICATE");
  }

  if (!Array.isArray(candidate.wallets) || candidate.wallets.length === 0) {
    throw new Error(`NETWORK_CONFIG_INVALID:${filePath}`);
  }
  const wallets = candidate.wallets.map((value, index) => {
    const wallet = asRecord(value, `wallets.${index}`);
    assertClosedFields(wallet, WALLET_FIELDS, "NETWORK_FIELD_UNKNOWN", `wallets.${index}`);
    const name = requireString(wallet.name, `wallets.${index}.name`);
    if (!WALLET_NAMES.has(name)) throw new Error(`NETWORK_WALLET_INVALID:${name}`);
    const reference = wallet.reference === undefined ? undefined : requireString(wallet.reference, `wallets.${index}.reference`);
    if (name === "patient" && reference !== "Patient/pat-ana") throw new Error("NETWORK_PATIENT_ANA_INVALID");
    return { name, address: requireAddress(wallet.address, `wallets.${index}.address`), ...(reference === undefined ? {} : { reference }) };
  });
  if (new Set(wallets.map((wallet) => wallet.name)).size !== wallets.length || !wallets.some((wallet) => wallet.name === "patient")) {
    throw new Error("NETWORK_WALLET_SET_INVALID");
  }

  const rawInstitutions = asRecord(candidate.institutions, "institutions");
  assertClosedFields(rawInstitutions, INSTITUTION_NAMES, "NETWORK_FIELD_UNKNOWN", "institutions");
  const institutions = {} as PublicNetworkConfiguration["institutions"];
  for (const name of INSTITUTION_NAMES) {
    const entry = asRecord(rawInstitutions[name], `institutions.${name}`);
    assertClosedFields(entry, INSTITUTION_FIELDS, "NETWORK_FIELD_UNKNOWN", `institutions.${name}`);
    const walletAddresses = asRecord(entry.walletAddresses, `institutions.${name}.walletAddresses`);
    assertClosedFields(walletAddresses, INSTITUTION_WALLET_FIELDS, "NETWORK_FIELD_UNKNOWN", `institutions.${name}.walletAddresses`);
    institutions[name] = {
      organizationReference: requireString(entry.organizationReference, `institutions.${name}.organizationReference`),
      practitionerReference: requireString(entry.practitionerReference, `institutions.${name}.practitionerReference`),
      walletAddresses: {
        deployer: requireAddress(walletAddresses.deployer, `institutions.${name}.walletAddresses.deployer`),
        patient: requireAddress(walletAddresses.patient, `institutions.${name}.walletAddresses.patient`),
        practitioner: requireAddress(walletAddresses.practitioner, `institutions.${name}.walletAddresses.practitioner`),
        organization: requireAddress(walletAddresses.organization, `institutions.${name}.walletAddresses.organization`),
        pep: requireAddress(walletAddresses.pep, `institutions.${name}.walletAddresses.pep`)
      }
    };
  }
  const sanitized = sanitizePublicNetwork({ schemaVersion: 2, chainId: candidate.chainId as number, validators, wallets, institutions });
  readPatientAnaAddress(sanitized);
  return sanitized;
}

function assertClosedFields(
  value: Record<string, unknown>,
  allowed: readonly string[],
  errorCode: string,
  prefix = ""
): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) throw new Error(`${errorCode}:${prefix ? `${prefix}.` : ""}${key}`);
  }
}

function asRecord(value: unknown, pathName: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`NETWORK_CONFIG_INVALID:${pathName}`);
  return value as Record<string, unknown>;
}

function requireString(value: unknown, pathName: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`NETWORK_FIELD_INVALID:${pathName}`);
  return value;
}

function requireAddress(value: unknown, pathName: string): string {
  if (typeof value !== "string" || !isAddress(value) || value === ZeroAddress) {
    throw new Error(`NETWORK_ADDRESS_INVALID:${pathName}`);
  }
  return value;
}

function requireContractAddress(value: unknown, field: string): string {
  if (typeof value !== "string" || !isAddress(value) || value === ZeroAddress) {
    throw new Error(`DEPLOYMENT_BINDING_ADDRESS_INVALID:${field}`);
  }
  return value;
}

async function main(): Promise<void> {
  const deployment = readPersistentDeployment();
  const network = readPublicNetwork();
  const provider = new JsonRpcProvider(process.env.BLOCKCHAIN_RPC_URL ?? "http://127.0.0.1:8546");
  try {
    const patientAddress = readPatientAnaAddress(network);
    const verification = await verifyPersistentDeployment(provider, deployment, patientAddress);
    const accessControl = new Contract(deployment.healthAccessControl, readArtifact("HealthAccessControl"), provider);
    const owner = verification.owner;
    const registryAddresses = verification.registries;
    const institutionRegistry = new Contract(
      registryAddresses.institutionRegistry,
      ["function getInstitution(bytes32) view returns (tuple(address gatewayAccount, bytes32 metadataCommitment, bool active))"],
      provider
    );
    const consentRegistry = new Contract(
      registryAddresses.consentRegistry,
      ["function patientConsentControllers(address) view returns (bool)"],
      provider
    );
    const { verifyExistingInstitutionalBootstrap } = await import("./bootstrap-state.js");
    const state = await verifyExistingInstitutionalBootstrap(accessControl, institutionRegistry, consentRegistry, network);
    const participantStatus = state.institutions.map((entry) => {
      const gatewayAccount = String(tupleValue(entry.institution, "gatewayAccount", 0));
      return {
        slug: entry.slug,
        organization: {
          reference: entry.organizationReference,
          account: String(tupleValue(entry.organization, "account", 0)),
          active: Boolean(tupleValue(entry.organization, "active", 1))
        },
        practitioner: {
          reference: entry.practitionerReference,
          account: String(tupleValue(entry.practitioner, "account", 0)),
          organizationHash: String(tupleValue(entry.practitioner, "organizationHash", 1)),
          roleCode: Number(tupleValue(entry.practitioner, "roleCode", 2)),
          specialtyCode: Number(tupleValue(entry.practitioner, "specialtyCode", 3)),
          licenseActive: Boolean(tupleValue(entry.practitioner, "licenseActive", 4)),
          active: Boolean(tupleValue(entry.practitioner, "active", 5))
        },
        institution: {
          gatewayAccount,
          metadataCommitment: String(tupleValue(entry.institution, "metadataCommitment", 1)),
          active: Boolean(tupleValue(entry.institution, "active", 2)),
          pepAuthorized: entry.pepAuthorized
        }
      };
    });
    const policyIdHash = keccak256(toUtf8Bytes("POLICY_TREATMENT_OBSERVATION"));
    const policy = state.policy.current;
    console.log(JSON.stringify({
      status: "ok",
      chainId: deployment.chainId,
      blockNumber: await provider.getBlockNumber(),
      deployment: sanitizeDeployment(deployment),
      contract: {
        address: deployment.healthAccessControl,
        code: "present",
        owner,
        registries: registryAddresses
      },
      participants: {
        patientAna: {
          reference: "Patient/pat-ana",
          address: patientAddress,
          controllerAuthorized: state.patientConsentController
        },
        institutions: participantStatus
      },
      policy: {
        reference: "POLICY_TREATMENT_OBSERVATION@1",
        policyIdHash,
        definitionHash: String(tupleValue(policy, "definitionHash", 2)),
        resourceTypeCode: Number(tupleValue(policy, "resourceTypeCode", 3)),
        actionCode: Number(tupleValue(policy, "actionCode", 4)),
        purposeCode: Number(tupleValue(policy, "purposeCode", 5)),
        requiredMask: Number(tupleValue(policy, "requiredMask", 6)),
        requiredRoleCode: Number(tupleValue(policy, "requiredRoleCode", 7)),
        requiredSpecialtyCode: Number(tupleValue(policy, "requiredSpecialtyCode", 8)),
        active: Boolean(tupleValue(policy, "active", 11))
      }
    }, null, 2));
  } finally {
    provider.destroy();
  }
}

function tupleValue(value: unknown, name: string, index: number): unknown {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string | number, unknown>;
  return record[name] ?? record[index];
}

function readArtifact(name: string): InterfaceAbi {
  const artifactPath = path.resolve(process.cwd(), "artifacts", "contracts", `${name}.sol`, `${name}.json`);
  return JSON.parse(readFileSync(artifactPath, "utf8")).abi as InterfaceAbi;
}

if (process.argv.some((argument) => /(?:^|[\\/])read-deployment\.(?:ts|js)$/.test(argument))) {
  await main();
}
