import { network } from "hardhat";

export const { ethers } = await network.create();

export type HealthAccessDeployment = {
  deployer: string;
  attributeRegistry: string;
  consentRegistry: string;
  auditRegistry: string;
  resourceRegistry: string;
  healthAccessControl: string;
  institutionRegistry: string;
};

export async function deployHealthAccessContracts(): Promise<HealthAccessDeployment> {
  const [deployer] = await ethers.getSigners();

  const AttributeRegistry = await ethers.getContractFactory("AttributeRegistry");
  const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
  const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
  const ResourceRegistry = await ethers.getContractFactory("ResourceRegistry");
  const HealthAccessControl = await ethers.getContractFactory("HealthAccessControl");

  const attributeRegistry = await AttributeRegistry.deploy();
  await attributeRegistry.waitForDeployment();

  const consentRegistry = await ConsentRegistry.deploy();
  await consentRegistry.waitForDeployment();

  const auditRegistry = await AuditRegistry.deploy();
  await auditRegistry.waitForDeployment();

  const resourceRegistry = await ResourceRegistry.deploy();
  await resourceRegistry.waitForDeployment();

  const healthAccessControl = await HealthAccessControl.deploy(
    await attributeRegistry.getAddress(),
    await consentRegistry.getAddress(),
    await auditRegistry.getAddress(),
    await resourceRegistry.getAddress()
  );
  await healthAccessControl.waitForDeployment();

  const accessControlAddress = await healthAccessControl.getAddress();
  await (await attributeRegistry.transferOwnership(accessControlAddress)).wait();
  await (await resourceRegistry.transferOwnership(accessControlAddress)).wait();
  await (await consentRegistry.authorizeWriter(accessControlAddress, true)).wait();
  await (await consentRegistry.authorizePatientConsentController(accessControlAddress, true)).wait();
  await (await auditRegistry.authorizeWriter(accessControlAddress, true)).wait();

  const institutionRegistry = await healthAccessControl.institutionRegistry();

  return {
    deployer: deployer.address,
    attributeRegistry: await attributeRegistry.getAddress(),
    consentRegistry: await consentRegistry.getAddress(),
    auditRegistry: await auditRegistry.getAddress(),
    resourceRegistry: await resourceRegistry.getAddress(),
    healthAccessControl: accessControlAddress,
    institutionRegistry
  };
}

async function main() {
  const deployment = await deployHealthAccessContracts();
  console.log(JSON.stringify(deployment, null, 2));
}
