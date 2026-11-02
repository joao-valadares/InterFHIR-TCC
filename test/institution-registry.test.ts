import { expect } from "chai";
import { mkdtemp, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { Wallet } from "ethers";
import { network } from "hardhat";

import {
  verifyPersistentDeployment,
  writePersistentDeployment,
  type PersistentDeployment,
  type PublicNetworkConfiguration
} from "../scripts/read-deployment.js";
import * as deploymentModule from "../scripts/read-deployment.js";
import {
  bootstrapInstitutionalState,
  preflightInstitutionalBootstrap,
  verifyExistingInstitutionalBootstrap
} from "../scripts/bootstrap-state.js";
import { deployAll } from "../scripts/deploy-json-rpc.js";

const { ethers } = await network.create();

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

async function expectRejected(action: () => Promise<unknown>, message: string): Promise<void> {
  try {
    await action();
    expect.fail(`Expected rejection: ${message}`);
  } catch (error) {
    expect((error as Error).message).to.equal(message);
  }
}

async function deployPersistentFixture() {
  const [owner, other, patient] = await ethers.getSigners();
  const AttributeRegistry = await ethers.getContractFactory("AttributeRegistry");
  const ConsentRegistry = await ethers.getContractFactory("ConsentRegistry");
  const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
  const ResourceRegistry = await ethers.getContractFactory("ResourceRegistry");
  const HealthAccessControl = await ethers.getContractFactory("HealthAccessControl");
  const attributes = await AttributeRegistry.deploy();
  const consents = await ConsentRegistry.deploy();
  const audit = await AuditRegistry.deploy();
  const resources = await ResourceRegistry.deploy();
  const accessControl = await HealthAccessControl.deploy(
    await attributes.getAddress(),
    await consents.getAddress(),
    await audit.getAddress(),
    await resources.getAddress()
  );
  const chain = await ethers.provider.getNetwork();
  const deployment: PersistentDeployment = {
    schemaVersion: 1,
    chainId: Number(chain.chainId),
    blockNumber: await ethers.provider.getBlockNumber(),
    deployer: owner.address,
    attributeRegistry: await attributes.getAddress(),
    consentRegistry: await consents.getAddress(),
    auditRegistry: await audit.getAddress(),
    resourceRegistry: await resources.getAddress(),
    institutionRegistry: await accessControl.institutionRegistry(),
    healthAccessControl: await accessControl.getAddress()
  };
  return { owner, other, patient, attributes, consents, audit, resources, accessControl, deployment };
}

function publicNetworkFixture(): PublicNetworkConfiguration {
  const address = (value: number) => `0x${value.toString(16).padStart(40, "0")}`;
  return {
    schemaVersion: 2,
    chainId: 1337,
    validators: [{ name: "hospital-a", address: address(1) }],
    wallets: [{ name: "patient", address: address(2), reference: "Patient/pat-ana" }],
    institutions: {
      "hospital-a": {
        organizationReference: "Organization/hospital-a",
        practitionerReference: "Practitioner/ana",
        walletAddresses: {
          deployer: address(3), patient: address(2), practitioner: address(4), organization: address(5), pep: address(6)
        }
      },
      "clinic-b": {
        organizationReference: "Organization/clinic-b",
        practitionerReference: "Practitioner/bruno",
        walletAddresses: {
          deployer: address(3), patient: address(2), practitioner: address(7), organization: address(8), pep: address(9)
        }
      }
    }
  };
}

describe("InstitutionRegistry", function () {
  it("registers an institutional gateway with metadata commitment and can deactivate it", async function () {
    const [owner, gateway] = await ethers.getSigners();
    const InstitutionRegistry = await ethers.getContractFactory("InstitutionRegistry");
    const registry = await InstitutionRegistry.deploy();
    const organizationHash = id("Organization/clinic-b");
    const metadataCommitment = id("clinic-b-udap-metadata-v1");

    await expect(
      registry.registerInstitution(organizationHash, gateway.address, metadataCommitment)
    )
      .to.emit(registry, "InstitutionRegistered")
      .withArgs(organizationHash, gateway.address, metadataCommitment, owner.address);

    expect((await registry.getInstitution(organizationHash)).active).to.equal(true);
    await registry.setInstitutionActive(organizationHash, false);
    expect((await registry.getInstitution(organizationHash)).active).to.equal(false);
  });

  it("rejects non-owner institution administration", async function () {
    const [, attacker, gateway] = await ethers.getSigners();
    const InstitutionRegistry = await ethers.getContractFactory("InstitutionRegistry");
    const registry = await InstitutionRegistry.deploy();

    await expect(
      registry.connect(attacker).registerInstitution(id("Organization/clinic-b"), gateway.address, id("metadata"))
    ).to.be.revertedWith("ONLY_OWNER");
  });

  it("binds the configured gateway to an institution", async function () {
    const [, gateway, otherGateway] = await ethers.getSigners();
    const InstitutionRegistry = await ethers.getContractFactory("InstitutionRegistry");
    const registry = await InstitutionRegistry.deploy();
    const organizationHash = id("Organization/clinic-b");

    await registry.registerInstitution(organizationHash, gateway.address, id("metadata"));
    expect(await registry.isGatewayAuthorized(organizationHash, gateway.address)).to.equal(true);
    expect(await registry.isGatewayAuthorized(organizationHash, otherGateway.address)).to.equal(false);
    await expect(registry.setInstitutionGateway(organizationHash, otherGateway.address))
      .to.emit(registry, "InstitutionGatewayChanged")
      .withArgs(organizationHash, gateway.address, otherGateway.address, (await registry.owner()));
    expect(await registry.isGatewayAuthorized(organizationHash, otherGateway.address)).to.equal(true);
  });

  it("exposes a fail-closed institution comparison for read-before-write bootstrap", async function () {
    let bootstrapModule: Record<string, unknown> | undefined;
    try {
      bootstrapModule = (await import("../scripts/bootstrap-institutional-network.js")) as unknown as Record<string, unknown>;
    } catch {
      bootstrapModule = undefined;
    }

    const assertInstitutionRecordMatches = bootstrapModule?.assertInstitutionRecordMatches as
      | ((actual: unknown, expected: { gatewayAccount: string; metadataCommitment: string }, reference: string) => void)
      | undefined;
    expect(assertInstitutionRecordMatches).to.be.a("function");
    if (!assertInstitutionRecordMatches) throw new Error("INSTITUTION_COMPARISON_HELPER_MISSING");

    const expected = {
      gatewayAccount: "0x0000000000000000000000000000000000000002",
      metadataCommitment: "0x0000000000000000000000000000000000000000000000000000000000000003"
    };
    assertInstitutionRecordMatches(
      { gatewayAccount: expected.gatewayAccount, metadataCommitment: expected.metadataCommitment, active: true },
      expected,
      "Organization/clinic-b"
    );
    expect(() => assertInstitutionRecordMatches(
      { gatewayAccount: "0x0000000000000000000000000000000000000004", metadataCommitment: expected.metadataCommitment, active: true },
      expected,
      "Organization/clinic-b"
    )).to.throw("BOOTSTRAP_DIVERGENCE:institution:Organization/clinic-b");
  });

  it("allows stale deployment redeploy only for an exact missing-code error and explicit E2E flag", async function () {
    const deployModule = (await import("../scripts/deploy-json-rpc.js")) as unknown as Record<string, unknown>;
    const shouldRedeployStaleDeployment = deployModule.shouldRedeployStaleDeployment as
      | ((error: unknown, env: Record<string, string | undefined>) => boolean)
      | undefined;
    expect(shouldRedeployStaleDeployment).to.be.a("function");
    if (!shouldRedeployStaleDeployment) throw new Error("STALE_DEPLOYMENT_REDEPLOY_HELPER_MISSING");

    const enabled = { E2E_ALLOW_STALE_DEPLOYMENT_REDEPLOY: "true" };
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_CONTRACT_CODE_MISSING:attributeRegistry"), enabled)).to.equal(true);
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_CONTRACT_CODE_MISSING:attributeRegistry:extra"), enabled)).to.equal(false);
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_CONTRACT_CODE_MISSING:"), enabled)).to.equal(false);
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_CHAIN_ID_MISMATCH:1337:31337"), enabled)).to.equal(false);
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_OWNER_MISMATCH"), enabled)).to.equal(false);
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_REGISTRY_MISMATCH:auditRegistry"), enabled)).to.equal(false);
    expect(shouldRedeployStaleDeployment(new Error("UNEXPECTED_DEPLOYMENT_ERROR"), enabled)).to.equal(false);
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_CONTRACT_CODE_MISSING:attributeRegistry"), {})).to.equal(false);
    expect(shouldRedeployStaleDeployment(new Error("DEPLOYMENT_CONTRACT_CODE_MISSING:attributeRegistry"), {
      E2E_ALLOW_STALE_DEPLOYMENT_REDEPLOY: "false"
    })).to.equal(false);
  });

  it("replaces an existing persistent deployment without leaving a temporary file", async function () {
    const fixture = await deployPersistentFixture();
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-deployment-"));
    const filePath = path.join(directory, "deployment.json");
    const previous: PersistentDeployment = { ...fixture.deployment, blockNumber: fixture.deployment.blockNumber + 1 };
    const replacement: PersistentDeployment = { ...fixture.deployment, blockNumber: fixture.deployment.blockNumber + 2 };

    try {
      await writeFile(filePath, `${JSON.stringify(previous, null, 2)}\n`, "utf8");
      await writePersistentDeployment(replacement, filePath);

      expect(await readFile(filePath, "utf8")).to.equal(`${JSON.stringify(replacement, null, 2)}\n`);
      expect(await readdir(directory)).to.deep.equal(["deployment.json"]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("preserves the previous deployment and cleans the temporary file when replacement fails before rename", async function () {
    const fixture = await deployPersistentFixture();
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-deployment-"));
    const filePath = path.join(directory, "deployment.json");
    const previousContent = `${JSON.stringify(fixture.deployment, null, 2)}\n`;
    const replacementContent = `${JSON.stringify({ ...fixture.deployment, blockNumber: fixture.deployment.blockNumber + 1 }, null, 2)}\n`;
    const replaceFileAtomically = (deploymentModule as unknown as {
      replaceFileAtomically?: (filePath: string, content: string, renameFile: (source: string, target: string) => Promise<void>) => Promise<void>;
    }).replaceFileAtomically;

    try {
      await writeFile(filePath, previousContent, "utf8");
      expect(replaceFileAtomically).to.be.a("function");
      if (!replaceFileAtomically) throw new Error("ATOMIC_REPLACE_HELPER_MISSING");
      await expectRejected(
        () => replaceFileAtomically(filePath, replacementContent, async (temporaryPath, targetPath) => {
          expect(await readFile(temporaryPath, "utf8")).to.equal(replacementContent);
          expect(targetPath).to.equal(filePath);
          throw new Error("ATOMIC_RENAME_FAILED");
        }),
        "ATOMIC_RENAME_FAILED"
      );

      expect(await readFile(filePath, "utf8")).to.equal(previousContent);
      expect(await readdir(directory)).to.deep.equal(["deployment.json"]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("surfaces temporary cleanup failure while preserving the rename failure", async function () {
    const fixture = await deployPersistentFixture();
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-deployment-"));
    const filePath = path.join(directory, "deployment.json");
    const previousContent = `${JSON.stringify(fixture.deployment, null, 2)}\n`;
    const replacementContent = `${JSON.stringify({ ...fixture.deployment, blockNumber: fixture.deployment.blockNumber + 1 }, null, 2)}\n`;
    const replaceFileAtomically = (deploymentModule as unknown as {
      replaceFileAtomically?: (
        filePath: string,
        content: string,
        renameFile: (source: string, target: string) => Promise<void>,
        removeFile: (source: string) => Promise<void>
      ) => Promise<void>;
    }).replaceFileAtomically;

    try {
      await writeFile(filePath, previousContent, "utf8");
      expect(replaceFileAtomically).to.be.a("function");
      if (!replaceFileAtomically) throw new Error("ATOMIC_REPLACE_HELPER_MISSING");

      try {
        await replaceFileAtomically(
          filePath,
          replacementContent,
          async () => {
            throw new Error("ATOMIC_RENAME_FAILED");
          },
          async () => {
            throw new Error("ATOMIC_CLEANUP_FAILED");
          }
        );
        expect.fail("Expected temporary cleanup failure");
      } catch (error) {
        expect(error).to.be.instanceOf(AggregateError);
        expect((error as Error).message).to.equal("DEPLOYMENT_TEMPORARY_CLEANUP_FAILED");
        expect((error as AggregateError).cause).to.be.instanceOf(Error);
        expect(((error as AggregateError).cause as Error).message).to.equal("ATOMIC_RENAME_FAILED");
        expect((error as AggregateError).errors).to.have.length(2);
        expect((error as AggregateError).errors.map((entry) => (entry as Error).message)).to.deep.equal([
          "ATOMIC_RENAME_FAILED",
          "ATOMIC_CLEANUP_FAILED"
        ]);
      }

      expect(await readFile(filePath, "utf8")).to.equal(previousContent);
      expect(await readdir(directory)).to.have.length(2);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("does not remove a temporary file when exclusive creation fails before ownership", async function () {
    const fixture = await deployPersistentFixture();
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-deployment-"));
    const filePath = path.join(directory, "deployment.json");
    const previousContent = `${JSON.stringify(fixture.deployment, null, 2)}\n`;
    const replacementContent = `${JSON.stringify({ ...fixture.deployment, blockNumber: fixture.deployment.blockNumber + 1 }, null, 2)}\n`;
    const replaceFileAtomically = (deploymentModule as unknown as {
      replaceFileAtomically?: (
        filePath: string,
        content: string,
        renameFile: (source: string, target: string) => Promise<void>,
        removeFile: (source: string) => Promise<void>,
        openFile: (source: string, flags: string) => Promise<unknown>
      ) => Promise<void>;
    }).replaceFileAtomically;
    let openCalls = 0;
    let removeCalls = 0;

    try {
      await writeFile(filePath, previousContent, "utf8");
      expect(replaceFileAtomically).to.be.a("function");
      if (!replaceFileAtomically) throw new Error("ATOMIC_REPLACE_HELPER_MISSING");

      await expectRejected(
        () => replaceFileAtomically(
          filePath,
          replacementContent,
          async () => {
            throw new Error("UNEXPECTED_RENAME_CALL");
          },
          async () => {
            removeCalls += 1;
          },
          async (_temporaryPath, flags) => {
            openCalls += 1;
            expect(flags).to.equal("wx");
            throw Object.assign(new Error("EEXIST"), { code: "EEXIST" });
          }
        ),
        "EEXIST"
      );

      expect(openCalls).to.equal(1);
      expect(removeCalls).to.equal(0);
      expect(await readFile(filePath, "utf8")).to.equal(previousContent);
      expect(await readdir(directory)).to.deep.equal(["deployment.json"]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("surfaces cleanup failure after a successful rename", async function () {
    const fixture = await deployPersistentFixture();
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-deployment-"));
    const filePath = path.join(directory, "deployment.json");
    const previousContent = `${JSON.stringify(fixture.deployment, null, 2)}\n`;
    const replacementContent = `${JSON.stringify({ ...fixture.deployment, blockNumber: fixture.deployment.blockNumber + 1 }, null, 2)}\n`;
    const replaceFileAtomically = (deploymentModule as unknown as {
      replaceFileAtomically?: (
        filePath: string,
        content: string,
        renameFile: (source: string, target: string) => Promise<void>,
        removeFile: (source: string) => Promise<void>
      ) => Promise<void>;
    }).replaceFileAtomically;
    let cleanupCalls = 0;

    try {
      await writeFile(filePath, previousContent, "utf8");
      expect(replaceFileAtomically).to.be.a("function");
      if (!replaceFileAtomically) throw new Error("ATOMIC_REPLACE_HELPER_MISSING");

      try {
        await replaceFileAtomically(
          filePath,
          replacementContent,
          (source, target) => rename(source, target),
          async () => {
            cleanupCalls += 1;
            throw new Error("ATOMIC_CLEANUP_FAILED_AFTER_RENAME");
          }
        );
        expect.fail("Expected temporary cleanup failure");
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect(error).not.to.be.instanceOf(AggregateError);
        expect((error as Error).message).to.equal("DEPLOYMENT_TEMPORARY_CLEANUP_FAILED");
        expect(((error as Error & { cause?: Error }).cause)?.message).to.equal("ATOMIC_CLEANUP_FAILED_AFTER_RENAME");
      }

      expect(cleanupCalls).to.equal(1);
      expect(await readFile(filePath, "utf8")).to.equal(replacementContent);
      expect(await readdir(directory)).to.deep.equal(["deployment.json"]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("preserves a write failure when closing the temporary file also fails", async function () {
    const replaceFileAtomically = (deploymentModule as unknown as {
      replaceFileAtomically?: (
        filePath: string,
        content: string,
        renameFile: (source: string, target: string) => Promise<void>,
        removeFile: (source: string) => Promise<void>,
        openFile: (source: string, flags: string) => Promise<{
          writeFile: (content: string, options: { encoding: string }) => Promise<void>;
          sync: () => Promise<void>;
          close: () => Promise<void>;
        }>
      ) => Promise<void>;
    }).replaceFileAtomically;
    const writeError = new Error("ATOMIC_WRITE_FAILED");
    const closeError = new Error("ATOMIC_CLOSE_FAILED");
    let closeCalls = 0;
    let cleanupCalls = 0;
    let renameCalls = 0;

    expect(replaceFileAtomically).to.be.a("function");
    if (!replaceFileAtomically) throw new Error("ATOMIC_REPLACE_HELPER_MISSING");

    try {
      await replaceFileAtomically(
        path.join(os.tmpdir(), "interfhir-write-close.json"),
        "replacement",
        async () => {
          renameCalls += 1;
        },
        async () => {
          cleanupCalls += 1;
        },
        async () => ({
          writeFile: async () => {
            throw writeError;
          },
          sync: async () => undefined,
          close: async () => {
            closeCalls += 1;
            throw closeError;
          }
        })
      );
      expect.fail("Expected write and close failure");
    } catch (error) {
      expect(error).to.be.instanceOf(AggregateError);
      expect((error as AggregateError).cause).to.equal(writeError);
      expect((error as AggregateError).errors).to.deep.equal([writeError, closeError]);
    }

    expect(closeCalls).to.equal(1);
    expect(cleanupCalls).to.equal(1);
    expect(renameCalls).to.equal(0);
  });

  it("preserves a sync failure when closing the temporary file also fails", async function () {
    const replaceFileAtomically = (deploymentModule as unknown as {
      replaceFileAtomically?: (
        filePath: string,
        content: string,
        renameFile: (source: string, target: string) => Promise<void>,
        removeFile: (source: string) => Promise<void>,
        openFile: (source: string, flags: string) => Promise<{
          writeFile: (content: string, options: { encoding: string }) => Promise<void>;
          sync: () => Promise<void>;
          close: () => Promise<void>;
        }>
      ) => Promise<void>;
    }).replaceFileAtomically;
    const syncError = new Error("ATOMIC_SYNC_FAILED");
    const closeError = new Error("ATOMIC_CLOSE_FAILED");
    let writeCalls = 0;
    let closeCalls = 0;
    let cleanupCalls = 0;
    let renameCalls = 0;

    expect(replaceFileAtomically).to.be.a("function");
    if (!replaceFileAtomically) throw new Error("ATOMIC_REPLACE_HELPER_MISSING");

    try {
      await replaceFileAtomically(
        path.join(os.tmpdir(), "interfhir-sync-close.json"),
        "replacement",
        async () => {
          renameCalls += 1;
        },
        async () => {
          cleanupCalls += 1;
        },
        async () => ({
          writeFile: async () => {
            writeCalls += 1;
          },
          sync: async () => {
            throw syncError;
          },
          close: async () => {
            closeCalls += 1;
            throw closeError;
          }
        })
      );
      expect.fail("Expected sync and close failure");
    } catch (error) {
      expect(error).to.be.instanceOf(AggregateError);
      expect((error as AggregateError).cause).to.equal(syncError);
      expect((error as AggregateError).errors).to.deep.equal([syncError, closeError]);
    }

    expect(writeCalls).to.equal(1);
    expect(closeCalls).to.equal(1);
    expect(cleanupCalls).to.equal(1);
    expect(renameCalls).to.equal(0);
  });

  it("validates HealthAccessControl owner and all five persisted registry bindings", async function () {
    const fixture = await deployPersistentFixture();
    const provider = ethers.provider as unknown as import("ethers").JsonRpcProvider;

    await verifyPersistentDeployment(provider, fixture.deployment);
    await expectRejected(
      () => verifyPersistentDeployment(provider, { ...fixture.deployment, deployer: fixture.other.address }),
      "DEPLOYMENT_OWNER_MISMATCH"
    );

    const replacements = {
      attributeRegistry: await (await ethers.getContractFactory("AttributeRegistry")).deploy(),
      consentRegistry: await (await ethers.getContractFactory("ConsentRegistry")).deploy(),
      auditRegistry: await (await ethers.getContractFactory("AuditRegistry")).deploy(),
      resourceRegistry: await (await ethers.getContractFactory("ResourceRegistry")).deploy(),
      institutionRegistry: await (await ethers.getContractFactory("InstitutionRegistry")).deploy()
    };
    const replacementAddresses = {
      attributeRegistry: await replacements.attributeRegistry.getAddress(),
      consentRegistry: await replacements.consentRegistry.getAddress(),
      auditRegistry: await replacements.auditRegistry.getAddress(),
      resourceRegistry: await replacements.resourceRegistry.getAddress(),
      institutionRegistry: await replacements.institutionRegistry.getAddress()
    };
    for (const field of Object.keys(replacementAddresses) as Array<keyof typeof replacementAddresses>) {
      await expectRejected(
        () => verifyPersistentDeployment(provider, { ...fixture.deployment, [field]: replacementAddresses[field] }),
        `DEPLOYMENT_REGISTRY_MISMATCH:${field}`
      );
    }

    await expectRejected(
      () => verifyPersistentDeployment(provider, { ...fixture.deployment, chainId: fixture.deployment.chainId + 1 }),
      `DEPLOYMENT_CHAIN_ID_MISMATCH:${fixture.deployment.chainId + 1}:${fixture.deployment.chainId}`
    );
    await expectRejected(
      () => verifyPersistentDeployment(provider, { ...fixture.deployment, auditRegistry: fixture.other.address }),
      "DEPLOYMENT_CONTRACT_CODE_MISSING:auditRegistry"
    );
  });

  it("requires Ana to be an on-chain ConsentRegistry patient controller", async function () {
    const fixture = await deployPersistentFixture();
    const provider = ethers.provider as unknown as import("ethers").JsonRpcProvider;

    expect(await fixture.consents.patientConsentControllers(fixture.patient.address)).to.equal(false);
    await expectRejected(
      () => verifyPersistentDeployment(provider, fixture.deployment, fixture.patient.address),
      "DEPLOYMENT_PATIENT_CONTROLLER_MISMATCH"
    );

    await fixture.consents.authorizePatientConsentController(fixture.patient.address, true);
    await verifyPersistentDeployment(provider, fixture.deployment, fixture.patient.address);
    expect(await fixture.consents.patientConsentControllers(fixture.patient.address)).to.equal(true);
  });

  it("registers Ana during the initial persistent deployment", async function () {
    const [fundingAccount, patient] = await ethers.getSigners();
    const deployer = Wallet.createRandom().connect(ethers.provider as unknown as import("ethers").JsonRpcProvider);
    await fundingAccount.sendTransaction({ to: deployer.address, value: ethers.parseEther("10") });

    const deployment = await deployAll(deployer as unknown as Wallet, patient.address);
    const consentRegistry = await ethers.getContractAt("ConsentRegistry", deployment.consentRegistry);
    expect(await consentRegistry.patientConsentControllers(patient.address)).to.equal(true);
  });

  it("preflights every institution before exposing any write transaction", async function () {
    const fixture = await deployPersistentFixture();
    const networkFixture = publicNetworkFixture();
    networkFixture.wallets[0].address = fixture.patient.address;
    networkFixture.institutions["hospital-a"].walletAddresses.patient = fixture.patient.address;
    networkFixture.institutions["clinic-b"].walletAddresses.patient = fixture.patient.address;

    await fixture.attributes.registerOrganization(fixture.other.address, id("Organization/clinic-b"));
    await fixture.consents.authorizePatientConsentController(fixture.patient.address, true);
    const institutionRegistry = await ethers.getContractAt("InstitutionRegistry", fixture.deployment.institutionRegistry);

    await expectRejected(
      () => bootstrapInstitutionalState(
        fixture.accessControl as unknown as import("ethers").Contract,
        institutionRegistry as unknown as import("ethers").Contract,
        fixture.consents as unknown as import("ethers").Contract,
        networkFixture
      ),
      "BOOTSTRAP_DIVERGENCE:organization:Organization/clinic-b"
    );
    expect((await fixture.attributes.getOrganization(id("Organization/hospital-a"))).account).to.equal(ethers.ZeroAddress);
  });

  it("applies the complete plan once and returns no writes on the repeat", async function () {
    const fixture = await deployPersistentFixture();
    const networkFixture = publicNetworkFixture();
    networkFixture.wallets[0].address = fixture.patient.address;
    networkFixture.institutions["hospital-a"].walletAddresses.patient = fixture.patient.address;
    networkFixture.institutions["clinic-b"].walletAddresses.patient = fixture.patient.address;
    await fixture.attributes.transferOwnership(await fixture.accessControl.getAddress());
    await fixture.resources.transferOwnership(await fixture.accessControl.getAddress());
    await fixture.consents.authorizeWriter(await fixture.accessControl.getAddress(), true);
    await fixture.consents.authorizePatientConsentController(fixture.patient.address, true);
    await fixture.consents.authorizePatientConsentController(await fixture.accessControl.getAddress(), true);
    const institutionRegistry = await ethers.getContractAt("InstitutionRegistry", fixture.deployment.institutionRegistry);

    const first = await bootstrapInstitutionalState(
      fixture.accessControl as unknown as import("ethers").Contract,
      institutionRegistry as unknown as import("ethers").Contract,
      fixture.consents as unknown as import("ethers").Contract,
      networkFixture
    );
    expect(first.writes).to.have.length(9);
    const second = await bootstrapInstitutionalState(
      fixture.accessControl as unknown as import("ethers").Contract,
      institutionRegistry as unknown as import("ethers").Contract,
      fixture.consents as unknown as import("ethers").Contract,
      networkFixture
    );
    expect(second.writes).to.deep.equal([]);
  });

  it("fails closed when status observes an incomplete on-chain bootstrap", async function () {
    const fixture = await deployPersistentFixture();
    const networkFixture = publicNetworkFixture();
    networkFixture.wallets[0].address = fixture.patient.address;
    networkFixture.institutions["hospital-a"].walletAddresses.patient = fixture.patient.address;
    networkFixture.institutions["clinic-b"].walletAddresses.patient = fixture.patient.address;
    await fixture.consents.authorizePatientConsentController(fixture.patient.address, true);
    const institutionRegistry = await ethers.getContractAt("InstitutionRegistry", fixture.deployment.institutionRegistry);

    await expectRejected(
      () => verifyExistingInstitutionalBootstrap(
        fixture.accessControl as unknown as import("ethers").Contract,
        institutionRegistry as unknown as import("ethers").Contract,
        fixture.consents as unknown as import("ethers").Contract,
        networkFixture
      ),
      "BOOTSTRAP_STATE_INCOMPLETE:organization:Organization/hospital-a"
    );
  });

  it("reads the policy before writes and rejects a divergent policy", async function () {
    const fixture = await deployPersistentFixture();
    const networkFixture = publicNetworkFixture();
    networkFixture.wallets[0].address = fixture.patient.address;
    networkFixture.institutions["hospital-a"].walletAddresses.patient = fixture.patient.address;
    networkFixture.institutions["clinic-b"].walletAddresses.patient = fixture.patient.address;
    await fixture.consents.authorizePatientConsentController(fixture.patient.address, true);
    await fixture.accessControl.createPolicyVersion({
      policyId: id("POLICY_TREATMENT_OBSERVATION"),
      version: 1,
      definitionHash: id("wrong-definition"),
      resourceTypeCode: 1,
      actionCode: 1,
      purposeCode: 1,
      requiredMask: 1,
      requiredRoleCode: 1,
      requiredSpecialtyCode: 1,
      effectiveFrom: 0,
      effectiveUntil: 0,
      active: true
    });
    const institutionRegistry = await ethers.getContractAt("InstitutionRegistry", fixture.deployment.institutionRegistry);

    await expectRejected(
      () => preflightInstitutionalBootstrap(
        fixture.accessControl as unknown as import("ethers").Contract,
        institutionRegistry as unknown as import("ethers").Contract,
        fixture.consents as unknown as import("ethers").Contract,
        networkFixture
      ),
      "BOOTSTRAP_DIVERGENCE:policy:POLICY_TREATMENT_OBSERVATION@1"
    );
    expect((await fixture.attributes.getOrganization(id("Organization/hospital-a"))).account).to.equal(ethers.ZeroAddress);
  });
});
