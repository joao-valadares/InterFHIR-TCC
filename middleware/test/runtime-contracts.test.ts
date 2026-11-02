import { expect } from "chai";
import { existsSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { createConfiguredContractRuntime } from "../../scripts/runtime-contracts.js";
import { assertCanonicalRuntimeDependencies } from "../../scripts/runtime-contracts.js";
import {
  readPublicNetwork,
  readPersistentDeployment,
  sanitizeDeployment,
  sanitizePublicNetwork,
  writePersistentDeployment,
  type PersistentDeployment,
  type PublicNetworkConfiguration
} from "../../scripts/read-deployment.js";

describe("API contract runtime", function () {
  async function expectRejected(action: () => Promise<unknown>, message: string): Promise<void> {
    try {
      await action();
      expect.fail(`Expected rejection: ${message}`);
    } catch (error) {
      expect((error as Error).message).to.equal(message);
    }
  }

  it("rejects a production-looking API when canonical consent and interfhir dependencies are incomplete", function () {
    expect(() => assertCanonicalRuntimeDependencies({
      manifestSigningConfigured: false,
      patientConsentServiceConfigured: false,
      directedAccessConfigured: false,
      interfhirConfigured: false
    })).to.throw(
      "CANONICAL_RUNTIME_INCOMPLETE:manifestSigning,patientConsents,directedAccess,interfhir"
    );
    expect(() => assertCanonicalRuntimeDependencies({
      manifestSigningConfigured: true,
      patientConsentServiceConfigured: true,
      directedAccessConfigured: true,
      interfhirConfigured: true
    })).not.to.throw();
  });

  it("provides a persistent JSON-RPC attachment mode", async function () {
    let runtimeModule: Record<string, unknown> | undefined;
    try {
      runtimeModule = (await import(
        "../../scripts/runtime-contracts.js"
      )) as unknown as Record<string, unknown>;
    } catch {
      runtimeModule = undefined;
    }

    expect(runtimeModule?.createConfiguredContractRuntime).to.be.a("function");
  });

  it("rejects an implicit ephemeral deployment outside bootstrap mode", async function () {
    try {
      await createConfiguredContractRuntime({
        blockchainRpcUrl: "http://127.0.0.1:8545",
        deploymentPath: path.join(os.tmpdir(), "interfhir-no-deployment.json"),
        allowEphemeralDeployment: false
      });
      expect.fail("Expected HEALTH_ACCESS_CONTROL_ADDRESS_REQUIRED");
    } catch (error) {
      expect((error as Error).message).to.equal(
        "HEALTH_ACCESS_CONTROL_ADDRESS_REQUIRED"
      );
    }
  });

  it("requires configured private keys for an attached JSON-RPC deployment", async function () {
    try {
      await createConfiguredContractRuntime({ blockchainRpcUrl: "http://127.0.0.1:8545", healthAccessControlAddress: "0x0000000000000000000000000000000000000001", deploymentPath: path.join(os.tmpdir(), "interfhir-no-deployment.json"), allowEphemeralDeployment: false });
      expect.fail("Expected BLOCKCHAIN_PEP_PRIVATE_KEY_REQUIRED");
    } catch (error) {
      expect((error as Error).message).to.equal("BLOCKCHAIN_PEP_PRIVATE_KEY_REQUIRED");
    }
  });

  it("reads persistent deployment metadata without accepting private-key material", async function () {
    let runtimeModule: Record<string, unknown> | undefined;
    try {
      runtimeModule = (await import("../../scripts/runtime-contracts.js")) as unknown as Record<string, unknown>;
    } catch {
      runtimeModule = undefined;
    }

    const readPersistentDeployment = runtimeModule?.readPersistentDeployment as
      | ((filePath: string) => Record<string, unknown>)
      | undefined;
    expect(readPersistentDeployment).to.be.a("function");
    if (!readPersistentDeployment) throw new Error("READ_DEPLOYMENT_HELPER_MISSING");

    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-deployment-"));
    const filePath = path.join(directory, "deployment.json");
    await writeFile(filePath, JSON.stringify({
      schemaVersion: 1,
      chainId: 1337,
      blockNumber: 12,
      deployer: "0x0000000000000000000000000000000000000001",
      healthAccessControl: "0x0000000000000000000000000000000000000002",
      attributeRegistry: "0x0000000000000000000000000000000000000003",
      consentRegistry: "0x0000000000000000000000000000000000000004",
      auditRegistry: "0x0000000000000000000000000000000000000005",
      resourceRegistry: "0x0000000000000000000000000000000000000006",
      institutionRegistry: "0x0000000000000000000000000000000000000007"
    }), "utf8");

    const deployment = readPersistentDeployment(filePath);
    expect(deployment.healthAccessControl).to.equal("0x0000000000000000000000000000000000000002");
    expect(JSON.stringify(deployment)).not.to.match(/PRIVATE_KEY|privateKey/i);

    await writeFile(filePath, JSON.stringify({
      ...deployment,
      deployerPrivateKey: "redacted-test-material"
    }), "utf8");
    expect(() => readPersistentDeployment(filePath)).to.throw("DEPLOYMENT_PRIVATE_KEY_MATERIAL");
  });

  it("keeps deployment serialization closed and drops arbitrary fields from public projection", async function () {
    const deployment: PersistentDeployment = {
      schemaVersion: 1,
      chainId: 1337,
      blockNumber: 12,
      deployer: "0x0000000000000000000000000000000000000001",
      healthAccessControl: "0x0000000000000000000000000000000000000002",
      attributeRegistry: "0x0000000000000000000000000000000000000003",
      consentRegistry: "0x0000000000000000000000000000000000000004",
      auditRegistry: "0x0000000000000000000000000000000000000005",
      resourceRegistry: "0x0000000000000000000000000000000000000006",
      institutionRegistry: "0x0000000000000000000000000000000000000007"
    };
    const secret = "0xarbitrary-secret-material";
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-closed-deployment-"));
    const outputPath = path.join(directory, "deployment.json");

    await expectRejected(
      () => writePersistentDeployment(
        { ...deployment, unexpected: { nested: secret } } as unknown as PersistentDeployment,
        outputPath
      ),
      "DEPLOYMENT_FIELD_UNKNOWN:unexpected"
    );
    expect(existsSync(outputPath)).to.equal(false);

    const sanitized = sanitizeDeployment(
      { ...deployment, unexpected: { nested: secret } } as unknown as PersistentDeployment
    ) as unknown as Record<string, unknown>;
    expect(sanitized).not.to.have.property("unexpected");
    expect(JSON.stringify(sanitized)).not.to.include(secret);
  });

  it("rejects arbitrary nested public-network fields and sanitizes status fixtures", async function () {
    const network: PublicNetworkConfiguration = {
      schemaVersion: 2,
      chainId: 1337,
      validators: [{ name: "hospital-a", address: "0x0000000000000000000000000000000000000001" }],
      wallets: [{ name: "patient", address: "0x0000000000000000000000000000000000000002", reference: "Patient/pat-ana" }],
      institutions: {
        "hospital-a": {
          organizationReference: "Organization/hospital-a",
          practitionerReference: "Practitioner/ana",
          walletAddresses: {
            deployer: "0x0000000000000000000000000000000000000003",
            patient: "0x0000000000000000000000000000000000000002",
            practitioner: "0x0000000000000000000000000000000000000004",
            organization: "0x0000000000000000000000000000000000000005",
            pep: "0x0000000000000000000000000000000000000006"
          }
        },
        "clinic-b": {
          organizationReference: "Organization/clinic-b",
          practitionerReference: "Practitioner/bruno",
          walletAddresses: {
            deployer: "0x0000000000000000000000000000000000000003",
            patient: "0x0000000000000000000000000000000000000002",
            practitioner: "0x0000000000000000000000000000000000000007",
            organization: "0x0000000000000000000000000000000000000008",
            pep: "0x0000000000000000000000000000000000000009"
          }
        }
      }
    };
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-closed-network-"));
    const filePath = path.join(directory, "network.json");
    const secret = "-----BEGIN PRIVATE KEY-----arbitrary-secret";
    await writeFile(filePath, JSON.stringify({ ...network, institutions: {
      ...network.institutions,
      "hospital-a": {
        ...network.institutions["hospital-a"],
        walletAddresses: { ...network.institutions["hospital-a"].walletAddresses, unexpected: "unexpected-value" }
      }
    }}), "utf8");

    expect(() => readPublicNetwork(filePath)).to.throw("NETWORK_FIELD_UNKNOWN:institutions.hospital-a.walletAddresses.unexpected");
    await writeFile(filePath, JSON.stringify({ ...network, arbitrary: { nested: secret } }), "utf8");
    expect(() => readPublicNetwork(filePath)).to.throw("DEPLOYMENT_PRIVATE_KEY_MATERIAL");
    expect(JSON.stringify(sanitizePublicNetwork({ ...network, unexpected: { nested: secret } } as unknown as PublicNetworkConfiguration))).not.to.include(secret);
  });
});
