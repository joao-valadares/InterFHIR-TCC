import { readFileSync } from "node:fs";

import { expect } from "chai";

describe("network status import graph", function () {
  it("keeps bootstrap validation independent from the status runner", async function () {
    const bootstrapSource = readFileSync(
      new URL("../scripts/bootstrap-state.ts", import.meta.url),
      "utf8"
    );
    expect(bootstrapSource).not.to.contain('from "./read-deployment.js"');

    const [deploymentModule, bootstrapModule] = await Promise.all([
      import("../scripts/read-deployment.js"),
      import("../scripts/bootstrap-state.js")
    ]);
    const patientAddress = "0x0000000000000000000000000000000000000001";
    const network = {
      schemaVersion: 2,
      chainId: 1337,
      validators: [{ name: "hospital-a", address: patientAddress }],
      wallets: [{ name: "patient", address: patientAddress, reference: "Patient/pat-ana" }],
      institutions: {
        "hospital-a": {
          organizationReference: "Organization/hospital-a",
          practitionerReference: "Practitioner/ana",
          walletAddresses: {
            deployer: patientAddress,
            patient: patientAddress,
            practitioner: patientAddress,
            organization: patientAddress,
            pep: patientAddress
          }
        },
        "clinic-b": {
          organizationReference: "Organization/clinic-b",
          practitionerReference: "Practitioner/bruno",
          walletAddresses: {
            deployer: patientAddress,
            patient: patientAddress,
            practitioner: patientAddress,
            organization: patientAddress,
            pep: patientAddress
          }
        }
      }
    };

    expect(deploymentModule.readPatientAnaAddress(network)).to.equal(patientAddress);
    expect(bootstrapModule.preflightInstitutionalBootstrap).to.be.a("function");
  });
});
