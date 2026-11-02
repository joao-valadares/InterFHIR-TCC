import { expect } from "chai";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

describe("canonical start-api configuration boundary", function () {
  it("rejects direct startup when INSTITUTION_GATEWAY is missing", function () {
    const result = runDirectStartApi({ FHIR_VAULT_ID: "hospital-a" });

    expect(result.status).to.not.equal(0);
    expect(result.output).to.include("INSTITUTION_GATEWAY_REQUIRED");
  });

  it("rejects direct startup when FHIR_VAULT_ID is missing", function () {
    const result = runDirectStartApi({ INSTITUTION_GATEWAY: "hospital-a" });

    expect(result.status).to.not.equal(0);
    expect(result.output).to.include("FHIR_VAULT_NOT_CONFIGURED");
  });

  it("rejects direct startup when gateway and vault selections mismatch", function () {
    const result = runDirectStartApi({
      INSTITUTION_GATEWAY: "hospital-a",
      FHIR_VAULT_ID: "clinic-b"
    });

    expect(result.status).to.not.equal(0);
    expect(result.output).to.include("INSTITUTION_GATEWAY_MISMATCH");
  });
});

function runDirectStartApi(overrides: Record<string, string>): {
  status: number | null;
  output: string;
} {
  const env = { ...process.env };
  delete env.INSTITUTION_GATEWAY;
  delete env.FHIR_VAULT_ID;
  Object.assign(env, overrides);

  const result = spawnSync(
    process.execPath,
    [
      resolve(process.cwd(), "node_modules/hardhat/dist/src/cli.js"),
      "run",
      "--no-compile",
      "scripts/start-api.ts"
    ],
    {
      cwd: process.cwd(),
      env,
      encoding: "utf8",
      timeout: 30_000
    }
  );

  return {
    status: result.status,
    output: `${result.stdout ?? ""}\n${result.stderr ?? ""}`
  };
}
