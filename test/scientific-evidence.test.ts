import { expect } from "chai";
import { summarizeSamples, classifyTestFile, observeDelivery, sourceIdentity } from "../scripts/scientific/evidence.js";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

describe("scientific evidence", () => {
  it("changes source identity when clinical fixtures or identity configuration change, but not reports", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "interfhir-evidence-"));
    const git = (args: string[]) => execFileSync("git", args, { cwd: root, windowsHide: true, stdio: "pipe" });
    try {
      await mkdir(path.join(root, "fixtures"));
      await mkdir(path.join(root, "infra"));
      await mkdir(path.join(root, "reports"));
      for (const file of ["fixtures/patient.json", "infra/identity.json"]) await writeFile(path.join(root, file), "{}\n");
      git(["init", "--quiet"]);
      git(["add", "."]);
      git(["-c", "user.name=Evidence test", "-c", "user.email=evidence@localhost", "commit", "--quiet", "-m", "Fixture"]);
      const original = await sourceIdentity(root);
      for (const file of ["fixtures/patient.json", "infra/identity.json"]) {
        await writeFile(path.join(root, file), '{"changed":true}\n');
        expect((await sourceIdentity(root)).sourceHash, file).not.to.equal(original.sourceHash);
        await writeFile(path.join(root, file), "{}\n");
      }
      await writeFile(path.join(root, "reports/result.json"), '{"status":"passed"}\n');
      expect((await sourceIdentity(root)).sourceHash).to.equal(original.sourceHash);
    } finally {
      if (path.dirname(root) !== path.resolve(os.tmpdir()) || !path.basename(root).startsWith("interfhir-evidence-")) throw new Error("UNEXPECTED_TEST_TEMP_PATH");
      await rm(root, { recursive: true, force: true });
    }
  });
  it("does not describe leaked clinical payload as no delivery", () => {
    expect(observeDelivery({ resource: { resourceType: "Observation", id: "secret" } }, false)).to.equal("unexpected");
    expect(observeDelivery({ error: "ACCESS_DENIED" }, false)).to.equal("none");
    expect(observeDelivery(undefined, false)).to.equal("unknown");
  });
  it("keeps failed samples separate and uses the nearest-rank p95", () => {
    const result = summarizeSamples([{ durationMs: 1, success: true }, { durationMs: 3, success: true }, { durationMs: 100, success: false }]);
    expect(result).to.include({ count: 3, succeeded: 2, failed: 1, mean: 2, median: 2, p95: 3 });
    expect(summarizeSamples([]).mean).to.equal(null);
  });
  it("assigns every test file to exactly one supported category", () => {
    expect(classifyTestFile("test/registries.test.ts")).to.equal("contracts");
    expect(classifyTestFile("middleware/test/postgres-share-repository.test.ts")).to.equal("postgres");
    expect(classifyTestFile("middleware/test/http-authentication.test.ts")).to.equal("https");
    expect(classifyTestFile("middleware/test/patient-consent-service.test.ts")).to.equal("unit");
    expect(classifyTestFile("test/scientific-evidence.test.ts")).to.equal("unit");
  });
});
