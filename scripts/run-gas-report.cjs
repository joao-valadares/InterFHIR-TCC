const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const reportsDir = path.join(root, "reports");
const gasStatsPath = path.join(reportsDir, "gas-stats.json");
const gasSummaryPath = path.join(reportsDir, "gas-summary.md");

fs.mkdirSync(reportsDir, { recursive: true });

const hardhat = spawnSync(
  process.execPath,
  [path.join(root, "scripts", "run-hardhat.cjs"), "test", "--gas-stats-json", gasStatsPath],
  {
    cwd: root,
    stdio: "inherit",
    shell: false
  }
);

if (hardhat.status !== 0) {
  process.exit(hardhat.status ?? 1);
}

const gasStats = JSON.parse(fs.readFileSync(gasStatsPath, "utf8"));
const healthAccessControlDeployment = Object.values(gasStats.contracts ?? {})
  .find((contract) => contract.contractName === "HealthAccessControl")?.deployment;
if (!healthAccessControlDeployment || healthAccessControlDeployment.runtimeSize > 24576) {
  throw new Error("HEALTH_ACCESS_CONTROL_RUNTIME_SIZE_LIMIT_EXCEEDED");
}
const rows = [];

for (const contract of Object.values(gasStats.contracts ?? {})) {
  const deployment = contract.deployment;
  if (deployment !== null) {
    rows.push({
      contract: contract.contractName,
      operation: "deploy",
      min: deployment.min,
      avg: deployment.avg,
      median: deployment.median,
      max: deployment.max,
      count: deployment.count,
      runtimeSize: deployment.runtimeSize
    });
  }

  for (const [operation, stats] of Object.entries(contract.functions ?? {})) {
    rows.push({
      contract: contract.contractName,
      operation,
      min: stats.min,
      avg: stats.avg,
      median: stats.median,
      max: stats.max,
      count: stats.count,
      runtimeSize: ""
    });
  }
}

const interestingOperations = new Set([
  "deploy",
  "authorizePatientConsentController",
  "registerConsent",
  "registerConsentFor",
  "revokeConsent",
  "registerPatientConsent",
  "registerPatientConsentFor",
  "supersedePatientConsentFor",
  "revokePatientConsent",
  "revokePatientConsentFor",
  "createPolicyVersion",
  "deactivatePolicy",
  "requestAccess",
  "verifyAccess",
  "requestInstitutionalAccess",
  "verifyInstitutionalAccess",
  "finalizeEnforcement",
  "setOrganizationActive",
  "setPractitionerActive",
  "setPractitionerLicenseActive",
  "setInstitutionActive",
  "registerResourceHash",
  "recordDecision"
]);

const filteredRows = rows.filter((row) => interestingOperations.has(row.operation));
const markdown = [
  "# InterFHIR Gas Metrics",
  "",
  "Generated from `hardhat test --gas-stats-json reports/gas-stats.json`.",
  "",
  "| Contract | Operation | Min | Avg | Median | Max | Count | Runtime size |",
  "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
  ...filteredRows.map((row) =>
    `| ${row.contract} | ${row.operation} | ${row.min} | ${row.avg} | ${row.median} | ${row.max} | ${row.count} | ${row.runtimeSize} |`
  ),
  "",
  "## TCC Reading Notes",
  "",
  "- `registerConsent` and `revokeConsent` represent patient sovereignty operations.",
  "- `requestAccess` and `verifyAccess` remain explicit disabled compatibility ABIs; canonical reads use versioned institutional authorization.",
  "- `runtime size` helps compare deploy/storage footprint across contract architecture changes.",
  "- Keep sensitive FHIR payloads off-chain; gas should grow with metadata, not clinical record size.",
  ""
].join("\n");

fs.writeFileSync(gasSummaryPath, markdown);
console.log(`Gas metrics written to ${path.relative(root, gasStatsPath)} and ${path.relative(root, gasSummaryPath)}`);
