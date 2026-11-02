import { assertRuntimeResourceIdentity, runtimeEnvironment } from "../../scripts/runtime-environment.js";
import { spawn, execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { access, mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { expect } from "chai";
import { Result } from "ethers";
import { sourceIdentity } from "../../scripts/scientific/evidence.js";
import { getNetworkPolicyDefinition } from "../src/authorization/policy-definition.js";

import {
  assertNegativeResponse,
  assertReadinessGate,
  assertSanitizedE2EReport,
  assertConsentProjectionChain,
  createEnvironmentBlockedReport
} from "../../scripts/e2e/e2e-assertions.js";
import { createFailedE2EReport } from "../../scripts/e2e/e2e-assertions.js";
import {
  assertProjectVolumeIdentity,
  buildProjectScopedResetPlan,
  buildE2ERuntimeTargets,
  createE2ERequestId,
  E2E_REQUEST_IDS,
  E2E_PROJECT_NAME,
  E2E_PROJECT_VOLUME_NAMES
} from "../../scripts/e2e/e2e-fixtures.js";
import { E2E_SCENARIO_IDS } from "../../scripts/e2e/e2e-fixtures.js";
import {
  EXPECTED_DENIAL_STATUSES,
  executeDenied,
  DEFAULT_COMPOSE_TIMEOUT_MS,
  DEFAULT_NETWORK_TIMEOUT_MS,
  createE2EIdempotencyKey,
  fetchWithTimeout,
  buildTamperedManifestVersionMutation,
  readComposeTimeoutMs,
  withE2ETemporaryFiles,
  runProcess,
  withTimeout,
  writeReport
} from "../../scripts/e2e/run-real-e2e.js";

describe("real E2E report and safety gates", function () {
  it("keeps source provenance in the latest E2E pointer exactly as in the immutable run", async function () {
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-report-envelope-"));
    const previousCwd = process.cwd();
    const git = (...args: string[]) => execFileSync("git", args, { cwd: directory, windowsHide: true, stdio: "pipe" });
    try {
      await writeFile(path.join(directory, "package.json"), "{}\n");
      git("init", "--quiet");
      git("add", ".");
      git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "--quiet", "-m", "fixture");
      process.chdir(directory);
      const report = createEnvironmentBlockedReport({ generatedAt: "2026-11-01T00:00:00Z", reason: "DEPENDENCY_UNAVAILABLE", checks: [] });
      const reportPath = path.join(directory, "reports/e2e-latest.json");
      await writeReport({ projectRoot: directory, reportPath }, report);
      const latest = JSON.parse(readFileSync(reportPath, "utf8"));
      expect(latest.source?.revision).to.equal(git("rev-parse", "HEAD").toString().trim());
      expect(latest.report).to.deep.equal(report);
      const archived = JSON.parse(readFileSync(path.join(directory, "reports/runs", latest.runId, "e2e.json"), "utf8"));
      expect(latest).to.deep.equal(archived);
    } finally {
      process.chdir(previousCwd);
      if (path.dirname(directory) !== path.resolve(os.tmpdir()) || !path.basename(directory).startsWith("interfhir-report-envelope-")) throw new Error("UNEXPECTED_TEST_TEMP_PATH");
      await rm(directory, { recursive: true, force: true });
    }
  });
  it("enumerates positive policy variations and discriminating denials", function () {
    expect([...E2E_SCENARIO_IDS]).to.include.members([
      "authorized-general-policy-bruno", "authorized-general-policy-daniel",
      "authorized-specialist-policy-carla", "general-policy-role-denied",
      "specialist-policy-role-denied", "specialist-policy-specialty-denied"
      , "tampered-historical-fhir-content", "authorized-restored-historical-version"
    ]);
  });

  it("preserves completed successes and the failing case in an interrupted campaign", function () {
    const report = createFailedE2EReport({ generatedAt: "2026-10-15T12:00:00Z", reason: "AUDIT_UNAVAILABLE", checks: [], completed: [
      { id: "authorized-consent-read", status: "passed", outcome: "authorized", dataDelivery: "authorized", httpStatus: 200, reason: "PERMIT", observedReads: { fhirVread: 1, auditEvent: 1, commitmentCheck: 1 } },
      { id: "authorized-general-policy-daniel", status: "failed", outcome: "blocked", dataDelivery: "unknown", reason: "AUDIT_UNAVAILABLE", observedReads: {} }
    ] });
    expect(report.summary).to.deep.equal({ total: E2E_SCENARIO_IDS.length, passed: 1, failed: 1, blocked: E2E_SCENARIO_IDS.length - 2 });
    expect(report.scenarios[0]).to.include({ status: "passed", dataDelivery: "authorized" });
    expect(report.scenarios.find(s => s.id === "authorized-general-policy-daniel")).to.include({ status: "failed", reason: "AUDIT_UNAVAILABLE" });
    expect(() => assertSanitizedE2EReport(report)).not.to.throw();
  });

  it("registers materially different E2E policies without replacing the baseline policy", function () {
    const general = getNetworkPolicyDefinition("POLICY_E2E_GENERAL_OBSERVATION", 1);
    const specialist = getNetworkPolicyDefinition("POLICY_E2E_SPECIALIST_OBSERVATION", 1);
    expect(general).to.include({ requiredRoleCode: 1, resourceType: "Observation", purpose: "TREAT" });
    expect(general?.requiredSpecialtyCode).to.equal(undefined);
    expect(specialist).to.include({ requiredRoleCode: 2, requiredSpecialtyCode: 2 });
    expect(specialist?.definitionHash).not.to.equal(general?.definitionHash);
    expect(getNetworkPolicyDefinition("POLICY_TREATMENT_OBSERVATION", 1)).to.include({ requiredRoleCode: 1, requiredSpecialtyCode: 1 });
  });

  it("hashes the current sources after an unstaged module rename", async function () {
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-source-identity-"));
    const git = (...args: string[]) => execFileSync("git", ["-c", `safe.directory=${directory.replaceAll("\\", "/")}`, ...args], { cwd: directory, windowsHide: true, stdio: "pipe" });
    try {
      await mkdir(path.join(directory, "middleware/src/previous"), { recursive: true });
      await writeFile(path.join(directory, "middleware/src/previous/client.ts"), "export const version = 1;\n");
      git("init");
      git("add", "middleware");
      git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-m", "fixture");
      const before = await sourceIdentity(directory);
      await rename(path.join(directory, "middleware/src/previous"), path.join(directory, "middleware/src/interfhir"));
      const after = await sourceIdentity(directory);
      expect(after.revision).to.equal(before.revision);
      expect(after.dirty).to.equal(true);
      expect(after.sourceHash).not.to.equal(before.sourceHash);
      expect((await sourceIdentity(directory)).sourceHash).to.equal(after.sourceHash);
    } finally {
      const resolved = path.resolve(directory);
      if (path.dirname(resolved) !== path.resolve(os.tmpdir()) || !path.basename(resolved).startsWith("interfhir-source-identity-")) throw new Error("UNSAFE_FIXTURE_CLEANUP");
      await rm(resolved, { recursive: true, force: true });
    }
  });

  it("retains the assertion failure when a denial leaks clinical content", async function () {
    const completed: import("../../scripts/e2e/e2e-assertions.js").E2EScenarioReport[] = [];
    await executeDenied(completed, "revoked-consent", async () => ({
      status: 403,
      body: { error: "SHARE_NOT_ACTIVE", resource: { resourceType: "Observation" } }
    }));
    expect(completed[0]).to.include({
      status: "failed", dataDelivery: "unexpected",
      reason: "E2E_NEGATIVE_RESPONSE_CONTAINS_CLINICAL_PAYLOAD"
    });
  });

  it("does not hide a wrong denial reason behind the HTTP status", async function () {
    const completed: import("../../scripts/e2e/e2e-assertions.js").E2EScenarioReport[] = [];
    await executeDenied(completed, "revoked-consent", async () => ({
      status: 403, body: { error: "UNRELATED_ERROR" }
    }));
    expect(completed[0]).to.include({ status: "failed", reason: "E2E_DENIAL_REASON_MISMATCH" });
  });

  it("keeps negative internal-read counts unknown when no counter was collected", async function () {
    const completed: import("../../scripts/e2e/e2e-assertions.js").E2EScenarioReport[] = [];
    await executeDenied(completed, "revoked-consent", async () => ({
      status: 403, body: { error: "SHARE_NOT_ACTIVE" }
    }));
    expect(completed[0]).to.include({ status: "passed", dataDelivery: "none" });
    expect(completed[0].observedReads).to.deep.equal({});
  });
  it("accepts the sanitized shape emitted by a fully passed live E2E", function () {
    const report = createEnvironmentBlockedReport({ generatedAt: "2026-10-15T12:00:00Z", reason: "UNIT_FIXTURE", checks: [] });
    report.executionMode = "live";
    report.scenarios = report.scenarios.map((scenario): import("../../scripts/e2e/e2e-assertions.js").E2EScenarioReport => ({
      ...scenario, status: "passed", reason: "UNIT_FIXTURE",
      outcome: scenario.id.startsWith("authorized-") ? "authorized" : "denied",
      dataDelivery: scenario.id.startsWith("authorized-") ? "authorized" : "none",
      httpStatus: scenario.id.startsWith("authorized-") ? 200 : 403,
      observedReads: scenario.id.startsWith("authorized-") ? { fhirVread: 1, auditEvent: 1, commitmentCheck: 1 } : {}
    }));
    report.summary = { total: E2E_SCENARIO_IDS.length, passed: E2E_SCENARIO_IDS.length, failed: 0, blocked: 0 };
    report.scenarios[1].policyEvidence = {
      policyId: "POLICY_E2E_GENERAL_OBSERVATION", policyVersion: 1,
      requiredRoleCode: 1, requiredSpecialtyCode: 0, professionalRoleCode: 1, professionalSpecialtyCode: 3,
      individualConstraint: false, pinnedVersion: "2", currentVersion: "3"
    };
    report.limitations = [
      "This local E2E is an integration proof, not a production capacity or throughput claim.",
      "The report contains only states, counts, pseudonymous hashes and sanitized reasons."
    ];
    expect(() => assertSanitizedE2EReport(report)).not.to.throw();
  });
  it("dispatches each E2E lifecycle command explicitly from npm", function () {
    const packageJson = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as {
      scripts?: Record<string, string>;
    };
    const expectedCommands = {
      "e2e:up": "tsx scripts/e2e/run-real-e2e.ts up",
      "e2e:wait": "tsx scripts/e2e/run-real-e2e.ts wait",
      "e2e:run": "tsx scripts/e2e/run-real-e2e.ts run",
      "e2e:down": "tsx scripts/e2e/run-real-e2e.ts down"
    };

    for (const [scriptName, expectedCommand] of Object.entries(expectedCommands)) {
      expect(packageJson.scripts?.[scriptName], `${scriptName} must invoke its explicit lifecycle command`)
        .to.equal(expectedCommand);
    }
  });

  it("rejects a positive scenario that declares success without clinical delivery", function () {
    const report = createEnvironmentBlockedReport({ generatedAt: "2026-10-15T12:00:00Z", reason: "UNIT_FIXTURE", checks: [] });
    report.scenarios[0] = { ...report.scenarios[0], status: "passed", outcome: "authorized", dataDelivery: "none", httpStatus: 200, observedReads: {} };
    report.summary = { total: E2E_SCENARIO_IDS.length, passed: 1, failed: 0, blocked: E2E_SCENARIO_IDS.length - 1 };
    expect(() => assertSanitizedE2EReport(report)).to.throw("E2E_REPORT_POSITIVE_EVIDENCE_INVALID");
  });

  it("marks every live scenario blocked when a required dependency is unavailable", function () {
    const report = createEnvironmentBlockedReport({
      generatedAt: "2026-08-01T12:00:00.000Z",
      reason: "FHIR_METADATA_UNAVAILABLE",
      checks: [{ service: "hospital-a-fhir", status: "blocked", reason: "ECONNREFUSED" }]
    });

    expect(report.executionMode).to.equal("environment-blocked");
    expect(report.summary).to.deep.equal({ total: E2E_SCENARIO_IDS.length, passed: 0, failed: 0, blocked: E2E_SCENARIO_IDS.length });
    expect(report.scenarios.every((scenario) => scenario.status === "blocked")).to.equal(true);
    expect(report.scenarios.every((scenario) => scenario.dataDelivery === "unknown")).to.equal(true);
    expect(() => assertSanitizedE2EReport(report)).not.to.throw();
  });

  it("keeps the readiness gate closed unless every real dependency is ready", function () {
    expect(() => assertReadinessGate([
      { service: "hospital-a-fhir", status: "ok" },
      { service: "besu", status: "failed", reason: "RPC_UNAVAILABLE" }
    ])).to.throw("E2E_READINESS_BLOCKED");

    expect(() => assertReadinessGate([
      { service: "hospital-a-fhir", status: "ok" },
      { service: "besu", status: "ok" }
    ])).not.to.throw();
  });

  it("builds a reset plan limited to this isolated project's Compose files", function () {
    const plan = buildProjectScopedResetPlan(process.cwd());

    expect(plan).to.have.length(1);
    expect(plan[0].composeFiles).to.deep.equal([
      "docker-compose.yml",
      "docker-compose.dev.yml",
      "docker-compose.identity.yml",
      "docker-compose.blockchain.yml"
    ]);
    expect(plan.every((command) => command.args.includes("--volumes"))).to.equal(true);
    expect(plan.every((command) => command.args.includes("--remove-orphans"))).to.equal(false);
    expect(plan.every((command) => command.args.includes("--project-name"))).to.equal(true);
    expect(plan.every((command) => command.args.every((argument) => !/[;&|<>`$]/.test(argument)))).to.equal(true);
  });

  it("requires root and project labels without relying on working_dir", function () {
    const config = runtimeEnvironment();
    expect(() => assertRuntimeResourceIdentity([{ Name: config.projectName + "-data", Labels: { "org.interfhir.root": config.root, "com.docker.compose.project": config.projectName } }])).not.to.throw();
  });
  it("accepts absent resources as an idempotent reset state", function () {
    expect(() => assertRuntimeResourceIdentity([])).not.to.throw();
  });
  it("rejects resources with a mismatched project, root or Docker name", function () {
    const config = runtimeEnvironment();
    const valid = { Name: config.projectName + "-data", Labels: { "org.interfhir.root": config.root, "com.docker.compose.project": config.projectName } };
    expect(() => assertRuntimeResourceIdentity([{ ...valid, Name: "other-data" }])).to.throw("RESOURCE_NAME_MISMATCH");
    for (const key of Object.keys(valid.Labels)) expect(() => assertRuntimeResourceIdentity([{ ...valid, Labels: { ...valid.Labels, [key]: "other" } }])).to.throw("RESOURCE_OWNERSHIP_MISMATCH");
  });

  it("rejects a volume whose Compose project or working directory is not this worktree", function () {
    const validVolume = {
      name: E2E_PROJECT_VOLUME_NAMES[0],
      labels: {
        "com.docker.compose.project": E2E_PROJECT_NAME,
        "com.docker.compose.project.working_dir": process.cwd()
      }
    };
    expect(() => assertProjectVolumeIdentity([validVolume], process.cwd())).not.to.throw();
    expect(() => assertProjectVolumeIdentity([{
      name: validVolume.name,
      labels: { "com.docker.compose.project": E2E_PROJECT_NAME }
    }], process.cwd())).not.to.throw();
    expect(() => assertProjectVolumeIdentity([{
      ...validVolume,
      labels: { ...validVolume.labels, "com.docker.compose.project": "another-checkout" }
    }], process.cwd())).to.throw("E2E_PROJECT_VOLUME_IDENTITY_MISMATCH");
    expect(() => assertProjectVolumeIdentity([{
      ...validVolume,
      name: "interfhir-volume-from-another-checkout"
    }], process.cwd())).to.throw("E2E_PROJECT_VOLUME_UNEXPECTED");
  });

  it("rejects an explicitly empty Compose working_dir label", function () {
    expect(() => assertProjectVolumeIdentity([{
      name: E2E_PROJECT_VOLUME_NAMES[0],
      labels: {
        "com.docker.compose.project": E2E_PROJECT_NAME,
        "com.docker.compose.project.working_dir": ""
      }
    }], process.cwd())).to.throw("E2E_PROJECT_VOLUME_IDENTITY_MISMATCH");
  });

  it("rejects a non-empty Compose working_dir label from another worktree", function () {
    expect(() => assertProjectVolumeIdentity([{
      name: E2E_PROJECT_VOLUME_NAMES[0],
      labels: {
        "com.docker.compose.project": E2E_PROJECT_NAME,
        "com.docker.compose.project.working_dir": path.join(process.cwd(), "..", "another-worktree")
      }
    }], process.cwd())).to.throw("E2E_PROJECT_VOLUME_IDENTITY_MISMATCH");
  });

  it("requires negative responses to be HTTP denials without clinical payload", function () {
    expect(() => assertNegativeResponse({ status: 403, body: { error: "CONSENT_REVOKED" } }, 403)).not.to.throw();
    expect(() => assertNegativeResponse({ status: 503, body: { error: "BLOCKCHAIN_UNAVAILABLE" } }, [503])).not.to.throw();
    expect(() => assertNegativeResponse({ status: 403, body: { resource: { resourceType: "Observation" } } }, 403))
      .to.throw("E2E_NEGATIVE_RESPONSE_CONTAINS_CLINICAL_PAYLOAD");
    expect(() => assertNegativeResponse({ status: 500, body: { error: "INTERNAL_ERROR" } }, 403))
      .to.throw("E2E_NEGATIVE_RESPONSE_STATUS_UNEXPECTED");
    expect(() => assertNegativeResponse({ status: 409, body: { error: "CONFLICT" } }, 403))
      .to.throw("E2E_NEGATIVE_RESPONSE_STATUS_UNEXPECTED");
    expect(() => assertNegativeResponse({ status: 200, body: { error: "unexpected" } }, 403))
      .to.throw("E2E_NEGATIVE_RESPONSE_STATUS_INVALID");
  });

  it("blocks report generation when a forbidden live secret or clinical field is present", function () {
    const report = createEnvironmentBlockedReport({
      generatedAt: "2026-08-01T12:00:00.000Z",
      reason: "DEPENDENCY_UNAVAILABLE",
      checks: []
    });
    const unsafe = { ...report, scenarios: report.scenarios.map((scenario, index) =>
      index === 0 ? { ...scenario, resource: { resourceType: "Observation" } } : scenario
    ) } as never;

    expect(() => assertSanitizedE2EReport(unsafe)).to.throw("E2E_REPORT_FORBIDDEN_FIELD:resource");

    const nestedUnsafe = { ...report, limitations: [{ diagnostics: { authorizationHeader: "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwYXRpZW50In0.signature" } }] } as never;
    expect(() => assertSanitizedE2EReport(nestedUnsafe)).to.throw("E2E_REPORT_FORBIDDEN_FIELD:authorizationHeader");

    const alternateUnsafe = { ...report, limitations: [{ tlsCertificate: "-----BEGIN CERTIFICATE-----\nsecret\n-----END CERTIFICATE-----" }] } as never;
    expect(() => assertSanitizedE2EReport(alternateUnsafe)).to.throw("E2E_REPORT_FORBIDDEN_FIELD:tlsCertificate");

    const privateJwkUnsafe = { ...report, limitations: [{ nested: { material: { kty: "EC", d: "private" } } }] } as never;
    expect(() => assertSanitizedE2EReport(privateJwkUnsafe)).to.throw("E2E_REPORT_FORBIDDEN_KEY_MATERIAL");

    const serializedFhir = { ...report, limitations: [JSON.stringify({ resourceType: "Observation", id: "obs-ana-1", subject: { reference: "Patient/pat-ana" } })] } as never;
    expect(() => assertSanitizedE2EReport(serializedFhir)).to.throw("E2E_REPORT_FORBIDDEN_CLINICAL_VALUE");

    const serializedToken = { ...report, limitations: [JSON.stringify({ access_token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJwYXRpZW50In0.signature" })] } as never;
    expect(() => assertSanitizedE2EReport(serializedToken)).to.throw("E2E_REPORT_FORBIDDEN_FIELD:access_token");

    const serializedIdentity = { ...report, limitations: [{ nested: JSON.stringify({ organizationReference: "Organization/clinic-b" }) }] } as never;
    expect(() => assertSanitizedE2EReport(serializedIdentity)).to.throw("E2E_REPORT_FORBIDDEN_FIELD:organizationReference");

    const embeddedSecret = { ...report, limitations: ["client_secret=local-only-secret"] } as never;
    expect(() => assertSanitizedE2EReport(embeddedSecret)).to.throw("E2E_REPORT_FORBIDDEN_SECRET_VALUE");

    const opaqueBearer = { ...report, limitations: ["Bearer opaque-access-token"] } as never;
    expect(() => assertSanitizedE2EReport(opaqueBearer)).to.throw("E2E_REPORT_FORBIDDEN_SECRET_VALUE");

    const nestedFhir = { ...report, readiness: [{ service: "hapi", status: "ok", details: { resourceType: "Observation" } }] } as never;
    expect(() => assertSanitizedE2EReport(nestedFhir)).to.throw("E2E_REPORT_FORBIDDEN_CLINICAL_VALUE");

    const safe = createEnvironmentBlockedReport({ generatedAt: "2026-08-01T12:00:00.000Z", reason: "STABLE_REASON_CODE", checks: [] });
    safe.scenarios[0].responseHash = "sha256:" + "a".repeat(64);
    safe.scenarios[0].reason = "STABLE_REASON_CODE";
    expect(() => assertSanitizedE2EReport(safe)).not.to.throw();
  });

  it("always includes the OIDC, mTLS, UDAP, HAPI, PostgreSQL and Besu readiness targets", function () {
    const services = buildE2ERuntimeTargets({});
    expect(services.map((target) => target.service)).to.include.members([
      "hospital-a-fhir",
      "clinic-b-fhir",
      "hospital-a-metadata-postgres",
      "clinic-b-metadata-postgres",
      "besu-hospital-a-validator",
      "hospital-a-oidc",
      "clinic-b-oidc",
      "hospital-a-gateway",
      "clinic-b-gateway",
      "hospital-a-udap"
    ]);
    expect(services.find((target) => target.service === "keycloak")?.endpoint)
      .to.equal("http://127.0.0.1:8190/health/ready");
  });

  it("keeps denial statuses specific to each failure class", function () {
    expect(EXPECTED_DENIAL_STATUSES["wrong-organization"]).to.deep.equal([403]);
    expect(EXPECTED_DENIAL_STATUSES["tampered-manifest"]).to.deep.equal([409]);
    expect(EXPECTED_DENIAL_STATUSES["assertion-replay"]).to.deep.equal([409]);
    expect(EXPECTED_DENIAL_STATUSES["blockchain-unavailable"]).to.deep.equal([503]);
    expect(Object.values(EXPECTED_DENIAL_STATUSES).flat()).not.to.include(500);
  });

  it("uses unique custodian-compatible request ids for every live read scenario", function () {
    const requestIds = Object.values(E2E_REQUEST_IDS);
    expect(new Set(requestIds).size).to.equal(requestIds.length);
    for (const requestId of requestIds) {
      expect(requestId).to.match(/^req_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    }
    expect(createE2ERequestId("req_11111111-1111-4111-8111-111111111111")).to.equal("req_11111111-1111-4111-8111-111111111111");
    expect(() => createE2ERequestId("e2e-authorized-read-001")).to.throw("E2E_REQUEST_ID_INVALID");
  });

  it("uses a distinct E2E idempotency key per execution", function () {
    expect(createE2EIdempotencyKey("consent", "run-a")).to.equal("e2e-consent-run-a");
    expect(createE2EIdempotencyKey("consent", "run-a")).not.to.equal(createE2EIdempotencyKey("consent", "run-b"));
  });

  it("queries the Consent identity hash and validates every returned projection field", async function () {
    const consentHash = `0x${"1".repeat(64)}`;
    const consentProjectionHash = `0x${"2".repeat(64)}`;
    const mapped = { consentHash, consentProjectionHash };
    const response = { consentHash: consentProjectionHash, consentVersion: "3" };
    let queriedConsentHash: string | undefined;
    const chainProjection = Result.fromItems(
      [`0x${"0".repeat(64)}`, 1n, 3n, consentProjectionHash, true, 0],
      ["policyIdHash", "policyVersion", "consentVersion", "consentProjectionHash", "active", "status"]
    );

    await assertConsentProjectionChain(response, mapped, async (requestedConsentHash) => {
      queriedConsentHash = requestedConsentHash;
      return chainProjection;
    });
    expect(queriedConsentHash).to.equal(consentHash);

    await expectRejected(
      assertConsentProjectionChain({ consentHash, consentVersion: "3" }, mapped, async () => chainProjection),
      "E2E_CONSENT_PROJECTION_HASH_MISMATCH"
    );

    await expectRejected(
      assertConsentProjectionChain(response, mapped, async () => ({ active: false, consentVersion: 3, consentProjectionHash })),
      "E2E_CONSENT_CHAIN_PROJECTION_INVALID"
    );
    await expectRejected(
      assertConsentProjectionChain(response, mapped, async () => ({ active: true, consentVersion: 4, consentProjectionHash })),
      "E2E_CONSENT_CHAIN_PROJECTION_INVALID"
    );
    await expectRejected(
      assertConsentProjectionChain(response, mapped, async () => ({ active: true, consentVersion: 3, consentProjectionHash: consentHash })),
      "E2E_CONSENT_CHAIN_PROJECTION_INVALID"
    );
  });

  it("bounds network and asynchronous work", async function () {
    expect(DEFAULT_NETWORK_TIMEOUT_MS).to.equal(60_000);
    await expectRejected(withTimeout(new Promise<never>(() => undefined), 5, "E2E_TIMEOUT_TEST"), "E2E_TIMEOUT_TEST");
    await expectRejected(fetchWithTimeout("http://example.invalid", {}, 5, async () => new Promise<Response>(() => undefined)), "E2E_NETWORK_TIMEOUT");
    await expectRejected(runProcess(process.execPath, ["-e", "setTimeout(() => undefined, 1000)"], process.cwd(), {}, 25), "COMMAND_TIMEOUT");
  });

  it("uses a Compose-specific timeout of at least ten minutes with an explicit override", function () {
    expect(DEFAULT_COMPOSE_TIMEOUT_MS).to.be.at.least(600_000);
    expect(readComposeTimeoutMs({})).to.equal(DEFAULT_COMPOSE_TIMEOUT_MS);
    expect(readComposeTimeoutMs({ E2E_COMPOSE_TIMEOUT_MS: "1000" })).to.equal(1_000);
    expect(readComposeTimeoutMs({ E2E_COMPOSE_TIMEOUT_MS: "900000" })).to.equal(900_000);

    for (const value of [
      "0",
      "1",
      "1800001",
      "600000.5",
      "-1",
      "+1",
      "9007199254740992",
      "999999999999999999999999"
    ]) {
      expect(
        () => readComposeTimeoutMs({ E2E_COMPOSE_TIMEOUT_MS: value }),
        `E2E_COMPOSE_TIMEOUT_MS=${value} must be rejected`
      ).to.throw("E2E_INVALID_NUMBER:E2E_COMPOSE_TIMEOUT_MS");
    }
  });

  it("invokes an absolute npm.cmd path successfully on Windows without mocks", async function () {
    if (process.platform !== "win32") return;

    const npmCommand = path.join(path.dirname(process.execPath), "npm.cmd");
    await runProcess(npmCommand, ["--version"], process.cwd(), {}, 10_000);
  });

  it("resolves a bare npm.cmd command on Windows without mocks", async function () {
    if (process.platform !== "win32") return;

    await runProcess("npm.cmd", ["--version"], process.cwd(), {}, 10_000);
  });

  it("tampers the exact manifest version commitment without changing the current FHIR fixture", function () {
    const original = {
      manifest_id: "manifest-1",
      share_id: "share-1",
      version: 1,
      status: "active" as const,
      custodian_organization_reference: "Organization/hospital-a",
      grantee_organization_reference: "Organization/clinic-b",
      resource_reference: "Observation/obs-ana-1",
      resource_type: "Observation",
      fhir_version_id: "7",
      subject_reference: "Patient/pat-ana",
      consent_reference_hash: "0x" + "1".repeat(64),
      consent_projection_hash: "0x" + "2".repeat(64),
      resource_hash: "sha256:" + "3".repeat(64),
      previous_version_commitment: "0x" + "0".repeat(64),
      commitment: "0x" + "4".repeat(64),
      signing_key_id: "hospital-a-manifest-2026",
      signature: "signature",
      created_at: "2026-08-01T12:00:00.000Z",
      updated_at: null
    };
    const mutation = buildTamperedManifestVersionMutation(original);
    expect(mutation.fhir_version_id).to.equal("7-tampered");
    expect(mutation.commitment).not.to.equal(original.commitment);
    expect(original.resource_reference).to.equal("Observation/obs-ana-1");
    expect(original.resource_hash).to.equal("sha256:" + "3".repeat(64));
  });

  it("cleans compose.env after successful, blocked and thrown temporary-file owners", async function () {
    for (const outcome of ["success", "blocked", "fault"] as const) {
      const directory = await mkdtemp(path.join(os.tmpdir(), "task10-e2e-"));
      const composeEnvPath = path.join(directory, "compose.env");
      try {
        const operation = withE2ETemporaryFiles(async (scope) => {
          scope.register(composeEnvPath);
          await writeFile(composeEnvPath, "SECRET_MATERIAL=must-not-remain\n", "utf8");
          if (outcome === "fault") throw new Error("E2E_TEST_FAULT");
          return outcome;
        });
        if (outcome === "fault") {
          await expectRejected(operation, "E2E_TEST_FAULT");
        } else {
          expect(await operation).to.equal(outcome);
        }
        await expectMissing(composeEnvPath);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    }
  });
});

async function expectRejected(promise: Promise<unknown>, message: string) {
  try {
    await promise;
    expect.fail(`Expected rejection containing ${message}`);
  } catch (error) {
    expect(String(error instanceof Error ? error.message : error)).to.include(message);
  }
}

async function expectMissing(filePath: string) {
  try {
    await access(filePath);
    expect.fail(`Expected ${filePath} to be absent`);
  } catch (error) {
    if (error instanceof Error && !String(error.message).includes("Expected")) return;
    throw error;
  }
}
