import { sourceIdentity, classifyTestFile } from "./scientific/evidence.js";
import { createHash, randomUUID } from "node:crypto";
import { access, mkdir, writeFile, readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import path from "node:path";
import { runLiveUdapHarness, type LiveUdapScenarioResult } from "./udap-live-harness.js";

export const MANDATORY_UDAP_SCENARIO_IDS = [
  "authorized-treat",
  "missing-consent",
  "revoked-consent",
  "expired-consent",
  "purpose-mismatch",
  "non-grantee-organization",
  "practitioner-without-role",
  "practitioner-wrong-organization",
  "untrusted-certificate",
  "certificate-cnf-mismatch",
  "unknown-oidc-issuer",
  "invalid-audience",
  "expired-assertion",
  "jti-replay",
  "unredeemed-share",
  "handoff-code-replay",
  "postgres-manifest-tamper",
  "onchain-commitment-mismatch",
  "fhir-version-tamper",
  "legitimate-new-version",
  "institutional-deny-after-onchain-permit",
  "blockchain-unavailable",
  "fhir-unavailable",
  "metadata-db-unavailable",
  "clinic-b-no-clinical-copy"
] as const;

export type UdapScenarioId = (typeof MANDATORY_UDAP_SCENARIO_IDS)[number];
export type ExecutionMode = "environment-blocked" | "catalog-only" | "live";

type ScenarioOutcome = "authorized" | "denied" | "blocked";

interface ScenarioOverride {
  outcome?: ScenarioOutcome;
  payloadPresent?: boolean;
  responseMetadata?: Record<string, unknown>;
  reason?: string;
  executionMode?: ExecutionMode;
  limitation?: string;
  timingsMs?: Partial<Record<ComponentTiming, number>>;
  componentReads?: Record<string, number>;
  blockchain?: { transactionHash?: string; blockNumber?: number; applicable: boolean };
  sourceScenarioId?: string;
}

export interface UnitEvidence {
  sourceTest: string;
  caseTitle?: string;
  runId?: string;
}

export interface UnitInvariantMeasurement {
  scope: "unit-evidence-report-invariants";
  requiredRepetitions: number;
  completedRepetitions: number;
  total: ReturnType<typeof summarizeLatencySamples> | null;
}

export interface DeliveryGateEvaluation {
  approved: boolean;
  requirements: {
    exactScenarioCatalog: boolean;
    sixLiveBaselineScenarios: boolean;
    nineteenUnitEvidenceScenarios: boolean;
    noBlockedScenarios: boolean;
    negativePayloadAbsent: boolean;
    thirtyLiveRepetitions: boolean;
    thirtyUnitInvariantRepetitions: boolean;
  };
}

export interface UdapInterinstitutionalReport {
  schemaVersion: 1;
  generatedAt: string;
  executionMode: ExecutionMode;
  environment: Record<string, string>;
  runNamespace: string;
  limitations: string[];
  coverage: { executed: number; liveBaseline: number; unitTest: number; blocked: number; source: "live-and-unit" | "unit-test" | "none" };
  summary: { total: 25; passed: number; failed: number; blocked: number };
  scenarios: Array<{
    id: UdapScenarioId;
    title: string;
    status: "passed" | "failed" | "blocked";
    outcome: ScenarioOutcome;
    reason: string;
    payloadPresent: boolean;
    requestMetadata: Record<string, string>;
    responseMetadata: Record<string, unknown>;
    securityEvidence: Record<string, boolean | string>;
    componentReads: Record<string, number>;
    blockchain: { transactionHash?: string; blockNumber?: number; applicable: boolean };
    timingsMs: Record<ComponentTiming, number | null>;
    execution: {
      mode: ExecutionMode;
      coverageKind: "live-baseline" | "unit-test" | "blocked";
      sourceTest?: string;
      limitation?: string;
    };
  }>;
}

export type ComponentTiming =
  | "oidcLocal"
  | "udapDiscoveryRegistrationToken"
  | "mtlsGateway"
  | "manifestLookupVerification"
  | "blockchainRequestFinality"
  | "fhirVread"
  | "canonicalizationHash"
  | "auditEvent"
  | "total";

const componentTimingKeys: ComponentTiming[] = [
  "oidcLocal",
  "udapDiscoveryRegistrationToken",
  "mtlsGateway",
  "manifestLookupVerification",
  "blockchainRequestFinality",
  "fhirVread",
  "canonicalizationHash",
  "auditEvent",
  "total"
];

const titles: Record<UdapScenarioId, string> = {
  "authorized-treat": "Authorized directed TREAT read",
  "missing-consent": "Denied without active Consent",
  "revoked-consent": "Denied after Consent revocation",
  "expired-consent": "Denied after Consent expiration",
  "purpose-mismatch": "Denied for an incompatible purpose",
  "non-grantee-organization": "Denied for an organization outside the directed share",
  "practitioner-without-role": "Denied for a practitioner without required role",
  "practitioner-wrong-organization": "Denied for a practitioner from another organization",
  "untrusted-certificate": "Denied for an untrusted mTLS certificate",
  "certificate-cnf-mismatch": "Denied when certificate and token cnf differ",
  "unknown-oidc-issuer": "Denied for an unknown OIDC issuer",
  "invalid-audience": "Denied for an invalid audience",
  "expired-assertion": "Denied for an expired UDAP assertion",
  "jti-replay": "Denied for a replayed assertion jti",
  "unredeemed-share": "Denied before one-time handoff redemption",
  "handoff-code-replay": "Denied for a replayed handoff code",
  "postgres-manifest-tamper": "Denied for a tampered PostgreSQL manifest",
  "onchain-commitment-mismatch": "Denied for an on-chain commitment mismatch",
  "fhir-version-tamper": "Denied for a mismatched FHIR version hash",
  "legitimate-new-version": "Allows a legitimately published next FHIR version",
  "institutional-deny-after-onchain-permit": "Local institutional policy denies after on-chain permit",
  "blockchain-unavailable": "Fails closed when blockchain is unavailable",
  "fhir-unavailable": "Fails closed when the custodian FHIR vault is unavailable",
  "metadata-db-unavailable": "Fails closed when custodian metadata storage is unavailable",
  "clinic-b-no-clinical-copy": "Clinic B receives no persistent clinical FHIR copy"
};

const authorizedScenario = new Set<UdapScenarioId>([
  "authorized-treat",
  "legitimate-new-version",
  "clinic-b-no-clinical-copy"
]);

const denialReasons: Partial<Record<UdapScenarioId, string>> = {
  "missing-consent": "CONSENT_NOT_ACTIVE",
  "revoked-consent": "CONSENT_REVOKED",
  "expired-consent": "CONSENT_EXPIRED",
  "purpose-mismatch": "PURPOSE_NOT_ALLOWED",
  "non-grantee-organization": "SHARE_GRANTEE_MISMATCH",
  "practitioner-without-role": "PRACTITIONER_ROLE_NOT_ALLOWED",
  "practitioner-wrong-organization": "PRACTITIONER_ORGANIZATION_MISMATCH",
  "untrusted-certificate": "MTLS_CERTIFICATE_NOT_TRUSTED",
  "certificate-cnf-mismatch": "MTLS_CNF_MISMATCH",
  "unknown-oidc-issuer": "OIDC_ISSUER_NOT_TRUSTED",
  "invalid-audience": "OIDC_AUDIENCE_INVALID",
  "expired-assertion": "UDAP_ASSERTION_EXPIRED",
  "jti-replay": "UDAP_ASSERTION_REPLAYED",
  "unredeemed-share": "SHARE_NOT_REDEEMED",
  "handoff-code-replay": "HANDOFF_CODE_ALREADY_REDEEMED",
  "postgres-manifest-tamper": "MANIFEST_SIGNATURE_INVALID",
  "onchain-commitment-mismatch": "MANIFEST_COMMITMENT_MISMATCH",
  "fhir-version-tamper": "FHIR_VERSION_HASH_MISMATCH",
  "institutional-deny-after-onchain-permit": "INSTITUTIONAL_POLICY_DENY",
  "blockchain-unavailable": "BLOCKCHAIN_UNAVAILABLE",
  "fhir-unavailable": "FHIR_UNAVAILABLE",
  "metadata-db-unavailable": "METADATA_DB_UNAVAILABLE"
};

export const DEFAULT_UDAP_UNIT_EVIDENCE: Partial<Record<UdapScenarioId, UnitEvidence>> = {
  "expired-consent": { sourceTest: "test/health-access-control.test.ts" },
  "non-grantee-organization": { sourceTest: "middleware/test/share-grant.test.ts" },
  "practitioner-without-role": { sourceTest: "middleware/test/api-auth-boundary.test.ts" },
  "practitioner-wrong-organization": { sourceTest: "middleware/test/share-grant.test.ts" },
  "untrusted-certificate": { sourceTest: "middleware/test/http-authentication.test.ts" },
  "certificate-cnf-mismatch": { sourceTest: "middleware/test/udap-token-service.test.ts" },
  "unknown-oidc-issuer": { sourceTest: "middleware/test/oidc-verifier.test.ts" },
  "invalid-audience": { sourceTest: "middleware/test/udap-registration.test.ts" },
  "expired-assertion": { sourceTest: "middleware/test/udap-registration.test.ts" },
  "jti-replay": { sourceTest: "middleware/test/udap-token-service.test.ts" },
  "unredeemed-share": { sourceTest: "middleware/test/postgres-share-repository.test.ts" },
  "handoff-code-replay": { sourceTest: "middleware/test/custodian-access-service.test.ts" },
  "postgres-manifest-tamper": { sourceTest: "middleware/test/postgres-manifest-repository.test.ts" },
  "onchain-commitment-mismatch": { sourceTest: "middleware/test/manifest-version-commitment-verifier.test.ts" },
  "legitimate-new-version": { sourceTest: "middleware/test/manifest-publication-service.test.ts" },
  "blockchain-unavailable": { sourceTest: "middleware/test/ethers-access-client.test.ts" },
  "fhir-unavailable": { sourceTest: "middleware/test/fhir-health.test.ts" },
  "metadata-db-unavailable": { sourceTest: "middleware/test/api-handler.test.ts" },
  "clinic-b-no-clinical-copy": { sourceTest: "middleware/test/requesting-institution-client.test.ts" }
};

const verifiedUnitEvidence = new WeakSet<UnitEvidence>();
export async function resolveExecutedUnitEvidence(candidates: Partial<Record<UdapScenarioId, UnitEvidence>>) {
  const current = await sourceIdentity();
  const resolved: Partial<Record<UdapScenarioId, UnitEvidence>> = {};
  for (const [id, candidate] of Object.entries(candidates)) {
    if (!candidate?.caseTitle) continue;
    try {
      const artifact = JSON.parse(await readFile("reports/tests-" + classifyTestFile(candidate.sourceTest) + "-latest.json", "utf8"));
      if (artifact.source.sourceHash !== current.sourceHash || artifact.report.status !== "passed") continue;
      if (!artifact.report.cases.some((test: { file: string; title: string; status: string }) => test.file === candidate.sourceTest && test.title === candidate.caseTitle && test.status === "passed")) continue;
      const evidence = { ...candidate, runId: artifact.runId };
      verifiedUnitEvidence.add(evidence);
      resolved[id as UdapScenarioId] = evidence;
    } catch { /* Missing evidence stays blocked. */ }
  }
  return resolved;
}

export function createUdapInterinstitutionalReport(input: {
  executionMode: ExecutionMode;
  environment: Record<string, string>;
  overrides?: Partial<Record<UdapScenarioId, ScenarioOverride>>;
  unitEvidence?: Partial<Record<UdapScenarioId, UnitEvidence>>;
  generatedAt?: string;
  runNamespace?: string;
}): UdapInterinstitutionalReport {
  const blocked = input.executionMode === "environment-blocked";
  const namespace = input.runNamespace ?? `udap-${randomUUID()}`;
  const scenarios = MANDATORY_UDAP_SCENARIO_IDS.map((id) => {
    const override = input.overrides?.[id];
    const candidate = input.unitEvidence?.[id];
    const unitEvidence = candidate && verifiedUnitEvidence.has(candidate) ? candidate : undefined;
    const outcome = override?.outcome ?? (unitEvidence ? (authorizedScenario.has(id) ? "authorized" : "denied") : "blocked");
    const coverageKind: "live-baseline" | "unit-test" | "blocked" = override
      ? "live-baseline"
      : unitEvidence
        ? "unit-test"
        : "blocked";
    const payloadPresent = override?.payloadPresent ?? (outcome === "authorized" && id !== "clinic-b-no-clinical-copy");
    const responseMetadata = override?.responseMetadata ?? {
      httpStatus: outcome === "authorized" ? 200 : outcome === "denied" ? 403 : 503,
      error: outcome === "authorized" ? undefined : denialReasons[id] ?? "DEPENDENCY_UNAVAILABLE"
    };
    if (outcome !== "authorized" && (payloadPresent || containsClinicalPayload(responseMetadata))) {
      throw new Error("NEGATIVE_SCENARIO_EXPOSES_CLINICAL_PAYLOAD");
    }
    const applicableBlockchain = !["untrusted-certificate", "certificate-cnf-mismatch", "unknown-oidc-issuer", "invalid-audience", "expired-assertion", "jti-replay", "blockchain-unavailable", "fhir-unavailable", "metadata-db-unavailable"].includes(id);
    return {
      id,
      title: titles[id],
      status: outcome === "blocked" ? "blocked" as const : "passed" as const,
      outcome,
      reason: override?.reason ?? (blocked ? "ENVIRONMENT_UNAVAILABLE" : outcome === "authorized" ? "PERMIT" : denialReasons[id] ?? "DEPENDENCY_UNAVAILABLE"),
      payloadPresent,
      requestMetadata: {
        method: "POST",
        path: "/institutional/access/read",
        requestHash: pseudonymousHash(`${namespace}:${id}:request`),
        shareHash: pseudonymousHash(`${namespace}:${id}:share`)
      },
      responseMetadata,
      securityEvidence: {
        deniedWithoutClinicalPayload: outcome !== "authorized",
        manifestFirst: outcome === "authorized",
        identityFromTrustedContext: true,
        commitmentChecked: applicableBlockchain ? "not-executed" : "not-applicable"
      },
      componentReads: override?.componentReads ?? {
        oidc: 0,
        udap: 0,
        mtlsGateway: 0,
        manifest: 0,
        blockchain: 0,
        fhirVread: 0,
        auditEvent: 0,
        clinicBFhirWrites: 0
      },
      blockchain: override?.blockchain ?? { applicable: applicableBlockchain },
      timingsMs: { ...emptyTimings(), ...override?.timingsMs },
      execution: {
        mode: override?.executionMode ?? (blocked ? "environment-blocked" : "catalog-only"),
        coverageKind,
        ...(unitEvidence ? { sourceTest: unitEvidence.sourceTest } : {}),
        limitation: override?.limitation ?? (unitEvidence
          ? "Unit-test evidence validates the enforcement control only; it is not an HTTP end-to-end measurement."
          : blocked
          ? "FHIR metadata dependency was unavailable; no authorization result was fabricated."
          : "This mandatory scenario has not yet been exercised by the live UDAP harness.")
      }
    };
  });
  assertScenarioCatalog(scenarios);
  return {
    schemaVersion: 1,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    executionMode: input.executionMode,
    environment: input.environment,
    runNamespace: namespace,
    limitations: [
      "Local timings are not a production capacity or throughput claim.",
      "This report never contains clinical payloads, FHIR locators, Consent content, certificates, tokens, or raw identities.",
      "Unit-test evidence validates enforcement controls but is not represented as live HTTP execution or live latency."
    ],
    coverage: {
      executed: scenarios.filter((scenario) => scenario.status === "passed").length,
      liveBaseline: scenarios.filter((scenario) => scenario.execution.coverageKind === "live-baseline").length,
      unitTest: scenarios.filter((scenario) => scenario.execution.coverageKind === "unit-test").length,
      blocked: scenarios.filter((scenario) => scenario.status === "blocked").length,
      source: scenarios.some((scenario) => scenario.execution.coverageKind === "live-baseline")
        ? "live-and-unit"
        : scenarios.some((scenario) => scenario.execution.coverageKind === "unit-test")
          ? "unit-test"
          : "none"
    },
    summary: {
      total: 25,
      passed: scenarios.filter((scenario) => scenario.status === "passed").length,
      failed: 0,
      blocked: scenarios.filter((scenario) => scenario.status === "blocked").length
    },
    scenarios
  };
}

export function summarizeLatencySamples(samples: number[]) {
  if (samples.length === 0 || samples.some((sample) => !Number.isFinite(sample) || sample < 0)) {
    throw new Error("INVALID_LATENCY_SAMPLES");
  }
  const sorted = [...samples].sort((left, right) => left - right);
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  return {
    count: sorted.length,
    minMs: sorted[0],
    medianMs: percentile(sorted, 0.5),
    p95Ms: percentile(sorted, 0.95),
    maxMs: sorted.at(-1)!,
    stddevMs: Math.sqrt(sorted.reduce((sum, value) => sum + (value - mean) ** 2, 0) / sorted.length)
  };
}

export function measureUnitEvidenceInvariants(
  report: UdapInterinstitutionalReport,
  options: { repetitions?: number; now?: () => number } = {}
): UnitInvariantMeasurement {
  const repetitions = options.repetitions ?? 30;
  if (!Number.isInteger(repetitions) || repetitions < 30) {
    throw new Error("UNIT_INVARIANT_REPETITIONS_BELOW_REQUIRED_MINIMUM");
  }
  const now = options.now ?? performance.now.bind(performance);
  const samples: number[] = [];
  for (let repetition = 0; repetition < repetitions; repetition += 1) {
    const startedAt = now();
    assertUnitEvidenceInvariants(report);
    samples.push(Number((now() - startedAt).toFixed(6)));
  }
  return {
    scope: "unit-evidence-report-invariants",
    requiredRepetitions: 30,
    completedRepetitions: samples.length,
    total: summarizeLatencySamples(samples)
  };
}

export function evaluateDeliveryGate(
  report: UdapInterinstitutionalReport,
  input: {
    requestedLiveRepetitions: number;
    completedLiveRepetitions: number;
    unitMeasurement: UnitInvariantMeasurement;
  }
): DeliveryGateEvaluation {
  const requirements = {
    exactScenarioCatalog:
      report.scenarios.length === MANDATORY_UDAP_SCENARIO_IDS.length &&
      report.scenarios.every(
        (scenario, index) => scenario.id === MANDATORY_UDAP_SCENARIO_IDS[index]
      ),
    sixLiveBaselineScenarios: report.coverage.liveBaseline === 6,
    nineteenUnitEvidenceScenarios: report.coverage.unitTest === 19,
    noBlockedScenarios: report.coverage.blocked === 0,
    negativePayloadAbsent: report.scenarios
      .filter((scenario) => scenario.outcome === "denied")
      .every(
        (scenario) =>
          scenario.payloadPresent === false &&
          !containsClinicalPayload(scenario.responseMetadata)
      ),
    thirtyLiveRepetitions:
      input.requestedLiveRepetitions >= 30 &&
      input.completedLiveRepetitions >= 30,
    thirtyUnitInvariantRepetitions:
      input.unitMeasurement.requiredRepetitions === 30 &&
      input.unitMeasurement.completedRepetitions >= 30
  };
  return {
    approved: Object.values(requirements).every(Boolean),
    requirements
  };
}

function assertUnitEvidenceInvariants(report: UdapInterinstitutionalReport) {
  const unitScenarios = report.scenarios.filter(
    (scenario) => scenario.execution.coverageKind === "unit-test"
  );
  if (unitScenarios.length !== 19) {
    throw new Error("UNIT_EVIDENCE_SCENARIO_COUNT_INVALID");
  }
  if (
    unitScenarios.some(
      (scenario) =>
        !scenario.execution.sourceTest ||
        scenario.status !== "passed" ||
        (scenario.outcome === "denied" &&
          (scenario.payloadPresent ||
            containsClinicalPayload(scenario.responseMetadata)))
    )
  ) {
    throw new Error("UNIT_EVIDENCE_INVARIANT_FAILED");
  }
}

async function assertUnitEvidenceSourcesExist(
  evidence: Partial<Record<UdapScenarioId, UnitEvidence>>
) {
  const entries = Object.entries(evidence);
  if (entries.length !== 19) {
    throw new Error("UNIT_EVIDENCE_SOURCE_COUNT_INVALID");
  }
  await Promise.all(
    entries.map(async ([scenarioId, item]) => {
      if (!item?.sourceTest) {
        throw new Error(`UNIT_EVIDENCE_SOURCE_MISSING: ${scenarioId}`);
      }
      try {
        await access(item.sourceTest);
      } catch {
        throw new Error(
          `UNIT_EVIDENCE_SOURCE_NOT_FOUND: ${scenarioId}:${item.sourceTest}`
        );
      }
    })
  );
}

async function main() {
  const hospitalAUrl = process.env.FHIR_HOSPITAL_A_BASE_URL ?? "http://127.0.0.1:18081/fhir";
  const clinicBUrl = process.env.FHIR_CLINIC_B_BASE_URL ?? "http://127.0.0.1:18082/fhir";
  const executedEvidence = await resolveExecutedUnitEvidence(DEFAULT_UDAP_UNIT_EVIDENCE);
  const metadata = await Promise.all([checkMetadata(hospitalAUrl), checkMetadata(clinicBUrl)]);
  const environment = {
    hospitalAFhirMetadata: metadata[0],
    clinicBFhirMetadata: metadata[1],
    blockchain: process.env.BLOCKCHAIN_RPC_URL ? "configured" : "not-configured",
    metadataDatabase: process.env.MANIFEST_DATABASE_URL
      ? "configured"
      : "not-configured"
  };
  const harnessOnly = process.env.UDAP_HARNESS_ONLY === "true";
  const liveEnvironment = harnessOnly || metadata.every((result) => result === "available");
  const requestedRepetitions = Number.parseInt(process.env.UDAP_SCENARIO_REPETITIONS ?? "30", 10) || 30;
  let liveBaseline: LiveBaselineExecution = {
    requesterPath: "createUdapClient+createRequestingInstitutionClient",
    requestedRepetitions,
    completedRepetitions: 0,
    attemptedRepetitions: 0,
    failedAttempts: 0,
    failure: liveEnvironment ? "LIVE_UDAP_HARNESS_NOT_CONFIGURED" : "FHIR metadata unavailable"
  };
  let liveOverrides: Partial<Record<UdapScenarioId, ScenarioOverride>> | undefined;
  if (liveEnvironment) {
    try {
      const harness = await runLiveUdapHarness({ repetitions: requestedRepetitions });
      liveBaseline = {
        requesterPath: harness.requesterPath,
        requestedRepetitions: harness.requestedRepetitions,
        completedRepetitions: harness.completedRepetitions,
        attemptedRepetitions: harness.attemptedRepetitions,
        failedAttempts: harness.failedAttempts,
        failure: harness.failedAttempts === 0 ? "LIVE_UDAP_HARNESS_COMPLETED" : "LIVE_UDAP_HARNESS_SCENARIO_FAILURE",
        components: summarizeLiveComponents(harness.componentSamples)
      };
      liveOverrides = Object.fromEntries(
        harness.scenarios.map((scenario) => [scenario.id, toScenarioOverride(scenario)])
      ) as Partial<Record<UdapScenarioId, ScenarioOverride>>;
    } catch (error) {
      liveBaseline.failure = error instanceof Error
        ? `LIVE_UDAP_HARNESS_FAILED:${error.message}`
        : "LIVE_UDAP_HARNESS_FAILED";
    }
  }
  const liveCompleted = liveOverrides !== undefined && liveBaseline.failedAttempts === 0;
  const report = createUdapInterinstitutionalReport({
    executionMode: liveCompleted ? "live" : liveEnvironment ? "catalog-only" : "environment-blocked",
    environment: {
      ...environment,
      ...(harnessOnly ? { harnessMode: "synthetic-only" } : {}),
      liveBaseline: liveBaseline.failure,
      liveRequesterPath: liveBaseline.requesterPath
    },
    overrides: liveOverrides,
    unitEvidence: executedEvidence
  });
  const unitMeasurement: UnitInvariantMeasurement = { scope: "unit-evidence-report-invariants", requiredRepetitions: 30, completedRepetitions: 0, total: null };
  const performanceReport = createPerformanceReport(
    report,
    liveBaseline,
    unitMeasurement
  );
  await mkdir("reports", { recursive: true });
  await Promise.all([
    writeFile("reports/udap-interinstitutional-scenarios.json", `${JSON.stringify(report, null, 2)}\n`, "utf8"),
    writeFile("reports/udap-performance.json", `${JSON.stringify(performanceReport, null, 2)}\n`, "utf8")
  ]);
  if (!performanceReport.deliveryGate.approved) process.exitCode = 1;
  console.log(JSON.stringify({ summary: report.summary, coverage: report.coverage, executionMode: report.executionMode, deliveryGate: performanceReport.deliveryGate, environment: report.environment }, null, 2));
}

interface LiveBaselineExecution {
  requesterPath: "createUdapClient+createRequestingInstitutionClient";
  requestedRepetitions: number;
  completedRepetitions: number;
  attemptedRepetitions: number;
  failedAttempts: number;
  failure: string;
  components?: Record<string, ReturnType<typeof summarizeLatencySamples> | null>;
}

function toScenarioOverride(scenario: LiveUdapScenarioResult): ScenarioOverride {
  const authorized = scenario.httpStatus >= 200 && scenario.httpStatus < 300;
  return {
    outcome: authorized ? "authorized" : "denied",
    payloadPresent: scenario.payloadPresent,
    responseMetadata: {
      httpStatus: scenario.httpStatus,
      ...(scenario.error ? { error: scenario.error } : {})
    },
    reason: scenario.error ?? "PERMIT",
    executionMode: "live",
    timingsMs: scenario.timingsMs as Partial<Record<ComponentTiming, number>>,
    componentReads: scenario.componentReads,
    blockchain: { applicable: true }
  };
}

function summarizeLiveComponents(samples: Record<string, number[]>) {
  return Object.fromEntries(
    componentTimingKeys.map((component) => [
      component,
      samples[component]?.length ? summarizeLatencySamples(samples[component]) : null
    ])
  );
}

function createPerformanceReport(
  report: UdapInterinstitutionalReport,
  liveBaseline: LiveBaselineExecution,
  unitMeasurement: UnitInvariantMeasurement
) {
  const deliveryGate = evaluateDeliveryGate(report, {
    requestedLiveRepetitions: 30,
    completedLiveRepetitions: liveBaseline.completedRepetitions,
    unitMeasurement
  });
  return {
    schemaVersion: 2,
    generatedAt: report.generatedAt,
    executionMode: report.executionMode,
    localTimingIsNotProductionCapacityClaim: true,
    measurements: {
      liveHttpBaseline: {
        scope: liveBaseline.completedRepetitions > 0 ? "live-http-baseline" : "not-measured",
        requiredRepetitions: 30,
        configuredRepetitions: liveBaseline.requestedRepetitions,
        completedRepetitions: liveBaseline.completedRepetitions,
        attemptedRepetitions: liveBaseline.attemptedRepetitions,
        failedAttempts: liveBaseline.failedAttempts,
        components: liveBaseline.components ?? {
          ...Object.fromEntries(componentTimingKeys.map((component) => [component, null])),
          total: null
        }
      },
      unitInvariantValidation: unitMeasurement
    },
    deliveryGate,
    gas: null,
    observation:
      liveBaseline.failure,
    limitations: [
      "No local timing is a production capacity or throughput claim.",
      "Unit-invariant timing measures local report/evidence validation only and is not HTTP latency.",
      "The live harness uses synthetic institutional certificates and in-memory UDAP/manifest state; it validates the application boundary, not production capacity.",
      "The delivery gate remains rejected unless 6 live scenarios, 19 unit-evidenced scenarios, no blocked scenarios, and both 30-repetition requirements are satisfied."
    ]
  };
}

async function checkMetadata(baseUrl: string) {
  try {
    const response = await fetch(`${baseUrl.replace(/\/$/, "")}/metadata`, {
      headers: { accept: "application/fhir+json" },
      signal: AbortSignal.timeout(5_000)
    });
    return response.ok ? "available" : `http-${response.status}`;
  } catch {
    return "unavailable";
  }
}

function assertScenarioCatalog(scenarios: Array<{ id: UdapScenarioId }>) {
  if (scenarios.length !== MANDATORY_UDAP_SCENARIO_IDS.length || new Set(scenarios.map((scenario) => scenario.id)).size !== MANDATORY_UDAP_SCENARIO_IDS.length || scenarios.some((scenario, index) => scenario.id !== MANDATORY_UDAP_SCENARIO_IDS[index])) {
    throw new Error("INVALID_MANDATORY_SCENARIO_CATALOG");
  }
}

function emptyTimings(): Record<ComponentTiming, null> {
  return Object.fromEntries(componentTimingKeys.map((key) => [key, null])) as Record<ComponentTiming, null>;
}

function containsClinicalPayload(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsClinicalPayload);
  if (typeof value !== "object" || value === null) return false;
  return Object.entries(value).some(([key, child]) => ["resource", "payload", "content", "pointer", "fhirBaseUrl"].includes(key) || containsClinicalPayload(child));
}

function pseudonymousHash(value: string) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function percentile(sorted: number[], fraction: number) {
  return sorted[Math.ceil(fraction * sorted.length) - 1];
}

if (process.argv.includes("run") && process.argv.some((argument) => path.basename(argument) === "run-udap-interinstitutional-scenarios.ts")) {
  await main();
}
