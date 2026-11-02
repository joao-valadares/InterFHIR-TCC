import { createHash } from "node:crypto";

import { E2E_SCENARIO_IDS, type E2ECheck, type E2EScenarioId } from "./e2e-fixtures.js";

export interface E2EScenarioReport {
  id: E2EScenarioId;
  status: "passed" | "failed" | "blocked";
  outcome: "authorized" | "denied" | "blocked";
  dataDelivery: "authorized" | "none" | "unexpected" | "unknown";
  httpStatus?: number;
  reason: string;
  responseHash?: string;
  observedReads?: Record<string, number>;
  policyEvidence?: {
    policyId: string;
    policyVersion: number;
    requiredRoleCode: number;
    requiredSpecialtyCode: number;
    professionalRoleCode: number;
    professionalSpecialtyCode: number;
    individualConstraint: boolean;
    pinnedVersion: string;
    currentVersion: string;
  };
}

export interface E2EReport {
  schemaVersion: 2;
  generatedAt: string;
  executionMode: "live" | "environment-blocked" | "failed";
  readiness: Array<Pick<E2ECheck, "service" | "status" | "reason">>;
  summary: {
    total: number;
    passed: number;
    failed: number;
    blocked: number;
  };
  scenarios: E2EScenarioReport[];
  evidence: {
    liveServices: boolean;
    realOidc: boolean;
    realMtls: boolean;
    realUdap: boolean;
    persistentBesu: boolean;
    persistentPostgres: boolean;
    hapiFhir: boolean;
  };
  limitations: string[];
}

export interface E2EHttpResponse {
  status: number;
  body: unknown;
}

export function createEnvironmentBlockedReport(input: {
  generatedAt: string;
  reason: string;
  checks: E2ECheck[];
}): E2EReport {
  const scenarios = E2E_SCENARIO_IDS.map((id) => ({
    id,
    status: "blocked" as const,
    outcome: "blocked" as const,
    dataDelivery: "unknown" as const,
    reason: input.reason,
    responseHash: pseudonymousHash(`${id}:${input.reason}`),
    observedReads: {}
  }));
  return {
    schemaVersion: 2,
    generatedAt: input.generatedAt,
    executionMode: "environment-blocked",
    readiness: input.checks.map(({ service, status, reason }) => ({ service, status, ...(reason ? { reason } : {}) })),
    summary: summarizeScenarios(scenarios),
    scenarios,
    evidence: {
      liveServices: false,
      realOidc: false,
      realMtls: false,
      realUdap: false,
      persistentBesu: false,
      persistentPostgres: false,
      hapiFhir: false
    },
    limitations: [
      "The live E2E did not execute because a required local dependency was unavailable.",
      "No authorization result, clinical response or local timing was fabricated."
    ]
  };
}

export function createFailedE2EReport(input: {
  generatedAt: string;
  reason: string;
  checks: E2ECheck[];
  completed: E2EScenarioReport[];
}): E2EReport {
  const completedIds = new Set(input.completed.map((scenario) => scenario.id));
  const scenarios = E2E_SCENARIO_IDS.map((id) => {
    const completed = input.completed.find((scenario) => scenario.id === id);
    if (completed) return completed;
    return {
      id,
      status: "blocked" as const,
      outcome: "blocked" as const,
      dataDelivery: "unknown" as const,
      reason: `E2E_NOT_COMPLETED:${input.reason}`,
      responseHash: pseudonymousHash(`${id}:${input.reason}`),
      observedReads: {}
    };
  });
  return {
    schemaVersion: 2,
    generatedAt: input.generatedAt,
    executionMode: "failed",
    readiness: input.checks.map(({ service, status, reason }) => ({ service, status, ...(reason ? { reason } : {}) })),
    summary: summarizeScenarios(scenarios),
    scenarios,
    evidence: {
      liveServices: true,
      realOidc: completedIds.has("authorized-consent-read"),
      realMtls: completedIds.has("authorized-consent-read"),
      realUdap: completedIds.has("authorized-consent-read"),
      persistentBesu: completedIds.has("authorized-consent-read"),
      persistentPostgres: completedIds.has("authorized-consent-read"),
      hapiFhir: completedIds.has("authorized-consent-read")
    },
    limitations: [
      "The live execution stopped after a non-environment failure; incomplete scenarios remain blocked.",
      "A failed execution is not a successful end-to-end authorization proof."
    ]
  };
}

export function assertReadinessGate(
  checks: Array<{ service: string; status: "ok" | "failed" | "blocked"; reason?: string }>
): void {
  const failure = checks.find((check) => check.status !== "ok");
  if (failure) {
    throw new Error(`E2E_READINESS_BLOCKED:${failure.service}:${failure.reason ?? "DEPENDENCY_UNAVAILABLE"}`);
  }
}

export function assertConsentProjectionResponse(
  response: Record<string, unknown>,
  mapped: { consentProjectionHash: string }
): void {
  if (response.consentHash !== mapped.consentProjectionHash) {
    throw new Error("E2E_CONSENT_PROJECTION_HASH_MISMATCH");
  }
}

export async function assertConsentProjectionChain(
  response: Record<string, unknown>,
  mapped: { consentHash: string; consentProjectionHash: string },
  readProjection: (consentHash: string) => Promise<unknown>
): Promise<void> {
  assertConsentProjectionResponse(response, mapped);
  const projection = await readProjection(mapped.consentHash);
  const active = Boolean(readProjectionField(projection, "active", 4));
  const version = Number(readProjectionField(projection, "consentVersion", 2));
  const projectionHash = String(readProjectionField(projection, "consentProjectionHash", 3));
  if (!active || version !== Number(response.consentVersion) || projectionHash !== mapped.consentProjectionHash) {
    throw new Error("E2E_CONSENT_CHAIN_PROJECTION_INVALID");
  }
}

export function assertNegativeResponse(
  response: E2EHttpResponse,
  expectedStatus: number | readonly number[]
): void {
  if (!Number.isInteger(response.status) || response.status < 400 || response.status >= 600) {
    throw new Error("E2E_NEGATIVE_RESPONSE_STATUS_INVALID");
  }
  if (response.status === 500) {
    throw new Error("E2E_NEGATIVE_RESPONSE_STATUS_UNEXPECTED");
  }
  const expected = Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus];
  if (!expected.includes(response.status)) {
    throw new Error(`E2E_NEGATIVE_RESPONSE_STATUS_UNEXPECTED:${response.status}`);
  }
  if (containsClinicalPayload(response.body)) {
    throw new Error("E2E_NEGATIVE_RESPONSE_CONTAINS_CLINICAL_PAYLOAD");
  }
}

export function assertSanitizedE2EReport(report: E2EReport): void {
  if (report.schemaVersion !== 2 || report.scenarios.length !== E2E_SCENARIO_IDS.length) {
    throw new Error("E2E_REPORT_SCHEMA_INVALID");
  }
  if (report.scenarios.some((scenario, index) => scenario.id !== E2E_SCENARIO_IDS[index])) {
    throw new Error("E2E_REPORT_SCENARIO_CATALOG_INVALID");
  }
  const actualSummary = summarizeScenarios(report.scenarios);
  if (JSON.stringify(actualSummary) !== JSON.stringify(report.summary)) {
    throw new Error("E2E_REPORT_SUMMARY_INVALID");
  }
  if (report.scenarios.some((scenario) => scenario.status === "passed" && scenario.outcome !== "authorized" && scenario.dataDelivery !== "none")) {
    throw new Error("E2E_REPORT_NEGATIVE_DELIVERY_INVALID");
  }
  if (report.scenarios.some(scenario => scenario.status === "passed" && scenario.outcome === "authorized" &&
    (scenario.httpStatus !== 200 || scenario.dataDelivery !== "authorized" ||
      scenario.observedReads?.fhirVread !== 1 || scenario.observedReads?.auditEvent !== 1 || scenario.observedReads?.commitmentCheck !== 1))) {
    throw new Error("E2E_REPORT_POSITIVE_EVIDENCE_INVALID");
  }
  inspectSanitizedValue(report);
}

export function summarizeScenarios(scenarios: E2EScenarioReport[]) {
  return {
    total: scenarios.length,
    passed: scenarios.filter((scenario) => scenario.status === "passed").length,
    failed: scenarios.filter((scenario) => scenario.status === "failed").length,
    blocked: scenarios.filter((scenario) => scenario.status === "blocked").length
  };
}

export function pseudonymousHash(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
}

function containsClinicalPayload(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsClinicalPayload);
  if (!isRecord(value)) return false;
  return Object.entries(value).some(([key, child]) =>
    isClinicalField(key) || isClinicalObject(child) || containsClinicalPayload(child)
  );
}

function readProjectionField(projection: unknown, name: string, index: number): unknown {
  if (isRecord(projection) && name in projection) return projection[name];
  if (Array.isArray(projection)) {
    const namedProjection = projection as unknown as Record<string, unknown>;
    const namedValue = namedProjection[name];
    if (namedValue !== undefined) return namedValue;
    return projection[index];
  }
  return undefined;
}

function inspectSanitizedValue(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(inspectSanitizedValue);
    return;
  }
  if (typeof value === "string") {
    const serialized = parseSerializedObject(value);
    if (serialized !== undefined) inspectSanitizedValue(serialized);
    if (isForbiddenSensitiveValue(value)) {
      throw new Error("E2E_REPORT_FORBIDDEN_SECRET_VALUE");
    }
    return;
  }
  if (!isRecord(value)) return;
  const normalizedKeys = Object.keys(value).map((key) => key.replace(/[^a-z0-9]/gi, "").toLowerCase());
  if (
    normalizedKeys.includes("d") ||
    normalizedKeys.includes("privatekey") ||
    normalizedKeys.includes("certificate") ||
    (normalizedKeys.includes("kty") && ["n", "e", "x", "y"].some((key) => normalizedKeys.includes(key)))
  ) {
    throw new Error("E2E_REPORT_FORBIDDEN_KEY_MATERIAL");
  }
  for (const [key, child] of Object.entries(value)) {
    if (key.toLowerCase() === "resourcetype" || key.toLowerCase() === "fhirresource") {
      throw new Error("E2E_REPORT_FORBIDDEN_CLINICAL_VALUE");
    }
    if (isForbiddenField(key)) {
      throw new Error(`E2E_REPORT_FORBIDDEN_FIELD:${key}`);
    }
    if (isClinicalObject(child)) {
      throw new Error("E2E_REPORT_FORBIDDEN_CLINICAL_VALUE");
    }
    inspectSanitizedValue(child);
  }
}

const FORBIDDEN_FIELD_PARTS = [
  "accesstoken",
  "idtoken",
  "refreshtoken",
  "clientassertion",
  "handoffcode",
  "authorization",
  "bearer",
  "secret",
  "password",
  "passphrase",
  "privatekey",
  "publickey",
  "certificate",
  "certchain",
  "pem",
  "jwk",
  "credential",
  "signingkey",
  "key",
  "cert",
  "token",
  "rawfhir",
  "clinicalpayload",
  "clinicaldata",
  "patient",
  "practitioner",
  "organization",
  "identity",
  "principal",
  "actor",
  "issuer",
  "clientid",
  "username",
  "email",
  "subject",
  "consentreference",
  "resourcereference",
  "fhirlocator",
  "fhirbaseurl",
  "pointer",
  "payload",
  "content",
  "resource",
  "manifest"
];

function isForbiddenField(key: string): boolean {
  const normalized = key.replace(/[^a-z0-9]/gi, "").toLowerCase();
  return FORBIDDEN_FIELD_PARTS.some((part) => normalized.includes(part));
}

function isClinicalField(key: string): boolean {
  const normalized = key.replace(/[^a-z0-9]/gi, "").toLowerCase();
  return [
    "resource",
    "resourcetype",
    "fhirresource",
    "clinicalpayload",
    "clinicaldata",
    "patientreference",
    "resourcereference",
    "consentreference",
    "fhirlocator",
    "fhirbaseurl"
  ].some((part) => normalized.includes(part));
}

function isClinicalObject(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return Object.keys(value).some((key) => {
    const normalized = key.replace(/[^a-z0-9]/gi, "").toLowerCase();
    return ["resourcetype", "fhirresource", "fhirversionid", "patientreference", "resourcereference"].includes(normalized);
  });
}

function isForbiddenSensitiveValue(value: string): boolean {
  if (/^sha256:[a-f0-9]{64}$/i.test(value)) return false;
  return (
    /-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE|PUBLIC KEY)-----/i.test(value) ||
    /\bBearer\s+[^\s,;}]+/i.test(value) ||
    /(?:Bearer\s+)?eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/i.test(value) ||
    /(?:"|')d(?:"|')\s*:\s*(?:"|')[^"']+(?:"|')/i.test(value) ||
    /(?:Patient|Practitioner|Organization|Observation|Consent|Bundle)\/[A-Za-z0-9._-]+/i.test(value) ||
    /(?:access[_-]?token|client[_-]?assertion|client[_-]?secret|password|passphrase|private[_-]?key|public[_-]?key|certificate|credential|secret)\s*[:=]\s*[^\s,;}]+/i.test(value)
  );
}

function parseSerializedObject(value: string): Record<string, unknown> | unknown[] | undefined {
  const trimmed = value.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return undefined;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    return isRecord(parsed) || Array.isArray(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
