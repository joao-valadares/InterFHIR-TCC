import { expect } from "chai";

import {
  DEFAULT_UDAP_UNIT_EVIDENCE,
  MANDATORY_UDAP_SCENARIO_IDS,
  createUdapInterinstitutionalReport,
  evaluateDeliveryGate,
  measureUnitEvidenceInvariants,
  summarizeLatencySamples
} from "../../scripts/run-udap-interinstitutional-scenarios.js";
import { runLiveUdapHarness } from "../../scripts/udap-live-harness.js";

describe("UDAP interinstitutional scenario report", function () {
  it("requires the complete unique mandatory scenario catalog", function () {
    const report = createUdapInterinstitutionalReport({
      executionMode: "environment-blocked",
      environment: { fhirMetadata: "unavailable" }
    });

    expect(report.scenarios.map((scenario) => scenario.id)).to.deep.equal(
      MANDATORY_UDAP_SCENARIO_IDS
    );
    expect(report.summary).to.deep.equal({
      total: 25,
      passed: 0,
      failed: 0,
      blocked: 25
    });
    expect(report.scenarios.every((scenario) => scenario.payloadPresent === false)).to.equal(true);
  });

  it("rejects a negative scenario that exposes clinical payload fields", function () {
    expect(() =>
      createUdapInterinstitutionalReport({
        executionMode: "catalog-only",
        environment: { fhirMetadata: "available" },
        overrides: {
          "missing-consent": {
            outcome: "denied",
            payloadPresent: true,
            responseMetadata: { resource: "Observation/secret" }
          }
        }
      })
    ).to.throw("NEGATIVE_SCENARIO_EXPOSES_CLINICAL_PAYLOAD");
  });

  it("calculates local timing statistics without treating them as production capacity", function () {
    expect(summarizeLatencySamples([1, 2, 3, 4, 5])).to.deep.equal({
      count: 5,
      minMs: 1,
      medianMs: 3,
      p95Ms: 5,
      maxMs: 5,
      stddevMs: Math.sqrt(2)
    });
  });

  it("keeps a source-file reference blocked without an executed case at the current source revision", function () {
    const report = createUdapInterinstitutionalReport({
      executionMode: "catalog-only",
      environment: { fhirMetadata: "available" },
      unitEvidence: {
        "expired-consent": {
          sourceTest: "middleware/test/health-access-service.test.ts"
        }
      }
    });
    const covered = report.scenarios.find((scenario) => scenario.id === "expired-consent");
    const stillBlocked = report.scenarios.find((scenario) => scenario.id === "untrusted-certificate");

    expect(covered).to.deep.include({ status: "blocked", outcome: "blocked", payloadPresent: false });
    expect(covered?.execution).to.deep.include({ coverageKind: "blocked" });
    expect(stillBlocked).to.deep.include({ status: "blocked" });
  });

  it("refuses performance measurements of unexecuted evidence", function () {
    const report = createUdapInterinstitutionalReport({
      executionMode: "catalog-only",
      environment: { fhirMetadata: "available" },
      unitEvidence: DEFAULT_UDAP_UNIT_EVIDENCE
    });
    expect(() => measureUnitEvidenceInvariants(report)).to.throw("UNIT_EVIDENCE_SCENARIO_COUNT_INVALID");
  });

  it("keeps the gate closed until live UDAP coverage is produced", function () {
    const report = createUdapInterinstitutionalReport({
      executionMode: "catalog-only",
      environment: { fhirMetadata: "available" },
      unitEvidence: DEFAULT_UDAP_UNIT_EVIDENCE
    });
    const unitMeasurement = {
      scope: "unit-evidence-report-invariants" as const,
      requiredRepetitions: 30,
      completedRepetitions: 30,
      total: summarizeLatencySamples(Array.from({ length: 30 }, () => 1))
    };

    expect(evaluateDeliveryGate(report, {
      requestedLiveRepetitions: 30,
      completedLiveRepetitions: 1,
      unitMeasurement
    }).approved).to.equal(false);
    expect(evaluateDeliveryGate(report, {
      requestedLiveRepetitions: 30,
      completedLiveRepetitions: 30,
      unitMeasurement
    }).approved).to.equal(false);
  });

  it("executes the six baseline scenarios through the local mTLS UDAP gateway", async function (this: { timeout(ms: number): void }) {
    this.timeout(20_000);
    const result = await runLiveUdapHarness({ repetitions: 1 });

    expect(result.completedRepetitions).to.equal(1);
    expect(result.scenarios).to.have.length(6);
    expect(result.scenarios.map((scenario) => scenario.id)).to.deep.equal([
      "authorized-treat",
      "missing-consent",
      "revoked-consent",
      "purpose-mismatch",
      "fhir-version-tamper",
      "institutional-deny-after-onchain-permit"
    ]);
    expect(result.scenarios.every((scenario) => scenario.httpStatus === 200 || scenario.httpStatus === 403)).to.equal(true);
    expect(result.scenarios.find((scenario) => scenario.id === "authorized-treat")?.httpStatus).to.equal(200);
    expect(result.scenarios.find((scenario) => scenario.id === "fhir-version-tamper")?.error).to.equal("MANIFEST_RESOURCE_HASH_MISMATCH");
  });
});
