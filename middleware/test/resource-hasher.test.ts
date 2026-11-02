import { expect } from "chai";

import {
  canonicalizeFhirResource,
  extractFhirVersionId,
  hashFhirResource
} from "../src/fhir/resource-hasher.js";

describe("FHIR resource hasher", function () {
  it("creates the same canonical hash for semantically equal resources with reordered keys", function () {
    const first = {
      resourceType: "Observation",
      id: "obs-1",
      status: "final",
      subject: { reference: "Patient/maria" },
      valueQuantity: { value: 80, unit: "mmHg" }
    };
    const second = {
      valueQuantity: { unit: "mmHg", value: 80 },
      subject: { reference: "Patient/maria" },
      status: "final",
      id: "obs-1",
      resourceType: "Observation"
    };

    expect(canonicalizeFhirResource(first)).to.equal(canonicalizeFhirResource(second));
    expect(hashFhirResource(first)).to.equal(hashFhirResource(second));
  });

  it("changes the hash when clinical content changes", function () {
    const baseline = {
      resourceType: "Observation",
      id: "obs-1",
      status: "final",
      subject: { reference: "Patient/maria" },
      valueQuantity: { value: 80, unit: "mmHg" }
    };
    const tampered = {
      ...baseline,
      valueQuantity: { value: 120, unit: "mmHg" }
    };

    expect(hashFhirResource(tampered)).to.not.equal(hashFhirResource(baseline));
  });

  it("rejects resources without FHIR identity fields", function () {
    expect(() => hashFhirResource({ resourceType: "Observation" })).to.throw("FHIR_RESOURCE_WITHOUT_ID");
    expect(() => hashFhirResource({ id: "obs-1" })).to.throw("FHIR_RESOURCE_WITHOUT_RESOURCE_TYPE");
  });

  it("extracts a required FHIR version identifier", function () {
    expect(
      extractFhirVersionId({
        resourceType: "Observation",
        id: "obs-1",
        meta: { versionId: "7" }
      })
    ).to.equal("7");
    expect(() => extractFhirVersionId({ resourceType: "Observation", id: "obs-1" })).to.throw(
      "FHIR_VERSION_ID_REQUIRED"
    );
  });
});
