import { readFile } from "node:fs/promises";
import path from "node:path";

import { expect } from "chai";

import { checkDocumentation } from "../scripts/check-docs.js";

describe("documentation contract check", function () {
  const root = process.cwd();

  it("accepts the committed route, OpenAPI and security documentation", async function () {
    const result = await checkDocumentation({ root });

    expect(result.errors).to.deep.equal([]);
  });

  it("fails when the canonical patient Consent route is removed from the code fixture", async function () {
    const routeSource = await readFile(
      path.join(root, "middleware", "src", "api", "api-handler.ts"),
      "utf8"
    );
    const mutatedRouteSource = routeSource.replace(
      'path === "/patient/consents"',
      'path === "/patient/consents-removed"'
    );

    const result = await checkDocumentation({ root, routeSourceText: mutatedRouteSource });

    expect(result.errors.some((error) => error.includes("/patient/consents"))).to.equal(true);
  });

  it("fails when the canonical patient Consent method is changed in the code fixture", async function () {
    const routeSource = await readFile(
      path.join(root, "middleware", "src", "api", "api-handler.ts"),
      "utf8"
    );
    const mutatedRouteSource = routeSource.replace(
      'method === "POST" && path === "/patient/consents"',
      'method === "GET" && path === "/patient/consents"'
    );

    const result = await checkDocumentation({ root, routeSourceText: mutatedRouteSource });

    expect(result.errors.some((error) => error.includes("CODE_ROUTE_MARKER_MISSING:POST /patient/consents"))).to.equal(true);
  });

  it("fails when only the GET FHIR route marker is mutated in the code fixture", async function () {
    const routeSource = await readFile(
      path.join(root, "middleware", "src", "api", "api-handler.ts"),
      "utf8"
    );
    const mutatedRouteSource = routeSource.replace(
      'if (method === "GET" && path.startsWith("/fhir/"))',
      'if (method === "GET" && path.startsWith("/fhir-mutated/"))'
    );

    const result = await checkDocumentation({ root, routeSourceText: mutatedRouteSource });

    expect(result.errors).to.include("CODE_ROUTE_MARKER_MISSING:GET /fhir/{path}:if (method === \"GET\" && path.startsWith(\"/fhir/\"))");
  });

  it("fails when a required OpenAPI schema is removed from the fixture", async function () {
    const openApi = await readFile(path.join(root, "docs", "openapi.yaml"), "utf8");
    const mutatedOpenApi = openApi.replace(
      "PatientConsentCreateRequest:",
      "PatientConsentCreateRequestRemoved:"
    );

    const result = await checkDocumentation({ root, openApiText: mutatedOpenApi });

    expect(result.errors.some((error) => error.includes("PatientConsentCreateRequest"))).to.equal(true);
  });

  it("fails when the mTLS authentication marker is removed from OpenAPI", async function () {
    const openApi = await readFile(path.join(root, "docs", "openapi.yaml"), "utf8");
    const mutatedOpenApi = openApi.replaceAll("mutualTLS", "removedAuthenticationScheme");

    const result = await checkDocumentation({ root, openApiText: mutatedOpenApi });

    expect(result.errors).to.include("OPENAPI_MARKER_MISSING:mutualTLS");
  });

  it("fails when the runtime success status for a route is changed", async function () {
    const routeSource = await readFile(
      path.join(root, "middleware", "src", "api", "api-handler.ts"),
      "utf8"
    );
    const mutatedRouteSource = routeSource.replace(
      /status: 201,\r?\n      body: await dependencies\.patientConsents\.create/,
      "status: 200,\n      body: await dependencies.patientConsents.create"
    );

    const result = await checkDocumentation({ root, routeSourceText: mutatedRouteSource });

    expect(result.errors.some((error) => error.includes("CODE_ROUTE_STATUS_MISMATCH:POST /patient/consents"))).to.equal(true);
  });

  it("fails when a documented error status is removed from a canonical operation", async function () {
    const openApi = await readFile(path.join(root, "docs", "openapi.yaml"), "utf8");
    const mutatedOpenApi = openApi.replace(
      /        "400":\r?\n          \$ref: "#\/components\/responses\/Denied"\r?\n        "401":/,
      '        "401":'
    );

    const result = await checkDocumentation({ root, openApiText: mutatedOpenApi });

    expect(result.errors).to.include("OPENAPI_STATUS_MISSING:POST /patient/consents:400");
  });

  it("fails when a required 400 response loses its component schema reference", async function () {
    const openApi = await readFile(path.join(root, "docs", "openapi.yaml"), "utf8");
    const mutatedOpenApi = openApi.replace(
      /        "400":\r?\n          \$ref: "#\/components\/responses\/Denied"\r?\n        "401":/,
      "        \"400\":\n          description: missing response reference\n        \"401\":"
    );

    const result = await checkDocumentation({ root, openApiText: mutatedOpenApi });

    expect(result.errors).to.include("OPENAPI_RESPONSE_REF_MISSING:POST /patient/consents:400:#/components/responses/Denied");
  });

  it("fails when the manual gateway and client-certificate pairing is changed", async function () {
    const manual = await readFile(path.join(root, "docs", "manual-e2e.md"), "utf8");
    const mutatedDocumentation = manual.replace(
      "Hospital A gateway (https://localhost:3001) expects Organization/clinic-b and .local/pki/clinic-b/client.crt",
      "Hospital A gateway (https://localhost:3001) expects Organization/hospital-a and .local/pki/hospital-a/client.crt"
    );

    const result = await checkDocumentation({ root, documentationText: mutatedDocumentation });

    expect(result.errors).to.include("DOCUMENTATION_MARKER_MISSING:Hospital A gateway (https://localhost:3001) expects Organization/clinic-b and .local/pki/clinic-b/client.crt");
  });

  it("fails when a normal curl mTLS example reintroduces SkipCertificateCheck", async function () {
    const manual = await readFile(path.join(root, "docs", "manual-e2e.md"), "utf8");
    const mutatedDocumentation = manual.replace(
      "curl.exe --fail-with-body --silent --show-error --cacert $caPath --cert $clinicBClientCertPath",
      "curl.exe --fail-with-body --silent --show-error --cacert $caPath -SkipCertificateCheck --cert $clinicBClientCertPath"
    );

    const result = await checkDocumentation({ root, documentationText: mutatedDocumentation });

    expect(result.errors).to.include("DOCUMENTATION_MTLS_SKIP_CERTIFICATE_CHECK");
  });

  it("fails when the first documented curl command uses the gateway's own certificate", async function () {
    const manual = await readFile(path.join(root, "docs", "manual-e2e.md"), "utf8");
    const mutatedDocumentation = manual.replace(
      "--cert $clinicBClientCertPath --key $clinicBClientKeyPath",
      "--cert $hospitalAClientCertPath --key $clinicBClientKeyPath"
    );

    const result = await checkDocumentation({ root, documentationText: mutatedDocumentation });

    expect(result.errors.some((error) => error.includes("DOCUMENTATION_MTLS_CERT_MISMATCH:Hospital A"))).to.equal(true);
  });

  it("fails when the first documented curl command uses the wrong CA", async function () {
    const manual = await readFile(path.join(root, "docs", "manual-e2e.md"), "utf8");
    const mutatedDocumentation = manual.replace(
      "--cacert $caPath --cert $clinicBClientCertPath",
      "--cacert $clinicBClientCertPath --cert $clinicBClientCertPath"
    );

    const result = await checkDocumentation({ root, documentationText: mutatedDocumentation });

    expect(result.errors.some((error) => error.includes("DOCUMENTATION_MTLS_CA_MISMATCH:Hospital A"))).to.equal(true);
  });

  it("fails when a canonical route loses its runtime authentication requirement", async function () {
    const routeSource = await readFile(
      path.join(root, "middleware", "src", "api", "api-handler.ts"),
      "utf8"
    );
    const mutatedRouteSource = routeSource.replaceAll("requirePatient(request)", "removedPatientAuthentication(request)");

    const result = await checkDocumentation({ root, routeSourceText: mutatedRouteSource });

    expect(result.errors.some((error) => error.includes("CODE_ROUTE_AUTH_MISSING:POST /patient/consents"))).to.equal(true);
  });

  it("fails when the OpenAPI operation loses its security requirement", async function () {
    const openApi = await readFile(path.join(root, "docs", "openapi.yaml"), "utf8");
    const mutatedOpenApi = openApi.replace(
      /      security:\r?\n        - oidcBearer: \[\]\r?\n      parameters:/,
      "      security: []\n      parameters:"
    );

    const result = await checkDocumentation({ root, openApiText: mutatedOpenApi });

    expect(result.errors.some((error) => error.includes("OPENAPI_SECURITY_MISSING:POST /patient/consents"))).to.equal(true);
  });

  it("fails when the OpenAPI denial schema loses its no-payload contract", async function () {
    const openApi = await readFile(path.join(root, "docs", "openapi.yaml"), "utf8");
    const mutatedOpenApi = openApi.replace(
      /      additionalProperties: false\r?\n      description: Error responses contain no clinical payload, FHIR locator or storage pointer\./,
      "      description: Error responses contain no clinical payload, FHIR locator or storage pointer."
    );

    const result = await checkDocumentation({ root, openApiText: mutatedOpenApi });

    expect(result.errors).to.include("OPENAPI_NO_PAYLOAD_CONTRACT_MISSING");
  });
});
