import { readFile } from "node:fs/promises";
import path from "node:path";

export interface DocumentationCheckOptions {
  root?: string;
  routeSourceText?: string;
  openApiText?: string;
  documentationText?: string;
}

export interface DocumentationCheckResult {
  errors: string[];
  checkedFiles: string[];
  jsonExamples: number;
}

interface RouteContract {
  method: string;
  path: string;
  sourceBlockMarker: string;
  sourceRequiredMarkers?: string[];
  sourceGlobalMarkers?: string[];
  sourceStatusMarkers?: string[];
  operationId: string;
  security?: string[];
  requestSchema?: string;
  responseSchema?: string;
  statuses: string[];
  errorResponseRefs?: Record<string, string>;
}

const DOCUMENT_FILES = [
  "README.md",
  "docs/manual-e2e.md",
  "docs/tcc-project-guide.md",
  "docs/reproducao.md",
  "docs/correspondencia-tcc-codigo.md",
  "docs/avaliacao-ampliada-2026-10-15.md",
  "docs/openapi.yaml"
] as const;

/**
 * This is the offline contract for the routes intentionally exposed by the
 * current handler. The checker validates this catalog against both the
 * handler source and the OpenAPI operations; it does not treat prose markers
 * as a substitute for either source.
 */
const ROUTE_CONTRACTS: RouteContract[] = [
  {
    method: "GET", path: "/health", sourceBlockMarker: 'if (method === "GET" && path === "/health")',
    sourceStatusMarkers: ["status: healthy ? 200 : 503"], operationId: "health", responseSchema: "HealthResponse", statuses: ["200", "503"]
  },
  {
    method: "GET", path: "/fhir/.well-known/udap", sourceBlockMarker: 'if (method === "GET" && path === "/fhir/.well-known/udap")',
    sourceStatusMarkers: ["status: 200"], operationId: "udapDiscovery", statuses: ["200", "404"], errorResponseRefs: { "404": "#/components/responses/NotFound" }
  },
  {
    method: "GET", path: "/.well-known/udap/jwks.json", sourceBlockMarker: 'if (method === "GET" && path === udapIssuerJwksPath',
    sourceGlobalMarkers: ["DEFAULT_UDAP_ISSUER_JWKS_PATH"], sourceStatusMarkers: ["status: 200", "status: 503"], operationId: "udapIssuerJwks", statuses: ["200", "404", "503"], errorResponseRefs: { "404": "#/components/responses/NotFound", "503": "#/components/responses/Unavailable" }
  },
  {
    method: "POST", path: "/udap/register", sourceBlockMarker: 'if (method === "POST" && path === "/udap/register")',
    sourceRequiredMarkers: ["requireUdapCertificate"], sourceStatusMarkers: ["status: 201"], operationId: "udapDynamicRegistration", security: ["mutualTLS"], requestSchema: "UdapRegistrationRequest", responseSchema: "UdapRegistrationResponse", statuses: ["201", "400", "401", "403", "404", "409", "500"], errorResponseRefs: { "400": "#/components/responses/Denied", "401": "#/components/responses/MtlsRequired", "403": "#/components/responses/Denied", "404": "#/components/responses/NotFound", "409": "#/components/responses/Conflict", "500": "#/components/responses/InternalError" }
  },
  {
    method: "POST", path: "/udap/token", sourceBlockMarker: 'if (method === "POST" && path === "/udap/token")',
    sourceRequiredMarkers: ["requireUdapCertificate"], sourceStatusMarkers: ["status: 200"], operationId: "udapToken", security: ["mutualTLS"], requestSchema: "UdapTokenRequest", responseSchema: "UdapTokenResponse", statuses: ["200", "400", "401", "403", "404", "409", "500"], errorResponseRefs: { "400": "#/components/responses/Denied", "401": "#/components/responses/MtlsRequired", "403": "#/components/responses/Denied", "404": "#/components/responses/NotFound", "409": "#/components/responses/Conflict", "500": "#/components/responses/InternalError" }
  },
  {
    method: "POST", path: "/patient/consents", sourceBlockMarker: 'if (method === "POST" && path === "/patient/consents")',
    sourceRequiredMarkers: ["requirePatient(request)"], sourceStatusMarkers: ["status: 201"], operationId: "createPatientConsent", security: ["oidcBearer"], requestSchema: "PatientConsentCreateRequest", responseSchema: "PatientConsentCreateResponse", statuses: ["201", "400", "401", "403", "404", "409", "500", "503"], errorResponseRefs: { "400": "#/components/responses/Denied", "401": "#/components/responses/AuthenticationRequired", "403": "#/components/responses/Denied", "404": "#/components/responses/NotFound", "409": "#/components/responses/Conflict", "500": "#/components/responses/InternalError", "503": "#/components/responses/Unavailable" }
  },
  {
    method: "POST", path: "/patient/consents/{consentReference}/revoke", sourceBlockMarker: "if (patientConsentRevoke)", sourceGlobalMarkers: ['const patientConsentRevoke = method === "POST"'],
    sourceRequiredMarkers: ["requirePatient(request)"], sourceStatusMarkers: ["status: 200"], operationId: "revokePatientConsent", security: ["oidcBearer"], responseSchema: "PatientConsentRevokeResponse", statuses: ["200", "400", "401", "403", "404", "409", "500", "503"], errorResponseRefs: { "400": "#/components/responses/Denied", "401": "#/components/responses/AuthenticationRequired", "403": "#/components/responses/Denied", "404": "#/components/responses/NotFound", "409": "#/components/responses/Conflict", "500": "#/components/responses/InternalError", "503": "#/components/responses/Unavailable" }
  },
  {
    method: "POST", path: "/interfhir/v1/shares/redeem", sourceBlockMarker: 'if (method === "POST" && path === "/interfhir/v1/shares/redeem")',
    sourceRequiredMarkers: ["requireInstitutionService(request)", "requireUdapCertificate"], sourceStatusMarkers: ["status: 200"], operationId: "redeemOneTimeHandoff", security: ["udapBearer", "mutualTLS"], requestSchema: "ShareRedeemRequest", responseSchema: "ShareRedeemResponse", statuses: ["200", "400", "401", "403", "404", "409", "500", "503"], errorResponseRefs: { "400": "#/components/responses/Denied", "401": "#/components/responses/AuthenticationRequired", "403": "#/components/responses/Denied", "404": "#/components/responses/NotFound", "409": "#/components/responses/Conflict", "500": "#/components/responses/InternalError", "503": "#/components/responses/Unavailable" }
  },
  {
    method: "GET", path: "/interfhir/v1/shares/{shareId}", sourceBlockMarker: "if (shareLookup)", sourceGlobalMarkers: ['const shareLookup = method === "GET"'],
    sourceRequiredMarkers: ["requireInstitutionService(request)", "requireUdapCertificate"], sourceStatusMarkers: ["status: 200"], operationId: "getShareSummary", security: ["udapBearer", "mutualTLS"], responseSchema: "ShareRedeemResponse", statuses: ["200", "400", "401", "403", "404", "409", "500", "503"], errorResponseRefs: { "400": "#/components/responses/Denied", "401": "#/components/responses/AuthenticationRequired", "403": "#/components/responses/Denied", "404": "#/components/responses/NotFound", "409": "#/components/responses/Conflict", "500": "#/components/responses/InternalError", "503": "#/components/responses/Unavailable" }
  },
  {
    method: "POST", path: "/interfhir/v1/access/read", sourceBlockMarker: 'if (method === "POST" && path === "/interfhir/v1/access/read")',
    sourceRequiredMarkers: ["requireInstitutionService(request)", "requireUdapCertificate"], sourceStatusMarkers: ["status: 200"], operationId: "readAuthorizedShare", security: ["udapBearer", "mutualTLS"], requestSchema: "InterFHIRReadRequest", responseSchema: "InterFHIRReadResponse", statuses: ["200", "400", "401", "403", "404", "409", "500", "503"], errorResponseRefs: { "400": "#/components/responses/Denied", "401": "#/components/responses/AuthenticationRequired", "403": "#/components/responses/Denied", "404": "#/components/responses/NotFound", "409": "#/components/responses/Conflict", "500": "#/components/responses/InternalError", "503": "#/components/responses/Unavailable" }
  },
  {
    method: "POST", path: "/patient/shares", sourceBlockMarker: 'if (method === "POST" && path === "/patient/shares")', sourceStatusMarkers: ["status: 410"], operationId: "retiredPatientShares", statuses: ["410"]
  },
  {
    method: "POST", path: "/access/read", sourceBlockMarker: 'if (method === "POST" && path === "/access/read")', sourceRequiredMarkers: ["LEGACY_READ_ROUTE_DISABLED"], sourceStatusMarkers: ["status: 410"], operationId: "retiredAccessRead", statuses: ["410"], errorResponseRefs: { "410": "#/components/responses/LegacyRead" }
  },
  {
    method: "POST", path: "/access/read-manifest", sourceBlockMarker: 'if (method === "POST" && path === "/access/read-manifest")', sourceRequiredMarkers: ["LEGACY_READ_ROUTE_DISABLED"], sourceStatusMarkers: ["status: 410"], operationId: "retiredAccessReadManifest", statuses: ["410"], errorResponseRefs: { "410": "#/components/responses/LegacyRead" }
  },
  {
    method: "GET", path: "/fhir/{path}", sourceBlockMarker: 'if (method === "GET" && path.startsWith("/fhir/"))', sourceRequiredMarkers: ["FHIR_DIRECT_ACCESS_BLOCKED"], sourceStatusMarkers: ["status: 403"], operationId: "blockedDirectFhirGet", statuses: ["403"], errorResponseRefs: { "403": "#/components/responses/FhirBlocked" }
  },
  {
    method: "POST", path: "/fhir/{path}", sourceBlockMarker: 'if (method === "POST" && path.startsWith("/fhir/"))', sourceRequiredMarkers: ["FHIR_DIRECT_ACCESS_BLOCKED"], sourceStatusMarkers: ["status: 403"], operationId: "blockedDirectFhirPost", statuses: ["403"], errorResponseRefs: { "403": "#/components/responses/FhirBlocked" }
  },
  ...[
    ["POST", "/setup/demo/participants", "retiredDemoParticipants"],
    ["POST", "/setup/demo/policy", "retiredDemoPolicy"],
    ["POST", "/policies/register", "retiredPolicyRegistration"],
    ["POST", "/resources/register-hash", "retiredResourceHash"],
    ["POST", "/manifests/publish", "retiredManifestPublish"],
    ["POST", "/manifests/revoke", "retiredManifestRevoke"],
    ["POST", "/consents/register", "retiredConsentRegistration"],
    ["POST", "/consents/revoke", "retiredConsentRevoke"],
    ["GET", "/manifests/{manifestId}", "retiredManifestRead"]
  ].map(([method, routePath, operationId]) => ({
    method, path: routePath, sourceBlockMarker: "if (isRetiredGenericAdministrativeRoute(method, path))", sourceGlobalMarkers: [routePath.includes("{manifestId}") ? 'path.startsWith("/manifests/")' : `path === "${routePath}"`, method === "POST" ? 'method === "POST" && (' : 'method === "GET" && path.startsWith("/manifests/")'], sourceRequiredMarkers: ["LEGACY_ADMIN_ROUTE_DISABLED"], sourceStatusMarkers: ["status: 410"], operationId, statuses: ["410"], errorResponseRefs: { "410": "#/components/responses/LegacyAdmin" }
  }))
];

const REQUIRED_SCHEMAS = [
  "PatientConsentCreateRequest",
  "PatientConsentCreateResponse",
  "PatientConsentRevokeResponse",
  "InterFHIRReadRequest",
  "InterFHIRReadResponse",
  "ShareRedeemRequest",
  "ShareRedeemResponse",
  "UdapRegistrationRequest",
  "UdapRegistrationResponse",
  "UdapTokenRequest",
  "UdapTokenResponse",
  "ErrorResponse",
  "HealthResponse"
] as const;

const REQUIRED_DOCUMENT_MARKERS = [
  "POST /patient/consents",
  "POST /interfhir/v1/shares/redeem",
  "POST /interfhir/v1/access/read",
  "GET /interfhir/v1/shares/{shareId}",
  "FHIR_DIRECT_ACCESS_BLOCKED",
  "LEGACY_READ_ROUTE_DISABLED",
  "Authorization: Bearer",
  "mTLS",
  "private_key_jwt",
  "iss === sub === client_id",
  "pending -> anchor -> active",
  "Docker/Keycloak/Postgres",
  "sem payload clínico",
  "Hospital A gateway (https://localhost:3001) expects Organization/clinic-b and .local/pki/clinic-b/client.crt",
  "Clinic B gateway (https://localhost:3002) expects Organization/hospital-a and .local/pki/hospital-a/client.crt",
  "--cacert $caPath",
  "--cert $clinicBClientCertPath",
  "--key $clinicBClientKeyPath"
] as const;

export async function checkDocumentation(
  options: DocumentationCheckOptions = {}
): Promise<DocumentationCheckResult> {
  const root = options.root ?? path.resolve(process.cwd());
  const errors: string[] = [];
  const checkedFiles: string[] = [];
  const documents: string[] = [];

  for (const relativePath of DOCUMENT_FILES) {
    if (relativePath === "docs/openapi.yaml" && options.openApiText !== undefined) {
      documents.push(options.openApiText);
      checkedFiles.push(relativePath);
      continue;
    }
    if (relativePath === "README.md" && options.documentationText !== undefined) {
      documents.push(options.documentationText);
      checkedFiles.push(relativePath);
      continue;
    }
    try {
      documents.push(await readFile(path.join(root, relativePath), "utf8"));
      checkedFiles.push(relativePath);
    } catch {
      errors.push(`MISSING_DOCUMENT:${relativePath}`);
    }
  }

  const documentationText = options.documentationText ?? documents.join("\n");
  const openApiText = options.openApiText ?? await readOptional(root, "docs/openapi.yaml", errors);
  const routeSourceText = options.routeSourceText ?? await readOptional(root, "middleware/src/api/api-handler.ts", errors);

  validateRuntimeCatalog(routeSourceText, errors);
  validateOpenApi(openApiText, errors);

  for (const route of ROUTE_CONTRACTS) {
    const operationBlock = yamlOperationBlock(openApiText, route.path, route.method);
    if (operationBlock === undefined) {
      errors.push(`OPENAPI_OPERATION_MISSING:${route.method} ${route.path}`);
    } else {
      validateOpenApiOperation(route, operationBlock, errors);
    }

    if (!documentationText.includes(`${route.method} ${route.path}`) && !documentationText.includes(route.path)) {
      errors.push(`DOCUMENTED_ROUTE_MISSING:${route.method} ${route.path}`);
    }
  }

  for (const marker of REQUIRED_DOCUMENT_MARKERS) {
    if (!documentationText.includes(marker)) errors.push(`DOCUMENTATION_MARKER_MISSING:${marker}`);
  }
  validateManualMtlsCommands(documentationText, errors);
  if (documentationText.split(/\r?\n/).some((line) => line.includes("curl.exe") && line.includes("SkipCertificateCheck"))) {
    errors.push("DOCUMENTATION_MTLS_SKIP_CERTIFICATE_CHECK");
  }

  const jsonExamples = extractJsonExamples(documentationText, errors);
  if (jsonExamples < 6) errors.push(`JSON_EXAMPLES_TOO_FEW:${jsonExamples}`);

  return { errors, checkedFiles, jsonExamples };
}

function validateRuntimeCatalog(source: string, errors: string[]) {
  for (const route of ROUTE_CONTRACTS) {
    const block = sourceBlock(source, route.sourceBlockMarker);
    if (!block) {
      errors.push(`CODE_ROUTE_MARKER_MISSING:${route.method} ${route.path}:${route.sourceBlockMarker}`);
      continue;
    }
    for (const marker of route.sourceRequiredMarkers ?? []) {
      if (!block.includes(marker)) {
        const errorKind = marker.startsWith("require") ? "CODE_ROUTE_AUTH_MISSING" : "CODE_ROUTE_CONTRACT_MISSING";
        errors.push(`${errorKind}:${route.method} ${route.path}:${marker}`);
      }
    }
    for (const marker of route.sourceGlobalMarkers ?? []) {
      if (!source.includes(marker)) errors.push(`CODE_ROUTE_CONTRACT_MISSING:${route.method} ${route.path}:${marker}`);
    }
    for (const marker of route.sourceStatusMarkers ?? []) {
      if (!block.includes(marker)) errors.push(`CODE_ROUTE_STATUS_MISMATCH:${route.method} ${route.path}:${marker}`);
    }
  }
  if (!source.includes("function mapError") || !source.includes('body: { error: code }')) {
    errors.push("CODE_ERROR_RESPONSE_CONTRACT_MISSING");
  }
}

function validateOpenApi(openApi: string, errors: string[]) {
  for (const schema of REQUIRED_SCHEMAS) {
    const block = yamlBlock(openApi, `${schema}:`, 4);
    if (!block) errors.push(`OPENAPI_SCHEMA_MISSING:${schema}`);
  }

  const errorSchema = yamlBlock(openApi, "ErrorResponse:", 4);
  const errorProperties = errorSchema ? yamlBlock(errorSchema, "properties:", 6) : undefined;
  const propertyNames = errorProperties ? [...errorProperties.matchAll(/^        ([A-Za-z][A-Za-z0-9_]*):/gm)].map((match) => match[1]) : [];
  if (
    !errorSchema ||
    !errorSchema.includes("type: object") ||
    !errorSchema.includes("required: [error]") ||
    !errorSchema.includes("additionalProperties: false") ||
    !errorProperties ||
    !propertyHasType(errorProperties, "error", "string") ||
    propertyNames.some((name) => !["error", "field"].includes(name))
  ) {
    errors.push("OPENAPI_NO_PAYLOAD_CONTRACT_MISSING");
  }

  const responses = yamlBlock(openApi, "responses:", 2);
  for (const responseName of ["AuthenticationRequired", "MtlsRequired", "Denied", "Conflict", "Unavailable", "InternalError", "NotFound", "FhirBlocked", "LegacyRead", "LegacyAdmin"]) {
    const response = responses ? yamlBlock(responses, `${responseName}:`, 4) : undefined;
    if (!response || !response.includes("#/components/schemas/ErrorResponse")) {
      errors.push(`OPENAPI_ERROR_RESPONSE_SCHEMA_REF_MISSING:${responseName}`);
    }
  }

  const patientConsentSchema = yamlBlock(openApi, "PatientConsentCreateRequest:", 4);
  if (!patientConsentSchema || !patientConsentSchema.includes("additionalProperties: false")) {
    errors.push("OPENAPI_SCHEMA_CONTRACT_MISSING:PatientConsentCreateRequest:additionalProperties");
  }

  const tokenSchema = yamlBlock(openApi, "UdapTokenResponse:", 4);
  if (!tokenSchema || !propertyHasType(tokenSchema, "assertionHash", "string") || !propertyHasType(tokenSchema, "claims", "object")) {
    errors.push("OPENAPI_SCHEMA_CONTRACT_MISSING:UdapTokenResponse:assertionHash-or-claims");
  }

  const securitySchemes = yamlBlock(openApi, "securitySchemes:", 2);
  for (const scheme of ["oidcBearer", "udapBearer", "mutualTLS"]) {
    if (!securitySchemes || !yamlBlock(securitySchemes, `${scheme}:`, 4)) {
      errors.push(`OPENAPI_SECURITY_SCHEME_MISSING:${scheme}`);
    }
  }
  if (!openApi.includes("mutualTLS")) errors.push("OPENAPI_MARKER_MISSING:mutualTLS");
}

function validateOpenApiOperation(route: RouteContract, operation: string, errors: string[]) {
  const operationId = operation.match(/^\s{6}operationId:\s*([^\s#]+)/m)?.[1];
  if (operationId !== route.operationId) errors.push(`OPENAPI_OPERATION_ID_MISMATCH:${route.method} ${route.path}`);

  for (const security of route.security ?? []) {
    const expression = new RegExp(`(?:^|\\n)\\s*(?:-\\s*)?${escapeRegExp(security)}:`);
    if (!expression.test(operation)) errors.push(`OPENAPI_SECURITY_MISSING:${route.method} ${route.path}:${security}`);
  }
  if (route.requestSchema && !operation.includes(`#/components/schemas/${route.requestSchema}`)) {
    errors.push(`OPENAPI_REQUEST_SCHEMA_MISSING:${route.method} ${route.path}:${route.requestSchema}`);
  }
  if (route.responseSchema && !operation.includes(`#/components/schemas/${route.responseSchema}`)) {
    errors.push(`OPENAPI_RESPONSE_SCHEMA_MISSING:${route.method} ${route.path}:${route.responseSchema}`);
  }

  const statuses = [...operation.matchAll(/^\s{8}"(\d{3})":/gm)].map((match) => match[1]);
  for (const status of route.statuses) {
    if (!statuses.includes(status)) errors.push(`OPENAPI_STATUS_MISSING:${route.method} ${route.path}:${status}`);
  }
  for (const [status, expectedRef] of Object.entries(route.errorResponseRefs ?? {})) {
    const response = yamlBlock(operation, `"${status}":`, 8);
    const actualRef = response?.match(/^\s{10}\$ref:\s*"([^"]+)"/m)?.[1];
    if (actualRef !== expectedRef) {
      errors.push(`OPENAPI_RESPONSE_REF_MISSING:${route.method} ${route.path}:${status}:${expectedRef}`);
    }
  }
}

function validateManualMtlsCommands(documentationText: string, errors: string[]) {
  for (const line of documentationText.split(/\r?\n/)) {
    const isCurl = /^\s*(?:\$\w+\s*=\s*)?curl\.exe\b/.test(line);
    const isUdapNodeCommand = /^\s*npm run udap:(?:register-client|request)\b/.test(line);
    if (!isCurl && !isUdapNodeCommand) continue;

    const url = argumentValue(line, isCurl ? "--url" : "--base-url");
    if (!url) {
      errors.push(`DOCUMENTATION_MTLS_URL_MISSING:${isCurl ? "curl" : "udap"}`);
      continue;
    }

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      errors.push(`DOCUMENTATION_MTLS_URL_INVALID:${url}`);
      continue;
    }
    if (parsed.pathname === "/health") continue;
    if (parsed.protocol !== "https:") {
      errors.push(`DOCUMENTATION_MTLS_SCHEME_INVALID:${url}`);
    }
    const gateway = parsed.port === "3001" ? "Hospital A" : parsed.port === "3002" ? "Clinic B" : undefined;
    if (!gateway) {
      errors.push(`DOCUMENTATION_MTLS_GATEWAY_UNKNOWN:${url}`);
      continue;
    }

    const certFlag = isCurl ? "--cert" : "--tls-cert-path";
    const keyFlag = isCurl ? "--key" : "--tls-key-path";
    const caFlag = isCurl ? "--cacert" : "--tls-ca-path";
    const cert = argumentValue(line, certFlag);
    const key = argumentValue(line, keyFlag);
    const ca = argumentValue(line, caFlag);
    if (!cert) errors.push(`DOCUMENTATION_MTLS_CERT_MISSING:${gateway}`);
    if (!key) errors.push(`DOCUMENTATION_MTLS_KEY_MISSING:${gateway}`);
    if (!ca) errors.push(`DOCUMENTATION_MTLS_CA_MISSING:${gateway}`);

    const expected = gateway === "Hospital A"
      ? { cert: ["$clinicBClientCertPath", ".local/pki/clinic-b/client.crt"], key: ["$clinicBClientKeyPath", ".local/pki/clinic-b/client.key"] }
      : { cert: ["$hospitalAClientCertPath", ".local/pki/hospital-a/client.crt"], key: ["$hospitalAClientKeyPath", ".local/pki/hospital-a/client.key"] };
    if (cert && !expected.cert.includes(cert)) errors.push(`DOCUMENTATION_MTLS_CERT_MISMATCH:${gateway}:${cert}`);
    if (key && !expected.key.includes(key)) errors.push(`DOCUMENTATION_MTLS_KEY_MISMATCH:${gateway}:${key}`);
    if (ca && !["$caPath", ".local/pki/ca/ca.crt"].includes(ca)) errors.push(`DOCUMENTATION_MTLS_CA_MISMATCH:${gateway}:${ca}`);
  }
}

function argumentValue(line: string, name: string) {
  const match = line.match(new RegExp(`${escapeRegExp(name)}\\s+(?:"([^"]+)"|'([^']+)'|(\\S+))`));
  return match?.[1] ?? match?.[2] ?? match?.[3];
}

function yamlOperationBlock(openApi: string, routePath: string, method: string) {
  const pathBlock = yamlBlock(openApi, `${routePath}:`, 2);
  return pathBlock ? yamlBlock(pathBlock, `${method.toLowerCase()}:`, 4) : undefined;
}

function yamlBlock(text: string, header: string, indent: number): string | undefined {
  const lines = text.split(/\r?\n/);
  const expected = `${" ".repeat(indent)}${header}`;
  const start = lines.findIndex((line) => line === expected);
  if (start < 0) return undefined;
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.trim().length === 0) continue;
    const leadingSpaces = line.match(/^ */)?.[0].length ?? 0;
    if (leadingSpaces <= indent) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

function sourceBlock(source: string, marker: string) {
  const start = source.indexOf(marker);
  if (start < 0) return undefined;
  const nextTopLevelBranch = source.slice(start + marker.length).search(/\n  (?:if|const|return) /);
  return source.slice(start, nextTopLevelBranch < 0 ? source.length : start + marker.length + nextTopLevelBranch);
}

function propertyHasType(schema: string, property: string, type: string) {
  const expression = new RegExp(`${escapeRegExp(property)}:\\s*(?:\\{\\s*)?type:\\s*${escapeRegExp(type)}(?:\\s*[,}])?`);
  return expression.test(schema);
}

async function readOptional(root: string, relativePath: string, errors: string[]) {
  try {
    return await readFile(path.join(root, relativePath), "utf8");
  } catch {
    errors.push(`MISSING_SOURCE:${relativePath}`);
    return "";
  }
}

function extractJsonExamples(documentationText: string, errors: string[]) {
  const blocks = [...documentationText.matchAll(/(?:```|~~~)json\r?\n([\s\S]*?)(?:```|~~~)/g)];
  let valid = 0;
  for (const block of blocks) {
    try {
      JSON.parse(block[1]);
      valid += 1;
    } catch {
      errors.push("INVALID_JSON_EXAMPLE");
    }
  }
  return valid;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

if (process.argv[1] && path.basename(process.argv[1]) === "check-docs.ts") {
  const result = await checkDocumentation();
  if (result.errors.length > 0) {
    for (const error of result.errors) console.error(error);
    process.exitCode = 1;
  } else {
    console.log(JSON.stringify({ status: "ok", checkedFiles: result.checkedFiles, jsonExamples: result.jsonExamples }, null, 2));
  }
}
