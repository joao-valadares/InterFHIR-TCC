import type { FhirResource } from "../fhir/resource-hasher.js";
import type { AuthenticatedPrincipal } from "../auth/principal.js";
import type { CertificateIdentity } from "../pki/certificate-identity.js";
import { assertInstitutionBinding, requireInstitutionBinding } from "../config.js";
import { assertUdapTrustedJwks } from "../identity/key-material.js";
import type { JsonWebKeyRecord } from "../identity/key-material.js";
import type {
  PatientConsentCreateRequest,
  PatientConsentService
} from "../consent/patient-consent-service.js";

export interface ApiRequest {
  method: string;
  path: string;
  body?: unknown;
  authorization?: string;
  principal?: AuthenticatedPrincipal;
  certificateIdentity?: CertificateIdentity;
  idempotencyKey?: string;
  headers?: Record<string, string | undefined>;
}

export interface ApiResponse {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

export interface ApiReadRequest {
  resourceReference: string;
  patientReference: string;
  practitionerReference: string;
  organizationReference: string;
  purposeOfUse: string;
  requestTime: number;
  recordedAt: string;
}

export interface ApiFhirClient {
  readResource(resourceReference: string): Promise<FhirResource>;
  createResource(resource: FhirResource): Promise<FhirResource>;
  createAuditEvent(event: unknown): Promise<void>;
  health?(): Promise<boolean>;
}

export interface ApiManifestReadRequest {
  manifestId: string;
  practitionerReference: string;
  organizationReference: string;
  purposeOfUse: string;
  requestTime: number;
  recordedAt: string;
}

export interface ApiAccessService {
  handleRead?: (request: ApiReadRequest) => Promise<ApiResponse>;
  handleReadByManifest?: (request: ApiManifestReadRequest) => Promise<ApiResponse>;
  [key: string]: unknown;
}

export interface ApiAdminService {
  /** Institution to which this gateway is configured and administratively bound. */
  institutionReference: string;
  health?(): Promise<boolean>;
}

export interface HealthAccessApiDependencies {
  fhirClient: ApiFhirClient;
  accessService?: ApiAccessService;
  adminService: ApiAdminService;
  manifestRepository?: {
    health(): Promise<boolean>;
  };
  udap?: {
    issuerJwksUri?: string;
    issuerJwks?: { keys: JsonWebKeyRecord[] };
    discovery: { metadata(): Promise<unknown> };
    registration: { register(body: { software_statement: string }, certificate: { subjectOrganization: string; x5tS256: string }): Promise<unknown> };
    token: { issue(body: { grant_type: string; scope: string; client_assertion_type: string; client_assertion: string; udap: string }, certificate: { fingerprint256: string; x5tS256: string }): Promise<unknown> };
  };
  interfhir?: {
    redeemHandoff(input: { handoffCode: string; granteeOrganizationReference: string; now: string }): Promise<unknown>;
    getShare(input: { shareId: string; granteeOrganizationReference: string; now: string }): Promise<unknown>;
    readShare(input: { shareId: string; manifestId: string; requesterOrganizationReference: string; practitionerReference: string; operation: "read"; purposeOfUse: string; requestTime: string; requestId: string; assertionHash: string }): Promise<unknown>;
  };
  patientShares?: { create(input: { patientReference: string; granteeOrganizationReference: string; consentReference: string; resourceReferences: string[]; purposeOfUse: string; validUntil: string }): Promise<unknown> };
  patientConsents?: {
    create(input: Parameters<PatientConsentService["create"]>[0]): Promise<unknown>;
    revoke(input: Parameters<PatientConsentService["revoke"]>[0]): Promise<unknown>;
  };
}

export interface HealthAccessApiOptions {
  bootstrapEnabled?: boolean;
  institutionReference?: string;
  now?: () => number;
}

export function createHealthAccessApi(
  dependencies: HealthAccessApiDependencies,
  options: HealthAccessApiOptions = {}
) {
  const adminServiceInstitution = requireInstitutionBinding(
    dependencies.adminService.institutionReference
  );
  if (options.institutionReference !== undefined) {
    assertInstitutionBinding(
      options.institutionReference,
      adminServiceInstitution
    );
  }
  const effectiveOptions: HealthAccessApiOptions = {
    ...options,
    institutionReference: options.institutionReference ?? adminServiceInstitution
  };
  return {
    async handle(request: ApiRequest): Promise<ApiResponse> {
      try {
        return await route(request, dependencies, effectiveOptions);
      } catch (error) {
        return mapError(error);
      }
    }
  };
}

async function route(
  request: ApiRequest,
  dependencies: HealthAccessApiDependencies,
  options: HealthAccessApiOptions
): Promise<ApiResponse> {
  const method = request.method.toUpperCase();
  const path = normalizePath(request.path);

  if (method === "GET" && path === udapIssuerJwksPath(dependencies.udap?.issuerJwksUri)) {
    if (!dependencies.udap) return { status: 404, body: { error: "UDAP_NOT_CONFIGURED" } };
    const issuerJwks = publicIssuerJwks(dependencies.udap.issuerJwks);
    if (!issuerJwks) return { status: 503, body: { error: "UDAP_JWKS_UNAVAILABLE" } };
    return {
      status: 200,
      headers: { "content-type": "application/json" },
      body: issuerJwks
    };
  }

  if (method === "GET" && path === "/health") {
    const fhir = await optionalHealth(dependencies.fhirClient.health);
    const blockchain = await optionalHealth(dependencies.adminService.health);
    const manifests = await optionalHealth(
      dependencies.manifestRepository?.health
    );
    const healthy = fhir && blockchain && manifests;
    return {
      status: healthy ? 200 : 503,
      body: {
        status: healthy ? "ok" : "unavailable",
        fhir: healthText(fhir),
        blockchain: healthText(blockchain),
        ...(dependencies.manifestRepository
          ? { manifests: healthText(manifests) }
          : {}),
      }
    };
  }

  if (method === "GET" && path === "/fhir/.well-known/udap") {
    if (!dependencies.udap) return { status: 404, body: { error: "UDAP_NOT_CONFIGURED" } };
    return { status: 200, body: await dependencies.udap.discovery.metadata() };
  }

  if (method === "POST" && path === "/udap/register") {
    if (!dependencies.udap) return { status: 404, body: { error: "UDAP_NOT_CONFIGURED" } };
    const certificate = requireUdapCertificate(request);
    if ("status" in certificate) return certificate;
    return { status: 201, body: await dependencies.udap.registration.register({ software_statement: requireStringField(request.body, "software_statement") }, certificate) };
  }

  if (method === "POST" && path === "/udap/token") {
    if (!dependencies.udap) return { status: 404, body: { error: "UDAP_NOT_CONFIGURED" } };
    const certificate = requireUdapCertificate(request);
    if ("status" in certificate) return certificate;
    return { status: 200, body: await dependencies.udap.token.issue({ grant_type: requireStringField(request.body, "grant_type"), scope: requireStringField(request.body, "scope"), client_assertion_type: requireStringField(request.body, "client_assertion_type"), client_assertion: requireStringField(request.body, "client_assertion"), udap: requireStringField(request.body, "udap") }, { fingerprint256: certificate.fingerprint256, x5tS256: certificate.x5tS256 }) };
  }

  if (method === "POST" && path === "/interfhir/v1/shares/redeem") {
    if (!dependencies.interfhir) return { status: 404, body: { error: "INTERFHIR_NOT_CONFIGURED" } };
    const service = requireInstitutionService(request);
    if ("status" in service) return service;
    const certificate = requireUdapCertificate(request);
    if ("status" in certificate) return certificate;
    if (certificate.x5tS256 !== service.certificateThumbprint) return { status: 403, body: { error: "UDAP_TOKEN_CERTIFICATE_MISMATCH" } };
    return { status: 200, body: await dependencies.interfhir.redeemHandoff({ handoffCode: requireStringField(request.body, "handoffCode"), granteeOrganizationReference: service.organizationReference, now: new Date((options.now?.() ?? Math.floor(Date.now() / 1000)) * 1000).toISOString() }) };
  }

  const shareLookup = method === "GET" ? /^\/interfhir\/v1\/shares\/([^/]+)$/.exec(path) : undefined;
  if (shareLookup) {
    if (!dependencies.interfhir) return { status: 404, body: { error: "INTERFHIR_NOT_CONFIGURED" } };
    const service = requireInstitutionService(request);
    if ("status" in service) return service;
    const certificate = requireUdapCertificate(request);
    if ("status" in certificate) return certificate;
    if (certificate.x5tS256 !== service.certificateThumbprint) return { status: 403, body: { error: "UDAP_TOKEN_CERTIFICATE_MISMATCH" } };
    return { status: 200, body: await dependencies.interfhir.getShare({ shareId: decodeURIComponent(shareLookup[1]), granteeOrganizationReference: service.organizationReference, now: new Date((options.now?.() ?? Math.floor(Date.now() / 1000)) * 1000).toISOString() }) };
  }

  const patientConsentRevoke = method === "POST"
    ? /^\/patient\/consents\/(.+)\/revoke$/.exec(path)
    : undefined;
  if (patientConsentRevoke) {
    if (!dependencies.patientConsents) return { status: 404, body: { error: "PATIENT_CONSENTS_NOT_CONFIGURED" } };
    const patient = requirePatient(request);
    if ("status" in patient) return patient;
    return {
      status: 200,
      body: await dependencies.patientConsents.revoke({
        patientReference: patient.patientReference,
        consentReference: decodeURIComponent(patientConsentRevoke[1])
      })
    };
  }

  if (method === "POST" && path === "/patient/consents") {
    if (!dependencies.patientConsents) return { status: 404, body: { error: "PATIENT_CONSENTS_NOT_CONFIGURED" } };
    const patient = requirePatient(request);
    if ("status" in patient) return patient;
    const idempotencyKey = request.idempotencyKey ?? request.headers?.["idempotency-key"];
    if (!idempotencyKey) throw new Error("MISSING_IDEMPOTENCY_KEY");
    return {
      status: 201,
      body: await dependencies.patientConsents.create({
        patientReference: patient.patientReference,
        idempotencyKey,
        request: requirePatientConsentRequest(request.body)
      })
    };
  }

  if (method === "POST" && path === "/patient/shares") {
    return { status: 410, body: { error: "LEGACY_PATIENT_SHARE_ROUTE_DISABLED" } };
  }

  if (method === "POST" && path === "/interfhir/v1/access/read") {
    if (!dependencies.interfhir) return { status: 404, body: { error: "INTERFHIR_NOT_CONFIGURED" } };
    const service = requireInstitutionService(request);
    if ("status" in service) return service;
    const certificate = requireUdapCertificate(request);
    if ("status" in certificate) return certificate;
    if (certificate.x5tS256 !== service.certificateThumbprint) return { status: 403, body: { error: "UDAP_TOKEN_CERTIFICATE_MISMATCH" } };
    const purposeOfUse = requireStringField(request.body, "purposeOfUse");
    if (!service.purposeOfUse.includes(purposeOfUse)) return { status: 403, body: { error: "UDAP_PURPOSE_NOT_ALLOWED" } };
    const result = await dependencies.interfhir.readShare({ shareId: requireStringField(request.body, "shareId"), manifestId: requireStringField(request.body, "manifestId"), operation: requireStringField(request.body, "operation") as "read", purposeOfUse, requestId: requireStringField(request.body, "requestId"), requesterOrganizationReference: service.organizationReference, practitionerReference: service.practitionerReference, requestTime: new Date((options.now?.() ?? Math.floor(Date.now() / 1000)) * 1000).toISOString(), assertionHash: service.assertionHash });
    return isApiResponse(result) ? result : { status: 200, body: result };
  }

  if (method === "GET" && path.startsWith("/fhir/")) {
    return { status: 403, body: { error: "FHIR_DIRECT_ACCESS_BLOCKED" } };
  }

  if (method === "POST" && path.startsWith("/fhir/")) {
    return { status: 403, body: { error: "FHIR_DIRECT_ACCESS_BLOCKED" } };
  }

  if (path.startsWith("/fhir/")) {
    return { status: 403, body: { error: "FHIR_DIRECT_ACCESS_BLOCKED" } };
  }

  if (isRetiredGenericAdministrativeRoute(method, path)) {
    return { status: 410, body: { error: "LEGACY_ADMIN_ROUTE_DISABLED" } };
  }

  if (method === "POST" && path === "/access/read") {
    return {
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    };
  }

  if (method === "POST" && path === "/access/read-manifest") {
    return {
      status: 410,
      body: { error: "LEGACY_READ_ROUTE_DISABLED" }
    };
  }

  return { status: 404, body: { error: "ROUTE_NOT_FOUND" } };
}

function requireUdapCertificate(request: ApiRequest): { fingerprint256: string; subjectOrganization: string; x5tS256: string } | ApiResponse {
  if (!request.certificateIdentity) return { status: 401, body: { error: "MTLS_CERTIFICATE_REQUIRED" } };
  if (!request.certificateIdentity.x5tS256) return { status: 401, body: { error: "MTLS_CERTIFICATE_THUMBPRINT_REQUIRED" } };
  return { fingerprint256: request.certificateIdentity.fingerprint256, subjectOrganization: request.certificateIdentity.subjectOrganization, x5tS256: request.certificateIdentity.x5tS256 };
}

async function optionalHealth(check: (() => Promise<boolean>) | undefined) {
  if (!check) {
    return true;
  }
  try {
    return await check();
  } catch {
    return false;
  }
}

function healthText(value: boolean) {
  return value ? "ok" : "unavailable";
}

function normalizePath(path: string) {
  const cleanPath = path.split("?")[0] ?? "/";
  if (cleanPath.length > 1 && cleanPath.endsWith("/")) {
    return cleanPath.slice(0, -1);
  }
  return cleanPath;
}

function requireStringField(body: unknown, field: string) {
  const value = readField(body, field);
  if (typeof value !== "string" || value.length === 0) {
    throw missingField(field);
  }
  return value;
}

function optionalStringField(body: unknown, field: string) {
  const value = readField(body, field);
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value.length === 0) {
    throw missingField(field);
  }
  return value;
}

function readField(body: unknown, field: string) {
  if (!isRecord(body)) {
    return undefined;
  }
  return body[field];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function missingField(field: string) {
  const error = new Error("MISSING_FIELD") as Error & { field: string };
  error.field = field;
  return error;
}

function unknownField(field: string) {
  const error = new Error("UNKNOWN_FIELD") as Error & { field: string };
  error.field = field;
  return error;
}

function mapError(error: unknown): ApiResponse {
  if (error instanceof Error && error.message === "MISSING_FIELD") {
    return { status: 400, body: { error: "MISSING_FIELD", field: (error as Error & { field?: string }).field } };
  }
  if (error instanceof Error && error.message === "UNKNOWN_FIELD") {
    return { status: 400, body: { error: "UNKNOWN_FIELD", field: (error as Error & { field?: string }).field } };
  }
  if (error instanceof Error && error.message === "MANIFEST_NOT_FOUND") {
    return { status: 404, body: { error: error.message } };
  }
  if (
    error instanceof Error &&
    (error.message.startsWith("UNKNOWN_VAULT:") ||
      [
        "MANIFEST_POINTER_HASH_MISMATCH",
        "MANIFEST_POINTER_INVALID",
        "MANIFEST_STORAGE_KIND_INVALID",
        "MANIFEST_VAULT_MISMATCH",
        "UNTRUSTED_VAULT_LOCATION",
        "VAULT_CUSTODIAN_MISMATCH"
      ].includes(error.message))
  ) {
    return { status: 400, body: { error: error.message } };
  }
  if (
    error instanceof Error &&
    [
      "MANIFEST_NOT_ACTIVE",
      "MANIFEST_STORED_COMMITMENT_MISMATCH",
      "MANIFEST_COMMITMENT_MISMATCH",
      "MANIFEST_VERSION_ALREADY_EXISTS",
      "INVALID_MANIFEST_VERSION",
      "PREVIOUS_VERSION_HASH_MISMATCH"
    ].includes(error.message)
  ) {
    return { status: 409, body: { error: error.message } };
  }
  const code = safeApiErrorCode(error);
  if (isTemporaryMetadataStoreFailure(error)) {
    return { status: 503, body: { error: "METADATA_STORE_UNAVAILABLE" } };
  }
  if ([
    "MISSING_IDEMPOTENCY_KEY",
    "INVALID_IDEMPOTENCY_KEY",
    "PATIENT_REFERENCE_NOT_ALLOWED",
    "FHIR_BODY_NOT_ALLOWED",
    "PATIENT_REFERENCE_REQUIRED",
    "CONSENT_REQUEST_REQUIRED",
    "INVALID_CONSENT_REFERENCE",
    "INVALID_CONSENT_PERIOD",
    "INVALID_FHIR_DATETIME",
    "INVALID_REFERENCE",
    "INVALID_PATIENT_REFERENCE",
    "INVALID_GRANTEE_ORGANIZATION_REFERENCE",
    "INVALID_PRACTITIONER_REFERENCE",
    "INVALID_RESOURCE_REFERENCE",
    "INVALID_CONSENT_PURPOSE",
    "INVALID_POLICY_ID",
    "INVALID_POLICY_VERSION",
    "INVALID_POLICY_REFERENCE",
    "INVALID_POLICY_PURPOSE",
    "INVALID_POLICY_RESOURCE_TYPE",
    "INVALID_POLICY_ACTION",
    "INVALID_POLICY_ATTRIBUTES",
    "UNSUPPORTED_RESOURCE_TYPE",
    "UNSUPPORTED_ACTION",
    "UNSUPPORTED_POLICY_SCOPE",
    "UNSUPPORTED_PURPOSE",
    "DIRECTED_CONSENT_RESOURCE_SCOPE_UNSUPPORTED",
    "UDAP_SOFTWARE_STATEMENT_INVALID",
    "UDAP_SOFTWARE_STATEMENT_REQUIRED",
    "FHIR_RESOURCE_PATIENT_MISMATCH",
    "INVALID_POLICY_ROLE",
    "INVALID_POLICY_SPECIALTY",
    "INVALID_POLICY_EFFECTIVE_PERIOD",
    "INVALID_NETWORK_POLICY_DEFINITION_HASH",
    "NETWORK_POLICY_DEFINITION_HASH_MISMATCH",
    "UNKNOWN_NETWORK_POLICY",
    "UNKNOWN_NETWORK_POLICY_VERSION",
    "POLICY_PURPOSE_MISMATCH",
    "POLICY_RESOURCE_MISMATCH",
    "POLICY_ACTION_MISMATCH",
    "UNSUPPORTED_POLICY_ACTION",
    "CONSENT_BEFORE_POLICY_EFFECTIVE",
    "CONSENT_AFTER_POLICY_EXPIRY",
    "FHIR_CONSENT_POLICY_NOT_FOUND",
    "FHIR_CONSENT_POLICY_VERSION_NOT_FOUND",
    "FHIR_CONSENT_POLICY_REFERENCE_INVALID",
    "FHIR_CONSENT_POLICY_VERSION_INVALID",
    "FHIR_CONSENT_POLICY_SYSTEM_MISMATCH",
    "FHIR_CONSENT_POLICY_RESOURCE_MISMATCH",
    "FHIR_CONSENT_POLICY_ACTION_MISMATCH",
    "FHIR_CONSENT_POLICY_PURPOSE_MISMATCH",
    "FHIR_CONSENT_POLICY_NOT_EFFECTIVE",
    "FHIR_CONSENT_POLICY_EXPIRED",
    "FHIR_CONSENT_POLICY_ATTRIBUTES_MISMATCH",
    "FHIR_CONSENT_INVALID_PERIOD",
    "FHIR_CONSENT_RESOURCE_TYPE_MISMATCH",
    "FHIR_CONSENT_RESOURCE_SCOPE_INVALID",
    "FHIR_CONSENT_WITHOUT_ACTION",
    "FHIR_CONSENT_WITHOUT_PURPOSE",
    "FHIR_CONSENT_WITHOUT_RESOURCE_TYPE",
    "FHIR_CONSENT_WITHOUT_POLICY",
    "FHIR_CONSENT_WITHOUT_PRACTITIONER",
    "FHIR_CONSENT_AMBIGUOUS_ACTION",
    "FHIR_CONSENT_AMBIGUOUS_CLASS",
    "FHIR_CONSENT_AMBIGUOUS_ORGANIZATION",
    "FHIR_CONSENT_AMBIGUOUS_POLICY",
    "FHIR_CONSENT_AMBIGUOUS_PRACTITIONER",
    "FHIR_CONSENT_AMBIGUOUS_PURPOSE",
    "RESOURCE_IDENTITY_MISMATCH",
    "FHIR_CONSENT_SCOPE_MISMATCH",
    "REQUEST_ID_INVALID",
    "FHIR_RESOURCE_NOT_CONSENT",
    "FHIR_CONSENT_NOT_ACTIVE",
    "FHIR_CONSENT_WITHOUT_ID",
    "FHIR_CONSENT_WITHOUT_PROVISION",
    "FHIR_CONSENT_WITHOUT_PATIENT",
    "FHIR_CONSENT_WITHOUT_ORGANIZATION",
    "FHIR_CONSENT_WITHOUT_RESOURCE",
    "FHIR_CONSENT_WITHOUT_PERIOD_START",
    "FHIR_CONSENT_WITHOUT_PERIOD_END"
  ].includes(code)) {
    return { status: 400, body: { error: code } };
  }
  if ([
    "FHIR_CONSENT_PATIENT_MISMATCH",
    "INSTITUTION_NOT_REGISTERED",
    "PRACTITIONER_ORGANIZATION_MISMATCH",
    "POLICY_NOT_FOUND",
    "POLICY_NOT_ACTIVE",
    "POLICY_SCOPE_MISMATCH",
    "UDAP_REGISTRATION_ORGANIZATION_MISMATCH",
    "UDAP_REGISTRATION_CERTIFICATE_MISMATCH",
    "UDAP_ORGANIZATION_MISMATCH",
    "UDAP_CERTIFICATE_BINDING_MISMATCH",
    "UDAP_SCOPE_NOT_ALLOWED",
    "UDAP_PURPOSE_NOT_ALLOWED",
    "UDAP_ASSERTION_IAT_INVALID",
    "UDAP_ASSERTION_LIFETIME_INVALID",
    "HANDOFF_NOT_REDEEMED",
    "SHARE_NOT_ACTIVE",
    "SHARE_OUTSIDE_VALIDITY_PERIOD",
    "CONSENT_CHAIN_PROJECTION_MISMATCH",
    "ROLE_FORBIDDEN"
  ].includes(code)) {
    return { status: 403, body: { error: code } };
  }
  if (["RESOURCE_NOT_FOUND", "CONSENT_NOT_FOUND"].includes(code)) {
    return { status: 404, body: { error: code } };
  }
  if (["IDEMPOTENCY_RESULT_UNAVAILABLE", "IDEMPOTENCY_KEY_SCOPE_MISMATCH", "IDEMPOTENCY_OPERATION_IN_PROGRESS", "CONSENT_OPERATION_TERMINAL", "SHARE_NOT_REACTIVATABLE", "IDEMPOTENCY_DIGEST_MISSING", "SHARE_OPERATION_SCOPE_MISMATCH", "HANDOFF_ISSUE_INTERRUPTED", "HANDOFF_CODE_ALREADY_ISSUED", "HANDOFF_CODE_ALREADY_REDEEMED", "UDAP_ASSERTION_REPLAY", "CONSENT_CHAIN_CONFIRMATION_UNAVAILABLE", "CONSENT_OPERATION_LEASE_LOST"].includes(code)) {
    return { status: 409, body: { error: code } };
  }
  if ([
    "NETWORK_POLICY_VERSION_ALREADY_REGISTERED",
    "NETWORK_POLICY_DEFINITION_CONFLICT",
    "POLICY_VERSION_ALREADY_EXISTS",
    "CONSENT_VERSION_ALREADY_EXISTS",
    "FHIR_CONSENT_ORGANIZATION_CONFLICT",
    "POLICY_REGISTRATION_CONFLICT"
  ].includes(code)) {
    return { status: 409, body: { error: code } };
  }
  return { status: 500, body: { error: code } };
}

function isRetiredGenericAdministrativeRoute(method: string, path: string) {
  return (
    (method === "POST" && (
      path === "/setup/demo/participants" ||
      path === "/setup/demo/policy" ||
      path === "/policies/register" ||
      path === "/resources/register-hash" ||
      path === "/manifests/publish" ||
      path === "/manifests/revoke" ||
      path === "/consents/register" ||
      path === "/consents/revoke"
    )) ||
    (method === "GET" && path.startsWith("/manifests/"))
  );
}

const DEFAULT_UDAP_ISSUER_JWKS_PATH = "/.well-known/udap/jwks.json";

function udapIssuerJwksPath(uri: string | undefined) {
  if (!uri) return DEFAULT_UDAP_ISSUER_JWKS_PATH;
  try {
    const parsed = new URL(uri);
    return normalizePath(parsed.pathname);
  } catch {
    return DEFAULT_UDAP_ISSUER_JWKS_PATH;
  }
}

function publicIssuerJwks(value: { keys: JsonWebKeyRecord[] } | undefined) {
  if (!value || !Array.isArray(value.keys) || value.keys.length === 0) return undefined;
  try {
    assertUdapTrustedJwks(value.keys);
  } catch {
    return undefined;
  }
  return {
    keys: value.keys.map(projectPublicJwk)
  };
}

function projectPublicJwk(key: JsonWebKeyRecord): JsonWebKeyRecord {
  const common: JsonWebKeyRecord = {
    kty: key.kty,
    kid: key.kid,
    alg: key.alg,
    ...(typeof key.use === "string" ? { use: key.use } : {}),
    ...(Array.isArray(key.key_ops) && key.key_ops.every((value) => typeof value === "string")
      ? { key_ops: key.key_ops }
      : {})
  };
  if (key.kty === "RSA") {
    return { ...common, n: key.n, e: key.e };
  }
  return { ...common, crv: key.crv, x: key.x, y: key.y };
}

function safeApiErrorCode(error: unknown) {
  const message = error instanceof Error ? error.message : "INTERNAL_ERROR";
  return /^[A-Z][A-Z0-9_:-]{1,127}$/.test(message) ? message : "INTERNAL_ERROR";
}

function isTemporaryMetadataStoreFailure(error: unknown) {
  if (!(error instanceof Error)) return false;
  const code = (error as Error & { code?: unknown }).code;
  return code === "57P01" || code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "ECONNRESET";
}

function requirePractitioner(
  request: ApiRequest
): Extract<AuthenticatedPrincipal, { kind: "practitioner" }> | ApiResponse {
  if (!request.principal) {
    return { status: 401, body: { error: "AUTHENTICATION_REQUIRED" } };
  }
  if (request.principal.kind !== "practitioner") {
    return { status: 403, body: { error: "ROLE_FORBIDDEN" } };
  }
  return request.principal;
}

function requireStringArrayField(body: unknown, field: string): string[] {
  if (!isRecord(body) || !Array.isArray(body[field]) || !body[field].every((value) => typeof value === "string" && value.length > 0)) throw missingField(field);
  return body[field] as string[];
}

function requirePatientConsentRequest(body: unknown): PatientConsentCreateRequest {
  if (readField(body, "patientReference") !== undefined) {
    throw new Error("PATIENT_REFERENCE_NOT_ALLOWED");
  }
  if (readField(body, "resource") !== undefined || readField(body, "fhir") !== undefined || readField(body, "resourceType") !== undefined) {
    throw new Error("FHIR_BODY_NOT_ALLOWED");
  }
  if (isRecord(body)) {
    const allowedFields = new Set([
      "granteeOrganizationReference",
      "practitionerReference",
      "resourceReference",
      "purposeOfUse",
      "policyId",
      "policyVersion",
      "validUntil"
    ]);
    const unknown = Object.keys(body).find((field) => !allowedFields.has(field));
    if (unknown !== undefined) throw unknownField(unknown);
  }
  const policyVersion = readField(body, "policyVersion");
  if (typeof policyVersion !== "number" || !Number.isSafeInteger(policyVersion) || policyVersion < 1) {
    throw missingField("policyVersion");
  }
  const practitionerReference = optionalStringField(body, "practitionerReference");
  return {
    granteeOrganizationReference: requireStringField(body, "granteeOrganizationReference"),
    ...(practitionerReference ? { practitionerReference } : {}),
    resourceReference: requireStringField(body, "resourceReference"),
    purposeOfUse: requireStringField(body, "purposeOfUse"),
    policyId: requireStringField(body, "policyId"),
    policyVersion,
    validUntil: requireStringField(body, "validUntil")
  };
}

function requireInstitutionService(request: ApiRequest): Extract<AuthenticatedPrincipal, { kind: "service" }> | ApiResponse {
  if (!request.principal) return { status: 401, body: { error: "AUTHENTICATION_REQUIRED" } };
  if (request.principal.kind !== "service") return { status: 403, body: { error: "ROLE_FORBIDDEN" } };
  return request.principal;
}

function isApiResponse(value: unknown): value is ApiResponse {
  return typeof value === "object" && value !== null && "status" in value && "body" in value && typeof (value as { status?: unknown }).status === "number";
}
function requirePatient(request: ApiRequest): Extract<AuthenticatedPrincipal, { kind: "patient" }> | ApiResponse { if (!request.principal) return { status: 401, body: { error: "AUTHENTICATION_REQUIRED" } }; if (request.principal.kind !== "patient") return { status: 403, body: { error: "ROLE_FORBIDDEN" } }; return request.principal; }

function trustedRequestTime(options: HealthAccessApiOptions) {
  return options.now?.() ?? Math.floor(Date.now() / 1000);
}
