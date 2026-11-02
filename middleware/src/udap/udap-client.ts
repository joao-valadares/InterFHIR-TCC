import { randomUUID } from "node:crypto";
import { request as httpsRequest } from "node:https";

import { SignJWT, createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";

import { assertUdapPublicJwk } from "../identity/key-material.js";

export interface UdapClientTlsOptions {
  key: string | Buffer;
  cert: string | Buffer;
  ca: string | Buffer;
  servername?: string;
}

export type UdapHttpRequestInit = {
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
  tls: UdapClientTlsOptions;
};

export interface UdapHttpResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type UdapHttpFetch = (
  url: string,
  init: UdapHttpRequestInit
) => Promise<UdapHttpResponse>;

export interface UdapDiscoveryMetadata {
  udap_versions_supported: string[];
  udap_profiles_supported: string[];
  udap_authorization_extensions_supported: string[];
  udap_authorization_extensions_required: string[];
  grant_types_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  token_endpoint: string;
  registration_endpoint: string;
  issuer: string;
  scopes_supported: string[];
  token_endpoint_auth_signing_alg_values_supported: string[];
  signed_metadata: string;
  jwks_uri?: string;
}

export interface UdapTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
}

export function createUdapClient(options: {
  discoveryTrust: { issuer: string; origin: string; jwks: JSONWebKeySet };
  clientId: string;
  organizationReference: string;
  certificateThumbprint: string;
  signingKey: CryptoKey | Uint8Array;
  signingKeyId: string;
  signingAlgorithm: "RS256" | "ES256";
  publicJwk: Record<string, unknown>;
  allowedScopes?: string[];
  fetch: UdapHttpFetch;
  now?: () => number;
}) {
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const allowedScopes = options.allowedScopes ?? ["system/Observation.r"];

  if (!nonEmpty(options.clientId) || !nonEmpty(options.organizationReference) || !nonEmpty(options.certificateThumbprint)) {
    throw new Error("UDAP_CLIENT_CONFIGURATION_INVALID");
  }
  assertUdapPublicJwk(options.publicJwk, "UDAP_CLIENT_PUBLIC_JWK_INVALID");
  if (options.publicJwk.alg !== options.signingAlgorithm) throw new Error("UDAP_CLIENT_PUBLIC_JWK_ALGORITHM_MISMATCH");
  if (!nonEmpty(options.signingKeyId) || allowedScopes.length === 0 || allowedScopes.some((scope) => !nonEmpty(scope))) {
    throw new Error("UDAP_CLIENT_CONFIGURATION_INVALID");
  }

  const verifyMetadata = async (metadata: UdapDiscoveryMetadata) => {
    const trust = options.discoveryTrust;
    if (!trust) throw new Error("UDAP_DISCOVERY_TRUST_NOT_CONFIGURED");
    try {
      const { payload } = await jwtVerify(metadata.signed_metadata, createLocalJWKSet(trust.jwks), {
        algorithms: ["RS256", "ES256"], issuer: trust.issuer, requiredClaims: ["exp", "iat", "iss"], currentDate: new Date(now() * 1000)
      });
      if (metadata.issuer !== trust.issuer || Number(payload.iat) > now()) throw new Error();
      for (const field of ["token_endpoint", "registration_endpoint", "jwks_uri"] as const) {
        if (metadata[field] !== payload[field]) throw new Error();
        if (metadata[field]) {
          const endpoint = new URL(metadata[field]);
          if (endpoint.protocol !== "https:" || endpoint.origin !== trust.origin || endpoint.username || endpoint.password || endpoint.hash) throw new Error();
        }
      }
    } catch { throw new Error("UDAP_SIGNED_METADATA_INVALID"); }
  };
  return {
    async discover(baseUrlOrDiscoveryUrl: string, tls: UdapClientTlsOptions): Promise<UdapDiscoveryMetadata> {
      const url = discoveryUrl(baseUrlOrDiscoveryUrl);
      if (!options.discoveryTrust || new URL(url).origin !== options.discoveryTrust.origin) throw new Error("UDAP_DISCOVERY_ORIGIN_UNTRUSTED");
      const response = await options.fetch(url, {
        method: "GET",
        headers: { accept: "application/json" },
        tls
      });
      const metadata = requireDiscoveryResponse(await responseBody(response, "UDAP_DISCOVERY"));
      await verifyMetadata(metadata);
      return metadata;
    },

    async createSoftwareStatement(input: { registrationEndpoint: string }): Promise<string> {
      requireHttpsEndpoint(input.registrationEndpoint, "UDAP_REGISTRATION_ENDPOINT_INVALID");
      const issuedAt = now();
      return new SignJWT({
        client_id: options.clientId,
        organization_reference: options.organizationReference,
        certificate_thumbprint: options.certificateThumbprint,
        jwks: [options.publicJwk],
        allowed_scopes: allowedScopes
      })
        .setProtectedHeader({ alg: options.signingAlgorithm, kid: options.signingKeyId, typ: "JWT" })
        .setIssuer(options.clientId)
        .setSubject(options.clientId)
        .setAudience(input.registrationEndpoint)
        .setJti(randomUUID())
        .setIssuedAt(issuedAt)
        .setExpirationTime(issuedAt + 300)
        .sign(options.signingKey);
    },

    async registerClient(input: {
      metadata: UdapDiscoveryMetadata;
      softwareStatement: string;
      tls: UdapClientTlsOptions;
    }): Promise<{ client_id: string; organizationReference: string }> {
      await verifyMetadata(input.metadata);
      assertDiscoverySupports(input.metadata, options.signingAlgorithm);
      const response = await postJson(options.fetch, input.metadata.registration_endpoint, input.tls, {
        software_statement: input.softwareStatement
      });
      if (!isRecord(response) || response.client_id !== options.clientId || response.organizationReference !== options.organizationReference) {
        throw new Error("UDAP_REGISTRATION_RESPONSE_INVALID");
      }
      return {
        client_id: response.client_id,
        organizationReference: response.organizationReference
      };
    },

    async createAssertion(input: {
      tokenEndpoint: string;
      practitionerReference: string;
      roleCode: string;
      purposeOfUse: string;
    }): Promise<string> {
      requireHttpsEndpoint(input.tokenEndpoint, "UDAP_TOKEN_ENDPOINT_INVALID");
      if (!nonEmpty(input.practitionerReference) || !nonEmpty(input.roleCode) || !nonEmpty(input.purposeOfUse)) {
        throw new Error("UDAP_ASSERTION_INPUT_INVALID");
      }
      const issuedAt = now();
      return new SignJWT({
        extensions: {
          "hl7-b2b": {
            version: "1",
            subject_id: input.practitionerReference,
            subject_role: input.roleCode,
            organization_id: options.organizationReference,
            purpose_of_use: [input.purposeOfUse]
          }
        }
      })
        .setProtectedHeader({ alg: options.signingAlgorithm, kid: options.signingKeyId, typ: "JWT" })
        .setIssuer(options.clientId)
        .setSubject(options.clientId)
        .setAudience(input.tokenEndpoint)
        .setJti(randomUUID())
        .setIssuedAt(issuedAt)
        .setExpirationTime(issuedAt + 300)
        .sign(options.signingKey);
    },

    async requestToken(input: {
      metadata: UdapDiscoveryMetadata;
      assertion: string;
      tls: UdapClientTlsOptions;
    }): Promise<UdapTokenResponse> {
      await verifyMetadata(input.metadata);
      assertDiscoverySupports(input.metadata, options.signingAlgorithm);
      const response = await postJson(options.fetch, input.metadata.token_endpoint, input.tls, {
        grant_type: "client_credentials",
        scope: allowedScopes[0],
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: input.assertion,
        udap: "1"
      });
      if (!isRecord(response) || !nonEmpty(response.access_token) || response.token_type !== "Bearer" || typeof response.expires_in !== "number" || response.expires_in <= 0 || response.expires_in > 300) {
        throw new Error("UDAP_TOKEN_RESPONSE_INVALID");
      }
      return {
        access_token: response.access_token,
        token_type: "Bearer",
        expires_in: response.expires_in
      };
    }
  };
}

/** Node HTTPS transport used by DCR, token, handoff redemption and reads. */
export function createMtlsUdapFetch(): UdapHttpFetch {
  return (url, init) => new Promise((resolve, reject) => {
    let target: URL;
    try {
      target = new URL(url);
    } catch {
      reject(new Error("UDAP_URL_INVALID"));
      return;
    }
    if (target.protocol !== "https:") {
      reject(new Error("UDAP_HTTPS_REQUIRED"));
      return;
    }
    const request = httpsRequest({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      method: init.method,
      key: init.tls.key,
      cert: init.tls.cert,
      ca: init.tls.ca,
      ...(init.tls.servername ? { servername: init.tls.servername } : {}),
      rejectUnauthorized: true,
      headers: init.headers
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve({
          status: response.statusCode ?? 0,
          ok: (response.statusCode ?? 0) >= 200 && (response.statusCode ?? 0) < 300,
          async json() {
            try {
              return JSON.parse(raw) as unknown;
            } catch {
              throw new Error("UDAP_HTTP_RESPONSE_INVALID");
            }
          }
        });
      });
    });
    request.on("error", reject);
    if (init.body !== undefined) request.write(init.body);
    request.end();
  });
}

function discoveryUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("UDAP_DISCOVERY_URL_INVALID");
  }
  if (url.protocol !== "https:") throw new Error("UDAP_HTTPS_REQUIRED");
  if (url.pathname.endsWith("/.well-known/udap")) return url.toString().replace(/\/$/, "");
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/fhir/.well-known/udap`;
  return url.toString().replace(/\/$/, "");
}

async function postJson(fetch: UdapHttpFetch, url: string, tls: UdapClientTlsOptions, body: Record<string, string>) {
  requireHttpsEndpoint(url, "UDAP_ENDPOINT_INVALID");
  const response = await fetch(url, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify(body),
    tls
  });
  return responseBody(response, "UDAP_HTTP");
}

async function responseBody(response: UdapHttpResponse, prefix: string): Promise<unknown> {
  const body = await response.json();
  if (!response.ok) {
    const error = isRecord(body) && typeof body.error === "string" && body.error.length > 0 ? body.error : "REMOTE_ERROR";
    throw new Error(`${prefix}_HTTP_${response.status}:${error}`);
  }
  return body;
}

function requireDiscoveryResponse(value: unknown): UdapDiscoveryMetadata {
  if (!isRecord(value) ||
    !stringArray(value.udap_versions_supported) ||
    !stringArray(value.udap_profiles_supported) ||
    !stringArray(value.udap_authorization_extensions_supported) ||
    !stringArray(value.udap_authorization_extensions_required) ||
    !stringArray(value.grant_types_supported) ||
    !stringArray(value.token_endpoint_auth_methods_supported) ||
    !stringArray(value.scopes_supported) ||
    !stringArray(value.token_endpoint_auth_signing_alg_values_supported) ||
    !nonEmpty(value.token_endpoint) ||
    !nonEmpty(value.registration_endpoint) ||
    !nonEmpty(value.issuer) ||
    !nonEmpty(value.signed_metadata)) {
    throw new Error("UDAP_DISCOVERY_RESPONSE_INVALID");
  }
  if (typeof value.jwks_uri !== "undefined" && !nonEmpty(value.jwks_uri)) {
    throw new Error("UDAP_DISCOVERY_RESPONSE_INVALID");
  }
  const metadata = value as unknown as UdapDiscoveryMetadata;
  assertDiscoverySupports(metadata);
  return metadata;
}

function assertDiscoverySupports(metadata: UdapDiscoveryMetadata, algorithm?: "RS256" | "ES256") {
  if (!metadata.udap_versions_supported.includes("1") ||
    !metadata.udap_profiles_supported.includes("udap_dcr") ||
    !metadata.udap_profiles_supported.includes("udap_authn") ||
    !metadata.udap_profiles_supported.includes("udap_authz") ||
    !metadata.udap_authorization_extensions_supported.includes("hl7-b2b") ||
    !metadata.udap_authorization_extensions_required.includes("hl7-b2b") ||
    !metadata.grant_types_supported.includes("client_credentials") ||
    !metadata.token_endpoint_auth_methods_supported.includes("private_key_jwt") ||
    !metadata.scopes_supported.includes("system/Observation.r") ||
    (algorithm !== undefined && !metadata.token_endpoint_auth_signing_alg_values_supported.includes(algorithm))) {
    throw new Error("UDAP_DISCOVERY_CAPABILITY_UNSUPPORTED");
  }
  requireHttpsEndpoint(metadata.issuer, "UDAP_ISSUER_INVALID");
  requireHttpsEndpoint(metadata.token_endpoint, "UDAP_TOKEN_ENDPOINT_INVALID");
  requireHttpsEndpoint(metadata.registration_endpoint, "UDAP_REGISTRATION_ENDPOINT_INVALID");
  if (metadata.jwks_uri !== undefined) requireHttpsEndpoint(metadata.jwks_uri, "UDAP_JWKS_URI_INVALID");
}

function requireHttpsEndpoint(value: string, error: string) {
  try {
    if (new URL(value).protocol !== "https:") throw new Error(error);
  } catch {
    throw new Error(error);
  }
}

function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every((entry) => nonEmpty(entry));
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
