import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";

import { importPKCS8 } from "jose";

import { createRequestingInstitutionClient } from "../middleware/src/interfhir/requesting-institution-client.js";
import { certificateIdentityFromPem } from "../middleware/src/pki/certificate-identity.js";
import { assertUdapPublicJwk } from "../middleware/src/identity/key-material.js";
import { createMtlsUdapFetch, createUdapClient } from "../middleware/src/udap/udap-client.js";

export async function runUdapRequester(argv: string[] = process.argv.slice(2), env: NodeJS.ProcessEnv = process.env) {
  const handoffCode = requiredArg(argv, "handoff-code");
  const expectedShareId = requiredArg(argv, "share-id");
  const expectedManifestId = requiredArg(argv, "manifest-id");
  const discoveryUrl = optionalArg(argv, "base-url") ?? env.UDAP_REQUESTER_BASE_URL ?? env.UDAP_CLINIC_B_DISCOVERY_URL ?? env.UDAP_DISCOVERY_URL;
  if (!discoveryUrl) throw new Error("MISSING_ARGUMENT:base-url-or-UDAP_REQUESTER_BASE_URL");
  const clientId = optionalArg(argv, "client-id") ?? "clinic-b-gateway";
  const organizationReference = optionalArg(argv, "organization-reference") ?? "Organization/clinic-b";
  const practitionerReference = optionalArg(argv, "practitioner-reference") ?? "Practitioner/bruno";
  const roleCode = optionalArg(argv, "role-code") ?? "physician";
  const purposeOfUse = optionalArg(argv, "purpose-of-use") ?? "TREAT";
  const requestId = optionalArg(argv, "request-id") ?? `req_${randomUUID()}`;
  const signingKeyPath = resolveArtifactPath(optionalArg(argv, "signing-key-path") ?? env.UDAP_REQUESTER_SIGNING_KEY_PATH ?? env.UDAP_CLINIC_B_SIGNING_KEY_PATH ?? ".local/udap/clinic-b-client-signing.key");
  const publicJwkPath = resolveArtifactPath(optionalArg(argv, "public-jwk-path") ?? env.UDAP_REQUESTER_PUBLIC_JWK_PATH ?? env.UDAP_CLINIC_B_PUBLIC_JWK_PATH ?? ".local/udap/clinic-b-client-public-jwk.json");
  const tlsKeyPath = resolveArtifactPath(optionalArg(argv, "tls-key-path") ?? env.UDAP_REQUESTER_TLS_KEY_PATH ?? env.CLINIC_B_TLS_CLIENT_KEY_PATH ?? ".local/pki/clinic-b/client.key");
  const tlsCertPath = resolveArtifactPath(optionalArg(argv, "tls-cert-path") ?? env.UDAP_REQUESTER_TLS_CERT_PATH ?? env.CLINIC_B_TLS_CLIENT_CERT_PATH ?? ".local/pki/clinic-b/client.crt");
  const tlsCaPath = resolveArtifactPath(optionalArg(argv, "tls-ca-path") ?? env.UDAP_REQUESTER_TLS_CA_PATH ?? env.CLINIC_B_TLS_CA_PATH ?? ".local/pki/ca/ca.crt");
  const servername = optionalArg(argv, "tls-servername");

  const [signingKeyPem, publicJwkText, tlsKey, tlsCert, tlsCa] = await Promise.all([
    readFile(signingKeyPath, "utf8"),
    readFile(publicJwkPath, "utf8"),
    readFile(tlsKeyPath),
    readFile(tlsCertPath, "utf8"),
    readFile(tlsCaPath)
  ]);
  const publicJwk = parsePublicJwk(publicJwkText);
  const signingKey = await importPKCS8(signingKeyPem, "RS256");
  const certificate = certificateIdentityFromPem(tlsCert);
  if (!certificate.x5tS256) throw new Error("UDAP_REQUESTER_CERTIFICATE_THUMBPRINT_UNAVAILABLE");
  const tls = { key: tlsKey, cert: tlsCert, ca: tlsCa, ...(servername ? { servername } : {}) };
  const fetch = createMtlsUdapFetch();
  const trustedOrigin = new URL(discoveryUrl).origin;
  const trustedJwks = JSON.parse(await readFile(resolveArtifactPath(env.UDAP_CUSTODIAN_TRUSTED_JWKS_PATH ?? ".local/udap/hospital-a-issuer-jwks.json"), "utf8"));
  const client = createUdapClient({
    discoveryTrust: { origin: trustedOrigin, issuer: env.UDAP_CUSTODIAN_ISSUER ?? trustedOrigin, jwks: trustedJwks },
    clientId,
    organizationReference,
    certificateThumbprint: certificate.x5tS256,
    signingKey,
    signingKeyId: String(publicJwk.kid),
    signingAlgorithm: "RS256",
    publicJwk,
    fetch
  });
  const metadata = await client.discover(discoveryUrl, tls);
  const assertion = await client.createAssertion({
    tokenEndpoint: metadata.token_endpoint,
    practitionerReference,
    roleCode,
    purposeOfUse
  });
  const token = await client.requestToken({ metadata, assertion, tls });
  const requester = createRequestingInstitutionClient({
    custodianBaseUrl: new URL(metadata.registration_endpoint).origin,
    tls,
    fetch
  });
  const redeemed = await requester.redeemHandoff({ handoffCode, udapToken: token.access_token });
  if (redeemed.shareId !== expectedShareId) throw new Error("UDAP_REQUESTER_SHARE_SCOPE_MISMATCH");
  const expectedManifest = redeemed.manifests.find((manifest) => manifest.manifestId === expectedManifestId);
  if (!expectedManifest) throw new Error("UDAP_REQUESTER_MANIFEST_SCOPE_MISMATCH");
  const readResponse = await requester.readShare({
    shareId: expectedShareId,
    manifestId: expectedManifestId,
    resourceType: expectedManifest.resourceType,
    purposeOfUse,
    requestId,
    udapToken: token.access_token
  });
  if (
    readResponse.manifest.shareId !== expectedShareId ||
    readResponse.manifest.manifestId !== expectedManifestId ||
    readResponse.resource.resourceType !== expectedManifest.resourceType
  ) {
    throw new Error("UDAP_REQUESTER_READ_RESPONSE_SCOPE_MISMATCH");
  }

  return {
    status: "authorized",
    shareId: expectedShareId,
    manifestId: expectedManifestId,
    purposeOfUse,
    requestId,
    read: "completed",
    payloadSuppressed: true,
    tokenExpiresIn: token.expires_in
  };
}

function parsePublicJwk(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    assertUdapPublicJwk(parsed as Record<string, unknown>, "UDAP_REQUESTER_PUBLIC_JWK_INVALID");
    return parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof Error && error.message === "UDAP_REQUESTER_PUBLIC_JWK_INVALID") throw error;
    throw new Error("UDAP_REQUESTER_PUBLIC_JWK_INVALID");
  }
}

function resolveArtifactPath(value: string) {
  return path.isAbsolute(value) ? value : path.resolve(process.cwd(), value);
}

function requiredArg(argv: string[], name: string) {
  const value = optionalArg(argv, name);
  if (!value) throw new Error(`MISSING_ARGUMENT:${name}`);
  return value;
}

function optionalArg(argv: string[], name: string) {
  const index = argv.indexOf(`--${name}`);
  return index >= 0 ? argv[index + 1] : undefined;
}

if (process.argv.some((argument) => path.basename(argument) === "run-udap-requester.ts")) {
  console.log(JSON.stringify(await runUdapRequester(), null, 2));
}
