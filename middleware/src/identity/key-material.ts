import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
  type KeyObject
} from "node:crypto";
import { readFile } from "node:fs/promises";

export type JsonWebKeyRecord = Record<string, unknown>;

export interface IdentityKeyMaterialConfig {
  tls?: {
    keyPath: string;
    certPath: string;
    caPath: string;
  };
  udap?: {
    signingKeyPath: string;
    signingKeyId: string;
    signingAlgorithm: "RS256" | "ES256";
    issuerJwksPath?: string;
  };
  manifestSigning?: {
    privateJwk: JsonWebKeyRecord;
    publicJwk: JsonWebKeyRecord;
    keyId: string;
  };
}

export function assertManifestJwkPair(
  privateJwk: JsonWebKeyRecord,
  publicJwk: JsonWebKeyRecord,
  keyId: string
) {
  assertManifestPrivateJwk(privateJwk, keyId);
  assertManifestPublicJwk(publicJwk, keyId);
  if (
    privateJwk.x !== publicJwk.x ||
    privateJwk.y !== publicJwk.y
  ) {
    throw new Error("MANIFEST_SIGNING_PUBLIC_KEY_MISMATCH");
  }

  let derivedPublicJwk: JsonWebKeyRecord;
  try {
    const privateKey = createPrivateKey({
      key: privateJwk as unknown as import("node:crypto").JsonWebKey,
      format: "jwk"
    });
    derivedPublicJwk = publicJwkFromKeyObject(privateKey);
  } catch {
    throw new Error("MANIFEST_SIGNING_PRIVATE_JWK_INVALID");
  }
  if (publicJwkFingerprint(derivedPublicJwk) !== publicJwkFingerprint(publicJwk)) {
    throw new Error("MANIFEST_SIGNING_PUBLIC_KEY_MISMATCH");
  }
}

export function assertUdapTrustedJwks(keys: JsonWebKeyRecord[]) {
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error("UDAP_TRUSTED_JWKS_INVALID");
  }
  for (const key of keys) {
    assertUdapPublicJwk(key);
  }
}

export function assertUdapPublicJwk(
  key: JsonWebKeyRecord,
  invalidError = "UDAP_TRUSTED_JWKS_INVALID"
) {
  if (!key || typeof key !== "object" || Array.isArray(key)) {
    throw new Error(invalidError);
  }
  if (["d", "p", "q", "dp", "dq", "qi", "k", "oth"].some((field) => key[field] !== undefined)) {
    throw new Error("UDAP_TRUSTED_JWKS_PRIVATE_MATERIAL");
  }
  if (!nonEmptyString(key.kid) || !nonEmptyString(key.alg)) {
    throw new Error(invalidError);
  }
  if (key.kty === "RSA") {
    if (key.alg !== "RS256" || !base64UrlBytes(key.n, 1) || !base64UrlBytes(key.e, 1)) {
      throw new Error(invalidError);
    }
  } else if (key.kty === "EC") {
    if (
      key.alg !== "ES256" ||
      key.crv !== "P-256" ||
      !base64UrlBytes(key.x, 32, true) ||
      !base64UrlBytes(key.y, 32, true)
    ) {
      throw new Error(invalidError);
    }
  } else {
    throw new Error(invalidError);
  }

  try {
    createPublicKey({ key: key as unknown as import("node:crypto").JsonWebKey, format: "jwk" });
  } catch {
    throw new Error(invalidError);
  }
}

export function publicJwkFingerprint(publicJwk: JsonWebKeyRecord): string {
  const canonical = canonicalPublicJwk(publicJwk);
  return createHash("sha256")
    .update(JSON.stringify(canonical), "utf8")
    .digest("base64url");
}

export function publicJwkMetadataFingerprint(publicJwk: JsonWebKeyRecord): string {
  return createHash("sha256")
    .update(JSON.stringify(canonicalPublicJwkWithMetadata(publicJwk)), "utf8")
    .digest("base64url");
}

export function assertPublicJwkSetsEqual(
  configured: JsonWebKeyRecord[],
  signedMetadata: JsonWebKeyRecord[]
) {
  try {
    assertUdapTrustedJwks(configured);
    assertUdapTrustedJwks(signedMetadata);
  } catch {
    throw new Error("UDAP_SIGNED_METADATA_JWKS_MISMATCH");
  }
  const configuredFingerprints = configured.map(publicJwkMetadataFingerprint).sort();
  const metadataFingerprints = signedMetadata.map(publicJwkMetadataFingerprint).sort();
  if (
    configuredFingerprints.length !== metadataFingerprints.length ||
    configuredFingerprints.some((fingerprint, index) => fingerprint !== metadataFingerprints[index])
  ) {
    throw new Error("UDAP_SIGNED_METADATA_JWKS_MISMATCH");
  }
}

export function assertIdentityKeySeparation(
  entries: Array<{
    name: string;
    publicJwk: JsonWebKeyRecord;
    purpose?: string;
  }>
) {
  for (let index = 0; index < entries.length; index += 1) {
    for (let otherIndex = index + 1; otherIndex < entries.length; otherIndex += 1) {
      const left = entries[index];
      const right = entries[otherIndex];
      if (left.purpose !== undefined && left.purpose === right.purpose) continue;
      if (publicJwkFingerprint(left.publicJwk) === publicJwkFingerprint(right.publicJwk)) {
        throw new Error(`IDENTITY_KEY_PURPOSE_CONFLICT: ${left.name}=${right.name}`);
      }
    }
  }
}

export async function validateIdentityKeyMaterial(
  config: IdentityKeyMaterialConfig
) {
  const entries: Array<{
    name: string;
    publicJwk: JsonWebKeyRecord;
    purpose?: string;
  }> = [];

  if (config.manifestSigning) {
    assertManifestJwkPair(
      config.manifestSigning.privateJwk,
      config.manifestSigning.publicJwk,
      config.manifestSigning.keyId
    );
    entries.push({
      name: "manifest-signing-key",
      publicJwk: config.manifestSigning.publicJwk,
      purpose: "manifest"
    });
  }

  if (config.tls) {
    const tlsPrivateKey = await readPrivateKey(config.tls.keyPath, "TLS_PRIVATE_KEY_UNAVAILABLE");
    const tlsPrivatePublicJwk = publicJwkFromKeyObject(tlsPrivateKey);
    const tlsCertificateJwk = publicJwkFromCertificate(
      await readCertificate(config.tls.certPath, "TLS_CERTIFICATE_UNAVAILABLE")
    );
    if (publicJwkFingerprint(tlsPrivatePublicJwk) !== publicJwkFingerprint(tlsCertificateJwk)) {
      throw new Error("TLS_KEY_CERT_PUBLIC_KEY_MISMATCH");
    }
    entries.push(
      { name: "tls-private-key", publicJwk: tlsPrivatePublicJwk, purpose: "tls" },
      { name: "tls-certificate", publicJwk: tlsCertificateJwk, purpose: "tls" }
    );
    const caCertificateJwk = publicJwkFromCertificate(
      await readCertificate(config.tls.caPath, "TLS_CA_CERTIFICATE_UNAVAILABLE")
    );
    entries.push({ name: "tls-ca-certificate", publicJwk: caCertificateJwk, purpose: "tls-ca" });
  }

  if (config.udap) {
    const udapPrivateKey = await readPrivateKey(
      config.udap.signingKeyPath,
      "UDAP_SIGNING_KEY_UNAVAILABLE"
    );
    const expectedKeyType = config.udap.signingAlgorithm === "RS256" ? "rsa" : "ec";
    if (udapPrivateKey.asymmetricKeyType !== expectedKeyType) {
      throw new Error("UDAP_SIGNING_KEY_ALGORITHM_MISMATCH");
    }
    const udapPublicJwk = publicJwkFromKeyObject(udapPrivateKey);
    assertUdapPublicJwk({
      ...udapPublicJwk,
      kid: config.udap.signingKeyId,
      alg: config.udap.signingAlgorithm
    });
    entries.push({ name: "udap-signing-key", publicJwk: udapPublicJwk, purpose: "udap" });

    if (config.udap.issuerJwksPath) {
      const issuerJwks = await readIssuerJwks(config.udap.issuerJwksPath);
      const activeKeys = issuerJwks.filter(
        (key) => key.kid === config.udap?.signingKeyId && key.alg === config.udap?.signingAlgorithm
      );
      if (activeKeys.length !== 1) {
        throw new Error("UDAP_ISSUER_JWKS_SIGNING_KEY_METADATA_MISMATCH");
      }
      if (publicJwkFingerprint(activeKeys[0]) !== publicJwkFingerprint(udapPublicJwk)) {
        throw new Error("UDAP_ISSUER_JWKS_MISMATCH");
      }
    }
  }

  assertIdentityKeySeparation(entries);
}

function assertManifestPrivateJwk(key: JsonWebKeyRecord, keyId: string) {
  if (
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    key.alg !== "ES256" ||
    key.kid !== keyId ||
    !base64UrlBytes(key.x, 32, true) ||
    !base64UrlBytes(key.y, 32, true) ||
    !base64UrlBytes(key.d, 32, true)
  ) {
    if (key.kid !== keyId) throw new Error("MANIFEST_SIGNING_KEY_ID_MISMATCH");
    throw new Error("MANIFEST_SIGNING_PRIVATE_JWK_INVALID");
  }
}

function assertManifestPublicJwk(key: JsonWebKeyRecord, keyId: string) {
  if (["d", "p", "q", "dp", "dq", "qi", "k"].some((field) => key[field] !== undefined)) {
    throw new Error("MANIFEST_SIGNING_PUBLIC_JWK_PRIVATE");
  }
  if (
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    key.alg !== "ES256" ||
    key.kid !== keyId ||
    !base64UrlBytes(key.x, 32, true) ||
    !base64UrlBytes(key.y, 32, true)
  ) {
    if (key.kid !== keyId) throw new Error("MANIFEST_SIGNING_KEY_ID_MISMATCH");
    throw new Error("MANIFEST_SIGNING_PUBLIC_JWK_INVALID");
  }
  try {
    createPublicKey({ key: key as unknown as import("node:crypto").JsonWebKey, format: "jwk" });
  } catch {
    throw new Error("MANIFEST_SIGNING_PUBLIC_JWK_INVALID");
  }
}

function canonicalPublicJwk(publicJwk: JsonWebKeyRecord): JsonWebKeyRecord {
  if (publicJwk.kty === "RSA") {
    if (!base64UrlBytes(publicJwk.n, 1) || !base64UrlBytes(publicJwk.e, 1)) {
      throw new Error("IDENTITY_KEY_MATERIAL_INVALID");
    }
    return { e: publicJwk.e, kty: "RSA", n: publicJwk.n };
  }
  if (publicJwk.kty === "EC") {
    if (
      publicJwk.crv !== "P-256" ||
      !base64UrlBytes(publicJwk.x, 32, true) ||
      !base64UrlBytes(publicJwk.y, 32, true)
    ) {
      throw new Error("IDENTITY_KEY_MATERIAL_INVALID");
    }
    return { crv: "P-256", kty: "EC", x: publicJwk.x, y: publicJwk.y };
  }
  throw new Error("IDENTITY_KEY_MATERIAL_INVALID");
}

function canonicalPublicJwkWithMetadata(publicJwk: JsonWebKeyRecord): JsonWebKeyRecord {
  const canonical = canonicalPublicJwk(publicJwk);
  return {
    ...canonical,
    kid: publicJwk.kid,
    alg: publicJwk.alg,
    ...(publicJwk.use !== undefined ? { use: publicJwk.use } : {}),
    ...(publicJwk.key_ops !== undefined ? { key_ops: publicJwk.key_ops } : {})
  };
}

function publicJwkFromKeyObject(key: KeyObject): JsonWebKeyRecord {
  try {
    return createPublicKey(key).export({ format: "jwk" }) as JsonWebKeyRecord;
  } catch {
    throw new Error("IDENTITY_KEY_MATERIAL_INVALID");
  }
}

function publicJwkFromCertificate(certificate: X509Certificate): JsonWebKeyRecord {
  try {
    return certificate.publicKey.export({ format: "jwk" }) as JsonWebKeyRecord;
  } catch {
    throw new Error("IDENTITY_KEY_MATERIAL_INVALID");
  }
}

async function readPrivateKey(filePath: string, errorCode: string) {
  try {
    return createPrivateKey(await readFile(filePath));
  } catch {
    throw new Error(`${errorCode}: ${filePath}`);
  }
}

async function readCertificate(filePath: string, errorCode: string) {
  try {
    return new X509Certificate(await readFile(filePath));
  } catch {
    throw new Error(`${errorCode}: ${filePath}`);
  }
}

async function readIssuerJwks(filePath: string): Promise<JsonWebKeyRecord[]> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(filePath, "utf8"));
  } catch {
    throw new Error(`UDAP_ISSUER_JWKS_UNAVAILABLE: ${filePath}`);
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    !Array.isArray((parsed as { keys?: unknown }).keys)
  ) {
    throw new Error("UDAP_ISSUER_JWKS_INVALID");
  }
  const keys = (parsed as { keys: unknown[] }).keys;
  try {
    assertUdapTrustedJwks(keys as JsonWebKeyRecord[]);
  } catch {
    throw new Error("UDAP_ISSUER_JWKS_INVALID");
  }
  return keys as JsonWebKeyRecord[];
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function base64UrlBytes(value: unknown, expectedLength: number, exactLength = false): value is string {
  if (!nonEmptyString(value) || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const bytes = Buffer.from(value, "base64url");
    return (exactLength ? bytes.length === expectedLength : bytes.length >= expectedLength) && bytes.toString("base64url") === value;
  } catch {
    return false;
  }
}
