import { mkdir, access, writeFile } from "node:fs/promises";
import path from "node:path";
import { exportJWK, exportPKCS8, generateKeyPair, SignJWT, type JWK } from "jose";

const outputDirectory = path.resolve(process.cwd(), ".local", "udap");
const force = process.argv.includes("--force");

const outputNames = [
  "hospital-a-signing.key",
  "hospital-a-signing.jwk.json",
  "hospital-a-issuer-jwks.json",
  "hospital-a-signed-metadata.jwt",
  "hospital-a-trusted-jwks.json",
  "clinic-b-client-signing.key",
  "clinic-b-client-jwk.json",
  "clinic-b-client-public-jwk.json"
];

await mkdir(outputDirectory, { recursive: true });
const existing = [] as string[];
for (const name of outputNames) {
  try {
    await access(path.join(outputDirectory, name));
    existing.push(name);
  } catch {
    // The artifact is absent and can be created.
  }
}
if (existing.length > 0 && !force) {
  throw new Error(`UDAP_KEYS_ALREADY_EXIST: use --force to replace ${existing.join(", ")}`);
}

const hospital = await createKeyMaterial("hospital-a-udap-2026");
const clinic = await createKeyMaterial("clinic-b-udap-client-2026");

await writePrivate(path.join(outputDirectory, "hospital-a-signing.key"), hospital.privatePem);
await writeJson(path.join(outputDirectory, "hospital-a-signing.jwk.json"), hospital.privateJwk, 0o600);
await writeJson(path.join(outputDirectory, "hospital-a-issuer-jwks.json"), { keys: [hospital.publicJwk] });
const issuerJwksUri = "https://hospital-a.local/.well-known/udap/jwks.json";
const signedMetadata = await new SignJWT({
  token_endpoint: "https://hospital-a.local/udap/token",
  registration_endpoint: "https://hospital-a.local/udap/register",
  jwks_uri: issuerJwksUri,
  jwks: { keys: [hospital.publicJwk] }
})
  .setProtectedHeader({ alg: "RS256", kid: hospital.privateJwk.kid, typ: "JWT" })
  .setIssuer("https://hospital-a.local")
  .setIssuedAt()
  .setExpirationTime("365d")
  .sign(hospital.privateKey);
await writePublicText(path.join(outputDirectory, "hospital-a-signed-metadata.jwt"), `${signedMetadata}\n`);
await writeJson(path.join(outputDirectory, "hospital-a-trusted-jwks.json"), { keys: [clinic.publicJwk] });
await writePrivate(path.join(outputDirectory, "clinic-b-client-signing.key"), clinic.privatePem);
await writeJson(path.join(outputDirectory, "clinic-b-client-jwk.json"), clinic.privateJwk, 0o600);
await writeJson(path.join(outputDirectory, "clinic-b-client-public-jwk.json"), clinic.publicJwk);

console.log(JSON.stringify({
  status: "generated",
  directory: outputDirectory,
  artifacts: outputNames,
  hospitalSigningKeyId: hospital.privateJwk.kid,
  clinicClientKeyId: clinic.privateJwk.kid,
  algorithm: "RS256",
  issuerJwksUri
}, null, 2));

async function createKeyMaterial(keyId: string) {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { modulusLength: 2048, extractable: true });
  const privateJwk = withMetadata(await exportJWK(privateKey), keyId);
  const publicJwk = withMetadata(await exportJWK(publicKey), keyId);
  const privatePem = await exportPKCS8(privateKey);
  return { privateJwk, publicJwk, privatePem, privateKey };
}

function withMetadata(jwk: JWK, keyId: string): JWK {
  return { ...jwk, kid: keyId, alg: "RS256", use: "sig" };
}

function publicJson(value: JWK) {
  const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicJwk } = value;
  return publicJwk;
}

async function writePrivate(filePath: string, value: string) {
  await writeFile(filePath, value, { encoding: "utf8", mode: 0o600 });
}

async function writePublicText(filePath: string, value: string) {
  await writeFile(filePath, value, { encoding: "utf8", mode: 0o644 });
}

async function writeJson(filePath: string, value: JWK | { keys: JWK[] }, mode = 0o644) {
  const sanitized = "keys" in value ? { keys: value.keys.map(publicJson) } : value;
  await writeFile(filePath, `${JSON.stringify(sanitized, null, 2)}\n`, { encoding: "utf8", mode });
}
