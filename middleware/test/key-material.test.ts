import { expect } from "chai";
import { exportJWK, exportPKCS8, generateKeyPair } from "jose";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  assertIdentityKeySeparation,
  assertManifestJwkPair,
  assertPublicJwkSetsEqual,
  assertUdapTrustedJwks,
  publicJwkFingerprint,
  validateIdentityKeyMaterial
} from "../src/identity/key-material.js";

describe("identity key material", function () {
  it("requires a real ES256 P-256 manifest pair with matching public coordinates", async function () {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const privateJwk = { ...(await exportJWK(privateKey)), alg: "ES256", kid: "manifest-2026" };
    const publicJwk = { ...(await exportJWK(publicKey)), alg: "ES256", kid: "manifest-2026" };
    const alternate = await generateKeyPair("ES256", { extractable: true });
    const alternatePublicJwk = { ...(await exportJWK(alternate.publicKey)), alg: "ES256", kid: "manifest-2026" };

    expect(() => assertManifestJwkPair(privateJwk, publicJwk, "manifest-2026")).not.to.throw();
    expect(() => assertManifestJwkPair(privateJwk, alternatePublicJwk, "manifest-2026"))
      .to.throw("MANIFEST_SIGNING_PUBLIC_KEY_MISMATCH");
    expect(() => assertManifestJwkPair({ ...privateJwk, d: undefined }, publicJwk, "manifest-2026"))
      .to.throw("MANIFEST_SIGNING_PRIVATE_JWK_INVALID");
    expect(() => assertManifestJwkPair(privateJwk, { ...publicJwk, d: "private-material" }, "manifest-2026"))
      .to.throw("MANIFEST_SIGNING_PUBLIC_JWK_PRIVATE");
  });

  it("requires public RSA/EC fields and rejects private material in trusted UDAP JWKS", async function () {
    const { publicKey } = await generateKeyPair("RS256", { extractable: true });
    const publicJwk = { ...(await exportJWK(publicKey)), alg: "RS256", kid: "clinic-b-2026" };

    expect(() => assertUdapTrustedJwks([publicJwk])).not.to.throw();
    expect(() => assertUdapTrustedJwks([{ ...publicJwk, d: "private-material" }]))
      .to.throw("UDAP_TRUSTED_JWKS_PRIVATE_MATERIAL");
    expect(() => assertUdapTrustedJwks([{ ...publicJwk, oth: [{ r: "private" }] }]))
      .to.throw("UDAP_TRUSTED_JWKS_PRIVATE_MATERIAL");
    expect(() => assertUdapTrustedJwks([{ kty: "RSA", alg: "RS256", kid: "missing-modulus" }]))
      .to.throw("UDAP_TRUSTED_JWKS_INVALID");
    expect(() => assertUdapTrustedJwks([{ kty: "EC", crv: "P-256", alg: "RS256", kid: "wrong-alg", x: publicJwk.n, y: publicJwk.e }]))
      .to.throw("UDAP_TRUSTED_JWKS_INVALID");
  });

  it("rejects copied public material even when paths and kids differ", async function () {
    const { publicKey } = await generateKeyPair("RS256", { extractable: true });
    const udapPublic = { ...(await exportJWK(publicKey)), alg: "RS256", kid: "udap-key" };
    const copiedManifestPublic = { ...udapPublic, kid: "manifest-key" };

    expect(publicJwkFingerprint(udapPublic)).to.equal(publicJwkFingerprint(copiedManifestPublic));
    expect(() => assertIdentityKeySeparation([
      { name: "udap-signing-key", publicJwk: udapPublic },
      { name: "manifest-signing-key", publicJwk: copiedManifestPublic }
    ])).to.throw("IDENTITY_KEY_PURPOSE_CONFLICT");
  });

  it("checks the configured issuer JWKS against the actual UDAP private key at runtime", async function () {
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-key-material-"));
    try {
      const signing = await generateKeyPair("RS256", { extractable: true });
      const other = await generateKeyPair("RS256", { extractable: true });
      const signingPath = path.join(directory, "udap-signing.key");
      const issuerJwksPath = path.join(directory, "issuer-jwks.json");
      const otherPublicJwk = { ...(await exportJWK(other.publicKey)), kid: "hospital-a-udap-2026", alg: "RS256" };
      await writeFile(signingPath, await exportPKCS8(signing.privateKey), "utf8");
      await writeFile(issuerJwksPath, JSON.stringify({ keys: [otherPublicJwk] }), "utf8");

      try {
        await validateIdentityKeyMaterial({
          udap: {
            signingKeyPath: signingPath,
            signingKeyId: "hospital-a-udap-2026",
            signingAlgorithm: "RS256",
            issuerJwksPath
          }
        });
        expect.fail("Expected issuer JWKS mismatch");
      } catch (error) {
        expect((error as Error).message).to.equal("UDAP_ISSUER_JWKS_MISMATCH");
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("requires the active issuer JWKS key metadata to match the configured signer", async function () {
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-key-metadata-"));
    try {
      const signing = await generateKeyPair("RS256", { extractable: true });
      const signingPath = path.join(directory, "udap-signing.key");
      const issuerJwksPath = path.join(directory, "issuer-jwks.json");
      const publicJwk = { ...(await exportJWK(signing.publicKey)), kid: "wrong-kid", alg: "RS256" };
      await writeFile(signingPath, await exportPKCS8(signing.privateKey), "utf8");
      await writeFile(issuerJwksPath, JSON.stringify({ keys: [publicJwk] }), "utf8");

      try {
        await validateIdentityKeyMaterial({
          udap: {
            signingKeyPath: signingPath,
            signingKeyId: "hospital-a-udap-2026",
            signingAlgorithm: "RS256",
            issuerJwksPath
          }
        });
        expect.fail("Expected issuer JWK metadata mismatch");
      } catch (error) {
        expect((error as Error).message).to.equal("UDAP_ISSUER_JWKS_SIGNING_KEY_METADATA_MISMATCH");
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("fails closed when startup issuer JWKS contains RSA oth private material", async function () {
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-key-oth-"));
    try {
      const signing = await generateKeyPair("RS256", { extractable: true });
      const signingPath = path.join(directory, "udap-signing.key");
      const issuerJwksPath = path.join(directory, "issuer-jwks.json");
      const publicJwk = {
        ...(await exportJWK(signing.publicKey)),
        kid: "hospital-a-udap-2026",
        alg: "RS256",
        oth: [{ r: "private" }]
      };
      await writeFile(signingPath, await exportPKCS8(signing.privateKey), "utf8");
      await writeFile(issuerJwksPath, JSON.stringify({ keys: [publicJwk] }), "utf8");

      try {
        await validateIdentityKeyMaterial({
          udap: {
            signingKeyPath: signingPath,
            signingKeyId: "hospital-a-udap-2026",
            signingAlgorithm: "RS256",
            issuerJwksPath
          }
        });
        expect.fail("Expected issuer JWKS private material rejection");
      } catch (error) {
        expect((error as Error).message).to.equal("UDAP_ISSUER_JWKS_INVALID");
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("rejects a signing PEM whose algorithm does not match configuration", async function () {
    const directory = await mkdtemp(path.join(os.tmpdir(), "interfhir-key-algorithm-"));
    try {
      const signing = await generateKeyPair("RS256", { extractable: true });
      const signingPath = path.join(directory, "udap-signing.key");
      await writeFile(signingPath, await exportPKCS8(signing.privateKey), "utf8");
      try {
        await validateIdentityKeyMaterial({
          udap: {
            signingKeyPath: signingPath,
            signingKeyId: "hospital-a-udap-2026",
            signingAlgorithm: "ES256"
          }
        });
        expect.fail("Expected signing algorithm mismatch");
      } catch (error) {
        expect((error as Error).message).to.equal("UDAP_SIGNING_KEY_ALGORITHM_MISMATCH");
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("compares signed metadata JWKS entries including kid and alg", async function () {
    const { publicKey } = await generateKeyPair("RS256", { extractable: true });
    const configured = { ...(await exportJWK(publicKey)), kid: "hospital-a-udap-2026", alg: "RS256" };
    expect(() => assertPublicJwkSetsEqual([configured], [{ ...configured, kid: "rotated-key" }]))
      .to.throw("UDAP_SIGNED_METADATA_JWKS_MISMATCH");
    expect(() => assertPublicJwkSetsEqual([configured], [{ ...configured, alg: "ES256" }]))
      .to.throw("UDAP_SIGNED_METADATA_JWKS_MISMATCH");
    expect(() => assertPublicJwkSetsEqual([configured], [{ ...configured }])).not.to.throw();
  });
});
