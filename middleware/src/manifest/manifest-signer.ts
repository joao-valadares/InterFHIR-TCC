import { CompactSign, compactVerify, type JWK } from "jose";
import type { KeyObject } from "node:crypto";

import {
  computeManifestCommitment,
  type ResourceManifestVersion
} from "./resource-manifest.js";

export interface ManifestSigner {
  sign(commitment: string): Promise<{
    algorithm: "ES256";
    signingKeyId: string;
    signature: string;
  }>;
  verify(manifest: ResourceManifestVersion): Promise<boolean>;
}

type ManifestSigningKey = globalThis.CryptoKey | KeyObject | JWK | Uint8Array;

export function createManifestSigner(input: {
  privateKey: ManifestSigningKey;
  publicKey: ManifestSigningKey;
  signingKeyId: string;
}): ManifestSigner {
  return {
    async sign(commitment) {
      const signature = await new CompactSign(encode(commitment))
        .setProtectedHeader({ alg: "ES256", kid: input.signingKeyId })
        .sign(input.privateKey);
      return {
        algorithm: "ES256",
        signingKeyId: input.signingKeyId,
        signature
      };
    },
    async verify(manifest) {
      if (manifest.signingKeyId !== input.signingKeyId) {
        return false;
      }
      const { commitment, signature: _signature, ...draft } = manifest;
      if (computeManifestCommitment(draft) !== commitment) {
        return false;
      }
      try {
        const result = await compactVerify(manifest.signature, input.publicKey);
        return (
          result.protectedHeader.alg === "ES256" &&
          result.protectedHeader.kid === input.signingKeyId &&
          decode(result.payload) === manifest.commitment
        );
      } catch {
        return false;
      }
    }
  };
}

function encode(value: string) {
  return new TextEncoder().encode(value);
}

function decode(value: Uint8Array) {
  return new TextDecoder().decode(value);
}
