import { ethers } from "ethers";

import type { ManifestAnchor } from "./manifest-publication-service.js";
import type { ResourceManifestVersion } from "./resource-manifest.js";

interface SignerLike {
  address: string;
}

interface ManifestRecordLike {
  commitment?: string;
  status?: bigint | number;
  exists?: boolean;
  0?: string;
  1?: bigint | number;
  2?: boolean;
}

interface CustodianManifestContract {
  anchorManifestVersion(
    manifestIdHash: string,
    version: number,
    commitment: string,
    previousVersionCommitment: string
  ): Promise<TransactionLike>;
  supersedeAndAnchorManifestVersion(
    manifestIdHash: string,
    currentVersion: number,
    expectedCurrentCommitment: string,
    supersededCommitment: string,
    nextVersion: number,
    nextCommitment: string
  ): Promise<TransactionLike>;
  revokeManifestVersion(
    manifestIdHash: string,
    version: number,
    expectedCurrentCommitment: string,
    revokedCommitment: string
  ): Promise<TransactionLike>;
  getManifestRecord(
    manifestIdHash: string,
    version: number
  ): Promise<ManifestRecordLike>;
  connect(signer: SignerLike): CustodianManifestContract;
}

interface TransactionLike {
  hash: string;
  wait(): Promise<unknown>;
}

export function createCustodianManifestAnchor(options: {
  accessControl: CustodianManifestContract;
  signer?: SignerLike;
}): ManifestAnchor {
  const contract = options.signer
    ? options.accessControl.connect(options.signer)
    : options.accessControl;
  return {
    async anchorInitial(manifest) {
      const transaction = await contract.anchorManifestVersion(
        ethers.keccak256(ethers.toUtf8Bytes(manifest.manifestId)),
        manifest.version,
        manifest.commitment,
        manifest.previousVersionCommitment
      );
      await transaction.wait();
    },
    async supersedeAndAnchor(
      current: ResourceManifestVersion,
      superseded: ResourceManifestVersion,
      active: ResourceManifestVersion
    ) {
      const transaction = await contract.supersedeAndAnchorManifestVersion(
        ethers.keccak256(ethers.toUtf8Bytes(current.manifestId)),
        current.version,
        current.commitment,
        superseded.commitment,
        active.version,
        active.commitment
      );
      await transaction.wait();
    },
    async getManifestRecord(manifestId, version) {
      const record = await contract.getManifestRecord(
        ethers.keccak256(ethers.toUtf8Bytes(manifestId)),
        version
      );
      return {
        commitment: record.commitment ?? record[0],
        status: Number(record.status ?? record[1] ?? 0),
        exists: Boolean(record.exists ?? record[2])
      };
    },
    async revoke(current, revoked) {
      const transaction = await contract.revokeManifestVersion(
        ethers.keccak256(ethers.toUtf8Bytes(current.manifestId)),
        current.version,
        current.commitment,
        revoked.commitment
      );
      await transaction.wait();
    }
  };
}
