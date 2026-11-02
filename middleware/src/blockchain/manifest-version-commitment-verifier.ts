import { ethers } from "ethers";
import { computeManifestCommitment, type ResourceManifestVersion } from "../manifest/resource-manifest.js";

export function createManifestVersionCommitmentVerifier(accessControl: { getManifestRecord(manifestIdHash: string, version: number): Promise<{ commitment?: string; status?: bigint | number; exists?: boolean; 0?: string; 1?: bigint | number; 2?: boolean }> }) {
  return {
    async verify(manifest: ResourceManifestVersion) {
      const record = await accessControl.getManifestRecord(ethers.keccak256(ethers.toUtf8Bytes(manifest.manifestId)), manifest.version);
      return (record.exists ?? record[2]) === true && Number(record.status ?? record[1]) === 1 && (record.commitment ?? record[0]) === computeManifestCommitment(manifest);
    }
  };
}
