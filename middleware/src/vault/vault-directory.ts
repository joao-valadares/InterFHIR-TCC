export interface VaultServiceCredentials {
  bearerToken: string;
}

export interface VaultDescriptor {
  id: string;
  vaultId: string;
  custodianOrganizationReference: string;
  fhirBaseUrl: string;
  serviceCredentials?: VaultServiceCredentials;
  seedBundlePath: string;
  requiredResources: string[];
}

export interface VaultDirectory {
  require(
    vaultId: string,
    custodianOrganizationReference: string
  ): VaultDescriptor;
  list(): VaultDescriptor[];
}

export function createVaultDirectory(
  descriptors: readonly VaultDescriptor[]
): VaultDirectory {
  const byVaultId = new Map<string, VaultDescriptor>();
  for (const descriptor of descriptors) {
    if (byVaultId.has(descriptor.vaultId)) {
      throw new Error(`DUPLICATE_VAULT: ${descriptor.vaultId}`);
    }
    byVaultId.set(descriptor.vaultId, descriptor);
  }

  return {
    require(vaultId, custodianOrganizationReference) {
      const descriptor = byVaultId.get(vaultId);
      if (!descriptor) {
        throw new Error(`UNKNOWN_VAULT: ${vaultId}`);
      }
      if (
        descriptor.custodianOrganizationReference !==
        custodianOrganizationReference
      ) {
        throw new Error("VAULT_CUSTODIAN_MISMATCH");
      }
      return descriptor;
    },

    list() {
      return Array.from(byVaultId.values());
    }
  };
}
