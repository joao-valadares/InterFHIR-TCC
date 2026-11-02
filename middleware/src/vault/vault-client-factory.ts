import {
  createHapiFhirClient,
  type HapiFhirClient
} from "../fhir/hapi-fhir-client.js";
import type {
  VaultDescriptor,
  VaultDirectory
} from "./vault-directory.js";

export interface VaultClientContext {
  descriptor: VaultDescriptor;
  client: HapiFhirClient;
}

export interface VaultClientFactory {
  forVault(
    vaultId: string,
    custodianOrganizationReference: string
  ): VaultClientContext;
}

export function createVaultClientFactory(options: {
  directory: VaultDirectory;
  fetch?: typeof fetch;
}): VaultClientFactory {
  const clients = new Map<string, HapiFhirClient>();

  return {
    forVault(vaultId, custodianOrganizationReference) {
      const descriptor = options.directory.require(
        vaultId,
        custodianOrganizationReference
      );
      let client = clients.get(descriptor.vaultId);
      if (!client) {
        client = createHapiFhirClient({
          baseUrl: descriptor.fhirBaseUrl,
          ...(descriptor.serviceCredentials
            ? {
                authorization: `Bearer ${descriptor.serviceCredentials.bearerToken}`
              }
            : {}),
          ...(options.fetch ? { fetch: options.fetch } : {})
        });
        clients.set(descriptor.vaultId, client);
      }
      return { descriptor, client };
    }
  };
}
