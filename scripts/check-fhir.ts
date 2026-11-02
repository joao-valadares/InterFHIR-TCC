import { loadHealthAccessConfig } from "../middleware/src/config.js";
import { checkFhirRuntime } from "../middleware/src/fhir/fhir-health.js";

async function main() {
  const config = loadHealthAccessConfig();
  const vaults = process.env.FHIR_VAULT_ID
    ? [config.selectedFhirVault]
    : Object.values(config.fhirVaults);

  for (const vault of vaults) {
    const result = await checkFhirRuntime({
      baseUrl: vault.baseUrl,
      requiredResources: vault.requiredResources
    });

    console.log(
      JSON.stringify(
        {
          vaultId: vault.id,
          fhirBaseUrl: vault.baseUrl,
          ...result
        },
        null,
        2
      )
    );

    if (!result.ready) {
      process.exitCode = 1;
    }
  }
}

await main();
