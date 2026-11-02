import { readFileSync } from "node:fs";

import { loadHealthAccessConfig } from "../middleware/src/config.js";

async function main() {
  const config = loadHealthAccessConfig();
  const vaults = process.env.FHIR_VAULT_ID
    ? [config.selectedFhirVault]
    : Object.values(config.fhirVaults);

  for (const vault of vaults) {
    const bundle = JSON.parse(readFileSync(vault.seedBundlePath, "utf8"));
    const response = await fetch(vault.baseUrl, {
      method: "POST",
      headers: {
        "content-type": "application/fhir+json",
        accept: "application/fhir+json"
      },
      body: JSON.stringify(bundle)
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`FHIR_SEED_FAILED_${vault.id}_${response.status}: ${body}`);
    }

    const result = await response.json();
    console.log(
      JSON.stringify(
        {
          vaultId: vault.id,
          fhirBaseUrl: vault.baseUrl,
          bundlePath: vault.seedBundlePath,
          status: response.status,
          responseResourceType: result.resourceType,
          entries: Array.isArray(result.entry) ? result.entry.length : 0
        },
        null,
        2
      )
    );
  }
}

await main();
