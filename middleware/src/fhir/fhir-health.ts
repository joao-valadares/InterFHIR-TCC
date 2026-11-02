export const MINIMUM_HEALTH_ACCESS_RESOURCES = [
  "Patient/maria",
  "Practitioner/ana",
  "Organization/hospital-a",
  "Observation/obs-1",
  "DiagnosticReport/report-1",
  "Immunization/imm-1",
  "Consent/cons-1",
  "Consent/cons-report-1",
  "Consent/cons-immunization-1"
];

interface FhirRuntimeCheckOptions {
  baseUrl: string;
  requiredResources?: string[];
  fetch?: typeof fetch;
}

interface WaitForFhirMetadataOptions {
  vaultId: string;
  baseUrl: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

export interface FhirRuntimeCheckResult {
  ready: boolean;
  checked: string[];
  failed?: {
    endpoint: string;
    status: number;
  };
}

export async function checkFhirRuntime(options: FhirRuntimeCheckOptions): Promise<FhirRuntimeCheckResult> {
  const fetchImpl = options.fetch ?? fetch;
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const checked: string[] = [];

  for (const endpoint of ["metadata", ...(options.requiredResources ?? MINIMUM_HEALTH_ACCESS_RESOURCES)]) {
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}/${endpoint}`, {
        method: "GET",
        headers: { accept: "application/fhir+json" }
      });
    } catch {
      return {
        ready: false,
        checked,
        failed: {
          endpoint,
          status: 0
        }
      };
    }

    if (!response.ok) {
      return {
        ready: false,
        checked,
        failed: {
          endpoint,
          status: response.status
        }
      };
    }

    checked.push(endpoint);
  }

  return { ready: true, checked };
}

export async function waitForFhirMetadata(
  options: WaitForFhirMetadataOptions
): Promise<FhirRuntimeCheckResult> {
  const timeoutMs = options.timeoutMs ?? 120_000;
  const pollIntervalMs = options.pollIntervalMs ?? 2_000;
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? delay;
  const startedAt = now();
  let lastFailure: FhirRuntimeCheckResult["failed"];

  while (true) {
    const result = await checkFhirRuntime({
      baseUrl: options.baseUrl,
      requiredResources: [],
      ...(options.fetch ? { fetch: options.fetch } : {})
    });
    if (result.ready) {
      return result;
    }
    lastFailure = result.failed;
    if (now() - startedAt >= timeoutMs) {
      throw new Error(
        `FHIR_VAULT_NOT_READY: ${options.vaultId} endpoint=${
          lastFailure?.endpoint ?? "metadata"
        } status=${lastFailure?.status ?? 0} timeoutMs=${timeoutMs}`
      );
    }
    await sleep(pollIntervalMs);
  }
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
