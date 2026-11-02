import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest, type RequestOptions as HttpsRequestOptions } from "node:https";

import pg from "pg";

const { Client } = pg;

export type RuntimeDependencyKind = "http" | "postgres" | "jsonrpc" | "docker-network";

export interface RuntimeTlsConfig {
  caPath?: string;
  certPath?: string;
  keyPath?: string;
  serverName?: string;
}

export interface RuntimeTarget {
  service: string;
  endpoint: string;
  kind: RuntimeDependencyKind;
  remediation: string;
  connectionString?: string;
  networkName?: string;
  tls?: RuntimeTlsConfig;
}

export interface RuntimeDependencyResult {
  service: string;
  endpoint: string;
  status: "ok" | "failed";
  lastStatus?: number;
  lastError?: string;
  remediation: string;
}

type RuntimeFetch = (
  input: string,
  init?: RequestInit
) => Promise<Response>;

interface RuntimeCheckOptions {
  fetch?: RuntimeFetch;
  connectPostgres?: (connectionString: string) => Promise<void>;
  inspectNetwork?: (networkName: string) => Promise<void>;
  requestTimeoutMs?: number;
}

interface RuntimeWaitOptions extends RuntimeCheckOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

export function buildRuntimeTargets(
  env: Record<string, string | undefined> = process.env
): RuntimeTarget[] {
  const hospitalAFhir = firstValue(
    env.RUNTIME_HOSPITAL_A_FHIR_BASE_URL,
    env.FHIR_HOSPITAL_A_BASE_URL,
    "http://127.0.0.1:8081/fhir"
  );
  const clinicBFhir = firstValue(
    env.RUNTIME_CLINIC_B_FHIR_BASE_URL,
    env.FHIR_CLINIC_B_BASE_URL,
    "http://127.0.0.1:8082/fhir"
  );
  const hospitalAMetadata = firstValue(
    env.RUNTIME_HOSPITAL_A_METADATA_DATABASE_URL,
    env.HOSPITAL_A_METADATA_DATABASE_URL,
    "postgresql://hospital_a_metadata:hospital_a_metadata@127.0.0.1:5433/interfhir_hospital_a_metadata"
  );
  const clinicBMetadata = firstValue(
    env.RUNTIME_CLINIC_B_METADATA_DATABASE_URL,
    env.CLINIC_B_METADATA_DATABASE_URL,
    "postgresql://clinic_b_metadata:clinic_b_metadata@127.0.0.1:5435/interfhir_clinic_b_metadata"
  );
  const rpcUrl = firstValue(
    env.RUNTIME_BLOCKCHAIN_RPC_URL,
    env.BLOCKCHAIN_RPC_URL,
    "http://127.0.0.1:8546"
  );
  const hospitalAJwks = firstValue(
    env.RUNTIME_HOSPITAL_A_JWKS_URI,
    env.OIDC_HOSPITAL_A_JWKS_URI,
    "http://127.0.0.1:8180/realms/hospital-a/protocol/openid-connect/certs"
  );
  const clinicBJwks = firstValue(
    env.RUNTIME_CLINIC_B_JWKS_URI,
    env.OIDC_CLINIC_B_JWKS_URI,
    "http://127.0.0.1:8180/realms/clinic-b/protocol/openid-connect/certs"
  );
  const hospitalAGateway = firstValue(
    env.RUNTIME_HOSPITAL_A_GATEWAY_URL,
    env.HEALTH_ACCESS_PUBLIC_HOSPITAL_A_URL,
    "https://localhost:3001"
  );
  const clinicBGateway = firstValue(
    env.RUNTIME_CLINIC_B_GATEWAY_URL,
    env.HEALTH_ACCESS_PUBLIC_CLINIC_B_URL,
    "https://localhost:3002"
  );
  const targets: RuntimeTarget[] = [
    dockerNetworkTarget(
      "institutional-identity-network",
      env.RUNTIME_INSTITUTIONAL_IDENTITY_NETWORK ?? "interfhir-institutional-identity",
      "Run docker compose -f docker-compose.identity.yml up -d keycloak, then rerun runtime:check."
    ),
    dockerNetworkTarget(
      "institutional-blockchain-network",
      env.RUNTIME_INSTITUTIONAL_BLOCKCHAIN_NETWORK ?? "interfhir-institutional-blockchain",
      "Run docker compose -f docker-compose.blockchain.yml up -d besu-hospital-a-validator, then rerun runtime:check."
    ),
    httpTarget(
      "hospital-a-fhir",
      `${stripTrailingSlash(hospitalAFhir)}/metadata`,
      "Start hospital-a-fhir and wait for its HAPI /fhir/metadata endpoint."
    ),
    httpTarget(
      "clinic-b-fhir",
      `${stripTrailingSlash(clinicBFhir)}/metadata`,
      "Start clinic-b-fhir and wait for its HAPI /fhir/metadata endpoint."
    ),
    postgresTarget(
      "hospital-a-metadata-postgres",
      hospitalAMetadata,
      "Start hospital-a-metadata-postgres and verify host port 5433 or container port 5432."
    ),
    postgresTarget(
      "clinic-b-metadata-postgres",
      clinicBMetadata,
      "Start clinic-b-metadata-postgres and verify host port 5435 or container port 5432."
    ),
    jsonRpcTarget(
      "besu-hospital-a-validator",
      rpcUrl,
      "Start the configured Besu validator and verify host 8546/container 8545 routing."
    ),
    httpTarget(
      "hospital-a-jwks",
      hospitalAJwks,
      "Start Keycloak and verify the Hospital A realm JWKS endpoint."
    ),
    httpTarget(
      "clinic-b-jwks",
      clinicBJwks,
      "Start Keycloak and verify the Clínica B realm JWKS endpoint."
    ),
    httpTarget(
      "hospital-a-gateway",
      `${stripTrailingSlash(hospitalAGateway)}/health`,
      "Start hospital-a-gateway after its FHIR, metadata, identity and blockchain dependencies are ready.",
      gatewayTlsConfig(env, "HOSPITAL_A")
    ),
    httpTarget(
      "clinic-b-gateway",
      `${stripTrailingSlash(clinicBGateway)}/health`,
      "Start clinic-b-gateway after its FHIR, metadata, identity and B2B dependencies are ready.",
      gatewayTlsConfig(env, "CLINIC_B")
    )
  ];

  if (udapServerEnabled(env)) {
    const discovery = firstValue(
      env.RUNTIME_UDAP_DISCOVERY_URL,
      env.UDAP_DISCOVERY_URL,
      `${firstValue(env.UDAP_BASE_URL, hospitalAGateway)}/fhir/.well-known/udap`
    );
    targets.splice(
      targets.findIndex((target) => target.service === "hospital-a-gateway"),
      0,
      httpTarget(
        "hospital-a-udap",
        discovery,
        "Start the Hospital A gateway and verify /fhir/.well-known/udap.",
        gatewayTlsConfig(env, "HOSPITAL_A")
      )
    );
  }

  if (udapRequesterEnabled(env)) {
    const discovery = firstValue(
      env.RUNTIME_CLINIC_B_UDAP_DISCOVERY_URL,
      env.UDAP_CLINIC_B_DISCOVERY_URL,
      `${stripTrailingSlash(hospitalAGateway)}/fhir/.well-known/udap`
    );
    targets.splice(
      targets.findIndex((target) => target.service === "clinic-b-gateway"),
      0,
      httpTarget(
        "clinic-b-udap-requester",
        discovery,
        "Start the Hospital A UDAP issuer and verify the Clínica B requester discovery target.",
        gatewayTlsConfig(env, "HOSPITAL_A")
      )
    );
  }

  return targets;
}

export async function checkRuntimeDependency(
  target: RuntimeTarget,
  options: RuntimeCheckOptions = {}
): Promise<RuntimeDependencyResult> {
  try {
    if (target.kind === "docker-network") {
      await (options.inspectNetwork ?? inspectDockerNetwork)(target.networkName ?? target.endpoint);
      return okResult(target, 200);
    }

    if (target.kind === "postgres") {
      await (options.connectPostgres ?? connectPostgres)(
        target.connectionString ?? target.endpoint
      );
      return okResult(target, 200);
    }

    const response = target.tls && !options.fetch
      ? await requestRuntimeEndpoint(target, options.requestTimeoutMs ?? 5_000)
      : await fetchWithTimeout(options.fetch ?? fetch, target, options.requestTimeoutMs ?? 5_000);
    if (!response.ok) {
      return failedResult(target, response.status, `HTTP ${response.status}`);
    }

    if (target.kind === "jsonrpc") {
      const body = await response.json().catch(() => undefined) as { result?: unknown; error?: { code?: unknown; message?: unknown } } | undefined;
      if (body?.error) {
        const code = typeof body.error.code === "number" ? ` ${body.error.code}` : "";
        const message = typeof body.error.message === "string" ? ` ${body.error.message}` : "";
        return failedResult(target, response.status, `JSON-RPC error${code}${message}`);
      }
      if (!body || !("result" in body)) {
        return failedResult(target, response.status, "JSON-RPC result missing");
      }
    }

    return okResult(target, response.status);
  } catch (error) {
    return failedResult(
      target,
      0,
      error instanceof Error ? error.message : String(error)
    );
  }
}

export async function waitForRuntimeDependencies(
  targets: RuntimeTarget[],
  options: RuntimeWaitOptions = {}
): Promise<RuntimeDependencyResult[]> {
  const timeoutMs = options.timeoutMs ?? 120_000;
  const pollIntervalMs = options.pollIntervalMs ?? 2_000;
  const now = options.now ?? Date.now;
  const sleep = options.sleep ?? delay;
  const results: RuntimeDependencyResult[] = [];

  for (const target of targets) {
    const startedAt = now();
    let result = await checkRuntimeDependency(target, options);
    while (result.status === "failed" && now() - startedAt < timeoutMs) {
      await sleep(pollIntervalMs);
      result = await checkRuntimeDependency(target, options);
    }
    results.push(result);
    if (result.status === "failed") return results;
  }

  return results;
}

function httpTarget(
  service: string,
  endpoint: string,
  remediation: string,
  tls?: RuntimeTlsConfig
): RuntimeTarget {
  return { service, endpoint, kind: "http", remediation, ...(tls ? { tls } : {}) };
}

function postgresTarget(service: string, connectionString: string, remediation: string): RuntimeTarget {
  return {
    service,
    endpoint: postgresEndpoint(connectionString),
    connectionString,
    kind: "postgres",
    remediation
  };
}

function jsonRpcTarget(service: string, endpoint: string, remediation: string): RuntimeTarget {
  return { service, endpoint, kind: "jsonrpc", remediation };
}

function dockerNetworkTarget(
  service: string,
  networkName: string,
  remediation: string
): RuntimeTarget {
  return {
    service,
    endpoint: networkName,
    kind: "docker-network",
    networkName,
    remediation
  };
}

function gatewayTlsConfig(
  env: Record<string, string | undefined>,
  prefix: "HOSPITAL_A" | "CLINIC_B"
): RuntimeTlsConfig | undefined {
  const caPath = firstValue(
    env[`RUNTIME_${prefix}_TLS_CA_PATH`],
    env[`RUNTIME_${prefix}_TLS_CLIENT_CA_PATH`],
    env[`${prefix}_TLS_CA_PATH`],
    env.HEALTH_ACCESS_TLS_CA_PATH
  );
  const certPath = firstValue(
    env[`RUNTIME_${prefix}_TLS_CERT_PATH`],
    env[`RUNTIME_${prefix}_TLS_CLIENT_CERT_PATH`],
    env[`${prefix}_TLS_CLIENT_CERT_PATH`]
  );
  const keyPath = firstValue(
    env[`RUNTIME_${prefix}_TLS_KEY_PATH`],
    env[`RUNTIME_${prefix}_TLS_CLIENT_KEY_PATH`],
    env[`${prefix}_TLS_CLIENT_KEY_PATH`]
  );
  const serverName = firstValue(
    env[`RUNTIME_${prefix}_TLS_SERVER_NAME`],
    env[`${prefix}_TLS_SERVER_NAME`]
  );
  if (!caPath && !certPath && !keyPath) return undefined;
  return {
    ...(caPath ? { caPath } : {}),
    ...(certPath ? { certPath } : {}),
    ...(keyPath ? { keyPath } : {}),
    ...(serverName ? { serverName } : {})
  };
}

function udapServerEnabled(env: Record<string, string | undefined>) {
  const explicitFlag = firstValue(env.UDAP_ENABLED);
  if (explicitFlag === "false") return false;
  if (explicitFlag === "true") return true;
  const configured = [
    env.RUNTIME_UDAP_DISCOVERY_URL,
    env.UDAP_DISCOVERY_URL,
    env.UDAP_ISSUER,
    env.UDAP_BASE_URL,
    env.UDAP_SIGNING_KEY_PATH,
    env.UDAP_SIGNING_KEY_ID,
    env.UDAP_TRUSTED_JWKS_JSON,
    env.UDAP_TRUSTED_JWKS_PATH
  ];
  return configured.some((value) => typeof value === "string" && value.trim().length > 0);
}

function udapRequesterEnabled(env: Record<string, string | undefined>) {
  const explicitFlag = firstValue(env.UDAP_CLINIC_B_ENABLED);
  if (explicitFlag === "false") return false;
  if (explicitFlag === "true") return true;
  const configured = [
    env.RUNTIME_CLINIC_B_UDAP_DISCOVERY_URL,
    env.UDAP_CLINIC_B_DISCOVERY_URL,
    env.UDAP_CLINIC_B_SIGNING_KEY_PATH,
    env.UDAP_CLINIC_B_SIGNING_KEY_ID,
    env.UDAP_CLINIC_B_TRUSTED_JWKS_JSON,
    env.UDAP_CLINIC_B_TRUSTED_JWKS_PATH
  ];
  return configured.some((value) => typeof value === "string" && value.trim().length > 0);
}

async function inspectDockerNetwork(networkName: string) {
  await new Promise<void>((resolve, reject) => {
    execFile(
      "docker",
      ["network", "inspect", networkName, "--format", "{{.Name}}"],
      { timeout: 5_000, windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          const detail = (stderr || error.message).trim();
          reject(new Error(detail || "DOCKER_NETWORK_INSPECT_FAILED"));
          return;
        }
        if (stdout.trim() !== networkName) {
          reject(new Error(`DOCKER_NETWORK_NOT_FOUND: ${networkName}`));
          return;
        }
        resolve();
      }
    );
  });
}

interface RuntimeResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

async function requestRuntimeEndpoint(
  target: RuntimeTarget,
  timeoutMs: number
): Promise<RuntimeResponse> {
  const parsed = new URL(target.endpoint);
  if (target.tls && parsed.protocol !== "https:") {
    throw new Error("RUNTIME_TLS_REQUIRES_HTTPS");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`RUNTIME_SCHEME_UNSUPPORTED: ${parsed.protocol}`);
  }

  const body = target.kind === "jsonrpc"
    ? JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] })
    : undefined;
  const headers = target.kind === "jsonrpc"
    ? { accept: "application/json", "content-type": "application/json" }
    : { accept: "application/json" };
  const baseOptions = {
    method: target.kind === "jsonrpc" ? "POST" : "GET",
    hostname: parsed.hostname,
    ...(parsed.port ? { port: Number(parsed.port) } : {}),
    path: `${parsed.pathname || "/"}${parsed.search}`,
    headers
  };

  return new Promise<RuntimeResponse>((resolve, reject) => {
    const onResponse = (response: import("node:http").IncomingMessage) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve({
          ok: (response.statusCode ?? 0) >= 200 && (response.statusCode ?? 0) < 300,
          status: response.statusCode ?? 0,
          async json() {
            if (!raw.trim()) return undefined;
            return JSON.parse(raw) as unknown;
          }
        });
      });
    };
    const request = parsed.protocol === "https:"
      ? httpsRequest({ ...baseOptions, ...readTlsRequestOptions(target) }, onResponse)
      : httpRequest(baseOptions, onResponse);
    request.setTimeout(timeoutMs, () => request.destroy(new Error(`RUNTIME_REQUEST_TIMEOUT: ${timeoutMs}`)));
    request.once("error", reject);
    if (body) request.write(body);
    request.end();
  });
}

function readTlsRequestOptions(target: RuntimeTarget): HttpsRequestOptions {
  const tls = target.tls;
  if (!tls?.caPath) throw new Error("RUNTIME_TLS_CA_REQUIRED");
  if ((tls.certPath && !tls.keyPath) || (!tls.certPath && tls.keyPath)) {
    throw new Error("RUNTIME_TLS_CLIENT_CONFIG_INCOMPLETE");
  }
  return {
    ca: readFileSync(tls.caPath),
    ...(tls.certPath && tls.keyPath
      ? { cert: readFileSync(tls.certPath), key: readFileSync(tls.keyPath) }
      : {}),
    rejectUnauthorized: true,
    ...(tls.serverName ? { servername: tls.serverName } : {})
  };
}

async function fetchWithTimeout(
  fetchImpl: RuntimeFetch,
  target: RuntimeTarget,
  timeoutMs: number
) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(target.endpoint, {
      method: target.kind === "jsonrpc" ? "POST" : "GET",
      headers: target.kind === "jsonrpc" ? { "content-type": "application/json" } : { accept: "application/json" },
      ...(target.kind === "jsonrpc"
        ? { body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }) }
        : {}),
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function connectPostgres(connectionString: string) {
  const client = new Client({ connectionString, connectionTimeoutMillis: 5_000 });
  await client.connect();
  try {
    await client.query("SELECT 1");
  } finally {
    await client.end();
  }
}

function okResult(target: RuntimeTarget, status: number): RuntimeDependencyResult {
  return {
    service: target.service,
    endpoint: target.endpoint,
    status: "ok",
    lastStatus: status,
    remediation: target.remediation
  };
}

function failedResult(target: RuntimeTarget, status: number, error: string): RuntimeDependencyResult {
  return {
    service: target.service,
    endpoint: target.endpoint,
    status: "failed",
    lastStatus: status,
    lastError: error,
    remediation: target.remediation
  };
}

function postgresEndpoint(connectionString: string) {
  try {
    const url = new URL(connectionString);
    return `${url.hostname}:${url.port || "5432"}`;
  } catch {
    return connectionString;
  }
}

function firstValue(...values: Array<string | undefined>) {
  return values.find((value) => typeof value === "string" && value.trim().length > 0) ?? "";
}

function stripTrailingSlash(value: string) {
  return value.replace(/\/+$/, "");
}

function delay(milliseconds: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}

export async function main() {
  const targets = buildRuntimeTargets();
  const checks = await waitForRuntimeDependencies(targets, {
    timeoutMs: readNumberEnv("RUNTIME_WAIT_TIMEOUT_MS", 120_000),
    pollIntervalMs: readNumberEnv("RUNTIME_POLL_INTERVAL_MS", 2_000),
    requestTimeoutMs: readNumberEnv("RUNTIME_REQUEST_TIMEOUT_MS", 5_000)
  });
  const firstFailure = checks.find((check) => check.status === "failed");
  console.log(JSON.stringify({
    status: firstFailure ? "blocked" : "ready",
    checks,
    firstFailure: firstFailure ?? null
  }, null, 2));
  if (firstFailure) process.exitCode = 1;
}

function readNumberEnv(name: string, fallback: number) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  if (!/^\d+$/.test(value)) throw new Error(`INVALID_RUNTIME_NUMBER: ${name}`);
  return Number(value);
}

if (process.argv.some((argument) => /[\\/]wait-for-services\.(?:ts|js)$/.test(argument))) {
  await main();
}
