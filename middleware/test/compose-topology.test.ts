import { expect } from "chai";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const yaml = createRequire(import.meta.url)("js-yaml") as {
  load(source: string): unknown;
};

const compose = readText("../../docker-compose.yml");
const devCompose = readText("../../docker-compose.dev.yml");
const middlewareDockerfile = readText("../../docker/middleware.Dockerfile");
const envExample = readText("../../.env.example");

describe("institutional Compose topology", function () {
  it("pins registry images by digest so a later tag update cannot change the laboratory", function () {
    for (const relativePath of ["../../docker-compose.yml", "../../docker-compose.identity.yml", "../../docker-compose.blockchain.yml"]) {
      const configuration = yaml.load(readText(relativePath)) as { services: Record<string, { image?: string; build?: unknown }> };
      for (const [name, service] of Object.entries(configuration.services)) {
        if (service.image && !service.build) expect(service.image, name).to.match(/@sha256:[a-f0-9]{64}$/);
      }
    }
    for (const relativePath of ["../../docker/hapi-fhir.Dockerfile", "../../docker/middleware.Dockerfile"]) {
      const baseImages = [...readText(relativePath).matchAll(/^FROM\s+(\S+)/gm)].map(match => match[1]);
      expect(baseImages).not.to.be.empty;
      for (const image of baseImages) expect(image, relativePath).to.match(/@sha256:[a-f0-9]{64}$/);
    }
  });
  it("recovers gateways when blockchain or database startup finishes later", function () {
    const configuration = yaml.load(compose) as { services: Record<string, { restart: string }> };
    for (const name of ["hospital-a-gateway", "clinic-b-gateway"]) expect(configuration.services[name].restart).to.equal("unless-stopped");
  });
  it("mounts only institution-scoped identity files at absolute container paths", function () {
    const hospital = serviceBlock(compose, "hospital-a-gateway");
    const clinic = serviceBlock(compose, "clinic-b-gateway");

    for (const block of [hospital, clinic]) {
      expect(block).not.to.include("./.local/pki:/run/interfhir/pki");
      expect(block).not.to.include("./.local/udap:/run/interfhir/udap");
      expect(environmentBlock(block)).not.to.match(/\.local\//);
    }

    expect(hospital).to.include("/run/interfhir/pki/ca/ca.crt:ro");
    expect(hospital).to.include("/run/interfhir/pki/hospital-a/server.key:ro");
    expect(hospital).to.include("/run/interfhir/pki/hospital-a/server.crt:ro");
    expect(hospital).to.include("/run/interfhir/pki/hospital-a/client.key:ro");
    expect(hospital).to.include("/run/interfhir/pki/hospital-a/client.crt:ro");
    expect(hospital).to.include("/run/interfhir/udap/hospital-a-signing.key:ro");
    expect(hospital).to.include("/run/interfhir/udap/hospital-a-signing.jwk.json:ro");
    expect(hospital).to.include("/run/interfhir/udap/hospital-a-issuer-jwks.json:ro");
    expect(hospital).to.include("/run/interfhir/udap/hospital-a-trusted-jwks.json:ro");
    expect(hospital).to.include("/run/interfhir/udap/hospital-a-signed-metadata.jwt:ro");

    expect(clinic).to.include("/run/interfhir/pki/ca/ca.crt:ro");
    expect(clinic).to.include("/run/interfhir/pki/clinic-b/server.key:ro");
    expect(clinic).to.include("/run/interfhir/pki/clinic-b/server.crt:ro");
    expect(clinic).to.include("/run/interfhir/pki/clinic-b/client.key:ro");
    expect(clinic).to.include("/run/interfhir/pki/clinic-b/client.crt:ro");
    expect(clinic).to.include("/run/interfhir/udap/clinic-b-client-signing.key:ro");
    expect(clinic).to.include("/run/interfhir/udap/clinic-b-client-public-jwk.json:ro");
    expect(clinic).to.include("/run/interfhir/udap/hospital-a-issuer-jwks.json:ro");
  });

  it("wires persistent contract runtime placeholders into both gateways without bootstrap", function () {
    const institutionMappings = {
      "hospital-a-gateway": {
        prefix: "HOSPITAL_A",
        rpcDefault: "http://besu-hospital-a-validator:8545"
      },
      "clinic-b-gateway": {
        prefix: "CLINIC_B",
        rpcDefault: "http://besu-hospital-a-validator:8545"
      }
    } as const;
    const walletRoles = [
      "DEPLOYER",
      "PATIENT",
      "PRACTITIONER",
      "ORGANIZATION",
      "PEP"
    ];

    for (const [service, mapping] of Object.entries(institutionMappings)) {
      const environment = environmentBlock(serviceBlock(compose, service));
      const expectedMappings = [
        ["BLOCKCHAIN_RPC_URL", `${mapping.prefix}_BLOCKCHAIN_RPC_URL:-${mapping.rpcDefault}`],
        ["HEALTH_ACCESS_CONTROL_ADDRESS", `${mapping.prefix}_HEALTH_ACCESS_CONTROL_ADDRESS:-`],
        ...walletRoles.map((role) => [
          `BLOCKCHAIN_${role}_PRIVATE_KEY`,
          `${mapping.prefix}_BLOCKCHAIN_${role}_PRIVATE_KEY:-`
        ])
      ];
      for (const [internalName, externalName] of expectedMappings) {
        expect(environment).to.include(`${internalName}: \${${externalName}}`);
      }
      expect(environment).not.to.include("127.0.0.1:8546");
      expect(environment).not.to.include("${BLOCKCHAIN_RPC_URL");
      expect(environment).not.to.include("${HEALTH_ACCESS_CONTROL_ADDRESS");
      expect(environment).not.to.match(/\$\{(?:HEALTH_ACCESS_CONTROL_ADDRESS|BLOCKCHAIN_(?:DEPLOYER|PATIENT|PRACTITIONER|ORGANIZATION|PEP)_PRIVATE_KEY):-/);
      const otherPrefix = mapping.prefix === "HOSPITAL_A" ? "CLINIC_B" : "HOSPITAL_A";
      expect(environment).not.to.include(`\${${otherPrefix}_`);
      expect(environment).to.match(/^\s*HEALTH_ACCESS_BOOTSTRAP_ENABLED: "false"/m);
    }
    for (const prefix of ["HOSPITAL_A", "CLINIC_B"]) {
      expect(envExample).to.match(new RegExp(`^${prefix}_BLOCKCHAIN_RPC_URL=`, "m"));
      expect(envExample).to.match(new RegExp(`^${prefix}_HEALTH_ACCESS_CONTROL_ADDRESS=`, "m"));
      for (const role of walletRoles) {
        expect(envExample).to.match(new RegExp(`^${prefix}_BLOCKCHAIN_${role}_PRIVATE_KEY=`, "m"));
      }
    }
    expect(envExample).to.match(/^HOSPITAL_A_BLOCKCHAIN_RPC_URL=$/m);
    expect(envExample).to.match(/^CLINIC_B_BLOCKCHAIN_RPC_URL=$/m);
    for (const variable of [
      "BLOCKCHAIN_RPC_URL",
      "HEALTH_ACCESS_CONTROL_ADDRESS",
      "BLOCKCHAIN_DEPLOYER_PRIVATE_KEY",
      "BLOCKCHAIN_PATIENT_PRIVATE_KEY",
      "BLOCKCHAIN_PRACTITIONER_PRIVATE_KEY",
      "BLOCKCHAIN_ORGANIZATION_PRIVATE_KEY",
      "BLOCKCHAIN_PEP_PRIVATE_KEY"
    ]) {
      expect(envExample).to.match(new RegExp(`^${variable}=`, "m"));
      expect(compose).not.to.include(`\${${variable}`);
    }
    expect(envExample).to.include("docker-compose.yml never");
    expect(middlewareDockerfile).to.include("RUN node scripts/run-hardhat.cjs compile");
    expect(middlewareDockerfile).to.include("CMD [\"node\", \"scripts/run-hardhat.cjs\", \"run\", \"scripts/start-institution-gateway.ts\"]");
  });

  it("keeps Clinic B requester UDAP settings out of the local issuer configuration", function () {
    const environment = environmentBlock(serviceBlock(compose, "clinic-b-gateway"));
    expect(environment).to.include('UDAP_ENABLED: "false"');
    expect(environment).to.include("UDAP_REQUESTER_ENABLED: ${UDAP_CLINIC_B_ENABLED:-false}");
    expect(environment).to.include("UDAP_REQUESTER_DISCOVERY_URL: ${UDAP_CLINIC_B_DISCOVERY_URL:-}");
    expect(environment).to.include("UDAP_REQUESTER_SIGNING_KEY_PATH: /run/interfhir/udap/clinic-b-client-signing.key");
    for (const variable of [
      "UDAP_ISSUER",
      "UDAP_BASE_URL",
      "UDAP_TOKEN_AUDIENCE",
      "UDAP_SIGNING_KEY_PATH",
      "UDAP_SIGNING_KEY_ID",
      "UDAP_TRUSTED_JWKS_PATH",
      "UDAP_ISSUER_JWKS_PATH",
      "UDAP_ISSUER_JWKS_URI",
      "UDAP_SIGNED_METADATA_PATH"
    ]) {
      expect(environment).not.to.match(new RegExp(`^\\s*${variable}:`, "m"));
    }
  });

  it("keeps public and peer listeners distinct inside the gateways", function () {
    expect(compose).to.match(/HEALTH_ACCESS_PUBLIC_PORT: "3000"/);
    expect(compose).to.match(/HEALTH_ACCESS_PEER_PORT: "4000"/);
    expect(devCompose).to.include('127.0.0.1:${INTERFHIR_HOSPITAL_A_GATEWAY_HOST_PORT:-3001}:3000');
    expect(devCompose).to.include('127.0.0.1:${INTERFHIR_HOSPITAL_A_PEER_HOST_PORT:-4001}:4000');
    expect(devCompose).to.include('127.0.0.1:${INTERFHIR_CLINIC_B_GATEWAY_HOST_PORT:-3002}:3000');
    expect(devCompose).to.include('127.0.0.1:${INTERFHIR_CLINIC_B_PEER_HOST_PORT:-4002}:4000');
    expect(devCompose).not.to.include('127.0.0.1:4001:3000');
    expect(devCompose).not.to.include('127.0.0.1:4002:3000');
  });

  it("uses CA-backed HTTPS healthchecks and declares the required external networks", function () {
    for (const service of ["hospital-a-gateway", "clinic-b-gateway"]) {
      const block = serviceBlock(compose, service);
      expect(block).to.include("https://localhost:3000/health");
      expect(block).to.include("process.env.HEALTH_ACCESS_TLS_CA_PATH");
      expect(block).not.to.include("fetch('http://127.0.0.1:3000/health')");
    }
    const networks = (yaml.load(compose) as { networks: Record<string, { name: string; external: boolean }> }).networks;
    for (const network of ["institutional-identity", "institutional-blockchain"]) {
      expect(networks[network].name).to.equal("${INTERFHIR_PROJECT_NAME}-" + network);
      expect(networks[network].external).to.equal(false);
    }
  });

  it("compiles the HAPI healthcheck with the Java runtime version of HAPI", function () {
    const hapiDockerfile = readText("../../docker/hapi-fhir.Dockerfile");

    expect(hapiDockerfile).to.match(/^FROM eclipse-temurin:17-jdk@sha256:[a-f0-9]{64} AS healthcheck-builder$/m);
    expect(hapiDockerfile).not.to.include("eclipse-temurin:21-jdk");
  });

  it("configures both HAPI services with HAPI's PostgreSQL database platform", function () {
    const expectedPlatform = "ca.uhn.fhir.jpa.model.dialect.HapiFhirPostgresDialect";
    const expectedApplicationJson = JSON.stringify({
      "spring.jpa.properties.hibernate.dialect": expectedPlatform
    });

    for (const service of ["hospital-a-fhir", "clinic-b-fhir"]) {
      const environment = environmentBlock(serviceBlock(compose, service));
      expect(environment).to.include(`- SPRING_APPLICATION_JSON=${expectedApplicationJson}`);
      for (const variable of [
        "SPRING_JPA_DATABASEPLATFORM",
        "SPRING_JPA_DATABASE_PLATFORM",
        "SPRING_JPA_PROPERTIES_HIBERNATE_DIALECT"
      ]) {
        expect(environment).not.to.match(new RegExp(`^\\s*-\\s*${variable}=`, "m"));
      }
    }
  });

  it("parses both HAPI environment shapes and validates the effective dialect configuration", function () {
    const parsedCompose = parseComposeDocument(compose);
    const expectedPlatform = "ca.uhn.fhir.jpa.model.dialect.HapiFhirPostgresDialect";

    for (const serviceName of ["hospital-a-fhir", "clinic-b-fhir"]) {
      const sourceEnvironment = parsedCompose.services[serviceName].environment;
      const environmentDefinitions = [
        sourceEnvironment,
        Object.fromEntries(normalizeEnvironment(sourceEnvironment))
      ];

      for (const definition of environmentDefinitions) {
        const environment = normalizeEnvironment(definition);
        const applicationJson = JSON.parse(environment.get("SPRING_APPLICATION_JSON") ?? "null");

        expect(applicationJson).to.deep.equal({
          "spring.jpa.properties.hibernate.dialect": expectedPlatform
        });
        for (const variable of [
          "SPRING_JPA_DATABASEPLATFORM",
          "SPRING_JPA_DATABASE_PLATFORM",
          "SPRING_JPA_PROPERTIES_HIBERNATE_DIALECT"
        ]) {
          expect(environment.has(variable)).to.equal(false);
        }
      }
    }
  });
});

function readText(relativePath: string) {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8").replaceAll("\r\n", "\n");
}

function serviceBlock(document: string, service: string) {
  const marker = `  ${service}:\n`;
  const start = document.indexOf(marker);
  if (start < 0) throw new Error(`COMPOSE_SERVICE_NOT_FOUND: ${service}`);
  const remainder = document.slice(start + marker.length);
  const nextService = remainder.search(/\n  [a-z0-9-]+:\n|\nnetworks:\n|\nvolumes:\n/);
  return remainder.slice(0, nextService < 0 ? remainder.length : nextService);
}

function environmentBlock(service: string) {
  const start = service.indexOf("\n    environment:\n");
  if (start < 0) throw new Error("COMPOSE_ENVIRONMENT_NOT_FOUND");
  const remainder = service.slice(start + "\n    environment:\n".length);
  const end = remainder.search(/\n    volumes:\n|\n    healthcheck:\n|\n    networks:\n/);
  return remainder.slice(0, end < 0 ? remainder.length : end);
}

type ComposeService = {
  environment?: unknown;
};

type ComposeDocument = {
  services: Record<string, ComposeService>;
};

function parseComposeDocument(source: string): ComposeDocument {
  const parsed = yaml.load(source);
  if (!isRecord(parsed) || !isRecord(parsed.services)) {
    throw new Error("COMPOSE_SERVICES_NOT_FOUND");
  }
  return { services: parsed.services as Record<string, ComposeService> };
}

function normalizeEnvironment(environment: unknown): Map<string, string> {
  if (Array.isArray(environment)) {
    return new Map(environment.map((entry) => {
      if (typeof entry !== "string") {
        throw new Error("COMPOSE_ENVIRONMENT_ENTRY_INVALID");
      }
      const separator = entry.indexOf("=");
      return separator < 0
        ? [entry, ""]
        : [entry.slice(0, separator), entry.slice(separator + 1)];
    }));
  }

  if (isRecord(environment)) {
    return new Map(Object.entries(environment).map(([key, value]) => [
      key,
      value == null ? "" : String(value)
    ]));
  }

  throw new Error("COMPOSE_ENVIRONMENT_INVALID");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
