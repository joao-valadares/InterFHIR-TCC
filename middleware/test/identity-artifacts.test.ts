import { expect } from "chai";
import { readFileSync } from "node:fs";

const root = new URL("../../", import.meta.url);

describe("identity artifacts", function () {
  it("defines local-only human users, confidential direct-grant clients and all identity mappers", function () {
    for (const realmName of ["realm-hospital-a.json", "realm-clinic-b.json"]) {
      const realm = JSON.parse(readFileSync(new URL(`infra/keycloak/${realmName}`, root), "utf8")) as {
        clients: Array<{ clientId?: string; publicClient?: boolean; directAccessGrantsEnabled?: boolean; protocolMappers?: Array<{ name?: string; protocolMapper?: string; config?: Record<string, string> }> }>;
        users: Array<{ credentials?: Array<{ type?: string; value?: string; temporary?: boolean }>; attributes?: Record<string, string[]> }>;
      };
      expect(realm.clients.some((client) => client.publicClient === false && client.directAccessGrantsEnabled === true)).to.equal(true);
      const mapperNames = new Set(realm.clients.flatMap((client) => (client.protocolMappers ?? []).map((mapper) => mapper.name)));
      expect([...mapperNames]).to.include.members(["role", "patientReference", "practitionerReference", "organizationReference", "roleCode", "specialtyCode"]);
      for (const client of realm.clients.filter((candidate) => candidate.publicClient === false)) {
        const audienceMapper = (client.protocolMappers ?? []).find((mapper) => mapper.protocolMapper === "oidc-audience-mapper");
        expect(audienceMapper).to.deep.include({ protocolMapper: "oidc-audience-mapper" });
        expect(audienceMapper?.config).to.deep.include({
          "included.client.audience": "interfhir-api",
          "access.token.claim": "true",
          "id.token.claim": "false"
        });
      }
      expect(realm.users).to.have.length(3);
      expect(realm.users.every((user) => user.credentials?.[0]?.type === "password" && user.credentials[0].value?.startsWith("local-only-") && user.credentials[0].temporary === false)).to.equal(true);
    }
  });

  it("imports demo users with a complete Keycloak profile and no required actions", function () {
    for (const realmName of ["realm-hospital-a.json", "realm-clinic-b.json"]) {
      const realm = JSON.parse(readFileSync(new URL(`infra/keycloak/${realmName}`, root), "utf8")) as {
        users: Array<{
          username?: string;
          email?: string;
          firstName?: string;
          lastName?: string;
          requiredActions?: string[];
        }>;
      };

      expect(realm.users).to.have.length(3);
      for (const user of realm.users) {
        expect(user.email, `${realmName}:${user.username}:email`).to.match(/^[^@\s]+@[^@\s]+\.[^@\s]+$/);
        expect(user.firstName, `${realmName}:${user.username}:firstName`).to.be.a("string").and.not.empty;
        expect(user.lastName, `${realmName}:${user.username}:lastName`).to.be.a("string").and.not.empty;
        expect(user.requiredActions, `${realmName}:${user.username}:requiredActions`).to.deep.equal([]);
      }
    }
  });

  it("keeps PKI outputs purpose-specific and refuses implicit replacement", function () {
    const script = readFileSync(new URL("scripts/generate-local-pki.ps1", root), "utf8");
    expect(script).to.include('$Purpose.key');
    expect(script).to.include("serverAuth");
    expect(script).to.include('$Purpose.key');
    expect(script).to.include("clientAuth");
    expect(script).to.include("PKI_ALREADY_EXISTS");
    expect(script).to.include("-Force");
    expect(script).not.to.include("extendedKeyUsage=serverAuth,clientAuth");
    expect(script).to.include("CA_PRIVATE_KEY_REMAINS");
    expect(script).not.to.match(/ca\.key[^\r\n]*SilentlyContinue/);
  });

  it("provides a dedicated UDAP generator with explicit overwrite protection", function () {
    const script = readFileSync(new URL("scripts/generate-udap-keys.ts", root), "utf8");
    expect(script).to.include("hospital-a-signing.key");
    expect(script).to.include("hospital-a-trusted-jwks.json");
    expect(script).to.include("hospital-a-issuer-jwks.json");
    expect(script).to.include("hospital-a-signed-metadata.jwt");
    expect(script).to.include("clinic-b-client-signing.key");
    expect(script).to.include("clinic-b-client-public-jwk.json");
    expect(script).to.include("keys: [hospital.publicJwk]");
    expect(script).to.include("keys: [clinic.publicJwk]");
    expect(script).to.include("jwks_uri: issuerJwksUri");
    expect(script).to.include("--force");
    expect(script).to.include("UDAP_KEYS_ALREADY_EXIST");
  });

  it("makes Keycloak import deterministic and readiness observable", function () {
    const compose = readFileSync(new URL("docker-compose.identity.yml", root), "utf8");
    expect(compose).to.include("start-dev --import-realm");
    expect(compose).to.include("healthcheck:");
    expect(compose).to.include("/health/ready");
    expect(compose).to.include("./infra/keycloak:/opt/keycloak/data/import:ro");
  });

  it("uses an image-native bounded Keycloak readiness probe instead of curl", function () {
    const compose = readFileSync(new URL("docker-compose.identity.yml", root), "utf8").replace(/\r\n/g, "\n");
    const healthcheckStart = compose.indexOf("    healthcheck:\n");
    const healthcheckEnd = compose.indexOf("\n    networks:\n", healthcheckStart);
    expect(healthcheckStart).to.be.greaterThan(-1);
    expect(healthcheckEnd).to.be.greaterThan(healthcheckStart);
    const healthcheck = compose.slice(healthcheckStart, healthcheckEnd);

    expect(healthcheck).not.to.match(/\bcurl\b/);
    expect(healthcheck).to.include("bash -c");
    expect(healthcheck).to.include("/dev/tcp/127.0.0.1/9000");
    expect(healthcheck).to.include("GET /health/ready");
    expect(healthcheck).to.match(/read\s+-r\s+-t\s+[1-9][0-9]*/);
    expect(healthcheck).to.match(/HTTP\/1\.[01]\s+200/);
    expect(healthcheck).to.match(/\$\$status\b/);
    expect(healthcheck).not.to.match(/(^|[^$])\$status\b/);
  });

  it("keeps the advertised public JWKS URI aligned with the API route", function () {
    const example = readFileSync(new URL(".env.example", root), "utf8");
    const handler = readFileSync(new URL("middleware/src/api/api-handler.ts", root), "utf8");
    expect(example).to.match(/^UDAP_ISSUER_JWKS_URI=https:\/\/hospital-a\.local\/\.well-known\/udap\/jwks\.json$/m);
    expect(handler).to.include('"/.well-known/udap/jwks.json"');
    expect(handler).to.include('"UDAP_JWKS_UNAVAILABLE"');
    expect(handler).to.include('"content-type": "application/json"');
  });
});
