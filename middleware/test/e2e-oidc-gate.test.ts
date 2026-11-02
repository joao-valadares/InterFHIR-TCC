import { expect } from "chai";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, SignJWT } from "jose";

const identityCompose = readText("../../docker-compose.identity.yml");
const envExample = readText("../../.env.example");
const e2eRunner = readText("../../scripts/e2e/run-real-e2e.ts");

interface GateModule {
  KEYCLOAK_CONTAINER_HOSTNAME: string;
  buildKeycloakDemoUserProfiles(config: Record<string, string>): Array<{
    id: string;
    realm: string;
    username: string;
    password: string;
    clientSecret: string;
    issuer: string;
    expectedClaims: Record<string, string>;
  }>;
  assertKeycloakDemoUserClaims(profile: { id: string; expectedClaims: Record<string, string> }, claims: Record<string, unknown>): void;
  runKeycloakOidcGate(config: Record<string, string>): Promise<{ validatedUsers: number }>;
}

const demoConfig: Record<string, string> = {
  patientUsername: "hospital-a-patient",
  patientPassword: "patient-password",
  hospitalAPractitionerUsername: "hospital-a-practitioner",
  hospitalAPractitionerPassword: "hospital-a-practitioner-password",
  administratorUsername: "hospital-a-admin",
  administratorPassword: "hospital-a-admin-password",
  clinicBPatientUsername: "clinic-b-patient",
  clinicBPatientPassword: "clinic-b-patient-password",
  practitionerUsername: "clinic-b-practitioner",
  practitionerPassword: "clinic-b-practitioner-password",
  clinicBAdministratorUsername: "clinic-b-admin",
  clinicBAdministratorPassword: "clinic-b-admin-password",
  patientClientSecret: "hospital-a-secret",
  clinicBClientSecret: "clinic-b-secret",
  hospitalAOidcIssuer: "http://keycloak:8080/realms/hospital-a",
  clinicBOidcIssuer: "http://keycloak:8080/realms/clinic-b",
  hospitalAJwksUrl: "http://keycloak:8180/realms/hospital-a/protocol/openid-connect/certs",
  clinicBJwksUrl: "http://keycloak:8180/realms/clinic-b/protocol/openid-connect/certs"
};

async function loadGateModule(): Promise<GateModule> {
  return await import("../../scripts/e2e/run-real-e2e.js") as unknown as GateModule;
}

describe("real Keycloak E2E gate", () => {
  it("defines six users with role and subject claims for both realms", async () => {
    const gate = await loadGateModule();
    const profiles = gate.buildKeycloakDemoUserProfiles(demoConfig);

    expect(profiles).to.have.length(6);
    expect(profiles.map((profile) => `${profile.realm}/${profile.username}`)).to.deep.equal([
      "hospital-a/hospital-a-patient",
      "hospital-a/hospital-a-practitioner",
      "hospital-a/hospital-a-admin",
      "clinic-b/clinic-b-patient",
      "clinic-b/clinic-b-practitioner",
      "clinic-b/clinic-b-admin"
    ]);

    expect(profiles.find((profile) => profile.id === "hospital-a-patient")?.expectedClaims).to.deep.equal({
      role: "patient",
      patientReference: "Patient/pat-ana",
      organizationReference: "Organization/hospital-a"
    });
    expect(profiles.find((profile) => profile.id === "clinic-b-practitioner")?.expectedClaims).to.deep.equal({
      role: "practitioner",
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/clinic-b"
    });
  });

  it("rejects a token whose institution or subject claim does not match the imported profile", async () => {
    const gate = await loadGateModule();
    const profile = gate.buildKeycloakDemoUserProfiles(demoConfig).find((candidate) => candidate.id === "clinic-b-practitioner");
    expect(profile).to.not.equal(undefined);

    expect(() => gate.assertKeycloakDemoUserClaims(profile!, {
      role: "practitioner",
      practitionerReference: "Practitioner/bruno",
      organizationReference: "Organization/hospital-a"
    })).to.throw("OIDC_CLAIM_INVALID:clinic-b-practitioner:organizationReference");
  });

  it("uses the canonical Clinic B Practitioner reference across identity and E2E inputs", () => {
    const clinicBRealm = JSON.parse(readText("../../infra/keycloak/realm-clinic-b.json")) as {
      users: Array<{ username?: string; attributes?: { practitionerReference?: string[] } }>;
    };
    const practitioner = clinicBRealm.users.find((user) => user.attributes?.practitionerReference !== undefined);
    expect(practitioner?.username).to.equal("profissional.bruno");
    expect(practitioner?.attributes?.practitionerReference).to.deep.equal(["Practitioner/bruno"]);
    expect(e2eRunner).to.include('practitionerReference: "Practitioner/bruno"');
    expect(readText("../../scripts/bootstrap-state.ts")).to.include('practitionerReference: "Practitioner/bruno"');
  });

  it("pins the issuer host and port used by the container to the trusted internal issuer", async () => {
    const gate = await loadGateModule();
    expect(gate.KEYCLOAK_CONTAINER_HOSTNAME).to.equal("http://keycloak:8080");
  });

  it("keeps the Compose default, example environment and E2E Compose environment on http://keycloak:8080", () => {
    expect(identityCompose).to.include("KC_HOSTNAME: ${KEYCLOAK_CONTAINER_HOSTNAME:-http://keycloak:8080}");
    expect(envExample).to.match(/^KEYCLOAK_CONTAINER_HOSTNAME=http:\/\/keycloak:8080$/m);
    expect(e2eRunner).to.include("KEYCLOAK_CONTAINER_HOSTNAME,");
  });

  it("exercises the six-user OIDC gate with real RS256 and JWKS verification", async () => {
    const gate = await loadGateModule();
    const realmKeys = {
      "hospital-a": await createRealmKey("hospital-a"),
      "clinic-b": await createRealmKey("clinic-b")
    };
    const server = createServer((request, response) => {
      void serveOidcRequest(request, response, gate, realmKeys);
    });
    await listen(server);
    const address = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const config = buildStubConfig(baseUrl);

    try {
      const result = await gate.runKeycloakOidcGate(config);
      expect(result).to.deep.equal({ validatedUsers: 6 });
    } finally {
      await close(server);
    }
  });
});

function buildStubConfig(baseUrl: string): Record<string, string> {
  return {
    keycloakUrl: baseUrl,
    patientUsername: "hospital-a-patient",
    patientPassword: "hospital-a-patient-password",
    patientClientSecret: "hospital-a-client-secret",
    hospitalAPractitionerUsername: "hospital-a-practitioner",
    hospitalAPractitionerPassword: "hospital-a-practitioner-password",
    administratorUsername: "hospital-a-administrator",
    administratorPassword: "hospital-a-administrator-password",
    clinicBPatientUsername: "clinic-b-patient",
    clinicBPatientPassword: "clinic-b-patient-password",
    clinicBClientSecret: "clinic-b-client-secret",
    practitionerUsername: "clinic-b-practitioner",
    practitionerPassword: "clinic-b-practitioner-password",
    clinicBAdministratorUsername: "clinic-b-administrator",
    clinicBAdministratorPassword: "clinic-b-administrator-password",
    hospitalAOidcIssuer: `${baseUrl}/realms/hospital-a`,
    clinicBOidcIssuer: `${baseUrl}/realms/clinic-b`,
    hospitalAJwksUrl: `${baseUrl}/realms/hospital-a/protocol/openid-connect/certs`,
    clinicBJwksUrl: `${baseUrl}/realms/clinic-b/protocol/openid-connect/certs`
  };
}

type RealmKey = {
  privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
  publicJwk: Record<string, unknown>;
};

async function createRealmKey(realm: string): Promise<RealmKey> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  return {
    privateKey,
    publicJwk: { ...(await exportJWK(publicKey)), alg: "RS256", kid: `oidc-gate-test-${realm}`, use: "sig" }
  };
}

async function serveOidcRequest(
  request: import("node:http").IncomingMessage,
  response: import("node:http").ServerResponse,
  gate: GateModule,
  realmKeys: Record<string, RealmKey>
): Promise<void> {
  try {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "127.0.0.1"}`);
    const realm = url.pathname.split("/")[2];
    const key = realmKeys[realm];
    if (url.pathname.endsWith("/protocol/openid-connect/certs")) {
      return key ? writeJson(response, 200, { keys: [key.publicJwk] }) : writeJson(response, 404, { error: "unknown_realm" });
    }
    if (request.method !== "POST" || !url.pathname.endsWith("/protocol/openid-connect/token")) {
      return writeJson(response, 404, { error: "not_found" });
    }

    const form = new URLSearchParams(await readRequestBody(request));
    const profiles = gate.buildKeycloakDemoUserProfiles(buildStubConfig(url.origin));
    const profile = profiles.find((candidate) => candidate.realm === realm && candidate.username === form.get("username"));
    if (!key || !profile || form.get("password") !== profile.password || form.get("client_secret") !== profile.clientSecret) {
      return writeJson(response, 400, { error: "invalid_grant" });
    }

    const token = await new SignJWT({ ...profile.expectedClaims, preferred_username: profile.username })
      .setProtectedHeader({ alg: "RS256", kid: String(key.publicJwk.kid), typ: "JWT" })
      .setIssuer(profile.issuer)
      .setAudience("interfhir-api")
      .setSubject(profile.id)
      .setJti(`oidc-gate-jti-${profile.id}`)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(key.privateKey);
    return writeJson(response, 200, { access_token: token, token_type: "Bearer" });
  } catch {
    return writeJson(response, 500, { error: "stub_failure" });
  }
}

function readRequestBody(request: import("node:http").IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function writeJson(response: import("node:http").ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function listen(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function readText(relativePath: string): string {
  return readFileSync(new URL(relativePath, import.meta.url), "utf8").replaceAll("\r\n", "\n");
}
