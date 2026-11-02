import { expect } from "chai";

import { createUdapDiscovery } from "../src/udap/udap-discovery.js";

describe("UDAP discovery", function () {
  it("publishes the required B2B profile and absolute endpoints", async function () {
    const discovery = createUdapDiscovery({
      issuer: "https://hospital-a.local/udap",
      baseUrl: "https://hospital-a.local",
      signedMetadata: "signed-metadata-jws"
    });
    expect(await discovery.metadata()).to.deep.equal({
      udap_versions_supported: ["1"],
      udap_profiles_supported: ["udap_dcr", "udap_authn", "udap_authz"],
      udap_authorization_extensions_supported: ["hl7-b2b"],
      udap_authorization_extensions_required: ["hl7-b2b"],
      grant_types_supported: ["client_credentials"],
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      token_endpoint: "https://hospital-a.local/udap/token",
      registration_endpoint: "https://hospital-a.local/udap/register",
      issuer: "https://hospital-a.local/udap",
      scopes_supported: ["system/Observation.r"],
      token_endpoint_auth_signing_alg_values_supported: ["RS256", "ES256"],
      signed_metadata: "signed-metadata-jws"
    });
  });

  it("publishes the configured public issuer JWKS URI", async function () {
    const discovery = createUdapDiscovery({
      issuer: "https://hospital-a.local",
      baseUrl: "https://hospital-a.local",
      signedMetadata: "signed-metadata-jws",
      issuerJwksUri: "https://hospital-a.local/.well-known/udap/jwks.json"
    });
    expect((await discovery.metadata()).jwks_uri).to.equal("https://hospital-a.local/.well-known/udap/jwks.json");
  });
});
