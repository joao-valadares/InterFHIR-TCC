export function createUdapDiscovery(options: {
  issuer: string;
  baseUrl: string;
  signedMetadata: string;
  issuerJwksUri?: string;
}) {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  return {
    async metadata() {
      return {
        udap_versions_supported: ["1"],
        udap_profiles_supported: ["udap_dcr", "udap_authn", "udap_authz"],
        udap_authorization_extensions_supported: ["hl7-b2b"],
        udap_authorization_extensions_required: ["hl7-b2b"],
        grant_types_supported: ["client_credentials"],
        token_endpoint_auth_methods_supported: ["private_key_jwt"],
        token_endpoint: `${baseUrl}/udap/token`,
        registration_endpoint: `${baseUrl}/udap/register`,
        issuer: options.issuer,
        scopes_supported: ["system/Observation.r"],
        token_endpoint_auth_signing_alg_values_supported: ["RS256", "ES256"],
        signed_metadata: options.signedMetadata,
        ...(options.issuerJwksUri ? { jwks_uri: options.issuerJwksUri } : {})
      };
    }
  };
}
