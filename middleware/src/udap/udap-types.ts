export interface Hl7B2bAuthorizationExtension {
  version: "1";
  subject_name?: string;
  subject_id: string;
  subject_role: string;
  organization_name?: string;
  organization_id: string;
  purpose_of_use: string[];
  consent_policy?: string[];
  consent_reference?: string[];
}

export interface UdapAuthenticationClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  extensions: { "hl7-b2b": Hl7B2bAuthorizationExtension };
}
